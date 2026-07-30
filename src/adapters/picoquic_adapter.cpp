#include "adapter_factory.h"
#include "resumption_envelope.h"
#include "core/strict_config.h"

#include <picoquic.h>
#include <picoquic_internal.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <optional>
#include <source_location>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace quicperf {
namespace {

constexpr char alpn[] = "qperf/2";
constexpr uint32_t resumptionMagic = 0x51505052U;
constexpr size_t resumptionParameterCount = 6;
constexpr size_t resumptionHeaderBytes = 4 + 4 + 4 + 2 + resumptionParameterCount * 8;
constexpr size_t resumptionStateLimit = 16 * 1024 - resumptionEnvelopeBytes;
constexpr uint64_t nanosecondsPerSecond = 1'000'000'000ULL;
constexpr uint32_t quicEarlyDataTicketLimit = std::numeric_limits<uint32_t>::max();

bool postHandshakeReady(picoquic_cnx_t* connection) noexcept
{
  const auto state = picoquic_get_cnx_state(connection);
  return state == picoquic_state_client_ready_start || state == picoquic_state_ready;
}

bool disableOpenSslTimedReseeding()
{
  time_t interval = 0;
  OSSL_PARAM parameters[] = {
      OSSL_PARAM_construct_time_t(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, &interval),
      OSSL_PARAM_construct_end()};
  for (EVP_RAND_CTX* context : {
           RAND_get0_primary(nullptr), RAND_get0_public(nullptr),
           RAND_get0_private(nullptr)})
    if (!context || EVP_RAND_CTX_set_params(context, parameters) != 1) return false;
  return true;
}

bool configuredLeafIsEd25519(const std::string& path)
{
  BIO* input = BIO_new_file(path.c_str(), "r");
  if (!input) return false;
  X509* certificate = PEM_read_bio_X509(input, nullptr, nullptr, nullptr);
  BIO_free(input);
  if (!certificate) return false;
  const bool result = X509_get_signature_nid(certificate) == NID_ED25519;
  X509_free(certificate);
  return result;
}

void storeU16(std::byte* destination, uint16_t value)
{
  value = htons(value);
  std::memcpy(destination, &value, sizeof(value));
}

void storeU32(std::byte* destination, uint32_t value)
{
  value = htonl(value);
  std::memcpy(destination, &value, sizeof(value));
}

void storeU64(std::byte* destination, uint64_t value)
{
  const uint32_t high = htonl(static_cast<uint32_t>(value >> 32));
  const uint32_t low = htonl(static_cast<uint32_t>(value));
  std::memcpy(destination, &high, sizeof(high));
  std::memcpy(destination + sizeof(high), &low, sizeof(low));
}

uint16_t loadU16(const std::byte* source)
{
  uint16_t value = 0;
  std::memcpy(&value, source, sizeof(value));
  return ntohs(value);
}

uint32_t loadU32(const std::byte* source)
{
  uint32_t value = 0;
  std::memcpy(&value, source, sizeof(value));
  return ntohl(value);
}

uint64_t loadU64(const std::byte* source)
{
  uint32_t high = 0;
  uint32_t low = 0;
  std::memcpy(&high, source, sizeof(high));
  std::memcpy(&low, source + sizeof(high), sizeof(low));
  return (static_cast<uint64_t>(ntohl(high)) << 32) | ntohl(low);
}

bool remoteInitiated(uint64_t streamId, EndpointRole role) noexcept
{
  const bool initiatedByServer = (streamId & 1U) != 0;
  return initiatedByServer == (role == EndpointRole::client);
}

bool bidirectional(uint64_t streamId) noexcept { return (streamId & 2U) == 0; }

int noVerifyCertificate(ptls_verify_certificate_t*, ptls_t*, const char*,
                        int (**verifySign)(void*, uint16_t, ptls_iovec_t, ptls_iovec_t),
                        void** verifyData, ptls_iovec_t*, size_t)
{
  *verifySign = nullptr;
  *verifyData = nullptr;
  return 0;
}

constexpr uint16_t noVerifySignatureAlgorithms[] = {
    PTLS_SIGNATURE_ED25519, PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384, PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256, PTLS_SIGNATURE_RSA_PKCS1_SHA256,
    PTLS_SIGNATURE_RSA_PKCS1_SHA1, UINT16_MAX};

ptls_verify_certificate_t noVerify = {noVerifyCertificate, noVerifySignatureAlgorithms};

class PicoquicAdapter final : public Adapter {
public:
  PicoquicAdapter();
  ~PicoquicAdapter() override;

  const Capabilities& capabilities() const noexcept override { return capabilities_; }
  bool configure(std::string_view canonicalConfig, AdapterError& error) override;
  bool setLocalAddress(const sockaddr_in& local, AdapterError& error) override;
  bool receiveBatch(std::span<const ReceivedPacket> packets, uint64_t nowRawNs,
                    AdapterError& error) override;
  size_t pollTransmitBatch(std::span<TransmitPacket> packets, uint64_t nowRawNs,
                           AdapterError& error) override;
  uint64_t nextTimeoutRawNs() const noexcept override { return nextTimeoutRawNs_; }
  bool onTimeout(uint64_t nowRawNs, AdapterError& error) override;
  bool connect(const sockaddr_in& peer, uint64_t nowRawNs, uint64_t& connectionId,
               AdapterError& error) override;
  PrimitiveStatus acceptConnection(uint64_t, uint64_t& connectionId,
                                   AdapterError& error) override;
  bool isConnected(uint64_t connectionId, uint64_t, bool& connected,
                   AdapterError& error) override;
  bool connectionIsClosed(uint64_t connectionId, uint64_t, bool& closed,
                          AdapterError& error) override;
  bool releaseConnectionWhenClosed(uint64_t connectionId, uint64_t,
                                   AdapterError& error) override;
  PrimitiveStatus openBidirectionalStream(uint64_t connectionId, uint64_t,
                                          uint64_t& streamId, AdapterError& error) override;
  PrimitiveStatus acceptBidirectionalStream(uint64_t connectionId, uint64_t,
                                            uint64_t& streamId, AdapterError& error) override;
  PrimitiveStatus openUnidirectionalStream(uint64_t connectionId, uint64_t,
                                           uint64_t& streamId, AdapterError& error) override;
  PrimitiveStatus acceptUnidirectionalStream(uint64_t connectionId, uint64_t,
                                             uint64_t& streamId, AdapterError& error) override;
  bool writeStream(uint64_t connectionId, uint64_t streamId,
                   std::span<const std::byte> bytes, uint64_t, size_t& written,
                   AdapterError& error) override;
  bool consumeStreamData(uint64_t connectionId, uint64_t streamId,
                         std::span<std::byte> bytes, uint64_t, size_t& read,
                         bool& finished, AdapterError& error) override;
  bool finishStream(uint64_t connectionId, uint64_t streamId, uint64_t,
                    AdapterError& error) override;
  bool resetStream(uint64_t connectionId, uint64_t streamId, uint64_t applicationError,
                   uint64_t, AdapterError& error) override;
  bool stopSending(uint64_t connectionId, uint64_t streamId, uint64_t applicationError,
                   uint64_t, AdapterError& error) override;
  PrimitiveStatus sendDatagram(uint64_t connectionId, std::span<const std::byte> bytes,
                               uint64_t, AdapterError& error) override;
  PrimitiveStatus consumeDatagram(uint64_t connectionId, std::span<std::byte> bytes,
                                  uint64_t, size_t& read, AdapterError& error) override;
  PrimitiveStatus exportResumptionState(uint64_t connectionId, uint64_t,
                                        std::span<std::byte> bytes, size_t& written,
                                        AdapterError& error) override;
  PrimitiveStatus importResumptionState(std::span<const std::byte> bytes, bool useZeroRtt,
                                        uint64_t, AdapterError& error) override;
  bool connectionResumed(uint64_t connectionId, uint64_t, bool& resumed,
                         AdapterError& error) override;
  bool zeroRttAttempted(uint64_t connectionId, uint64_t, bool& attempted,
                       AdapterError& error) override;
  bool zeroRttAccepted(uint64_t connectionId, uint64_t, bool& accepted,
                      AdapterError& error) override;
  bool zeroRttRejected(uint64_t connectionId, uint64_t, bool& rejected,
                      AdapterError& error) override;
  bool closeConnection(uint64_t connectionId, uint64_t applicationError,
                       uint64_t, AdapterError& error) override;
  bool peerTerminalFacts(uint64_t connectionId, uint64_t streamId, uint64_t,
                         PeerTerminalFacts& facts, AdapterError& error) override;
  TransportCounters snapshotTransportCounters() const noexcept override;
  NegotiatedSettings snapshotNegotiatedSettings() const noexcept override;
  bool reset(AdapterError& error) override;
  bool stop(AdapterError& error) override { return reset(error); }

private:
  struct Stream {
    std::vector<std::byte> received;
    size_t receivedOffset = 0;
    uint64_t consumedCreditsPending = 0;
    bool remoteFin = false;
    bool peerFin = false;
    bool peerReset = false;
    bool peerStopSending = false;
    uint64_t peerResetError = 0;
    uint64_t peerStopSendingError = 0;
    uint64_t acceptedSendBytes = 0;
  };

  struct Connection {
    uint64_t id = 0;
    picoquic_cnx_t* native = nullptr;
    picoquic_cnx_t* retiredNative = nullptr;
    uint64_t acceptedSendBytes = 0;
    std::unordered_map<uint64_t, Stream> streams;
    std::unordered_set<uint64_t> acceptedStreams;
    std::deque<uint64_t> acceptedBidi;
    std::deque<uint64_t> acceptedUni;
    std::deque<std::vector<std::byte>> datagrams;
    uint64_t nextBidi = 0;
    uint64_t nextUni = 0;
    bool zeroRttAttempted = false;
    bool applicationDataObserved = false;
    bool connectedReported = false;
    bool localCloseRequested = false;
    bool peerConnectionClose = false;
    uint64_t peerConnectionCloseError = 0;
    uint64_t peerConnectionCloseReasonLength = 0;
    bool peerCloseConsumed = false;
    bool closedReported = false;
    bool releaseWhenClosed = false;
    uint64_t finalLocalError = 0;
    uint64_t finalRemoteError = 0;
    uint64_t finalRemoteApplicationError = 0;
    uint64_t finalOffendingFrame = 0;
    std::string finalLocalErrorReason;
    std::vector<std::byte> resumptionState;
    TransportCounters finalCounters {};
  };

  static int callback(picoquic_cnx_t* native, uint64_t streamId, uint8_t* bytes,
                      size_t length, picoquic_call_back_event_t event,
                      void* context, void* streamContext);
  bool valid(int code, std::string_view operation, AdapterError& error) const;
  Connection* ensureConnection(picoquic_cnx_t* native);
  Connection* find(
      uint64_t id, AdapterError& error,
      const std::source_location& caller = std::source_location::current()) const;
  void finishNative(Connection& connection) noexcept;
  void reapClosedConnections();
  bool captureResumptionState(Connection& connection, AdapterError& error);
  static bool discardPendingSend(Connection& connection, Stream& stream,
                                 const picoquic_stream_head_t& native) noexcept;
  bool setCallerTime(uint64_t nowRawNs, AdapterError& error) noexcept;
  void updateTimeout(uint64_t nowRawNs) noexcept;
  PrimitiveStatus openStream(Connection& connection, bool bidi, uint64_t& streamId,
                             AdapterError& error);
  PrimitiveStatus acceptStream(Connection& connection, bool bidi, uint64_t& streamId,
                               AdapterError& error);

  Capabilities capabilities_;
  EndpointConfig config_ {};
  picoquic_quic_t* engine_ = nullptr;
  sockaddr_in localAddress_ {};
  std::vector<std::unique_ptr<Connection>> connections_;
  std::unordered_map<uint64_t, Connection*> byId_;
  std::unordered_map<picoquic_cnx_t*, Connection*> byNative_;
  std::deque<uint64_t> acceptedConnections_;
  std::optional<std::vector<std::byte>> importedState_;
  std::unordered_set<std::string> consumedTickets_;
  bool importedZeroRtt_ = false;
  uint64_t nextConnectionId_ = 1;
  uint64_t nextTimeoutRawNs_ = 0;
  uint64_t calendarEpochUs_ = 0;
  uint64_t simulatedTimeUs_ = 0;
  uint64_t rawEpochNs_ = 0;
  uint64_t lastRawNs_ = 0;
  bool callerTimeSet_ = false;
  bool configured_ = false;
  bool localAddressSet_ = false;
  bool configuredLeafSignatureVerified_ = false;
  std::array<ptls_key_exchange_algorithm_t*, 2> tlsKeyExchanges_ {};
  std::array<uint8_t, 16> ticketEncryptionKey_ {};
  std::array<std::array<std::byte, maxUdpPayloadSize>, packetBatchSize> output_ {};
  TransportCounters counters_ {};
};

PicoquicAdapter::PicoquicAdapter()
{
  capabilities_.library = "picoquic";
  capabilities_.buildId = "picoquic-master-2b1e14d-quicperf7-terminal-facts-v5";
  capabilities_.adapterAbiVersion = 2;
  capabilities_.server = true;
  capabilities_.client = true;
  capabilities_.backends = {PacketBackend::syscall, PacketBackend::iouring};
  capabilities_.scenarios = {
      workload::Scenario::download, workload::Scenario::upload,
      workload::Scenario::multistreamDownload, workload::Scenario::multistreamUpload,
      workload::Scenario::bidi, workload::Scenario::lossRecovery,
      workload::Scenario::flowControl, workload::Scenario::smallPayloadPps,
      workload::Scenario::datagram,
      workload::Scenario::reqresp, workload::Scenario::streamChurn,
      workload::Scenario::closeResetCleanup,
      workload::Scenario::connect, workload::Scenario::resumedConnect,
      workload::Scenario::zeroRttReqresp, workload::Scenario::memoryCurve};
  capabilities_.datagram = true;
  capabilities_.resumption = true;
  capabilities_.earlyData = true;
  capabilities_.effectiveFeatures = {
      "common_cpp_packet_io", "borrowed_packet_batch_64", "ipv4", "quic_v1",
      "tls_1_3", "qperf_2_alpn", "bidirectional_stream", "unidirectional_stream",
      "datagram", "resumption", "early_data", "post_bind_local_address",
      "reset_stream", "stop_sending", "connection_close",
      "peer_terminal_facts", "flow_control_blocked_counters"};
}

PicoquicAdapter::~PicoquicAdapter()
{
  AdapterError ignored;
  reset(ignored);
}

bool PicoquicAdapter::valid(int code, std::string_view operation, AdapterError& error) const
{
  if (code == 0) return true;
  error = {static_cast<uint64_t>(static_cast<int64_t>(code) < 0 ?
                                    -static_cast<int64_t>(code) : code),
           std::string(operation) + " failed with picoquic error " + std::to_string(code)};
  return false;
}

PicoquicAdapter::Connection* PicoquicAdapter::ensureConnection(picoquic_cnx_t* native)
{
  const auto found = byNative_.find(native);
  if (found != byNative_.end()) return found->second;
  auto owned = std::make_unique<Connection>();
  owned->id = nextConnectionId_++;
  owned->native = native;
  owned->nextBidi = config_.role == EndpointRole::server ? 1 : 0;
  owned->nextUni = config_.role == EndpointRole::server ? 3 : 2;
  Connection* result = owned.get();
  connections_.push_back(std::move(owned));
  byId_[result->id] = result;
  byNative_[native] = result;
  picoquic_set_callback(native, callback, this);
  if (config_.role == EndpointRole::server) acceptedConnections_.push_back(result->id);
  return result;
}

PicoquicAdapter::Connection* PicoquicAdapter::find(
    uint64_t id, AdapterError& error, const std::source_location& caller) const
{
  const auto found = byId_.find(id);
  if (found != byId_.end() && found->second->native) return found->second;
  if (found != byId_.end())
  {
    const Connection& connection = *found->second;
    error = {2, "closed picoquic connection " + std::to_string(id) + " in " +
                    caller.function_name() + ": local=" +
                    std::to_string(connection.finalLocalError) + ",remote=" +
                    std::to_string(connection.finalRemoteError) + ",packets_sent=" +
                    std::to_string(connection.finalCounters.packetsSent) +
                    ",packets_received=" +
                    std::to_string(connection.finalCounters.packetsReceived) +
                    ",packets_lost=" +
                    std::to_string(connection.finalCounters.packetsLost) +
                    ",offending_frame=" +
                    std::to_string(connection.finalOffendingFrame) + ",reason=" +
                    connection.finalLocalErrorReason};
    return nullptr;
  }
  error = {2, "unknown picoquic connection " + std::to_string(id) + " in " +
                  caller.function_name()};
  return nullptr;
}

void PicoquicAdapter::finishNative(Connection& connection) noexcept
{
  if (!connection.native) return;
  connection.finalCounters.packetsReceived = connection.native->nb_packets_received;
  connection.finalCounters.packetsSent = connection.native->nb_packets_sent;
  connection.finalCounters.packetsRetransmitted = connection.native->nb_retransmission_total;
  connection.finalCounters.flowControlBlockedEvents = connection.native->nb_data_blocked_sent;
  connection.finalCounters.streamCreditBlockedEvents =
      connection.native->nb_stream_data_blocked_sent;
  for (int index = 0; index < connection.native->nb_paths; ++index)
    if (connection.native->path[index])
      connection.finalCounters.packetsLost += connection.native->path[index]->nb_losses_found;
  connection.finalLocalError = connection.native->local_error;
  connection.finalRemoteError = connection.native->remote_error;
  connection.finalRemoteApplicationError = connection.native->remote_application_error;
  connection.finalOffendingFrame = connection.native->offending_frame_type;
  if (connection.native->local_error_reason)
    connection.finalLocalErrorReason = connection.native->local_error_reason;
  byNative_.erase(connection.native);
  connection.retiredNative = connection.native;
  connection.native = nullptr;
}

void PicoquicAdapter::reapClosedConnections()
{
  std::erase_if(connections_, [this](const auto& owned) {
    Connection& connection = *owned;
    if (connection.native || !connection.closedReported)
      return false;
    counters_.packetsReceived += connection.finalCounters.packetsReceived;
    counters_.packetsSent += connection.finalCounters.packetsSent;
    counters_.packetsLost += connection.finalCounters.packetsLost;
    counters_.packetsRetransmitted += connection.finalCounters.packetsRetransmitted;
    counters_.flowControlBlockedEvents +=
        connection.finalCounters.flowControlBlockedEvents;
    counters_.streamCreditBlockedEvents +=
        connection.finalCounters.streamCreditBlockedEvents;
    if (connection.retiredNative)
    {
      picoquic_set_callback(connection.retiredNative, nullptr, nullptr);
      picoquic_delete_cnx(connection.retiredNative);
    }
    connection.retiredNative = nullptr;
    byId_.erase(connection.id);
    std::erase(acceptedConnections_, connection.id);
    return true;
  });
}

bool PicoquicAdapter::captureResumptionState(Connection& connection,
                                              AdapterError& error)
{
  if (config_.role != EndpointRole::client || !connection.native ||
      !connection.resumptionState.empty() || !connection.native->issued_ticket_id)
  {
    error = {};
    return true;
  }
  const picoquic_stored_ticket_t* ticket = picoquic_get_stored_ticket(
      engine_, config_.tlsHostname.c_str(), config_.tlsHostname.size(), alpn,
      sizeof(alpn) - 1, 0, 0, connection.native->issued_ticket_id);
  if (!ticket)
  {
    error = {};
    return true;
  }
  if (resumptionHeaderBytes + ticket->ticket_length > resumptionStateLimit)
  {
    error = {1, "picoquic connection ticket exceeds the resumption-state limit"};
    return false;
  }
  connection.resumptionState.resize(resumptionHeaderBytes + ticket->ticket_length);
  std::span<std::byte> payload(connection.resumptionState);
  storeU32(payload.data(), resumptionMagic);
  storeU32(payload.data() + 4, 1);
  storeU32(payload.data() + 8, ticket->version);
  storeU16(payload.data() + 12, ticket->ticket_length);
  const std::array<uint64_t, resumptionParameterCount> values = {
      ticket->tp_0rtt[picoquic_tp_0rtt_max_data],
      ticket->tp_0rtt[picoquic_tp_0rtt_max_stream_data_bidi_local],
      ticket->tp_0rtt[picoquic_tp_0rtt_max_stream_data_bidi_remote],
      ticket->tp_0rtt[picoquic_tp_0rtt_max_stream_data_uni],
      ticket->tp_0rtt[picoquic_tp_0rtt_max_streams_id_bidir],
      ticket->tp_0rtt[picoquic_tp_0rtt_max_streams_id_unidir]};
  size_t offset = 14;
  for (const uint64_t value : values)
  {
    storeU64(payload.data() + offset, value);
    offset += 8;
  }
  std::memcpy(payload.data() + resumptionHeaderBytes, ticket->ticket,
              ticket->ticket_length);
  error = {};
  return true;
}

bool PicoquicAdapter::discardPendingSend(
    Connection& connection, Stream& stream,
    const picoquic_stream_head_t& native) noexcept
{
  if (stream.acceptedSendBytes < native.sent_offset) return false;
  const uint64_t pending = stream.acceptedSendBytes - native.sent_offset;
  if (connection.acceptedSendBytes < pending) return false;
  connection.acceptedSendBytes -= pending;
  stream.acceptedSendBytes = native.sent_offset;
  return true;
}

int PicoquicAdapter::callback(picoquic_cnx_t* native, uint64_t streamId,
                              uint8_t* bytes, size_t length,
                              picoquic_call_back_event_t event,
                              void* context, void*)
{
  auto& self = *static_cast<PicoquicAdapter*>(context);
  Connection* connection = self.ensureConnection(native);
  switch (event)
  {
  case picoquic_callback_stream_data:
  case picoquic_callback_stream_fin:
  case picoquic_callback_stream_reset:
  case picoquic_callback_stop_sending:
  {
    connection->applicationDataObserved = true;
    Stream& stream = connection->streams[streamId];
    if (self.config_.scenario == "flow_control" &&
        picoquic_set_app_flow_control(native, streamId, 1) != 0)
      return -1;
    if (bytes && length)
    {
      const auto* first = reinterpret_cast<const std::byte*>(bytes);
      stream.received.insert(stream.received.end(), first, first + length);
    }
    if (event == picoquic_callback_stream_fin || event == picoquic_callback_stream_reset)
      stream.remoteFin = true;
    if (event == picoquic_callback_stream_fin) stream.peerFin = true;
    if (event == picoquic_callback_stream_reset)
    {
      stream.peerReset = true;
      if (const auto* nativeStream = picoquic_find_stream(native, streamId))
        stream.peerResetError = nativeStream->remote_error;
    }
    if (event == picoquic_callback_stop_sending)
    {
      stream.peerStopSending = true;
      if (const auto* nativeStream = picoquic_find_stream(native, streamId))
      {
        stream.peerStopSendingError = nativeStream->remote_stop_error;
        if (!discardPendingSend(*connection, stream, *nativeStream)) return -1;
      }
    }
    if (remoteInitiated(streamId, self.config_.role) &&
        connection->acceptedStreams.insert(streamId).second)
      (bidirectional(streamId) ? connection->acceptedBidi : connection->acceptedUni)
          .push_back(streamId);
    break;
  }
  case picoquic_callback_datagram:
  {
    const auto* first = reinterpret_cast<const std::byte*>(bytes);
    connection->datagrams.emplace_back(first, first + length);
    break;
  }
  case picoquic_callback_close:
  case picoquic_callback_stateless_reset:
    self.finishNative(*connection);
    connection->closedReported = connection->releaseWhenClosed;
    break;
  case picoquic_callback_application_close:
    connection->peerConnectionClose = true;
    connection->peerConnectionCloseError = native->remote_application_error;
    connection->peerConnectionCloseReasonLength =
        native->remote_error_reason ? std::strlen(native->remote_error_reason) : 0;
    break;
  default:
    break;
  }
  return 0;
}

bool PicoquicAdapter::configure(std::string_view canonicalConfig, AdapterError& error)
{
  AdapterError ignored;
  reset(ignored);
  const ConfigResult parsed = parseEndpointConfig(canonicalConfig);
  if (!parsed)
  {
    error = {1, parsed.error};
    return false;
  }
  if (parsed.config.congestionController != "cubic" &&
      parsed.config.congestionController != "reno" &&
      parsed.config.congestionController != "bbr")
  {
    error = {1, "picoquic cannot honor the requested congestion controller"};
    return false;
  }
  if (parsed.config.packetIo.ecn)
  {
    error = {1, "picoquic adapter cannot expose transmit ECN metadata"};
    return false;
  }
  config_ = parsed.config;
  if (config_.quicVersion != "0x00000001" || config_.tlsVersion != "TLSv1.3" ||
      config_.tlsCipherSuite != "TLS_AES_128_GCM_SHA256" ||
      config_.tlsKeyExchange != "X25519" || config_.tlsLeafSignature != "Ed25519" ||
      config_.initialCongestionWindowBytes != PICOQUIC_CWIN_INITIAL ||
      config_.tlsTicketLifetimeNs % nanosecondsPerSecond != 0 ||
      config_.tlsTicketLifetimeNs / nanosecondsPerSecond >
          std::numeric_limits<uint32_t>::max() ||
      config_.tlsMaximumEarlyDataBytes > std::numeric_limits<uint32_t>::max() ||
      !config_.tlsOneUseTickets)
  {
    error = {1, "picoquic cannot honor the requested frozen QUIC/TLS treatment"};
    return false;
  }
  configuredLeafSignatureVerified_ = configuredLeafIsEd25519(config_.certificatePath);
  if (!configuredLeafSignatureVerified_)
  {
    error = {10, "configured picoquic leaf certificate is not Ed25519"};
    return false;
  }
  if (config_.calendarUnixSeconds >
      std::numeric_limits<uint64_t>::max() / 1'000'000ULL)
  {
    error = {1, "picoquic frozen TLS calendar time overflows microseconds"};
    return false;
  }
  calendarEpochUs_ = config_.calendarUnixSeconds * 1'000'000ULL;
  simulatedTimeUs_ = calendarEpochUs_;
  if (!disableOpenSslTimedReseeding())
  {
    error = {10, "failed to disable OpenSSL wall-clock DRBG reseeding"};
    return false;
  }
  FILE* random = std::fopen("/dev/urandom", "rb");
  if (!random || std::fread(ticketEncryptionKey_.data(), 1,
                            ticketEncryptionKey_.size(), random) !=
                     ticketEncryptionKey_.size())
  {
    if (random) std::fclose(random);
    error = {10, "failed to generate picoquic ticket encryption key"};
    return false;
  }
  std::fclose(random);
  const char* certificate = config_.role == EndpointRole::server ?
      config_.certificatePath.c_str() : nullptr;
  const char* privateKey = config_.role == EndpointRole::server ?
      config_.privateKeyPath.c_str() : nullptr;
  uint64_t nativeConnectionLimit = config_.connectionCount;
  if (nativeConnectionLimit > std::numeric_limits<uint32_t>::max())
  {
    error = {1, "picoquic native connection limit overflows"};
    reset(ignored);
    return false;
  }
  if (config_.scenario == "connect" || config_.scenario == "resumed_connect" ||
      config_.scenario == "zero_rtt_reqresp")
  {
    if (config_.globalOperationSlots >
        std::numeric_limits<uint32_t>::max() - nativeConnectionLimit)
    {
      error = {1, "picoquic native lifecycle connection limit overflows"};
      reset(ignored);
      return false;
    }
    // A complete successor cohort can reach the server before closing packets
    // for the predecessor cohort have been serialized and reclaimed.
    nativeConnectionLimit += config_.globalOperationSlots;
  }
  engine_ = picoquic_create(
      static_cast<uint32_t>(nativeConnectionLimit), certificate, privateKey,
      config_.chainPath.c_str(), alpn,
      callback, this, nullptr, nullptr, nullptr, simulatedTimeUs_, &simulatedTimeUs_,
      config_.role == EndpointRole::client ? "/dev/null" : nullptr,
      ticketEncryptionKey_.data(), ticketEncryptionKey_.size());
  if (!engine_)
  {
    error = {10, "picoquic_create failed"};
    return false;
  }
  auto* tls = static_cast<ptls_context_t*>(engine_->tls_master_ctx);
  tlsKeyExchanges_ = {&ptls_openssl_x25519, nullptr};
  if (!tls || picoquic_set_cipher_suite(engine_, PICOQUIC_AES_128_GCM_SHA256) != 0)
  {
    error = {10, "picoquic cannot constrain TLS to AES-128-GCM-SHA256"};
    reset(ignored);
    return false;
  }
  tls->key_exchanges = tlsKeyExchanges_.data();
  tls->ticket_lifetime = static_cast<uint32_t>(
      config_.tlsTicketLifetimeNs / nanosecondsPerSecond);
  tls->max_early_data_size = quicEarlyDataTicketLimit;
  if (!tls->cipher_suites || !tls->cipher_suites[0] || tls->cipher_suites[1] ||
      tls->cipher_suites[0]->id != PICOQUIC_AES_128_GCM_SHA256 ||
      !tls->key_exchanges || !tls->key_exchanges[0] || tls->key_exchanges[1] ||
      tls->key_exchanges[0]->id != PTLS_GROUP_X25519 ||
      tls->ticket_lifetime != config_.tlsTicketLifetimeNs / nanosecondsPerSecond ||
      tls->max_early_data_size != quicEarlyDataTicketLimit)
  {
    error = {10, "picoquic TLS treatment readback mismatch"};
    reset(ignored);
    return false;
  }
  if (config_.tlsVerifyPeer)
  {
    auto* verifier = tls ?
        reinterpret_cast<ptls_openssl_verify_certificate_t*>(tls->verify_certificate) :
        nullptr;
    X509_VERIFY_PARAM* parameters = verifier && verifier->cert_store ?
        X509_STORE_get0_param(verifier->cert_store) : nullptr;
    if (!parameters ||
        config_.calendarUnixSeconds >
            static_cast<uint64_t>(std::numeric_limits<time_t>::max()))
    {
      error = {10, "picoquic OpenSSL verifier cannot accept frozen TLS time"};
      reset(ignored);
      return false;
    }
    X509_VERIFY_PARAM_set_time(
        parameters, static_cast<time_t>(config_.calendarUnixSeconds));
  }
  if (!config_.tlsVerifyPeer) picoquic_set_verify_certificate_callback(engine_, &noVerify, nullptr);
  picoquic_tp_t parameters = *picoquic_get_default_tp(engine_);
  parameters.initial_max_stream_data_bidi_local = config_.streamWindow;
  parameters.initial_max_stream_data_bidi_remote = config_.streamWindow;
  parameters.initial_max_stream_data_uni = config_.streamWindow;
  parameters.initial_max_data = config_.connectionWindow;
  parameters.initial_max_stream_id_bidir = config_.maxBidiStreams;
  parameters.initial_max_stream_id_unidir = config_.maxUniStreams;
  parameters.max_idle_timeout = config_.idleTimeoutMs;
  parameters.max_packet_size = config_.maxUdpPayloadSize;
  parameters.max_ack_delay = static_cast<uint32_t>(config_.maxAckDelayNs / 1'000);
  if (!config_.ackFrequency) parameters.min_ack_delay = 0;
  parameters.active_connection_id_limit =
      static_cast<uint32_t>(config_.activeConnectionIdLimit);
  parameters.ack_delay_exponent = static_cast<uint8_t>(config_.ackDelayExponent);
  parameters.max_datagram_frame_size = config_.datagramMaxFrameSize;
  parameters.migration_disabled = config_.activeMigration ? 0 : 1;
  if (!valid(picoquic_set_default_tp(engine_, &parameters),
             "picoquic_set_default_tp", error))
  {
    reset(ignored);
    return false;
  }
  const picoquic_tp_t* transportReadback = picoquic_get_default_tp(engine_);
  if (!transportReadback ||
      (transportReadback->min_ack_delay > 0) != config_.ackFrequency)
  {
    error = {10, "picoquic ACK-frequency transport treatment readback mismatch"};
    reset(ignored);
    return false;
  }
  picoquic_set_default_idle_timeout(engine_, config_.idleTimeoutMs);
  engine_->local_cnxid_length = static_cast<uint8_t>(config_.connectionIdBytes);
  picoquic_register_all_congestion_control_algorithms();
  picoquic_set_default_congestion_algorithm_by_name(
      engine_, config_.congestionController.c_str());
  if (!engine_->default_congestion_alg ||
      config_.congestionController != engine_->default_congestion_alg->congestion_algorithm_id)
  {
    error = {10, "picoquic congestion-controller readback mismatch"};
    reset(ignored);
    return false;
  }
  picoquic_set_default_pmtud_policy(
      engine_, config_.packetIo.pmtud ? picoquic_pmtud_basic : picoquic_pmtud_blocked);
  picoquic_set_mtu_max(engine_, config_.maxUdpPayloadSize);
  picoquic_set_max_data_control(engine_, config_.connectionWindow);
  picoquic_set_packet_train_mode(engine_, 0);
  unsigned char randomProbe = 0;
  if (RAND_bytes(&randomProbe, sizeof(randomProbe)) != 1 ||
      RAND_priv_bytes(&randomProbe, sizeof(randomProbe)) != 1)
  {
    error = {10, "failed to prime OpenSSL DRBGs before READY"};
    reset(ignored);
    return false;
  }
  configured_ = true;
  error = {};
  return true;
}

bool PicoquicAdapter::setLocalAddress(const sockaddr_in& local, AdapterError& error)
{
  if (!configured_ || localAddressSet_ || !connections_.empty() ||
      local.sin_family != AF_INET || local.sin_port == 0)
  {
    error = {1, "post-bind local address must be set once before connection creation"};
    return false;
  }
  in_addr expected {};
  if (inet_pton(AF_INET, config_.bindAddress.c_str(), &expected) != 1 ||
      (expected.s_addr != htonl(INADDR_ANY) && expected.s_addr != local.sin_addr.s_addr) ||
      (config_.bindPort && htons(config_.bindPort) != local.sin_port))
  {
    error = {1, "post-bind local address differs from the immutable configuration"};
    return false;
  }
  localAddress_ = local;
  localAddressSet_ = true;
  error = {};
  return true;
}

bool PicoquicAdapter::setCallerTime(uint64_t nowRawNs, AdapterError& error) noexcept
{
  if (!nowRawNs || (callerTimeSet_ && nowRawNs < lastRawNs_))
  {
    error = {1, "picoquic caller time is zero or regressed"};
    return false;
  }
  if (!callerTimeSet_)
  {
    rawEpochNs_ = nowRawNs;
    callerTimeSet_ = true;
  }
  const uint64_t elapsedUs = (nowRawNs - rawEpochNs_) / 1'000ULL;
  if (elapsedUs > std::numeric_limits<uint64_t>::max() - calendarEpochUs_)
  {
    error = {1, "picoquic caller time exceeds the virtual clock range"};
    return false;
  }
  simulatedTimeUs_ = calendarEpochUs_ + elapsedUs;
  lastRawNs_ = nowRawNs;
  error = {};
  return true;
}

bool PicoquicAdapter::receiveBatch(std::span<const ReceivedPacket> packets,
                                   uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  if (!configured_ || !localAddressSet_ || packets.size() > packetBatchSize)
  {
    error = {2, "picoquic receive requires a configured post-bind adapter and at most 64 packets"};
    return false;
  }
  const uint64_t nowUs = simulatedTimeUs_;
  for (const auto& packet : packets)
  {
    if (packet.bytes.empty() || packet.bytes.size() > config_.maxUdpPayloadSize ||
        packet.peer.sin_family != AF_INET || packet.ecn)
    {
      error = {1, "invalid borrowed picoquic receive packet"};
      return false;
    }
    picoquic_cnx_t* native = nullptr;
    const int status = picoquic_incoming_packet_ex(
        engine_, const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(packet.bytes.data())),
        packet.bytes.size(), reinterpret_cast<sockaddr*>(const_cast<sockaddr_in*>(&packet.peer)),
        reinterpret_cast<sockaddr*>(&localAddress_), 0, 0, &native, nowUs);
    if (!valid(status, "picoquic_incoming_packet", error)) return false;
    if (native)
    {
      const auto found = byNative_.find(native);
      if (found != byNative_.end() &&
          !captureResumptionState(*found->second, error))
        return false;
    }
  }
  reapClosedConnections();
  updateTimeout(nowRawNs);
  error = {};
  return true;
}

size_t PicoquicAdapter::pollTransmitBatch(std::span<TransmitPacket> packets,
                                          uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return 0;
  if (!configured_)
  {
    error = {2, "picoquic adapter is not configured"};
    return 0;
  }
  const uint64_t nowUs = simulatedTimeUs_;
  const size_t capacity = std::min({packets.size(), output_.size(), packetBatchSize});
  size_t count = 0;
  std::vector<Connection*> serializedCloses;
  for (; count < capacity; ++count)
  {
    size_t length = 0;
    sockaddr_storage peer {};
    sockaddr_storage local {};
    int interfaceIndex = 0;
    picoquic_cnx_t* preparedConnection = nullptr;
    const int status = picoquic_prepare_next_packet_ex(
        engine_, nowUs, reinterpret_cast<uint8_t*>(output_[count].data()),
        std::min<size_t>(output_[count].size(), config_.maxUdpPayloadSize), &length,
        &peer, &local, &interfaceIndex, nullptr, &preparedConnection, nullptr);
    if (!valid(status, "picoquic_prepare_next_packet_ex", error)) return count;
    if (!length) break;
    if (peer.ss_family != AF_INET)
    {
      error = {1, "picoquic returned a non-IPv4 transmit path"};
      return count;
    }
    packets[count].bytes = std::span<const std::byte>(output_[count]).first(length);
    std::memcpy(&packets[count].peer, &peer, sizeof(sockaddr_in));
    packets[count].ecn = 0;
    packets[count].gsoSegmentSize = 0;
    packets[count].desiredSendRawNs = nowRawNs;
    if (preparedConnection &&
        picoquic_get_cnx_state(preparedConnection) == picoquic_state_closing)
    {
      const auto found = byNative_.find(preparedConnection);
      if (found != byNative_.end() && found->second->localCloseRequested &&
          std::ranges::find(serializedCloses, found->second) == serializedCloses.end())
        serializedCloses.push_back(found->second);
    }
  }
  for (Connection* connection : serializedCloses)
  {
    connection->closedReported = true;
    finishNative(*connection);
  }
  reapClosedConnections();
  updateTimeout(nowRawNs);
  error = {};
  return count;
}

void PicoquicAdapter::updateTimeout(uint64_t nowRawNs) noexcept
{
  if (!engine_ || !callerTimeSet_) { nextTimeoutRawNs_ = 0; return; }
  const uint64_t wakeUs = picoquic_get_next_wake_time(engine_, simulatedTimeUs_);
  if (wakeUs <= simulatedTimeUs_)
  {
    nextTimeoutRawNs_ = nowRawNs;
    return;
  }
  const uint64_t delayUs = wakeUs - simulatedTimeUs_;
  nextTimeoutRawNs_ = delayUs >
          (std::numeric_limits<uint64_t>::max() - nowRawNs) / 1'000ULL ?
      std::numeric_limits<uint64_t>::max() : nowRawNs + delayUs * 1'000ULL;
}

bool PicoquicAdapter::onTimeout(uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  if (!configured_)
  {
    error = {2, "picoquic adapter is not configured"};
    return false;
  }
  ++counters_.timerExpirations;
  updateTimeout(nowRawNs);
  error = {};
  return true;
}

bool PicoquicAdapter::connect(const sockaddr_in& peer, uint64_t nowRawNs,
                              uint64_t& connectionId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  reapClosedConnections();
  const size_t activeConnections = std::ranges::count_if(
      connections_, [](const auto& connection) { return connection->native != nullptr; });
  if (!configured_ || !localAddressSet_ || config_.role != EndpointRole::client ||
      peer.sin_family != AF_INET || activeConnections >= config_.connectionCount)
  {
    error = {2, "picoquic connect requires a configured client, valid peer, and free slot"};
    return false;
  }
  in_addr expected {};
  if (inet_pton(AF_INET, config_.peerAddress.c_str(), &expected) != 1 ||
      expected.s_addr != peer.sin_addr.s_addr || ntohs(peer.sin_port) != config_.peerPort)
  {
    error = {1, "connect peer differs from the immutable endpoint configuration"};
    return false;
  }
  if (importedState_)
  {
    if (importedState_->size() < resumptionHeaderBytes ||
        loadU32(importedState_->data()) != resumptionMagic ||
        loadU32(importedState_->data() + 4) != 1)
    {
      error = {1, "malformed picoquic resumption state"};
      return false;
    }
    const uint32_t ticketVersion = loadU32(importedState_->data() + 8);
    const uint16_t ticketLength = loadU16(importedState_->data() + 12);
    if (ticketLength != importedState_->size() - resumptionHeaderBytes)
    {
      error = {1, "malformed picoquic resumption ticket length"};
      return false;
    }
    picoquic_tp_t parameters {};
    size_t offset = 14;
    parameters.initial_max_data = loadU64(importedState_->data() + offset); offset += 8;
    parameters.initial_max_stream_data_bidi_local = loadU64(importedState_->data() + offset); offset += 8;
    parameters.initial_max_stream_data_bidi_remote = loadU64(importedState_->data() + offset); offset += 8;
    parameters.initial_max_stream_data_uni = loadU64(importedState_->data() + offset); offset += 8;
    parameters.initial_max_stream_id_bidir = loadU64(importedState_->data() + offset); offset += 8;
    parameters.initial_max_stream_id_unidir = loadU64(importedState_->data() + offset);
    if (!valid(picoquic_store_ticket(
                   engine_, config_.tlsHostname.c_str(), config_.tlsHostname.size(), alpn,
                   sizeof(alpn) - 1, ticketVersion, nullptr, 0, nullptr, 0,
                   reinterpret_cast<uint8_t*>(importedState_->data() + resumptionHeaderBytes),
                   ticketLength, &parameters),
               "picoquic_store_ticket", error))
      return false;
    consumedTickets_.emplace(
        reinterpret_cast<const char*>(importedState_->data()), importedState_->size());
  }
  picoquic_cnx_t* native = picoquic_create_cnx(
      engine_, picoquic_null_connection_id, picoquic_null_connection_id,
      reinterpret_cast<const sockaddr*>(&peer), simulatedTimeUs_, 0,
      config_.tlsHostname.c_str(), alpn, true);
  if (!native)
  {
    error = {10, "picoquic_create_cnx failed"};
    return false;
  }
  if (!valid(picoquic_set_local_addr(native, reinterpret_cast<sockaddr*>(&localAddress_)),
             "picoquic_set_local_addr", error) ||
      !valid(picoquic_start_client_cnx(native), "picoquic_start_client_cnx", error))
  {
    picoquic_delete_cnx(native);
    return false;
  }
  Connection* connection = ensureConnection(native);
  connection->zeroRttAttempted = importedState_.has_value() && importedZeroRtt_ &&
      picoquic_is_0rtt_available(native) != 0;
  importedState_.reset();
  importedZeroRtt_ = false;
  connectionId = connection->id;
  updateTimeout(nowRawNs);
  error = {};
  return true;
}

PrimitiveStatus PicoquicAdapter::acceptConnection(uint64_t nowRawNs, uint64_t& connectionId,
                                                   AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  if (!configured_ || config_.role != EndpointRole::server)
  {
    error = {2, "picoquic accept requires a configured server"};
    return PrimitiveStatus::fatal;
  }
  if (acceptedConnections_.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  connectionId = acceptedConnections_.front();
  acceptedConnections_.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

bool PicoquicAdapter::isConnected(uint64_t id, uint64_t nowRawNs, bool& connected,
                                   AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  const auto found = byId_.find(id);
  if (found == byId_.end())
  {
    error = {2, "unknown picoquic connection " + std::to_string(id)};
    return false;
  }
  Connection* connection = found->second;
  if (!connection->native)
  {
    connected = connection->connectedReported || connection->applicationDataObserved ||
        connection->localCloseRequested || connection->peerConnectionClose ||
        connection->peerCloseConsumed;
    if (!connected)
    {
      error = {2, "picoquic connection closed before becoming connected: local=" +
                      std::to_string(connection->finalLocalError) + ",remote=" +
                      std::to_string(connection->finalRemoteError) + ",reason=" +
                      connection->finalLocalErrorReason};
      return false;
    }
    connection->connectedReported = true;
    error = {};
    return true;
  }
  connected = postHandshakeReady(connection->native) || connection->applicationDataObserved ||
      connection->localCloseRequested;
  connection->connectedReported = connection->connectedReported || connected;
  error = {};
  return true;
}

bool PicoquicAdapter::connectionIsClosed(uint64_t id, uint64_t nowRawNs, bool& closed,
                                         AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  const auto found = byId_.find(id);
  if (found == byId_.end())
  {
    error = {2, "unknown picoquic connection " + std::to_string(id)};
    return false;
  }
  Connection& connection = *found->second;
  if (!connection.native && !connection.localCloseRequested &&
      !connection.peerConnectionClose && !connection.peerCloseConsumed)
  {
    error = {
        2,
        "picoquic connection closed without peer application close: local=" +
            std::to_string(connection.finalLocalError) + ",remote=" +
            std::to_string(connection.finalRemoteError) + ",remote_application=" +
            std::to_string(connection.finalRemoteApplicationError) + ",packets_sent=" +
            std::to_string(connection.finalCounters.packetsSent) + ",packets_received=" +
            std::to_string(connection.finalCounters.packetsReceived) + ",packets_lost=" +
            std::to_string(connection.finalCounters.packetsLost) + ",offending_frame=" +
            std::to_string(connection.finalOffendingFrame) + ",reason=" +
            connection.finalLocalErrorReason};
    return false;
  }
  closed = connection.native == nullptr || connection.peerConnectionClose ||
      connection.peerCloseConsumed;
  connection.closedReported = connection.closedReported || closed;
  error = {};
  return true;
}

bool PicoquicAdapter::releaseConnectionWhenClosed(uint64_t id, uint64_t nowRawNs,
                                                  AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  const auto found = byId_.find(id);
  if (found == byId_.end())
  {
    error = {2, "unknown picoquic connection " + std::to_string(id) +
                    " for closed release"};
    return false;
  }
  Connection& connection = *found->second;
  connection.releaseWhenClosed = true;
  if (!connection.native || connection.peerConnectionClose || connection.peerCloseConsumed)
  {
    connection.closedReported = true;
    finishNative(connection);
    reapClosedConnections();
  }
  error = {};
  return true;
}

PrimitiveStatus PicoquicAdapter::openStream(Connection& connection, bool bidi,
                                             uint64_t& streamId, AdapterError& error)
{
  const uint64_t candidate = bidi ? connection.nextBidi : connection.nextUni;
  const uint64_t limit = bidi ? connection.native->max_stream_id_bidir_remote :
                                connection.native->max_stream_id_unidir_remote;
  if (candidate > limit)
  {
    ++counters_.streamCreditBlockedEvents;
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  if (!valid(picoquic_add_to_stream(connection.native, candidate, nullptr, 0, 0),
             "picoquic stream creation", error))
    return PrimitiveStatus::fatal;
  streamId = candidate;
  (bidi ? connection.nextBidi : connection.nextUni) += 4;
  connection.streams.try_emplace(streamId);
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus PicoquicAdapter::acceptStream(Connection& connection, bool bidi,
                                               uint64_t& streamId, AdapterError& error)
{
  auto& pending = bidi ? connection.acceptedBidi : connection.acceptedUni;
  if (pending.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  streamId = pending.front();
  pending.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus PicoquicAdapter::openBidirectionalStream(
    uint64_t id, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  Connection* c = find(id, error);
  return c ? openStream(*c, true, streamId, error) : PrimitiveStatus::fatal;
}
PrimitiveStatus PicoquicAdapter::acceptBidirectionalStream(
    uint64_t id, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  Connection* c = find(id, error);
  return c ? acceptStream(*c, true, streamId, error) : PrimitiveStatus::fatal;
}
PrimitiveStatus PicoquicAdapter::openUnidirectionalStream(
    uint64_t id, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  Connection* c = find(id, error);
  return c ? openStream(*c, false, streamId, error) : PrimitiveStatus::fatal;
}
PrimitiveStatus PicoquicAdapter::acceptUnidirectionalStream(
    uint64_t id, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  Connection* c = find(id, error);
  return c ? acceptStream(*c, false, streamId, error) : PrimitiveStatus::fatal;
}

bool PicoquicAdapter::writeStream(uint64_t id, uint64_t streamId,
                                  std::span<const std::byte> bytes, uint64_t nowRawNs,
                                  size_t& written, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  written = 0;
  Connection* connection = find(id, error);
  if (!connection || !connection->streams.contains(streamId))
  {
    if (connection) error = {1, "write targets an unknown picoquic stream"};
    return false;
  }
  Stream& stream = connection->streams.at(streamId);
  const picoquic_stream_head_t* nativeStream =
      picoquic_find_stream(connection->native, streamId);
  if (!nativeStream)
  {
    error = {1, "picoquic write stream disappeared before admission"};
    return false;
  }
  const uint64_t serialized = nativeStream->sent_offset;
  const uint64_t pending = stream.acceptedSendBytes > serialized ?
      stream.acceptedSendBytes - serialized : 0;
  if (stream.acceptedSendBytes > nativeStream->maxdata_remote ||
      connection->acceptedSendBytes > connection->native->maxdata_remote)
  {
    error = {1, "picoquic accepted stream bytes exceed peer flow-control credit"};
    return false;
  }
  const uint64_t queueLimit = std::max<uint64_t>(
      {config_.bulkChunkBytes, config_.requestBodyBytes,
       config_.responseBodyBytes, config_.operationBodyBytes,
       config_.maxUdpPayloadSize});
  const uint64_t available = std::min({
      pending < queueLimit ? queueLimit - pending : 0,
      nativeStream->maxdata_remote - stream.acceptedSendBytes,
      connection->native->maxdata_remote - connection->acceptedSendBytes});
  written = static_cast<size_t>(std::min<uint64_t>(bytes.size(), available));
  if (!written)
  {
    error = {};
    return true;
  }
  if (stream.acceptedSendBytes > std::numeric_limits<uint64_t>::max() - written ||
      connection->acceptedSendBytes >
          std::numeric_limits<uint64_t>::max() - written)
  {
    error = {1, "picoquic accepted stream offset overflow"};
    written = 0;
    return false;
  }
  if (!valid(picoquic_add_to_stream(
                 connection->native, streamId,
                 reinterpret_cast<const uint8_t*>(bytes.data()), written, 0),
             "picoquic_add_to_stream", error))
  {
    written = 0;
    return false;
  }
  stream.acceptedSendBytes += written;
  connection->acceptedSendBytes += written;
  error = {};
  return true;
}

bool PicoquicAdapter::consumeStreamData(uint64_t id, uint64_t streamId,
                                        std::span<std::byte> bytes, uint64_t nowRawNs,
                                        size_t& read, bool& finished, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  read = 0;
  finished = false;
  const auto connectionEntry = byId_.find(id);
  if (connectionEntry == byId_.end())
  {
    error = {2, "unknown picoquic connection " + std::to_string(id)};
    return false;
  }
  Connection* connection = connectionEntry->second;
  const auto found = connection->streams.find(streamId);
  if (found == connection->streams.end())
  {
    error = {1, "read targets an unknown picoquic stream"};
    return false;
  }
  Stream& stream = found->second;
  read = std::min(bytes.size(), stream.received.size() - stream.receivedOffset);
  if (read)
  {
    std::copy_n(stream.received.begin() + stream.receivedOffset, read, bytes.begin());
    stream.receivedOffset += read;
    if (stream.receivedOffset == stream.received.size())
    {
      stream.received.clear();
      stream.receivedOffset = 0;
    }
    if (config_.scenario == "flow_control" &&
        connection->native->cnx_state != picoquic_state_ready)
    {
      error = {1, "picoquic flow-control reopen attempted outside ready state: " +
                      std::to_string(connection->native->cnx_state)};
      return false;
    }
    if (config_.scenario == "flow_control")
    {
      if (stream.consumedCreditsPending >
          std::numeric_limits<uint64_t>::max() - read)
      {
        error = {1, "picoquic pending flow-control credit overflow"};
        return false;
      }
      stream.consumedCreditsPending += read;
      const uint64_t creditQuantum = config_.streamWindow / 4;
      if (stream.consumedCreditsPending >= creditQuantum)
      {
        auto* nativeStream = picoquic_find_stream(connection->native, streamId);
        if (!nativeStream || nativeStream->maxdata_local < nativeStream->consumed_offset)
        {
          error = {1, "picoquic stream credit state is inconsistent"};
          return false;
        }
        const uint64_t grant = stream.consumedCreditsPending -
            stream.consumedCreditsPending % creditQuantum;
        const uint64_t available = nativeStream->maxdata_local -
            nativeStream->consumed_offset;
        if (available > std::numeric_limits<uint64_t>::max() - grant)
        {
          error = {1, "picoquic stream credit target overflow"};
          return false;
        }
        if (!valid(picoquic_open_flow_control(
                       connection->native, streamId, available + grant),
                   "picoquic_open_flow_control", error))
          return false;
        stream.consumedCreditsPending -= grant;
      }
    }
  }
  finished = stream.remoteFin && stream.receivedOffset == stream.received.size();
  error = {};
  return true;
}

bool PicoquicAdapter::finishStream(uint64_t id, uint64_t streamId, uint64_t nowRawNs,
                                   AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* connection = find(id, error);
  if (!connection || !connection->streams.contains(streamId))
  {
    if (connection) error = {1, "finish targets an unknown picoquic stream"};
    return false;
  }
  return valid(picoquic_add_to_stream(connection->native, streamId, nullptr, 0, 1),
               "picoquic stream FIN", error);
}

bool PicoquicAdapter::resetStream(uint64_t id, uint64_t streamId, uint64_t appError,
                                  uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* connection = find(id, error);
  if (!connection || !connection->streams.contains(streamId)) return false;
  const picoquic_stream_head_t* native =
      picoquic_find_stream(connection->native, streamId);
  if (!native)
  {
    error = {1, "picoquic reset stream disappeared before reset"};
    return false;
  }
  if (!valid(picoquic_reset_stream(connection->native, streamId, appError),
             "picoquic_reset_stream", error))
    return false;
  if (!discardPendingSend(
          *connection, connection->streams.at(streamId), *native))
  {
    error = {1, "picoquic reset stream send accounting is inconsistent"};
    return false;
  }
  error = {};
  return true;
}
bool PicoquicAdapter::stopSending(uint64_t id, uint64_t streamId, uint64_t appError,
                                  uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  return c && valid(picoquic_stop_sending(c->native, streamId, appError),
                    "picoquic_stop_sending", error);
}

PrimitiveStatus PicoquicAdapter::sendDatagram(uint64_t id,
                                              std::span<const std::byte> bytes,
                                              uint64_t nowRawNs,
                                              AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  Connection* c = find(id, error);
  if (!c) return PrimitiveStatus::fatal;
  if (!postHandshakeReady(c->native))
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  if (!valid(picoquic_queue_datagram_frame(
                 c->native, bytes.size(), reinterpret_cast<const uint8_t*>(bytes.data())),
             "picoquic_queue_datagram_frame", error))
    return PrimitiveStatus::fatal;
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus PicoquicAdapter::consumeDatagram(uint64_t id,
                                                 std::span<std::byte> bytes,
                                                 uint64_t nowRawNs,
                                                 size_t& read, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  read = 0;
  Connection* c = find(id, error);
  if (!c) return PrimitiveStatus::fatal;
  if (c->datagrams.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  if (c->datagrams.front().size() > bytes.size())
  {
    error = {1, "borrowed picoquic DATAGRAM receive buffer is too small"};
    return PrimitiveStatus::fatal;
  }
  read = c->datagrams.front().size();
  std::copy(c->datagrams.front().begin(), c->datagrams.front().end(), bytes.begin());
  c->datagrams.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus PicoquicAdapter::exportResumptionState(
    uint64_t id, uint64_t nowRawNs, std::span<std::byte> bytes, size_t& written,
    AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  written = 0;
  Connection* c = find(id, error);
  if (!c) return PrimitiveStatus::fatal;
  if (c->resumptionState.empty())
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  if (resumptionEnvelopeBytes + c->resumptionState.size() > bytes.size())
  {
    error = {1, "borrowed picoquic resumption output buffer is too small"};
    return PrimitiveStatus::fatal;
  }
  return sealResumptionState(c->resumptionState, nowRawNs,
                             bytes, written, error) ?
      PrimitiveStatus::ready : PrimitiveStatus::fatal;
}

PrimitiveStatus PicoquicAdapter::importResumptionState(
    std::span<const std::byte> bytes, bool zeroRtt, uint64_t nowRawNs,
    AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  std::span<const std::byte> payload;
  if (openResumptionState(bytes, nowRawNs, config_.tlsTicketLifetimeNs,
                          payload, error) != PrimitiveStatus::ready)
    return PrimitiveStatus::fatal;
  const std::string identity(
      reinterpret_cast<const char*>(payload.data()), payload.size());
  if (!configured_ || config_.role != EndpointRole::client || importedState_ ||
      consumedTickets_.contains(identity) || payload.size() < resumptionHeaderBytes)
  {
    error = {1, "invalid or overlapping picoquic resumption import"};
    return PrimitiveStatus::fatal;
  }
  importedState_.emplace(payload.begin(), payload.end());
  importedZeroRtt_ = zeroRtt;
  error = {};
  return PrimitiveStatus::ready;
}

bool PicoquicAdapter::connectionResumed(uint64_t id, uint64_t nowRawNs, bool& resumed,
                                        AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  if (!c) return false;
  resumed = picoquic_tls_is_psk_handshake(c->native) != 0;
  error = {};
  return true;
}
bool PicoquicAdapter::zeroRttAttempted(uint64_t id, uint64_t nowRawNs, bool& attempted,
                                       AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  if (!c) return false;
  attempted = c->zeroRttAttempted;
  error = {};
  return true;
}
bool PicoquicAdapter::zeroRttAccepted(uint64_t id, uint64_t nowRawNs, bool& accepted,
                                      AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  if (!c) return false;
  accepted = c->zeroRttAttempted && c->native->zero_rtt_data_accepted != 0;
  error = {};
  return true;
}
bool PicoquicAdapter::zeroRttRejected(uint64_t id, uint64_t nowRawNs, bool& rejected,
                                      AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  if (!c) return false;
  const auto state = picoquic_get_cnx_state(c->native);
  rejected = c->zeroRttAttempted && state >= picoquic_state_client_ready_start &&
      c->native->zero_rtt_data_accepted == 0;
  error = {};
  return true;
}

bool PicoquicAdapter::closeConnection(uint64_t id, uint64_t appError, uint64_t nowRawNs,
                                      AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  if (!c) return false;
  if (c->localCloseRequested)
  {
    error = {1, "duplicate picoquic connection close request"};
    return false;
  }
  c->localCloseRequested = true;
  if (!valid(picoquic_close(c->native, appError), "picoquic_close", error))
  {
    c->localCloseRequested = false;
    return false;
  }
  return true;
}

bool PicoquicAdapter::peerTerminalFacts(uint64_t id, uint64_t streamId,
                                        uint64_t nowRawNs,
                                        PeerTerminalFacts& facts, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  facts = {};
  const auto found = byId_.find(id);
  if (found == byId_.end())
  {
    error = {2, "unknown picoquic connection for peer terminal facts"};
    return false;
  }
  Connection& connection = *found->second;
  facts.available = true;
  facts.connectionClose = connection.peerConnectionClose;
  facts.connectionCloseError = connection.peerConnectionCloseError;
  facts.connectionCloseReasonLength = connection.peerConnectionCloseReasonLength;
  if (const auto stream = connection.streams.find(streamId);
      stream != connection.streams.end())
  {
    facts.fin = stream->second.peerFin;
    facts.resetStream = stream->second.peerReset;
    facts.stopSending = stream->second.peerStopSending;
    facts.resetStreamError = stream->second.peerResetError;
    facts.stopSendingError = stream->second.peerStopSendingError;
  }
  if (facts.connectionClose)
  {
    connection.peerConnectionClose = false;
    connection.peerCloseConsumed = true;
    connection.closedReported = true;
    finishNative(connection);
  }
  error = {};
  return true;
}

TransportCounters PicoquicAdapter::snapshotTransportCounters() const noexcept
{
  TransportCounters result = counters_;
  for (const auto& connection : connections_)
  {
    if (!connection->native)
    {
      result.packetsReceived += connection->finalCounters.packetsReceived;
      result.packetsSent += connection->finalCounters.packetsSent;
      result.packetsLost += connection->finalCounters.packetsLost;
      result.packetsRetransmitted += connection->finalCounters.packetsRetransmitted;
      continue;
    }
    result.packetsReceived += connection->native->nb_packets_received;
    result.packetsSent += connection->native->nb_packets_sent;
    result.packetsRetransmitted += connection->native->nb_retransmission_total;
    result.flowControlBlockedEvents += connection->native->nb_data_blocked_sent;
    result.streamCreditBlockedEvents += connection->native->nb_stream_data_blocked_sent;
    for (int index = 0; index < connection->native->nb_paths; ++index)
      if (connection->native->path[index])
        result.packetsLost += connection->native->path[index]->nb_losses_found;
  }
  return result;
}

NegotiatedSettings PicoquicAdapter::snapshotNegotiatedSettings() const noexcept
{
  NegotiatedSettings result;
  result.evidenceSource =
      "picoquic_remote_transport_parameters+picotls_singleton_post_handshake_policy+"
      "picoquic_applied_settings+qpf2_lifecycle_policy";
  const auto unavailable = [&result](std::string field) {
    if (std::ranges::find(result.unavailableFields, field) ==
        result.unavailableFields.end())
      result.unavailableFields.push_back(std::move(field));
  };
  if (!engine_ || connections_.empty())
  {
    unavailable("no_post_handshake_connection");
    return result;
  }
  const auto* tls = static_cast<const ptls_context_t*>(engine_->tls_master_ctx);
  if (!tls || !tls->cipher_suites || !tls->cipher_suites[0] ||
      tls->cipher_suites[1] ||
      tls->cipher_suites[0]->id != PICOQUIC_AES_128_GCM_SHA256 ||
      !tls->key_exchanges || !tls->key_exchanges[0] || tls->key_exchanges[1] ||
      tls->key_exchanges[0]->id != PTLS_GROUP_X25519)
  {
    unavailable("tls_singleton_policy_readback");
    return result;
  }

  const auto activeForEvidence = [](const Connection& connection) {
    // A locally requested close remains safe to inspect until picoquic has
    // serialized it and retired the native object. Keeping that generation
    // as evidence bridges cleanup turnover while incomplete successors are
    // intentionally ignored.
    return !connection.peerConnectionClose && !connection.peerCloseConsumed &&
        !connection.closedReported && connection.native &&
        postHandshakeReady(connection.native) &&
        connection.native->remote_parameters_received;
  };
  const auto firstActive = std::ranges::find_if(
      connections_, [&](const auto& connection) {
        return activeForEvidence(*connection);
      });
  if (firstActive == connections_.end())
  {
    unavailable("no_active_post_handshake_connection");
    return result;
  }
  const Connection& first = **firstActive;
  const picoquic_tp_t& remote = first.native->remote_parameters;
  const picoquic_connection_id_t remoteId = picoquic_get_remote_cnxid(first.native);
  const char* negotiatedAlpn = picoquic_tls_get_negotiated_alpn(first.native);
  const char* negotiatedSni = picoquic_tls_get_sni(first.native);
  if (!negotiatedAlpn || !negotiatedSni)
  {
    unavailable("tls_identity");
    return result;
  }

  result.available = true;
  result.quicVersion = picoquic_supported_versions[first.native->version_index].version;
  result.alpn = negotiatedAlpn;
  result.tlsVersion = "TLSv1.3";
  result.tlsCipherSuite = "TLS_AES_128_GCM_SHA256";
  result.tlsKeyExchange = "X25519";
  result.tlsLeafSignature = configuredLeafSignatureVerified_ ? "Ed25519" : "";
  result.peerCertificateVerified = config_.role == EndpointRole::client &&
      config_.tlsVerifyPeer && engine_->is_cert_store_not_empty;
  result.hostnameVerified = result.peerCertificateVerified &&
      std::string_view(negotiatedSni) == config_.tlsHostname;
  result.congestionController = first.native->congestion_alg ?
      first.native->congestion_alg->congestion_algorithm_id : "";
  result.initialCongestionWindowBytes = PICOQUIC_CWIN_INITIAL;
  result.maxUdpPayloadSize = remote.max_packet_size;
  result.maxAckDelayNs = static_cast<uint64_t>(remote.max_ack_delay) * 1'000ULL;
  result.ackDelayExponent = remote.ack_delay_exponent;
  result.ackFrequency = remote.min_ack_delay > 0;
  result.activeMigration = remote.migration_disabled == 0;
  result.activeConnectionIdLimit = remote.active_connection_id_limit;
  result.connectionIdBytes = remoteId.id_len;
  result.maxIdleTimeoutNs = remote.max_idle_timeout * 1'000'000ULL;
  result.maxBidiStreams = remote.initial_max_stream_id_bidir;
  result.maxUniStreams = remote.initial_max_stream_id_unidir;
  result.streamCreditReplenishBelow = config_.streamCreditReplenishBelow;
  result.connectionWindowBytes = remote.initial_max_data;
  result.streamWindowBytes = std::min(
      {remote.initial_max_stream_data_bidi_local,
       remote.initial_max_stream_data_bidi_remote,
       remote.initial_max_stream_data_uni});
  result.datagramMaxFrameSize = remote.max_datagram_frame_size;
  result.ticketLifetimeNs =
      static_cast<uint64_t>(tls->ticket_lifetime) * nanosecondsPerSecond;
  result.maximumEarlyDataBytes = config_.tlsMaximumEarlyDataBytes;
  result.oneUseTickets = config_.tlsOneUseTickets;

  if (!configuredLeafSignatureVerified_) unavailable("tls_leaf_signature");
  if (std::string_view(negotiatedSni) != config_.tlsHostname) unavailable("tls_hostname");
  if (!first.native->congestion_alg) unavailable("congestion_controller");

  for (const auto& owned : connections_)
  {
    const Connection& connection = *owned;
    if (&connection == &first || !activeForEvidence(connection)) continue;
    if (picoquic_supported_versions[connection.native->version_index].version !=
            result.quicVersion ||
        !connection.native->congestion_alg ||
        std::string_view(connection.native->congestion_alg->congestion_algorithm_id) !=
            result.congestionController)
    {
      unavailable("per_connection_evidence_mismatch");
      break;
    }
    const picoquic_tp_t& peer = connection.native->remote_parameters;
    const picoquic_connection_id_t peerId = picoquic_get_remote_cnxid(connection.native);
    const char* peerAlpn = picoquic_tls_get_negotiated_alpn(connection.native);
    const char* peerSni = picoquic_tls_get_sni(connection.native);
    if (!peerAlpn || std::string_view(peerAlpn) != result.alpn || !peerSni ||
        std::string_view(peerSni) != config_.tlsHostname ||
        peer.max_packet_size != result.maxUdpPayloadSize ||
        static_cast<uint64_t>(peer.max_ack_delay) * 1'000ULL != result.maxAckDelayNs ||
        peer.ack_delay_exponent != result.ackDelayExponent ||
        (peer.min_ack_delay > 0) != result.ackFrequency ||
        (peer.migration_disabled == 0) != result.activeMigration ||
        peer.active_connection_id_limit != result.activeConnectionIdLimit ||
        peerId.id_len != result.connectionIdBytes ||
        peer.max_idle_timeout * 1'000'000ULL != result.maxIdleTimeoutNs ||
        peer.initial_max_stream_id_bidir != result.maxBidiStreams ||
        peer.initial_max_stream_id_unidir != result.maxUniStreams ||
        peer.initial_max_data != result.connectionWindowBytes ||
        std::min({peer.initial_max_stream_data_bidi_local,
                  peer.initial_max_stream_data_bidi_remote,
                  peer.initial_max_stream_data_uni}) != result.streamWindowBytes ||
        peer.max_datagram_frame_size != result.datagramMaxFrameSize)
    {
      unavailable("per_connection_evidence_mismatch");
      break;
    }
  }
  return result;
}

bool PicoquicAdapter::reset(AdapterError& error)
{
  if (engine_) { picoquic_free(engine_); engine_ = nullptr; }
  byId_.clear();
  byNative_.clear();
  connections_.clear();
  acceptedConnections_.clear();
  importedState_.reset();
  consumedTickets_.clear();
  config_ = {};
  localAddress_ = {};
  importedZeroRtt_ = false;
  nextConnectionId_ = 1;
  nextTimeoutRawNs_ = 0;
  calendarEpochUs_ = 0;
  simulatedTimeUs_ = 0;
  rawEpochNs_ = 0;
  lastRawNs_ = 0;
  callerTimeSet_ = false;
  configured_ = false;
  localAddressSet_ = false;
  configuredLeafSignatureVerified_ = false;
  tlsKeyExchanges_.fill(nullptr);
  ticketEncryptionKey_.fill(0);
  counters_ = {};
  error = {};
  return true;
}

} // namespace

std::unique_ptr<Adapter> makeTransportAdapter()
{
  return std::make_unique<PicoquicAdapter>();
}

} // namespace quicperf
