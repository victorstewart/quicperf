#include "adapter_factory.h"
#include "resumption_envelope.h"
#include "core/strict_config.h"

#include <tquic.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <arpa/inet.h>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace quicperf {
namespace {

constexpr int tquicDone = -100;
constexpr int tquicStreamLimit = -4;
constexpr uint64_t applicationBufferBytes = 256 * 1024;
constexpr uint64_t controlStreamReserveBytes = 4 * 1024;
constexpr char alpn[] = "qperf/2";
constexpr std::array<uint16_t, 1> signatureAlgorithms = {SSL_SIGN_ED25519};
std::atomic<uint64_t> frozenTlsUnixSeconds {0};
thread_local bool callerClockPrimed = false;

void frozenTlsTime(const SSL*, timeval* clock)
{
  clock->tv_sec = static_cast<time_t>(
      frozenTlsUnixSeconds.load(std::memory_order_relaxed));
  clock->tv_usec = 0;
}

bool remoteInitiated(uint64_t streamId, EndpointRole role) noexcept
{
  const bool initiatedByServer = (streamId & 1U) != 0;
  return initiatedByServer == (role == EndpointRole::client);
}

bool bidirectional(uint64_t streamId) noexcept { return (streamId & 2U) == 0; }

void appendU64(std::vector<std::byte>& output, uint64_t value)
{
  for (int shift = 56; shift >= 0; shift -= 8)
    output.push_back(static_cast<std::byte>((value >> shift) & 0xff));
}

class TquicAdapter final : public Adapter {
public:
  TquicAdapter();
  ~TquicAdapter() override;

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
  PrimitiveStatus acceptConnection(uint64_t nowRawNs, uint64_t& connectionId,
                                   AdapterError& error) override;
  bool isConnected(uint64_t connectionId, uint64_t nowRawNs, bool& connected,
                   AdapterError& error) override;
  bool connectionIsClosed(uint64_t connectionId, uint64_t nowRawNs, bool& closed,
                          AdapterError& error) override;
  bool releaseConnectionWhenClosed(uint64_t connectionId, uint64_t nowRawNs,
                                   AdapterError& error) override;
  bool peerTerminalFacts(uint64_t connectionId, uint64_t streamId, uint64_t nowRawNs,
                         PeerTerminalFacts& facts, AdapterError& error) override;
  PrimitiveStatus openBidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                          uint64_t& streamId, AdapterError& error) override;
  PrimitiveStatus acceptBidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                            uint64_t& streamId, AdapterError& error) override;
  PrimitiveStatus openUnidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                           uint64_t& streamId, AdapterError& error) override;
  PrimitiveStatus acceptUnidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                             uint64_t& streamId, AdapterError& error) override;
  bool writeStream(uint64_t connectionId, uint64_t streamId,
                   std::span<const std::byte> bytes, uint64_t nowRawNs, size_t& written,
                   AdapterError& error) override;
  bool consumeStreamData(uint64_t connectionId, uint64_t streamId,
                         std::span<std::byte> bytes, uint64_t nowRawNs, size_t& read,
                         bool& finished, AdapterError& error) override;
  bool finishStream(uint64_t connectionId, uint64_t streamId, uint64_t nowRawNs,
                    AdapterError& error) override;
  bool resetStream(uint64_t connectionId, uint64_t streamId, uint64_t applicationError,
                   uint64_t nowRawNs, AdapterError& error) override;
  bool stopSending(uint64_t connectionId, uint64_t streamId, uint64_t applicationError,
                   uint64_t nowRawNs, AdapterError& error) override;
  PrimitiveStatus sendDatagram(uint64_t connectionId, std::span<const std::byte> bytes,
                               uint64_t nowRawNs, AdapterError& error) override;
  PrimitiveStatus consumeDatagram(uint64_t connectionId, std::span<std::byte> bytes,
                                  uint64_t nowRawNs, size_t& read, AdapterError& error) override;
  PrimitiveStatus exportResumptionState(uint64_t connectionId, uint64_t nowRawNs,
                                        std::span<std::byte> bytes, size_t& written,
                                        AdapterError& error) override;
  PrimitiveStatus importResumptionState(std::span<const std::byte> bytes, bool useZeroRtt,
                                        uint64_t nowRawNs, AdapterError& error) override;
  bool connectionResumed(uint64_t connectionId, uint64_t nowRawNs, bool& resumed,
                         AdapterError& error) override;
  bool zeroRttAttempted(uint64_t connectionId, uint64_t nowRawNs, bool& attempted,
                       AdapterError& error) override;
  bool zeroRttAccepted(uint64_t connectionId, uint64_t nowRawNs, bool& accepted,
                      AdapterError& error) override;
  bool zeroRttRejected(uint64_t connectionId, uint64_t nowRawNs, bool& rejected,
                      AdapterError& error) override;
  bool closeConnection(uint64_t connectionId, uint64_t applicationError,
                       uint64_t nowRawNs, AdapterError& error) override;
  TransportCounters snapshotTransportCounters() const noexcept override;
  NegotiatedSettings snapshotNegotiatedSettings() const noexcept override;
  bool reset(AdapterError& error) override;
  bool stop(AdapterError& error) override { return reset(error); }

private:
  struct Stream {
    bool finishPending = false;
    bool finishSent = false;
    bool writeBlocked = false;
    bool closed = false;
  };

  struct Connection {
    uint64_t id = 0;
    uint64_t nativeIndex = 0;
    quic_conn_t* native = nullptr;
    std::unordered_map<uint64_t, Stream> streams;
    std::deque<uint64_t> pendingFinishes;
    std::optional<uint64_t> controlStreamId;
    std::unordered_set<uint64_t> acceptedStreams;
    std::deque<uint64_t> acceptedBidi;
    std::deque<uint64_t> acceptedUni;
    bool zeroRttAttempted = false;
    bool earlyObserved = false;
    bool peerConnectionClose = false;
    bool releaseWhenClosed = false;
    uint64_t peerConnectionCloseError = 0;
    uint64_t peerConnectionCloseReasonLength = 0;
    std::unordered_map<uint64_t, PeerTerminalFacts> terminalFacts;
    std::string closeReason;
    TransportCounters finalCounters {};
  };

  struct QueuedPacket {
    std::vector<std::byte> bytes;
    sockaddr_in peer {};
  };

  static int sendPackets(void* context, quic_packet_out_spec_t* packets, unsigned count);
  static void connectionCreated(void* context, quic_conn_t* connection);
  static void connectionEstablished(void*, quic_conn_t*) {}
  static void connectionClosed(void* context, quic_conn_t* connection);
  static void streamCreated(void* context, quic_conn_t* connection, uint64_t streamId);
  static void streamReadable(void*, quic_conn_t*, uint64_t) {}
  static void streamWritable(void*, quic_conn_t*, uint64_t) {}
  static void streamClosed(void* context, quic_conn_t* connection, uint64_t streamId);
  static void datagramReadable(void*, quic_conn_t*) {}
  static int selectAlpn(SSL*, const uint8_t** output, uint8_t* outputLength,
                        const uint8_t* input, unsigned inputLength, void*);
  static int tlsContextIndex();
  static int newSession(SSL* ssl, SSL_SESSION* session);

  bool valid(int code, std::string_view operation, AdapterError& error) const;
  bool setCallerTime(uint64_t nowRawNs, AdapterError& error) const;
  Connection* find(uint64_t id, AdapterError& error) const;
  Connection* findNative(quic_conn_t* native) const;
  bool process(AdapterError& error);
  bool retryPendingFinishes(AdapterError& error);
  void reapReleasedConnections();
  void updateTimeout(uint64_t nowRawNs) noexcept;
  PrimitiveStatus openStream(Connection& connection, bool bidi, uint64_t& streamId,
                             AdapterError& error);
  PrimitiveStatus acceptStream(Connection& connection, bool bidi, uint64_t& streamId,
                               AdapterError& error);

  Capabilities capabilities_;
  EndpointConfig config_ {};
  quic_config_t* nativeConfig_ = nullptr;
  quic_tls_config_t* tlsConfig_ = nullptr;
  SSL_CTX* tlsContext_ = nullptr;
  quic_endpoint_t* endpoint_ = nullptr;
  sockaddr_in localAddress_ {};
  std::vector<std::unique_ptr<Connection>> connections_;
  std::unordered_map<uint64_t, Connection*> byId_;
  std::unordered_map<uint64_t, Connection*> byNativeIndex_;
  std::deque<uint64_t> acceptedConnections_;
  std::deque<QueuedPacket> output_;
  std::array<std::vector<std::byte>, packetBatchSize> emitted_ {};
  std::optional<std::vector<std::byte>> importedSession_;
  std::unordered_set<std::string> consumedSessions_;
  std::deque<std::vector<std::byte>> savedSessions_;
  bool importedZeroRtt_ = false;
  std::string callbackError_;
  uint64_t nextConnectionId_ = 1;
  uint64_t nextTimeoutRawNs_ = 0;
  bool configured_ = false;
  bool localAddressSet_ = false;
  TransportCounters counters_ {};
  std::array<uint8_t, 48> ticketKey_ {};
};

TquicAdapter::TquicAdapter()
{
  capabilities_.library = "tquic";
  capabilities_.buildId = "tquic-50f5a55-quicperf8-exact-treatment-v1";
  capabilities_.adapterAbiVersion = 2;
  capabilities_.server = true;
  capabilities_.client = true;
  capabilities_.backends = {PacketBackend::syscall, PacketBackend::iouring};
  capabilities_.scenarios = {
      workload::Scenario::download, workload::Scenario::upload,
      workload::Scenario::multistreamDownload, workload::Scenario::multistreamUpload,
      workload::Scenario::bidi, workload::Scenario::lossRecovery,
      workload::Scenario::flowControl,
      workload::Scenario::smallPayloadPps,
      workload::Scenario::datagram, workload::Scenario::reqresp,
      workload::Scenario::streamChurn, workload::Scenario::closeResetCleanup,
      workload::Scenario::connect,
      workload::Scenario::resumedConnect, workload::Scenario::zeroRttReqresp,
      workload::Scenario::memoryCurve};
  capabilities_.datagram = true;
  capabilities_.resumption = true;
  capabilities_.earlyData = true;
  capabilities_.effectiveFeatures = {
      "common_cpp_packet_io", "borrowed_packet_batch_64", "ipv4", "quic_v1",
      "tls_1_3", "qperf_2_alpn", "bidirectional_stream", "unidirectional_stream",
      "datagram", "resumption", "early_data", "post_bind_local_address",
      "reset_stream", "stop_sending", "connection_close",
      "caller_supplied_raw_time", "peer_terminal_facts", "transport_loss_counter",
      "recovery_probe_counter", "flow_control_blocked_counters",
      "synthetic_address_token_clock",
      "exact_retransmission_counter_unavailable"};
}

TquicAdapter::~TquicAdapter()
{
  AdapterError ignored;
  reset(ignored);
}

int TquicAdapter::selectAlpn(SSL*, const uint8_t** output, uint8_t* outputLength,
                             const uint8_t* input, unsigned inputLength, void*)
{
  size_t offset = 0;
  while (offset < inputLength)
  {
    const size_t length = input[offset++];
    if (length > inputLength - offset) return SSL_TLSEXT_ERR_ALERT_FATAL;
    if (length == sizeof(alpn) - 1 &&
        std::equal(input + offset, input + offset + length,
                   reinterpret_cast<const uint8_t*>(alpn)))
    {
      *output = input + offset;
      *outputLength = static_cast<uint8_t>(length);
      return SSL_TLSEXT_ERR_OK;
    }
    offset += length;
  }
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

int TquicAdapter::tlsContextIndex()
{
  static const int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return index;
}

int TquicAdapter::newSession(SSL* ssl, SSL_SESSION* session)
{
  SSL_CTX* context = SSL_get_SSL_CTX(ssl);
  auto* self = context ?
      static_cast<TquicAdapter*>(SSL_CTX_get_ex_data(context, tlsContextIndex())) : nullptr;
  if (!self) return 0;
  uint8_t* encoded = nullptr;
  size_t encodedLength = 0;
  if (SSL_SESSION_to_bytes(session, &encoded, &encodedLength) != 1) return 0;
  const uint8_t* parameters = nullptr;
  size_t parameterLength = 0;
  SSL_get_peer_quic_transport_params(ssl, &parameters, &parameterLength);
  std::vector<std::byte> output;
  output.reserve(16 + encodedLength + parameterLength);
  appendU64(output, encodedLength);
  output.insert(output.end(), reinterpret_cast<std::byte*>(encoded),
                reinterpret_cast<std::byte*>(encoded) + encodedLength);
  appendU64(output, parameterLength);
  if (parameters)
    output.insert(output.end(), reinterpret_cast<const std::byte*>(parameters),
                  reinterpret_cast<const std::byte*>(parameters) + parameterLength);
  OPENSSL_free(encoded);
  self->savedSessions_.push_back(std::move(output));
  return 0;
}

bool TquicAdapter::valid(int code, std::string_view operation, AdapterError& error) const
{
  if (code == 0) return true;
  error = {static_cast<uint64_t>(-static_cast<int64_t>(code)),
           std::string(operation) + " failed with tquic error " + std::to_string(code)};
  return false;
}

bool TquicAdapter::setCallerTime(uint64_t nowRawNs, AdapterError& error) const
{
  if (quic_set_now_raw_ns(nowRawNs)) return true;
  error = {1, "tquic caller time is zero, regressed, or outside Instant range"};
  return false;
}

int TquicAdapter::sendPackets(void* context, quic_packet_out_spec_t* packets, unsigned count)
{
  auto& self = *static_cast<TquicAdapter*>(context);
  unsigned accepted = 0;
  for (; accepted < count && self.output_.size() < packetPoolSize; ++accepted)
  {
    const auto& packet = packets[accepted];
    if (!packet.dst_addr || packet.dst_addr_len != sizeof(sockaddr_in) ||
        static_cast<const sockaddr*>(packet.dst_addr)->sa_family != AF_INET)
    {
      self.callbackError_ = "tquic returned a non-IPv4 transmit path";
      break;
    }
    size_t length = 0;
    for (size_t index = 0; index < packet.iovlen; ++index)
    {
      if (packet.iov[index].iov_len > maxUdpPayloadSize -
          std::min(maxUdpPayloadSize, length))
      {
        self.callbackError_ = "tquic transmit packet exceeds the frozen UDP payload limit";
        break;
      }
      length += packet.iov[index].iov_len;
    }
    if (!self.callbackError_.empty()) break;
    QueuedPacket queued;
    queued.bytes.reserve(length);
    for (size_t index = 0; index < packet.iovlen; ++index)
    {
      const auto* first = static_cast<const std::byte*>(packet.iov[index].iov_base);
      queued.bytes.insert(queued.bytes.end(), first, first + packet.iov[index].iov_len);
    }
    std::memcpy(&queued.peer, packet.dst_addr, sizeof(queued.peer));
    self.output_.push_back(std::move(queued));
  }
  return static_cast<int>(accepted);
}

void TquicAdapter::connectionCreated(void* context, quic_conn_t* native)
{
  auto& self = *static_cast<TquicAdapter*>(context);
  auto owned = std::make_unique<Connection>();
  owned->id = self.nextConnectionId_++;
  owned->nativeIndex = quic_conn_index(native);
  owned->native = native;
  Connection* result = owned.get();
  self.connections_.push_back(std::move(owned));
  self.byId_[result->id] = result;
  self.byNativeIndex_[result->nativeIndex] = result;
  quic_conn_set_context(native, result);
  if (self.config_.role == EndpointRole::server)
    self.acceptedConnections_.push_back(result->id);
}

void TquicAdapter::connectionClosed(void* context, quic_conn_t* native)
{
  auto& self = *static_cast<TquicAdapter*>(context);
  Connection* connection = self.findNative(native);
  if (!connection) return;
  if (const auto* stats = quic_conn_stats(native))
  {
    connection->finalCounters.packetsReceived = stats->recv_count;
    connection->finalCounters.packetsSent = stats->sent_count;
    connection->finalCounters.packetsLost = stats->lost_count;
    connection->finalCounters.flowControlBlockedEvents = stats->data_blocked_sent;
    connection->finalCounters.streamCreditBlockedEvents = stats->stream_data_blocked_sent;
    connection->finalCounters.recoveryWakeups = stats->recovery_wakeups;
  }
  bool peerApplication = false;
  uint64_t peerCode = 0;
  const uint8_t* peerReason = nullptr;
  size_t peerReasonLength = 0;
  if (quic_conn_peer_error(native, &peerApplication, &peerCode,
                           &peerReason, &peerReasonLength) && peerApplication)
  {
    connection->peerConnectionClose = true;
    connection->peerConnectionCloseError = peerCode;
    connection->peerConnectionCloseReasonLength = peerReasonLength;
  }
  if (quic_conn_is_handshake_timeout(native))
    connection->closeReason = "handshake timeout";
  else if (quic_conn_is_idle_timeout(native))
    connection->closeReason = "idle timeout";
  else if (quic_conn_is_reset(native))
    connection->closeReason = "stateless reset";
  else
  {
    bool application = false;
    uint64_t code = 0;
    const uint8_t* reason = nullptr;
    size_t reasonLength = 0;
    if (quic_conn_local_error(native, &application, &code, &reason, &reasonLength))
      connection->closeReason = std::string(application ? "local application error " :
                                                        "local transport error ") +
                                std::to_string(code);
    else if (quic_conn_peer_error(native, &application, &code, &reason, &reasonLength))
      connection->closeReason = std::string(application ? "peer application error " :
                                                        "peer transport error ") +
                                std::to_string(code);
    else
      connection->closeReason = "unspecified close";
  }
  connection->closeReason += " (received=" +
      std::to_string(connection->finalCounters.packetsReceived) + ", sent=" +
      std::to_string(connection->finalCounters.packetsSent) + ", lost=" +
      std::to_string(connection->finalCounters.packetsLost) + ", timer_expirations=" +
      std::to_string(self.counters_.timerExpirations) + ")";
  connection->native = nullptr;
}

void TquicAdapter::streamCreated(void* context, quic_conn_t* native, uint64_t streamId)
{
  auto& self = *static_cast<TquicAdapter*>(context);
  Connection* connection = self.findNative(native);
  if (!connection) return;
  connection->streams.try_emplace(streamId);
  if (bidirectional(streamId) &&
      (!connection->controlStreamId || streamId < *connection->controlStreamId))
    connection->controlStreamId = streamId;
  quic_stream_wantread(native, streamId, true);
  if (!remoteInitiated(streamId, self.config_.role) ||
      !connection->acceptedStreams.insert(streamId).second)
    return;
  (bidirectional(streamId) ? connection->acceptedBidi : connection->acceptedUni)
      .push_back(streamId);
}

void TquicAdapter::streamClosed(void* context, quic_conn_t* native,
                                uint64_t streamId)
{
  auto& self = *static_cast<TquicAdapter*>(context);
  Connection* connection = self.findNative(native);
  if (!connection) return;
  const auto found = connection->streams.find(streamId);
  if (found == connection->streams.end()) return;
  found->second.finishPending = false;
  found->second.finishSent = true;
  found->second.closed = true;
}

TquicAdapter::Connection* TquicAdapter::find(uint64_t id, AdapterError& error) const
{
  const auto found = byId_.find(id);
  if (found != byId_.end() && found->second->native) return found->second;
  error = {2, found == byId_.end() ? "unknown tquic connection" :
      "closed tquic connection: " + found->second->closeReason};
  return nullptr;
}

TquicAdapter::Connection* TquicAdapter::findNative(quic_conn_t* native) const
{
  if (!native) return nullptr;
  const auto found = byNativeIndex_.find(quic_conn_index(native));
  return found == byNativeIndex_.end() ? nullptr : found->second;
}

bool TquicAdapter::configure(std::string_view canonicalConfig, AdapterError& error)
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
      parsed.config.congestionController != "bbr")
  {
    error = {1, "tquic cannot honor the requested congestion controller"};
    return false;
  }
  if (parsed.config.packetIo.ecn)
  {
    error = {1, "tquic adapter cannot exchange packet ECN metadata"};
    return false;
  }
  config_ = parsed.config;
  if (config_.calendarUnixSeconds == 0 ||
      config_.calendarUnixSeconds >
          static_cast<uint64_t>(std::numeric_limits<time_t>::max()))
  {
    error = {1, "tquic frozen TLS calendar time is out of range"};
    return false;
  }
  uint64_t expected = 0;
  if (!frozenTlsUnixSeconds.compare_exchange_strong(
          expected, config_.calendarUnixSeconds, std::memory_order_relaxed) &&
      expected != config_.calendarUnixSeconds)
  {
    error = {1, "tquic worker calendar time changed after initialization"};
    return false;
  }
  if (!callerClockPrimed)
  {
    if (!quic_set_now_raw_ns(1))
    {
      error = {1, "failed to initialize tquic caller clock before READY"};
      return false;
    }
    callerClockPrimed = true;
  }
  nativeConfig_ = quic_config_new();
  FILE* random = std::fopen("/dev/urandom", "rb");
  if (!random || std::fread(ticketKey_.data(), 1, ticketKey_.size(), random) != ticketKey_.size())
  {
    if (random) std::fclose(random);
    error = {10, "failed to generate tquic ticket key"};
    reset(ignored);
    return false;
  }
  std::fclose(random);
  tlsContext_ = SSL_CTX_new(TLS_method());
  if (!tlsContext_ ||
      SSL_CTX_set_min_proto_version(tlsContext_, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(tlsContext_, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set1_groups_list(tlsContext_, "X25519") != 1 ||
      SSL_CTX_set_signing_algorithm_prefs(
          tlsContext_, signatureAlgorithms.data(), signatureAlgorithms.size()) != 1 ||
      SSL_CTX_set_verify_algorithm_prefs(
          tlsContext_, signatureAlgorithms.data(), signatureAlgorithms.size()) != 1 ||
      SSL_CTX_set_tlsext_ticket_keys(tlsContext_, ticketKey_.data(), ticketKey_.size()) != 1)
  {
    error = {10, "failed to configure tquic TLS policy"};
    reset(ignored);
    return false;
  }
  SSL_CTX_set_early_data_enabled(tlsContext_, 1);
  SSL_CTX_set_current_time_cb(tlsContext_, frozenTlsTime);
  X509_VERIFY_PARAM_set_time_posix(
      SSL_CTX_get0_param(tlsContext_), config_.calendarUnixSeconds);
  SSL_CTX_set_session_psk_dhe_timeout(
      tlsContext_, config_.tlsTicketLifetimeNs / 1'000'000'000ULL);
  SSL_CTX_set_num_tickets(tlsContext_, 1);
  SSL_CTX_set_verify(tlsContext_, config_.tlsVerifyPeer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                     nullptr);
  SSL_CTX_set_ex_data(tlsContext_, tlsContextIndex(), this);
  if (config_.role == EndpointRole::server)
  {
    if (SSL_CTX_use_certificate_chain_file(tlsContext_, config_.certificatePath.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(tlsContext_, config_.privateKeyPath.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(tlsContext_) != 1)
    {
      error = {10, "failed to load tquic server certificate or private key"};
      reset(ignored);
      return false;
    }
    SSL_CTX_set_alpn_select_cb(tlsContext_, selectAlpn, nullptr);
  }
  else
  {
    SSL_CTX_set_session_cache_mode(tlsContext_, SSL_SESS_CACHE_CLIENT |
                                   SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_new_cb(tlsContext_, newSession);
    if (config_.tlsVerifyPeer &&
        SSL_CTX_load_verify_locations(tlsContext_, config_.chainPath.c_str(), nullptr) != 1)
    {
      error = {10, "failed to load tquic trust chain"};
      reset(ignored);
      return false;
    }
    const std::array<uint8_t, sizeof(alpn)> wireAlpn = {
        sizeof(alpn) - 1, 'q', 'p', 'e', 'r', 'f', '/', '2'};
    SSL_CTX_set_alpn_protos(tlsContext_, wireAlpn.data(), wireAlpn.size());
  }
  tlsConfig_ = quic_tls_config_new_with_ssl_ctx(tlsContext_);
  if (!nativeConfig_ || !tlsConfig_)
  {
    error = {10, "failed to create tquic transport or TLS configuration"};
    reset(ignored);
    return false;
  }
  if (config_.role == EndpointRole::client)
  {
    quic_tls_config_set_verify(tlsConfig_, config_.tlsVerifyPeer);
    if (config_.tlsVerifyPeer &&
        !valid(quic_tls_config_set_ca_certs(tlsConfig_, config_.chainPath.c_str()),
               "quic_tls_config_set_ca_certs", error))
    {
      reset(ignored);
      return false;
    }
  }
  quic_tls_config_set_early_data_enabled(tlsConfig_, true);
  quic_tls_config_set_session_timeout(tlsConfig_,
      static_cast<uint32_t>(config_.tlsTicketLifetimeNs / 1'000'000'000ULL));
  quic_config_set_tls_config(nativeConfig_, tlsConfig_);
  quic_config_set_max_idle_timeout(nativeConfig_, config_.idleTimeoutMs);
  quic_config_set_max_handshake_timeout(nativeConfig_, config_.idleTimeoutMs);
  quic_config_set_recv_udp_payload_size(nativeConfig_, config_.maxUdpPayloadSize);
  quic_config_set_send_udp_payload_size(nativeConfig_, config_.maxUdpPayloadSize);
  enable_dplpmtud(nativeConfig_, config_.packetIo.pmtud);
  quic_config_set_max_connection_window(nativeConfig_, config_.connectionWindow);
  quic_config_set_max_stream_window(nativeConfig_, config_.streamWindow);
  quic_config_set_initial_max_data(nativeConfig_, config_.connectionWindow);
  quic_config_set_initial_max_stream_data_bidi_local(nativeConfig_, config_.streamWindow);
  quic_config_set_initial_max_stream_data_bidi_remote(nativeConfig_, config_.streamWindow);
  quic_config_set_initial_max_stream_data_uni(nativeConfig_, config_.streamWindow);
  quic_config_set_initial_max_streams_bidi(nativeConfig_, config_.maxBidiStreams);
  quic_config_set_initial_max_streams_uni(nativeConfig_, config_.maxUniStreams);
  quic_config_set_ack_delay_exponent(nativeConfig_, config_.ackDelayExponent);
  quic_config_set_max_ack_delay(nativeConfig_, config_.maxAckDelayNs / 1'000'000ULL);
  quic_config_set_active_connection_id_limit(
      nativeConfig_, config_.activeConnectionIdLimit);
  quic_config_set_disable_active_migration(nativeConfig_, !config_.activeMigration);
  quic_config_set_cid_len(nativeConfig_, config_.connectionIdBytes);
  quic_config_set_initial_congestion_window(
      nativeConfig_, config_.initialCongestionWindowBytes / config_.maxUdpPayloadSize);
  quic_config_set_max_concurrent_conns(nativeConfig_, config_.connectionCount);
  quic_config_set_send_batch_size(nativeConfig_, packetBatchSize);
  quic_config_set_max_datagram_frame_size(nativeConfig_, config_.datagramMaxFrameSize);
  quic_config_set_max_datagram_send_queue_size(
      nativeConfig_, config_.datagramMaxUnreturnedPerConnection);
  quic_config_set_max_datagram_recv_queue_size(
      nativeConfig_, config_.datagramMaxUnreturnedPerConnection);
  quic_config_enable_pacing(nativeConfig_, config_.packetIo.commonPacing);
  quic_config_set_congestion_control_algorithm(
      nativeConfig_, config_.congestionController == "bbr" ?
          QUIC_CONGESTION_CONTROL_ALGORITHM_BBR : QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC);

  static const quic_transport_methods_t transportMethods = {
      connectionCreated, connectionEstablished, connectionClosed, streamCreated,
      streamReadable, streamWritable, streamClosed, nullptr, datagramReadable,
      nullptr, nullptr};
  static const quic_packet_send_methods_t sendMethods = {sendPackets};
  endpoint_ = quic_endpoint_new(nativeConfig_, config_.role == EndpointRole::server,
                                &transportMethods, this, &sendMethods, this);
  if (!endpoint_)
  {
    error = {10, "quic_endpoint_new failed"};
    reset(ignored);
    return false;
  }
  configured_ = true;
  error = {};
  return true;
}

bool TquicAdapter::setLocalAddress(const sockaddr_in& local, AdapterError& error)
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

bool TquicAdapter::process(AdapterError& error)
{
  if (!retryPendingFinishes(error)) return false;
  const int status = quic_endpoint_process_connections(endpoint_);
  reapReleasedConnections();
  if (!callbackError_.empty())
  {
    error = {1, std::exchange(callbackError_, {})};
    return false;
  }
  if (status == tquicDone)
  {
    error = {};
    return true;
  }
  return valid(status, "quic_endpoint_process_connections", error);
}

bool TquicAdapter::retryPendingFinishes(AdapterError& error)
{
  const std::byte empty {};
  for (const auto& connection : connections_)
  {
    if (!connection->native) continue;
    for (size_t attempts = connection->pendingFinishes.size(); attempts > 0; --attempts)
    {
      const uint64_t streamId = connection->pendingFinishes.front();
      connection->pendingFinishes.pop_front();
      const auto found = connection->streams.find(streamId);
      if (found == connection->streams.end() || !found->second.finishPending ||
          found->second.closed)
        continue;
      Stream& stream = found->second;
      const ssize_t status = quic_stream_write(
          connection->native, streamId,
          reinterpret_cast<const uint8_t*>(&empty), 0, true);
      if (status == tquicDone)
      {
        connection->pendingFinishes.push_back(streamId);
        continue;
      }
      if (status < 0)
        return valid(static_cast<int>(status), "deferred tquic stream FIN", error);
      stream.finishPending = false;
      stream.finishSent = true;
    }
  }
  error = {};
  return true;
}

void TquicAdapter::reapReleasedConnections()
{
  std::erase_if(connections_, [this](const auto& owned) {
    const Connection& connection = *owned;
    if (connection.native || !connection.releaseWhenClosed) return false;
    byId_.erase(connection.id);
    const auto native = byNativeIndex_.find(connection.nativeIndex);
    if (native != byNativeIndex_.end() && native->second == &connection)
      byNativeIndex_.erase(native);
    std::erase(acceptedConnections_, connection.id);
    return true;
  });
}

bool TquicAdapter::receiveBatch(std::span<const ReceivedPacket> packets,
                                uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  if (!configured_ || !localAddressSet_ || packets.size() > packetBatchSize)
  {
    error = {2, "tquic receive requires a configured post-bind adapter and at most 64 packets"};
    return false;
  }
  for (const auto& packet : packets)
  {
    if (packet.bytes.empty() || packet.bytes.size() > config_.maxUdpPayloadSize ||
        packet.peer.sin_family != AF_INET || (!config_.packetIo.ecn && packet.ecn))
    {
      error = {1, "invalid borrowed tquic receive packet"};
      return false;
    }
    quic_packet_info_t info {
        reinterpret_cast<const sockaddr*>(&packet.peer), sizeof(packet.peer),
        reinterpret_cast<const sockaddr*>(&localAddress_), sizeof(localAddress_)};
    const int status = quic_endpoint_recv(
        endpoint_, const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(packet.bytes.data())),
        packet.bytes.size(), &info);
    if (!valid(status, "quic_endpoint_recv", error)) return false;
  }
  if (!process(error)) return false;
  for (const auto& connection : connections_)
    if (connection->native)
      connection->earlyObserved |= quic_conn_is_in_early_data(connection->native);
  updateTimeout(nowRawNs);
  error = {};
  return true;
}

size_t TquicAdapter::pollTransmitBatch(std::span<TransmitPacket> packets,
                                       uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return 0;
  if (!configured_)
  {
    error = {2, "tquic adapter is not configured"};
    return 0;
  }
  if (!process(error)) return 0;
  const size_t count = std::min({packets.size(), output_.size(), packetBatchSize});
  for (size_t index = 0; index < count; ++index)
  {
    auto& queued = output_.front();
    emitted_[index] = std::move(queued.bytes);
    packets[index].bytes = emitted_[index];
    packets[index].peer = queued.peer;
    packets[index].ecn = 0;
    packets[index].gsoSegmentSize = 0;
    packets[index].desiredSendRawNs = nowRawNs;
    output_.pop_front();
  }
  updateTimeout(nowRawNs);
  error = {};
  return count;
}

void TquicAdapter::updateTimeout(uint64_t nowRawNs) noexcept
{
  const uint64_t milliseconds = endpoint_ ? quic_endpoint_timeout(endpoint_) :
                                           std::numeric_limits<uint64_t>::max();
  if (milliseconds == std::numeric_limits<uint64_t>::max())
  {
    nextTimeoutRawNs_ = 0;
    return;
  }
  const uint64_t maximumDelay = std::numeric_limits<uint64_t>::max() - nowRawNs;
  const uint64_t deadline = milliseconds > maximumDelay / 1'000'000ULL ?
      std::numeric_limits<uint64_t>::max() : nowRawNs + milliseconds * 1'000'000ULL;
  if (!nextTimeoutRawNs_ || deadline < nextTimeoutRawNs_)
    nextTimeoutRawNs_ = deadline;
}

bool TquicAdapter::onTimeout(uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  if (!configured_)
  {
    error = {2, "tquic adapter is not configured"};
    return false;
  }
  nextTimeoutRawNs_ = 0;
  quic_endpoint_on_timeout(endpoint_);
  ++counters_.timerExpirations;
  if (!process(error)) return false;
  updateTimeout(nowRawNs);
  error = {};
  return true;
}

bool TquicAdapter::connect(const sockaddr_in& peer, uint64_t nowRawNs,
                           uint64_t& connectionId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  const size_t activeConnections = std::ranges::count_if(
      connections_, [](const auto& connection) {
        return connection->native &&
            !quic_conn_is_closing(connection->native) &&
            !quic_conn_is_draining(connection->native) &&
            !quic_conn_is_closed(connection->native);
      });
  if (!configured_ || !localAddressSet_ || config_.role != EndpointRole::client ||
      peer.sin_family != AF_INET || activeConnections >= config_.connectionCount)
  {
    error = {2, "tquic connect requires a configured client, valid peer, and free slot"};
    return false;
  }
  in_addr expected {};
  if (inet_pton(AF_INET, config_.peerAddress.c_str(), &expected) != 1 ||
      expected.s_addr != peer.sin_addr.s_addr || ntohs(peer.sin_port) != config_.peerPort)
  {
    error = {1, "connect peer differs from the immutable endpoint configuration"};
    return false;
  }
  const uint8_t* session = importedSession_ ?
      reinterpret_cast<const uint8_t*>(importedSession_->data()) : nullptr;
  const size_t sessionLength = importedSession_ ? importedSession_->size() : 0;
  uint64_t nativeIndex = 0;
  const int status = quic_endpoint_connect(
      endpoint_, reinterpret_cast<const sockaddr*>(&localAddress_), sizeof(localAddress_),
      reinterpret_cast<const sockaddr*>(&peer), sizeof(peer), config_.tlsHostname.c_str(),
      session, sessionLength, nullptr, 0, nullptr, &nativeIndex);
  if (!valid(status, "quic_endpoint_connect", error)) return false;
  const auto found = byNativeIndex_.find(nativeIndex);
  if (found == byNativeIndex_.end())
  {
    error = {1, "tquic did not report its newly created client connection"};
    return false;
  }
  found->second->zeroRttAttempted = importedSession_.has_value() && importedZeroRtt_;
  found->second->earlyObserved |= quic_conn_is_in_early_data(found->second->native);
  if (importedSession_)
    consumedSessions_.emplace(
        reinterpret_cast<const char*>(importedSession_->data()), importedSession_->size());
  importedSession_.reset();
  importedZeroRtt_ = false;
  connectionId = found->second->id;
  updateTimeout(nowRawNs);
  error = {};
  return true;
}

PrimitiveStatus TquicAdapter::acceptConnection(uint64_t nowRawNs, uint64_t& connectionId,
                                                AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  if (!configured_ || config_.role != EndpointRole::server)
  {
    error = {2, "tquic accept requires a configured server"};
    return PrimitiveStatus::fatal;
  }
  if (acceptedConnections_.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  connectionId = acceptedConnections_.front();
  acceptedConnections_.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

bool TquicAdapter::isConnected(uint64_t id, uint64_t nowRawNs, bool& connected,
                               AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* connection = find(id, error);
  if (!connection) return false;
  connection->earlyObserved |= quic_conn_is_in_early_data(connection->native);
  connected = quic_conn_is_established(connection->native) &&
      !quic_conn_is_closing(connection->native) && !quic_conn_is_draining(connection->native) &&
      !quic_conn_is_closed(connection->native);
  error = {};
  return true;
}

bool TquicAdapter::connectionIsClosed(uint64_t id, uint64_t nowRawNs, bool& closed,
                                      AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  const auto found = byId_.find(id);
  if (found == byId_.end())
  {
    error = {2, "unknown tquic connection for closure query"};
    return false;
  }
  const Connection& connection = *found->second;
  closed = !connection.native || quic_conn_is_draining(connection.native) ||
      quic_conn_is_closed(connection.native);
  error = {};
  return true;
}

bool TquicAdapter::releaseConnectionWhenClosed(uint64_t id, uint64_t nowRawNs,
                                               AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  const auto found = byId_.find(id);
  if (found == byId_.end())
  {
    error = {2, "unknown tquic connection for closed release"};
    return false;
  }
  found->second->releaseWhenClosed = true;
  reapReleasedConnections();
  error = {};
  return true;
}

bool TquicAdapter::peerTerminalFacts(uint64_t id, uint64_t streamId,
                                     uint64_t nowRawNs, PeerTerminalFacts& facts,
                                     AdapterError& error)
{
  facts = {};
  if (!setCallerTime(nowRawNs, error)) return false;
  const auto found = byId_.find(id);
  if (found == byId_.end() || !found->second->streams.contains(streamId))
  {
    error = {2, "terminal facts target an unknown tquic connection or stream"};
    return false;
  }
  Connection& connection = *found->second;
  facts = connection.terminalFacts[streamId];
  facts.available = true;
  if (connection.native)
  {
    bool fin = false;
    bool resetStream = false;
    uint64_t resetError = 0;
    bool stopSending = false;
    uint64_t stopError = 0;
    quic_stream_peer_terminal(connection.native, streamId, &fin, &resetStream,
                              &resetError, &stopSending, &stopError);
    facts.fin |= fin;
    if (resetStream)
    {
      facts.resetStream = true;
      facts.resetStreamError = resetError;
    }
    if (stopSending)
    {
      facts.stopSending = true;
      facts.stopSendingError = stopError;
    }
    bool application = false;
    uint64_t closeError = 0;
    const uint8_t* closeReason = nullptr;
    size_t closeReasonLength = 0;
    if (quic_conn_peer_error(connection.native, &application, &closeError,
                             &closeReason, &closeReasonLength) && application)
    {
      connection.peerConnectionClose = true;
      connection.peerConnectionCloseError = closeError;
      connection.peerConnectionCloseReasonLength = closeReasonLength;
    }
    connection.terminalFacts[streamId] = facts;
  }
  facts.connectionClose = connection.peerConnectionClose;
  facts.connectionCloseError = connection.peerConnectionCloseError;
  facts.connectionCloseReasonLength = connection.peerConnectionCloseReasonLength;
  error = {};
  return true;
}

PrimitiveStatus TquicAdapter::openStream(Connection& connection, bool bidi,
                                         uint64_t& streamId, AdapterError& error)
{
  const int status = bidi ? quic_stream_bidi_new(connection.native, 0, false, &streamId) :
                            quic_stream_uni_new(connection.native, 0, false, &streamId);
  if (status == tquicStreamLimit || status == tquicDone)
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  if (!valid(status, bidi ? "quic_stream_bidi_new" : "quic_stream_uni_new", error))
    return PrimitiveStatus::fatal;
  connection.streams.try_emplace(streamId);
  if (bidi && (!connection.controlStreamId || streamId < *connection.controlStreamId))
    connection.controlStreamId = streamId;
  quic_stream_wantread(connection.native, streamId, true);
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus TquicAdapter::acceptStream(Connection& connection, bool bidi,
                                           uint64_t& streamId, AdapterError& error)
{
  auto& pending = bidi ? connection.acceptedBidi : connection.acceptedUni;
  if (pending.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  streamId = pending.front();
  pending.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus TquicAdapter::openBidirectionalStream(
    uint64_t id, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  Connection* c = find(id, error);
  return c ? openStream(*c, true, streamId, error) : PrimitiveStatus::fatal;
}
PrimitiveStatus TquicAdapter::acceptBidirectionalStream(
    uint64_t id, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  Connection* c = find(id, error);
  return c ? acceptStream(*c, true, streamId, error) : PrimitiveStatus::fatal;
}
PrimitiveStatus TquicAdapter::openUnidirectionalStream(
    uint64_t id, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  Connection* c = find(id, error);
  return c ? openStream(*c, false, streamId, error) : PrimitiveStatus::fatal;
}
PrimitiveStatus TquicAdapter::acceptUnidirectionalStream(
    uint64_t id, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  Connection* c = find(id, error);
  return c ? acceptStream(*c, false, streamId, error) : PrimitiveStatus::fatal;
}

bool TquicAdapter::writeStream(uint64_t id, uint64_t streamId,
                               std::span<const std::byte> bytes, uint64_t nowRawNs,
                               size_t& written, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  written = 0;
  Connection* connection = find(id, error);
  if (!connection)
    return false;
  const auto found = connection->streams.find(streamId);
  if (found == connection->streams.end() || found->second.closed)
  {
    error = {1, "write targets an unknown or closed tquic stream"};
    return false;
  }
  const bool control = connection->controlStreamId &&
      streamId == *connection->controlStreamId;
  const uint64_t buffered = quic_conn_stream_send_buffered(connection->native);
  const uint64_t bufferLimit = applicationBufferBytes -
      (control ? 0 : controlStreamReserveBytes);
  if (buffered >= bufferLimit)
  {
    error = {};
    return true;
  }
  if (bytes.empty())
  {
    error = {};
    return true;
  }
  size_t allowed = static_cast<size_t>(std::min<uint64_t>(
      bytes.size(), bufferLimit - buffered));
  const ssize_t capacity = quic_stream_capacity(connection->native, streamId);
  if (capacity == tquicDone)
  {
    error = {};
    return true;
  }
  if (capacity < 0)
    return valid(static_cast<int>(capacity), "quic_stream_capacity", error);
  Stream& stream = found->second;
  if (capacity == 0)
  {
    if (!stream.writeBlocked) ++counters_.flowControlBlockedEvents;
    stream.writeBlocked = true;
    error = {};
    return true;
  }
  allowed = std::min(allowed, static_cast<size_t>(capacity));
  const ssize_t status = quic_stream_write(
      connection->native, streamId, reinterpret_cast<const uint8_t*>(bytes.data()),
      allowed, false);
  if (status == tquicDone)
  {
    if (!stream.writeBlocked) ++counters_.flowControlBlockedEvents;
    stream.writeBlocked = true;
    error = {};
    return true;
  }
  if (status < 0) return valid(static_cast<int>(status), "quic_stream_write", error);
  stream.writeBlocked = false;
  written = status;
  error = {};
  return true;
}

bool TquicAdapter::consumeStreamData(uint64_t id, uint64_t streamId,
                                     std::span<std::byte> bytes, uint64_t nowRawNs,
                                     size_t& read, bool& finished, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  read = 0;
  finished = false;
  Connection* connection = find(id, error);
  if (!connection || !connection->streams.contains(streamId))
  {
    if (connection) error = {1, "read targets an unknown tquic stream"};
    return false;
  }
  bool fin = false;
  const ssize_t status = quic_stream_read(
      connection->native, streamId, reinterpret_cast<uint8_t*>(bytes.data()),
      bytes.size(), &fin);
  if (status < 0)
  {
    finished = quic_stream_finished(connection->native, streamId);
    error = {};
    return true;
  }
  read = status;
  finished = fin;
  error = {};
  return true;
}

bool TquicAdapter::finishStream(uint64_t id, uint64_t streamId, uint64_t nowRawNs,
                                AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* connection = find(id, error);
  if (!connection)
    return false;
  const auto found = connection->streams.find(streamId);
  if (found == connection->streams.end())
  {
    error = {1, "finish targets an unknown tquic stream"};
    return false;
  }
  Stream& stream = found->second;
  if (stream.closed || stream.finishPending || stream.finishSent)
  {
    error = {};
    return true;
  }
  const std::byte empty {};
  const ssize_t status = quic_stream_write(
      connection->native, streamId, reinterpret_cast<const uint8_t*>(&empty), 0, true);
  if (status == tquicDone)
  {
    stream.finishPending = true;
    connection->pendingFinishes.push_back(streamId);
    error = {};
    return true;
  }
  if (status < 0) return valid(static_cast<int>(status), "tquic stream FIN", error);
  stream.finishSent = true;
  error = {};
  return true;
}

bool TquicAdapter::resetStream(uint64_t id, uint64_t streamId, uint64_t appError,
                               uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  return c && valid(quic_stream_shutdown(c->native, streamId, QUIC_SHUTDOWN_WRITE, appError),
                    "tquic RESET_STREAM", error);
}
bool TquicAdapter::stopSending(uint64_t id, uint64_t streamId, uint64_t appError,
                               uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  return c && valid(quic_stream_shutdown(c->native, streamId, QUIC_SHUTDOWN_READ, appError),
                    "tquic STOP_SENDING", error);
}

PrimitiveStatus TquicAdapter::sendDatagram(uint64_t id,
                                           std::span<const std::byte> bytes,
                                           uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  Connection* c = find(id, error);
  if (!c) return PrimitiveStatus::fatal;
  const ssize_t status = quic_datagram_write(
      c->native, 0, reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(),
      config_.idleTimeoutMs);
  if (status == tquicDone) { error = {}; return PrimitiveStatus::wouldBlock; }
  if (status < 0)
  {
    valid(static_cast<int>(status), "quic_datagram_write", error);
    return PrimitiveStatus::fatal;
  }
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus TquicAdapter::consumeDatagram(uint64_t id,
                                              std::span<std::byte> bytes, uint64_t nowRawNs,
                                              size_t& read, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  read = 0;
  Connection* c = find(id, error);
  if (!c) return PrimitiveStatus::fatal;
  const ssize_t status = quic_datagram_read(
      c->native, reinterpret_cast<uint8_t*>(bytes.data()), bytes.size());
  if (status < 0) { error = {}; return PrimitiveStatus::wouldBlock; }
  read = status;
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus TquicAdapter::exportResumptionState(
    uint64_t id, uint64_t nowRawNs, std::span<std::byte> bytes, size_t& written,
    AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  written = 0;
  Connection* c = find(id, error);
  if (!c) return PrimitiveStatus::fatal;
  if (!savedSessions_.empty())
  {
    if (!sealResumptionState(
            savedSessions_.front(), nowRawNs, bytes, written, error))
      return PrimitiveStatus::fatal;
    savedSessions_.pop_front();
    return PrimitiveStatus::ready;
  }
  const uint8_t* session = nullptr;
  size_t length = 0;
  quic_conn_session(c->native, &session, &length);
  if (!session || !length) { error = {}; return PrimitiveStatus::wouldBlock; }
  return sealResumptionState(
             std::span(reinterpret_cast<const std::byte*>(session), length),
             nowRawNs, bytes, written, error) ?
      PrimitiveStatus::ready : PrimitiveStatus::fatal;
}

PrimitiveStatus TquicAdapter::importResumptionState(
    std::span<const std::byte> bytes, bool zeroRtt, uint64_t nowRawNs,
    AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  std::span<const std::byte> session;
  if (openResumptionState(bytes, nowRawNs, config_.tlsTicketLifetimeNs,
                          session, error) != PrimitiveStatus::ready)
    return PrimitiveStatus::fatal;
  const std::string ticket(
      reinterpret_cast<const char*>(session.data()), session.size());
  if (!configured_ || config_.role != EndpointRole::client || importedSession_ ||
      session.empty() || consumedSessions_.contains(ticket))
  {
    error = {1, "invalid, overlapping, or already consumed tquic resumption import"};
    return PrimitiveStatus::fatal;
  }
  importedSession_.emplace(session.begin(), session.end());
  importedZeroRtt_ = zeroRtt;
  error = {};
  return PrimitiveStatus::ready;
}

bool TquicAdapter::connectionResumed(uint64_t id, uint64_t nowRawNs, bool& resumed,
                                     AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  if (!c) return false;
  resumed = quic_conn_is_resumed(c->native);
  error = {};
  return true;
}
bool TquicAdapter::zeroRttAttempted(uint64_t id, uint64_t nowRawNs, bool& attempted,
                                    AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  if (!c) return false;
  attempted = c->zeroRttAttempted;
  error = {};
  return true;
}
bool TquicAdapter::zeroRttAccepted(uint64_t id, uint64_t nowRawNs, bool& accepted,
                                   AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  if (!c) return false;
  accepted = c->zeroRttAttempted && c->earlyObserved && quic_conn_is_established(c->native);
  error = {};
  return true;
}
bool TquicAdapter::zeroRttRejected(uint64_t id, uint64_t nowRawNs, bool& rejected,
                                   AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  if (!c) return false;
  rejected = c->zeroRttAttempted && !c->earlyObserved && quic_conn_is_established(c->native);
  error = {};
  return true;
}

bool TquicAdapter::closeConnection(uint64_t id, uint64_t appError, uint64_t nowRawNs,
                                   AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  Connection* c = find(id, error);
  return c && valid(quic_conn_close(c->native, true, appError, nullptr, 0),
                    "quic_conn_close", error);
}

TransportCounters TquicAdapter::snapshotTransportCounters() const noexcept
{
  TransportCounters result = counters_;
  for (const auto& connection : connections_)
  {
    if (connection->native)
    {
      if (const auto* stats = quic_conn_stats(connection->native))
      {
        result.packetsReceived += stats->recv_count;
        result.packetsSent += stats->sent_count;
        result.packetsLost += stats->lost_count;
        result.recoveryWakeups += stats->recovery_wakeups;
        result.flowControlBlockedEvents += stats->data_blocked_sent;
        result.streamCreditBlockedEvents += stats->stream_data_blocked_sent;
      }
    }
    else
    {
      result.packetsReceived += connection->finalCounters.packetsReceived;
      result.packetsSent += connection->finalCounters.packetsSent;
      result.packetsLost += connection->finalCounters.packetsLost;
      result.recoveryWakeups += connection->finalCounters.recoveryWakeups;
      result.flowControlBlockedEvents +=
          connection->finalCounters.flowControlBlockedEvents;
      result.streamCreditBlockedEvents +=
          connection->finalCounters.streamCreditBlockedEvents;
    }
  }
  return result;
}

NegotiatedSettings TquicAdapter::snapshotNegotiatedSettings() const noexcept
{
  const auto snapshot = [this](const Connection& connection) {
    NegotiatedSettings result;
    result.evidenceSource =
        "tquic_peer_transport_params+boringssl_post_handshake+"
        "tquic_applied_settings+qpf2_lifecycle_policy";
    const auto unavailable = [&result](std::string field) {
      if (std::find(result.unavailableFields.begin(), result.unavailableFields.end(),
                    field) == result.unavailableFields.end())
        result.unavailableFields.push_back(std::move(field));
    };
    if (!connection.native || !quic_conn_is_established(connection.native))
    {
      unavailable("handshake_not_complete");
      return result;
    }
    quic_conn_negotiated_t peer {};
    if (!quic_conn_negotiated(connection.native, &peer))
    {
      unavailable("remote_transport_or_tls_state");
      return result;
    }

    result.available = true;
    result.quicVersion = peer.quic_version;
    const uint8_t* negotiatedAlpn = nullptr;
    size_t negotiatedAlpnLength = 0;
    quic_conn_application_proto(
        connection.native, &negotiatedAlpn, &negotiatedAlpnLength);
    if (negotiatedAlpn && negotiatedAlpnLength)
      result.alpn.assign(
          reinterpret_cast<const char*>(negotiatedAlpn), negotiatedAlpnLength);
    else unavailable("alpn");

    if (peer.tls_version == TLS1_3_VERSION) result.tlsVersion = "TLSv1.3";
    else unavailable("tls_version");
    switch (peer.tls_cipher_suite)
    {
      case 0x1301: result.tlsCipherSuite = "TLS_AES_128_GCM_SHA256"; break;
      case 0x1302: result.tlsCipherSuite = "TLS_AES_256_GCM_SHA384"; break;
      case 0x1303: result.tlsCipherSuite = "TLS_CHACHA20_POLY1305_SHA256"; break;
      default: unavailable("tls_cipher_suite"); break;
    }
    if (peer.tls_key_exchange_group == SSL_CURVE_X25519)
      result.tlsKeyExchange = "X25519";
    else unavailable("tls_key_exchange");

    if (config_.role == EndpointRole::client)
    {
      if (peer.tls_peer_certificate_present &&
          peer.tls_peer_signature_algorithm == SSL_SIGN_ED25519)
        result.tlsLeafSignature = "Ed25519";
      else unavailable("tls_leaf_signature");
    }
    else if (X509* certificate = SSL_CTX_get0_certificate(tlsContext_))
    {
      if (X509_get_signature_nid(certificate) == NID_ED25519)
        result.tlsLeafSignature = "Ed25519";
      else unavailable("tls_leaf_signature");
    }
    else unavailable("tls_leaf_signature");
    result.peerCertificateVerified = config_.role == EndpointRole::client &&
        peer.tls_peer_certificate_present && peer.tls_peer_certificate_verified;
    result.hostnameVerified = result.peerCertificateVerified;

    result.congestionController = config_.congestionController;
    result.initialCongestionWindowBytes = config_.initialCongestionWindowBytes;
    result.maxUdpPayloadSize = peer.max_udp_payload_size;
    result.maxAckDelayNs = peer.max_ack_delay * 1'000'000ULL;
    result.ackDelayExponent = peer.ack_delay_exponent;
    result.ackFrequency = false;
    result.activeMigration = !peer.disable_active_migration;
    result.activeConnectionIdLimit = peer.active_connection_id_limit;
    result.connectionIdBytes = peer.destination_connection_id_len;
    result.maxIdleTimeoutNs = peer.max_idle_timeout * 1'000'000ULL;
    result.maxBidiStreams = peer.initial_max_streams_bidi;
    result.maxUniStreams = peer.initial_max_streams_uni;
    result.streamCreditReplenishBelow = config_.streamCreditReplenishBelow;
    result.connectionWindowBytes = peer.initial_max_data;
    result.streamWindowBytes = peer.initial_max_stream_data_bidi_local;
    if (peer.initial_max_stream_data_bidi_remote != result.streamWindowBytes ||
        peer.initial_max_stream_data_uni != result.streamWindowBytes)
      unavailable("peer_stream_window_inconsistent");
    result.datagramMaxFrameSize = peer.max_datagram_frame_size;
    result.ticketLifetimeNs = config_.tlsTicketLifetimeNs;
    result.maximumEarlyDataBytes = config_.tlsMaximumEarlyDataBytes;
    result.oneUseTickets = config_.tlsOneUseTickets;
    return result;
  };

  const auto first = std::ranges::find_if(connections_, [](const auto& connection) {
    return !connection->releaseWhenClosed;
  });
  if (first == connections_.end())
  {
    NegotiatedSettings result;
    result.unavailableFields = {"no_post_handshake_connection"};
    return result;
  }
  NegotiatedSettings result = snapshot(**first);
  const auto same = [](const NegotiatedSettings& left,
                       const NegotiatedSettings& right) {
    return left.available == right.available &&
        left.unavailableFields == right.unavailableFields &&
        left.quicVersion == right.quicVersion && left.alpn == right.alpn &&
        left.tlsVersion == right.tlsVersion &&
        left.tlsCipherSuite == right.tlsCipherSuite &&
        left.tlsKeyExchange == right.tlsKeyExchange &&
        left.tlsLeafSignature == right.tlsLeafSignature &&
        left.peerCertificateVerified == right.peerCertificateVerified &&
        left.hostnameVerified == right.hostnameVerified &&
        left.congestionController == right.congestionController &&
        left.initialCongestionWindowBytes == right.initialCongestionWindowBytes &&
        left.maxUdpPayloadSize == right.maxUdpPayloadSize &&
        left.maxAckDelayNs == right.maxAckDelayNs &&
        left.ackDelayExponent == right.ackDelayExponent &&
        left.ackFrequency == right.ackFrequency &&
        left.activeMigration == right.activeMigration &&
        left.activeConnectionIdLimit == right.activeConnectionIdLimit &&
        left.connectionIdBytes == right.connectionIdBytes &&
        left.maxIdleTimeoutNs == right.maxIdleTimeoutNs &&
        left.maxBidiStreams == right.maxBidiStreams &&
        left.maxUniStreams == right.maxUniStreams &&
        left.streamCreditReplenishBelow == right.streamCreditReplenishBelow &&
        left.connectionWindowBytes == right.connectionWindowBytes &&
        left.streamWindowBytes == right.streamWindowBytes &&
        left.datagramMaxFrameSize == right.datagramMaxFrameSize &&
        left.ticketLifetimeNs == right.ticketLifetimeNs &&
        left.maximumEarlyDataBytes == right.maximumEarlyDataBytes &&
        left.oneUseTickets == right.oneUseTickets;
  };
  for (const auto& connection : connections_)
  {
    if (connection->releaseWhenClosed || connection.get() == first->get()) continue;
    if (!same(result, snapshot(*connection)))
    {
      result.unavailableFields = {"per_connection_evidence_mismatch"};
      break;
    }
  }
  return result;
}

bool TquicAdapter::reset(AdapterError& error)
{
  if (endpoint_)
  {
    quic_endpoint_close(endpoint_, true);
    quic_endpoint_free(endpoint_);
    endpoint_ = nullptr;
  }
  byId_.clear();
  byNativeIndex_.clear();
  connections_.clear();
  acceptedConnections_.clear();
  output_.clear();
  importedSession_.reset();
  consumedSessions_.clear();
  savedSessions_.clear();
  if (tlsConfig_) { quic_tls_config_free(tlsConfig_); tlsConfig_ = nullptr; }
  if (tlsContext_) { SSL_CTX_free(tlsContext_); tlsContext_ = nullptr; }
  if (nativeConfig_) { quic_config_free(nativeConfig_); nativeConfig_ = nullptr; }
  config_ = {};
  localAddress_ = {};
  importedZeroRtt_ = false;
  callbackError_.clear();
  nextConnectionId_ = 1;
  nextTimeoutRawNs_ = 0;
  configured_ = false;
  localAddressSet_ = false;
  counters_ = {};
  ticketKey_.fill(0);
  error = {};
  return true;
}

} // namespace

std::unique_ptr<Adapter> makeTransportAdapter()
{
  return std::make_unique<TquicAdapter>();
}

} // namespace quicperf
