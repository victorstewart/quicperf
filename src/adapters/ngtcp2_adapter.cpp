#include "adapter_factory.h"
#include "core/strict_config.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace quicperf {
namespace {

constexpr size_t connectionIdLength = 8;
constexpr size_t applicationBufferBytes = 256 * 1024;
constexpr uint64_t datagramFrameBytes = 1'200;
constexpr uint64_t maxAckDelayNs = 25'000'000;
constexpr uint64_t ticketLifetimeSeconds = 300;
constexpr std::array<uint8_t, 8> alpn = {7, 'q', 'p', 'e', 'r', 'f', '/', '2'};
constexpr uint32_t resumptionMagic = 0x51505253U;
std::atomic<uint64_t> frozenTlsUnixSeconds {0};

bool remoteInitiated(uint64_t streamId, EndpointRole role) noexcept
{
  const bool initiatedByServer = (streamId & 1U) != 0;
  return initiatedByServer == (role == EndpointRole::client);
}

void frozenTlsTime(const SSL*, timeval* clock)
{
  clock->tv_sec = static_cast<time_t>(frozenTlsUnixSeconds.load(std::memory_order_relaxed));
  clock->tv_usec = 0;
}

bool sameAddress(const sockaddr_in& left, const sockaddr_in& right) noexcept
{
  return left.sin_family == AF_INET && right.sin_family == AF_INET &&
      left.sin_port == right.sin_port && left.sin_addr.s_addr == right.sin_addr.s_addr;
}

std::string cidKey(const uint8_t* data, size_t length)
{
  return std::string(reinterpret_cast<const char*>(data), length);
}

void storeU32(std::byte* destination, uint32_t value)
{
  value = htonl(value);
  std::memcpy(destination, &value, sizeof(value));
}

uint32_t loadU32(const std::byte* source)
{
  uint32_t value = 0;
  std::memcpy(&value, source, sizeof(value));
  return ntohl(value);
}

std::string tlsError(std::string prefix)
{
  const unsigned long code = ERR_get_error();
  if (!code) return prefix;
  prefix += ": ";
  prefix += ERR_error_string(code, nullptr);
  return prefix;
}

class Ngtcp2Adapter final : public Adapter {
public:
  Ngtcp2Adapter();
  ~Ngtcp2Adapter() override;

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
  bool peerTerminalFacts(uint64_t connectionId, uint64_t streamId, uint64_t,
                         PeerTerminalFacts& facts, AdapterError& error) override;
  bool closeConnection(uint64_t connectionId, uint64_t applicationError,
                       uint64_t, AdapterError& error) override;
  TransportCounters snapshotTransportCounters() const noexcept override;
  NegotiatedSettings snapshotNegotiatedSettings() const noexcept override;
  bool reset(AdapterError& error) override;
  bool stop(AdapterError& error) override { return reset(error); }

private:
  struct TransmitChunk {
    uint64_t offset = 0;
    std::vector<std::byte> bytes;
    size_t submitted = 0;
    bool abandoned = false;
  };

  struct Stream {
    std::vector<std::byte> received;
    uint64_t receiveOffset = 0;
    bool remoteFin = false;
    bool remoteReset = false;
    uint64_t remoteResetError = 0;
    bool accepted = false;
    std::deque<TransmitChunk> transmit;
    uint64_t nextTransmitOffset = 0;
    uint64_t acknowledgedTransmitOffset = 0;
    bool finPending = false;
    bool finSent = false;
    bool transmitScheduled = false;

    TransmitChunk* firstUnsubmitted() noexcept
    {
      const auto found = std::find_if(transmit.begin(), transmit.end(), [](const auto& chunk) {
        return !chunk.abandoned && chunk.submitted < chunk.bytes.size();
      });
      return found == transmit.end() ? nullptr : &*found;
    }

    bool hasUnsubmitted() const noexcept
    {
      return std::ranges::any_of(transmit, [](const auto& chunk) {
        return !chunk.abandoned && chunk.submitted < chunk.bytes.size();
      });
    }

    size_t abandonUnsubmitted() noexcept
    {
      size_t abandoned = 0;
      for (auto& chunk : transmit)
      {
        if (chunk.abandoned) continue;
        abandoned += chunk.bytes.size() - chunk.submitted;
        chunk.abandoned = true;
      }
      return abandoned;
    }
  };

  struct PendingDatagram {
    uint64_t id = 0;
    std::vector<std::byte> bytes;
  };

  struct Connection {
    Connection(Ngtcp2Adapter& adapter, uint64_t identifier, const sockaddr_in& localAddress,
               const sockaddr_in& peerAddress)
        : owner(adapter), id(identifier), local(localAddress), peer(peerAddress),
          reference {getConnection, this}
    {}
    ~Connection()
    {
      if (conn) ngtcp2_conn_del(conn);
      if (ssl) SSL_free(ssl);
    }

    static ngtcp2_conn* getConnection(ngtcp2_crypto_conn_ref* reference)
    {
      return static_cast<Connection*>(reference->user_data)->conn;
    }

    Ngtcp2Adapter& owner;
    uint64_t id;
    sockaddr_in local {};
    sockaddr_in peer {};
    ngtcp2_conn* conn = nullptr;
    SSL* ssl = nullptr;
    ngtcp2_crypto_conn_ref reference {};
    std::map<int64_t, Stream> streams;
    std::deque<int64_t> transmitStreams;
    std::deque<int64_t> acceptedBidirectionalStreams;
    std::deque<int64_t> acceptedUnidirectionalStreams;
    std::optional<int64_t> controlStreamId;
    std::deque<std::vector<std::byte>> receivedDatagrams;
    std::deque<PendingDatagram> transmitDatagrams;
    uint64_t nextDatagramId = 1;
    size_t queuedDataBytes = 0;
    bool accepted = false;
    bool handshakeCompleted = false;
    bool handshakeConfirmed = false;
    bool resumed = false;
    bool zeroRttAttempted = false;
    bool zeroRttAccepted = false;
    bool zeroRttRejected = false;
    size_t earlyDataBytes = 0;
    bool closePending = false;
    bool closeWritten = false;
    bool releaseWhenClosed = false;
    bool remoteConnectionClose = false;
    uint64_t closeError = 0;
    int tlsVerifyError = X509_V_OK;
    std::vector<std::byte> session;
    std::vector<std::byte> zeroRttTransportParameters;
  };

  struct ImportedState {
    std::vector<std::byte> session;
    std::vector<std::byte> transportParameters;
    bool zeroRtt = false;
    std::string identity;
  };

  static void randomBytes(uint8_t* destination, size_t length, const ngtcp2_rand_ctx*);
  static int newConnectionId(ngtcp2_conn*, ngtcp2_cid* cid,
                             ngtcp2_stateless_reset_token* token, size_t length,
                             void* userData);
  static int removeConnectionId(ngtcp2_conn*, const ngtcp2_cid* cid, void* userData);
  static int streamOpened(ngtcp2_conn*, int64_t streamId, void* userData);
  static int streamData(ngtcp2_conn*, uint32_t flags, int64_t streamId, uint64_t offset,
                        const uint8_t* data, size_t length, void* userData, void*);
  static int streamDataAcknowledged(ngtcp2_conn*, int64_t streamId, uint64_t offset,
                                    uint64_t length, void* userData, void*);
  static int streamClosed(ngtcp2_conn*, uint32_t, int64_t streamId, uint64_t,
                          void* userData, void*);
  static int streamReset(ngtcp2_conn*, int64_t streamId, uint64_t,
                         uint64_t applicationError, void* userData, void*);
  static int datagramReceived(ngtcp2_conn*, uint32_t, const uint8_t* data, size_t length,
                              void* userData);
  static int handshakeCompleted(ngtcp2_conn*, void* userData);
  static int handshakeConfirmed(ngtcp2_conn*, void* userData);
  static int earlyDataRejected(ngtcp2_conn*, void* userData);
  static int newSession(SSL* ssl, SSL_SESSION* session);
  static int verifyCertificate(int ok, X509_STORE_CTX* context);
  static int selectAlpn(SSL*, const uint8_t** output, uint8_t* outputLength,
                        const uint8_t* input, unsigned inputLength, void*);

  static ngtcp2_callbacks callbacks(bool server);
  ngtcp2_settings settings(uint64_t nowRawNs) const;
  ngtcp2_transport_params transportParameters() const;
  bool initializeTlsContext(AdapterError& error);
  bool initializeTls(Connection& connection, AdapterError& error);
  Connection* createClient(const sockaddr_in& peer, uint64_t nowRawNs, AdapterError& error);
  Connection* createServer(const ReceivedPacket& packet, uint64_t nowRawNs,
                           AdapterError& error);
  static bool active(const Connection& connection) noexcept;
  size_t activeConnectionCount() const noexcept;
  Connection* find(uint64_t id, AdapterError& error) const;
  Connection* route(std::span<const std::byte> packet) const;
  bool registerCid(Connection& connection, const ngtcp2_cid& cid);
  void unregisterCid(Connection& connection, const ngtcp2_cid& cid);
  void eraseCidMappings(Connection& connection);
  bool reapReleasedConnections(AdapterError& error);
  ngtcp2_path path(Connection& connection) const;
  bool writePacket(Connection& connection, std::span<std::byte> destination,
                   uint64_t nowRawNs, TransmitPacket& packet, AdapterError& error);
  void updateTimeout() noexcept;
  bool validError(int code, std::string_view operation, AdapterError& error) const;

  Capabilities capabilities_;
  EndpointConfig config_ {};
  sockaddr_in localAddress_ {};
  SSL_CTX* tlsContext_ = nullptr;
  std::vector<std::unique_ptr<Connection>> connections_;
  std::unordered_map<uint64_t, Connection*> connectionsById_;
  std::unordered_map<std::string, Connection*> connectionsByCid_;
  std::deque<uint64_t> acceptedConnections_;
  std::optional<ImportedState> importedState_;
  std::unordered_set<std::string> consumedTickets_;
  uint64_t nextConnectionId_ = 1;
  uint64_t nextTimeoutRawNs_ = 0;
  size_t transmitCursor_ = 0;
  size_t queuedApplicationBytes_ = 0;
  bool configured_ = false;
  bool localAddressSet_ = false;
  std::array<std::array<std::byte, maxUdpPayloadSize>, packetBatchSize> output_ {};
  TransportCounters counters_ {};
};

Ngtcp2Adapter::Ngtcp2Adapter()
{
  capabilities_.library = "ngtcp2";
  capabilities_.buildId = "ngtcp2-1.22.1-quicperf8-transport-v2";
  capabilities_.adapterAbiVersion = 2;
  capabilities_.server = true;
  capabilities_.client = true;
  capabilities_.backends = {PacketBackend::syscall, PacketBackend::iouring};
  capabilities_.scenarios = {
      workload::Scenario::download, workload::Scenario::upload,
      workload::Scenario::multistreamDownload, workload::Scenario::multistreamUpload,
      workload::Scenario::bidi, workload::Scenario::lossRecovery,
      workload::Scenario::flowControl, workload::Scenario::smallPayloadPps,
      workload::Scenario::datagram, workload::Scenario::reqresp,
      workload::Scenario::streamChurn, workload::Scenario::connect,
      workload::Scenario::resumedConnect, workload::Scenario::zeroRttReqresp,
      workload::Scenario::closeResetCleanup, workload::Scenario::memoryCurve};
  capabilities_.datagram = true;
  capabilities_.resumption = true;
  capabilities_.earlyData = true;
  capabilities_.effectiveFeatures = {
      "common_cpp_packet_io", "borrowed_packet_batch_64", "ipv4",
      "quic_v1", "tls_1_3", "tls_aes_128_gcm_sha256", "x25519",
      "qperf_2_alpn", "bidirectional_stream", "unidirectional_stream",
      "datagram", "resumption", "early_data", "post_bind_local_address",
      "reset_stream", "stop_sending", "connection_close",
      "peer_terminal_facts",
      "exact_retransmission_counter_unavailable"};
}

Ngtcp2Adapter::~Ngtcp2Adapter()
{
  AdapterError ignored;
  reset(ignored);
}

bool Ngtcp2Adapter::validError(int code, std::string_view operation, AdapterError& error) const
{
  if (code == 0) return true;
  error.code = static_cast<uint64_t>(-static_cast<int64_t>(code));
  error.message = std::string(operation) + ": " + ngtcp2_strerror(code);
  return false;
}

void Ngtcp2Adapter::randomBytes(uint8_t* destination, size_t length, const ngtcp2_rand_ctx*)
{
  if (length > static_cast<size_t>(std::numeric_limits<int>::max()) ||
      RAND_bytes(destination, static_cast<int>(length)) != 1)
    std::abort();
}

int Ngtcp2Adapter::newConnectionId(ngtcp2_conn*, ngtcp2_cid* cid,
                                   ngtcp2_stateless_reset_token* token, size_t length,
                                   void* userData)
{
  auto& connection = *static_cast<Connection*>(userData);
  if (length != connectionIdLength ||
      RAND_bytes(cid->data, static_cast<int>(length)) != 1 ||
      RAND_bytes(token->data, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  cid->datalen = length;
  if (!connection.owner.registerCid(connection, *cid))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  return 0;
}

int Ngtcp2Adapter::removeConnectionId(ngtcp2_conn*, const ngtcp2_cid* cid, void* userData)
{
  auto& connection = *static_cast<Connection*>(userData);
  connection.owner.unregisterCid(connection, *cid);
  return 0;
}

int Ngtcp2Adapter::streamOpened(ngtcp2_conn*, int64_t streamId, void* userData)
{
  auto& connection = *static_cast<Connection*>(userData);
  auto& stream = connection.streams[streamId];
  if (!stream.accepted)
  {
    stream.accepted = true;
    if ((streamId & 0x2) == 0)
    {
      if (!connection.controlStreamId || streamId < *connection.controlStreamId)
        connection.controlStreamId = streamId;
      connection.acceptedBidirectionalStreams.push_back(streamId);
    }
    else
      connection.acceptedUnidirectionalStreams.push_back(streamId);
  }
  return 0;
}

int Ngtcp2Adapter::streamData(ngtcp2_conn* conn, uint32_t flags, int64_t streamId,
                              uint64_t offset, const uint8_t* data, size_t length,
                              void* userData, void*)
{
  auto& connection = *static_cast<Connection*>(userData);
  auto& stream = connection.streams[streamId];
  if (!stream.accepted)
  {
    stream.accepted = true;
    if ((streamId & 0x2) == 0)
    {
      if (!connection.controlStreamId || streamId < *connection.controlStreamId)
        connection.controlStreamId = streamId;
      connection.acceptedBidirectionalStreams.push_back(streamId);
    }
    else
      connection.acceptedUnidirectionalStreams.push_back(streamId);
  }
  if (stream.receiveOffset > std::numeric_limits<uint64_t>::max() - stream.received.size())
    return NGTCP2_ERR_CALLBACK_FAILURE;
  const uint64_t bufferedEnd = stream.receiveOffset + stream.received.size();
  if (offset > bufferedEnd || length > std::numeric_limits<uint64_t>::max() - offset)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  const uint64_t packetEnd = offset + length;
  if (packetEnd > bufferedEnd)
  {
    const size_t skip = static_cast<size_t>(bufferedEnd - offset);
    const auto* first = reinterpret_cast<const std::byte*>(data + skip);
    stream.received.insert(stream.received.end(), first, first + (length - skip));
  }
  if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) stream.remoteFin = true;
  (void)conn;
  return 0;
}

int Ngtcp2Adapter::streamDataAcknowledged(ngtcp2_conn*, int64_t streamId,
                                          uint64_t offset, uint64_t length,
                                          void* userData, void*)
{
  auto& connection = *static_cast<Connection*>(userData);
  const auto found = connection.streams.find(streamId);
  if (found == connection.streams.end()) return NGTCP2_ERR_CALLBACK_FAILURE;
  Stream& stream = found->second;
  if (offset != stream.acknowledgedTransmitOffset ||
      length > std::numeric_limits<uint64_t>::max() - offset)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  stream.acknowledgedTransmitOffset = offset + length;
  while (!stream.transmit.empty())
  {
    const auto& chunk = stream.transmit.front();
    if (chunk.offset > std::numeric_limits<uint64_t>::max() - chunk.bytes.size() ||
        chunk.offset + chunk.bytes.size() > stream.acknowledgedTransmitOffset)
      break;
    stream.transmit.pop_front();
  }
  return 0;
}

int Ngtcp2Adapter::streamClosed(ngtcp2_conn* conn, uint32_t, int64_t streamId, uint64_t,
                                void* userData, void*)
{
  auto& connection = *static_cast<Connection*>(userData);
  const auto found = connection.streams.find(streamId);
  if (found == connection.streams.end()) return 0;
  Stream& stream = found->second;
  const size_t abandoned = stream.abandonUnsubmitted();
  const bool control = connection.controlStreamId && *connection.controlStreamId == streamId;
  if (abandoned > connection.owner.queuedApplicationBytes_ ||
      (!control && abandoned > connection.queuedDataBytes))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  connection.owner.queuedApplicationBytes_ -= abandoned;
  if (!control) connection.queuedDataBytes -= abandoned;
  stream.transmit.clear();
  stream.finSent = true;
  if (remoteInitiated(static_cast<uint64_t>(streamId), connection.owner.config_.role))
  {
    if ((streamId & 0x2) == 0)
      ngtcp2_conn_extend_max_streams_bidi(conn, 1);
    else
      ngtcp2_conn_extend_max_streams_uni(conn, 1);
  }
  return 0;
}

int Ngtcp2Adapter::streamReset(ngtcp2_conn*, int64_t streamId, uint64_t,
                               uint64_t applicationError, void* userData, void*)
{
  auto& stream = static_cast<Connection*>(userData)->streams[streamId];
  stream.remoteReset = true;
  stream.remoteResetError = applicationError;
  return 0;
}

int Ngtcp2Adapter::datagramReceived(ngtcp2_conn*, uint32_t, const uint8_t* data,
                                    size_t length, void* userData)
{
  auto& connection = *static_cast<Connection*>(userData);
  const auto* first = reinterpret_cast<const std::byte*>(data);
  connection.receivedDatagrams.emplace_back(first, first + length);
  return 0;
}

int Ngtcp2Adapter::handshakeCompleted(ngtcp2_conn* conn, void* userData)
{
  auto& connection = *static_cast<Connection*>(userData);
  const SSL_CIPHER* cipher = connection.ssl ? SSL_get_current_cipher(connection.ssl) : nullptr;
  if (!cipher || std::strcmp(SSL_CIPHER_get_name(cipher), "TLS_AES_128_GCM_SHA256") != 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  connection.handshakeCompleted = true;
  connection.resumed = connection.ssl && SSL_session_reused(connection.ssl);
  connection.zeroRttAccepted = connection.zeroRttAttempted && connection.ssl &&
      SSL_early_data_accepted(connection.ssl);
  connection.zeroRttRejected = connection.zeroRttAttempted &&
      (!connection.zeroRttAccepted || ngtcp2_conn_get_tls_early_data_rejected(conn));
  std::array<uint8_t, 512> parameters {};
  const ngtcp2_ssize length = ngtcp2_conn_encode_0rtt_transport_params(
      conn, parameters.data(), parameters.size());
  if (length > 0)
  {
    const auto* first = reinterpret_cast<const std::byte*>(parameters.data());
    connection.zeroRttTransportParameters.assign(first, first + length);
  }
  return 0;
}

int Ngtcp2Adapter::handshakeConfirmed(ngtcp2_conn*, void* userData)
{
  static_cast<Connection*>(userData)->handshakeConfirmed = true;
  return 0;
}

int Ngtcp2Adapter::earlyDataRejected(ngtcp2_conn*, void* userData)
{
  static_cast<Connection*>(userData)->zeroRttRejected = true;
  return 0;
}

int Ngtcp2Adapter::newSession(SSL* ssl, SSL_SESSION* session)
{
  const auto* reference = static_cast<ngtcp2_crypto_conn_ref*>(SSL_get_app_data(ssl));
  if (!reference || !reference->user_data) return 0;
  auto& connection = *static_cast<Connection*>(reference->user_data);
  uint8_t* encoded = nullptr;
  size_t length = 0;
  if (SSL_SESSION_to_bytes(session, &encoded, &length) != 1) return 0;
  const auto* first = reinterpret_cast<const std::byte*>(encoded);
  connection.session.assign(first, first + length);
  OPENSSL_free(encoded);
  return 0;
}

int Ngtcp2Adapter::verifyCertificate(int ok, X509_STORE_CTX* context)
{
  auto* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(
      context, SSL_get_ex_data_X509_STORE_CTX_idx()));
  auto* reference = ssl ?
      static_cast<ngtcp2_crypto_conn_ref*>(SSL_get_app_data(ssl)) : nullptr;
  auto* connection = reference && reference->user_data ?
      static_cast<Connection*>(reference->user_data) : nullptr;
  if (!ok)
  {
    if (connection) connection->tlsVerifyError = X509_STORE_CTX_get_error(context);
    return 0;
  }
  if (connection && X509_STORE_CTX_get_error_depth(context) == 0)
  {
    X509* certificate = X509_STORE_CTX_get_current_cert(context);
    if (!certificate || X509_check_host(
        certificate, connection->owner.config_.tlsHostname.c_str(),
        connection->owner.config_.tlsHostname.size(),
        X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) != 1)
    {
      connection->tlsVerifyError = X509_V_ERR_HOSTNAME_MISMATCH;
      X509_STORE_CTX_set_error(context, X509_V_ERR_HOSTNAME_MISMATCH);
      return 0;
    }
  }
  return 1;
}

int Ngtcp2Adapter::selectAlpn(SSL*, const uint8_t** output, uint8_t* outputLength,
                              const uint8_t* input, unsigned inputLength, void*)
{
  size_t offset = 0;
  while (offset < inputLength)
  {
    const size_t length = input[offset++];
    if (length > inputLength - offset) return SSL_TLSEXT_ERR_ALERT_FATAL;
    if (length == alpn[0] &&
        std::equal(input + offset, input + offset + length, alpn.begin() + 1))
    {
      *output = input + offset;
      *outputLength = static_cast<uint8_t>(length);
      return SSL_TLSEXT_ERR_OK;
    }
    offset += length;
  }
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

ngtcp2_callbacks Ngtcp2Adapter::callbacks(bool server)
{
  ngtcp2_callbacks value {};
  value.client_initial = server ? nullptr : ngtcp2_crypto_client_initial_cb;
  value.recv_client_initial = server ? ngtcp2_crypto_recv_client_initial_cb : nullptr;
  value.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  value.encrypt = ngtcp2_crypto_encrypt_cb;
  value.decrypt = ngtcp2_crypto_decrypt_cb;
  value.hp_mask = ngtcp2_crypto_hp_mask_cb;
  value.recv_stream_data = streamData;
  value.acked_stream_data_offset = streamDataAcknowledged;
  value.stream_open = streamOpened;
  value.stream_close = streamClosed;
  value.stream_reset = streamReset;
  value.recv_retry = server ? nullptr : ngtcp2_crypto_recv_retry_cb;
  value.rand = randomBytes;
  value.update_key = ngtcp2_crypto_update_key_cb;
  value.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  value.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  value.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  value.get_new_connection_id2 = newConnectionId;
  value.remove_connection_id = removeConnectionId;
  value.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
  value.handshake_completed = handshakeCompleted;
  value.handshake_confirmed = handshakeConfirmed;
  value.recv_datagram = datagramReceived;
  value.tls_early_data_rejected = earlyDataRejected;
  return value;
}

ngtcp2_settings Ngtcp2Adapter::settings(uint64_t nowRawNs) const
{
  ngtcp2_settings value;
  ngtcp2_settings_default(&value);
  value.initial_ts = nowRawNs;
  value.cc_algo = config_.congestionController == "bbr" ? NGTCP2_CC_ALGO_BBR :
      config_.congestionController == "reno" ? NGTCP2_CC_ALGO_RENO : NGTCP2_CC_ALGO_CUBIC;
  value.max_window = config_.connectionWindow;
  value.max_stream_window = config_.streamWindow;
  value.max_tx_udp_payload_size = config_.maxUdpPayloadSize;
  value.no_tx_udp_payload_size_shaping = 1;
  return value;
}

ngtcp2_transport_params Ngtcp2Adapter::transportParameters() const
{
  ngtcp2_transport_params value;
  ngtcp2_transport_params_default(&value);
  value.initial_max_streams_bidi = config_.maxBidiStreams;
  value.initial_max_streams_uni = config_.maxUniStreams;
  value.initial_max_stream_data_bidi_local = config_.streamWindow;
  value.initial_max_stream_data_bidi_remote = config_.streamWindow;
  value.initial_max_stream_data_uni = config_.streamWindow;
  value.initial_max_data = config_.connectionWindow;
  value.max_idle_timeout = config_.idleTimeoutMs * NGTCP2_MILLISECONDS;
  value.max_udp_payload_size = config_.maxUdpPayloadSize;
  value.active_connection_id_limit = 2;
  value.ack_delay_exponent = 3;
  value.max_ack_delay = maxAckDelayNs;
  value.max_datagram_frame_size = datagramFrameBytes;
  value.disable_active_migration = 1;
  return value;
}

bool Ngtcp2Adapter::initializeTlsContext(AdapterError& error)
{
  constexpr uint16_t signatureAlgorithms[] = {SSL_SIGN_ED25519};
  tlsContext_ = SSL_CTX_new(config_.role == EndpointRole::server ? TLS_server_method() :
                                                                TLS_client_method());
  if (!tlsContext_)
  {
    error = {10, tlsError("SSL_CTX_new")};
    return false;
  }
  const int configured = config_.role == EndpointRole::server ?
      ngtcp2_crypto_boringssl_configure_server_context(tlsContext_) :
      ngtcp2_crypto_boringssl_configure_client_context(tlsContext_);
  if (configured != 0 || SSL_CTX_set_min_proto_version(tlsContext_, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(tlsContext_, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set1_groups_list(tlsContext_, "X25519") != 1 ||
      SSL_CTX_set_signing_algorithm_prefs(tlsContext_, signatureAlgorithms,
                                          std::size(signatureAlgorithms)) != 1 ||
      SSL_CTX_set_verify_algorithm_prefs(tlsContext_, signatureAlgorithms,
                                         std::size(signatureAlgorithms)) != 1)
  {
    error = {10, tlsError("failed to configure frozen TLS policy")};
    return false;
  }
  SSL_CTX_set_early_data_enabled(tlsContext_, 1);
  SSL_CTX_set_current_time_cb(tlsContext_, frozenTlsTime);
  X509_VERIFY_PARAM_set_time_posix(
      SSL_CTX_get0_param(tlsContext_), config_.calendarUnixSeconds);
  SSL_CTX_set_session_psk_dhe_timeout(tlsContext_, ticketLifetimeSeconds);
  SSL_CTX_set_num_tickets(tlsContext_, 1);

  if (config_.role == EndpointRole::server)
  {
    if (SSL_CTX_use_PrivateKey_file(tlsContext_, config_.privateKeyPath.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_certificate_chain_file(tlsContext_, config_.certificatePath.c_str()) != 1 ||
        SSL_CTX_check_private_key(tlsContext_) != 1)
    {
      error = {10, tlsError("failed to load server certificate or private key")};
      return false;
    }
    BIO* chain = BIO_new_file(config_.chainPath.c_str(), "r");
    if (!chain)
    {
      error = {10, tlsError("failed to open server certificate chain")};
      return false;
    }
    size_t chainCertificates = 0;
    while (X509* certificate = PEM_read_bio_X509(chain, nullptr, nullptr, nullptr))
    {
      const int added = SSL_CTX_add1_chain_cert(tlsContext_, certificate);
      X509_free(certificate);
      if (added != 1)
      {
        BIO_free(chain);
        error = {10, tlsError("failed to install server certificate chain")};
        return false;
      }
      ++chainCertificates;
    }
    BIO_free(chain);
    ERR_clear_error();
    if (!chainCertificates)
    {
      error = {10, "server certificate chain is empty"};
      return false;
    }
    std::array<uint8_t, 48> ticketKey {};
    if (RAND_bytes(ticketKey.data(), ticketKey.size()) != 1 ||
        SSL_CTX_set_tlsext_ticket_keys(tlsContext_, ticketKey.data(), ticketKey.size()) != 1)
    {
      error = {10, tlsError("failed to configure TLS ticket key")};
      return false;
    }
    SSL_CTX_set_alpn_select_cb(tlsContext_, selectAlpn, nullptr);
  }
  else
  {
    SSL_CTX_set_session_cache_mode(tlsContext_, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_new_cb(tlsContext_, newSession);
    if (config_.tlsVerifyPeer)
    {
      if (SSL_CTX_load_verify_locations(tlsContext_, config_.chainPath.c_str(), nullptr) != 1)
      {
        error = {10, tlsError("failed to load TLS trust chain")};
        return false;
      }
      SSL_CTX_set_verify(tlsContext_, SSL_VERIFY_PEER, verifyCertificate);
    }
    else
    {
      SSL_CTX_set_verify(tlsContext_, SSL_VERIFY_NONE, nullptr);
    }
  }
  return true;
}

bool Ngtcp2Adapter::configure(std::string_view canonicalConfig, AdapterError& error)
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
      parsed.config.congestionController != "bbr" &&
      parsed.config.congestionController != "reno")
  {
    error = {1, "ngtcp2 cannot honor the requested congestion controller"};
    return false;
  }
  config_ = parsed.config;
  if (config_.calendarUnixSeconds == 0 ||
      config_.calendarUnixSeconds > static_cast<uint64_t>(std::numeric_limits<time_t>::max()))
  {
    error = {1, "ngtcp2 frozen TLS calendar time is out of range"};
    return false;
  }
  uint64_t expected = 0;
  if (!frozenTlsUnixSeconds.compare_exchange_strong(
          expected, config_.calendarUnixSeconds, std::memory_order_relaxed) &&
      expected != config_.calendarUnixSeconds)
  {
    error = {1, "ngtcp2 worker calendar time changed after initialization"};
    return false;
  }
  if (!initializeTlsContext(error))
  {
    reset(ignored);
    return false;
  }
  configured_ = true;
  error = {};
  return true;
}

bool Ngtcp2Adapter::setLocalAddress(const sockaddr_in& local, AdapterError& error)
{
  if (!configured_ || !connections_.empty() || local.sin_family != AF_INET ||
      local.sin_port == 0)
  {
    error = {1, "post-bind local address must be set once before connection creation"};
    return false;
  }
  in_addr configuredAddress {};
  if (inet_pton(AF_INET, config_.bindAddress.c_str(), &configuredAddress) != 1 ||
      (configuredAddress.s_addr != htonl(INADDR_ANY) &&
       configuredAddress.s_addr != local.sin_addr.s_addr) ||
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

ngtcp2_path Ngtcp2Adapter::path(Connection& connection) const
{
  ngtcp2_path value {};
  value.local.addr = reinterpret_cast<sockaddr*>(&connection.local);
  value.local.addrlen = sizeof(connection.local);
  value.remote.addr = reinterpret_cast<sockaddr*>(&connection.peer);
  value.remote.addrlen = sizeof(connection.peer);
  return value;
}

bool Ngtcp2Adapter::registerCid(Connection& connection, const ngtcp2_cid& cid)
{
  const std::string key = cidKey(cid.data, cid.datalen);
  const auto [found, inserted] = connectionsByCid_.emplace(key, &connection);
  return inserted || found->second == &connection;
}

void Ngtcp2Adapter::unregisterCid(Connection& connection, const ngtcp2_cid& cid)
{
  const auto found = connectionsByCid_.find(cidKey(cid.data, cid.datalen));
  if (found != connectionsByCid_.end() && found->second == &connection)
    connectionsByCid_.erase(found);
}

void Ngtcp2Adapter::eraseCidMappings(Connection& connection)
{
  for (auto iterator = connectionsByCid_.begin(); iterator != connectionsByCid_.end();)
  {
    if (iterator->second == &connection) iterator = connectionsByCid_.erase(iterator);
    else ++iterator;
  }
}

bool Ngtcp2Adapter::reapReleasedConnections(AdapterError& error)
{
  bool erased = false;
  for (auto iterator = connections_.begin(); iterator != connections_.end();)
  {
    Connection& connection = **iterator;
    const bool closed = connection.closeWritten || connection.remoteConnectionClose ||
        ngtcp2_conn_in_closing_period(connection.conn) ||
        ngtcp2_conn_in_draining_period(connection.conn);
    if (!connection.releaseWhenClosed || !closed)
    {
      ++iterator;
      continue;
    }
    size_t abandoned = 0;
    for (const auto& [streamId, stream] : connection.streams)
    {
      (void)streamId;
      for (const auto& chunk : stream.transmit)
      {
        if (chunk.abandoned) continue;
        const size_t pending = chunk.bytes.size() - chunk.submitted;
        if (pending > std::numeric_limits<size_t>::max() - abandoned)
        {
          error = {1, "ngtcp2 released connection queue accounting overflow"};
          return false;
        }
        abandoned += pending;
      }
    }
    if (abandoned > queuedApplicationBytes_)
    {
      error = {1, "ngtcp2 released connection queue accounting underflow"};
      return false;
    }
    queuedApplicationBytes_ -= abandoned;
    eraseCidMappings(connection);
    connectionsById_.erase(connection.id);
    std::erase(acceptedConnections_, connection.id);
    iterator = connections_.erase(iterator);
    erased = true;
  }
  if (erased) transmitCursor_ = 0;
  error = {};
  return true;
}

bool Ngtcp2Adapter::initializeTls(Connection& connection, AdapterError& error)
{
  connection.ssl = SSL_new(tlsContext_);
  if (!connection.ssl)
  {
    error = {10, tlsError("SSL_new")};
    return false;
  }
  SSL_set_app_data(connection.ssl, &connection.reference);
  if (config_.role == EndpointRole::server)
  {
    SSL_set_accept_state(connection.ssl);
    std::array<uint8_t, 512> context {};
    const ngtcp2_ssize length = ngtcp2_conn_encode_0rtt_transport_params(
        connection.conn, context.data(), context.size());
    if (length <= 0 || SSL_set_quic_early_data_context(
        connection.ssl, context.data(), static_cast<size_t>(length)) != 1)
    {
      error = {10, tlsError("failed to configure QUIC early-data context")};
      return false;
    }
  }
  else
  {
    SSL_set_connect_state(connection.ssl);
    if (SSL_set_alpn_protos(connection.ssl, alpn.data(), alpn.size()) != 0)
    {
      error = {10, tlsError("failed to configure client ALPN")};
      return false;
    }
    if (SSL_set_tlsext_host_name(connection.ssl, config_.tlsHostname.c_str()) != 1)
    {
      error = {10, tlsError("failed to configure client SNI")};
      return false;
    }
    if (importedState_)
    {
      connection.zeroRttAttempted = importedState_->zeroRtt;
      SSL_SESSION* session = SSL_SESSION_from_bytes(
          reinterpret_cast<const uint8_t*>(importedState_->session.data()),
          importedState_->session.size(), tlsContext_);
      if (!session || SSL_set_session(connection.ssl, session) != 1)
      {
        if (session) SSL_SESSION_free(session);
        error = {10, tlsError("failed to install imported TLS session")};
        return false;
      }
      SSL_SESSION_free(session);
      if (importedState_->zeroRtt &&
          !validError(ngtcp2_conn_decode_and_set_0rtt_transport_params(
              connection.conn,
              reinterpret_cast<const uint8_t*>(importedState_->transportParameters.data()),
              importedState_->transportParameters.size()),
              "ngtcp2_conn_decode_and_set_0rtt_transport_params", error))
        return false;
      consumedTickets_.insert(importedState_->identity);
      importedState_.reset();
    }
  }
  ngtcp2_conn_set_tls_native_handle(connection.conn, connection.ssl);
  return true;
}

Ngtcp2Adapter::Connection* Ngtcp2Adapter::createClient(
    const sockaddr_in& peer, uint64_t nowRawNs, AdapterError& error)
{
  auto owned = std::make_unique<Connection>(*this, nextConnectionId_++, localAddress_, peer);
  Connection& connection = *owned;
  ngtcp2_cid dcid {}, scid {};
  dcid.datalen = connectionIdLength;
  scid.datalen = connectionIdLength;
  if (RAND_bytes(dcid.data, dcid.datalen) != 1 || RAND_bytes(scid.data, scid.datalen) != 1)
  {
    error = {10, tlsError("failed to generate QUIC connection IDs")};
    return nullptr;
  }
  auto callbackSet = callbacks(false);
  auto settingSet = settings(nowRawNs);
  auto parameters = transportParameters();
  auto connectionPath = path(connection);
  if (!validError(ngtcp2_conn_client_new(
          &connection.conn, &dcid, &scid, &connectionPath, NGTCP2_PROTO_VER_V1,
          &callbackSet, &settingSet, &parameters, nullptr, &connection),
          "ngtcp2_conn_client_new", error))
    return nullptr;
  if (!registerCid(connection, scid))
  {
    error = {1, "generated duplicate ngtcp2 source connection ID"};
    return nullptr;
  }
  if (!initializeTls(connection, error))
  {
    eraseCidMappings(connection);
    return nullptr;
  }
  Connection* result = &connection;
  connectionsById_[connection.id] = result;
  connections_.push_back(std::move(owned));
  return result;
}

Ngtcp2Adapter::Connection* Ngtcp2Adapter::createServer(
    const ReceivedPacket& packet, uint64_t nowRawNs, AdapterError& error)
{
  ngtcp2_pkt_hd header {};
  const auto* bytes = reinterpret_cast<const uint8_t*>(packet.bytes.data());
  const int accepted = ngtcp2_accept(&header, bytes, packet.bytes.size());
  if (accepted != 0 || header.version != NGTCP2_PROTO_VER_V1)
  {
    error = {static_cast<uint64_t>(accepted ? -accepted : 1),
             "packet is not an acceptable QUIC v1 Initial"};
    return nullptr;
  }
  uint64_t nativeConnectionLimit = config_.connectionCount;
  if (config_.scenario == "connect" || config_.scenario == "resumed_connect" ||
      config_.scenario == "zero_rtt_reqresp")
  {
    if (config_.globalOperationSlots >
        std::numeric_limits<uint64_t>::max() - nativeConnectionLimit)
    {
      error = {1, "native lifecycle connection limit overflow"};
      return nullptr;
    }
    nativeConnectionLimit += config_.globalOperationSlots;
  }
  if (activeConnectionCount() >= nativeConnectionLimit)
  {
    error = {1, "received more connections than the bounded native lifecycle count"};
    return nullptr;
  }
  auto owned = std::make_unique<Connection>(
      *this, nextConnectionId_++, localAddress_, packet.peer);
  Connection& connection = *owned;
  ngtcp2_cid source {};
  source.datalen = connectionIdLength;
  if (RAND_bytes(source.data, source.datalen) != 1)
  {
    error = {10, tlsError("failed to generate QUIC connection ID")};
    return nullptr;
  }
  auto callbackSet = callbacks(true);
  auto settingSet = settings(nowRawNs);
  auto parameters = transportParameters();
  parameters.original_dcid = header.dcid;
  parameters.original_dcid_present = 1;
  auto connectionPath = path(connection);
  if (!validError(ngtcp2_conn_server_new(
          &connection.conn, &header.scid, &source, &connectionPath, header.version,
          &callbackSet, &settingSet, &parameters, nullptr, &connection),
          "ngtcp2_conn_server_new", error))
    return nullptr;
  if (!registerCid(connection, source) || !registerCid(connection, header.dcid))
  {
    eraseCidMappings(connection);
    error = {1, "generated duplicate ngtcp2 server connection ID"};
    return nullptr;
  }
  if (!initializeTls(connection, error))
  {
    eraseCidMappings(connection);
    return nullptr;
  }
  connection.accepted = true;
  Connection* result = &connection;
  connectionsById_[connection.id] = result;
  acceptedConnections_.push_back(connection.id);
  connections_.push_back(std::move(owned));
  return result;
}

size_t Ngtcp2Adapter::activeConnectionCount() const noexcept
{
  return std::ranges::count_if(connections_, [](const auto& owned) { return active(*owned); });
}

bool Ngtcp2Adapter::active(const Connection& connection) noexcept
{
  return !connection.closePending &&
      !ngtcp2_conn_in_closing_period(connection.conn) &&
      !ngtcp2_conn_in_draining_period(connection.conn);
}

Ngtcp2Adapter::Connection* Ngtcp2Adapter::find(uint64_t id, AdapterError& error) const
{
  const auto found = connectionsById_.find(id);
  if (found != connectionsById_.end()) return found->second;
  error = {2, "unknown ngtcp2 connection"};
  return nullptr;
}

Ngtcp2Adapter::Connection* Ngtcp2Adapter::route(std::span<const std::byte> packet) const
{
  if (packet.empty()) return nullptr;
  const auto* bytes = reinterpret_cast<const uint8_t*>(packet.data());
  const uint8_t* dcid = nullptr;
  size_t dcidLength = 0;
  if (bytes[0] & 0x80)
  {
    ngtcp2_version_cid versionCid {};
    if (ngtcp2_pkt_decode_version_cid(&versionCid, bytes, packet.size(), connectionIdLength) != 0)
      return nullptr;
    dcid = versionCid.dcid;
    dcidLength = versionCid.dcidlen;
  }
  else
  {
    if (packet.size() < 1 + connectionIdLength) return nullptr;
    dcid = bytes + 1;
    dcidLength = connectionIdLength;
  }
  const auto found = connectionsByCid_.find(cidKey(dcid, dcidLength));
  return found == connectionsByCid_.end() ? nullptr : found->second;
}

bool Ngtcp2Adapter::receiveBatch(std::span<const ReceivedPacket> packets,
                                 uint64_t nowRawNs, AdapterError& error)
{
  if (!configured_ || !localAddressSet_)
  {
    error = {2, "ngtcp2 adapter lacks configured post-bind local address"};
    return false;
  }
  if (packets.size() > packetBatchSize)
  {
    error = {1, "ngtcp2 receive batch exceeds 64 packets"};
    return false;
  }
  for (const auto& packet : packets)
  {
    if (packet.bytes.empty() || packet.bytes.size() > config_.maxUdpPayloadSize ||
        packet.peer.sin_family != AF_INET || (!config_.packetIo.ecn && packet.ecn))
    {
      error = {1, "invalid borrowed receive packet"};
      return false;
    }
    Connection* connection = route(packet.bytes);
    if (!connection &&
        (config_.role == EndpointRole::client ||
         !(std::to_integer<uint8_t>(packet.bytes.front()) & 0x80)))
    {
      // A client cannot establish state from unsolicited input, and an
      // unknown short-header destination cannot establish server state. The
      // packet may be late traffic for a retired lifecycle connection.
      continue;
    }
    if (!connection && config_.role == EndpointRole::server)
      connection = createServer(packet, nowRawNs, error);
    if (!connection) return false;
    if (!sameAddress(connection->peer, packet.peer))
    {
      error = {1, "packet peer changed while active migration is disabled"};
      return false;
    }
    auto connectionPath = path(*connection);
    ngtcp2_pkt_info packetInfo {};
    packetInfo.ecn = packet.ecn & NGTCP2_ECN_MASK;
    ngtcp2_pkt_info* packetInfoPointer = config_.packetIo.ecn ? &packetInfo : nullptr;
    const int status = ngtcp2_conn_read_pkt(
        connection->conn, &connectionPath, packetInfoPointer,
        reinterpret_cast<const uint8_t*>(packet.bytes.data()), packet.bytes.size(), nowRawNs);
    if (status == NGTCP2_ERR_CLOSING || status == NGTCP2_ERR_DRAINING ||
        ngtcp2_conn_in_closing_period(connection->conn) ||
        ngtcp2_conn_in_draining_period(connection->conn))
    {
      if (!connection->closePending) connection->remoteConnectionClose = true;
      if (status == NGTCP2_ERR_CLOSING || status == NGTCP2_ERR_DRAINING) continue;
    }
    if (status == NGTCP2_ERR_CRYPTO)
    {
      std::string message = tlsError("ngtcp2 TLS packet processing");
      if (const char* state = SSL_state_string_long(connection->ssl); state && *state)
        message += ": state=" + std::string(state);
      if (connection->tlsVerifyError != X509_V_OK)
      {
        message += ": ";
        message += X509_verify_cert_error_string(connection->tlsVerifyError);
      }
      error = {static_cast<uint64_t>(-status), std::move(message)};
      return false;
    }
    if (!validError(status, "ngtcp2_conn_read_pkt", error)) return false;
  }
  if (!reapReleasedConnections(error)) return false;
  updateTimeout();
  error = {};
  return true;
}

bool Ngtcp2Adapter::writePacket(Connection& connection, std::span<std::byte> destination,
                                uint64_t nowRawNs, TransmitPacket& packet,
                                AdapterError& error)
{
  if (ngtcp2_conn_in_draining_period(connection.conn) ||
      (ngtcp2_conn_in_closing_period(connection.conn) && connection.closeWritten))
    return false;
  ngtcp2_path_storage pathStorage;
  ngtcp2_path_storage_zero(&pathStorage);
  ngtcp2_pkt_info packetInfo {};
  ngtcp2_pkt_info* packetInfoPointer = config_.packetIo.ecn ? &packetInfo : nullptr;
  ngtcp2_ssize written = 0;

  if (connection.closePending && !connection.closeWritten)
  {
    ngtcp2_ccerr closeError;
    ngtcp2_ccerr_default(&closeError);
    ngtcp2_ccerr_set_application_error(&closeError, connection.closeError, nullptr, 0);
    written = ngtcp2_conn_write_connection_close(
        connection.conn, &pathStorage.path, packetInfoPointer,
        reinterpret_cast<uint8_t*>(destination.data()), destination.size(), &closeError,
        nowRawNs);
    if (written >= 0) connection.closeWritten = written > 0;
  }
  else if (!connection.transmitDatagrams.empty())
  {
    auto& datagram = connection.transmitDatagrams.front();
    int accepted = 0;
    written = ngtcp2_conn_write_datagram(
        connection.conn, &pathStorage.path, packetInfoPointer,
        reinterpret_cast<uint8_t*>(destination.data()), destination.size(), &accepted,
        NGTCP2_WRITE_DATAGRAM_FLAG_NONE, datagram.id,
        reinterpret_cast<const uint8_t*>(datagram.bytes.data()), datagram.bytes.size(),
        nowRawNs);
    if (accepted)
    {
      if (datagram.bytes.size() > connection.queuedDataBytes)
      {
        error = {1, "ngtcp2 DATAGRAM queue accounting underflow"};
        return false;
      }
      queuedApplicationBytes_ -= datagram.bytes.size();
      connection.queuedDataBytes -= datagram.bytes.size();
      connection.transmitDatagrams.pop_front();
    }
  }
  else
  {
    int64_t streamId = -1;
    ngtcp2_vec vector {};
    size_t vectorCount = 0;
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
    Stream* stream = nullptr;
    TransmitChunk* chunk = nullptr;
    while (!connection.transmitStreams.empty())
    {
      streamId = connection.transmitStreams.front();
      connection.transmitStreams.pop_front();
      const auto streamIterator = connection.streams.find(streamId);
      if (streamIterator == connection.streams.end()) continue;
      stream = &streamIterator->second;
      stream->transmitScheduled = false;
      if (stream->hasUnsubmitted() || (stream->finPending && !stream->finSent)) break;
      stream = nullptr;
      streamId = -1;
    }
    if (stream)
    {
      chunk = stream->firstUnsubmitted();
      if (chunk)
      {
        vector.base = reinterpret_cast<uint8_t*>(chunk->bytes.data() + chunk->submitted);
        vector.len = chunk->bytes.size() - chunk->submitted;
        vectorCount = 1;
      }
      const size_t pendingChunks = std::ranges::count_if(
          stream->transmit, [](const auto& item) {
            return !item.abandoned && item.submitted < item.bytes.size();
          });
      if (stream->finPending && pendingChunks <= 1)
        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }
    ngtcp2_ssize accepted = -1;
    written = ngtcp2_conn_writev_stream(
        connection.conn, &pathStorage.path, packetInfoPointer,
        reinterpret_cast<uint8_t*>(destination.data()), destination.size(), &accepted,
        flags, streamId, vectorCount ? &vector : nullptr, vectorCount, nowRawNs);
    if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED)
    {
      written = ngtcp2_conn_write_pkt(
          connection.conn, &pathStorage.path, packetInfoPointer,
          reinterpret_cast<uint8_t*>(destination.data()), destination.size(), nowRawNs);
    }
    else if (written == NGTCP2_ERR_STREAM_SHUT_WR && stream)
    {
      const size_t abandoned = stream->abandonUnsubmitted();
      if (abandoned > queuedApplicationBytes_)
      {
        error = {1, "ngtcp2 stream queue accounting underflow"};
        return false;
      }
      queuedApplicationBytes_ -= abandoned;
      const bool control = connection.controlStreamId && *connection.controlStreamId == streamId;
      if (!control)
      {
        if (abandoned > connection.queuedDataBytes)
        {
          error = {1, "ngtcp2 connection queue accounting underflow"};
          return false;
        }
        connection.queuedDataBytes -= abandoned;
      }
      stream->finSent = true;
      written = 0;
    }
    else if (accepted > 0 && stream && chunk)
    {
      const size_t consumed = static_cast<size_t>(accepted);
      if (consumed > chunk->bytes.size() - chunk->submitted)
      {
        error = {1, "ngtcp2 accepted more stream bytes than offered"};
        return false;
      }
      chunk->submitted += consumed;
      queuedApplicationBytes_ -= consumed;
      const bool control = connection.controlStreamId && *connection.controlStreamId == streamId;
      if (!control)
      {
        if (consumed > connection.queuedDataBytes)
        {
          error = {1, "ngtcp2 connection queue accounting underflow"};
          return false;
        }
        connection.queuedDataBytes -= consumed;
      }
      if ((flags & NGTCP2_WRITE_STREAM_FLAG_FIN) && !stream->hasUnsubmitted())
        stream->finSent = true;
    }
    else if (stream && stream->finPending && !stream->hasUnsubmitted() && written > 0)
    {
      stream->finSent = true;
    }
    if (stream && !stream->transmitScheduled &&
        (stream->hasUnsubmitted() || (stream->finPending && !stream->finSent)))
    {
      stream->transmitScheduled = true;
      connection.transmitStreams.push_back(streamId);
    }
  }

  if (written < 0)
  {
    validError(static_cast<int>(written), "ngtcp2 packet write", error);
    return false;
  }
  if (written == 0) return false;
  if (!pathStorage.path.remote.addr || pathStorage.path.remote.addr->sa_family != AF_INET ||
      pathStorage.path.remote.addrlen != sizeof(sockaddr_in))
  {
    error = {1, "ngtcp2 returned a non-IPv4 transmit path"};
    return false;
  }
  packet.bytes = destination.first(static_cast<size_t>(written));
  std::memcpy(&packet.peer, pathStorage.path.remote.addr, sizeof(packet.peer));
  packet.ecn = config_.packetIo.ecn ? packetInfo.ecn : 0;
  packet.gsoSegmentSize = 0;
  packet.desiredSendRawNs = nowRawNs;
  return true;
}

size_t Ngtcp2Adapter::pollTransmitBatch(std::span<TransmitPacket> packets,
                                       uint64_t nowRawNs, AdapterError& error)
{
  if (!configured_)
  {
    error = {2, "ngtcp2 adapter is not configured"};
    return 0;
  }
  const size_t capacity = std::min({packets.size(), output_.size(), packetBatchSize});
  if (!capacity || connections_.empty())
  {
    updateTimeout();
    error = {};
    return 0;
  }
  size_t count = 0;
  size_t misses = 0;
  std::array<Connection*, packetBatchSize> wrote {};
  size_t wroteCount = 0;
  const auto updateTransmitTimes = [&]() {
    for (size_t index = 0; index < wroteCount; ++index)
      ngtcp2_conn_update_pkt_tx_time(wrote[index]->conn, nowRawNs);
  };
  while (count < capacity && misses < connections_.size())
  {
    if (transmitCursor_ >= connections_.size()) transmitCursor_ = 0;
    Connection& connection = *connections_[transmitCursor_++];
    AdapterError writeError;
    if (writePacket(connection, output_[count], nowRawNs, packets[count], writeError))
    {
      const auto wroteConnections =
          std::span<Connection* const>(wrote).first(wroteCount);
      if (std::ranges::find(wroteConnections, &connection) ==
          wroteConnections.end())
        wrote[wroteCount++] = &connection;
      ++count;
      misses = 0;
    }
    else if (!writeError.message.empty())
    {
      updateTransmitTimes();
      error = std::move(writeError);
      return count;
    }
    else
    {
      ++misses;
    }
  }
  updateTransmitTimes();
  if (!reapReleasedConnections(error)) return count;
  updateTimeout();
  error = {};
  return count;
}

void Ngtcp2Adapter::updateTimeout() noexcept
{
  nextTimeoutRawNs_ = 0;
  for (const auto& connection : connections_)
  {
    if (!active(*connection)) continue;
    const uint64_t expiry = ngtcp2_conn_get_expiry(connection->conn);
    if (expiry != std::numeric_limits<uint64_t>::max() &&
        (!nextTimeoutRawNs_ || expiry < nextTimeoutRawNs_))
      nextTimeoutRawNs_ = expiry;
  }
}

bool Ngtcp2Adapter::onTimeout(uint64_t nowRawNs, AdapterError& error)
{
  if (!configured_)
  {
    error = {2, "ngtcp2 adapter is not configured"};
    return false;
  }
  for (const auto& connection : connections_)
  {
    if (!active(*connection)) continue;
    if (ngtcp2_conn_get_expiry(connection->conn) > nowRawNs) continue;
    ++counters_.timerExpirations;
    const int status = ngtcp2_conn_handle_expiry(connection->conn, nowRawNs);
    if (!validError(status, "ngtcp2_conn_handle_expiry", error)) return false;
  }
  updateTimeout();
  error = {};
  return true;
}

bool Ngtcp2Adapter::connect(const sockaddr_in& peer, uint64_t nowRawNs,
                            uint64_t& connectionId, AdapterError& error)
{
  if (!configured_ || !localAddressSet_ || config_.role != EndpointRole::client)
  {
    error = {2, "ngtcp2 connect requires a configured client and post-bind address"};
    return false;
  }
  if (peer.sin_family != AF_INET || activeConnectionCount() >= config_.connectionCount)
  {
    error = {1, "invalid peer or configured connection count exhausted"};
    return false;
  }
  in_addr configuredAddress {};
  if (inet_pton(AF_INET, config_.peerAddress.c_str(), &configuredAddress) != 1 ||
      peer.sin_addr.s_addr != configuredAddress.s_addr ||
      ntohs(peer.sin_port) != config_.peerPort)
  {
    error = {1, "connect peer differs from the immutable endpoint configuration"};
    return false;
  }
  Connection* connection = createClient(peer, nowRawNs, error);
  if (!connection) return false;
  connectionId = connection->id;
  updateTimeout();
  error = {};
  return true;
}

PrimitiveStatus Ngtcp2Adapter::acceptConnection(uint64_t, uint64_t& connectionId,
                                                AdapterError& error)
{
  if (!configured_ || config_.role != EndpointRole::server)
  {
    error = {2, "ngtcp2 accept requires a configured server endpoint"};
    return PrimitiveStatus::fatal;
  }
  if (acceptedConnections_.empty())
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  connectionId = acceptedConnections_.front();
  acceptedConnections_.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

bool Ngtcp2Adapter::isConnected(uint64_t connectionId, uint64_t, bool& connected,
                                AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return false;
  connected = connection->handshakeCompleted &&
      (config_.role == EndpointRole::server || connection->handshakeConfirmed) &&
      !ngtcp2_conn_in_closing_period(connection->conn) &&
      !ngtcp2_conn_in_draining_period(connection->conn);
  error = {};
  return true;
}

bool Ngtcp2Adapter::connectionIsClosed(uint64_t connectionId, uint64_t, bool& closed,
                                       AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return false;
  closed = connection->remoteConnectionClose ||
      ngtcp2_conn_in_draining_period(connection->conn);
  error = {};
  return true;
}

bool Ngtcp2Adapter::releaseConnectionWhenClosed(
    uint64_t connectionId, uint64_t, AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return false;
  connection->releaseWhenClosed = true;
  return reapReleasedConnections(error);
}

PrimitiveStatus Ngtcp2Adapter::openBidirectionalStream(
    uint64_t connectionId, uint64_t, uint64_t& streamId, AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  int64_t nativeId = -1;
  const int status = ngtcp2_conn_open_bidi_stream(connection->conn, &nativeId, nullptr);
  if (status == NGTCP2_ERR_STREAM_ID_BLOCKED)
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  if (!validError(status, "ngtcp2_conn_open_bidi_stream", error))
    return PrimitiveStatus::fatal;
  connection->streams.try_emplace(nativeId);
  if (!connection->controlStreamId || nativeId < *connection->controlStreamId)
    connection->controlStreamId = nativeId;
  streamId = static_cast<uint64_t>(nativeId);
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus Ngtcp2Adapter::acceptBidirectionalStream(
    uint64_t connectionId, uint64_t, uint64_t& streamId, AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (connection->acceptedBidirectionalStreams.empty())
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  streamId = static_cast<uint64_t>(connection->acceptedBidirectionalStreams.front());
  connection->acceptedBidirectionalStreams.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus Ngtcp2Adapter::openUnidirectionalStream(
    uint64_t connectionId, uint64_t, uint64_t& streamId, AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  int64_t nativeId = -1;
  const int status = ngtcp2_conn_open_uni_stream(connection->conn, &nativeId, nullptr);
  if (status == NGTCP2_ERR_STREAM_ID_BLOCKED)
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  if (!validError(status, "ngtcp2_conn_open_uni_stream", error))
    return PrimitiveStatus::fatal;
  connection->streams.try_emplace(nativeId);
  streamId = static_cast<uint64_t>(nativeId);
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus Ngtcp2Adapter::acceptUnidirectionalStream(
    uint64_t connectionId, uint64_t, uint64_t& streamId, AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (connection->acceptedUnidirectionalStreams.empty())
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  streamId = static_cast<uint64_t>(connection->acceptedUnidirectionalStreams.front());
  connection->acceptedUnidirectionalStreams.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

bool Ngtcp2Adapter::writeStream(uint64_t connectionId, uint64_t streamId,
                                std::span<const std::byte> bytes, uint64_t,
                                size_t& written, AdapterError& error)
{
  written = 0;
  Connection* connection = find(connectionId, error);
  if (!connection || streamId > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
  {
    if (connection) error = {1, "stream ID exceeds ngtcp2 range"};
    return false;
  }
  const auto found = connection->streams.find(static_cast<int64_t>(streamId));
  if (found == connection->streams.end() || found->second.finPending)
  {
    error = {1, "write targets an unknown or finished stream"};
    return false;
  }
  Stream& stream = found->second;
  const size_t controlReserve = std::min(
      applicationBufferBytes / 2,
      static_cast<size_t>(config_.connectionCount) * size_t {4'096});
  const bool control = connection->controlStreamId &&
      *connection->controlStreamId == static_cast<int64_t>(streamId);
  const size_t queueLimit = control ? applicationBufferBytes :
      applicationBufferBytes - controlReserve;
  const size_t globalAvailable = queueLimit - std::min(queueLimit, queuedApplicationBytes_);
  const size_t dataLimit = applicationBufferBytes - controlReserve;
  const size_t perConnectionDataLimit = std::max<size_t>(
      1, dataLimit / std::max<uint64_t>(1, config_.connectionCount));
  const size_t connectionAvailable = perConnectionDataLimit -
      std::min(perConnectionDataLimit, connection->queuedDataBytes);
  const size_t available = control ? globalAvailable :
      std::min(globalAvailable, connectionAvailable);
  const size_t earlyAvailable = connection->zeroRttAttempted &&
      !connection->handshakeCompleted ? 4'096 - std::min<size_t>(4'096, connection->earlyDataBytes) :
                                        available;
  written = std::min({available, earlyAvailable, bytes.size()});
  if (written > std::numeric_limits<uint64_t>::max() - stream.nextTransmitOffset)
  {
    written = 0;
    error = {1, "ngtcp2 stream transmit offset overflow"};
    return false;
  }
  if (written)
  {
    stream.transmit.push_back({
        stream.nextTransmitOffset,
        {bytes.begin(), bytes.begin() + written},
        0,
        false,
    });
    stream.nextTransmitOffset += written;
    if (!stream.transmitScheduled)
    {
      stream.transmitScheduled = true;
      connection->transmitStreams.push_back(static_cast<int64_t>(streamId));
    }
  }
  queuedApplicationBytes_ += written;
  if (!control) connection->queuedDataBytes += written;
  if (connection->zeroRttAttempted && !connection->handshakeCompleted)
    connection->earlyDataBytes += written;
  error = {};
  return true;
}

bool Ngtcp2Adapter::consumeStreamData(uint64_t connectionId, uint64_t streamId,
                                      std::span<std::byte> bytes, uint64_t, size_t& read,
                                      bool& finished, AdapterError& error)
{
  read = 0;
  finished = false;
  Connection* connection = find(connectionId, error);
  if (!connection || streamId > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
  {
    if (connection) error = {1, "stream ID exceeds ngtcp2 range"};
    return false;
  }
  const auto found = connection->streams.find(static_cast<int64_t>(streamId));
  if (found == connection->streams.end())
  {
    error = {1, "read targets an unknown stream"};
    return false;
  }
  Stream& stream = found->second;
  read = std::min(bytes.size(), stream.received.size());
  if (read)
  {
    std::copy_n(stream.received.begin(), read, bytes.begin());
    stream.received.erase(stream.received.begin(), stream.received.begin() + read);
    stream.receiveOffset += read;
    ngtcp2_conn_extend_max_stream_offset(connection->conn, static_cast<int64_t>(streamId), read);
    ngtcp2_conn_extend_max_offset(connection->conn, read);
  }
  finished = stream.remoteFin && stream.received.empty();
  error = {};
  return true;
}

bool Ngtcp2Adapter::finishStream(uint64_t connectionId, uint64_t streamId, uint64_t,
                                 AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection || streamId > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
  {
    if (connection) error = {1, "stream ID exceeds ngtcp2 range"};
    return false;
  }
  const auto found = connection->streams.find(static_cast<int64_t>(streamId));
  if (found == connection->streams.end())
  {
    error = {1, "finish targets an unknown stream"};
    return false;
  }
  found->second.finPending = true;
  if (!found->second.transmitScheduled)
  {
    found->second.transmitScheduled = true;
    connection->transmitStreams.push_back(static_cast<int64_t>(streamId));
  }
  error = {};
  return true;
}

bool Ngtcp2Adapter::resetStream(uint64_t connectionId, uint64_t streamId,
                                uint64_t applicationError, uint64_t,
                                AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection || streamId > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
  {
    if (connection) error = {1, "stream ID exceeds ngtcp2 range"};
    return false;
  }
  const auto found = connection->streams.find(static_cast<int64_t>(streamId));
  if (found == connection->streams.end())
  {
    error = {1, "reset targets an unknown stream"};
    return false;
  }
  if (!validError(ngtcp2_conn_shutdown_stream_write(
      connection->conn, 0, static_cast<int64_t>(streamId), applicationError),
      "ngtcp2_conn_shutdown_stream_write", error))
    return false;
  Stream& stream = found->second;
  const size_t abandoned = stream.abandonUnsubmitted();
  const bool control = connection->controlStreamId &&
      *connection->controlStreamId == static_cast<int64_t>(streamId);
  if (abandoned > queuedApplicationBytes_ ||
      (!control && abandoned > connection->queuedDataBytes))
  {
    error = {1, "ngtcp2 stream queue accounting underflow"};
    return false;
  }
  queuedApplicationBytes_ -= abandoned;
  if (!control) connection->queuedDataBytes -= abandoned;
  stream.finPending = true;
  stream.finSent = true;
  error = {};
  return true;
}

bool Ngtcp2Adapter::stopSending(uint64_t connectionId, uint64_t streamId,
                                uint64_t applicationError, uint64_t,
                                AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection || streamId > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
  {
    if (connection) error = {1, "stream ID exceeds ngtcp2 range"};
    return false;
  }
  return validError(ngtcp2_conn_shutdown_stream_read(
      connection->conn, 0, static_cast<int64_t>(streamId), applicationError),
      "ngtcp2_conn_shutdown_stream_read", error);
}

PrimitiveStatus Ngtcp2Adapter::sendDatagram(uint64_t connectionId,
                                            std::span<const std::byte> bytes, uint64_t,
                                            AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (!connection->handshakeCompleted)
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  const auto* remote = ngtcp2_conn_get_remote_transport_params(connection->conn);
  if (!remote || !remote->max_datagram_frame_size || bytes.size() > datagramFrameBytes)
  {
    error = {1, "peer did not negotiate the requested QUIC DATAGRAM capability"};
    return PrimitiveStatus::fatal;
  }
  const size_t controlReserve = std::min(
      applicationBufferBytes / 2,
      static_cast<size_t>(config_.connectionCount) * size_t {4'096});
  const size_t dataLimit = applicationBufferBytes - controlReserve;
  const size_t perConnectionDataLimit = std::max<size_t>(
      1, dataLimit / std::max<uint64_t>(1, config_.connectionCount));
  if (bytes.size() > dataLimit - std::min(dataLimit, queuedApplicationBytes_) ||
      bytes.size() > perConnectionDataLimit -
          std::min(perConnectionDataLimit, connection->queuedDataBytes))
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  connection->transmitDatagrams.push_back(
      {connection->nextDatagramId++, {bytes.begin(), bytes.end()}});
  queuedApplicationBytes_ += bytes.size();
  connection->queuedDataBytes += bytes.size();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus Ngtcp2Adapter::consumeDatagram(uint64_t connectionId,
                                               std::span<std::byte> bytes, uint64_t,
                                               size_t& read, AdapterError& error)
{
  read = 0;
  Connection* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (connection->receivedDatagrams.empty())
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  const auto& datagram = connection->receivedDatagrams.front();
  if (datagram.size() > bytes.size())
  {
    error = {1, "borrowed DATAGRAM receive buffer is too small"};
    return PrimitiveStatus::fatal;
  }
  read = datagram.size();
  std::copy(datagram.begin(), datagram.end(), bytes.begin());
  connection->receivedDatagrams.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus Ngtcp2Adapter::exportResumptionState(
    uint64_t connectionId, uint64_t, std::span<std::byte> bytes, size_t& written,
    AdapterError& error)
{
  written = 0;
  Connection* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (connection->session.empty() || connection->zeroRttTransportParameters.empty())
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  if (connection->session.size() > std::numeric_limits<uint32_t>::max() ||
      connection->zeroRttTransportParameters.size() > std::numeric_limits<uint32_t>::max())
  {
    error = {1, "ngtcp2 resumption state exceeds the v2 encoding"};
    return PrimitiveStatus::fatal;
  }
  constexpr size_t headerBytes = 16;
  const size_t required = headerBytes + connection->session.size() +
      connection->zeroRttTransportParameters.size();
  if (required > bytes.size())
  {
    error = {1, "borrowed resumption output buffer is too small"};
    return PrimitiveStatus::fatal;
  }
  storeU32(bytes.data(), resumptionMagic);
  storeU32(bytes.data() + 4, 1);
  storeU32(bytes.data() + 8, static_cast<uint32_t>(connection->session.size()));
  storeU32(bytes.data() + 12,
           static_cast<uint32_t>(connection->zeroRttTransportParameters.size()));
  std::copy(connection->session.begin(), connection->session.end(), bytes.begin() + headerBytes);
  std::copy(connection->zeroRttTransportParameters.begin(),
            connection->zeroRttTransportParameters.end(),
            bytes.begin() + headerBytes + connection->session.size());
  written = required;
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus Ngtcp2Adapter::importResumptionState(
    std::span<const std::byte> bytes, bool useZeroRtt, uint64_t, AdapterError& error)
{
  constexpr size_t headerBytes = 16;
  const std::string identity(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  if (!configured_ || config_.role != EndpointRole::client || importedState_ ||
      consumedTickets_.contains(identity) ||
      bytes.size() < headerBytes || loadU32(bytes.data()) != resumptionMagic ||
      loadU32(bytes.data() + 4) != 1)
  {
    error = {1, "invalid or overlapping ngtcp2 resumption import"};
    return PrimitiveStatus::fatal;
  }
  const size_t sessionLength = loadU32(bytes.data() + 8);
  const size_t parameterLength = loadU32(bytes.data() + 12);
  if (sessionLength > bytes.size() - headerBytes ||
      parameterLength != bytes.size() - headerBytes - sessionLength || !sessionLength ||
      (useZeroRtt && !parameterLength))
  {
    error = {1, "malformed ngtcp2 resumption state lengths"};
    return PrimitiveStatus::fatal;
  }
  ImportedState state;
  state.session.assign(bytes.begin() + headerBytes,
                       bytes.begin() + headerBytes + sessionLength);
  state.transportParameters.assign(bytes.begin() + headerBytes + sessionLength, bytes.end());
  state.zeroRtt = useZeroRtt;
  state.identity = identity;
  importedState_ = std::move(state);
  error = {};
  return PrimitiveStatus::ready;
}

bool Ngtcp2Adapter::connectionResumed(uint64_t connectionId, uint64_t, bool& resumed,
                                      AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return false;
  resumed = connection->resumed;
  error = {};
  return true;
}

bool Ngtcp2Adapter::zeroRttAttempted(uint64_t connectionId, uint64_t, bool& attempted,
                                    AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return false;
  attempted = connection->zeroRttAttempted;
  error = {};
  return true;
}

bool Ngtcp2Adapter::zeroRttAccepted(uint64_t connectionId, uint64_t, bool& accepted,
                                   AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return false;
  accepted = connection->zeroRttAccepted;
  error = {};
  return true;
}

bool Ngtcp2Adapter::zeroRttRejected(uint64_t connectionId, uint64_t, bool& rejected,
                                   AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return false;
  rejected = connection->zeroRttRejected;
  error = {};
  return true;
}

bool Ngtcp2Adapter::peerTerminalFacts(uint64_t connectionId, uint64_t streamId,
                                      uint64_t, PeerTerminalFacts& facts,
                                      AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return false;
  const auto found = connection->streams.find(static_cast<int64_t>(streamId));
  facts = {};
  facts.available = true;
  facts.connectionClose = connection->remoteConnectionClose;
  uint64_t stopError = 0;
  facts.stopSending = ngtcp2_conn_get_received_stop_sending(
      connection->conn, static_cast<int64_t>(streamId), &stopError) != 0;
  facts.stopSendingError = stopError;
  if (found != connection->streams.end())
  {
    const Stream& stream = found->second;
    facts.fin = stream.remoteFin;
    facts.resetStream = stream.remoteReset;
    facts.resetStreamError = stream.remoteResetError;
  }
  error = {};
  return true;
}

bool Ngtcp2Adapter::closeConnection(uint64_t connectionId, uint64_t applicationError,
                                    uint64_t, AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return false;
  connection->closePending = true;
  connection->closeError = applicationError;
  error = {};
  return true;
}

TransportCounters Ngtcp2Adapter::snapshotTransportCounters() const noexcept
{
  TransportCounters result = counters_;
  for (const auto& connection : connections_)
  {
    ngtcp2_conn_info info {};
    ngtcp2_conn_get_conn_info(connection->conn, &info);
    result.packetsReceived += info.pkt_recv;
    result.packetsSent += info.pkt_sent;
    result.packetsLost += info.pkt_lost;
    uint64_t dataBlocked = 0;
    uint64_t streamDataBlocked = 0;
    ngtcp2_conn_get_quicperf_blocked_frame_counts(
        connection->conn, &dataBlocked, &streamDataBlocked);
    result.flowControlBlockedEvents += dataBlocked;
    result.streamCreditBlockedEvents += streamDataBlocked;
  }
  return result;
}

NegotiatedSettings Ngtcp2Adapter::snapshotNegotiatedSettings() const noexcept
{
  NegotiatedSettings result;
  result.evidenceSource =
      "ngtcp2_conn_remote_transport_params+boringssl_post_handshake+"
      "ngtcp2_applied_settings+qpf2_lifecycle_policy";
  const auto unavailable = [&result](std::string field) {
    if (std::ranges::find(result.unavailableFields, field) == result.unavailableFields.end())
      result.unavailableFields.push_back(std::move(field));
  };
  const auto established = std::ranges::find_if(connections_, [](const auto& owned) {
    return owned->handshakeCompleted;
  });
  if (established == connections_.end())
  {
    unavailable("no_post_handshake_connection");
    return result;
  }

  const Connection& connection = **established;
  if (!connection.handshakeCompleted || !connection.ssl)
  {
    unavailable("handshake_not_complete");
    return result;
  }
  const auto* remote = ngtcp2_conn_get_remote_transport_params(connection.conn);
  if (!remote)
  {
    unavailable("remote_transport_parameters");
    return result;
  }

  result.available = true;
  result.quicVersion = ngtcp2_conn_get_negotiated_version(connection.conn);
  const uint8_t* alpnBytes = nullptr;
  unsigned alpnLength = 0;
  SSL_get0_alpn_selected(connection.ssl, &alpnBytes, &alpnLength);
  if (alpnBytes && alpnLength) result.alpn.assign(
      reinterpret_cast<const char*>(alpnBytes), alpnLength);
  else unavailable("alpn");
  if (const char* version = SSL_get_version(connection.ssl)) result.tlsVersion = version;
  else unavailable("tls_version");
  if (const SSL_CIPHER* cipher = SSL_get_current_cipher(connection.ssl))
    result.tlsCipherSuite = SSL_CIPHER_get_name(cipher);
  else unavailable("tls_cipher_suite");
  const int group = SSL_get_negotiated_group(connection.ssl);
  if (group == NID_X25519) result.tlsKeyExchange = "X25519";
  else if (const char* name = OBJ_nid2sn(group)) result.tlsKeyExchange = name;
  else unavailable("tls_key_exchange");

  X509* ownedPeer = nullptr;
  X509* certificate = nullptr;
  if (config_.role == EndpointRole::client)
  {
    ownedPeer = SSL_get_peer_certificate(connection.ssl);
    certificate = ownedPeer;
  }
  else
  {
    certificate = SSL_get_certificate(connection.ssl);
  }
  if (certificate)
  {
    const int signature = X509_get_signature_nid(certificate);
    if (signature == NID_ED25519) result.tlsLeafSignature = "Ed25519";
    else if (const char* name = OBJ_nid2sn(signature)) result.tlsLeafSignature = name;
    else unavailable("tls_leaf_signature");
  }
  else unavailable("tls_leaf_signature");
  if (ownedPeer) X509_free(ownedPeer);
  result.peerCertificateVerified = config_.role == EndpointRole::client &&
      connection.tlsVerifyError == X509_V_OK;
  result.hostnameVerified = result.peerCertificateVerified;

  result.maxUdpPayloadSize = ngtcp2_conn_get_path_max_tx_udp_payload_size(connection.conn);
  result.maxAckDelayNs = remote->max_ack_delay;
  result.ackDelayExponent = remote->ack_delay_exponent;
  result.activeMigration = remote->disable_active_migration == 0;
  result.activeConnectionIdLimit = remote->active_connection_id_limit;
  if (const ngtcp2_cid* dcid = ngtcp2_conn_get_dcid(connection.conn))
    result.connectionIdBytes = dcid->datalen;
  else unavailable("connection_id_bytes");
  result.maxIdleTimeoutNs = remote->max_idle_timeout;
  result.maxBidiStreams = remote->initial_max_streams_bidi;
  result.maxUniStreams = remote->initial_max_streams_uni;
  result.connectionWindowBytes = remote->initial_max_data;
  result.streamWindowBytes = std::min(
      remote->initial_max_stream_data_bidi_local,
      remote->initial_max_stream_data_bidi_remote);
  result.datagramMaxFrameSize = remote->max_datagram_frame_size;

  result.congestionController = config_.congestionController;
  result.initialCongestionWindowBytes = config_.initialCongestionWindowBytes;
  result.ackFrequency = config_.ackFrequency;
  result.streamCreditReplenishBelow = config_.streamCreditReplenishBelow;
  result.ticketLifetimeNs = config_.tlsTicketLifetimeNs;
  result.maximumEarlyDataBytes = config_.tlsMaximumEarlyDataBytes;
  result.oneUseTickets = config_.tlsOneUseTickets;

  for (const auto& owned : connections_)
  {
    const auto& peer = *owned;
    if (&peer == &connection || !peer.handshakeCompleted) continue;
    const auto* peerRemote = peer.conn ? ngtcp2_conn_get_remote_transport_params(peer.conn) : nullptr;
    const uint8_t* peerAlpn = nullptr;
    unsigned peerAlpnLength = 0;
    if (peer.ssl) SSL_get0_alpn_selected(peer.ssl, &peerAlpn, &peerAlpnLength);
    const ngtcp2_cid* peerDcid = peer.conn ? ngtcp2_conn_get_dcid(peer.conn) : nullptr;
    const char* peerVersion = peer.ssl ? SSL_get_version(peer.ssl) : nullptr;
    const SSL_CIPHER* peerCipher = peer.ssl ? SSL_get_current_cipher(peer.ssl) : nullptr;
    if (!peer.handshakeCompleted || !peer.ssl ||
        ngtcp2_conn_get_negotiated_version(peer.conn) != result.quicVersion ||
        ngtcp2_conn_get_path_max_tx_udp_payload_size(peer.conn) != result.maxUdpPayloadSize ||
        !peerRemote || peerRemote->max_ack_delay != result.maxAckDelayNs ||
        peerRemote->ack_delay_exponent != result.ackDelayExponent ||
        (peerRemote->disable_active_migration == 0) != result.activeMigration ||
        peerRemote->active_connection_id_limit != result.activeConnectionIdLimit ||
        peerRemote->max_idle_timeout != result.maxIdleTimeoutNs ||
        peerRemote->initial_max_streams_bidi != result.maxBidiStreams ||
        peerRemote->initial_max_streams_uni != result.maxUniStreams ||
        peerRemote->initial_max_data != result.connectionWindowBytes ||
        std::min(peerRemote->initial_max_stream_data_bidi_local,
                 peerRemote->initial_max_stream_data_bidi_remote) != result.streamWindowBytes ||
        peerRemote->max_datagram_frame_size != result.datagramMaxFrameSize ||
        !peerDcid || peerDcid->datalen != result.connectionIdBytes ||
        peerAlpnLength != result.alpn.size() ||
        (peerAlpnLength && std::memcmp(peerAlpn, result.alpn.data(), peerAlpnLength) != 0) ||
        !peerVersion || std::string_view(peerVersion) != result.tlsVersion ||
        !peerCipher || std::string_view(SSL_CIPHER_get_name(peerCipher)) !=
            result.tlsCipherSuite || SSL_get_negotiated_group(peer.ssl) != group)
    {
      unavailable("per_connection_evidence_mismatch");
      break;
    }
  }
  return result;
}

bool Ngtcp2Adapter::reset(AdapterError& error)
{
  for (const auto& connection : connections_) eraseCidMappings(*connection);
  connectionsById_.clear();
  connections_.clear();
  connectionsByCid_.clear();
  acceptedConnections_.clear();
  importedState_.reset();
  consumedTickets_.clear();
  if (tlsContext_)
  {
    SSL_CTX_free(tlsContext_);
    tlsContext_ = nullptr;
  }
  config_ = {};
  localAddress_ = {};
  nextConnectionId_ = 1;
  nextTimeoutRawNs_ = 0;
  transmitCursor_ = 0;
  queuedApplicationBytes_ = 0;
  configured_ = false;
  localAddressSet_ = false;
  counters_ = {};
  error = {};
  return true;
}

} // namespace

std::unique_ptr<Adapter> makeTransportAdapter()
{
  return std::make_unique<Ngtcp2Adapter>();
}

} // namespace quicperf
