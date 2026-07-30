#include "adapter_factory.h"
#include "resumption_envelope.h"
#include "core/strict_config.h"

#include <lsquic.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace quicperf {
namespace {

constexpr std::array<unsigned char, 8> alpn {7, 'q', 'p', 'e', 'r', 'f', '/', '2'};
constexpr std::array<uint16_t, 1> signatureAlgorithms {SSL_SIGN_ED25519};
constexpr std::array<unsigned char, 48> ticketKey {
    0x71, 0x75, 0x69, 0x63, 0x70, 0x65, 0x72, 0x66,
    0x2d, 0x6c, 0x73, 0x71, 0x75, 0x69, 0x63, 0x2d,
    0x72, 0x65, 0x73, 0x75, 0x6d, 0x65, 0x2d, 0x30,
    0x72, 0x74, 0x74, 0x2d, 0x6c, 0x6f, 0x6f, 0x70,
    0x62, 0x61, 0x63, 0x6b, 0x2d, 0x74, 0x69, 0x63,
    0x6b, 0x65, 0x74, 0x2d, 0x6b, 0x65, 0x79, 0x21};

std::string sslError(std::string prefix)
{
  const unsigned long code = ERR_get_error();
  if (!code) return prefix;
  prefix += ": ";
  prefix += ERR_error_string(code, nullptr);
  return prefix;
}

class LsquicAdapter final : public Adapter {
public:
  LsquicAdapter();
  ~LsquicAdapter() override;

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
  bool peerTerminalFacts(uint64_t connectionId, uint64_t streamId, uint64_t,
                         PeerTerminalFacts& facts, AdapterError& error) override;
  PrimitiveStatus openBidirectionalStream(uint64_t connectionId, uint64_t,
                                          uint64_t& streamId, AdapterError& error) override;
  PrimitiveStatus acceptBidirectionalStream(uint64_t connectionId, uint64_t,
                                            uint64_t& streamId, AdapterError& error) override;
  PrimitiveStatus openUnidirectionalStream(uint64_t, uint64_t, uint64_t&,
                                           AdapterError& error) override;
  PrimitiveStatus acceptUnidirectionalStream(uint64_t, uint64_t, uint64_t&,
                                             AdapterError& error) override;
  bool writeStream(uint64_t connectionId, uint64_t streamId,
                   std::span<const std::byte> bytes, uint64_t, size_t& written,
                   AdapterError& error) override;
  bool consumeStreamData(uint64_t connectionId, uint64_t streamId,
                         std::span<std::byte> bytes, uint64_t, size_t& read,
                         bool& finished, AdapterError& error) override;
  bool finishStream(uint64_t connectionId, uint64_t streamId, uint64_t,
                    AdapterError& error) override;
  bool resetStream(uint64_t, uint64_t, uint64_t, uint64_t,
                   AdapterError& error) override;
  bool stopSending(uint64_t, uint64_t, uint64_t, uint64_t,
                   AdapterError& error) override;
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
  bool zeroRttAttempted(uint64_t, uint64_t, bool&, AdapterError& error) override;
  bool zeroRttAccepted(uint64_t, uint64_t, bool&, AdapterError& error) override;
  bool zeroRttRejected(uint64_t, uint64_t, bool&, AdapterError& error) override;
  bool closeConnection(uint64_t connectionId, uint64_t, uint64_t,
                       AdapterError& error) override;
  TransportCounters snapshotTransportCounters() const noexcept override;
  NegotiatedSettings snapshotNegotiatedSettings() const noexcept override;
  bool reset(AdapterError& error) override;
  bool stop(AdapterError& error) override { return reset(error); }

private:
  struct Stream {
    lsquic_stream_t* stream = nullptr;
    std::vector<std::byte> received;
    size_t receiveOffset = 0;
    bool remoteFin = false;
    bool remoteReset = false;
    bool remoteStop = false;
    uint64_t remoteResetError = 0;
    uint64_t remoteStopError = 0;
    uint64_t localResetError = 0;
    int readError = 0;
    bool localReset = false;
    bool closed = false;
  };

  struct Connection {
    LsquicAdapter* owner = nullptr;
    uint64_t id = 0;
    lsquic_conn_t* conn = nullptr;
    sockaddr_in peer {};
    std::unordered_map<uint64_t, std::unique_ptr<Stream>> streams;
    std::deque<uint64_t> openedStreams;
    std::deque<uint64_t> acceptedStreams;
    std::deque<std::vector<std::byte>> transmitDatagrams;
    std::deque<std::vector<std::byte>> receivedDatagrams;
    std::vector<std::byte> session;
    bool accepted = false;
    bool resumed = false;
    bool closed = false;
    bool releaseWhenClosed = false;
    uint64_t accountedPacketsLost = 0;
    uint64_t accountedPacketsRetransmitted = 0;
    bool pendingStream = false;
    bool peerConnectionClose = false;
    uint64_t peerConnectionCloseError = 0;
    uint64_t peerConnectionCloseReasonLength = 0;
  };

  struct OutputPacket {
    std::vector<std::byte> bytes;
    sockaddr_in peer {};
    uint8_t ecn = 0;
  };

  static lsquic_conn_ctx_t* newConnection(void* context, lsquic_conn_t* conn);
  static void connectionClosed(lsquic_conn_t* conn);
  static lsquic_stream_ctx_t* newStream(void* context, lsquic_stream_t* stream);
  static void streamRead(lsquic_stream_t* stream, lsquic_stream_ctx_t* context);
  static void streamWrite(lsquic_stream_t* stream, lsquic_stream_ctx_t* context);
  static void streamClosed(lsquic_stream_t* stream, lsquic_stream_ctx_t* context);
  static void streamReset(lsquic_stream_t* stream, lsquic_stream_ctx_t* context,
                          int how, uint64_t applicationError);
  static void connectionCloseReceived(lsquic_conn_t* conn, int applicationError,
                                      uint64_t errorCode, const char*, int reasonLength);
  static ssize_t datagramWrite(lsquic_conn_t* conn, void* bytes, size_t capacity);
  static void datagramRead(lsquic_conn_t* conn, const void* bytes, size_t length);
  static void handshakeDone(lsquic_conn_t* conn, lsquic_hsk_status status);
  static void sessionResumeInfo(lsquic_conn_t* conn, const unsigned char* bytes,
                                size_t length);
  static int packetsOut(void* context, const lsquic_out_spec* specifications,
                        unsigned count);
  static SSL_CTX* getSslContext(void* peerContext, const sockaddr*);
  static int verifyCertificate(void* context, stack_st_X509* chain);
  static int selectAlpn(SSL*, const unsigned char** output, unsigned char* outputLength,
                        const unsigned char* input, unsigned inputLength, void*);
  static int saveSession(SSL* ssl, SSL_SESSION* session);
  static int sslOwnerIndex();

  bool initializeTls(AdapterError& error);
  bool initializeEngine(AdapterError& error);
  Connection* find(uint64_t id, AdapterError& error) const;
  Connection* find(lsquic_conn_t* conn) const;
  Connection& adopt(lsquic_conn_t* conn);
  static bool archiveTransportCounters(Connection& connection,
                                       AdapterError* error = nullptr);
  void reapReleasedConnections();
  Stream* findStream(Connection& connection, uint64_t id, AdapterError& error) const;
  void process(uint64_t nowRawNs);
  void updateTimeout(uint64_t nowRawNs) noexcept;
  PrimitiveStatus unavailable(std::string_view primitive, AdapterError& error) const;

  Capabilities capabilities_;
  EndpointConfig config_ {};
  sockaddr_in localAddress_ {};
  SSL_CTX* sslContext_ = nullptr;
  lsquic_engine_t* engine_ = nullptr;
  lsquic_engine_settings settings_ {};
  lsquic_stream_if streamInterface_ {};
  std::unordered_map<lsquic_conn_t*, std::unique_ptr<Connection>> connections_;
  std::vector<std::unique_ptr<Connection>> retiredConnections_;
  std::unordered_map<uint64_t, Connection*> connectionsById_;
  std::deque<uint64_t> acceptedConnections_;
  std::deque<OutputPacket> outputQueue_;
  std::vector<std::byte> importedSession_;
  std::unordered_set<std::string> consumedSessions_;
  uint64_t nextConnectionId_ = 1;
  uint64_t nextTimeoutRawNs_ = 0;
  bool configured_ = false;
  bool localAddressSet_ = false;
  bool importedSessionPending_ = false;
  bool importedZeroRtt_ = false;
  std::array<std::array<std::byte, maxUdpPayloadSize>, packetBatchSize> output_ {};
  TransportCounters counters_ {};
};

LsquicAdapter::LsquicAdapter()
{
  capabilities_.library = "lsquic";
  capabilities_.buildId = "lsquic-4.7.0-quicperf5-exact-treatment";
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
      workload::Scenario::streamChurn, workload::Scenario::closeResetCleanup,
      workload::Scenario::connect,
      workload::Scenario::resumedConnect, workload::Scenario::zeroRttReqresp,
      workload::Scenario::memoryCurve};
  capabilities_.datagram = true;
  capabilities_.resumption = true;
  capabilities_.earlyData = true;
  capabilities_.effectiveFeatures = {
      "common_cpp_packet_io", "borrowed_packet_batch_64", "ipv4", "quic_v1",
      "tls_1_3", "tls_aes_128_gcm_sha256", "x25519", "qperf_2_alpn",
      "bidirectional_stream", "datagram", "resumption", "early_data",
      "post_bind_local_address", "reset_stream", "stop_sending",
      "connection_close", "peer_terminal_facts", "unidirectional_stream_unavailable",
      "transport_loss_retransmission_counters"};
}

LsquicAdapter::~LsquicAdapter()
{
  AdapterError ignored;
  reset(ignored);
}

int LsquicAdapter::sslOwnerIndex()
{
  static const int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return index;
}

int LsquicAdapter::selectAlpn(SSL*, const unsigned char** output,
                              unsigned char* outputLength, const unsigned char* input,
                              unsigned inputLength, void*)
{
  return SSL_select_next_proto(const_cast<unsigned char**>(output), outputLength,
                               alpn.data(), alpn.size(), input, inputLength) ==
      OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
}

int LsquicAdapter::saveSession(SSL* ssl, SSL_SESSION* session)
{
  SSL_CTX* context = SSL_get_SSL_CTX(ssl);
  auto* owner = context ? static_cast<LsquicAdapter*>(
      SSL_CTX_get_ex_data(context, sslOwnerIndex())) : nullptr;
  lsquic_conn_t* conn = lsquic_ssl_to_conn(ssl);
  Connection* connection = owner ? owner->find(conn) : nullptr;
  if (!connection) return 0;
  unsigned char* bytes = nullptr;
  size_t length = 0;
  if (lsquic_ssl_sess_to_resume_info(ssl, session, &bytes, &length) == 0)
  {
    const auto* first = reinterpret_cast<const std::byte*>(bytes);
    connection->session.assign(first, first + length);
    std::free(bytes);
  }
  return 0;
}

SSL_CTX* LsquicAdapter::getSslContext(void* peerContext, const sockaddr*)
{
  auto* owner = static_cast<LsquicAdapter*>(peerContext);
  return owner ? owner->sslContext_ : nullptr;
}

int LsquicAdapter::verifyCertificate(void* context, stack_st_X509* chain)
{
  auto* owner = static_cast<LsquicAdapter*>(context);
  if (!owner || !owner->config_.tlsVerifyPeer) return 0;
  if (!chain || sk_X509_num(chain) == 0) return -1;
  X509_STORE* store = SSL_CTX_get_cert_store(owner->sslContext_);
  X509_STORE_CTX* verification = X509_STORE_CTX_new();
  if (!verification) return -1;
  X509* leaf = sk_X509_value(chain, 0);
  const int initialized = X509_STORE_CTX_init(
      verification, store, leaf, chain);
  const int verified = initialized == 1 ? X509_verify_cert(verification) : 0;
  const int hostname = X509_check_host(leaf, owner->config_.tlsHostname.c_str(),
                                       owner->config_.tlsHostname.size(), 0, nullptr);
  X509_STORE_CTX_free(verification);
  return verified == 1 && hostname == 1 ? 0 : -1;
}

bool LsquicAdapter::initializeTls(AdapterError& error)
{
  sslContext_ = SSL_CTX_new(TLS_method());
  if (!sslContext_) { error = {10, sslError("SSL_CTX_new")}; return false; }
  if (SSL_CTX_set_min_proto_version(sslContext_, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(sslContext_, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set1_groups_list(sslContext_, "X25519") != 1 ||
      SSL_CTX_set_signing_algorithm_prefs(
          sslContext_, signatureAlgorithms.data(), signatureAlgorithms.size()) != 1 ||
      SSL_CTX_set_verify_algorithm_prefs(
          sslContext_, signatureAlgorithms.data(), signatureAlgorithms.size()) != 1 ||
      SSL_CTX_use_certificate_file(
          sslContext_, config_.certificatePath.c_str(), SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_use_PrivateKey_file(
          sslContext_, config_.privateKeyPath.c_str(), SSL_FILETYPE_PEM) != 1 ||
      SSL_CTX_check_private_key(sslContext_) != 1 ||
      SSL_CTX_load_verify_locations(sslContext_, config_.chainPath.c_str(), nullptr) != 1 ||
      SSL_CTX_set_alpn_protos(sslContext_, alpn.data(), alpn.size()) != 0 ||
      SSL_CTX_set_tlsext_ticket_keys(
          sslContext_, ticketKey.data(), ticketKey.size()) != 1)
  {
    error = {10, sslError("LSQUIC TLS configuration")};
    return false;
  }
  SSL_CTX_set_alpn_select_cb(sslContext_, selectAlpn, nullptr);
  SSL_CTX_set_verify(sslContext_, config_.tlsVerifyPeer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                     nullptr);
  X509_VERIFY_PARAM_set_time_posix(
      SSL_CTX_get0_param(sslContext_), config_.calendarUnixSeconds);
  if (config_.tlsVerifyPeer &&
      X509_VERIFY_PARAM_set1_host(SSL_CTX_get0_param(sslContext_),
                                  config_.tlsHostname.c_str(),
                                  config_.tlsHostname.size()) != 1)
  {
    error = {10, sslError("LSQUIC TLS hostname configuration")};
    return false;
  }
  SSL_CTX_set_early_data_enabled(sslContext_, 1);
  SSL_CTX_set_session_psk_dhe_timeout(
      sslContext_, static_cast<uint32_t>(config_.tlsTicketLifetimeNs / 1'000'000'000ULL));
  SSL_CTX_set_num_tickets(sslContext_, 1);
  SSL_CTX_set_ex_data(sslContext_, sslOwnerIndex(), this);
  SSL_CTX_set_session_cache_mode(sslContext_, SSL_SESS_CACHE_CLIENT);
  SSL_CTX_sess_set_new_cb(sslContext_, saveSession);
  return true;
}

bool LsquicAdapter::initializeEngine(AdapterError& error)
{
  static std::once_flag initialized;
  static int initializationResult = -1;
  std::call_once(initialized, [] {
    initializationResult = lsquic_global_init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER);
  });
  if (initializationResult != 0)
  {
    error = {11, "lsquic_global_init failed"};
    return false;
  }
  const unsigned flags = config_.role == EndpointRole::server ? LSENG_SERVER : 0;
  lsquic_engine_init_settings(&settings_, flags);
  if (config_.connectionWindow > std::numeric_limits<unsigned>::max() ||
      config_.streamWindow > std::numeric_limits<unsigned>::max() ||
      config_.maxBidiStreams > std::numeric_limits<unsigned>::max() ||
      config_.maxUniStreams > std::numeric_limits<unsigned>::max())
  {
    error = {11, "LSQUIC configuration exceeds unsigned transport limits"};
    return false;
  }
  settings_.es_versions = 1U << LSQVER_I001;
  settings_.es_sfcw = static_cast<unsigned>(config_.streamWindow);
  settings_.es_cfcw = static_cast<unsigned>(config_.connectionWindow);
  settings_.es_max_sfcw = settings_.es_sfcw;
  settings_.es_max_cfcw = settings_.es_cfcw;
  settings_.es_init_max_data = settings_.es_cfcw;
  settings_.es_init_max_stream_data_bidi_local = settings_.es_sfcw;
  settings_.es_init_max_stream_data_bidi_remote = settings_.es_sfcw;
  settings_.es_init_max_stream_data_uni = settings_.es_sfcw;
  settings_.es_init_max_streams_bidi = static_cast<unsigned>(config_.maxBidiStreams);
  settings_.es_init_max_streams_uni = static_cast<unsigned>(config_.maxUniStreams);
  settings_.es_max_streams_in = static_cast<unsigned>(config_.maxBidiStreams);
  settings_.es_idle_timeout = static_cast<unsigned>((config_.idleTimeoutMs + 999) / 1000);
  settings_.es_scid_len = static_cast<unsigned>(config_.connectionIdBytes);
  settings_.es_pace_packets = 1;
  settings_.es_cc_algo = config_.congestionController == "cubic" ? 1 : 2;
  settings_.es_init_cwnd_bytes = static_cast<unsigned>(config_.initialCongestionWindowBytes);
  settings_.es_delayed_acks = config_.ackFrequency ? 1 : 0;
  settings_.es_allow_migration = config_.activeMigration ? 1 : 0;
  settings_.es_active_connection_id_limit =
      static_cast<unsigned>(config_.activeConnectionIdLimit);
  settings_.es_ecn = config_.packetIo.ecn ? 1 : 0;
  settings_.es_max_udp_payload_size_rx = config_.maxUdpPayloadSize;
  settings_.es_dplpmtud = config_.packetIo.pmtud ? 1 : 0;
  settings_.es_base_plpmtu = config_.maxUdpPayloadSize;
  settings_.es_max_plpmtu = config_.maxUdpPayloadSize;
  settings_.es_max_batch_size = packetBatchSize;
  settings_.es_datagrams = 1;
  settings_.es_max_datagram_frame_size =
      static_cast<unsigned>(config_.datagramMaxFrameSize);

  streamInterface_.on_new_conn = newConnection;
  streamInterface_.on_conn_closed = connectionClosed;
  streamInterface_.on_new_stream = newStream;
  streamInterface_.on_read = streamRead;
  streamInterface_.on_write = streamWrite;
  streamInterface_.on_close = streamClosed;
  streamInterface_.on_reset_ext = streamReset;
  streamInterface_.on_conncloseframe_received = connectionCloseReceived;
  streamInterface_.on_dg_write = datagramWrite;
  streamInterface_.on_datagram = datagramRead;
  streamInterface_.on_hsk_done = handshakeDone;
  streamInterface_.on_sess_resume_info = sessionResumeInfo;

  lsquic_engine_api api {};
  api.ea_settings = &settings_;
  api.ea_stream_if = &streamInterface_;
  api.ea_stream_if_ctx = this;
  api.ea_packets_out = packetsOut;
  api.ea_packets_out_ctx = this;
  api.ea_get_ssl_ctx = getSslContext;
  api.ea_verify_cert = verifyCertificate;
  api.ea_verify_ctx = this;
  api.ea_alpn = "qperf/2";
  engine_ = lsquic_engine_new(flags, &api);
  if (!engine_) { error = {11, "lsquic_engine_new failed"}; return false; }
  return true;
}

bool LsquicAdapter::configure(std::string_view canonicalConfig, AdapterError& error)
{
  if (configured_) { error = {1, "LSQUIC adapter is already configured"}; return false; }
  auto parsed = parseEndpointConfig(canonicalConfig);
  if (!parsed) { error = {1, parsed.error}; return false; }
  config_ = std::move(parsed.config);
  if (!initializeTls(error) || !initializeEngine(error))
  {
    AdapterError ignored;
    reset(ignored);
    return false;
  }
  configured_ = true;
  error = {};
  return true;
}

bool LsquicAdapter::setLocalAddress(const sockaddr_in& local, AdapterError& error)
{
  if (!configured_ || localAddressSet_ || !connections_.empty() || local.sin_family != AF_INET)
  {
    error = {2, "LSQUIC requires one post-bind IPv4 local address before connections"};
    return false;
  }
  in_addr configured {};
  if (inet_pton(AF_INET, config_.bindAddress.c_str(), &configured) != 1 ||
      configured.s_addr != local.sin_addr.s_addr ||
      (config_.bindPort && ntohs(local.sin_port) != config_.bindPort))
  {
    error = {2, "post-bind local address differs from frozen configuration"};
    return false;
  }
  localAddress_ = local;
  localAddressSet_ = true;
  error = {};
  return true;
}

LsquicAdapter::Connection* LsquicAdapter::find(uint64_t id, AdapterError& error) const
{
  const auto found = connectionsById_.find(id);
  if (found != connectionsById_.end()) return found->second;
  error = {3, "unknown LSQUIC connection"};
  return nullptr;
}

LsquicAdapter::Connection* LsquicAdapter::find(lsquic_conn_t* conn) const
{
  const auto found = connections_.find(conn);
  return found == connections_.end() ? nullptr : found->second.get();
}

LsquicAdapter::Connection& LsquicAdapter::adopt(lsquic_conn_t* conn)
{
  const auto existing = connections_.find(conn);
  if (existing != connections_.end())
  {
    if (!existing->second->closed) return *existing->second;
    // LSQUIC may recycle a native connection address before the common
    // workload engine has observed and released the old logical generation.
    // Keep that generation addressable by ID, but free the native-pointer key
    // for the newly accepted connection.
    retiredConnections_.push_back(std::move(existing->second));
    connections_.erase(existing);
  }
  auto owned = std::make_unique<Connection>();
  owned->owner = this;
  owned->id = nextConnectionId_++;
  owned->conn = conn;
  const sockaddr* local = nullptr;
  const sockaddr* peer = nullptr;
  if (lsquic_conn_get_sockaddr(conn, &local, &peer) == 0 && peer && peer->sa_family == AF_INET)
    std::memcpy(&owned->peer, peer, sizeof(sockaddr_in));
  Connection* raw = owned.get();
  connectionsById_.emplace(raw->id, raw);
  connections_.emplace(conn, std::move(owned));
  lsquic_conn_set_ctx(conn, reinterpret_cast<lsquic_conn_ctx_t*>(raw));
  return *raw;
}

LsquicAdapter::Stream* LsquicAdapter::findStream(Connection& connection, uint64_t id,
                                                  AdapterError& error) const
{
  const auto found = connection.streams.find(id);
  if (found != connection.streams.end() && !found->second->closed) return found->second.get();
  error = {4, "unknown or closed LSQUIC stream"};
  return nullptr;
}

lsquic_conn_ctx_t* LsquicAdapter::newConnection(void* context, lsquic_conn_t* conn)
{
  auto& connection = static_cast<LsquicAdapter*>(context)->adopt(conn);
  if (connection.owner->config_.role == EndpointRole::server && !connection.accepted)
  {
    connection.accepted = true;
    connection.owner->acceptedConnections_.push_back(connection.id);
  }
  return reinterpret_cast<lsquic_conn_ctx_t*>(&connection);
}

void LsquicAdapter::connectionClosed(lsquic_conn_t* conn)
{
  auto* connection = reinterpret_cast<Connection*>(lsquic_conn_get_ctx(conn));
  if (!connection || connection->closed) return;
  archiveTransportCounters(*connection);
  connection->closed = true;
}

bool LsquicAdapter::archiveTransportCounters(Connection& connection,
                                             AdapterError* error)
{
  lsquic_conn_info info {};
  if (!connection.conn || lsquic_conn_get_info(connection.conn, &info) != 0)
  {
    if (error) *error = {15, "lsquic_conn_get_info failed while retiring connection"};
    return false;
  }
  if (info.lci_pkts_lost < connection.accountedPacketsLost ||
      info.lci_pkts_retx < connection.accountedPacketsRetransmitted)
  {
    if (error) *error = {15, "LSQUIC transport counters regressed"};
    return false;
  }
  connection.owner->counters_.packetsLost +=
      info.lci_pkts_lost - connection.accountedPacketsLost;
  connection.owner->counters_.packetsRetransmitted +=
      info.lci_pkts_retx - connection.accountedPacketsRetransmitted;
  connection.accountedPacketsLost = info.lci_pkts_lost;
  connection.accountedPacketsRetransmitted = info.lci_pkts_retx;
  return true;
}

lsquic_stream_ctx_t* LsquicAdapter::newStream(void*, lsquic_stream_t* stream)
{
  if (!stream) return nullptr;
  auto* connection = reinterpret_cast<Connection*>(
      lsquic_conn_get_ctx(lsquic_stream_conn(stream)));
  if (!connection) return nullptr;
  const uint64_t id = lsquic_stream_id(stream);
  auto owned = std::make_unique<Stream>();
  owned->stream = stream;
  Stream* raw = owned.get();
  connection->streams[id] = std::move(owned);
  const bool clientInitiated = (id & 1U) == 0;
  const bool locallyInitiated = clientInitiated ==
      (connection->owner->config_.role == EndpointRole::client);
  if (locallyInitiated)
  {
    connection->pendingStream = false;
    connection->openedStreams.push_back(id);
  }
  else connection->acceptedStreams.push_back(id);
  lsquic_stream_wantread(stream, 1);
  return reinterpret_cast<lsquic_stream_ctx_t*>(raw);
}

void LsquicAdapter::streamRead(lsquic_stream_t* stream, lsquic_stream_ctx_t* context)
{
  auto* state = reinterpret_cast<Stream*>(context);
  if (!state) return;
  std::array<std::byte, 64 * 1024> buffer {};
  for (;;)
  {
    const ssize_t count = lsquic_stream_read(stream, buffer.data(), buffer.size());
    if (count > 0)
      state->received.insert(state->received.end(), buffer.begin(), buffer.begin() + count);
    else if (count == 0)
    {
      state->remoteFin = true;
      if (lsquic_stream_shutdown(stream, 0) != 0)
        state->readError = errno ? errno : EIO;
      break;
    }
    else if (errno == EWOULDBLOCK || errno == EAGAIN) break;
    else
    {
      state->readError = errno ? errno : EIO;
      lsquic_stream_wantread(stream, 0);
      break;
    }
  }
}

void LsquicAdapter::streamWrite(lsquic_stream_t* stream, lsquic_stream_ctx_t*)
{
  lsquic_stream_wantwrite(stream, 0);
}

void LsquicAdapter::streamClosed(lsquic_stream_t*, lsquic_stream_ctx_t* context)
{
  auto* stream = reinterpret_cast<Stream*>(context);
  if (stream) stream->closed = true;
}

void LsquicAdapter::streamReset(lsquic_stream_t* native, lsquic_stream_ctx_t* context,
                                int how, uint64_t applicationError)
{
  auto* stream = reinterpret_cast<Stream*>(context);
  if (!stream) return;
  if (how == 0 || how == 2)
  {
    stream->remoteReset = true;
    stream->remoteResetError = applicationError;
  }
  if (how == 1 || how == 2)
  {
    stream->remoteStop = true;
    stream->remoteStopError = applicationError;
    // LSQUIC generates its default RESET_STREAM immediately after this
    // callback. Supply the application-selected code first; the library's
    // fallback observes the pending reset and leaves it unchanged.
    if (how == 1 && !stream->localReset &&
        lsquic_stream_reset_ext(native, applicationError) == 0)
    {
      stream->localReset = true;
      stream->localResetError = applicationError;
    }
  }
}

void LsquicAdapter::connectionCloseReceived(lsquic_conn_t* conn, int,
                                            uint64_t errorCode, const char*,
                                            int reasonLength)
{
  auto* connection = reinterpret_cast<Connection*>(lsquic_conn_get_ctx(conn));
  if (!connection) return;
  connection->peerConnectionClose = true;
  connection->peerConnectionCloseError = errorCode;
  connection->peerConnectionCloseReasonLength =
      reasonLength > 0 ? static_cast<uint64_t>(reasonLength) : 0;
}

ssize_t LsquicAdapter::datagramWrite(lsquic_conn_t* conn, void* bytes, size_t capacity)
{
  auto* connection = reinterpret_cast<Connection*>(lsquic_conn_get_ctx(conn));
  if (!connection || connection->transmitDatagrams.empty()) return 0;
  auto& datagram = connection->transmitDatagrams.front();
  if (datagram.size() > capacity) return -1;
  std::memcpy(bytes, datagram.data(), datagram.size());
  const ssize_t length = static_cast<ssize_t>(datagram.size());
  connection->transmitDatagrams.pop_front();
  lsquic_conn_want_datagram_write(conn, !connection->transmitDatagrams.empty());
  return length;
}

void LsquicAdapter::datagramRead(lsquic_conn_t* conn, const void* bytes, size_t length)
{
  auto* connection = reinterpret_cast<Connection*>(lsquic_conn_get_ctx(conn));
  if (!connection) return;
  const auto* first = static_cast<const std::byte*>(bytes);
  connection->receivedDatagrams.emplace_back(first, first + length);
}

void LsquicAdapter::handshakeDone(lsquic_conn_t* conn, lsquic_hsk_status status)
{
  auto* connection = reinterpret_cast<Connection*>(lsquic_conn_get_ctx(conn));
  if (!connection) return;
  connection->resumed = status == LSQ_HSK_RESUMED_OK;
}

void LsquicAdapter::sessionResumeInfo(lsquic_conn_t* conn, const unsigned char* bytes,
                                      size_t length)
{
  auto* connection = reinterpret_cast<Connection*>(lsquic_conn_get_ctx(conn));
  if (!connection) return;
  const auto* first = reinterpret_cast<const std::byte*>(bytes);
  connection->session.assign(first, first + length);
}

int LsquicAdapter::packetsOut(void* context, const lsquic_out_spec* specifications,
                              unsigned count)
{
  auto& owner = *static_cast<LsquicAdapter*>(context);
  for (unsigned index = 0; index < count; ++index)
  {
    const auto& specification = specifications[index];
    size_t length = 0;
    for (size_t item = 0; item < specification.iovlen; ++item)
      length += specification.iov[item].iov_len;
    if (length > maxUdpPayloadSize || !specification.dest_sa ||
        specification.dest_sa->sa_family != AF_INET)
    {
      errno = EMSGSIZE;
      return index ? static_cast<int>(index) : -1;
    }
    OutputPacket packet;
    packet.bytes.resize(length);
    size_t offset = 0;
    for (size_t item = 0; item < specification.iovlen; ++item)
    {
      std::memcpy(packet.bytes.data() + offset, specification.iov[item].iov_base,
                  specification.iov[item].iov_len);
      offset += specification.iov[item].iov_len;
    }
    std::memcpy(&packet.peer, specification.dest_sa, sizeof(sockaddr_in));
    packet.ecn = static_cast<uint8_t>(specification.ecn);
    owner.outputQueue_.push_back(std::move(packet));
    ++owner.counters_.packetsSent;
  }
  return static_cast<int>(count);
}

void LsquicAdapter::updateTimeout(uint64_t nowRawNs) noexcept
{
  int microseconds = 0;
  if (!engine_ || !lsquic_engine_earliest_adv_tick(engine_, &microseconds))
  {
    nextTimeoutRawNs_ = 0;
    return;
  }
  const uint64_t delay = microseconds <= 0 ? 1 : static_cast<uint64_t>(microseconds) * 1000;
  nextTimeoutRawNs_ = nowRawNs > std::numeric_limits<uint64_t>::max() - delay ?
      std::numeric_limits<uint64_t>::max() : nowRawNs + delay;
}

void LsquicAdapter::process(uint64_t nowRawNs)
{
  lsquic_engine_process_conns(engine_);
  if (lsquic_engine_has_unsent_packets(engine_)) lsquic_engine_send_unsent_packets(engine_);
  reapReleasedConnections();
  updateTimeout(nowRawNs);
}

void LsquicAdapter::reapReleasedConnections()
{
  std::erase_if(connections_, [this](const auto& item) {
    const auto& connection = item.second;
    if (!connection->closed || !connection->releaseWhenClosed) return false;
    connectionsById_.erase(connection->id);
    return true;
  });
  std::erase_if(retiredConnections_, [this](const auto& connection) {
    if (!connection->closed || !connection->releaseWhenClosed) return false;
    connectionsById_.erase(connection->id);
    return true;
  });
}

bool LsquicAdapter::receiveBatch(std::span<const ReceivedPacket> packets, uint64_t nowRawNs,
                                 AdapterError& error)
{
  if (!configured_ || !localAddressSet_) { error = {5, "LSQUIC adapter is not ready"}; return false; }
  for (const auto& packet : packets)
  {
    if (packet.peer.sin_family != AF_INET || packet.bytes.empty())
    {
      error = {5, "invalid LSQUIC received packet"};
      return false;
    }
    const int result = lsquic_engine_packet_in(
        engine_, reinterpret_cast<const unsigned char*>(packet.bytes.data()), packet.bytes.size(),
        reinterpret_cast<const sockaddr*>(&localAddress_),
        reinterpret_cast<const sockaddr*>(&packet.peer), this, packet.ecn);
    if (result < 0) { error = {5, "lsquic_engine_packet_in failed"}; return false; }
    ++counters_.packetsReceived;
  }
  process(nowRawNs);
  error = {};
  return true;
}

size_t LsquicAdapter::pollTransmitBatch(std::span<TransmitPacket> packets,
                                        uint64_t nowRawNs, AdapterError& error)
{
  if (!configured_ || !localAddressSet_) { error = {6, "LSQUIC adapter is not ready"}; return 0; }
  process(nowRawNs);
  const size_t count = std::min({packets.size(), output_.size(), outputQueue_.size()});
  for (size_t index = 0; index < count; ++index)
  {
    auto packet = std::move(outputQueue_.front());
    outputQueue_.pop_front();
    std::copy(packet.bytes.begin(), packet.bytes.end(), output_[index].begin());
    packets[index] = {std::span<const std::byte>(output_[index]).first(packet.bytes.size()),
                      packet.peer, packet.ecn, 0, nowRawNs};
  }
  error = {};
  return count;
}

bool LsquicAdapter::onTimeout(uint64_t nowRawNs, AdapterError& error)
{
  if (!engine_) { error = {7, "LSQUIC adapter is not configured"}; return false; }
  ++counters_.timerExpirations;
  process(nowRawNs);
  error = {};
  return true;
}

bool LsquicAdapter::connect(const sockaddr_in& peer, uint64_t nowRawNs,
                            uint64_t& connectionId, AdapterError& error)
{
  if (!configured_ || !localAddressSet_ || config_.role != EndpointRole::client ||
      peer.sin_family != AF_INET)
  {
    error = {8, "LSQUIC connect requires a configured client and IPv4 peer"};
    return false;
  }
  const unsigned char* session = importedSessionPending_ ?
      reinterpret_cast<const unsigned char*>(importedSession_.data()) : nullptr;
  const size_t sessionLength = importedSessionPending_ ? importedSession_.size() : 0;
  const bool useZeroRtt = importedSessionPending_ && importedZeroRtt_;
  const std::string sessionKey = importedSessionPending_ ?
      std::string(reinterpret_cast<const char*>(importedSession_.data()),
                  importedSession_.size()) : std::string {};
  lsquic_conn_t* conn = lsquic_engine_connect_ext(
      engine_, LSQVER_I001, reinterpret_cast<const sockaddr*>(&localAddress_),
      reinterpret_cast<const sockaddr*>(&peer), this, nullptr, config_.tlsHostname.c_str(),
      config_.maxUdpPayloadSize, session, sessionLength, nullptr, 0, useZeroRtt);
  importedSessionPending_ = false;
  importedZeroRtt_ = false;
  if (!conn) { error = {8, "lsquic_engine_connect failed"}; return false; }
  if (!sessionKey.empty()) consumedSessions_.insert(sessionKey);
  auto& connection = adopt(conn);
  connection.peer = peer;
  connectionId = connection.id;
  process(nowRawNs);
  error = {};
  return true;
}

PrimitiveStatus LsquicAdapter::acceptConnection(uint64_t, uint64_t& connectionId,
                                                 AdapterError& error)
{
  if (config_.role != EndpointRole::server) return unavailable("acceptConnection", error);
  if (acceptedConnections_.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  connectionId = acceptedConnections_.front();
  acceptedConnections_.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

bool LsquicAdapter::isConnected(uint64_t connectionId, uint64_t, bool& connected,
                                AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  connected = !connection->closed &&
      lsquic_conn_status(connection->conn, nullptr, 0) == LSCONN_ST_CONNECTED;
  error = {};
  return true;
}

bool LsquicAdapter::peerTerminalFacts(uint64_t connectionId, uint64_t streamId,
                                      uint64_t, PeerTerminalFacts& facts,
                                      AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  const auto found = connection->streams.find(streamId);
  if (found == connection->streams.end())
  {
    error = {4, "unknown LSQUIC stream"};
    return false;
  }
  const auto& stream = *found->second;
  facts.available = true;
  facts.fin = stream.remoteFin;
  facts.resetStream = stream.remoteReset;
  facts.stopSending = stream.remoteStop;
  facts.connectionClose = connection->peerConnectionClose;
  facts.resetStreamError = stream.remoteResetError;
  facts.stopSendingError = stream.remoteStopError;
  facts.connectionCloseError = connection->peerConnectionCloseError;
  facts.connectionCloseReasonLength = connection->peerConnectionCloseReasonLength;
  error = {};
  return true;
}

bool LsquicAdapter::connectionIsClosed(uint64_t connectionId, uint64_t,
                                       bool& closed, AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  closed = connection->closed;
  error = {};
  return true;
}

bool LsquicAdapter::releaseConnectionWhenClosed(uint64_t connectionId, uint64_t,
                                                AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  if (!connection->closed && !archiveTransportCounters(*connection, &error))
    return false;
  connection->releaseWhenClosed = true;
  connectionsById_.erase(connectionId);
  if (!connection->closed) lsquic_conn_abort(connection->conn);
  error = {};
  return true;
}

PrimitiveStatus LsquicAdapter::openBidirectionalStream(uint64_t connectionId, uint64_t,
                                                       uint64_t& streamId,
                                                       AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (!connection->openedStreams.empty())
  {
    streamId = connection->openedStreams.front();
    connection->openedStreams.pop_front();
    error = {};
    return PrimitiveStatus::ready;
  }
  if (!connection->pendingStream)
  {
    connection->pendingStream = true;
    lsquic_conn_make_stream(connection->conn);
    if (!connection->openedStreams.empty())
    {
      streamId = connection->openedStreams.front();
      connection->openedStreams.pop_front();
      error = {};
      return PrimitiveStatus::ready;
    }
  }
  error = {};
  return PrimitiveStatus::wouldBlock;
}

PrimitiveStatus LsquicAdapter::acceptBidirectionalStream(uint64_t connectionId, uint64_t,
                                                         uint64_t& streamId,
                                                         AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (connection->acceptedStreams.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  streamId = connection->acceptedStreams.front();
  connection->acceptedStreams.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus LsquicAdapter::unavailable(std::string_view primitive,
                                           AdapterError& error) const
{
  error = {9, "LSQUIC source package does not expose " + std::string(primitive)};
  return PrimitiveStatus::fatal;
}

PrimitiveStatus LsquicAdapter::openUnidirectionalStream(uint64_t, uint64_t, uint64_t&,
                                                        AdapterError& error)
{
  return unavailable("unidirectional stream creation", error);
}

PrimitiveStatus LsquicAdapter::acceptUnidirectionalStream(uint64_t, uint64_t, uint64_t&,
                                                          AdapterError& error)
{
  return unavailable("unidirectional stream acceptance", error);
}

bool LsquicAdapter::writeStream(uint64_t connectionId, uint64_t streamId,
                                std::span<const std::byte> bytes, uint64_t,
                                size_t& written, AdapterError& error)
{
  written = 0;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  auto* stream = findStream(*connection, streamId, error);
  if (!stream) return false;
  const ssize_t result = lsquic_stream_write(stream->stream, bytes.data(), bytes.size());
  if (result < 0 && errno != EWOULDBLOCK && errno != EAGAIN)
  {
    error = {10, "lsquic_stream_write failed: " + std::string(std::strerror(errno))};
    return false;
  }
  written = result > 0 ? static_cast<size_t>(result) : 0;
  if (written) lsquic_stream_flush(stream->stream);
  error = {};
  return true;
}

bool LsquicAdapter::consumeStreamData(uint64_t connectionId, uint64_t streamId,
                                      std::span<std::byte> bytes, uint64_t,
                                      size_t& read, bool& finished, AdapterError& error)
{
  read = 0;
  finished = false;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  const auto found = connection->streams.find(streamId);
  if (found == connection->streams.end())
  {
    error = {4, "unknown LSQUIC stream"};
    return false;
  }
  auto* stream = found->second.get();
  if (stream->readError && !(stream->remoteReset && stream->readError == ECONNRESET))
  {
    error = {10, "lsquic_stream_read failed: " +
                     std::string(std::strerror(stream->readError))};
    return false;
  }
  read = std::min(bytes.size(), stream->received.size() - stream->receiveOffset);
  std::copy_n(stream->received.begin() + stream->receiveOffset, read, bytes.begin());
  stream->receiveOffset += read;
  finished = stream->remoteFin && stream->receiveOffset == stream->received.size();
  if (stream->receiveOffset == stream->received.size())
  {
    stream->received.clear();
    stream->receiveOffset = 0;
  }
  error = {};
  return true;
}

bool LsquicAdapter::finishStream(uint64_t connectionId, uint64_t streamId, uint64_t,
                                 AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  auto* stream = findStream(*connection, streamId, error);
  if (!stream) return false;
  if (lsquic_stream_shutdown(stream->stream, 1) != 0)
  {
    error = {11, "lsquic_stream_shutdown(write) failed"};
    return false;
  }
  lsquic_stream_flush(stream->stream);
  error = {};
  return true;
}

bool LsquicAdapter::resetStream(uint64_t connectionId, uint64_t streamId,
                                uint64_t applicationError, uint64_t,
                                AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  auto* stream = findStream(*connection, streamId, error);
  if (!stream) return false;
  if (stream->localReset)
  {
    if (stream->localResetError != applicationError)
    {
      error = {11, "LSQUIC stream was already reset with a different application error"};
      return false;
    }
    error = {};
    return true;
  }
  if (lsquic_stream_reset_ext(stream->stream, applicationError) != 0)
  {
    error = {11, "lsquic_stream_reset_ext failed: " +
                     std::string(std::strerror(errno))};
    return false;
  }
  stream->localReset = true;
  stream->localResetError = applicationError;
  error = {};
  return true;
}

bool LsquicAdapter::stopSending(uint64_t connectionId, uint64_t streamId,
                                uint64_t applicationError, uint64_t,
                                AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  auto* stream = findStream(*connection, streamId, error);
  if (!stream) return false;
  if (lsquic_stream_stop_sending_ext(stream->stream, applicationError) != 0)
  {
    error = {12, "lsquic_stream_stop_sending_ext failed: " +
                     std::string(std::strerror(errno))};
    return false;
  }
  error = {};
  return true;
}

PrimitiveStatus LsquicAdapter::sendDatagram(uint64_t connectionId,
                                            std::span<const std::byte> bytes,
                                            uint64_t, AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (connection->closed ||
      lsquic_conn_status(connection->conn, nullptr, 0) != LSCONN_ST_CONNECTED)
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  if (bytes.empty() || bytes.size() > config_.maxUdpPayloadSize)
    return unavailable("requested DATAGRAM size", error);
  if (lsquic_conn_set_min_datagram_size(connection->conn, bytes.size()) != 0)
  {
    error = {12, "lsquic_conn_set_min_datagram_size failed"};
    return PrimitiveStatus::fatal;
  }
  connection->transmitDatagrams.emplace_back(bytes.begin(), bytes.end());
  if (lsquic_conn_want_datagram_write(connection->conn, 1) < 0)
  {
    connection->transmitDatagrams.pop_back();
    error = {12, "lsquic_conn_want_datagram_write failed"};
    return PrimitiveStatus::fatal;
  }
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus LsquicAdapter::consumeDatagram(uint64_t connectionId,
                                               std::span<std::byte> bytes,
                                               uint64_t, size_t& read,
                                               AdapterError& error)
{
  read = 0;
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (connection->receivedDatagrams.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  auto& datagram = connection->receivedDatagrams.front();
  if (datagram.size() > bytes.size()) return unavailable("DATAGRAM destination capacity", error);
  read = datagram.size();
  std::copy(datagram.begin(), datagram.end(), bytes.begin());
  connection->receivedDatagrams.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus LsquicAdapter::exportResumptionState(uint64_t connectionId, uint64_t nowRawNs,
                                                     std::span<std::byte> bytes,
                                                     size_t& written,
                                                     AdapterError& error)
{
  written = 0;
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (connection->session.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  return sealResumptionState(connection->session, nowRawNs, bytes, written, error) ?
      PrimitiveStatus::ready : PrimitiveStatus::fatal;
}

PrimitiveStatus LsquicAdapter::importResumptionState(std::span<const std::byte> bytes,
                                                     bool useZeroRtt, uint64_t nowRawNs,
                                                     AdapterError& error)
{
  if (bytes.empty() || importedSessionPending_)
    return unavailable("empty or concurrent resumption import", error);
  std::span<const std::byte> session;
  if (openResumptionState(bytes, nowRawNs, config_.tlsTicketLifetimeNs,
                          session, error) != PrimitiveStatus::ready)
    return PrimitiveStatus::fatal;
  const std::string sessionKey(
      reinterpret_cast<const char*>(session.data()), session.size());
  if (consumedSessions_.contains(sessionKey))
    return unavailable("resumption ticket was already consumed", error);
  importedSession_.assign(session.begin(), session.end());
  importedSessionPending_ = true;
  importedZeroRtt_ = useZeroRtt;
  error = {};
  return PrimitiveStatus::ready;
}

bool LsquicAdapter::connectionResumed(uint64_t connectionId, uint64_t, bool& resumed,
                                      AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  resumed = connection->resumed;
  error = {};
  return true;
}

bool LsquicAdapter::zeroRttAttempted(uint64_t connectionId, uint64_t, bool& attempted,
                                     AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  int nativeAttempted = 0, accepted = 0, rejected = 0;
  if (lsquic_conn_get_early_data_status(
          connection->conn, &nativeAttempted, &accepted, &rejected) != 0)
  {
    error = {13, "lsquic_conn_get_early_data_status failed"};
    return false;
  }
  attempted = nativeAttempted != 0;
  error = {};
  return true;
}

bool LsquicAdapter::zeroRttAccepted(uint64_t connectionId, uint64_t, bool& accepted,
                                    AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  int attempted = 0, nativeAccepted = 0, rejected = 0;
  if (lsquic_conn_get_early_data_status(
          connection->conn, &attempted, &nativeAccepted, &rejected) != 0)
  {
    error = {13, "lsquic_conn_get_early_data_status failed"};
    return false;
  }
  accepted = nativeAccepted != 0;
  error = {};
  return true;
}

bool LsquicAdapter::zeroRttRejected(uint64_t connectionId, uint64_t, bool& rejected,
                                    AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  int attempted = 0, accepted = 0, nativeRejected = 0;
  if (lsquic_conn_get_early_data_status(
          connection->conn, &attempted, &accepted, &nativeRejected) != 0)
  {
    error = {13, "lsquic_conn_get_early_data_status failed"};
    return false;
  }
  rejected = nativeRejected != 0;
  error = {};
  return true;
}

bool LsquicAdapter::closeConnection(uint64_t connectionId, uint64_t applicationError,
                                    uint64_t,
                                    AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  if (lsquic_conn_close_ext(connection->conn, applicationError, "", 0) != 0)
  {
    error = {14, "lsquic_conn_close_ext failed: " +
                     std::string(std::strerror(errno))};
    return false;
  }
  error = {};
  return true;
}

TransportCounters LsquicAdapter::snapshotTransportCounters() const noexcept
{
  TransportCounters result = counters_;
  uint64_t lost = 0;
  uint64_t retransmitted = 0;
  for (const auto& [_, connection] : connectionsById_)
  {
    if (connection->closed) continue;
    lsquic_conn_info info {};
    if (lsquic_conn_get_info(connection->conn, &info) == 0)
    {
      lost += info.lci_pkts_lost;
      retransmitted += info.lci_pkts_retx;
    }
  }
  result.packetsLost += lost;
  result.packetsRetransmitted += retransmitted;
  return result;
}

NegotiatedSettings LsquicAdapter::snapshotNegotiatedSettings() const noexcept
{
  const auto snapshot = [this](const Connection& connection)
  {
    NegotiatedSettings result;
    result.evidenceSource =
        "lsquic_peer_transport_params+boringssl_post_handshake+"
        "lsquic_applied_settings+qpf2_lifecycle_policy";
    const auto unavailable = [&result](std::string field) {
      if (std::find(result.unavailableFields.begin(), result.unavailableFields.end(),
                    field) == result.unavailableFields.end())
        result.unavailableFields.push_back(std::move(field));
    };
    if (!connection.conn || connection.closed ||
        lsquic_conn_status(connection.conn, nullptr, 0) != LSCONN_ST_CONNECTED)
    {
      unavailable("handshake_not_complete");
      return result;
    }
    lsquic_conn_negotiated peer {};
    if (lsquic_conn_get_negotiated(connection.conn, &peer) != 0)
    {
      unavailable("remote_transport_or_tls_state");
      return result;
    }
    result.available = true;
    result.quicVersion = peer.quic_version;
    result.alpn.assign(reinterpret_cast<const char*>(peer.alpn), peer.alpn_len);
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
    else if (X509* certificate = SSL_CTX_get0_certificate(sslContext_))
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
    result.initialCongestionWindowBytes = settings_.es_init_cwnd_bytes;
    result.maxUdpPayloadSize = peer.max_udp_payload_size;
    result.maxAckDelayNs = peer.max_ack_delay * 1'000'000ULL;
    result.ackDelayExponent = peer.ack_delay_exponent;
    result.ackFrequency = settings_.es_delayed_acks != 0;
    result.activeMigration = !peer.disable_active_migration;
    result.activeConnectionIdLimit = peer.active_connection_id_limit;
    result.connectionIdBytes = peer.connection_id_len;
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

  NegotiatedSettings result;
  bool found = false;
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
  for (const auto& [_, connection] : connectionsById_)
  {
    if (!connection->conn || connection->closed ||
        lsquic_conn_status(connection->conn, nullptr, 0) != LSCONN_ST_CONNECTED)
      continue;
    auto current = snapshot(*connection);
    if (!found)
    {
      result = std::move(current);
      found = true;
    }
    else if (!same(result, current))
    {
      result.unavailableFields = {"per_connection_evidence_mismatch"};
      break;
    }
  }
  if (!found) result.unavailableFields = {"no_established_connection"};
  return result;
}

bool LsquicAdapter::reset(AdapterError& error)
{
  if (engine_) lsquic_engine_destroy(std::exchange(engine_, nullptr));
  connections_.clear();
  retiredConnections_.clear();
  connectionsById_.clear();
  acceptedConnections_.clear();
  outputQueue_.clear();
  importedSession_.clear();
  consumedSessions_.clear();
  if (sslContext_) SSL_CTX_free(std::exchange(sslContext_, nullptr));
  nextConnectionId_ = 1;
  nextTimeoutRawNs_ = 0;
  configured_ = false;
  localAddressSet_ = false;
  importedSessionPending_ = false;
  importedZeroRtt_ = false;
  counters_ = {};
  settings_ = {};
  streamInterface_ = {};
  error = {};
  return true;
}

} // namespace

std::unique_ptr<Adapter> makeTransportAdapter()
{
  return std::make_unique<LsquicAdapter>();
}

} // namespace quicperf
