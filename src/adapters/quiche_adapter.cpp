#include "adapter_factory.h"
#include "resumption_envelope.h"
#include "core/measurement.h"
#include "core/strict_config.h"

#include <quiche.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
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

constexpr size_t connectionIdLength = 8;
constexpr uint8_t initialPacketType = 1;
constexpr std::array<uint8_t, 8> alpn = {7, 'q', 'p', 'e', 'r', 'f', '/', '2'};
constexpr std::array<uint16_t, 1> signatureAlgorithms = {SSL_SIGN_ED25519};

void debugLog(const char* line, void*) { std::fprintf(stderr, "quiche: %s\n", line); }

bool sameAddress(const sockaddr_in& left, const sockaddr_in& right) noexcept
{
  return left.sin_family == AF_INET && right.sin_family == AF_INET &&
      left.sin_port == right.sin_port && left.sin_addr.s_addr == right.sin_addr.s_addr;
}

std::string cidKey(const uint8_t* data, size_t length)
{
  return std::string(reinterpret_cast<const char*>(data), length);
}

void appendU64(std::vector<std::byte>& output, uint64_t value)
{
  for (int shift = 56; shift >= 0; shift -= 8)
    output.push_back(static_cast<std::byte>((value >> shift) & 0xff));
}

bool remoteInitiated(uint64_t streamId, EndpointRole role) noexcept
{
  const bool initiatedByServer = (streamId & 1U) != 0;
  return initiatedByServer == (role == EndpointRole::client);
}

bool bidirectional(uint64_t streamId) noexcept { return (streamId & 2U) == 0; }

class QuicheAdapter final : public Adapter {
public:
  QuicheAdapter();
  ~QuicheAdapter() override;

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
  struct Connection {
    ~Connection() { if (native) quiche_conn_free(native); }
    uint64_t id = 0;
    quiche_conn* native = nullptr;
    SSL* tls = nullptr; // Owned by native.
    sockaddr_in local {};
    sockaddr_in peer {};
    std::unordered_set<uint64_t> knownStreams;
    std::unordered_set<uint64_t> acceptedStreams;
    std::unordered_set<uint64_t> writeBlockedStreams;
    std::deque<uint64_t> acceptedBidi;
    std::deque<uint64_t> acceptedUni;
    std::unordered_map<uint64_t, PeerTerminalFacts> peerTerminal;
    PeerTerminalFacts peerConnectionTerminal {};
    uint64_t nextBidi = 0;
    uint64_t nextUni = 0;
    uint64_t timeoutRawNs = 0;
    bool zeroRttAttempted = false;
    bool earlyObserved = false;
    bool locallyClosing = false;
  };

  struct Header {
    uint32_t version = 0;
    uint8_t type = 0;
    std::array<uint8_t, QUICHE_MAX_CONN_ID_LEN> scid {};
    size_t scidLength = scid.size();
    std::array<uint8_t, QUICHE_MAX_CONN_ID_LEN> dcid {};
    size_t dcidLength = dcid.size();
    std::array<uint8_t, 256> token {};
    size_t tokenLength = token.size();
  };

  static bool randomCid(std::array<uint8_t, connectionIdLength>& cid,
                        AdapterError& error);
  static int selectAlpn(SSL*, const uint8_t** output, uint8_t* outputLength,
                        const uint8_t* input, unsigned inputLength, void*);
  static int tlsContextIndex();
  static int newSession(SSL* ssl, SSL_SESSION* session);
  SSL* newSsl(AdapterError& error) const;
  bool valid(int code, std::string_view operation, AdapterError& error) const;
  bool parseHeader(std::span<const std::byte> bytes, Header& header,
                   AdapterError& error) const;
  Connection* createClient(const sockaddr_in& peer, AdapterError& error);
  Connection* createServer(const ReceivedPacket& packet, const Header& header,
                           AdapterError& error);
  Connection* find(uint64_t id, AdapterError& error) const;
  Connection* route(const Header& header) const;
  void refreshCids(Connection& connection);
  void refreshStreams(Connection& connection);
  size_t activeConnections() const noexcept;
  uint64_t serverConnectionLimit() const noexcept;
  void retireConnection(uint64_t id) noexcept;
  void reapLocallyClosed() noexcept;
  void updateTimeout(uint64_t nowRawNs) noexcept;
  PrimitiveStatus openStream(Connection& connection, bool bidi, uint64_t& streamId,
                             AdapterError& error);
  PrimitiveStatus acceptStream(Connection& connection, bool bidi, uint64_t& streamId,
                               AdapterError& error);
  bool retainPeerStop(Connection& connection, uint64_t streamId, AdapterError& error);

  Capabilities capabilities_;
  EndpointConfig config_ {};
  quiche_config* nativeConfig_ = nullptr;
  SSL_CTX* tlsContext_ = nullptr;
  sockaddr_in localAddress_ {};
  std::vector<std::unique_ptr<Connection>> connections_;
  std::unordered_map<uint64_t, Connection*> byId_;
  std::unordered_map<std::string, Connection*> byCid_;
  std::deque<uint64_t> acceptedConnections_;
  std::optional<std::vector<std::byte>> importedSession_;
  std::unordered_set<std::string> consumedSessions_;
  std::deque<std::vector<std::byte>> savedSessions_;
  bool importedZeroRtt_ = false;
  uint64_t nextConnectionId_ = 1;
  uint64_t nextTimeoutRawNs_ = 0;
  size_t transmitCursor_ = 0;
  bool configured_ = false;
  bool localAddressSet_ = false;
  std::array<std::array<std::byte, maxUdpPayloadSize>, packetBatchSize> output_ {};
  std::array<uint8_t, 48> ticketKey_ {};
  TransportCounters counters_ {};
};

QuicheAdapter::QuicheAdapter()
{
  capabilities_.library = "quiche";
  capabilities_.buildId = std::string("quiche-") + quiche_version() + "-terminal-facts-v3";
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
      workload::Scenario::memoryCurve, workload::Scenario::closeResetCleanup};
  capabilities_.datagram = true;
  capabilities_.resumption = true;
  capabilities_.earlyData = true;
  capabilities_.effectiveFeatures = {
      "common_cpp_packet_io", "borrowed_packet_batch_64", "ipv4", "quic_v1",
      "tls_1_3", "qperf_2_alpn", "bidirectional_stream", "unidirectional_stream",
      "datagram", "resumption", "early_data", "post_bind_local_address",
      "reset_stream", "stop_sending", "connection_close", "peer_terminal_facts",
      "exact_transport_counters"};
}

QuicheAdapter::~QuicheAdapter()
{
  AdapterError ignored;
  reset(ignored);
}

bool QuicheAdapter::valid(int code, std::string_view operation, AdapterError& error) const
{
  if (code == 0) return true;
  error = {static_cast<uint64_t>(-static_cast<int64_t>(code)),
           std::string(operation) + " failed with quiche error " + std::to_string(code)};
  return false;
}

bool QuicheAdapter::randomCid(std::array<uint8_t, connectionIdLength>& cid,
                              AdapterError& error)
{
  if (RAND_bytes(cid.data(), cid.size()) != 1)
  {
    error = {10, "failed to generate quiche connection ID"};
    return false;
  }
  return true;
}

int QuicheAdapter::selectAlpn(SSL*, const uint8_t** output, uint8_t* outputLength,
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

int QuicheAdapter::tlsContextIndex()
{
  static const int index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return index;
}

int QuicheAdapter::newSession(SSL* ssl, SSL_SESSION* session)
{
  SSL_CTX* context = SSL_get_SSL_CTX(ssl);
  auto* self = context ?
      static_cast<QuicheAdapter*>(SSL_CTX_get_ex_data(context, tlsContextIndex())) : nullptr;
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

SSL* QuicheAdapter::newSsl(AdapterError& error) const
{
  SSL* ssl = SSL_new(tlsContext_);
  if (!ssl)
  {
    error = {10, "SSL_new failed for quiche"};
    return nullptr;
  }
  if (config_.role == EndpointRole::client &&
      (SSL_set_tlsext_host_name(ssl, config_.tlsHostname.c_str()) != 1 ||
       (config_.tlsVerifyPeer && SSL_set1_host(ssl, config_.tlsHostname.c_str()) != 1)))
  {
    SSL_free(ssl);
    error = {10, "failed to set quiche TLS hostname"};
    return nullptr;
  }
  return ssl;
}

bool QuicheAdapter::configure(std::string_view canonicalConfig, AdapterError& error)
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
    error = {1, "quiche cannot honor the requested congestion controller"};
    return false;
  }
  if (parsed.config.packetIo.ecn)
  {
    error = {1, "quiche adapter cannot exchange packet ECN metadata"};
    return false;
  }
  config_ = parsed.config;
  if (std::getenv("QUICPERF_ADAPTER_DEBUG")) quiche_enable_debug_logging(debugLog, nullptr);
  FILE* random = std::fopen("/dev/urandom", "rb");
  if (!random || std::fread(ticketKey_.data(), 1, ticketKey_.size(), random) != ticketKey_.size())
  {
    if (random) std::fclose(random);
    error = {10, "failed to generate quiche ticket key"};
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
    error = {10, "failed to configure quiche TLS policy"};
    reset(ignored);
    return false;
  }
  SSL_CTX_set_early_data_enabled(tlsContext_, 1);
  SSL_CTX_set_session_psk_dhe_timeout(tlsContext_, 300);
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
      error = {10, "failed to load quiche server certificate or private key"};
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
      error = {10, "failed to load quiche trust chain"};
      reset(ignored);
      return false;
    }
    SSL_CTX_set_alpn_protos(tlsContext_, alpn.data(), alpn.size());
  }
  nativeConfig_ = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if (!nativeConfig_)
  {
    error = {10, "quiche_config_new failed"};
    return false;
  }
  int status = quiche_config_set_application_protos(nativeConfig_, alpn.data(), alpn.size());
  if (!status && config_.role == EndpointRole::server)
    status = quiche_config_load_cert_chain_from_pem_file(
        nativeConfig_, config_.certificatePath.c_str());
  if (!status && config_.role == EndpointRole::server)
    status = quiche_config_load_priv_key_from_pem_file(
        nativeConfig_, config_.privateKeyPath.c_str());
  if (!status && config_.role == EndpointRole::client && config_.tlsVerifyPeer)
    status = quiche_config_load_verify_locations_from_file(
        nativeConfig_, config_.chainPath.c_str());
  if (status)
  {
    valid(status, "quiche TLS configuration", error);
    reset(ignored);
    return false;
  }
  quiche_config_verify_peer(nativeConfig_, config_.tlsVerifyPeer);
  quiche_config_set_max_idle_timeout(nativeConfig_, config_.idleTimeoutMs);
  quiche_config_set_max_recv_udp_payload_size(nativeConfig_, config_.maxUdpPayloadSize);
  quiche_config_set_max_send_udp_payload_size(nativeConfig_, config_.maxUdpPayloadSize);
  quiche_config_set_initial_max_data(nativeConfig_, config_.connectionWindow);
  quiche_config_set_initial_max_stream_data_bidi_local(nativeConfig_, config_.streamWindow);
  quiche_config_set_initial_max_stream_data_bidi_remote(nativeConfig_, config_.streamWindow);
  quiche_config_set_initial_max_stream_data_uni(nativeConfig_, config_.streamWindow);
  quiche_config_set_initial_max_streams_bidi(nativeConfig_, config_.maxBidiStreams);
  quiche_config_set_initial_max_streams_uni(nativeConfig_, config_.maxUniStreams);
  quiche_config_set_ack_delay_exponent(nativeConfig_, config_.ackDelayExponent);
  quiche_config_set_max_ack_delay(nativeConfig_, config_.maxAckDelayNs / 1'000'000);
  quiche_config_set_max_connection_window(nativeConfig_, config_.connectionWindow);
  quiche_config_set_max_stream_window(nativeConfig_, config_.streamWindow);
  quiche_config_set_disable_active_migration(nativeConfig_, true);
  quiche_config_set_active_connection_id_limit(
      nativeConfig_, config_.activeConnectionIdLimit);
  quiche_config_set_initial_congestion_window_packets(
      nativeConfig_, config_.initialCongestionWindowBytes / config_.maxUdpPayloadSize);
  quiche_config_discover_pmtu(nativeConfig_, config_.packetIo.pmtud);
  quiche_config_enable_pacing(nativeConfig_, config_.packetIo.commonPacing);
  quiche_config_enable_dgram(nativeConfig_, true,
                             config_.datagramMaxUnreturnedPerConnection,
                             config_.datagramMaxUnreturnedPerConnection);
  quiche_config_set_max_datagram_frame_size(
      nativeConfig_, config_.datagramMaxFrameSize);
  quiche_config_enable_early_data(nativeConfig_);
  if (!valid(quiche_config_set_cc_algorithm_name(
                 nativeConfig_, config_.congestionController.c_str()),
             "quiche_config_set_cc_algorithm_name", error))
  {
    reset(ignored);
    return false;
  }
  configured_ = true;
  error = {};
  return true;
}

bool QuicheAdapter::setLocalAddress(const sockaddr_in& local, AdapterError& error)
{
  if (!configured_ || localAddressSet_ || !connections_.empty() ||
      local.sin_family != AF_INET || local.sin_port == 0)
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

bool QuicheAdapter::parseHeader(std::span<const std::byte> bytes, Header& header,
                                AdapterError& error) const
{
  if (bytes.empty() || bytes.size() > config_.maxUdpPayloadSize)
  {
    error = {1, "invalid borrowed receive packet"};
    return false;
  }
  const int status = quiche_header_info(
      reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(), connectionIdLength,
      &header.version, &header.type, header.scid.data(), &header.scidLength,
      header.dcid.data(), &header.dcidLength, header.token.data(), &header.tokenLength);
  return valid(status, "quiche_header_info", error);
}

QuicheAdapter::Connection* QuicheAdapter::find(uint64_t id, AdapterError& error) const
{
  const auto found = byId_.find(id);
  if (found != byId_.end()) return found->second;
  error = {2, "unknown quiche connection"};
  return nullptr;
}

QuicheAdapter::Connection* QuicheAdapter::route(const Header& header) const
{
  const auto found = byCid_.find(cidKey(header.dcid.data(), header.dcidLength));
  return found == byCid_.end() ? nullptr : found->second;
}

size_t QuicheAdapter::activeConnections() const noexcept
{
  const bool replaceDraining = config_.scenario == "connect" ||
      config_.scenario == "resumed_connect" ||
      config_.scenario == "zero_rtt_reqresp";
  return std::ranges::count_if(connections_, [replaceDraining](const auto& connection) {
    return !connection->locallyClosing &&
        (!replaceDraining || !quiche_conn_is_draining(connection->native)) &&
        !quiche_conn_is_closed(connection->native);
  });
}

uint64_t QuicheAdapter::serverConnectionLimit() const noexcept
{
  const bool lifecycle = config_.scenario == "connect" ||
      config_.scenario == "resumed_connect" ||
      config_.scenario == "zero_rtt_reqresp";
  if (!lifecycle) return config_.connectionCount;
  if (config_.globalOperationSlots >
      std::numeric_limits<uint64_t>::max() - config_.connectionCount)
    return std::numeric_limits<uint64_t>::max();
  return config_.connectionCount + config_.globalOperationSlots;
}

void QuicheAdapter::retireConnection(uint64_t id) noexcept
{
  const auto found = byId_.find(id);
  if (found == byId_.end()) return;
  Connection* connection = found->second;
  const quiche_stats stats = [&] {
    quiche_stats value {};
    quiche_conn_stats(connection->native, &value);
    return value;
  }();
  counters_.packetsReceived += stats.recv;
  counters_.packetsSent += stats.sent;
  counters_.packetsLost += stats.lost;
  counters_.packetsRetransmitted += stats.retrans;
  counters_.flowControlBlockedEvents +=
      stats.data_blocked_sent_count + stats.stream_data_blocked_sent_count;
  std::erase_if(byCid_, [connection](const auto& item) { return item.second == connection; });
  byId_.erase(found);
  std::erase_if(connections_, [connection](const auto& owned) {
    return owned.get() == connection;
  });
  transmitCursor_ = 0;
}

void QuicheAdapter::reapLocallyClosed() noexcept
{
  std::vector<uint64_t> retired;
  for (const auto& connection : connections_)
    if (connection->locallyClosing && quiche_conn_is_closed(connection->native))
      retired.push_back(connection->id);
  for (const uint64_t id : retired) retireConnection(id);
}

void QuicheAdapter::refreshCids(Connection& connection)
{
  quiche_connection_id_iter* iterator = quiche_conn_source_ids(connection.native);
  if (!iterator) return;
  const uint8_t* cid = nullptr;
  size_t length = 0;
  while (quiche_connection_id_iter_next(iterator, &cid, &length))
    byCid_[cidKey(cid, length)] = &connection;
  quiche_connection_id_iter_free(iterator);
}

void QuicheAdapter::refreshStreams(Connection& connection)
{
  quiche_stream_iter* iterator = quiche_conn_readable(connection.native);
  if (!iterator) return;
  uint64_t streamId = 0;
  while (quiche_stream_iter_next(iterator, &streamId))
  {
    connection.knownStreams.insert(streamId);
    if (!remoteInitiated(streamId, config_.role) ||
        !connection.acceptedStreams.insert(streamId).second)
      continue;
    (bidirectional(streamId) ? connection.acceptedBidi : connection.acceptedUni)
        .push_back(streamId);
  }
  quiche_stream_iter_free(iterator);
}

QuicheAdapter::Connection* QuicheAdapter::createClient(const sockaddr_in& peer,
                                                        AdapterError& error)
{
  std::array<uint8_t, connectionIdLength> cid {};
  if (!randomCid(cid, error)) return nullptr;
  auto owned = std::make_unique<Connection>();
  owned->id = nextConnectionId_++;
  owned->local = localAddress_;
  owned->peer = peer;
  owned->nextBidi = 0;
  owned->nextUni = 2;
  SSL* ssl = newSsl(error);
  if (!ssl) return nullptr;
  owned->native = quiche_conn_new_with_tls(
      cid.data(), cid.size(), nullptr, 0,
      reinterpret_cast<const sockaddr*>(&owned->local), sizeof(owned->local),
      reinterpret_cast<const sockaddr*>(&owned->peer), sizeof(owned->peer), nativeConfig_, ssl,
      false);
  if (!owned->native)
  {
    SSL_free(ssl);
    error = {10, "quiche_connect failed"};
    return nullptr;
  }
  owned->tls = ssl;
  if (importedSession_)
  {
    if (!valid(quiche_conn_set_session(
                   owned->native,
                   reinterpret_cast<const uint8_t*>(importedSession_->data()),
                   importedSession_->size()),
               "quiche_conn_set_session", error))
      return nullptr;
    owned->zeroRttAttempted = importedZeroRtt_;
    consumedSessions_.emplace(
        reinterpret_cast<const char*>(importedSession_->data()), importedSession_->size());
    importedSession_.reset();
    importedZeroRtt_ = false;
  }
  Connection* result = owned.get();
  connections_.push_back(std::move(owned));
  byId_[result->id] = result;
  byCid_[cidKey(cid.data(), cid.size())] = result;
  return result;
}

QuicheAdapter::Connection* QuicheAdapter::createServer(
    const ReceivedPacket& packet, const Header& header, AdapterError& error)
{
  if (header.version != QUICHE_PROTOCOL_VERSION || header.type != initialPacketType ||
      packet.bytes.size() < QUICHE_MIN_CLIENT_INITIAL_LEN ||
      activeConnections() >= serverConnectionLimit())
  {
    error = {1, "packet is not an acceptable QUIC v1 Initial"};
    return nullptr;
  }
  std::array<uint8_t, connectionIdLength> cid {};
  if (!randomCid(cid, error)) return nullptr;
  auto owned = std::make_unique<Connection>();
  owned->id = nextConnectionId_++;
  owned->local = localAddress_;
  owned->peer = packet.peer;
  owned->nextBidi = 1;
  owned->nextUni = 3;
  SSL* ssl = newSsl(error);
  if (!ssl) return nullptr;
  owned->native = quiche_conn_new_with_tls(
      cid.data(), cid.size(), nullptr, 0,
      reinterpret_cast<const sockaddr*>(&owned->local), sizeof(owned->local),
      reinterpret_cast<const sockaddr*>(&owned->peer), sizeof(owned->peer), nativeConfig_, ssl,
      true);
  if (!owned->native)
  {
    SSL_free(ssl);
    error = {10, "quiche_accept failed"};
    return nullptr;
  }
  owned->tls = ssl;
  Connection* result = owned.get();
  connections_.push_back(std::move(owned));
  byId_[result->id] = result;
  byCid_[cidKey(cid.data(), cid.size())] = result;
  byCid_[cidKey(header.dcid.data(), header.dcidLength)] = result;
  acceptedConnections_.push_back(result->id);
  return result;
}

bool QuicheAdapter::receiveBatch(std::span<const ReceivedPacket> packets,
                                 uint64_t nowRawNs, AdapterError& error)
{
  if (!configured_ || !localAddressSet_ || packets.size() > packetBatchSize)
  {
    error = {2, "quiche receive requires a configured post-bind adapter and at most 64 packets"};
    return false;
  }
  for (const auto& packet : packets)
  {
    if (packet.peer.sin_family != AF_INET || (!config_.packetIo.ecn && packet.ecn))
    {
      error = {1, "invalid borrowed receive metadata"};
      return false;
    }
    Header header;
    if (!parseHeader(packet.bytes, header, error)) return false;
    Connection* connection = route(header);
    if (!connection && config_.role == EndpointRole::server &&
        header.version == QUICHE_PROTOCOL_VERSION && header.type == initialPacketType &&
        packet.bytes.size() >= QUICHE_MIN_CLIENT_INITIAL_LEN &&
        activeConnections() < serverConnectionLimit())
      connection = createServer(packet, header, error);
    // A peer can legitimately retransmit packets for a connection that has
    // already entered draining while a replacement connection is being
    // established. Unknown non-Initial packets are statelessly discarded.
    if (!connection) continue;
    if (!sameAddress(connection->peer, packet.peer))
    {
      error = {1, "packet peer changed while active migration is disabled"};
      return false;
    }
    quiche_recv_info info {
        reinterpret_cast<sockaddr*>(&connection->peer), sizeof(connection->peer),
        reinterpret_cast<sockaddr*>(&connection->local), sizeof(connection->local)};
    const ssize_t status = quiche_conn_recv(
        connection->native,
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(packet.bytes.data())),
        packet.bytes.size(), &info);
    if (status < 0)
    {
      valid(static_cast<int>(status), "quiche_conn_recv", error);
      return false;
    }
    connection->earlyObserved |= quiche_conn_is_in_early_data(connection->native);
    refreshCids(*connection);
    refreshStreams(*connection);
  }
  updateTimeout(nowRawNs);
  error = {};
  return true;
}

size_t QuicheAdapter::pollTransmitBatch(std::span<TransmitPacket> packets,
                                        uint64_t nowRawNs, AdapterError& error)
{
  if (!configured_)
  {
    error = {2, "quiche adapter is not configured"};
    return 0;
  }
  reapLocallyClosed();
  const size_t capacity = std::min({packets.size(), output_.size(), packetBatchSize});
  size_t count = 0;
  size_t misses = 0;
  while (count < capacity && !connections_.empty() && misses < connections_.size())
  {
    if (transmitCursor_ >= connections_.size()) transmitCursor_ = 0;
    Connection& connection = *connections_[transmitCursor_++];
    quiche_send_info info {};
    const ssize_t status = quiche_conn_send(
        connection.native, reinterpret_cast<uint8_t*>(output_[count].data()),
        std::min<size_t>(output_[count].size(), config_.maxUdpPayloadSize), &info);
    if (status == QUICHE_ERR_DONE)
    {
      ++misses;
      continue;
    }
    if (status < 0)
    {
      valid(static_cast<int>(status), "quiche_conn_send", error);
      return count;
    }
    if (info.to.ss_family != AF_INET || info.to_len != sizeof(sockaddr_in))
    {
      error = {1, "quiche returned a non-IPv4 transmit path"};
      return count;
    }
    packets[count].bytes = std::span<const std::byte>(output_[count]).first(status);
    std::memcpy(&packets[count].peer, &info.to, sizeof(sockaddr_in));
    packets[count].ecn = 0;
    packets[count].gsoSegmentSize = 0;
    const uint64_t desiredMonoNs = static_cast<uint64_t>(info.at.tv_sec) * 1'000'000'000ULL +
        static_cast<uint64_t>(info.at.tv_nsec);
    if (config_.packetIo.commonPacing)
    {
      packets[count].desiredSendRawNs = 0;
      packets[count].desiredSendMonotonicNs = desiredMonoNs;
    }
    else
    {
      packets[count].desiredSendRawNs = nowRawNs;
      packets[count].desiredSendMonotonicNs = 0;
    }
    connection.earlyObserved |= quiche_conn_is_in_early_data(connection.native);
    refreshCids(connection);
    ++count;
    misses = 0;
  }
  updateTimeout(nowRawNs);
  error = {};
  return count;
}

void QuicheAdapter::updateTimeout(uint64_t nowRawNs) noexcept
{
  nextTimeoutRawNs_ = 0;
  for (const auto& connection : connections_)
  {
    if (quiche_conn_is_closed(connection->native))
    {
      connection->timeoutRawNs = 0;
      continue;
    }
    const uint64_t relative = quiche_conn_timeout_as_nanos(connection->native);
    if (relative == std::numeric_limits<uint64_t>::max())
    {
      connection->timeoutRawNs = 0;
      continue;
    }
    connection->timeoutRawNs = relative > std::numeric_limits<uint64_t>::max() - nowRawNs ?
        std::numeric_limits<uint64_t>::max() : nowRawNs + relative;
    if (!nextTimeoutRawNs_ || connection->timeoutRawNs < nextTimeoutRawNs_)
      nextTimeoutRawNs_ = connection->timeoutRawNs;
  }
}

bool QuicheAdapter::onTimeout(uint64_t nowRawNs, AdapterError& error)
{
  if (!configured_)
  {
    error = {2, "quiche adapter is not configured"};
    return false;
  }
  for (const auto& connection : connections_)
  {
    if (quiche_conn_is_closed(connection->native) || !connection->timeoutRawNs ||
        connection->timeoutRawNs > nowRawNs) continue;
    quiche_conn_on_timeout(connection->native);
    ++counters_.timerExpirations;
  }
  updateTimeout(nowRawNs);
  error = {};
  return true;
}

bool QuicheAdapter::connect(const sockaddr_in& peer, uint64_t nowRawNs,
                            uint64_t& connectionId, AdapterError& error)
{
  if (!configured_ || !localAddressSet_ || config_.role != EndpointRole::client ||
      peer.sin_family != AF_INET || activeConnections() >= config_.connectionCount)
  {
    error = {2, "quiche connect requires a configured client, valid peer, and free slot"};
    return false;
  }
  in_addr expected {};
  if (inet_pton(AF_INET, config_.peerAddress.c_str(), &expected) != 1 ||
      expected.s_addr != peer.sin_addr.s_addr || ntohs(peer.sin_port) != config_.peerPort)
  {
    error = {1, "connect peer differs from the immutable endpoint configuration"};
    return false;
  }
  Connection* connection = createClient(peer, error);
  if (!connection) return false;
  connectionId = connection->id;
  updateTimeout(nowRawNs);
  error = {};
  return true;
}

PrimitiveStatus QuicheAdapter::acceptConnection(uint64_t, uint64_t& connectionId,
                                                 AdapterError& error)
{
  if (!configured_ || config_.role != EndpointRole::server)
  {
    error = {2, "quiche accept requires a configured server"};
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

bool QuicheAdapter::isConnected(uint64_t connectionId, uint64_t, bool& connected,
                                AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return false;
  connection->earlyObserved |= quiche_conn_is_in_early_data(connection->native);
  connected = quiche_conn_is_established(connection->native) &&
      !quiche_conn_is_draining(connection->native) && !quiche_conn_is_closed(connection->native);
  error = {};
  return true;
}

bool QuicheAdapter::connectionIsClosed(uint64_t connectionId, uint64_t, bool& closed,
                                       AdapterError& error)
{
  Connection* connection = find(connectionId, error);
  if (!connection) return false;
  closed = quiche_conn_is_draining(connection->native) ||
      quiche_conn_is_closed(connection->native);
  error = {};
  return true;
}

PrimitiveStatus QuicheAdapter::openStream(Connection& connection, bool bidi,
                                          uint64_t& streamId, AdapterError& error)
{
  const uint64_t left = bidi ? quiche_conn_peer_streams_left_bidi(connection.native) :
                               quiche_conn_peer_streams_left_uni(connection.native);
  if (!left)
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  const uint64_t candidate = bidi ? connection.nextBidi : connection.nextUni;
  uint64_t streamError = 0;
  const ssize_t status = quiche_conn_stream_send(
      connection.native, candidate, nullptr, 0, false, &streamError);
  if (status == QUICHE_ERR_STREAM_LIMIT || status == QUICHE_ERR_DONE)
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  if (status < 0)
  {
    valid(static_cast<int>(status), "quiche stream creation", error);
    return PrimitiveStatus::fatal;
  }
  streamId = candidate;
  (bidi ? connection.nextBidi : connection.nextUni) += 4;
  connection.knownStreams.insert(streamId);
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus QuicheAdapter::acceptStream(Connection& connection, bool bidi,
                                            uint64_t& streamId, AdapterError& error)
{
  refreshStreams(connection);
  auto& pending = bidi ? connection.acceptedBidi : connection.acceptedUni;
  if (pending.empty())
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  streamId = pending.front();
  pending.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus QuicheAdapter::openBidirectionalStream(
    uint64_t id, uint64_t, uint64_t& streamId, AdapterError& error)
{
  Connection* connection = find(id, error);
  return connection ? openStream(*connection, true, streamId, error) : PrimitiveStatus::fatal;
}

PrimitiveStatus QuicheAdapter::acceptBidirectionalStream(
    uint64_t id, uint64_t, uint64_t& streamId, AdapterError& error)
{
  Connection* connection = find(id, error);
  return connection ? acceptStream(*connection, true, streamId, error) : PrimitiveStatus::fatal;
}

PrimitiveStatus QuicheAdapter::openUnidirectionalStream(
    uint64_t id, uint64_t, uint64_t& streamId, AdapterError& error)
{
  Connection* connection = find(id, error);
  return connection ? openStream(*connection, false, streamId, error) : PrimitiveStatus::fatal;
}

PrimitiveStatus QuicheAdapter::acceptUnidirectionalStream(
    uint64_t id, uint64_t, uint64_t& streamId, AdapterError& error)
{
  Connection* connection = find(id, error);
  return connection ? acceptStream(*connection, false, streamId, error) : PrimitiveStatus::fatal;
}

bool QuicheAdapter::writeStream(uint64_t id, uint64_t streamId,
                                std::span<const std::byte> bytes, uint64_t,
                                size_t& written, AdapterError& error)
{
  written = 0;
  Connection* connection = find(id, error);
  if (!connection || !connection->knownStreams.contains(streamId))
  {
    if (connection) error = {1, "write targets an unknown quiche stream"};
    return false;
  }
  if (connection->writeBlockedStreams.contains(streamId))
  {
    const ssize_t capacity =
        quiche_conn_stream_capacity(connection->native, streamId);
    if (capacity == 0)
    {
      error = {};
      return true;
    }
    connection->writeBlockedStreams.erase(streamId);
  }
  uint64_t streamError = 0;
  const ssize_t status = quiche_conn_stream_send(
      connection->native, streamId,
      reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(), false, &streamError);
  if (status == QUICHE_ERR_DONE)
  {
    connection->writeBlockedStreams.insert(streamId);
    error = {};
    return true;
  }
  if (status == QUICHE_ERR_STREAM_STOPPED)
  {
    connection->writeBlockedStreams.erase(streamId);
    auto& facts = connection->peerTerminal[streamId];
    facts.available = true;
    facts.stopSending = true;
    facts.stopSendingError = streamError;
    error = {};
    return true;
  }
  if (status == QUICHE_ERR_INVALID_STREAM_STATE)
  {
    const auto found = connection->peerTerminal.find(streamId);
    if (found != connection->peerTerminal.end() && found->second.stopSending)
    {
      error = {};
      return true;
    }
  }
  if (status < 0) return valid(static_cast<int>(status), "quiche_conn_stream_send", error);
  connection->writeBlockedStreams.erase(streamId);
  written = static_cast<size_t>(status);
  error = {};
  return true;
}

bool QuicheAdapter::retainPeerStop(Connection& connection, uint64_t streamId,
                                   AdapterError& error)
{
  auto& facts = connection.peerTerminal[streamId];
  if (facts.stopSending)
  {
    error = {};
    return true;
  }
  uint8_t empty = 0;
  uint64_t streamError = 0;
  const ssize_t status = quiche_conn_stream_send(
      connection.native, streamId, &empty, 0, false, &streamError);
  if (status == QUICHE_ERR_STREAM_STOPPED)
  {
    facts.available = true;
    facts.stopSending = true;
    facts.stopSendingError = streamError;
  }
  else if (status < 0 && status != QUICHE_ERR_DONE &&
           status != QUICHE_ERR_INVALID_STREAM_STATE &&
           status != QUICHE_ERR_FINAL_SIZE)
  {
    return valid(static_cast<int>(status),
                 "quiche peer STOP_SENDING retention query", error);
  }
  error = {};
  return true;
}

bool QuicheAdapter::consumeStreamData(uint64_t id, uint64_t streamId,
                                      std::span<std::byte> bytes, uint64_t,
                                      size_t& read, bool& finished, AdapterError& error)
{
  read = 0;
  finished = false;
  Connection* connection = find(id, error);
  if (!connection || !connection->knownStreams.contains(streamId))
  {
    if (connection) error = {1, "read targets an unknown quiche stream"};
    return false;
  }
  // quiche garbage-collects a bidirectional stream once both halves become
  // terminal. Retain an already-received STOP_SENDING error before receiving
  // FIN or RESET_STREAM can complete the other half and collect the stream.
  if (!retainPeerStop(*connection, streamId, error)) return false;
  bool fin = false;
  uint64_t streamError = 0;
  const ssize_t status = quiche_conn_stream_recv(
      connection->native, streamId, reinterpret_cast<uint8_t*>(bytes.data()),
      bytes.size(), &fin, &streamError);
  if (status == QUICHE_ERR_DONE)
  {
    finished = quiche_conn_stream_finished(connection->native, streamId);
    error = {};
    return true;
  }
  if (status == QUICHE_ERR_STREAM_RESET)
  {
    auto& facts = connection->peerTerminal[streamId];
    facts.available = true;
    facts.resetStream = true;
    facts.resetStreamError = streamError;
    error = {};
    return true;
  }
  if (status == QUICHE_ERR_INVALID_STREAM_STATE)
  {
    const auto found = connection->peerTerminal.find(streamId);
    if (found != connection->peerTerminal.end() &&
        (found->second.fin || found->second.resetStream))
    {
      error = {};
      return true;
    }
  }
  if (status < 0) return valid(static_cast<int>(status), "quiche_conn_stream_recv", error);
  read = static_cast<size_t>(status);
  finished = fin;
  if (fin)
  {
    auto& facts = connection->peerTerminal[streamId];
    facts.available = true;
    facts.fin = true;
  }
  error = {};
  return true;
}

bool QuicheAdapter::finishStream(uint64_t id, uint64_t streamId, uint64_t,
                                 AdapterError& error)
{
  Connection* connection = find(id, error);
  if (!connection || !connection->knownStreams.contains(streamId))
  {
    if (connection) error = {1, "finish targets an unknown quiche stream"};
    return false;
  }
  uint64_t streamError = 0;
  const ssize_t status = quiche_conn_stream_send(
      connection->native, streamId, nullptr, 0, true, &streamError);
  if (status < 0) return valid(static_cast<int>(status), "quiche stream FIN", error);
  error = {};
  return true;
}

bool QuicheAdapter::resetStream(uint64_t id, uint64_t streamId, uint64_t appError,
                                uint64_t, AdapterError& error)
{
  Connection* connection = find(id, error);
  if (!connection) return false;
  const int status = quiche_conn_stream_shutdown(
      connection->native, streamId, QUICHE_SHUTDOWN_WRITE, appError);
  const auto terminal = connection->peerTerminal.find(streamId);
  if (status == QUICHE_ERR_DONE && terminal != connection->peerTerminal.end() &&
      terminal->second.stopSending && terminal->second.stopSendingError == appError)
  {
    error = {};
    return true;
  }
  return valid(status, "quiche RESET_STREAM", error);
}

bool QuicheAdapter::stopSending(uint64_t id, uint64_t streamId, uint64_t appError,
                                uint64_t, AdapterError& error)
{
  Connection* connection = find(id, error);
  return connection && valid(quiche_conn_stream_shutdown(
      connection->native, streamId, QUICHE_SHUTDOWN_READ, appError),
      "quiche STOP_SENDING", error);
}

PrimitiveStatus QuicheAdapter::sendDatagram(uint64_t id,
                                            std::span<const std::byte> bytes, uint64_t,
                                            AdapterError& error)
{
  Connection* connection = find(id, error);
  if (!connection) return PrimitiveStatus::fatal;
  const ssize_t maximum = quiche_conn_dgram_max_writable_len(connection->native);
  if (maximum == QUICHE_ERR_DONE || quiche_conn_is_dgram_send_queue_full(connection->native))
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  if (maximum < 0 || bytes.size() > static_cast<size_t>(maximum))
  {
    error = {1, "peer did not negotiate the requested quiche DATAGRAM size"};
    return PrimitiveStatus::fatal;
  }
  const ssize_t status = quiche_conn_dgram_send(
      connection->native, reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
  if (status == QUICHE_ERR_DONE) { error = {}; return PrimitiveStatus::wouldBlock; }
  if (status < 0)
  {
    valid(static_cast<int>(status), "quiche_conn_dgram_send", error);
    return PrimitiveStatus::fatal;
  }
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus QuicheAdapter::consumeDatagram(uint64_t id,
                                               std::span<std::byte> bytes, uint64_t,
                                               size_t& read, AdapterError& error)
{
  read = 0;
  Connection* connection = find(id, error);
  if (!connection) return PrimitiveStatus::fatal;
  const ssize_t front = quiche_conn_dgram_recv_front_len(connection->native);
  if (front == QUICHE_ERR_DONE) { error = {}; return PrimitiveStatus::wouldBlock; }
  if (front < 0 || static_cast<size_t>(front) > bytes.size())
  {
    error = {1, "borrowed quiche DATAGRAM receive buffer is too small"};
    return PrimitiveStatus::fatal;
  }
  const ssize_t status = quiche_conn_dgram_recv(
      connection->native, reinterpret_cast<uint8_t*>(bytes.data()), bytes.size());
  if (status < 0)
  {
    valid(static_cast<int>(status), "quiche_conn_dgram_recv", error);
    return PrimitiveStatus::fatal;
  }
  read = static_cast<size_t>(status);
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus QuicheAdapter::exportResumptionState(
    uint64_t id, uint64_t nowRawNs, std::span<std::byte> bytes, size_t& written,
    AdapterError& error)
{
  written = 0;
  Connection* connection = find(id, error);
  if (!connection) return PrimitiveStatus::fatal;
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
  quiche_conn_session(connection->native, &session, &length);
  if (!session || !length) { error = {}; return PrimitiveStatus::wouldBlock; }
  return sealResumptionState(
             std::span(reinterpret_cast<const std::byte*>(session), length),
             nowRawNs, bytes, written, error) ?
      PrimitiveStatus::ready : PrimitiveStatus::fatal;
}

PrimitiveStatus QuicheAdapter::importResumptionState(
    std::span<const std::byte> bytes, bool useZeroRtt, uint64_t nowRawNs,
    AdapterError& error)
{
  std::span<const std::byte> session;
  if (openResumptionState(bytes, nowRawNs, config_.tlsTicketLifetimeNs,
                          session, error) != PrimitiveStatus::ready)
    return PrimitiveStatus::fatal;
  const std::string ticket(
      reinterpret_cast<const char*>(session.data()), session.size());
  if (!configured_ || config_.role != EndpointRole::client || importedSession_ ||
      session.empty() || consumedSessions_.contains(ticket))
  {
    error = {1, "invalid, overlapping, or already consumed quiche resumption import"};
    return PrimitiveStatus::fatal;
  }
  importedSession_.emplace(session.begin(), session.end());
  importedZeroRtt_ = useZeroRtt;
  error = {};
  return PrimitiveStatus::ready;
}

bool QuicheAdapter::connectionResumed(uint64_t id, uint64_t, bool& resumed,
                                      AdapterError& error)
{
  Connection* connection = find(id, error);
  if (!connection) return false;
  resumed = quiche_conn_is_resumed(connection->native);
  error = {};
  return true;
}

bool QuicheAdapter::zeroRttAttempted(uint64_t id, uint64_t, bool& attempted,
                                     AdapterError& error)
{
  Connection* connection = find(id, error);
  if (!connection) return false;
  attempted = connection->zeroRttAttempted;
  error = {};
  return true;
}

bool QuicheAdapter::zeroRttAccepted(uint64_t id, uint64_t, bool& accepted,
                                    AdapterError& error)
{
  Connection* connection = find(id, error);
  if (!connection) return false;
  accepted = connection->zeroRttAttempted && connection->earlyObserved &&
      quiche_conn_is_established(connection->native);
  error = {};
  return true;
}

bool QuicheAdapter::zeroRttRejected(uint64_t id, uint64_t, bool& rejected,
                                    AdapterError& error)
{
  Connection* connection = find(id, error);
  if (!connection) return false;
  rejected = connection->zeroRttAttempted && quiche_conn_is_established(connection->native) &&
      !connection->earlyObserved;
  error = {};
  return true;
}

bool QuicheAdapter::closeConnection(uint64_t id, uint64_t applicationError,
                                    uint64_t, AdapterError& error)
{
  Connection* connection = find(id, error);
  if (!connection || !valid(quiche_conn_close(
          connection->native, true, applicationError, nullptr, 0),
          "quiche_conn_close", error)) return false;
  connection->locallyClosing = true;
  return true;
}

bool QuicheAdapter::peerTerminalFacts(uint64_t id, uint64_t streamId, uint64_t,
                                      PeerTerminalFacts& facts, AdapterError& error)
{
  facts = {};
  Connection* connection = find(id, error);
  if (!connection) return false;
  facts.available = true;

  bool isApplication = false;
  uint64_t connectionError = 0;
  const uint8_t* reason = nullptr;
  size_t reasonLength = 0;
  if (quiche_conn_peer_error(connection->native, &isApplication, &connectionError,
                             &reason, &reasonLength) && isApplication)
  {
    connection->peerConnectionTerminal.available = true;
    connection->peerConnectionTerminal.connectionClose = true;
    connection->peerConnectionTerminal.connectionCloseError = connectionError;
    connection->peerConnectionTerminal.connectionCloseReasonLength = reasonLength;
  }

  if (const auto found = connection->peerTerminal.find(streamId);
      found != connection->peerTerminal.end()) facts = found->second;
  facts.available = true;
  facts.connectionClose = connection->peerConnectionTerminal.connectionClose;
  facts.connectionCloseError = connection->peerConnectionTerminal.connectionCloseError;
  facts.connectionCloseReasonLength =
      connection->peerConnectionTerminal.connectionCloseReasonLength;
  if (facts.connectionClose)
  {
    const auto retained = facts;
    retireConnection(id);
    facts = retained;
    error = {};
    return true;
  }
  if (!connection->knownStreams.contains(streamId))
  {
    error = {1, "peer terminal query targets an unknown quiche stream"};
    return false;
  }

  uint8_t empty = 0;
  uint64_t streamError = 0;
  if (!facts.stopSending)
  {
    if (!retainPeerStop(*connection, streamId, error)) return false;
    facts = connection->peerTerminal[streamId];
    facts.available = true;
  }

  if (!facts.fin && !facts.resetStream)
  {
    bool fin = false;
    streamError = 0;
    const ssize_t receiveStatus = quiche_conn_stream_recv(
        connection->native, streamId, &empty, 0, &fin, &streamError);
    if (receiveStatus == QUICHE_ERR_STREAM_RESET)
    {
      facts.resetStream = true;
      facts.resetStreamError = streamError;
    }
    else if (receiveStatus >= 0)
    {
      facts.fin = fin;
    }
    else if (receiveStatus == QUICHE_ERR_DONE)
    {
      facts.fin = quiche_conn_stream_finished(connection->native, streamId);
    }
    else if (receiveStatus != QUICHE_ERR_INVALID_STREAM_STATE ||
             !facts.stopSending)
    {
      return valid(static_cast<int>(receiveStatus),
                   "quiche peer terminal receive query", error);
    }
  }

  connection->peerTerminal[streamId] = facts;
  error = {};
  return true;
}

TransportCounters QuicheAdapter::snapshotTransportCounters() const noexcept
{
  TransportCounters result = counters_;
  for (const auto& connection : connections_)
  {
    quiche_stats stats {};
    quiche_conn_stats(connection->native, &stats);
    result.packetsReceived += stats.recv;
    result.packetsSent += stats.sent;
    result.packetsLost += stats.lost;
    result.packetsRetransmitted += stats.retrans;
    result.flowControlBlockedEvents +=
        stats.data_blocked_sent_count + stats.stream_data_blocked_sent_count;
  }
  return result;
}

NegotiatedSettings QuicheAdapter::snapshotNegotiatedSettings() const noexcept
{
  const auto snapshot = [this](const Connection& connection) {
    NegotiatedSettings result;
    result.evidenceSource =
        "quiche_conn_peer_transport_params+boringssl_post_handshake+"
        "quiche_applied_settings+qpf2_lifecycle_policy";
    const auto unavailable = [&result](std::string field) {
      if (std::ranges::find(result.unavailableFields, field) ==
          result.unavailableFields.end())
        result.unavailableFields.push_back(std::move(field));
    };
    if (!connection.native || !connection.tls ||
        !quiche_conn_is_established(connection.native))
    {
      unavailable("handshake_not_complete");
      return result;
    }
    quiche_transport_params peer {};
    if (!quiche_conn_peer_transport_params(connection.native, &peer))
    {
      unavailable("remote_transport_parameters");
      return result;
    }

    result.available = true;
    result.quicVersion = QUICHE_PROTOCOL_VERSION;
    const uint8_t* negotiatedAlpn = nullptr;
    size_t negotiatedAlpnLength = 0;
    quiche_conn_application_proto(
        connection.native, &negotiatedAlpn, &negotiatedAlpnLength);
    if (negotiatedAlpn && negotiatedAlpnLength)
      result.alpn.assign(
          reinterpret_cast<const char*>(negotiatedAlpn), negotiatedAlpnLength);
    else unavailable("alpn");
    if (const char* version = SSL_get_version(connection.tls))
      result.tlsVersion = version;
    else unavailable("tls_version");
    if (const SSL_CIPHER* cipher = SSL_get_current_cipher(connection.tls))
      result.tlsCipherSuite = SSL_CIPHER_get_name(cipher);
    else unavailable("tls_cipher_suite");
    const uint16_t group = SSL_get_curve_id(connection.tls);
    if (group == SSL_CURVE_X25519) result.tlsKeyExchange = "X25519";
    else if (const char* name = SSL_get_curve_name(group)) result.tlsKeyExchange = name;
    else unavailable("tls_key_exchange");

    X509* ownedPeer = nullptr;
    X509* certificate = nullptr;
    if (config_.role == EndpointRole::client)
    {
      ownedPeer = SSL_get_peer_certificate(connection.tls);
      certificate = ownedPeer;
    }
    else certificate = SSL_get_certificate(connection.tls);
    if (certificate)
    {
      const int signature = X509_get_signature_nid(certificate);
      if (signature == NID_ED25519) result.tlsLeafSignature = "Ed25519";
      else if (const char* name = OBJ_nid2sn(signature))
        result.tlsLeafSignature = name;
      else unavailable("tls_leaf_signature");
    }
    else unavailable("tls_leaf_signature");
    if (ownedPeer) X509_free(ownedPeer);
    result.peerCertificateVerified = config_.role == EndpointRole::client &&
        SSL_get_verify_result(connection.tls) == X509_V_OK;
    result.hostnameVerified = result.peerCertificateVerified;

    result.congestionController = config_.congestionController;
    result.initialCongestionWindowBytes = config_.initialCongestionWindowBytes;
    result.maxUdpPayloadSize = peer.peer_max_udp_payload_size;
    result.maxAckDelayNs = peer.peer_max_ack_delay * 1'000'000ULL;
    result.ackDelayExponent = peer.peer_ack_delay_exponent;
    result.ackFrequency = false;
    result.activeMigration = !peer.peer_disable_active_migration;
    result.activeConnectionIdLimit = peer.peer_active_conn_id_limit;
    const uint8_t* destinationId = nullptr;
    size_t destinationIdLength = 0;
    quiche_conn_destination_id(
        connection.native, &destinationId, &destinationIdLength);
    if (destinationId && destinationIdLength)
      result.connectionIdBytes = destinationIdLength;
    else unavailable("connection_id_bytes");
    result.maxIdleTimeoutNs = peer.peer_max_idle_timeout * 1'000'000ULL;
    result.maxBidiStreams = peer.peer_initial_max_streams_bidi;
    result.maxUniStreams = peer.peer_initial_max_streams_uni;
    result.streamCreditReplenishBelow = config_.streamCreditReplenishBelow;
    result.connectionWindowBytes = peer.peer_initial_max_data;
    result.streamWindowBytes = std::min(
        peer.peer_initial_max_stream_data_bidi_local,
        peer.peer_initial_max_stream_data_bidi_remote);
    if (peer.peer_max_datagram_frame_size >= 0)
      result.datagramMaxFrameSize =
          static_cast<uint64_t>(peer.peer_max_datagram_frame_size);
    else unavailable("datagram_max_frame_size");
    result.ticketLifetimeNs = config_.tlsTicketLifetimeNs;
    result.maximumEarlyDataBytes = config_.tlsMaximumEarlyDataBytes;
    result.oneUseTickets = config_.tlsOneUseTickets;
    return result;
  };

  const auto established = std::ranges::find_if(connections_, [](const auto& owned) {
    return owned->native && quiche_conn_is_established(owned->native);
  });
  if (established == connections_.end())
  {
    NegotiatedSettings result;
    result.unavailableFields = {"no_post_handshake_connection"};
    return result;
  }
  NegotiatedSettings result = snapshot(**established);
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
  for (const auto& owned : connections_)
  {
    if (owned.get() == established->get() || !owned->native ||
        !quiche_conn_is_established(owned->native))
      continue;
    if (!same(result, snapshot(*owned)))
    {
      result.unavailableFields = {"per_connection_evidence_mismatch"};
      break;
    }
  }
  return result;
}

bool QuicheAdapter::reset(AdapterError& error)
{
  byId_.clear();
  byCid_.clear();
  connections_.clear();
  acceptedConnections_.clear();
  importedSession_.reset();
  consumedSessions_.clear();
  savedSessions_.clear();
  if (nativeConfig_)
  {
    quiche_config_free(nativeConfig_);
    nativeConfig_ = nullptr;
  }
  if (tlsContext_) { SSL_CTX_free(tlsContext_); tlsContext_ = nullptr; }
  config_ = {};
  localAddress_ = {};
  importedZeroRtt_ = false;
  nextConnectionId_ = 1;
  nextTimeoutRawNs_ = 0;
  transmitCursor_ = 0;
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
  return std::make_unique<QuicheAdapter>();
}

} // namespace quicperf
