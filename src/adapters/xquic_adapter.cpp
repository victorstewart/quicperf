#include "adapter_factory.h"
#include "core/measurement.h"
#include "core/strict_config.h"

#include <xquic/xqc_errno.h>
#include <xquic/xquic.h>

#include <openssl/pem.h>
#include <openssl/obj.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
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

constexpr std::string_view protocol = "qperf/2";
constexpr uint32_t resumptionMagic = 0x58515253U;
constexpr size_t resumptionHeaderBytes = 20;
constexpr uint64_t applicationBufferBytes = 256 * 1024;
constexpr std::array<char, 48> ticketKey {
    'q', 'u', 'i', 'c', 'p', 'e', 'r', 'f', 'x', 'q', 'u', 'i', 'c', 't', 'k', '2',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v'};

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

void storeU64(std::byte* destination, uint64_t value)
{
  for (size_t index = 0; index < 8; ++index)
    destination[index] = static_cast<std::byte>(value >> (56 - index * 8));
}

uint64_t loadU64(const std::byte* source)
{
  uint64_t value = 0;
  for (size_t index = 0; index < 8; ++index)
    value = (value << 8) | std::to_integer<uint8_t>(source[index]);
  return value;
}

class XquicAdapter final : public Adapter {
public:
  XquicAdapter();
  ~XquicAdapter() override;

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
  bool resetStream(uint64_t, uint64_t, uint64_t, uint64_t,
                   AdapterError& error) override;
  bool stopSending(uint64_t, uint64_t, uint64_t, uint64_t,
                   AdapterError& error) override;
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
    xqc_stream_t* stream = nullptr;
    std::vector<std::byte> received;
    size_t receiveOffset = 0;
    bool writable = true;
    bool finishPending = false;
    bool finishSent = false;
    bool remoteFin = false;
    bool closed = false;
    PeerTerminalFacts terminalFacts {};
  };

  struct Connection {
    XquicAdapter* owner = nullptr;
    uint64_t id = 0;
    xqc_connection_t* conn = nullptr;
    xqc_cid_t cid {};
    sockaddr_in peer {};
    std::unordered_map<uint64_t, std::unique_ptr<Stream>> streams;
    std::deque<uint64_t> acceptedBidi;
    std::deque<uint64_t> acceptedUni;
    std::optional<uint64_t> controlStreamId;
    std::deque<std::vector<std::byte>> datagrams;
    std::vector<std::byte> session;
    std::vector<std::byte> transportParameters;
    bool connected = false;
    bool closing = false;
    bool closed = false;
    bool releaseWhenClosed = false;
    bool imported = false;
    bool earlyAttempted = false;
    bool resumed = false;
    bool earlyAccepted = false;
    bool earlyRejected = false;
    bool verificationObserved = false;
    bool peerCertificateVerified = false;
    bool hostnameVerified = false;
    size_t earlyDataBytes = 0;
    uint64_t sessionIssuedRawNs = 0;
    uint64_t sessionTicketLifetimeNs = 0;
    bool sessionEarlyDataCapable = false;
    bool peerConnectionClose = false;
    uint64_t peerConnectionCloseError = 0;
    uint64_t peerConnectionCloseReasonLength = 0;
    uint64_t finalPacketsLost = 0;
    bool socketContinuationQueued = false;
  };

  struct ImportedState {
    std::vector<std::byte> session;
    std::vector<std::byte> transportParameters;
    std::string identity;
    uint64_t issuedRawNs = 0;
    bool zeroRtt = false;
  };

  struct OutputPacket {
    std::vector<std::byte> bytes;
    sockaddr_in peer {};
  };

  static void setTimer(xqc_usec_t wakeAfter, void* context);
  static xqc_usec_t realtimeNowUs();
  static xqc_usec_t monotonicNowUs();
  static void ignoreLog(xqc_log_level_t, const void* bytes, size_t length, void*)
  {
    if (std::getenv("QUICPERF_XQUIC_LOG") && bytes && length)
    {
      std::fwrite(bytes, 1, length, stderr);
      std::fputc('\n', stderr);
    }
  }
  static void ignoreQlog(qlog_event_importance_t, const void*, size_t, void*) {}
  static int serverAccept(xqc_engine_t*, xqc_connection_t* conn,
                          const xqc_cid_t* cid, void* context);
  static void serverRefuse(xqc_engine_t*, xqc_connection_t*, const xqc_cid_t*, void*) {}
  static ssize_t statelessReset(const unsigned char* bytes, size_t length,
                                const sockaddr* peer, socklen_t peerLength,
                                const sockaddr*, socklen_t, void* context);
  static ssize_t writeBeforeAccept(const unsigned char* bytes, size_t length,
                                   const sockaddr* peer, socklen_t peerLength,
                                   void* context);
  static ssize_t writeSocket(const unsigned char* bytes, size_t length,
                             const sockaddr* peer, socklen_t peerLength, void* context);
  static ssize_t writeMmsg(const iovec* vectors, unsigned count,
                           const sockaddr* peer, socklen_t peerLength, void* context);
  static ssize_t writeSocketEx(uint64_t, const unsigned char* bytes, size_t length,
                               const sockaddr* peer, socklen_t peerLength, void* context);
  static ssize_t writeMmsgEx(uint64_t, const iovec* vectors, unsigned count,
                             const sockaddr* peer, socklen_t peerLength, void* context);
  static void updateCid(xqc_connection_t*, const xqc_cid_t*,
                        const xqc_cid_t* cid, void* context);
  static void saveToken(const unsigned char*, uint32_t, void*) {}
  static void saveSession(const char* bytes, size_t length, void* context);
  static void saveTransportParameters(const char* bytes, size_t length, void* context);
  static int selectCertificate(const char* sni, void** chain, void** certificate,
                               void** key, void* context);
  static int verifyCertificate(const unsigned char* certificates[],
                               const size_t lengths[], size_t count, void* context);
  static void peerAddressChanged(xqc_connection_t*, void*) {}
  static void pathPeerAddressChanged(xqc_connection_t*, uint64_t, void*) {}
  static int connectionCreated(xqc_connection_t* conn, const xqc_cid_t* cid,
                               void* context, void*);
  static xqc_int_t connectionClosing(xqc_connection_t* conn, const xqc_cid_t*,
                                     xqc_int_t, void* context);
  static int connectionClosed(xqc_connection_t* conn, const xqc_cid_t*,
                              void* context, void*);
  static void handshakeDone(xqc_connection_t* conn, void* context, void*);
  static xqc_int_t streamCreated(xqc_stream_t* stream, void* context);
  static xqc_int_t streamReadable(xqc_stream_t* stream, void* context);
  static xqc_int_t streamWritable(xqc_stream_t* stream, void* context);
  static xqc_int_t streamClosed(xqc_stream_t* stream, void* context);
  static void streamClosing(xqc_stream_t* stream, xqc_int_t, void* context);
  static void datagramRead(xqc_connection_t*, void* context, const void* bytes,
                           size_t length, uint64_t);
  static void datagramWrite(xqc_connection_t*, void*) {}
  static void datagramMss(xqc_connection_t*, size_t, void*) {}

  bool initializeEngine(AdapterError& error);
  bool initializeServerCertificate(AdapterError& error);
  bool initializeTrustStore(AdapterError& error);
  void useCommonTime(uint64_t nowRawNs) noexcept;
  xqc_conn_settings_t connectionSettings() const;
  Connection* find(uint64_t id, AdapterError& error) const;
  Stream* findStream(Connection& connection, uint64_t id, AdapterError& error) const;
  Connection& createConnection();
  size_t activeServerConnections() const noexcept;
  uint64_t serverConnectionLimit() const noexcept;
  void retainControlStream(Connection& connection, uint64_t streamId,
                           xqc_stream_t* stream);
  bool writablePacketBytes(const Connection& connection, bool control,
                           size_t& bytes, AdapterError& error) const;
  static void retainConnectionClose(xqc_connection_t* conn, Connection& state);
  static void retainTerminalFacts(xqc_stream_t* stream, Stream& state);
  void refresh(Connection& connection);
  void reapReleasedConnections();
  void process(uint64_t nowRawNs);
  PrimitiveStatus openStream(uint64_t connectionId, xqc_stream_direction_t direction,
                             uint64_t& streamId, AdapterError& error);
  PrimitiveStatus acceptStream(uint64_t connectionId, bool unidirectional,
                               uint64_t& streamId, AdapterError& error);
  PrimitiveStatus unavailable(std::string_view primitive, AdapterError& error) const;
  void queueSocketContinuation(Connection& connection);
  ssize_t queuePacket(const unsigned char* bytes, size_t length,
                      const sockaddr* peer, socklen_t peerLength);

  Capabilities capabilities_;
  EndpointConfig config_ {};
  sockaddr_in localAddress_ {};
  xqc_engine_t* engine_ = nullptr;
  STACK_OF(X509)* serverChain_ = nullptr;
  X509* serverCertificate_ = nullptr;
  EVP_PKEY* serverKey_ = nullptr;
  X509_STORE* trustStore_ = nullptr;
  std::unordered_map<uint64_t, std::unique_ptr<Connection>> connections_;
  std::unordered_map<xqc_connection_t*, Connection*> connectionsByPointer_;
  std::deque<uint64_t> acceptedConnections_;
  std::deque<uint64_t> socketContinuations_;
  std::deque<OutputPacket> outputQueue_;
  std::unique_ptr<ImportedState> importedState_;
  std::unordered_set<std::string> consumedSessions_;
  uint64_t nextConnectionId_ = 1;
  uint64_t nextWakeUs_ = 0;
  uint64_t nextTimeoutRawNs_ = 0;
  uint64_t clockAnchorRawNs_ = 0;
  uint64_t clockAnchorRealtimeNs_ = 0;
  uint64_t callbackRawNs_ = 0;
  static thread_local XquicAdapter* callbackClockOwner_;
  bool admissionRefused_ = false;
  bool configured_ = false;
  bool localAddressSet_ = false;
  std::array<std::array<std::byte, maxUdpPayloadSize>, packetBatchSize> output_ {};
  TransportCounters counters_ {};
};

thread_local XquicAdapter* XquicAdapter::callbackClockOwner_ = nullptr;

XquicAdapter::XquicAdapter()
{
  capabilities_.library = "xquic";
  capabilities_.buildId = "xquic-1.9.2-quicperf12-transport-v2";
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
      "tls_1_3", "tls_aes_128_gcm_sha256", "x25519", "qperf_2_alpn",
      "bidirectional_stream", "unidirectional_stream", "datagram", "resumption",
      "early_data", "post_bind_local_address", "connection_close",
      "application_error_reset", "application_error_stop_sending", "peer_terminal_facts",
      "transport_loss_counter",
      "exact_retransmission_counter_unavailable"};
}

XquicAdapter::~XquicAdapter()
{
  AdapterError ignored;
  reset(ignored);
}

void XquicAdapter::setTimer(xqc_usec_t wakeAfter, void* context)
{
  static_cast<XquicAdapter*>(context)->nextWakeUs_ = wakeAfter;
}

xqc_usec_t XquicAdapter::realtimeNowUs()
{
  const auto* owner = callbackClockOwner_;
  if (!owner) return 0;
  return realtimeAtRaw(owner->callbackRawNs_, owner->clockAnchorRawNs_,
                       owner->clockAnchorRealtimeNs_) / 1'000;
}

xqc_usec_t XquicAdapter::monotonicNowUs()
{
  return callbackClockOwner_ ? callbackClockOwner_->callbackRawNs_ / 1'000 : 0;
}

void XquicAdapter::useCommonTime(uint64_t nowRawNs) noexcept
{
  callbackClockOwner_ = this;
  callbackRawNs_ = nowRawNs;
}

XquicAdapter::Connection& XquicAdapter::createConnection()
{
  auto owned = std::make_unique<Connection>();
  owned->owner = this;
  owned->id = nextConnectionId_++;
  Connection* raw = owned.get();
  connections_.emplace(raw->id, std::move(owned));
  return *raw;
}

size_t XquicAdapter::activeServerConnections() const noexcept
{
  const bool replaceClosing = config_.scenario == "connect" ||
      config_.scenario == "resumed_connect" ||
      config_.scenario == "zero_rtt_reqresp" ||
      config_.scenario == "close_reset_cleanup";
  return std::ranges::count_if(connections_, [replaceClosing](const auto& item) {
    // A failed pre-handshake admission must not block its retransmitted Initial.
    if (item.second->closed && !item.second->connected) return false;
    return !replaceClosing || (!item.second->closed && !item.second->closing);
  });
}

uint64_t XquicAdapter::serverConnectionLimit() const noexcept
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

void XquicAdapter::retainControlStream(Connection& connection, uint64_t streamId,
                                       xqc_stream_t* stream)
{
  if (!stream || xqc_stream_get_direction(stream) != XQC_STREAM_BIDI) return;
  if (!connection.controlStreamId || streamId < *connection.controlStreamId)
    connection.controlStreamId = streamId;
  if (*connection.controlStreamId == streamId)
    xqc_stream_set_high_priority(stream, XQC_TRUE);
}

bool XquicAdapter::writablePacketBytes(const Connection& connection, bool control,
                                       size_t& bytes, AdapterError& error) const
{
  const uint64_t packetBytes = std::max<uint64_t>(1, config_.maxUdpPayloadSize);
  const uint64_t totalPackets = std::max<uint64_t>(1, applicationBufferBytes / packetBytes);
  const uint64_t connectionCount = std::max<uint64_t>(1, config_.connectionCount);
  const uint64_t reserveConnections = std::min<uint64_t>(
      connectionCount, applicationBufferBytes / 4'096);
  const uint64_t reserveBytes = std::min<uint64_t>(
      applicationBufferBytes / 2, reserveConnections * 4'096);
  const uint64_t reservePackets = std::min<uint64_t>(
      totalPackets - 1, (reserveBytes + packetBytes - 1) / packetBytes);
  const uint64_t dataPackets = totalPackets - reservePackets;
  const uint64_t globalLimit = control ? totalPackets : dataPackets;
  const uint64_t connectionLimit = std::max<uint64_t>(
      1, (control ? totalPackets : dataPackets) / connectionCount);
  uint64_t globalUsed = outputQueue_.size();
  uint64_t connectionUnsent = 0;
  uint64_t connectionUsed = 0;
  uint64_t connectionMax = 0;
  for (const auto& [id, candidate] : connections_)
  {
    (void)id;
    if (!candidate->conn) continue;
    uint64_t used = 0;
    uint64_t maximum = 0;
    uint64_t unsent = 0;
    if (xqc_conn_get_send_queue_state(
            candidate->conn, &used, &maximum, &unsent) != XQC_OK || maximum == 0)
    {
      bytes = 0;
      error = {9, "XQUIC send-queue accounting unavailable"};
      return false;
    }
    globalUsed = globalUsed > std::numeric_limits<uint64_t>::max() - unsent ?
        std::numeric_limits<uint64_t>::max() : globalUsed + unsent;
    if (candidate.get() == &connection)
    {
      connectionUsed = used;
      connectionMax = maximum;
      connectionUnsent = unsent;
    }
  }
  if (connectionMax == 0)
  {
    bytes = 0;
    error = {9, "XQUIC connection is absent from send-queue accounting"};
    return false;
  }
  const uint64_t globalAvailable = globalLimit - std::min(globalLimit, globalUsed);
  const uint64_t connectionAvailable =
      connectionLimit - std::min(connectionLimit, connectionUnsent);
  const uint64_t retainedReserve = std::min<uint64_t>(
      connectionMax - 1, (4'096 + packetBytes - 1) / packetBytes);
  const uint64_t retainedLimit = control ?
      connectionMax : connectionMax - retainedReserve;
  const uint64_t retainedAvailable =
      retainedLimit - std::min(retainedLimit, connectionUsed);
  const uint64_t packets = std::min({
      globalAvailable, connectionAvailable, retainedAvailable});
  const uint64_t availableBytes = packets > std::numeric_limits<size_t>::max() / packetBytes ?
      std::numeric_limits<size_t>::max() : packets * packetBytes;
  bytes = static_cast<size_t>(availableBytes);
  error = {};
  return true;
}

XquicAdapter::Connection* XquicAdapter::find(uint64_t id, AdapterError& error) const
{
  const auto found = connections_.find(id);
  if (found != connections_.end()) return found->second.get();
  error = {3, "unknown XQUIC connection"};
  return nullptr;
}

XquicAdapter::Stream* XquicAdapter::findStream(Connection& connection, uint64_t id,
                                                AdapterError& error) const
{
  const auto found = connection.streams.find(id);
  if (found != connection.streams.end() && !found->second->closed) return found->second.get();
  error = {4, "unknown or closed XQUIC stream"};
  return nullptr;
}

ssize_t XquicAdapter::queuePacket(const unsigned char* bytes, size_t length,
                                  const sockaddr* peer, socklen_t peerLength)
{
  if (!bytes || !peer || peerLength < sizeof(sockaddr_in) || peer->sa_family != AF_INET ||
      length > maxUdpPayloadSize) return XQC_SOCKET_ERROR;
  const size_t packetCapacity = std::max<uint64_t>(
      1, applicationBufferBytes / config_.maxUdpPayloadSize);
  if (outputQueue_.size() >= packetCapacity) return XQC_SOCKET_EAGAIN;
  OutputPacket packet;
  const auto* first = reinterpret_cast<const std::byte*>(bytes);
  packet.bytes.assign(first, first + length);
  std::memcpy(&packet.peer, peer, sizeof(sockaddr_in));
  outputQueue_.push_back(std::move(packet));
  ++counters_.packetsSent;
  return static_cast<ssize_t>(length);
}

void XquicAdapter::queueSocketContinuation(Connection& connection)
{
  if (connection.socketContinuationQueued) return;
  connection.socketContinuationQueued = true;
  socketContinuations_.push_back(connection.id);
}

ssize_t XquicAdapter::writeSocket(const unsigned char* bytes, size_t length,
                                  const sockaddr* peer, socklen_t peerLength, void* context)
{
  auto* connection = static_cast<Connection*>(context);
  const ssize_t result = connection->owner->queuePacket(bytes, length, peer, peerLength);
  if (result == XQC_SOCKET_EAGAIN)
    connection->owner->queueSocketContinuation(*connection);
  return result;
}

ssize_t XquicAdapter::writeSocketEx(uint64_t, const unsigned char* bytes, size_t length,
                                    const sockaddr* peer, socklen_t peerLength, void* context)
{
  return writeSocket(bytes, length, peer, peerLength, context);
}

ssize_t XquicAdapter::writeMmsg(const iovec* vectors, unsigned count,
                                const sockaddr* peer, socklen_t peerLength, void* context)
{
  auto* connection = static_cast<Connection*>(context);
  unsigned sent = 0;
  for (; sent < count; ++sent)
  {
    const ssize_t result = connection->owner->queuePacket(
        static_cast<const unsigned char*>(vectors[sent].iov_base), vectors[sent].iov_len,
        peer, peerLength);
    if (result < 0)
    {
      if (result == XQC_SOCKET_EAGAIN)
        connection->owner->queueSocketContinuation(*connection);
      return sent ? static_cast<ssize_t>(sent) : result;
    }
  }
  return static_cast<ssize_t>(sent);
}

ssize_t XquicAdapter::writeMmsgEx(uint64_t, const iovec* vectors, unsigned count,
                                  const sockaddr* peer, socklen_t peerLength, void* context)
{
  return writeMmsg(vectors, count, peer, peerLength, context);
}

ssize_t XquicAdapter::statelessReset(const unsigned char* bytes, size_t length,
                                     const sockaddr* peer, socklen_t peerLength,
                                     const sockaddr*, socklen_t, void* context)
{
  return static_cast<XquicAdapter*>(context)->queuePacket(bytes, length, peer, peerLength);
}

ssize_t XquicAdapter::writeBeforeAccept(const unsigned char* bytes, size_t length,
                                        const sockaddr* peer, socklen_t peerLength,
                                        void* context)
{
  return static_cast<XquicAdapter*>(context)->queuePacket(bytes, length, peer, peerLength);
}

int XquicAdapter::serverAccept(xqc_engine_t*, xqc_connection_t* conn,
                               const xqc_cid_t* cid, void* context)
{
  auto& owner = *static_cast<XquicAdapter*>(context);
  if (owner.activeServerConnections() >= owner.serverConnectionLimit())
  {
    owner.admissionRefused_ = true;
    xqc_conn_set_transport_user_data(conn, nullptr);
    xqc_datagram_set_user_data(conn, nullptr);
    return -1;
  }
  auto& connection = owner.createConnection();
  connection.conn = conn;
  connection.cid = *cid;
  owner.connectionsByPointer_.emplace(conn, &connection);
  xqc_conn_set_transport_user_data(conn, &connection);
  xqc_datagram_set_user_data(conn, &connection);
  owner.acceptedConnections_.push_back(connection.id);
  return 0;
}

void XquicAdapter::updateCid(xqc_connection_t*, const xqc_cid_t*,
                             const xqc_cid_t* cid, void* context)
{
  if (context && cid) static_cast<Connection*>(context)->cid = *cid;
}

void XquicAdapter::saveSession(const char* bytes, size_t length, void* context)
{
  auto* connection = static_cast<Connection*>(context);
  if (!connection || !bytes) return;
  const auto* first = reinterpret_cast<const std::byte*>(bytes);
  connection->session.assign(first, first + length);
  connection->sessionIssuedRawNs = connection->owner->callbackRawNs_;
  BIO* bio = BIO_new_mem_buf(bytes, length);
  SSL_SESSION* session = bio ? PEM_read_bio_SSL_SESSION(bio, nullptr, nullptr, nullptr) : nullptr;
  if (session)
  {
    connection->sessionTicketLifetimeNs =
        static_cast<uint64_t>(SSL_SESSION_get_timeout(session)) * 1'000'000'000ULL;
    connection->sessionEarlyDataCapable = SSL_SESSION_early_data_capable(session) == 1;
  }
  SSL_SESSION_free(session);
  BIO_free(bio);
}

void XquicAdapter::saveTransportParameters(const char* bytes, size_t length, void* context)
{
  auto* connection = static_cast<Connection*>(context);
  if (!connection || !bytes) return;
  const auto* first = reinterpret_cast<const std::byte*>(bytes);
  connection->transportParameters.assign(first, first + length);
}

int XquicAdapter::selectCertificate(const char* sni, void** chain, void** certificate,
                                    void** key, void* context)
{
  auto* connection = static_cast<Connection*>(context);
  if (!connection || !sni || connection->owner->config_.tlsHostname != sni) return -1;
  *chain = connection->owner->serverChain_;
  *certificate = connection->owner->serverCertificate_;
  *key = connection->owner->serverKey_;
  return *chain && *certificate && *key ? XQC_OK : -1;
}

int XquicAdapter::verifyCertificate(const unsigned char* certificates[],
                                    const size_t lengths[], size_t count, void* context)
{
  auto* connection = static_cast<Connection*>(context);
  if (!connection || !connection->owner->config_.tlsVerifyPeer) return 0;
  if (!certificates || !lengths || count == 0 || !connection->owner->trustStore_) return -1;
  X509_STORE_CTX* verification = X509_STORE_CTX_new();
  STACK_OF(X509)* chain = sk_X509_new_null();
  X509* leaf = nullptr;
  bool decoded = verification && chain;
  for (size_t index = 0; decoded && index < count; ++index)
  {
    const unsigned char* cursor = certificates[index];
    X509* certificate = d2i_X509(nullptr, &cursor, static_cast<long>(lengths[index]));
    if (!certificate) { decoded = false; break; }
    if (index == 0) leaf = certificate;
    else sk_X509_push(chain, certificate);
  }
  const bool chainValid = decoded && leaf &&
      X509_STORE_CTX_init(verification, connection->owner->trustStore_, leaf, chain) == 1 &&
      X509_verify_cert(verification) == 1;
  const bool hostnameValid = chainValid &&
      X509_check_host(leaf, connection->owner->config_.tlsHostname.c_str(),
                      connection->owner->config_.tlsHostname.size(), 0, nullptr) == 1;
  connection->verificationObserved = true;
  connection->peerCertificateVerified = chainValid;
  connection->hostnameVerified = hostnameValid;
  X509_free(leaf);
  sk_X509_pop_free(chain, X509_free);
  X509_STORE_CTX_free(verification);
  return chainValid && hostnameValid ? 0 : -1;
}

int XquicAdapter::connectionCreated(xqc_connection_t* conn, const xqc_cid_t* cid,
                                    void* context, void*)
{
  auto* connection = static_cast<Connection*>(context);
  if (!connection) return -1;
  connection->conn = conn;
  connection->cid = *cid;
  connection->owner->connectionsByPointer_[conn] = connection;
  xqc_datagram_set_user_data(conn, connection);
  return 0;
}

xqc_int_t XquicAdapter::connectionClosing(xqc_connection_t* conn, const xqc_cid_t*,
                                          xqc_int_t, void* context)
{
  auto* connection = static_cast<Connection*>(context);
  if (!connection || connection->closing) return XQC_OK;
  const auto stats = xqc_conn_get_stats(connection->owner->engine_, &connection->cid);
  connection->finalPacketsLost = stats.lost_count;
  retainConnectionClose(conn, *connection);
  connection->closing = true;
  return XQC_OK;
}

void XquicAdapter::retainConnectionClose(xqc_connection_t* conn, Connection& state)
{
  uint64_t error = 0;
  uint64_t reasonLength = 0;
  if (xqc_conn_peer_close_error(conn, &error, &reasonLength) != XQC_TRUE) return;
  state.peerConnectionClose = true;
  state.peerConnectionCloseError = error;
  state.peerConnectionCloseReasonLength = reasonLength;
}

int XquicAdapter::connectionClosed(xqc_connection_t* conn, const xqc_cid_t*,
                                   void* context, void*)
{
  auto* connection = static_cast<Connection*>(context);
  if (connection)
  {
    retainConnectionClose(conn, *connection);
    for (auto& [_, stream] : connection->streams)
      if (stream->stream) retainTerminalFacts(stream->stream, *stream);
    connection->closed = true;
    connection->conn = nullptr;
    connection->owner->connectionsByPointer_.erase(conn);
  }
  return 0;
}

void XquicAdapter::refresh(Connection& connection)
{
  if (!engine_ || !connection.conn) return;
  const xqc_conn_stats_t stats = xqc_conn_get_stats(engine_, &connection.cid);
  connection.resumed = connection.resumed || stats.session_reused == XQC_TRUE;
  if (stats.early_data_flag == XQC_0RTT_ACCEPT)
  {
    connection.earlyAttempted = true;
    connection.earlyAccepted = true;
    connection.resumed = true;
  }
  else if (stats.early_data_flag == XQC_0RTT_REJECT)
  {
    connection.earlyAttempted = true;
    connection.earlyRejected = true;
  }
}

void XquicAdapter::handshakeDone(xqc_connection_t* conn, void* context, void*)
{
  auto* connection = static_cast<Connection*>(context);
  if (!connection) return;
  connection->conn = conn;
  connection->connected = true;
  connection->owner->refresh(*connection);
}

xqc_int_t XquicAdapter::streamCreated(xqc_stream_t* stream, void* context)
{
  auto* connection = static_cast<Connection*>(xqc_get_conn_user_data_by_stream(stream));
  if (!connection) return -1;
  const uint64_t id = xqc_stream_id(stream);
  const bool clientInitiated = (id & 1U) == 0;
  const bool locallyInitiated = clientInitiated ==
      (connection->owner->config_.role == EndpointRole::client);
  if (locallyInitiated)
  {
    xqc_stream_set_user_data(stream, context);
    return 0;
  }
  auto found = connection->streams.find(id);
  if (found == connection->streams.end())
  {
    auto state = std::make_unique<Stream>();
    state->stream = stream;
    connection->streams.emplace(id, std::move(state));
    if (xqc_stream_get_direction(stream) == XQC_STREAM_UNI)
      connection->acceptedUni.push_back(id);
    else connection->acceptedBidi.push_back(id);
  }
  connection->owner->retainControlStream(*connection, id, stream);
  xqc_stream_set_user_data(stream, connection->streams.at(id).get());
  return 0;
}

xqc_int_t XquicAdapter::streamReadable(xqc_stream_t* stream, void* context)
{
  auto* state = static_cast<Stream*>(context);
  if (!state) return -1;
  auto* connection = static_cast<Connection*>(xqc_get_conn_user_data_by_stream(stream));
  if (!connection) return -1;
  std::array<std::byte, 64 * 1024> bytes {};
  for (;;)
  {
    uint8_t fin = 0;
    const ssize_t count = xqc_stream_recv(
        stream, reinterpret_cast<unsigned char*>(bytes.data()), bytes.size(), &fin);
    if (count == -XQC_EAGAIN) break;
    if (count == -XQC_ESTREAM_RESET)
    {
      retainTerminalFacts(stream, *state);
      break;
    }
    if (count < 0) return count;
    if (count > 0)
    {
      const size_t received = static_cast<size_t>(count);
      if (!connection->connected &&
          (connection->earlyDataBytes > connection->owner->config_.tlsMaximumEarlyDataBytes ||
           received > connection->owner->config_.tlsMaximumEarlyDataBytes -
               connection->earlyDataBytes))
        return -XQC_EPROTO;
      if (!connection->connected) connection->earlyDataBytes += received;
      state->received.insert(state->received.end(), bytes.begin(), bytes.begin() + count);
    }
    if (fin)
    {
      state->remoteFin = true;
      state->terminalFacts.available = true;
      state->terminalFacts.fin = true;
      break;
    }
    if (count == 0) break;
  }
  return 0;
}

xqc_int_t XquicAdapter::streamWritable(xqc_stream_t* stream, void* context)
{
  auto* state = static_cast<Stream*>(context);
  if (!state || !stream) return -1;
  state->writable = true;
  if (!state->finishPending) return XQC_OK;
  const ssize_t result = xqc_stream_send(stream, nullptr, 0, 1);
  if (result == -XQC_EAGAIN)
  {
    state->writable = false;
    return XQC_OK;
  }
  if (result < 0) return static_cast<xqc_int_t>(result);
  state->finishPending = false;
  state->finishSent = true;
  return XQC_OK;
}

void XquicAdapter::retainTerminalFacts(xqc_stream_t* stream, Stream& state)
{
  xqc_bool_t fin = XQC_FALSE;
  xqc_bool_t reset = XQC_FALSE;
  xqc_bool_t stop = XQC_FALSE;
  uint64_t resetError = 0;
  uint64_t stopError = 0;
  if (!stream || xqc_stream_peer_terminal(stream, &fin, &reset, &resetError,
                                           &stop, &stopError) != XQC_OK)
    return;
  state.terminalFacts.available = true;
  state.terminalFacts.fin |= fin == XQC_TRUE || state.remoteFin;
  if (reset == XQC_TRUE)
  {
    state.terminalFacts.resetStream = true;
    state.terminalFacts.resetStreamError = resetError;
  }
  if (stop == XQC_TRUE)
  {
    state.terminalFacts.stopSending = true;
    state.terminalFacts.stopSendingError = stopError;
  }
}

void XquicAdapter::streamClosing(xqc_stream_t* stream, xqc_int_t, void* context)
{
  auto* state = static_cast<Stream*>(context);
  if (state) retainTerminalFacts(stream, *state);
}

xqc_int_t XquicAdapter::streamClosed(xqc_stream_t* stream, void* context)
{
  auto* state = static_cast<Stream*>(context);
  if (state)
  {
    streamReadable(stream, context);
    retainTerminalFacts(stream, *state);
    state->stream = nullptr;
    state->finishPending = false;
    state->closed = true;
  }
  return 0;
}

void XquicAdapter::datagramRead(xqc_connection_t* conn, void* context, const void* bytes,
                                size_t length, uint64_t)
{
  auto* connection = static_cast<Connection*>(context);
  if (!connection || !bytes) return;
  if (!connection->connected &&
      (connection->earlyDataBytes > connection->owner->config_.tlsMaximumEarlyDataBytes ||
       length > connection->owner->config_.tlsMaximumEarlyDataBytes -
           connection->earlyDataBytes))
  {
    xqc_conn_close_with_error(conn, 1);
    return;
  }
  if (!connection->connected) connection->earlyDataBytes += length;
  const auto* first = static_cast<const std::byte*>(bytes);
  connection->datagrams.emplace_back(first, first + length);
}

xqc_conn_settings_t XquicAdapter::connectionSettings() const
{
  xqc_conn_settings_t settings = xqc_conn_get_conn_settings_template(XQC_CONN_SETTINGS_DEFAULT);
  settings.pacing_on = config_.packetIo.commonPacing;
  settings.cong_ctrl_callback = config_.congestionController == "cubic" ? xqc_cubic_cb : xqc_bbr_cb;
  settings.cc_params.customize_on = 1;
  settings.cc_params.init_cwnd_bytes = config_.initialCongestionWindowBytes;
  settings.proto_version = XQC_VERSION_V1;
  settings.init_idle_time_out = config_.idleTimeoutMs;
  settings.idle_time_out = config_.idleTimeoutMs;
  settings.max_udp_payload_size = config_.maxUdpPayloadSize;
  settings.init_recv_window = std::min<uint64_t>(
      config_.connectionWindow, std::numeric_limits<uint32_t>::max());
  settings.initial_max_data = config_.connectionWindow;
  settings.initial_max_stream_data = config_.streamWindow;
  settings.stream_credit_replenish_below = config_.streamCreditReplenishBelow;
  settings.max_ack_delay = static_cast<uint32_t>(config_.maxAckDelayNs / 1'000'000);
  settings.ack_delay_exponent = config_.ackDelayExponent;
  settings.adaptive_ack_frequency = config_.ackFrequency;
  settings.enable_multipath = 0;
  settings.active_connection_id_limit = config_.activeConnectionIdLimit;
  settings.max_streams_bidi = config_.maxBidiStreams;
  settings.max_streams_uni = config_.maxUniStreams;
  settings.max_datagram_frame_size = config_.datagramMaxFrameSize;
  settings.enable_pmtud = config_.packetIo.pmtud ? 3 : 0;
  return settings;
}

bool XquicAdapter::initializeServerCertificate(AdapterError& error)
{
  BIO* certificateFile = BIO_new_file(config_.certificatePath.c_str(), "r");
  BIO* keyFile = BIO_new_file(config_.privateKeyPath.c_str(), "r");
  BIO* chainFile = BIO_new_file(config_.chainPath.c_str(), "r");
  serverChain_ = sk_X509_new_null();
  serverCertificate_ = certificateFile ?
      PEM_read_bio_X509(certificateFile, nullptr, nullptr, nullptr) : nullptr;
  serverKey_ = keyFile ? PEM_read_bio_PrivateKey(keyFile, nullptr, nullptr, nullptr) : nullptr;
  X509* issuer = chainFile ? PEM_read_bio_X509(chainFile, nullptr, nullptr, nullptr) : nullptr;
  BIO_free(certificateFile);
  BIO_free(keyFile);
  BIO_free(chainFile);
  if (!serverChain_ || !serverCertificate_ || !serverKey_ || !issuer ||
      X509_check_private_key(serverCertificate_, serverKey_) != 1 ||
      sk_X509_push(serverChain_, issuer) == 0)
  {
    X509_free(issuer);
    error = {10, "XQUIC failed to load the configured certificate chain and key"};
    return false;
  }
  return true;
}

bool XquicAdapter::initializeTrustStore(AdapterError& error)
{
  trustStore_ = X509_STORE_new();
  if (!trustStore_ ||
      X509_STORE_load_locations(trustStore_, config_.chainPath.c_str(), nullptr) != 1)
  {
    error = {10, "XQUIC failed to load the configured trust chain"};
    return false;
  }
  return true;
}

bool XquicAdapter::initializeEngine(AdapterError& error)
{
  xqc_log_disable(std::getenv("QUICPERF_XQUIC_LOG") ? XQC_FALSE : XQC_TRUE);
  xqc_engine_type_t type = config_.role == EndpointRole::server ?
      XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT;
  if (type == XQC_ENGINE_SERVER && !initializeServerCertificate(error)) return false;
  if (type == XQC_ENGINE_CLIENT && config_.tlsVerifyPeer && !initializeTrustStore(error))
    return false;
  xqc_config_t engineConfig {};
  if (xqc_engine_get_default_config(&engineConfig, type) != XQC_OK)
  {
    error = {10, "xqc_engine_get_default_config failed"};
    return false;
  }
  engineConfig.cfg_log_level = XQC_LOG_ERROR;
  engineConfig.cfg_log_event = 0;
  engineConfig.cfg_log_timestamp = 0;
  engineConfig.cid_len = config_.connectionIdBytes;
  engineConfig.sendmmsg_on = 1;

  xqc_engine_ssl_config_t tls {};
  tls.ciphers = const_cast<char*>("TLS_AES_128_GCM_SHA256");
  tls.groups = const_cast<char*>("X25519");
  if (config_.tlsTicketLifetimeNs % 1'000'000'000ULL != 0 ||
      config_.tlsTicketLifetimeNs / 1'000'000'000ULL > UINT32_MAX)
  {
    error = {10, "XQUIC requires an integral 32-bit TLS ticket lifetime in seconds"};
    return false;
  }
  tls.session_timeout = static_cast<uint32_t>(
      config_.tlsTicketLifetimeNs / 1'000'000'000ULL);
  if (config_.role == EndpointRole::server)
  {
    tls.private_key_file = config_.privateKeyPath.data();
    tls.cert_file = config_.certificatePath.data();
    tls.session_ticket_key_data = const_cast<char*>(ticketKey.data());
    tls.session_ticket_key_len = ticketKey.size();
  }

  xqc_engine_callback_t engineCallbacks {};
  engineCallbacks.set_event_timer = setTimer;
  engineCallbacks.realtime_ts = realtimeNowUs;
  engineCallbacks.monotonic_ts = monotonicNowUs;
  engineCallbacks.log_callbacks.xqc_log_write_err = ignoreLog;
  engineCallbacks.log_callbacks.xqc_log_write_stat = ignoreLog;
  engineCallbacks.log_callbacks.xqc_qlog_event_write = ignoreQlog;

  xqc_transport_callbacks_t transport {};
  transport.server_accept = serverAccept;
  transport.server_refuse = serverRefuse;
  transport.stateless_reset = statelessReset;
  transport.write_socket = writeSocket;
  transport.write_mmsg = writeMmsg;
  transport.write_socket_ex = writeSocketEx;
  transport.write_mmsg_ex = writeMmsgEx;
  transport.conn_update_cid_notify = updateCid;
  transport.save_token = saveToken;
  transport.save_session_cb = saveSession;
  transport.save_tp_cb = saveTransportParameters;
  transport.conn_cert_cb = selectCertificate;
  transport.cert_verify_cb = verifyCertificate;
  transport.conn_closing = connectionClosing;
  transport.conn_peer_addr_changed_notify = peerAddressChanged;
  transport.path_peer_addr_changed_notify = pathPeerAddressChanged;
  transport.conn_send_packet_before_accept = writeBeforeAccept;

  engine_ = xqc_engine_create(type, &engineConfig, &tls, &engineCallbacks, &transport, this);
  if (!engine_) { error = {10, "xqc_engine_create failed"}; return false; }
  xqc_app_proto_callbacks_t application {};
  application.conn_cbs.conn_create_notify = connectionCreated;
  application.conn_cbs.conn_close_notify = connectionClosed;
  application.conn_cbs.conn_handshake_finished = handshakeDone;
  application.stream_cbs.stream_create_notify = streamCreated;
  application.stream_cbs.stream_read_notify = streamReadable;
  application.stream_cbs.stream_write_notify = streamWritable;
  application.stream_cbs.stream_close_notify = streamClosed;
  application.stream_cbs.stream_closing_notify = streamClosing;
  application.dgram_cbs.datagram_read_notify = datagramRead;
  application.dgram_cbs.datagram_write_notify = datagramWrite;
  application.dgram_cbs.datagram_mss_updated_notify = datagramMss;
  if (xqc_engine_register_alpn(
      engine_, protocol.data(), protocol.size(), &application, nullptr) != XQC_OK)
  {
    error = {10, "xqc_engine_register_alpn failed"};
    return false;
  }
  if (config_.role == EndpointRole::server)
  {
    auto settings = connectionSettings();
    xqc_server_set_conn_settings(engine_, &settings);
  }
  return true;
}

bool XquicAdapter::configure(std::string_view canonicalConfig, AdapterError& error)
{
  if (configured_) { error = {1, "XQUIC adapter is already configured"}; return false; }
  auto parsed = parseEndpointConfig(canonicalConfig);
  if (!parsed) { error = {1, parsed.error}; return false; }
  config_ = std::move(parsed.config);
  if (config_.calendarUnixSeconds >
      std::numeric_limits<uint64_t>::max() / 1'000'000'000ULL)
  {
    error = {1, "XQUIC frozen TLS calendar time overflows nanoseconds"};
    return false;
  }
  clockAnchorRawNs_ = monotonicRawNowNs();
  clockAnchorRealtimeNs_ = config_.calendarUnixSeconds * 1'000'000'000ULL;
  useCommonTime(clockAnchorRawNs_);
  if (!initializeEngine(error))
  {
    AdapterError ignored;
    reset(ignored);
    return false;
  }
  configured_ = true;
  error = {};
  return true;
}

bool XquicAdapter::setLocalAddress(const sockaddr_in& local, AdapterError& error)
{
  in_addr configured {};
  if (!configured_ || localAddressSet_ || !connections_.empty() || local.sin_family != AF_INET ||
      inet_pton(AF_INET, config_.bindAddress.c_str(), &configured) != 1 ||
      configured.s_addr != local.sin_addr.s_addr ||
      (config_.bindPort && ntohs(local.sin_port) != config_.bindPort))
  {
    error = {2, "post-bind IPv4 local address differs from frozen XQUIC configuration"};
    return false;
  }
  localAddress_ = local;
  localAddressSet_ = true;
  error = {};
  return true;
}

void XquicAdapter::process(uint64_t nowRawNs)
{
  useCommonTime(nowRawNs);
  xqc_engine_main_logic(engine_);
  reapReleasedConnections();
  const uint64_t delay = std::max<uint64_t>(1, nextWakeUs_) * 1000;
  nextTimeoutRawNs_ = nowRawNs > std::numeric_limits<uint64_t>::max() - delay ?
      std::numeric_limits<uint64_t>::max() : nowRawNs + delay;
}

void XquicAdapter::reapReleasedConnections()
{
  std::erase_if(connections_, [this](const auto& item) {
    if (!item.second->closed || !item.second->releaseWhenClosed) return false;
    counters_.packetsLost += item.second->finalPacketsLost;
    std::erase(acceptedConnections_, item.first);
    return true;
  });
}

bool XquicAdapter::receiveBatch(std::span<const ReceivedPacket> packets, uint64_t nowRawNs,
                                AdapterError& error)
{
  if (!configured_ || !localAddressSet_) { error = {5, "XQUIC adapter is not ready"}; return false; }
  for (const auto& packet : packets)
  {
    if (packet.peer.sin_family != AF_INET || packet.bytes.empty())
    {
      error = {5, "invalid XQUIC received packet"};
      return false;
    }
    useCommonTime(packet.receivedRawNs);
    const xqc_int_t result = xqc_engine_packet_process(
        engine_, reinterpret_cast<const unsigned char*>(packet.bytes.data()), packet.bytes.size(),
        reinterpret_cast<const sockaddr*>(&localAddress_), sizeof(localAddress_),
        reinterpret_cast<const sockaddr*>(&packet.peer), sizeof(packet.peer),
        packet.receivedRawNs / 1000, this);
    if (result == -XQC_ECREATE_CONN && std::exchange(admissionRefused_, false))
    {
      ++counters_.packetsReceived;
      continue;
    }
    admissionRefused_ = false;
    if (result == -XQC_ECONN_NFOUND || result == -XQC_EILLPKT)
    {
      ++counters_.packetsReceived;
      continue;
    }
    if (result != XQC_OK)
    {
      error = {5, "xqc_engine_packet_process failed with XQUIC error " +
                      std::to_string(result)};
      return false;
    }
    ++counters_.packetsReceived;
  }
  xqc_engine_finish_recv(engine_);
  process(nowRawNs);
  error = {};
  return true;
}

size_t XquicAdapter::pollTransmitBatch(std::span<TransmitPacket> packets,
                                       uint64_t nowRawNs, AdapterError& error)
{
  if (!configured_ || !localAddressSet_) { error = {6, "XQUIC adapter is not ready"}; return 0; }
  const size_t packetCapacity = std::max<uint64_t>(
      1, applicationBufferBytes / std::max<uint64_t>(1, config_.maxUdpPayloadSize));
  for (size_t attempts = socketContinuations_.size();
       attempts > 0 && outputQueue_.size() < packetCapacity; --attempts)
  {
    const uint64_t connectionId = socketContinuations_.front();
    socketContinuations_.pop_front();
    const auto found = connections_.find(connectionId);
    if (found != connections_.end() && found->second->conn)
    {
      found->second->socketContinuationQueued = false;
      xqc_conn_continue_send_by_conn(found->second->conn);
    }
  }
  process(nowRawNs);
  const size_t count = std::min({packets.size(), output_.size(), outputQueue_.size()});
  for (size_t index = 0; index < count; ++index)
  {
    auto packet = std::move(outputQueue_.front());
    outputQueue_.pop_front();
    std::copy(packet.bytes.begin(), packet.bytes.end(), output_[index].begin());
    packets[index] = {std::span<const std::byte>(output_[index]).first(packet.bytes.size()),
                      packet.peer, 0, 0, nowRawNs};
  }
  error = {};
  return count;
}

bool XquicAdapter::onTimeout(uint64_t nowRawNs, AdapterError& error)
{
  if (!engine_) { error = {7, "XQUIC adapter is not configured"}; return false; }
  ++counters_.timerExpirations;
  process(nowRawNs);
  error = {};
  return true;
}

bool XquicAdapter::connect(const sockaddr_in& peer, uint64_t nowRawNs,
                           uint64_t& connectionId, AdapterError& error)
{
  if (!configured_ || !localAddressSet_ || config_.role != EndpointRole::client ||
      peer.sin_family != AF_INET)
  {
    error = {8, "XQUIC connect requires a configured client and IPv4 peer"};
    return false;
  }
  auto& connection = createConnection();
  connection.peer = peer;
  useCommonTime(nowRawNs);
  xqc_conn_ssl_config_t tls {};
  std::string importedIdentity;
  tls.cert_verify_flag = config_.tlsVerifyPeer ?
      XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED : 0;
  if (importedState_)
  {
    connection.imported = true;
    connection.sessionIssuedRawNs = importedState_->issuedRawNs;
    importedIdentity = importedState_->identity;
    tls.session_ticket_data = reinterpret_cast<char*>(importedState_->session.data());
    tls.session_ticket_len = importedState_->session.size();
    tls.transport_parameter_data = reinterpret_cast<char*>(
        importedState_->transportParameters.data());
    tls.transport_parameter_data_len = importedState_->transportParameters.size();
  }
  auto settings = connectionSettings();
  const xqc_cid_t* cid = xqc_connect(
      engine_, &settings, nullptr, 0, config_.tlsHostname.c_str(), 0, &tls,
      reinterpret_cast<const sockaddr*>(&peer), sizeof(peer), protocol.data(), &connection);
  const bool zeroRtt = importedState_ && importedState_->zeroRtt;
  importedState_.reset();
  if (!cid)
  {
    connections_.erase(connection.id);
    error = {8, "xqc_connect failed"};
    return false;
  }
  connection.cid = *cid;
  connection.conn = xqc_engine_get_conn_by_scid(engine_, cid);
  if (connection.conn) connectionsByPointer_[connection.conn] = &connection;
  connection.earlyAttempted = zeroRtt && connection.conn &&
      xqc_conn_is_ready_to_send_early_data(connection.conn);
  if (!importedIdentity.empty()) consumedSessions_.insert(std::move(importedIdentity));
  connectionId = connection.id;
  process(nowRawNs);
  error = {};
  return true;
}

PrimitiveStatus XquicAdapter::acceptConnection(uint64_t nowRawNs, uint64_t& connectionId,
                                                AdapterError& error)
{
  useCommonTime(nowRawNs);
  if (config_.role != EndpointRole::server) return unavailable("acceptConnection", error);
  if (acceptedConnections_.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  connectionId = acceptedConnections_.front();
  acceptedConnections_.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

bool XquicAdapter::isConnected(uint64_t connectionId, uint64_t nowRawNs, bool& connected,
                               AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  connected = connection->connected && !connection->closing && !connection->closed;
  error = {};
  return true;
}

bool XquicAdapter::connectionIsClosed(uint64_t connectionId, uint64_t nowRawNs,
                                      bool& closed, AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  closed = connection->closing || connection->closed;
  error = {};
  return true;
}

bool XquicAdapter::releaseConnectionWhenClosed(uint64_t connectionId,
                                               uint64_t nowRawNs,
                                               AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  connection->releaseWhenClosed = true;
  reapReleasedConnections();
  error = {};
  return true;
}

PrimitiveStatus XquicAdapter::openStream(uint64_t connectionId,
                                          xqc_stream_direction_t direction,
                                          uint64_t& streamId, AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (!connection->conn) { error = {}; return PrimitiveStatus::wouldBlock; }
  auto state = std::make_unique<Stream>();
  xqc_stream_t* stream = xqc_stream_create_with_direction(
      connection->conn, direction, state.get());
  if (!stream) { error = {}; return PrimitiveStatus::wouldBlock; }
  state->stream = stream;
  streamId = xqc_stream_id(stream);
  xqc_stream_set_user_data(stream, state.get());
  retainControlStream(*connection, streamId, stream);
  connection->streams[streamId] = std::move(state);
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus XquicAdapter::openBidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                                      uint64_t& streamId,
                                                      AdapterError& error)
{
  useCommonTime(nowRawNs);
  return openStream(connectionId, XQC_STREAM_BIDI, streamId, error);
}

PrimitiveStatus XquicAdapter::openUnidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                                       uint64_t& streamId,
                                                       AdapterError& error)
{
  useCommonTime(nowRawNs);
  return openStream(connectionId, XQC_STREAM_UNI, streamId, error);
}

PrimitiveStatus XquicAdapter::acceptStream(uint64_t connectionId, bool unidirectional,
                                            uint64_t& streamId, AdapterError& error)
{
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  auto& queue = unidirectional ? connection->acceptedUni : connection->acceptedBidi;
  if (queue.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  streamId = queue.front();
  queue.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus XquicAdapter::acceptBidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                                        uint64_t& streamId,
                                                        AdapterError& error)
{
  useCommonTime(nowRawNs);
  return acceptStream(connectionId, false, streamId, error);
}

PrimitiveStatus XquicAdapter::acceptUnidirectionalStream(uint64_t connectionId, uint64_t nowRawNs,
                                                         uint64_t& streamId,
                                                         AdapterError& error)
{
  useCommonTime(nowRawNs);
  return acceptStream(connectionId, true, streamId, error);
}

bool XquicAdapter::writeStream(uint64_t connectionId, uint64_t streamId,
                               std::span<const std::byte> bytes, uint64_t nowRawNs,
                               size_t& written, AdapterError& error)
{
  useCommonTime(nowRawNs);
  written = 0;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  auto* stream = findStream(*connection, streamId, error);
  if (!stream) return false;
  if (!stream->writable) { error = {}; return true; }
  const bool control = connection->controlStreamId &&
      *connection->controlStreamId == streamId;
  size_t packetBytes = 0;
  if (!writablePacketBytes(*connection, control, packetBytes, error)) return false;
  const bool early = connection->earlyAttempted && !connection->connected;
  size_t allowed = std::min(bytes.size(), packetBytes);
  if (early)
  {
    if (connection->earlyDataBytes > config_.tlsMaximumEarlyDataBytes)
    {
      error = {9, "XQUIC early-data accounting exceeded the configured limit"};
      return false;
    }
    allowed = std::min<size_t>(
        allowed, config_.tlsMaximumEarlyDataBytes - connection->earlyDataBytes);
    if (allowed == 0) { error = {}; return true; }
  }
  if (allowed == 0) { error = {}; return true; }
  const ssize_t result = xqc_stream_send(
      stream->stream, reinterpret_cast<unsigned char*>(const_cast<std::byte*>(bytes.data())),
      allowed, 0);
  if (result == -XQC_EAGAIN)
  {
    stream->writable = false;
    error = {};
    return true;
  }
  if (result < 0)
  {
    error = {9, "xqc_stream_send failed with XQUIC error " + std::to_string(result)};
    return false;
  }
  written = static_cast<size_t>(result);
  if (early) connection->earlyDataBytes += written;
  error = {};
  return true;
}

bool XquicAdapter::consumeStreamData(uint64_t connectionId, uint64_t streamId,
                                     std::span<std::byte> bytes, uint64_t nowRawNs,
                                     size_t& read, bool& finished, AdapterError& error)
{
  useCommonTime(nowRawNs);
  read = 0;
  finished = false;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  const auto found = connection->streams.find(streamId);
  if (found == connection->streams.end())
  {
    error = {4, "unknown XQUIC stream"};
    return false;
  }
  auto* stream = found->second.get();
  read = std::min(bytes.size(), stream->received.size() - stream->receiveOffset);
  std::copy_n(stream->received.begin() + stream->receiveOffset, read, bytes.begin());
  stream->receiveOffset += read;
  finished = (stream->remoteFin || stream->terminalFacts.fin) &&
      stream->receiveOffset == stream->received.size();
  if (stream->receiveOffset == stream->received.size())
  {
    stream->received.clear();
    stream->receiveOffset = 0;
  }
  error = {};
  return true;
}

bool XquicAdapter::finishStream(uint64_t connectionId, uint64_t streamId, uint64_t nowRawNs,
                                AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  auto* stream = findStream(*connection, streamId, error);
  if (!stream) return false;
  if (stream->finishSent || stream->finishPending) { error = {}; return true; }
  if (!stream->writable)
  {
    stream->finishPending = true;
    error = {};
    return true;
  }
  const ssize_t result = xqc_stream_send(stream->stream, nullptr, 0, 1);
  if (result == -XQC_EAGAIN)
  {
    stream->writable = false;
    stream->finishPending = true;
    error = {};
    return true;
  }
  if (result < 0)
  {
    retainTerminalFacts(stream->stream, *stream);
    error = {
        10,
        "xqc_stream_send(FIN) failed: result=" + std::to_string(result) +
            " connection=" + std::to_string(connectionId) +
            " stream=" + std::to_string(streamId) +
            " peer_fin=" + std::to_string(stream->terminalFacts.fin) +
            " peer_reset=" + std::to_string(stream->terminalFacts.resetStream) +
            " peer_stop=" + std::to_string(stream->terminalFacts.stopSending),
    };
    return false;
  }
  stream->finishSent = true;
  error = {};
  return true;
}

PrimitiveStatus XquicAdapter::unavailable(std::string_view primitive,
                                          AdapterError& error) const
{
  error = {11, "XQUIC source package does not expose " + std::string(primitive)};
  return PrimitiveStatus::fatal;
}

bool XquicAdapter::resetStream(uint64_t connectionId, uint64_t streamId,
                               uint64_t applicationError, uint64_t nowRawNs,
                               AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  auto* stream = findStream(*connection, streamId, error);
  if (!stream) return false;
  if (xqc_stream_reset(stream->stream, applicationError) != XQC_OK)
  {
    error = {12, "xqc_stream_reset failed"};
    return false;
  }
  error = {};
  return true;
}

bool XquicAdapter::stopSending(uint64_t connectionId, uint64_t streamId,
                               uint64_t applicationError, uint64_t nowRawNs,
                               AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  auto* stream = findStream(*connection, streamId, error);
  if (!stream) return false;
  if (xqc_stream_stop_sending(stream->stream, applicationError) != XQC_OK)
  {
    error = {12, "xqc_stream_stop_sending failed"};
    return false;
  }
  error = {};
  return true;
}

PrimitiveStatus XquicAdapter::sendDatagram(uint64_t connectionId,
                                           std::span<const std::byte> bytes,
                                           uint64_t nowRawNs, AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (!connection->conn) { error = {}; return PrimitiveStatus::wouldBlock; }
  size_t packetBytes = 0;
  if (!writablePacketBytes(*connection, false, packetBytes, error))
    return PrimitiveStatus::fatal;
  if (bytes.size() > packetBytes) { error = {}; return PrimitiveStatus::wouldBlock; }
  const bool early = connection->earlyAttempted && !connection->connected;
  if (early && (connection->earlyDataBytes > config_.tlsMaximumEarlyDataBytes ||
                bytes.size() > config_.tlsMaximumEarlyDataBytes - connection->earlyDataBytes))
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  uint64_t id = 0;
  const xqc_int_t result = xqc_datagram_send(
      connection->conn, const_cast<std::byte*>(bytes.data()), bytes.size(), &id,
      XQC_DATA_QOS_NORMAL);
  if (result == -XQC_EAGAIN) { error = {}; return PrimitiveStatus::wouldBlock; }
  if (result != XQC_OK) return unavailable("requested DATAGRAM operation", error);
  if (early) connection->earlyDataBytes += bytes.size();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus XquicAdapter::consumeDatagram(uint64_t connectionId,
                                              std::span<std::byte> bytes,
                                              uint64_t nowRawNs, size_t& read,
                                              AdapterError& error)
{
  useCommonTime(nowRawNs);
  read = 0;
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (connection->datagrams.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  auto& datagram = connection->datagrams.front();
  if (datagram.size() > bytes.size()) return unavailable("DATAGRAM destination capacity", error);
  read = datagram.size();
  std::copy(datagram.begin(), datagram.end(), bytes.begin());
  connection->datagrams.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus XquicAdapter::exportResumptionState(uint64_t connectionId, uint64_t nowRawNs,
                                                    std::span<std::byte> bytes,
                                                    size_t& written,
                                                    AdapterError& error)
{
  useCommonTime(nowRawNs);
  written = 0;
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (connection->session.empty() || connection->transportParameters.empty())
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  const size_t required = resumptionHeaderBytes + connection->session.size() +
      connection->transportParameters.size();
  if (required > bytes.size() || connection->session.size() > UINT32_MAX ||
      connection->transportParameters.size() > UINT32_MAX)
    return unavailable("resumption export destination capacity", error);
  storeU32(bytes.data(), resumptionMagic);
  storeU32(bytes.data() + 4, connection->session.size());
  storeU32(bytes.data() + 8, connection->transportParameters.size());
  storeU64(bytes.data() + 12, connection->sessionIssuedRawNs);
  std::copy(connection->session.begin(), connection->session.end(),
            bytes.begin() + resumptionHeaderBytes);
  std::copy(connection->transportParameters.begin(), connection->transportParameters.end(),
            bytes.begin() + resumptionHeaderBytes + connection->session.size());
  written = required;
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus XquicAdapter::importResumptionState(std::span<const std::byte> bytes,
                                                    bool useZeroRtt, uint64_t nowRawNs,
                                                    AdapterError& error)
{
  useCommonTime(nowRawNs);
  if (importedState_ || bytes.size() < resumptionHeaderBytes ||
      loadU32(bytes.data()) != resumptionMagic)
    return unavailable("valid one-shot resumption state", error);
  const size_t sessionLength = loadU32(bytes.data() + 4);
  const size_t parameterLength = loadU32(bytes.data() + 8);
  const uint64_t issuedRawNs = loadU64(bytes.data() + 12);
  if (sessionLength == 0 || parameterLength == 0 ||
      sessionLength > bytes.size() - resumptionHeaderBytes ||
      parameterLength != bytes.size() - resumptionHeaderBytes - sessionLength)
    return unavailable("valid resumption state lengths", error);
  if (nowRawNs < issuedRawNs || nowRawNs - issuedRawNs >= config_.tlsTicketLifetimeNs)
    return unavailable("unexpired resumption state", error);
  const std::string identity(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  if (consumedSessions_.contains(identity))
    return unavailable("unused resumption state", error);
  const auto sessionBytes = bytes.subspan(resumptionHeaderBytes, sessionLength);
  BIO* bio = BIO_new_mem_buf(sessionBytes.data(), sessionBytes.size());
  SSL_SESSION* session = bio ? PEM_read_bio_SSL_SESSION(bio, nullptr, nullptr, nullptr) : nullptr;
  const bool earlyCapable = session && SSL_SESSION_early_data_capable(session) == 1;
  SSL_SESSION_free(session);
  BIO_free(bio);
  if (useZeroRtt && !earlyCapable)
    return unavailable("early-data-capable resumption state", error);
  importedState_ = std::make_unique<ImportedState>();
  importedState_->session.assign(sessionBytes.begin(), sessionBytes.end());
  importedState_->transportParameters.assign(
      bytes.begin() + resumptionHeaderBytes + sessionLength, bytes.end());
  importedState_->identity = identity;
  importedState_->issuedRawNs = issuedRawNs;
  importedState_->zeroRtt = useZeroRtt;
  error = {};
  return PrimitiveStatus::ready;
}

bool XquicAdapter::connectionResumed(uint64_t connectionId, uint64_t nowRawNs, bool& resumed,
                                     AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  refresh(*connection);
  resumed = connection->resumed;
  error = {};
  return true;
}

bool XquicAdapter::zeroRttAttempted(uint64_t connectionId, uint64_t nowRawNs, bool& attempted,
                                    AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  refresh(*connection);
  attempted = connection->earlyAttempted;
  error = {};
  return true;
}

bool XquicAdapter::zeroRttAccepted(uint64_t connectionId, uint64_t nowRawNs, bool& accepted,
                                   AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  refresh(*connection);
  accepted = connection->earlyAccepted;
  error = {};
  return true;
}

bool XquicAdapter::zeroRttRejected(uint64_t connectionId, uint64_t nowRawNs, bool& rejected,
                                   AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  refresh(*connection);
  rejected = connection->earlyRejected;
  error = {};
  return true;
}

bool XquicAdapter::closeConnection(uint64_t connectionId, uint64_t applicationError,
                                   uint64_t nowRawNs, AdapterError& error)
{
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  const xqc_int_t result = xqc_conn_close_application(connection->conn, applicationError);
  if (result != XQC_OK) { error = {12, "xqc_conn_close_application failed"}; return false; }
  error = {};
  return true;
}

bool XquicAdapter::peerTerminalFacts(uint64_t connectionId, uint64_t streamId,
                                     uint64_t nowRawNs, PeerTerminalFacts& facts,
                                     AdapterError& error)
{
  facts = {};
  useCommonTime(nowRawNs);
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  const auto found = connection->streams.find(streamId);
  if (found == connection->streams.end())
  {
    error = {4, "unknown XQUIC stream"};
    return false;
  }
  auto& stream = *found->second;
  if (stream.stream) retainTerminalFacts(stream.stream, stream);
  facts = stream.terminalFacts;
  facts.available = true;
  facts.connectionClose = connection->peerConnectionClose;
  facts.connectionCloseError = connection->peerConnectionCloseError;
  facts.connectionCloseReasonLength = connection->peerConnectionCloseReasonLength;
  error = {};
  return true;
}

TransportCounters XquicAdapter::snapshotTransportCounters() const noexcept
{
  callbackClockOwner_ = const_cast<XquicAdapter*>(this);
  TransportCounters result = counters_;
  uint64_t lost = 0;
  for (const auto& [_, connection] : connections_)
  {
    if (!connection->conn || connection->closed) continue;
    const auto stats = xqc_conn_get_stats(engine_, &connection->cid);
    lost += stats.lost_count;
  }
  result.packetsLost += lost;
  return result;
}

NegotiatedSettings XquicAdapter::snapshotNegotiatedSettings() const noexcept
{
  callbackClockOwner_ = const_cast<XquicAdapter*>(this);
  const auto snapshot = [this](const Connection& connection) {
    NegotiatedSettings result;
    result.evidenceSource =
        "xqc live initial-path controller+post-handshake local/peer transport parameters+"
        "BoringSSL TLS/session state+adapter one-use/early-data policy";
    const auto unavailable = [&result](std::string field) {
      if (std::ranges::find(result.unavailableFields, field) ==
          result.unavailableFields.end())
        result.unavailableFields.push_back(std::move(field));
    };
    if (!connection.conn || !connection.connected || connection.closed)
    {
      unavailable("handshake_not_complete");
      return result;
    }

    auto* ssl = static_cast<SSL*>(xqc_conn_get_ssl(connection.conn));
    if (!ssl)
    {
      unavailable("tls_state");
      return result;
    }
    result.available = true;
    result.quicVersion = xqc_conn_get_quic_version(connection.conn);

    const unsigned char* alpn = nullptr;
    unsigned int alpnLength = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpnLength);
    if (alpn && alpnLength)
      result.alpn.assign(reinterpret_cast<const char*>(alpn), alpnLength);
    else unavailable("alpn");
    if (const char* version = SSL_get_version(ssl); version && std::strcmp(version, "unknown"))
      result.tlsVersion = version;
    else unavailable("tls_version");
    if (const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl))
      result.tlsCipherSuite = SSL_CIPHER_get_name(cipher);
    else unavailable("tls_cipher_suite");
    const int group = SSL_get_negotiated_group(ssl);
    if (group > 0)
    {
      if (const char* name = OBJ_nid2sn(group)) result.tlsKeyExchange = name;
    }
    if (result.tlsKeyExchange.empty()) unavailable("tls_key_exchange");

    X509* ownedPeer = nullptr;
    X509* certificate = nullptr;
    if (config_.role == EndpointRole::client)
    {
      ownedPeer = SSL_get_peer_certificate(ssl);
      certificate = ownedPeer;
    }
    else certificate = SSL_get_certificate(ssl);
    if (certificate)
    {
      const int signature = X509_get_signature_nid(certificate);
      if (signature == NID_ED25519) result.tlsLeafSignature = "Ed25519";
      else if (const char* name = OBJ_nid2sn(signature)) result.tlsLeafSignature = name;
      else unavailable("tls_leaf_signature");
    }
    else unavailable("tls_leaf_signature");
    X509_free(ownedPeer);

    if (config_.role == EndpointRole::client && config_.tlsVerifyPeer)
    {
      if (!connection.verificationObserved) unavailable("peer_certificate_verification");
      result.peerCertificateVerified = connection.peerCertificateVerified;
      result.hostnameVerified = connection.hostnameVerified;
    }

    const auto local = xqc_conn_get_public_local_trans_settings(connection.conn);
    const auto peer = xqc_conn_get_public_remote_trans_settings(connection.conn);
    switch (local.congestion_control)
    {
      case XQC_CONGESTION_CONTROL_CUBIC: result.congestionController = "cubic"; break;
      case XQC_CONGESTION_CONTROL_BBR: result.congestionController = "bbr"; break;
      default: unavailable("congestion_controller"); break;
    }
    result.initialCongestionWindowBytes = local.initial_congestion_window_bytes;
    result.maxUdpPayloadSize = peer.max_udp_payload_size;
    result.maxAckDelayNs = peer.max_ack_delay * 1'000'000ULL;
    result.ackDelayExponent = peer.ack_delay_exponent;
    result.ackFrequency = local.ack_frequency_extension != 0;
    result.activeMigration = peer.disable_active_migration == 0;
    result.activeConnectionIdLimit = peer.active_connection_id_limit;
    if (local.source_connection_id_length &&
        local.source_connection_id_length == local.destination_connection_id_length)
      result.connectionIdBytes = local.source_connection_id_length;
    else unavailable("connection_id_bytes");
    result.maxIdleTimeoutNs = peer.max_idle_timeout * 1'000'000ULL;
    result.maxBidiStreams = peer.max_streams_bidi;
    result.maxUniStreams = peer.max_streams_uni;
    result.streamCreditReplenishBelow = local.stream_credit_replenish_below;
    result.connectionWindowBytes = peer.max_data;
    result.streamWindowBytes = std::min(
        {peer.max_stream_data_bidi_local, peer.max_stream_data_bidi_remote,
         peer.max_stream_data_uni});
    if (peer.max_stream_data_bidi_local != result.streamWindowBytes ||
        peer.max_stream_data_bidi_remote != result.streamWindowBytes ||
        peer.max_stream_data_uni != result.streamWindowBytes)
      unavailable("peer_stream_window_inconsistent");
    result.datagramMaxFrameSize = peer.max_datagram_frame_size;

    uint64_t ticketLifetimeNs = connection.sessionTicketLifetimeNs;
    if (!ticketLifetimeNs)
    {
      if (SSL_SESSION* session = SSL_get_session(ssl))
        ticketLifetimeNs = static_cast<uint64_t>(SSL_SESSION_get_timeout(session)) *
            1'000'000'000ULL;
    }
    if (ticketLifetimeNs) result.ticketLifetimeNs = ticketLifetimeNs;
    else unavailable("ticket_lifetime_ns");
    result.maximumEarlyDataBytes = config_.tlsMaximumEarlyDataBytes;
    result.oneUseTickets = config_.tlsOneUseTickets;
    return result;
  };

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

  NegotiatedSettings result;
  bool found = false;
  for (const auto& [_, connection] : connections_)
  {
    if (!connection->conn || connection->closing || connection->closed) continue;
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

bool XquicAdapter::reset(AdapterError& error)
{
  if (engine_)
  {
    useCommonTime(monotonicRawNowNs());
    xqc_engine_destroy(std::exchange(engine_, nullptr));
  }
  sk_X509_pop_free(std::exchange(serverChain_, nullptr), X509_free);
  X509_free(std::exchange(serverCertificate_, nullptr));
  EVP_PKEY_free(std::exchange(serverKey_, nullptr));
  X509_STORE_free(std::exchange(trustStore_, nullptr));
  connectionsByPointer_.clear();
  connections_.clear();
  acceptedConnections_.clear();
  socketContinuations_.clear();
  outputQueue_.clear();
  importedState_.reset();
  consumedSessions_.clear();
  nextConnectionId_ = 1;
  nextWakeUs_ = 0;
  nextTimeoutRawNs_ = 0;
  clockAnchorRawNs_ = 0;
  clockAnchorRealtimeNs_ = 0;
  callbackRawNs_ = 0;
  if (callbackClockOwner_ == this) callbackClockOwner_ = nullptr;
  admissionRefused_ = false;
  configured_ = false;
  localAddressSet_ = false;
  counters_ = {};
  error = {};
  return true;
}

} // namespace

std::unique_ptr<Adapter> makeTransportAdapter()
{
  return std::make_unique<XquicAdapter>();
}

} // namespace quicperf
