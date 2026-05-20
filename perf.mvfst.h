#pragma once

#include <event2/event.h>
#include <fizz/backend/openssl/certificate/CertUtils.h>
#include <fizz/backend/openssl/certificate/OpenSSLCertificateVerifier.h>
#include <fizz/client/FizzClientContext.h>
#include <fizz/protocol/CertificateVerifier.h>
#include <fizz/protocol/clock/SystemClock.h>
#include <fizz/server/DefaultCertManager.h>
#include <fizz/server/FizzServerContext.h>
#include <fizz/server/TicketPolicy.h>
#include <fizz/server/TicketTypes.h>
#include <folly/FileUtil.h>
#include <folly/SocketAddress.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/EventBase.h>
#include <quic/api/QuicSocket.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/BufUtil.h>
#include <quic/common/NetworkData.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/fizz/client/handshake/QuicPskCache.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocketImpl.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/handshake/QuicFizzFactory.h>
#include <quic/server/QuicServerTransport.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

class MvfstNoVerify : public fizz::CertificateVerifier {
public:

  ~MvfstNoVerify() override = default;

  fizz::Status verify(std::shared_ptr<const fizz::Cert>& ret, fizz::Error&,
                      const std::vector<std::shared_ptr<const fizz::PeerCert>>& certs) const override
  {
    if (!certs.empty())
    {
      ret = certs.front();
    }
    return fizz::Status::Success;
  }

  fizz::Status getCertificateRequestExtensions(std::vector<fizz::Extension>&, fizz::Error&) const override
  {
    return fizz::Status::Success;
  }
};

static folly::SocketAddress mvfstSocketAddressFromSockaddr(const struct sockaddr *address)
{
  folly::SocketAddress out;
  out.setFromSockaddr(address, sizeof(struct sockaddr_in6));
  return out;
}

static std::string mvfstReadFile(const char *path)
{
  std::string out;
  if (!folly::readFile(path, out))
  {
    fprintf(stderr, "mvfst failed to read file: %s\n", path);
    abort();
  }
  return out;
}

template <Mode mode>
class MvfstNetworkSocket final : public quic::QuicAsyncUDPSocketImpl {
private:

  NetworkHub<mode> *networkHub = nullptr;
  std::shared_ptr<quic::QuicEventBase> evb;
  folly::SocketAddress localAddress;
  quic::QuicAsyncUDPSocket::ReadCallback *readCallback = nullptr;
  quic::QuicAsyncUDPSocket::WriteCallback *writeCallback = nullptr;
  MultiUDPContext *pendingWriteBatch = nullptr;
  bool readPaused = true;

  static quic::Expected<void, quic::QuicError> ok(void)
  {
    return quic::Expected<void, quic::QuicError> {};
  }

  static quic::Expected<void, quic::QuicError> unsupported(const char *what)
  {
    return quic::make_unexpected(quic::QuicError(
        quic::QuicErrorCode(quic::LocalErrorCode::INVALID_OPERATION),
        std::string(what)));
  }

  ssize_t appendPacket(MultiUDPContext *packets, const folly::SocketAddress& address,
                       const struct iovec *vec, size_t iovecLen)
  {
    size_t total = 0;
    for (size_t i = 0; i < iovecLen; ++i)
    {
      total += vec[i].iov_len;
    }
    if (total > MAX_IPV6_UDP_PACKET_SIZE)
    {
      errno = EMSGSIZE;
      return -1;
    }

    UDPContext *packet = packets->nextPacket();
    if (packet == nullptr)
    {
      errno = EAGAIN;
      return -1;
    }

    size_t offset = 0;
    for (size_t i = 0; i < iovecLen; ++i)
    {
      memcpy(packet->buffer() + offset, vec[i].iov_base, vec[i].iov_len);
      offset += vec[i].iov_len;
    }

    struct sockaddr_storage storage = {};
    address.getAddress(&storage);
    packet->setLength(total);
    packet->copyInAddress(reinterpret_cast<const struct sockaddr *>(&storage));
    return static_cast<ssize_t>(total);
  }

  MultiUDPContext *takeSendPool(void)
  {
    MultiUDPContext *packets = networkHub->sendPool.get();
    if (packets != nullptr)
    {
      return packets;
    }
    networkHub->flush();
    networkHub->drainSendCompletions();
    return networkHub->sendPool.get();
  }

  void queuePendingWriteBatch(void)
  {
    if (pendingWriteBatch == nullptr)
    {
      return;
    }
    MultiUDPContext *packets = pendingWriteBatch;
    pendingWriteBatch = nullptr;
    if (packets->count > 0)
    {
      networkHub->sendBatch(packets);
    }
    else
    {
      packets->reset();
      networkHub->sendPool.relinquish(packets);
    }
  }

public:

  MvfstNetworkSocket(NetworkHub<mode> *hub, std::shared_ptr<quic::QuicEventBase> eventBase)
      : networkHub(hub),
        evb(std::move(eventBase)),
        localAddress(mvfstSocketAddressFromSockaddr(hub->socket.address()))
  {
  }

  quic::Expected<void, quic::QuicError> init(sa_family_t) override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> bind(const folly::SocketAddress& address) override
  {
    localAddress = address;
    return ok();
  }
  bool isBound() const override
  {
    return true;
  }
  quic::Expected<void, quic::QuicError> connect(const folly::SocketAddress&) override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> close() override
  {
    return ok();
  }

  void resumeRead(quic::QuicAsyncUDPSocket::ReadCallback *callback) override
  {
    readCallback = callback;
    readPaused = false;
  }

  void pauseRead() override
  {
    readPaused = true;
  }
  bool isReadPaused() const override
  {
    return readPaused;
  }

  quic::Expected<void, quic::QuicError> resumeWrite(quic::QuicAsyncUDPSocket::WriteCallback *callback) override
  {
    writeCallback = callback;
    if (writeCallback != nullptr)
    {
      writeCallback->onSocketWritable();
    }
    return ok();
  }

  void pauseWrite() override
  {
    writeCallback = nullptr;
  }
  bool isWritableCallbackSet() const override
  {
    return writeCallback != nullptr;
  }

  ssize_t write(const folly::SocketAddress& address, const struct iovec *vec, size_t iovecLen) override
  {
    if (pendingWriteBatch == nullptr)
    {
      pendingWriteBatch = takeSendPool();
    }
    if (pendingWriteBatch == nullptr)
    {
      errno = EAGAIN;
      return -1;
    }

    ssize_t written = appendPacket(pendingWriteBatch, address, vec, iovecLen);
    if (written >= 0)
    {
      if (pendingWriteBatch->isFull())
      {
        queuePendingWriteBatch();
      }
    }
    else
    {
      pendingWriteBatch->reset();
      networkHub->sendPool.relinquish(pendingWriteBatch);
      pendingWriteBatch = nullptr;
    }
    return written;
  }

  int writem(quic::AddressRange addrs, iovec *iov,
             size_t *numIovecsInBuffer, size_t count) override
  {
    queuePendingWriteBatch();
    MultiUDPContext *packets = nullptr;
    size_t iovOffset = 0;
    int sent = 0;
    for (size_t i = 0; i < count; ++i)
    {
      if (packets == nullptr)
      {
        packets = takeSendPool();
        if (packets == nullptr)
        {
          errno = EAGAIN;
          break;
        }
      }

      if (appendPacket(packets, addrs[i], iov + iovOffset, numIovecsInBuffer[i]) < 0)
      {
        break;
      }
      iovOffset += numIovecsInBuffer[i];
      ++sent;

      if (packets->isFull())
      {
        networkHub->sendBatch(packets);
        packets = nullptr;
      }
    }

    if (packets != nullptr)
    {
      if (packets->count > 0)
      {
        networkHub->sendBatch(packets);
      }
      else
      {
        packets->reset();
        networkHub->sendPool.relinquish(packets);
      }
    }
    networkHub->flush();
    if (sent == 0)
    {
      errno = EAGAIN;
      return -1;
    }
    return sent;
  }

  void flushPendingWrites(void)
  {
    queuePendingWriteBatch();
    networkHub->flush();
  }

  ssize_t writeGSO(const folly::SocketAddress& address, const struct iovec *vec,
                   size_t iovecLen, WriteOptions options) override
  {
    if (options.gso > 0 || options.zerocopy)
    {
      errno = ENOTSUP;
      return -1;
    }
    return write(address, vec, iovecLen);
  }

  int writemGSO(quic::AddressRange, const quic::BufPtr *,
                size_t, const WriteOptions *) override
  {
    errno = ENOTSUP;
    return -1;
  }

  int writemGSO(quic::AddressRange addrs, iovec *iov,
                size_t *numIovecsInBuffer, size_t count, const WriteOptions *options) override
  {
    if (options != nullptr)
    {
      for (size_t i = 0; i < count; ++i)
      {
        if (options[i].gso > 0 || options[i].zerocopy)
        {
          errno = ENOTSUP;
          return -1;
        }
      }
    }
    return writem(addrs, iov, numIovecsInBuffer, count);
  }

  ssize_t recvmsg(struct msghdr *, int) override
  {
    errno = EAGAIN;
    return -1;
  }

  int recvmmsg(struct mmsghdr *, unsigned int, unsigned int, struct timespec *) override
  {
    errno = EAGAIN;
    return -1;
  }

  quic::Expected<int, quic::QuicError> getGSO() override
  {
    return -1;
  }
  quic::Expected<int, quic::QuicError> getGRO() override
  {
    return -1;
  }
  quic::Expected<void, quic::QuicError> setGRO(bool) override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> setRecvTos(bool) override
  {
    return ok();
  }
  quic::Expected<bool, quic::QuicError> getRecvTos() override
  {
    return false;
  }
  quic::Expected<void, quic::QuicError> setTosOrTrafficClass(uint8_t) override
  {
    return ok();
  }
  quic::Expected<folly::SocketAddress, quic::QuicError> address() const override
  {
    return localAddress;
  }
  const folly::SocketAddress& addressRef() const override
  {
    return localAddress;
  }
  void attachEventBase(std::shared_ptr<quic::QuicEventBase> eventBase) override
  {
    evb = std::move(eventBase);
  }
  void detachEventBase() override
  {
    evb.reset();
  }
  std::shared_ptr<quic::QuicEventBase> getEventBase() const override
  {
    return evb;
  }
  quic::Expected<void, quic::QuicError> setCmsgs(const folly::SocketCmsgMap&) override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> appendCmsgs(const folly::SocketCmsgMap&) override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> setAdditionalCmsgsFunc(std::function<quic::Optional<folly::SocketCmsgMap>()>&&) override
  {
    return ok();
  }
  quic::Expected<int, quic::QuicError> getTimestamping() override
  {
    return -1;
  }
  quic::Expected<void, quic::QuicError> setReuseAddr(bool) override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> setDFAndTurnOffPMTU() override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> setErrMessageCallback(ErrMessageCallback *) override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> applyOptions(const folly::SocketOptionMap&, folly::SocketOptionKey::ApplyPos) override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> setReusePort(bool) override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> setRcvBuf(int) override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> setSndBuf(int) override
  {
    return ok();
  }
  quic::Expected<void, quic::QuicError> setFD(int, FDOwnership) override
  {
    return ok();
  }
  int getFD() override
  {
    return networkHub->socket.fd;
  }
  quic::QuicAsyncUDPSocket::ReadCallback *storedReadCallback() const
  {
    return readCallback;
  }
};

class MvfstHandler final : public quic::QuicSocket::ConnectionSetupCallback,
                           public quic::QuicSocket::ConnectionCallback,
                           public quic::QuicSocket::ReadCallback,
                           public quic::QuicSocket::WriteCallback,
                           public quic::QuicSocket::DatagramCallback {
public:

  std::shared_ptr<quic::QuicSocket> socket;
  quic::StreamId stream = UINT64_MAX;
  std::vector<quic::StreamId> streams;
  bool transportReady = false;
  bool handshakeDone = false;
  bool connectionEnded = false;
  bool connectionError = false;
  bool echoDatagrams = false;
  uint64_t datagramReceived = 0;
  uint64_t datagramEchoed = 0;

  void setSocket(std::shared_ptr<quic::QuicSocket> value)
  {
    socket = std::move(value);
    auto result = socket->setDatagramCallback(this);
    if (result.hasError())
    {
      fprintf(stderr, "mvfst datagram callback setup failed\n");
      connectionError = true;
    }
  }

  void onConnectionSetupError(quic::QuicError error) noexcept override
  {
    fprintf(stderr, "mvfst setup error: %s\n", error.message.c_str());
    connectionError = true;
  }

  void onTransportReady() noexcept override
  {
    transportReady = true;
  }
  void onReplaySafe() noexcept override
  {
    handshakeDone = true;
  }
  void onFullHandshakeDone() noexcept override
  {
    handshakeDone = true;
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override
  {
    if (stream == UINT64_MAX)
    {
      stream = id;
    }
    streams.push_back(id);
    if (socket)
    {
      socket->setReadCallback(id, this);
    }
  }

  void onNewUnidirectionalStream(quic::StreamId) noexcept override {}
  void onStopSending(quic::StreamId, quic::ApplicationErrorCode) noexcept override {}
  void onConnectionEnd() noexcept override
  {
    connectionEnded = true;
  }
  void onConnectionEnd(quic::QuicError) noexcept override
  {
    connectionEnded = true;
  }
  void onConnectionError(quic::QuicError error) noexcept override
  {
    if (error.message.find("No Error") != std::string::npos)
    {
      connectionEnded = true;
      return;
    }
    if (benchmarkScenario == BenchmarkScenario::datagram &&
        datagramReceived >= benchmarkScenarioOperations)
    {
      connectionEnded = true;
      return;
    }
    fprintf(stderr, "mvfst connection error: %s\n", error.message.c_str());
    connectionError = true;
  }

  void readAvailable(quic::StreamId) noexcept override {}
  void readError(quic::StreamId, quic::QuicError error) noexcept override
  {
    if (error.message.find("No Error") != std::string::npos)
    {
      connectionEnded = true;
      return;
    }
    fprintf(stderr, "mvfst read error: %s\n", error.message.c_str());
    connectionError = true;
  }

  void onDatagramsAvailable() noexcept override
  {
    if (!socket)
    {
      return;
    }
    auto result = socket->readDatagrams();
    if (result.hasError())
    {
      fprintf(stderr, "mvfst datagram read failed\n");
      connectionError = true;
      return;
    }
    for (const auto& datagram : *result)
    {
      ++datagramReceived;
      if (!echoDatagrams)
      {
        continue;
      }
      auto chain = datagram.bufQueue().front()->cloneCoalesced();
      auto writeResult = socket->writeDatagram(std::move(chain));
      if (writeResult.hasError())
      {
        fprintf(stderr, "mvfst datagram echo failed\n");
        connectionError = true;
        return;
      }
      ++datagramEchoed;
    }
  }
};

class MvfstEarlyDataAppParams final : public quic::EarlyDataAppParamsHandler {
public:

  bool validate(const quic::Optional<std::string>&, const quic::BufPtr&) override
  {
    return true;
  }

  quic::BufPtr get() override
  {
    return folly::IOBuf::copyBuffer("quicperf");
  }
};

static std::shared_ptr<quic::BasicQuicPskCache> mvfstBenchmarkPskCache(void)
{
  static std::shared_ptr<quic::BasicQuicPskCache> cache =
      std::make_shared<quic::BasicQuicPskCache>();
  return cache;
}

static folly::ByteRange mvfstBenchmarkTicketSecret(void)
{
  static const std::array<uint8_t, 32> secret = {
      0x6d, 0x76, 0x66, 0x73, 0x74, 0x2d, 0x71, 0x75,
      0x69, 0x63, 0x70, 0x65, 0x72, 0x66, 0x2d, 0x74,
      0x69, 0x63, 0x6b, 0x65, 0x74, 0x2d, 0x73, 0x65,
      0x63, 0x72, 0x65, 0x74, 0x2d, 0x30, 0x31, 0x21};
  return folly::ByteRange(secret.data(), secret.size());
}

template <Mode mode>
class Mvfst : public QuicLibrary<mode> {
private:

  using QuicLibrary<mode>::networkHub;

  folly::EventBase eventBase;
  std::shared_ptr<quic::FollyQuicEventBase> quicEventBase;
  std::shared_ptr<quic::QuicClientTransport> client;
  std::unique_ptr<MvfstHandler> clientHandler;
  std::shared_ptr<fizz::server::FizzServerContext> serverContext;
  std::shared_ptr<quic::FizzClientQuicHandshakeContext> clientContext;
  MvfstEarlyDataAppParams earlyDataAppParams;
  MvfstNetworkSocket<mode> *clientNetworkSocket = nullptr;
  quic::StreamId stream = UINT64_MAX;
  alignas(64) std::array<uint8_t, benchmarkAppChunkSize> buffer = {};
  bool importedResumption = false;
  bool importedZeroRtt = false;
  bool resumedObserved = false;
  bool zeroRttAttemptedObserved = false;
  bool zeroRttAcceptedObserved = false;
  bool zeroRttRejectedObserved = false;

  enum class ServerPhase : uint8_t {
    readRequest,
    transfer,
    readDone,
    sendAck,
    finish,
    complete
  };

  struct GenericServerStream {
    quic::StreamId stream = UINT64_MAX;
    ServerPhase phase = ServerPhase::readRequest;
    std::array<uint8_t, sizeof(uint64_t)> request = {};
    size_t requestRead = 0;
    uint64_t requestValue = 0;
    uint64_t requestRemaining = 0;
    uint64_t payloadRemaining = 0;
    uint64_t responseRemaining = 0;
    uint8_t done = 0;
    size_t doneRead = 0;
    uint8_t ack = 0;
    size_t ackSent = 0;
    bool complete = false;
  };

  struct ServerConn {
    folly::SocketAddress peer;
    std::unique_ptr<MvfstHandler> handler;
    MvfstNetworkSocket<mode> *networkSocket = nullptr;
    std::unique_ptr<quic::DefaultConnectionIdAlgo> connIdAlgo;
    std::shared_ptr<quic::QuicServerTransport> transport;
    std::vector<GenericServerStream> genericStreams;
    ServerPhase phase = ServerPhase::readRequest;
    std::array<uint8_t, sizeof(uint64_t)> request = {};
    size_t requestRead = 0;
    uint64_t bytesRemaining = 0;
    uint8_t done = 0;
    size_t doneRead = 0;
    uint8_t ack = 0;
    size_t ackSent = 0;
    bool complete = false;
    uint64_t datagramDrainDeadlineUs = 0;
  };

  struct GenericClientStream {
    quic::StreamId stream = UINT64_MAX;
    ServerPhase phase = ServerPhase::readRequest;
    std::array<uint8_t, sizeof(uint64_t)> request = {};
    size_t requestSent = 0;
    uint64_t requestValue = 0;
    uint64_t payloadBytes = 0;
    uint64_t responseBytes = 0;
    uint8_t done = 0;
    size_t doneSent = 0;
    uint8_t ack = 0;
    size_t ackRead = 0;
    bool finished = false;
    bool complete = false;
  };

  std::vector<std::unique_ptr<ServerConn>> serverConns;
  std::unordered_map<std::string, ServerConn *> serverConnsByPeer;
  std::vector<GenericClientStream> genericClientStreams;
  uint64_t genericClientBytes = 0;
  uint64_t genericOpenedStreams = 0;
  uint64_t genericCompletedStreams = 0;
  bool genericStarted = false;

  static void encodeU64(uint64_t value, uint8_t out[8])
  {
    for (int i = 7; i >= 0; --i)
    {
      out[i] = static_cast<uint8_t>(value & 0xff);
      value >>= 8;
    }
  }

  static uint64_t decodeU64(const uint8_t in[8])
  {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i)
    {
      value = (value << 8) | in[i];
    }
    return value;
  }

  quic::TransportSettings transportSettings(void) const
  {
    quic::TransportSettings settings;
    settings.advertisedInitialConnectionFlowControlWindow = benchmarkConnectionWindow;
    settings.advertisedInitialBidiLocalStreamFlowControlWindow = benchmarkStreamWindow;
    settings.advertisedInitialBidiRemoteStreamFlowControlWindow = benchmarkStreamWindow;
    settings.advertisedInitialUniStreamFlowControlWindow = benchmarkStreamWindow;
    settings.advertisedInitialMaxStreamsBidi = benchmarkMaxBidiStreams;
    settings.advertisedInitialMaxStreamsUni = benchmarkMaxUniStreams;
    settings.idleTimeout = std::chrono::milliseconds(benchmarkIdleTimeoutMs);
    settings.defaultCongestionController = benchmarkCongestionProfileUsesCubic()
                                               ? quic::CongestionControlType::Cubic
                                               : quic::CongestionControlType::BBR;
    if (importedZeroRtt)
    {
      settings.attemptEarlyData = true;
    }
    settings.zeroRttSourceTokenMatchingPolicy =
        quic::ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
    settings.pacingEnabled = true;
    settings.pacingEnabledFirstFlight = true;
    settings.maxRecvPacketSize = benchmarkUdpPayloadSize;
    settings.canIgnorePathMTU = true;
    settings.maxBatchSize = benchmarkUdpBatchSize;
    settings.writeConnectionDataPacketsLimit = benchmarkUdpBatchSize;
    settings.datagramConfig.enabled = true;
    settings.datagramConfig.readBufSize = benchmarkDatagramQueueSlots;
    settings.datagramConfig.writeBufSize = benchmarkDatagramQueueSlots;
    std::array<uint8_t, quic::kStatelessResetTokenSecretLength> resetSecret = {};
    for (size_t i = 0; i < resetSecret.size(); ++i)
    {
      resetSecret[i] = static_cast<uint8_t>(0xa5 ^ i);
    }
    settings.statelessResetTokenSecret = resetSecret;
    if (benchmarkCongestionProfileIsAggressive())
    {
      settings.initCwndInMss = benchmarkAggressiveInitialCwndPackets;
    }
    return settings;
  }

  void driveEvents(void)
  {
    flushPendingSocketWrites();
    for (int i = 0; i < 4; ++i)
    {
      eventBase.loopOnce(EVLOOP_NONBLOCK);
    }
    flushPendingSocketWrites();
    networkHub->flush();
    networkHub->drainSendCompletions();
    failOnClientConnectionError("driveEvents");
  }

  void flushPendingSocketWrites(void)
  {
    if (clientNetworkSocket != nullptr)
    {
      clientNetworkSocket->flushPendingWrites();
    }
    for (auto& owned : serverConns)
    {
      if (owned->networkSocket != nullptr)
      {
        owned->networkSocket->flushPendingWrites();
      }
    }
  }

  void failOnClientConnectionError(const char *where) const
  {
    if constexpr (mode & Mode::client)
    {
      if (clientHandler && clientHandler->connectionError)
      {
        fprintf(stderr, "mvfst fatal client connection error while %s\n", where);
        abort();
      }
    }
  }

  quic::NetworkData networkDataFromPacket(UDPContext *msg)
  {
    auto packetBuffer = folly::IOBuf::copyBuffer(msg->buffer(), msg->msg_len);
    quic::ReceivedUdpPacket packet(std::move(packetBuffer));
    packet.timings.receiveTimePoint = quic::Clock::now();
    return quic::NetworkData(std::move(packet));
  }

  std::shared_ptr<fizz::server::FizzServerContext> makeServerContext(void)
  {
    std::unique_ptr<fizz::SelfCert> cert;
    fizz::Error certError;
    if (fizz::openssl::CertUtils::makeSelfCert(cert, certError, mvfstReadFile(tls_cert), mvfstReadFile(tls_key)) == fizz::Status::Fail)
    {
      fprintf(stderr, "mvfst failed to create self cert: %s\n", certError.msg() != nullptr ? certError.msg() : "unknown");
      abort();
    }
    auto certManager = std::make_unique<fizz::server::DefaultCertManager>();
    certManager->addCertAndSetDefault(std::shared_ptr<fizz::SelfCert>(std::move(cert)));

    auto context = std::make_shared<fizz::server::FizzServerContext>();
    context->setFactory(std::make_shared<quic::QuicFizzFactory>());
    context->setCertManager(std::move(certManager));
    auto ticketCipher = std::make_shared<fizz::server::AES128TicketCipher>(
        context->getFactoryPtr(),
        std::make_shared<fizz::server::DefaultCertManager>());
    ticketCipher->setTicketSecrets({mvfstBenchmarkTicketSecret()});
    fizz::server::TicketPolicy ticketPolicy;
    ticketPolicy.setTicketValidity(std::chrono::hours(1));
    ticketPolicy.setHandshakeValidity(std::chrono::hours(1));
    ticketCipher->setPolicy(std::move(ticketPolicy));
    context->setTicketCipher(std::move(ticketCipher));
    context->setOmitEarlyRecordLayer(true);
    context->setClock(std::make_shared<fizz::SystemClock>());
    context->setEarlyDataSettings(
        true,
        fizz::server::ClockSkewTolerance {
            .before = std::chrono::milliseconds(-1000),
            .after = std::chrono::milliseconds(1000)},
        std::make_shared<fizz::server::AllowAllReplayReplayCache>());
    context->setSupportedSigSchemes({fizz::SignatureScheme::ed25519,
                                     fizz::SignatureScheme::ecdsa_secp256r1_sha256,
                                     fizz::SignatureScheme::rsa_pss_sha256});
    context->setSupportedAlpns({"perf"});
    return context;
  }

  std::shared_ptr<quic::FizzClientQuicHandshakeContext> makeClientContext(void)
  {
    auto fizzClientContext = std::make_shared<fizz::client::FizzClientContext>();
    fizzClientContext->setClock(std::make_shared<fizz::SystemClock>());
    fizzClientContext->setSendEarlyData(true);
    fizzClientContext->setSupportedAlpns({"perf"});
    fizzClientContext->setSupportedSigSchemes({fizz::SignatureScheme::ed25519,
                                               fizz::SignatureScheme::ecdsa_secp256r1_sha256,
                                               fizz::SignatureScheme::rsa_pss_sha256});
    fizzClientContext->setSupportedGroups({fizz::NamedGroup::x25519, fizz::NamedGroup::secp256r1});
    fizzClientContext->setDefaultShares({fizz::NamedGroup::x25519});

    std::shared_ptr<fizz::CertificateVerifier> verifier =
        benchmarkTlsVerifyPeer()
            ? std::shared_ptr<fizz::CertificateVerifier>(
                  fizz::openssl::OpenSSLCertificateVerifier::createFromCAFile(
                      fizz::VerificationContext::Client, tls_chain)
                      .release())
            : std::shared_ptr<fizz::CertificateVerifier>(std::make_shared<MvfstNoVerify>());

    return quic::FizzClientQuicHandshakeContext::Builder()
        .setFizzClientContext(std::move(fizzClientContext))
        .setCertificateVerifier(std::move(verifier))
        .setPskCache(mvfstBenchmarkPskCache())
        .build();
  }

  void updateZeroRttState(void)
  {
    if constexpr (mode & Mode::client)
    {
      if (!client)
      {
        return;
      }
      if (importedResumption && clientHandler && clientHandler->handshakeDone)
      {
        resumedObserved = client->isTLSResumed();
      }
      switch (client->getZeroRttState())
      {
        case quic::QuicClientTransportLite::ZeroRttAttemptState::Accepted:
          zeroRttAttemptedObserved = true;
          zeroRttAcceptedObserved = true;
          zeroRttRejectedObserved = false;
          break;
        case quic::QuicClientTransportLite::ZeroRttAttemptState::Rejected:
          zeroRttAttemptedObserved = true;
          zeroRttRejectedObserved = true;
          break;
        case quic::QuicClientTransportLite::ZeroRttAttemptState::NotAttempted:
          break;
      }
    }
  }

  ServerConn& serverConnFor(UDPContext *msg)
  {
    std::string key = benchmarkPeerKey(msg->address());
    auto found = serverConnsByPeer.find(key);
    if (found != serverConnsByPeer.end())
    {
      return *found->second;
    }

    auto owned = std::make_unique<ServerConn>();
    owned->peer = mvfstSocketAddressFromSockaddr(msg->address());
    owned->handler = std::make_unique<MvfstHandler>();
    owned->handler->echoDatagrams = benchmarkScenario == BenchmarkScenario::datagram;
    owned->connIdAlgo = std::make_unique<quic::DefaultConnectionIdAlgo>();

    auto socket = std::make_unique<MvfstNetworkSocket<mode>>(networkHub, quicEventBase);
    owned->networkSocket = socket.get();
    owned->transport = std::make_shared<quic::QuicServerTransport>(
        quicEventBase,
        std::move(socket),
        owned->handler.get(),
        owned->handler.get(),
        serverContext);
    owned->handler->setSocket(owned->transport);
    owned->transport->setConnectionIdAlgo(owned->connIdAlgo.get());
    owned->transport->setServerConnectionIdParams(quic::ServerConnectionIdParams(1, 1, 0));
    owned->transport->setTransportSettings(transportSettings());
    owned->transport->setClientConnectionId(quic::ConnectionId::createZeroLength());
    owned->transport->setOriginalPeerAddress(owned->peer);
    owned->transport->accept();

    ServerConn *raw = owned.get();
    serverConns.push_back(std::move(owned));
    serverConnsByPeer.emplace(std::move(key), raw);
    return *raw;
  }

  void deliverPacket(UDPContext *msg)
  {
    auto peer = mvfstSocketAddressFromSockaddr(msg->address());
    if constexpr (mode & Mode::server)
    {
      ServerConn& active = serverConnFor(msg);
      active.transport->onNetworkData(active.transport->getLocalAddress(), networkDataFromPacket(msg), peer);
    }
    else
    {
      if (client)
      {
        client->onNetworkData(client->getLocalAddress(), networkDataFromPacket(msg), peer);
      }
    }
  }

  void pumpOnce(uint64_t waitUs = 1000)
  {
    driveEvents();
    networkHub->recvmsgWithTimeout(static_cast<int64_t>(waitUs), [&](UDPContext *msg) -> void {
      deliverPacket(msg);
    });
    driveEvents();
  }

  std::pair<size_t, bool> readSome(std::shared_ptr<quic::QuicSocket>& socket, quic::StreamId activeStream,
                                   uint8_t *data, size_t length)
  {
    auto result = socket->read(activeStream, length);
    if (result.hasError())
    {
      fprintf(stderr, "mvfst stream read failed\n");
      abort();
    }
    bool fin = result->second;
    if (!result->first)
    {
      return {0, fin};
    }
    auto bytes = result->first->coalesce();
    if (bytes.size() > length)
    {
      fprintf(stderr, "mvfst read exceeded caller buffer\n");
      abort();
    }
    memcpy(data, bytes.data(), bytes.size());
    return {bytes.size(), fin};
  }

  size_t writeSome(std::shared_ptr<quic::QuicSocket>& socket, quic::StreamId activeStream,
                   const uint8_t *data, size_t length)
  {
    auto writable = socket->getMaxWritableOnStream(activeStream);
    if (writable.hasError())
    {
      fprintf(stderr, "mvfst stream writable query failed\n");
      abort();
    }
    if (*writable == 0)
    {
      return 0;
    }
    size_t chunk = static_cast<size_t>(std::min<uint64_t>(length, *writable));
    auto result = socket->writeChain(activeStream, folly::IOBuf::copyBuffer(data, chunk), false);
    if (result.hasError())
    {
      fprintf(stderr, "mvfst stream write failed\n");
      abort();
    }
    driveEvents();
    return chunk;
  }

  void finishStream(std::shared_ptr<quic::QuicSocket>& socket, quic::StreamId activeStream)
  {
    socket->writeChain(activeStream, folly::IOBuf::create(0), true);
    driveEvents();
  }

  void sendAll(std::shared_ptr<quic::QuicSocket>& socket, quic::StreamId activeStream,
               const uint8_t *data, size_t length)
  {
    size_t offset = 0;
    while (offset < length)
    {
      size_t written = writeSome(socket, activeStream, data + offset, length - offset);
      if (written == 0)
      {
        pumpOnce();
      }
      else
      {
        offset += written;
      }
    }
  }

  void recvExact(std::shared_ptr<quic::QuicSocket>& socket, quic::StreamId activeStream,
                 uint8_t *data, size_t length)
  {
    size_t offset = 0;
    while (offset < length)
    {
      auto [read, fin] = readSome(socket, activeStream, data + offset, length - offset);
      if (read == 0)
      {
        if (fin)
        {
          fprintf(stderr, "mvfst stream ended before expected bytes\n");
          abort();
        }
        pumpOnce();
      }
      else
      {
        offset += read;
      }
    }
  }

  void sendBytes(std::shared_ptr<quic::QuicSocket>& socket, quic::StreamId activeStream, uint64_t bytes)
  {
    while (bytes > 0)
    {
      size_t chunk = static_cast<size_t>(std::min<uint64_t>(bytes, buffer.size()));
      sendAll(socket, activeStream, buffer.data(), chunk);
      bytes -= chunk;
    }
  }

  void recvBytes(std::shared_ptr<quic::QuicSocket>& socket, quic::StreamId activeStream, uint64_t bytes)
  {
    while (bytes > 0)
    {
      size_t chunk = static_cast<size_t>(std::min<uint64_t>(bytes, buffer.size()));
      recvExact(socket, activeStream, buffer.data(), chunk);
      bytes -= chunk;
    }
  }

  static bool genericUsesSizedRequest(void)
  {
    return benchmarkScenarioIsSmallGenericStreamWorkload(benchmarkScenario);
  }

  uint64_t genericTransferBytesForStream(uint64_t index, uint64_t totalBytes) const
  {
    const uint64_t count = std::max<uint64_t>(1, benchmarkGenericStreamsPerConnection());
    const uint64_t base = totalBytes / count;
    if (index + 1 == count)
    {
      return totalBytes - (base * (count - 1));
    }
    return std::max<uint64_t>(1, base);
  }

  GenericClientStream makeGenericClientStream(quic::StreamId activeStream, uint64_t index, uint64_t totalBytes)
  {
    GenericClientStream state = {};
    state.stream = activeStream;
    if (genericUsesSizedRequest())
    {
      state.requestValue = benchmarkGenericReqRespRequestBytes();
      state.responseBytes = benchmarkGenericReqRespResponseBytes();
    }
    else
    {
      const uint64_t streamBytes = genericTransferBytesForStream(index, totalBytes);
      encodeU64(streamBytes, state.request.data());
      state.requestValue = state.request.size();
      state.payloadBytes = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
                            benchmarkScenario == BenchmarkScenario::bidi)
                               ? streamBytes
                               : 0;
      state.responseBytes = benchmarkScenario == BenchmarkScenario::multistream_upload ? 1 : streamBytes;
    }
    return state;
  }

  GenericServerStream *serverGenericStreamFor(ServerConn& active, quic::StreamId activeStream)
  {
    for (auto& streamState : active.genericStreams)
    {
      if (streamState.stream == activeStream)
      {
        return &streamState;
      }
    }
    active.genericStreams.push_back(GenericServerStream {.stream = activeStream});
    return &active.genericStreams.back();
  }

  void discoverGenericServerStreams(ServerConn& active)
  {
    for (quic::StreamId activeStream : active.handler->streams)
    {
      (void)serverGenericStreamFor(active, activeStream);
    }
  }

  bool processGenericServerStream(ServerConn& active, GenericServerStream& streamState)
  {
    if (streamState.complete)
    {
      return false;
    }

    std::shared_ptr<quic::QuicSocket> socket = active.transport;
    switch (streamState.phase)
    {
      case ServerPhase::readRequest:
        {
          if (genericUsesSizedRequest())
          {
            if (streamState.requestRemaining == 0)
            {
              streamState.requestRemaining = benchmarkGenericReqRespRequestBytes();
            }
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(streamState.requestRemaining, buffer.size()));
            auto [read, fin] = readSome(socket, streamState.stream, buffer.data(), chunk);
            (void)fin;
            streamState.requestRemaining -= read;
            if (streamState.requestRemaining == 0)
            {
              streamState.responseRemaining = benchmarkGenericReqRespResponseBytes();
              streamState.phase = ServerPhase::transfer;
            }
            return read > 0;
          }

          auto [read, fin] = readSome(socket, streamState.stream,
                                      streamState.request.data() + streamState.requestRead,
                                      streamState.request.size() - streamState.requestRead);
          (void)fin;
          streamState.requestRead += read;
          if (streamState.requestRead == streamState.request.size())
          {
            streamState.requestValue = decodeU64(streamState.request.data());
            streamState.payloadRemaining = (benchmarkScenario == BenchmarkScenario::multistream_upload ||
                                            benchmarkScenario == BenchmarkScenario::bidi)
                                               ? streamState.requestValue
                                               : 0;
            streamState.responseRemaining = benchmarkScenario == BenchmarkScenario::multistream_upload
                                                ? 1
                                                : streamState.requestValue;
            streamState.phase = ServerPhase::transfer;
          }
          return read > 0;
        }
      case ServerPhase::transfer:
        {
          bool progressed = false;
          if (streamState.payloadRemaining > 0)
          {
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(streamState.payloadRemaining, buffer.size()));
            auto [read, fin] = readSome(socket, streamState.stream, buffer.data(), chunk);
            (void)fin;
            streamState.payloadRemaining -= read;
            progressed = read > 0;
          }
          if (streamState.responseRemaining > 0)
          {
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(streamState.responseRemaining, buffer.size()));
            size_t written = writeSome(socket, streamState.stream, buffer.data(), chunk);
            streamState.responseRemaining -= written;
            progressed = written > 0 || progressed;
          }
          if (streamState.payloadRemaining == 0 && streamState.responseRemaining == 0)
          {
            streamState.phase = ServerPhase::readDone;
            return true;
          }
          return progressed;
        }
      case ServerPhase::readDone:
        {
          auto [read, fin] = readSome(socket, streamState.stream,
                                      &streamState.done + streamState.doneRead,
                                      sizeof(streamState.done) - streamState.doneRead);
          (void)fin;
          streamState.doneRead += read;
          if (streamState.doneRead == sizeof(streamState.done))
          {
            streamState.phase = ServerPhase::sendAck;
          }
          return read > 0;
        }
      case ServerPhase::sendAck:
        {
          size_t written = writeSome(socket, streamState.stream,
                                     &streamState.ack + streamState.ackSent,
                                     sizeof(streamState.ack) - streamState.ackSent);
          streamState.ackSent += written;
          if (streamState.ackSent == sizeof(streamState.ack))
          {
            streamState.phase = ServerPhase::finish;
          }
          return written > 0;
        }
      case ServerPhase::finish:
        {
          finishStream(socket, streamState.stream);
          streamState.phase = ServerPhase::complete;
          streamState.complete = true;
          return true;
        }
      case ServerPhase::complete:
        return false;
    }
    return false;
  }

  bool processGenericServer(ServerConn& active)
  {
    discoverGenericServerStreams(active);
    bool progressed = false;
    for (auto& streamState : active.genericStreams)
    {
      progressed = processGenericServerStream(active, streamState) || progressed;
    }
    return progressed;
  }

  void waitForTargetServerConnections(void)
  {
    while (serverConns.size() < benchmarkServerTargetConnections)
    {
      pumpOnce();
    }
  }

  void waitForPrimaryServerStreams(void)
  {
    waitForTargetServerConnections();
    for (;;)
    {
      bool allReady = true;
      for (auto& owned : serverConns)
      {
        if (owned->handler->stream == UINT64_MAX)
        {
          allReady = false;
          break;
        }
      }
      if (allReady)
      {
        return;
      }
      pumpOnce();
    }
  }

  void runServerGenericConnections(void)
  {
    const uint64_t targetStreams =
        static_cast<uint64_t>(benchmarkServerTargetConnections) * benchmarkGenericStreamsPerConnection();
    uint64_t completed = 0;
    while (completed < targetStreams)
    {
      bool progressed = false;
      completed = 0;
      for (auto& owned : serverConns)
      {
        bool connProgressed = processGenericServer(*owned);
        progressed = connProgressed || progressed;
        for (const auto& streamState : owned->genericStreams)
        {
          if (streamState.complete)
          {
            ++completed;
          }
        }
        pumpOnce(0);
      }
      if (!progressed)
      {
        pumpOnce();
      }
      else
      {
        pumpOnce(0);
      }
    }
    for (;;)
    {
      bool allClosed = true;
      for (auto& owned : serverConns)
      {
        if (!owned->handler->connectionEnded && !owned->handler->connectionError)
        {
          allClosed = false;
          break;
        }
      }
      if (allClosed)
      {
        break;
      }
      pumpOnce();
    }
  }

  void runServerIdleConnections(void)
  {
    while (serverConns.size() < benchmarkServerTargetConnections)
    {
      pumpOnce();
    }
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(benchmarkIdleHoldMs);
    while (std::chrono::steady_clock::now() < deadline)
    {
      pumpOnce();
    }
    for (auto& owned : serverConns)
    {
      owned->transport->closeNow(quic::Optional<quic::QuicError> {});
    }
    for (uint32_t i = 0; i < 256; ++i)
    {
      pumpOnce(1000);
    }
  }

  void runClientIdleCleanup(void)
  {
    client->closeNow(quic::Optional<quic::QuicError> {});
    for (uint32_t i = 0; i < 256; ++i)
    {
      pumpOnce(1000);
      if ((clientHandler->connectionEnded || clientHandler->connectionError) && i >= 8)
      {
        break;
      }
    }
  }

  bool processGenericClientStream(GenericClientStream& streamState)
  {
    if (streamState.complete)
    {
      return false;
    }

    std::shared_ptr<quic::QuicSocket> socket = client;
    switch (streamState.phase)
    {
      case ServerPhase::readRequest:
        {
          const uint64_t requestBytes = streamState.requestValue;
          if (streamState.requestSent < requestBytes)
          {
            size_t remaining = static_cast<size_t>(std::min<uint64_t>(
                requestBytes - streamState.requestSent, buffer.size()));
            const uint8_t *data = genericUsesSizedRequest()
                                      ? buffer.data()
                                      : streamState.request.data() + streamState.requestSent;
            size_t written = writeSome(socket, streamState.stream, data, remaining);
            streamState.requestSent += written;
            if (written == 0)
            {
              return false;
            }
          }
          if (streamState.requestSent == requestBytes)
          {
            streamState.phase = ServerPhase::transfer;
          }
          return true;
        }
      case ServerPhase::transfer:
        {
          bool progressed = false;
          if (streamState.payloadBytes > 0)
          {
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(streamState.payloadBytes, buffer.size()));
            size_t written = writeSome(socket, streamState.stream, buffer.data(), chunk);
            streamState.payloadBytes -= written;
            progressed = written > 0;
          }
          if (streamState.responseBytes > 0)
          {
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(streamState.responseBytes, buffer.size()));
            auto [read, fin] = readSome(socket, streamState.stream, buffer.data(), chunk);
            (void)fin;
            streamState.responseBytes -= read;
            progressed = read > 0 || progressed;
          }
          if (streamState.payloadBytes == 0 && streamState.responseBytes == 0)
          {
            streamState.phase = ServerPhase::readDone;
            return true;
          }
          return progressed;
        }
      case ServerPhase::readDone:
        {
          size_t written = writeSome(socket, streamState.stream,
                                     &streamState.done + streamState.doneSent,
                                     sizeof(streamState.done) - streamState.doneSent);
          streamState.doneSent += written;
          if (streamState.doneSent == sizeof(streamState.done))
          {
            finishStream(socket, streamState.stream);
            streamState.finished = true;
            streamState.phase = ServerPhase::sendAck;
          }
          return written > 0;
        }
      case ServerPhase::sendAck:
        {
          auto [read, fin] = readSome(socket, streamState.stream,
                                      &streamState.ack + streamState.ackRead,
                                      sizeof(streamState.ack) - streamState.ackRead);
          (void)fin;
          streamState.ackRead += read;
          if (streamState.ackRead == sizeof(streamState.ack))
          {
            streamState.phase = ServerPhase::complete;
            streamState.complete = true;
          }
          return read > 0;
        }
      case ServerPhase::finish:
        return false;
      case ServerPhase::complete:
        return false;
    }
    return false;
  }

  void openMoreGenericClientStreams(uint64_t bytes)
  {
    std::shared_ptr<quic::QuicSocket> socket = client;
    const uint64_t targetStreams = benchmarkGenericStreamsPerConnection();
    const uint64_t maxActive = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
    while (genericOpenedStreams < targetStreams && genericClientStreams.size() < maxActive)
    {
      auto result = socket->createBidirectionalStream();
      if (result.hasError())
      {
        break;
      }
      client->setReadCallback(*result, clientHandler.get());
      genericClientStreams.push_back(makeGenericClientStream(*result, genericOpenedStreams, bytes));
      ++genericOpenedStreams;
    }
  }

  bool processGenericClientStreams(void)
  {
    bool progressed = false;
    for (auto& streamState : genericClientStreams)
    {
      if (!streamState.complete)
      {
        progressed = processGenericClientStream(streamState) || progressed;
      }
    }
    genericClientStreams.erase(std::remove_if(genericClientStreams.begin(), genericClientStreams.end(),
                                              [&](const GenericClientStream& streamState) {
                                                if (streamState.complete)
                                                {
                                                  ++genericCompletedStreams;
                                                  return true;
                                                }
                                                return false;
                                              }),
                               genericClientStreams.end());
    return progressed;
  }

  void resetGenericClientStreams(void)
  {
    genericClientStreams.clear();
    genericClientBytes = 0;
    genericOpenedStreams = 0;
    genericCompletedStreams = 0;
    genericStarted = false;
  }

  void runClientGeneric(uint64_t bytes)
  {
    genericClientBytes = bytes;
    if (!genericStarted)
    {
      resetGenericClientStreams();
      genericClientBytes = bytes;
      genericStarted = true;
    }
    const uint64_t targetStreams = benchmarkGenericStreamsPerConnection();
    while (genericCompletedStreams < targetStreams)
    {
      openMoreGenericClientStreams(genericClientBytes);
      bool progressed = processGenericClientStreams();
      if (!progressed)
      {
        pumpOnce();
      }
      else
      {
        pumpOnce(0);
      }
    }
    updateZeroRttState();
  }

  size_t datagramPayloadSize(void) const
  {
    return std::min<size_t>(benchmarkScenarioMessageBytes, buffer.size());
  }

  uint64_t datagramMaxAttempts(void) const
  {
    const uint64_t maxInFlight = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
    return benchmarkScenarioOperations +
           (std::max<uint64_t>(benchmarkScenarioOperations, maxInFlight) * 64ULL);
  }

  void runClientDatagram(void)
  {
    const uint64_t operations = benchmarkScenarioOperations;
    const uint64_t maxInFlight = std::max<uint32_t>(1, benchmarkScenarioStreamsInFlight);
    const uint64_t maxAttempts = datagramMaxAttempts();
    const size_t payloadSize = datagramPayloadSize();
    uint64_t sent = 0;
    uint64_t drainDeadlineUs = 0;
    while (clientHandler->datagramReceived < operations ||
           drainDeadlineUs == 0 ||
           timeNowUs() < drainDeadlineUs)
    {
      bool progressed = false;
      while (clientHandler->datagramReceived < operations &&
             sent < maxAttempts &&
             sent - clientHandler->datagramReceived < maxInFlight)
      {
        auto result = client->writeDatagram(
            folly::IOBuf::copyBuffer(buffer.data(), payloadSize));
        if (result.hasError())
        {
          break;
        }
        ++sent;
        progressed = true;
      }
      if (sent >= maxAttempts && clientHandler->datagramReceived < operations)
      {
        fprintf(stderr, "mvfst datagram delivery target not reached received=%" PRIu64 " sent=%" PRIu64 " target=%" PRIu64 "\n",
                clientHandler->datagramReceived, sent, operations);
        abort();
      }
      if (clientHandler->datagramReceived >= operations && drainDeadlineUs == 0)
      {
        drainDeadlineUs = timeNowUs() + 100'000;
      }
      const uint64_t nowUs = timeNowUs();
      const uint64_t waitUs = drainDeadlineUs != 0 && nowUs < drainDeadlineUs
                                  ? std::min<uint64_t>(1000, drainDeadlineUs - nowUs)
                                  : 1000;
      pumpOnce(progressed ? 0 : waitUs);
    }
    benchmarkRecordDatagramClientCounters(sent, clientHandler->datagramReceived);
  }

  void startClientConnection(struct sockaddr *address)
  {
    auto socket = std::make_unique<MvfstNetworkSocket<mode>>(networkHub, quicEventBase);
    clientNetworkSocket = socket.get();
    clientHandler = std::make_unique<MvfstHandler>();
    client = quic::QuicClientTransport::newClient(
        quicEventBase,
        std::move(socket),
        clientContext,
        0);
    clientHandler->setSocket(client);
    client->setHostname("localhost");
    client->addNewPeerAddress(mvfstSocketAddressFromSockaddr(address));
    client->setTransportSettings(transportSettings());
    client->setEarlyDataAppParamsHandler(&earlyDataAppParams);
    client->start(clientHandler.get(), clientHandler.get());
    zeroRttAttemptedObserved = importedResumption && client->hasZeroRttWriteCipher();
  }

  void waitForClientHandshake(void)
  {
    while (!clientHandler->handshakeDone && !clientHandler->connectionError)
    {
      pumpOnce();
    }
    updateZeroRttState();
    if (clientHandler->connectionError)
    {
      abort();
    }
  }

  void runServerDatagramConnections(void)
  {
    waitForTargetServerConnections();
    uint32_t completed = 0;
    while (completed < benchmarkServerTargetConnections)
    {
      completed = 0;
      const uint64_t nowUs = timeNowUs();
      for (auto& owned : serverConns)
      {
        if (owned->handler->datagramEchoed >= benchmarkScenarioOperations)
        {
          if (owned->datagramDrainDeadlineUs == 0)
          {
            owned->datagramDrainDeadlineUs = nowUs + 100'000;
          }
          if (nowUs >= owned->datagramDrainDeadlineUs)
          {
            ++completed;
          }
        }
      }
      if (completed >= benchmarkServerTargetConnections)
      {
        break;
      }
      pumpOnce(1000);
    }
  }

  bool processServer(ServerConn& active)
  {
    if (active.handler->stream == UINT64_MAX)
    {
      return false;
    }

    std::shared_ptr<quic::QuicSocket> socket = active.transport;
    quic::StreamId activeStream = active.handler->stream;
    switch (active.phase)
    {
      case ServerPhase::readRequest:
        {
          auto [read, fin] = readSome(socket, activeStream, active.request.data() + active.requestRead, active.request.size() - active.requestRead);
          (void)fin;
          active.requestRead += read;
          if (active.requestRead == active.request.size())
          {
            active.bytesRemaining = decodeU64(active.request.data());
            active.phase = ServerPhase::transfer;
          }
          return read > 0;
        }
      case ServerPhase::transfer:
        {
          if (active.bytesRemaining == 0)
          {
            active.phase = ServerPhase::readDone;
            return true;
          }
          size_t chunk = static_cast<size_t>(std::min<uint64_t>(active.bytesRemaining, buffer.size()));
          if (benchmarkIsUpload())
          {
            auto [read, fin] = readSome(socket, activeStream, buffer.data(), chunk);
            (void)fin;
            active.bytesRemaining -= read;
            return read > 0;
          }
          size_t written = writeSome(socket, activeStream, buffer.data(), chunk);
          active.bytesRemaining -= written;
          return written > 0;
        }
      case ServerPhase::readDone:
        {
          auto [read, fin] = readSome(socket, activeStream, &active.done + active.doneRead, sizeof(active.done) - active.doneRead);
          (void)fin;
          active.doneRead += read;
          if (active.doneRead == sizeof(active.done))
          {
            active.phase = ServerPhase::sendAck;
          }
          return read > 0;
        }
      case ServerPhase::sendAck:
        {
          size_t written = writeSome(socket, activeStream, &active.ack + active.ackSent, sizeof(active.ack) - active.ackSent);
          active.ackSent += written;
          if (active.ackSent == sizeof(active.ack))
          {
            active.phase = ServerPhase::finish;
          }
          return written > 0;
        }
      case ServerPhase::finish:
        {
          finishStream(socket, activeStream);
          active.phase = ServerPhase::complete;
          active.complete = true;
          return true;
        }
      case ServerPhase::complete:
        return false;
    }
    return false;
  }

  void runServerConnections(void)
  {
    uint32_t completed = 0;
    while (completed < benchmarkServerTargetConnections)
    {
      bool progressed = false;
      completed = 0;
      for (auto& owned : serverConns)
      {
        ServerConn& active = *owned;
        bool connProgressed = false;
        if (!active.complete)
        {
          connProgressed = processServer(active);
          progressed = connProgressed || progressed;
        }
        if (active.complete)
        {
          ++completed;
        }
        pumpOnce(!connProgressed && !active.complete ? 100 : 0);
      }
      if (!progressed)
      {
        pumpOnce();
      }
      else
      {
        pumpOnce(0);
      }
    }
    for (;;)
    {
      bool allClosed = true;
      for (auto& owned : serverConns)
      {
        if (!owned->handler->connectionEnded && !owned->handler->connectionError)
        {
          allClosed = false;
          break;
        }
      }
      if (allClosed)
      {
        break;
      }
      pumpOnce();
    }
  }

  void runClientDownload(uint64_t bytes)
  {
    std::shared_ptr<quic::QuicSocket> socket = client;
    uint8_t request[8];
    encodeU64(bytes, request);
    sendAll(socket, stream, request, sizeof(request));
    recvBytes(socket, stream, bytes);
    uint8_t done = 0;
    sendAll(socket, stream, &done, sizeof(done));
    finishStream(socket, stream);
    uint8_t ack = 0;
    recvExact(socket, stream, &ack, sizeof(ack));
  }

  void runClientUpload(uint64_t bytes)
  {
    std::shared_ptr<quic::QuicSocket> socket = client;
    uint8_t request[8];
    encodeU64(bytes, request);
    sendAll(socket, stream, request, sizeof(request));
    sendBytes(socket, stream, bytes);
    uint8_t done = 0;
    sendAll(socket, stream, &done, sizeof(done));
    finishStream(socket, stream);
    uint8_t ack = 0;
    recvExact(socket, stream, &ack, sizeof(ack));
  }

public:

  ~Mvfst()
  {
    if (client)
    {
      if (stream != UINT64_MAX)
      {
        client->setReadCallback(stream, nullptr);
      }
      client->closeNow(quic::Optional<quic::QuicError> {});
    }
    for (auto& owned : serverConns)
    {
      if (owned->transport)
      {
        if (owned->handler && owned->handler->stream != UINT64_MAX)
        {
          owned->transport->setReadCallback(owned->handler->stream, nullptr);
        }
      }
    }
    driveEvents();
    if (clientHandler)
    {
      clientHandler->socket.reset();
    }
    for (auto& owned : serverConns)
    {
      if (owned->handler)
      {
        owned->handler->socket.reset();
      }
    }
    client.reset();
    serverConns.clear();
    delete networkHub;
  }

  void instanceSetup(uint16_t localPort, int argc, char *argv[])
  {
    (void)argc;
    (void)argv;
    std::fill(buffer.begin(), buffer.end(), 0x7);
    networkHub = new NetworkHub<mode>(localPort);
    quicEventBase = std::make_shared<quic::FollyQuicEventBase>(&eventBase);
    if constexpr (mode & Mode::server)
    {
      serverContext = makeServerContext();
      serverConns.reserve(benchmarkServerTargetConnections);
    }
    else
    {
      clientContext = makeClientContext();
    }
  }

  void connectToServer(struct sockaddr *address)
  {
    if constexpr (mode & Mode::client)
    {
      startClientConnection(address);
      waitForClientHandshake();
    }
  }

  void connectToServerForZeroRtt(struct sockaddr *address) override
  {
    if constexpr (mode & Mode::client)
    {
      startClientConnection(address);
      if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
      {
        resetGenericClientStreams();
        genericStarted = true;
        openMoreGenericClientStreams(0);
        processGenericClientStreams();
        driveEvents();
        zeroRttAttemptedObserved = zeroRttAttemptedObserved || client->hasZeroRttWriteCipher();
      }
    }
  }

  void openStream(void)
  {
    if constexpr (mode & Mode::client)
    {
      while (stream == UINT64_MAX)
      {
        auto result = client->createBidirectionalStream();
        if (!result.hasError())
        {
          stream = *result;
          client->setReadCallback(stream, clientHandler.get());
          break;
        }
        pumpOnce();
      }
    }
  }

  void idleHold(uint64_t holdMs) override
  {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(holdMs);
    while (std::chrono::steady_clock::now() < deadline)
    {
      pumpOnce();
    }
  }

  void startPerfTest(uint64_t nBytes = 0)
  {
    updateZeroRttState();
    if (benchmarkIsIdleFootprint())
    {
      if constexpr (mode & Mode::server)
      {
        runServerIdleConnections();
      }
      else
      {
        runClientIdleCleanup();
      }
      return;
    }
    if (benchmarkScenarioIsGenericStreamWorkload(benchmarkScenario))
    {
      if constexpr (mode & Mode::server)
      {
        runServerGenericConnections();
      }
      else
      {
        runClientGeneric(nBytes);
      }
      return;
    }
    if (benchmarkScenario == BenchmarkScenario::datagram)
    {
      if constexpr (mode & Mode::server)
      {
        runServerDatagramConnections();
      }
      else
      {
        runClientDatagram();
      }
      return;
    }
    if constexpr (mode & Mode::server)
    {
      runServerConnections();
    }
    else
    {
      if (benchmarkIsUpload())
      {
        runClientUpload(nBytes);
      }
      else
      {
        runClientDownload(nBytes);
      }
    }
  }

  bool supportsSessionResumption(void) const override
  {
    return true;
  }

  bool supportsZeroRtt(void) const override
  {
    return true;
  }

  bool exportResumptionState(BenchmarkResumptionState& state) override
  {
    if constexpr (mode & Mode::client)
    {
      for (unsigned i = 0; i < 200; ++i)
      {
        if (mvfstBenchmarkPskCache()->getPsk("localhost").has_value())
        {
          state.session.assign({'m', 'v', 'f', 's', 't', '-', 'p', 's', 'k'});
          state.proofLabel = "mvfst_basic_quic_psk_cache_and_zero_rtt_state";
          return true;
        }
        pumpOnce();
      }
    }
    return false;
  }

  bool importResumptionState(const BenchmarkResumptionState& state, bool enableZeroRtt) override
  {
    if constexpr (mode & Mode::client)
    {
      if (state.session.empty())
      {
        return false;
      }
      importedResumption = true;
      importedZeroRtt = enableZeroRtt;
      resumedObserved = false;
      zeroRttAttemptedObserved = false;
      zeroRttAcceptedObserved = false;
      zeroRttRejectedObserved = false;
      return true;
    }
    return false;
  }

  bool connectionWasResumed(void) const override
  {
    return importedResumption && resumedObserved;
  }

  bool zeroRttWasAttempted(void) const override
  {
    return importedZeroRtt && zeroRttAttemptedObserved;
  }

  bool zeroRttWasAccepted(void) const override
  {
    return importedZeroRtt && zeroRttAcceptedObserved;
  }

  bool zeroRttWasRejected(void) const override
  {
    return importedZeroRtt && zeroRttRejectedObserved;
  }

  const char *resumptionProofLabel(void) const override
  {
    return "mvfst_basic_quic_psk_cache_and_zero_rtt_state";
  }
};
