#include "adapter_factory.h"
#include "core/timer_queue.h"
#include "core/strict_config.h"

#include <fizz/backend/openssl/certificate/CertUtils.h>
#include <fizz/backend/openssl/certificate/OpenSSLCertificateVerifier.h>
#include <fizz/client/FizzClientContext.h>
#include <fizz/protocol/CertificateVerifier.h>
#include <fizz/protocol/clock/Clock.h>
#include <fizz/server/DefaultCertManager.h>
#include <fizz/server/FizzServerContext.h>
#include <fizz/server/TicketPolicy.h>
#include <fizz/server/TicketTypes.h>
#include <folly/FileUtil.h>
#include <folly/SocketAddress.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/ssl/OpenSSLTransportCertificate.h>
#include <folly/ssl/OpenSSLCertUtils.h>
#include <glog/logging.h>
#include <quic/api/QuicSocket.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/NetworkData.h>
#include <quic/common/events/QuicEventBase.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocketImpl.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/client/handshake/QuicPskCache.h>
#include <quic/fizz/handshake/QuicFizzFactory.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/server/QuicServerTransport.h>

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <deque>
#include <functional>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace quicperf {
namespace {

constexpr uint32_t resumptionMagic = 0x4d565253U;
constexpr uint64_t applicationBufferBytes = 256 * 1024;

folly::SocketAddress socketAddress(const sockaddr_in& address)
{
  folly::SocketAddress result;
  result.setFromSockaddr(reinterpret_cast<const sockaddr*>(&address), sizeof(address));
  return result;
}

std::string readFile(const std::string& path)
{
  std::string result;
  if (!folly::readFile(path.c_str(), result)) return {};
  return result;
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

void storeU64(std::byte* destination, uint64_t value)
{
  for (int shift = 56; shift >= 0; shift -= 8) *destination++ = std::byte(value >> shift);
}

uint64_t loadU64(const std::byte* source)
{
  uint64_t value = 0;
  for (unsigned index = 0; index < 8; ++index)
    value = (value << 8) | std::to_integer<uint8_t>(source[index]);
  return value;
}

class NoVerify final : public fizz::CertificateVerifier {
public:
  fizz::Status verify(std::shared_ptr<const fizz::Cert>& result, fizz::Error&,
                      const std::vector<std::shared_ptr<const fizz::PeerCert>>& certificates)
      const override
  {
    if (!certificates.empty()) result = certificates.front();
    return fizz::Status::Success;
  }

  fizz::Status getCertificateRequestExtensions(
      std::vector<fizz::Extension>&, fizz::Error&) const override
  {
    return fizz::Status::Success;
  }
};

class ObservedCertificateVerifier final : public fizz::CertificateVerifier {
public:
  explicit ObservedCertificateVerifier(
      std::shared_ptr<fizz::CertificateVerifier> delegate)
      : delegate_(std::move(delegate))
  {}

  fizz::Status verify(
      std::shared_ptr<const fizz::Cert>& result, fizz::Error& error,
      const std::vector<std::shared_ptr<const fizz::PeerCert>>& certificates)
      const override
  {
    const auto status = delegate_->verify(result, error, certificates);
    if (status == fizz::Status::Success) verified_ = true;
    return status;
  }

  fizz::Status getCertificateRequestExtensions(
      std::vector<fizz::Extension>& extensions, fizz::Error& error) const override
  {
    return delegate_->getCertificateRequestExtensions(extensions, error);
  }

  bool verified() const noexcept { return verified_; }

private:
  std::shared_ptr<fizz::CertificateVerifier> delegate_;
  mutable bool verified_ = false;
};

class FixedFizzClock final : public fizz::Clock {
public:
  explicit FixedFizzClock(uint64_t unixSeconds)
      : now_(std::chrono::system_clock::time_point(
            std::chrono::seconds(static_cast<int64_t>(unixSeconds))))
  {}

  std::chrono::system_clock::time_point getCurrentTime() const override { return now_; }

private:
  std::chrono::system_clock::time_point now_;
};

class RecordingQuicPskCache final : public quic::QuicPskCache {
public:
  quic::Optional<quic::QuicCachedPsk> getPsk(
      const std::string& identity) override
  {
    const auto found = current_.find(identity);
    return found == current_.end() ?
        quic::Optional<quic::QuicCachedPsk> {} : found->second;
  }

  void putPsk(std::string const& identity, quic::QuicCachedPsk psk) override
  {
    if (issuedIdentities_.insert(psk.cachedPsk.psk).second)
    {
      issued_.push_back(psk);
      ++issuedCount_;
    }
    current_[identity] = std::move(psk);
  }

  void putImported(std::string const& identity, quic::QuicCachedPsk psk)
  {
    current_[identity] = std::move(psk);
  }

  void removePsk(const std::string& identity) override { current_.erase(identity); }

  quic::Optional<quic::QuicCachedPsk> takeIssued()
  {
    if (issued_.empty()) return {};
    auto result = std::move(issued_.front());
    issued_.pop_front();
    return result;
  }

  bool hasIssued() const noexcept { return issuedCount_ != 0; }

private:
  std::unordered_map<std::string, quic::QuicCachedPsk> current_;
  std::unordered_set<std::string> issuedIdentities_;
  std::deque<quic::QuicCachedPsk> issued_;
  size_t issuedCount_ = 0;
};

class EarlyDataParameters final : public quic::EarlyDataAppParamsHandler {
public:
  bool validate(const quic::Optional<std::string>&, const quic::BufPtr&) override
  {
    return true;
  }
  quic::BufPtr get() override { return folly::IOBuf::copyBuffer("qperf/2"); }
};

class ManualQuicEventBase final : public quic::QuicEventBase {
public:
  void setNow(uint64_t nowRawNs)
  {
    if (!nowRawNs || (nowSet_ && nowRawNs < nowRawNs_))
      throw std::invalid_argument("mvfst caller time is zero or regressed");
    nowRawNs_ = nowRawNs;
    nowSet_ = true;
  }

  std::optional<uint64_t> nextDeadline() const noexcept
  {
    if (!currentCallbacks_.empty() || !nextCallbacks_.empty()) return nowRawNs_;
    return timers_.nextDeadline();
  }

  size_t runReady()
  {
    requireNow();
    currentCallbacks_.swap(nextCallbacks_);
    inLoop_ = true;
    size_t count = timers_.runReady(nowRawNs_);
    for (size_t guard = 0;
         !currentCallbacks_.empty() && guard < maxCallbacksPerDrive;
         ++guard)
    {
      auto callback = std::move(currentCallbacks_.front());
      currentCallbacks_.pop_front();
      callback();
      ++count;
    }
    inLoop_ = false;
    if (!currentCallbacks_.empty())
    {
      currentCallbacks_.insert(
          currentCallbacks_.end(),
          std::make_move_iterator(nextCallbacks_.begin()),
          std::make_move_iterator(nextCallbacks_.end()));
      nextCallbacks_.swap(currentCallbacks_);
      currentCallbacks_.clear();
    }
    return count;
  }

  uint64_t timerExpirations() const noexcept { return timerExpirations_; }

  void runInLoop(quic::QuicEventBaseLoopCallback* callback, bool thisIteration) override
  {
    if (!callback) return;
    auto* wrapper = static_cast<LoopCallbackWrapper*>(getImplHandle(callback));
    if (!wrapper)
    {
      wrapper = new LoopCallbackWrapper(callback);
      setImplHandle(callback, wrapper);
    }
    auto state = wrapper->state_;
    if (state->scheduled) return;
    state->scheduled = true;
    const uint64_t generation = ++state->generation;
    auto& callbacks = inLoop_ && thisIteration ? currentCallbacks_ : nextCallbacks_;
    callbacks.emplace_back([state = std::move(state), generation] {
      if (!state->scheduled || state->generation != generation) return;
      state->scheduled = false;
      state->callback->runLoopCallback();
    });
  }

  void runInLoop(std::function<void()> callback, bool thisIteration) override
  {
    if (!callback) return;
    auto& callbacks = inLoop_ && thisIteration ? currentCallbacks_ : nextCallbacks_;
    callbacks.push_back(std::move(callback));
  }

  void runAfterDelay(std::function<void()> callback, uint32_t milliseconds) override
  {
    if (!callback) return;
    requireNow();
    timers_.add(deadline(std::chrono::milliseconds(milliseconds)),
                [callback = std::move(callback)](uint64_t) mutable { callback(); });
  }

  void runInEventBaseThreadAndWait(std::function<void()> callback) noexcept override
  {
    if (callback) callback();
  }

  void runImmediatelyOrRunInEventBaseThreadAndWait(
      std::function<void()> callback) noexcept override
  {
    if (callback) callback();
  }

  void runInEventBaseThread(std::function<void()> callback) noexcept override
  {
    if (callback) callback();
  }

  void runImmediatelyOrRunInEventBaseThread(
      std::function<void()> callback) noexcept override
  {
    if (callback) callback();
  }

  bool isInEventBaseThread() const override { return true; }

  void scheduleTimeout(quic::QuicTimerCallback* callback,
                       std::chrono::milliseconds timeout) override
  {
    schedule(callback, timeout);
  }

  bool scheduleTimeoutHighRes(quic::QuicTimerCallback* callback,
                              std::chrono::microseconds timeout) override
  {
    schedule(callback, timeout);
    return callback != nullptr;
  }

  bool loopOnce(int = 0) override { return runReady() != 0; }

  bool loop() override
  {
    const bool progressed = !terminated_ && nextDeadline() &&
        *nextDeadline() <= nowRawNs_ && runReady() != 0;
    terminated_ = false;
    return progressed;
  }

  void loopForever() override { loop(); }
  bool loopIgnoreKeepAlive() override { return loop(); }
  void terminateLoopSoon() override { terminated_ = true; }
  std::chrono::milliseconds getTimerTickInterval() const override
  {
    return std::chrono::milliseconds(1);
  }

private:
  static constexpr size_t maxCallbacksPerDrive = 4096;

  struct LoopState {
    quic::QuicEventBaseLoopCallback* callback = nullptr;
    uint64_t generation = 0;
    bool scheduled = false;
  };

  class LoopCallbackWrapper final
      : public quic::QuicEventBaseLoopCallback::LoopCallbackImpl {
  public:
    explicit LoopCallbackWrapper(quic::QuicEventBaseLoopCallback* callback)
        : state_(std::make_shared<LoopState>(LoopState {.callback = callback}))
    {}
    void cancelImpl() noexcept override
    {
      state_->scheduled = false;
      ++state_->generation;
    }
    bool isScheduledImpl() const noexcept override { return state_->scheduled; }

  private:
    friend class ManualQuicEventBase;
    std::shared_ptr<LoopState> state_;
  };

  struct TimerState {
    ManualQuicEventBase* owner = nullptr;
    quic::QuicTimerCallback* callback = nullptr;
    TimerQueue::TimerId timerId = 0;
    uint64_t deadlineRawNs = 0;
    uint64_t generation = 0;
    bool scheduled = false;
  };

  class TimerCallbackWrapper final : public quic::QuicTimerCallback::TimerCallbackImpl {
  public:
    TimerCallbackWrapper(ManualQuicEventBase& owner, quic::QuicTimerCallback* callback)
        : state_(std::make_shared<TimerState>(
              TimerState {.owner = &owner, .callback = callback}))
    {}
    void cancelImpl() noexcept override
    {
      if (state_->scheduled) state_->owner->timers_.cancel(state_->timerId);
      state_->scheduled = false;
      ++state_->generation;
    }
    bool isScheduledImpl() const noexcept override { return state_->scheduled; }
    std::chrono::milliseconds getTimeRemainingImpl() const noexcept override
    {
      if (!state_->scheduled || state_->deadlineRawNs <= state_->owner->nowRawNs_)
        return std::chrono::milliseconds(0);
      return std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::nanoseconds(state_->deadlineRawNs - state_->owner->nowRawNs_));
    }

  private:
    friend class ManualQuicEventBase;
    std::shared_ptr<TimerState> state_;
  };

  template <typename Duration>
  uint64_t deadline(Duration timeout) const
  {
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(timeout).count();
    const uint64_t delta = nanoseconds > 0 ? static_cast<uint64_t>(nanoseconds) : 0;
    return delta > std::numeric_limits<uint64_t>::max() - nowRawNs_ ?
        std::numeric_limits<uint64_t>::max() : nowRawNs_ + delta;
  }

  template <typename Duration>
  void schedule(quic::QuicTimerCallback* callback, Duration timeout)
  {
    if (!callback) return;
    requireNow();
    auto* wrapper = static_cast<TimerCallbackWrapper*>(getImplHandle(callback));
    if (!wrapper)
    {
      wrapper = new TimerCallbackWrapper(*this, callback);
      setImplHandle(callback, wrapper);
    }
    wrapper->cancelImpl();
    auto state = wrapper->state_;
    state->scheduled = true;
    state->deadlineRawNs = deadline(timeout);
    const uint64_t deadlineRawNs = state->deadlineRawNs;
    const uint64_t generation = ++state->generation;
    state->timerId = timers_.add(deadlineRawNs,
        [state, generation](uint64_t) {
          if (!state->scheduled || state->generation != generation) return;
          state->scheduled = false;
          state->timerId = 0;
          ++state->owner->timerExpirations_;
          state->callback->timeoutExpired();
        });
  }

  void requireNow() const
  {
    if (!nowSet_) throw std::logic_error("mvfst event base used before caller time was set");
  }

  TimerQueue timers_;
  std::deque<std::function<void()>> currentCallbacks_;
  std::deque<std::function<void()>> nextCallbacks_;
  uint64_t nowRawNs_ = 0;
  bool nowSet_ = false;
  bool inLoop_ = false;
  bool terminated_ = false;
  uint64_t timerExpirations_ = 0;
};

class MvfstAdapter;

class MvfstNetworkSocket final : public quic::QuicAsyncUDPSocketImpl {
public:
  MvfstNetworkSocket(MvfstAdapter& owner, std::shared_ptr<quic::QuicEventBase> eventBase,
                     const sockaddr_in& local);

  quic::Expected<void, quic::QuicError> init(sa_family_t) override;
  quic::Expected<void, quic::QuicError> bind(const folly::SocketAddress& address) override;
  bool isBound() const override { return true; }
  quic::Expected<void, quic::QuicError> connect(const folly::SocketAddress&) override;
  quic::Expected<void, quic::QuicError> close() override;
  void resumeRead(ReadCallback* callback) override { readCallback_ = callback; readPaused_ = false; }
  void pauseRead() override { readPaused_ = true; }
  bool isReadPaused() const override { return readPaused_; }
  quic::Expected<void, quic::QuicError> resumeWrite(WriteCallback* callback) override;
  void pauseWrite() override { writeCallback_ = nullptr; }
  bool isWritableCallbackSet() const override { return writeCallback_ != nullptr; }
  ssize_t write(const folly::SocketAddress& address, const iovec* vectors,
                size_t vectorCount) override;
  int writem(quic::AddressRange addresses, iovec* vectors,
             size_t* vectorsPerAddress, size_t count) override;
  ssize_t writeGSO(const folly::SocketAddress& address, const iovec* vectors,
                   size_t vectorCount, WriteOptions options) override;
  int writemGSO(quic::AddressRange, const quic::BufPtr*, size_t,
                const WriteOptions*) override;
  int writemGSO(quic::AddressRange addresses, iovec* vectors,
                size_t* vectorsPerAddress, size_t count,
                const WriteOptions* options) override;
  ssize_t recvmsg(msghdr*, int) override { errno = EAGAIN; return -1; }
  int recvmmsg(mmsghdr*, unsigned, unsigned, timespec*) override
  {
    errno = EAGAIN;
    return -1;
  }
  quic::Expected<int, quic::QuicError> getGSO() override { return -1; }
  quic::Expected<int, quic::QuicError> getGRO() override { return -1; }
  quic::Expected<void, quic::QuicError> setGRO(bool) override;
  quic::Expected<void, quic::QuicError> setRecvTos(bool) override;
  quic::Expected<bool, quic::QuicError> getRecvTos() override { return false; }
  quic::Expected<void, quic::QuicError> setTosOrTrafficClass(uint8_t) override;
  quic::Expected<folly::SocketAddress, quic::QuicError> address() const override
  {
    return localAddress_;
  }
  const folly::SocketAddress& addressRef() const override { return localAddress_; }
  void attachEventBase(std::shared_ptr<quic::QuicEventBase> eventBase) override
  {
    eventBase_ = std::move(eventBase);
  }
  void detachEventBase() override { eventBase_.reset(); }
  std::shared_ptr<quic::QuicEventBase> getEventBase() const override { return eventBase_; }
  quic::Expected<void, quic::QuicError> setCmsgs(const folly::SocketCmsgMap&) override;
  quic::Expected<void, quic::QuicError> appendCmsgs(const folly::SocketCmsgMap&) override;
  quic::Expected<void, quic::QuicError> setAdditionalCmsgsFunc(
      std::function<quic::Optional<folly::SocketCmsgMap>()>&&) override;
  quic::Expected<int, quic::QuicError> getTimestamping() override { return -1; }
  quic::Expected<void, quic::QuicError> setReuseAddr(bool) override;
  quic::Expected<void, quic::QuicError> setDFAndTurnOffPMTU() override;
  quic::Expected<void, quic::QuicError> setErrMessageCallback(ErrMessageCallback*) override;
  quic::Expected<void, quic::QuicError> applyOptions(
      const folly::SocketOptionMap&, folly::SocketOptionKey::ApplyPos) override;
  quic::Expected<void, quic::QuicError> setReusePort(bool) override;
  quic::Expected<void, quic::QuicError> setRcvBuf(int) override;
  quic::Expected<void, quic::QuicError> setSndBuf(int) override;
  quic::Expected<void, quic::QuicError> setFD(int, FDOwnership) override;
  int getFD() override { return -1; }

private:
  static quic::Expected<void, quic::QuicError> ok()
  {
    return quic::Expected<void, quic::QuicError> {};
  }
  MvfstAdapter& owner_;
  std::shared_ptr<quic::QuicEventBase> eventBase_;
  folly::SocketAddress localAddress_;
  ReadCallback* readCallback_ = nullptr;
  WriteCallback* writeCallback_ = nullptr;
  bool readPaused_ = true;
};

class MvfstAdapter final : public Adapter {
public:
  MvfstAdapter();
  ~MvfstAdapter() override;

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
  bool peerTerminalFacts(uint64_t connectionId, uint64_t streamId, uint64_t,
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
  TransportCounters snapshotTransportCounters() const noexcept override;
  NegotiatedSettings snapshotNegotiatedSettings() const noexcept override;
  bool reset(AdapterError& error) override;
  bool stop(AdapterError& error) override { return reset(error); }

  ssize_t queuePacket(const folly::SocketAddress& peer, const iovec* vectors,
                      size_t vectorCount);

private:
  struct Stream {
    std::vector<std::byte> received;
    size_t receiveOffset = 0;
    bool remoteFin = false;
    bool remoteReset = false;
    bool remoteStop = false;
    uint64_t remoteResetError = 0;
    uint64_t remoteStopError = 0;
    bool readClosed = false;
  };

  struct Connection;

  class Handler final : public quic::QuicSocket::ConnectionSetupCallback,
                        public quic::QuicSocket::ConnectionCallback,
                        public quic::QuicSocket::ReadCallback,
                        public quic::QuicSocket::WriteCallback,
                        public quic::QuicSocket::DatagramCallback {
  public:
    explicit Handler(Connection& connection) : connection_(connection) {}
    void setSocket(std::shared_ptr<quic::QuicSocket> socket);
    void onConnectionSetupError(quic::QuicError) noexcept override;
    void onTransportReady() noexcept override;
    void onReplaySafe() noexcept override;
    void onFullHandshakeDone() noexcept override;
    void onNewBidirectionalStream(quic::StreamId id) noexcept override;
    void onNewUnidirectionalStream(quic::StreamId id) noexcept override;
    void onStopSending(quic::StreamId, quic::ApplicationErrorCode) noexcept override;
    void onConnectionEnd() noexcept override;
    void onConnectionEnd(quic::QuicError) noexcept override;
    void onConnectionError(quic::QuicError) noexcept override;
    void readAvailable(quic::StreamId id) noexcept override;
    void readError(quic::StreamId id, quic::QuicError) noexcept override;
    void onDatagramsAvailable() noexcept override;

  private:
    Connection& connection_;
  };

  struct Connection {
    MvfstAdapter* owner = nullptr;
    uint64_t id = 0;
    sockaddr_in peer {};
    std::shared_ptr<quic::QuicSocket> socket;
    std::shared_ptr<quic::QuicClientTransport> client;
    std::shared_ptr<quic::QuicServerTransport> server;
    std::unique_ptr<Handler> handler;
    std::unique_ptr<quic::DefaultConnectionIdAlgo> connectionIdAlgorithm;
    std::unordered_map<uint64_t, Stream> streams;
    std::deque<uint64_t> acceptedBidi;
    std::deque<uint64_t> acceptedUni;
    std::deque<std::vector<std::byte>> datagrams;
    bool transportReady = false;
    bool handshakeDone = false;
    bool ended = false;
    bool failed = false;
    bool imported = false;
    bool earlyAttempted = false;
    bool resumed = false;
    bool earlyAccepted = false;
    bool earlyRejected = false;
    bool localCloseRequested = false;
    bool peerConnectionClose = false;
    uint64_t peerConnectionCloseError = 0;
    uint64_t peerConnectionCloseReasonLength = 0;
  };

  struct OutputPacket {
    std::vector<std::byte> bytes;
    sockaddr_in peer {};
  };

  struct ImportedState {
    uint64_t key = 0;
    bool zeroRtt = false;
  };

  struct ExportedPsk {
    quic::QuicCachedPsk psk;
    uint64_t issuedRawNs = 0;
  };

  [[maybe_unused]] bool initializeContexts(AdapterError& error);
  std::shared_ptr<fizz::server::FizzServerContext> makeServerContext(AdapterError& error);
  std::shared_ptr<quic::FizzClientQuicHandshakeContext> makeClientContext(AdapterError& error);
  quic::TransportSettings transportSettings(bool zeroRtt) const;
  Connection& createConnection(const sockaddr_in& peer);
  Connection* createServerConnection(const ReceivedPacket& packet, AdapterError& error);
  Connection* find(uint64_t id, AdapterError& error) const;
  Stream* findStream(Connection& connection, uint64_t id, AdapterError& error);
  bool setCallerTime(uint64_t nowRawNs, AdapterError& error);
  void restoreCallerTimeForSnapshot() const noexcept;
  bool drive(uint64_t nowRawNs, AdapterError& error);
  void deliver(Connection& connection, const ReceivedPacket& packet);
  Connection* route(const ReceivedPacket& packet) const;
  void rememberConnectionIds(Connection& connection);
  void drainStream(Connection& connection, uint64_t id);
  void drainDatagrams(Connection& connection);
  void updateResumption(Connection& connection);
  PrimitiveStatus openStream(uint64_t connectionId, bool unidirectional, uint64_t nowRawNs,
                             uint64_t& streamId, AdapterError& error);
  PrimitiveStatus acceptStream(uint64_t connectionId, bool unidirectional, uint64_t nowRawNs,
                               uint64_t& streamId, AdapterError& error);
  PrimitiveStatus unavailable(std::string_view primitive, AdapterError& error) const;

  Capabilities capabilities_;
  EndpointConfig config_ {};
  sockaddr_in localAddress_ {};
  std::shared_ptr<ManualQuicEventBase> quicEventBase_;
  std::shared_ptr<fizz::server::FizzServerContext> serverContext_;
  std::shared_ptr<quic::FizzClientQuicHandshakeContext> clientContext_;
  std::shared_ptr<RecordingQuicPskCache> pskCache_;
  std::shared_ptr<ObservedCertificateVerifier> certificateVerifier_;
  std::shared_ptr<quic::CongestionControllerFactory> congestionControllerFactory_;
  EarlyDataParameters earlyDataParameters_;
  std::unordered_map<uint64_t, std::unique_ptr<Connection>> connections_;
  std::unordered_map<std::string, Connection*> connectionsByCid_;
  std::deque<uint64_t> acceptedConnections_;
  std::deque<OutputPacket> outputQueue_;
  std::unordered_map<uint64_t, ExportedPsk> exportedPsks_;
  std::unordered_set<std::string> consumedPskIdentities_;
  std::unique_ptr<ImportedState> importedState_;
  uint64_t nextConnectionId_ = 1;
  uint64_t nextPskId_ = 1;
  uint64_t nextTimeoutRawNs_ = 0;
  uint64_t lastCallerTimeRawNs_ = 0;
  bool configured_ = false;
  bool localAddressSet_ = false;
  std::array<std::array<std::byte, maxUdpPayloadSize>, packetBatchSize> output_ {};
  TransportCounters counters_ {};
};

MvfstNetworkSocket::MvfstNetworkSocket(
    MvfstAdapter& owner, std::shared_ptr<quic::QuicEventBase> eventBase,
    const sockaddr_in& local)
    : owner_(owner), eventBase_(std::move(eventBase)), localAddress_(socketAddress(local))
{}

quic::Expected<void, quic::QuicError> MvfstNetworkSocket::init(sa_family_t) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::bind(
    const folly::SocketAddress& address) { localAddress_ = address; return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::connect(
    const folly::SocketAddress&) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::close() { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::resumeWrite(WriteCallback* callback)
{
  writeCallback_ = callback;
  if (writeCallback_) writeCallback_->onSocketWritable();
  return ok();
}

ssize_t MvfstNetworkSocket::write(const folly::SocketAddress& address,
                                  const iovec* vectors, size_t vectorCount)
{
  return owner_.queuePacket(address, vectors, vectorCount);
}

int MvfstNetworkSocket::writem(quic::AddressRange addresses, iovec* vectors,
                               size_t* vectorsPerAddress, size_t count)
{
  size_t offset = 0;
  size_t sent = 0;
  for (; sent < count; ++sent)
  {
    if (owner_.queuePacket(addresses[sent], vectors + offset, vectorsPerAddress[sent]) < 0)
      break;
    offset += vectorsPerAddress[sent];
  }
  if (!sent) { errno = EAGAIN; return -1; }
  return static_cast<int>(sent);
}

ssize_t MvfstNetworkSocket::writeGSO(const folly::SocketAddress& address,
                                     const iovec* vectors, size_t vectorCount,
                                     WriteOptions options)
{
  if (options.gso || options.zerocopy) { errno = ENOTSUP; return -1; }
  return write(address, vectors, vectorCount);
}

int MvfstNetworkSocket::writemGSO(quic::AddressRange, const quic::BufPtr*, size_t,
                                  const WriteOptions*)
{
  errno = ENOTSUP;
  return -1;
}

int MvfstNetworkSocket::writemGSO(quic::AddressRange addresses, iovec* vectors,
                                  size_t* vectorsPerAddress, size_t count,
                                  const WriteOptions* options)
{
  if (options)
    for (size_t index = 0; index < count; ++index)
      if (options[index].gso || options[index].zerocopy) { errno = ENOTSUP; return -1; }
  return writem(addresses, vectors, vectorsPerAddress, count);
}

quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setGRO(bool) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setRecvTos(bool) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setTosOrTrafficClass(uint8_t) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setCmsgs(const folly::SocketCmsgMap&) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::appendCmsgs(const folly::SocketCmsgMap&) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setAdditionalCmsgsFunc(
    std::function<quic::Optional<folly::SocketCmsgMap>()>&&) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setReuseAddr(bool) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setDFAndTurnOffPMTU() { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setErrMessageCallback(ErrMessageCallback*) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::applyOptions(
    const folly::SocketOptionMap&, folly::SocketOptionKey::ApplyPos) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setReusePort(bool) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setRcvBuf(int) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setSndBuf(int) { return ok(); }
quic::Expected<void, quic::QuicError> MvfstNetworkSocket::setFD(int, FDOwnership) { return ok(); }

MvfstAdapter::MvfstAdapter()
{
  FLAGS_minloglevel = google::GLOG_ERROR;
  congestionControllerFactory_ =
      std::make_shared<quic::DefaultCongestionControllerFactory>();
  capabilities_.library = "mvfst";
  capabilities_.buildId = "mvfst-155afab-quicperf4-caller-time-v1";
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
      "common_cpp_packet_io", "borrowed_packet_batch_64", "caller_supplied_raw_time",
      "runtime_threads_none", "ipv4", "quic_v1", "tls_1_3",
      "tls_aes_128_gcm_sha256", "x25519", "qperf_2_alpn",
      "canonical_tls_hostname", "ca_verified_peer", "post_bind_local_address",
      "bidirectional_stream", "unidirectional_stream", "datagram", "resumption",
      "early_data", "reset_stream", "stop_sending", "connection_close",
      "peer_terminal_facts", "transport_loss_counter", "recovery_probe_counter",
      "flow_control_blocked_counters", "fd_free_manual_quic_eventbase",
      "frozen_fizz_calendar_clock"};
}

MvfstAdapter::~MvfstAdapter()
{
  AdapterError ignored;
  reset(ignored);
}

std::shared_ptr<fizz::server::FizzServerContext> MvfstAdapter::makeServerContext(
    AdapterError& error)
{
  std::unique_ptr<fizz::SelfCert> certificate;
  fizz::Error certificateError;
  const std::string cert = readFile(config_.certificatePath);
  const std::string key = readFile(config_.privateKeyPath);
  if (cert.empty() || key.empty() || fizz::openssl::CertUtils::makeSelfCert(
      certificate, certificateError, cert, key) == fizz::Status::Fail)
  {
    error = {10, "mvfst failed to load server certificate and key"};
    return {};
  }
  auto manager = std::make_shared<fizz::server::DefaultCertManager>();
  manager->addCertAndSetDefault(std::shared_ptr<fizz::SelfCert>(std::move(certificate)));
  auto context = std::make_shared<fizz::server::FizzServerContext>();
  context->setFactory(std::make_shared<quic::QuicFizzFactory>());
  context->setCertManager(manager);
  auto cipher = std::make_shared<fizz::server::AES128TicketCipher>(
      context->getFactoryPtr(), manager);
  static const std::array<uint8_t, 32> secret {
      0x6d, 0x76, 0x66, 0x73, 0x74, 0x2d, 0x71, 0x70,
      0x65, 0x72, 0x66, 0x2d, 0x74, 0x69, 0x63, 0x6b,
      0x65, 0x74, 0x2d, 0x73, 0x65, 0x63, 0x72, 0x65,
      0x74, 0x2d, 0x76, 0x32, 0x2d, 0x30, 0x31, 0x21};
  cipher->setTicketSecrets({folly::ByteRange(secret.data(), secret.size())});
  const auto calendarClock =
      std::make_shared<FixedFizzClock>(config_.calendarUnixSeconds);
  const auto ticketLifetime = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::nanoseconds(config_.tlsTicketLifetimeNs));
  fizz::server::TicketPolicy policy;
  policy.setClock(calendarClock);
  policy.setTicketValidity(ticketLifetime);
  policy.setHandshakeValidity(ticketLifetime);
  cipher->setPolicy(std::move(policy));
  context->setTicketCipher(std::move(cipher));
  context->setOmitEarlyRecordLayer(true);
  context->setClock(std::move(calendarClock));
  // RFC 9001 requires QUIC NewSessionTicket early_data extensions to carry
  // 0xffffffff. Quicperf's smaller early-data treatment remains an
  // application admission limit and is reported separately below.
  context->setMaxEarlyDataSize(std::numeric_limits<uint32_t>::max());
  context->setEarlyDataSettings(
      true, fizz::server::ClockSkewTolerance {
                .before = std::chrono::milliseconds(-1000),
                .after = std::chrono::milliseconds(1000)},
      std::make_shared<fizz::server::AllowAllReplayReplayCache>());
  context->setSupportedSigSchemes({fizz::SignatureScheme::ed25519,
                                   fizz::SignatureScheme::ecdsa_secp256r1_sha256,
                                   fizz::SignatureScheme::rsa_pss_sha256});
  context->setSupportedAlpns({"qperf/2"});
  return context;
}

std::shared_ptr<quic::FizzClientQuicHandshakeContext> MvfstAdapter::makeClientContext(
    AdapterError& error)
{
  auto fizz = std::make_shared<fizz::client::FizzClientContext>();
  fizz->setClock(std::make_shared<FixedFizzClock>(config_.calendarUnixSeconds));
  fizz->setSendEarlyData(true);
  fizz->setSupportedAlpns({"qperf/2"});
  fizz->setSupportedSigSchemes({fizz::SignatureScheme::ed25519,
                                fizz::SignatureScheme::ecdsa_secp256r1_sha256,
                                fizz::SignatureScheme::rsa_pss_sha256});
  fizz->setSupportedGroups({fizz::NamedGroup::x25519});
  fizz->setDefaultShares({fizz::NamedGroup::x25519});
  std::shared_ptr<fizz::CertificateVerifier> verifier;
  if (config_.tlsVerifyPeer)
  {
    auto store = folly::ssl::OpenSSLCertUtils::readStoreFromFile(config_.chainPath);
    if (!store) { error = {10, "mvfst failed to load CA chain"}; return {}; }
    auto parameters = folly::ssl::X509VerifyParam(X509_VERIFY_PARAM_new());
    if (!parameters || config_.calendarUnixSeconds >
            static_cast<uint64_t>(std::numeric_limits<time_t>::max()))
    {
      error = {10, "mvfst frozen TLS calendar time is out of range"};
      return {};
    }
    X509_VERIFY_PARAM_set_time(
        parameters.get(), static_cast<time_t>(config_.calendarUnixSeconds));
    if (X509_VERIFY_PARAM_set1_host(
            parameters.get(), config_.tlsHostname.c_str(), config_.tlsHostname.size()) != 1 ||
        X509_VERIFY_PARAM_set_flags(parameters.get(), X509_V_FLAG_USE_CHECK_TIME) != 1 ||
        X509_STORE_set1_param(store.get(), parameters.get()) != 1)
    {
      error = {10, "mvfst failed to configure frozen certificate and hostname verification"};
      return {};
    }
    certificateVerifier_ = std::make_shared<ObservedCertificateVerifier>(
        std::make_shared<fizz::openssl::OpenSSLCertificateVerifier>(
            fizz::VerificationContext::Client, std::move(store)));
    verifier = certificateVerifier_;
  }
  else verifier = std::make_shared<NoVerify>();
  return quic::FizzClientQuicHandshakeContext::Builder()
      .setFizzClientContext(std::move(fizz))
      .setCertificateVerifier(std::move(verifier))
      .setPskCache(pskCache_)
      .build();
}

bool MvfstAdapter::initializeContexts(AdapterError& error)
{
  quicEventBase_ = std::make_shared<ManualQuicEventBase>();
  if (config_.role == EndpointRole::server)
    return static_cast<bool>(serverContext_ = makeServerContext(error));
  pskCache_ = std::make_shared<RecordingQuicPskCache>();
  return static_cast<bool>(clientContext_ = makeClientContext(error));
}

quic::TransportSettings MvfstAdapter::transportSettings(bool zeroRtt) const
{
  quic::TransportSettings settings;
  settings.advertisedInitialConnectionFlowControlWindow = config_.connectionWindow;
  settings.advertisedInitialBidiLocalStreamFlowControlWindow = config_.streamWindow;
  settings.advertisedInitialBidiRemoteStreamFlowControlWindow = config_.streamWindow;
  settings.advertisedInitialUniStreamFlowControlWindow = config_.streamWindow;
  settings.advertisedInitialMaxStreamsBidi = config_.maxBidiStreams;
  settings.advertisedInitialMaxStreamsUni = config_.maxUniStreams;
  settings.streamCreditReplenishBelow = config_.streamCreditReplenishBelow;
  settings.idleTimeout = std::chrono::milliseconds(config_.idleTimeoutMs);
  settings.ackDelayExponent = config_.ackDelayExponent;
  settings.minAckDelay.reset();
  settings.defaultCongestionController = config_.congestionController == "cubic" ?
      quic::CongestionControlType::Cubic : quic::CongestionControlType::BBR;
  settings.initCwndInBytes = config_.initialCongestionWindowBytes;
  settings.disableMigration = !config_.activeMigration;
  settings.selfActiveConnectionIdLimit = config_.activeConnectionIdLimit;
  settings.attemptEarlyData = zeroRtt;
  settings.zeroRttSourceTokenMatchingPolicy =
      quic::ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
  settings.pacingEnabled = config_.packetIo.commonPacing;
  settings.pacingEnabledFirstFlight = true;
  settings.totalBufferSpaceAvailable = applicationBufferBytes;
  settings.maxRecvPacketSize = config_.maxUdpPayloadSize;
  settings.canIgnorePathMTU = !config_.packetIo.pmtud;
  settings.maxBatchSize = packetBatchSize;
  settings.writeConnectionDataPacketsLimit = packetBatchSize;
  std::array<uint8_t, quic::kStatelessResetTokenSecretLength> resetSecret {};
  for (size_t index = 0; index < resetSecret.size(); ++index)
    resetSecret[index] = static_cast<uint8_t>(0xa5U ^ index);
  settings.statelessResetTokenSecret = resetSecret;
  settings.datagramConfig.enabled = true;
  settings.datagramConfig.readBufSize = config_.datagramMaxUnreturnedPerConnection ?
      config_.datagramMaxUnreturnedPerConnection : 128;
  settings.datagramConfig.maxReadFrameSize = config_.datagramMaxFrameSize;
  settings.datagramConfig.writeBufSize = settings.datagramConfig.readBufSize;
  return settings;
}

bool MvfstAdapter::configure(std::string_view canonicalConfig, AdapterError& error)
{
  if (configured_) { error = {1, "mvfst adapter is already configured"}; return false; }
  auto parsed = parseEndpointConfig(canonicalConfig);
  if (!parsed) { error = {1, parsed.error}; return false; }
  config_ = std::move(parsed.config);
  if (config_.calendarUnixSeconds >
      static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
  {
    error = {1, "mvfst frozen calendar time exceeds the supported range"};
    return false;
  }
  if (!initializeContexts(error)) return false;
  configured_ = true;
  error = {};
  return true;
}

bool MvfstAdapter::setLocalAddress(const sockaddr_in& local, AdapterError& error)
{
  in_addr configured {};
  if (!configured_ || localAddressSet_ || !connections_.empty() || local.sin_family != AF_INET ||
      inet_pton(AF_INET, config_.bindAddress.c_str(), &configured) != 1 ||
      configured.s_addr != local.sin_addr.s_addr ||
      (config_.bindPort && ntohs(local.sin_port) != config_.bindPort))
  {
    error = {2, "post-bind IPv4 local address differs from frozen mvfst configuration"};
    return false;
  }
  localAddress_ = local;
  localAddressSet_ = true;
  error = {};
  return true;
}

ssize_t MvfstAdapter::queuePacket(const folly::SocketAddress& peer, const iovec* vectors,
                                  size_t vectorCount)
{
  size_t length = 0;
  for (size_t index = 0; index < vectorCount; ++index) length += vectors[index].iov_len;
  if (length > maxUdpPayloadSize) { errno = EMSGSIZE; return -1; }
  OutputPacket packet;
  packet.bytes.resize(length);
  size_t offset = 0;
  for (size_t index = 0; index < vectorCount; ++index)
  {
    std::memcpy(packet.bytes.data() + offset, vectors[index].iov_base, vectors[index].iov_len);
    offset += vectors[index].iov_len;
  }
  sockaddr_storage storage {};
  peer.getAddress(&storage);
  if (storage.ss_family != AF_INET) { errno = EAFNOSUPPORT; return -1; }
  std::memcpy(&packet.peer, &storage, sizeof(sockaddr_in));
  outputQueue_.push_back(std::move(packet));
  ++counters_.packetsSent;
  return static_cast<ssize_t>(length);
}

MvfstAdapter::Connection& MvfstAdapter::createConnection(const sockaddr_in& peer)
{
  auto owned = std::make_unique<Connection>();
  owned->owner = this;
  owned->id = nextConnectionId_++;
  owned->peer = peer;
  owned->handler = std::make_unique<Handler>(*owned);
  Connection* raw = owned.get();
  connections_.emplace(raw->id, std::move(owned));
  return *raw;
}

MvfstAdapter::Connection* MvfstAdapter::createServerConnection(
    const ReceivedPacket& packet, AdapterError& error)
{
  const auto* bytes = reinterpret_cast<const uint8_t*>(packet.bytes.data());
  if (packet.bytes.size() < 7 || !(bytes[0] & 0x80))
  {
    error = {5, "mvfst server requires an initial long-header packet"};
    return nullptr;
  }
  const size_t destinationLength = bytes[5];
  const size_t sourceLengthOffset = 6 + destinationLength;
  if (destinationLength > quic::kMaxConnectionIdSize ||
      sourceLengthOffset >= packet.bytes.size())
  {
    error = {5, "mvfst initial destination connection ID is malformed"};
    return nullptr;
  }
  const size_t sourceLength = bytes[sourceLengthOffset];
  if (sourceLength > quic::kMaxConnectionIdSize ||
      sourceLengthOffset + 1 + sourceLength > packet.bytes.size())
  {
    error = {5, "mvfst initial source connection ID is malformed"};
    return nullptr;
  }
  const std::vector<uint8_t> destinationBytes(
      bytes + 6, bytes + 6 + destinationLength);
  const std::vector<uint8_t> sourceBytes(
      bytes + sourceLengthOffset + 1,
      bytes + sourceLengthOffset + 1 + sourceLength);
  auto destination = quic::ConnectionId::create(destinationBytes);
  auto source = quic::ConnectionId::create(sourceBytes);
  if (destination.hasError() || source.hasError())
  {
    error = {5, "mvfst initial connection ID is invalid"};
    return nullptr;
  }

  auto& connection = createConnection(packet.peer);
  connection.connectionIdAlgorithm = std::make_unique<quic::DefaultConnectionIdAlgo>();
  auto network = std::make_unique<MvfstNetworkSocket>(
      *this, quicEventBase_, localAddress_);
  connection.server = std::make_shared<quic::QuicServerTransport>(
      quicEventBase_, std::move(network), connection.handler.get(), connection.handler.get(),
      serverContext_, nullptr, true);
  connection.socket = connection.server;
  connection.handler->setSocket(connection.socket);
  connection.server->setConnectionIdAlgo(connection.connectionIdAlgorithm.get());
  connection.server->setServerConnectionIdParams(quic::ServerConnectionIdParams(1, 1, 0));
  connection.server->setCongestionControllerFactory(congestionControllerFactory_);
  connection.server->setTransportSettings(transportSettings(false));
  connection.server->setEarlyDataAppParamsHandler(&earlyDataParameters_);
  connection.server->setClientConnectionId(*source);
  connection.server->setClientChosenDestConnectionId(*destination);
  connection.server->setOriginalPeerAddress(socketAddress(packet.peer));
  connection.server->accept(quic::QuicVersion::QUIC_V1);
  rememberConnectionIds(connection);
  acceptedConnections_.push_back(connection.id);
  error = {};
  return &connection;
}

MvfstAdapter::Connection* MvfstAdapter::find(uint64_t id, AdapterError& error) const
{
  const auto found = connections_.find(id);
  if (found != connections_.end()) return found->second.get();
  error = {3, "unknown mvfst connection"};
  return nullptr;
}

MvfstAdapter::Stream* MvfstAdapter::findStream(Connection& connection, uint64_t id,
                                               AdapterError& error)
{
  const auto found = connection.streams.find(id);
  if (found != connection.streams.end()) return &found->second;
  error = {4, "unknown mvfst stream"};
  return nullptr;
}

void MvfstAdapter::Handler::setSocket(std::shared_ptr<quic::QuicSocket> socket)
{
  connection_.socket = std::move(socket);
  if (connection_.socket && connection_.socket->setDatagramCallback(this).hasError())
    connection_.failed = true;
}

void MvfstAdapter::Handler::onConnectionSetupError(quic::QuicError) noexcept
{
  connection_.failed = true;
}
void MvfstAdapter::Handler::onTransportReady() noexcept { connection_.transportReady = true; }
void MvfstAdapter::Handler::onReplaySafe() noexcept { connection_.handshakeDone = true; }
void MvfstAdapter::Handler::onFullHandshakeDone() noexcept { connection_.handshakeDone = true; }

void MvfstAdapter::Handler::onNewBidirectionalStream(quic::StreamId id) noexcept
{
  connection_.streams.try_emplace(id);
  connection_.acceptedBidi.push_back(id);
  if (connection_.socket->setReadCallback(id, this).hasError()) connection_.failed = true;
}

void MvfstAdapter::Handler::onNewUnidirectionalStream(quic::StreamId id) noexcept
{
  connection_.streams.try_emplace(id);
  connection_.acceptedUni.push_back(id);
  if (connection_.socket->setReadCallback(id, this).hasError()) connection_.failed = true;
}

void MvfstAdapter::Handler::onStopSending(
    quic::StreamId id, quic::ApplicationErrorCode applicationError) noexcept
{
  auto& stream = connection_.streams[id];
  stream.remoteStop = true;
  stream.remoteStopError = applicationError;
}

void MvfstAdapter::Handler::onConnectionEnd() noexcept { connection_.ended = true; }
void MvfstAdapter::Handler::onConnectionEnd(quic::QuicError error) noexcept
{
  connection_.ended = true;
  if (connection_.localCloseRequested) return;
  if (const auto* applicationError = error.code.asApplicationErrorCode())
  {
    connection_.peerConnectionClose = true;
    connection_.peerConnectionCloseError = *applicationError;
    connection_.peerConnectionCloseReasonLength = error.message.size();
    for (auto& [_, stream] : connection_.streams)
    {
      stream.remoteReset = false;
      stream.remoteResetError = 0;
    }
  }
}
void MvfstAdapter::Handler::onConnectionError(quic::QuicError error) noexcept
{
  connection_.failed = true;
  if (connection_.localCloseRequested) return;
  if (const auto* applicationError = error.code.asApplicationErrorCode())
  {
    connection_.peerConnectionClose = true;
    connection_.peerConnectionCloseError = *applicationError;
    connection_.peerConnectionCloseReasonLength = error.message.size();
  }
}
void MvfstAdapter::Handler::readAvailable(quic::StreamId id) noexcept
{
  connection_.owner->drainStream(connection_, id);
}
void MvfstAdapter::Handler::readError(quic::StreamId id, quic::QuicError error) noexcept
{
  auto& stream = connection_.streams[id];
  if (!connection_.localCloseRequested)
    if (const auto* applicationError = error.code.asApplicationErrorCode())
    {
      stream.remoteReset = true;
      stream.remoteResetError = *applicationError;
    }
  stream.readClosed = true;
}
void MvfstAdapter::Handler::onDatagramsAvailable() noexcept
{
  connection_.owner->drainDatagrams(connection_);
}

void MvfstAdapter::drainStream(Connection& connection, uint64_t id)
{
  auto found = connection.streams.find(id);
  if (found == connection.streams.end()) return;
  for (;;)
  {
    auto result = connection.socket->read(id, 64 * 1024);
    if (result.hasError()) break;
    if (result->first)
    {
      auto bytes = result->first->coalesce();
      const auto* first = reinterpret_cast<const std::byte*>(bytes.data());
      found->second.received.insert(found->second.received.end(), first, first + bytes.size());
    }
    if (result->second)
    {
      found->second.remoteFin = true;
      connection.socket->setReadCallback(
          id, nullptr, quic::Optional<quic::ApplicationErrorCode> {});
      break;
    }
    if (!result->first) break;
  }
}

void MvfstAdapter::drainDatagrams(Connection& connection)
{
  auto result = connection.socket->readDatagramBufs();
  if (result.hasError()) { connection.failed = true; return; }
  for (auto& buffer : *result)
  {
    auto bytes = buffer->coalesce();
    const auto* first = reinterpret_cast<const std::byte*>(bytes.data());
    connection.datagrams.emplace_back(first, first + bytes.size());
  }
}

void MvfstAdapter::deliver(Connection& connection, const ReceivedPacket& packet)
{
  auto bytes = folly::IOBuf::copyBuffer(packet.bytes.data(), packet.bytes.size());
  quic::ReceivedUdpPacket received(std::move(bytes));
  received.timings.receiveTimePoint = quic::Clock::now();
  quic::NetworkData data(std::move(received));
  if (connection.server)
    connection.server->onNetworkData(socketAddress(localAddress_), std::move(data),
                                     socketAddress(packet.peer));
  else if (connection.client)
    connection.client->onNetworkData(socketAddress(localAddress_), std::move(data),
                                     socketAddress(packet.peer));
  rememberConnectionIds(connection);
}

void MvfstAdapter::rememberConnectionIds(Connection& connection)
{
  if (!connection.socket) return;
  const auto remember = [&](const quic::Optional<quic::ConnectionId>& id) {
    if (id && id->size())
      connectionsByCid_[std::string(
          reinterpret_cast<const char*>(id->data()), id->size())] = &connection;
  };
  remember(connection.socket->getClientConnectionId());
  remember(connection.socket->getServerConnectionId());
  remember(connection.socket->getClientChosenDestConnectionId());
  if (const auto* state = connection.socket->getState())
    for (const auto& id : state->selfConnectionIds) remember(id.connId);
}

MvfstAdapter::Connection* MvfstAdapter::route(const ReceivedPacket& packet) const
{
  if (packet.bytes.size() < 2) return nullptr;
  const auto* bytes = reinterpret_cast<const uint8_t*>(packet.bytes.data());
  if (bytes[0] & 0x80)
  {
    if (packet.bytes.size() < 6) return nullptr;
    const size_t length = bytes[5];
    if (length > 20 || packet.bytes.size() < 6 + length) return nullptr;
    const auto found = connectionsByCid_.find(std::string(
        reinterpret_cast<const char*>(bytes + 6), length));
    return found == connectionsByCid_.end() ? nullptr : found->second;
  }
  for (const auto& [cid, connection] : connectionsByCid_)
    if (packet.bytes.size() >= 1 + cid.size() &&
        std::memcmp(bytes + 1, cid.data(), cid.size()) == 0) return connection;
  return nullptr;
}

void MvfstAdapter::updateResumption(Connection& connection)
{
  if (!connection.client) return;
  connection.resumed = connection.resumed || (connection.imported && connection.client->isTLSResumed());
  switch (connection.client->getZeroRttState())
  {
    case quic::QuicClientTransportLite::ZeroRttAttemptState::Accepted:
      connection.earlyAttempted = true;
      connection.earlyAccepted = true;
      connection.resumed = true;
      break;
    case quic::QuicClientTransportLite::ZeroRttAttemptState::Rejected:
      connection.earlyAttempted = true;
      connection.earlyRejected = true;
      break;
    case quic::QuicClientTransportLite::ZeroRttAttemptState::NotAttempted:
      break;
  }
}

bool MvfstAdapter::setCallerTime(uint64_t nowRawNs, AdapterError& error)
{
  if (!quic::Clock::setNowRawNanoseconds(nowRawNs))
  {
    error = {14, "mvfst caller monotonic time is zero, out of range, or regressed"};
    return false;
  }
  lastCallerTimeRawNs_ = nowRawNs;
  if (quicEventBase_) quicEventBase_->setNow(nowRawNs);
  return true;
}

void MvfstAdapter::restoreCallerTimeForSnapshot() const noexcept
{
  if (lastCallerTimeRawNs_)
    (void)quic::Clock::setNowRawNanoseconds(lastCallerTimeRawNs_);
}

bool MvfstAdapter::drive(uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  quicEventBase_->loop();
  for (auto& [_, connection] : connections_)
  {
    updateResumption(*connection);
    // mvfst can issue or activate additional self connection IDs from event-
    // loop callbacks rather than directly while processing an input packet.
    // Refresh the external packet router after each callback batch.
    rememberConnectionIds(*connection);
  }
  nextTimeoutRawNs_ = quicEventBase_->nextDeadline().value_or(0);
  return true;
}

bool MvfstAdapter::receiveBatch(std::span<const ReceivedPacket> packets, uint64_t nowRawNs,
                                AdapterError& error)
{
  if (!configured_ || !localAddressSet_) { error = {5, "mvfst adapter is not ready"}; return false; }
  if (!setCallerTime(nowRawNs, error)) return false;
  for (const auto& packet : packets)
  {
    if (packet.peer.sin_family != AF_INET || packet.bytes.empty())
    {
      error = {5, "invalid mvfst received packet"};
      return false;
    }
    Connection* connection = route(packet);
    if (config_.role == EndpointRole::server)
    {
      if (!connection && !(std::to_integer<uint8_t>(packet.bytes.front()) & 0x80))
      {
        // Short-header packets do not carry enough information to create or
        // recover connection state. A server dispatcher must drop an unknown
        // destination (including stateless resets and late retired traffic).
        ++counters_.packetsReceived;
        continue;
      }
      else if (!connection) connection = createServerConnection(packet, error);
    }
    else if (!connection && connections_.size() == 1)
      connection = connections_.begin()->second.get();
    if (!connection)
    {
      if (error.message.empty()) error = {5, "mvfst has no connection for received packet"};
      return false;
    }
    deliver(*connection, packet);
    ++counters_.packetsReceived;
  }
  if (!drive(nowRawNs, error)) return false;
  error = {};
  return true;
}

size_t MvfstAdapter::pollTransmitBatch(std::span<TransmitPacket> packets,
                                       uint64_t nowRawNs, AdapterError& error)
{
  if (!configured_ || !localAddressSet_) { error = {6, "mvfst adapter is not ready"}; return 0; }
  if (!drive(nowRawNs, error)) return 0;
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

bool MvfstAdapter::onTimeout(uint64_t nowRawNs, AdapterError& error)
{
  if (!configured_) { error = {7, "mvfst adapter is not configured"}; return false; }
  if (!drive(nowRawNs, error)) return false;
  error = {};
  return true;
}

bool MvfstAdapter::connect(const sockaddr_in& peer, uint64_t nowRawNs,
                           uint64_t& connectionId, AdapterError& error)
{
  if (!configured_ || !localAddressSet_ || config_.role != EndpointRole::client ||
      peer.sin_family != AF_INET)
  {
    error = {8, "mvfst connect requires a configured client and IPv4 peer"};
    return false;
  }
  if (!setCallerTime(nowRawNs, error)) return false;
  auto& connection = createConnection(peer);
  bool zeroRtt = false;
  if (importedState_)
  {
    auto psk = exportedPsks_.extract(importedState_->key);
    if (psk.empty())
    {
      error = {8, "mvfst resumption state is no longer available"};
      return false;
    }
    consumedPskIdentities_.insert(psk.mapped().psk.cachedPsk.psk);
    pskCache_->putImported(config_.tlsHostname, std::move(psk.mapped().psk));
    connection.imported = true;
    zeroRtt = importedState_->zeroRtt;
    importedState_.reset();
  }
  auto network = std::make_unique<MvfstNetworkSocket>(*this, quicEventBase_, localAddress_);
  connection.client = quic::QuicClientTransport::newClient(
      quicEventBase_, std::move(network), clientContext_, config_.connectionIdBytes, true);
  connection.socket = connection.client;
  connection.handler->setSocket(connection.socket);
  connection.client->setSupportedVersions({quic::QuicVersion::QUIC_V1});
  connection.client->setHostname(config_.tlsHostname);
  connection.client->addNewPeerAddress(socketAddress(peer));
  connection.client->setCongestionControllerFactory(congestionControllerFactory_);
  connection.client->setTransportSettings(transportSettings(zeroRtt));
  connection.client->setEarlyDataAppParamsHandler(&earlyDataParameters_);
  connection.client->start(connection.handler.get(), connection.handler.get());
  rememberConnectionIds(connection);
  connection.earlyAttempted = zeroRtt && connection.client->hasZeroRttWriteCipher();
  connectionId = connection.id;
  if (!drive(nowRawNs, error)) return false;
  error = {};
  return true;
}

PrimitiveStatus MvfstAdapter::acceptConnection(uint64_t nowRawNs, uint64_t& connectionId,
                                                AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  if (config_.role != EndpointRole::server) return unavailable("acceptConnection", error);
  if (acceptedConnections_.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  connectionId = acceptedConnections_.front();
  acceptedConnections_.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

bool MvfstAdapter::isConnected(uint64_t connectionId, uint64_t nowRawNs, bool& connected,
                               AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  connected = connection->handshakeDone && !connection->ended && !connection->failed &&
      (config_.role == EndpointRole::server || connection->imported ||
       (pskCache_ && pskCache_->hasIssued()));
  error = {};
  return true;
}

bool MvfstAdapter::connectionIsClosed(uint64_t connectionId, uint64_t nowRawNs,
                                      bool& closed, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  closed = connection->ended || connection->failed || connection->peerConnectionClose;
  error = {};
  return true;
}

bool MvfstAdapter::peerTerminalFacts(uint64_t connectionId, uint64_t streamId,
                                     uint64_t nowRawNs, PeerTerminalFacts& facts,
                                     AdapterError& error)
{
  facts = {};
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  facts.available = true;
  facts.connectionClose = connection->peerConnectionClose;
  facts.connectionCloseError = connection->peerConnectionCloseError;
  facts.connectionCloseReasonLength = connection->peerConnectionCloseReasonLength;
  if (const auto stream = connection->streams.find(streamId);
      stream != connection->streams.end())
  {
    facts.fin = stream->second.remoteFin;
    facts.resetStream = stream->second.remoteReset;
    facts.stopSending = stream->second.remoteStop;
    facts.resetStreamError = stream->second.remoteResetError;
    facts.stopSendingError = stream->second.remoteStopError;
    stream->second.remoteFin = false;
    stream->second.remoteReset = false;
    stream->second.remoteStop = false;
  }
  connection->peerConnectionClose = false;
  error = {};
  return true;
}

PrimitiveStatus MvfstAdapter::openStream(uint64_t connectionId, bool unidirectional,
                                         uint64_t nowRawNs,
                                         uint64_t& streamId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  auto result = unidirectional ? connection->socket->createUnidirectionalStream(
      !connection->earlyAttempted) : connection->socket->createBidirectionalStream(
      !connection->earlyAttempted);
  if (result.hasError()) { error = {}; return PrimitiveStatus::wouldBlock; }
  streamId = *result;
  connection->streams.try_emplace(streamId);
  if (!unidirectional &&
      connection->socket->setReadCallback(streamId, connection->handler.get()).hasError())
  {
    error = {9, "mvfst setReadCallback failed"};
    return PrimitiveStatus::fatal;
  }
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus MvfstAdapter::openBidirectionalStream(uint64_t connectionId,
                                                      uint64_t nowRawNs,
                                                      uint64_t& streamId,
                                                      AdapterError& error)
{
  return openStream(connectionId, false, nowRawNs, streamId, error);
}
PrimitiveStatus MvfstAdapter::openUnidirectionalStream(uint64_t connectionId,
                                                       uint64_t nowRawNs,
                                                       uint64_t& streamId,
                                                       AdapterError& error)
{
  return openStream(connectionId, true, nowRawNs, streamId, error);
}

PrimitiveStatus MvfstAdapter::acceptStream(uint64_t connectionId, bool unidirectional,
                                           uint64_t nowRawNs,
                                           uint64_t& streamId, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  auto& queue = unidirectional ? connection->acceptedUni : connection->acceptedBidi;
  if (queue.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  streamId = queue.front();
  queue.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus MvfstAdapter::acceptBidirectionalStream(uint64_t connectionId,
                                                        uint64_t nowRawNs,
                                                        uint64_t& streamId,
                                                        AdapterError& error)
{
  return acceptStream(connectionId, false, nowRawNs, streamId, error);
}
PrimitiveStatus MvfstAdapter::acceptUnidirectionalStream(uint64_t connectionId,
                                                         uint64_t nowRawNs,
                                                         uint64_t& streamId,
                                                         AdapterError& error)
{
  return acceptStream(connectionId, true, nowRawNs, streamId, error);
}

bool MvfstAdapter::writeStream(uint64_t connectionId, uint64_t streamId,
                               std::span<const std::byte> bytes, uint64_t nowRawNs,
                               size_t& written, AdapterError& error)
{
  written = 0;
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection || !findStream(*connection, streamId, error)) return false;
  auto writable = connection->socket->getMaxWritableOnStream(streamId);
  if (writable.hasError())
  {
    error = {9, "mvfst could not query stream write capacity"};
    return false;
  }
  const size_t accepted = static_cast<size_t>(
      std::min<uint64_t>(bytes.size(), *writable));
  if (accepted == 0) { error = {}; return true; }
  auto result = connection->socket->writeChain(
      streamId, folly::IOBuf::copyBuffer(bytes.data(), accepted), false);
  if (result.hasError()) { error = {}; return true; }
  written = accepted;
  error = {};
  return true;
}

bool MvfstAdapter::consumeStreamData(uint64_t connectionId, uint64_t streamId,
                                     std::span<std::byte> bytes, uint64_t nowRawNs,
                                     size_t& read, bool& finished, AdapterError& error)
{
  read = 0;
  finished = false;
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  auto* stream = findStream(*connection, streamId, error);
  if (!stream) return false;
  if (!stream->readClosed) drainStream(*connection, streamId);
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

bool MvfstAdapter::finishStream(uint64_t connectionId, uint64_t streamId,
                                uint64_t nowRawNs,
                                AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection || !findStream(*connection, streamId, error)) return false;
  if (connection->socket->writeChain(streamId, folly::IOBuf::create(0), true).hasError())
  {
    error = {10, "mvfst stream FIN failed"};
    return false;
  }
  error = {};
  return true;
}

bool MvfstAdapter::resetStream(uint64_t connectionId, uint64_t streamId,
                               uint64_t applicationError, uint64_t nowRawNs,
                               AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection || !findStream(*connection, streamId, error)) return false;
  if (connection->socket->resetStream(streamId, applicationError).hasError())
  {
    error = {11, "mvfst resetStream failed"};
    return false;
  }
  error = {};
  return true;
}

bool MvfstAdapter::stopSending(uint64_t connectionId, uint64_t streamId,
                               uint64_t applicationError, uint64_t nowRawNs,
                               AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection || !findStream(*connection, streamId, error)) return false;
  if (connection->socket->stopSending(streamId, applicationError).hasError())
  {
    error = {12, "mvfst stopSending failed"};
    return false;
  }
  error = {};
  return true;
}

PrimitiveStatus MvfstAdapter::sendDatagram(uint64_t connectionId,
                                           std::span<const std::byte> bytes,
                                           uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  if (!connection->transportReady) { error = {}; return PrimitiveStatus::wouldBlock; }
  if (connection->socket->writeDatagram(
      folly::IOBuf::copyBuffer(bytes.data(), bytes.size())).hasError())
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus MvfstAdapter::consumeDatagram(uint64_t connectionId,
                                              std::span<std::byte> bytes,
                                              uint64_t nowRawNs, size_t& read,
                                              AdapterError& error)
{
  read = 0;
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  drainDatagrams(*connection);
  if (connection->datagrams.empty()) { error = {}; return PrimitiveStatus::wouldBlock; }
  auto& datagram = connection->datagrams.front();
  if (datagram.size() > bytes.size()) return unavailable("DATAGRAM destination capacity", error);
  read = datagram.size();
  std::copy(datagram.begin(), datagram.end(), bytes.begin());
  connection->datagrams.pop_front();
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus MvfstAdapter::exportResumptionState(uint64_t connectionId,
                                                    uint64_t nowRawNs,
                                                    std::span<std::byte> bytes,
                                                    size_t& written,
                                                    AdapterError& error)
{
  written = 0;
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  auto* connection = find(connectionId, error);
  if (!connection) return PrimitiveStatus::fatal;
  auto psk = pskCache_ ? pskCache_->takeIssued() :
      quic::Optional<quic::QuicCachedPsk> {};
  if (!psk.has_value()) { error = {}; return PrimitiveStatus::wouldBlock; }
  const auto& identity = psk->cachedPsk.psk;
  if (consumedPskIdentities_.contains(identity) ||
      std::ranges::any_of(exportedPsks_, [&identity](const auto& entry) {
        return entry.second.psk.cachedPsk.psk == identity;
      }))
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }
  if (bytes.size() < 12) return unavailable("resumption export destination capacity", error);
  const uint64_t key = nextPskId_++;
  exportedPsks_.emplace(key, ExportedPsk {std::move(*psk), nowRawNs});
  storeU32(bytes.data(), resumptionMagic);
  storeU64(bytes.data() + 4, key);
  written = 12;
  error = {};
  return PrimitiveStatus::ready;
}

PrimitiveStatus MvfstAdapter::importResumptionState(std::span<const std::byte> bytes,
                                                    bool useZeroRtt, uint64_t nowRawNs,
                                                    AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return PrimitiveStatus::fatal;
  if (bytes.size() != 12 || loadU32(bytes.data()) != resumptionMagic || importedState_)
    return unavailable("valid one-shot in-process resumption state", error);
  const uint64_t key = loadU64(bytes.data() + 4);
  const auto state = exportedPsks_.find(key);
  if (state == exportedPsks_.end()) return unavailable("known resumption state", error);
  if (nowRawNs < state->second.issuedRawNs ||
      nowRawNs - state->second.issuedRawNs >= config_.tlsTicketLifetimeNs)
  {
    exportedPsks_.erase(state);
    return unavailable("unexpired resumption state", error);
  }
  importedState_ = std::make_unique<ImportedState>(ImportedState {key, useZeroRtt});
  error = {};
  return PrimitiveStatus::ready;
}

bool MvfstAdapter::connectionResumed(uint64_t connectionId, uint64_t nowRawNs,
                                     bool& resumed,
                                     AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  updateResumption(*connection);
  resumed = connection->resumed;
  error = {};
  return true;
}
bool MvfstAdapter::zeroRttAttempted(uint64_t connectionId, uint64_t nowRawNs,
                                    bool& attempted,
                                    AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  updateResumption(*connection);
  attempted = connection->earlyAttempted;
  error = {};
  return true;
}
bool MvfstAdapter::zeroRttAccepted(uint64_t connectionId, uint64_t nowRawNs,
                                   bool& accepted,
                                   AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  updateResumption(*connection);
  accepted = connection->earlyAccepted;
  error = {};
  return true;
}
bool MvfstAdapter::zeroRttRejected(uint64_t connectionId, uint64_t nowRawNs,
                                   bool& rejected,
                                   AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  updateResumption(*connection);
  rejected = connection->earlyRejected;
  error = {};
  return true;
}

bool MvfstAdapter::closeConnection(uint64_t connectionId, uint64_t applicationError,
                                   uint64_t nowRawNs, AdapterError& error)
{
  if (!setCallerTime(nowRawNs, error)) return false;
  auto* connection = find(connectionId, error);
  if (!connection) return false;
  connection->localCloseRequested = true;
  connection->socket->closeNow(quic::QuicError(
      quic::QuicErrorCode(quic::ApplicationErrorCode(applicationError)), ""));
  error = {};
  return true;
}

TransportCounters MvfstAdapter::snapshotTransportCounters() const noexcept
{
  restoreCallerTimeForSnapshot();
  TransportCounters result = counters_;
  uint64_t lost = 0;
  uint64_t retransmitted = 0;
  uint64_t recoveryWakeups = 0;
  uint64_t flowControlBlockedEvents = 0;
  uint64_t streamCreditBlockedEvents = 0;
  for (const auto& [_, connection] : connections_)
  {
    if (!connection->socket) continue;
    const auto info = connection->socket->getTransportInfo();
    lost += info.totalPacketsMarkedLost;
    retransmitted += info.packetsRetransmitted;
    recoveryWakeups += info.totalPTOCount;
    flowControlBlockedEvents += info.dataBlockedFramesSent;
    streamCreditBlockedEvents += info.streamDataBlockedFramesSent;
  }
  result.packetsLost = lost;
  result.packetsRetransmitted = retransmitted;
  result.recoveryWakeups = recoveryWakeups;
  result.flowControlBlockedEvents = flowControlBlockedEvents;
  result.streamCreditBlockedEvents = streamCreditBlockedEvents;
  result.timerExpirations = quicEventBase_ ? quicEventBase_->timerExpirations() : 0;
  return result;
}

NegotiatedSettings MvfstAdapter::snapshotNegotiatedSettings() const noexcept
{
  restoreCallerTimeForSnapshot();
  NegotiatedSettings result;
  result.evidenceSource =
      "mvfst QuicSocket post-handshake TLS summary, connection IDs, transport parameters, and stats";
  const auto unavailable = [&result](std::string field) {
    if (std::ranges::find(result.unavailableFields, field) == result.unavailableFields.end())
      result.unavailableFields.push_back(std::move(field));
  };
  const auto activeForEvidence = [](const Connection& candidate) {
    return candidate.socket && candidate.handshakeDone && !candidate.ended &&
        !candidate.failed && !candidate.localCloseRequested &&
        !candidate.peerConnectionClose;
  };
  const Connection* connection = nullptr;
  for (const auto& [_, candidate] : connections_)
  {
    if (activeForEvidence(*candidate))
    {
      connection = candidate.get();
      break;
    }
  }
  if (!connection)
  {
    unavailable("no_post_handshake_connection");
    return result;
  }

  const auto tls = connection->socket->getTLSSummary();
  const auto peer = connection->socket->getPeerTransportParams();
  if (!tls) unavailable("tls_summary");
  if (!peer) unavailable("peer_transport_parameters");
  if (!tls || !peer) return result;
  result.available = true;
  result.quicVersion = connection->socket->getConnectionsStats().version;
  result.alpn = tls->alpn;
  result.tlsVersion = tls->tlsVersion;
  result.tlsCipherSuite = tls->cipherSuite;
  if (tls->namedGroup == "x25519") result.tlsKeyExchange = "X25519";
  else if (tls->namedGroup == "secp256r1") result.tlsKeyExchange = "P-256";
  else result.tlsKeyExchange = tls->namedGroup;

  const auto certificate = config_.role == EndpointRole::client ?
      connection->socket->getPeerCertificate() :
      connection->socket->getSelfCertificate();
  auto x509 = folly::OpenSSLTransportCertificate::tryExtractX509(certificate.get());
  if (!x509) unavailable("tls_leaf_signature");
  else
  {
    const int signature = X509_get_signature_nid(x509.get());
    if (signature == NID_ED25519) result.tlsLeafSignature = "Ed25519";
    else if (const char* name = OBJ_nid2sn(signature)) result.tlsLeafSignature = name;
    else unavailable("tls_leaf_signature");
  }
  result.peerCertificateVerified = config_.role == EndpointRole::client &&
      config_.tlsVerifyPeer && certificateVerifier_ && certificateVerifier_->verified();
  result.hostnameVerified = result.peerCertificateVerified;

  const auto integer = [&](quic::TransportParameterId id,
                           std::string_view field,
                           std::optional<uint64_t> defaultValue = std::nullopt) -> uint64_t {
    auto value = quic::getIntegerParameter(id, *peer);
    if (value.hasError())
    {
      unavailable(std::string(field));
      return 0;
    }
    if (!value.value())
    {
      if (defaultValue) return *defaultValue;
      unavailable(std::string(field));
      return 0;
    }
    return *value.value();
  };
  result.maxUdpPayloadSize = integer(
      quic::TransportParameterId::max_packet_size, "max_udp_payload_size");
  const auto maxAckDelay = quic::getIntegerParameter(
      quic::TransportParameterId::max_ack_delay, *peer);
  if (maxAckDelay.hasError()) unavailable("max_ack_delay_ns");
  else result.maxAckDelayNs = maxAckDelay.value().value_or(25) * 1'000'000ULL;
  result.ackDelayExponent = integer(
      quic::TransportParameterId::ack_delay_exponent, "ack_delay_exponent", 3);
  result.ackFrequency = quic::findParameter(
      *peer, quic::TransportParameterId::min_ack_delay) != peer->end();
  const auto& local = connection->socket->getTransportSettings();
  result.activeMigration = config_.role == EndpointRole::server ?
      !local.disableMigration :
      quic::findParameter(*peer, quic::TransportParameterId::disable_migration) == peer->end();
  result.activeConnectionIdLimit = integer(
      quic::TransportParameterId::active_connection_id_limit,
      "active_connection_id_limit", 2);
  result.maxIdleTimeoutNs = integer(
      quic::TransportParameterId::idle_timeout, "max_idle_timeout_ns") * 1'000'000ULL;
  result.maxBidiStreams = integer(
      quic::TransportParameterId::initial_max_streams_bidi, "max_bidi_streams");
  result.maxUniStreams = integer(
      quic::TransportParameterId::initial_max_streams_uni, "max_uni_streams");
  result.connectionWindowBytes = integer(
      quic::TransportParameterId::initial_max_data, "connection_window_bytes");
  const uint64_t peerBidiLocal = integer(
      quic::TransportParameterId::initial_max_stream_data_bidi_local,
      "stream_window_bytes");
  const uint64_t peerBidiRemote = integer(
      quic::TransportParameterId::initial_max_stream_data_bidi_remote,
      "stream_window_bytes");
  result.streamWindowBytes = std::min(peerBidiLocal, peerBidiRemote);
  result.datagramMaxFrameSize = integer(
      quic::TransportParameterId::max_datagram_frame_size,
      "datagram_max_frame_size");

  const auto connectionId = config_.role == EndpointRole::client ?
      connection->socket->getServerConnectionId() :
      connection->socket->getClientConnectionId();
  if (connectionId) result.connectionIdBytes = connectionId->size();
  else unavailable("connection_id_bytes");

  switch (connection->socket->getTransportInfo().congestionControlType)
  {
    case quic::CongestionControlType::Cubic:
      result.congestionController = "cubic";
      break;
    case quic::CongestionControlType::BBR:
      result.congestionController = "bbr";
      break;
    default:
      unavailable("congestion_controller");
      break;
  }
  result.initialCongestionWindowBytes = local.initCwndInBytes ?
      local.initCwndInBytes :
      local.initCwndInMss * connection->socket->getTransportInfo().mss;
  result.streamCreditReplenishBelow = local.streamCreditReplenishBelow;
  if (config_.role == EndpointRole::server)
  {
    result.ticketLifetimeNs = config_.tlsTicketLifetimeNs;
    if (!serverContext_ ||
        serverContext_->getMaxEarlyDataSize() != std::numeric_limits<uint32_t>::max())
      unavailable("quic_early_data_wire_sentinel");
    result.maximumEarlyDataBytes = config_.tlsMaximumEarlyDataBytes;
  }
  else
  {
    const auto psk = pskCache_ ? pskCache_->getPsk(config_.tlsHostname) :
        quic::Optional<quic::QuicCachedPsk> {};
    if (!psk) unavailable("ticket_lifetime_ns");
    else
    {
      const auto lifetime = std::chrono::duration_cast<std::chrono::nanoseconds>(
          psk->cachedPsk.ticketExpirationTime - psk->cachedPsk.ticketIssueTime).count();
      if (lifetime <= 0) unavailable("ticket_lifetime_ns");
      else result.ticketLifetimeNs = static_cast<uint64_t>(lifetime);
      if (psk->cachedPsk.maxEarlyDataSize != std::numeric_limits<uint32_t>::max())
        unavailable("quic_early_data_wire_sentinel");
      result.maximumEarlyDataBytes = config_.tlsMaximumEarlyDataBytes;
    }
  }
  result.oneUseTickets = config_.tlsOneUseTickets;

  for (const auto& [_, candidate] : connections_)
  {
    if (!activeForEvidence(*candidate)) continue;
    const auto routesToCandidate = [&](const quic::Optional<quic::ConnectionId>& id) {
      if (!id || !id->size()) return true;
      const auto found = connectionsByCid_.find(std::string(
          reinterpret_cast<const char*>(id->data()), id->size()));
      return found != connectionsByCid_.end() && found->second == candidate.get();
    };
    if (!routesToCandidate(candidate->socket->getClientConnectionId()) ||
        !routesToCandidate(candidate->socket->getServerConnectionId()) ||
        !routesToCandidate(candidate->socket->getClientChosenDestConnectionId()))
    {
      unavailable("connection_settings_disagree");
      break;
    }
    if (candidate.get() == connection) continue;
    const auto candidateTls = candidate->socket->getTLSSummary();
    const auto candidatePeer = candidate->socket->getPeerTransportParams();
    if (!candidateTls || !candidatePeer)
    {
      unavailable("connection_settings_disagree");
      break;
    }
    const auto equalInteger = [&](quic::TransportParameterId id,
                                  uint64_t expected,
                                  std::optional<uint64_t> defaultValue = std::nullopt) {
      const auto value = quic::getIntegerParameter(id, *candidatePeer);
      return !value.hasError() &&
          (value.value() ? *value.value() == expected :
                           defaultValue && *defaultValue == expected);
    };
    const auto candidateInteger = [&](quic::TransportParameterId id)
        -> std::optional<uint64_t> {
      const auto value = quic::getIntegerParameter(id, *candidatePeer);
      if (value.hasError() || !value.value()) return std::nullopt;
      return *value.value();
    };
    const auto candidateMaxAck = quic::getIntegerParameter(
        quic::TransportParameterId::max_ack_delay, *candidatePeer);
    const auto candidateConnectionId = config_.role == EndpointRole::client ?
        candidate->socket->getServerConnectionId() :
        candidate->socket->getClientConnectionId();
    const auto candidateCertificate = config_.role == EndpointRole::client ?
        candidate->socket->getPeerCertificate() :
        candidate->socket->getSelfCertificate();
    auto candidateX509 = folly::OpenSSLTransportCertificate::tryExtractX509(
        candidateCertificate.get());
    const auto& candidateLocal = candidate->socket->getTransportSettings();
    const auto candidateInfo = candidate->socket->getTransportInfo();
    const bool candidateActiveMigration = config_.role == EndpointRole::server ?
        !candidateLocal.disableMigration :
        quic::findParameter(*candidatePeer, quic::TransportParameterId::disable_migration) ==
            candidatePeer->end();
    const bool candidateAckFrequency = quic::findParameter(
        *candidatePeer, quic::TransportParameterId::min_ack_delay) != candidatePeer->end();
    const std::string candidateKeyExchange = candidateTls->namedGroup == "x25519" ?
        "X25519" : candidateTls->namedGroup == "secp256r1" ?
            "P-256" : candidateTls->namedGroup;
    const auto candidateBidiLocal = candidateInteger(
        quic::TransportParameterId::initial_max_stream_data_bidi_local);
    const auto candidateBidiRemote = candidateInteger(
        quic::TransportParameterId::initial_max_stream_data_bidi_remote);
    const uint64_t candidateInitialCwnd = candidateLocal.initCwndInBytes ?
        candidateLocal.initCwndInBytes : candidateLocal.initCwndInMss * candidateInfo.mss;
    const bool candidateCongestionMatches =
        (result.congestionController == "cubic" &&
         candidateInfo.congestionControlType == quic::CongestionControlType::Cubic) ||
        (result.congestionController == "bbr" &&
         candidateInfo.congestionControlType == quic::CongestionControlType::BBR);
    if (candidateTls->alpn != result.alpn ||
        candidateTls->tlsVersion != result.tlsVersion ||
        candidateTls->cipherSuite != result.tlsCipherSuite ||
        candidateKeyExchange != result.tlsKeyExchange || !candidateX509 ||
        X509_get_signature_nid(candidateX509.get()) != NID_ED25519 ||
        candidate->socket->getConnectionsStats().version != result.quicVersion ||
        !equalInteger(quic::TransportParameterId::max_packet_size,
                      result.maxUdpPayloadSize) ||
        candidateMaxAck.hasError() ||
        candidateMaxAck.value().value_or(25) * 1'000'000ULL != result.maxAckDelayNs ||
        !equalInteger(quic::TransportParameterId::ack_delay_exponent,
                      result.ackDelayExponent, 3) ||
        candidateAckFrequency != result.ackFrequency ||
        candidateActiveMigration != result.activeMigration ||
        !equalInteger(quic::TransportParameterId::active_connection_id_limit,
                      result.activeConnectionIdLimit, 2) ||
        !candidateConnectionId || candidateConnectionId->size() != result.connectionIdBytes ||
        !equalInteger(quic::TransportParameterId::idle_timeout,
                      result.maxIdleTimeoutNs / 1'000'000ULL) ||
        !equalInteger(quic::TransportParameterId::initial_max_streams_bidi,
                      result.maxBidiStreams) ||
        !equalInteger(quic::TransportParameterId::initial_max_streams_uni,
                      result.maxUniStreams) ||
        !equalInteger(quic::TransportParameterId::initial_max_data,
                      result.connectionWindowBytes) ||
        !candidateBidiLocal || !candidateBidiRemote ||
        std::min(*candidateBidiLocal, *candidateBidiRemote) != result.streamWindowBytes ||
        !equalInteger(quic::TransportParameterId::max_datagram_frame_size,
                      result.datagramMaxFrameSize) ||
        !candidateCongestionMatches || candidateInitialCwnd != result.initialCongestionWindowBytes ||
        candidateLocal.streamCreditReplenishBelow != result.streamCreditReplenishBelow)
    {
      unavailable("connection_settings_disagree");
      break;
    }
  }
  return result;
}

PrimitiveStatus MvfstAdapter::unavailable(std::string_view primitive,
                                          AdapterError& error) const
{
  error = {13, "mvfst cannot satisfy " + std::string(primitive)};
  return PrimitiveStatus::fatal;
}

bool MvfstAdapter::reset(AdapterError& error)
{
  if (lastCallerTimeRawNs_ && quicEventBase_)
  {
    quic::Clock::setNowRawNanoseconds(lastCallerTimeRawNs_);
    quicEventBase_->setNow(lastCallerTimeRawNs_);
  }
  for (auto& [_, connection] : connections_)
  {
    if (connection->socket)
      connection->socket->closeNow(quic::Optional<quic::QuicError> {});
  }
  if (quicEventBase_) quicEventBase_->loop();
  for (auto& [_, connection] : connections_)
  {
    if (connection->handler) connection->handler->setSocket(nullptr);
    connection->socket.reset();
    connection->client.reset();
    connection->server.reset();
  }
  connections_.clear();
  connectionsByCid_.clear();
  acceptedConnections_.clear();
  outputQueue_.clear();
  exportedPsks_.clear();
  consumedPskIdentities_.clear();
  importedState_.reset();
  serverContext_.reset();
  clientContext_.reset();
  pskCache_.reset();
  certificateVerifier_.reset();
  quicEventBase_.reset();
  nextConnectionId_ = 1;
  nextPskId_ = 1;
  nextTimeoutRawNs_ = 0;
  lastCallerTimeRawNs_ = 0;
  configured_ = false;
  localAddressSet_ = false;
  counters_ = {};
  quic::Clock::resetInjectedNow();
  error = {};
  return true;
}

} // namespace

std::unique_ptr<Adapter> makeTransportAdapter()
{
  return std::make_unique<MvfstAdapter>();
}

} // namespace quicperf
