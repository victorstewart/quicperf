#include "adapters/declared_adapter.h"
#include "core/event_loop.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>

namespace {

class EmptyPacketIo final : public quicperf::PacketIoDriver {
public:
  uint16_t bind(uint32_t, uint16_t) override { return 0; }
  std::span<const quicperf::ReceivedPacket> receive(uint64_t) override
  {
    ++receiveCalls;
    return {};
  }
  size_t send(std::span<const quicperf::TransmitPacket>, uint64_t) override
  {
    ++sendCalls;
    return 0;
  }
  void armLossRecovery(std::span<const uint8_t, 32>, uint64_t, uint64_t, uint8_t) override {}
  void resetLossRecovery() override {}
  void shareLossRecovery(std::shared_ptr<quicperf::LossRecoveryStream>) override {}
  bool hasPendingTransmit() const noexcept override { return false; }
  int wait(uint64_t) override
  {
    ++waitCalls;
    return 0;
  }
  int socketFd() const noexcept override { return -1; }
  std::vector<int> ownedFileDescriptors() const override { return {}; }
  const quicperf::PacketIoCounters& counters() const noexcept override { return counters_; }
  quicperf::PacketBackend backend() const noexcept override
  {
    return quicperf::PacketBackend::syscall;
  }

  uint64_t receiveCalls = 0;
  uint64_t sendCalls = 0;
  uint64_t waitCalls = 0;

private:
  quicperf::PacketIoCounters counters_ {};
};

} // namespace

int main()
{
  EmptyPacketIo packetIo;
  quicperf::DeclaredAdapter adapter("event-loop-contract");
  quicperf::EventLoop loop(
      packetIo, adapter,
      quicperf::ClockBridge(quicperf::ClockBridgeSample {0, 0, 0, 0, 0}));
  quicperf::AdapterError error;

  // The scheduling quantum has already expired. The loop must still perform
  // one nonblocking drive; expiration suppresses waiting, not transport work.
  assert(!loop.driveOnce(1, error));
  assert(packetIo.receiveCalls == 1);
  assert(packetIo.waitCalls == 0);
  assert(error.message == "unconfigured adapter");

  assert(quicperf::detail::waitRequired(
      true, true, false, false, 1, 2));
  assert(quicperf::detail::waitRequired(
      true, true, true, true, 1, 2));
  assert(!quicperf::detail::waitRequired(
      true, true, true, false, 1, 2));
  assert(!quicperf::detail::waitRequired(
      false, true, false, false, 1, 2));
  assert(!quicperf::detail::waitRequired(
      true, false, false, false, 1, 2));
  assert(!quicperf::detail::waitRequired(
      true, true, false, false, 2, 2));
}
