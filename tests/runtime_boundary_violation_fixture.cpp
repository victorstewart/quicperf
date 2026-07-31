#include "core/runtime_monitor_protocol.h"
#include "core/runtime_ownership.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <liburing.h>
#include <poll.h>
#include <stdexcept>
#include <string_view>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace {

using VdsoClockGettime = int (*)(clockid_t, timespec*);

class FakePacketIo final : public quicperf::PacketIoDriver {
public:
  explicit FakePacketIo(int descriptor) : descriptor_(descriptor) {}
  uint16_t bind(uint32_t, uint16_t) override { return 0; }
  std::span<const quicperf::ReceivedPacket> receive(uint64_t) override { return {}; }
  size_t send(std::span<const quicperf::TransmitPacket>, uint64_t) override { return 0; }
  void armLossRecovery(std::span<const uint8_t, 32>, uint64_t, uint64_t, uint8_t) override {}
  void resetLossRecovery() override {}
  void shareLossRecovery(std::shared_ptr<quicperf::LossRecoveryStream>) override {}
  bool hasPendingTransmit() const noexcept override { return false; }
  int wait(uint64_t) override { return 0; }
  int socketFd() const noexcept override { return descriptor_; }
  std::vector<int> ownedFileDescriptors() const override { return {descriptor_}; }
  const quicperf::PacketIoCounters& counters() const noexcept override { return counters_; }
  quicperf::PacketBackend backend() const noexcept override
  {
    return quicperf::PacketBackend::syscall;
  }

private:
  int descriptor_;
  quicperf::PacketIoCounters counters_ {};
};

int exercise(std::string_view mode)
{
  const int control = open("/dev/null", O_RDONLY | O_CLOEXEC);
  const int packet = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (control < 0 || packet < 0) throw std::runtime_error("cannot create fixture descriptors");
  FakePacketIo packetIo(packet);
  quicperf::PacketIoDriver* owners[] = {&packetIo};
  VdsoClockGettime vdsoClock = nullptr;
  if (mode == "vdso-private-clock")
  {
    void* vdso = dlopen("linux-vdso.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!vdso) throw std::runtime_error("cannot open vDSO");
    vdsoClock = reinterpret_cast<VdsoClockGettime>(
        dlsym(vdso, "__vdso_clock_gettime"));
    if (!vdsoClock) throw std::runtime_error("cannot resolve vDSO clock");
  }

  quicperf::armExternalRuntimeMonitor();
  quicperf::attestRuntimeOwnership(control, owners, 1, "fixture-ready");
  quicperf::armRuntimePrivateClockAudit(true);
  quicperf::setRuntimeCalendarUnixSeconds(1'784'376'000);
  quicperf::setRuntimeClockAnchor(1'000'000'000, 2'000'000'000);
  quicperf::AdapterRuntimeScope scope(1'000'000'000);
  if (mode == "positive")
  {
    timespec raw {};
    timespec monotonic {};
    timespec realtime {};
    return clock_gettime(CLOCK_MONOTONIC_RAW, &raw) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &monotonic) != 0 ||
        clock_gettime(CLOCK_REALTIME, &realtime) != 0;
  }
  if (mode == "direct-clock-syscall")
  {
    timespec value {};
    (void)syscall(SYS_clock_gettime, CLOCK_MONOTONIC_RAW, &value);
  }
  else if (mode == "hidden-fd")
  {
    (void)open("/dev/null", O_RDONLY | O_CLOEXEC);
  }
  else if (mode == "hidden-socket")
  {
    (void)socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  }
  else if (mode == "hidden-poller")
  {
    (void)epoll_create1(EPOLL_CLOEXEC);
  }
  else if (mode == "static-liburing")
  {
    io_uring ring {};
    (void)io_uring_queue_init(8, &ring, 0);
  }
  else if (mode == "hidden-thread")
  {
    std::jthread worker([] {});
    worker.join();
  }
  else if (mode == "poller-wait")
  {
    (void)poll(nullptr, 0, 0);
  }
  else if (mode == "vdso-private-clock")
  {
    timespec value {};
    (void)vdsoClock(CLOCK_MONOTONIC_RAW, &value);
  }
  else
  {
    throw std::runtime_error("unknown runtime-boundary fixture mode");
  }
  return 0;
}

} // namespace

int main(int argc, char** argv)
{
  try
  {
    return argc == 2 ? exercise(argv[1]) : 2;
  }
  catch (const std::exception& error)
  {
    write(STDERR_FILENO, error.what(), std::char_traits<char>::length(error.what()));
    write(STDERR_FILENO, "\n", 1);
    return 2;
  }
}
