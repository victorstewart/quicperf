#include "core/runtime_ownership.h"

#include <atomic>
#include <chrono>
#include <dlfcn.h>
#include <fcntl.h>
#include <iostream>
#include <liburing.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <stdexcept>
#include <thread>
#include <unistd.h>

namespace {

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

template<class Function>
bool throwsOwnership(Function&& function)
{
  try
  {
    function();
  }
  catch (const std::runtime_error&)
  {
    return true;
  }
  return false;
}

template<class Function>
bool detectsClockBypass(Function&& function)
{
  const pid_t child = fork();
  if (child < 0) return false;
  if (child == 0)
  {
    quicperf::armRuntimePrivateClockAudit(true);
    quicperf::setRuntimeCalendarUnixSeconds(1'784'376'000);
    quicperf::setRuntimeClockAnchor(1'234'567'890'123ULL, 2'234'567'890'123ULL);
    quicperf::AdapterRuntimeScope scope(1'234'567'890'123ULL);
    function();
    _exit(0);
  }
  int status = 0;
  return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
      WEXITSTATUS(status) == 86;
}

} // namespace

int main()
{
  if (syscall(SYS_close_range, 3U, ~0U, 0U) != 0) return 1;
  const int control = open("/dev/null", O_RDONLY | O_CLOEXEC);
  const int packet = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (control < 0 || packet < 0) return 1;
  FakePacketIo driver(packet);
  quicperf::PacketIoDriver* owners[] = {&driver};
  quicperf::attestRuntimeOwnership(control, owners, 1, "positive");

  const int hiddenDescriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (hiddenDescriptor < 0 || !throwsOwnership([&] {
        quicperf::attestRuntimeOwnership(control, owners, 1, "hidden-descriptor");
      }))
    return 2;
  close(hiddenDescriptor);

  const int hiddenSocket = static_cast<int>(
      syscall(SYS_socket, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
  if (hiddenSocket < 0 || !throwsOwnership([&] {
        quicperf::attestRuntimeOwnership(control, owners, 1, "direct-socket-syscall");
      }))
    return 3;
  close(hiddenSocket);

  const int hiddenPoller = epoll_create1(EPOLL_CLOEXEC);
  if (hiddenPoller < 0 || !throwsOwnership([&] {
        quicperf::attestRuntimeOwnership(control, owners, 1, "hidden-poller");
      }))
    return 4;
  close(hiddenPoller);

  io_uring hiddenRing {};
  if (io_uring_queue_init(8, &hiddenRing, 0) != 0 || !throwsOwnership([&] {
        quicperf::attestRuntimeOwnership(control, owners, 1, "static-liburing");
      }))
    return 5;
  io_uring_queue_exit(&hiddenRing);

  std::atomic<bool> stop {false};
  std::jthread hiddenThread([&](std::stop_token token) {
    while (!token.stop_requested() && !stop.load()) std::this_thread::yield();
  });
  if (!throwsOwnership([&] {
        quicperf::attestRuntimeOwnership(control, owners, 1, "hidden-thread");
      }))
    return 6;
  stop.store(true);
  hiddenThread.request_stop();
  hiddenThread.join();
  quicperf::attestRuntimeOwnership(control, owners, 1, "restored");
  quicperf::setRuntimeCalendarUnixSeconds(1'784'376'000);
  quicperf::setRuntimeClockAnchor(1'234'567'890'123ULL, 2'234'567'890'123ULL);
  {
    quicperf::AdapterRuntimeScope scope(1'234'567'890'123ULL);
    timespec monotonic {};
    timespec raw {};
    timespec realtime {};
    timeval wall {};
    time_t seconds = 0;
    const auto chronoSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (clock_gettime(CLOCK_MONOTONIC, &monotonic) != 0 ||
        monotonic.tv_sec != 2'234 || monotonic.tv_nsec != 567'890'123 ||
        clock_gettime(CLOCK_MONOTONIC_RAW, &raw) != 0 ||
        raw.tv_sec != 1'234 || raw.tv_nsec != 567'890'123 ||
        clock_gettime(CLOCK_REALTIME, &realtime) != 0 ||
        realtime.tv_sec != 1'784'376'000 || realtime.tv_nsec != 0 ||
        gettimeofday(&wall, nullptr) != 0 || wall.tv_sec != 1'784'376'000 ||
        wall.tv_usec != 0 || time(&seconds) != 1'784'376'000 ||
        seconds != 1'784'376'000 || chronoSeconds != 1'784'376'000)
      return 7;
  }
  if (!detectsClockBypass([] {
        timespec value {};
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value);
      }))
    return 8;
  if (!detectsClockBypass([] {
        (void)dlsym(RTLD_DEFAULT, "__vdso_clock_gettime");
      }))
    return 9;
  close(packet);
  close(control);
  std::cout << "runtime_ownership_contract status=ok\n";
  return 0;
}
