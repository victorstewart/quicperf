#include "runtime_ownership.h"
#include "runtime_monitor_protocol.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <fcntl.h>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <cstring>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace quicperf {
namespace {

thread_local size_t adapterRuntimeDepth = 0;
thread_local uint64_t adapterRawTimeNs = 0;
std::atomic<uint64_t> adapterCalendarUnixSeconds {0};
std::atomic<uint64_t> adapterRawAnchorNs {0};
std::atomic<uint64_t> adapterMonotonicAnchorNs {0};
std::atomic<bool> privateClockAuditArmed {false};
std::atomic<bool> externalMonitorArmed {false};

void monitorMarker(runtime_monitor::Marker marker,
                   uint64_t first = 0,
                   uint64_t second = 0) noexcept
{
  if (!externalMonitorArmed.load(std::memory_order_relaxed)) return;
  (void)syscall(
      SYS_gettid, runtime_monitor::markerMagic,
      static_cast<uint64_t>(marker), first, second);
}

void addTracedSyscall(std::vector<sock_filter>& filter, int number)
{
  filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                            static_cast<uint32_t>(number), 0, 1));
  filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE));
}

void installExternalMonitorFilter()
{
#if !defined(__x86_64__)
  throw std::runtime_error("external runtime monitor currently requires x86_64");
#else
  std::vector<sock_filter> filter;
  filter.push_back(BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)));
  filter.push_back(BPF_JUMP(
      BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
  filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
  filter.push_back(BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)));

  addTracedSyscall(filter, SYS_gettid);
  addTracedSyscall(filter, SYS_clock_gettime);
  addTracedSyscall(filter, SYS_gettimeofday);
  addTracedSyscall(filter, SYS_time);
  addTracedSyscall(filter, SYS_open);
  addTracedSyscall(filter, SYS_openat);
#ifdef SYS_openat2
  addTracedSyscall(filter, SYS_openat2);
#endif
  addTracedSyscall(filter, SYS_creat);
  addTracedSyscall(filter, SYS_socket);
  addTracedSyscall(filter, SYS_socketpair);
  addTracedSyscall(filter, SYS_pipe);
  addTracedSyscall(filter, SYS_pipe2);
  addTracedSyscall(filter, SYS_dup);
  addTracedSyscall(filter, SYS_dup2);
  addTracedSyscall(filter, SYS_dup3);
  addTracedSyscall(filter, SYS_fcntl);
  addTracedSyscall(filter, SYS_epoll_create);
  addTracedSyscall(filter, SYS_epoll_create1);
  addTracedSyscall(filter, SYS_eventfd);
  addTracedSyscall(filter, SYS_eventfd2);
  addTracedSyscall(filter, SYS_timerfd_create);
  addTracedSyscall(filter, SYS_signalfd);
  addTracedSyscall(filter, SYS_signalfd4);
  addTracedSyscall(filter, SYS_inotify_init);
  addTracedSyscall(filter, SYS_inotify_init1);
  addTracedSyscall(filter, SYS_io_uring_setup);
  addTracedSyscall(filter, SYS_clone);
#ifdef SYS_clone3
  addTracedSyscall(filter, SYS_clone3);
#endif
  addTracedSyscall(filter, SYS_fork);
  addTracedSyscall(filter, SYS_vfork);
  addTracedSyscall(filter, SYS_poll);
  addTracedSyscall(filter, SYS_ppoll);
  addTracedSyscall(filter, SYS_select);
  addTracedSyscall(filter, SYS_pselect6);
  addTracedSyscall(filter, SYS_epoll_wait);
  addTracedSyscall(filter, SYS_epoll_pwait);
#ifdef SYS_epoll_pwait2
  addTracedSyscall(filter, SYS_epoll_pwait2);
#endif
  addTracedSyscall(filter, SYS_io_uring_enter);
  addTracedSyscall(filter, SYS_nanosleep);
  addTracedSyscall(filter, SYS_clock_nanosleep);
  filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

  sock_fprog program {
      .len = static_cast<unsigned short>(filter.size()),
      .filter = filter.data(),
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
      prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0)
    throw std::runtime_error(
        "cannot install unprivileged external runtime-monitor filter");
#endif
}

[[noreturn]] void privateClockViolation(const char* operation, void* caller)
{
  static constexpr char prefix[] =
      "quicperf runtime ownership: post-READY adapter private clock read: ";
  write(STDERR_FILENO, prefix, sizeof(prefix) - 1);
  write(STDERR_FILENO, operation, std::strlen(operation));
  Dl_info info {};
  char location[768] {};
  if (dladdr(caller, &info) && info.dli_fbase && info.dli_fname)
  {
    const int length = snprintf(
        location, sizeof(location), " caller=%s+0x%zx",
        info.dli_fname,
        static_cast<size_t>(static_cast<char*>(caller) -
                            static_cast<char*>(info.dli_fbase)));
    if (length > 0) write(STDERR_FILENO, location, static_cast<size_t>(length));
  }
  write(STDERR_FILENO, "\n", 1);
  _exit(86);
}

std::optional<std::string> taskName(pid_t task)
{
  const std::string path = "/proc/self/task/" + std::to_string(task) + "/comm";
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0 && errno == ENOENT) return std::nullopt;
  if (descriptor < 0) throw std::runtime_error("runtime ownership cannot read task identity");
  char value[128] {};
  const ssize_t length = read(descriptor, value, sizeof(value) - 1);
  const int saved = errno;
  close(descriptor);
  if (length < 0 && saved == ENOENT) return std::nullopt;
  if (length <= 0)
  {
    errno = saved;
    throw std::runtime_error("runtime ownership cannot read task identity");
  }
  std::string result(value, static_cast<size_t>(length));
  if (!result.empty() && result.back() == '\n') result.pop_back();
  return result;
}

std::vector<pid_t> userspaceTasks()
{
  DIR* directory = opendir("/proc/self/task");
  if (!directory) throw std::runtime_error("runtime ownership cannot enumerate tasks");
  std::vector<pid_t> result;
  while (const dirent* entry = readdir(directory))
  {
    if (entry->d_name[0] == '.') continue;
    pid_t task = 0;
    const char* end = entry->d_name + std::char_traits<char>::length(entry->d_name);
    const auto parsed = std::from_chars(entry->d_name, end, task);
    if (parsed.ec != std::errc {} || parsed.ptr != end || task <= 0) continue;
    const auto name = taskName(task);
    if (name && !name->starts_with("iou-wrk-")) result.push_back(task);
  }
  closedir(directory);
  std::ranges::sort(result);
  return result;
}

std::set<int> openDescriptors()
{
  DIR* directory = opendir("/proc/self/fd");
  if (!directory) throw std::runtime_error("runtime ownership cannot enumerate descriptors");
  const int enumerationDescriptor = dirfd(directory);
  std::set<int> result;
  while (const dirent* entry = readdir(directory))
  {
    if (entry->d_name[0] == '.') continue;
    int descriptor = -1;
    const char* end = entry->d_name + std::char_traits<char>::length(entry->d_name);
    const auto parsed = std::from_chars(entry->d_name, end, descriptor);
    if (parsed.ec == std::errc {} && parsed.ptr == end && descriptor >= 0 &&
        descriptor != enumerationDescriptor)
      result.insert(descriptor);
  }
  closedir(directory);
  return result;
}

std::string descriptorDescription(int descriptor)
{
  const std::string path = "/proc/self/fd/" + std::to_string(descriptor);
  char target[512] {};
  const ssize_t length = readlink(path.c_str(), target, sizeof(target) - 1);
  return std::to_string(descriptor) + "=" +
      (length < 0 ? std::string("unreadable") : std::string(target, static_cast<size_t>(length)));
}

std::string descriptorSet(const std::set<int>& descriptors)
{
  std::string result;
  for (const int descriptor : descriptors)
  {
    if (!result.empty()) result += ',';
    result += descriptorDescription(descriptor);
  }
  return result;
}

} // namespace

AdapterRuntimeScope::AdapterRuntimeScope(uint64_t nowRawNs) noexcept
{
  if (nowRawNs) adapterRawTimeNs = nowRawNs;
  monitorMarker(runtime_monitor::Marker::scopeEnter);
  ++adapterRuntimeDepth;
}

AdapterRuntimeScope::~AdapterRuntimeScope()
{
  monitorMarker(runtime_monitor::Marker::scopeExit);
  --adapterRuntimeDepth;
}

void setRuntimeCalendarUnixSeconds(uint64_t seconds) noexcept
{
  adapterCalendarUnixSeconds.store(seconds, std::memory_order_release);
}

void setRuntimeClockAnchor(uint64_t rawNs, uint64_t monotonicNs) noexcept
{
  adapterMonotonicAnchorNs.store(monotonicNs, std::memory_order_relaxed);
  adapterRawAnchorNs.store(rawNs, std::memory_order_release);
}

void armRuntimePrivateClockAudit(bool enabled) noexcept
{
  privateClockAuditArmed.store(enabled, std::memory_order_release);
}

void armExternalRuntimeMonitor()
{
  const char* requested = getenv("QUICPERF_EXTERNAL_RUNTIME_MONITOR");
  if (!requested) return;
  if (std::strcmp(requested, "1") != 0)
    throw std::runtime_error(
        "QUICPERF_EXTERNAL_RUNTIME_MONITOR must be exactly 1");
  if (externalMonitorArmed.exchange(true, std::memory_order_acq_rel)) return;
  try
  {
    installExternalMonitorFilter();
  }
  catch (...)
  {
    externalMonitorArmed.store(false, std::memory_order_release);
    throw;
  }
}

void attestRuntimeOwnership(int controlFd,
                            std::span<PacketIoDriver* const> packetIo,
                            size_t expectedThreads,
                            std::string_view phase)
{
  const auto tasks = userspaceTasks();
  auto observedTasks = tasks;
  for (size_t attempt = 0; observedTasks.size() != expectedThreads && attempt < 50; ++attempt)
  {
    std::this_thread::yield();
    observedTasks = userspaceTasks();
  }
  if (observedTasks.size() != expectedThreads)
    throw std::runtime_error(
        "runtime ownership thread count differs at " + std::string(phase) +
        ": expected=" + std::to_string(expectedThreads) +
        " observed=" + std::to_string(observedTasks.size()));

  std::set<int> expected {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, controlFd};
  for (PacketIoDriver* driver : packetIo)
  {
    if (!driver) throw std::runtime_error("runtime ownership received a null packet-I/O owner");
    for (const int descriptor : driver->ownedFileDescriptors())
    {
      if (descriptor < 0 || !expected.insert(descriptor).second)
        throw std::runtime_error("runtime ownership descriptor declaration is invalid");
    }
  }
  const auto observed = openDescriptors();
  if (observed != expected)
    throw std::runtime_error(
        "runtime ownership descriptor set differs at " + std::string(phase) +
        ": expected={" + descriptorSet(expected) +
        "} observed={" + descriptorSet(observed) + '}');
  monitorMarker(
      runtime_monitor::Marker::ownership, expectedThreads, expected.size());
}

} // namespace quicperf

extern "C" int __real_clock_gettime(clockid_t, timespec*);
extern "C" int __wrap_clock_gettime(clockid_t clock, timespec* value)
{
  if (quicperf::adapterRuntimeDepth)
  {
    if (!value || !quicperf::adapterRawTimeNs)
    {
      errno = EINVAL;
      return -1;
    }
    uint64_t nanoseconds = 0;
    switch (clock)
    {
      case CLOCK_MONOTONIC:
      {
        const uint64_t rawAnchor = quicperf::adapterRawAnchorNs.load(
            std::memory_order_acquire);
        const uint64_t monotonicAnchor = quicperf::adapterMonotonicAnchorNs.load(
            std::memory_order_relaxed);
        if (!rawAnchor || !monotonicAnchor)
        {
          errno = EINVAL;
          return -1;
        }
        nanoseconds = quicperf::adapterRawTimeNs >= rawAnchor ?
            monotonicAnchor + (quicperf::adapterRawTimeNs - rawAnchor) :
            monotonicAnchor - std::min(
                monotonicAnchor, rawAnchor - quicperf::adapterRawTimeNs);
        break;
      }
      case CLOCK_MONOTONIC_RAW:
        nanoseconds = quicperf::adapterRawTimeNs;
        break;
      case CLOCK_REALTIME:
      {
        const uint64_t seconds = quicperf::adapterCalendarUnixSeconds.load(
            std::memory_order_acquire);
        if (!seconds)
        {
          errno = EINVAL;
          return -1;
        }
        value->tv_sec = static_cast<time_t>(seconds);
        value->tv_nsec = 0;
        return 0;
      }
      default:
        if (quicperf::privateClockAuditArmed.load(std::memory_order_acquire))
          quicperf::privateClockViolation(
              "unsupported clock_gettime domain", __builtin_return_address(0));
        return __real_clock_gettime(clock, value);
    }
    value->tv_sec = static_cast<time_t>(nanoseconds / 1'000'000'000ULL);
    value->tv_nsec = static_cast<long>(nanoseconds % 1'000'000'000ULL);
    return 0;
  }
  return __real_clock_gettime(clock, value);
}

extern "C" int __real_gettimeofday(timeval*, void*);
extern "C" int __wrap_gettimeofday(timeval* value, void* zone)
{
  if (quicperf::adapterRuntimeDepth)
  {
    if (!value || zone || !quicperf::adapterCalendarUnixSeconds.load(std::memory_order_acquire))
    {
      errno = EINVAL;
      return -1;
    }
    value->tv_sec = static_cast<time_t>(
        quicperf::adapterCalendarUnixSeconds.load(std::memory_order_acquire));
    value->tv_usec = 0;
    return 0;
  }
  return __real_gettimeofday(value, zone);
}

extern "C" time_t __real_time(time_t*);
extern "C" time_t __wrap_time(time_t* value)
{
  if (quicperf::adapterRuntimeDepth)
  {
    const auto now = static_cast<time_t>(
        quicperf::adapterCalendarUnixSeconds.load(std::memory_order_acquire));
    if (!now)
    {
      errno = EINVAL;
      return static_cast<time_t>(-1);
    }
    if (value) *value = now;
    return now;
  }
  return __real_time(value);
}

extern "C" std::chrono::system_clock::time_point
__real__ZNSt6chrono3_V212system_clock3nowEv();
extern "C" std::chrono::system_clock::time_point
__wrap__ZNSt6chrono3_V212system_clock3nowEv()
{
  if (quicperf::adapterRuntimeDepth)
  {
    const uint64_t seconds = quicperf::adapterCalendarUnixSeconds.load(
        std::memory_order_acquire);
    if (!seconds) quicperf::privateClockViolation(
        "system_clock without frozen calendar", __builtin_return_address(0));
    return std::chrono::system_clock::time_point(std::chrono::seconds(seconds));
  }
  return __real__ZNSt6chrono3_V212system_clock3nowEv();
}

extern "C" int64_t PR_Now()
{
  timeval value {};
  if (quicperf::adapterRuntimeDepth)
  {
    const uint64_t seconds = quicperf::adapterCalendarUnixSeconds.load(
        std::memory_order_acquire);
    if (!seconds || seconds >
        static_cast<uint64_t>(std::numeric_limits<int64_t>::max() / 1'000'000)) return 0;
    return static_cast<int64_t>(seconds * 1'000'000);
  }
  if (syscall(SYS_gettimeofday, &value, nullptr) != 0) return 0;
  return static_cast<int64_t>(value.tv_sec) * 1'000'000 + value.tv_usec;
}

extern "C" void* __real_dlsym(void*, const char*);
extern "C" void* __wrap_dlsym(void* handle, const char* symbol)
{
  if (quicperf::privateClockAuditArmed.load(std::memory_order_acquire) &&
      quicperf::adapterRuntimeDepth && symbol &&
      (std::strcmp(symbol, "__vdso_clock_gettime") == 0 ||
       std::strcmp(symbol, "clock_gettime") == 0 ||
       std::strcmp(symbol, "gettimeofday") == 0 ||
       std::strcmp(symbol, "time") == 0))
    quicperf::privateClockViolation(
        "vDSO/private clock lookup", __builtin_return_address(0));
  return __real_dlsym(handle, symbol);
}
