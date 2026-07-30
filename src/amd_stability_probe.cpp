#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sched.h>
#include <string_view>
#include <time.h>
#include <vector>

namespace {

[[noreturn]] void fail(const char* message) {
  std::fprintf(stderr, "quicperf-amd-stability-probe: %s: %s\n", message,
               std::strerror(errno));
  std::exit(2);
}

uint64_t parseUnsigned(std::string_view text, const char* label) {
  uint64_t value = 0;
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc{} || end != text.data() + text.size()) {
    std::fprintf(stderr, "quicperf-amd-stability-probe: invalid %s\n", label);
    std::exit(2);
  }
  return value;
}

uint64_t rawNow() {
  timespec now{};
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0) {
    fail("clock_gettime(CLOCK_MONOTONIC_RAW) failed");
  }
  return static_cast<uint64_t>(now.tv_sec) * 1'000'000'000ULL +
         static_cast<uint64_t>(now.tv_nsec);
}

void pinToCpu(unsigned cpu) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  if (sched_setaffinity(0, sizeof(set), &set) != 0) {
    fail("sched_setaffinity failed");
  }
  cpu_set_t observed;
  CPU_ZERO(&observed);
  if (sched_getaffinity(0, sizeof(observed), &observed) != 0 ||
      CPU_COUNT(&observed) != 1 || !CPU_ISSET(cpu, &observed)) {
    errno = EINVAL;
    fail("exact CPU-affinity readback failed");
  }
}

void waitUntil(uint64_t target) {
  for (;;) {
    const uint64_t now = rawNow();
    if (now >= target) {
      return;
    }
    const uint64_t remaining = target - now;
    if (remaining > 2'000'000ULL) {
      timespec delay{0, static_cast<long>(remaining - 1'000'000ULL)};
      if (nanosleep(&delay, nullptr) != 0 && errno != EINTR) {
        fail("nanosleep failed");
      }
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 7 || std::string_view(argv[1]) != "--cpu" ||
      std::string_view(argv[3]) != "--start-raw-ns" ||
      std::string_view(argv[5]) != "--duration-seconds") {
    std::fprintf(stderr,
                 "usage: quicperf-amd-stability-probe --cpu N "
                 "--start-raw-ns N --duration-seconds N\n");
    return 2;
  }
  const uint64_t cpuValue = parseUnsigned(argv[2], "CPU");
  const uint64_t start = parseUnsigned(argv[4], "start time");
  const uint64_t duration = parseUnsigned(argv[6], "duration");
  if (cpuValue >= CPU_SETSIZE || duration == 0 || duration > 120) {
    std::fprintf(stderr, "quicperf-amd-stability-probe: argument outside frozen bounds\n");
    return 2;
  }
  pinToCpu(static_cast<unsigned>(cpuValue));
  waitUntil(start);
  const uint64_t actualStart = rawNow();
  if (actualStart < start || actualStart - start > 1'000'000ULL) {
    std::fprintf(stderr, "quicperf-amd-stability-probe: start boundary missed\n");
    return 3;
  }

  std::vector<uint64_t> buckets;
  buckets.reserve(duration);
  uint64_t state = 0x9e3779b97f4a7c15ULL ^ cpuValue;
  for (uint64_t second = 1; second <= duration; ++second) {
    const uint64_t boundary = start + second * 1'000'000'000ULL;
    uint64_t count = 0;
    while (rawNow() < boundary) {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
#if defined(__GNUC__) || defined(__clang__)
      asm volatile("" : "+r"(state));
#endif
      ++count;
    }
    buckets.push_back(count);
  }
  const uint64_t actualEnd = rawNow();
  std::printf("{\"actual_end_raw_ns\":%llu,\"actual_start_raw_ns\":%llu,"
              "\"buckets\":[",
              static_cast<unsigned long long>(actualEnd),
              static_cast<unsigned long long>(actualStart));
  for (size_t index = 0; index < buckets.size(); ++index) {
    std::printf("%s%llu", index == 0 ? "" : ",",
                static_cast<unsigned long long>(buckets[index]));
  }
  std::printf("],\"cpu\":%llu,\"final_state\":\"%016llx\","
              "\"schema_version\":\"quicperf.amd-stability-probe.v1\","
              "\"start_raw_ns\":%llu}\n",
              static_cast<unsigned long long>(cpuValue),
              static_cast<unsigned long long>(state),
              static_cast<unsigned long long>(start));
  return 0;
}
