#include <errno.h>
#include <stdint.h>
#include <time.h>

int64_t quicperf_monitor_spin_until_raw_ns(int64_t target_raw_ns)
{
  if (target_raw_ns <= 0)
    return -EINVAL;
  for (;;)
  {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value) != 0)
      return -errno;
    const int64_t observed =
        (int64_t)value.tv_sec * 1000000000LL + (int64_t)value.tv_nsec;
    if (observed >= target_raw_ns)
      return observed;
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("pause");
#endif
  }
}
