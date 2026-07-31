#include "measurement.h"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <stdexcept>
#include <time.h>

namespace quicperf {
namespace {

uint64_t clockNow(clockid_t clock)
{
  timespec value {};
  if (clock_gettime(clock, &value) != 0) throw std::runtime_error("clock_gettime failed");
  return static_cast<uint64_t>(value.tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(value.tv_nsec);
}

} // namespace

uint64_t monotonicRawNowNs() { return clockNow(CLOCK_MONOTONIC_RAW); }
uint64_t monotonicNowNs() { return clockNow(CLOCK_MONOTONIC); }
uint64_t realtimeNowNs() { return clockNow(CLOCK_REALTIME); }

uint64_t realtimeAtRaw(uint64_t rawNowNs, uint64_t anchorRawNs,
                       uint64_t anchorRealtimeNs) noexcept
{
  const uint64_t elapsed = rawNowNs >= anchorRawNs ? rawNowNs - anchorRawNs : 0;
  return elapsed > std::numeric_limits<uint64_t>::max() - anchorRealtimeNs ?
      std::numeric_limits<uint64_t>::max() : anchorRealtimeNs + elapsed;
}

ClockBridgeSample ClockBridge::sample()
{
  ClockBridgeSample best {};
  best.bracketNs = std::numeric_limits<uint64_t>::max();
  for (unsigned index = 0; index < 32; ++index)
  {
    ClockBridgeSample current {};
    current.monotonicBeforeNs = monotonicNowNs();
    current.rawNs = monotonicRawNowNs();
    current.monotonicAfterNs = monotonicNowNs();
    current.bracketNs = current.monotonicAfterNs - current.monotonicBeforeNs;
    const uint64_t midpoint = current.monotonicBeforeNs + current.bracketNs / 2;
    current.rawMinusMonotonicNs = static_cast<int64_t>(current.rawNs) - static_cast<int64_t>(midpoint);
    if (current.bracketNs < best.bracketNs) best = current;
  }
  return best;
}

uint64_t ClockBridge::monotonicDeadline(uint64_t rawDeadlineNs) const
{
  const int64_t translated = static_cast<int64_t>(rawDeadlineNs) - before_.rawMinusMonotonicNs;
  if (translated < 0) throw std::overflow_error("raw deadline cannot be represented on monotonic clock");
  return static_cast<uint64_t>(translated);
}

uint64_t ClockBridge::rawDeadline(uint64_t monotonicDeadlineNs) const noexcept
{
  if (before_.rawMinusMonotonicNs >= 0)
  {
    const uint64_t offset = static_cast<uint64_t>(before_.rawMinusMonotonicNs);
    return monotonicDeadlineNs > std::numeric_limits<uint64_t>::max() - offset ?
        std::numeric_limits<uint64_t>::max() : monotonicDeadlineNs + offset;
  }
  const uint64_t offset = static_cast<uint64_t>(-(before_.rawMinusMonotonicNs + 1)) + 1;
  return monotonicDeadlineNs > offset ? monotonicDeadlineNs - offset : 0;
}

bool ClockBridge::validateAfter(ClockBridgeSample after, uint64_t measurementWindowNs, std::string& reason) const
{
  if (before_.bracketNs > 50'000 || after.bracketNs > 50'000)
  {
    reason = "clock_bridge_bracket_exceeds_50us";
    return false;
  }
  if (after.rawNs < before_.rawNs ||
      after.monotonicBeforeNs < before_.monotonicBeforeNs ||
      after.rawNs - before_.rawNs < measurementWindowNs)
  {
    reason = "clock_bridge_elapsed_time_regressed_or_short";
    return false;
  }
  const uint64_t drift = static_cast<uint64_t>(std::llabs(after.rawMinusMonotonicNs - before_.rawMinusMonotonicNs));
  const uint64_t limit =
      std::max<uint64_t>(100'000, (after.rawNs - before_.rawNs) / 2'000);
  if (drift > limit)
  {
    reason = "clock_bridge_drift_exceeds_limit";
    return false;
  }
  return true;
}

bool MeasurementWindow::valid(std::string& reason) const
{
  if (warmupStartRawNs == 0 || warmupStartRawNs > startRawNs || startRawNs >= endRawNs || traceEpochRawNs != startRawNs)
  {
    reason = "invalid_measurement_boundaries";
    return false;
  }
  return true;
}

size_t MeasurementWindow::subwindow(uint64_t timestampRawNs) const noexcept
{
  if (timestampRawNs <= startRawNs) return 0;
  if (timestampRawNs >= endRawNs) return 199;
  return std::min<size_t>(199, static_cast<size_t>((timestampRawNs - startRawNs) * 200 / durationNs()));
}

} // namespace quicperf
