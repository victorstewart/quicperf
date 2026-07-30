#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace quicperf {

uint64_t monotonicRawNowNs();
uint64_t monotonicNowNs();
uint64_t realtimeNowNs();
uint64_t realtimeAtRaw(uint64_t rawNowNs, uint64_t anchorRawNs,
                       uint64_t anchorRealtimeNs) noexcept;

struct ClockBridgeSample {
  uint64_t monotonicBeforeNs;
  uint64_t rawNs;
  uint64_t monotonicAfterNs;
  int64_t rawMinusMonotonicNs;
  uint64_t bracketNs;
};

class ClockBridge {
public:
  static ClockBridgeSample sample();
  explicit ClockBridge(ClockBridgeSample before) : before_(before) {}
  uint64_t monotonicDeadline(uint64_t rawDeadlineNs) const;
  uint64_t rawDeadline(uint64_t monotonicDeadlineNs) const noexcept;
  bool validateAfter(ClockBridgeSample after, uint64_t measurementWindowNs, std::string& reason) const;
  const ClockBridgeSample& before() const noexcept { return before_; }

private:
  ClockBridgeSample before_;
};

struct MeasurementWindow {
  uint64_t warmupStartRawNs;
  uint64_t startRawNs;
  uint64_t endRawNs;
  uint64_t traceEpochRawNs;

  bool valid(std::string& reason) const;
  bool contains(uint64_t timestampRawNs) const noexcept { return timestampRawNs >= startRawNs && timestampRawNs < endRawNs; }
  uint64_t durationNs() const noexcept { return endRawNs - startRawNs; }
  size_t subwindow(uint64_t timestampRawNs) const noexcept;
};

} // namespace quicperf
