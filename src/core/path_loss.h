#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <span>

namespace quicperf {

bool lossRecoveryDrop(std::span<const uint8_t, 32> traceSeed,
                      bool measurement, uint8_t direction,
                      uint64_t packetOrdinal);

struct LossDecision {
  bool active = false;
  bool measurement = false;
  bool drop = false;
};

class LossRecoveryStream {
public:
  void arm(std::span<const uint8_t, 32> traceSeed,
           uint64_t measurementStartRawNs,
           uint64_t measurementEndRawNs, uint8_t direction);
  void reset();
  LossDecision next(uint64_t nowRawNs);
  bool armed() const;

private:
  std::array<uint8_t, 32> traceSeed_ {};
  std::array<uint64_t, 2> ordinals_ {};
  uint64_t measurementStartRawNs_ = 0;
  uint64_t measurementEndRawNs_ = 0;
  uint8_t direction_ = 0;
  bool armed_ = false;
  mutable std::mutex mutex_;
};

} // namespace quicperf
