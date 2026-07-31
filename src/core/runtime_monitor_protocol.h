#pragma once

#include <cstdint>

namespace quicperf::runtime_monitor {

inline constexpr uint64_t markerMagic = 0x51504652544d4f4eULL;

enum class Marker : uint64_t {
  scopeEnter = 1,
  scopeExit = 2,
  ownership = 3,
};

} // namespace quicperf::runtime_monitor
