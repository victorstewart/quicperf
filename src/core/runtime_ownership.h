#pragma once

#include "packet_io.h"

#include <cstdint>
#include <span>
#include <string_view>

namespace quicperf {

class AdapterRuntimeScope {
public:
  explicit AdapterRuntimeScope(uint64_t nowRawNs = 0) noexcept;
  ~AdapterRuntimeScope();
  AdapterRuntimeScope(const AdapterRuntimeScope&) = delete;
  AdapterRuntimeScope& operator=(const AdapterRuntimeScope&) = delete;
};

void setRuntimeCalendarUnixSeconds(uint64_t seconds) noexcept;
void setRuntimeClockAnchor(uint64_t rawNs, uint64_t monotonicNs) noexcept;
void armRuntimePrivateClockAudit(bool enabled) noexcept;
void armExternalRuntimeMonitor();

void attestRuntimeOwnership(int controlFd,
                            std::span<PacketIoDriver* const> packetIo,
                            size_t expectedThreads,
                            std::string_view phase);

} // namespace quicperf
