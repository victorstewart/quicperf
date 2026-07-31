#pragma once

#include "adapter.h"
#include "measurement.h"
#include "packet_io.h"
#include "timer_queue.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace quicperf {

namespace detail {

constexpr bool waitRequired(bool mayWait, bool receiveEmpty,
                            bool transmitProduced, bool transmitPending,
                            uint64_t nowRawNs, uint64_t stopRawNs) noexcept
{
  return mayWait && receiveEmpty &&
      (!transmitProduced || transmitPending) && nowRawNs < stopRawNs;
}

} // namespace detail

class EventLoop {
public:
  EventLoop(PacketIoDriver& packetIo, Adapter& adapter, ClockBridge bridge);
  bool driveOnce(uint64_t stopRawNs, AdapterError& error);
  bool driveOnceNonblocking(AdapterError& error);
  bool driveUntil(uint64_t stopRawNs, AdapterError& error);
  TimerQueue& timers() noexcept { return timers_; }

private:
  bool driveReady(uint64_t nowRawNs, uint64_t stopRawNs, bool mayWait,
                  AdapterError& error);
  uint64_t waitNanoseconds(uint64_t nowRawNs, uint64_t stopRawNs) const noexcept;
  PacketIoDriver& packetIo_;
  Adapter& adapter_;
  ClockBridge bridge_;
  TimerQueue timers_;
  std::array<TransmitPacket, packetBatchSize> transmit_ {};
  std::array<std::vector<std::byte>, packetBatchSize> transmitStorage_ {};
  size_t transmitOffset_ = 0;
  size_t transmitCount_ = 0;
};

} // namespace quicperf
