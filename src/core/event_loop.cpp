#include "event_loop.h"
#include "runtime_ownership.h"

#include <algorithm>
#include <limits>

namespace quicperf {

EventLoop::EventLoop(PacketIoDriver& packetIo, Adapter& adapter, ClockBridge bridge)
    : packetIo_(packetIo), adapter_(adapter), bridge_(bridge)
{
}

uint64_t EventLoop::waitNanoseconds(uint64_t nowRawNs, uint64_t stopRawNs) const noexcept
{
  uint64_t deadline = stopRawNs;
  uint64_t adapterDeadline = 0;
  {
    AdapterRuntimeScope scope(nowRawNs);
    adapterDeadline = adapter_.nextTimeoutRawNs();
  }
  if (adapterDeadline != 0) deadline = std::min(deadline, adapterDeadline);
  if (const auto timer = timers_.nextDeadline()) deadline = std::min(deadline, *timer);
  if (transmitOffset_ < transmitCount_)
  {
    const uint64_t transmitDeadline = transmit_[transmitOffset_].desiredSendRawNs;
    if (transmitDeadline != 0) deadline = std::min(deadline, transmitDeadline);
  }
  if (deadline <= nowRawNs) return 0;
  return std::min<uint64_t>(1'000'000'000, deadline - nowRawNs);
}

bool EventLoop::driveOnce(uint64_t stopRawNs, AdapterError& error)
{
  const uint64_t now = monotonicRawNowNs();
  return driveReady(now, stopRawNs, now < stopRawNs, error);
}

bool EventLoop::driveOnceNonblocking(AdapterError& error)
{
  const uint64_t now = monotonicRawNowNs();
  return driveReady(now, now, false, error);
}

bool EventLoop::driveReady(uint64_t now, uint64_t stopRawNs, bool mayWait,
                           AdapterError& error)
{
  const auto packets = packetIo_.receive(now);
  if (!packets.empty())
  {
    AdapterRuntimeScope scope(now);
    if (!adapter_.receiveBatch(packets, now, error)) return false;
  }
  timers_.runReady(now);
  uint64_t adapterDeadline = 0;
  {
    AdapterRuntimeScope scope(now);
    adapterDeadline = adapter_.nextTimeoutRawNs();
  }
  if (adapterDeadline != 0 && adapterDeadline <= now)
  {
    AdapterRuntimeScope scope(now);
    if (!adapter_.onTimeout(now, error)) return false;
  }
  if (packetIo_.hasPendingTransmit())
  {
    packetIo_.send({}, now);
    if (packetIo_.hasPendingTransmit())
    {
      if (mayWait) packetIo_.wait(waitNanoseconds(now, stopRawNs));
      return true;
    }
  }
  if (transmitOffset_ < transmitCount_)
  {
    transmitOffset_ += packetIo_.send(
        std::span<const TransmitPacket>(transmit_).subspan(
            transmitOffset_, transmitCount_ - transmitOffset_), now);
    if (transmitOffset_ < transmitCount_)
    {
      if (mayWait) packetIo_.wait(waitNanoseconds(now, stopRawNs));
      return true;
    }
    transmitOffset_ = 0;
    transmitCount_ = 0;
  }
  size_t count = 0;
  {
    AdapterRuntimeScope scope(now);
    count = adapter_.pollTransmitBatch(transmit_, now, error);
  }
  if (!error.message.empty() || count > transmit_.size()) return false;
  for (size_t index = 0; index < count; ++index)
  {
    auto& packet = transmit_[index];
    if (packet.desiredSendMonotonicNs != 0)
    {
      if (packet.desiredSendRawNs != 0)
      {
        error = {1, "adapter supplied transmit deadlines in two clock domains"};
        return false;
      }
      packet.desiredSendRawNs = std::max(
          now, bridge_.rawDeadline(packet.desiredSendMonotonicNs));
      packet.desiredSendMonotonicNs = 0;
    }
    auto& storage = transmitStorage_[index];
    storage.assign(packet.bytes.begin(), packet.bytes.end());
    packet.bytes = storage;
  }
  transmitOffset_ = 0;
  transmitCount_ = count;
  if (transmitCount_)
    transmitOffset_ = packetIo_.send(
        std::span<const TransmitPacket>(transmit_).first(transmitCount_), now);
  if (transmitOffset_ == transmitCount_)
  {
    transmitOffset_ = 0;
    transmitCount_ = 0;
  }
  const uint64_t afterSend = monotonicRawNowNs();
  if (detail::waitRequired(
          mayWait, packets.empty(), count != 0, transmitCount_ != 0,
          afterSend, stopRawNs))
    packetIo_.wait(waitNanoseconds(afterSend, stopRawNs));
  return true;
}

bool EventLoop::driveUntil(uint64_t stopRawNs, AdapterError& error)
{
  while (monotonicRawNowNs() < stopRawNs)
  {
    if (!driveOnce(stopRawNs, error)) return false;
  }
  return true;
}

} // namespace quicperf
