#include "timer_queue.h"

#include <limits>
#include <stdexcept>

namespace quicperf {

TimerQueue::TimerId TimerQueue::add(uint64_t deadlineRawNs, Callback callback)
{
  if (deadlineRawNs == 0 || !callback || nextId_ == std::numeric_limits<TimerId>::max())
    throw std::invalid_argument("invalid timer");
  const TimerId id = nextId_++;
  timers_.emplace(deadlineRawNs, Timer {id, std::move(callback)});
  return id;
}

bool TimerQueue::cancel(TimerId id)
{
  for (auto timer = timers_.begin(); timer != timers_.end(); ++timer)
  {
    if (timer->second.id == id)
    {
      timers_.erase(timer);
      return true;
    }
  }
  return false;
}

std::optional<uint64_t> TimerQueue::nextDeadline() const noexcept
{
  return timers_.empty() ? std::nullopt : std::optional<uint64_t> {timers_.begin()->first};
}

size_t TimerQueue::runReady(uint64_t nowRawNs)
{
  size_t count = 0;
  while (!timers_.empty() && timers_.begin()->first <= nowRawNs)
  {
    auto node = timers_.extract(timers_.begin());
    node.mapped().callback(nowRawNs);
    ++count;
  }
  return count;
}

} // namespace quicperf
