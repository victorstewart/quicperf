#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>

namespace quicperf {

class TimerQueue {
public:
  using TimerId = uint64_t;
  using Callback = std::function<void(uint64_t)>;

  TimerId add(uint64_t deadlineRawNs, Callback callback);
  bool cancel(TimerId id);
  std::optional<uint64_t> nextDeadline() const noexcept;
  size_t runReady(uint64_t nowRawNs);
  bool empty() const noexcept { return timers_.empty(); }

private:
  struct Timer { TimerId id; Callback callback; };
  TimerId nextId_ = 1;
  std::multimap<uint64_t, Timer> timers_;
};

} // namespace quicperf
