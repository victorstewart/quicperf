#include "result.h"

#include <limits>

namespace quicperf {

void TrialResult::validate(bool operationRate)
{
  if (measurementStartRawNs == 0 || measurementStartRawNs >= measurementEndRawNs) invalidReasons.emplace_back("invalid_measurement_interval");
  if (counters.duplicates != 0) invalidReasons.emplace_back("duplicate_completion");
  if (counters.payloadErrors != 0) invalidReasons.emplace_back("payload_validation_error");
  if (counters.workCapHits != 0) invalidReasons.emplace_back("finite_work_cap");
  if (counters.streamCreditExhaustions != 0) invalidReasons.emplace_back("stream_credit_exhaustion");
  if (counters.generatorStarvations != 0) invalidReasons.emplace_back("generator_starvation");
  for (size_t index = 0; index < counters.subwindows.size(); index += 20)
  {
    uint64_t validated = 0;
    uint64_t blocked = 0;
    for (size_t offset = 0; offset < 20; ++offset)
    {
      const auto& window = counters.subwindows[index + offset];
      if (window.validatedUnits > std::numeric_limits<uint64_t>::max() - validated ||
          window.blockedEvents > std::numeric_limits<uint64_t>::max() - blocked)
      {
        invalidReasons.emplace_back("subwindow_counter_overflow");
        return;
      }
      validated += window.validatedUnits;
      blocked += window.blockedEvents;
    }
    if (validated == 0 && blocked == 0)
    {
      invalidReasons.emplace_back("subwindow_without_progress_or_causal_block");
      break;
    }
  }
  resolutionLimited = operationRate && counters.peerValidated < 400;
  censored = counters.workCapHits != 0 || counters.streamCreditExhaustions != 0 || counters.generatorStarvations != 0;
}

} // namespace quicperf
