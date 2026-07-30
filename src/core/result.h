#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace quicperf {

struct SubwindowCounters {
  uint64_t validatedUnits = 0;
  uint64_t blockedEvents = 0;
};

struct WorkloadCounters {
  uint64_t admitted = 0;
  uint64_t accepted = 0;
  uint64_t peerValidated = 0;
  uint64_t completedAfterEnd = 0;
  uint64_t duplicates = 0;
  uint64_t payloadErrors = 0;
  uint64_t unreturned = 0;
  uint64_t workCapHits = 0;
  uint64_t streamCreditExhaustions = 0;
  uint64_t generatorStarvations = 0;
  // Two hundred private accounting bins make both qualification ratios and
  // their ten nested validity buckets exact.  The public PROGRESS contract
  // remains ten buckets by aggregating twenty adjacent private bins.
  std::array<SubwindowCounters, 200> subwindows {};
};

struct TrialResult {
  uint64_t measurementStartRawNs = 0;
  uint64_t measurementEndRawNs = 0;
  WorkloadCounters counters;
  bool resolutionLimited = false;
  bool censored = false;
  std::vector<std::string> invalidReasons;

  bool valid() const noexcept { return invalidReasons.empty() && !censored && !resolutionLimited; }
  void validate(bool operationRate);
};

} // namespace quicperf
