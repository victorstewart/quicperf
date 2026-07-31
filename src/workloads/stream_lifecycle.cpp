#include "workloads.h"

#include <stdexcept>

namespace quicperf::workloads {

WorkloadShape streamLifecycleShape(workload::Scenario scenario)
{
  using enum workload::Scenario;
  switch (scenario)
  {
    case streamChurn: return {scenario, 16, 1, 16, 1, 1, 0, 0, true, true};
    case closeResetCleanup: return {scenario, 16, 0, 16, 1, 1, 0, 0, true, true};
    default: throw std::invalid_argument("scenario is not a stream lifecycle workload");
  }
}

} // namespace quicperf::workloads
