#include "workloads.h"

#include <stdexcept>

namespace quicperf::workloads {

WorkloadShape connectionLifecycleShape(workload::Scenario scenario)
{
  using enum workload::Scenario;
  switch (scenario)
  {
    case connect:
    case resumedConnect:
      return {scenario, 16, 1, 16, 0, 0, 0, 0, true, true};
    case zeroRttReqresp:
      return {scenario, 16, 1, 16, 64, 1'024, 0, 0, true, true};
    default:
      throw std::invalid_argument("scenario is not a connection lifecycle workload");
  }
}

} // namespace quicperf::workloads
