#include "workloads.h"

#include <stdexcept>

namespace quicperf::workloads {

WorkloadShape requestResponseShape(workload::Scenario scenario)
{
  using enum workload::Scenario;
  switch (scenario)
  {
    case smallPayloadPps: return {scenario, 16, 1, 16, 0, 0, 64, 0, true, false};
    case reqresp: return {scenario, 16, 1, 16, 64, 1'024, 0, 0, true, true};
    case zeroRttReqresp: return {scenario, 16, 1, 16, 64, 1'024, 0, 0, true, true};
    default: throw std::invalid_argument("scenario is not a request/response workload");
  }
}

} // namespace quicperf::workloads
