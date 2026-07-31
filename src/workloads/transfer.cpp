#include "workloads.h"

#include <stdexcept>

namespace quicperf::workloads {

WorkloadShape transferShape(workload::Scenario scenario)
{
  using enum workload::Scenario;
  switch (scenario)
  {
    case download:
    case upload:
    case lossRecovery:
    case flowControl:
      return {scenario, 16, 1, 16, 8, 0, 0, 0, true, false};
    case multistreamDownload:
    case multistreamUpload:
      return {scenario, 16, 8, 128, 8, 0, 0, 0, true, false};
    case bidi:
      return {scenario, 16, 1, 16, 8, 0, 0, 0, true, false};
    default:
      throw std::invalid_argument("scenario is not a transfer workload");
  }
}

} // namespace quicperf::workloads
