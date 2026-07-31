#include "workloads.h"

namespace quicperf::workloads {

WorkloadShape datagramShape()
{
  return {workload::Scenario::datagram, 16, 0, 2'048, 0, 0, 64, 128, true, true};
}

} // namespace quicperf::workloads
