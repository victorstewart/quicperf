#pragma once

#include "../core/workload_protocol.h"

#include <array>
#include <cstdint>
#include <string>

namespace quicperf::workloads {

struct WorkloadShape {
  workload::Scenario scenario;
  uint32_t connections;
  uint32_t activeStreamsPerConnection;
  uint32_t aggregateSlots;
  uint32_t requestBodyBytes;
  uint32_t responseBodyBytes;
  uint32_t messageBodyBytes;
  uint32_t maxUnreturnedDatagramsPerConnection;
  bool indefinitelyReplenished;
  bool requiresPeerAck;
};

WorkloadShape transferShape(workload::Scenario scenario);
WorkloadShape requestResponseShape(workload::Scenario scenario);
WorkloadShape connectionLifecycleShape(workload::Scenario scenario);
WorkloadShape datagramShape();
WorkloadShape streamLifecycleShape(workload::Scenario scenario);

struct MemorySnapshot {
  uint64_t cgroupBytes;
  uint64_t privateCleanBytes;
  uint64_t privateDirtyBytes;
  uint64_t anonymousBytes;
};

MemorySnapshot readMemorySnapshot(const std::string& cgroupMemoryCurrent, const std::string& smapsRollup);

} // namespace quicperf::workloads
