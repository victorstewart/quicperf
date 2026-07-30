#pragma once

#include "packet_io.h"
#include "workload_protocol.h"

#include <string>
#include <vector>

namespace quicperf {

struct Capabilities {
  std::string library;
  std::string buildId;
  uint32_t adapterAbiVersion = 2;
  bool server = false;
  bool client = false;
  std::vector<PacketBackend> backends;
  std::vector<workload::Scenario> scenarios;
  bool datagram = false;
  bool resumption = false;
  bool earlyData = false;
  std::vector<std::string> effectiveFeatures;
};

} // namespace quicperf
