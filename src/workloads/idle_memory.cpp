#include "workloads.h"

#include <fstream>
#include <stdexcept>

namespace quicperf::workloads {
namespace {

uint64_t readIntegerFile(const std::string& path)
{
  std::ifstream input(path);
  uint64_t value = 0;
  if (!(input >> value)) throw std::runtime_error("unable to read memory counter: " + path);
  return value;
}

uint64_t parseKbLine(const std::string& line, const std::string& name)
{
  if (!line.starts_with(name + ":")) return 0;
  const size_t begin = line.find_first_of("0123456789");
  if (begin == std::string::npos) throw std::runtime_error("malformed smaps_rollup counter");
  size_t consumed = 0;
  const uint64_t value = std::stoull(line.substr(begin), &consumed);
  return value * 1'024;
}

} // namespace

MemorySnapshot readMemorySnapshot(const std::string& cgroupMemoryCurrent, const std::string& smapsRollup)
{
  MemorySnapshot snapshot {readIntegerFile(cgroupMemoryCurrent), 0, 0, 0};
  std::ifstream input(smapsRollup);
  if (!input) throw std::runtime_error("unable to read smaps_rollup: " + smapsRollup);
  std::string line;
  while (std::getline(input, line))
  {
    snapshot.privateCleanBytes += parseKbLine(line, "Private_Clean");
    snapshot.privateDirtyBytes += parseKbLine(line, "Private_Dirty");
    snapshot.anonymousBytes += parseKbLine(line, "Anonymous");
  }
  return snapshot;
}

} // namespace quicperf::workloads
