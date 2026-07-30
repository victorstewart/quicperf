#include "adapters/adapter_factory.h"
#include "core/control_protocol.h"
#include "core/event_loop.h"
#include "core/runtime_ownership.h"
#include "core/strict_config.h"
#include "core/workload_engine.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <elf.h>
#include <iostream>
#include <link.h>
#include <limits>
#include <malloc.h>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <time.h>
#include <utility>
#include <vector>
#include <string_view>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace quicperf {
namespace {

using control::Bytes;
using control::Field;
using control::MessageType;
using control::Packet;
using control::Tlv;
using control::WireType;

int controlFd(int argc, char** argv)
{
  constexpr std::string_view prefix = "--control-fd=";
  for (int index = 2; index < argc; ++index)
  {
    const std::string_view argument = argv[index];
    if (!argument.starts_with(prefix)) continue;
    int fd = -1;
    const auto value = argument.substr(prefix.size());
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), fd);
    if (parsed.ec == std::errc {} && parsed.ptr == value.data() + value.size() && fd >= 0) return fd;
  }
  throw std::invalid_argument("missing or invalid --control-fd");
}

bool primeAllocatorArena() noexcept
{
  constexpr size_t allocationBytes = 64U << 10;
  std::array<void*, 256> allocations {};
  size_t allocated = 0;
  for (; allocated < allocations.size(); ++allocated)
  {
    allocations[allocated] = malloc(allocationBytes);
    if (!allocations[allocated]) break;
    auto* bytes = static_cast<volatile unsigned char*>(allocations[allocated]);
    bytes[0] = 0;
    bytes[allocationBytes - 1] = 0;
  }
  while (allocated) free(allocations[--allocated]);
  (void)malloc_trim(0);
  return std::ranges::all_of(allocations, [](void* allocation) {
    return allocation != nullptr;
  });
}

void primeSystemRuntime()
{
  tzset();
  if (!primeAllocatorArena())
    throw std::runtime_error("cannot prime the system allocator");
  bool threadPrimed = false;
  std::jthread thread([&] { threadPrimed = primeAllocatorArena(); });
  thread.join();
  if (!threadPrimed)
    throw std::runtime_error("cannot prime the threaded system allocator");
}

void sendPacket(int fd, const Packet& packet)
{
  const auto encoded = control::encode(packet);
  const ssize_t sent = send(fd, encoded.data(), encoded.size(), MSG_NOSIGNAL);
  if (sent != static_cast<ssize_t>(encoded.size())) throw std::runtime_error("control send failed");
}

Packet receivePacket(int fd, uint64_t sequence)
{
  std::vector<uint8_t> bytes(control::maximumPacketSize);
  const ssize_t count = recv(fd, bytes.data(), bytes.size(), 0);
  if (count <= 0) throw std::runtime_error("control receive failed");
  const auto decoded = control::decode(std::span<const uint8_t>(bytes).first(static_cast<size_t>(count)), sequence);
  if (!decoded) throw std::runtime_error(decoded.error);
  return decoded.packet;
}

int findMainBuildId(dl_phdr_info* info, size_t, void* opaque)
{
  if (info->dlpi_name && *info->dlpi_name) return 0;
  auto& result = *static_cast<Bytes*>(opaque);
  for (ElfW(Half) index = 0; index < info->dlpi_phnum; ++index)
  {
    const auto& header = info->dlpi_phdr[index];
    if (header.p_type != PT_NOTE) continue;
    const auto* bytes = reinterpret_cast<const uint8_t*>(info->dlpi_addr + header.p_vaddr);
    size_t offset = 0;
    while (offset + sizeof(ElfW(Nhdr)) <= header.p_memsz)
    {
      const auto* note = reinterpret_cast<const ElfW(Nhdr)*>(bytes + offset);
      offset += sizeof(ElfW(Nhdr));
      const size_t nameOffset = offset;
      offset += (note->n_namesz + 3U) & ~size_t {3U};
      const size_t descriptionOffset = offset;
      offset += (note->n_descsz + 3U) & ~size_t {3U};
      if (offset > header.p_memsz) break;
      if (note->n_type == NT_GNU_BUILD_ID && note->n_namesz == 4 &&
          std::memcmp(bytes + nameOffset, "GNU", 4) == 0 && note->n_descsz > 0)
      {
        result.assign(bytes + descriptionOffset, bytes + descriptionOffset + note->n_descsz);
        return 1;
      }
    }
  }
  return 0;
}

Bytes buildId(const Capabilities&)
{
  static const Bytes value = [] {
    Bytes result;
    dl_iterate_phdr(findMainBuildId, &result);
    if (result.empty()) throw std::runtime_error("ELF build ID is unavailable");
    return result;
  }();
  return value;
}

std::string joinBackends(const Capabilities& capabilities)
{
  std::string value;
  for (const auto backend : capabilities.backends)
  {
    if (!value.empty()) value.push_back(',');
    value += backend == PacketBackend::syscall ? "syscall" : "iouring";
  }
  return value.empty() ? "none" : value;
}

std::string joinRoles(const Capabilities& capabilities)
{
  std::string value;
  if (capabilities.server) value = "server";
  if (capabilities.client) value += value.empty() ? "client" : ",client";
  return value.empty() ? "none" : value;
}

std::string joinScenarios(const Capabilities& capabilities)
{
  std::string value;
  for (const auto scenario : capabilities.scenarios)
  {
    if (!value.empty()) value.push_back(',');
    value += std::to_string(static_cast<uint16_t>(scenario));
  }
  return value.empty() ? "none" : value;
}

std::string joinFeatures(const Capabilities& capabilities)
{
  std::string value;
  for (const auto& feature : capabilities.effectiveFeatures)
  {
    if (!value.empty()) value.push_back(',');
    value += feature;
  }
  return value.empty() ? "none" : value;
}

Packet hello(const Capabilities& capabilities, std::string role, uint64_t sequence)
{
  return {MessageType::hello, 0, sequence,
          {{Field::role, WireType::utf8, std::move(role)}, {Field::buildId, WireType::bytes, buildId(capabilities)},
           {Field::controlVersion, WireType::u64, uint64_t {control::protocolVersion}}}};
}

Packet capabilityPacket(const Capabilities& capabilities, uint64_t sequence)
{
  return {MessageType::capabilities, 0, sequence,
          {{Field::library, WireType::utf8, capabilities.library},
           {Field::buildId, WireType::bytes, buildId(capabilities)},
           {Field::protocolVersion, WireType::u64, uint64_t {control::protocolVersion}},
           {Field::roles, WireType::utf8, joinRoles(capabilities)},
           {Field::backends, WireType::utf8, joinBackends(capabilities)},
           {Field::scenarios, WireType::utf8, joinScenarios(capabilities)},
           {Field::capabilities, WireType::utf8,
            std::string(capabilities.datagram ? "datagram" : "stream") +
                (capabilities.resumption ? ",resumption" : "") + (capabilities.earlyData ? ",early_data" : "")},
           {Field::effectiveFeatures, WireType::utf8, joinFeatures(capabilities)}}};
}

int describe(int fd, Adapter& adapter)
{
  sendPacket(fd, hello(adapter.capabilities(), "describe", 1));
  sendPacket(fd, capabilityPacket(adapter.capabilities(), 2));
  const auto shutdown = receivePacket(fd, 1);
  if (shutdown.type != MessageType::shutdown) throw std::runtime_error("describe expected SHUTDOWN");
  sendPacket(fd, {MessageType::shutdownAck, 0, 3, {}});
  return 0;
}

const Bytes& bytesField(const Packet& packet, Field field)
{
  const auto* value = control::find(packet, field);
  if (!value) throw std::runtime_error("missing control bytes field");
  return std::get<Bytes>(value->value);
}

const std::string& textField(const Packet& packet, Field field)
{
  const auto* value = control::find(packet, field);
  if (!value) throw std::runtime_error("missing control text field");
  return std::get<std::string>(value->value);
}

uint64_t unsignedField(const Packet& packet, Field field)
{
  const auto* value = control::find(packet, field);
  if (!value) throw std::runtime_error("missing control integer field");
  return std::get<uint64_t>(value->value);
}

std::string backendName(PacketBackend backend)
{
  return backend == PacketBackend::syscall ? "syscall" : "iouring";
}

bool supports(const Capabilities& capabilities, workload::Scenario scenario)
{
  return std::ranges::find(capabilities.scenarios, scenario) != capabilities.scenarios.end();
}

std::pair<uint32_t, uint32_t> shardConnectionRange(
    uint32_t total, uint32_t workers, uint32_t shard)
{
  const uint32_t base = total / workers;
  const uint32_t remainder = total % workers;
  return {
      shard * base + std::min(shard, remainder),
      base + (shard < remainder ? 1U : 0U),
  };
}

std::vector<int> allowedCpus()
{
  cpu_set_t set;
  CPU_ZERO(&set);
  if (sched_getaffinity(0, sizeof(set), &set) != 0) throw std::runtime_error("sched_getaffinity failed");
  std::vector<int> cpus;
  for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
    if (CPU_ISSET(cpu, &set)) cpus.push_back(cpu);
  if (cpus.empty()) throw std::runtime_error("worker has no allowed CPU");
  return cpus;
}

void pinThread(int cpu)
{
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0)
    throw std::runtime_error("pthread_setaffinity_np failed");
}

uint64_t threadCpuNowNs(clockid_t clock)
{
  timespec value {};
  if (clock_gettime(clock, &value) != 0)
    throw std::runtime_error("thread CPU clock failed");
  return static_cast<uint64_t>(value.tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(value.tv_nsec);
}

struct EndpointCpuSample
{
  uint64_t rawNs;
  uint64_t cpuNs;
};

EndpointCpuSample sampleEndpointCpu(std::span<const clockid_t> clocks)
{
  const uint64_t before = monotonicRawNowNs();
  uint64_t cpu = 0;
  for (const auto clock : clocks)
  {
    const uint64_t value = threadCpuNowNs(clock);
    if (value > std::numeric_limits<uint64_t>::max() - cpu)
      throw std::overflow_error("endpoint CPU clock overflow");
    cpu += value;
  }
  const uint64_t after = monotonicRawNowNs();
  return {before + (after - before) / 2, cpu};
}

std::string decimalRatio(uint64_t numerator, uint64_t denominator, unsigned digits = 9)
{
  if (denominator == 0 || numerator == 0) return "0";
  const uint64_t whole = numerator / denominator;
  uint64_t remainder = numerator % denominator;
  std::string result = std::to_string(whole);
  if (!remainder) return result;
  result.push_back('.');
  for (unsigned index = 0; index < digits && remainder; ++index)
  {
    const unsigned __int128 scaled = static_cast<unsigned __int128>(remainder) * 10;
    result.push_back(static_cast<char>('0' + scaled / denominator));
    remainder = static_cast<uint64_t>(scaled % denominator);
  }
  while (result.back() == '0') result.pop_back();
  if (result.back() == '.') result.pop_back();
  return result;
}

template <typename T>
void addChecked(T& destination, T value)
{
  if (value > std::numeric_limits<T>::max() - destination)
    throw std::overflow_error("endpoint counter overflow");
  destination += value;
}

void addSnapshot(workload::RuntimeSnapshot& destination, const workload::RuntimeSnapshot& source)
{
  auto addCounters = [](WorkloadCounters& left, const WorkloadCounters& right) {
    addChecked(left.admitted, right.admitted);
    addChecked(left.accepted, right.accepted);
    addChecked(left.peerValidated, right.peerValidated);
    addChecked(left.completedAfterEnd, right.completedAfterEnd);
    addChecked(left.duplicates, right.duplicates);
    addChecked(left.payloadErrors, right.payloadErrors);
    addChecked(left.unreturned, right.unreturned);
    addChecked(left.workCapHits, right.workCapHits);
    addChecked(left.streamCreditExhaustions, right.streamCreditExhaustions);
    addChecked(left.generatorStarvations, right.generatorStarvations);
    for (size_t index = 0; index < left.subwindows.size(); ++index)
    {
      addChecked(left.subwindows[index].validatedUnits, right.subwindows[index].validatedUnits);
      addChecked(left.subwindows[index].blockedEvents, right.subwindows[index].blockedEvents);
    }
  };
  addCounters(destination.counters, source.counters);
  addChecked(destination.transport.packetsReceived, source.transport.packetsReceived);
  addChecked(destination.transport.packetsSent, source.transport.packetsSent);
  addChecked(destination.transport.packetsLost, source.transport.packetsLost);
  addChecked(destination.transport.packetsRetransmitted, source.transport.packetsRetransmitted);
  addChecked(destination.transport.timerExpirations, source.transport.timerExpirations);
  addChecked(destination.transport.recoveryWakeups, source.transport.recoveryWakeups);
  addChecked(destination.transport.flowControlBlockedEvents, source.transport.flowControlBlockedEvents);
  addChecked(destination.transport.streamCreditBlockedEvents, source.transport.streamCreditBlockedEvents);
  addChecked(destination.flowControlWriteBlockedEvents, source.flowControlWriteBlockedEvents);
  addChecked(destination.peerValidated, source.peerValidated);
  addChecked(destination.failed, source.failed);
  addChecked(destination.outstanding, source.outstanding);
  addChecked(destination.inFlight, source.inFlight);
  addChecked(destination.byteCapHits, source.byteCapHits);
  addChecked(destination.streamCapHits, source.streamCapHits);
  addChecked(destination.streamIdCapHits, source.streamIdCapHits);
  addChecked(destination.socketDrops, source.socketDrops);
  addChecked(destination.liveConnections, source.liveConnections);
  addChecked(destination.readyConnections, source.readyConnections);
  addChecked(destination.stopSent, source.stopSent);
  addChecked(destination.stopReceived, source.stopReceived);
  addChecked(destination.stopAcknowledged, source.stopAcknowledged);
  addChecked(destination.stopAckSent, source.stopAckSent);
  addChecked(destination.stopOffered, source.stopOffered);
  for (const auto& incoming : source.connectionValidatedUnits)
  {
    const auto existing = std::ranges::find(
        destination.connectionValidatedUnits, incoming.ordinal,
        &workload::ConnectionValidatedUnits::ordinal);
    if (existing != destination.connectionValidatedUnits.end())
      throw std::runtime_error(
          "logical connection ordinal is duplicated across endpoint shards");
    destination.connectionValidatedUnits.push_back(incoming);
  }
  std::ranges::sort(
      destination.connectionValidatedUnits, {}, &workload::ConnectionValidatedUnits::ordinal);
  for (const auto& incoming : source.connectionBarrierStates)
  {
    const auto existing = std::ranges::find(
        destination.connectionBarrierStates, incoming.ordinal,
        &workload::ConnectionBarrierState::ordinal);
    if (existing != destination.connectionBarrierStates.end())
      throw std::runtime_error(
          "logical connection barrier ordinal is duplicated across endpoint shards");
    destination.connectionBarrierStates.push_back(incoming);
  }
  std::ranges::sort(
      destination.connectionBarrierStates, {}, &workload::ConnectionBarrierState::ordinal);
  for (size_t index = 0; index < destination.cleanupStrata.size(); ++index)
  {
    addChecked(destination.cleanupStrata[index], source.cleanupStrata[index]);
    addChecked(destination.cleanupPending[index], source.cleanupPending[index]);
  }
  addChecked(destination.tailStartedOperations, source.tailStartedOperations);
  addChecked(destination.tailFailedOperations, source.tailFailedOperations);
  addChecked(destination.tailCensoredOperations, source.tailCensoredOperations);
  for (size_t index = 0; index < destination.tailPrefixStarted.size(); ++index)
  {
    addChecked(destination.tailPrefixStarted[index], source.tailPrefixStarted[index]);
    addChecked(destination.tailPrefixSuccessful[index], source.tailPrefixSuccessful[index]);
    addChecked(destination.tailPrefixFailed[index], source.tailPrefixFailed[index]);
    destination.tailPrefixObservations[index].insert(
        destination.tailPrefixObservations[index].end(),
        source.tailPrefixObservations[index].begin(),
        source.tailPrefixObservations[index].end());
  }
  destination.tailObservations.insert(destination.tailObservations.end(),
                                      source.tailObservations.begin(), source.tailObservations.end());
  if (destination.tailOwnership == workload::RuntimeSnapshot::TailOwnership::none)
    destination.tailOwnership = source.tailOwnership;
  else if (source.tailOwnership != workload::RuntimeSnapshot::TailOwnership::none &&
           destination.tailOwnership != source.tailOwnership)
    throw std::logic_error("endpoint shards disagree on tail evidence ownership");
  destination.completionReconciled = destination.completionReconciled && source.completionReconciled;
  if (!destination.hasNegotiatedSettings)
  {
    destination.hasNegotiatedSettings = source.hasNegotiatedSettings;
    destination.negotiatedSettings = source.negotiatedSettings;
    destination.negotiatedSettingsMatch = source.negotiatedSettingsMatch;
    destination.negotiatedSettingsMismatchReason = source.negotiatedSettingsMismatchReason;
  }
  else if (source.hasNegotiatedSettings)
  {
    const auto destinationEvidence = negotiatedSettingsJson(
        destination.negotiatedSettings, destination.negotiatedSettingsMatch,
        destination.negotiatedSettingsMismatchReason);
    const auto sourceEvidence = negotiatedSettingsJson(
        source.negotiatedSettings, source.negotiatedSettingsMatch,
        source.negotiatedSettingsMismatchReason);
    if (destinationEvidence != sourceEvidence)
      throw std::runtime_error(
          "endpoint shards produced nonidentical negotiated treatment evidence: destination=" +
          destinationEvidence + " source=" + sourceEvidence);
  }
  destination.flowControlRecoveryEvidence = destination.flowControlRecoveryEvidence || source.flowControlRecoveryEvidence;
}

std::string barrierStateSummary(const workload::RuntimeSnapshot& snapshot)
{
  std::ostringstream output;
  output << '[';
  for (size_t index = 0; index < snapshot.connectionBarrierStates.size(); ++index)
  {
    if (index) output << ',';
    const auto& state = snapshot.connectionBarrierStates[index];
    output << state.ordinal << ':' << state.sentFrames << '/'
           << state.receivedFrames << '/';
    if (state.peerSentFramesKnown) output << state.peerSentFrames;
    else output << '?';
    if (state.pendingApplicationFrames) output << 'p';
  }
  output << ']';
  return output.str();
}

struct EndpointShard {
  std::unique_ptr<Adapter> adapter;
  std::unique_ptr<PacketIoDriver> packetIo;
  std::unique_ptr<EventLoop> eventLoop;
  std::unique_ptr<workload::Runtime> runtime;
  std::mutex mutex;

  bool step(uint64_t stopRawNs, AdapterError& error)
  {
    return stepImpl(stopRawNs, false, error);
  }

  bool stepNonblocking(AdapterError& error)
  {
    return stepImpl(0, true, error);
  }

private:
  bool stepImpl(uint64_t stopRawNs, bool nonblocking, AdapterError& error)
  {
    std::lock_guard lock(mutex);
    uint64_t now = monotonicRawNowNs();
    const auto appendRuntime = [&] {
      AdapterRuntimeScope scope(now);
      const auto snapshot = runtime->snapshot();
      error.message += " [runtime live=" + std::to_string(snapshot.liveConnections) +
          " ready=" + std::to_string(snapshot.readyConnections) +
          " validated=" + std::to_string(snapshot.counters.peerValidated) +
          " peer_validated=" + std::to_string(snapshot.peerValidated) +
          " cleanup=" + std::to_string(snapshot.cleanupStrata[0]) + '/' +
              std::to_string(snapshot.cleanupStrata[1]) + '/' +
              std::to_string(snapshot.cleanupStrata[2]) + '/' +
              std::to_string(snapshot.cleanupStrata[3]) +
          " cleanup_pending=" + std::to_string(snapshot.cleanupPending[0]) + '/' +
              std::to_string(snapshot.cleanupPending[1]) + '/' +
              std::to_string(snapshot.cleanupPending[2]) + '/' +
              std::to_string(snapshot.cleanupPending[3]) +
          " outstanding=" + std::to_string(snapshot.outstanding) +
          " in_flight=" + std::to_string(snapshot.inFlight) +
          " stop_sent=" + std::to_string(snapshot.stopSent) +
          " stop_received=" + std::to_string(snapshot.stopReceived) +
          " stop_acknowledged=" + std::to_string(snapshot.stopAcknowledged) +
          " stop_ack_sent=" + std::to_string(snapshot.stopAckSent) + ']';
    };
    bool pumped = false;
    {
      AdapterRuntimeScope scope(now);
      pumped = runtime->pump(now, error);
    }
    if (!pumped)
    {
      appendRuntime();
      return false;
    }
    if (!(nonblocking ? eventLoop->driveOnceNonblocking(error) :
                       eventLoop->driveOnce(stopRawNs, error)))
    {
      const auto& counters = packetIo->counters();
      error.message += " [packet_io sent=" + std::to_string(counters.packetsSent) +
          " received=" + std::to_string(counters.packetsReceived) +
          " send_calls=" + std::to_string(counters.sendCalls) +
          " backpressure=" + std::to_string(counters.backpressureEvents) + ']';
      return false;
    }
    const uint64_t afterDriveNow = monotonicRawNowNs();
    {
      AdapterRuntimeScope scope(afterDriveNow);
      pumped = runtime->pump(afterDriveNow, error);
    }
    if (!pumped)
    {
      appendRuntime();
      return false;
    }
    return true;
  }

public:

  bool stopAdmission(uint64_t nowRawNs, AdapterError& error)
  {
    std::lock_guard lock(mutex);
    AdapterRuntimeScope scope(nowRawNs);
    return runtime->stopAdmission(nowRawNs, error);
  }

  workload::RuntimeSnapshot snapshot()
  {
    std::lock_guard lock(mutex);
    AdapterRuntimeScope scope;
    return runtime->snapshot();
  }

  bool complete()
  {
    std::lock_guard lock(mutex);
    AdapterRuntimeScope scope;
    return runtime->completionReconciled();
  }


  bool idleEstablished()
  {
    std::lock_guard lock(mutex);
    AdapterRuntimeScope scope;
    return runtime->idleEstablished();
  }

  PacketIoCounters packetIoCounters()
  {
    std::lock_guard lock(mutex);
    return packetIo->counters();
  }
};

std::vector<PacketIoDriver*> packetIoOwners(
    const std::vector<std::unique_ptr<EndpointShard>>& shards)
{
  std::vector<PacketIoDriver*> result;
  result.reserve(shards.size());
  for (const auto& shard : shards) result.push_back(shard->packetIo.get());
  return result;
}

bool runtimeOwnershipAuditEnabled()
{
  const char* value = getenv("QUICPERF_RUNTIME_OWNERSHIP_AUDIT");
  if (!value) return false;
  if (strcmp(value, "1") != 0)
    throw std::runtime_error("QUICPERF_RUNTIME_OWNERSHIP_AUDIT must be exactly 1");
  return true;
}

workload::RuntimeSnapshot aggregate(std::vector<std::unique_ptr<EndpointShard>>& shards)
{
  workload::RuntimeSnapshot result;
  result.completionReconciled = true;
  for (auto& shard : shards) addSnapshot(result, shard->snapshot());
  return result;
}

PacketIoCounters aggregatePacketIo(std::vector<std::unique_ptr<EndpointShard>>& shards)
{
  PacketIoCounters result;
  for (auto& shard : shards)
  {
    const auto source = shard->packetIoCounters();
#define QUICPERF_ADD_PACKET_COUNTER(field) addChecked(result.field, source.field)
    QUICPERF_ADD_PACKET_COUNTER(packetsReceived);
    QUICPERF_ADD_PACKET_COUNTER(packetsSent);
    QUICPERF_ADD_PACKET_COUNTER(udpDatagramsReceived);
    QUICPERF_ADD_PACKET_COUNTER(udpDatagramsSent);
    QUICPERF_ADD_PACKET_COUNTER(groSegmentsReceived);
    QUICPERF_ADD_PACKET_COUNTER(gsoSegmentsSent);
    QUICPERF_ADD_PACKET_COUNTER(receiveCalls);
    QUICPERF_ADD_PACKET_COUNTER(sendCalls);
    QUICPERF_ADD_PACKET_COUNTER(receiveErrors);
    QUICPERF_ADD_PACKET_COUNTER(sendErrors);
    QUICPERF_ADD_PACKET_COUNTER(backpressureEvents);
    QUICPERF_ADD_PACKET_COUNTER(lossPacketsConsidered);
    QUICPERF_ADD_PACKET_COUNTER(lossPacketsDropped);
    QUICPERF_ADD_PACKET_COUNTER(lossWarmupPacketsConsidered);
    QUICPERF_ADD_PACKET_COUNTER(lossWarmupPacketsDropped);
    QUICPERF_ADD_PACKET_COUNTER(lossMeasurementPacketsConsidered);
    QUICPERF_ADD_PACKET_COUNTER(lossMeasurementPacketsDropped);
#undef QUICPERF_ADD_PACKET_COUNTER
  }
  return result;
}

bool allIdleEstablished(std::vector<std::unique_ptr<EndpointShard>>& shards)
{
  return std::ranges::all_of(shards, [](auto& shard) { return shard->idleEstablished(); });
}

std::string countersJson(const workload::RuntimeSnapshot& snapshot)
{
  std::ostringstream output;
  output << "{\"application_bytes_or_operations\":" << snapshot.counters.peerValidated
         << ",\"peer_application_bytes_or_operations\":" << snapshot.peerValidated
         << ",\"packets_received\":" << snapshot.transport.packetsReceived
         << ",\"packets_sent\":" << snapshot.transport.packetsSent
         << ",\"packets_lost\":" << snapshot.transport.packetsLost
         << ",\"packets_retransmitted\":" << snapshot.transport.packetsRetransmitted
         << ",\"timer_expirations\":" << snapshot.transport.timerExpirations << '}';
  return output.str();
}

std::string tailOwnershipName(workload::RuntimeSnapshot::TailOwnership ownership)
{
  using enum workload::RuntimeSnapshot::TailOwnership;
  if (ownership == complete) return "complete";
  if (ownership == senderStarts) return "sender_starts";
  if (ownership == receiverTerminals) return "receiver_terminals";
  return "none";
}

std::string tailJson(const workload::RuntimeSnapshot& snapshot, uint64_t globalStart)
{
  if (snapshot.tailOwnership == workload::RuntimeSnapshot::TailOwnership::none) return "null";
  auto observations = snapshot.tailObservations;
  std::ranges::sort(observations, [](const auto& left, const auto& right) {
    return std::pair {left.startRawNs, left.operationSequence} <
        std::pair {right.startRawNs, right.operationSequence};
  });
  if (observations.size() > 1'024) observations.resize(1'024);
  std::ostringstream output;
  output << "{\"started_operations\":" << snapshot.tailStartedOperations
         << ",\"failed_operations\":" << snapshot.tailFailedOperations
         << ",\"censored_operations\":" << snapshot.tailCensoredOperations
         << ",\"prefixes\":[";
  constexpr std::array<uint64_t, 4> durationsSeconds {2, 5, 10, 20};
  for (size_t index = 0; index < durationsSeconds.size(); ++index)
  {
    if (index) output << ',';
    const auto started = snapshot.tailPrefixStarted[index];
    const auto successful = snapshot.tailPrefixSuccessful[index];
    const auto failed = snapshot.tailPrefixFailed[index];
    if (successful > started || failed > started - successful)
      throw std::runtime_error("tail prefix counters do not reconcile");
    auto prefixObservations = snapshot.tailPrefixObservations[index];
    std::ranges::sort(prefixObservations, [](const auto& left, const auto& right) {
      return std::pair {left.startRawNs, left.operationSequence} <
          std::pair {right.startRawNs, right.operationSequence};
    });
    if (prefixObservations.size() > 1'024) prefixObservations.resize(1'024);
    std::vector<uint64_t> latencies;
    latencies.reserve(prefixObservations.size());
    for (const auto& observation : prefixObservations)
      latencies.push_back(observation.terminalRawNs - observation.startRawNs);
    std::ranges::sort(latencies);
    const auto p99 = latencies.empty() ? 0 :
        latencies[((99 * latencies.size() + 99) / 100) - 1];
    output << "{\"duration_seconds\":" << durationsSeconds[index]
           << ",\"started_operations\":" << started
           << ",\"successful_operations\":" << successful
           << ",\"failed_operations\":" << failed
           << ",\"censored_operations\":" << (started - successful - failed)
           << ",\"p99_ns\":" << p99
           << '}';
  }
  output << "],\"histogram_resolution_ns\":1,\"operations\":[";
  for (size_t index = 0; index < observations.size(); ++index)
  {
    if (index) output << ',';
    const auto& observation = observations[index];
    if (observation.startRawNs < globalStart || observation.terminalRawNs < observation.startRawNs)
      throw std::runtime_error("tail observation is outside the common raw-clock domain");
    // RESULT is one <=64 KiB control packet.  Encode the endpoint-private wire
    // form as [sequence,start-offset,latency]; the coordinator expands it to
    // the strict result-v2 object before validation or persistence.
    output << '[' << observation.operationSequence
           << ',' << (observation.startRawNs - globalStart)
           << ',' << (observation.terminalRawNs - observation.startRawNs) << ']';
  }
  output << "]}";
  return output.str();
}

std::string endpointResultJson(const Bytes& trialId, const Bytes& cellId,
                               const EndpointConfig& config, std::string_view canonicalConfig,
                               const workload::RuntimeSnapshot& snapshot,
                               const PacketIoCounters& packetIo, uint64_t globalStart,
                               uint64_t globalEnd, uint64_t actualStart, uint64_t actualEnd,
                               std::string_view cpuP95, bool clockValid)
{
  const auto scenario = workload::scenarioFromName(config.scenario);
  uint64_t numerator = snapshot.counters.peerValidated;
  if (config.role == EndpointRole::server && workload::serverUsesPeerNumerator(scenario))
    numerator = snapshot.peerValidated;
  const auto configBytes = std::span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(canonicalConfig.data()), canonicalConfig.size());
  const auto configHash = workload::sha256(configBytes);
  std::ostringstream output;
  output << "{\"actual_end_raw_ns\":" << actualEnd
         << ",\"actual_start_raw_ns\":" << actualStart
         << ",\"backend\":\"" << backendName(config.backend) << "\""
         << ",\"byte_cap_hits\":" << snapshot.byteCapHits
         << ",\"cell_id\":\"" << workload::hex(cellId) << "\""
         << ",\"cleanup_strata\":[" << snapshot.cleanupStrata[0] << ',' << snapshot.cleanupStrata[1]
         << ',' << snapshot.cleanupStrata[2] << ',' << snapshot.cleanupStrata[3] << ']'
         << ",\"client_cpu_fraction_of_quota_p95\":\"" << cpuP95 << "\""
         << ",\"completed\":" << numerator
         << ",\"denominator_raw_ns\":" << (globalEnd - globalStart)
         << ",\"duplicate\":" << snapshot.counters.duplicates
         << ",\"effective_config_hash\":\"" << workload::hex(configHash) << "\""
         << ",\"failed\":" << snapshot.failed
         << ",\"flow_control_blocked_events\":" << snapshot.transport.flowControlBlockedEvents
         << ",\"flow_control_write_blocked_events\":" << snapshot.flowControlWriteBlockedEvents
         << ",\"flow_control_recovery_evidence\":" << (snapshot.flowControlRecoveryEvidence ? "true" : "false")
         << ",\"generator_starvation_events\":" << snapshot.counters.generatorStarvations
         << ",\"global_end_raw_ns\":" << globalEnd
         << ",\"global_start_raw_ns\":" << globalStart
         << ",\"in_flight\":" << snapshot.inFlight
         << ",\"loss_direction\":" << (config.role == EndpointRole::server ? 0 : 1)
         << ",\"loss_measurement_packets_considered\":" << packetIo.lossMeasurementPacketsConsidered
         << ",\"loss_measurement_packets_dropped\":" << packetIo.lossMeasurementPacketsDropped
         << ",\"loss_packets_considered\":" << packetIo.lossPacketsConsidered
         << ",\"loss_packets_dropped\":" << packetIo.lossPacketsDropped
         << ",\"loss_warmup_packets_considered\":" << packetIo.lossWarmupPacketsConsidered
         << ",\"loss_warmup_packets_dropped\":" << packetIo.lossWarmupPacketsDropped
         << ",\"measurement_subwindows\":[";
  for (size_t index = 0; index < snapshot.counters.subwindows.size(); ++index)
  {
    if (index) output << ',';
    output << "{\"blocked_events\":" << snapshot.counters.subwindows[index].blockedEvents
           << ",\"validated_units\":" << snapshot.counters.subwindows[index].validatedUnits << '}';
  }
  output << ']'
         << ",\"negotiated\":" << negotiatedSettingsJson(
                snapshot.negotiatedSettings, snapshot.negotiatedSettingsMatch,
                snapshot.negotiatedSettingsMismatchReason)
         << ",\"negotiated_settings_match\":" << (snapshot.negotiatedSettingsMatch ? "true" : "false")
         << ",\"numerator\":" << numerator
         << ",\"outstanding\":" << snapshot.outstanding
         << ",\"payload_errors\":" << snapshot.counters.payloadErrors
         << ",\"peer_numerator\":" << snapshot.peerValidated
         << ",\"per_connection_validated_units\":[";
  for (size_t index = 0; index < snapshot.connectionValidatedUnits.size(); ++index)
  {
    if (index) output << ',';
    const auto& connection = snapshot.connectionValidatedUnits[index];
    output << '[' << connection.ordinal << ',' << connection.units << ']';
  }
  output << ']'
         << ",\"role\":\"" << (config.role == EndpointRole::server ? "server" : "client") << "\""
         << ",\"scenario\":\"" << config.scenario << "\""
         << ",\"schema_version\":\"quicperf.endpoint-result.v2\""
         << ",\"socket_drops\":" << snapshot.socketDrops
         << ",\"stream_cap_hits\":" << snapshot.streamCapHits
         << ",\"stream_credit_blocked_events\":" << snapshot.transport.streamCreditBlockedEvents
         << ",\"stream_id_cap_hits\":" << snapshot.streamIdCapHits
         << ",\"tail\":" << tailJson(snapshot, globalStart)
         << ",\"tail_observation_ownership\":\"" << tailOwnershipName(snapshot.tailOwnership) << "\""
         << ",\"termination_reason\":\"" << (clockValid ? "deadline_reached" : "protocol_error") << "\""
         << ",\"trial_id\":\"" << workload::hex(trialId) << "\""
         << ",\"unreturned\":" << snapshot.counters.unreturned
         << ",\"transport_packets_lost\":" << snapshot.transport.packetsLost
         << ",\"transport_packets_retransmitted\":" << snapshot.transport.packetsRetransmitted
         << ",\"transport_recovery_wakeups\":" << snapshot.transport.recoveryWakeups
         << ",\"transport_timer_expirations\":" << snapshot.transport.timerExpirations
         << ",\"work_cap_hits\":" << snapshot.counters.workCapHits << '}';
  return output.str();
}

int worker(int fd, std::unique_ptr<Adapter> firstAdapter, std::string role)
{
  primeSystemRuntime();
  uint64_t outgoing = 1;
  uint64_t incoming = 1;
  const auto initialCapabilities = firstAdapter->capabilities();
  sendPacket(fd, hello(initialCapabilities, role, outgoing++));
  sendPacket(fd, capabilityPacket(initialCapabilities, outgoing++));
  const auto laneCpus = allowedCpus();
  if ((role == "server" && laneCpus.empty()) || (role == "client" && laneCpus.size() < 2))
    throw std::runtime_error("worker CPU affinity is smaller than the declared event-loop topology");
  std::vector<std::unique_ptr<Adapter>> adapters;
  adapters.push_back(std::move(firstAdapter));
  std::optional<PacketBackend> frozenBackend;
  std::optional<size_t> frozenWorkerCount;
  for (;;)
  {
    const auto configPacket = receivePacket(fd, incoming++);
    if (configPacket.type == MessageType::shutdown)
    {
      for (auto& adapter : adapters)
      {
        AdapterError ignored;
        adapter->stop(ignored);
      }
      sendPacket(fd, {MessageType::shutdownAck, 0, outgoing++, {}});
      return 0;
    }
    if (configPacket.type != MessageType::config) throw std::runtime_error("worker expected CONFIG");
    const Bytes trialId = bytesField(configPacket, Field::trialId);
    const Bytes cellId = bytesField(configPacket, Field::cellId);
    const std::string canonicalConfig = textField(configPacket, Field::configJson);
    const auto parsed = parseEndpointConfig(canonicalConfig);
    if (!parsed)
    {
      sendPacket(fd, {MessageType::unsupported, 0, outgoing++,
                      {{Field::trialId, WireType::bytes, trialId}, {Field::reason, WireType::utf8, parsed.error}}});
      continue;
    }
    const EndpointConfig config = parsed.config;
    setRuntimeCalendarUnixSeconds(config.calendarUnixSeconds);
    if ((role == "server") != (config.role == EndpointRole::server))
      throw std::runtime_error("CONFIG role differs from the immutable worker role");
    const size_t requiredWorkers = static_cast<size_t>(config.eventLoopWorkers);
    if (requiredWorkers != laneCpus.size())
      throw std::runtime_error("CONFIG event-loop topology differs from worker CPU affinity");
    if (frozenWorkerCount && *frozenWorkerCount != requiredWorkers)
    {
      sendPacket(fd, {MessageType::unsupported, 0, outgoing++,
                      {{Field::trialId, WireType::bytes, trialId},
                       {Field::reason, WireType::utf8,
                        std::string("persistent worker event-loop topology cannot change")}}});
      continue;
    }
    if (frozenBackend && *frozenBackend != config.backend)
    {
      sendPacket(fd, {MessageType::unsupported, 0, outgoing++,
                      {{Field::trialId, WireType::bytes, trialId},
                       {Field::reason, WireType::utf8, std::string("persistent worker backend cannot change")}}});
      continue;
    }
    workload::Scenario scenario;
    try
    {
      scenario = workload::scenarioFromName(config.scenario);
    }
    catch (const std::exception& error)
    {
      sendPacket(fd, {MessageType::unsupported, 0, outgoing++,
                      {{Field::trialId, WireType::bytes, trialId},
                       {Field::reason, WireType::utf8, std::string(error.what())}}});
      continue;
    }
    if (!supports(adapters.front()->capabilities(), scenario))
    {
      sendPacket(fd, {MessageType::unsupported, 0, outgoing++,
                      {{Field::trialId, WireType::bytes, trialId},
                       {Field::reason, WireType::utf8, std::string("adapter does not attest the requested workload scenario")}}});
      continue;
    }
    while (adapters.size() < requiredWorkers)
    {
      auto extra = makeTransportAdapter();
      if (extra->capabilities().library != initialCapabilities.library)
        throw std::runtime_error("transport adapter factory identity changed within one worker");
      adapters.push_back(std::move(extra));
    }

    std::vector<std::unique_ptr<EndpointShard>> shards;
    std::string unsupportedReason;
    uint16_t serverPort = 0;
    try
    {
      for (size_t index = 0; index < requiredWorkers; ++index)
      {
        AdapterError error;
        if (!adapters[index]->configure(canonicalConfig, error))
        {
          unsupportedReason = error.message.empty() ? "adapter rejected CONFIG" : error.message;
          break;
        }
        auto shard = std::make_unique<EndpointShard>();
        shard->adapter = std::move(adapters[index]);
        try
        {
          shard->packetIo = makePacketIoDriver(config.backend, config.packetIo);
          in_addr address {};
          if (inet_pton(AF_INET, config.bindAddress.c_str(), &address) != 1)
            throw std::runtime_error("strict bind address became invalid");
          const uint16_t port = shard->packetIo->bind(address.s_addr, config.bindPort);
          sockaddr_in local {};
          local.sin_family = AF_INET;
          local.sin_addr = address;
          local.sin_port = htons(port);
          if (!shard->adapter->setLocalAddress(local, error))
          {
            unsupportedReason = error.message.empty() ? "adapter rejected the bound local address" : error.message;
            adapters[index] = std::move(shard->adapter);
            break;
          }
          if (index == 0) serverPort = port;
        }
        catch (...)
        {
          adapters[index] = std::move(shard->adapter);
          throw;
        }
        shards.push_back(std::move(shard));
      }
    }
    catch (const std::exception& error)
    {
      unsupportedReason = error.what();
    }
    for (size_t index = 0; index < shards.size(); ++index)
      adapters[index] = std::move(shards[index]->adapter);
    if (!unsupportedReason.empty() || shards.size() != requiredWorkers)
    {
      for (auto& adapter : adapters)
      {
        if (!adapter) continue;
        AdapterError ignored;
        adapter->reset(ignored);
      }
      sendPacket(fd, {MessageType::unsupported, 0, outgoing++,
                      {{Field::trialId, WireType::bytes, trialId},
                       {Field::reason, WireType::utf8,
                        unsupportedReason.empty() ? std::string("endpoint shard construction failed") : unsupportedReason}}});
      continue;
    }
    // Restore adapters to their shards after the failure-path ownership pass.
    for (size_t index = 0; index < shards.size(); ++index)
      shards[index]->adapter = std::move(adapters[index]);
    if (config.pathProfile == "loss_recovery_v1")
    {
      auto stream = std::make_shared<LossRecoveryStream>();
      for (auto& shard : shards) shard->packetIo->shareLossRecovery(stream);
    }
    frozenBackend = config.backend;
    frozenWorkerCount = requiredWorkers;
    if (config.role == EndpointRole::server)
      sendPacket(fd, {MessageType::bound, 0, outgoing++,
                      {{Field::trialId, WireType::bytes, trialId},
                     {Field::udpPort, WireType::u64, uint64_t {serverPort}}}});
    const auto ownedPacketIo = packetIoOwners(shards);
    armExternalRuntimeMonitor();
    attestRuntimeOwnership(fd, ownedPacketIo, 1, "ready");
    const bool runtimeOwnershipAudit = runtimeOwnershipAuditEnabled();
    const auto initialBridge = ClockBridge::sample();
    const uint64_t initialRawNow = monotonicRawNowNs();
    setRuntimeClockAnchor(
        initialRawNow, ClockBridge(initialBridge).monotonicDeadline(initialRawNow));
    sendPacket(fd, {MessageType::ready, 0, outgoing++,
                    {{Field::trialId, WireType::bytes, trialId},
                     {Field::pid, WireType::u64, static_cast<uint64_t>(getpid())},
                     {Field::backend, WireType::utf8, backendName(config.backend)},
                     {Field::rawNowNs, WireType::u64, monotonicRawNowNs()}}});
    armRuntimePrivateClockAudit(runtimeOwnershipAudit);

    auto arm = receivePacket(fd, incoming++);
    if (arm.type == MessageType::exercise)
    {
      if (bytesField(arm, Field::trialId) != trialId)
        throw std::runtime_error("worker expected matching EXERCISE");
      const uint64_t exerciseStarted = monotonicRawNowNs();
      const uint64_t exerciseDeadline = unsignedField(arm, Field::exerciseDeadlineRawNs);
      if (exerciseDeadline <= exerciseStarted || exerciseDeadline - exerciseStarted > 5'000'000'000ULL)
        throw std::runtime_error("EXERCISE deadline is outside the bounded reset-contract window");
      MeasurementWindow exerciseWindow {
          exerciseStarted, exerciseStarted, exerciseDeadline, exerciseStarted};
      const auto exerciseBridge = ClockBridge::sample();
      setRuntimeClockAnchor(
          exerciseStarted, ClockBridge(exerciseBridge).monotonicDeadline(exerciseStarted));
      for (size_t index = 0; index < shards.size(); ++index)
      {
        const auto [exerciseFirst, exerciseConnections] = shardConnectionRange(
            config.connectionCount, requiredWorkers, static_cast<uint32_t>(index));
        shards[index]->eventLoop = std::make_unique<EventLoop>(
            *shards[index]->packetIo, *shards[index]->adapter, ClockBridge(exerciseBridge));
        shards[index]->runtime = std::make_unique<workload::Runtime>(
            *shards[index]->adapter, config, exerciseWindow,
            std::span<const uint8_t, 32>(trialId.data(), 32),
            std::span<const uint8_t, 32>(cellId.data(), 32),
            exerciseFirst, exerciseConnections);
        AdapterError error;
        const uint64_t startNow = monotonicRawNowNs();
        bool started = false;
        {
          AdapterRuntimeScope scope(startNow);
          started = shards[index]->runtime->start(startNow, error);
        }
        if (!started)
          throw std::runtime_error(error.message.empty() ? "reset exercise start failed" : error.message);
      }
      struct ExerciseState {
        std::mutex mutex;
        std::vector<bool> created;
        std::string error;
      } exerciseState;
      exerciseState.created.resize(shards.size(), false);
      std::vector<std::jthread> exerciseWorkers;
      exerciseWorkers.reserve(shards.size());
      for (size_t index = 0; index < shards.size(); ++index)
      {
        exerciseWorkers.emplace_back([&, index](std::stop_token stop) {
          try
          {
            pinThread(laneCpus[index]);
            AdapterError error;
            while (!stop.stop_requested())
            {
              const uint64_t now = monotonicRawNowNs();
              if (now >= exerciseDeadline)
              {
                std::lock_guard lock(exerciseState.mutex);
                if (!exerciseState.created[index] && exerciseState.error.empty())
                  exerciseState.error = "reset exercise did not create live work before its deadline";
                return;
              }
              if (!shards[index]->stepNonblocking(error))
                throw std::runtime_error(error.message.empty() ? "reset exercise event loop failed" : error.message);
              const auto snapshot = shards[index]->snapshot();
              if (snapshot.liveConnections && snapshot.counters.admitted &&
                  snapshot.negotiatedSettingsMatch)
              {
                std::lock_guard lock(exerciseState.mutex);
                exerciseState.created[index] = true;
              }
            }
          }
          catch (const std::exception& error)
          {
            std::lock_guard lock(exerciseState.mutex);
            if (exerciseState.error.empty()) exerciseState.error = error.what();
          }
        });
      }
      if (runtimeOwnershipAudit)
        attestRuntimeOwnership(
            fd, ownedPacketIo, exerciseWorkers.size() + 1, "exercise");
      for (;;)
      {
        std::string error;
        bool created = false;
        {
          std::lock_guard lock(exerciseState.mutex);
          error = exerciseState.error;
          created = std::ranges::all_of(exerciseState.created, [](bool value) { return value; });
        }
        if (!error.empty()) throw std::runtime_error(error);
        if (created) break;
        if (monotonicRawNowNs() >= exerciseDeadline)
          throw std::runtime_error("reset exercise timed out before creating live work");
        std::this_thread::yield();
      }
      const auto exercised = aggregate(shards);
      const uint64_t workInventory = exercised.counters.admitted + exercised.outstanding + exercised.inFlight;
      if (!exercised.liveConnections || !workInventory)
        throw std::runtime_error("reset exercise lost its created work before attestation");
      sendPacket(fd, {MessageType::exercised, 0, outgoing++,
                      {{Field::trialId, WireType::bytes, trialId},
                       {Field::liveConnections, WireType::u64, exercised.liveConnections},
                       {Field::liveStreams, WireType::u64, exercised.inFlight},
                       {Field::liveTickets, WireType::u64, uint64_t {0}},
                       {Field::workInventory, WireType::u64, workInventory}}});
      const auto reset = receivePacket(fd, incoming++);
      if (reset.type != MessageType::reset || bytesField(reset, Field::trialId) != trialId)
        throw std::runtime_error("worker expected matching RESET after EXERCISED");
      for (auto& worker : exerciseWorkers) worker.request_stop();
      for (auto& worker : exerciseWorkers)
        if (worker.joinable()) worker.join();
      attestRuntimeOwnership(fd, ownedPacketIo, 1, "exercise-complete");
      for (size_t index = 0; index < shards.size(); ++index)
      {
        shards[index]->runtime.reset();
        shards[index]->eventLoop.reset();
        shards[index]->packetIo.reset();
        AdapterError error;
        AdapterRuntimeScope scope(monotonicRawNowNs());
        if (!shards[index]->adapter->reset(error))
          throw std::runtime_error(error.message.empty() ? "adapter reset failed" : error.message);
        adapters[index] = std::move(shards[index]->adapter);
      }
      attestRuntimeOwnership(fd, {}, 1, "exercise-reset-complete");
      sendPacket(fd, {MessageType::resetAck, 0, outgoing++,
                      {{Field::trialId, WireType::bytes, trialId},
                       {Field::liveConnections, WireType::u64, uint64_t {0}},
                       {Field::liveStreams, WireType::u64, uint64_t {0}},
                       {Field::liveTickets, WireType::u64, uint64_t {0}},
                       {Field::workInventory, WireType::u64, uint64_t {0}}}});
      continue;
    }
    MeasurementWindow window {};
    for (;;)
    {
      if (arm.type == MessageType::shutdown)
      {
        for (auto& shard : shards)
        {
          AdapterError ignored;
          AdapterRuntimeScope scope(monotonicRawNowNs());
          shard->adapter->stop(ignored);
        }
        sendPacket(fd, {MessageType::shutdownAck, 0, outgoing++, {}});
        return 0;
      }
      if (arm.type != MessageType::arm ||
          bytesField(arm, Field::trialId) != trialId)
        throw std::runtime_error("worker expected matching ARM");
      window = {
          unsignedField(arm, Field::warmupStartRawNs),
          unsignedField(arm, Field::measurementStartRawNs),
          unsignedField(arm, Field::measurementEndRawNs),
          unsignedField(arm, Field::traceEpochRawNs)};
      std::string windowError;
      if (!window.valid(windowError) ||
          window.startRawNs - window.warmupStartRawNs !=
              config.warmupDurationNs ||
          window.durationNs() != config.measurementDurationNs)
        throw std::runtime_error(
            windowError.empty() ? "ARM does not match CONFIG timing" :
                                  windowError);
      const uint64_t armObservedRawNs = monotonicRawNowNs();
      if (window.warmupStartRawNs > armObservedRawNs) break;
      sendPacket(
          fd,
          {MessageType::armRejected,
           0,
           outgoing++,
           {{Field::trialId, WireType::bytes, trialId},
            {Field::rawNowNs, WireType::u64, armObservedRawNs},
            {Field::reason, WireType::utf8,
             std::string("arm_window_not_in_future")}}});
      arm = receivePacket(fd, incoming++);
    }
    if (config.pathProfile == "loss_recovery_v1")
    {
      const uint8_t direction = config.role == EndpointRole::server ? 0 : 1;
      shards.front()->packetIo->armLossRecovery(
          config.traceSeed, window.startRawNs, window.endRawNs, direction);
    }
    const auto bridgeBefore = ClockBridge::sample();
    const uint64_t bridgeAnchorRawNs = monotonicRawNowNs();
    setRuntimeClockAnchor(
        bridgeAnchorRawNs, ClockBridge(bridgeBefore).monotonicDeadline(bridgeAnchorRawNs));
    for (size_t index = 0; index < shards.size(); ++index)
    {
      const auto [shardFirst, shardConnections] = shardConnectionRange(
          config.connectionCount, requiredWorkers, static_cast<uint32_t>(index));
      shards[index]->eventLoop = std::make_unique<EventLoop>(*shards[index]->packetIo,
                                                             *shards[index]->adapter,
                                                             ClockBridge(bridgeBefore));
      shards[index]->runtime = std::make_unique<workload::Runtime>(
          *shards[index]->adapter, config, window,
          std::span<const uint8_t, 32>(trialId.data(), 32),
          std::span<const uint8_t, 32>(cellId.data(), 32),
          shardFirst, shardConnections);
      AdapterError error;
      const uint64_t startNow = monotonicRawNowNs();
      bool started = false;
      {
        AdapterRuntimeScope scope(startNow);
        started = shards[index]->runtime->start(startNow, error);
      }
      if (!started)
        throw std::runtime_error(error.message.empty() ? "workload start failed" : error.message);
    }
    sendPacket(fd, {MessageType::armed, 0, outgoing++,
                    {{Field::trialId, WireType::bytes, trialId},
                     {Field::rawNowNs, WireType::u64, monotonicRawNowNs()}}});

    struct BackgroundState {
      std::mutex mutex;
      std::string error;
      std::atomic<size_t> boundary {0};
      std::atomic<size_t> arrived {0};
      std::atomic<size_t> completed {0};
    } background;
    const uint64_t completionDeadline = window.endRawNs + config.idleTimeoutMs * 1'000'000ULL;
    std::vector<std::jthread> backgroundWorkers;
    backgroundWorkers.reserve(shards.size() - 1);
    for (size_t index = 1; index < shards.size(); ++index)
    {
      backgroundWorkers.emplace_back([&, index, deadline = completionDeadline](std::stop_token stop) {
        try
        {
          pinThread(laneCpus[index]);
          AdapterError error;
          for (size_t boundaryIndex = 0;
               boundaryIndex <= 10 && !stop.stop_requested(); ++boundaryIndex)
          {
            const uint64_t boundary = boundaryIndex == 0 ? window.startRawNs :
                window.startRawNs + boundaryIndex * window.durationNs() / 10;
            while (!stop.stop_requested() && monotonicRawNowNs() < boundary)
            {
              const uint64_t now = monotonicRawNowNs();
              if (!shards[index]->step(std::min(boundary, now + 250'000), error))
                throw std::runtime_error(error.message.empty() ? "background event loop failed" : error.message);
            }
            background.arrived.fetch_add(1);
            while (!stop.stop_requested() &&
                   background.boundary.load() == boundaryIndex)
              std::this_thread::yield();
          }
          if (!stop.stop_requested() && !shards[index]->stopAdmission(monotonicRawNowNs(), error))
            throw std::runtime_error(error.message.empty() ? "background workload stop failed" : error.message);
          while (!stop.stop_requested() && !shards[index]->complete() && monotonicRawNowNs() < deadline)
          {
            if (!shards[index]->stepNonblocking(error))
              throw std::runtime_error(error.message.empty() ? "background completion loop failed" : error.message);
          }
          if (!stop.stop_requested() && shards[index]->complete())
            background.completed.fetch_add(1);
        }
        catch (const std::exception& error)
        {
          std::lock_guard lock(background.mutex);
          if (background.error.empty()) background.error = error.what();
        }
      });
    }
    if (runtimeOwnershipAudit)
      attestRuntimeOwnership(
          fd, ownedPacketIo, backgroundWorkers.size() + 1, "armed");
    pinThread(laneCpus[0]);
    auto backgroundError = [&]() -> std::string {
      std::lock_guard lock(background.mutex);
      return background.error;
    };
    const size_t backgroundCount = shards.size() - 1;
    auto awaitBackgroundBoundary = [&]() {
      while (background.arrived.load() != backgroundCount)
      {
        if (const auto failure = backgroundError(); !failure.empty())
          throw std::runtime_error(failure);
        std::this_thread::yield();
      }
    };
    auto releaseBackgroundBoundary = [&]() {
      background.arrived.store(0);
      background.boundary.fetch_add(1);
    };
    std::vector<clockid_t> cpuClocks;
    cpuClocks.reserve(backgroundWorkers.size() + 1);
    auto registerCpuClock = [&](pthread_t thread) {
      clockid_t clock {};
      const int error = pthread_getcpuclockid(thread, &clock);
      if (error != 0)
        throw std::runtime_error(
            "event-loop thread CPU clock failed: " + std::string(std::strerror(error)));
      cpuClocks.push_back(clock);
    };
    registerCpuClock(pthread_self());
    for (auto& worker : backgroundWorkers)
      registerCpuClock(worker.native_handle());
    auto driveFirstUntil = [&](uint64_t deadline) {
      AdapterError error;
      while (monotonicRawNowNs() < deadline)
      {
        if (const auto failure = backgroundError(); !failure.empty()) throw std::runtime_error(failure);
        const uint64_t now = monotonicRawNowNs();
        if (!shards[0]->step(std::min(deadline, now + 250'000), error))
          throw std::runtime_error(error.message.empty() ? "event loop failed" : error.message);
      }
    };

    driveFirstUntil(window.startRawNs);
    awaitBackgroundBoundary();
    if (scenario == workload::Scenario::memoryCurve && !allIdleEstablished(shards))
    {
      const auto idle = aggregate(shards);
      throw std::runtime_error(
          "memory_curve did not establish its exact idle connection treatment before T0: ready=" +
          std::to_string(idle.readyConnections) + " live=" + std::to_string(idle.liveConnections) +
          " expected=" + std::to_string(config.connectionCount));
    }
    const uint64_t actualStart = monotonicRawNowNs();
    sendPacket(fd, {MessageType::measurementStarted, 0, outgoing++,
                    {{Field::trialId, WireType::bytes, trialId},
                     {Field::rawNowNs, WireType::u64, actualStart}}});
    auto previousCpu = sampleEndpointCpu(cpuClocks);
    releaseBackgroundBoundary();
    uint64_t actualEnd = actualStart;
    std::array<std::pair<uint64_t, uint64_t>, 10> cpuFractions {};
    for (size_t index = 0; index < 10; ++index)
    {
      const uint64_t boundary = window.startRawNs + (index + 1) * window.durationNs() / 10;
      driveFirstUntil(boundary);
      awaitBackgroundBoundary();
      const uint64_t now = monotonicRawNowNs();
      actualEnd = now;
      if (runtimeOwnershipAudit)
        attestRuntimeOwnership(
            fd, ownedPacketIo, backgroundWorkers.size() + 1,
            "measurement-boundary");
      const auto cpu = sampleEndpointCpu(cpuClocks);
      cpuFractions[index] = {
          cpu.cpuNs - previousCpu.cpuNs,
          (cpu.rawNs - previousCpu.rawNs) * requiredWorkers,
      };
      previousCpu = cpu;
      const auto current = aggregate(shards);
      uint64_t progressValidated = 0;
      bool progressBlocked = false;
      for (size_t offset = 0; offset < 20; ++offset)
      {
        const auto& privateWindow = current.counters.subwindows[index * 20 + offset];
        addChecked(progressValidated, privateWindow.validatedUnits);
        progressBlocked = progressBlocked || privateWindow.blockedEvents != 0;
      }
      sendPacket(fd, {MessageType::progress, 0, outgoing++,
                      {{Field::trialId, WireType::bytes, trialId},
                       {Field::eventIndex, WireType::u64, static_cast<uint64_t>(index)},
                       {Field::rawNowNs, WireType::u64, now},
                       {Field::validatedUnits, WireType::u64, progressValidated},
                       {Field::blocked, WireType::boolean, progressBlocked}}});
      releaseBackgroundBoundary();
    }
    AdapterError stopError;
    if (!shards[0]->stopAdmission(monotonicRawNowNs(), stopError))
      throw std::runtime_error(stopError.message.empty() ? "workload stop failed" : stopError.message);
    sendPacket(fd, {MessageType::measurementStopped, 0, outgoing++,
                    {{Field::trialId, WireType::bytes, trialId},
                     {Field::rawNowNs, WireType::u64, actualEnd}}});
    driveFirstUntil(std::min(completionDeadline, monotonicRawNowNs() + 1));
    while (!(shards[0]->complete() && background.completed.load() == backgroundCount) &&
           monotonicRawNowNs() < completionDeadline)
    {
      if (const auto failure = backgroundError(); !failure.empty()) throw std::runtime_error(failure);
      AdapterError error;
      if (!shards[0]->stepNonblocking(error))
        throw std::runtime_error(error.message.empty() ?
            "completion event loop failed" : error.message);
    }
    if (!(shards[0]->complete() && background.completed.load() == backgroundCount))
    {
      for (auto& worker : backgroundWorkers) worker.request_stop();
      for (auto& worker : backgroundWorkers)
        if (worker.joinable()) worker.join();
      const auto stalled = aggregate(shards);
      PacketIoCounters packetIo;
      for (auto& shard : shards)
      {
        const auto counters = shard->packetIoCounters();
        packetIo.packetsReceived += counters.packetsReceived;
        packetIo.packetsSent += counters.packetsSent;
        packetIo.sendCalls += counters.sendCalls;
        packetIo.sendErrors += counters.sendErrors;
        packetIo.backpressureEvents += counters.backpressureEvents;
      }
      throw std::runtime_error(
          "QPF2 completion reconciliation timed out: live=" + std::to_string(stalled.liveConnections) +
          " stop_sent=" + std::to_string(stalled.stopSent) +
          " stop_offered=" + std::to_string(stalled.stopOffered) +
          " stop_received=" + std::to_string(stalled.stopReceived) +
          " stop_acknowledged=" + std::to_string(stalled.stopAcknowledged) +
          " stop_ack_sent=" + std::to_string(stalled.stopAckSent) +
          " barrier=" + barrierStateSummary(stalled) +
          " cleanup=" + std::to_string(stalled.cleanupStrata[0]) + '/' +
              std::to_string(stalled.cleanupStrata[1]) + '/' +
              std::to_string(stalled.cleanupStrata[2]) + '/' +
              std::to_string(stalled.cleanupStrata[3]) +
          " cleanup_pending=" + std::to_string(stalled.cleanupPending[0]) + '/' +
              std::to_string(stalled.cleanupPending[1]) + '/' +
              std::to_string(stalled.cleanupPending[2]) + '/' +
              std::to_string(stalled.cleanupPending[3]) +
          " outstanding=" + std::to_string(stalled.outstanding) +
          " in_flight=" + std::to_string(stalled.inFlight) +
          " packets_sent=" + std::to_string(stalled.transport.packetsSent) +
          " packets_received=" + std::to_string(stalled.transport.packetsReceived) +
          " packets_lost=" + std::to_string(stalled.transport.packetsLost) +
          " packets_retransmitted=" + std::to_string(stalled.transport.packetsRetransmitted) +
          " recovery_wakeups=" + std::to_string(stalled.transport.recoveryWakeups) +
          " timer_expirations=" + std::to_string(stalled.transport.timerExpirations) +
          " flow_blocks=" + std::to_string(stalled.transport.flowControlBlockedEvents) +
          " stream_blocks=" + std::to_string(stalled.transport.streamCreditBlockedEvents) +
          " io_packets_sent=" + std::to_string(packetIo.packetsSent) +
          " io_packets_received=" + std::to_string(packetIo.packetsReceived) +
          " io_send_calls=" + std::to_string(packetIo.sendCalls) +
          " io_send_errors=" + std::to_string(packetIo.sendErrors) +
          " io_backpressure=" + std::to_string(packetIo.backpressureEvents));
    }
    for (auto& worker : backgroundWorkers)
      if (worker.joinable()) worker.join();
    attestRuntimeOwnership(fd, ownedPacketIo, 1, "measurement-complete");
    const auto after = ClockBridge::sample();
    std::string clockReason;
    const uint64_t timingLimit = std::max<uint64_t>(2'000'000, window.durationNs() / 1'000);
    const bool timingValid = actualStart >= window.startRawNs && actualEnd >= window.endRawNs &&
        actualStart - window.startRawNs <= timingLimit && actualEnd - window.endRawNs <= timingLimit &&
        actualEnd - actualStart >= window.durationNs() - std::min(window.durationNs(), timingLimit) &&
        actualEnd - actualStart <= window.durationNs() + timingLimit;
    const bool clockValid = timingValid &&
        ClockBridge(bridgeBefore).validateAfter(after, window.durationNs(), clockReason);
    auto final = aggregate(shards);
    const auto packetIo = aggregatePacketIo(shards);
    sendPacket(fd, {MessageType::completionAck, 0, outgoing++,
                    {{Field::trialId, WireType::bytes, trialId},
                     {Field::countersJson, WireType::utf8, countersJson(final)}}});
    std::ranges::sort(cpuFractions, [](const auto& left, const auto& right) {
      return static_cast<unsigned __int128>(left.first) * right.second <
          static_cast<unsigned __int128>(right.first) * left.second;
    });
    const auto p95 = decimalRatio(cpuFractions[9].first, cpuFractions[9].second);
    sendPacket(fd, {MessageType::result, 0, outgoing++,
                    {{Field::trialId, WireType::bytes, trialId},
                     {Field::resultJson, WireType::utf8,
                      endpointResultJson(trialId, cellId, config, canonicalConfig, final, packetIo,
                                         window.startRawNs, window.endRawNs, actualStart,
                                         actualEnd, p95, clockValid)}}});

    std::optional<Packet> terminal;
    while (!terminal && monotonicRawNowNs() < completionDeadline)
    {
      pollfd control {fd, POLLIN, 0};
      const int ready = poll(&control, 1, 0);
      if (ready < 0)
      {
        if (errno == EINTR) continue;
        throw std::runtime_error("control poll after RESULT failed");
      }
      if (ready > 0)
      {
        terminal = receivePacket(fd, incoming++);
        break;
      }
      AdapterError drainError;
      for (auto& shard : shards)
        if (!shard->stepNonblocking(drainError))
          throw std::runtime_error(
              drainError.message.empty() ?
                  "post-RESULT transport drain failed" : drainError.message);
    }
    if (!terminal)
    {
      const auto stalled = aggregate(shards);
      throw std::runtime_error(
          "coordinator terminal command missed completion deadline: live=" +
          std::to_string(stalled.liveConnections) +
          " stop_sent=" + std::to_string(stalled.stopSent) +
          " stop_offered=" + std::to_string(stalled.stopOffered) +
          " stop_received=" + std::to_string(stalled.stopReceived) +
          " stop_acknowledged=" + std::to_string(stalled.stopAcknowledged) +
          " stop_ack_sent=" + std::to_string(stalled.stopAckSent) +
          " barrier=" + barrierStateSummary(stalled) +
          " outstanding=" + std::to_string(stalled.outstanding) +
          " in_flight=" + std::to_string(stalled.inFlight) +
          " packets_sent=" + std::to_string(stalled.transport.packetsSent) +
          " packets_received=" + std::to_string(stalled.transport.packetsReceived) +
          " packets_lost=" + std::to_string(stalled.transport.packetsLost) +
          " packets_retransmitted=" + std::to_string(stalled.transport.packetsRetransmitted) +
          " recovery_wakeups=" + std::to_string(stalled.transport.recoveryWakeups) +
          " timer_expirations=" + std::to_string(stalled.transport.timerExpirations));
    }
    if (terminal->type == MessageType::shutdown)
    {
      for (auto& shard : shards)
      {
        AdapterError ignored;
        AdapterRuntimeScope scope(monotonicRawNowNs());
        shard->adapter->stop(ignored);
      }
      sendPacket(fd, {MessageType::shutdownAck, 0, outgoing++, {}});
      return 0;
    }
    if (terminal->type != MessageType::reset || bytesField(*terminal, Field::trialId) != trialId)
      throw std::runtime_error("worker expected matching RESET or SHUTDOWN after RESULT");
    for (size_t index = 0; index < shards.size(); ++index)
    {
      shards[index]->runtime.reset();
      shards[index]->eventLoop.reset();
      shards[index]->packetIo.reset();
      AdapterError error;
      AdapterRuntimeScope scope(monotonicRawNowNs());
      if (!shards[index]->adapter->reset(error))
        throw std::runtime_error(error.message.empty() ? "adapter reset failed" : error.message);
      adapters[index] = std::move(shards[index]->adapter);
    }
    attestRuntimeOwnership(fd, {}, 1, "reset-complete");
    sendPacket(fd, {MessageType::resetAck, 0, outgoing++,
                    {{Field::trialId, WireType::bytes, trialId},
                     {Field::liveConnections, WireType::u64, uint64_t {0}},
                     {Field::liveStreams, WireType::u64, uint64_t {0}},
                     {Field::liveTickets, WireType::u64, uint64_t {0}},
                     {Field::workInventory, WireType::u64, uint64_t {0}}}});
  }
}

} // namespace
} // namespace quicperf

int quicperfV2Main(int argc, char** argv)
{
  try
  {
    if (argc < 2) return 4;
    auto adapter = quicperf::makeTransportAdapter();
    const int fd = quicperf::controlFd(argc, argv);
    const std::string_view command = argv[1];
    if (command == "describe") return quicperf::describe(fd, *adapter);
    if (command != "worker") return 4;
    std::string role;
    for (int index = 2; index < argc; ++index)
    {
      const std::string_view argument = argv[index];
      if (argument == "--role=server") role = "server";
      if (argument == "--role=client") role = "client";
    }
    if (role.empty()) return 4;
    return quicperf::worker(fd, std::move(adapter), role);
  }
  catch (const std::exception& error)
  {
    std::cerr << "quicperf endpoint: " << error.what() << '\n';
    return 5;
  }
}
