#pragma once

#include "adapter.h"
#include "measurement.h"
#include "result.h"
#include "strict_config.h"
#include "workload_protocol.h"

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace quicperf::workload {

struct OfferedFrame {
  Header header;
  uint64_t payloadOffset;
  size_t payloadLength;
};

class Engine {
public:
  Engine(Scenario scenario, uint64_t trialNonce, MeasurementWindow window, bool operationRate);

  OfferedFrame next(Type type, size_t payloadLength, uint16_t flags, uint64_t nowRawNs);
  void accepted(const OfferedFrame& frame, size_t bytes);
  bool validate(const Header& header, std::span<const uint8_t> payload, uint64_t completionRawNs, std::string& reason);
  void blocked(uint64_t nowRawNs);
  void stopAdmission() noexcept { admitting_ = false; }
  TrialResult finish();
  const WorkloadCounters& counters() const noexcept { return result_.counters; }

private:
  Scenario scenario_;
  uint64_t nonce_;
  MeasurementWindow window_;
  bool operationRate_;
  bool admitting_ = true;
  uint64_t sendSequence_ = 0;
  uint64_t receiveSequence_ = 0;
  TrialResult result_;
};

struct TailObservation {
  uint64_t operationSequence;
  uint64_t startRawNs;
  uint64_t terminalRawNs;
};

struct ConnectionValidatedUnits {
  uint32_t ordinal;
  uint64_t units;
};

struct ConnectionBarrierState {
  uint32_t ordinal;
  uint64_t sentFrames;
  uint64_t receivedFrames;
  uint64_t peerSentFrames;
  bool peerSentFramesKnown;
  bool pendingApplicationFrames;
};

struct RuntimeSnapshot {
  WorkloadCounters counters;
  TransportCounters transport;
  uint64_t peerValidated = 0;
  uint64_t failed = 0;
  uint64_t outstanding = 0;
  uint64_t inFlight = 0;
  uint64_t byteCapHits = 0;
  uint64_t streamCapHits = 0;
  uint64_t streamIdCapHits = 0;
  uint64_t socketDrops = 0;
  uint64_t liveConnections = 0;
  uint64_t readyConnections = 0;
  uint64_t stopSent = 0;
  uint64_t stopReceived = 0;
  uint64_t stopAcknowledged = 0;
  uint64_t stopAckSent = 0;
  uint64_t stopOffered = 0;
  std::array<uint64_t, 4> cleanupStrata {};
  std::array<uint64_t, 4> cleanupPending {};
  uint64_t tailStartedOperations = 0;
  uint64_t tailFailedOperations = 0;
  uint64_t tailCensoredOperations = 0;
  std::array<uint64_t, 4> tailPrefixStarted {};
  std::array<uint64_t, 4> tailPrefixSuccessful {};
  std::array<uint64_t, 4> tailPrefixFailed {};
  std::array<std::vector<TailObservation>, 4> tailPrefixObservations;
  std::vector<TailObservation> tailObservations;
  std::vector<ConnectionValidatedUnits> connectionValidatedUnits;
  std::vector<ConnectionBarrierState> connectionBarrierStates;
  enum class TailOwnership { none, complete, senderStarts, receiverTerminals } tailOwnership = TailOwnership::none;
  bool completionReconciled = false;
  bool hasNegotiatedSettings = false;
  bool negotiatedSettingsMatch = false;
  NegotiatedSettings negotiatedSettings;
  std::string negotiatedSettingsMismatchReason;
  uint64_t flowControlWriteBlockedEvents = 0;
  bool flowControlRecoveryEvidence = false;
};

// The runtime is the sole owner of QPF2 application semantics.  Adapters expose
// transport primitives; this class supplies framing, replenishment, receiver
// validation, common-window accounting, and STOP/STOP_ACK reconciliation.
class Runtime {
public:
  Runtime(Adapter& adapter, EndpointConfig config, MeasurementWindow window,
          std::span<const uint8_t, 32> trialId, std::span<const uint8_t, 32> cellId,
          uint32_t connectionFirst, uint32_t connectionCount);
  ~Runtime();
  Runtime(Runtime&&) noexcept;
  Runtime& operator=(Runtime&&) noexcept;
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  bool start(uint64_t nowRawNs, AdapterError& error);
  bool pump(uint64_t nowRawNs, AdapterError& error);
  bool stopAdmission(uint64_t nowRawNs, AdapterError& error);
  bool completionReconciled() const noexcept;
  bool idleEstablished() const noexcept;
  uint64_t validatedUnits() const noexcept;
  bool blockedInSubwindow(size_t index) const noexcept;
  RuntimeSnapshot snapshot() const;

private:
  struct Implementation;
  std::unique_ptr<Implementation> implementation_;
};

Scenario scenarioFromName(std::string_view name);
bool scenarioMeasuresOperations(Scenario scenario) noexcept;
bool serverUsesPeerNumerator(Scenario scenario) noexcept;
std::array<uint8_t, 32> sha256(std::span<const uint8_t> bytes) noexcept;
std::string hex(std::span<const uint8_t> bytes);

} // namespace quicperf::workload
