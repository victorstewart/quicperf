#pragma once

#include <cstdint>

namespace quicperf::control {

enum class MessageType : uint16_t {
  hello = 1,
  capabilities = 2,
  config = 3,
  bound = 4,
  ready = 5,
  arm = 6,
  armed = 7,
  measurementStarted = 8,
  progress = 9,
  measurementStopped = 10,
  completionAck = 11,
  result = 12,
  unsupported = 13,
  error = 14,
  reset = 15,
  resetAck = 16,
  shutdown = 17,
  shutdownAck = 18,
  exercise = 19,
  exercised = 20,
  armRejected = 21,
};

enum class WireType : uint8_t { u64 = 1, i64 = 2, utf8 = 3, bytes = 4, boolean = 5 };

enum class Field : uint16_t {
  role = 1,
  buildId = 2,
  controlVersion = 3,
  library = 4,
  protocolVersion = 5,
  roles = 6,
  backends = 7,
  scenarios = 8,
  capabilities = 9,
  effectiveFeatures = 10,
  trialId = 11,
  cellId = 12,
  configJson = 13,
  udpPort = 14,
  pid = 15,
  backend = 16,
  rawNowNs = 17,
  warmupStartRawNs = 18,
  measurementStartRawNs = 19,
  measurementEndRawNs = 20,
  traceEpochRawNs = 21,
  eventIndex = 22,
  validatedUnits = 23,
  blocked = 24,
  countersJson = 25,
  resultJson = 26,
  reason = 27,
  errorCode = 28,
  liveConnections = 29,
  liveStreams = 30,
  liveTickets = 31,
  workInventory = 32,
  exerciseDeadlineRawNs = 33,
};

} // namespace quicperf::control
