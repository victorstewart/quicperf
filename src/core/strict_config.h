#pragma once

#include "packet_io.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace quicperf {

enum class EndpointRole { server, client };

struct EndpointConfig {
  uint32_t schemaVersion = 0;
  EndpointRole role = EndpointRole::server;
  PacketBackend backend = PacketBackend::syscall;
  std::string bindAddress;
  uint16_t bindPort = 0;
  std::string peerAddress;
  uint16_t peerPort = 0;
  uint64_t calendarUnixSeconds = 0;
  std::string certificatePath;
  std::string privateKeyPath;
  std::string chainPath;
  std::string tlsHostname;
  bool tlsVerifyPeer = false;
  std::string tlsVersion;
  std::string tlsCipherSuite;
  std::string tlsKeyExchange;
  std::string tlsLeafSignature;
  uint64_t tlsTicketLifetimeNs = 0;
  uint64_t tlsMaximumEarlyDataBytes = 0;
  bool tlsOneUseTickets = false;
  std::string quicVersion;
  std::string alpn;
  std::string congestionController;
  uint64_t initialCongestionWindowBytes = 0;
  uint64_t maxAckDelayNs = 0;
  uint64_t ackDelayExponent = 0;
  bool ackFrequency = false;
  bool activeMigration = false;
  uint64_t activeConnectionIdLimit = 0;
  uint64_t connectionIdBytes = 0;
  uint64_t connectionWindow = 0;
  uint64_t streamWindow = 0;
  uint64_t maxBidiStreams = 0;
  uint64_t maxUniStreams = 0;
  uint64_t streamCreditReplenishBelow = 0;
  uint64_t idleTimeoutMs = 0;
  uint32_t maxUdpPayloadSize = 0;
  uint64_t datagramMaxFrameSize = 0;
  PacketIoConfig packetIo;
  std::string pathProfile;
  std::array<uint8_t, 32> traceSeed {};
  std::string scenario;
  uint64_t connectionCount = 0;
  uint64_t eventLoopWorkers = 0;
  uint64_t activeStreamsPerConnection = 0;
  uint64_t bulkChunkBytes = 0;
  uint64_t requestBodyBytes = 0;
  uint64_t responseBodyBytes = 0;
  uint64_t operationBodyBytes = 0;
  uint64_t datagramBodyBytes = 0;
  uint64_t datagramMaxUnreturnedPerConnection = 0;
  uint64_t globalOperationSlots = 0;
  uint64_t ticketSlots = 0;
  uint64_t warmupDurationNs = 0;
  uint64_t measurementDurationNs = 0;
  uint64_t progressIntervalNs = 0;
};

struct ConfigResult {
  EndpointConfig config {};
  std::string error;
  explicit operator bool() const noexcept { return error.empty(); }
};

// Endpoint configuration is a canonical, flat JSON object. Keys must be in
// lexicographic order and every field is required; there are no defaults.
ConfigResult parseEndpointConfig(std::string_view canonicalJson);

} // namespace quicperf
