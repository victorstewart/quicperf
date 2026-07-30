#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace quicperf {

struct EndpointConfig;

// Effective and post-handshake evidence. A configured default is not evidence:
// adapters may report local policy only after its setter and readback or
// pinned implementation invariant has been checked, and peer-controlled fields
// must come from post-handshake transport/TLS state. Any unavailable field
// keeps publication validation fail-closed.
struct NegotiatedSettings {
  bool available = false;
  std::string evidenceSource;
  std::vector<std::string> unavailableFields;
  uint32_t quicVersion = 0;
  std::string alpn;
  std::string tlsVersion;
  std::string tlsCipherSuite;
  std::string tlsKeyExchange;
  std::string tlsLeafSignature;
  bool peerCertificateVerified = false;
  bool hostnameVerified = false;
  std::string congestionController;
  uint64_t initialCongestionWindowBytes = 0;
  uint64_t maxUdpPayloadSize = 0;
  uint64_t maxAckDelayNs = 0;
  uint64_t ackDelayExponent = 0;
  bool ackFrequency = false;
  bool activeMigration = false;
  uint64_t activeConnectionIdLimit = 0;
  uint64_t connectionIdBytes = 0;
  uint64_t maxIdleTimeoutNs = 0;
  uint64_t maxBidiStreams = 0;
  uint64_t maxUniStreams = 0;
  uint64_t streamCreditReplenishBelow = 0;
  uint64_t connectionWindowBytes = 0;
  uint64_t streamWindowBytes = 0;
  uint64_t datagramMaxFrameSize = 0;
  uint64_t ticketLifetimeNs = 0;
  uint64_t maximumEarlyDataBytes = 0;
  bool oneUseTickets = false;
};

bool negotiatedSettingsMatch(const NegotiatedSettings& settings,
                             const EndpointConfig& config,
                             std::string& reason) noexcept;
std::string negotiatedSettingsJson(const NegotiatedSettings& settings,
                                   bool matches,
                                   std::string_view mismatchReason);

} // namespace quicperf
