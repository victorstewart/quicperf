#include "core/negotiated_settings.h"
#include "core/strict_config.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>

namespace {

quicperf::EndpointConfig config()
{
  quicperf::EndpointConfig value;
  value.role = quicperf::EndpointRole::client;
  value.tlsVerifyPeer = true;
  value.quicVersion = "0x00000001";
  value.alpn = "qperf/2";
  value.tlsVersion = "TLSv1.3";
  value.tlsCipherSuite = "TLS_AES_128_GCM_SHA256";
  value.tlsKeyExchange = "X25519";
  value.tlsLeafSignature = "Ed25519";
  value.congestionController = "cubic";
  value.initialCongestionWindowBytes = 13'500;
  value.maxUdpPayloadSize = 1'350;
  value.maxAckDelayNs = 25'000'000;
  value.ackDelayExponent = 3;
  value.ackFrequency = false;
  value.activeMigration = false;
  value.activeConnectionIdLimit = 2;
  value.connectionIdBytes = 8;
  value.idleTimeoutMs = 30'000;
  value.maxBidiStreams = 256;
  value.maxUniStreams = 256;
  value.streamCreditReplenishBelow = 32;
  value.connectionWindow = 64ULL * 1024 * 1024;
  value.streamWindow = 64ULL * 1024 * 1024;
  value.datagramMaxFrameSize = 1'200;
  value.tlsTicketLifetimeNs = 300'000'000'000;
  value.tlsMaximumEarlyDataBytes = 4'096;
  value.tlsOneUseTickets = true;
  return value;
}

quicperf::NegotiatedSettings exact(const quicperf::EndpointConfig& expected)
{
  quicperf::NegotiatedSettings value;
  value.available = true;
  value.evidenceSource = "behavioral-test-post-handshake-api";
  value.quicVersion = 1;
  value.alpn = expected.alpn;
  value.tlsVersion = expected.tlsVersion;
  value.tlsCipherSuite = expected.tlsCipherSuite;
  value.tlsKeyExchange = expected.tlsKeyExchange;
  value.tlsLeafSignature = expected.tlsLeafSignature;
  value.peerCertificateVerified = true;
  value.hostnameVerified = true;
  value.congestionController = expected.congestionController;
  value.initialCongestionWindowBytes = expected.initialCongestionWindowBytes;
  value.maxUdpPayloadSize = expected.maxUdpPayloadSize;
  value.maxAckDelayNs = expected.maxAckDelayNs;
  value.ackDelayExponent = expected.ackDelayExponent;
  value.ackFrequency = expected.ackFrequency;
  value.activeMigration = expected.activeMigration;
  value.activeConnectionIdLimit = expected.activeConnectionIdLimit;
  value.connectionIdBytes = expected.connectionIdBytes;
  value.maxIdleTimeoutNs = expected.idleTimeoutMs * 1'000'000;
  value.maxBidiStreams = expected.maxBidiStreams;
  value.maxUniStreams = expected.maxUniStreams;
  value.streamCreditReplenishBelow = expected.streamCreditReplenishBelow;
  value.connectionWindowBytes = expected.connectionWindow;
  value.streamWindowBytes = expected.streamWindow;
  value.datagramMaxFrameSize = expected.datagramMaxFrameSize;
  value.ticketLifetimeNs = expected.tlsTicketLifetimeNs;
  value.maximumEarlyDataBytes = expected.tlsMaximumEarlyDataBytes;
  value.oneUseTickets = expected.tlsOneUseTickets;
  return value;
}

} // namespace

int main()
{
  const auto expected = config();
  std::string reason;
  quicperf::NegotiatedSettings missing;
  assert(!quicperf::negotiatedSettingsMatch(missing, expected, reason));
  assert(reason == "post_handshake_treatment_evidence_unavailable");

  auto observed = exact(expected);
  reason.clear();
  assert(quicperf::negotiatedSettingsMatch(observed, expected, reason));
  assert(reason.empty());
  const auto json = quicperf::negotiatedSettingsJson(observed, true, reason);
  assert(json.find("\"matches\":true") != std::string::npos);
  assert(json.find("TLS_AES_128_GCM_SHA256") != std::string::npos);

  observed.maxAckDelayNs++;
  assert(!quicperf::negotiatedSettingsMatch(observed, expected, reason));
  assert(reason == "max_ack_delay_mismatch");
  observed = exact(expected);
  observed.unavailableFields = {"tls_key_exchange"};
  assert(!quicperf::negotiatedSettingsMatch(observed, expected, reason));
  assert(reason == "post_handshake_treatment_field_unavailable:tls_key_exchange");
}
