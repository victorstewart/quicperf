#include "negotiated_settings.h"

#include "strict_config.h"

#include <algorithm>
#include <sstream>

namespace quicperf {
namespace {

std::string escaped(std::string_view value)
{
  std::ostringstream out;
  for (const unsigned char byte : value)
  {
    if (byte == '"' || byte == '\\') out << '\\' << static_cast<char>(byte);
    else if (byte >= 0x20 && byte < 0x7f) out << static_cast<char>(byte);
    else out << "\\u00" << "0123456789abcdef"[byte >> 4]
             << "0123456789abcdef"[byte & 0xf];
  }
  return out.str();
}

template <typename Left, typename Right>
bool exact(const Left& observed, const Right& expected, std::string_view field,
           std::string& reason)
{
  if (observed == expected) return true;
  reason = std::string(field) + "_mismatch";
  return false;
}

} // namespace

bool negotiatedSettingsMatch(const NegotiatedSettings& value,
                             const EndpointConfig& config,
                             std::string& reason) noexcept
{
  if (!value.available)
  {
    reason = "post_handshake_treatment_evidence_unavailable";
    return false;
  }
  if (!value.unavailableFields.empty())
  {
    reason = "post_handshake_treatment_field_unavailable:" + value.unavailableFields.front();
    return false;
  }
  return exact(value.quicVersion, uint32_t {1}, "quic_version", reason) &&
      exact(value.alpn, config.alpn, "alpn", reason) &&
      exact(value.tlsVersion, config.tlsVersion, "tls_version", reason) &&
      exact(value.tlsCipherSuite, config.tlsCipherSuite, "tls_cipher_suite", reason) &&
      exact(value.tlsKeyExchange, config.tlsKeyExchange, "tls_key_exchange", reason) &&
      exact(value.tlsLeafSignature, config.tlsLeafSignature, "tls_leaf_signature", reason) &&
      exact(value.peerCertificateVerified, config.tlsVerifyPeer, "peer_certificate_verification", reason) &&
      exact(value.hostnameVerified, config.tlsVerifyPeer, "hostname_verification", reason) &&
      exact(value.congestionController, config.congestionController, "congestion_controller", reason) &&
      exact(value.initialCongestionWindowBytes, config.initialCongestionWindowBytes, "initial_congestion_window", reason) &&
      exact(value.maxUdpPayloadSize, uint64_t {config.maxUdpPayloadSize}, "max_udp_payload_size", reason) &&
      exact(value.maxAckDelayNs, config.maxAckDelayNs, "max_ack_delay", reason) &&
      exact(value.ackDelayExponent, config.ackDelayExponent, "ack_delay_exponent", reason) &&
      exact(value.ackFrequency, config.ackFrequency, "ack_frequency", reason) &&
      exact(value.activeMigration, config.activeMigration, "active_migration", reason) &&
      exact(value.activeConnectionIdLimit, config.activeConnectionIdLimit, "active_connection_id_limit", reason) &&
      exact(value.connectionIdBytes, config.connectionIdBytes, "connection_id_bytes", reason) &&
      exact(value.maxIdleTimeoutNs, config.idleTimeoutMs * 1'000'000ULL, "max_idle_timeout", reason) &&
      exact(value.maxBidiStreams, config.maxBidiStreams, "max_bidi_streams", reason) &&
      exact(value.maxUniStreams, config.maxUniStreams, "max_uni_streams", reason) &&
      exact(value.streamCreditReplenishBelow, config.streamCreditReplenishBelow, "stream_credit_replenish_below", reason) &&
      exact(value.connectionWindowBytes, config.connectionWindow, "connection_window", reason) &&
      exact(value.streamWindowBytes, config.streamWindow, "stream_window", reason) &&
      exact(value.datagramMaxFrameSize, config.datagramMaxFrameSize, "datagram_max_frame_size", reason) &&
      exact(value.ticketLifetimeNs, config.tlsTicketLifetimeNs, "ticket_lifetime", reason) &&
      exact(value.maximumEarlyDataBytes, config.tlsMaximumEarlyDataBytes, "maximum_early_data", reason) &&
      exact(value.oneUseTickets, config.tlsOneUseTickets, "one_use_tickets", reason);
}

std::string negotiatedSettingsJson(const NegotiatedSettings& value, bool matches,
                                   std::string_view mismatchReason)
{
  auto unavailable = value.unavailableFields;
  std::ranges::sort(unavailable);
  unavailable.erase(std::unique(unavailable.begin(), unavailable.end()), unavailable.end());
  std::ostringstream out;
  out << "{\"ack_delay_exponent\":" << value.ackDelayExponent
      << ",\"ack_frequency\":" << (value.ackFrequency ? "true" : "false")
      << ",\"active_connection_id_limit\":" << value.activeConnectionIdLimit
      << ",\"active_migration\":" << (value.activeMigration ? "true" : "false")
      << ",\"alpn\":\"" << escaped(value.alpn) << "\""
      << ",\"available\":" << (value.available ? "true" : "false")
      << ",\"congestion_controller\":\"" << escaped(value.congestionController) << "\""
      << ",\"connection_id_bytes\":" << value.connectionIdBytes
      << ",\"connection_window_bytes\":" << value.connectionWindowBytes
      << ",\"datagram_max_frame_size\":" << value.datagramMaxFrameSize
      << ",\"evidence_source\":\"" << escaped(value.evidenceSource) << "\""
      << ",\"hostname_verified\":" << (value.hostnameVerified ? "true" : "false")
      << ",\"initial_congestion_window_bytes\":" << value.initialCongestionWindowBytes
      << ",\"matches\":" << (matches ? "true" : "false")
      << ",\"max_ack_delay_ns\":" << value.maxAckDelayNs
      << ",\"max_bidi_streams\":" << value.maxBidiStreams
      << ",\"max_idle_timeout_ns\":" << value.maxIdleTimeoutNs
      << ",\"max_udp_payload_size\":" << value.maxUdpPayloadSize
      << ",\"max_uni_streams\":" << value.maxUniStreams
      << ",\"maximum_early_data_bytes\":" << value.maximumEarlyDataBytes
      << ",\"mismatch_reason\":\"" << escaped(mismatchReason) << "\""
      << ",\"one_use_tickets\":" << (value.oneUseTickets ? "true" : "false")
      << ",\"peer_certificate_verified\":" << (value.peerCertificateVerified ? "true" : "false")
      << ",\"quic_version\":" << value.quicVersion
      << ",\"stream_credit_replenish_below\":" << value.streamCreditReplenishBelow
      << ",\"stream_window_bytes\":" << value.streamWindowBytes
      << ",\"ticket_lifetime_ns\":" << value.ticketLifetimeNs
      << ",\"tls_cipher_suite\":\"" << escaped(value.tlsCipherSuite) << "\""
      << ",\"tls_key_exchange\":\"" << escaped(value.tlsKeyExchange) << "\""
      << ",\"tls_leaf_signature\":\"" << escaped(value.tlsLeafSignature) << "\""
      << ",\"tls_version\":\"" << escaped(value.tlsVersion) << "\""
      << ",\"unavailable_fields\":[";
  for (size_t index = 0; index < unavailable.size(); ++index)
  {
    if (index) out << ',';
    out << '\"' << escaped(unavailable[index]) << '\"';
  }
  out << "]}";
  return out.str();
}

} // namespace quicperf
