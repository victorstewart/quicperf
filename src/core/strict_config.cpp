#include "strict_config.h"

#include <array>
#include <arpa/inet.h>
#include <charconv>
#include <limits>
#include <map>
#include <variant>

namespace quicperf {
namespace {

using Scalar = std::variant<uint64_t, std::string, bool>;

class Parser {
public:
  explicit Parser(std::string_view input) : input_(input) {}

  bool parse(std::map<std::string, Scalar>& values, std::string& error)
  {
    if (!take('{')) return fail(error, "configuration must be a JSON object");
    std::string previous;
    if (take('}')) return fail(error, "configuration object is empty");
    for (;;)
    {
      std::string key;
      if (!parseString(key) || key.empty()) return fail(error, "invalid configuration key");
      if (!previous.empty() && key <= previous) return fail(error, "configuration keys are not canonical");
      previous = key;
      if (!take(':')) return fail(error, "missing configuration colon");
      Scalar value;
      if (!parseScalar(value)) return fail(error, "invalid configuration scalar");
      if (!values.emplace(std::move(key), std::move(value)).second) return fail(error, "duplicate configuration key");
      if (take('}')) break;
      if (!take(',')) return fail(error, "missing configuration comma");
    }
    if (offset_ != input_.size()) return fail(error, "trailing configuration bytes");
    return true;
  }

private:
  bool fail(std::string& error, std::string message)
  {
    error = std::move(message);
    return false;
  }

  bool take(char expected)
  {
    if (offset_ >= input_.size() || input_[offset_] != expected) return false;
    ++offset_;
    return true;
  }

  bool parseScalar(Scalar& value)
  {
    if (offset_ >= input_.size()) return false;
    if (input_.substr(offset_, 4) == "true")
    {
      offset_ += 4;
      value = true;
      return true;
    }
    if (input_.substr(offset_, 5) == "false")
    {
      offset_ += 5;
      value = false;
      return true;
    }
    if (input_[offset_] == '"')
    {
      std::string text;
      if (!parseString(text)) return false;
      value = std::move(text);
      return true;
    }
    const size_t begin = offset_;
    if (input_[offset_] == '0')
    {
      ++offset_;
      if (offset_ < input_.size() && input_[offset_] >= '0' && input_[offset_] <= '9') return false;
    }
    else
    {
      if (input_[offset_] < '1' || input_[offset_] > '9') return false;
      while (offset_ < input_.size() && input_[offset_] >= '0' && input_[offset_] <= '9') ++offset_;
    }
    uint64_t number = 0;
    const auto parsed = std::from_chars(input_.data() + begin, input_.data() + offset_, number);
    if (parsed.ec != std::errc {} || parsed.ptr != input_.data() + offset_) return false;
    value = number;
    return true;
  }

  bool parseString(std::string& out)
  {
    if (!take('"')) return false;
    while (offset_ < input_.size())
    {
      const unsigned char byte = input_[offset_++];
      if (byte == '"') return !out.empty();
      if (byte < 0x20 || byte >= 0x80 || byte == '\\') return false;
      out.push_back(static_cast<char>(byte));
    }
    return false;
  }

  std::string_view input_;
  size_t offset_ = 0;
};

template <typename T>
bool read(const std::map<std::string, Scalar>& values, std::string_view key, T& out)
{
  const auto found = values.find(std::string(key));
  if (found == values.end()) return false;
  const auto* value = std::get_if<T>(&found->second);
  if (!value) return false;
  out = *value;
  return true;
}

bool workloadValid(const EndpointConfig& config)
{
  const auto exact = [&](uint64_t active, uint64_t bulk, uint64_t request, uint64_t response,
                         uint64_t operation, uint64_t datagram, uint64_t unreturned,
                         uint64_t slots, uint64_t tickets) {
    return config.activeStreamsPerConnection == active && config.bulkChunkBytes == bulk &&
        config.requestBodyBytes == request && config.responseBodyBytes == response &&
        config.operationBodyBytes == operation && config.datagramBodyBytes == datagram &&
        config.datagramMaxUnreturnedPerConnection == unreturned &&
        config.globalOperationSlots == slots && config.ticketSlots == tickets;
  };
  const auto& scenario = config.scenario;
  if (scenario == "download" || scenario == "upload" || scenario == "loss_recovery" || scenario == "flow_control")
    return exact(1, 262'144, 8, 0, 0, 0, 0, 0, 0);
  if (scenario == "multistream_download" || scenario == "multistream_upload")
    return exact(8, 262'144, 8, 0, 0, 0, 0, 0, 0);
  if (scenario == "bidi") return exact(1, 262'144, 0, 0, 0, 0, 0, 0, 0);
  if (scenario == "small_payload_pps") return exact(1, 0, 0, 0, 64, 0, 0, 0, 0);
  if (scenario == "datagram") return exact(0, 0, 0, 0, 0, 64, 128, 2'048, 0);
  if (scenario == "reqresp") return exact(1, 0, 64, 1'024, 0, 0, 0, 16, 0);
  if (scenario == "stream_churn" || scenario == "close_reset_cleanup")
    return exact(1, 0, 0, 0, 1, 0, 0, 16, 0);
  if (scenario == "connect") return exact(0, 0, 0, 0, 0, 0, 0, 16, 0);
  if (scenario == "resumed_connect") return exact(0, 0, 0, 0, 0, 0, 0, 16, 16);
  if (scenario == "zero_rtt_reqresp") return exact(1, 0, 64, 1'024, 0, 0, 0, 16, 16);
  if (scenario == "memory_curve") return exact(1, 262'144, 1, 1, 1, 64, 0, 1, 0);
  return false;
}

bool decodeDigest(std::string_view text, std::array<uint8_t, 32>& digest)
{
  if (text.size() != digest.size() * 2) return false;
  const auto nibble = [](char value) -> int {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
  };
  for (size_t index = 0; index < digest.size(); ++index)
  {
    const int high = nibble(text[index * 2]);
    const int low = nibble(text[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    digest[index] = static_cast<uint8_t>(high << 4 | low);
  }
  return true;
}

} // namespace

ConfigResult parseEndpointConfig(std::string_view canonicalJson)
{
  ConfigResult result;
  std::map<std::string, Scalar> values;
  Parser parser(canonicalJson);
  if (!parser.parse(values, result.error)) return result;
  constexpr std::array<std::string_view, 63> keys {
      "ack_delay_exponent", "ack_frequency", "active_connection_id_limit", "active_migration",
      "active_streams_per_connection", "alpn", "backend", "bind_address", "bind_port", "bulk_chunk_bytes",
      "busy_polling", "calendar_unix_seconds", "certificate_path", "chain_path", "common_pacing", "congestion_controller",
      "connection_count", "connection_window", "datagram_body_bytes", "datagram_max_unreturned_per_connection",
      "datagram_max_frame_size", "ecn", "event_loop_workers", "global_operation_slots", "idle_timeout_ms",
      "initial_congestion_window_bytes", "connection_id_bytes", "max_ack_delay_ns", "max_bidi_streams",
      "max_udp_payload_size", "max_uni_streams", "measurement_duration_ns", "operation_body_bytes",
      "path_profile", "peer_address", "peer_port", "pmtud", "private_key_path", "progress_interval_ns",
      "quic_version", "receive_timestamps", "request_body_bytes", "require_multishot_receive",
      "response_body_bytes", "role", "scenario", "schema_version", "stream_credit_replenish_below",
      "stream_window", "ticket_slots", "tls_cipher_suite", "tls_hostname", "tls_key_exchange",
      "tls_leaf_signature", "tls_maximum_early_data_bytes", "tls_one_use_tickets",
      "tls_ticket_lifetime_ns", "tls_verify_peer", "tls_version", "trace_seed", "udp_gro", "udp_gso", "warmup_duration_ns"};
  if (values.size() != keys.size())
  {
    result.error = "configuration contains missing or unknown fields";
    return result;
  }
  for (const auto key : keys)
  {
    if (!values.contains(std::string(key)))
    {
      result.error = "configuration contains missing or unknown fields";
      return result;
    }
  }

  uint64_t schema = 0, port = 0, peerPort = 0, payload = 0;
  std::string role, backend, traceSeed;
  auto& config = result.config;
  const bool typed = read(values, "schema_version", schema) && read(values, "role", role) &&
      read(values, "backend", backend) && read(values, "bind_address", config.bindAddress) &&
      read(values, "bind_port", port) && read(values, "peer_address", config.peerAddress) &&
      read(values, "peer_port", peerPort) &&
      read(values, "calendar_unix_seconds", config.calendarUnixSeconds) &&
      read(values, "certificate_path", config.certificatePath) &&
      read(values, "private_key_path", config.privateKeyPath) && read(values, "chain_path", config.chainPath) &&
      read(values, "tls_hostname", config.tlsHostname) &&
      read(values, "tls_verify_peer", config.tlsVerifyPeer) &&
      read(values, "tls_version", config.tlsVersion) &&
      read(values, "tls_cipher_suite", config.tlsCipherSuite) &&
      read(values, "tls_key_exchange", config.tlsKeyExchange) &&
      read(values, "tls_leaf_signature", config.tlsLeafSignature) &&
      read(values, "tls_ticket_lifetime_ns", config.tlsTicketLifetimeNs) &&
      read(values, "tls_maximum_early_data_bytes", config.tlsMaximumEarlyDataBytes) &&
      read(values, "tls_one_use_tickets", config.tlsOneUseTickets) &&
      read(values, "quic_version", config.quicVersion) && read(values, "alpn", config.alpn) &&
      read(values, "congestion_controller", config.congestionController) &&
      read(values, "initial_congestion_window_bytes", config.initialCongestionWindowBytes) &&
      read(values, "max_ack_delay_ns", config.maxAckDelayNs) &&
      read(values, "ack_delay_exponent", config.ackDelayExponent) &&
      read(values, "ack_frequency", config.ackFrequency) &&
      read(values, "active_migration", config.activeMigration) &&
      read(values, "active_connection_id_limit", config.activeConnectionIdLimit) &&
      read(values, "connection_id_bytes", config.connectionIdBytes) &&
      read(values, "connection_window", config.connectionWindow) && read(values, "stream_window", config.streamWindow) &&
      read(values, "max_bidi_streams", config.maxBidiStreams) && read(values, "max_uni_streams", config.maxUniStreams) &&
      read(values, "stream_credit_replenish_below", config.streamCreditReplenishBelow) &&
      read(values, "idle_timeout_ms", config.idleTimeoutMs) && read(values, "max_udp_payload_size", payload) &&
      read(values, "datagram_max_frame_size", config.datagramMaxFrameSize) &&
      read(values, "path_profile", config.pathProfile) &&
      read(values, "trace_seed", traceSeed) &&
      read(values, "scenario", config.scenario) && read(values, "connection_count", config.connectionCount) &&
      read(values, "event_loop_workers", config.eventLoopWorkers) &&
      read(values, "active_streams_per_connection", config.activeStreamsPerConnection) &&
      read(values, "bulk_chunk_bytes", config.bulkChunkBytes) && read(values, "request_body_bytes", config.requestBodyBytes) &&
      read(values, "response_body_bytes", config.responseBodyBytes) &&
      read(values, "operation_body_bytes", config.operationBodyBytes) &&
      read(values, "datagram_body_bytes", config.datagramBodyBytes) &&
      read(values, "datagram_max_unreturned_per_connection", config.datagramMaxUnreturnedPerConnection) &&
      read(values, "global_operation_slots", config.globalOperationSlots) && read(values, "ticket_slots", config.ticketSlots) &&
      read(values, "warmup_duration_ns", config.warmupDurationNs) &&
      read(values, "measurement_duration_ns", config.measurementDurationNs) &&
      read(values, "progress_interval_ns", config.progressIntervalNs) &&
      read(values, "pmtud", config.packetIo.pmtud) && read(values, "ecn", config.packetIo.ecn) &&
      read(values, "receive_timestamps", config.packetIo.receiveTimestamps) &&
      read(values, "busy_polling", config.packetIo.busyPolling) &&
      read(values, "common_pacing", config.packetIo.commonPacing) &&
      read(values, "udp_gro", config.packetIo.udpGro) && read(values, "udp_gso", config.packetIo.udpGso) &&
      read(values, "require_multishot_receive", config.packetIo.requireMultishotReceive);
  if (!typed || schema != 2 || (role != "server" && role != "client") ||
      (backend != "syscall" && backend != "iouring") || config.bindAddress.empty() ||
      config.peerAddress.empty() || config.tlsHostname.empty() || config.congestionController.empty() ||
      config.calendarUnixSeconds == 0 ||
      config.quicVersion != "0x00000001" || config.alpn != "qperf/2" ||
      config.initialCongestionWindowBytes != 13'500 || config.maxAckDelayNs != 25'000'000 ||
      config.ackDelayExponent != 3 || config.ackFrequency || config.activeMigration ||
      config.activeConnectionIdLimit != 2 || config.connectionIdBytes != 8 ||
      config.streamCreditReplenishBelow != 32 || config.datagramMaxFrameSize != 1'200 ||
      config.tlsVersion != "TLSv1.3" || config.tlsCipherSuite != "TLS_AES_128_GCM_SHA256" ||
      config.tlsKeyExchange != "X25519" || config.tlsLeafSignature != "Ed25519" ||
      config.tlsTicketLifetimeNs != 300'000'000'000 || config.tlsMaximumEarlyDataBytes != 4'096 ||
      !config.tlsOneUseTickets ||
      !decodeDigest(traceSeed, config.traceSeed) ||
      (config.scenario == "loss_recovery" ?
           config.pathProfile != "loss_recovery_v1" :
           config.pathProfile != "loopback") ||
      port > 65'535 || peerPort > 65'535 ||
      (role == "server" && (config.peerAddress != "0.0.0.0" || peerPort != 0)) ||
      (role == "client" && (config.peerAddress == "0.0.0.0" || peerPort == 0)) || payload != maxUdpPayloadSize ||
      config.connectionWindow == 0 || config.streamWindow == 0 || config.maxBidiStreams == 0 ||
      config.maxUniStreams == 0 || config.idleTimeoutMs == 0 || config.packetIo.busyPolling ||
      (config.connectionCount == 0 && config.scenario != "memory_curve") ||
      config.measurementDurationNs == 0 || config.progressIntervalNs == 0 ||
      config.progressIntervalNs > config.measurementDurationNs ||
      (role == "server" ? config.eventLoopWorkers != 1 :
                          (config.eventLoopWorkers != 2 && config.eventLoopWorkers != 4)) ||
      !workloadValid(config) ||
      ((config.scenario == "connect" || config.scenario == "resumed_connect" ||
        config.scenario == "zero_rtt_reqresp") ?
           config.warmupDurationNs != 0 : config.warmupDurationNs == 0))
  {
    result.error = "invalid endpoint configuration value";
    return result;
  }
  in_addr bindAddress {};
  in_addr peerAddress {};
  if (inet_pton(AF_INET, config.bindAddress.c_str(), &bindAddress) != 1 ||
      inet_pton(AF_INET, config.peerAddress.c_str(), &peerAddress) != 1)
  {
    result.error = "endpoint addresses must be canonical IPv4 text";
    return result;
  }
  std::array<char, INET_ADDRSTRLEN> bindText {}, peerText {};
  if (!inet_ntop(AF_INET, &bindAddress, bindText.data(), bindText.size()) ||
      !inet_ntop(AF_INET, &peerAddress, peerText.data(), peerText.size()) ||
      config.bindAddress != bindText.data() || config.peerAddress != peerText.data())
  {
    result.error = "endpoint addresses must be canonical IPv4 text";
    return result;
  }
  config.schemaVersion = static_cast<uint32_t>(schema);
  config.role = role == "server" ? EndpointRole::server : EndpointRole::client;
  config.backend = backend == "syscall" ? PacketBackend::syscall : PacketBackend::iouring;
  config.bindPort = static_cast<uint16_t>(port);
  config.peerPort = static_cast<uint16_t>(peerPort);
  config.maxUdpPayloadSize = static_cast<uint32_t>(payload);
  return result;
}

} // namespace quicperf
