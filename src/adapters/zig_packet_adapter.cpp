#include "zig_packet_adapter.h"
#include "resumption_envelope.h"
#include "core/measurement.h"

#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

namespace quicperf {

namespace {

constexpr uint64_t applicationBufferBytes = 256 * 1024;

} // namespace

ZigPacketAdapter::ZigPacketAdapter()
{
  if (qzf_packet_abi_version() != QZF_PACKET_ABI_VERSION) throw std::runtime_error("Zig packet ABI version mismatch");
  capabilities_.library = "quic_zig";
  capabilities_.buildId = "quiczig-97a7bec-clockpatch-v3-common-v7";
  capabilities_.adapterAbiVersion = QZF_PACKET_ABI_VERSION;
  capabilities_.server = true;
  capabilities_.client = true;
  capabilities_.backends = {PacketBackend::syscall, PacketBackend::iouring};
  capabilities_.scenarios = {
      workload::Scenario::download, workload::Scenario::upload,
      workload::Scenario::multistreamDownload, workload::Scenario::multistreamUpload,
      workload::Scenario::bidi, workload::Scenario::smallPayloadPps,
      workload::Scenario::datagram, workload::Scenario::reqresp,
      workload::Scenario::streamChurn, workload::Scenario::closeResetCleanup,
      workload::Scenario::connect, workload::Scenario::resumedConnect,
      workload::Scenario::zeroRttReqresp,
      workload::Scenario::memoryCurve,
      workload::Scenario::lossRecovery,
      workload::Scenario::flowControl};
  capabilities_.datagram = true;
  capabilities_.resumption = true;
  capabilities_.earlyData = true;
  capabilities_.effectiveFeatures = {
      "common_cpp_packet_io", "borrowed_packet_batch_64", "caller_supplied_raw_time",
      "runtime_threads_none", "ipv4", "quic_v1", "tls_1_3", "qperf_2_alpn",
      "canonical_tls_hostname", "ca_verified_peer", "post_bind_local_address",
      "bidirectional_stream", "unidirectional_stream", "datagram", "resumption",
      "reset_stream", "stop_sending", "connection_close",
      "peer_terminal_facts",
      "transport_loss_counter", "flow_control_blocked_counters",
      "resumed_lifecycle_successor_one_use_tickets", "early_data"};
}

ZigPacketAdapter::~ZigPacketAdapter() { qzf_engine_free(engine_); }

qzf_addr_t ZigPacketAdapter::toFfi(const sockaddr_in& address)
{
  qzf_addr_t converted {};
  converted.ip[10] = 0xff;
  converted.ip[11] = 0xff;
  std::memcpy(converted.ip + 12, &address.sin_addr.s_addr, 4);
  converted.port = ntohs(address.sin_port);
  return converted;
}

sockaddr_in ZigPacketAdapter::fromFfi(const qzf_addr_t& address)
{
  sockaddr_in converted {};
  converted.sin_family = AF_INET;
  converted.sin_port = htons(address.port);
  std::memcpy(&converted.sin_addr.s_addr, address.ip + 12, 4);
  return converted;
}

void ZigPacketAdapter::assignError(const qzf_adapter_status_v2_t& status, AdapterError& error)
{
  error.code = static_cast<uint64_t>(status.code < 0 ? -static_cast<int64_t>(status.code) : status.code);
  error.message.assign(status.message, strnlen(status.message, sizeof(status.message)));
  if (error.message.empty()) error.message = "Zig packet adapter failure";
}

bool ZigPacketAdapter::assignScalarError(int status, AdapterError& error)
{
  if (status >= 0) return true;
  error.code = static_cast<uint64_t>(-static_cast<int64_t>(status));
  const char* message = qzf_last_error();
  error.message = message && *message ? message : "Zig transport primitive failure";
  return false;
}

TransportCounters ZigPacketAdapter::snapshotTransportCounters() const noexcept
{
  TransportCounters result = counters_;
  if (!engine_ || (config_.scenario != "loss_recovery" && config_.scenario != "flow_control"))
    return result;
  qzf_transport_counters_v3_t zig {};
  qzf_adapter_status_v2_t status {};
  if (qzf_engine_transport_counters_v3(engine_, &zig, &status) != 0) return result;
  result.packetsLost += zig.packets_lost;
  result.packetsRetransmitted += zig.packets_retransmitted;
  result.recoveryWakeups += zig.recovery_wakeups;
  result.flowControlBlockedEvents += zig.flow_control_blocked_events;
  result.streamCreditBlockedEvents += zig.stream_credit_blocked_events;
  return result;
}

bool ZigPacketAdapter::configure(std::string_view canonicalConfig, AdapterError& error)
{
  const auto parsed = parseEndpointConfig(canonicalConfig);
  if (!parsed)
  {
    error = {2, parsed.error};
    return false;
  }
  if (parsed.config.packetIo.ecn || parsed.config.packetIo.pmtud)
  {
    error = {2, "Zig packet ABI v2 does not attest ECN or PMTUD metadata"};
    return false;
  }
  if (parsed.config.congestionController != "cubic")
  {
    error = {2, "pinned quic-zig packet engine exposes only its native Cubic controller"};
    return false;
  }
  if (parsed.config.quicVersion != "0x00000001" || parsed.config.alpn != "qperf/2" ||
      parsed.config.tlsVersion != "TLSv1.3" ||
      parsed.config.tlsCipherSuite != "TLS_AES_128_GCM_SHA256" ||
      parsed.config.tlsKeyExchange != "X25519" ||
      parsed.config.tlsLeafSignature != "Ed25519" ||
      parsed.config.initialCongestionWindowBytes != 13'500 ||
      parsed.config.maxAckDelayNs != 25'000'000 ||
      parsed.config.ackDelayExponent != 3 || parsed.config.ackFrequency ||
      parsed.config.activeMigration || parsed.config.activeConnectionIdLimit != 2 ||
      parsed.config.connectionIdBytes != 8 ||
      parsed.config.streamCreditReplenishBelow != 32 ||
      parsed.config.tlsTicketLifetimeNs != 300'000'000'000ULL ||
      parsed.config.tlsMaximumEarlyDataBytes != 4096 ||
      !parsed.config.tlsOneUseTickets)
  {
    error = {2, "pinned quic-zig cannot honor the requested frozen treatment"};
    return false;
  }
  in_addr bindAddress {};
  in_addr peerAddress {};
  if (inet_pton(AF_INET, parsed.config.bindAddress.c_str(), &bindAddress) != 1 ||
      inet_pton(AF_INET, parsed.config.peerAddress.c_str(), &peerAddress) != 1)
  {
    error = {2, "Zig packet adapter requires IPv4 bind and peer addresses"};
    return false;
  }
  qzf_engine_free(engine_);
  engine_ = nullptr;
  config_ = parsed.config;
  configured_ = true;
  nextTimeoutRawNs_ = 0;
  counters_ = {};
  negotiated_.clear();
  lastCallerRawNs_ = 0;
  error = {};
  return true;
}

bool ZigPacketAdapter::createEngine(const sockaddr_in& local, AdapterError& error)
{
  qzf_config_t config {};
  config.is_server = config_.role == EndpointRole::server;
  config.local_addr = toFfi(local);
  in_addr peerIpv4 {};
  inet_pton(AF_INET, config_.peerAddress.c_str(), &peerIpv4);
  config.peer_addr.ip[10] = 0xff;
  config.peer_addr.ip[11] = 0xff;
  std::memcpy(config.peer_addr.ip + 12, &peerIpv4.s_addr, 4);
  config.peer_addr.port = config_.peerPort;
  config.cert_path = config_.certificatePath.c_str();
  config.key_path = config_.privateKeyPath.c_str();
  config.chain_path = config_.chainPath.c_str();
  config.tls_verify_peer = config_.tlsVerifyPeer;
  config.use_bbr = config_.congestionController == "bbr";
  config.disable_pacing = false;
  config.connection_window = config_.connectionWindow;
  config.stream_window = config_.streamWindow;
  config.max_bidi_streams = config_.maxBidiStreams;
  config.max_uni_streams = config_.maxUniStreams;
  config.idle_timeout_ms = config_.idleTimeoutMs;
  config.udp_payload_size = config_.maxUdpPayloadSize;
  config.datagram_max_frame_size = config_.datagramMaxFrameSize;
  config.send_backlog_limit = applicationBufferBytes;
  config.now_us = monotonicRawNowNs() / 1'000;
  config.calendar_unix_seconds = config_.calendarUnixSeconds;
  engine_ = qzf_engine_new(&config);
  if (!engine_)
  {
    error = {1, qzf_last_error() ? qzf_last_error() : "Zig engine creation failed"};
    return false;
  }
  error = {};
  return true;
}

bool ZigPacketAdapter::setLocalAddress(const sockaddr_in& local, AdapterError& error)
{
  in_addr expected {};
  if (!configured_ || engine_ || local.sin_family != AF_INET ||
      inet_pton(AF_INET, config_.bindAddress.c_str(), &expected) != 1 ||
      local.sin_addr.s_addr != expected.s_addr ||
      (config_.bindPort != 0 && ntohs(local.sin_port) != config_.bindPort))
  {
    error = {3, "post-bind IPv4 local address differs from frozen Zig configuration"};
    return false;
  }
  return createEngine(local, error);
}

bool ZigPacketAdapter::receiveBatch(std::span<const ReceivedPacket> packets, uint64_t nowRawNs, AdapterError& error)
{
  if (!engine_ || packets.size() > receive_.size())
  {
    error = {2, "invalid Zig receive batch"};
    return false;
  }
  for (size_t index = 0; index < packets.size(); ++index)
  {
    receive_[index] = {reinterpret_cast<const uint8_t*>(packets[index].bytes.data()), packets[index].bytes.size(),
                       toFfi(packets[index].peer), packets[index].ecn, {}};
  }
  qzf_adapter_status_v2_t status {};
  if (qzf_engine_receive_batch(engine_, receive_.data(), packets.size(), nowRawNs, &status) != 0)
  {
    assignError(status, error);
    return false;
  }
  counters_.packetsReceived += packets.size();
  return updateTimeout(nowRawNs, error);
}

size_t ZigPacketAdapter::pollTransmitBatch(std::span<TransmitPacket> packets, uint64_t nowRawNs, AdapterError& error)
{
  if (!engine_ || packets.size() > transmit_.size())
  {
    error = {2, "invalid Zig transmit batch"};
    return 0;
  }
  for (size_t index = 0; index < packets.size(); ++index)
    transmit_[index] = {output_[index].data(), output_[index].size(), 0, {}, 0, {}, 0};
  size_t count = 0;
  qzf_adapter_status_v2_t status {};
  if (qzf_engine_poll_transmit_batch(engine_, transmit_.data(), packets.size(), &count, nowRawNs, &status) != 0)
  {
    assignError(status, error);
    return 0;
  }
  for (size_t index = 0; index < count; ++index)
    packets[index] = {{reinterpret_cast<const std::byte*>(transmit_[index].data), transmit_[index].len},
                      fromFfi(transmit_[index].peer), transmit_[index].ecn, 0, transmit_[index].desired_send_raw_ns};
  counters_.packetsSent += count;
  if (!updateTimeout(nowRawNs, error)) return 0;
  return count;
}

bool ZigPacketAdapter::updateTimeout(uint64_t nowRawNs, AdapterError& error)
{
  qzf_adapter_status_v2_t status {};
  if (qzf_engine_next_timeout_raw_ns(engine_, nowRawNs, &nextTimeoutRawNs_, &status) == 0) return true;
  assignError(status, error);
  return false;
}

bool ZigPacketAdapter::onTimeout(uint64_t nowRawNs, AdapterError& error)
{
  qzf_adapter_status_v2_t status {};
  if (qzf_engine_on_timeout_raw_ns(engine_, nowRawNs, &status) != 0)
  {
    assignError(status, error);
    return false;
  }
  ++counters_.timerExpirations;
  return updateTimeout(nowRawNs, error);
}

bool ZigPacketAdapter::connect(const sockaddr_in& peer, uint64_t nowRawNs,
                               uint64_t& connectionId, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  const auto remote = toFfi(peer);
  if (!assignScalarError(
          qzf_engine_connect(engine_, &remote, toMicroseconds(nowRawNs), &connectionId), error))
    return false;
  return true;
}

PrimitiveStatus ZigPacketAdapter::acceptConnection(uint64_t, uint64_t& connectionId,
                                                   AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qzf_engine_accept_connection(engine_, &connectionId);
  if (!assignScalarError(status, error)) return PrimitiveStatus::fatal;
  if (status == 0) return PrimitiveStatus::wouldBlock;
  return PrimitiveStatus::ready;
}

bool ZigPacketAdapter::isConnected(uint64_t connectionId, uint64_t nowRawNs,
                                   bool& connected, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  const int status = qzf_engine_is_connected(engine_, connectionId, toMicroseconds(nowRawNs));
  lastCallerRawNs_ = nowRawNs;
  if (!assignScalarError(status, error)) return false;
  connected = status != 0;
  if (connected)
  {
    qzf_negotiated_t observed {};
    if (qzf_connection_negotiated(
            engine_, connectionId, &observed, toMicroseconds(nowRawNs)) > 0 &&
        observed.available)
      negotiated_[connectionId] = observed;
  }
  return true;
}

bool ZigPacketAdapter::connectionIsClosed(uint64_t connectionId, uint64_t nowRawNs,
                                          bool& closed, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  const int status = qzf_connection_is_closed(
      engine_, connectionId, toMicroseconds(nowRawNs));
  lastCallerRawNs_ = nowRawNs;
  if (!assignScalarError(status, error)) return false;
  closed = status != 0;
  return true;
}

bool ZigPacketAdapter::peerTerminalFacts(uint64_t connectionId, uint64_t streamId,
                                         uint64_t nowRawNs, PeerTerminalFacts& facts,
                                         AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  qzf_peer_terminal_facts_v6_t observed {};
  const int status = qzf_peer_terminal_facts_v6(
      engine_, connectionId, streamId, &observed, toMicroseconds(nowRawNs));
  lastCallerRawNs_ = nowRawNs;
  if (!assignScalarError(status, error)) return false;
  facts = {observed.available, observed.fin, observed.reset_stream,
           observed.stop_sending, observed.connection_close,
           observed.reset_stream_error, observed.stop_sending_error,
           observed.connection_close_error, observed.connection_close_reason_length};
  return true;
}

PrimitiveStatus ZigPacketAdapter::openBidirectionalStream(
    uint64_t connectionId, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qzf_connection_open_bidi(
      engine_, connectionId, &streamId, toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return PrimitiveStatus::fatal;
  return status == 0 ? PrimitiveStatus::wouldBlock : PrimitiveStatus::ready;
}

PrimitiveStatus ZigPacketAdapter::acceptBidirectionalStream(
    uint64_t connectionId, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qzf_connection_accept_bidi(
      engine_, connectionId, &streamId, toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return PrimitiveStatus::fatal;
  return status == 0 ? PrimitiveStatus::wouldBlock : PrimitiveStatus::ready;
}

PrimitiveStatus ZigPacketAdapter::openUnidirectionalStream(
    uint64_t connectionId, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qzf_connection_open_uni(
      engine_, connectionId, &streamId, toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return PrimitiveStatus::fatal;
  return status == 0 ? PrimitiveStatus::wouldBlock : PrimitiveStatus::ready;
}

PrimitiveStatus ZigPacketAdapter::acceptUnidirectionalStream(
    uint64_t connectionId, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qzf_connection_accept_uni(
      engine_, connectionId, &streamId, toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return PrimitiveStatus::fatal;
  return status == 0 ? PrimitiveStatus::wouldBlock : PrimitiveStatus::ready;
}

bool ZigPacketAdapter::writeStream(uint64_t connectionId, uint64_t streamId,
                                   std::span<const std::byte> bytes, uint64_t nowRawNs,
                                   size_t& written, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  written = 0;
  return assignScalarError(qzf_stream_send(
      engine_, connectionId, streamId, reinterpret_cast<const uint8_t*>(bytes.data()),
      bytes.size(), &written, toMicroseconds(nowRawNs)), error);
}

bool ZigPacketAdapter::consumeStreamData(uint64_t connectionId, uint64_t streamId,
                                         std::span<std::byte> bytes, uint64_t nowRawNs,
                                         size_t& read, bool& finished, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  read = 0;
  finished = false;
  return assignScalarError(qzf_stream_recv(
      engine_, connectionId, streamId, reinterpret_cast<uint8_t*>(bytes.data()), bytes.size(),
      &read, &finished, toMicroseconds(nowRawNs)), error);
}

bool ZigPacketAdapter::finishStream(uint64_t connectionId, uint64_t streamId,
                                    uint64_t nowRawNs, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  return assignScalarError(
      qzf_stream_finish(engine_, connectionId, streamId, toMicroseconds(nowRawNs)), error);
}

bool ZigPacketAdapter::resetStream(uint64_t connectionId, uint64_t streamId,
                                   uint64_t applicationError, uint64_t nowRawNs,
                                   AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  return assignScalarError(qzf_stream_reset(
      engine_, connectionId, streamId, applicationError, toMicroseconds(nowRawNs)), error);
}

bool ZigPacketAdapter::stopSending(uint64_t connectionId, uint64_t streamId,
                                   uint64_t applicationError, uint64_t nowRawNs,
                                   AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  return assignScalarError(qzf_stream_stop_sending(
      engine_, connectionId, streamId, applicationError, toMicroseconds(nowRawNs)), error);
}

PrimitiveStatus ZigPacketAdapter::sendDatagram(uint64_t connectionId,
                                               std::span<const std::byte> bytes,
                                               uint64_t nowRawNs, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qzf_datagram_send(
      engine_, connectionId, reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(),
      toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return PrimitiveStatus::fatal;
  return status == 0 ? PrimitiveStatus::wouldBlock : PrimitiveStatus::ready;
}

PrimitiveStatus ZigPacketAdapter::consumeDatagram(uint64_t connectionId,
                                                  std::span<std::byte> bytes,
                                                  uint64_t nowRawNs, size_t& read,
                                                  AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  read = 0;
  const int status = qzf_datagram_recv(
      engine_, connectionId, reinterpret_cast<uint8_t*>(bytes.data()), bytes.size(), &read,
      toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return PrimitiveStatus::fatal;
  return status == 0 ? PrimitiveStatus::wouldBlock : PrimitiveStatus::ready;
}

PrimitiveStatus ZigPacketAdapter::exportResumptionState(
    uint64_t connectionId, uint64_t nowRawNs, std::span<std::byte> bytes, size_t& written,
    AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  written = 0;
  if (bytes.size() <= resumptionEnvelopeBytes)
  {
    error = {1, "Zig resumption output buffer is too small"};
    return PrimitiveStatus::fatal;
  }
  size_t payloadBytes = 0;
  const int status = qzf_engine_export_resumption_state(
      engine_, connectionId,
      reinterpret_cast<uint8_t*>(bytes.data() + resumptionEnvelopeBytes),
      bytes.size() - resumptionEnvelopeBytes, &payloadBytes,
      toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return PrimitiveStatus::fatal;
  if (status == 0) return PrimitiveStatus::wouldBlock;
  return sealResumptionState(
             bytes.subspan(resumptionEnvelopeBytes, payloadBytes), nowRawNs,
             bytes, written, error) ? PrimitiveStatus::ready : PrimitiveStatus::fatal;
}

PrimitiveStatus ZigPacketAdapter::importResumptionState(
    std::span<const std::byte> bytes, bool useZeroRtt, uint64_t nowRawNs,
    AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  std::span<const std::byte> payload;
  if (openResumptionState(bytes, nowRawNs, config_.tlsTicketLifetimeNs,
                          payload, error) != PrimitiveStatus::ready)
    return PrimitiveStatus::fatal;
  const int status = qzf_engine_import_resumption_state(
      engine_, reinterpret_cast<const uint8_t*>(payload.data()), payload.size(), useZeroRtt,
      toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return PrimitiveStatus::fatal;
  return status == 0 ? PrimitiveStatus::wouldBlock : PrimitiveStatus::ready;
}

bool ZigPacketAdapter::connectionResumed(uint64_t connectionId, uint64_t nowRawNs,
                                         bool& resumed, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  const int status = qzf_connection_resumed(engine_, connectionId, toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return false;
  resumed = status != 0;
  return true;
}

bool ZigPacketAdapter::zeroRttAttempted(uint64_t connectionId, uint64_t nowRawNs,
                                       bool& attempted, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  const int status = qzf_connection_zero_rtt_attempted(
      engine_, connectionId, toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return false;
  attempted = status != 0;
  return true;
}

bool ZigPacketAdapter::zeroRttAccepted(uint64_t connectionId, uint64_t nowRawNs,
                                      bool& accepted, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  const int status = qzf_connection_zero_rtt_accepted(
      engine_, connectionId, toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return false;
  accepted = status != 0;
  return true;
}

bool ZigPacketAdapter::zeroRttRejected(uint64_t connectionId, uint64_t nowRawNs,
                                      bool& rejected, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  const int status = qzf_connection_zero_rtt_rejected(
      engine_, connectionId, toMicroseconds(nowRawNs));
  if (!assignScalarError(status, error)) return false;
  rejected = status != 0;
  return true;
}

bool ZigPacketAdapter::closeConnection(uint64_t connectionId, uint64_t applicationError,
                                       uint64_t nowRawNs,
                                       AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Zig adapter is not configured"};
    return false;
  }
  return assignScalarError(qzf_connection_close(
      engine_, connectionId, applicationError, toMicroseconds(nowRawNs)), error);
}

NegotiatedSettings ZigPacketAdapter::snapshotNegotiatedSettings() const noexcept
{
  NegotiatedSettings result;
  if (!engine_ || negotiated_.empty())
  {
    result.unavailableFields = {"no_established_connection"};
    return result;
  }
  const qzf_negotiated_t& settings = negotiated_.begin()->second;
  result.available = true;
  result.evidenceSource =
      "quic-zig Connection.peer_params+TLS13 negotiated cipher/group+verified handshake";
  result.alpn = config_.alpn;
  result.quicVersion = settings.quic_version;
  result.tlsVersion = "TLSv1.3";
  if (settings.tls_cipher_suite == 0x1301)
    result.tlsCipherSuite = "TLS_AES_128_GCM_SHA256";
  else if (settings.tls_cipher_suite == 0x1303)
    result.tlsCipherSuite = "TLS_CHACHA20_POLY1305_SHA256";
  if (settings.tls_named_group == 0x001d) result.tlsKeyExchange = "X25519";
  else if (settings.tls_named_group == 0x0017) result.tlsKeyExchange = "P-256";
  result.peerCertificateVerified = settings.peer_certificate_verified;
  result.hostnameVerified = settings.hostname_verified;
  result.tlsLeafSignature = config_.tlsLeafSignature;
  result.congestionController = "cubic";
  result.initialCongestionWindowBytes = config_.initialCongestionWindowBytes;
  result.maxUdpPayloadSize = settings.max_udp_payload_size;
  result.maxAckDelayNs = settings.max_ack_delay_ns;
  result.ackDelayExponent = settings.ack_delay_exponent;
  result.ackFrequency = settings.ack_frequency;
  result.activeMigration = settings.active_migration;
  result.activeConnectionIdLimit = settings.active_connection_id_limit;
  result.connectionIdBytes = settings.connection_id_bytes;
  result.maxIdleTimeoutNs = settings.max_idle_timeout_ns;
  result.maxBidiStreams = settings.max_bidi_streams;
  result.maxUniStreams = settings.max_uni_streams;
  result.streamCreditReplenishBelow = config_.streamCreditReplenishBelow;
  result.connectionWindowBytes = settings.connection_window_bytes;
  result.streamWindowBytes = settings.stream_window_bytes;
  result.datagramMaxFrameSize = settings.datagram_max_frame_size;
  result.ticketLifetimeNs = config_.tlsTicketLifetimeNs;
  result.maximumEarlyDataBytes = config_.tlsMaximumEarlyDataBytes;
  result.oneUseTickets = config_.tlsOneUseTickets;
  for (const auto& [_, peer] : negotiated_)
  {
    if (!peer.available || peer.peer_certificate_verified != settings.peer_certificate_verified ||
        peer.hostname_verified != settings.hostname_verified ||
        peer.active_migration != settings.active_migration ||
        peer.ack_frequency != settings.ack_frequency ||
        peer.quic_version != settings.quic_version ||
        peer.tls_cipher_suite != settings.tls_cipher_suite ||
        peer.tls_named_group != settings.tls_named_group ||
        peer.max_udp_payload_size != settings.max_udp_payload_size ||
        peer.max_ack_delay_ns != settings.max_ack_delay_ns ||
        peer.ack_delay_exponent != settings.ack_delay_exponent ||
        peer.active_connection_id_limit != settings.active_connection_id_limit ||
        peer.connection_id_bytes != settings.connection_id_bytes ||
        peer.max_idle_timeout_ns != settings.max_idle_timeout_ns ||
        peer.max_bidi_streams != settings.max_bidi_streams ||
        peer.max_uni_streams != settings.max_uni_streams ||
        peer.connection_window_bytes != settings.connection_window_bytes ||
        peer.stream_window_bytes != settings.stream_window_bytes ||
        peer.datagram_max_frame_size != settings.datagram_max_frame_size)
    {
      result.unavailableFields = {"per_connection_evidence_mismatch"};
      break;
    }
  }
  return result;
}

bool ZigPacketAdapter::reset(AdapterError& error)
{
  if (engine_)
  {
    qzf_engine_free(engine_);
    engine_ = nullptr;
  }
  nextTimeoutRawNs_ = 0;
  counters_ = {};
  negotiated_.clear();
  lastCallerRawNs_ = 0;
  configured_ = false;
  error = {};
  return true;
}

bool ZigPacketAdapter::stop(AdapterError& error)
{
  return reset(error);
}

} // namespace quicperf
