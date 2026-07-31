#include "rust_packet_adapter.h"
#include "resumption_envelope.h"
#include "core/measurement.h"

#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

namespace quicperf {
RustPacketAdapter::RustPacketAdapter(uint32_t libraryKind, std::string library) : libraryKind_(libraryKind)
{
  if (qpf_packet_abi_version() != QPF_PACKET_ABI_VERSION) throw std::runtime_error("Rust packet ABI version mismatch");
  capabilities_.library = std::move(library);
  capabilities_.buildId = "rust-packet-ffi-v8-exact-treatment";
  capabilities_.adapterAbiVersion = QPF_PACKET_ABI_VERSION;
  const bool callerTimeCompatible = libraryKind_ == QPF_LIBRARY_QUINN ||
      libraryKind_ == QPF_LIBRARY_NOQ || libraryKind_ == QPF_LIBRARY_NEQO ||
      libraryKind_ == QPF_LIBRARY_S2N;
  capabilities_.server = callerTimeCompatible;
  capabilities_.client = callerTimeCompatible;
  capabilities_.backends = {PacketBackend::syscall, PacketBackend::iouring};
  if (callerTimeCompatible) capabilities_.scenarios = {
      workload::Scenario::download, workload::Scenario::upload,
      workload::Scenario::multistreamDownload, workload::Scenario::multistreamUpload,
      workload::Scenario::bidi, workload::Scenario::smallPayloadPps,
      workload::Scenario::datagram, workload::Scenario::reqresp,
      workload::Scenario::streamChurn,
      workload::Scenario::connect, workload::Scenario::resumedConnect,
      workload::Scenario::zeroRttReqresp, workload::Scenario::memoryCurve,
      workload::Scenario::lossRecovery, workload::Scenario::flowControl,
      workload::Scenario::closeResetCleanup};
  capabilities_.datagram = callerTimeCompatible;
  capabilities_.resumption = callerTimeCompatible;
  capabilities_.earlyData = callerTimeCompatible;
  capabilities_.effectiveFeatures = {
      "common_cpp_packet_io", "borrowed_packet_batch_64", "caller_supplied_raw_time",
      "runtime_threads_none", "ipv4", "quic_v1", "tls_1_3", "qperf_2_alpn",
      "canonical_tls_hostname", "ca_verified_peer", "post_bind_local_address",
      "bidirectional_stream", "unidirectional_stream", "datagram", "resumption",
      "early_data", "reset_stream", "stop_sending", "connection_close",
      "peer_terminal_facts",
      "transport_loss_counter", "recovery_probe_counter",
      "flow_control_blocked_counters"};
  if (!callerTimeCompatible)
    capabilities_.effectiveFeatures = {"unavailable_pinned_std_instant_requires_private_clock"};
}

RustPacketAdapter::~RustPacketAdapter()
{
  qpf_engine_free(engine_);
}

qpf_addr_t RustPacketAdapter::toFfi(const sockaddr_in& address)
{
  qpf_addr_t converted {};
  converted.ip[10] = 0xff;
  converted.ip[11] = 0xff;
  std::memcpy(converted.ip + 12, &address.sin_addr.s_addr, 4);
  converted.port = ntohs(address.sin_port);
  return converted;
}

sockaddr_in RustPacketAdapter::fromFfi(const qpf_addr_t& address)
{
  sockaddr_in converted {};
  converted.sin_family = AF_INET;
  converted.sin_port = htons(address.port);
  std::memcpy(&converted.sin_addr.s_addr, address.ip + 12, 4);
  return converted;
}

void RustPacketAdapter::assignError(const qpf_adapter_status_v2_t& status, AdapterError& error)
{
  error.code = static_cast<uint64_t>(status.code < 0 ? -static_cast<int64_t>(status.code) : status.code);
  error.message.assign(status.message, strnlen(status.message, sizeof(status.message)));
  if (error.message.empty()) error.message = "Rust packet adapter failure";
}

bool RustPacketAdapter::assignScalarError(int status, AdapterError& error)
{
  if (status >= 0) return true;
  error.code = static_cast<uint64_t>(-static_cast<int64_t>(status));
  const char* message = qpf_last_error();
  error.message = message && *message ? message : "Rust transport primitive failure";
  return false;
}

TransportCounters RustPacketAdapter::snapshotTransportCounters() const noexcept
{
  TransportCounters result = counters_;
  if (!engine_) return result;
  qpf_transport_counters_v3_t rust {};
  qpf_adapter_status_v2_t status {};
  if (qpf_engine_transport_counters_v3(engine_, &rust, &status) != 0) return result;
  result.packetsLost += rust.packets_lost;
  result.packetsRetransmitted += rust.packets_retransmitted;
  result.recoveryWakeups += rust.recovery_wakeups;
  result.flowControlBlockedEvents += rust.flow_control_blocked_events;
  result.streamCreditBlockedEvents += rust.stream_credit_blocked_events;
  return result;
}

NegotiatedSettings RustPacketAdapter::snapshotNegotiatedSettings() const noexcept
{
  NegotiatedSettings result;
  result.evidenceSource = "rust_packet_ffi_v7_peer_transport_and_tls";
  if (!engine_)
  {
    result.unavailableFields = {"rust_packet_engine_not_configured"};
    return result;
  }
  qpf_negotiated_settings_v7_t rust {};
  qpf_adapter_status_v2_t status {};
  if (qpf_engine_negotiated_settings_v7(engine_, &rust, &status) != 0)
  {
    result.unavailableFields = {"rust_packet_negotiated_snapshot_failed"};
    return result;
  }
  auto unavailable = [&](std::string field) {
    result.unavailableFields.push_back(std::move(field));
  };
  result.available = rust.available != 0;
  if (rust.alpn_qperf_2) result.alpn = "qperf/2";
  else unavailable("alpn");
  result.quicVersion = rust.quic_version;
  if (rust.tls_version == 0x0304) result.tlsVersion = "TLSv1.3";
  else unavailable("tls_version");
  if (rust.tls_cipher_suite == 0x1301)
    result.tlsCipherSuite = "TLS_AES_128_GCM_SHA256";
  else unavailable("tls_cipher_suite");
  if (rust.tls_key_exchange_group == 0x001d) result.tlsKeyExchange = "X25519";
  else unavailable("tls_key_exchange");
  if (rust.tls_leaf_ed25519 && rust.tls_leaf_signature_algorithm == 0x0807)
    result.tlsLeafSignature = "Ed25519";
  else unavailable("tls_leaf_signature");
  result.peerCertificateVerified = rust.peer_certificate_verified != 0;
  result.hostnameVerified = rust.hostname_verified != 0;
  if (config_.tlsVerifyPeer && !rust.peer_certificate_present)
    unavailable("peer_certificate_present");
  result.congestionController = rust.use_bbr ? "bbr" : "cubic";
  result.initialCongestionWindowBytes = rust.initial_congestion_window_bytes;
  result.maxUdpPayloadSize = rust.max_udp_payload_size;
  result.maxAckDelayNs = rust.max_ack_delay_ns;
  result.ackDelayExponent = rust.ack_delay_exponent;
  result.ackFrequency = rust.ack_frequency != 0;
  result.activeMigration = rust.active_migration != 0;
  result.activeConnectionIdLimit = rust.active_connection_id_limit;
  result.connectionIdBytes = rust.connection_id_bytes;
  result.maxIdleTimeoutNs = rust.max_idle_timeout_ns;
  result.maxBidiStreams = rust.max_bidi_streams;
  result.maxUniStreams = rust.max_uni_streams;
  result.streamCreditReplenishBelow = rust.stream_credit_replenish_below;
  result.connectionWindowBytes = rust.connection_window_bytes;
  result.streamWindowBytes = rust.stream_window_bytes;
  result.datagramMaxFrameSize = rust.datagram_max_frame_size;
  result.ticketLifetimeNs = rust.ticket_lifetime_ns;
  result.maximumEarlyDataBytes = rust.maximum_early_data_bytes;
  result.oneUseTickets = rust.one_use_tickets != 0;
  return result;
}

bool RustPacketAdapter::configure(std::string_view canonicalConfig, AdapterError& error)
{
  const auto parsed = parseEndpointConfig(canonicalConfig);
  if (!parsed)
  {
    error = {2, parsed.error};
    return false;
  }
  if (parsed.config.packetIo.ecn || parsed.config.packetIo.pmtud)
  {
    error = {2, "Rust packet ABI v2 does not attest ECN or PMTUD metadata"};
    return false;
  }
  in_addr ipv4 {};
  if (inet_pton(AF_INET, parsed.config.bindAddress.c_str(), &ipv4) != 1)
  {
    error = {2, "Rust packet adapter requires an IPv4 bind address"};
    return false;
  }
  if (parsed.config.alpn != "qperf/2" || parsed.config.tlsHostname != "server.quicperf.test")
  {
    error = {2, "Rust packet adapters require ALPN qperf/2 and hostname server.quicperf.test"};
    return false;
  }
  if (inet_pton(AF_INET, parsed.config.peerAddress.c_str(), &ipv4) != 1)
  {
    error = {2, "Rust packet adapter requires an IPv4 peer address"};
    return false;
  }
  qpf_engine_free(engine_);
  engine_ = nullptr;
  config_ = parsed.config;
  configured_ = true;
  nextTimeoutRawNs_ = 0;
  counters_ = {};
  return true;
}

bool RustPacketAdapter::setLocalAddress(const sockaddr_in& local, AdapterError& error)
{
  if (!configured_ || local.sin_family != AF_INET)
  {
    error = {2, "Rust packet adapter is not configured with an IPv4 local address"};
    return false;
  }
  sockaddr_in peer {};
  peer.sin_family = AF_INET;
  peer.sin_port = htons(config_.peerPort);
  if (inet_pton(AF_INET, config_.peerAddress.c_str(), &peer.sin_addr) != 1)
  {
    error = {2, "Rust packet adapter requires an IPv4 peer address"};
    return false;
  }
  qpf_config_t config {};
  config.library = libraryKind_;
  config.is_server = config_.role == EndpointRole::server;
  config.local_addr = toFfi(local);
  config.peer_addr = toFfi(peer);
  config.cert_path = config_.certificatePath.c_str();
  config.key_path = config_.privateKeyPath.c_str();
  config.chain_path = config_.chainPath.c_str();
  config.tls_hostname = config_.tlsHostname.c_str();
  config.tls_verify_peer = config_.tlsVerifyPeer;
  config.use_bbr = config_.congestionController == "bbr";
  config.initial_congestion_window_bytes = config_.initialCongestionWindowBytes;
  config.max_ack_delay_ns = config_.maxAckDelayNs;
  config.ack_delay_exponent = config_.ackDelayExponent;
  config.ack_frequency = config_.ackFrequency;
  config.active_migration = config_.activeMigration;
  config.active_connection_id_limit = config_.activeConnectionIdLimit;
  config.connection_id_bytes = config_.connectionIdBytes;
  config.connection_window = config_.connectionWindow;
  config.stream_window = config_.streamWindow;
  config.stream_credit_replenish_below = config_.streamCreditReplenishBelow;
  config.max_bidi_streams = config_.maxBidiStreams;
  config.max_uni_streams = config_.maxUniStreams;
  config.idle_timeout_ms = config_.idleTimeoutMs;
  config.udp_payload_size = config_.maxUdpPayloadSize;
  config.datagram_max_frame_size = config_.datagramMaxFrameSize;
  config.datagram_max_unreturned_per_connection =
      config_.datagramMaxUnreturnedPerConnection;
  config.ticket_lifetime_ns = config_.tlsTicketLifetimeNs;
  config.maximum_early_data_bytes = config_.tlsMaximumEarlyDataBytes;
  config.one_use_tickets = config_.tlsOneUseTickets;
  config.now_us = monotonicRawNowNs() / 1'000;
  config.calendar_unix_seconds = config_.calendarUnixSeconds;
  qpf_engine_free(engine_);
  engine_ = qpf_engine_new(&config);
  if (!engine_)
  {
    error = {1, qpf_last_error() ? qpf_last_error() : "Rust engine creation failed"};
    return false;
  }
  return true;
}

bool RustPacketAdapter::receiveBatch(std::span<const ReceivedPacket> packets, uint64_t nowRawNs, AdapterError& error)
{
  if (!engine_ || packets.size() > receive_.size())
  {
    error = {2, "invalid Rust receive batch"};
    return false;
  }
  for (size_t index = 0; index < packets.size(); ++index)
  {
    receive_[index] = {reinterpret_cast<const uint8_t*>(packets[index].bytes.data()), packets[index].bytes.size(),
                       toFfi(packets[index].peer), packets[index].ecn, {}};
  }
  qpf_adapter_status_v2_t status {};
  if (qpf_engine_receive_batch(engine_, receive_.data(), packets.size(), nowRawNs, &status) != 0)
  {
    assignError(status, error);
    return false;
  }
  counters_.packetsReceived += packets.size();
  return updateTimeout(nowRawNs, error);
}

size_t RustPacketAdapter::pollTransmitBatch(std::span<TransmitPacket> packets, uint64_t nowRawNs, AdapterError& error)
{
  if (!engine_ || packets.size() > transmit_.size())
  {
    error = {2, "invalid Rust transmit batch"};
    return 0;
  }
  for (size_t index = 0; index < packets.size(); ++index)
  {
    transmit_[index] = {output_[index].data(), output_[index].size(), 0, {}, 0, {}, 0};
  }
  size_t count = 0;
  qpf_adapter_status_v2_t status {};
  if (qpf_engine_poll_transmit_batch(engine_, transmit_.data(), packets.size(), &count, nowRawNs, &status) != 0)
  {
    assignError(status, error);
    return 0;
  }
  for (size_t index = 0; index < count; ++index)
  {
    packets[index] = {{reinterpret_cast<const std::byte*>(transmit_[index].data), transmit_[index].len},
                      fromFfi(transmit_[index].peer), transmit_[index].ecn, 0,
                      transmit_[index].desired_send_raw_ns};
  }
  counters_.packetsSent += count;
  if (!updateTimeout(nowRawNs, error)) return 0;
  return count;
}

bool RustPacketAdapter::updateTimeout(uint64_t nowRawNs, AdapterError& error)
{
  qpf_adapter_status_v2_t status {};
  if (qpf_engine_next_timeout_raw_ns(engine_, nowRawNs, &nextTimeoutRawNs_, &status) == 0) return true;
  assignError(status, error);
  return false;
}

bool RustPacketAdapter::completeOperation(int status, uint64_t nowRawNs,
                                          AdapterError& error)
{
  return assignScalarError(status, error) && updateTimeout(nowRawNs, error);
}

PrimitiveStatus RustPacketAdapter::completePrimitiveOperation(
    int status, uint64_t nowRawNs, AdapterError& error)
{
  if (!completeOperation(status, nowRawNs, error)) return PrimitiveStatus::fatal;
  return status == 0 ? PrimitiveStatus::wouldBlock : PrimitiveStatus::ready;
}

bool RustPacketAdapter::onTimeout(uint64_t nowRawNs, AdapterError& error)
{
  qpf_adapter_status_v2_t status {};
  if (qpf_engine_on_timeout_raw_ns(engine_, nowRawNs, &status) != 0)
  {
    assignError(status, error);
    return false;
  }
  ++counters_.timerExpirations;
  return updateTimeout(nowRawNs, error);
}

bool RustPacketAdapter::connect(const sockaddr_in& peer, uint64_t nowRawNs,
                                uint64_t& connectionId, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  const auto remote = toFfi(peer);
  return completeOperation(
      qpf_engine_connect(engine_, &remote, toMicroseconds(nowRawNs), &connectionId),
      nowRawNs, error);
}

PrimitiveStatus RustPacketAdapter::acceptConnection(uint64_t nowRawNs, uint64_t& connectionId,
                                                    AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qpf_engine_accept_connection(engine_, &connectionId);
  return completePrimitiveOperation(status, nowRawNs, error);
}

bool RustPacketAdapter::isConnected(uint64_t connectionId, uint64_t nowRawNs,
                                    bool& connected, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  const int status = qpf_engine_is_connected(engine_, connectionId, toMicroseconds(nowRawNs));
  if (!completeOperation(status, nowRawNs, error)) return false;
  connected = status != 0;
  return true;
}

bool RustPacketAdapter::connectionIsClosed(uint64_t connectionId, uint64_t nowRawNs,
                                           bool& closed, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  const int status = qpf_connection_is_closed(
      engine_, connectionId, toMicroseconds(nowRawNs));
  if (!completeOperation(status, nowRawNs, error)) return false;
  closed = status != 0;
  return true;
}

bool RustPacketAdapter::releaseConnectionWhenClosed(
    uint64_t connectionId, uint64_t nowRawNs, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  return completeOperation(
      qpf_connection_retire(engine_, connectionId, toMicroseconds(nowRawNs)),
      nowRawNs, error);
}

PrimitiveStatus RustPacketAdapter::openBidirectionalStream(
    uint64_t connectionId, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qpf_connection_open_bidi(
      engine_, connectionId, &streamId, toMicroseconds(nowRawNs));
  return completePrimitiveOperation(status, nowRawNs, error);
}

PrimitiveStatus RustPacketAdapter::acceptBidirectionalStream(
    uint64_t connectionId, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qpf_connection_accept_bidi(
      engine_, connectionId, &streamId, toMicroseconds(nowRawNs));
  return completePrimitiveOperation(status, nowRawNs, error);
}

PrimitiveStatus RustPacketAdapter::openUnidirectionalStream(
    uint64_t connectionId, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qpf_connection_open_uni(
      engine_, connectionId, &streamId, toMicroseconds(nowRawNs));
  return completePrimitiveOperation(status, nowRawNs, error);
}

PrimitiveStatus RustPacketAdapter::acceptUnidirectionalStream(
    uint64_t connectionId, uint64_t nowRawNs, uint64_t& streamId, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qpf_connection_accept_uni(
      engine_, connectionId, &streamId, toMicroseconds(nowRawNs));
  return completePrimitiveOperation(status, nowRawNs, error);
}

bool RustPacketAdapter::writeStream(uint64_t connectionId, uint64_t streamId,
                                    std::span<const std::byte> bytes, uint64_t nowRawNs,
                                    size_t& written, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  written = 0;
  return completeOperation(qpf_stream_send(
      engine_, connectionId, streamId, reinterpret_cast<const uint8_t*>(bytes.data()),
      bytes.size(), &written, toMicroseconds(nowRawNs)), nowRawNs, error);
}

bool RustPacketAdapter::consumeStreamData(uint64_t connectionId, uint64_t streamId,
                                          std::span<std::byte> bytes, uint64_t nowRawNs,
                                          size_t& read, bool& finished, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  read = 0;
  finished = false;
  return completeOperation(qpf_stream_recv(
      engine_, connectionId, streamId, reinterpret_cast<uint8_t*>(bytes.data()), bytes.size(),
      &read, &finished, toMicroseconds(nowRawNs)), nowRawNs, error);
}

bool RustPacketAdapter::finishStream(uint64_t connectionId, uint64_t streamId,
                                     uint64_t nowRawNs, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  return completeOperation(
      qpf_stream_finish(engine_, connectionId, streamId, toMicroseconds(nowRawNs)),
      nowRawNs, error);
}

bool RustPacketAdapter::resetStream(uint64_t connectionId, uint64_t streamId,
                                    uint64_t applicationError, uint64_t nowRawNs,
                                    AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  return completeOperation(qpf_stream_reset(engine_, connectionId, streamId,
      applicationError, toMicroseconds(nowRawNs)), nowRawNs, error);
}

bool RustPacketAdapter::stopSending(uint64_t connectionId, uint64_t streamId,
                                    uint64_t applicationError, uint64_t nowRawNs,
                                    AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  return completeOperation(qpf_stream_stop_sending(engine_, connectionId, streamId,
      applicationError, toMicroseconds(nowRawNs)), nowRawNs, error);
}

PrimitiveStatus RustPacketAdapter::sendDatagram(uint64_t connectionId,
                                                std::span<const std::byte> bytes,
                                                uint64_t nowRawNs, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  const int status = qpf_datagram_send(
      engine_, connectionId, reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(),
      toMicroseconds(nowRawNs));
  return completePrimitiveOperation(status, nowRawNs, error);
}

PrimitiveStatus RustPacketAdapter::consumeDatagram(uint64_t connectionId,
                                                   std::span<std::byte> bytes,
                                                   uint64_t nowRawNs, size_t& read,
                                                   AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  read = 0;
  const int status = qpf_datagram_recv(
      engine_, connectionId, reinterpret_cast<uint8_t*>(bytes.data()), bytes.size(), &read,
      toMicroseconds(nowRawNs));
  return completePrimitiveOperation(status, nowRawNs, error);
}

PrimitiveStatus RustPacketAdapter::exportResumptionState(
    uint64_t connectionId, uint64_t nowRawNs, std::span<std::byte> bytes, size_t& written,
    AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  written = 0;
  if (bytes.size() <= resumptionEnvelopeBytes)
  {
    error = {1, "Rust resumption output buffer is too small"};
    return PrimitiveStatus::fatal;
  }
  size_t payloadBytes = 0;
  const int status = qpf_engine_export_resumption_state(
      engine_, connectionId,
      reinterpret_cast<uint8_t*>(bytes.data() + resumptionEnvelopeBytes),
      bytes.size() - resumptionEnvelopeBytes, &payloadBytes,
      toMicroseconds(nowRawNs));
  if (!completeOperation(status, nowRawNs, error)) return PrimitiveStatus::fatal;
  if (status == 0) return PrimitiveStatus::wouldBlock;
  return sealResumptionState(
             bytes.subspan(resumptionEnvelopeBytes, payloadBytes), nowRawNs,
             bytes, written, error) ? PrimitiveStatus::ready : PrimitiveStatus::fatal;
}

PrimitiveStatus RustPacketAdapter::importResumptionState(
    std::span<const std::byte> bytes, bool useZeroRtt, uint64_t nowRawNs,
    AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return PrimitiveStatus::fatal;
  }
  std::span<const std::byte> payload;
  if (openResumptionState(bytes, nowRawNs, config_.tlsTicketLifetimeNs,
                          payload, error) != PrimitiveStatus::ready)
    return PrimitiveStatus::fatal;
  const int status = qpf_engine_import_resumption_state(
      engine_, reinterpret_cast<const uint8_t*>(payload.data()), payload.size(), useZeroRtt,
      toMicroseconds(nowRawNs));
  return completePrimitiveOperation(status, nowRawNs, error);
}

bool RustPacketAdapter::connectionResumed(uint64_t connectionId, uint64_t nowRawNs,
                                          bool& resumed, AdapterError& error)
{
  const int status = engine_ ? qpf_connection_resumed(
      engine_, connectionId, toMicroseconds(nowRawNs)) : -1;
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  if (!completeOperation(status, nowRawNs, error)) return false;
  resumed = status != 0;
  return true;
}

bool RustPacketAdapter::zeroRttAttempted(uint64_t connectionId, uint64_t nowRawNs,
                                        bool& attempted, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  const int status = qpf_connection_zero_rtt_attempted(
      engine_, connectionId, toMicroseconds(nowRawNs));
  if (!completeOperation(status, nowRawNs, error)) return false;
  attempted = status != 0;
  return true;
}

bool RustPacketAdapter::zeroRttAccepted(uint64_t connectionId, uint64_t nowRawNs,
                                       bool& accepted, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  const int status = qpf_connection_zero_rtt_accepted(
      engine_, connectionId, toMicroseconds(nowRawNs));
  if (!completeOperation(status, nowRawNs, error)) return false;
  accepted = status != 0;
  return true;
}

bool RustPacketAdapter::zeroRttRejected(uint64_t connectionId, uint64_t nowRawNs,
                                       bool& rejected, AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  const int status = qpf_connection_zero_rtt_rejected(
      engine_, connectionId, toMicroseconds(nowRawNs));
  if (!completeOperation(status, nowRawNs, error)) return false;
  rejected = status != 0;
  return true;
}

bool RustPacketAdapter::closeConnection(uint64_t connectionId, uint64_t applicationError,
                                        uint64_t nowRawNs,
                                        AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  return completeOperation(qpf_connection_close(engine_, connectionId, applicationError,
      toMicroseconds(nowRawNs)), nowRawNs, error);
}

bool RustPacketAdapter::peerTerminalFacts(uint64_t connectionId, uint64_t streamId,
                                          uint64_t nowRawNs, PeerTerminalFacts& facts,
                                          AdapterError& error)
{
  if (!engine_)
  {
    error = {2, "Rust adapter is not configured"};
    return false;
  }
  qpf_peer_terminal_facts_v6_t observed {};
  const int status = qpf_peer_terminal_facts_v6(
      engine_, connectionId, streamId, &observed, toMicroseconds(nowRawNs));
  if (!completeOperation(status, nowRawNs, error)) return false;
  facts = {observed.available, observed.fin, observed.reset_stream,
           observed.stop_sending, observed.connection_close,
           observed.reset_stream_error, observed.stop_sending_error,
           observed.connection_close_error, observed.connection_close_reason_length};
  return true;
}

bool RustPacketAdapter::reset(AdapterError& error)
{
  if (engine_)
  {
    qpf_engine_free(engine_);
    engine_ = nullptr;
  }
  nextTimeoutRawNs_ = 0;
  counters_ = {};
  error = {};
  return true;
}

bool RustPacketAdapter::stop(AdapterError& error)
{
  return reset(error);
}

} // namespace quicperf
