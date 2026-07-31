#include "adapters/adapter_factory.h"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <time.h>

#ifndef EXPECTED_LIBRARY
#error EXPECTED_LIBRARY must name the adapter under test
#endif

#ifndef EXPECT_UNIDIRECTIONAL_STREAMS
#error EXPECT_UNIDIRECTIONAL_STREAMS must be zero or one
#endif

#ifndef EXPECT_EARLY_DATA
#error EXPECT_EARLY_DATA must be zero or one
#endif

#ifndef EXPECT_RESET_STOP
#error EXPECT_RESET_STOP must be zero or one
#endif

#ifndef EXPECT_SUPPORTED
#error EXPECT_SUPPORTED must be zero or one
#endif

namespace {

using quicperf::Adapter;
using quicperf::AdapterError;
using quicperf::PrimitiveStatus;
using quicperf::ReceivedPacket;
using quicperf::TransmitPacket;

size_t directoryEntries(const char* path)
{
  size_t result = 0;
  for ([[maybe_unused]] const auto& entry : std::filesystem::directory_iterator(path)) ++result;
  return result;
}

bool hasForbiddenDescriptor()
{
  for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd"))
  {
    std::error_code error;
    const std::string target = std::filesystem::read_symlink(entry.path(), error).string();
    if (error) continue;
    if (target.starts_with("socket:") || target == "anon_inode:[eventpoll]" ||
        target == "anon_inode:[eventfd]" || target == "anon_inode:[io_uring]" ||
        target == "anon_inode:[timerfd]" || target == "anon_inode:[signalfd]")
      return true;
  }
  return false;
}

sockaddr_in address(std::string_view text, uint16_t port)
{
  sockaddr_in result {};
  result.sin_family = AF_INET;
  result.sin_port = htons(port);
  const std::string owned(text);
  assert(inet_pton(AF_INET, owned.c_str(), &result.sin_addr) == 1);
  return result;
}

uint64_t nowRawNs()
{
  timespec value {};
  assert(clock_gettime(CLOCK_MONOTONIC_RAW, &value) == 0);
  return static_cast<uint64_t>(value.tv_sec) * 1'000'000'000 + value.tv_nsec;
}

std::string config(bool server)
{
  const std::string root = QUICPERF_SOURCE_DIR;
  return
      "{\"ack_delay_exponent\":3,\"ack_frequency\":false,"
      "\"active_connection_id_limit\":2,\"active_migration\":false,"
      "\"active_streams_per_connection\":1,\"alpn\":\"qperf/2\","
      "\"backend\":\"syscall\","
      "\"bind_address\":\"127.0.0.1\",\"bind_port\":" +
      std::to_string(server ? 4433 : 40000) + ","
      "\"bulk_chunk_bytes\":262144,\"busy_polling\":false,"
      "\"calendar_unix_seconds\":1784376000,"
      "\"certificate_path\":\"" + root + "/tls/bench.cert.pem\","
      "\"chain_path\":\"" + root + "/tls/bench.chain.pem\","
      "\"common_pacing\":true,\"congestion_controller\":\"cubic\","
      "\"connection_count\":3,\"connection_id_bytes\":8,"
      "\"connection_window\":67108864,\"datagram_body_bytes\":0,"
      "\"datagram_max_frame_size\":1200,\"datagram_max_unreturned_per_connection\":0,"
      "\"ecn\":false,\"event_loop_workers\":" + std::to_string(server ? 1 : 2) + ","
      "\"global_operation_slots\":0,\"idle_timeout_ms\":30000,"
      "\"initial_congestion_window_bytes\":13500,\"max_ack_delay_ns\":25000000,"
      "\"max_bidi_streams\":256,\"max_udp_payload_size\":1350,"
      "\"max_uni_streams\":256,\"measurement_duration_ns\":2000000000,"
      "\"operation_body_bytes\":0,\"path_profile\":\"loopback\",\"peer_address\":\"" +
      (server ? "0.0.0.0" : "127.0.0.1") + "\",\"peer_port\":" +
      std::to_string(server ? 0 : 4433) + ",\"pmtud\":false,"
      "\"private_key_path\":\"" + root + "/tls/bench.key.pem\","
      "\"progress_interval_ns\":200000000,\"quic_version\":\"0x00000001\","
      "\"receive_timestamps\":false,"
      "\"request_body_bytes\":8,\"require_multishot_receive\":false,"
      "\"response_body_bytes\":0,\"role\":\"" + (server ? "server" : "client") + "\","
      "\"scenario\":\"download\",\"schema_version\":2,"
      "\"stream_credit_replenish_below\":32,\"stream_window\":67108864,"
      "\"ticket_slots\":0,\"tls_cipher_suite\":\"TLS_AES_128_GCM_SHA256\","
      "\"tls_hostname\":\"localhost\",\"tls_key_exchange\":\"X25519\","
      "\"tls_leaf_signature\":\"Ed25519\",\"tls_maximum_early_data_bytes\":4096,"
      "\"tls_one_use_tickets\":true,\"tls_ticket_lifetime_ns\":300000000000,"
      "\"tls_verify_peer\":" +
      (server ? "false" : "true") + ",\"tls_version\":\"TLSv1.3\","
      "\"trace_seed\":\"0000000000000000000000000000000000000000000000000000000000000000\","
      "\"udp_gro\":true,\"udp_gso\":true,\"warmup_duration_ns\":250000000}";
}

void transfer(Adapter& source, Adapter& destination, const sockaddr_in& sourceAddress,
              uint64_t nowRawNs)
{
  std::array<TransmitPacket, 64> transmitted {};
  AdapterError error;
  const size_t count = source.pollTransmitBatch(transmitted, nowRawNs, error);
  assert(error.message.empty());
  std::array<ReceivedPacket, 64> received {};
  for (size_t index = 0; index < count; ++index)
    received[index] = {transmitted[index].bytes, sourceAddress, transmitted[index].ecn,
                       transmitted[index].gsoSegmentSize, nowRawNs};
  assert(!count || destination.receiveBatch(
      std::span<const ReceivedPacket>(received).first(count), nowRawNs, error));
}

void drive(Adapter& client, Adapter& server, const sockaddr_in& clientAddress,
           const sockaddr_in& serverAddress, uint64_t& nowRawNs)
{
  transfer(client, server, clientAddress, nowRawNs);
  transfer(server, client, serverAddress, nowRawNs);
  AdapterError error;
  if (client.nextTimeoutRawNs() && client.nextTimeoutRawNs() <= nowRawNs)
    assert(client.onTimeout(nowRawNs, error));
  if (server.nextTimeoutRawNs() && server.nextTimeoutRawNs() <= nowRawNs)
    assert(server.onTimeout(nowRawNs, error));
  nowRawNs += 1'000'000;
}

uint64_t acceptConnection(Adapter& server, Adapter& client,
                          const sockaddr_in& clientAddress,
                          const sockaddr_in& serverAddress, uint64_t& nowRawNs)
{
  AdapterError error;
  for (unsigned iteration = 0; iteration < 10'000; ++iteration)
  {
    uint64_t id = 0;
    const auto status = server.acceptConnection(nowRawNs, id, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::ready) return id;
    drive(client, server, clientAddress, serverAddress, nowRawNs);
  }
  std::cerr << "connection was not accepted\n";
  std::abort();
}

void waitConnected(Adapter& client, Adapter& server, uint64_t clientId,
                   uint64_t serverId, const sockaddr_in& clientAddress,
                   const sockaddr_in& serverAddress, uint64_t& nowRawNs)
{
  AdapterError error;
  for (unsigned iteration = 0; iteration < 10'000; ++iteration)
  {
    bool clientReady = false;
    bool serverReady = false;
    assert(client.isConnected(clientId, nowRawNs, clientReady, error));
    assert(server.isConnected(serverId, nowRawNs, serverReady, error));
    if (clientReady && serverReady) return;
    drive(client, server, clientAddress, serverAddress, nowRawNs);
  }
  bool clientReady = false;
  bool serverReady = false;
  client.isConnected(clientId, nowRawNs, clientReady, error);
  server.isConnected(serverId, nowRawNs, serverReady, error);
  const auto clientCounters = client.snapshotTransportCounters();
  const auto serverCounters = server.snapshotTransportCounters();
  std::cerr << "handshake did not complete: client=" << clientReady
            << " server=" << serverReady
            << " client_packets=" << clientCounters.packetsSent << '/'
            << clientCounters.packetsReceived
            << " server_packets=" << serverCounters.packetsSent << '/'
            << serverCounters.packetsReceived << '\n';
  std::abort();
}

uint64_t openStream(Adapter& sender, Adapter& receiver, bool bidirectional,
                    uint64_t connectionId,
                    const sockaddr_in& senderAddress,
                    const sockaddr_in& receiverAddress, uint64_t& nowRawNs)
{
  AdapterError error;
  for (unsigned iteration = 0; iteration < 10'000; ++iteration)
  {
    uint64_t id = 0;
    const auto status = bidirectional ?
        sender.openBidirectionalStream(connectionId, nowRawNs, id, error) :
        sender.openUnidirectionalStream(connectionId, nowRawNs, id, error);
    if (status == PrimitiveStatus::fatal)
      std::cerr << "open " << (bidirectional ? "bidirectional" : "unidirectional")
                << " stream failed: " << error.code << ": " << error.message << '\n';
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::ready) return id;
    drive(sender, receiver, senderAddress, receiverAddress, nowRawNs);
  }
  std::cerr << "local stream did not open\n";
  std::abort();
}

uint64_t acceptStream(Adapter& receiver, Adapter& sender, bool bidirectional,
                      uint64_t connectionId,
                      const sockaddr_in& senderAddress,
                      const sockaddr_in& receiverAddress, uint64_t& nowRawNs)
{
  AdapterError error;
  for (unsigned iteration = 0; iteration < 10'000; ++iteration)
  {
    uint64_t id = 0;
    const auto status = bidirectional ?
        receiver.acceptBidirectionalStream(connectionId, nowRawNs, id, error) :
        receiver.acceptUnidirectionalStream(connectionId, nowRawNs, id, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::ready) return id;
    drive(sender, receiver, senderAddress, receiverAddress, nowRawNs);
  }
  std::cerr << "peer stream was not accepted\n";
  std::abort();
}

} // namespace

int main()
{
  const size_t initialFds = directoryEntries("/proc/self/fd");
  const size_t initialThreads = directoryEntries("/proc/self/task");
  auto client = quicperf::makeTransportAdapter();
  auto server = quicperf::makeTransportAdapter();
  assert(client->capabilities().library == EXPECTED_LIBRARY);
  AdapterError error;
#if !EXPECT_SUPPORTED
  assert(!client->capabilities().server && !client->capabilities().client);
  assert(client->capabilities().scenarios.empty());
  assert(!client->capabilities().datagram);
  assert(!client->capabilities().resumption);
  assert(!client->capabilities().earlyData);
  assert(!client->configure(config(false), error));
  assert(!error.message.empty());
  assert(directoryEntries("/proc/self/fd") == initialFds);
  assert(directoryEntries("/proc/self/task") == initialThreads);
  return 0;
#endif
  assert(client->capabilities().server && client->capabilities().client);
  assert(client->capabilities().datagram);
  assert(client->capabilities().resumption);
  assert(client->capabilities().earlyData == static_cast<bool>(EXPECT_EARLY_DATA));
  const bool cleanupAdvertised = std::find(
      client->capabilities().scenarios.begin(), client->capabilities().scenarios.end(),
      quicperf::workload::Scenario::closeResetCleanup) !=
      client->capabilities().scenarios.end();
  assert(cleanupAdvertised == static_cast<bool>(EXPECT_RESET_STOP));
  if (!client->configure(config(false), error))
  {
    std::cerr << "client configure: " << error.code << ": " << error.message << '\n';
    return 1;
  }
  if (!server->configure(config(true), error))
  {
    std::cerr << "server configure: " << error.code << ": " << error.message << '\n';
    return 1;
  }
  const size_t initializedFds = directoryEntries("/proc/self/fd");
  assert(!hasForbiddenDescriptor());
  assert(directoryEntries("/proc/self/task") == initialThreads);
  const auto clientAddress = address("127.0.0.1", 40000);
  const auto serverAddress = address("127.0.0.1", 4433);
  assert(client->setLocalAddress(clientAddress, error));
  assert(server->setLocalAddress(serverAddress, error));

  uint64_t nowRawNs = ::nowRawNs();
  uint64_t clientId = 0;
  assert(client->connect(serverAddress, nowRawNs, clientId, error));
  const uint64_t serverId = acceptConnection(
      *server, *client, clientAddress, serverAddress, nowRawNs);
  waitConnected(*client, *server, clientId, serverId,
                clientAddress, serverAddress, nowRawNs);

  const auto clientSettings = client->snapshotNegotiatedSettings();
  const auto serverSettings = server->snapshotNegotiatedSettings();
  assert(clientSettings.available && serverSettings.available);
  assert(!clientSettings.evidenceSource.empty());
  assert(!clientSettings.unavailableFields.empty());
  assert(clientSettings.connectionIdBytes == 8);
  assert(clientSettings.tlsCipherSuite == "TLS_AES_128_GCM_SHA256");
  if (std::string_view(EXPECTED_LIBRARY) == "lsquic")
  {
    assert(clientSettings.quicVersion == 1);
  }
  else
  {
    assert(clientSettings.alpn == "qperf/2");
    assert(clientSettings.tlsVersion == "TLSv1.3");
    assert(clientSettings.tlsKeyExchange == "X25519");
    assert(clientSettings.datagramMaxFrameSize == 1200);
  }

  const uint64_t clientStream = openStream(
      *client, *server, true, clientId, clientAddress, serverAddress, nowRawNs);
  const std::string payload = "limited native adapter packet boundary";
  const auto bytes = std::as_bytes(std::span(payload));
  size_t written = 0;
  assert(client->writeStream(clientId, clientStream, bytes, nowRawNs, written, error));
  assert(written == bytes.size());
  assert(client->finishStream(clientId, clientStream, nowRawNs, error));
  const uint64_t serverStream = acceptStream(
      *server, *client, true, serverId, clientAddress, serverAddress, nowRawNs);
  assert(serverStream == clientStream);
  std::array<std::byte, 128> output {};
  bool complete = false;
  for (unsigned iteration = 0; iteration < 10'000 && !complete; ++iteration)
  {
    size_t read = 0;
    assert(server->consumeStreamData(
        serverId, serverStream, output, nowRawNs, read, complete, error));
    if (read) assert(std::equal(output.begin(), output.begin() + read, bytes.begin()));
    if (!complete) drive(*client, *server, clientAddress, serverAddress, nowRawNs);
  }
  assert(complete);

  const std::array<std::byte, 88> datagram {};
  assert(client->sendDatagram(clientId, datagram, nowRawNs, error) ==
         PrimitiveStatus::ready);
  bool gotDatagram = false;
  for (unsigned iteration = 0; iteration < 10'000 && !gotDatagram; ++iteration)
  {
    size_t read = 0;
    const auto status = server->consumeDatagram(serverId, output, nowRawNs, read, error);
    assert(status != PrimitiveStatus::fatal);
    gotDatagram = status == PrimitiveStatus::ready;
    if (gotDatagram) assert(read == datagram.size());
    else drive(*client, *server, clientAddress, serverAddress, nowRawNs);
  }
  assert(gotDatagram);

#if EXPECT_UNIDIRECTIONAL_STREAMS
  const uint64_t clientUni = openStream(
      *client, *server, false, clientId, clientAddress, serverAddress, nowRawNs);
  assert(client->finishStream(clientId, clientUni, nowRawNs, error));
  const uint64_t serverUni = acceptStream(
      *server, *client, false, serverId, clientAddress, serverAddress, nowRawNs);
  assert(serverUni == clientUni);
#else
  uint64_t unsupportedId = 0;
  assert(client->openUnidirectionalStream(clientId, nowRawNs, unsupportedId, error) ==
         PrimitiveStatus::fatal);
#endif
#if EXPECT_RESET_STOP
  const uint64_t lifecycleStream = openStream(
      *client, *server, true, clientId, clientAddress, serverAddress, nowRawNs);
  const std::array<std::byte, 1> proof {};
  size_t proofWritten = 0;
  assert(client->writeStream(
      clientId, lifecycleStream, proof, nowRawNs, proofWritten, error));
  assert(proofWritten == proof.size());
  const uint64_t peerLifecycleStream = acceptStream(
      *server, *client, true, serverId, clientAddress, serverAddress, nowRawNs);
  assert(peerLifecycleStream == lifecycleStream);
  assert(client->resetStream(clientId, lifecycleStream, 7, nowRawNs, error));
  assert(server->stopSending(serverId, peerLifecycleStream, 8, nowRawNs, error));
#else
  assert(!client->resetStream(clientId, clientStream, 7, nowRawNs, error));
  assert(!client->stopSending(clientId, clientStream, 7, nowRawNs, error));
#endif
  assert(client->snapshotTransportCounters().packetsSent > 0);
  assert(client->snapshotTransportCounters().packetsReceived > 0);
  assert(directoryEntries("/proc/self/fd") == initializedFds);
  assert(!hasForbiddenDescriptor());
  assert(directoryEntries("/proc/self/task") == initialThreads);
  assert(client->stop(error));
  assert(server->stop(error));
  assert(client->snapshotTransportCounters().packetsSent == 0);
  assert(directoryEntries("/proc/self/fd") == initialFds);
}
