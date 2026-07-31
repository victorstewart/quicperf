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
#include <vector>

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

sockaddr_in address(std::string_view text, uint16_t port)
{
  sockaddr_in result {};
  result.sin_family = AF_INET;
  result.sin_port = htons(port);
  const std::string owned(text);
  assert(inet_pton(AF_INET, owned.c_str(), &result.sin_addr) == 1);
  return result;
}

std::string config(bool server)
{
  const std::string root = QUICPERF_SOURCE_DIR;
  const std::string peerAddress = server ? "0.0.0.0" : "127.0.0.1";
  const unsigned peerPort = server ? 0 : 4433;
  const unsigned workers = server ? 1 : 2;
  const std::string verify = server ? "false" : "true";
  return
      "{\"ack_delay_exponent\":3,\"ack_frequency\":false,"
      "\"active_connection_id_limit\":2,\"active_migration\":false,"
      "\"active_streams_per_connection\":1,\"alpn\":\"qperf/2\","
      "\"backend\":\"syscall\","
      "\"bind_address\":\"127.0.0.1\",\"bind_port\":0,"
      "\"bulk_chunk_bytes\":262144,\"busy_polling\":false,"
      "\"calendar_unix_seconds\":1784376000,"
      "\"certificate_path\":\"" + root + "/tls/server.cert.pem\","
      "\"chain_path\":\"" + root + "/tls/chain.cert.pem\","
      "\"common_pacing\":true,\"congestion_controller\":\"cubic\","
      "\"connection_count\":3,\"connection_id_bytes\":8,"
      "\"connection_window\":67108864,\"datagram_body_bytes\":0,"
      "\"datagram_max_frame_size\":1200,\"datagram_max_unreturned_per_connection\":0,"
      "\"ecn\":false,\"event_loop_workers\":" + std::to_string(workers) + ","
      "\"global_operation_slots\":0,\"idle_timeout_ms\":30000,"
      "\"initial_congestion_window_bytes\":13500,\"max_ack_delay_ns\":25000000,"
      "\"max_bidi_streams\":256,\"max_udp_payload_size\":1350,"
      "\"max_uni_streams\":256,\"measurement_duration_ns\":2000000000,"
      "\"operation_body_bytes\":0,\"path_profile\":\"loopback\",\"peer_address\":\"" + peerAddress + "\","
      "\"peer_port\":" + std::to_string(peerPort) + ",\"pmtud\":false,"
      "\"private_key_path\":\"" + root + "/tls/server.key.pem\","
      "\"progress_interval_ns\":200000000,\"quic_version\":\"0x00000001\","
      "\"receive_timestamps\":false,"
      "\"request_body_bytes\":8,\"require_multishot_receive\":false,"
      "\"response_body_bytes\":0,\"role\":\"" + (server ? "server" : "client") + "\","
      "\"scenario\":\"download\",\"schema_version\":2,"
      "\"stream_credit_replenish_below\":32,\"stream_window\":67108864,"
      "\"ticket_slots\":0,\"tls_cipher_suite\":\"TLS_AES_128_GCM_SHA256\","
      "\"tls_hostname\":\"server.quicperf.test\",\"tls_key_exchange\":\"X25519\","
      "\"tls_leaf_signature\":\"Ed25519\",\"tls_maximum_early_data_bytes\":4096,"
      "\"tls_one_use_tickets\":true,\"tls_ticket_lifetime_ns\":300000000000,"
      "\"tls_verify_peer\":" + verify + ",\"tls_version\":\"TLSv1.3\","
      "\"trace_seed\":\"0000000000000000000000000000000000000000000000000000000000000000\","
      "\"udp_gro\":true,\"udp_gso\":true,"
      "\"warmup_duration_ns\":250000000}";
}

size_t transfer(Adapter& source, Adapter& destination, const sockaddr_in& sourceAddress,
                uint64_t nowRawNs)
{
  std::array<TransmitPacket, 64> transmitted {};
  AdapterError error;
  const size_t count = source.pollTransmitBatch(transmitted, nowRawNs, error);
  if (!error.message.empty())
  {
    std::cerr << "transmit batch: " << error.message << '\n';
    std::abort();
  }
  std::array<ReceivedPacket, 64> received {};
  for (size_t index = 0; index < count; ++index)
  {
    assert(!transmitted[index].bytes.empty());
    received[index] = {transmitted[index].bytes, sourceAddress, transmitted[index].ecn,
                       transmitted[index].gsoSegmentSize, nowRawNs};
  }
  if (count && !destination.receiveBatch(
      std::span<const ReceivedPacket>(received).first(count), nowRawNs, error))
  {
    std::cerr << "receive batch: " << error.message << '\n';
    std::abort();
  }
  return count;
}

void expire(Adapter& adapter, uint64_t nowRawNs)
{
  AdapterError error;
  const uint64_t expiry = adapter.nextTimeoutRawNs();
  if (expiry && expiry <= nowRawNs) assert(adapter.onTimeout(nowRawNs, error));
}

void drive(Adapter& client, Adapter& server, const sockaddr_in& clientAddress,
           const sockaddr_in& serverAddress, uint64_t& nowRawNs)
{
  transfer(client, server, clientAddress, nowRawNs);
  transfer(server, client, serverAddress, nowRawNs);
  expire(client, nowRawNs);
  expire(server, nowRawNs);
  nowRawNs += 1'000'000;
}

void waitConnected(Adapter& client, Adapter& server, uint64_t clientId, uint64_t serverId,
                   const sockaddr_in& clientAddress, const sockaddr_in& serverAddress,
                   uint64_t& nowRawNs)
{
  AdapterError error;
  for (size_t iteration = 0; iteration < 10'000; ++iteration)
  {
    bool clientReady = false;
    bool serverReady = false;
    assert(client.isConnected(clientId, nowRawNs, clientReady, error));
    assert(server.isConnected(serverId, nowRawNs, serverReady, error));
    if (clientReady && serverReady) return;
    drive(client, server, clientAddress, serverAddress, nowRawNs);
  }
  assert(false && "ngtcp2 handshake did not complete");
}

uint64_t waitAcceptedConnection(Adapter& server, Adapter& client,
                                const sockaddr_in& clientAddress,
                                const sockaddr_in& serverAddress, uint64_t& nowRawNs)
{
  AdapterError error;
  for (size_t iteration = 0; iteration < 10'000; ++iteration)
  {
    uint64_t id = 0;
    const auto status = server.acceptConnection(nowRawNs, id, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::ready) return id;
    drive(client, server, clientAddress, serverAddress, nowRawNs);
  }
  assert(false && "ngtcp2 server did not accept the connection");
  return 0;
}

uint64_t openStream(Adapter& adapter, bool bidirectional, uint64_t connectionId,
                    uint64_t nowRawNs)
{
  AdapterError error;
  uint64_t streamId = 0;
  const auto status = bidirectional ?
      adapter.openBidirectionalStream(connectionId, nowRawNs, streamId, error) :
      adapter.openUnidirectionalStream(connectionId, nowRawNs, streamId, error);
  assert(status == PrimitiveStatus::ready);
  return streamId;
}

uint64_t waitAcceptedStream(Adapter& receiver, Adapter& sender, bool bidirectional,
                            uint64_t receiverConnectionId,
                            const sockaddr_in& senderAddress,
                            const sockaddr_in& receiverAddress, uint64_t& nowRawNs)
{
  AdapterError error;
  for (size_t iteration = 0; iteration < 10'000; ++iteration)
  {
    uint64_t streamId = 0;
    const auto status = bidirectional ?
        receiver.acceptBidirectionalStream(receiverConnectionId, nowRawNs, streamId, error) :
        receiver.acceptUnidirectionalStream(receiverConnectionId, nowRawNs, streamId, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::ready) return streamId;
    drive(sender, receiver, senderAddress, receiverAddress, nowRawNs);
  }
  assert(false && "ngtcp2 peer stream did not open");
  return 0;
}

void sendAndVerifyStream(Adapter& sender, Adapter& receiver, bool bidirectional,
                         uint64_t senderConnectionId, uint64_t receiverConnectionId,
                         const sockaddr_in& senderAddress,
                         const sockaddr_in& receiverAddress, uint64_t& nowRawNs,
                         std::string_view payload)
{
  AdapterError error;
  const uint64_t senderStream = openStream(sender, bidirectional, senderConnectionId, nowRawNs);
  const auto bytes = std::as_bytes(std::span(payload));
  size_t written = 0;
  assert(sender.writeStream(senderConnectionId, senderStream, bytes, nowRawNs, written, error));
  assert(written == bytes.size());
  assert(sender.finishStream(senderConnectionId, senderStream, nowRawNs, error));
  const uint64_t receiverStream = waitAcceptedStream(
      receiver, sender, bidirectional, receiverConnectionId, senderAddress, receiverAddress,
      nowRawNs);
  assert(receiverStream == senderStream);
  std::array<std::byte, 128> output {};
  for (size_t iteration = 0; iteration < 10'000; ++iteration)
  {
    size_t read = 0;
    bool finished = false;
    assert(receiver.consumeStreamData(receiverConnectionId, receiverStream, output,
                                      nowRawNs, read, finished, error));
    if (read)
    {
      assert(read == bytes.size());
      assert(std::equal(output.begin(), output.begin() + read, bytes.begin()));
    }
    if (finished)
    {
      assert(read == bytes.size());
      return;
    }
    drive(sender, receiver, senderAddress, receiverAddress, nowRawNs);
  }
  assert(false && "ngtcp2 stream did not finish");
}

} // namespace

int main()
{
  const size_t initialFds = directoryEntries("/proc/self/fd");
  const size_t initialThreads = directoryEntries("/proc/self/task");
  auto client = quicperf::makeTransportAdapter();
  auto server = quicperf::makeTransportAdapter();
  assert(client->capabilities().library == "ngtcp2");
  assert(client->capabilities().scenarios.size() == 16);
  assert(std::find(client->capabilities().scenarios.begin(),
                   client->capabilities().scenarios.end(),
                   quicperf::workload::Scenario::memoryCurve) !=
         client->capabilities().scenarios.end());
  assert(std::find(client->capabilities().scenarios.begin(),
                   client->capabilities().scenarios.end(),
                   quicperf::workload::Scenario::closeResetCleanup) !=
         client->capabilities().scenarios.end());
  AdapterError error;
  if (!client->configure(config(false), error))
  {
    std::cerr << "client configure: " << error.message << '\n';
    return 1;
  }
  if (!server->configure(config(true), error))
  {
    std::cerr << "server configure: " << error.message << '\n';
    return 1;
  }
  const sockaddr_in clientAddress = address("127.0.0.1", 40000);
  const sockaddr_in serverAddress = address("127.0.0.1", 4433);
  assert(client->setLocalAddress(clientAddress, error));
  assert(server->setLocalAddress(serverAddress, error));
  assert(directoryEntries("/proc/self/fd") == initialFds);
  assert(directoryEntries("/proc/self/task") == initialThreads);

  uint64_t nowRawNs = 1'000'000'000;
  std::array<std::byte, 23> staleLongHeader {};
  staleLongHeader[0] = std::byte {0xc0};
  staleLongHeader[4] = std::byte {0x01};
  staleLongHeader[5] = std::byte {0x08};
  staleLongHeader[14] = std::byte {0x08};
  const ReceivedPacket stalePacket {
      staleLongHeader, serverAddress, 0, 0, nowRawNs};
  assert(client->receiveBatch(std::span(&stalePacket, 1), nowRawNs, error));

  uint64_t clientId = 0;
  if (!client->connect(serverAddress, nowRawNs, clientId, error))
  {
    std::cerr << "client connect: " << error.message << '\n';
    return 1;
  }
  const uint64_t serverId = waitAcceptedConnection(
      *server, *client, clientAddress, serverAddress, nowRawNs);
  waitConnected(*client, *server, clientId, serverId,
                clientAddress, serverAddress, nowRawNs);

  const uint64_t controlStream = openStream(*client, true, clientId, nowRawNs);
  const std::array<std::byte, 64> controlHello {};
  size_t controlWritten = 0;
  assert(client->writeStream(clientId, controlStream, controlHello, nowRawNs,
                             controlWritten, error));
  assert(controlWritten == controlHello.size());
  const uint64_t peerControlStream = waitAcceptedStream(
      *server, *client, true, serverId, clientAddress, serverAddress, nowRawNs);
  assert(peerControlStream == controlStream);
  std::array<std::byte, 64> controlOutput {};
  size_t controlRead = 0;
  bool controlFinished = false;
  assert(server->consumeStreamData(serverId, peerControlStream, controlOutput,
                                   nowRawNs, controlRead, controlFinished, error));
  assert(controlRead == controlHello.size() && !controlFinished);

  sendAndVerifyStream(*client, *server, true, clientId, serverId,
                      clientAddress, serverAddress, nowRawNs, "bidirectional");
  sendAndVerifyStream(*client, *server, false, clientId, serverId,
                      clientAddress, serverAddress, nowRawNs, "unidirectional");

  const std::array<std::byte, 88> datagram {};
  assert(client->sendDatagram(clientId, datagram, nowRawNs, error) == PrimitiveStatus::ready);
  std::array<std::byte, 128> datagramOutput {};
  bool receivedDatagram = false;
  for (size_t iteration = 0; iteration < 10'000 && !receivedDatagram; ++iteration)
  {
    size_t read = 0;
    const auto status = server->consumeDatagram(serverId, datagramOutput, nowRawNs, read, error);
    assert(status != PrimitiveStatus::fatal);
    receivedDatagram = status == PrimitiveStatus::ready;
    if (receivedDatagram) assert(read == datagram.size());
    else drive(*client, *server, clientAddress, serverAddress, nowRawNs);
  }
  assert(receivedDatagram);

  std::array<std::byte, 4096> ticket {};
  size_t ticketLength = 0;
  for (size_t iteration = 0; iteration < 10'000; ++iteration)
  {
    const auto status = client->exportResumptionState(
        clientId, nowRawNs, ticket, ticketLength, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::ready) break;
    drive(*client, *server, clientAddress, serverAddress, nowRawNs);
  }
  assert(ticketLength > 16);
  assert(client->importResumptionState(
      std::span<const std::byte>(ticket).first(ticketLength), false, nowRawNs, error) ==
      PrimitiveStatus::ready);
  uint64_t resumedClientId = 0;
  assert(client->connect(serverAddress, nowRawNs, resumedClientId, error));
  const auto establishedTreatmentWithPendingAdmission =
      client->snapshotNegotiatedSettings();
  assert(establishedTreatmentWithPendingAdmission.available);
  assert(establishedTreatmentWithPendingAdmission.unavailableFields.empty());
  const uint64_t resumedServerId = waitAcceptedConnection(
      *server, *client, clientAddress, serverAddress, nowRawNs);
  waitConnected(*client, *server, resumedClientId, resumedServerId,
                clientAddress, serverAddress, nowRawNs);
  bool resumed = false;
  assert(client->connectionResumed(resumedClientId, nowRawNs, resumed, error));
  assert(resumed);

  ticketLength = 0;
  for (size_t iteration = 0; iteration < 10'000; ++iteration)
  {
    const auto status = client->exportResumptionState(
        resumedClientId, nowRawNs, ticket, ticketLength, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::ready) break;
    drive(*client, *server, clientAddress, serverAddress, nowRawNs);
  }
  assert(ticketLength > 16);
  assert(client->importResumptionState(
      std::span<const std::byte>(ticket).first(ticketLength), true, nowRawNs, error) ==
      PrimitiveStatus::ready);
  uint64_t earlyClientId = 0;
  assert(client->connect(serverAddress, nowRawNs, earlyClientId, error));
  assert(client->importResumptionState(
      std::span<const std::byte>(ticket).first(ticketLength), false, nowRawNs, error) ==
      PrimitiveStatus::fatal);
  error = {};
  const uint64_t earlyStream = openStream(*client, true, earlyClientId, nowRawNs);
  const std::array<std::byte, 64> earlyRequest {};
  size_t earlyWritten = 0;
  assert(client->writeStream(earlyClientId, earlyStream, earlyRequest, nowRawNs,
                             earlyWritten, error));
  assert(earlyWritten == earlyRequest.size());
  assert(client->finishStream(earlyClientId, earlyStream, nowRawNs, error));
  const uint64_t earlyServerId = waitAcceptedConnection(
      *server, *client, clientAddress, serverAddress, nowRawNs);
  waitConnected(*client, *server, earlyClientId, earlyServerId,
                clientAddress, serverAddress, nowRawNs);
  bool earlyAttempted = false;
  bool earlyAccepted = false;
  bool earlyRejected = false;
  assert(client->zeroRttAttempted(earlyClientId, nowRawNs, earlyAttempted, error));
  assert(client->zeroRttAccepted(earlyClientId, nowRawNs, earlyAccepted, error));
  assert(client->zeroRttRejected(earlyClientId, nowRawNs, earlyRejected, error));
  assert(earlyAttempted && earlyAccepted && !earlyRejected);
  const uint64_t acceptedEarlyStream = waitAcceptedStream(
      *server, *client, true, earlyServerId, clientAddress, serverAddress, nowRawNs);
  assert(acceptedEarlyStream == earlyStream);
  std::array<std::byte, 64> earlyOutput {};
  size_t earlyRead = 0;
  bool earlyFinished = false;
  assert(server->consumeStreamData(earlyServerId, acceptedEarlyStream, earlyOutput,
                                   nowRawNs, earlyRead, earlyFinished, error));
  assert(earlyRead == earlyRequest.size() && earlyFinished);

  const auto lifecycleStream = [&]() {
    const uint64_t stream = openStream(*client, true, resumedClientId, nowRawNs);
    const std::array<std::byte, 1> proof {};
    size_t proofWritten = 0;
    assert(client->writeStream(resumedClientId, stream, proof, nowRawNs,
                               proofWritten, error));
    assert(proofWritten == proof.size());
    const uint64_t peerStream = waitAcceptedStream(
        *server, *client, true, resumedServerId, clientAddress, serverAddress,
        nowRawNs);
    assert(peerStream == stream);
    return stream;
  };
  const auto waitTerminal = [&](uint64_t stream, auto predicate) {
    for (size_t iteration = 0; iteration < 10'000; ++iteration)
    {
      quicperf::PeerTerminalFacts facts;
      assert(client->peerTerminalFacts(
          resumedClientId, stream, nowRawNs, facts, error));
      assert(facts.available);
      if (predicate(facts)) return;
      drive(*client, *server, clientAddress, serverAddress, nowRawNs);
    }
    assert(false && "ngtcp2 peer terminal fact was not observed");
  };

  const uint64_t resetStream = lifecycleStream();
  assert(server->resetStream(resumedServerId, resetStream, 7, nowRawNs, error));
  waitTerminal(resetStream, [](const auto& facts) {
    return facts.resetStream && facts.resetStreamError == 7;
  });

  const uint64_t stoppedStream = lifecycleStream();
  assert(server->stopSending(resumedServerId, stoppedStream, 8, nowRawNs, error));
  waitTerminal(stoppedStream, [](const auto& facts) {
    return facts.stopSending && facts.stopSendingError == 8;
  });

  const uint64_t closeStream = lifecycleStream();
  assert(server->closeConnection(resumedServerId, 9, nowRawNs, error));
  waitTerminal(closeStream, [](const auto& facts) {
    return facts.connectionClose;
  });

  const uint64_t saturatedDataStream = openStream(*client, true, clientId, nowRawNs);
  const std::array<std::byte, 64 * 1024> saturatedData {};
  size_t saturatedBytes = 0;
  for (size_t iteration = 0; iteration < 8; ++iteration)
  {
    size_t accepted = 0;
    assert(client->writeStream(clientId, saturatedDataStream, saturatedData,
                               nowRawNs, accepted, error));
    saturatedBytes += accepted;
    if (accepted == 0) break;
  }
  assert(saturatedBytes > 0);
  const std::array<std::byte, 128> stopControl {};
  controlWritten = 0;
  assert(client->writeStream(clientId, controlStream, stopControl, nowRawNs,
                             controlWritten, error));
  assert(controlWritten == stopControl.size());

  const auto counters = client->snapshotTransportCounters();
  assert(counters.packetsSent > 0);
  assert(counters.packetsReceived > 0);
  assert(directoryEntries("/proc/self/fd") == initialFds);
  assert(directoryEntries("/proc/self/task") == initialThreads);
  assert(client->stop(error));
  assert(server->stop(error));
  assert(client->snapshotTransportCounters().packetsSent == 0);
  assert(client->configure(config(false), error));
  assert(client->setLocalAddress(clientAddress, error));
  assert(client->reset(error));
  assert(client->snapshotTransportCounters().packetsReceived == 0);
}
