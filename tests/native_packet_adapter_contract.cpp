#include "adapters/adapter_factory.h"
#include "core/measurement.h"
#include "core/runtime_ownership.h"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>

#ifndef EXPECT_EARLY_DATA
#define EXPECT_EARLY_DATA 1
#endif

#ifndef EXPECT_NEGOTIATED_EVIDENCE
#define EXPECT_NEGOTIATED_EVIDENCE 0
#endif

#ifndef EXPECT_PENDING_ADMISSION_EVIDENCE
#define EXPECT_PENDING_ADMISSION_EVIDENCE 0
#endif

#ifndef EXPECT_SUCCESSOR_TICKET
#define EXPECT_SUCCESSOR_TICKET EXPECT_EARLY_DATA
#endif

#ifndef EXPECT_ONE_USE_TICKET_ENFORCEMENT
#define EXPECT_ONE_USE_TICKET_ENFORCEMENT 0
#endif

#ifndef EXPECT_EFFECTIVE_EARLY_DATA_CAP
#define EXPECT_EFFECTIVE_EARLY_DATA_CAP 0
#endif

#ifndef EXPECT_UNIDIRECTIONAL_STREAMS
#define EXPECT_UNIDIRECTIONAL_STREAMS 1
#endif

#ifndef EXPECT_PEER_TERMINAL_FACTS
#define EXPECT_PEER_TERMINAL_FACTS 0
#endif

#ifndef EXPECT_RECOVERY_WAKEUP_COUNTER
#define EXPECT_RECOVERY_WAKEUP_COUNTER 0
#endif

#ifndef EXPECT_PRE_READY_FILE_FDS
#define EXPECT_PRE_READY_FILE_FDS 0
#endif

#ifndef EXPECT_CONNECTION_ADMISSION_LIMIT
#define EXPECT_CONNECTION_ADMISSION_LIMIT 0
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

std::map<int, std::filesystem::path> persistentFileDescriptors()
{
  std::map<int, std::filesystem::path> result;
  for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd"))
  {
    std::error_code error;
    const auto target = std::filesystem::read_symlink(entry.path(), error);
    if (error || target.native().starts_with("/proc/")) continue;
    const auto status = std::filesystem::status(entry.path(), error);
    if (error) continue;
    const int descriptor = std::stoi(entry.path().filename().string());
    if (std::filesystem::is_regular_file(status)) result.emplace(descriptor, target);
  }
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
  return
      "{\"ack_delay_exponent\":3,\"ack_frequency\":false,"
      "\"active_connection_id_limit\":2,\"active_migration\":false,"
      "\"active_streams_per_connection\":0,\"alpn\":\"qperf/2\",\"backend\":\"syscall\","
      "\"bind_address\":\"127.0.0.1\",\"bind_port\":0,"
      "\"bulk_chunk_bytes\":0,\"busy_polling\":false,"
      "\"calendar_unix_seconds\":1784376000,"
      "\"certificate_path\":\"" + root + "/tls/server.cert.pem\","
      "\"chain_path\":\"" + root + "/tls/chain.cert.pem\","
      "\"common_pacing\":true,\"congestion_controller\":\"cubic\","
      "\"connection_count\":3,\"connection_id_bytes\":8,\"connection_window\":67108864,"
      "\"datagram_body_bytes\":64,\"datagram_max_frame_size\":1200,"
      "\"datagram_max_unreturned_per_connection\":128,"
      "\"ecn\":false,\"event_loop_workers\":" + std::to_string(server ? 1 : 2) + ","
      "\"global_operation_slots\":2048,\"idle_timeout_ms\":30000,"
      "\"initial_congestion_window_bytes\":13500,\"max_ack_delay_ns\":25000000,"
      "\"max_bidi_streams\":256,\"max_udp_payload_size\":1350,"
      "\"max_uni_streams\":256,\"measurement_duration_ns\":2000000000,"
      "\"operation_body_bytes\":0,\"path_profile\":\"loopback\",\"peer_address\":\"" +
      (server ? "0.0.0.0" : "127.0.0.1") + "\",\"peer_port\":" +
      std::to_string(server ? 0 : 4433) + ",\"pmtud\":false,"
      "\"private_key_path\":\"" + root + "/tls/server.key.pem\","
      "\"progress_interval_ns\":200000000,\"quic_version\":\"0x00000001\","
      "\"receive_timestamps\":false,"
      "\"request_body_bytes\":0,\"require_multishot_receive\":false,"
      "\"response_body_bytes\":0,\"role\":\"" + (server ? "server" : "client") + "\","
      "\"scenario\":\"datagram\",\"schema_version\":2,"
      "\"stream_credit_replenish_below\":32,\"stream_window\":67108864,\"ticket_slots\":0,"
      "\"tls_cipher_suite\":\"TLS_AES_128_GCM_SHA256\","
      "\"tls_hostname\":\"server.quicperf.test\",\"tls_key_exchange\":\"X25519\","
      "\"tls_leaf_signature\":\"Ed25519\",\"tls_maximum_early_data_bytes\":4096,"
      "\"tls_one_use_tickets\":true,\"tls_ticket_lifetime_ns\":300000000000,"
      "\"tls_verify_peer\":" +
      (server ? "false" : "true") + ",\"tls_version\":\"TLSv1.3\","
      "\"trace_seed\":\"0000000000000000000000000000000000000000000000000000000000000000\","
      "\"udp_gro\":true,\"udp_gso\":true,"
      "\"warmup_duration_ns\":250000000}";
}

size_t transfer(Adapter& source, Adapter& destination, const sockaddr_in& sourceAddress,
                uint64_t& nowRawNs)
{
  std::array<TransmitPacket, 64> transmitted {};
  AdapterError error;
  size_t count = 0;
  {
    quicperf::AdapterRuntimeScope sendScope(nowRawNs);
    count = source.pollTransmitBatch(transmitted, nowRawNs, error);
  }
  if (!error.message.empty())
  {
    std::cerr << "transmit: " << error.message << '\n';
    std::abort();
  }
  if (!count) return 0;

  nowRawNs += 1'000;
  quicperf::AdapterRuntimeScope receiveScope(nowRawNs);
  std::array<ReceivedPacket, 64> received {};
  for (size_t index = 0; index < count; ++index)
  {
    assert(!transmitted[index].bytes.empty());
    received[index] = {transmitted[index].bytes, sourceAddress, transmitted[index].ecn,
                       transmitted[index].gsoSegmentSize, nowRawNs};
  }
  if (!destination.receiveBatch(
      std::span<const ReceivedPacket>(received).first(count), nowRawNs, error))
  {
    std::cerr << "receive: " << error.message << '\n';
    std::abort();
  }
  return count;
}

void drive(Adapter& client, Adapter& server, const sockaddr_in& clientAddress,
           const sockaddr_in& serverAddress, uint64_t& nowRawNs)
{
  transfer(client, server, clientAddress, nowRawNs);
  transfer(server, client, serverAddress, nowRawNs);
  AdapterError error;
  const uint64_t clientExpiry = client.nextTimeoutRawNs();
  if (clientExpiry && clientExpiry <= nowRawNs) assert(client.onTimeout(nowRawNs, error));
  const uint64_t serverExpiry = server.nextTimeoutRawNs();
  if (serverExpiry && serverExpiry <= nowRawNs) assert(server.onTimeout(nowRawNs, error));
  nowRawNs += 1'000'000;
  quicperf::AdapterRuntimeScope updateRuntimeClock(nowRawNs);
}

uint64_t waitAcceptedConnection(Adapter& server, Adapter& client,
                                const sockaddr_in& clientAddress,
                                const sockaddr_in& serverAddress, uint64_t clientId,
                                uint64_t& nowRawNs)
{
  AdapterError error;
  for (size_t iteration = 0; iteration < 20'000; ++iteration)
  {
    uint64_t id = 0;
    const auto status = server.acceptConnection(nowRawNs, id, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::ready) return id;
    drive(client, server, clientAddress, serverAddress, nowRawNs);
    bool connected = false;
    if (!client.isConnected(clientId, nowRawNs, connected, error))
    {
      std::cerr << "client failed before server acceptance: " << error.message << '\n';
      std::abort();
    }
  }
  assert(false && "server did not accept the connection");
  return 0;
}

void waitConnected(Adapter& client, Adapter& server, uint64_t clientId, uint64_t serverId,
                   const sockaddr_in& clientAddress, const sockaddr_in& serverAddress,
                   uint64_t& nowRawNs)
{
  AdapterError error;
  for (size_t iteration = 0; iteration < 20'000; ++iteration)
  {
    bool clientReady = false;
    bool serverReady = false;
    const bool clientOk = client.isConnected(clientId, nowRawNs, clientReady, error);
    const std::string clientError = error.message;
    error = {};
    const bool serverOk = server.isConnected(serverId, nowRawNs, serverReady, error);
    if (!clientOk || !serverOk)
    {
      if (!clientOk) std::cerr << "client connection state: " << clientError << '\n';
      if (!serverOk) std::cerr << "server connection state: " << error.message << '\n';
      std::abort();
    }
    if (clientReady && serverReady) return;
    drive(client, server, clientAddress, serverAddress, nowRawNs);
  }
  assert(false && "handshake did not complete");
}

uint64_t waitAcceptedStream(Adapter& receiver, Adapter& sender, bool bidi,
                            uint64_t receiverConnectionId,
                            const sockaddr_in& senderAddress,
                            const sockaddr_in& receiverAddress, uint64_t& nowRawNs)
{
  AdapterError error;
  for (size_t iteration = 0; iteration < 20'000; ++iteration)
  {
    uint64_t streamId = 0;
    const auto status = bidi ?
        receiver.acceptBidirectionalStream(receiverConnectionId, nowRawNs, streamId, error) :
        receiver.acceptUnidirectionalStream(receiverConnectionId, nowRawNs, streamId, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::ready) return streamId;
    drive(sender, receiver, senderAddress, receiverAddress, nowRawNs);
  }
  const auto senderCounters = sender.snapshotTransportCounters();
  const auto receiverCounters = receiver.snapshotTransportCounters();
  std::cerr << "peer stream did not become readable: sender_packets="
            << senderCounters.packetsSent << '/' << senderCounters.packetsReceived
            << " receiver_packets=" << receiverCounters.packetsSent << '/'
            << receiverCounters.packetsReceived << " next_timeout="
            << sender.nextTimeoutRawNs() << " now=" << nowRawNs
            << " error=" << error.message << '\n';
  assert(false && "peer stream did not become readable");
  return 0;
}

void verifyStream(Adapter& sender, Adapter& receiver, bool bidi,
                  uint64_t senderConnectionId, uint64_t receiverConnectionId,
                  const sockaddr_in& senderAddress, const sockaddr_in& receiverAddress,
                  uint64_t& nowRawNs, std::string_view payload)
{
  AdapterError error;
  uint64_t streamId = 0;
  const auto opened = bidi ?
      sender.openBidirectionalStream(senderConnectionId, nowRawNs, streamId, error) :
      sender.openUnidirectionalStream(senderConnectionId, nowRawNs, streamId, error);
  assert(opened == PrimitiveStatus::ready);
  const auto input = std::as_bytes(std::span(payload));
  size_t totalWritten = 0;
  for (size_t iteration = 0; totalWritten < input.size() && iteration < 20'000; ++iteration)
  {
    size_t written = 0;
    assert(sender.writeStream(senderConnectionId, streamId,
                              input.subspan(totalWritten), nowRawNs,
                              written, error));
    totalWritten += written;
    if (!written)
      drive(sender, receiver, senderAddress, receiverAddress, nowRawNs);
  }
  assert(totalWritten == input.size());
  assert(sender.finishStream(senderConnectionId, streamId, nowRawNs, error));
  const uint64_t peerStream = waitAcceptedStream(
      receiver, sender, bidi, receiverConnectionId, senderAddress, receiverAddress, nowRawNs);
  assert(peerStream == streamId);
  std::array<std::byte, 128> output {};
  size_t total = 0;
  for (size_t iteration = 0; iteration < 20'000; ++iteration)
  {
    size_t read = 0;
    bool finished = false;
    assert(receiver.consumeStreamData(receiverConnectionId, peerStream,
                                      std::span(output).subspan(total), nowRawNs,
                                      read, finished, error));
    total += read;
    if (finished)
    {
      assert(total == input.size());
      assert(std::equal(output.begin(), output.begin() + total, input.begin()));
      return;
    }
    drive(sender, receiver, senderAddress, receiverAddress, nowRawNs);
  }
  assert(false && "stream did not finish");
}

void verifyExpiredTicket(Adapter& adapter, std::span<const std::byte> state,
                         uint64_t nowRawNs)
{
  const pid_t child = fork();
  assert(child >= 0);
  if (child == 0)
  {
    AdapterError error;
    const auto result = adapter.importResumptionState(
        state, false, nowRawNs + 300'000'000'000ULL, error);
    _exit(result == PrimitiveStatus::fatal && error.code != 0 &&
              !error.message.empty() ? 0 : 1);
  }
  int status = 0;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

} // namespace

int main()
{
  const size_t initialFds = directoryEntries("/proc/self/fd");
  const auto initialFileDescriptors = persistentFileDescriptors();
  const size_t initialThreads = directoryEntries("/proc/self/task");
  auto client = quicperf::makeTransportAdapter();
  auto server = quicperf::makeTransportAdapter();
  assert(client->capabilities().library == EXPECTED_LIBRARY);
  assert(client->capabilities().server && client->capabilities().client);
  assert(client->capabilities().datagram);
  assert(client->capabilities().resumption);
  assert(client->capabilities().earlyData == static_cast<bool>(EXPECT_EARLY_DATA));
  assert(std::find(client->capabilities().scenarios.begin(),
                   client->capabilities().scenarios.end(),
                   quicperf::workload::Scenario::datagram) !=
         client->capabilities().scenarios.end());
  assert(std::find(client->capabilities().scenarios.begin(),
                   client->capabilities().scenarios.end(),
                   quicperf::workload::Scenario::memoryCurve) !=
         client->capabilities().scenarios.end());

  AdapterError error;
  assert(client->configure(config(false), error));
  assert(server->configure(config(true), error));
  const sockaddr_in clientAddress = address("127.0.0.1", 40000);
  const sockaddr_in serverAddress = address("127.0.0.1", 4433);
  assert(client->setLocalAddress(clientAddress, error));
  if (!server->setLocalAddress(serverAddress, error))
  {
    std::cerr << "server adapter initialization failed: " << error.message << '\n';
    return 2;
  }
  const size_t readyFds = directoryEntries("/proc/self/fd");
#if EXPECT_PRE_READY_FILE_FDS
  assert(readyFds >= initialFds);
  const auto readyFileDescriptors = persistentFileDescriptors();
  size_t addedDatabaseFiles = 0;
  for (const auto& [descriptor, target] : readyFileDescriptors)
  {
    if (initialFileDescriptors.contains(descriptor) &&
        initialFileDescriptors.at(descriptor) == target) continue;
    const auto parent = target.parent_path().filename().string();
    assert(parent.starts_with("quicperf-neqo-nss-"));
    assert(target.extension() == ".db");
    ++addedDatabaseFiles;
  }
  assert(addedDatabaseFiles > 0);
#else
  assert(readyFds == initialFds);
#endif
  assert(directoryEntries("/proc/self/task") == initialThreads);

  uint64_t nowRawNs = quicperf::monotonicRawNowNs();
  const auto bridge = quicperf::ClockBridge::sample();
  quicperf::setRuntimeCalendarUnixSeconds(1'784'376'000);
  quicperf::setRuntimeClockAnchor(
      nowRawNs, quicperf::ClockBridge(bridge).monotonicDeadline(nowRawNs));
  quicperf::AdapterRuntimeScope runtimeScope(nowRawNs);
  uint64_t clientId = 0;
  assert(client->connect(serverAddress, nowRawNs, clientId, error));
  const uint64_t serverId = waitAcceptedConnection(
      *server, *client, clientAddress, serverAddress, clientId, nowRawNs);
  waitConnected(*client, *server, clientId, serverId,
                clientAddress, serverAddress, nowRawNs);

#if EXPECT_NEGOTIATED_EVIDENCE
  const auto negotiated = client->snapshotNegotiatedSettings();
  assert(negotiated.available && !negotiated.evidenceSource.empty());
  assert(negotiated.unavailableFields.empty());
  assert(negotiated.alpn == "qperf/2");
  assert(negotiated.quicVersion == 1);
  assert(negotiated.tlsVersion == "TLSv1.3");
  assert(negotiated.tlsCipherSuite == "TLS_AES_128_GCM_SHA256");
  assert(negotiated.tlsKeyExchange == "X25519");
  assert(negotiated.tlsLeafSignature == "Ed25519");
  assert(negotiated.peerCertificateVerified && negotiated.hostnameVerified);
  assert(negotiated.congestionController == "cubic");
  assert(negotiated.initialCongestionWindowBytes == 13'500);
  assert(negotiated.maxUdpPayloadSize == 1350);
  assert(negotiated.maxAckDelayNs == 25'000'000);
  assert(negotiated.ackDelayExponent == 3 && !negotiated.ackFrequency);
  assert(!negotiated.activeMigration && negotiated.activeConnectionIdLimit == 2);
  assert(negotiated.connectionIdBytes == 8);
  assert(negotiated.maxIdleTimeoutNs == 30'000'000'000);
  assert(negotiated.maxBidiStreams == 256 && negotiated.maxUniStreams == 256);
  assert(negotiated.connectionWindowBytes == 67'108'864);
  assert(negotiated.streamWindowBytes == 67'108'864);
  assert(negotiated.streamCreditReplenishBelow == 32);
  assert(negotiated.datagramMaxFrameSize == 1200);
  assert(negotiated.ticketLifetimeNs == 300'000'000'000);
  assert(negotiated.maximumEarlyDataBytes == 4'096);
  assert(negotiated.oneUseTickets);
#endif

  verifyStream(*client, *server, true, clientId, serverId,
               clientAddress, serverAddress, nowRawNs, "bidirectional");
  verifyStream(*server, *client, true, serverId, clientId,
               serverAddress, clientAddress, nowRawNs, "server bidirectional");
#if EXPECT_UNIDIRECTIONAL_STREAMS
  verifyStream(*client, *server, false, clientId, serverId,
               clientAddress, serverAddress, nowRawNs, "unidirectional");
#endif

  const std::array<std::byte, 64> datagram {};
  assert(client->sendDatagram(clientId, datagram, nowRawNs, error) == PrimitiveStatus::ready);
  std::array<std::byte, 128> datagramOutput {};
  bool datagramReceived = false;
  for (size_t iteration = 0; iteration < 20'000 && !datagramReceived; ++iteration)
  {
    size_t read = 0;
    const auto status = server->consumeDatagram(
        serverId, datagramOutput, nowRawNs, read, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::ready)
    {
      assert(read == datagram.size());
      datagramReceived = true;
    }
    else drive(*client, *server, clientAddress, serverAddress, nowRawNs);
  }
  assert(datagramReceived);

  std::array<std::byte, 16 * 1024> session {};
  size_t sessionLength = 0;
  for (size_t iteration = 0; iteration < 20'000 && !sessionLength; ++iteration)
  {
    const auto status = client->exportResumptionState(
        clientId, nowRawNs, session, sessionLength, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::wouldBlock)
      drive(*client, *server, clientAddress, serverAddress, nowRawNs);
  }
  assert(sessionLength > 0);
#if EXPECT_ONE_USE_TICKET_ENFORCEMENT
  verifyExpiredTicket(
      *client, std::span<const std::byte>(session).first(sessionLength), nowRawNs);
#endif
  assert(client->importResumptionState(
      std::span<const std::byte>(session).first(sessionLength), false, nowRawNs, error) ==
      PrimitiveStatus::ready);
  uint64_t resumedClientId = 0;
  assert(client->connect(serverAddress, nowRawNs, resumedClientId, error));
#if EXPECT_PENDING_ADMISSION_EVIDENCE
  const auto establishedTreatmentWithPendingAdmission =
      client->snapshotNegotiatedSettings();
  assert(establishedTreatmentWithPendingAdmission.available);
  assert(establishedTreatmentWithPendingAdmission.unavailableFields.empty());
#endif
  const uint64_t resumedServerId = waitAcceptedConnection(
      *server, *client, clientAddress, serverAddress, resumedClientId, nowRawNs);
  waitConnected(*client, *server, resumedClientId, resumedServerId,
                clientAddress, serverAddress, nowRawNs);
  bool resumed = false;
  assert(client->connectionResumed(resumedClientId, nowRawNs, resumed, error));
  assert(resumed);

#if EXPECT_ONE_USE_TICKET_ENFORCEMENT
  AdapterError reusedTicketError;
  assert(client->importResumptionState(
      std::span<const std::byte>(session).first(sessionLength), false, nowRawNs,
      reusedTicketError) == PrimitiveStatus::fatal);
  assert(reusedTicketError.code != 0 && !reusedTicketError.message.empty());
#endif

  uint64_t creditClientId = resumedClientId;
#if EXPECT_SUCCESSOR_TICKET
  sessionLength = 0;
  for (size_t iteration = 0; iteration < 20'000 && !sessionLength; ++iteration)
  {
    const auto status = client->exportResumptionState(
        resumedClientId, nowRawNs, session, sessionLength, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::wouldBlock)
      drive(*client, *server, clientAddress, serverAddress, nowRawNs);
  }
  assert(sessionLength > 0);
#endif
#if EXPECT_EARLY_DATA
  assert(client->importResumptionState(
      std::span<const std::byte>(session).first(sessionLength), true, nowRawNs, error) ==
      PrimitiveStatus::ready);
  uint64_t earlyClientId = 0;
  assert(client->connect(serverAddress, nowRawNs, earlyClientId, error));
  uint64_t earlyStream = 0;
  assert(client->openBidirectionalStream(earlyClientId, nowRawNs, earlyStream, error) ==
         PrimitiveStatus::ready);
#if EXPECT_EFFECTIVE_EARLY_DATA_CAP
  const std::array<std::byte, 4'097> earlyRequest {};
#else
  const std::array<std::byte, 32> earlyRequest {};
#endif
  size_t earlyWritten = 0;
  assert(client->writeStream(earlyClientId, earlyStream, earlyRequest, nowRawNs,
                             earlyWritten, error));
#if EXPECT_EFFECTIVE_EARLY_DATA_CAP
  assert(earlyWritten == 4'096);
  size_t excessWritten = 0;
  assert(client->writeStream(
      earlyClientId, earlyStream, std::span<const std::byte>(earlyRequest).last(1),
      nowRawNs, excessWritten, error));
  assert(excessWritten == 0);
#else
  assert(earlyWritten == earlyRequest.size());
#endif
  assert(client->finishStream(earlyClientId, earlyStream, nowRawNs, error));
  const uint64_t earlyServerId = waitAcceptedConnection(
      *server, *client, clientAddress, serverAddress, earlyClientId, nowRawNs);
  waitConnected(*client, *server, earlyClientId, earlyServerId,
                clientAddress, serverAddress, nowRawNs);
  bool earlyAttempted = false;
  bool earlyAccepted = false;
  bool earlyRejected = false;
  assert(client->zeroRttAttempted(earlyClientId, nowRawNs, earlyAttempted, error));
  assert(client->zeroRttAccepted(earlyClientId, nowRawNs, earlyAccepted, error));
  assert(client->zeroRttRejected(earlyClientId, nowRawNs, earlyRejected, error));
  if (!earlyAttempted || !earlyAccepted || earlyRejected)
    std::cerr << EXPECTED_LIBRARY << " early-data state attempted=" << earlyAttempted
              << " accepted=" << earlyAccepted << " rejected=" << earlyRejected << '\n';
  assert(earlyAttempted && earlyAccepted && !earlyRejected);
  const uint64_t acceptedEarlyStream = waitAcceptedStream(
      *server, *client, true, earlyServerId, clientAddress, serverAddress, nowRawNs);
  assert(acceptedEarlyStream == earlyStream);
  std::array<std::byte,
#if EXPECT_EFFECTIVE_EARLY_DATA_CAP
             4'096
#else
             32
#endif
             > earlyOutput {};
  size_t earlyRead = 0;
  bool earlyFinished = false;
  for (size_t iteration = 0; iteration < 20'000 && !earlyFinished; ++iteration)
  {
    size_t read = 0;
    assert(server->consumeStreamData(
        earlyServerId, acceptedEarlyStream,
        std::span<std::byte>(earlyOutput).subspan(earlyRead),
        nowRawNs, read, earlyFinished, error));
    earlyRead += read;
    if (!earlyFinished) drive(*client, *server, clientAddress, serverAddress, nowRawNs);
  }
  if (earlyRead != earlyOutput.size() || !earlyFinished)
    std::cerr << EXPECTED_LIBRARY << " early-data delivery bytes=" << earlyRead
              << " finished=" << earlyFinished << '\n';
  assert(earlyRead == earlyOutput.size() && earlyFinished);
  creditClientId = earlyClientId;
#endif

#if EXPECT_CONNECTION_ADMISSION_LIMIT
  uint64_t excessClientId = 0;
  assert(client->connect(serverAddress, nowRawNs, excessClientId, error));
  bool excessAccepted = false;
  for (size_t iteration = 0; iteration < 1'000; ++iteration)
  {
    drive(*client, *server, clientAddress, serverAddress, nowRawNs);
    uint64_t excessServerId = 0;
    const auto status =
        server->acceptConnection(nowRawNs, excessServerId, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::ready)
    {
      excessAccepted = true;
      break;
    }
  }
  assert(!excessAccepted);
#endif

  size_t reservedStreams = 0;
  bool streamCreditBlocked = false;
  for (; reservedStreams < 1'024; ++reservedStreams)
  {
    uint64_t reservedStream = 0;
    const auto status = client->openBidirectionalStream(
        creditClientId, nowRawNs, reservedStream, error);
    assert(status != PrimitiveStatus::fatal);
    if (status == PrimitiveStatus::wouldBlock)
    {
      streamCreditBlocked = true;
      break;
    }
  }
  assert(reservedStreams > 0 && streamCreditBlocked);

  const uint64_t controlClientId = resumedClientId;
  const uint64_t controlServerId = resumedServerId;

#if EXPECT_RECOVERY_WAKEUP_COUNTER
  const auto countersBeforeLoss = client->snapshotTransportCounters();
  uint64_t lossStream = 0;
  const auto lossOpen =
      client->openBidirectionalStream(controlClientId, nowRawNs, lossStream, error);
  if (lossOpen != PrimitiveStatus::ready)
    std::cerr << EXPECTED_LIBRARY << " loss stream open failed status="
              << static_cast<int>(lossOpen) << " error=" << error.message << '\n';
  assert(lossOpen == PrimitiveStatus::ready);
  const std::array<std::byte, 4096> lossPayload {};
  size_t lossWritten = 0;
  assert(client->writeStream(controlClientId, lossStream, lossPayload, nowRawNs,
                             lossWritten, error));
  assert(lossWritten == lossPayload.size());
  assert(client->finishStream(controlClientId, lossStream, nowRawNs, error));
  bool observedRecoveryWakeup = false;
  for (size_t iteration = 0; iteration < 20'000 && !observedRecoveryWakeup; ++iteration)
  {
    std::array<TransmitPacket, 64> dropped {};
    const size_t droppedCount = client->pollTransmitBatch(dropped, nowRawNs, error);
    assert(error.message.empty());
    if (droppedCount == 0)
      transfer(*server, *client, serverAddress, nowRawNs);
    const uint64_t expiry = client->nextTimeoutRawNs();
    if (expiry > nowRawNs) nowRawNs = expiry;
    if (expiry && expiry <= nowRawNs) assert(client->onTimeout(nowRawNs, error));
    const auto counters = client->snapshotTransportCounters();
    assert(counters.packetsLost >= countersBeforeLoss.packetsLost);
    assert(counters.recoveryWakeups >= countersBeforeLoss.recoveryWakeups);
    observedRecoveryWakeup = counters.recoveryWakeups > countersBeforeLoss.recoveryWakeups;
    ++nowRawNs;
  }
  assert(observedRecoveryWakeup);
  const uint64_t recoveredStream = waitAcceptedStream(
      *server, *client, true, controlServerId,
      clientAddress, serverAddress, nowRawNs);
  assert(recoveredStream == lossStream);
  std::array<std::byte, 4096> recoveredPayload {};
  size_t recoveredBytes = 0;
  bool recoveredFin = false;
  for (size_t iteration = 0; iteration < 20'000 && !recoveredFin; ++iteration)
  {
    size_t read = 0;
    assert(server->consumeStreamData(
        controlServerId, recoveredStream,
        std::span(recoveredPayload).subspan(recoveredBytes),
        nowRawNs, read, recoveredFin, error));
    recoveredBytes += read;
    if (!recoveredFin)
      drive(*client, *server, clientAddress, serverAddress, nowRawNs);
  }
  assert(recoveredFin && recoveredBytes == lossPayload.size());
#endif

  const std::array<std::byte, 1> proof {};
#if EXPECT_PEER_TERMINAL_FACTS
  const auto openProofStream = [&] {
    uint64_t streamId = 0;
    assert(client->openBidirectionalStream(controlClientId, nowRawNs, streamId, error) ==
           PrimitiveStatus::ready);
    size_t written = 0;
    assert(client->writeStream(
        controlClientId, streamId, proof, nowRawNs, written, error));
    assert(written == proof.size());
    const uint64_t peerStream = waitAcceptedStream(
        *server, *client, true, controlServerId,
        clientAddress, serverAddress, nowRawNs);
    assert(peerStream == streamId);
    std::array<std::byte, 1> received {};
    size_t read = 0;
    bool finished = false;
    for (size_t iteration = 0; iteration < 20'000 && read != proof.size(); ++iteration)
    {
      size_t count = 0;
      assert(server->consumeStreamData(controlServerId, peerStream,
                                       std::span(received).subspan(read), nowRawNs,
                                       count, finished, error));
      read += count;
      if (read != proof.size())
        drive(*client, *server, clientAddress, serverAddress, nowRawNs);
    }
    assert(read == proof.size());
    written = 0;
    assert(server->writeStream(
        controlServerId, peerStream, proof, nowRawNs, written, error));
    assert(written == proof.size());
    read = 0;
    finished = false;
    for (size_t iteration = 0; iteration < 20'000 && read != proof.size(); ++iteration)
    {
      size_t count = 0;
      assert(client->consumeStreamData(controlClientId, streamId,
                                       std::span(received).subspan(read), nowRawNs,
                                       count, finished, error));
      read += count;
      if (read != proof.size())
        drive(*client, *server, clientAddress, serverAddress, nowRawNs);
    }
    assert(read == proof.size());
    return streamId;
  };
  const auto waitTerminal = [&](std::string_view terminal, Adapter& observer,
                                uint64_t connectionId, uint64_t streamId, auto matches) {
    quicperf::PeerTerminalFacts last;
    for (size_t iteration = 0; iteration < 20'000; ++iteration)
    {
      quicperf::PeerTerminalFacts facts;
      assert(observer.peerTerminalFacts(
          connectionId, streamId, nowRawNs, facts, error));
      assert(facts.available);
      if (matches(facts)) return;
      last = facts;
      drive(*client, *server, clientAddress, serverAddress, nowRawNs);
    }
    std::cerr << "terminal fact missing kind=" << terminal
              << " fin=" << last.fin << " reset=" << last.resetStream
              << " reset_error=" << last.resetStreamError
              << " stop=" << last.stopSending
              << " stop_error=" << last.stopSendingError
              << " close=" << last.connectionClose
              << " close_error=" << last.connectionCloseError
              << " close_reason_length=" << last.connectionCloseReasonLength << '\n';
    assert(false && "peer terminal fact was not observed");
  };

  const uint64_t finStream = openProofStream();
  assert(server->finishStream(controlServerId, finStream, nowRawNs, error));
  waitTerminal("fin", *client, controlClientId, finStream,
               [](const auto& facts) { return facts.fin; });

  const uint64_t resetStream = openProofStream();
  assert(server->resetStream(controlServerId, resetStream, 0x5150, nowRawNs, error));
  waitTerminal("reset", *client, controlClientId, resetStream, [](const auto& facts) {
    return facts.resetStream && facts.resetStreamError == 0x5150;
  });

  const uint64_t stoppedStream = openProofStream();
  assert(server->stopSending(controlServerId, stoppedStream, 0x5150, nowRawNs, error));
  waitTerminal("stop_sending", *client, controlClientId, stoppedStream, [](const auto& facts) {
    return facts.stopSending && facts.stopSendingError == 0x5150;
  });

  const uint64_t closeStream = openProofStream();
  assert(server->closeConnection(controlServerId, 0x5150, nowRawNs, error));
  waitTerminal("connection_close", *client, controlClientId, closeStream,
               [](const auto& facts) {
                 return facts.connectionClose && facts.connectionCloseError == 0x5150 &&
                     facts.connectionCloseReasonLength == 0;
               });
#else
  uint64_t lifecycleStream = 0;
  assert(client->openBidirectionalStream(clientId, nowRawNs, lifecycleStream, error) ==
         PrimitiveStatus::ready);
  size_t proofWritten = 0;
  assert(client->writeStream(clientId, lifecycleStream, proof, nowRawNs,
                             proofWritten, error));
  const uint64_t peerLifecycleStream = waitAcceptedStream(
      *server, *client, true, serverId, clientAddress, serverAddress, nowRawNs);
  assert(peerLifecycleStream == lifecycleStream);
  assert(client->resetStream(clientId, lifecycleStream, 7, nowRawNs, error));
  assert(server->stopSending(serverId, peerLifecycleStream, 8, nowRawNs, error));
  assert(client->closeConnection(clientId, 9, nowRawNs, error));
  drive(*client, *server, clientAddress, serverAddress, nowRawNs);
#endif

  const auto counters = client->snapshotTransportCounters();
  assert(counters.packetsSent > 0);
  assert(counters.packetsReceived > 0);
  assert(directoryEntries("/proc/self/fd") == readyFds);
  assert(directoryEntries("/proc/self/task") == initialThreads);
  assert(client->stop(error));
  assert(server->stop(error));
  assert(client->snapshotTransportCounters().packetsSent == 0);
}
