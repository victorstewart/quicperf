#include "core/measurement.h"
#include "core/packet_io.h"
#include "core/packet_io_internal.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>

namespace {

void exercise(quicperf::PacketBackend backend)
{
  quicperf::PacketIoConfig config;
  config.udpGso = false;
  config.udpGro = false;
  auto receiver = quicperf::makePacketIoDriver(backend, config);
  auto sender = quicperf::makePacketIoDriver(backend, config);
  const uint32_t loopback = htonl(INADDR_LOOPBACK);
  const uint16_t receiverPort = receiver->bind(loopback, 0);
  sender->bind(loopback, 0);

  const std::array<std::byte, 4> body {std::byte {1}, std::byte {2}, std::byte {3}, std::byte {4}};
  sockaddr_in peer {};
  peer.sin_family = AF_INET;
  peer.sin_addr.s_addr = loopback;
  peer.sin_port = htons(receiverPort);
  const uint64_t now = quicperf::monotonicRawNowNs();
  const quicperf::TransmitPacket packet {body, peer, 0, 0, now};
  assert(sender->send(std::span<const quicperf::TransmitPacket>(&packet, 1), now) == 1);

  std::span<const quicperf::ReceivedPacket> received;
  for (unsigned attempt = 0; attempt < 20 && received.empty(); ++attempt)
  {
    receiver->wait(10);
    received = receiver->receive(quicperf::monotonicRawNowNs());
  }
  assert(received.size() == 1);
  assert(received[0].bytes.size() == body.size());
  assert(std::memcmp(received[0].bytes.data(), body.data(), body.size()) == 0);
  assert(sender->counters().packetsSent == 1);
  assert(receiver->counters().packetsReceived == 1);
}

void exerciseSegmentation(quicperf::PacketBackend backend)
{
  quicperf::PacketIoConfig config;
  auto receiver = quicperf::makePacketIoDriver(backend, config);
  auto sender = quicperf::makePacketIoDriver(backend, config);
  const uint32_t loopback = htonl(INADDR_LOOPBACK);
  const uint16_t receiverPort = receiver->bind(loopback, 0);
  sender->bind(loopback, 0);
  std::array<std::byte, quicperf::maxUdpPayloadSize * 2> body {};
  body.fill(std::byte {0x5a});
  sockaddr_in peer {};
  peer.sin_family = AF_INET;
  peer.sin_addr.s_addr = loopback;
  peer.sin_port = htons(receiverPort);
  const uint64_t now = quicperf::monotonicRawNowNs();
  const quicperf::TransmitPacket packet {body, peer, 0, quicperf::maxUdpPayloadSize, now};
  assert(sender->send(std::span<const quicperf::TransmitPacket>(&packet, 1), now) == 1);
  size_t segments = 0;
  for (unsigned attempt = 0; attempt < 20 && segments < 2; ++attempt)
  {
    receiver->wait(10);
    for (const auto& received : receiver->receive(quicperf::monotonicRawNowNs()))
    {
      assert(received.bytes.size() == quicperf::maxUdpPayloadSize);
      for (const std::byte byte : received.bytes) assert(byte == std::byte {0x5a});
      ++segments;
    }
  }
  assert(segments == 2);
  assert(sender->counters().udpDatagramsSent == 1);
  assert(sender->counters().gsoSegmentsSent == 2);
  assert(receiver->counters().packetsReceived == 2);
}

void exerciseLossSegmentation(quicperf::PacketBackend backend)
{
  quicperf::PacketIoConfig config;
  auto receiver = quicperf::makePacketIoDriver(backend, config);
  auto sender = quicperf::makePacketIoDriver(backend, config);
  const uint32_t loopback = htonl(INADDR_LOOPBACK);
  const uint16_t receiverPort = receiver->bind(loopback, 0);
  sender->bind(loopback, 0);
  std::array<std::byte, quicperf::maxUdpPayloadSize * 2> body {};
  std::fill_n(body.begin(), quicperf::maxUdpPayloadSize, std::byte {0x11});
  std::fill(body.begin() + quicperf::maxUdpPayloadSize, body.end(), std::byte {0x22});
  sockaddr_in peer {};
  peer.sin_family = AF_INET;
  peer.sin_addr.s_addr = loopback;
  peer.sin_port = htons(receiverPort);
  std::array<uint8_t, 32> seed {};
  seed.fill(10);
  const uint64_t now = quicperf::monotonicRawNowNs();
  sender->armLossRecovery(seed, now - 1, now + 1'000'000'000, 0);
  const quicperf::TransmitPacket packet {
      body, peer, 0, quicperf::maxUdpPayloadSize, now};
  assert(sender->send(std::span<const quicperf::TransmitPacket>(&packet, 1), now) == 1);
  std::span<const quicperf::ReceivedPacket> received;
  for (unsigned attempt = 0; attempt < 20 && received.empty(); ++attempt)
  {
    receiver->wait(10);
    received = receiver->receive(quicperf::monotonicRawNowNs());
  }
  assert(received.size() == 1);
  assert(received[0].bytes.size() == quicperf::maxUdpPayloadSize);
  for (const std::byte byte : received[0].bytes) assert(byte == std::byte {0x22});
  const auto& counters = sender->counters();
  assert(counters.lossPacketsConsidered == 2);
  assert(counters.lossPacketsDropped == 1);
  assert(counters.lossWarmupPacketsConsidered == 0);
  assert(counters.lossMeasurementPacketsConsidered == 2);
  assert(counters.lossMeasurementPacketsDropped == 1);
  assert(counters.gsoSegmentsSent == 1);
  assert(!sender->hasPendingTransmit());
  sender->resetLossRecovery();
}

void exerciseMultishotReceive()
{
  quicperf::PacketIoConfig receiveConfig;
  receiveConfig.udpGso = false;
  receiveConfig.udpGro = false;
  receiveConfig.requireMultishotReceive = true;
  quicperf::PacketIoConfig sendConfig = receiveConfig;
  sendConfig.requireMultishotReceive = false;
  auto receiver = quicperf::makePacketIoDriver(
      quicperf::PacketBackend::iouring, receiveConfig);
  auto sender = quicperf::makePacketIoDriver(
      quicperf::PacketBackend::syscall, sendConfig);
  const uint32_t loopback = htonl(INADDR_LOOPBACK);
  const uint16_t receiverPort = receiver->bind(loopback, 0);
  sender->bind(loopback, 0);
  const std::array<std::byte, 3> body {
      std::byte {0x71}, std::byte {0x70}, std::byte {0x66}};
  sockaddr_in peer {};
  peer.sin_family = AF_INET;
  peer.sin_addr.s_addr = loopback;
  peer.sin_port = htons(receiverPort);
  for (unsigned round = 0; round < 2; ++round)
  {
    const uint64_t now = quicperf::monotonicRawNowNs();
    const quicperf::TransmitPacket packet {body, peer, 0, 0, now};
    assert(sender->send(std::span<const quicperf::TransmitPacket>(&packet, 1), now) == 1);
    std::span<const quicperf::ReceivedPacket> received;
    for (unsigned attempt = 0; attempt < 20 && received.empty(); ++attempt)
    {
      receiver->wait(10);
      received = receiver->receive(quicperf::monotonicRawNowNs());
    }
    assert(received.size() == 1);
    assert(received[0].bytes.size() == body.size());
    assert(std::memcmp(received[0].bytes.data(), body.data(), body.size()) == 0);
  }
  assert(receiver->counters().packetsReceived == 2);
  assert(receiver->counters().receiveErrors == 0);
}

void exerciseMultishotGroBatchEquivalence()
{
  quicperf::PacketIoConfig receiveConfig;
  receiveConfig.requireMultishotReceive = true;
  auto receiver = quicperf::makePacketIoDriver(
      quicperf::PacketBackend::iouring, receiveConfig);
  const uint32_t loopback = htonl(INADDR_LOOPBACK);
  const uint16_t receiverPort = receiver->bind(loopback, 0);
  const std::array<std::byte, 1> body {std::byte {0x71}};
  sockaddr_in peer {};
  peer.sin_family = AF_INET;
  peer.sin_addr.s_addr = loopback;
  peer.sin_port = htons(receiverPort);
  std::array<int, 8> senders;
  for (int& sender : senders)
  {
    sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    assert(sender >= 0);
    assert(sendto(sender, body.data(), body.size(), 0,
                  reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) ==
           static_cast<ssize_t>(body.size()));
  }
  receiver->wait(10'000'000);
  const auto first = receiver->receive(quicperf::monotonicRawNowNs());
  assert(!first.empty());
  assert(receiver->counters().udpDatagramsReceived == 1);
  for (unsigned attempt = 0;
       attempt < 20 && receiver->counters().udpDatagramsReceived < senders.size();
       ++attempt)
  {
    receiver->wait(10'000'000);
    receiver->receive(quicperf::monotonicRawNowNs());
  }
  assert(receiver->counters().udpDatagramsReceived == senders.size());
  for (const int sender : senders) close(sender);
}

} // namespace

int main()
{
  assert(quicperf::restartableMultishotReceiveError(-ENOBUFS, true));
  assert(quicperf::restartableMultishotReceiveError(-ENOBUFS, false));
  assert(!quicperf::restartableMultishotReceiveError(-ECANCELED, true));
  assert(quicperf::restartableMultishotReceiveError(-ECANCELED, false));
  assert(!quicperf::restartableMultishotReceiveError(-EIO, false));
  {
    const quicperf::ClockBridge positive(
        quicperf::ClockBridgeSample {0, 0, 0, 123, 0});
    assert(positive.rawDeadline(1'000) == 1'123);
    assert(positive.monotonicDeadline(1'123) == 1'000);
    const quicperf::ClockBridge negative(
        quicperf::ClockBridgeSample {0, 0, 0, -123, 0});
    assert(negative.rawDeadline(1'000) == 877);
    assert(negative.monotonicDeadline(877) == 1'000);
    assert(quicperf::realtimeAtRaw(1'250, 1'000, 5'000) == 5'250);
    assert(quicperf::realtimeAtRaw(999, 1'000, 5'000) == 5'000);
    std::string reason;
    const quicperf::ClockBridge longLived(
        quicperf::ClockBridgeSample {1'000, 1'000, 1'000, 0, 0});
    assert(longLived.validateAfter(
        quicperf::ClockBridgeSample {
            16'000'001'000, 16'000'001'000, 16'000'001'000, 1'000'000, 0},
        500'000'000, reason));
    assert(!longLived.validateAfter(
        quicperf::ClockBridgeSample {999, 999, 999, 0, 0},
        500'000'000, reason));
    assert(reason == "clock_bridge_elapsed_time_regressed_or_short");
    assert(!longLived.validateAfter(
        quicperf::ClockBridgeSample {
            16'000'001'000, 16'000'001'000, 16'000'001'000, 9'000'000, 0},
        500'000'000, reason));
    assert(reason == "clock_bridge_drift_exceeds_limit");
  }
  exercise(quicperf::PacketBackend::syscall);
  exerciseSegmentation(quicperf::PacketBackend::syscall);
  exerciseLossSegmentation(quicperf::PacketBackend::syscall);
  std::array<uint8_t, 32> vectorSeed {};
  for (size_t index = 0; index < vectorSeed.size(); ++index)
    vectorSeed[index] = static_cast<uint8_t>(index);
  assert(!quicperf::lossRecoveryDrop(vectorSeed, false, 0, 151));
  assert(quicperf::lossRecoveryDrop(vectorSeed, false, 0, 152));
  assert(!quicperf::lossRecoveryDrop(vectorSeed, true, 1, 110));
  assert(quicperf::lossRecoveryDrop(vectorSeed, true, 1, 111));
  try
  {
    exercise(quicperf::PacketBackend::iouring);
    exerciseSegmentation(quicperf::PacketBackend::iouring);
    exerciseLossSegmentation(quicperf::PacketBackend::iouring);
    exerciseMultishotReceive();
    exerciseMultishotGroBatchEquivalence();
  }
  catch (const std::exception& error)
  {
    std::cerr << "io_uring unavailable: " << error.what() << '\n';
    return 77;
  }
}
