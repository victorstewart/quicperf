#include "core/workload_engine.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <set>
#include <span>
#include <stdexcept>
#include <vector>

namespace {

using quicperf::Adapter;
using quicperf::AdapterError;
using quicperf::Capabilities;
using quicperf::EndpointConfig;
using quicperf::EndpointRole;
using quicperf::NegotiatedSettings;
using quicperf::PeerTerminalFacts;
using quicperf::PrimitiveStatus;
using quicperf::ReceivedPacket;
using quicperf::TransmitPacket;
using quicperf::TransportCounters;

struct Direction {
  std::map<uint64_t, std::deque<std::byte>> ready;
  std::map<uint64_t, std::deque<std::byte>> delayed;
  std::set<uint64_t> finished;
  std::set<uint64_t> delayedFinished;
  std::deque<uint64_t> acceptedStreams;
};

struct Link {
  Direction toClient;
  Direction toServer;
  std::vector<uint8_t> clientControl;
  std::vector<uint8_t> serverControl;
  uint64_t nextStream = 0;
  bool serverConnectionPending = false;
  bool delayServerApplication = true;
};

class MemoryAdapter final : public Adapter {
public:
  MemoryAdapter(Link& link, bool client) : link_(link), client_(client) {}

  const Capabilities& capabilities() const noexcept override
  {
    static const Capabilities value;
    return value;
  }

  bool configure(std::string_view, AdapterError& error) override
  {
    error = {};
    return true;
  }

  bool setLocalAddress(const sockaddr_in&, AdapterError& error) override
  {
    error = {};
    return true;
  }

  bool receiveBatch(std::span<const ReceivedPacket>, uint64_t,
                    AdapterError& error) override
  {
    error = {};
    return true;
  }

  size_t pollTransmitBatch(std::span<TransmitPacket>, uint64_t,
                           AdapterError& error) override
  {
    error = {};
    return 0;
  }

  uint64_t nextTimeoutRawNs() const noexcept override
  {
    return std::numeric_limits<uint64_t>::max();
  }

  bool onTimeout(uint64_t, AdapterError& error) override
  {
    error = {};
    return true;
  }

  bool connect(const sockaddr_in&, uint64_t, uint64_t& connectionId,
               AdapterError& error) override
  {
    connectionId = 1;
    link_.serverConnectionPending = true;
    error = {};
    return true;
  }

  PrimitiveStatus acceptConnection(uint64_t, uint64_t& connectionId,
                                   AdapterError& error) override
  {
    error = {};
    if (client_ || !link_.serverConnectionPending)
      return PrimitiveStatus::wouldBlock;
    link_.serverConnectionPending = false;
    connectionId = 1;
    return PrimitiveStatus::ready;
  }

  bool isConnected(uint64_t, uint64_t, bool& connected,
                   AdapterError& error) override
  {
    connected = true;
    error = {};
    return true;
  }

  PrimitiveStatus openBidirectionalStream(uint64_t, uint64_t,
                                          uint64_t& streamId,
                                          AdapterError& error) override
  {
    streamId = link_.nextStream++;
    outgoing().acceptedStreams.push_back(streamId);
    error = {};
    return PrimitiveStatus::ready;
  }

  PrimitiveStatus acceptBidirectionalStream(uint64_t, uint64_t,
                                            uint64_t& streamId,
                                            AdapterError& error) override
  {
    auto& streams = incoming().acceptedStreams;
    error = {};
    if (streams.empty()) return PrimitiveStatus::wouldBlock;
    streamId = streams.front();
    streams.pop_front();
    return PrimitiveStatus::ready;
  }

  PrimitiveStatus openUnidirectionalStream(uint64_t, uint64_t, uint64_t&,
                                           AdapterError& error) override
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }

  PrimitiveStatus acceptUnidirectionalStream(uint64_t, uint64_t, uint64_t&,
                                             AdapterError& error) override
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }

  bool writeStream(uint64_t, uint64_t streamId, std::span<const std::byte> bytes,
                   uint64_t, size_t& written, AdapterError& error) override
  {
    const bool delayed = !client_ && streamId != 0 &&
        link_.delayServerApplication;
    auto& destination = delayed ? outgoing().delayed[streamId] :
                                  outgoing().ready[streamId];
    destination.insert(destination.end(), bytes.begin(), bytes.end());
    if (streamId == 0)
    {
      auto& transcript = client_ ? link_.clientControl : link_.serverControl;
      for (const std::byte byte : bytes)
        transcript.push_back(std::to_integer<uint8_t>(byte));
    }
    written = bytes.size();
    error = {};
    return true;
  }

  bool consumeStreamData(uint64_t, uint64_t streamId, std::span<std::byte> bytes,
                         uint64_t, size_t& read, bool& finished,
                         AdapterError& error) override
  {
    auto& direction = incoming();
    auto& source = direction.ready[streamId];
    read = std::min(bytes.size(), source.size());
    for (size_t index = 0; index < read; ++index)
    {
      bytes[index] = source.front();
      source.pop_front();
    }
    finished = source.empty() && direction.finished.contains(streamId);
    error = {};
    return true;
  }

  bool finishStream(uint64_t, uint64_t streamId, uint64_t,
                    AdapterError& error) override
  {
    if (!client_ && streamId != 0 && link_.delayServerApplication)
      outgoing().delayedFinished.insert(streamId);
    else
      outgoing().finished.insert(streamId);
    error = {};
    return true;
  }

  bool resetStream(uint64_t, uint64_t streamId, uint64_t, uint64_t,
                   AdapterError& error) override
  {
    outgoing().finished.insert(streamId);
    error = {};
    return true;
  }

  bool stopSending(uint64_t, uint64_t, uint64_t, uint64_t,
                   AdapterError& error) override
  {
    error = {};
    return true;
  }

  PrimitiveStatus sendDatagram(uint64_t, std::span<const std::byte>, uint64_t,
                               AdapterError& error) override
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }

  PrimitiveStatus consumeDatagram(uint64_t, std::span<std::byte>, uint64_t,
                                  size_t& read, AdapterError& error) override
  {
    read = 0;
    error = {};
    return PrimitiveStatus::wouldBlock;
  }

  PrimitiveStatus exportResumptionState(uint64_t, uint64_t,
                                        std::span<std::byte>, size_t& written,
                                        AdapterError& error) override
  {
    written = 0;
    error = {};
    return PrimitiveStatus::wouldBlock;
  }

  PrimitiveStatus importResumptionState(std::span<const std::byte>, bool,
                                        uint64_t, AdapterError& error) override
  {
    error = {};
    return PrimitiveStatus::wouldBlock;
  }

  bool connectionResumed(uint64_t, uint64_t, bool& resumed,
                         AdapterError& error) override
  {
    resumed = false;
    error = {};
    return true;
  }

  bool zeroRttAttempted(uint64_t, uint64_t, bool& attempted,
                       AdapterError& error) override
  {
    attempted = false;
    error = {};
    return true;
  }

  bool zeroRttAccepted(uint64_t, uint64_t, bool& accepted,
                      AdapterError& error) override
  {
    accepted = false;
    error = {};
    return true;
  }

  bool zeroRttRejected(uint64_t, uint64_t, bool& rejected,
                      AdapterError& error) override
  {
    rejected = false;
    error = {};
    return true;
  }

  bool closeConnection(uint64_t, uint64_t, uint64_t,
                       AdapterError& error) override
  {
    error = {};
    return true;
  }

  TransportCounters snapshotTransportCounters() const noexcept override
  {
    return {};
  }

  NegotiatedSettings snapshotNegotiatedSettings() const noexcept override
  {
    return {};
  }

  bool reset(AdapterError& error) override
  {
    error = {};
    return true;
  }

  bool stop(AdapterError& error) override
  {
    error = {};
    return true;
  }

private:
  Direction& outgoing()
  {
    return client_ ? link_.toServer : link_.toClient;
  }

  Direction& incoming()
  {
    return client_ ? link_.toClient : link_.toServer;
  }

  Link& link_;
  bool client_;
};

EndpointConfig config(EndpointRole role)
{
  EndpointConfig value;
  value.role = role;
  value.peerAddress = "127.0.0.1";
  value.peerPort = 4433;
  value.scenario = "download";
  value.connectionCount = 1;
  value.activeStreamsPerConnection = 1;
  value.bulkChunkBytes = 1;
  value.requestBodyBytes = 0;
  value.connectionWindow = 1 << 20;
  value.streamWindow = 1 << 20;
  value.progressIntervalNs = 10;
  return value;
}

uint64_t stopFrameCount(std::span<const uint8_t> bytes)
{
  size_t offset = 0;
  while (offset <= bytes.size() &&
         bytes.size() - offset >= quicperf::workload::headerSize)
  {
    const auto decoded = quicperf::workload::decodeHeader(
        bytes.subspan(offset, quicperf::workload::headerSize));
    if (!decoded) throw std::runtime_error(decoded.error);
    offset += quicperf::workload::headerSize;
    if (decoded.header.payloadLength > bytes.size() - offset)
      throw std::runtime_error("partial control-stream frame");
    if (decoded.header.type == quicperf::workload::Type::stop)
    {
      if (decoded.header.payloadLength != 64)
        throw std::runtime_error("invalid STOP body");
      uint64_t value = 0;
      for (size_t index = 8; index < 16; ++index)
        value = (value << 8) | bytes[offset + index];
      return value;
    }
    offset += static_cast<size_t>(decoded.header.payloadLength);
  }
  throw std::runtime_error("STOP absent from control transcript");
}

bool pump(quicperf::workload::Runtime& client,
          quicperf::workload::Runtime& server, uint64_t now,
          AdapterError& error)
{
  return client.pump(now, error) && server.pump(now, error);
}

} // namespace

int main()
{
  using quicperf::MeasurementWindow;
  using quicperf::workload::Runtime;

  Link link;
  MemoryAdapter clientAdapter(link, true);
  MemoryAdapter serverAdapter(link, false);
  const MeasurementWindow window {1'000, 2'000, 4'000, 1'000};
  std::array<uint8_t, 32> trial {};
  std::array<uint8_t, 32> cell {};
  trial[0] = 1;
  cell[0] = 2;
  Runtime client(clientAdapter, config(EndpointRole::client), window,
                 trial, cell, 0, 1);
  Runtime server(serverAdapter, config(EndpointRole::server), window,
                 trial, cell, 0, 1);
  AdapterError error;
  if (!client.start(1'000, error) || !server.start(1'000, error)) return 1;
  for (unsigned iteration = 0; iteration < 80; ++iteration)
    if (!pump(client, server, 2'500, error)) return 2;

  if (!client.stopAdmission(4'000, error) ||
      !server.stopAdmission(4'000, error)) return 3;
  for (unsigned iteration = 0;
       iteration < 200 &&
       (!client.completionReconciled() || !server.completionReconciled());
       ++iteration)
    if (!pump(client, server, 4'000, error)) return 4;

  const auto beforeRelease = client.snapshot();
  if (beforeRelease.stopReceived != 1 ||
      beforeRelease.stopAcknowledged != 1 ||
      beforeRelease.stopAckSent != 1 ||
      !client.completionReconciled() || !server.completionReconciled())
    return 5;
  if (stopFrameCount(link.clientControl) != 2) return 6;
  if (stopFrameCount(link.serverControl) <= 1) return 7;
  if (link.toClient.delayed.empty()) return 8;
  return 0;
}
