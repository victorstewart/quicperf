#pragma once

#include "adapter_factory.h"

#include <utility>

namespace quicperf {

class DeclaredAdapter final : public Adapter {
public:
  explicit DeclaredAdapter(std::string library)
  {
    capabilities_.library = std::move(library);
    capabilities_.buildId = "packet-boundary-unavailable";
    capabilities_.adapterAbiVersion = 2;
    capabilities_.server = true;
    capabilities_.client = true;
    capabilities_.backends = {PacketBackend::syscall, PacketBackend::iouring};
    capabilities_.effectiveFeatures = {"common_cpp_packet_io", "publication_unavailable"};
  }

  const Capabilities& capabilities() const noexcept override { return capabilities_; }
  bool configure(std::string_view, AdapterError& error) override
  {
    error = {1, capabilities_.library + " has not exposed the required packet-driven adapter boundary"};
    return false;
  }
  bool setLocalAddress(const sockaddr_in&, AdapterError& error) override
  {
    return unavailable(error);
  }
  bool receiveBatch(std::span<const ReceivedPacket>, uint64_t, AdapterError& error) override
  {
    error = {1, "unconfigured adapter"};
    return false;
  }
  size_t pollTransmitBatch(std::span<TransmitPacket>, uint64_t, AdapterError& error) override
  {
    error = {1, "unconfigured adapter"};
    return 0;
  }
  uint64_t nextTimeoutRawNs() const noexcept override { return 0; }
  bool onTimeout(uint64_t, AdapterError& error) override
  {
    error = {1, "unconfigured adapter"};
    return false;
  }
  bool connect(const sockaddr_in&, uint64_t, uint64_t&, AdapterError& error) override
  {
    return unavailable(error);
  }
  PrimitiveStatus acceptConnection(uint64_t, uint64_t&, AdapterError& error) override
  {
    unavailable(error);
    return PrimitiveStatus::fatal;
  }
  bool isConnected(uint64_t, uint64_t, bool&, AdapterError& error) override
  {
    return unavailable(error);
  }
  PrimitiveStatus openBidirectionalStream(uint64_t, uint64_t, uint64_t&, AdapterError& error) override
  {
    unavailable(error);
    return PrimitiveStatus::fatal;
  }
  PrimitiveStatus acceptBidirectionalStream(uint64_t, uint64_t, uint64_t&, AdapterError& error) override
  {
    unavailable(error);
    return PrimitiveStatus::fatal;
  }
  PrimitiveStatus openUnidirectionalStream(uint64_t, uint64_t, uint64_t&, AdapterError& error) override
  {
    unavailable(error);
    return PrimitiveStatus::fatal;
  }
  PrimitiveStatus acceptUnidirectionalStream(uint64_t, uint64_t, uint64_t&, AdapterError& error) override
  {
    unavailable(error);
    return PrimitiveStatus::fatal;
  }
  bool writeStream(uint64_t, uint64_t, std::span<const std::byte>, uint64_t,
                   size_t&, AdapterError& error) override
  {
    return unavailable(error);
  }
  bool consumeStreamData(uint64_t, uint64_t, std::span<std::byte>, uint64_t,
                         size_t&, bool&, AdapterError& error) override
  {
    return unavailable(error);
  }
  bool finishStream(uint64_t, uint64_t, uint64_t, AdapterError& error) override
  {
    return unavailable(error);
  }
  bool resetStream(uint64_t, uint64_t, uint64_t, uint64_t, AdapterError& error) override
  {
    return unavailable(error);
  }
  bool stopSending(uint64_t, uint64_t, uint64_t, uint64_t, AdapterError& error) override
  {
    return unavailable(error);
  }
  PrimitiveStatus sendDatagram(uint64_t, std::span<const std::byte>, uint64_t,
                               AdapterError& error) override
  {
    unavailable(error);
    return PrimitiveStatus::fatal;
  }
  PrimitiveStatus consumeDatagram(uint64_t, std::span<std::byte>, uint64_t,
                                  size_t&, AdapterError& error) override
  {
    unavailable(error);
    return PrimitiveStatus::fatal;
  }
  PrimitiveStatus exportResumptionState(uint64_t, uint64_t, std::span<std::byte>,
                                        size_t&, AdapterError& error) override
  {
    unavailable(error);
    return PrimitiveStatus::fatal;
  }
  PrimitiveStatus importResumptionState(std::span<const std::byte>, bool, uint64_t,
                                        AdapterError& error) override
  {
    unavailable(error);
    return PrimitiveStatus::fatal;
  }
  bool connectionResumed(uint64_t, uint64_t, bool&, AdapterError& error) override
  {
    return unavailable(error);
  }
  bool zeroRttAttempted(uint64_t, uint64_t, bool&, AdapterError& error) override
  {
    return unavailable(error);
  }
  bool zeroRttAccepted(uint64_t, uint64_t, bool&, AdapterError& error) override
  {
    return unavailable(error);
  }
  bool zeroRttRejected(uint64_t, uint64_t, bool&, AdapterError& error) override
  {
    return unavailable(error);
  }
  bool closeConnection(uint64_t, uint64_t, uint64_t, AdapterError& error) override
  {
    return unavailable(error);
  }
  TransportCounters snapshotTransportCounters() const noexcept override { return {}; }
  bool reset(AdapterError&) override { return true; }
  bool stop(AdapterError&) override { return true; }

private:
  bool unavailable(AdapterError& error) const
  {
    error = {1, capabilities_.library + " packet-driven transport primitives are unavailable"};
    return false;
  }
  Capabilities capabilities_;
};

} // namespace quicperf
