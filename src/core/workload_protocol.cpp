#include "workload_protocol.h"

#include <limits>
#include <stdexcept>

namespace quicperf::workload {
namespace {

void put16(std::span<uint8_t> bytes, size_t& offset, uint16_t value)
{
  bytes[offset++] = static_cast<uint8_t>(value >> 8);
  bytes[offset++] = static_cast<uint8_t>(value);
}

void put32(std::span<uint8_t> bytes, size_t& offset, uint32_t value)
{
  for (int shift = 24; shift >= 0; shift -= 8) bytes[offset++] = static_cast<uint8_t>(value >> shift);
}

void put64(std::span<uint8_t> bytes, size_t& offset, uint64_t value)
{
  for (int shift = 56; shift >= 0; shift -= 8) bytes[offset++] = static_cast<uint8_t>(value >> shift);
}

bool get16(std::span<const uint8_t> bytes, size_t& offset, uint16_t& value)
{
  if (bytes.size() - offset < 2) return false;
  value = static_cast<uint16_t>((uint16_t {bytes[offset]} << 8) | bytes[offset + 1]);
  offset += 2;
  return true;
}

bool get32(std::span<const uint8_t> bytes, size_t& offset, uint32_t& value)
{
  if (bytes.size() - offset < 4) return false;
  value = 0;
  for (unsigned i = 0; i < 4; ++i) value = (value << 8) | bytes[offset + i];
  offset += 4;
  return true;
}

bool get64(std::span<const uint8_t> bytes, size_t& offset, uint64_t& value)
{
  if (bytes.size() - offset < 8) return false;
  value = 0;
  for (unsigned i = 0; i < 8; ++i) value = (value << 8) | bytes[offset + i];
  offset += 8;
  return true;
}

bool validType(uint16_t value)
{
  return value >= static_cast<uint16_t>(Type::hello) &&
      value <= static_cast<uint16_t>(Type::terminalReady);
}
bool validScenario(uint16_t value)
{
  return value >= static_cast<uint16_t>(Scenario::download) &&
      value <= static_cast<uint16_t>(Scenario::memoryCurve);
}

} // namespace

std::array<uint8_t, headerSize> encodeHeader(const Header& header)
{
  if (!validType(static_cast<uint16_t>(header.type)) || !validScenario(static_cast<uint16_t>(header.scenario)) ||
      (header.flags & ~allowedFlags) != 0 || header.sequence == 0)
  {
    throw std::invalid_argument("invalid QPF2 header");
  }
  std::array<uint8_t, headerSize> bytes {};
  size_t offset = 0;
  put32(bytes, offset, magic);
  put16(bytes, offset, version);
  put16(bytes, offset, static_cast<uint16_t>(header.type));
  put16(bytes, offset, static_cast<uint16_t>(header.scenario));
  put16(bytes, offset, header.flags);
  put64(bytes, offset, header.trialNonce);
  put64(bytes, offset, header.sequence);
  put64(bytes, offset, header.payloadLength);
  return bytes;
}

ParseResult decodeHeader(std::span<const uint8_t> bytes)
{
  if (bytes.size() != headerSize) return {{}, "QPF2 header must be exactly 36 bytes"};
  size_t offset = 0;
  uint32_t gotMagic = 0;
  uint16_t gotVersion = 0;
  uint16_t rawType = 0;
  uint16_t rawScenario = 0;
  Header header {};
  if (!get32(bytes, offset, gotMagic) || !get16(bytes, offset, gotVersion) ||
      !get16(bytes, offset, rawType) || !get16(bytes, offset, rawScenario) ||
      !get16(bytes, offset, header.flags) || !get64(bytes, offset, header.trialNonce) ||
      !get64(bytes, offset, header.sequence) || !get64(bytes, offset, header.payloadLength))
  {
    return {{}, "truncated QPF2 header"};
  }
  if (gotMagic != magic || gotVersion != version || !validType(rawType) || !validScenario(rawScenario) ||
      (header.flags & ~allowedFlags) != 0 || header.sequence == 0)
  {
    return {{}, "invalid QPF2 identity, enum, flags, or sequence"};
  }
  header.type = static_cast<Type>(rawType);
  header.scenario = static_cast<Scenario>(rawScenario);
  return {header, {}};
}

uint8_t deterministicPayloadByte(uint64_t trialNonce, uint64_t sequence, uint64_t offset) noexcept
{
  constexpr uint64_t multiplier = 1'315'423'911ULL;
  return static_cast<uint8_t>((trialNonce + sequence * multiplier + offset) % 251ULL);
}

bool validatePayload(std::span<const uint8_t> payload, uint64_t trialNonce, uint64_t sequence, uint64_t offset) noexcept
{
  constexpr uint64_t multiplier = 1'315'423'911ULL;
  uint64_t value = trialNonce + sequence * multiplier + offset;
  for (size_t index = 0; index < payload.size(); ++index)
  {
    if (payload[index] != static_cast<uint8_t>(value % 251ULL)) return false;
    ++value;
  }
  return true;
}

std::vector<uint8_t> makeDatagram(Scenario scenario, uint64_t trialNonce, uint64_t sequence)
{
  if (!validScenario(static_cast<uint16_t>(scenario)) || sequence == 0) throw std::invalid_argument("invalid QPF2 datagram identity");
  std::vector<uint8_t> bytes(24 + datagramBodySize);
  size_t offset = 0;
  put32(bytes, offset, magic);
  put16(bytes, offset, version);
  put16(bytes, offset, static_cast<uint16_t>(scenario));
  put64(bytes, offset, trialNonce);
  put64(bytes, offset, sequence);
  constexpr uint64_t multiplier = 1'315'423'911ULL;
  uint64_t value = trialNonce + sequence * multiplier;
  for (size_t index = 0; index < datagramBodySize; ++index)
  {
    bytes[offset + index] = static_cast<uint8_t>(value % 251ULL);
    ++value;
  }
  return bytes;
}

ParseResult validateDatagram(std::span<const uint8_t> datagram, Scenario scenario, uint64_t trialNonce, uint64_t expectedSequence)
{
  if (datagram.size() != 24 + datagramBodySize) return {{}, "QPF2 datagram length mismatch"};
  size_t offset = 0;
  uint32_t gotMagic = 0;
  uint16_t gotVersion = 0;
  uint16_t gotScenario = 0;
  uint64_t gotNonce = 0;
  uint64_t gotSequence = 0;
  get32(datagram, offset, gotMagic);
  get16(datagram, offset, gotVersion);
  get16(datagram, offset, gotScenario);
  get64(datagram, offset, gotNonce);
  get64(datagram, offset, gotSequence);
  if (gotMagic != magic || gotVersion != version || gotScenario != static_cast<uint16_t>(scenario) ||
      gotNonce != trialNonce || gotSequence != expectedSequence || expectedSequence == 0 ||
      !validatePayload(datagram.subspan(offset), trialNonce, expectedSequence))
  {
    return {{}, "invalid QPF2 datagram identity, sequence, or payload"};
  }
  return {{Type::op, scenario, 1U << 6, trialNonce, expectedSequence, datagramBodySize}, {}};
}

std::vector<uint8_t> makeSmallPayloadOperation(uint64_t trialNonce, uint64_t streamSequence,
                                               uint64_t connectionOrdinal,
                                               uint64_t startRawNs)
{
  if (trialNonce == 0 || streamSequence == 0 || startRawNs == 0)
    throw std::invalid_argument("invalid QPF2 small-payload operation identity");
  std::vector<uint8_t> bytes(smallPayloadBodySize);
  size_t offset = 0;
  put64(bytes, offset, connectionOrdinal);
  put64(bytes, offset, startRawNs);
  for (; offset < bytes.size(); ++offset)
    bytes[offset] = deterministicPayloadByte(trialNonce, streamSequence, offset);
  return bytes;
}

bool validateSmallPayloadOperation(std::span<const uint8_t> body, uint64_t trialNonce,
                                   uint64_t streamSequence, uint64_t& connectionOrdinal,
                                   uint64_t& startRawNs) noexcept
{
  if (body.size() != smallPayloadBodySize || trialNonce == 0 || streamSequence == 0) return false;
  size_t offset = 0;
  if (!get64(body, offset, connectionOrdinal) || !get64(body, offset, startRawNs) || startRawNs == 0)
    return false;
  return validatePayload(body.subspan(offset), trialNonce, streamSequence, offset);
}

} // namespace quicperf::workload
