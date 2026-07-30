#include "control_protocol.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <unordered_set>

namespace quicperf::control {
namespace {

void append16(std::vector<uint8_t>& out, uint16_t value)
{
  out.push_back(static_cast<uint8_t>(value >> 8));
  out.push_back(static_cast<uint8_t>(value));
}

void append32(std::vector<uint8_t>& out, uint32_t value)
{
  for (int shift = 24; shift >= 0; shift -= 8)
  {
    out.push_back(static_cast<uint8_t>(value >> shift));
  }
}

void append64(std::vector<uint8_t>& out, uint64_t value)
{
  for (int shift = 56; shift >= 0; shift -= 8)
  {
    out.push_back(static_cast<uint8_t>(value >> shift));
  }
}

bool take16(std::span<const uint8_t> in, size_t& offset, uint16_t& value)
{
  if (in.size() - offset < 2)
  {
    return false;
  }
  value = static_cast<uint16_t>((uint16_t {in[offset]} << 8) | in[offset + 1]);
  offset += 2;
  return true;
}

bool take32(std::span<const uint8_t> in, size_t& offset, uint32_t& value)
{
  if (in.size() - offset < 4)
  {
    return false;
  }
  value = 0;
  for (unsigned i = 0; i < 4; ++i)
  {
    value = (value << 8) | in[offset + i];
  }
  offset += 4;
  return true;
}

bool take64(std::span<const uint8_t> in, size_t& offset, uint64_t& value)
{
  if (in.size() - offset < 8)
  {
    return false;
  }
  value = 0;
  for (unsigned i = 0; i < 8; ++i)
  {
    value = (value << 8) | in[offset + i];
  }
  offset += 8;
  return true;
}

WireType expectedWire(Field field)
{
  switch (field)
  {
    case Field::controlVersion:
    case Field::protocolVersion:
    case Field::udpPort:
    case Field::pid:
    case Field::rawNowNs:
    case Field::warmupStartRawNs:
    case Field::measurementStartRawNs:
    case Field::measurementEndRawNs:
    case Field::traceEpochRawNs:
    case Field::eventIndex:
    case Field::validatedUnits:
    case Field::errorCode:
    case Field::liveConnections:
    case Field::liveStreams:
    case Field::liveTickets:
    case Field::workInventory:
    case Field::exerciseDeadlineRawNs:
      return WireType::u64;
    case Field::role:
    case Field::library:
    case Field::roles:
    case Field::backends:
    case Field::scenarios:
    case Field::capabilities:
    case Field::effectiveFeatures:
    case Field::configJson:
    case Field::backend:
    case Field::countersJson:
    case Field::resultJson:
    case Field::reason:
      return WireType::utf8;
    case Field::buildId:
    case Field::trialId:
    case Field::cellId:
      return WireType::bytes;
    case Field::blocked:
      return WireType::boolean;
  }
  throw std::invalid_argument("unknown control field");
}

std::vector<Field> requiredFields(MessageType type)
{
  using enum Field;
  switch (type)
  {
    case MessageType::hello: return {role, buildId, controlVersion};
    case MessageType::capabilities: return {library, buildId, protocolVersion, roles, backends, scenarios, capabilities, effectiveFeatures};
    case MessageType::config: return {trialId, cellId, configJson};
    case MessageType::bound: return {trialId, udpPort};
    case MessageType::ready: return {trialId, pid, backend, rawNowNs};
    case MessageType::arm: return {trialId, warmupStartRawNs, measurementStartRawNs, measurementEndRawNs, traceEpochRawNs};
    case MessageType::armed:
    case MessageType::measurementStarted:
    case MessageType::measurementStopped: return {trialId, rawNowNs};
    case MessageType::progress: return {trialId, eventIndex, rawNowNs, validatedUnits, blocked};
    case MessageType::completionAck: return {trialId, countersJson};
    case MessageType::result: return {trialId, resultJson};
    case MessageType::unsupported: return {trialId, reason};
    case MessageType::error: return {errorCode, reason};
    case MessageType::reset: return {trialId};
    case MessageType::resetAck:
      return {trialId, liveConnections, liveStreams, liveTickets, workInventory};
    case MessageType::exercise: return {trialId, exerciseDeadlineRawNs};
    case MessageType::exercised:
      return {trialId, liveConnections, liveStreams, liveTickets, workInventory};
    case MessageType::armRejected:
      return {trialId, rawNowNs, reason};
    case MessageType::shutdown:
    case MessageType::shutdownAck: return {};
  }
  throw std::invalid_argument("unknown control message");
}

bool isKnownMessage(uint16_t value)
{
  return value >= static_cast<uint16_t>(MessageType::hello) &&
         value <= static_cast<uint16_t>(MessageType::armRejected);
}

bool isKnownField(uint16_t value)
{
  return value >= static_cast<uint16_t>(Field::role) &&
         value <= static_cast<uint16_t>(Field::exerciseDeadlineRawNs);
}

} // namespace

std::vector<uint8_t> encode(const Packet& packet)
{
  if (packet.sequence == 0)
  {
    throw std::invalid_argument("control sequence starts at one");
  }
  auto required = requiredFields(packet.type);
  std::unordered_set<uint16_t> seen;
  std::vector<uint8_t> payload;
  auto fields = packet.fields;
  std::ranges::sort(fields, {}, [](const Tlv& field) { return static_cast<uint16_t>(field.field); });
  for (const auto& tlv : fields)
  {
    const uint16_t id = static_cast<uint16_t>(tlv.field);
    if (!seen.insert(id).second || expectedWire(tlv.field) != tlv.wire)
    {
      throw std::invalid_argument("duplicate field or wire mismatch");
    }
    std::vector<uint8_t> value;
    switch (tlv.wire)
    {
      case WireType::u64: append64(value, std::get<uint64_t>(tlv.value)); break;
      case WireType::i64: append64(value, static_cast<uint64_t>(std::get<int64_t>(tlv.value))); break;
      case WireType::utf8: {
        const auto& text = std::get<std::string>(tlv.value);
        if (text.empty() || text.find('\0') != std::string::npos)
        {
          throw std::invalid_argument("invalid UTF-8 control text");
        }
        value.assign(text.begin(), text.end());
        break;
      }
      case WireType::bytes: value = std::get<Bytes>(tlv.value); break;
      case WireType::boolean: value.push_back(std::get<bool>(tlv.value) ? 1 : 0); break;
    }
    append16(payload, id);
    payload.push_back(static_cast<uint8_t>(tlv.wire));
    payload.push_back(0);
    append32(payload, static_cast<uint32_t>(value.size()));
    payload.insert(payload.end(), value.begin(), value.end());
  }
  for (Field requiredField : required)
  {
    if (!seen.contains(static_cast<uint16_t>(requiredField)))
    {
      throw std::invalid_argument("missing required control field");
    }
  }
  if (payload.size() + 24 > maximumPacketSize)
  {
    throw std::invalid_argument("control packet exceeds 64 KiB");
  }
  std::vector<uint8_t> out;
  out.reserve(payload.size() + 24);
  append32(out, magic);
  append16(out, protocolVersion);
  append16(out, static_cast<uint16_t>(packet.type));
  append32(out, static_cast<uint32_t>(payload.size()));
  append32(out, packet.flags);
  append64(out, packet.sequence);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

DecodeResult decode(std::span<const uint8_t> bytes, uint64_t expectedSequence)
{
  auto fail = [](std::string error) { return DecodeResult {{}, std::move(error)}; };
  if (bytes.size() < 24 || bytes.size() > maximumPacketSize)
  {
    return fail("invalid control packet size");
  }
  size_t offset = 0;
  uint32_t gotMagic = 0;
  uint16_t version = 0;
  uint16_t rawType = 0;
  uint32_t length = 0;
  uint32_t flags = 0;
  uint64_t sequence = 0;
  if (!take32(bytes, offset, gotMagic) || !take16(bytes, offset, version) ||
      !take16(bytes, offset, rawType) || !take32(bytes, offset, length) ||
      !take32(bytes, offset, flags) || !take64(bytes, offset, sequence))
  {
    return fail("truncated control header");
  }
  if (gotMagic != magic || version != protocolVersion || !isKnownMessage(rawType))
  {
    return fail("bad control header identity");
  }
  if (length != bytes.size() - offset || sequence == 0 || sequence != expectedSequence)
  {
    return fail("payload length or sequence mismatch");
  }
  Packet packet {static_cast<MessageType>(rawType), flags, sequence, {}};
  std::unordered_set<uint16_t> seen;
  while (offset < bytes.size())
  {
    uint16_t id = 0;
    uint32_t valueLength = 0;
    if (!take16(bytes, offset, id) || bytes.size() - offset < 2)
    {
      return fail("truncated TLV header");
    }
    const auto wire = static_cast<WireType>(bytes[offset++]);
    const uint8_t reserved = bytes[offset++];
    if (!take32(bytes, offset, valueLength) || reserved != 0 || valueLength > bytes.size() - offset)
    {
      return fail("invalid TLV length or reserved byte");
    }
    if (!seen.insert(id).second)
    {
      return fail("duplicate TLV field");
    }
    auto value = bytes.subspan(offset, valueLength);
    offset += valueLength;
    if (!isKnownField(id))
    {
      if ((id & 0x8000U) != 0)
      {
        continue;
      }
      return fail("unknown required TLV field");
    }
    const auto field = static_cast<Field>(id);
    if (expectedWire(field) != wire)
    {
      return fail("TLV wire mismatch");
    }
    Value decoded;
    switch (wire)
    {
      case WireType::u64: {
        size_t inner = 0;
        uint64_t number = 0;
        if (value.size() != 8 || !take64(value, inner, number)) return fail("invalid u64 TLV");
        decoded = number;
        break;
      }
      case WireType::i64: {
        size_t inner = 0;
        uint64_t number = 0;
        if (value.size() != 8 || !take64(value, inner, number)) return fail("invalid i64 TLV");
        decoded = static_cast<int64_t>(number);
        break;
      }
      case WireType::utf8: {
        std::string text(value.begin(), value.end());
        if (text.empty() || text.find('\0') != std::string::npos) return fail("invalid text TLV");
        decoded = std::move(text);
        break;
      }
      case WireType::bytes: decoded = Bytes(value.begin(), value.end()); break;
      case WireType::boolean:
        if (value.size() != 1 || value[0] > 1) return fail("invalid boolean TLV");
        decoded = value[0] == 1;
        break;
      default: return fail("unknown wire type");
    }
    packet.fields.push_back({field, wire, std::move(decoded)});
  }
  const auto required = requiredFields(packet.type);
  for (Field field : required)
  {
    if (!seen.contains(static_cast<uint16_t>(field)))
    {
      return fail("missing required TLV field");
    }
  }
  const auto trial = find(packet, Field::trialId);
  const auto cell = find(packet, Field::cellId);
  if ((trial && std::get<Bytes>(trial->value).size() != 32) ||
      (cell && std::get<Bytes>(cell->value).size() != 32))
  {
    return fail("identity fields must be 32 bytes");
  }
  return {std::move(packet), {}};
}

const Tlv* find(const Packet& packet, Field field) noexcept
{
  const auto found = std::ranges::find(packet.fields, field, &Tlv::field);
  return found == packet.fields.end() ? nullptr : &*found;
}

} // namespace quicperf::control
