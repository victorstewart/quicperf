#pragma once

#include "control_fields.h"

#include <cstdint>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace quicperf::control {

constexpr uint32_t magic = 0x51504332U;
constexpr uint16_t protocolVersion = 1;
constexpr size_t maximumPacketSize = 65'536;

using Bytes = std::vector<uint8_t>;
using Value = std::variant<uint64_t, int64_t, std::string, Bytes, bool>;

struct Tlv {
  Field field;
  WireType wire;
  Value value;
};

struct Packet {
  MessageType type;
  uint32_t flags;
  uint64_t sequence;
  std::vector<Tlv> fields;
};

struct DecodeResult {
  Packet packet {};
  std::string error;
  explicit operator bool() const noexcept { return error.empty(); }
};

std::vector<uint8_t> encode(const Packet& packet);
DecodeResult decode(std::span<const uint8_t> bytes, uint64_t expectedSequence);
const Tlv* find(const Packet& packet, Field field) noexcept;

} // namespace quicperf::control
