#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace quicperf::workload {

constexpr uint32_t magic = 0x51504632U;
constexpr uint16_t version = 1;
constexpr size_t headerSize = 36;
constexpr uint16_t allowedFlags = 0x007f;
constexpr size_t dataBodySize = 262'144;
constexpr size_t datagramBodySize = 64;
constexpr size_t smallPayloadBodySize = 64;
constexpr size_t smallPayloadPrefixSize = 16;

enum class Type : uint16_t {
  hello = 1,
  helloAck = 2,
  request = 3,
  data = 4,
  op = 5,
  opAck = 6,
  stop = 7,
  stopAck = 8,
  error = 9,
  terminalReady = 10,
};
enum class Scenario : uint16_t {
  download = 1,
  upload = 2,
  multistreamDownload = 3,
  multistreamUpload = 4,
  bidi = 5,
  lossRecovery = 6,
  flowControl = 7,
  smallPayloadPps = 8,
  datagram = 9,
  reqresp = 10,
  streamChurn = 11,
  closeResetCleanup = 12,
  connect = 13,
  resumedConnect = 14,
  zeroRttReqresp = 15,
  memoryCurve = 16,
};

struct Header {
  Type type;
  Scenario scenario;
  uint16_t flags;
  uint64_t trialNonce;
  uint64_t sequence;
  uint64_t payloadLength;
};

struct ParseResult {
  Header header {};
  std::string error;
  explicit operator bool() const noexcept { return error.empty(); }
};

std::array<uint8_t, headerSize> encodeHeader(const Header& header);
ParseResult decodeHeader(std::span<const uint8_t> bytes);
uint8_t deterministicPayloadByte(uint64_t trialNonce, uint64_t sequence, uint64_t offset) noexcept;
bool validatePayload(std::span<const uint8_t> payload, uint64_t trialNonce, uint64_t sequence, uint64_t offset = 0) noexcept;
std::vector<uint8_t> makeDatagram(Scenario scenario, uint64_t trialNonce, uint64_t sequence);
ParseResult validateDatagram(std::span<const uint8_t> datagram, Scenario scenario, uint64_t trialNonce, uint64_t expectedSequence);
std::vector<uint8_t> makeSmallPayloadOperation(uint64_t trialNonce, uint64_t streamSequence,
                                               uint64_t connectionOrdinal,
                                               uint64_t startRawNs);
bool validateSmallPayloadOperation(std::span<const uint8_t> body, uint64_t trialNonce,
                                   uint64_t streamSequence, uint64_t& connectionOrdinal,
                                   uint64_t& startRawNs) noexcept;

} // namespace quicperf::workload
