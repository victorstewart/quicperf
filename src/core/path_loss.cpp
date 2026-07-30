#include "path_loss.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace quicperf {
namespace {

constexpr std::array<uint32_t, 64> roundConstants {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

class Sha256 {
public:
  Sha256()
      : state_ {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U}
  {
  }

  void update(std::span<const uint8_t> input)
  {
    if (input.size() > (std::numeric_limits<uint64_t>::max() - byteCount_) / 8)
      throw std::overflow_error("SHA-256 input length overflow");
    byteCount_ += input.size();
    while (!input.empty())
    {
      const size_t copied = std::min(input.size(), block_.size() - blockBytes_);
      std::memcpy(block_.data() + blockBytes_, input.data(), copied);
      blockBytes_ += copied;
      input = input.subspan(copied);
      if (blockBytes_ == block_.size())
      {
        compress(block_);
        blockBytes_ = 0;
      }
    }
  }

  std::array<uint8_t, 32> finish()
  {
    const uint64_t bitCount = byteCount_ * 8;
    block_[blockBytes_++] = 0x80;
    if (blockBytes_ > 56)
    {
      std::fill(block_.begin() + blockBytes_, block_.end(), 0);
      compress(block_);
      blockBytes_ = 0;
    }
    std::fill(block_.begin() + blockBytes_, block_.begin() + 56, 0);
    for (size_t index = 0; index < 8; ++index)
      block_[63 - index] = static_cast<uint8_t>(bitCount >> (index * 8));
    compress(block_);
    std::array<uint8_t, 32> digest {};
    for (size_t index = 0; index < state_.size(); ++index)
      for (size_t byte = 0; byte < 4; ++byte)
        digest[index * 4 + byte] =
            static_cast<uint8_t>(state_[index] >> (24 - byte * 8));
    return digest;
  }

private:
  void compress(const std::array<uint8_t, 64>& input)
  {
    std::array<uint32_t, 64> words {};
    for (size_t index = 0; index < 16; ++index)
      words[index] = static_cast<uint32_t>(input[index * 4]) << 24 |
          static_cast<uint32_t>(input[index * 4 + 1]) << 16 |
          static_cast<uint32_t>(input[index * 4 + 2]) << 8 |
          static_cast<uint32_t>(input[index * 4 + 3]);
    for (size_t index = 16; index < words.size(); ++index)
    {
      const uint32_t s0 = std::rotr(words[index - 15], 7) ^
          std::rotr(words[index - 15], 18) ^ (words[index - 15] >> 3);
      const uint32_t s1 = std::rotr(words[index - 2], 17) ^
          std::rotr(words[index - 2], 19) ^ (words[index - 2] >> 10);
      words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    auto [a, b, c, d, e, f, g, h] = state_;
    for (size_t index = 0; index < words.size(); ++index)
    {
      const uint32_t s1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
      const uint32_t choice = (e & f) ^ (~e & g);
      const uint32_t first = h + s1 + choice + roundConstants[index] + words[index];
      const uint32_t s0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
      const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t second = s0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + first;
      d = c;
      c = b;
      b = a;
      a = first + second;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  std::array<uint32_t, 8> state_;
  std::array<uint8_t, 64> block_ {};
  uint64_t byteCount_ = 0;
  size_t blockBytes_ = 0;
};

std::array<uint8_t, 32> hmacSha256(std::span<const uint8_t, 32> key,
                                  std::span<const uint8_t> message)
{
  std::array<uint8_t, 64> innerPad {};
  std::array<uint8_t, 64> outerPad {};
  innerPad.fill(0x36);
  outerPad.fill(0x5c);
  for (size_t index = 0; index < key.size(); ++index)
  {
    innerPad[index] ^= key[index];
    outerPad[index] ^= key[index];
  }
  Sha256 inner;
  inner.update(innerPad);
  inner.update(message);
  const auto innerDigest = inner.finish();
  Sha256 outer;
  outer.update(outerPad);
  outer.update(innerDigest);
  return outer.finish();
}

} // namespace

bool lossRecoveryDrop(std::span<const uint8_t, 32> traceSeed,
                      bool measurement, uint8_t direction,
                      uint64_t packetOrdinal)
{
  if (direction > 1) throw std::invalid_argument("loss direction must be zero or one");
  constexpr std::array<uint8_t, 17> domain {
      'l', 'o', 's', 's', '-', 'r', 'e', 'c', 'o', 'v', 'e', 'r', 'y', '-', 'v', '1', 0};
  std::array<uint8_t, 27> message {};
  std::copy(domain.begin(), domain.end(), message.begin());
  message[17] = static_cast<uint8_t>(measurement);
  message[18] = direction;
  for (size_t index = 0; index < 8; ++index)
    message[26 - index] = static_cast<uint8_t>(packetOrdinal >> (index * 8));
  const auto digest = hmacSha256(traceSeed, message);
  unsigned remainder = 0;
  for (const uint8_t byte : digest) remainder = (remainder * 256 + byte) % 100;
  return remainder == 0;
}

void LossRecoveryStream::arm(std::span<const uint8_t, 32> traceSeed,
                             uint64_t measurementStartRawNs,
                             uint64_t measurementEndRawNs,
                             uint8_t direction)
{
  std::lock_guard lock(mutex_);
  if (measurementStartRawNs == 0 || measurementStartRawNs >= measurementEndRawNs ||
      direction > 1)
    throw std::invalid_argument("invalid loss-recovery trace boundaries");
  std::copy(traceSeed.begin(), traceSeed.end(), traceSeed_.begin());
  measurementStartRawNs_ = measurementStartRawNs;
  measurementEndRawNs_ = measurementEndRawNs;
  direction_ = direction;
  ordinals_.fill(0);
  armed_ = true;
}

void LossRecoveryStream::reset()
{
  std::lock_guard lock(mutex_);
  traceSeed_.fill(0);
  ordinals_.fill(0);
  measurementStartRawNs_ = 0;
  measurementEndRawNs_ = 0;
  direction_ = 0;
  armed_ = false;
}

LossDecision LossRecoveryStream::next(uint64_t nowRawNs)
{
  std::lock_guard lock(mutex_);
  if (!armed_ || nowRawNs >= measurementEndRawNs_) return {};
  const bool measurement = nowRawNs >= measurementStartRawNs_;
  auto& ordinal = ordinals_[static_cast<size_t>(measurement)];
  if (ordinal == std::numeric_limits<uint64_t>::max())
    throw std::overflow_error("loss-recovery packet ordinal exhausted");
  const bool drop = lossRecoveryDrop(traceSeed_, measurement, direction_, ordinal++);
  return {true, measurement, drop};
}

bool LossRecoveryStream::armed() const
{
  std::lock_guard lock(mutex_);
  return armed_;
}

} // namespace quicperf
