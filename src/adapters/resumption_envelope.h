#pragma once

#include "core/adapter.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace quicperf {

inline constexpr std::array<std::byte, 8> resumptionEnvelopeMagic {
    std::byte {'Q'}, std::byte {'P'}, std::byte {'F'}, std::byte {'R'},
    std::byte {'S'}, std::byte {'T'}, std::byte {'0'}, std::byte {'1'}};
inline constexpr size_t resumptionEnvelopeBytes = 16;

inline bool sealResumptionState(std::span<const std::byte> payload,
                                uint64_t issuedRawNs,
                                std::span<std::byte> destination,
                                size_t& written,
                                AdapterError& error)
{
  written = 0;
  if (!issuedRawNs || payload.empty() ||
      payload.size() > destination.size() -
          std::min(destination.size(), resumptionEnvelopeBytes))
  {
    error = {1, "resumption envelope source or destination is invalid"};
    return false;
  }
  std::memmove(destination.data() + resumptionEnvelopeBytes,
               payload.data(), payload.size());
  std::copy(resumptionEnvelopeMagic.begin(), resumptionEnvelopeMagic.end(),
            destination.begin());
  for (size_t index = 0; index < sizeof(issuedRawNs); ++index)
    destination[resumptionEnvelopeMagic.size() + index] =
        static_cast<std::byte>(issuedRawNs >> (56 - index * 8));
  written = resumptionEnvelopeBytes + payload.size();
  error = {};
  return true;
}

inline PrimitiveStatus openResumptionState(std::span<const std::byte> encoded,
                                           uint64_t nowRawNs,
                                           uint64_t lifetimeNs,
                                           std::span<const std::byte>& payload,
                                           AdapterError& error)
{
  payload = {};
  if (encoded.size() <= resumptionEnvelopeBytes ||
      !std::equal(resumptionEnvelopeMagic.begin(), resumptionEnvelopeMagic.end(),
                  encoded.begin()))
  {
    error = {1, "resumption state has an invalid envelope"};
    return PrimitiveStatus::fatal;
  }
  uint64_t issuedRawNs = 0;
  for (size_t index = 0; index < sizeof(issuedRawNs); ++index)
    issuedRawNs = (issuedRawNs << 8) |
        std::to_integer<uint8_t>(encoded[resumptionEnvelopeMagic.size() + index]);
  if (!issuedRawNs || !lifetimeNs || nowRawNs < issuedRawNs ||
      nowRawNs - issuedRawNs >= lifetimeNs)
  {
    error = {1, "resumption state is expired or has invalid caller time"};
    return PrimitiveStatus::fatal;
  }
  payload = encoded.subspan(resumptionEnvelopeBytes);
  error = {};
  return PrimitiveStatus::ready;
}

} // namespace quicperf
