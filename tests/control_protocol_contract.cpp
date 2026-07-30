#include "core/control_protocol.h"

#include <iostream>

int main()
{
  using namespace quicperf::control;
  Bytes trial(32);
  for (size_t index = 0; index < trial.size(); ++index)
  {
    trial[index] = static_cast<uint8_t>(index);
  }
  Packet arm {
      MessageType::arm,
      0,
      9,
      {
          {Field::trialId, WireType::bytes, trial},
          {Field::warmupStartRawNs, WireType::u64, uint64_t {100}},
          {Field::measurementStartRawNs, WireType::u64, uint64_t {200}},
          {Field::measurementEndRawNs, WireType::u64, uint64_t {300}},
          {Field::traceEpochRawNs, WireType::u64, uint64_t {200}},
      },
  };
  const auto encoded = encode(arm);
  const auto decoded = decode(encoded, 9);
  if (!decoded || decoded.packet.type != MessageType::arm || decoded.packet.fields.size() != 5)
  {
    std::cerr << decoded.error << '\n';
    return 1;
  }
  auto duplicate = encoded;
  duplicate.insert(duplicate.end(), encoded.begin() + 24, encoded.begin() + 64);
  duplicate[11] = static_cast<uint8_t>(duplicate.size() - 24);
  if (decode(duplicate, 9))
  {
    return 2;
  }
  Packet resetAck {
      MessageType::resetAck,
      0,
      10,
      {
          {Field::trialId, WireType::bytes, trial},
          {Field::liveConnections, WireType::u64, uint64_t {0}},
          {Field::liveStreams, WireType::u64, uint64_t {0}},
          {Field::liveTickets, WireType::u64, uint64_t {0}},
          {Field::workInventory, WireType::u64, uint64_t {0}},
      },
  };
  const auto resetDecoded = decode(encode(resetAck), 10);
  if (!resetDecoded || resetDecoded.packet.fields.size() != 5)
  {
    return 3;
  }
  Packet exercise {
      MessageType::exercise,
      0,
      11,
      {
          {Field::trialId, WireType::bytes, trial},
          {Field::exerciseDeadlineRawNs, WireType::u64, uint64_t {123456789}},
      },
  };
  const auto exerciseDecoded = decode(encode(exercise), 11);
  if (!exerciseDecoded || exerciseDecoded.packet.type != MessageType::exercise ||
      exerciseDecoded.packet.fields.size() != 2)
  {
    return 4;
  }
  Packet exercised {
      MessageType::exercised,
      0,
      12,
      {
          {Field::trialId, WireType::bytes, trial},
          {Field::liveConnections, WireType::u64, uint64_t {16}},
          {Field::liveStreams, WireType::u64, uint64_t {4}},
          {Field::liveTickets, WireType::u64, uint64_t {0}},
          {Field::workInventory, WireType::u64, uint64_t {20}},
      },
  };
  const auto exercisedDecoded = decode(encode(exercised), 12);
  if (!exercisedDecoded || exercisedDecoded.packet.type != MessageType::exercised ||
      exercisedDecoded.packet.fields.size() != 5)
  {
    return 5;
  }
  Packet armRejected {
      MessageType::armRejected,
      0,
      13,
      {
          {Field::trialId, WireType::bytes, trial},
          {Field::rawNowNs, WireType::u64, uint64_t {99}},
          {Field::reason, WireType::utf8, std::string("arm_window_not_in_future")},
      },
  };
  const auto rejectedDecoded = decode(encode(armRejected), 13);
  if (!rejectedDecoded ||
      rejectedDecoded.packet.type != MessageType::armRejected ||
      rejectedDecoded.packet.fields.size() != 3)
  {
    return 6;
  }
  return 0;
}
