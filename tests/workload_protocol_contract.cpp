#include "core/workload_engine.h"
#include "workloads/workloads.h"

#include <array>
#include <limits>
#include <string_view>
#include <vector>

int main()
{
  using namespace quicperf;
  using namespace quicperf::workload;
  Header header {Type::data, Scenario::download, 0, 0x0102030405060708ULL, 1, 3};
  const auto encoded = encodeHeader(header);
  const auto decoded = decodeHeader(encoded);
  if (!decoded || decoded.header.trialNonce != header.trialNonce || decoded.header.payloadLength != 3) return 1;
  std::vector<uint8_t> payload(3);
  for (size_t index = 0; index < payload.size(); ++index) payload[index] = deterministicPayloadByte(header.trialNonce, 1, index);
  if (!validatePayload(payload, header.trialNonce, 1)) return 2;
  auto datagramBytes = makeDatagram(Scenario::datagram, header.trialNonce, 7);
  if (!validateDatagram(datagramBytes, Scenario::datagram, header.trialNonce, 7)) return 3;
  for (size_t index = 0; index < datagramBodySize; ++index)
    if (datagramBytes[24 + index] !=
        deterministicPayloadByte(header.trialNonce, 7, index)) return 22;
  std::array<uint8_t, 4> wrappedPayload {};
  const uint64_t wrappedNonce =
      std::numeric_limits<uint64_t>::max() - 7 * 1'315'423'911ULL - 1;
  for (size_t index = 0; index < wrappedPayload.size(); ++index)
    wrappedPayload[index] = deterministicPayloadByte(wrappedNonce, 7, index);
  if (!validatePayload(wrappedPayload, wrappedNonce, 7)) return 23;

  MeasurementWindow window {900, 1'000, 3'000, 1'000};
  const MeasurementWindow twoSeconds {
      900, 1'000, 2'000'001'000, 1'000};
  const MeasurementWindow fiveSeconds {
      900, 1'000, 5'000'001'000, 1'000};
  if (twoSeconds.subwindow(twoSeconds.startRawNs) != 0 ||
      twoSeconds.subwindow(twoSeconds.startRawNs + twoSeconds.durationNs() / 200) != 1 ||
      twoSeconds.subwindow(twoSeconds.endRawNs - 1) != 199 ||
      twoSeconds.subwindow(twoSeconds.endRawNs) != 199)
    return 22;
  if (fiveSeconds.subwindow(fiveSeconds.startRawNs) != 0 ||
      fiveSeconds.subwindow(fiveSeconds.startRawNs + 100 * fiveSeconds.durationNs() / 200) != 100 ||
      fiveSeconds.subwindow(fiveSeconds.endRawNs - 1) != 199 ||
      fiveSeconds.subwindow(fiveSeconds.endRawNs) != 199)
    return 23;
  Engine engine(Scenario::download, header.trialNonce, window, false);
  for (uint64_t sequence = 1; sequence <= 10; ++sequence)
  {
    auto offered = engine.next(Type::data, 1, 0, 1'000 + (sequence - 1) * 200);
    std::vector<uint8_t> byte {deterministicPayloadByte(header.trialNonce, sequence, 0)};
    std::string reason;
    if (!engine.validate(offered.header, byte, 1'000 + (sequence - 1) * 200, reason)) return 4;
  }
  const auto result = engine.finish();
  if (!result.valid() || result.counters.peerValidated != 10) return 5;
  constexpr std::string_view abc = "abc";
  const auto digest = sha256({reinterpret_cast<const uint8_t*>(abc.data()), abc.size()});
  if (hex(digest) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") return 6;

  constexpr std::array<std::string_view, 16> names {
      "download", "upload", "multistream_download", "multistream_upload", "bidi",
      "loss_recovery", "flow_control", "small_payload_pps", "datagram", "reqresp",
      "stream_churn", "close_reset_cleanup", "connect", "resumed_connect", "zero_rtt_reqresp",
      "memory_curve"};
  for (size_t index = 0; index < names.size(); ++index)
  {
    if (static_cast<uint16_t>(scenarioFromName(names[index])) != index + 1) return 7;
  }
  const Header memoryHeader {Type::hello, Scenario::memoryCurve, 0, header.trialNonce, 1, 64};
  const auto memoryDecoded = decodeHeader(encodeHeader(memoryHeader));
  if (!memoryDecoded || memoryDecoded.header.scenario != Scenario::memoryCurve) return 17;
  const Header terminalReady {Type::terminalReady, Scenario::closeResetCleanup,
                              1U << 4, header.trialNonce, 2, 0};
  const auto terminalReadyBytes = encodeHeader(terminalReady);
  const auto terminalReadyDecoded = decodeHeader(terminalReadyBytes);
  if (!terminalReadyDecoded || terminalReadyBytes[7] != 10 ||
      terminalReadyDecoded.header.type != Type::terminalReady ||
      terminalReadyDecoded.header.flags != terminalReady.flags ||
      terminalReadyDecoded.header.payloadLength != 0) return 21;
  constexpr uint64_t smallSequence = 9;
  constexpr uint64_t smallOrdinal = 3;
  constexpr uint64_t smallStart = 0x0102030405060708ULL;
  const auto smallBody = makeSmallPayloadOperation(header.trialNonce, smallSequence,
                                                   smallOrdinal, smallStart);
  const std::array<uint8_t, smallPayloadPrefixSize> smallPrefix {
      0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8};
  if (!std::ranges::equal(std::span(smallBody).first(smallPrefix.size()), smallPrefix)) return 18;
  uint64_t decodedOrdinal = 0;
  uint64_t decodedStart = 0;
  if (!validateSmallPayloadOperation(smallBody, header.trialNonce, smallSequence,
                                     decodedOrdinal, decodedStart) ||
      decodedOrdinal != smallOrdinal || decodedStart != smallStart) return 19;
  auto corruptSmall = smallBody;
  corruptSmall.back() ^= 1;
  if (validateSmallPayloadOperation(corruptSmall, header.trialNonce, smallSequence,
                                    decodedOrdinal, decodedStart)) return 20;
  using enum Scenario;
  if (!serverUsesPeerNumerator(download) || serverUsesPeerNumerator(upload) ||
      !serverUsesPeerNumerator(multistreamDownload) || serverUsesPeerNumerator(multistreamUpload) ||
      serverUsesPeerNumerator(bidi) || !serverUsesPeerNumerator(lossRecovery) ||
      !serverUsesPeerNumerator(flowControl) || serverUsesPeerNumerator(smallPayloadPps) ||
      !serverUsesPeerNumerator(datagram) || !serverUsesPeerNumerator(reqresp) ||
      !serverUsesPeerNumerator(streamChurn) || !serverUsesPeerNumerator(closeResetCleanup) ||
      !serverUsesPeerNumerator(connect) || !serverUsesPeerNumerator(resumedConnect) ||
      !serverUsesPeerNumerator(zeroRttReqresp)) return 8;
  if (workloads::transferShape(multistreamDownload).activeStreamsPerConnection != 8 ||
      workloads::requestResponseShape(reqresp).responseBodyBytes != 1'024 ||
      workloads::connectionLifecycleShape(resumedConnect).connections != 16 ||
      workloads::datagramShape().maxUnreturnedDatagramsPerConnection != 128 ||
      workloads::streamLifecycleShape(closeResetCleanup).aggregateSlots != 16) return 9;
  return 0;
}
