#include "workload_engine.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <deque>
#include <map>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>
#include <arpa/inet.h>

namespace quicperf::workload {

Engine::Engine(Scenario scenario, uint64_t trialNonce, MeasurementWindow window, bool operationRate)
    : scenario_(scenario), nonce_(trialNonce), window_(window), operationRate_(operationRate)
{
  std::string reason;
  if (nonce_ == 0 || !window_.valid(reason)) throw std::invalid_argument(reason.empty() ? "invalid workload identity" : reason);
  result_.measurementStartRawNs = window_.startRawNs;
  result_.measurementEndRawNs = window_.endRawNs;
}

OfferedFrame Engine::next(Type type, size_t payloadLength, uint16_t flags, uint64_t nowRawNs)
{
  if (!admitting_ || nowRawNs >= window_.endRawNs) throw std::logic_error("work admission is closed");
  if (sendSequence_ == std::numeric_limits<uint64_t>::max()) throw std::overflow_error("QPF2 send sequence exhausted");
  ++sendSequence_;
  ++result_.counters.admitted;
  return {{type, scenario_, flags, nonce_, sendSequence_, payloadLength}, 0, payloadLength};
}

void Engine::accepted(const OfferedFrame& frame, size_t bytes)
{
  if (bytes > frame.payloadLength - frame.payloadOffset) throw std::invalid_argument("accepted suffix exceeds offered bytes");
  result_.counters.accepted += bytes;
}

bool Engine::validate(const Header& header, std::span<const uint8_t> payload, uint64_t completionRawNs, std::string& reason)
{
  if (header.scenario != scenario_ || header.trialNonce != nonce_ || header.sequence != receiveSequence_ + 1 ||
      header.payloadLength != payload.size())
  {
    reason = "QPF2 identity, sequence, or length mismatch";
    return false;
  }
  if (!validatePayload(payload, nonce_, header.sequence))
  {
    ++result_.counters.payloadErrors;
    reason = "QPF2 deterministic payload mismatch";
    return false;
  }
  receiveSequence_ = header.sequence;
  if (window_.contains(completionRawNs))
  {
    result_.counters.peerValidated += payload.size();
    result_.counters.subwindows[window_.subwindow(completionRawNs)].validatedUnits += payload.size();
  }
  else if (completionRawNs >= window_.endRawNs)
  {
    result_.counters.completedAfterEnd += payload.size();
  }
  return true;
}

void Engine::blocked(uint64_t nowRawNs)
{
  if (window_.contains(nowRawNs)) ++result_.counters.subwindows[window_.subwindow(nowRawNs)].blockedEvents;
}

TrialResult Engine::finish()
{
  admitting_ = false;
  result_.validate(operationRate_);
  return result_;
}

namespace {

constexpr uint16_t uploadFlag = 1U << 0;
constexpr uint16_t earlyDataFlag = 1U << 1;
constexpr uint16_t resumedFlag = 1U << 2;
constexpr uint16_t finFlag = 1U << 3;
constexpr uint16_t resetFlag = 1U << 4;
constexpr uint16_t stopSendingFlag = 1U << 5;
constexpr uint64_t cleanupApplicationError = 0x5150;
constexpr uint64_t datagramDrainNs = 100'000'000ULL;

uint32_t rotateRight(uint32_t value, unsigned bits) noexcept
{
  return std::rotr(value, static_cast<int>(bits));
}

uint64_t load64(std::span<const uint8_t> bytes)
{
  uint64_t value = 0;
  for (const uint8_t byte : bytes.first<8>()) value = (value << 8) | byte;
  return value;
}

void store64(std::span<uint8_t> bytes, size_t offset, uint64_t value)
{
  for (int shift = 56; shift >= 0; shift -= 8) bytes[offset++] = static_cast<uint8_t>(value >> shift);
}

uint64_t read64(std::span<const uint8_t> bytes, size_t offset)
{
  uint64_t value = 0;
  for (unsigned index = 0; index < 8; ++index) value = (value << 8) | bytes[offset + index];
  return value;
}

bool isTransfer(Scenario scenario) noexcept
{
  using enum Scenario;
  return scenario == download || scenario == upload || scenario == multistreamDownload ||
      scenario == multistreamUpload || scenario == bidi || scenario == lossRecovery ||
      scenario == flowControl;
}

bool isDownload(Scenario scenario) noexcept
{
  using enum Scenario;
  return scenario == download || scenario == multistreamDownload ||
      scenario == lossRecovery || scenario == flowControl;
}

bool isUpload(Scenario scenario) noexcept
{
  using enum Scenario;
  return scenario == upload || scenario == multistreamUpload;
}

bool isFreshStreamOperation(Scenario scenario) noexcept
{
  using enum Scenario;
  return scenario == reqresp || scenario == streamChurn || scenario == closeResetCleanup;
}

bool isConnectionOperation(Scenario scenario) noexcept
{
  using enum Scenario;
  return scenario == connect || scenario == resumedConnect || scenario == zeroRttReqresp;
}

bool carriesConnectionIdentity(Scenario scenario) noexcept
{
  return isConnectionOperation(scenario) || scenario == Scenario::closeResetCleanup;
}

std::vector<uint8_t> identityPayload(std::span<const uint8_t, 32> trial,
                                     std::span<const uint8_t, 32> cell)
{
  std::vector<uint8_t> value;
  value.reserve(64);
  value.insert(value.end(), trial.begin(), trial.end());
  value.insert(value.end(), cell.begin(), cell.end());
  return value;
}

} // namespace

std::array<uint8_t, 32> sha256(std::span<const uint8_t> input) noexcept
{
  constexpr std::array<uint32_t, 64> constants {
      0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
      0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
      0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
      0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
      0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
      0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
      0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
      0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};
  std::array<uint32_t, 8> state {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                                 0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
  const uint64_t bitLength = static_cast<uint64_t>(input.size()) * 8;
  const size_t paddedLength = ((input.size() + 9 + 63) / 64) * 64;
  std::vector<uint8_t> padded(paddedLength);
  std::copy(input.begin(), input.end(), padded.begin());
  padded[input.size()] = 0x80;
  for (unsigned index = 0; index < 8; ++index)
    padded[paddedLength - 1 - index] = static_cast<uint8_t>(bitLength >> (index * 8));
  for (size_t block = 0; block < padded.size(); block += 64)
  {
    std::array<uint32_t, 64> words {};
    for (unsigned index = 0; index < 16; ++index)
    {
      const size_t offset = block + index * 4;
      words[index] = (uint32_t {padded[offset]} << 24) |
          (uint32_t {padded[offset + 1]} << 16) | (uint32_t {padded[offset + 2]} << 8) |
          uint32_t {padded[offset + 3]};
    }
    for (unsigned index = 16; index < 64; ++index)
    {
      const uint32_t s0 = rotateRight(words[index - 15], 7) ^ rotateRight(words[index - 15], 18) ^ (words[index - 15] >> 3);
      const uint32_t s1 = rotateRight(words[index - 2], 17) ^ rotateRight(words[index - 2], 19) ^ (words[index - 2] >> 10);
      words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    auto [a, b, c, d, e, f, g, h] = state;
    for (unsigned index = 0; index < 64; ++index)
    {
      const uint32_t s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const uint32_t choice = (e & f) ^ (~e & g);
      const uint32_t temporary1 = h + s1 + choice + constants[index] + words[index];
      const uint32_t s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temporary2 = s0 + majority;
      h = g; g = f; f = e; e = d + temporary1; d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
  }
  std::array<uint8_t, 32> digest {};
  for (size_t index = 0; index < state.size(); ++index)
    for (unsigned byte = 0; byte < 4; ++byte)
      digest[index * 4 + byte] = static_cast<uint8_t>(state[index] >> (24 - byte * 8));
  return digest;
}

std::string hex(std::span<const uint8_t> bytes)
{
  constexpr std::string_view alphabet = "0123456789abcdef";
  std::string output;
  output.reserve(bytes.size() * 2);
  for (const uint8_t byte : bytes)
  {
    output.push_back(alphabet[byte >> 4]);
    output.push_back(alphabet[byte & 0x0f]);
  }
  return output;
}

Scenario scenarioFromName(std::string_view name)
{
  using enum Scenario;
  if (name == "download") return download;
  if (name == "upload") return upload;
  if (name == "multistream_download") return multistreamDownload;
  if (name == "multistream_upload") return multistreamUpload;
  if (name == "bidi") return bidi;
  if (name == "loss_recovery") return lossRecovery;
  if (name == "flow_control") return flowControl;
  if (name == "small_payload_pps") return smallPayloadPps;
  if (name == "datagram") return datagram;
  if (name == "reqresp") return reqresp;
  if (name == "stream_churn") return streamChurn;
  if (name == "close_reset_cleanup") return closeResetCleanup;
  if (name == "connect") return connect;
  if (name == "resumed_connect") return resumedConnect;
  if (name == "zero_rtt_reqresp") return zeroRttReqresp;
  if (name == "memory_curve") return memoryCurve;
  throw std::invalid_argument("unknown workload scenario");
}

bool scenarioMeasuresOperations(Scenario scenario) noexcept
{
  return !isTransfer(scenario) && scenario != Scenario::memoryCurve;
}

bool serverUsesPeerNumerator(Scenario scenario) noexcept
{
  using enum Scenario;
  return isDownload(scenario) || scenario == datagram || scenario == reqresp ||
      scenario == streamChurn || scenario == closeResetCleanup ||
      isConnectionOperation(scenario);
}

struct Runtime::Implementation {
  enum class StreamKind { unknown, control, data, operation };

  struct TxFrame {
    Header header {};
    std::array<uint8_t, headerSize> encoded {};
    size_t headerOffset = 0;
    uint64_t payloadOffset = 0;
    std::vector<uint8_t> literal;
    std::vector<uint8_t> generated;
    size_t generatedOffset = 0;
    bool deterministic = true;
  };

  struct RxFrame {
    std::array<uint8_t, headerSize> encoded {};
    size_t headerOffset = 0;
    Header header {};
    bool haveHeader = false;
    uint64_t payloadOffset = 0;
    std::vector<uint8_t> literal;
  };

  struct Stream {
    uint64_t id = 0;
    StreamKind kind = StreamKind::unknown;
    uint64_t sendSequence = 0;
    uint64_t receiveSequence = 0;
    uint64_t operationSequence = 0;
    uint64_t operationStartRawNs = 0;
    std::deque<TxFrame> transmit;
    RxFrame receive;
    bool finishAfterTransmit = false;
    bool finishIssued = false;
    bool remoteFinished = false;
    bool operationComplete = false;
    bool terminalAction = false;
    bool terminalObserver = false;
    bool terminalReady = false;
    bool terminalIssued = false;
    bool flowControlWriteBlocked = false;
    uint16_t terminalFlags = 0;
  };

  struct Connection {
    uint64_t id = 0;
    uint32_t ordinal = 0;
    bool connected = false;
    bool controlOpening = false;
    bool helloSent = false;
    bool helloAcknowledged = false;
    bool requestSent = false;
    bool requestReceived = false;
    bool stopSent = false;
    bool stopReceived = false;
    bool stopAcknowledged = false;
    bool stopAckSent = false;
    bool stopOffered = false;
    bool lifecycleAck = false;
    bool retired = false;
    bool superseded = false;
    bool cleanupCloseObserved = false;
    bool treatmentVerified = false;
    bool hasControlStream = false;
    bool frameCountsRetired = false;
    uint64_t controlStream = 0;
    uint32_t desiredDataStreams = 0;
    uint32_t operationInFlight = 0;
    uint64_t localValidated = 0;
    uint64_t sentApplicationFrames = 0;
    uint64_t receivedApplicationFrames = 0;
    uint64_t peerFinalSentFrames = 0;
    bool peerFinalSentFramesKnown = false;
    uint64_t nextDatagramSequence = 1;
    uint64_t nextOperationSequence = 0;
    uint64_t lifecycleOperationSequence = 0;
    uint64_t lifecycleStartRawNs = 0;
    std::deque<std::pair<uint64_t, uint64_t>> datagramsOutstanding;
    std::deque<std::vector<uint8_t>> datagramsToEcho;
    std::map<uint64_t, Stream> streams;
    std::vector<std::byte> ticket;
    bool importedTicket = false;
  };

  Adapter& adapter;
  EndpointConfig config;
  MeasurementWindow window;
  Scenario scenario;
  std::array<uint8_t, 32> trialId {};
  std::array<uint8_t, 32> cellId {};
  std::vector<uint8_t> identity;
  uint64_t nonce = 0;
  uint32_t connectionFirst = 0;
  uint32_t connectionCount = 0;
  std::map<uint64_t, Connection> connections;
  std::map<uint32_t, uint64_t> latestLifecycleSequence;
  WorkloadCounters counters;
  uint64_t peerValidated = 0;
  uint64_t failed = 0;
  uint64_t byteCapHits = 0;
  uint64_t streamCapHits = 0;
  uint64_t streamIdCapHits = 0;
  std::array<uint64_t, 4> cleanupStrata {};
  uint64_t tailStartedOperations = 0;
  uint64_t tailFailedOperations = 0;
  uint64_t tailCensoredOperations = 0;
  std::array<uint64_t, 4> tailPrefixStarted {};
  std::array<uint64_t, 4> tailPrefixSuccessful {};
  std::array<uint64_t, 4> tailPrefixFailed {};
  std::array<std::vector<TailObservation>, 4> tailPrefixObservations;
  std::array<size_t, 4> tailPrefixLatestIndices {};
  std::vector<TailObservation> tailObservations;
  size_t tailLatestIndex = 0;
  std::set<uint64_t> receivedTailSequences;
  bool started = false;
  bool admitting = true;
  bool stopQueued = false;
  bool reconciled = false;
  uint64_t observedFlowControlBlocks = 0;
  uint64_t observedStreamCreditBlocks = 0;
  uint64_t flowControlWriteBlockedEvents = 0;
  bool flowControlBlockSeen = false;
  bool flowControlRecoveryEvidence = false;
  bool tailFinalized = false;
  bool datagramDrainFinished = false;
  uint64_t datagramDrainEndRawNs = 0;
  std::map<uint32_t, uint64_t> retiredValidatedByOrdinal;
  std::map<uint32_t, uint64_t> retiredSentFramesByOrdinal;
  std::map<uint32_t, uint64_t> retiredReceivedFramesByOrdinal;
  bool hasNegotiatedSettings = false;
  NegotiatedSettings negotiatedSettings;
  std::string negotiatedSettingsCanonical;
  size_t readBudget = 0;
  size_t writeBudget = 0;
  std::array<std::byte, 256 * 1024> applicationBuffer {};
  std::array<std::byte, 64 * 1024> receiveBuffer {};
  std::array<std::byte, 16 * 1024> ticketBuffer {};

  Implementation(Adapter& value, EndpointConfig endpoint, MeasurementWindow interval,
                 std::span<const uint8_t, 32> trial, std::span<const uint8_t, 32> cell,
                 uint32_t first, uint32_t count)
      : adapter(value), config(std::move(endpoint)), window(interval), scenario(scenarioFromName(config.scenario)),
        connectionFirst(first), connectionCount(count)
  {
    std::copy(trial.begin(), trial.end(), trialId.begin());
    std::copy(cell.begin(), cell.end(), cellId.begin());
    identity = identityPayload(trialId, cellId);
    constexpr std::string_view domain = "QPF2-nonce";
    std::array<uint8_t, domain.size() + 32> basis {};
    std::copy(domain.begin(), domain.end(), basis.begin());
    std::copy(trialId.begin(), trialId.end(), basis.begin() + domain.size());
    nonce = load64(sha256(basis));
    if (nonce == 0) throw std::invalid_argument("QPF2 trial nonce is zero");
  }

  bool client() const noexcept { return config.role == EndpointRole::client; }

  static bool literal(Type type) noexcept
  {
    return type == Type::hello || type == Type::helloAck || type == Type::stop || type == Type::stopAck;
  }

  static bool barrier(Type type) noexcept
  {
    return type == Type::stop || type == Type::stopAck;
  }

  bool literalBody(Type type) const noexcept
  {
    return literal(type) || (scenario == Scenario::smallPayloadPps && type == Type::op);
  }

  void queue(Stream& stream, Type type, uint64_t payloadLength, uint16_t flags,
             std::vector<uint8_t> body = {})
  {
    if (stream.sendSequence == std::numeric_limits<uint64_t>::max())
      throw std::overflow_error("QPF2 stream sequence exhausted");
    Header header {type, scenario, flags, nonce, ++stream.sendSequence, payloadLength};
    TxFrame frame {header, encodeHeader(header), 0, 0, std::move(body), {}, 0,
                   !literalBody(type)};
    if (!frame.deterministic && frame.literal.size() != payloadLength)
      throw std::logic_error("QPF2 literal payload length mismatch");
    stream.transmit.push_back(std::move(frame));
    ++counters.admitted;
  }

  bool logicalCurrent(const Connection& connection) const noexcept
  {
    return !connection.retired &&
        (!carriesConnectionIdentity(scenario) ||
         (!connection.superseded &&
          connection.ordinal != std::numeric_limits<uint32_t>::max()));
  }

  size_t logicalConnectionCount() const noexcept
  {
    return std::ranges::count_if(connections, [this](const auto& item) {
      return logicalCurrent(item.second);
    });
  }

  std::vector<uint8_t> helloPayload(const Connection& connection) const
  {
    auto payload = identity;
    if (carriesConnectionIdentity(scenario))
    {
      payload.resize(identity.size() + 2 * sizeof(uint64_t));
      store64(payload, identity.size(), connection.ordinal);
      store64(payload, identity.size() + sizeof(uint64_t),
              connection.lifecycleOperationSequence);
    }
    return payload;
  }

  static void retainTailObservation(
      std::vector<TailObservation>& observations, size_t& latestIndex,
      const TailObservation& value)
  {
    constexpr size_t limit = 1'024;
    const auto earlier = [](const TailObservation& left, const TailObservation& right) {
      return std::pair {left.startRawNs, left.operationSequence} <
          std::pair {right.startRawNs, right.operationSequence};
    };
    if (observations.size() < limit)
    {
      observations.push_back(value);
      if (observations.size() == 1 || earlier(observations[latestIndex], value))
        latestIndex = observations.size() - 1;
      return;
    }
    if (!earlier(value, observations[latestIndex])) return;
    observations[latestIndex] = value;
    latestIndex = static_cast<size_t>(
        std::ranges::max_element(observations, earlier) - observations.begin());
  }

  void recordTail(uint64_t operationSequence, uint64_t startRawNs, uint64_t terminalRawNs)
  {
    if (!window.contains(startRawNs) || !window.contains(terminalRawNs) || terminalRawNs < startRawNs) return;
    const TailObservation observation {operationSequence, startRawNs, terminalRawNs};
    constexpr std::array<uint64_t, 4> durationsNs {
        2'000'000'000ULL, 5'000'000'000ULL, 10'000'000'000ULL, 20'000'000'000ULL};
    for (size_t index = 0; index < durationsNs.size(); ++index)
    {
      const uint64_t available = window.endRawNs - window.startRawNs;
      const uint64_t duration = std::min(durationsNs[index], available);
      if (terminalRawNs - window.startRawNs < duration)
      {
        ++tailPrefixSuccessful[index];
        retainTailObservation(
            tailPrefixObservations[index], tailPrefixLatestIndices[index],
            observation);
      }
    }
    retainTailObservation(tailObservations, tailLatestIndex, observation);
  }

  void recordTailStart(uint64_t startRawNs)
  {
    if (!window.contains(startRawNs)) return;
    ++tailStartedOperations;
    constexpr std::array<uint64_t, 4> durationsNs {
        2'000'000'000ULL, 5'000'000'000ULL, 10'000'000'000ULL, 20'000'000'000ULL};
    for (size_t index = 0; index < durationsNs.size(); ++index)
    {
      const uint64_t available = window.endRawNs - window.startRawNs;
      const uint64_t duration = std::min(durationsNs[index], available);
      if (startRawNs - window.startRawNs < duration) ++tailPrefixStarted[index];
    }
  }

  void recordTailFailure(uint64_t startRawNs, uint64_t terminalRawNs)
  {
    if (!window.contains(startRawNs) || terminalRawNs < startRawNs) return;
    ++tailFailedOperations;
    constexpr std::array<uint64_t, 4> durationsNs {
        2'000'000'000ULL, 5'000'000'000ULL, 10'000'000'000ULL, 20'000'000'000ULL};
    for (size_t index = 0; index < durationsNs.size(); ++index)
    {
      const uint64_t available = window.endRawNs - window.startRawNs;
      const uint64_t duration = std::min(durationsNs[index], available);
      if (terminalRawNs - window.startRawNs < duration) ++tailPrefixFailed[index];
    }
  }

  std::vector<uint8_t> counterPayload(const Connection& connection) const
  {
    std::vector<uint8_t> bytes(64);
    const auto retired = retiredValidatedByOrdinal.find(connection.ordinal);
    const uint64_t retiredValidated = retired == retiredValidatedByOrdinal.end() ?
        0 : retired->second;
    if (connection.localValidated >
        std::numeric_limits<uint64_t>::max() - retiredValidated)
      throw std::overflow_error("QPF2 reconciled counter overflow");
    const auto retiredFrames = retiredSentFramesByOrdinal.find(connection.ordinal);
    const uint64_t retiredSentFrames = retiredFrames == retiredSentFramesByOrdinal.end() ?
        0 : retiredFrames->second;
    if (connection.sentApplicationFrames >
        std::numeric_limits<uint64_t>::max() - retiredSentFrames)
      throw std::overflow_error("QPF2 sent application-frame counter overflow");
    store64(bytes, 0, connection.localValidated + retiredValidated);
    store64(bytes, 8, connection.sentApplicationFrames + retiredSentFrames);
    store64(bytes, 16, counters.accepted);
    store64(bytes, 24, counters.completedAfterEnd);
    store64(bytes, 32, counters.duplicates);
    store64(bytes, 40, counters.payloadErrors);
    store64(bytes, 48, counters.unreturned);
    store64(bytes, 56, failed);
    return bytes;
  }

  bool retireValidated(Connection& connection, std::string_view context,
                       AdapterError& error)
  {
    auto& retired = retiredValidatedByOrdinal[connection.ordinal];
    if (connection.localValidated > std::numeric_limits<uint64_t>::max() - retired)
    {
      error = {1, "QPF2 retired " + std::string(context) + " counter overflow"};
      return false;
    }
    retired += connection.localValidated;
    connection.localValidated = 0;
    return true;
  }

  bool retireFrameCounts(Connection& connection, std::string_view context,
                         AdapterError& error)
  {
    if (connection.frameCountsRetired) return true;
    if (connection.ordinal == std::numeric_limits<uint32_t>::max())
    {
      if (connection.sentApplicationFrames != 0 ||
          connection.receivedApplicationFrames != 0)
      {
        error = {1, "QPF2 retired unclassified " + std::string(context) +
                        " connection carried application frames"};
        return false;
      }
      connection.frameCountsRetired = true;
      return true;
    }
    auto& sent = retiredSentFramesByOrdinal[connection.ordinal];
    auto& received = retiredReceivedFramesByOrdinal[connection.ordinal];
    if (connection.sentApplicationFrames >
            std::numeric_limits<uint64_t>::max() - sent ||
        connection.receivedApplicationFrames >
            std::numeric_limits<uint64_t>::max() - received)
    {
      error = {1, "QPF2 retired " + std::string(context) +
                      " application-frame counter overflow"};
      return false;
    }
    sent += connection.sentApplicationFrames;
    received += connection.receivedApplicationFrames;
    connection.sentApplicationFrames = 0;
    connection.receivedApplicationFrames = 0;
    connection.frameCountsRetired = true;
    return true;
  }

  bool peerFinalFramesReceived(const Connection& connection, bool& complete,
                               AdapterError& error) const
  {
    complete = false;
    if (!connection.peerFinalSentFramesKnown) return true;
    const auto retiredFrames = retiredReceivedFramesByOrdinal.find(connection.ordinal);
    const uint64_t retiredReceivedFrames =
        retiredFrames == retiredReceivedFramesByOrdinal.end() ?
        0 : retiredFrames->second;
    if (connection.receivedApplicationFrames >
        std::numeric_limits<uint64_t>::max() - retiredReceivedFrames)
    {
      error = {1, "QPF2 received application-frame counter overflow"};
      return false;
    }
    const uint64_t received =
        connection.receivedApplicationFrames + retiredReceivedFrames;
    if (received > connection.peerFinalSentFrames)
    {
      error = {1, "QPF2 received application-frame count exceeds peer STOP declaration"};
      return false;
    }
    const bool partialFrame = std::ranges::any_of(
        connection.streams, [](const auto& item) {
          const auto& receive = item.second.receive;
          return receive.headerOffset != 0 || receive.haveHeader;
        });
    complete = received == connection.peerFinalSentFrames && !partialFrame;
    return true;
  }

  static bool hasPendingApplicationFrames(const Connection& connection)
  {
    return std::ranges::any_of(connection.streams, [](const auto& item) {
      return std::ranges::any_of(item.second.transmit, [](const TxFrame& frame) {
        return !barrier(frame.header.type);
      });
    });
  }

  bool discardsPostWindowApplicationBacklog() const noexcept
  {
    return isTransfer(scenario) || scenario == Scenario::smallPayloadPps;
  }

  void discardPostWindowApplicationBacklog()
  {
    if (!discardsPostWindowApplicationBacklog()) return;
    for (auto& [id, connection] : connections)
    {
      (void)id;
      for (auto& [streamId, stream] : connection.streams)
      {
        (void)streamId;
        std::erase_if(stream.transmit, [](const TxFrame& frame) {
          return !barrier(frame.header.type);
        });
      }
    }
  }

  Stream& addStream(Connection& connection, uint64_t id, StreamKind kind)
  {
    auto [iterator, inserted] = connection.streams.try_emplace(id);
    if (inserted)
    {
      iterator->second.id = id;
      iterator->second.kind = kind;
    }
    else if (iterator->second.kind == StreamKind::unknown && kind != StreamKind::unknown)
    {
      iterator->second.kind = kind;
    }
    return iterator->second;
  }

  bool beginConnection(uint32_t ordinal, uint64_t operationSequence,
                       std::span<const std::byte> ticket,
                       bool zeroRtt, uint64_t now, AdapterError& error)
  {
    if (!ticket.empty())
    {
      const auto status = adapter.importResumptionState(ticket, zeroRtt, now, error);
      if (status == PrimitiveStatus::fatal) return false;
      if (status == PrimitiveStatus::wouldBlock)
      {
        error = {1, "resumption import unexpectedly blocked"};
        return false;
      }
    }
    sockaddr_in peer {};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(config.peerPort);
    if (inet_pton(AF_INET, config.peerAddress.c_str(), &peer.sin_addr) != 1)
    {
      error = {1, "invalid peer address after strict configuration"};
      return false;
    }
    uint64_t id = 0;
    if (!adapter.connect(peer, now, id, error)) return false;
    Connection connection;
    connection.id = id;
    connection.ordinal = ordinal;
    connection.nextOperationSequence = operationSequence;
    connection.lifecycleOperationSequence = operationSequence;
    connection.lifecycleStartRawNs = now;
    connection.importedTicket = !ticket.empty();
    connections.emplace(id, std::move(connection));
    if (isConnectionOperation(scenario)) recordTailStart(now);
    return true;
  }

  bool start(uint64_t now, AdapterError& error)
  {
    if (started)
    {
      error = {1, "workload runtime started twice"};
      return false;
    }
    started = true;
    if (!client()) return true;
    for (uint32_t index = 0; index < connectionCount; ++index)
      if (!beginConnection(connectionFirst + index, connectionFirst + index, {}, false, now, error)) return false;
    return true;
  }

  bool acceptConnections(uint64_t now, AdapterError& error)
  {
    if (client()) return true;
    for (;;)
    {
      uint64_t id = 0;
      const auto status = adapter.acceptConnection(now, id, error);
      if (status == PrimitiveStatus::fatal) return false;
      if (status == PrimitiveStatus::wouldBlock) return true;
      if (connections.contains(id))
      {
        error = {1, "adapter returned duplicate accepted connection"};
        return false;
      }
      Connection connection;
      connection.id = id;
      connection.ordinal = carriesConnectionIdentity(scenario) ?
          std::numeric_limits<uint32_t>::max() :
          connectionFirst + static_cast<uint32_t>(connections.size());
      connection.nextOperationSequence = connection.ordinal;
      connections.emplace(id, std::move(connection));
    }
  }

  bool acceptStreams(Connection& connection, uint64_t now, AdapterError& error)
  {
    for (;;)
    {
      uint64_t id = 0;
      const auto status = adapter.acceptBidirectionalStream(connection.id, now, id, error);
      if (status == PrimitiveStatus::fatal) return false;
      if (status == PrimitiveStatus::wouldBlock) return true;
      // Some transports report the stream-open callback for locally opened
      // streams through the same acceptance queue.  Its identity is already
      // registered, so consuming that notification is idempotent.
      if (connection.streams.contains(id)) continue;
      addStream(connection, id, StreamKind::unknown);
    }
  }

  bool openControl(Connection& connection, uint64_t now, AdapterError& error)
  {
    if (connection.hasControlStream || connection.controlOpening) return true;
    const bool early = scenario == Scenario::zeroRttReqresp;
    if (!connection.connected && !early) return true;
    uint64_t streamId = 0;
    const auto status = adapter.openBidirectionalStream(connection.id, now, streamId, error);
    if (status == PrimitiveStatus::fatal) return false;
    if (status == PrimitiveStatus::wouldBlock)
    {
      ++counters.streamCreditExhaustions;
      if (window.contains(now)) counters.subwindows[window.subwindow(now)].blockedEvents++;
      return true;
    }
    connection.controlStream = streamId;
    connection.hasControlStream = true;
    auto& stream = addStream(connection, streamId, StreamKind::control);
    auto hello = helloPayload(connection);
    const size_t helloBytes = hello.size();
    queue(stream, Type::hello, helloBytes, 0, std::move(hello));
    connection.helloSent = true;
    if (early)
    {
      queue(stream, Type::op, config.requestBodyBytes, earlyDataFlag);
      connection.lifecycleAck = false;
    }
    return true;
  }

  bool retireFailedStaticServerConnections(uint64_t now, AdapterError& error)
  {
    if (client() || isConnectionOperation(scenario) ||
        scenario == Scenario::closeResetCleanup) return true;
    for (auto& [_, connection] : connections)
    {
      if (connection.retired || connection.connected) continue;
      bool closed = false;
      if (!adapter.connectionIsClosed(connection.id, now, closed, error)) return false;
      if (!closed) continue;
      if (!retireFrameCounts(connection, "failed admission", error)) return false;
      if (!adapter.releaseConnectionWhenClosed(connection.id, now, error)) return false;
      connection.retired = true;
    }
    std::erase_if(connections, [](const auto& item) { return item.second.retired; });
    return true;
  }

  bool pumpConnections(uint64_t now, AdapterError& error)
  {
    // A failed Initial must vacate the logical cohort before its retransmission
    // is accepted, or the successor is assigned beyond the frozen cohort.
    if (!retireFailedStaticServerConnections(now, error)) return false;
    if (!acceptConnections(now, error)) return false;
    if (!retireClosedConnections(now, error)) return false;
    for (auto& [id, connection] : connections)
    {
      (void)id;
      if (connection.retired) continue;
      if (!connection.connected && !adapter.isConnected(connection.id, now, connection.connected, error)) return false;
      if (client() && !openControl(connection, now, error)) return false;
      if (!acceptStreams(connection, now, error)) return false;
    }
    return true;
  }

  bool refreshNegotiatedSettings(AdapterError& error)
  {
    if (hasNegotiatedSettings &&
        (scenario != Scenario::closeResetCleanup ||
         std::ranges::all_of(connections, [this](const auto& item) {
           return !logicalCurrent(item.second) || item.second.treatmentVerified;
         })))
      return true;
    if (logicalConnectionCount() != connectionCount ||
        !std::ranges::all_of(connections, [this](const auto& item) {
          const auto& connection = item.second;
          return !logicalCurrent(connection) || (connection.connected &&
              (client() && !isConnectionOperation(scenario) ?
                   connection.helloAcknowledged : connection.hasControlStream));
        }))
      return true;

    auto current = adapter.snapshotNegotiatedSettings();
    // Early-data servers may admit application streams before the transport's
    // post-handshake evidence callbacks have completed. Keep driving until the
    // evidence exists; snapshot validation still fails closed at result time.
    if (!current.available) return true;
    std::string mismatchReason;
    if (!negotiatedSettingsMatch(current, config, mismatchReason))
    {
      error = {1, "established connection set lacks exact negotiated treatment evidence: " +
                      mismatchReason};
      return false;
    }
    const auto canonical = negotiatedSettingsJson(current, true, {});
    if (hasNegotiatedSettings && canonical != negotiatedSettingsCanonical)
    {
      error = {1, "established connection set changed negotiated treatment evidence"};
      return false;
    }
    if (!hasNegotiatedSettings)
    {
      negotiatedSettings = std::move(current);
      negotiatedSettingsCanonical = canonical;
      hasNegotiatedSettings = true;
    }
    if (scenario == Scenario::closeResetCleanup)
      for (auto& [_, connection] : connections)
        if (logicalCurrent(connection)) connection.treatmentVerified = true;
    return true;
  }

  bool retireClosedConnections(uint64_t now, AdapterError& error)
  {
    if (!isConnectionOperation(scenario) && scenario != Scenario::closeResetCleanup)
      return true;
    struct Restart {
      uint32_t ordinal;
      uint64_t operationSequence;
    };
    std::vector<Restart> restarts;
    for (auto& [id, connection] : connections)
    {
      (void)id;
      // An accepted connection can close before the adapter ever reports it
      // connected.  It still has to be retired before stream polling.
      if (connection.retired) continue;
      bool closed = scenario == Scenario::closeResetCleanup &&
          connection.cleanupCloseObserved;
      if (!closed && !adapter.connectionIsClosed(connection.id, now, closed, error))
        return false;
      if (!closed) continue;
      // A replacement can close before its QPF2 control stream arrives.  It
      // never entered the cleanup state machine and has no peer terminal fact
      // to reconcile, but still falls through to native retirement below.
      if (scenario == Scenario::closeResetCleanup && connection.hasControlStream)
      {
        if (!connection.cleanupCloseObserved)
        {
          const auto closing = std::ranges::find_if(connection.streams, [](const auto& item) {
            const auto& stream = item.second;
            return stream.kind == StreamKind::operation && stream.terminalFlags == 0 &&
                !stream.operationComplete;
          });
          if (closing != connection.streams.end() && closing->second.terminalIssued &&
              !completeCleanupTerminal(connection, closing->second, now, error)) return false;
          if (closing != connection.streams.end() && !closing->second.terminalIssued)
            continue;
        }
        if (!connection.cleanupCloseObserved)
        {
          error = {1, "close_reset_cleanup connection " + std::to_string(connection.id) +
                          " closed without matching peer terminal evidence"};
          return false;
        }
        if (!retireValidated(connection, "cleanup", error)) return false;
        // A connection-close treatment can finish after the measurement
        // boundary.  Replace that connection even after admission stops so
        // the frozen logical cohort still has a control stream for the
        // unmeasured STOP/STOP_ACK reconciliation phase.
        if (client())
          restarts.push_back({connection.ordinal, connection.nextOperationSequence});
      }
      if (!retireFrameCounts(connection, "closed", error)) return false;
      if (!adapter.releaseConnectionWhenClosed(connection.id, now, error)) return false;
      connection.retired = true;
    }
    std::erase_if(connections, [](const auto& item) { return item.second.retired; });
    for (const auto& restart : restarts)
      if (!beginConnection(restart.ordinal, restart.operationSequence, {}, false, now, error))
        return false;
    return true;
  }

  bool completeTransmittedFrame(Connection& connection, Stream& stream,
                                AdapterError& error)
  {
    const Type type = stream.transmit.front().header.type;
    if (type == Type::stop) connection.stopOffered = true;
    if (!barrier(type))
    {
      if (connection.sentApplicationFrames == std::numeric_limits<uint64_t>::max())
      {
        error = {1, "QPF2 sent application-frame counter exhausted"};
        return false;
      }
      ++connection.sentApplicationFrames;
    }
    stream.transmit.pop_front();
    return true;
  }

  bool writeFrame(Connection& connection, Stream& stream, uint64_t now, AdapterError& error)
  {
    if (stream.transmit.empty()) return true;
    auto& frame = stream.transmit.front();
    std::span<const std::byte> offered;
    const bool header = frame.headerOffset < frame.encoded.size();
    if (header)
    {
      const auto* data = reinterpret_cast<const std::byte*>(frame.encoded.data() + frame.headerOffset);
      offered = {data, frame.encoded.size() - frame.headerOffset};
    }
    else
    {
      const uint64_t remaining = frame.header.payloadLength - frame.payloadOffset;
      if (remaining == 0)
        return completeTransmittedFrame(connection, stream, error);
      size_t length = static_cast<size_t>(std::min<uint64_t>(remaining, applicationBuffer.size()));
      if (frame.deterministic)
      {
        constexpr size_t perStreamGenerationSlice = 16 * 1024;
        if (frame.generated.empty())
        {
          length = std::min({length, writeBudget, perStreamGenerationSlice});
          if (length == 0) return true;
          frame.generated.resize(length);
          for (size_t index = 0; index < length; ++index)
            frame.generated[index] = deterministicPayloadByte(
                nonce, frame.header.sequence, frame.payloadOffset + index);
          frame.generatedOffset = 0;
          writeBudget -= length;
        }
        const auto* data = reinterpret_cast<const std::byte*>(
            frame.generated.data() + frame.generatedOffset);
        offered = {data, frame.generated.size() - frame.generatedOffset};
      }
      else
      {
        const auto* data = reinterpret_cast<const std::byte*>(frame.literal.data() + frame.payloadOffset);
        offered = {data, length};
      }
    }
    size_t written = 0;
    if (!adapter.writeStream(connection.id, stream.id, offered, now, written, error)) return false;
    if (written > offered.size())
    {
      error = {1, "adapter accepted beyond the offered stream suffix"};
      return false;
    }
    if (written == 0)
    {
      if (window.contains(now)) counters.subwindows[window.subwindow(now)].blockedEvents++;
      if (scenario == Scenario::flowControl && !stream.flowControlWriteBlocked)
      {
        stream.flowControlWriteBlocked = true;
        ++flowControlWriteBlockedEvents;
      }
      return true;
    }
    if (flowControlBlockSeen || stream.flowControlWriteBlocked)
      flowControlRecoveryEvidence = true;
    stream.flowControlWriteBlocked = false;
    counters.accepted += written;
    if (header) frame.headerOffset += written;
    else
    {
      frame.payloadOffset += written;
      if (frame.deterministic)
      {
        frame.generatedOffset += written;
        if (frame.generatedOffset == frame.generated.size())
        {
          frame.generated.clear();
          frame.generatedOffset = 0;
        }
      }
    }
    if (frame.headerOffset == frame.encoded.size() && frame.payloadOffset == frame.header.payloadLength)
      return completeTransmittedFrame(connection, stream, error);
    return true;
  }

  bool validateHeader(Stream& stream, const Header& header, AdapterError& error)
  {
    if (header.scenario != scenario || header.trialNonce != nonce ||
        header.sequence != stream.receiveSequence + 1)
    {
      error = {1, "QPF2 identity or sequence mismatch"};
      return false;
    }
    if (header.payloadLength > applicationBuffer.size() ||
        ((header.type == Type::stop || header.type == Type::stopAck) &&
         header.payloadLength != 64))
    {
      error = {1, "QPF2 payload length exceeds the common application bound"};
      return false;
    }
    bool shape = false;
    switch (header.type)
    {
      case Type::hello:
      case Type::helloAck:
        shape = header.flags == 0 &&
            header.payloadLength == identity.size() +
                (carriesConnectionIdentity(scenario) ? 2 * sizeof(uint64_t) : 0);
        break;
      case Type::request:
        shape = isTransfer(scenario) && header.payloadLength == config.requestBodyBytes &&
            header.flags == (isUpload(scenario) ? uploadFlag : 0);
        break;
      case Type::data:
        shape = isTransfer(scenario) && header.payloadLength == config.bulkChunkBytes &&
            (header.flags == 0 || (isUpload(scenario) && header.flags == uploadFlag));
        break;
      case Type::op:
        if (scenario == Scenario::smallPayloadPps)
          shape = header.flags == 0 && header.payloadLength == config.operationBodyBytes;
        else if (scenario == Scenario::reqresp)
          shape = header.flags == 0 && header.payloadLength == config.requestBodyBytes;
        else if (scenario == Scenario::streamChurn)
          shape = header.flags == 0 && header.payloadLength == config.operationBodyBytes;
        else if (scenario == Scenario::closeResetCleanup)
          shape = header.payloadLength == config.operationBodyBytes &&
              (header.flags == 0 || header.flags == finFlag || header.flags == resetFlag ||
               header.flags == stopSendingFlag);
        else if (scenario == Scenario::zeroRttReqresp)
          shape = header.flags == earlyDataFlag && header.payloadLength == config.requestBodyBytes;
        break;
      case Type::opAck:
        shape = (scenario == Scenario::reqresp || scenario == Scenario::zeroRttReqresp) ?
            header.flags == 0 && header.payloadLength == config.responseBodyBytes :
            (scenario == Scenario::streamChurn ?
                 header.flags == 0 && header.payloadLength == config.operationBodyBytes :
                 (scenario == Scenario::closeResetCleanup &&
                  header.payloadLength == config.operationBodyBytes &&
                  (header.flags == 0 || header.flags == finFlag || header.flags == resetFlag ||
                   header.flags == stopSendingFlag)));
        break;
      case Type::terminalReady:
        shape = scenario == Scenario::closeResetCleanup && header.payloadLength == 0 &&
            (header.flags == 0 || header.flags == finFlag || header.flags == resetFlag ||
             header.flags == stopSendingFlag);
        break;
      case Type::stop:
      case Type::stopAck: shape = header.flags == 0 && header.payloadLength == 64; break;
      case Type::error: shape = header.flags == 0; break;
    }
    if (!shape)
    {
      error = {1, "QPF2 frame type, flags, or payload length violates the scenario state machine"};
      return false;
    }
    return true;
  }

  bool handleFrame(Connection& connection, Stream& stream, const Header& header,
                   std::span<const uint8_t> body, uint64_t now, AdapterError& error)
  {
    stream.receiveSequence = header.sequence;
    if (stream.kind == StreamKind::unknown)
    {
      if (header.type == Type::hello) stream.kind = StreamKind::control;
      else if (header.type == Type::data) stream.kind = StreamKind::data;
      else if (header.type == Type::op || header.type == Type::opAck ||
               header.type == Type::terminalReady) stream.kind = StreamKind::operation;
      else
      {
        error = {1, "QPF2 first frame cannot classify the stream"};
        return false;
      }
    }
    switch (header.type)
    {
      case Type::hello:
        if (!std::ranges::equal(body.first(identity.size()), identity))
        {
          error = {1, "QPF2 HELLO trial/cell identity mismatch"};
          return false;
        }
        if (carriesConnectionIdentity(scenario))
        {
          const uint64_t ordinal = read64(body, identity.size());
          const uint64_t operationSequence =
              read64(body, identity.size() + sizeof(uint64_t));
          if (ordinal < connectionFirst ||
              ordinal >= static_cast<uint64_t>(connectionFirst) + connectionCount)
          {
            error = {1, "QPF2 lifecycle HELLO ordinal is outside the frozen cohort"};
            return false;
          }
          if (connectionCount == 0 || operationSequence < ordinal ||
              (operationSequence - ordinal) % connectionCount != 0)
          {
            error = {1, "QPF2 lifecycle HELLO sequence is outside the ordinal generation"};
            return false;
          }
          connection.ordinal = static_cast<uint32_t>(ordinal);
          connection.nextOperationSequence = operationSequence;
          connection.lifecycleOperationSequence = operationSequence;
          auto [latest, firstGeneration] = latestLifecycleSequence.try_emplace(
              connection.ordinal, operationSequence);
          if (!firstGeneration && operationSequence <= latest->second)
          {
            connection.superseded = true;
            return adapter.closeConnection(connection.id, 0, now, error);
          }
          latest->second = operationSequence;
          auto predecessor = std::ranges::find_if(connections, [&](const auto& item) {
            return item.first != connection.id && logicalCurrent(item.second) &&
                item.second.ordinal == ordinal;
          });
          if (predecessor != connections.end())
          {
            if ((scenario != Scenario::closeResetCleanup ||
                 !predecessor->second.cleanupCloseObserved) &&
                !adapter.closeConnection(predecessor->first, 0, now, error)) return false;
            predecessor->second.superseded = true;
          }
        }
        connection.controlStream = stream.id;
        connection.hasControlStream = true;
        {
          auto hello = helloPayload(connection);
          const size_t helloBytes = hello.size();
          queue(stream, Type::helloAck, helloBytes, 0, std::move(hello));
        }
        return true;
      case Type::helloAck:
        if (!client() || !std::ranges::equal(body, helloPayload(connection)))
        {
          error = {1, "QPF2 HELLO_ACK trial/cell identity mismatch"};
          return false;
        }
        connection.helloAcknowledged = true;
        return true;
      case Type::request:
        connection.requestReceived = true;
        connection.desiredDataStreams = static_cast<uint32_t>(config.activeStreamsPerConnection);
        return true;
      case Type::data:
        return true;
      case Type::op:
        if (scenario == Scenario::smallPayloadPps)
        {
          uint64_t ordinal = 0;
          uint64_t startRawNs = 0;
          if (!validateSmallPayloadOperation(body, nonce, header.sequence, ordinal, startRawNs) ||
              ordinal >= config.connectionCount || header.sequence == 0 || startRawNs > now)
          {
            ++counters.payloadErrors;
            error = {1, "QPF2 small-payload timing prefix is invalid"};
            return false;
          }
          const uint64_t round = header.sequence - 1;
          if (config.connectionCount != 0 &&
              round > (std::numeric_limits<uint64_t>::max() - ordinal) / config.connectionCount)
          {
            error = {1, "QPF2 small-payload operation sequence overflow"};
            return false;
          }
          const uint64_t operationSequence = round * config.connectionCount + ordinal;
          if (!receivedTailSequences.insert(operationSequence).second)
          {
            ++counters.duplicates;
            error = {1, "duplicate QPF2 small-payload operation identity"};
            return false;
          }
          recordTailStart(startRawNs);
          recordTail(operationSequence, startRawNs, now);
          if (window.contains(startRawNs) && now >= window.endRawNs) ++tailCensoredOperations;
          if (window.contains(now))
          {
            ++counters.peerValidated;
            ++connection.localValidated;
            ++counters.subwindows[window.subwindow(now)].validatedUnits;
          }
          else if (now >= window.endRawNs) ++counters.completedAfterEnd;
          return true;
        }
        if (scenario == Scenario::zeroRttReqresp && (header.flags & earlyDataFlag) == 0)
        {
          error = {1, "zero_rtt_reqresp request lacks early-data flag"};
          return false;
        }
        queue(stream, Type::opAck, config.responseBodyBytes ? config.responseBodyBytes : config.operationBodyBytes,
              header.flags & (finFlag | resetFlag | stopSendingFlag));
        stream.finishAfterTransmit =
            scenario != Scenario::closeResetCleanup && scenario != Scenario::zeroRttReqresp;
        if (scenario == Scenario::closeResetCleanup)
        {
          stream.terminalAction = true;
          stream.terminalFlags = header.flags;
          stream.operationStartRawNs = now;
        }
        return true;
      case Type::opAck: {
        if (!client())
        {
          error = {1, "server received an unsolicited QPF2 OP_ACK"};
          return false;
        }
        const bool completionInside = window.contains(now);
        if (isFreshStreamOperation(scenario))
        {
          if (scenario == Scenario::closeResetCleanup)
          {
            if (header.flags != stream.terminalFlags || stream.terminalObserver)
            {
              ++counters.duplicates;
              error = {1, "close_reset_cleanup OP_ACK terminal action mismatch or duplicate"};
              return false;
            }
            stream.terminalObserver = true;
            stream.terminalIssued = true;
            queue(stream, Type::terminalReady, 0, header.flags);
            return true;
          }
          recordTail(stream.operationSequence, stream.operationStartRawNs, now);
          if (completionInside)
          {
            ++counters.peerValidated;
            ++connection.localValidated;
            ++counters.subwindows[window.subwindow(now)].validatedUnits;
          }
          else if (now >= window.endRawNs) ++counters.completedAfterEnd;
          stream.operationComplete = true;
          if (connection.operationInFlight) --connection.operationInFlight;
        }
        else if (scenario == Scenario::zeroRttReqresp)
        {
          connection.lifecycleAck = true;
        }
        return true;
      }
      case Type::terminalReady:
        if (client() || scenario != Scenario::closeResetCleanup ||
            header.flags != stream.terminalFlags || stream.terminalReady ||
            stream.terminalIssued)
        {
          ++counters.duplicates;
          error = {1, "close_reset_cleanup TERMINAL_READY mismatch or duplicate"};
          return false;
        }
        stream.terminalReady = true;
        return true;
      case Type::stop:
        if (body.size() != 64)
        {
          error = {1, "QPF2 STOP counter length mismatch"};
          return false;
        }
        if (connection.stopReceived || connection.peerFinalSentFramesKnown)
        {
          ++counters.duplicates;
          error = {1, "duplicate QPF2 STOP"};
          return false;
        }
        connection.stopReceived = true;
        connection.peerFinalSentFrames = read64(body, 8);
        connection.peerFinalSentFramesKnown = true;
        return true;
      case Type::stopAck:
        if (body.size() != 64)
        {
          error = {1, "QPF2 STOP_ACK counter length mismatch"};
          return false;
        }
        if (connection.stopAcknowledged)
        {
          ++counters.duplicates;
          error = {1, "duplicate QPF2 STOP_ACK"};
          return false;
        }
        if (const uint64_t validated = read64(body, 0);
            validated > std::numeric_limits<uint64_t>::max() - peerValidated)
        {
          error = {1, "QPF2 peer reconciled counter overflow"};
          return false;
        }
        else
        {
          peerValidated += validated;
        }
        connection.stopAcknowledged = true;
        return true;
      case Type::error:
        error = {1, "peer reported a QPF2 application error"};
        return false;
    }
    error = {1, "unknown QPF2 frame type"};
    return false;
  }

  bool feed(Connection& connection, Stream& stream, std::span<const uint8_t> bytes,
            uint64_t now, AdapterError& error)
  {
    while (!bytes.empty())
    {
      auto& receive = stream.receive;
      if (!receive.haveHeader)
      {
        const size_t take = std::min(bytes.size(), receive.encoded.size() - receive.headerOffset);
        std::copy_n(bytes.begin(), take, receive.encoded.begin() + receive.headerOffset);
        receive.headerOffset += take;
        bytes = bytes.subspan(take);
        if (receive.headerOffset != receive.encoded.size()) continue;
        const auto decoded = decodeHeader(receive.encoded);
        if (!decoded)
        {
          error = {1, decoded.error};
          return false;
        }
        if (!validateHeader(stream, decoded.header, error)) return false;
        receive.header = decoded.header;
        receive.haveHeader = true;
        receive.payloadOffset = 0;
        receive.literal.clear();
        if (literalBody(receive.header.type)) receive.literal.reserve(static_cast<size_t>(receive.header.payloadLength));
      }
      const uint64_t remaining = receive.header.payloadLength - receive.payloadOffset;
      const size_t take = static_cast<size_t>(std::min<uint64_t>(remaining, bytes.size()));
      const auto fragment = bytes.first(take);
      if (literalBody(receive.header.type)) receive.literal.insert(receive.literal.end(), fragment.begin(), fragment.end());
      else if (!validatePayload(fragment, nonce, receive.header.sequence, receive.payloadOffset))
      {
        ++counters.payloadErrors;
        error = {1, "QPF2 deterministic payload mismatch"};
        return false;
      }
      if (receive.header.type == Type::data && !fragment.empty())
      {
        if (window.contains(now))
        {
          counters.peerValidated += fragment.size();
          connection.localValidated += fragment.size();
          counters.subwindows[window.subwindow(now)].validatedUnits += fragment.size();
        }
        else if (now >= window.endRawNs)
          counters.completedAfterEnd += fragment.size();
      }
      receive.payloadOffset += take;
      bytes = bytes.subspan(take);
      if (receive.payloadOffset != receive.header.payloadLength) continue;
      const auto body = std::span<const uint8_t>(receive.literal);
      if (!handleFrame(connection, stream, receive.header, body, now, error)) return false;
      if (!barrier(receive.header.type))
      {
        if (connection.receivedApplicationFrames == std::numeric_limits<uint64_t>::max())
        {
          error = {1, "QPF2 received application-frame counter exhausted"};
          return false;
        }
        ++connection.receivedApplicationFrames;
      }
      receive = {};
    }
    return true;
  }

  bool readStream(Connection& connection, Stream& stream, uint64_t now, AdapterError& error)
  {
    if (stream.remoteFinished) return true;
    if (readBudget == 0) return true;
    if (scenario == Scenario::flowControl && client() && stream.kind == StreamKind::data &&
        now < window.warmupStartRawNs + (window.startRawNs - window.warmupStartRawNs) / 2)
      return true;
    size_t count = 0;
    bool finished = false;
    const size_t offered = std::min({readBudget, receiveBuffer.size(), size_t {2'048}});
    if (!adapter.consumeStreamData(connection.id, stream.id,
                                   std::span<std::byte>(receiveBuffer).first(offered),
                                   now, count, finished, error)) return false;
    if (count > receiveBuffer.size())
    {
      error = {1, "adapter read beyond the borrowed stream buffer"};
      return false;
    }
    if (count && !feed(connection, stream,
                       {reinterpret_cast<const uint8_t*>(receiveBuffer.data()), count}, now, error)) return false;
    readBudget -= count;
    stream.remoteFinished = stream.remoteFinished || finished;
    return true;
  }

  bool openDataStreams(Connection& connection, uint64_t now, AdapterError& error)
  {
    const bool localSender = (client() && isUpload(scenario)) || (!client() && isDownload(scenario)) ||
        (client() && scenario == Scenario::bidi);
    if (!localSender || (!connection.requestSent && !connection.requestReceived)) return true;
    size_t existing = 0;
    for (const auto& [id, stream] : connection.streams)
    {
      (void)id;
      if (stream.kind == StreamKind::data) ++existing;
    }
    while (existing < config.activeStreamsPerConnection)
    {
      uint64_t id = 0;
      const auto status = adapter.openBidirectionalStream(connection.id, now, id, error);
      if (status == PrimitiveStatus::fatal) return false;
      if (status == PrimitiveStatus::wouldBlock)
      {
        if (window.contains(now)) counters.subwindows[window.subwindow(now)].blockedEvents++;
        return true;
      }
      addStream(connection, id, StreamKind::data);
      ++existing;
    }
    return true;
  }

  bool driveTransfer(Connection& connection, uint64_t now, AdapterError& error)
  {
    if (!connection.helloAcknowledged && client()) return true;
    if (client() && !connection.requestSent && now >= window.warmupStartRawNs)
    {
      auto found = connection.streams.find(connection.controlStream);
      if (found == connection.streams.end()) return true;
      const uint16_t flags = isUpload(scenario) ? uploadFlag : 0;
      queue(found->second, Type::request, config.requestBodyBytes, flags);
      connection.requestSent = true;
      if (scenario == Scenario::bidi) connection.desiredDataStreams = 1;
    }
    if (!openDataStreams(connection, now, error)) return false;
    if (!admitting || now < window.warmupStartRawNs) return true;
    const bool localSender = (client() && isUpload(scenario)) || (!client() && isDownload(scenario)) || scenario == Scenario::bidi;
    if (!localSender) return true;
    for (auto& [id, stream] : connection.streams)
    {
      (void)id;
      if (stream.kind == StreamKind::data && stream.transmit.empty())
        queue(stream, Type::data, config.bulkChunkBytes, isUpload(scenario) ? uploadFlag : 0);
    }
    return true;
  }

  uint16_t cleanupFlags(uint64_t operation) const noexcept
  {
    // Operation IDs are striped by connection ordinal and advance by the
    // frozen connection count. Rotate the stripe as well so no connection is
    // permanently coupled to one terminal treatment.
    const uint64_t round = operation / config.connectionCount;
    const uint64_t ordinal = operation % config.connectionCount;
    switch ((round + ordinal) % 4)
    {
      case 0: return finFlag;
      case 1: return resetFlag;
      case 2: return stopSendingFlag;
      default: return 0;
    }
  }

  size_t cleanupStratum(uint16_t flags) const
  {
    if (flags == finFlag) return 0;
    if (flags == resetFlag) return 1;
    if (flags == stopSendingFlag) return 2;
    if (flags == 0) return 3;
    throw std::logic_error("invalid close_reset_cleanup terminal flags");
  }

  bool completeCleanupTerminal(Connection& connection, Stream& stream, uint64_t now,
                               AdapterError& error)
  {
    bool observed = !client();
    if (!client() &&
        (stream.terminalFlags == finFlag || stream.terminalFlags == resetFlag))
      observed = stream.remoteFinished;
    if (client())
    {
      PeerTerminalFacts facts;
      if (!adapter.peerTerminalFacts(connection.id, stream.id, now, facts, error)) return false;
      if (!facts.available)
      {
        error = {1, "adapter did not expose close_reset_cleanup peer terminal facts"};
        return false;
      }
      if (stream.terminalFlags == finFlag) observed = facts.fin;
      else if (stream.terminalFlags == resetFlag)
        observed = facts.resetStream && facts.resetStreamError == cleanupApplicationError;
      else if (stream.terminalFlags == stopSendingFlag)
        observed = facts.stopSending && facts.stopSendingError == cleanupApplicationError;
      else if (stream.terminalFlags == 0) observed = facts.connectionClose;
    }
    if (!observed) return true;

    // FIN and RESET_STREAM terminate only the actor's send half. Once that
    // peer terminal fact has been observed, close the observer's already-used
    // request half. The actor retains the stream until that complementary FIN
    // is received above, allowing the transport to retire the bidirectional
    // stream and replenish credit. This cleanup is deliberately after
    // evidence; it is never used to infer the measured peer event.
    if (client() &&
        (stream.terminalFlags == finFlag || stream.terminalFlags == resetFlag) &&
        !adapter.finishStream(connection.id, stream.id, now, error)) return false;
    // An observed STOP_SENDING asks the local sender to terminate its half;
    // RESET_STREAM does that without serving as evidence for the peer event.
    if (client() && stream.terminalFlags == stopSendingFlag &&
        !adapter.resetStream(
            connection.id, stream.id, cleanupApplicationError, now, error)) return false;

    if (client()) recordTail(stream.operationSequence, stream.operationStartRawNs, now);
    if (window.contains(now))
    {
      ++counters.peerValidated;
      ++connection.localValidated;
      ++counters.subwindows[window.subwindow(now)].validatedUnits;
      ++cleanupStrata[cleanupStratum(stream.terminalFlags)];
    }
    else if (now >= window.endRawNs) ++counters.completedAfterEnd;
    stream.operationComplete = true;
    if (client() && connection.operationInFlight) --connection.operationInFlight;
    if (stream.terminalFlags == 0)
    {
      if (!retireValidated(connection, "observed cleanup-close", error)) return false;
      connection.cleanupCloseObserved = true;
    }
    return true;
  }

  bool driveOperation(Connection& connection, uint64_t now, AdapterError& error)
  {
    if (!client() || !connection.helloAcknowledged || !admitting || now < window.warmupStartRawNs) return true;
    if (scenario == Scenario::closeResetCleanup && !connection.treatmentVerified)
      return true;
    if (scenario == Scenario::smallPayloadPps)
    {
      auto found = std::ranges::find_if(connection.streams, [](const auto& item) {
        return item.second.kind == StreamKind::data;
      });
      if (found == connection.streams.end())
      {
        uint64_t id = 0;
        const auto status = adapter.openBidirectionalStream(connection.id, now, id, error);
        if (status == PrimitiveStatus::fatal) return false;
        if (status == PrimitiveStatus::wouldBlock)
        {
          if (window.contains(now))
            counters.subwindows[window.subwindow(now)].blockedEvents++;
          return true;
        }
        addStream(connection, id, StreamKind::data);
        found = connection.streams.find(id);
      }
      auto& stream = found->second;
      if (stream.transmit.empty())
      {
        const uint64_t sequence = stream.sendSequence + 1;
        queue(stream, Type::op, config.operationBodyBytes, 0,
              makeSmallPayloadOperation(nonce, sequence, connection.ordinal, now));
        recordTailStart(now);
      }
      return true;
    }
    if (!isFreshStreamOperation(scenario) || connection.operationInFlight) return true;
    if (scenario == Scenario::closeResetCleanup && std::ranges::any_of(
        connection.streams, [](const auto& item) {
          return item.second.terminalAction && !item.second.terminalIssued;
        })) return true;
    uint64_t id = 0;
    const auto status = adapter.openBidirectionalStream(connection.id, now, id, error);
    if (status == PrimitiveStatus::fatal) return false;
    if (status == PrimitiveStatus::wouldBlock)
    {
      if (window.contains(now)) counters.subwindows[window.subwindow(now)].blockedEvents++;
      return true;
    }
    auto& stream = addStream(connection, id, StreamKind::operation);
    stream.operationSequence = connection.nextOperationSequence;
    connection.nextOperationSequence += config.connectionCount;
    stream.operationStartRawNs = now;
    recordTailStart(now);
    const uint16_t flags = scenario == Scenario::closeResetCleanup ? cleanupFlags(stream.operationSequence) : 0;
    queue(stream, Type::op, config.operationBodyBytes ? config.operationBodyBytes : config.requestBodyBytes, flags);
    stream.terminalFlags = flags;
    stream.finishAfterTransmit = scenario != Scenario::closeResetCleanup;
    ++connection.operationInFlight;
    return true;
  }

  bool receiveDatagrams(Connection& connection, uint64_t now, AdapterError& error)
  {
    for (;;)
    {
      size_t count = 0;
      const auto status = adapter.consumeDatagram(connection.id, receiveBuffer, now, count, error);
      if (status == PrimitiveStatus::fatal) return false;
      if (status == PrimitiveStatus::wouldBlock) return true;
      if (count != 24 + config.datagramBodyBytes)
      {
        error = {1, "QPF2 DATAGRAM length mismatch"};
        return false;
      }
      const auto bytes = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(receiveBuffer.data()), count);
      const uint64_t sequence = read64(bytes, 16);
      if (!validateDatagram(bytes, scenario, nonce, sequence))
      {
        error = {1, "QPF2 DATAGRAM validation failed"};
        return false;
      }
      if (client())
      {
        const auto pending = std::ranges::find_if(
            connection.datagramsOutstanding,
            [sequence](const auto& item) { return item.first == sequence; });
        if (pending == connection.datagramsOutstanding.end())
        {
          if (!admitting && datagramDrainFinished) continue;
          ++counters.duplicates;
          error = {1, "unexpected or duplicate QPF2 DATAGRAM echo"};
          return false;
        }
        const uint64_t startRawNs = pending->second;
        if (pending == connection.datagramsOutstanding.begin())
          connection.datagramsOutstanding.pop_front();
        else
          connection.datagramsOutstanding.erase(pending);
        if (config.connectionCount != 0 &&
            sequence - 1 > (std::numeric_limits<uint64_t>::max() - connection.ordinal) /
                               config.connectionCount)
        {
          error = {1, "QPF2 DATAGRAM operation sequence overflow"};
          return false;
        }
        const uint64_t operationSequence = (sequence - 1) * config.connectionCount + connection.ordinal;
        recordTail(operationSequence, startRawNs, now);
        if (window.contains(now))
        {
          ++counters.peerValidated;
          ++connection.localValidated;
          ++counters.subwindows[window.subwindow(now)].validatedUnits;
        }
        else if (now >= window.endRawNs) ++counters.completedAfterEnd;
      }
      else
      {
        connection.datagramsToEcho.emplace_back(bytes.begin(), bytes.end());
      }
    }
  }

  bool driveDatagrams(Connection& connection, uint64_t now, AdapterError& error)
  {
    if (!receiveDatagrams(connection, now, error)) return false;
    while (!connection.datagramsToEcho.empty())
    {
      const auto& value = connection.datagramsToEcho.front();
      const auto status = adapter.sendDatagram(connection.id,
          {reinterpret_cast<const std::byte*>(value.data()), value.size()}, now, error);
      if (status == PrimitiveStatus::fatal) return false;
      if (status == PrimitiveStatus::wouldBlock) break;
      connection.datagramsToEcho.pop_front();
    }
    if (!client() || !connection.helloAcknowledged || !admitting || now < window.warmupStartRawNs) return true;
    while (connection.datagramsOutstanding.size() < config.datagramMaxUnreturnedPerConnection)
    {
      const uint64_t sequence = connection.nextDatagramSequence++;
      auto value = makeDatagram(scenario, nonce, sequence);
      const auto status = adapter.sendDatagram(connection.id,
          {reinterpret_cast<const std::byte*>(value.data()), value.size()}, now, error);
      if (status == PrimitiveStatus::fatal) return false;
      if (status == PrimitiveStatus::wouldBlock)
      {
        --connection.nextDatagramSequence;
        if (window.contains(now)) counters.subwindows[window.subwindow(now)].blockedEvents++;
        break;
      }
      connection.datagramsOutstanding.emplace_back(sequence, now);
      recordTailStart(now);
      ++counters.admitted;
    }
    return true;
  }

  bool exportTicket(Connection& connection, uint64_t now, std::vector<std::byte>& ticket,
                    AdapterError& error)
  {
    size_t written = 0;
    const auto status = adapter.exportResumptionState(connection.id, now, ticketBuffer, written, error);
    if (status == PrimitiveStatus::fatal) return false;
    if (status == PrimitiveStatus::wouldBlock) return true;
    ticket.assign(ticketBuffer.begin(), ticketBuffer.begin() + written);
    return true;
  }

  bool driveLifecycle(uint64_t now, AdapterError& error)
  {
    if (!client() || !admitting || !hasNegotiatedSettings || now >= window.endRawNs)
      return true;
    struct Restart {
      uint64_t id;
      uint32_t ordinal;
      uint64_t operationSequence;
      std::vector<std::byte> ticket;
      bool zeroRtt;
    };
    std::vector<Restart> restarts;
    for (auto& [id, connection] : connections)
    {
      if (connection.retired) continue;
      if (!connection.helloAcknowledged)
      {
        if (scenario != Scenario::zeroRttReqresp || !connection.connected ||
            !connection.importedTicket) continue;
        bool attempted = false, accepted = false, rejected = false;
        if (!adapter.zeroRttAttempted(id, now, attempted, error) ||
            !adapter.zeroRttAccepted(id, now, accepted, error) ||
            !adapter.zeroRttRejected(id, now, rejected, error)) return false;
        if (attempted && accepted && !rejected) continue;
        error = {1, "zero_rtt_reqresp connection " + std::to_string(id) +
                        " completed its handshake without accepted early data"};
        return false;
      }
      bool qualified = scenario == Scenario::connect;
      if (scenario == Scenario::resumedConnect)
      {
        bool resumed = false;
        if (!adapter.connectionResumed(id, now, resumed, error)) return false;
        qualified = resumed;
      }
      if (scenario == Scenario::zeroRttReqresp)
      {
        if (!connection.lifecycleAck) continue;
        bool attempted = false, accepted = false, rejected = false;
        if (!adapter.zeroRttAttempted(id, now, attempted, error) ||
            !adapter.zeroRttAccepted(id, now, accepted, error) ||
            !adapter.zeroRttRejected(id, now, rejected, error)) return false;
        qualified = attempted && accepted && !rejected && connection.lifecycleAck;
      }
      std::vector<std::byte> successor;
      if (scenario != Scenario::connect && !exportTicket(connection, now, successor, error)) return false;
      if (scenario != Scenario::connect && successor.empty()) continue;
      if (qualified && admitting && window.contains(now))
      {
        recordTail(connection.lifecycleOperationSequence, connection.lifecycleStartRawNs, now);
        ++counters.peerValidated;
        ++connection.localValidated;
        ++counters.subwindows[window.subwindow(now)].validatedUnits;
      }
      else if (qualified && now >= window.endRawNs)
      {
        if (!tailFinalized && window.contains(connection.lifecycleStartRawNs)) ++tailCensoredOperations;
        ++counters.completedAfterEnd;
      }
      if (!qualified && connection.importedTicket && now >= window.startRawNs)
      {
        ++failed;
        recordTailFailure(connection.lifecycleStartRawNs, now);
      }
      if (!adapter.closeConnection(id, 0, now, error)) return false;
      if (!adapter.releaseConnectionWhenClosed(id, now, error)) return false;
      if (!retireValidated(connection, "lifecycle", error)) return false;
      if (!retireFrameCounts(connection, "lifecycle", error)) return false;
      connection.retired = true;
      if (admitting)
      {
        if (connection.lifecycleOperationSequence >
            std::numeric_limits<uint64_t>::max() - config.connectionCount)
        {
          error = {1, "QPF2 lifecycle operation sequence exhausted"};
          return false;
        }
        restarts.push_back({id, connection.ordinal,
                            connection.lifecycleOperationSequence + config.connectionCount,
                            std::move(successor), scenario == Scenario::zeroRttReqresp});
      }
    }
    std::erase_if(connections, [](const auto& item) { return item.second.retired; });
    for (auto& restart : restarts)
      if (!beginConnection(restart.ordinal, restart.operationSequence, restart.ticket,
                           restart.zeroRtt, now, error)) return false;
    return true;
  }

  bool pumpStreams(uint64_t now, AdapterError& error)
  {
    for (auto& [connectionId, connection] : connections)
    {
      (void)connectionId;
      if (connection.retired) continue;
      for (auto& [streamId, stream] : connection.streams)
      {
        (void)streamId;
        if (!readStream(connection, stream, now, error)) return false;
      }
      if (isTransfer(scenario) && !driveTransfer(connection, now, error)) return false;
      if ((scenario == Scenario::smallPayloadPps || isFreshStreamOperation(scenario)) &&
          !driveOperation(connection, now, error)) return false;
      if (scenario == Scenario::datagram && !driveDatagrams(connection, now, error)) return false;
      for (auto& [streamId, stream] : connection.streams)
      {
        (void)streamId;
        if (!writeFrame(connection, stream, now, error)) return false;
        if (stream.terminalAction && stream.transmit.empty() && stream.terminalReady &&
            !stream.terminalIssued)
        {
          if (stream.terminalFlags & finFlag)
          {
            if (!adapter.finishStream(connection.id, stream.id, now, error)) return false;
          }
          else if (stream.terminalFlags & resetFlag)
          {
            if (!adapter.resetStream(
                connection.id, stream.id, cleanupApplicationError, now, error)) return false;
          }
          else if (stream.terminalFlags & stopSendingFlag)
          {
            if (!adapter.stopSending(
                connection.id, stream.id, cleanupApplicationError, now, error)) return false;
            // STOP_SENDING terminates the peer's send half. Close the actor's
            // response half as well so the stream can retire after the peer
            // observes the exact error.
            if (!adapter.finishStream(connection.id, stream.id, now, error)) return false;
          }
          else
          {
            if (!adapter.closeConnection(connection.id, 0, now, error)) return false;
          }
          stream.terminalIssued = true;
        }
        if (scenario == Scenario::closeResetCleanup && stream.terminalIssued &&
            !stream.operationComplete &&
            !completeCleanupTerminal(connection, stream, now, error)) return false;
        if (stream.finishAfterTransmit && stream.transmit.empty() && !stream.finishIssued)
        {
          if (!adapter.finishStream(connection.id, stream.id, now, error)) return false;
          stream.finishIssued = true;
        }
      }
      if (scenario == Scenario::closeResetCleanup)
        std::erase_if(connection.streams, [](const auto& item) {
          const auto& stream = item.second;
          return stream.kind == StreamKind::operation && stream.operationComplete &&
              stream.terminalFlags != 0;
        });
      else if (scenario == Scenario::reqresp || scenario == Scenario::streamChurn)
        std::erase_if(connection.streams, [&](const auto& item) {
          const auto& stream = item.second;
          return stream.kind == StreamKind::operation && stream.remoteFinished &&
              stream.finishIssued && stream.transmit.empty() &&
              (!client() || stream.operationComplete);
        });
    }
    return true;
  }

  bool queueStops(uint64_t now, AdapterError& error)
  {
    if (!stopQueued) return true;
    if (scenario == Scenario::closeResetCleanup && !cleanupOperationsSettled())
      return true;
    if (client() && scenario == Scenario::datagram && !datagramDrainFinished)
    {
      const bool pending = std::ranges::any_of(connections, [](const auto& item) {
        return !item.second.datagramsOutstanding.empty();
      });
      if (pending && now < datagramDrainEndRawNs) return true;
      for (auto& [id, connection] : connections)
      {
        (void)id;
        connection.datagramsOutstanding.clear();
      }
      datagramDrainFinished = true;
    }
    if (client() && isFreshStreamOperation(scenario) &&
        std::ranges::any_of(connections, [this](const auto& item) {
          return logicalCurrent(item.second) && item.second.operationInFlight != 0;
        }))
      return true;
    if (carriesConnectionIdentity(scenario) &&
        (logicalConnectionCount() != connectionCount ||
         std::ranges::any_of(connections, [this](const auto& item) {
           const auto& connection = item.second;
           return logicalCurrent(connection) &&
               (!connection.connected ||
                (client() ? !connection.helloAcknowledged : !connection.hasControlStream));
         })))
      return true;
    for (auto& [id, connection] : connections)
    {
      (void)id;
      if (!logicalCurrent(connection) || connection.cleanupCloseObserved ||
          connection.stopSent || !connection.hasControlStream) continue;
      if (client())
      {
        if (hasPendingApplicationFrames(connection)) continue;
      }
      else
      {
        if (!connection.stopReceived) continue;
        if (!discardsPostWindowApplicationBacklog())
        {
          bool peerFramesReceived = false;
          if (!peerFinalFramesReceived(connection, peerFramesReceived, error))
            return false;
          if (!peerFramesReceived || hasPendingApplicationFrames(connection))
            continue;
        }
      }
      const auto found = connection.streams.find(connection.controlStream);
      if (found == connection.streams.end())
      {
        error = {1, "live connection lacks its QPF2 control stream"};
        return false;
      }
      queue(found->second, Type::stop, 64, 0, counterPayload(connection));
      connection.stopSent = true;
    }
    return true;
  }

  bool cleanupOperationsSettled() const
  {
    return std::ranges::none_of(connections, [](const auto& connectionItem) {
      const auto& connection = connectionItem.second;
      if (connection.cleanupCloseObserved) return true;
      return std::ranges::any_of(connection.streams, [](const auto& streamItem) {
        const auto& stream = streamItem.second;
        return stream.kind == StreamKind::operation && !stream.operationComplete;
      });
    });
  }

  bool queueStopAcks(AdapterError& error)
  {
    if (scenario == Scenario::closeResetCleanup && !cleanupOperationsSettled())
      return true;
    for (auto& [id, connection] : connections)
    {
      (void)id;
      if (!connection.stopReceived || connection.stopAckSent ||
          connection.cleanupCloseObserved) continue;
      if (!discardsPostWindowApplicationBacklog())
      {
        bool peerFramesReceived = false;
        if (!peerFinalFramesReceived(connection, peerFramesReceived, error))
          return false;
        if (!peerFramesReceived) continue;
      }
      const auto found = connection.streams.find(connection.controlStream);
      if (found == connection.streams.end())
      {
        error = {1, "QPF2 STOP received on a connection without its control stream"};
        return false;
      }
      queue(found->second, Type::stopAck, 64, 0, counterPayload(connection));
      connection.stopAckSent = true;
    }
    return true;
  }

  bool updateReconciled()
  {
    if (!stopQueued) return false;
    if (carriesConnectionIdentity(scenario) &&
        logicalConnectionCount() != connectionCount) return false;
    bool any = false;
    for (const auto& [id, connection] : connections)
    {
      (void)id;
      if (!logicalCurrent(connection)) continue;
      if (scenario == Scenario::closeResetCleanup && connection.cleanupCloseObserved)
        continue;
      any = true;
      if (!connection.stopSent || !connection.stopReceived ||
          !connection.stopAcknowledged || !connection.stopAckSent)
        return false;
      if (!connection.streams.contains(connection.controlStream) ||
          std::ranges::any_of(connection.streams, [](const auto& item) {
            return !item.second.transmit.empty();
          }))
        return false;
    }
    reconciled = any || connectionCount == 0;
    return reconciled;
  }

  bool idleEstablished() const noexcept
  {
    if (scenario != Scenario::memoryCurve) return true;
    if (connections.size() != connectionCount) return false;
    return std::ranges::all_of(connections, [this](const auto& item) {
      const auto& connection = item.second;
      return !connection.retired && connection.connected &&
          (client() ? connection.helloAcknowledged : connection.hasControlStream);
    });
  }

  bool pump(uint64_t now, AdapterError& error)
  {
    if (!started)
    {
      error = {1, "workload runtime is not started"};
      return false;
    }
    const auto transport = adapter.snapshotTransportCounters();
    const uint64_t flowBlocks = transport.flowControlBlockedEvents;
    const uint64_t streamBlocks = transport.streamCreditBlockedEvents;
    if (flowBlocks > observedFlowControlBlocks || streamBlocks > observedStreamCreditBlocks)
      flowControlBlockSeen = true;
    observedFlowControlBlocks = flowBlocks;
    observedStreamCreditBlocks = streamBlocks;
    readBudget = applicationBuffer.size();
    writeBudget = applicationBuffer.size();
    const auto phase = [&error](bool ok, std::string_view name) {
      if (!ok && error.message.empty())
      {
        if (!error.code) error.code = 1;
        error.message = "QPF2 " + std::string(name) + " failed without adapter detail";
      }
      return ok;
    };
    if (!phase(pumpConnections(now, error), "connection pump")) return false;
    if (!phase(pumpStreams(now, error), "stream pump")) return false;
    if (!phase(refreshNegotiatedSettings(error), "negotiated-treatment refresh"))
      return false;
    if (scenario == Scenario::closeResetCleanup &&
        !phase(retireClosedConnections(now, error), "cleanup retirement")) return false;
    if (isConnectionOperation(scenario) &&
        !phase(driveLifecycle(now, error), "lifecycle drive")) return false;
    if (!phase(queueStopAcks(error), "STOP_ACK queue")) return false;
    if (!phase(queueStops(now, error), "STOP queue")) return false;
    updateReconciled();
    return true;
  }

  bool stopAdmission(uint64_t now, AdapterError& error)
  {
    if (!admitting) return true;
    admitting = false;
    stopQueued = true;
    discardPostWindowApplicationBacklog();
    if (!tailFinalized && client())
    {
      if (scenario == Scenario::datagram)
      {
        for (const auto& [id, connection] : connections)
        {
          (void)id;
          for (const auto& [sequence, startRawNs] : connection.datagramsOutstanding)
          {
            (void)sequence;
            if (window.contains(startRawNs)) ++tailCensoredOperations;
          }
        }
      }
      else if (isFreshStreamOperation(scenario))
      {
        for (const auto& [id, connection] : connections)
        {
          (void)id;
          for (const auto& [streamId, stream] : connection.streams)
          {
            (void)streamId;
            if (stream.kind == StreamKind::operation && !stream.operationComplete &&
                window.contains(stream.operationStartRawNs)) ++tailCensoredOperations;
          }
        }
      }
      else if (isConnectionOperation(scenario))
      {
        for (const auto& [id, connection] : connections)
        {
          (void)id;
          if (!connection.retired && window.contains(connection.lifecycleStartRawNs))
            ++tailCensoredOperations;
        }
      }
      tailFinalized = true;
    }
    counters.unreturned = 0;
    for (const auto& [id, connection] : connections)
    {
      (void)id;
      counters.unreturned += connection.datagramsOutstanding.size();
    }
    if (scenario == Scenario::datagram)
      datagramDrainEndRawNs = now > std::numeric_limits<uint64_t>::max() - datagramDrainNs ?
          std::numeric_limits<uint64_t>::max() : now + datagramDrainNs;
    if (!retireClosedConnections(now, error)) return false;
    return queueStops(now, error);
  }

  RuntimeSnapshot snapshot() const
  {
    RuntimeSnapshot value;
    value.counters = counters;
    value.transport = adapter.snapshotTransportCounters();
    value.peerValidated = peerValidated;
    value.failed = failed;
    value.byteCapHits = byteCapHits;
    value.streamCapHits = streamCapHits;
    value.streamIdCapHits = streamIdCapHits;
    value.cleanupStrata = cleanupStrata;
    value.tailStartedOperations = tailStartedOperations;
    value.tailFailedOperations = tailFailedOperations;
    value.tailCensoredOperations = tailCensoredOperations;
    value.tailPrefixStarted = tailPrefixStarted;
    value.tailPrefixSuccessful = tailPrefixSuccessful;
    value.tailPrefixFailed = tailPrefixFailed;
    value.tailPrefixObservations = tailPrefixObservations;
    for (auto& observations : value.tailPrefixObservations)
    {
      std::ranges::sort(observations, [](const auto& left, const auto& right) {
        return std::pair {left.startRawNs, left.operationSequence} <
            std::pair {right.startRawNs, right.operationSequence};
      });
      if (observations.size() > 1'024) observations.resize(1'024);
    }
    value.tailObservations = tailObservations;
    std::ranges::sort(value.tailObservations, [](const auto& left, const auto& right) {
      return std::pair {left.startRawNs, left.operationSequence} <
          std::pair {right.startRawNs, right.operationSequence};
    });
    if (scenario == Scenario::smallPayloadPps)
      value.tailOwnership = client() ? RuntimeSnapshot::TailOwnership::senderStarts :
                                       RuntimeSnapshot::TailOwnership::receiverTerminals;
    else if (scenarioMeasuresOperations(scenario) && client())
      value.tailOwnership = RuntimeSnapshot::TailOwnership::complete;
    if (connectionCount != 0)
    {
      value.negotiatedSettings = hasNegotiatedSettings ? negotiatedSettings :
          adapter.snapshotNegotiatedSettings();
      value.hasNegotiatedSettings = true;
      value.negotiatedSettingsMatch = negotiatedSettingsMatch(
          value.negotiatedSettings, config, value.negotiatedSettingsMismatchReason);
    }
    value.completionReconciled = reconciled;
    value.flowControlWriteBlockedEvents = flowControlWriteBlockedEvents;
    value.flowControlRecoveryEvidence = flowControlRecoveryEvidence;
    for (const auto& [id, connection] : connections)
    {
      (void)id;
      if (!logicalCurrent(connection)) continue;
      ++value.liveConnections;
      if (connection.connected && (client() ? connection.helloAcknowledged : connection.hasControlStream))
        ++value.readyConnections;
      value.stopSent += connection.stopSent;
      value.stopReceived += connection.stopReceived;
      value.stopAcknowledged += connection.stopAcknowledged;
      value.stopAckSent += connection.stopAckSent;
      value.stopOffered += connection.stopOffered;
      if (stopQueued)
      {
        const auto retired = retiredValidatedByOrdinal.find(connection.ordinal);
        const uint64_t retiredValidated =
            retired == retiredValidatedByOrdinal.end() ? 0 : retired->second;
        if (connection.localValidated >
            std::numeric_limits<uint64_t>::max() - retiredValidated)
          throw std::overflow_error("QPF2 snapshot connection counter overflow");
        value.connectionValidatedUnits.push_back(
            {connection.ordinal, connection.localValidated + retiredValidated});
        const auto retiredSent =
            retiredSentFramesByOrdinal.find(connection.ordinal);
        const auto retiredReceived =
            retiredReceivedFramesByOrdinal.find(connection.ordinal);
        const uint64_t sent = retiredSent == retiredSentFramesByOrdinal.end() ?
            0 : retiredSent->second;
        const uint64_t received =
            retiredReceived == retiredReceivedFramesByOrdinal.end() ?
            0 : retiredReceived->second;
        if (connection.sentApplicationFrames >
                std::numeric_limits<uint64_t>::max() - sent ||
            connection.receivedApplicationFrames >
                std::numeric_limits<uint64_t>::max() - received)
          throw std::overflow_error("QPF2 snapshot application-frame counter overflow");
        value.connectionBarrierStates.push_back(
            {connection.ordinal, connection.sentApplicationFrames + sent,
             connection.receivedApplicationFrames + received,
             connection.peerFinalSentFrames, connection.peerFinalSentFramesKnown,
             hasPendingApplicationFrames(connection)});
      }
      value.outstanding += connection.datagramsOutstanding.size() + connection.operationInFlight;
      for (const auto& [streamId, stream] : connection.streams)
      {
        (void)streamId;
        value.inFlight += !stream.transmit.empty();
        if (scenario == Scenario::closeResetCleanup &&
            stream.kind == StreamKind::operation && !stream.operationComplete)
          ++value.cleanupPending[cleanupStratum(stream.terminalFlags)];
      }
    }
    std::ranges::sort(
        value.connectionValidatedUnits, {}, &ConnectionValidatedUnits::ordinal);
    std::ranges::sort(
        value.connectionBarrierStates, {}, &ConnectionBarrierState::ordinal);
    return value;
  }
};

Runtime::Runtime(Adapter& adapter, EndpointConfig config, MeasurementWindow window,
                 std::span<const uint8_t, 32> trialId, std::span<const uint8_t, 32> cellId,
                 uint32_t connectionFirst, uint32_t connectionCount)
    : implementation_(std::make_unique<Implementation>(adapter, std::move(config), window,
                                                        trialId, cellId, connectionFirst,
                                                        connectionCount))
{
}

Runtime::~Runtime() = default;
Runtime::Runtime(Runtime&&) noexcept = default;
Runtime& Runtime::operator=(Runtime&&) noexcept = default;

bool Runtime::start(uint64_t nowRawNs, AdapterError& error)
{
  return implementation_->start(nowRawNs, error);
}

bool Runtime::pump(uint64_t nowRawNs, AdapterError& error)
{
  return implementation_->pump(nowRawNs, error);
}

bool Runtime::stopAdmission(uint64_t nowRawNs, AdapterError& error)
{
  return implementation_->stopAdmission(nowRawNs, error);
}

bool Runtime::completionReconciled() const noexcept
{
  return implementation_->reconciled;
}

bool Runtime::idleEstablished() const noexcept
{
  return implementation_->idleEstablished();
}

uint64_t Runtime::validatedUnits() const noexcept
{
  return implementation_->counters.peerValidated;
}

bool Runtime::blockedInSubwindow(size_t index) const noexcept
{
  return index < implementation_->counters.subwindows.size() &&
      implementation_->counters.subwindows[index].blockedEvents != 0;
}

RuntimeSnapshot Runtime::snapshot() const
{
  return implementation_->snapshot();
}

} // namespace quicperf::workload
