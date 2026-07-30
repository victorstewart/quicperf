# Benchmark methodology v2

This document is the normative benchmark contract. The only publication
workflow is `tools/quicperfctl doctor`, `campaign create`, two `campaign run`
sessions, `campaign analyze`, and `campaign finalize`. Strict canonical JSON is
the only v2 configuration source; environment variables are accepted only by
the explicit legacy translator.

## Estimands

Results are partitioned by campaign kind and may not be placed in a global
leaderboard.

| Estimand | Meaning |
|---|---|
| `fixed_treatment_server` | Server behavior on one isolated physical core at exactly 16 active connections, with four fixed reference-client cores and an equally weighted 50/50 mixture of the ngtcp2 and picoquic reference clients. |
| `capacity_frontier` | Maximum stable point on the frozen common concurrency grid under the same client CPU budget. Selected concurrency is part of the result. |
| `memory_curve` | Fresh-process memory intercept and per-connection slope on the common connection-count grid. |
| `tail` | Per-operation distribution from operations whose start and completion both occur inside the interval. |
| `symmetric_stack_pair` | Same-library client/server diagnostic; not a server-only result. |

The fixed-treatment server estimate is the equal mixture of its two frozen reference
clients across 12 Williams rows and two independently started sessions. It is
not a client-invariant server effect. Reference-client and session interactions
are always reported, and sensitive or unresolved dimensions constrain the
claim language.

## Frozen publication treatment

The canonical server order is `ngtcp2perf`, `lsperf`, `tquicperf`,
`quicheperf`, `picoperf`, `xquicperf`, `quinnperf`, `s2nperf`, `neqoperf`,
`noqperf`, `quiczigperf`, and `mvfstperf`. Publication supports this exact set;
subsets, odd-sized designs, and capability-filtered schedules are diagnostic.
An unsupported planned cell remains visible and blocks canonical publication.

Every fixed-treatment cell uses:

- one isolated physical server core and four isolated physical client cores;
- exactly 16 active connections, sharded four/four/four/four between four
  client event-loop workers;
- fixed server and reference-client CPU, cgroup, memory, NUMA, SMT, IRQ, and
  housekeeping policy;
- independent server and reference-client binary/backend selection;
- IPv4 UDP, MTU 1500, maximum UDP payload 1350, 64-packet batches, requested
  16 MiB socket buffers, a fixed 4,096-buffer pool, and common 256 KiB
  application buffers;
- PMTUD off, UDP GSO/GRO on, ECN off, kernel receive timestamps off, kernel
  busy polling off, common-core pacing on, and `SO_REUSEPORT` off;
- the same certificate chain, hostname, TLS verification, resumption and early-
  data policy, congestion controller, path, workload, clocks, and validity
  rules.

The role cgroups set `cpu.max` to `max 100000`. CPU capacity is enforced by
their disjoint `cpuset.cpus` assignments: one logical CPU from the isolated
server core and four logical CPUs from isolated client cores. A finite CFS
bandwidth quota equal to that same capacity is forbidden because quota-period
rounding can throttle a continuously busy, correctly pinned endpoint without
providing additional isolation. The cgroup throttle counters remain mandatory;
any positive boundary delta still invalidates the complete session.

IRQ exclusion covers physical cores, not only the logical CPUs selected by the
endpoint processes. Every SMT sibling of a measured core is boot-isolated with
the `domain` and `managed_irq` isolation flags, full tick suppression, and RCU
callback offload. The kernel default affinity is restricted to the complementary
housekeeping set. Writable affinity changes are operator-authorized and restored
exactly after the command. Linux cannot redirect a managed queue whose automatic
mask contains only isolated CPUs; such a queue is accepted only with the frozen
boot isolation and a zero delta for every numeric device-IRQ counter on measured
CPUs across each exact timed interval.
The immutable identity covers that boot policy, default mask, configured
per-IRQ affinities, and writability, but not a managed queue's dynamic
`effective_affinity_list`. Linux may move that effective assignment within its
unchanged allowed mask as the queue activates; the preparation check and
per-interval zero-delta gate, rather than a transient assignment snapshot,
enforce safety.
Runtime-writable IRQs are routed only to the non-monitor housekeeping physical
core. The host-stability monitor owns the other housekeeping physical core, so
interrupt handling cannot consume its exact-boundary scheduling budget.

An unavailable requested primitive invalidates the cell; adapter-specific
fallback is forbidden. Publication endpoints may not own sockets, private
network/event loops, packet batches, timers, pacing, or helper runtimes.

The v2 endpoint behaviorally attests runtime ownership in addition to the
source audit. At READY, after common worker joins, and after every reset, the
process enumerates `/proc/self/fd` and `/proc/self/task`: the descriptor set must
equal standard streams, the inherited control channel, and the descriptors
declared by the selected common packet-I/O driver. The syscall driver declares
its UDP socket and epoll instance; the io_uring driver declares its UDP socket
and every common receive/transmit ring. Kernel `iou-wrk-*` tasks are not adapter
threads. Any other descriptor or userspace task aborts the endpoint.

The fixed-treatment, capacity, and tail profiles define a
`persistent_reset` process treatment for steady-state scenarios. Endpoint
processes may survive across trials, but the common runtime destroys every
connection, stream, timer, ticket, packet-I/O object, and queued work item before
the adapter reset succeeds. The process set, worker generation, cgroup
membership, descriptor set, and task set must remain exact; any reset or
ownership failure invalidates the block and retires the worker. Allocator arenas
and library-global caches may persist and are explicitly part of this
steady-state service-process treatment. Connect, resumed-connect, and 0-RTT
lifecycle scenarios always use fresh processes, as does the memory curve.
Persistent service operation is therefore part of the named estimand, not an
optimization conditionally admitted by a separate fresh-process parity
campaign.

Exact-release runtime-boundary qualification sets
`QUICPERF_RUNTIME_OWNERSHIP_AUDIT=1` only for the diagnostic exercise. That adds
the same exact checks after common worker creation and at each measurement
boundary; it is never enabled for performance samples. The development
contract injects an undeclared file descriptor, a direct socket syscall, an
epoll poller, a static-liburing ring, and a hidden userspace thread and requires
each to be detected before the restored positive control passes.

The native link boundary virtualizes ordinary transport-library time reads only
while an adapter call is active. `CLOCK_MONOTONIC_RAW` receives the exact raw
time supplied by the common event loop; `CLOCK_MONOTONIC` receives the same
instant translated by the qualified raw/monotonic bridge; and `time()`,
`gettimeofday()`, and `CLOCK_REALTIME` receive the frozen TLS calendar value.
Calls made by scheduling, packet I/O, measurement, and control code remain real
host-clock reads. Libraries with native caller-time APIs continue to use them;
the link boundary is the common fallback for libraries without such an API.
The exact-release audit rejects unsupported clock domains and post-READY
vDSO/private-symbol lookup instead of silently falling back to a host clock.
Its positive control proves distinct raw, monotonic, and calendar values.

Pinned dependencies may carry quicperf-local changes only in their owning
`depofiles/*.DepoFile`. Each Depofile pins the immutable source revision,
embeds the local patch, verifies both the checked-out revision and base Git
tree, and applies the patch fail-closed inside Depo's isolated build before
staging any source or library artifact. The resulting tracked source tree must
match the Depofile's exact post-patch Git tree hash; an idempotent retry is
accepted only when that complete tree already matches. The Depofile itself is
an input to the dependency manifest, so any patch, pin, configuration, or tree
hash change invalidates the build identity. CMake and Cargo only consume those
staged artifacts; they do not apply or maintain a second patch series. These
patches remain part of quicperf and are never pushed to the dependency's
upstream repository.

The ngtcp2 row and ngtcp2 reference client use upstream commit
`716e64b05f4a3709dfc0b0522cf9fd4456d055e5` plus the local patch embedded in
`depofiles/ngtcp2.DepoFile`. In addition to exposing retained STOP_SENDING
facts and successfully serialized blocked-frame counters, the patch emits
MAX_DATA and MAX_STREAM_DATA after the application consumes 1/128 of the
configured receive window rather than 1/4. It does not enlarge initial or
sliding receive credit: each update still advances the limit only by bytes
already consumed. The earlier update prevents a high-rate loopback sender from
exhausting the remaining credit while its update is in flight.

The tquic row uses upstream commit
`50f5a55975fe5b64cce708bbf227dd0f29b59ee5` plus
the local patch embedded in `depofiles/tquic.DepoFile`. That patch routes
transport and address-token time through caller-supplied raw
time, exposes exact retained peer terminal facts and serialized flow-control
counters, and exposes a causal recovery/probe counter. Its one opaque
`Instant::now()` epoch is initialized before READY; no subsequent tquic
transport or token decision reads a current host clock.

The XQUIC row uses upstream commit
`64b8df3ac3f64111eb9e00be1a952ba5b07144bb` plus
the local patch embedded in `depofiles/xquic.DepoFile`. That patch parameterizes
XQUIC's existing RESET_STREAM and STOP_SENDING frame
writers with the caller's application error, retains exact peer FIN, RESET,
STOP_SENDING, and application CONNECTION_CLOSE facts until the adapter reads
them, preserves the independent local send half after a peer RESET_STREAM
instead of automatically mirroring the reset, exposes the existing TLS
resumption bit, and closes the `/dev/urandom` descriptor after each
random-buffer refill instead of retaining it for the engine lifetime. The
adapter anchors XQUIC's explicit realtime callback to the frozen campaign
calendar, so ticket issuance and expiry use the same calendar as TLS
validation. XQUIC still owns QUIC state and packet generation; the shared C++
path owns UDP I/O, event-loop driving, and timeout delivery.

## Workload and measurement contract

QPF2 provides deterministic application framing, trial/cell identity, exact
sequence and payload validation, replenishment, and end-of-window
reconciliation. Accepted writes, queued bytes, sent packets, opened streams,
handshake starts, and local callbacks are diagnostic. Primary rate numerators
contain only peer-validated application bytes or completed operations timestamped
inside the common `[T0,T1)` interval. Deterministic bulk bodies are validated
and timestamped per received fragment; the enclosing 256 KiB QPF2 frame must
still complete and reconcile, and any later identity, sequence, length, or
payload failure invalidates the trial. Endpoint evidence retains those same
validated units by frozen logical connection ordinal for diagnostics; these
totals never become replicates or change the aggregate estimand.

The 15 publication scenarios have exact, named payloads and state machines:

- bulk `download`, `upload`, both eight-stream variants, `loss_recovery`, and
  `flow_control` report validated body Gbit/s;
- `bidi` reports upload and download Gbit/s separately and requires both;
- `small_payload_pps` counts delivered 64-byte framed messages;
- `datagram` counts unique validated 64-byte QUIC DATAGRAM echoes and never
  substitutes a stream; after T1, a fixed 100 ms drain terminally classifies
  remaining IDs as unreturned without adding late echoes to the numerator;
- `reqresp` counts complete 64-byte request/1024-byte response pairs;
- `stream_churn` and `close_reset_cleanup` count validated terminal lifecycle
  operations, with the latter reporting four transition strata and their equal-
  weight geometric aggregate;
- `connect`, `resumed_connect`, and `zero_rtt_reqresp` count complete validated
  fresh-context operations with the required handshake, ticket, or accepted-
  early-data evidence.

`close_reset_cleanup` is advertised only when the actor can attest the local
action and the observer can attest the exact peer-observed FIN, RESET_STREAM,
STOP_SENDING, or CONNECTION_CLOSE terminal fact. The receiver first emits an
`OP_ACK` carrying the selected terminal flag and is the sole terminal actor. The
initiator returns a zero-body `TERMINAL_READY` carrying the same flag only after
it validates that `OP_ACK`; the actor issues the transport terminal action only
after validating that readiness frame. This receipt prevents RESET_STREAM or
CONNECTION_CLOSE from overtaking still-unobserved application bytes. The
initiator then observes the transport transition and never mirrors it.
RESET_STREAM and STOP_SENDING use application error `0x5150`. Neither `OP_ACK`
nor `TERMINAL_READY` is terminal evidence or can enter the numerator. Final STOP/STOP_ACK
reconciliation must match the actor and observer totals. Each stratum must
contain at least 100 completions; otherwise the sample and aggregate are
nonclaimable.

The common engine continually replenishes duration work until `T1`. A finite
work ceiling, stream-credit exhaustion, stalled generator, early progress stop,
or unaccepted offered suffix invalidates the trial. The 256 KiB bulk chunk is an
offered API slice, not a transfer limit.

Ordinary two-second duration trials have ten 200 ms diagnostic subwindows; the
ordinary five-second loss-recovery treatment has ten 500 ms subwindows. Those
durations are part of the fixed-treatment estimand: publication reports the
rate over the exact frozen interval and makes no claim that it equals a
10/20-second rate. Tail campaigns instead use their exact qualified common
scenario duration. A
subwindow must show progress or a causal blocked event. Subwindows are never statistical replicates.
Endpoint boundary release must occur no later than
`max(2 ms, measurement_duration / 1000)` after its scheduled boundary; the
numerator and denominator remain bound to the scheduled `[T0,T1)` interval.
The native engine privately retains 200 timestamp-derived accounting bins while
emitting the same ten public progress buckets by aggregating adjacent bins.
Before sample commit, the coordinator verifies exact ARM boundaries,
denominators, unsigned counters, 20:1 aggregation, numerator ownership, blocked
evidence, and equality with the raw sample numerator; the 200-bin private
vectors are then discarded. An optional window-invariance study may use the
first 40 or 50 private bins for a nested 2-second or 5-second numerator from the
same 10-second or 20-second stream, but that separate research question is not
a prerequisite for the fixed-window publication claim.
Integer operation-rate samples with fewer than 400 receiver-validated
completions are `resolution_limited` and make the row nonclaimable without
extension or retry. Byte rates have no achieved-byte floor.

`loss_recovery_v1` uses symmetric 10 ms one-way delay and the frozen HMAC-based
one-percent packet-unit decision stream independently in warmup and measurement.
Each lane owns persistent client, server, and router network namespaces. The
router qdiscs add delay only; the shared native packet-I/O core applies loss
before GSO and recomputes its exact directional packet ordinals. The attempt
must attest zero qdisc drops, exact HMAC drop counts, and transport
retransmission/recovery evidence. `flow_control` must attest 256 KiB connection
and 64 KiB stream windows. The receiver withholds data-stream consumption for
the first half of warmup, then resumes; the trial must attest a blocked event
followed by credit recovery before the measured interval. Native serialized
DATA_BLOCKED/STREAM_DATA_BLOCKED counters remain separate transport evidence.
The common adapter boundary additionally records a causal write-backpressure
event only when `writeStream` accepts zero bytes, and records recovery only
when that same stream later accepts bytes; either blocked signal may satisfy
the workload gate, but neither is relabeled as the other.

Memory uses fresh processes at the exact common N grid, a common settle rule,
cgroup memory and `smaps_rollup`; it reports intercept and per-connection slope.
It never reuses duration trials or the retired idle row.

## Global barrier and validity

The coordinator starts the server, reference client, and path controller before
measurement. `ARM` carries a common target time, endpoints answer `ARMED` with
raw-clock samples, and the coordinator derives per-endpoint deadlines from a
32-sample `CLOCK_MONOTONIC_RAW`/`CLOCK_MONOTONIC` bridge. Offset spread must be
at most 50 microseconds and start skew at most 100 microseconds. Dynamic traces
begin at the common barrier, never at process start.

V2.1, V2.2, and V2.3 give every ARM window a 750 ms nominal lead and require
at least 500 ms remaining immediately before ARM transmission. If setup consumes that guard,
the coordinator transactionally cancels the unobserved path and AMD boundaries
for the whole window and rebases every boundary; two such pre-send rebases are
the maximum. An endpoint that observes a late ARM returns structured
`ARM_REJECTED` without exiting or closing its control channel. The coordinator
then destroys both workers, atomically supersedes only the unstarted
microblock, and activates its exact preallocated retry. Late-ARM recovery has a
separate one-per-session control-plane budget. A late retry, exhausted budget,
partial boundary observation, or crossing a workload boundary fails closed.
No sample or journal `measuring` state exists before both endpoints accept the
same still-future window.

The Python coordinator never handles measured UDP packets, drives a transport
timer, generates offered work, or constructs a rate numerator. Those operations
remain inside the common native endpoint core on frozen server/client CPUs.
Python runs only on housekeeping CPUs; journal mutation is forbidden during the
measurement interval. Its affinity, CPU time, control-packet count, and journal
write count are retained in each sample. Publication additionally requires
exact host isolation and four-core client-headroom qualification, while
per-trial scheduler and IRQ telemetry gates indirect interference rather than
presuming it absent. Two-lane interference is neither required nor meaningful
for the frozen single-lane treatment.

An active publication session is owned by the durable publication-host service,
not an SSH client. Operational observation is passive: `journalctl` may follow
service events, `systemctl show` may read service state, and off-host telemetry
may observe the host without opening the run directory. Repeated live-journal
polling is prohibited. Polling the SQLite journal, WAL, logs, or result
artifacts—including `quicperfctl campaign status` and direct `sqlite3`
queries—is forbidden until the service exits at an atomic session boundary.
This prevents observer activity from becoming an unmodeled coordinator or
monitor load.

Client p95 CPU headroom is sampled from the sum of the exact persistent
event-loop thread CPU clocks while all background event loops are paused at
each of ten measurement boundaries. The endpoint requires its declared worker
count to equal its inherited CPU affinity. This avoids Linux process-clock
group-accounting jumps while retaining every task allowed by the runtime
ownership contract.

The headroom gate exercises the exact four-core client treatment. Its
500-millisecond screens cover all 12 servers, both server backends, and the
three frozen pressure scenarios, but do not enter the qualification estimate.
The mechanically selected worst cell then runs 12 held-out blocks. Every
held-out four-core p95 utilization must be strictly below 0.80. The retired
two-versus-four-core throughput comparison is not a publication gate: the
two-core treatment is no longer part of this estimand.

Per-trial CPU-ownership telemetry is direct rather than a residual between
unrelated kernel clocks. Before endpoint startup, the coordinator loads one
small `sched_switch` eBPF classifier for each measured CPU. During the armed
interval it accumulates each non-idle interval whose current cgroup is neither
the server nor client cgroup. It does not attach to a network interface or
inspect packet data; numeric device-IRQ deltas are checked independently. The
publication-host service supplies the required BPF/perf privilege, inability to
load or attach is a hard telemetry failure, and every descriptor is
trial-scoped and closed deterministically.

### AMD Ryzen 7 8845HS host-stability provider

`amd_delivered_performance_v1` is the approved alternative to a missing Linux
thermal-throttle event counter, and applies only when `/proc/cpuinfo` reports
the exact model string `AMD Ryzen 7 8845HS w/ Radeon 780M Graphics`. The frozen
allowlist records AMD product `AMD Ryzen 7 8845HS`, 3,800,000 kHz base
frequency, 100,000 m°C Tjmax, the authoritative [AMD product
specification](https://www.amd.com/en/products/processors/laptop/ryzen/8000-series/amd-ryzen-7-8845hs.html),
retrieval date 2026-07-19, and captured source SHA-256
`e64ce38835f11a31f236edc3eaaf2383b6591a4484fe430ef36735851f9aea43`.
Only this exact allowlist entry may supply Tjmax when k10temp omits
`temp1_crit`; it does not claim to count or attribute thermal events.

The provider requires `constant_tsc`, `nonstop_tsc`, and `aperfmperf`; readable
64-bit APERF/MPERF events on every measurement CPU; one readable k10temp Tctl;
boost off; governor and EPP both `performance`; and every affected policy fixed
at scaling min=max=3,800,000 kHz. Each CPU's APERF and MPERF events are opened
as one persistent Linux `perf_event_open` MSR-PMU group. Every read includes
event IDs plus `time_enabled` and `time_running`; any missing event, identity
change, short read, stalled clock, or unequal enabled/running time fails closed.
Separate `/dev/cpu/*/msr` reads are not valid evidence because they do not
sample the pair coherently.

The frozen Tctl ceiling is strictly below `min(80°C, Tjmax - 20°C)`, hence
strictly below 80°C on this CPU. A dedicated coordinator child owns exact
boundary APERF/MPERF, Tctl, `nr_throttled`, and `throttled_usec` snapshots plus
continuous policy readback. Its sampling thread uses `SCHED_FIFO` priority
51—above the PREEMPT_RT kernel's priority-50 threaded IRQ/idle-injection class
on a core from which device IRQs are already routed, and below priority-99
migration threads. Heavy policy reads are excluded from the final 50 ms before
each boundary; lightweight Tctl sampling continues until a final 10 ms guard,
when control passes to an attested native helper. The monitor keeps its Tctl
and cpufreq control descriptors open and uses offset-zero reads, avoiding
repeated sysfs traversal and open/close latency while still verifying every
policy value. Boundary Tctl is read before counter and cgroup work and advances
the continuous temperature cadence.

A separately executed `SCHED_FIFO` watchdog on the reserved SMT sibling owns
the uninterrupted coherent APERF/MPERF stream at the unchanged 100 ms period
(valid interval 50–200 ms) and a second Tctl stream half a 20 ms period out of
phase. It has its own interpreter, opens independent nonmultiplexed perf-event
groups, timestamps each completed group read, and sends sequenced evidence to
the boundary process. Its Tctl samples are merged with the primary stream. V2
retains its 50 ms maximum combined gap; V2.1, V2.2, and V2.3 predeclare a
250 ms maximum.
That gap is evaluated from the merged observed sample timestamps, not from when
already-timestamped watchdog messages happen to reach the parent.
Thus an interpreter or kernel stall
on the exact-boundary CPU cannot simultaneously erase continuous counter or
thermal evidence; malformed sequence, cadence loss, child exit, backpressure,
or incomplete stop attestation still fails closed. The GIL-holding helper spins
to the exact raw-clock target on the other isolated, nohz-full, RCU-offloaded
SMT thread. Both threads remain outside the endpoint, coordinator, and IRQ CPU
sets. The
two-level boundary guard takes precedence over periodic work; deferred reads run
immediately after the boundary and remain subject to their unchanged cadence
limits. The
remaining monitor loop uses a 100 µs interpreter handoff interval only for the
monitor lifetime; startup fails if process isolation, the real-time policy, or
the helper cannot be attested, and the prior interpreter setting is restored
exactly. The monitor never runs on an endpoint CPU or handles
benchmark packets. Its selected physical core is reserved from coordinator and
writable-IRQ affinity for the entire qualification or benchmark session, while
coordinator threads and IRQs use only the remaining frozen housekeeping cores.

Fresh legacy/V2 migration parity is a nonpublication gate, not a source of
benchmark rankings. The frozen matrix contains 12 implementations, two server
backends, and 16 legacy scenarios: the 15 V2 scenarios plus the retired
`idle_footprint` estimand. Every cell has 20 precomputed paired observations,
with exactly ten legacy-first and ten V2-first orders selected by the campaign
seed. A numeric legacy observation first passes its legacy environment
selection through the public fail-closed translator; the gate proves that the
translated server, client, backend, scenario, path, workload, TLS, transport,
socket, and resource treatment is identical to the native V2 cell before
executing a distinct strict-endpoint trial. Thus the comparison validates the
migration surface without retaining a second transport implementation behind
it. Numeric observations use the same implementation as server and client, the
selected server backend, the common io_uring client backend, 16 logical
connections on one server and two client cores, and the profile's exact
treatment apart from the gate-specific 500 ms measurement interval.
`close_reset_cleanup` retains its ordinary two-second interval because its
four terminal strata each require at least 100 observations. Both
executions in a pair share the frozen trace seed. The ordinary-sample 90%
interval for the mean log V2/legacy rate ratio must lie wholly inside
`log(0.97)` through `log(1.03)`; requested/effective common settings and
terminal validity must agree exactly. The publication trial's per-observation
400-operation censoring threshold does not replace this paired gate: a
lower-count parity observation is retained visibly, and its complete 20-pair
interval remains the acceptance criterion.
The 24 legacy loss-recovery cells are not assigned a numerical ratio because
their periodic drop model is not synchronized between endpoints or equivalent
to V2's seeded QUIC-packet trace; V2 must reject the reproduced legacy
scenario/path combination. The 24 idle-footprint cells likewise retain the
legacy duration-mode unsupported classification while V2 must classify the
estimand as replaced by the fresh-process memory curve.

Milestone A requires all 7,680 pairs on two qualified lanes in at most 3.5
hours, with useful measurement time at least 75% of two-lane wall capacity. A
one-lane execution cannot satisfy that estimand or runtime contract, so the
coordinator refuses full unqualified-host parity rather than spending hours on
necessarily nonpublication data. Failure diagnosis uses a bounded targeted
cell or smoke profile, never a reduced matrix presented as parity evidence.
This requirement belongs only to the optional migration-parity diagnostic; it
does not apply to the single-lane primary publication campaign.

For an interval of `dt` seconds, CPU activity means
`delta_MPERF >= 0.05 × 3.8e9 × dt`; delivered performance is
`delta_APERF / delta_MPERF`. Each active 100 ms window must be at least 98% of
that CPU's frozen cool reference, and each active timed interval's cumulative
ratio must be at least 99.5%. A counter reset, monitor migration or dropout,
Tctl breach, policy drift, sensor loss, monitor death, or positive delta in
either cgroup throttle counter fails closed.

Under V2.1, V2.2, and V2.3, `dt` is the actual observed interval between the
midpoint timestamps of the two coherent counter reads. Scheduled target timestamps are
retained separately. Each boundary must be within 5 ms of its target, and
observed interval-duration error must be at most 0.1% of the target interval.
The 5 ms phase cap bounds a common shift to 0.25% of the shortest two-second
measurement and cannot alter endpoint start or stop timing; the separate 0.1%
duration cap bounds the APERF/MPERF activity denominator directly. Neither
bound replaces any endpoint timing check.

Endpoint workload timing is unchanged: the coordinator's frozen ARM, warmup,
`T0`, and `T1` timestamps remain exact, endpoints must acknowledge and start
within their existing strict bounds, and only receiver-validated work inside
`[T0,T1)` enters a numerator. Observed monitor timestamps attest host activity;
they never move, extend, or reinterpret the workload window.

Calibration is bound to the exact boot, policy, monitor/helper binary, source,
dependency, profile, and analysis identities. It cools to at most 60°C for 30
continuous seconds, runs a 120-second pinned probe per measurement CPU, derives
ratio and deterministic-loop references only from `[10s,30s)`, gates seconds
30–120, proves a 3,420,000 kHz negative control within two seconds, restores
3,800,000 kHz in the safe max-then-min order, cools again, and repeats the
positive probe. Every benchmark session then has a 60-second positive probe
before and after it plus uninterrupted raw continuous evidence. Offline import
cannot create this qualification.

A delivered-performance, true Tctl breach, policy, sensor, continuous-counter,
cgroup-throttling, monitor-process, or missing-prerequisite violation archives
and invalidates the complete session, marks the campaign
`hardware_unqualified`, excludes every session sample, and cannot be retried.
V2.1, V2.2, and V2.3 localize only an isolated boundary phase/duration monitor
transient: the affected 24-trial microblock is superseded atomically and its one exact
preallocated retry mate runs next. Earlier healthy committed microblocks remain
evidence. A transient in that retry is immediately terminal. At most two such
localized transients may activate retries in one session; the cap is the
maximum observed in an eligible pre-V2.1 session and is frozen before V2.1 data
exist. Exceeding it fails closed. Sensor loss longer than the 250 ms combined
gap, monitor death, malformed evidence, or any hard hardware/policy violation
is never localized.

After `T1`, STOP/acknowledgment and counter reconciliation occur outside the
numerator. Each endpoint stops admission and freezes its exact in-window
validated counter. Streaming transfers and small-payload PPS discard
harness-owned frame suffixes that have not yet been offered to the transport;
bytes already accepted by a transport may drain, but cannot extend the sample
or enter the numerator. Small-payload operations use a dedicated stream so
their ordered backlog cannot precede `STOP` on the QPF2 control stream.

`STOP` declares the frozen validated counter and an accepted-frame diagnostic;
`STOP_ACK` returns the receiver's frozen validated counter as soon as the peer
declaration is parsed. Finite request/response, lifecycle, cleanup, and
DATAGRAM scenarios retain their scenario-specific terminal or bounded-drain
rules. Reconciliation requires both declarations, both acknowledgments, exact
cross-endpoint validated-counter agreement, and no harness-owned pending work.
It deliberately does not require an unbounded drain of transport-internal
post-window streaming data. Missing progress, caps, stalls, payload or identity
mismatch, duplicate completion, early/late barrier, path mismatch, transport
fallback, resource contamination, throttling, thermal events, unexpected
threads or FDs, or completion-bound failure invalidates the complete
microblock. Values are not discarded merely for being slow or extreme.

## Schedule and retries

For even `n=12`, the Williams base is `0,1,11,2,10,3,9,...`; row `r` adds `r`
modulo 12. Each of two independently started sessions executes all 12 rows.
Both sessions derive the same HMAC row order, with session two executing its
reverse. Matching rows use opposite reference clients; each session therefore
has six rows for each reference client. V2.2 and V2.3 have one frozen
`iouring` backend, so backend order is invariant rather than complemented. Every
microblock runs serially on frozen lane zero. A microblock shares one trace
realization, while matching rows in the other session use an independently
derived session trace seed.

The complete maximum schedule is frozen before outcomes. The publication
V2.2 and V2.3 campaigns have 15 scenarios × 1 server backend × 24 raw Williams
rows × 12 servers = 4,320 primary inferential trials. No peer-balance control exists
because no
second treatment runs concurrently. Exactly one dormant retry mate is frozen
for every inferential microblock, for 8,640 maximum trial IDs. The retry mates
have preassigned IDs, serial order coordinates, treatments, and fresh seeds; no
ID or seed is generated during recovery. V2.2 and V2.3 may activate only the affected
mate for an isolated boundary-monitor transient or late-ARM rejection, under
their separate frozen aggregate budgets. Remaining closed
treatment-independent infrastructure failures retain complete-session
recovery. A retry failure or exhaustion of its applicable budget makes the
session nonpublishable.
Scientific invalidity and genuine host-stability violations are never retried.
The schedule is never extended toward a favorable or noisy server.

## Capacity, memory, and tail separation

Capacity uses the same frozen domain for every implementation. Its five-point
search order derives only from the campaign seed; every search observation is
`exploratory`. Candidate nomination is mechanical, and candidate plus adjacent
grid points are confirmed with fresh held-out microblocks. Search observations
never enter confirmatory inference or become fixed-treatment comparisons.

Memory has no scout and fits its fresh-process curve on the frozen common N
grid. Tail has no aggregate-trial p99 claim: only its sufficient in-window
operation observations support distribution claims. Neither campaign may reuse
fixed-treatment observations.

Before a tail campaign is created for execution, its exact identity must have a
nonpublication tail-window qualification. The frozen maximum qualification
schedule contains 384 primary 20-second screens and 7,680 possible primary
held-out blocks, plus one dormant infrastructure retry mate for every primary.
All exercises derive nested 2/5/10/20-second prefixes from one raw stream.
Screening nominates the shortest common duration with at least 1,280 eligible
peer-validated successes in every cell, no cap or stall, and a one-sided 95%
Wilson failure/censoring upper bound below 1%.

For each `(scenario, backend, reference_client)` stratum, screening selects the
union of the worst eligible count, largest absolute prefix-versus-20-second
log-p99 discrepancy, and canonical ngtcp2 baseline, resolving equality by canonical order.
Exactly 20 fresh blocks run for each activated cell. Held-out simultaneous 90%
intervals enumerate all `2^20 = 1,048,576` common block-sign assignments over
the 2/5/10-second versus 20-second contrasts. A stratum selects the shortest
duration at or above its nomination for which every activated cell has at least
1,024 eligible operations, Wilson upper bound below 1%, identical validity, and
its interval inside ±`log(1.02)`. The scenario duration is the maximum of its
four backend/client strata and is frozen identically for all implementations.

Every final tail raw block must provide at least 1,024 eligible operations. The
native engine retains exactly the first 1,024 by `(start_timestamp,
operation_sequence)`, yielding exactly 24,576 values per aggregate stratum and
12,288 per reference-client stratum. It computes one nearest-rank raw-block p99;
matching session rows form 12 superblocks for exact 4,096-sign inference. Tail
trials never run until a count, extend, or top up after outcomes.

For `small_payload_pps`, the reference client owns operation starts and the
server owns successful or failed terminal observations. Reconciliation joins
those endpoint-owned counters by frozen prefix; starts without an in-window
terminal are censored. The receiver is not required to reproduce the sender's
start count, because an operation may validly cross `T1`, but terminal counts
may never exceed their corresponding starts.

## Identity, journal, and resume

`create` freezes the strict experiment spec, source/build/binary/dependency and
stable host-policy manifest, complete schedule, seeds, retry policy, validity
rules, and analysis identity. Publication requires a clean tree. An explicitly
dirty diagnostic records the exact diff bytes/hash and permanently carries
`nonpublication_dirty_source`.

An unqualified host cannot execute the publication suite or full migration
parity: neither can produce publication evidence, regardless of completeness.
Failure diagnosis uses bounded smoke profiles or targeted benchmark cells.
Diagnostic outputs remain ineligible for installation under `docs/results/v2/`.

The SQLite WAL journal enforces campaign, session, microblock, trial, attempt,
and cell state transitions. A complete microblock commits atomically; partial
work remains diagnostic. Committed records are immutable. One lock owns a run
directory. Resume rejects any changed spec, source, binary, loaded library,
toolchain, build flag, dependency, protocol, workload, TLS, path, resource,
host policy, schedule, or analysis field. Human logs and stale TSV files cannot
affect state. Export is deterministic and atomic.

## Inference

For every primary family `(estimand, scenario, path_profile, metric,
server_backend)`, the baseline is `ngtcp2perf`. Positive-metric comparisons use
24 raw session-level paired log ratios. Matching session rows are averaged into
12 predeclared superblock values, which are the primary inferential units.
Lower-is-better metrics are oriented so positive means implementation A is
better. The estimand gives equal weight to the two reference clients.

Simultaneous 95% intervals enumerate all 4,096 common sign vectors. The primary
max-|t| family covers the 11 baseline contrasts; the secondary table recomputes
its critical value over all 66 pairs. The conservative empirical 95th order
statistic is used. Practical margins are ±log(1.03) for rates and ±log(1.05)
for memory. Classifications are exactly `superior`, `inferior`, `equivalent`,
and `inconclusive`.

Sensitivity fits all 24 raw row contrasts to `[1, client, session,
client×session]`, treats matching Williams rows as 12 clusters, uses -0.5/+0.5 coding,
HC2 standard errors, and a common-cluster-sign
wild max-|t| distribution. Reports retain stratified estimates and display
`invariance_supported`, `reference_client_sensitive`, `session_sensitive`, or
`sensitivity_unresolved` as applicable. Sensitivity labels do not rewrite the
valid mixture estimate.

Invalid, failed, censored, unsupported, resolution-limited, and planned-but-
unmeasured cells remain in the cardinality and quality reports. They cannot
disappear through survivor filtering. Inferential tail claims exist only in the
tail campaign.

## Publication gate

Deterministic qualification includes an immutable current-binary native
interoperability preflight containing exactly 180 unique records: every
combination of 12 servers × 15 scenarios once. Both endpoint backends are
frozen to `iouring`. The two reference-client implementations are
identity-randomized and balanced 90/90 overall and 6/6 within each scenario.
Every tuple runs the release server and client binaries,
strict production CONFIG, exact TLS identity, and the common C++ I/O/time/event
path. It must complete scenario-specific QPF2 peer validation, terminal
semantics, STOP/ACK reconciliation, and bounded process, FD, socket, cgroup,
namespace, and path cleanup. Handshake-only success or inherited capability
metadata cannot create a PASS record. The final campaign remains the
authoritative 12-server × 2-client × 1-backend × 15-scenario design and repeats
each treatment cell across all 12 Williams rows in both sessions.

The preflight order and tuple IDs derive from the exact identity. Refresh is
crash-resumable only from a canonical committed plan prefix and produces all
180 records even when some fail. Ordinary doctor consumes the content-addressed
artifact; any relevant identity change requires a new refresh. Publication
requires exactly 180 PASS and zero failed, missing, duplicate, malformed,
fallback, timed-out, or unexpected-unsupported preflight records, followed by
complete valid final-campaign cardinality.

The publication schedule is serial. Each session contains 180 inferential
microblocks—12 Williams rows for each of 15 scenarios—and 2,160 trials. Across
both sessions, every `(server, scenario, server backend, reference client)`
stratum has exactly 12 observations, six in each session. Every server occupies
every Williams position and follows every other server exactly once per
session/scenario. Matching rows form 180 two-session pairs and use opposite
reference clients, the same sole `iouring` backend, and independent trace seeds.
Primary and dormant-retry serial placements are identical.

There is no concurrent peer treatment, parallel epoch, or
`parallel_balance_control` row. The former 576 controls existed solely to
balance simultaneous peer exposure and would control no nuisance factor in a
single-lane campaign. They are absent from the schedule, journal, runtime
utilization, and exports.

The 4,320 trials contain 9,504 seconds of validated measurement and 936
seconds of warmup. Serial execution makes their endpoint arm path 10,440
seconds. The 4,320 individual 750 ms arm leads add 3,240 seconds and the four
mandatory 60.25-second AMD probes add 241 seconds, for an exact 13,921-second
(3:52:01) scheduled floor, or 6,960.5 seconds (1:56:00.5) per session.

V2.2 froze an 8,400-second (2:20:00) ceiling per session. Its exact first
session stopped nonpublication after 8,363.071 seconds with seven unstarted
microblocks because the feasibility reserve could not fit them before that
ceiling. V2.3 changes only this operational policy: it freezes a 10,800-second
(3:00:00) ceiling per session and never reuses V2.2 samples. Historical design
evidence only—never publication input—records that `8f71fbc-r2` took
14,628.078 seconds for its two-backend session. Reconstructing its retained
`iouring` trials plus block gaps gives 7,301.392 seconds; adding 170.771 seconds
of non-attempt service time gives a 7,472.163-second expected one-backend
session. The 10,800-second ceiling is the revised conservative predeclared
allowance.
Useful measurement divided by observed one-lane wall capacity is reported
prominently but is not a publication qualification gate. Exact
cardinality and continuous health, policy, throttle, thermal, workload, timing,
and identity evidence remain mandatory.

Per-trial intrinsic nonmeasurement overhead excludes the predeclared accepted
750 ms ARM lead, warmup, measurement window, and any scheduled parallel
padding. It includes setup, control work, teardown, and any additional
cancel-and-rebase delay. Session median and p95 intrinsic overhead must remain
at or below 250 ms and 750 ms respectively. Deterministic analysis rendering
must complete within 60 seconds; implementation optimizations may reuse
treatment-independent fixed-design arithmetic but cannot change the 4,096-sign
inference or any rendered scientific artifact.

The clean-start conservative budget is 1,200 seconds for deterministic
verification + 3,847.8 seconds for admissions + 21,600 seconds for both session
ceilings + 600 seconds for analysis, finalization, export, and checksums =
27,247.8 seconds (7:34:07.8). The hard suite deadline is 30,000 seconds
(8:20:00), preserving the 2,752.2-second safety margin. Plan/create refuses an
identity whose derivation exceeds that deadline. A deadline or gate failure stops nonpublication without diagnostic
fallback or outcome-dependent rescheduling.

`finalize` returns success only after exact cardinality, clean provenance,
fairness, validity, two-session, analysis, and physical qualification gates all
pass. Required qualification includes host topology/isolation and health,
four-core client headroom, per-trial persistent-worker reset integrity,
fixed-window validity, runtime budgets, clocks, TLS, path control, workload
oracles, and adapter/reference-client interoperability. Lane interference is
not required for the frozen single-lane treatment.

`implementation_complete` means code and deterministic gates pass while every
unavailable physical gate is explicitly recorded as `NOT_RUN`.
`publication_qualified` additionally requires all physical/runtime gates to
pass on the exact qualified host identity and no unexpected unsupported or
missing canonical cell. `NOT_RUN` is never a pass and always prevents
publication.

Only an immutable export from a `publication_qualified` campaign may be copied
to `docs/results/v2.3/` and linked from `docs/latest-results.md`. Diagnostic,
dirty, incomplete, invalid, or merely implementation-complete runs must remain
outside the public result index.
