# quicperf V2.3 methodology

This document is the scientific contract for the V2.3 primary publication
campaign. The canonical machine-readable contract is
[`profiles/v2.3/publication.json`](../profiles/v2.3/publication.json). If prose
and profile disagree, execution fails rather than silently substituting a
treatment.

## Estimand and scope

The primary estimand is fixed-treatment server performance on the qualified
host: one isolated server physical core, four isolated client physical cores,
exactly 16 active connections, and the equal 50/50 mixture of the two frozen
reference clients (`ngtcp2perf` and `picoperf`). Every endpoint uses the common
C++ `iouring` UDP backend.

The treatment covers 12 server implementations and 15 scenarios. It does not
estimate capacity, memory scaling, long-tail latency, syscall-backend
performance, or symmetric same-stack performance. Those are excluded from
trials, inference, and claims. Diagnostic utilities cannot enter the V2.3
journal or receive publication status.

## Frozen treatment

The server order is `ngtcp2perf`, `lsperf`, `tquicperf`, `quicheperf`,
`picoperf`, `xquicperf`, `quinnperf`, `s2nperf`, `neqoperf`, `noqperf`,
`quiczigperf`, and `mvfstperf`.

The scenarios are:

1. `download`
2. `upload`
3. `multistream_download`
4. `multistream_upload`
5. `bidi`
6. `small_payload_pps`
7. `datagram`
8. `reqresp`
9. `stream_churn`
10. `connect`
11. `resumed_connect`
12. `zero_rtt_reqresp`
13. `loss_recovery`
14. `flow_control`
15. `close_reset_cleanup`

Ordinary windows are 2 seconds after a 250 ms warmup. Loss recovery uses a
5-second window after a 500 ms warmup. Connect, resumed-connect, and 0-RTT
scenarios have no warmup. The profile freezes all payload sizes, stream counts,
flow-control limits, operation slots, and ticket chains. There is no adaptive
load selection.

Transport is QUIC v1 with ALPN `qperf/2`, CUBIC, a 13,500-byte initial
congestion window, 1,350-byte maximum UDP payload, fixed ACK policy, no active
migration, and common-core pacing. TLS is TLS 1.3 with
`TLS_AES_128_GCM_SHA256`, X25519, Ed25519, strict hostname/chain verification,
and a frozen validation calendar. The 0-RTT treatment uses one-use tickets and
a 4,096-byte early-data maximum.

Sockets use IPv4, MTU 1,500, 64-packet receive/send batches, 16 MiB requested
socket buffers, a 4,096-buffer pool, UDP GSO/GRO, and no ECN, busy polling, or
receive timestamps. Loss recovery applies deterministic 1% QUIC-packet loss
and 10 ms one-way delay from an HMAC-derived trace; all other scenarios use
loopback without path impairment.

## Shared-I/O and workload validity

C++ owns measured socket creation, receive, send, batching, backend selection,
loss application, timeout scheduling, and the event loop. Transport adapters
consume caller-supplied monotonic and frozen calendar time. Rust, Zig, and
mvfst do not own a hidden competing UDP/event-loop path.

QPF2 endpoints declare their workload, negotiate the exact frozen treatment,
and attest reset completion before each persistent-worker trial. The global
barrier fixes endpoint start and stop times. Only receiver-validated work whose
start and terminal event both satisfy the scenario ownership rule contributes
to a numerator. Byte, operation, stream, DATAGRAM, cleanup, ticket, loss, and
transport-accounting invariants fail closed.

The `datagram` drive loop is batch-equivalent and reports unique validated 64-byte QUIC DATAGRAM echoes,
unreturned/lost messages, UDP packets, batching, polling, and DATAGRAMs per UDP
packet. GSO loss is applied to QUIC packets, not whole UDP super-packets.
Flow control proves bounded connection and stream windows while replenishing
consumed credit. Cleanup requires bounded process, FD, socket, cgroup,
namespace, and path state.

## Schedule and cardinality

Each independently started session contains all 12 Williams rows for all 15
scenarios. A microblock contains the 12 servers at one
scenario/reference-client/session/Williams-row coordinate.

- 180 microblocks and 2,160 primary trials per session
- two sessions
- 4,320 primary trials
- one dormant retry mate for every microblock
- 8,640 maximum preallocated trial IDs
- 180 retained server/scenario cells
- 24 rows per retained cell
- 12 matching-session superblocks per cell
- 2,160/2,160 reference-client balance

HMAC ordering is frozen before outcomes. The second session reverses row order
and uses the opposite reference-client assignment for matching rows. Execution
is one lane, so there is no concurrent-treatment balance control. Workers are
persistent but must prove complete reset between trials.

Retries never add post-outcome trial IDs. A treatment-independent transient
invalidates only its affected microblock and activates that microblock's
dormant mate. A failed retry, hard hardware/policy violation, or exhaustion of
the predeclared aggregate budget fails closed. No outcome-dependent
rescheduling or diagnostic fallback is permitted.

## ARM and monitor timing

Each endpoint window is armed with a 750 ms lead. Immediately before send, a
500 ms guard verifies that the whole window is still usable. A stale window is
transactionally cancelled and rebased, up to the frozen bound. A late ARM is a
structured rejection: it does not close the endpoint channel. The coordinator
recreates the worker and retries only the unstarted microblock under a separate
one-per-session control-plane budget.

Endpoint workload start and stop timing remains strict. Health-monitor
timestamps use observed boundaries: activity and APERF/MPERF calculations use
the actual observed interval. Monitor duration error may not exceed 0.1% and
the conservative phase-offset cap is 5 ms. Monitor wake lateness alone is not
misclassified as endpoint timing failure.

Tctl evidence combines boundary reads and the identified sensor stream. The
maximum permitted evidence gap is 250 ms; sensor loss beyond it fails closed.
The ceiling is 80°C. Any thermal breach, throttle counter increase, frequency,
governor/EPP/turbo, IRQ, scheduler, cgroup, swap, topology, isolation, or
external-noise violation invalidates the affected evidence according to its
hard-gate rule.

Live campaign monitoring is passive: service events and terminal snapshots are
allowed, but repeated polling of the live journal is prohibited.

## Host and identity qualification

Publication requires:

- a clean exact source archive, dependency pins, build flags, binaries, loaded
  libraries, toolchains, TLS assets, path profiles, schedule, and analysis
  identity;
- one isolated server physical core and four isolated client physical cores,
  with SMT siblings excluded and IRQs assigned to housekeeping CPUs;
- cgroup v2 delegation, zero swap for the service, fixed `performance`
  governor/EPP, turbo disabled, and 8 GiB endpoint memory ceilings;
- 180/180 fresh native interoperability records, balanced 90/90 over the two
  reference clients;
- host stability and four-client-core headroom qualification;
- an all-phase doctor pass on the exact identity.

The launcher may transactionally apply authorized temporary swap, power,
cgroup, and IRQ policy, then restore exact prior values. CPU isolation boot
arguments, missing kernel facilities, or unsupported hardware evidence require
operator action and possibly reboot; they are never fabricated by the
launcher. An unavailable required gate is `NOT_RUN`, never a pass.

## Statistical analysis

The primary family is
`estimand × scenario × path × metric × server_backend`. `ngtcp2perf` is the
baseline. The response is the paired log ratio, with positive values oriented
as better. Matching session rows form 12 superblocks.

Inference enumerates all 4,096 common sign patterns and uses the maximum
absolute t statistic across the 11 server-vs-baseline contrasts, controlling
the family-wise error rate at 0.05. The practical equivalence margin is
`log(1.03)`. Outputs include simultaneous intervals, superior/inferior/
equivalent/inconclusive classification, planning-variance misses, and separate
reference-client and session sensitivity. A variance miss does not disappear;
it constrains interpretation.

The frozen rho=0.25 calibration is unchanged from V2.2 because inferential
replication is unchanged:

| Criterion | Estimate | Exact one-sided 95% lower bound |
|---|---:|---:|
| Declared-effect power | 0.91504 | 0.91208 |
| Equivalence | 0.86680 | 0.86321 |
| Twice-margin power | 0.93216 | 0.92949 |

Calibration used 25,000 simulated campaigns per condition and passed the
predeclared 0.8 minimum.

## Runtime policy

The scheduled two-session floor is:

- measurement: 9,504 s
- warmup: 936 s
- 4,320 × 750 ms ARM lead: 3,240 s
- four physical probes: 241 s
- total: 13,921 s (3:52:01)

Historical pre-V2.3 spans are design evidence only, never publication input.
V2.3 changes V2.2 only by raising the operational session ceiling to 10,800 s
(3:00:00). It does not reuse any V2.2 trial.

The clean-start conservative budget is 1,200 s deterministic verification +
3,847.8 s admissions + 21,600 s sessions + 600 s analysis/finalization/export
= 27,247.8 s (7:34:07.8). The hard suite deadline is 30,000 s (8:20:00), leaving
2,752.2 s safety margin. Plan/create rejects an identity whose frozen
derivation exceeds the deadline. Exceeding an operational estimate alone does
not retroactively invalidate valid samples, but loss of continuous health
evidence does.

Useful-measurement fraction and intrinsic overhead are prominently reported
operational metrics, not publication gates. Rendering must finish within 60 s.

## Qualification and publication

The SQLite journal is authoritative. Resume requires the exact immutable
source, binary, build, host-policy, spec, schedule, and analysis identity.
Exports and logs are never progress or sample inputs.

`finalize` records `publication_qualified` only when cardinality, pairing,
workload, identity, timing, health, thermal, throttle, policy,
interoperability, physical admission, deterministic analysis, and checksums all
pass. `implementation_complete`, diagnostic output, a dirty run, or any
`NOT_RUN` gate is not publishable.

The [published campaign](results/v2/ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492/README.md)
is one host- and treatment-specific result, not a universal ordering.
