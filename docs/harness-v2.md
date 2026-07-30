# Harness v2 operations

`tools/quicperfctl` is the sole coordinator and publication entry point. It
loads strict canonical JSON, records all authoritative state in a SQLite WAL
journal, supervises already-built endpoints through Unix `SOCK_SEQPACKET`, and
exports deterministic reports. Stdout and stderr are bounded diagnostics, not
state or sample sources.

## Command surface

```text
quicperfctl doctor --profile <profile.json>
quicperfctl doctor --profile <profile.json> --phase deterministic \
  --refresh-interoperability
quicperfctl campaign create --profile <profile.json> --out <run-dir>
quicperfctl campaign run --run-dir <run-dir> --session <1|2>
quicperfctl campaign status --run-dir <run-dir>
quicperfctl campaign analyze --run-dir <run-dir>
quicperfctl campaign finalize --run-dir <run-dir>
quicperfctl capacity create|run|analyze|finalize ...
quicperfctl memory create|run|analyze|finalize ...
quicperfctl tail create|run|analyze|finalize ...
quicperfctl suite run --out <suite-dir> [--seed <64-hex>]
quicperfctl suite status --suite-dir <suite-dir>
quicperfctl suite resume --suite-dir <suite-dir>
quicperfctl qualification run|store|acquire|status \
  --kind <gate> --run-dir <run-dir> --artifact-store <store>
quicperfctl export --run-dir <run-dir>
quicperfctl legacy translate ...
```

Exit codes are stable across commands:

| Code | Meaning |
|---:|---|
| `0` | The operation completed; for `finalize`, the campaign is publication-valid. |
| `2` | Execution completed, but the campaign/result is nonpublishable. |
| `3` | Interrupted or incomplete and safely resumable. |
| `4` | Invalid configuration, failed preflight, or identity mismatch. |
| `5` | Internal orchestration, protocol, or storage failure. |
| `130` | User interrupt. |

A completed session can return `0` while status is `awaiting_session`.
`finalize` returns `2` until both independent required sessions are complete and
valid.

## Profiles

The canonical publication profile is
`profiles/v2.3/publication.json`. Legacy and non-primary profiles remain under
their original versioned directories:

- `publication.json`: canonical fixed-treatment server campaign;
- `capacity.json`: separate common-domain exploratory search and held-out
  confirmation;
- `memory.json`: fresh-process memory curve;
- `tail.json`: per-operation tail observations;
- `symmetric-diagnostic.json`: same-stack client/server diagnostic;
- `ci-smoke.json`: deterministic and fake-endpoint CI surface;
- parity and optional lane-interference, worker-reuse, window-equivalence, and
  tail-window validation profiles.

Loading rejects unknown or duplicate fields, missing fields, invalid identifiers
or paths, non-finite/overflow values, nonpositive durations, invalid enums, and
cross-field inconsistencies. A profile is an input to `create`; the immutable
copy inside the run directory is authoritative thereafter.

Every analysis plan also freezes the SHA-256 and selected planning result from
`profiles/v2/statistical-simulation/calibration-v2.json`. The coordinator
compares those exact bytes before execution. The checked-in v3 artifact contains
25,000 fixed-seed campaigns per required condition. Its 24-raw-row,
12-session-paired-superblock design passes the frozen equivalence and power
gates at both `rho=0` and the conservative `rho=0.25` planning boundary. It
retains the old single-session 12-row failure only as noncurrent failure
evidence.

## Workflow

### Doctor

`doctor` checks current source/build identities, exact binaries and loaded
libraries, endpoint capabilities and interoperability, TLS, workload oracles,
clock bridge, common packet-I/O settings, topology, cgroups, IRQs, path control,
host health, and resource availability. It never chooses a server-specific load
or imports old capability/result data.

Native interoperability is an exact current-binary preflight, not capability
metadata or a second benchmark campaign. It exercises every one of the 12 × 15
server/scenario combinations once (180 tuples). V2.3 uses `iouring` for both
endpoint roles; the two reference-client implementations are balanced 90/90
overall and 6/6 within each scenario. Refresh uses the common strict CONFIG,
TLS, QPF2, path,
cgroup, process-supervision, completion, STOP/ACK, and cleanup path,
checkpoints only a canonical plan prefix, and emits one PASS/FAIL record for
every tuple. The final 4,320-trial campaign—not this preflight—validates the
12 × 2 × 1 × 15 design over all 12 Williams rows in both sessions.
Preflight runs serially on the first qualified lane with a 250 ms post-trial
quiescence interval; concurrency is not part of this semantic gate. Ordinary
doctor loads the immutable
content-addressed artifact from `.data/interoperability-v2`; a changed source,
dependency, binary, loaded library, protocol, profile, TLS, runner, kernel, or
host-policy identity makes that artifact unavailable rather than reusable.

Qualification artifacts are exact-identity, content-addressed pass/fail
evidence, not benchmark observations, and cannot change a treatment or
substitute for current-session trials. The primary publication requires only
host stability and exact four-core client headroom. Lane interference is not a
gate for the frozen single-lane treatment.
Persistent workers are a frozen steady-state treatment whose reset inventory,
FD/task ownership, process set, and cgroup state are re-attested after every
trial. Allocator arenas and library-global caches may persist as part of this
named service-process treatment; connections, streams, timers, tickets, and
queued transport work may not. Its reported rates are explicitly the profile's
2-second windows
(5 seconds for loss recovery), so the primary claim does not require or imply
2/5-second equivalence to 10/20-second windows. Worker-reuse and window
equivalence commands remain available for separate research questions.

V2.3 retains the V2.1/V2.2 monitor attestation without changing endpoint
workload timing.
The journal retains each scheduled target and the observed midpoint timestamp
of each coherent APERF/MPERF read. Boundary phase is capped at 5 ms, observed
interval-duration error at 0.1%, and combined Tctl evidence gaps at 250 ms while
the strict 80°C ceiling and zero-throttling/policy gates remain fail closed.
Combined cadence uses the timestamp-ordered primary and watchdog samples,
independently of watchdog message-delivery latency.
Only an isolated boundary cadence transient supersedes its affected microblock
and activates that block's exact preallocated mate. A failed mate, more than two
localized transients in one session, sensor loss, continuous-monitor loss, or a
hardware/policy violation is terminal. The historical derivation is immutable
profile evidence, not an input learned from the new campaign.

The migration parity exercise is separate nonpublication evidence and is not a
publication prerequisite. Run it only when the question is whether the retired
legacy translation matches V2. It freezes 384
`(implementation, server backend, legacy scenario)`
cells and 20 deterministic pairs per cell. Each numeric pair validates the
public legacy environment translation against the frozen V2 treatment, then
executes distinct translated-legacy and native-V2 strict endpoint trials in a
seeded-balanced order on the same server and client cores. Both trials share
the pair's trace seed; the translated legacy client uses the frozen io_uring
reference-client backend. Both sides use the parity gate's 500 ms measurement
interval, except `close_reset_cleanup`, which uses its ordinary two-second
interval so every observation can satisfy the frozen 100-per-stratum terminal
cardinality. The 336 numeric cells require their 90% paired V2/legacy rate interval
inside `[0.97, 1.03]` and exact common settings/status semantics. Per-trial
operation-resolution censoring remains visible but is decided by this
20-pair-specific interval. The 24 legacy `loss_recovery` cells preserve the
retained positional CLI's unsynchronized periodic-drop model as invalid and
require V2 to reject that condition in favor of seeded QUIC-packet loss. The
24 obsolete `idle_footprint` cells preserve the positional legacy unsupported
classification and require V2 to reject that estimand in favor of
`memory_curve`.

The parity run owns an immutable `plan.json` and a WAL/FULL SQLite journal.
Every mode result commits under its precomputed pair ID, so the same command
resumes without creating observations. A qualified run requires two-lane
qualification, continuous AMD evidence, at most 3.5 hours wall time, and useful
measurement intervals totaling at least 75% of wall time. When an exact physical
qualification has already failed, the coordinator refuses
`--diagnostic-unqualified-host`: executing all 7,680 pairs on one lane cannot
satisfy Milestone A. Debug the failed qualification or parity cell with a
bounded targeted run instead. This 3.5-hour limit belongs only to the optional
migration-parity diagnostic; it is not the primary publication runtime.

Tail-window qualification freezes 384 twenty-second screening primaries and
7,680 possible twenty-block held-out primaries, each with one dormant retry ID.
Every exercise yields nested 2/5/10/20-second prefixes. Screening mechanically
nominates durations and servers; held-out analysis enumerates all 1,048,576
common 20-block sign assignments. A final tail campaign created with the exact
qualified artifact stores the selected common duration in every scenario cell.
Tail execution refuses an absent artifact or any mismatch between that decision
and its frozen schedule.

The tail workflow uses an identity run only to host nonpublication
qualification evidence, then creates the executable campaign from the resulting
content-addressed decision:

```sh
tools/quicperfctl tail create --profile profiles/v2/tail.json \
  --out .run/tail-window-identity
tools/quicperfctl qualification run --kind tail-window \
  --run-dir .run/tail-window-identity \
  --artifact-store .run/qualification-store
tools/quicperfctl tail create --profile profiles/v2/tail.json \
  --out .run/tail-v2 --qualification-store .run/qualification-store
```

The first run directory is never executed as a tail campaign. The second create
must resolve the exact same source, binary, dependency, profile, TLS, protocol,
kernel, microcode, topology, and host identity or acquisition fails closed.

### Create

`create` requires an unowned output directory. It freezes:

- canonical experiment and stable identity manifests;
- complete maximum schedule, cells, trial IDs, attempt IDs, trace seeds, and
  preallocated whole-microblock retry slots;
- source, dependency, build, binary, loaded-library, and host-policy identities;
- validity, completion, analysis, and multiplicity policy;
- exact physical CPU, NUMA, cgroup, lane, IRQ, and housekeeping assignments.

The campaign ID derives from the complete immutable basis. No outcomes or prior
measurements are read.

### Run and resume

`run` acquires the campaign lock and verifies the entire frozen identity before
starting. It owns endpoint process groups, pidfds, inherited control sockets,
reserved ports, cgroups, namespaces, qdiscs, and cleanup records. No shell or
nested Python process exists in the per-trial path.

One server and one reference-client worker are configured for each trial. The
server binds through the supervisor-owned reservation, then its bound address is
sent to the client. Both endpoints and the path controller reach readiness
before a common raw-clock ARM barrier starts warmup/measurement and a dynamic
trace.

Python is control-plane code, not a measured packet or workload engine. The
native endpoints own UDP receive/send, QUIC packet processing, workload
generation, pacing, transport timers, measurement timestamps, and numerator
construction on their frozen lane cores. The coordinator is pinned to the
frozen housekeeping cores, except that an active AMD stability monitor
exclusively reserves its selected housekeeping CPU. The coordinator sends only
bounded lifecycle/progress control packets and performs no journal writes
during the measurement interval. Each result records coordinator affinity,
coordinator CPU time, control-packet count, and the zero-write invariant.
Indirect scheduler/cache/IRQ interference is not assumed away:
core-isolation health, treatment-specific client headroom, per-trial scheduler
and IRQ telemetry, and applicable tail-window qualifications must pass for the
exact campaign identity. The primary campaign has no lane-interference gate
because it never runs concurrent lanes.
Persistent-worker reset integrity and fixed-window validity are instead
checked on every primary trial.

Trial health loads a minimal scheduler-tracepoint eBPF program before endpoint
startup and enables it only across the armed interval. On each measured CPU it
classifies the previous non-idle task by exact server/client cgroup identity and
accumulates only non-owned runtime; numeric device-IRQ counters remain a
separate rejection gate. The program attaches no network hook and reads no
packet or application data. Loading requires the BPF/perf authority supplied by
the publication-host service, fails closed when unavailable, and all map,
program, and event descriptors are closed with the trial.

The `close_reset_cleanup` treatment uses one actor and one observer per
operation. After validating the one-byte proof, the receiver acknowledges the
selected terminal flag and alone performs FIN, RESET_STREAM, STOP_SENDING, or
CONNECTION_CLOSE. The initiator counts only the matching peer transport fact.
Each result exposes all four stratum rates; their equal-weight geometric mean is
nonclaimable when any stratum has fewer than 100 completions.

A microblock becomes an inferential observation only after all 12 planned
server positions commit atomically. Interruption leaves partial attempts
diagnostic and resumable. Recovery verifies ownership before reaping resources;
it cannot signal a reused PID. Resume never edits the frozen schedule and never
duplicates a committed trial.

### Bounded publication suite

`suite run` is the canonical V2.3 publication coordinator. Its only claim set
is `fixed_treatment`, the primary server estimand. Capacity, memory, tail,
symmetric, all-confirmatory, and diagnostic fallback campaigns are outside the
V2.3 suite.

`suite plan` performs no writes and reports the selected trial cardinality,
measurement time, warmup time, serial arm floor, individual arm-lead floor,
scheduled floor, and fixed-treatment operational timeout before execution. For
the default profile it also reports the 180-tuple balanced interoperability
preflight, the two required admission gates (`host-stability` and
`client-headroom`), the `persistent_reset` worker treatment, and exact
frozen-window claim scope.

The one-lane campaign contains exactly 4,320 inferential trials and no
peer-balance controls. Its 9,504 measurement seconds plus 936 warmup seconds
form a 10,440-second endpoint arm path. The 4,320 individual 750 ms arm leads
add 3,240 seconds and the four mandatory AMD probes add 241 seconds, producing
an exact 13,921-second (3:52:01) scheduled floor for both sessions. Each session
contains 2,160 trials and 180 microblocks. V2.3 freezes a 10,800-second
(3:00:00) ceiling per session.

The frozen clean-start conservative budget is deterministic verification
1,200 s + full admission reservation 3,847.8 s + both session ceilings
21,600 s + final processing 600 s = 27,247.8 s (7:34:07.8). The suite hard
deadline is 30,000 s (8:20:00); plan/create rejects a larger derivation.

Before it starts a session, the coordinator writes a canonical suite identity
and creates only the selected campaign journals in frozen estimand order. The
suite seed deterministically derives a distinct campaign seed for each journal.
Profile hashes, campaign IDs, schedule hashes, planned cardinalities, and
maximum preallocated trial-ID cardinalities are recorded in `suite.json`; any
later profile or journal identity change fails closed. A fixed-treatment
session cannot admit a block that would exceed the frozen 3:00:00 ceiling plus
finalization reserve. A ceiling or gate failure stops nonpublication.

`suite status` is read-only and derives progress from the selected campaign
journals. `suite resume` completes an interrupted freeze, then resumes only
nonterminal sessions before deterministic analysis and finalization. The suite
file is orchestration identity, not a second sample store: campaign SQLite
journals remain the sole authorities for attempts, samples, retries, analysis,
and terminal status. An exclusive suite lock rejects concurrent coordinators,
and each suite-state replacement is file- and directory-synced.

The suite refuses `--diagnostic-unqualified-host`: an unqualified host cannot
produce publication evidence. V2.3 has no diagnostic fallback or
outcome-dependent rescheduling.

### Analyze and finalize

`analyze` reads committed journal facts and deterministically rebuilds quality,
cardinality, fixed-estimand, simultaneous-comparison, sensitivity, and audit
tables. It does not read human logs or exported TSV files. A renderer refuses
mixed estimands, clients, backends, paths, loads, TLS treatments, or metrics.
`cleanup-strata.tsv` reports each close/reset completion count and rate beside
the equal-weight geometric-mean sample metric.

Intrinsic nonmeasurement overhead excludes the accepted 750 ms ARM lead,
warmup, measurement, and scheduled parallel padding; it still charges all
setup, control, teardown, and extra rebase time. Finalization enforces the
unchanged 250 ms median, 750 ms p95, and 60-second deterministic-render gates.

`finalize` independently checks hashes and exact cardinality, complete paired
microblocks, the two required sessions, clean provenance, configured binary and
capability coverage, validity/censoring, simultaneous inference, qualification
artifacts, and physical runtime/health evidence. Any missing or `NOT_RUN` gate
returns nonpublishable status.

`export` writes a deterministic, atomically replaced artifact tree. Export does
not change campaign state or qualify a run.

## Run-directory authority

The journal is the sole mutable authority. The run directory contains immutable
canonical spec/manifest/schedule material, the WAL database and lock, bounded
human logs, cleanup ownership records, deterministic analysis, and atomic
exports. Names and exact layout are schema-versioned; consumers must use the
export command rather than scraping internal files.

Stale logs, copied TSV files, duplicate packets, reused output directories, and
partial exports cannot become samples. Committed records are immutable, and
every terminal state retains its reason.

## Physical qualification

The publication topology requires at least seven eligible physical cores: one
server core, four reference-client cores, and two
coordinator/path/IRQ/housekeeping cores. The primary profile freezes exactly
one execution lane; a second publication lane is forbidden rather than
conditionally enabled.

Publication commands on a systemd host use `tools/run-publication-host --
tools/quicperfctl ...`. The launcher creates one transient service with an
empty delegated root and a coordinator subgroup, activates only `cpu`,
`cpuset`, `memory`, and `pids` below that root, and points the harness at that
owned hierarchy. It snapshots swap, governor, EPP, turbo/boost, and boot
identity before changing anything. Publication also requires every SMT sibling
of every measured physical core to be boot-isolated with `isolcpus=domain,managed_irq`,
`nohz_full`, and `rcu_nocbs`, while `irqaffinity` names exactly the remaining
housekeeping CPUs. The launcher fails with the required topology-derived kernel
arguments if that boot policy or its sysfs readback is absent. A read-only
managed queue whose kernel mask contains only isolated CPUs cannot be redirected;
it is permitted only because the kernel activates it for I/O submitted on that
CPU, and every numeric device-IRQ counter on measured CPUs must have zero delta
across the timed interval. When runtime-writable default or per-IRQ affinities
need narrowing, the launcher includes every write in the consent plan and routes
them to housekeeping CPUs for the invocation.

The run identity freezes the boot policy, default mask, configured per-IRQ
affinities, and control writability. It intentionally excludes a managed
interrupt's dynamic `effective_affinity_list`: the kernel may move that
assignment within its frozen allowed mask as queues activate. Safety is still
fail-closed because snapshot/preparation validates the effective assignment,
and timed trials require zero numeric device-IRQ deltas on measured CPUs.
The runtime target also excludes the housekeeping physical core reserved for
the exact-boundary monitor; writable IRQs and the default mask use the other
housekeeping core.

An installed boot-isolation set may be a strict superset of the seven-core
publication requirement, allowing an intentionally unused core to remain
isolated across reboots. Every endpoint core and the monitor CPU must be in the
installed `isolcpus`, `nohz_full`, and `rcu_nocbs` sets; every additional
isolated CPU remains unavailable to coordinator and IRQ work. The effective
housekeeping set is the exact complement of the installed isolation policy;
IRQ targets additionally exclude the monitor's physical core. Accepting a
superset therefore does not weaken timed isolation.

When changes are required, the launcher prints the exact plan and requires
interactive `yes`; noninteractive automation must pass
`--allow-temporary-host-policy-changes` for each invocation. A digest of that
authorized plan is rechecked inside the delegated service immediately before
mutation. Preparation refuses swap with live pages; restoration changes only
the authorized controls and reproduces their active swap devices/priorities,
CPU values, default IRQ mask, and per-IRQ affinity lists after success, failure,
or interruption. The preparation process directly becomes the existing Python
coordinator, so it does not add another process to the measured control plane.
An exclusive launcher lock prevents one invocation from restoring another
invocation's state.

Deterministic implementation verification does not substitute for host
qualification. If a gate required by the selected profile—such as isolation,
privilege, core count, interference, tail-window, runtime, thermal, clock,
cgroup, IRQ, or health—cannot run, record it as `NOT_RUN`. This is a hard
`finalize` failure.

Completion labels have one meaning:

- `implementation_complete`: required code and deterministic tests pass; any
  unavailable physical gates are explicitly `NOT_RUN`;
- `publication_qualified`: every deterministic and physical/runtime gate passes
  for the exact campaign identity and the canonical matrix has no unexpected
  missing or unsupported cell.

Only the second state permits an export to be linked from the public result
index.
