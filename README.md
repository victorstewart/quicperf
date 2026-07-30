# quicperf

`quicperf` is a Linux benchmark system for controlled comparisons of QUIC
implementations through one shared packet-I/O, timing, workload, resource, and
measurement contract. The canonical coordinator is `tools/quicperfctl`; legacy
scripts are diagnostic compatibility surfaces, never publication paths.

The primary estimand is **fixed-treatment server performance**: one isolated
server physical core, exactly 16 active connections, four fixed reference-client
cores, a 50/50 mixture of the frozen ngtcp2 and picoquic reference clients, and
the same TLS, path, workload, backend, and resource treatment for all 12
servers. It is not a generic server effect and must not be described as
client-invariant when the sensitivity audit is unresolved or detects reference-
client dependence.

Separate campaign kinds estimate capacity frontier, fresh-process memory
intercept and per-connection slope, operation tails, and symmetric same-stack
behavior. Their results are never combined into one ranking.

- [Harness v2 guide](docs/harness-v2.md)
- [Benchmark contract](docs/methodology.md)
- [V2.1 methodology migration](docs/migration-v2.1.md)
- [Migration guide](docs/migration-v2.md)
- [Result index](docs/latest-results.md)
- [Control protocol](schemas/control-v1.md)

## Implementations

The canonical QUIC set, in frozen order, is `ngtcp2perf`, `lsperf`, `tquicperf`,
`quicheperf`, `picoperf`, `xquicperf`, `quinnperf`, `s2nperf`, `neqoperf`,
`noqperf`, `quiczigperf`, and `mvfstperf`. `tcpperf` is a TCP+TLS diagnostic
sidecar and is not part of a QUIC result family.

All publication adapters use the common C++ `quicperf_core` socket, event,
timer, measurement, and workload drivers. The two common packet-I/O backends are
`syscall` (`epoll`/`recvmmsg`/`sendmmsg`) and `iouring`. Rust and Zig code is a
packet engine behind the same borrowed-buffer batch boundary; it does not own a
socket, clock, pacing loop, or runtime worker.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel "$(nproc)"
```

Publication identity requires the frozen release policy: C/C++
`-O3 -DNDEBUG -march=native -mtune=native -flto=auto`; Rust `opt-level=3`, fat
LTO, one codegen unit, aborting panics, no debug or incremental build, and native
CPU; Zig `ReleaseFast` with native CPU. The effective commands, allocator,
dependencies, binaries, build IDs, and loaded libraries are attested. A
diagnostic build may differ but has a different identity and cannot finalize as
publication output.

## Canonical workflow

On a systemd host, run every publication command through the transactional
host-policy launcher:

```sh
tools/run-publication-host -- \
  tools/quicperfctl doctor --profile profiles/v2.3/publication.json
```

The launcher uses a transient delegated service, disables active unused swap,
sets governor/EPP to `performance`, disables turbo/boost, and enables the
service-owned `cpu`, `cpuset`, `memory`, and `pids` hierarchy. The same Python
process then becomes the quicperf coordinator; no extra policy process remains
in the measurement path. Measured physical-core siblings must first be isolated
at boot with topology-matched `isolcpus=domain,managed_irq`, `nohz_full`, and
`rcu_nocbs` arguments, with `irqaffinity` assigned to the complementary
housekeeping CPUs. The launcher reports the exact required arguments and fails
closed when a reboot is needed. It temporarily narrows writable IRQ affinities
to housekeeping CPUs. Read-only managed queues confined by the kernel to an
isolated CPU are covered by a zero-device-IRQ-delta gate during every timed
interval. If any host control must change, an interactive launch
prints the exact temporary plan and requires the operator to type `yes` before
mutation. Noninteractive automation must provide the per-invocation
`--allow-temporary-host-policy-changes` flag before `--`. Only controls changed
by that plan, including default and per-IRQ affinities, are restored to their
exact pre-run values on every normal, failed, or interrupted exit. A stale
crash-recovery state is restored before the next launch; concurrent launchers
are rejected.

```sh
tools/run-publication-host -- tools/quicperfctl doctor \
  --profile profiles/v2.3/publication.json
tools/run-publication-host -- tools/quicperfctl campaign create \
  --profile profiles/v2.3/publication.json --out .run/publication-v2.3
tools/run-publication-host -- tools/quicperfctl campaign run \
  --run-dir .run/publication-v2.3 --session 1
tools/run-publication-host -- tools/quicperfctl campaign run \
  --run-dir .run/publication-v2.3 --session 2
tools/run-publication-host -- tools/quicperfctl campaign status \
  --run-dir .run/publication-v2.3
tools/run-publication-host -- tools/quicperfctl campaign analyze \
  --run-dir .run/publication-v2.3
tools/run-publication-host -- tools/quicperfctl campaign finalize \
  --run-dir .run/publication-v2.3
tools/run-publication-host -- tools/quicperfctl export \
  --run-dir .run/publication-v2.3
```

After all exact-identity qualifications pass, the primary fixed-treatment
publication run is coordinated and crash-resumed as one frozen suite:

```sh
tools/quicperfctl suite plan
tools/run-publication-host -- tools/quicperfctl suite run \
  --out .run/publication-v2.3-suite
tools/run-publication-host -- tools/quicperfctl suite status \
  --suite-dir .run/publication-v2.3-suite
tools/run-publication-host -- tools/quicperfctl suite resume \
  --suite-dir .run/publication-v2.3-suite
```

The V2.3 campaign has exactly 4,320 inferential trials on one frozen
execution lane. Each selected reference-client implementation receives four
isolated client cores and four event-loop workers; “four client cores” does not
mean four client implementations. No peer-balance control is scheduled because
no second treatment runs concurrently. The exact two-session scheduled floor
is 3:52:01 and each session has a conservative 3:00:00 ceiling.
`suite plan` reports the exact 7:34:07.8 clean-start conservative budget and
refuses any derivation above the hard 8:20:00 deadline.

Only the primary campaign journal and schedule are created before the first
measured session. `suite status` derives state from those journals; it does not
maintain a competing sample or progress database. Capacity, memory, tail,
symmetric, all-confirmatory, and diagnostic fallback runs are outside V2.3.

An unqualified host cannot run the full suite: exhaustive diagnostic results
cannot qualify for publication. Use a bounded smoke or targeted benchmark run
only to investigate the failed gate.

`doctor` qualifies the current identities and host. `create` freezes the strict
canonical JSON spec, maximum schedule, seeds, retry slots, validity rules, and
analysis before confirmatory outcomes exist. `run` transactionally commits
complete balanced microblocks and safely resumes only an exact identity.
`analyze` is deterministic. `finalize` refuses incomplete, dirty, mismatched,
invalid, censored, unsupported, or unqualified campaigns.

No fixed-treatment publication step performs a saturation scout or chooses a
different load per implementation. Capacity search has its own profile and
command; all search observations are exploratory and held out from candidate
confirmation.

## Workloads

The fixed publication campaign contains 15 scenarios: `download`, `upload`,
`multistream_download`, `multistream_upload`, `bidi`, `loss_recovery`,
`flow_control`, `small_payload_pps`, `datagram`, `reqresp`, `stream_churn`,
`close_reset_cleanup`, `connect`, `resumed_connect`, and
`zero_rtt_reqresp`. Duration work is continuously replenished through the QPF2
application protocol; only receiver-validated completions inside the common
measurement interval form rate numerators. `bidi` keeps its two directions as
separate primary metrics.

Memory is a separate `memory_curve` campaign using fresh processes and the
common connection-count grid. It replaces the legacy idle-footprint row.
Tail is a separate eight-scenario campaign. Its exact-identity nonpublication
qualification derives nested 2/5/10/20-second prefixes, validates selected cells
with 20 held-out blocks and exact `2^20` common signs, then freezes one common
duration per scenario into the final schedule. Each final raw block retains the
first 1,024 eligible operations by start timestamp and sequence.

## Publication state

The repository contains no benchmark numbers. Prior generated outputs and the
mutable scout cache were removed because their provenance and fairness contract
do not satisfy v2. New result artifacts may be committed under
`docs/results/v2.3/` only after `finalize` records `publication_qualified` on a
qualified host.

Physical host qualification is not implied by a successful build or
deterministic test run. An unavailable gate required by the selected profile,
including client headroom, tail-window, runtime budget, or host health, is
recorded as `NOT_RUN`, which is a hard publication failure rather than a pass.
The fixed-treatment profile uses persistent workers with mandatory per-trial
reset attestation and makes exact 2-second-window claims (5 seconds for loss
recovery); it does not require separate fresh-process parity or long-window
equivalence campaigns.

## Diagnostic compatibility

Old positional endpoint invocation and `tools/run-benchmarks.sh` remain for one
release as targeted diagnostics. Their output cannot enter a v2 journal or
carry publication status. Use `tools/quicperfctl legacy translate` to convert
supported legacy environment settings into explicit JSON; unknown or
untranslatable options fail instead of being ignored.
