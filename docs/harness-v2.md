# quicperf V2.3 operator guide

V2.3 has one publication path: the fixed-treatment primary campaign in
[`profiles/v2.3/publication.json`](../profiles/v2.3/publication.json).
`tools/quicperfctl` is the only publication coordinator. Developer diagnostics
cannot write a publication journal or receive publication status.

## Before running

Use a dedicated Linux systemd host with:

- the required compilers and pinned dependency toolchains;
- Linux io_uring, cgroup v2 delegation, APERF/MPERF, the declared AMD Tctl
  sensor, and the required throttle evidence;
- one server physical core, four client physical cores, and separate
  housekeeping CPUs;
- no competing benchmark or repeated live-journal poller.

Build the exact release tree:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel "$(nproc)"
ctest --test-dir build --output-on-failure
python3 -m unittest discover -s tests -p 'test_*.py'
tools/run-mechanism-workload-smoke.sh
tools/run-high-value-workload-smoke.sh
tools/run-tls-verify-audit.sh
```

Do not select an arbitrary old build directory. Reuse one only when its source
path, compiler, dependency graph, configuration, and generated build graph
still match.

## Host preparation

Run doctor through the host-policy launcher:

```sh
tools/run-publication-host -- \
  tools/quicperfctl doctor --profile profiles/v2.3/publication.json
```

The launcher can prepare a transient delegated service, disable active unused
swap for that run, select `performance` governor/EPP, disable turbo/boost, and
move writable IRQ affinities to housekeeping CPUs. Interactive mode prints the
exact temporary plan and requires `yes`. Noninteractive automation must
explicitly authorize it:

```sh
tools/run-publication-host --allow-temporary-host-policy-changes -- \
  tools/quicperfctl doctor --profile profiles/v2.3/publication.json
```

Only values changed by the transaction are restored, on success, failure, or
interruption. A stale recovery record is restored before a new launch.
Concurrent launchers are rejected.

The launcher cannot manufacture CPU isolation or missing kernel/hardware
support. If doctor prints required `isolcpus=domain,managed_irq`, `nohz_full`,
`rcu_nocbs`, or `irqaffinity` boot arguments:

1. apply the exact topology-specific arguments to the bootloader;
2. reboot;
3. verify `/proc/cmdline`, physical-core sibling sets, and housekeeping IRQ
   placement;
4. rerun doctor.

Never mark an unavailable physical gate passed. `NOT_RUN` blocks publication.

## Command surface

```text
quicperfctl doctor
quicperfctl campaign create|run|status|analyze|finalize
quicperfctl qualification run|store|acquire|status
quicperfctl suite plan|run|resume|status
quicperfctl export
```

Removed scout, adaptive, capacity, memory, tail, symmetric, parity, legacy, and
diagnostic-fallback commands have no compatibility mode in V2.3.

## Preferred suite workflow

First inspect the immutable timing plan:

```sh
tools/quicperfctl suite plan
```

It must report:

- 4,320 primary trials and 8,640 maximum IDs;
- 13,921 s scheduled floor;
- 10,800 s ceiling per session;
- 27,247.8 s clean-start conservative budget;
- 30,000 s hard suite deadline.

Then run the crash-resumable suite:

```sh
tools/run-publication-host -- \
  tools/quicperfctl suite run --out .run/publication-v2.3
```

The suite executes only:

1. deterministic identity verification;
2. 180-tuple native interoperability;
3. host-stability and four-client-core headroom qualification;
4. all-phase doctor;
5. primary session 1;
6. primary session 2;
7. analysis, finalization, export, and checksums.

A gate or deadline failure stops nonpublication. There is no diagnostic
fallback or extra campaign.

## Passive status and resume

While a session is active, use service events rather than repeatedly querying
the live journal. At a safe boundary or after the service exits:

```sh
tools/run-publication-host -- \
  tools/quicperfctl suite status --suite-dir .run/publication-v2.3

tools/run-publication-host -- \
  tools/quicperfctl suite resume --suite-dir .run/publication-v2.3
```

The run-directory SQLite journal is authoritative. Resume accepts only the
exact frozen source, binary, build, host-policy, profile, schedule, and analysis
identity. TSVs, logs, and suite status are not sample or progress inputs.
Persistent workers use transactional ARM cancellation/rebase and structured
late-ARM recovery; only an unstarted microblock can consume its preallocated
retry.

## Manual campaign workflow

The suite is preferred because it binds admissions and deadline policy.
Individual campaign commands remain available for controlled reproduction:

```sh
tools/run-publication-host -- tools/quicperfctl campaign create \
  --profile profiles/v2.3/publication.json --out .run/publication-v2.3-manual
tools/run-publication-host -- tools/quicperfctl campaign run \
  --run-dir .run/publication-v2.3-manual --session 1
tools/run-publication-host -- tools/quicperfctl campaign run \
  --run-dir .run/publication-v2.3-manual --session 2
tools/run-publication-host -- tools/quicperfctl campaign analyze \
  --run-dir .run/publication-v2.3-manual
tools/run-publication-host -- tools/quicperfctl campaign finalize \
  --run-dir .run/publication-v2.3-manual
tools/run-publication-host -- tools/quicperfctl export \
  --run-dir .run/publication-v2.3-manual
```

Creating freezes canonical JSON, seeds, HMAC ordering, all primary and dormant
retry IDs, qualifications, validity rules, and analysis before outcomes exist.
Running commits complete microblocks atomically. An interruption never converts
a partial microblock into evidence.

## Qualification artifacts

Fresh exact-identity interoperability must contain 180 PASS records:
12 servers × 15 scenarios, balanced 90/90 across `ngtcp2perf` and `picoperf`,
all on `iouring`. A handshake alone is insufficient; each tuple must validate
the scenario workload, terminal semantics, negotiated treatment, and cleanup.

Required physical gates are host stability and four-client-core headroom.
Qualification store entries are content-addressed by all relevant source,
binary, profile, topology, host-policy, and measurement identities. A stale or
foreign artifact is rejected.

## Finalization and publication

`campaign analyze` is deterministic and outcome-read-only. `finalize` requires
4,320/4,320 valid samples, exact pairing, all hard gates, and canonical
artifact checksums. Successful build/tests alone are not qualification.

To reproduce the committed compact result bundle from the qualified immutable
campaign:

```sh
python3 tools/publish-v2-3-results.py \
  --campaign-dir .run/publication-v2.3/fixed \
  --repo-root .
python3 tools/publish-v2-3-results.py \
  --campaign-dir .run/publication-v2.3/fixed \
  --repo-root . --check
```

The publisher reads canonical immutable artifacts, never a live journal. It
rejects any wrong identity, missing row, invalid sample, checksum mismatch, or
oversized allowlisted file.

## Developer diagnostics

`tools/run-benchmarks.sh` and the retained mechanism, workload, and TLS smokes
are bounded diagnostics. The syscall backend may appear there to validate
mechanisms. Diagnostic output must remain outside `docs/results/` and cannot be
relabeled as V2.3 evidence.
