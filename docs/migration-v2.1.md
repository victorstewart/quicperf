# V2.1 publication methodology migration

V2.1 is a new, identity-bound publication methodology. It does not relabel,
import, or reinterpret V2 samples. A V2.1 campaign must use
`profiles/v2.1/publication.json`, a new source/binary identity, fresh
qualifications and interoperability evidence, and a brand-new SQLite journal.

The endpoint workload contract is unchanged. ARM, warmup, `T0`, `T1`,
STOP/acknowledgment, receiver validation, cardinality, TLS, workload validity,
schedule pairing, and exact source/binary/host identities retain their strict
V2 semantics.

V2.1 changes only the predeclared monitor and operational-runtime rules:

- The coordinator schedules each ARM window 750 ms ahead. Immediately before
  sending ARM it requires at least 500 ms of lead; a stale window is canceled
  in both the path and AMD boundary schedulers and the complete window is
  rebased. At most two pre-send rebases are allowed.
- An endpoint that receives ARM after its warmup boundary returns the structured
  `ARM_REJECTED` response and keeps its control channel open. The coordinator
  destroys both workers and supersedes only that unstarted microblock, then
  runs its exact preallocated retry. This control-plane retry has its own
  one-per-session budget; a rejection on the retry or budget exhaustion fails
  closed.
- Both target and observed boundary timestamps are retained. The observed
  timestamp is the midpoint of the coherent APERF/MPERF read.
- APERF/MPERF activity uses the actual observed interval. Boundary phase offset
  is capped at 5 ms and observed interval-duration error at 0.1%.
- Combined Tctl evidence may have a gap of at most 250 ms. A reading at or above
  80°C, sensor loss beyond that gap, counter loss, policy drift, any cgroup
  throttling, or monitor failure still fails closed.
- An isolated boundary phase/duration transient supersedes only its affected
  microblock and activates that microblock's exact preallocated retry. A failed
  retry is terminal. At most two localized transients may activate retries in a
  session.
- The two-monitor-transient cap and 6:06:00 per-session operational timeout
  were frozen from pre-V2.1 diagnostic evidence before the new campaign. The
  timeout carries the deterministic 675 ms-per-trial ARM-lead increase and
  three conservative worst-case retry blocks: two monitor transients plus the
  separate one-block ARM budget. Neither the timeout nor useful-wall fraction
  is a publication gate; both are prominently reported.

The evidence derivation is
`profiles/v2.1/evidence/pre-v2.1-runtime-policy.json` and is checksum-bound by
the profile. Campaign creation fails if it is missing or differs.

## Live operation

The durable publication-host service owns an active session; an SSH connection
does not. While a session is active, operators may follow the service's passive
event stream with `journalctl` or inspect service state with `systemctl show`.
Off-host telemetry is allowed only when it does not open the campaign run
directory.

Repeated live-journal polling is prohibited. Do not run `quicperfctl campaign
status`, direct `sqlite3` queries, or poll the SQLite journal, its WAL, logs, or
artifacts during a session. Those actions can perturb the coordinator and
monitor whose timing is being attested. Query the journal only after the
service exits at a session atomic boundary. The publication service itself
emits its terminal result and launches the next declared phase.

Canonical commands:

```sh
tools/run-publication-host -- tools/quicperfctl doctor \
  --profile profiles/v2.1/publication.json
tools/run-publication-host -- tools/quicperfctl campaign create \
  --profile profiles/v2.1/publication.json --out .run/publication-v2.1
tools/run-publication-host -- tools/quicperfctl campaign run \
  --run-dir .run/publication-v2.1 --session 1
tools/run-publication-host -- tools/quicperfctl campaign run \
  --run-dir .run/publication-v2.1 --session 2
tools/run-publication-host -- tools/quicperfctl campaign analyze \
  --run-dir .run/publication-v2.1
tools/run-publication-host -- tools/quicperfctl campaign finalize \
  --run-dir .run/publication-v2.1
tools/run-publication-host -- tools/quicperfctl export \
  --run-dir .run/publication-v2.1
```

Only an export whose fresh V2.1 journal records `publication_qualified` may be
copied under `docs/results/v2.1/`.
