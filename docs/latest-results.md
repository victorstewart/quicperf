# quicperf v2 result index

There are currently no publication-qualified v2 results in this repository.

All previously committed generated claims, result indexes, calibration output,
and fixed-design scout data were removed during the harness v2 cutover. They are
not numerical parity targets and must not be restored or imported into a v2
campaign.

Future entries may link only immutable artifacts under [`results/v2/`](results/v2/)
whose campaign finalized with `publication_qualified`. A successful build,
deterministic test suite, diagnostic run, incomplete session, or
`implementation_complete` status is insufficient. Any required physical gate
recorded as `NOT_RUN` prevents an entry here.

Current exact-identity campaign evidence is absent. Lane interference, client
headroom, publication runtime budgets, and publication host isolation/health
are therefore `NOT_RUN` for this index. Persistent-worker reset integrity and
fixed-window validity are checked in every primary trial rather than by
separate multi-hour prerequisite campaigns. These are unexecuted external
validation gates, not passes or measured failures.

The checked-in 25,000-campaign calibration passes the frozen implementation,
FWER, coverage, equivalence, and 80% power gates for the current 12
session-paired-superblock design. It retains the older underpowered design only
as explicit noncurrent failure evidence.

Each future entry must identify its estimand, campaign and manifest hashes,
source and binary identities, host policy, two independent sessions, fixed
treatment, reference-client mixture, packet-I/O backend, path, metric, validity
audit, simultaneous inference family, and sensitivity labels. Fixed-treatment,
capacity, memory, tail, and symmetric results must remain in separate tables.
