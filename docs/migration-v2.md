# Migrating to harness v2

Harness v2 is a hard publication cutover. Old generated results, calibration
outputs, fixed-design plans, and scout caches are intentionally not imported.
They used a different estimand, identity, schedule, and validity contract and
are not parity targets.

The one retained migration comparison is generated fresh with
`tools/quicperfctl legacy parity`. Numeric cells compare the public legacy
environment translation against the native V2 treatment through distinct
strict endpoint executions under one immutable 384-cell, 20-pair-per-cell plan.
Only the deliberately invalid legacy loss and retired idle-footprint cells
exercise the retained positional path. The artifact is migration evidence only
and is never installed under `docs/results/v2/`. On a physically unqualified
host it is explicitly watermarked diagnostic evidence.

## Command mapping

| Legacy surface | v2 behavior |
|---|---|
| `tools/run-publication-suite.py` | Fails with a precise migration message; start the canonical v2 campaign explicitly. |
| `tools/run-fixed-publication-suite.py` | Fails with exit 4; old plan files are not accepted or executed. |
| `tools/run-saturation-scout.py` | Fails with exit 4 and points to the separate frozen capacity workflow. |
| `tools/run-adaptive-publication-suite.py` | Fails with exit 4; the independent adaptive engine is removed. |
| `tools/run-benchmarks.sh` | Targeted row diagnostic; it cannot emit a v2 publication status or journal record. |
| `tools/render-latest-results.py` | Fails rather than rendering legacy TSVs; use canonical analyze/export and admit only a qualified export. |
| Positional `<binary> server|client ...` | One-release endpoint diagnostic; excluded from the control protocol and v2 journal. |

Use the canonical fixed-treatment workflow for publication:

```sh
tools/quicperfctl doctor --profile profiles/v2/publication.json
tools/quicperfctl campaign create \
  --profile profiles/v2/publication.json --out .run/publication-v2
tools/quicperfctl campaign run --run-dir .run/publication-v2 --session 1
tools/quicperfctl campaign run --run-dir .run/publication-v2 --session 2
tools/quicperfctl campaign analyze --run-dir .run/publication-v2
tools/quicperfctl campaign finalize --run-dir .run/publication-v2
```

Do not translate the old saturation-selected concurrency into the publication
profile. Fixed treatment is always 16 active connections for every server.
When maximum stable load is the question, use `capacity`; its search rows remain
exploratory and its held-out confirmation is reported as `capacity_frontier`.

Do not translate the old idle-footprint row. Use the `memory` workflow, which
starts a fresh process for every common N point and reports both intercept and
per-connection slope. Do not interpret symmetric same-stack observations as
server-only results; use the symmetric diagnostic profile and its exact label.

## Environment translation

V2 does not read benchmark configuration from the environment. Run
`tools/quicperfctl legacy translate` to produce explicit strict JSON. Every
supported setting appears in the output. An unknown, ambiguous, conflicting,
dead, or semantically untranslatable variable is a configuration error; no
option is silently ignored.

Output directories are exclusively owned. A legacy file tree is never a resume
source. To resume, use the same v2 run directory and immutable campaign identity;
the journal selects the next incomplete scheduled state.

## Result and terminology changes

P50/P90/P99 tables from aggregate legacy trials are not v2 inference. V2 uses
12 complete Williams microblocks, paired log ratios, simultaneous max-|t|
intervals, explicit practical margins, and separate sensitivity estimates.
Operation-tail claims require the dedicated tail campaign.

Removed legacy terminology: `tie` and `statistical_tie`. Non-significance does
not establish similarity. V2 classifications are `superior`, `inferior`,
`equivalent`, or `inconclusive`; equivalence requires the full simultaneous
interval inside the predeclared practical margin.

Old `publishable`, `converged`, or ranking labels do not map to
`publication_qualified`. A v2 campaign must pass the current clean-source,
identity, cardinality, fairness, validity, inference, two-session, and physical
qualification gates. `NOT_RUN` is not a pass.
