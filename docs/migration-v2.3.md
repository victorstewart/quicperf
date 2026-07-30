# Migrating to quicperf V2.3

V2.3 is a hard cutover from the former public scripts and from unpublished
V2/V2.1/V2.2 development profiles. There is no compatibility mode that can
upgrade old samples into V2.3 evidence.

## What changed

- `tools/quicperfctl` is the only publication coordinator.
- `profiles/v2.3/publication.json` is the only publication profile.
- Publication uses only the common C++ `iouring` backend.
- The primary design is 12 servers × 15 scenarios × 24 rows = 4,320 trials.
- Two balanced reference clients contribute equally; four client cores do not
  mean four client implementations.
- V2.3 has a 10,800-second operational ceiling per session and a
  30,000-second suite deadline.
- Scout/adaptive, capacity, memory, tail, symmetric, parity, legacy,
  all-confirmatory, and diagnostic-fallback command families were removed.
- `syscall` remains only in bounded developer mechanism diagnostics.

## Migrating automation

Replace script-specific publication calls with:

```sh
tools/run-publication-host -- \
  tools/quicperfctl doctor --profile profiles/v2.3/publication.json
tools/run-publication-host -- \
  tools/quicperfctl suite run --out .run/publication-v2.3
```

Resume only the exact run:

```sh
tools/run-publication-host -- \
  tools/quicperfctl suite resume --suite-dir .run/publication-v2.3
```

Unknown commands and old profiles fail. Do not translate environment variables
or positional endpoint arguments into publication claims.

## Data migration

There is none. V2.1 introduced observed monitor intervals, localized retries,
and hardened ARM recovery; V2.2 introduced the iouring-only primary design;
V2.3 changed only the per-session operational ceiling and its dependent suite
budget. Each version has a distinct methodology, schema, profile, schedule, and
identity. V2.3 does not reuse V2.2 samples.

Historical journals remain useful diagnostic/provenance records but cannot be
relabeled. Only an exact V2.3 campaign finalized as `publication_qualified` can
be published.

## Result consumers

Consume the compact campaign files under `docs/results/v2/<campaign-id>/`.
Use `status.json`, `analysis.json`, and `public-bundle-manifest.json` to bind
identity and qualification. Use `row-results.tsv` for retained cells and
`comparisons.tsv` for simultaneous intervals and sensitivity. Do not rank
unlike scenarios or ignore variance/sensitivity labels.
