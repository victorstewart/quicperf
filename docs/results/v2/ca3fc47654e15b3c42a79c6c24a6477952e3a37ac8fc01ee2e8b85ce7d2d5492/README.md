# quicperf V2.3 qualified campaign

Campaign `ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492` is the publication-qualified fixed-treatment server
benchmark produced by source `44250d751e650f11f620733aa6e5d0498f947d12` (Git tree `a72228525e2f09fabd0b01cee4888e201a376ef4`).

The primary estimand is server performance on one isolated physical core at
exactly 16 active connections, using four isolated client cores and an equal
50/50 mixture of the `ngtcp2perf` and `picoperf` reference clients. All 12
servers use the common C++ `iouring` UDP backend. Two independently started
sessions contribute 24 raw rows and 12 matching-session superblocks per
server/scenario family.

All 4,320 planned samples are valid. Exact 4,096 common-sign inference produced
459 superior, 374 inferior,
15 equivalent, and
307 inconclusive pairwise classifications. These
counts span scenario-specific families and are not a global ranking.

## Scenario results

- [Download](scenarios/download.md)
- [Upload](scenarios/upload.md)
- [Multi-stream download](scenarios/multistream_download.md)
- [Multi-stream upload](scenarios/multistream_upload.md)
- [Bidirectional transfer](scenarios/bidi.md)
- [Small-payload packet rate](scenarios/small_payload_pps.md)
- [QUIC DATAGRAM](scenarios/datagram.md)
- [Request/response](scenarios/reqresp.md)
- [Stream churn](scenarios/stream_churn.md)
- [Connection setup](scenarios/connect.md)
- [Resumed connection setup](scenarios/resumed_connect.md)
- [0-RTT request/response](scenarios/zero_rtt_reqresp.md)
- [Loss recovery](scenarios/loss_recovery.md)
- [Flow control](scenarios/flow_control.md)
- [Close/reset cleanup](scenarios/close_reset_cleanup.md)

## Machine-readable evidence

- [`row-results.tsv`](row-results.tsv): 180 retained server/scenario rows
- [`comparisons.tsv`](comparisons.tsv): simultaneous intervals and sensitivity
- [`quality-audit.tsv`](quality-audit.tsv): all 4,320 validity decisions
- [`scenario-coverage.tsv`](scenario-coverage.tsv): canonical capability audit
- [`status.json`](status.json), [`analysis.json`](analysis.json),
  [`manifest.json`](manifest.json), and [`spec.json`](spec.json): terminal
  qualification and identity
- [`public-bundle-manifest.json`](public-bundle-manifest.json): hashes and
  authoritative source paths for this compact bundle
- [`release-assets.json`](release-assets.json): full-evidence asset inventory

Dataset files are licensed under [CC BY 4.0](DATA-LICENSE.txt). Code remains
Apache-2.0. See [citation instructions](CITATION.md).
