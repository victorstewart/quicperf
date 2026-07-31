# 0-RTT request/response

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `lsperf` | 4,660.5 operations/s | 1.279 [1.272, 1.286] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L16) |
| `ngtcp2perf` | 3,643.6 operations/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L61) |
| `picoperf` | 3,586.4 operations/s | 0.984 [0.980, 0.988] | equivalent | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L91) |
| `tquicperf` | 1,643.8 operations/s | 0.451 [0.447, 0.455] | inferior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L166) |
| `quiczigperf` | 1,610.5 operations/s | 0.442 [0.439, 0.445] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L121) |
| `quicheperf` | 1,492.9 operations/s | 0.410 [0.408, 0.411] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L106) |
| `s2nperf` | 1,486.8 operations/s | 0.408 [0.405, 0.411] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L151) |
| `neqoperf` | 802.7 operations/s | 0.220 [0.219, 0.222] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L46) |
| `quinnperf` | 385.0 operations/s | 0.106 [0.104, 0.108] | inconclusive | planning envelope missed | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L136) |
| `noqperf` | 287.4 operations/s | 0.079 [0.078, 0.080] | inferior | within planning envelope | invariance supported | invariance supported | [TSV](../row-results.tsv#L76) |
| `mvfstperf` | 248.3 operations/s | 0.068 [0.068, 0.069] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L31) |
| `xquicperf` | 240.2 operations/s | 0.066 [0.066, 0.066] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L181) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
