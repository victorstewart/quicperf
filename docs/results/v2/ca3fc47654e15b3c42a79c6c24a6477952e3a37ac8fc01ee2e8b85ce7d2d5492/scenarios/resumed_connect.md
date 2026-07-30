# Resumed connection setup

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `lsperf` | 4,704.4 operations/s | 1.034 [1.029, 1.039] | inconclusive | within planning envelope | invariance supported | invariance supported | [TSV](../row-results.tsv#L12) |
| `s2nperf` | 4,657.9 operations/s | 1.024 [1.017, 1.031] | inconclusive | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L147) |
| `ngtcp2perf` | 4,549.4 operations/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L57) |
| `picoperf` | 3,741.0 operations/s | 0.822 [0.817, 0.827] | inferior | within planning envelope | invariance supported | invariance supported | [TSV](../row-results.tsv#L87) |
| `tquicperf` | 2,847.5 operations/s | 0.626 [0.622, 0.630] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L162) |
| `quiczigperf` | 1,782.2 operations/s | 0.392 [0.390, 0.394] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L117) |
| `neqoperf` | 871.2 operations/s | 0.191 [0.189, 0.194] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L42) |
| `quicheperf` | 577.9 operations/s | 0.127 [0.125, 0.129] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L102) |
| `quinnperf` | 453.4 operations/s | 0.100 [0.098, 0.101] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L132) |
| `noqperf` | 322.4 operations/s | 0.071 [0.070, 0.072] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L72) |
| `xquicperf` | 287.2 operations/s | 0.063 [0.062, 0.064] | inferior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L177) |
| `mvfstperf` | 271.0 operations/s | 0.060 [0.059, 0.060] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L27) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
