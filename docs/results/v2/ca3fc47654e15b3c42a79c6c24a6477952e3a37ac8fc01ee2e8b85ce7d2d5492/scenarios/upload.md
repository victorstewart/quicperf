# Upload

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `picoperf` | 1.571 Gbit/s | 1.753 [1.739, 1.767] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L90) |
| `lsperf` | 1.003 Gbit/s | 1.119 [1.110, 1.128] | superior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L15) |
| `ngtcp2perf` | 0.897 Gbit/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L60) |
| `quiczigperf` | 0.590 Gbit/s | 0.658 [0.654, 0.662] | inferior | within planning envelope | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L120) |
| `mvfstperf` | 0.553 Gbit/s | 0.617 [0.614, 0.619] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L30) |
| `s2nperf` | 0.538 Gbit/s | 0.600 [0.594, 0.607] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L150) |
| `quicheperf` | 0.505 Gbit/s | 0.563 [0.561, 0.565] | inferior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L105) |
| `tquicperf` | 0.445 Gbit/s | 0.497 [0.495, 0.499] | inferior | within planning envelope | invariance supported | invariance supported | [TSV](../row-results.tsv#L165) |
| `quinnperf` | 0.375 Gbit/s | 0.419 [0.417, 0.420] | inferior | within planning envelope | invariance supported | invariance supported | [TSV](../row-results.tsv#L135) |
| `neqoperf` | 0.367 Gbit/s | 0.409 [0.406, 0.413] | inferior | within planning envelope | invariance supported | sensitivity unresolved | [TSV](../row-results.tsv#L45) |
| `noqperf` | 0.217 Gbit/s | 0.242 [0.241, 0.243] | inferior | within planning envelope | invariance supported | session sensitive | [TSV](../row-results.tsv#L75) |
| `xquicperf` | 0.109 Gbit/s | 0.121 [0.120, 0.122] | inferior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L180) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
