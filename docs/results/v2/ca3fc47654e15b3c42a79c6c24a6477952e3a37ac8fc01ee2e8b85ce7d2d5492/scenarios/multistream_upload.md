# Multi-stream upload

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `picoperf` | 0.975 Gbit/s | 1.430 [1.421, 1.438] | superior | within planning envelope | invariance supported | sensitivity unresolved | [TSV](../row-results.tsv#L85) |
| `lsperf` | 0.690 Gbit/s | 1.012 [0.993, 1.030] | inconclusive | within planning envelope | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L10) |
| `ngtcp2perf` | 0.682 Gbit/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L55) |
| `quiczigperf` | 0.409 Gbit/s | 0.599 [0.596, 0.602] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L115) |
| `tquicperf` | 0.313 Gbit/s | 0.459 [0.456, 0.461] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L160) |
| `mvfstperf` | 0.287 Gbit/s | 0.421 [0.418, 0.424] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L25) |
| `quicheperf` | 0.283 Gbit/s | 0.416 [0.413, 0.419] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L100) |
| `s2nperf` | 0.235 Gbit/s | 0.345 [0.342, 0.347] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L145) |
| `neqoperf` | 0.212 Gbit/s | 0.312 [0.310, 0.313] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L40) |
| `quinnperf` | 0.171 Gbit/s | 0.251 [0.249, 0.252] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L130) |
| `xquicperf` | 0.104 Gbit/s | 0.153 [0.151, 0.154] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L175) |
| `noqperf` | 0.097 Gbit/s | 0.142 [0.141, 0.143] | inferior | within planning envelope | reference client sensitive | session sensitive | [TSV](../row-results.tsv#L70) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
