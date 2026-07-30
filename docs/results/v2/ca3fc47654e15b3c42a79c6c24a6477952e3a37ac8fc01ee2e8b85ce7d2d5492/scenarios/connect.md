# Connection setup

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `lsperf` | 4,983.2 operations/s | 1.166 [1.160, 1.172] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L4) |
| `s2nperf` | 4,456.4 operations/s | 1.042 [1.035, 1.050] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L139) |
| `ngtcp2perf` | 4,274.9 operations/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L49) |
| `picoperf` | 3,190.7 operations/s | 0.746 [0.743, 0.750] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L79) |
| `tquicperf` | 2,849.7 operations/s | 0.667 [0.661, 0.672] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L154) |
| `quiczigperf` | 1,697.7 operations/s | 0.397 [0.394, 0.400] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L109) |
| `neqoperf` | 908.6 operations/s | 0.213 [0.211, 0.215] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L34) |
| `quicheperf` | 600.7 operations/s | 0.141 [0.139, 0.143] | inferior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L94) |
| `quinnperf` | 451.6 operations/s | 0.106 [0.104, 0.107] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L124) |
| `noqperf` | 319.3 operations/s | 0.075 [0.074, 0.076] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L64) |
| `xquicperf` | 285.7 operations/s | 0.067 [0.066, 0.068] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L169) |
| `mvfstperf` | 267.7 operations/s | 0.063 [0.062, 0.063] | inferior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L19) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
