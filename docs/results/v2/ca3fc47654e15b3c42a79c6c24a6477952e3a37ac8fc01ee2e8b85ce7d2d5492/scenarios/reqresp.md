# Request/response

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `lsperf` | 46,490.2 operations/s | 2.191 [2.180, 2.203] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L11) |
| `picoperf` | 44,421.3 operations/s | 2.094 [2.078, 2.109] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L86) |
| `quicheperf` | 24,813.2 operations/s | 1.170 [1.160, 1.179] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L101) |
| `mvfstperf` | 22,158.2 operations/s | 1.044 [1.039, 1.050] | superior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L26) |
| `ngtcp2perf` | 21,216.2 operations/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L56) |
| `tquicperf` | 20,463.2 operations/s | 0.965 [0.955, 0.974] | inconclusive | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L161) |
| `quinnperf` | 17,736.8 operations/s | 0.836 [0.822, 0.851] | inferior | within planning envelope | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L131) |
| `s2nperf` | 17,341.6 operations/s | 0.817 [0.808, 0.827] | inferior | within planning envelope | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L146) |
| `neqoperf` | 11,393.8 operations/s | 0.537 [0.534, 0.540] | inferior | within planning envelope | invariance supported | invariance supported | [TSV](../row-results.tsv#L41) |
| `noqperf` | 10,200.2 operations/s | 0.481 [0.477, 0.484] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L71) |
| `xquicperf` | 3,487.1 operations/s | 0.164 [0.163, 0.166] | inferior | within planning envelope | reference client sensitive | invariance supported | [TSV](../row-results.tsv#L176) |
| `quiczigperf` | 2,143.8 operations/s | 0.101 [0.100, 0.102] | inferior | within planning envelope | sensitivity unresolved | invariance supported | [TSV](../row-results.tsv#L116) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
