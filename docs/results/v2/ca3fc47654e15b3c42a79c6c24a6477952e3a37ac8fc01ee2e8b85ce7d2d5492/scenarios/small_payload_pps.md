# Small-payload packet rate

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `picoperf` | 223,005.7 operations/s | 1.583 [1.533, 1.634] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L88) |
| `lsperf` | 160,942.9 operations/s | 1.142 [1.079, 1.210] | inconclusive | planning envelope missed | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L13) |
| `ngtcp2perf` | 140,882.2 operations/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L58) |
| `quiczigperf` | 119,638.8 operations/s | 0.849 [0.817, 0.882] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L118) |
| `quicheperf` | 103,237.8 operations/s | 0.733 [0.707, 0.760] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L103) |
| `mvfstperf` | 82,342.6 operations/s | 0.584 [0.558, 0.613] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L28) |
| `s2nperf` | 77,511.3 operations/s | 0.550 [0.527, 0.575] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L148) |
| `tquicperf` | 71,809.1 operations/s | 0.510 [0.481, 0.541] | inconclusive | planning envelope missed | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L163) |
| `neqoperf` | 65,928.5 operations/s | 0.468 [0.448, 0.489] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L43) |
| `quinnperf` | 61,659.4 operations/s | 0.438 [0.417, 0.459] | inconclusive | planning envelope missed | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L133) |
| `noqperf` | 37,100.0 operations/s | 0.263 [0.240, 0.290] | inconclusive | planning envelope missed | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L73) |
| `xquicperf` | 17,989.0 operations/s | 0.128 [0.120, 0.135] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L178) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
