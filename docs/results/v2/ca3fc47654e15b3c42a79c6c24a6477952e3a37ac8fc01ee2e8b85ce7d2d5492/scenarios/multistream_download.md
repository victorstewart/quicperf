# Multi-stream download

Primary estimand: one isolated server core, 16 active connections, four client cores, and the equal reference-client mixture.

| Implementation | Geometric mean | Ratio vs ngtcp2perf (simultaneous 95% interval) | Classification | Variance | Reference-client sensitivity | Session sensitivity | Machine row |
|---|---:|---:|---|---|---|---|---|
| `lsperf` | 1.358 Gbit/s | 1.780 [1.741, 1.820] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L9) |
| `picoperf` | 0.836 Gbit/s | 1.096 [1.073, 1.119] | inconclusive | planning envelope missed | sensitivity unresolved | sensitivity unresolved | [TSV](../row-results.tsv#L84) |
| `ngtcp2perf` | 0.763 Gbit/s | 1.000 (baseline) | baseline | baseline | baseline | baseline | [TSV](../row-results.tsv#L54) |
| `tquicperf` | 0.672 Gbit/s | 0.881 [0.863, 0.900] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L159) |
| `quiczigperf` | 0.659 Gbit/s | 0.864 [0.846, 0.883] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L114) |
| `mvfstperf` | 0.593 Gbit/s | 0.777 [0.762, 0.793] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L24) |
| `xquicperf` | 0.581 Gbit/s | 0.762 [0.745, 0.780] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L174) |
| `s2nperf` | 0.515 Gbit/s | 0.675 [0.657, 0.695] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L144) |
| `quicheperf` | 0.497 Gbit/s | 0.652 [0.640, 0.665] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L99) |
| `quinnperf` | 0.370 Gbit/s | 0.485 [0.475, 0.495] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L129) |
| `neqoperf` | 0.321 Gbit/s | 0.421 [0.412, 0.429] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L39) |
| `noqperf` | 0.259 Gbit/s | 0.339 [0.333, 0.346] | inconclusive | planning envelope missed | reference client sensitive | sensitivity unresolved | [TSV](../row-results.tsv#L69) |

Ratios are implementation/ngtcp2perf. Interpret them with the classification and sensitivity columns; this table is not a cross-scenario leaderboard.
