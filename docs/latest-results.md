# Latest Results

The adaptive publication runner samples each library/network/test row in randomized blocks until the row converges or fails. Rows that remain noisy or nonstationary are retained as converged with their measured distribution and diagnostic reasons.

Client load is swept upward per row to find server saturation using as many client threads as needed within the configured limit. Tables are sorted by best bad-tail p99 first; for rate and throughput metrics that means the higher lower-tail value is better.

Current run status: `not_ready`. The run produced 70 converged publication rows, 0 failed rows, and 2 not-ready rows; the tables below use the best available measured distributions and diagnostic reasons.

Raw QUIC data and gate details are committed under [`results/loopback-full-matrix-20260525T002622Z`](results/loopback-full-matrix-20260525T002622Z/).

## Results

### Download

Server-to-client bulk transfer; higher throughput is better.

| Library | Network | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | io_uring | cubic | 2 | 20 | gigabits/second | 16.413 | 15.129 | 14.961 |
| ngtcp2 | syscall | cubic | 2 | 20 | gigabits/second | 16.204 | 14.610 | 14.205 |
| LSQUIC | syscall | cubic | 1 | 20 | gigabits/second | 11.540 | 10.832 | 10.646 |
| LSQUIC | io_uring | cubic | 1 | 20 | gigabits/second | 11.384 | 10.664 | 10.592 |
| quic-zig | syscall | cubic | 1 | 20 | gigabits/second | 9.432 | 9.037 | 8.985 |
| quic-zig | io_uring | cubic | 1 | 20 | gigabits/second | 9.268 | 8.929 | 8.815 |
| quiche | syscall | cubic | 1 | 20 | gigabits/second | 9.375 | 8.499 | 8.270 |
| picoquic | syscall | cubic | 1 | 20 | gigabits/second | 8.238 | 7.607 | 7.369 |
| quiche | io_uring | cubic | 2 | 20 | gigabits/second | 7.503 | 6.993 | 6.715 |
| TQUIC | syscall | cubic | 2 | 20 | gigabits/second | 7.242 | 6.956 | 6.553 |
| TQUIC | io_uring | cubic | 3 | 20 | gigabits/second | 6.551 | 6.447 | 6.359 |
| mvfst | io_uring | cubic | 1 | 20 | gigabits/second | 6.613 | 6.459 | 6.109 |
| mvfst | syscall | cubic | 1 | 20 | gigabits/second | 6.417 | 6.078 | 5.960 |
| Quinn | io_uring | cubic | 2 | 20 | gigabits/second | 6.529 | 5.702 | 5.625 |
| Quinn | syscall | cubic | 2 | 20 | gigabits/second | 6.224 | 5.615 | 5.526 |
| noq | io_uring | cubic | 2 | 20 | gigabits/second | 5.169 | 4.682 | 4.567 |
| s2n-quic | syscall | cubic | 4 | 20 | gigabits/second | 5.518 | 4.406 | 3.862 |
| noq | syscall | cubic | 2 | 20 | gigabits/second | 4.735 | 4.536 | 3.730 |
| picoquic | io_uring | cubic | 1 | 20 | gigabits/second | 5.261 | 4.389 | 3.466 |
| XQUIC | syscall | cubic | 3 | 20 | gigabits/second | 4.386 | 3.391 | 3.173 |
| s2n-quic | io_uring | cubic | 5 | 20 | gigabits/second | 5.523 | 4.368 | 3.023 |
| Neqo | syscall | cubic | 1 | 20 | gigabits/second | 4.112 | 3.876 | 2.578 |
| XQUIC | io_uring | cubic | 3 | 20 | gigabits/second | 3.455 | 3.128 | 2.462 |
| Neqo | io_uring | cubic | 1 | 20 | gigabits/second | 4.193 | 3.895 | 2.346 |

### Upload

Client-to-server bulk transfer; higher throughput is better.

| Library | Network | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | cubic | 2 | 20 | gigabits/second | 27.615 | 24.783 | 24.695 |
| ngtcp2 | io_uring | cubic | 4 | 20 | gigabits/second | 25.211 | 24.166 | 23.632 |
| LSQUIC | syscall | cubic | 5 | 20 | gigabits/second | 21.387 | 19.808 | 19.349 |
| LSQUIC | io_uring | cubic | 5 | 20 | gigabits/second | 20.865 | 19.409 | 19.005 |
| quiche | syscall | cubic | 6 | 20 | gigabits/second | 13.976 | 13.766 | 13.645 |
| quiche | io_uring | cubic | 4 | 20 | gigabits/second | 13.080 | 12.478 | 12.259 |
| picoquic | io_uring | cubic | 6 | 20 | gigabits/second | 11.625 | 11.277 | 11.236 |
| TQUIC | io_uring | cubic | 4 | 20 | gigabits/second | 10.151 | 9.630 | 9.324 |
| TQUIC | syscall | cubic | 4 | 20 | gigabits/second | 10.669 | 9.919 | 9.258 |
| quic-zig | syscall | cubic | 1 | 20 | gigabits/second | 9.731 | 8.847 | 8.733 |
| quic-zig | io_uring | cubic | 1 | 20 | gigabits/second | 8.916 | 8.303 | 8.082 |
| mvfst | syscall | cubic | 14 | 20 | gigabits/second | 6.915 | 6.865 | 6.832 |
| mvfst | io_uring | cubic | 14 | 20 | gigabits/second | 6.629 | 6.431 | 6.290 |
| s2n-quic | syscall | cubic | 3 | 20 | gigabits/second | 6.080 | 5.746 | 5.471 |
| picoquic | syscall | cubic | 2 | 20 | gigabits/second | 11.182 | 6.399 | 5.152 |
| s2n-quic | io_uring | cubic | 3 | 20 | gigabits/second | 5.487 | 4.993 | 4.616 |
| Quinn | io_uring | cubic | 1 | 20 | gigabits/second | 4.077 | 3.959 | 3.901 |
| Neqo | syscall | cubic | 1 | 20 | gigabits/second | 4.144 | 3.994 | 3.604 |
| Quinn | syscall | cubic | 1 | 20 | gigabits/second | 3.432 | 3.391 | 3.366 |
| noq | io_uring | cubic | 1 | 20 | gigabits/second | 3.484 | 3.411 | 3.220 |
| noq | syscall | cubic | 1 | 20 | gigabits/second | 2.993 | 2.956 | 2.921 |
| XQUIC | syscall | cubic | 3 | 20 | gigabits/second | 3.149 | 2.997 | 2.860 |
| Neqo | io_uring | cubic | 1 | 20 | gigabits/second | 4.051 | 3.396 | 2.649 |
| XQUIC | io_uring | cubic | 1 | 20 | gigabits/second | 1.759 | 1.218 | 1.110 |

### Connect

Full connection establishment plus stream creation.

| Library | Network | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---:|---:|---:|
| XQUIC | io_uring | cubic | 16 | 20 | connections/second | 8,610 | 8,185 | 8,122 |
| ngtcp2 | io_uring | cubic | 15 | 20 | connections/second | 9,480 | 8,355 | 8,048 |
| LSQUIC | io_uring | cubic | 14 | 20 | connections/second | 8,219 | 7,890 | 7,599 |
| TQUIC | io_uring | cubic | 10 | 20 | connections/second | 6,674 | 6,345 | 6,240 |
| noq | io_uring | cubic | 14 | 20 | connections/second | 6,587 | 6,325 | 6,192 |
| Quinn | io_uring | cubic | 12 | 20 | connections/second | 7,074 | 6,761 | 6,120 |
| s2n-quic | io_uring | cubic | 15 | 20 | connections/second | 6,196 | 5,816 | 5,596 |
| quiche | io_uring | cubic | 12 | 20 | connections/second | 5,946 | 5,643 | 5,375 |
| picoquic | io_uring | cubic | 15 | 20 | connections/second | 4,957 | 4,556 | 3,876 |
| quic-zig | io_uring | cubic | 13 | 20 | connections/second | 3,946 | 3,646 | 3,589 |
| XQUIC | syscall | cubic | 7 | 20 | connections/second | 3,703 | 3,365 | 3,250 |
| noq | syscall | cubic | 6 | 20 | connections/second | 3,073 | 2,922 | 2,805 |
| LSQUIC | syscall | cubic | 4 | 20 | connections/second | 3,379 | 2,876 | 2,725 |
| ngtcp2 | syscall | cubic | 7 | 20 | connections/second | 3,000 | 2,783 | 2,707 |
| s2n-quic | syscall | cubic | 7 | 20 | connections/second | 2,887 | 2,741 | 2,581 |
| TQUIC | syscall | cubic | 7 | 20 | connections/second | 2,647 | 2,523 | 2,310 |
| picoquic | syscall | cubic | 7 | 20 | connections/second | 2,186 | 2,096 | 2,006 |
| quiche | syscall | cubic | 7 | 20 | connections/second | 2,441 | 2,369 | 1,939 |
| quic-zig | syscall | cubic | 5 | 20 | connections/second | 2,143 | 2,036 | 1,926 |
| Quinn | syscall | cubic | 4 | 20 | connections/second | 2,977 | 2,591 | 1,448 |
| mvfst | io_uring | cubic | 7 | 20 | connections/second | 815 | 760 | 710 |
| Neqo | syscall | cubic | 6 | 20 | connections/second | 816 | 720 | 687 |
| Neqo | io_uring | cubic | 5 | 20 | connections/second | 740 | 680 | 649 |
| mvfst | syscall | cubic | 8 | 20 | connections/second | 855 | 737 | 619 |

## Caveats

- `idle_footprint` is omitted from the current table because it was not part of this loopback refresh scenario set.
- `datagram` is omitted from the adaptive publication table; DATAGRAM support is covered by the high-value capability smoke and should remain separate until a fair adaptive DATAGRAM publication run is configured.
- Unsupported capability rows are explicit unsupported markers, not crashes.
- Row-level caveats and full gate reasons are in [`publication-results.tsv`](results/loopback-full-matrix-20260525T002622Z/publication-results.tsv), [`row-stats.tsv`](results/loopback-full-matrix-20260525T002622Z/row-stats.tsv), [`publication-row-audit.tsv`](results/loopback-full-matrix-20260525T002622Z/publication-row-audit.tsv), and [`saturation-decisions.tsv`](results/loopback-full-matrix-20260525T002622Z/saturation-decisions.tsv).
- Raw samples are in [`adaptive-samples.tsv`](results/loopback-full-matrix-20260525T002622Z/adaptive-samples.tsv).
