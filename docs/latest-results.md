# Latest Results

The adaptive publication runner samples each library/network/test row in randomized blocks until the row converges or fails. Rows that reach the stop decision are marked `converged`; high variance or nonstationarity remains visible in the diagnostic artifacts instead of becoming a separate terminal status.

Client load is swept upward per row to find server saturation. Tables are sorted by bad-tail p99 first; for these throughput and rate metrics that means the higher lower-tail value is better. `p50` is the publication statistic, while `p90` and `p99` are tail-visibility columns because the selected rows use 20 measured samples.

Current core publication subset status: `converged`. This subset covers `download`, `upload`, and `connect` only: 72 converged publication rows, 0 failed rows, and 0 not-ready rows from 8,580 measured discovery samples. Average samples per sampled thread row: 20.00.

Raw QUIC data, audit details, workload plans, and checksums are committed under [`results/loopback-core-publication-20260525T213948Z`](results/loopback-core-publication-20260525T213948Z/).

## Results

### Download

Server-to-client bulk transfer; higher throughput is better.

| Library | Network | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | io_uring | cubic | 2 | 20 | gigabits/second | 16.674 | 15.190 | 14.857 |
| ngtcp2 | syscall | cubic | 1 | 20 | gigabits/second | 15.026 | 13.940 | 13.857 |
| LSQUIC | syscall | cubic | 1 | 20 | gigabits/second | 11.789 | 10.797 | 10.716 |
| LSQUIC | io_uring | cubic | 1 | 20 | gigabits/second | 11.392 | 10.850 | 10.099 |
| quic-zig | syscall | cubic | 1 | 20 | gigabits/second | 9.585 | 8.995 | 8.989 |
| quiche | syscall | cubic | 2 | 20 | gigabits/second | 8.997 | 8.543 | 8.245 |
| picoquic | syscall | cubic | 1 | 20 | gigabits/second | 8.050 | 7.741 | 7.179 |
| TQUIC | syscall | cubic | 4 | 20 | gigabits/second | 7.406 | 7.083 | 6.488 |
| quiche | io_uring | cubic | 2 | 20 | gigabits/second | 7.756 | 6.742 | 6.460 |
| TQUIC | io_uring | cubic | 3 | 20 | gigabits/second | 6.547 | 6.240 | 6.161 |
| mvfst | io_uring | cubic | 1 | 20 | gigabits/second | 6.631 | 6.303 | 6.056 |
| quic-zig | io_uring | cubic | 1 | 20 | gigabits/second | 9.420 | 8.580 | 6.008 |
| mvfst | syscall | cubic | 1 | 20 | gigabits/second | 6.460 | 5.984 | 5.686 |
| Quinn | io_uring | cubic | 2 | 20 | gigabits/second | 6.588 | 5.804 | 5.655 |
| Quinn | syscall | cubic | 3 | 20 | gigabits/second | 5.831 | 5.692 | 5.613 |
| noq | io_uring | cubic | 2 | 20 | gigabits/second | 5.255 | 4.731 | 4.674 |
| noq | syscall | cubic | 3 | 20 | gigabits/second | 4.839 | 4.739 | 4.481 |
| picoquic | io_uring | cubic | 1 | 20 | gigabits/second | 5.165 | 4.689 | 4.007 |
| s2n-quic | syscall | cubic | 4 | 20 | gigabits/second | 5.476 | 4.302 | 3.143 |
| XQUIC | syscall | cubic | 3 | 20 | gigabits/second | 4.865 | 3.960 | 2.450 |
| Neqo | syscall | cubic | 1 | 20 | gigabits/second | 4.167 | 2.899 | 2.437 |
| Neqo | io_uring | cubic | 1 | 20 | gigabits/second | 4.084 | 2.574 | 2.337 |
| XQUIC | io_uring | cubic | 4 | 20 | gigabits/second | 3.384 | 2.851 | 2.311 |
| s2n-quic | io_uring | cubic | 6 | 20 | gigabits/second | 5.446 | 2.168 | 1.802 |

### Upload

Client-to-server bulk transfer; higher throughput is better.

| Library | Network | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | cubic | 3 | 20 | gigabits/second | 27.142 | 26.362 | 25.962 |
| ngtcp2 | io_uring | cubic | 5 | 20 | gigabits/second | 24.267 | 23.791 | 22.805 |
| LSQUIC | syscall | cubic | 5 | 20 | gigabits/second | 23.330 | 20.795 | 19.885 |
| quiche | syscall | cubic | 4 | 20 | gigabits/second | 13.907 | 13.451 | 13.217 |
| quiche | io_uring | cubic | 4 | 20 | gigabits/second | 12.813 | 12.525 | 12.205 |
| picoquic | io_uring | cubic | 5 | 20 | gigabits/second | 11.475 | 10.960 | 10.846 |
| TQUIC | syscall | cubic | 5 | 20 | gigabits/second | 11.059 | 10.553 | 9.664 |
| TQUIC | io_uring | cubic | 5 | 20 | gigabits/second | 10.061 | 9.793 | 9.300 |
| LSQUIC | io_uring | cubic | 5 | 20 | gigabits/second | 20.705 | 17.673 | 9.239 |
| quic-zig | syscall | cubic | 1 | 20 | gigabits/second | 9.278 | 8.919 | 8.416 |
| quic-zig | io_uring | cubic | 1 | 20 | gigabits/second | 9.206 | 8.728 | 8.111 |
| mvfst | syscall | cubic | 15 | 20 | gigabits/second | 6.907 | 6.779 | 6.670 |
| picoquic | syscall | cubic | 2 | 20 | gigabits/second | 11.433 | 9.576 | 6.385 |
| mvfst | io_uring | cubic | 14 | 20 | gigabits/second | 6.553 | 6.165 | 6.078 |
| s2n-quic | syscall | cubic | 2 | 20 | gigabits/second | 5.989 | 5.690 | 5.589 |
| s2n-quic | io_uring | cubic | 3 | 20 | gigabits/second | 5.526 | 5.133 | 5.040 |
| Quinn | io_uring | cubic | 1 | 20 | gigabits/second | 4.130 | 4.039 | 3.989 |
| Neqo | syscall | cubic | 1 | 20 | gigabits/second | 4.158 | 4.030 | 3.795 |
| Quinn | syscall | cubic | 1 | 20 | gigabits/second | 3.446 | 3.410 | 3.408 |
| noq | io_uring | cubic | 1 | 20 | gigabits/second | 3.568 | 3.256 | 3.024 |
| noq | syscall | cubic | 1 | 20 | gigabits/second | 3.016 | 2.971 | 2.956 |
| XQUIC | syscall | cubic | 4 | 20 | gigabits/second | 3.132 | 2.926 | 2.843 |
| Neqo | io_uring | cubic | 1 | 20 | gigabits/second | 3.976 | 3.165 | 2.633 |
| XQUIC | io_uring | cubic | 1 | 20 | gigabits/second | 1.726 | 1.107 | 1.009 |

### Connect

Full connection establishment plus bidirectional stream creation; higher rate is better.

| Library | Network | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | io_uring | cubic | 18 | 20 | connections/second | 9,968 | 9,675 | 9,280 |
| XQUIC | io_uring | cubic | 17 | 20 | connections/second | 8,833 | 8,111 | 7,460 |
| LSQUIC | io_uring | cubic | 11 | 20 | connections/second | 7,701 | 7,199 | 6,899 |
| Quinn | io_uring | cubic | 14 | 20 | connections/second | 7,158 | 6,839 | 6,623 |
| TQUIC | io_uring | cubic | 12 | 20 | connections/second | 7,220 | 6,846 | 6,288 |
| noq | io_uring | cubic | 10 | 20 | connections/second | 6,190 | 5,961 | 5,952 |
| quiche | io_uring | cubic | 12 | 20 | connections/second | 5,791 | 5,406 | 4,992 |
| s2n-quic | io_uring | cubic | 11 | 20 | connections/second | 5,656 | 5,159 | 4,968 |
| quic-zig | io_uring | cubic | 11 | 20 | connections/second | 3,799 | 3,561 | 3,351 |
| picoquic | io_uring | cubic | 10 | 20 | connections/second | 4,338 | 3,976 | 3,015 |
| Quinn | syscall | cubic | 7 | 20 | connections/second | 3,257 | 3,086 | 2,957 |
| LSQUIC | syscall | cubic | 5 | 20 | connections/second | 3,526 | 3,072 | 2,841 |
| TQUIC | syscall | cubic | 9 | 20 | connections/second | 2,961 | 2,789 | 2,761 |
| s2n-quic | syscall | cubic | 7 | 20 | connections/second | 2,828 | 2,693 | 2,665 |
| ngtcp2 | syscall | cubic | 7 | 20 | connections/second | 3,005 | 2,728 | 2,614 |
| XQUIC | syscall | cubic | 7 | 20 | connections/second | 3,607 | 3,402 | 2,414 |
| noq | syscall | cubic | 7 | 20 | connections/second | 3,091 | 2,909 | 2,104 |
| quic-zig | syscall | cubic | 6 | 20 | connections/second | 2,320 | 2,102 | 2,069 |
| quiche | syscall | cubic | 8 | 20 | connections/second | 2,437 | 2,131 | 2,062 |
| picoquic | syscall | cubic | 7 | 20 | connections/second | 2,200 | 2,052 | 2,010 |
| Neqo | syscall | cubic | 11 | 20 | connections/second | 1,010 | 905 | 777 |
| mvfst | syscall | cubic | 8 | 20 | connections/second | 858 | 792 | 732 |
| mvfst | io_uring | cubic | 6 | 20 | connections/second | 839 | 737 | 698 |
| Neqo | io_uring | cubic | 5 | 20 | connections/second | 784 | 654 | 323 |

## Caveats

- This loopback publication table covers `download`, `upload`, and `connect`; other scenarios remain in smoke, capability, or diagnostic artifacts until explicitly promoted.
- `datagram` is omitted from the adaptive publication table; DATAGRAM support is covered by high-value capability smoke and should remain separate until a fair adaptive DATAGRAM publication run is configured.
- `idle_footprint` is omitted because it was not part of this loopback publication scenario set.
- Unsupported capability rows are explicit unsupported markers, not crashes or claims that the upstream library lacks the feature.
- Row-level gate reasons are in [`publication-results.tsv`](results/loopback-core-publication-20260525T213948Z/publication-results.tsv), [`row-stats.tsv`](results/loopback-core-publication-20260525T213948Z/row-stats.tsv), [`publication-row-audit.tsv`](results/loopback-core-publication-20260525T213948Z/publication-row-audit.tsv), and [`saturation-decisions.tsv`](results/loopback-core-publication-20260525T213948Z/saturation-decisions.tsv).
- Raw measured samples are in [`adaptive-samples.tsv`](results/loopback-core-publication-20260525T213948Z/adaptive-samples.tsv); calibration samples are published separately and excluded from the tables.
