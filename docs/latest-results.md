# Latest Results

The adaptive publication runner samples each library/network/test row in randomized blocks until the row converges or fails. Rows that remain noisy or nonstationary are retained as converged with their measured distribution and diagnostic reasons.

Client load is swept upward per row to find server saturation using as many client threads as needed within the configured limit. Tables are sorted by best bad-tail p99 first; for rate and throughput metrics that means the higher lower-tail value is better.

Current run status: `converged`. The run produced 384 converged selected rows, 0 failed rows, and 0 not-ready rows across 384 selected rows (48 capability smoke, 96 lifecycle smoke, 240 publication). The tables below use the best available measured distributions and diagnostic reasons.

Raw QUIC data and gate details are committed under [`results/loopback-full-matrix-20260527T052921Z`](results/loopback-full-matrix-20260527T052921Z/).

## Results

### Download

Server-to-client bulk transfer; higher throughput is better.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | io_uring | publication | cubic | 3 | 20 | gigabits/second | 16.250 | 15.648 | 15.266 |
| ngtcp2 | syscall | publication | cubic | 2 | 20 | gigabits/second | 15.919 | 14.166 | 14.069 |
| LSQUIC | io_uring | publication | cubic | 1 | 20 | gigabits/second | 11.340 | 10.908 | 10.771 |
| LSQUIC | syscall | publication | cubic | 1 | 20 | gigabits/second | 11.381 | 10.857 | 10.746 |
| quic-zig | syscall | publication | cubic | 1 | 20 | gigabits/second | 9.574 | 8.926 | 8.840 |
| quiche | syscall | publication | cubic | 2 | 20 | gigabits/second | 9.543 | 8.822 | 8.757 |
| picoquic | syscall | publication | cubic | 1 | 20 | gigabits/second | 7.863 | 7.439 | 7.404 |
| quiche | io_uring | publication | cubic | 3 | 20 | gigabits/second | 7.772 | 7.355 | 7.259 |
| TQUIC | syscall | publication | cubic | 1 | 20 | gigabits/second | 7.376 | 6.876 | 6.794 |
| TQUIC | io_uring | publication | cubic | 3 | 20 | gigabits/second | 6.551 | 6.339 | 6.109 |
| mvfst | syscall | publication | cubic | 2 | 20 | gigabits/second | 6.054 | 5.883 | 5.867 |
| mvfst | io_uring | publication | cubic | 1 | 20 | gigabits/second | 6.358 | 5.747 | 5.705 |
| quic-zig | io_uring | publication | cubic | 1 | 20 | gigabits/second | 9.308 | 8.535 | 5.623 |
| Quinn | io_uring | publication | cubic | 2 | 20 | gigabits/second | 6.180 | 5.641 | 5.541 |
| Quinn | syscall | publication | cubic | 3 | 20 | gigabits/second | 6.082 | 5.650 | 5.507 |
| noq | syscall | publication | cubic | 3 | 20 | gigabits/second | 4.958 | 4.597 | 4.530 |
| s2n-quic | syscall | publication | cubic | 4 | 20 | gigabits/second | 5.476 | 4.791 | 4.346 |
| Neqo | syscall | publication | cubic | 1 | 20 | gigabits/second | 4.130 | 4.022 | 3.884 |
| picoquic | io_uring | publication | cubic | 1 | 20 | gigabits/second | 5.255 | 4.554 | 3.877 |
| noq | io_uring | publication | cubic | 2 | 20 | gigabits/second | 5.327 | 4.785 | 3.859 |
| XQUIC | syscall | publication | cubic | 2 | 20 | gigabits/second | 4.578 | 3.714 | 3.430 |
| XQUIC | io_uring | publication | cubic | 3 | 20 | gigabits/second | 3.428 | 3.123 | 2.691 |
| Neqo | io_uring | publication | cubic | 1 | 20 | gigabits/second | 4.180 | 3.986 | 2.647 |
| s2n-quic | io_uring | publication | cubic | 6 | 20 | gigabits/second | 5.493 | 1.975 | 1.523 |

### Upload

Client-to-server bulk transfer; higher throughput is better.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | publication | cubic | 4 | 20 | gigabits/second | 26.477 | 25.837 | 25.624 |
| ngtcp2 | io_uring | publication | cubic | 2 | 20 | gigabits/second | 23.520 | 22.751 | 22.431 |
| LSQUIC | syscall | publication | cubic | 5 | 20 | gigabits/second | 22.930 | 20.352 | 19.293 |
| quiche | syscall | publication | cubic | 5 | 20 | gigabits/second | 13.949 | 13.506 | 13.478 |
| quiche | io_uring | publication | cubic | 5 | 20 | gigabits/second | 12.994 | 12.705 | 12.537 |
| LSQUIC | io_uring | publication | cubic | 6 | 20 | gigabits/second | 20.750 | 11.412 | 10.960 |
| picoquic | io_uring | publication | cubic | 3 | 20 | gigabits/second | 11.008 | 10.046 | 9.910 |
| TQUIC | syscall | publication | cubic | 5 | 20 | gigabits/second | 10.980 | 10.204 | 9.740 |
| quic-zig | io_uring | publication | cubic | 1 | 20 | gigabits/second | 9.060 | 8.357 | 8.065 |
| TQUIC | io_uring | publication | cubic | 3 | 20 | gigabits/second | 9.590 | 8.320 | 8.038 |
| mvfst | io_uring | publication | cubic | 14 | 20 | gigabits/second | 6.760 | 6.726 | 6.640 |
| mvfst | syscall | publication | cubic | 15 | 20 | gigabits/second | 6.989 | 6.845 | 6.391 |
| s2n-quic | syscall | publication | cubic | 3 | 20 | gigabits/second | 6.119 | 5.599 | 5.383 |
| picoquic | syscall | publication | cubic | 2 | 20 | gigabits/second | 9.770 | 5.564 | 5.185 |
| s2n-quic | io_uring | publication | cubic | 4 | 20 | gigabits/second | 5.547 | 5.227 | 5.138 |
| quic-zig | syscall | publication | cubic | 1 | 20 | gigabits/second | 9.321 | 8.849 | 4.333 |
| Quinn | io_uring | publication | cubic | 1 | 20 | gigabits/second | 4.384 | 4.021 | 3.957 |
| Quinn | syscall | publication | cubic | 1 | 20 | gigabits/second | 3.467 | 3.410 | 3.391 |
| Neqo | syscall | publication | cubic | 1 | 20 | gigabits/second | 4.182 | 3.935 | 3.219 |
| noq | syscall | publication | cubic | 1 | 20 | gigabits/second | 3.007 | 2.973 | 2.956 |
| XQUIC | syscall | publication | cubic | 3 | 20 | gigabits/second | 3.085 | 2.964 | 2.734 |
| noq | io_uring | publication | cubic | 1 | 20 | gigabits/second | 3.475 | 3.393 | 2.501 |
| Neqo | io_uring | publication | cubic | 1 | 20 | gigabits/second | 4.026 | 3.151 | 2.330 |
| XQUIC | io_uring | publication | cubic | 1 | 20 | gigabits/second | 1.720 | 1.148 | 1.000 |

### Bidirectional

Simultaneous upload and download on one connection.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | publication | cubic | 3 | 20 | gigabits/second | 19.950 | 18.775 | 18.324 |
| ngtcp2 | io_uring | publication | cubic | 2 | 20 | gigabits/second | 19.788 | 18.347 | 17.706 |
| quiche | syscall | publication | cubic | 5 | 20 | gigabits/second | 11.215 | 10.831 | 10.742 |
| quiche | io_uring | publication | cubic | 4 | 20 | gigabits/second | 9.785 | 9.394 | 9.249 |
| quic-zig | syscall | publication | cubic | 1 | 20 | gigabits/second | 9.987 | 9.334 | 9.076 |
| TQUIC | syscall | publication | cubic | 2 | 20 | gigabits/second | 8.770 | 8.427 | 8.296 |
| quic-zig | io_uring | publication | cubic | 1 | 20 | gigabits/second | 8.875 | 8.144 | 7.855 |
| TQUIC | io_uring | publication | cubic | 4 | 20 | gigabits/second | 7.974 | 7.529 | 7.408 |
| mvfst | syscall | publication | cubic | 5 | 20 | gigabits/second | 7.107 | 6.969 | 6.918 |
| mvfst | io_uring | publication | cubic | 7 | 20 | gigabits/second | 6.874 | 6.782 | 6.761 |
| LSQUIC | syscall | publication | cubic | 1 | 20 | gigabits/second | 13.660 | 12.168 | 6.049 |
| LSQUIC | io_uring | publication | cubic | 1 | 20 | gigabits/second | 7.823 | 5.464 | 5.403 |
| s2n-quic | syscall | publication | cubic | 3 | 20 | gigabits/second | 5.444 | 5.215 | 5.080 |
| s2n-quic | io_uring | publication | cubic | 2 | 20 | gigabits/second | 5.344 | 5.052 | 4.839 |
| picoquic | syscall | publication | cubic | 1 | 20 | gigabits/second | 5.662 | 5.098 | 4.682 |
| picoquic | io_uring | publication | cubic | 1 | 20 | gigabits/second | 4.899 | 4.261 | 4.002 |
| Quinn | syscall | publication | cubic | 2 | 20 | gigabits/second | 4.155 | 3.999 | 3.981 |
| noq | syscall | publication | cubic | 2 | 20 | gigabits/second | 3.594 | 3.453 | 3.372 |
| Neqo | syscall | publication | cubic | 3 | 20 | gigabits/second | 3.308 | 3.181 | 3.066 |
| Neqo | io_uring | publication | cubic | 3 | 20 | gigabits/second | 3.278 | 3.223 | 3.014 |
| Quinn | io_uring | publication | cubic | 2 | 20 | gigabits/second | 4.401 | 3.700 | 2.986 |
| noq | io_uring | publication | cubic | 1 | 20 | gigabits/second | 3.810 | 3.328 | 2.958 |
| XQUIC | io_uring | publication | cubic | 2 | 20 | gigabits/second | 2.070 | 1.810 | 1.671 |
| XQUIC | syscall | publication | cubic | 2 | 20 | gigabits/second | 2.399 | 1.852 | 1.643 |

### Multistream Download

Server-to-client transfer split across concurrent streams.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | io_uring | publication | cubic | 1 | 20 | gigabits/second | 15.839 | 14.855 | 14.851 |
| ngtcp2 | syscall | publication | cubic | 3 | 20 | gigabits/second | 15.948 | 14.875 | 14.345 |
| quiche | syscall | publication | cubic | 3 | 20 | gigabits/second | 9.377 | 9.084 | 8.977 |
| quiche | io_uring | publication | cubic | 2 | 20 | gigabits/second | 8.059 | 7.844 | 7.577 |
| picoquic | syscall | publication | cubic | 1 | 20 | gigabits/second | 7.988 | 7.266 | 6.855 |
| TQUIC | syscall | publication | cubic | 2 | 20 | gigabits/second | 6.622 | 5.842 | 5.751 |
| mvfst | io_uring | publication | cubic | 2 | 20 | gigabits/second | 5.892 | 5.707 | 5.628 |
| Quinn | io_uring | publication | cubic | 2 | 20 | gigabits/second | 6.416 | 6.127 | 5.518 |
| TQUIC | io_uring | publication | cubic | 2 | 20 | gigabits/second | 6.392 | 5.613 | 5.503 |
| Quinn | syscall | publication | cubic | 2 | 20 | gigabits/second | 6.326 | 6.226 | 5.444 |
| mvfst | syscall | publication | cubic | 1 | 20 | gigabits/second | 5.797 | 5.386 | 5.195 |
| noq | io_uring | publication | cubic | 2 | 20 | gigabits/second | 5.322 | 5.193 | 5.133 |
| picoquic | io_uring | publication | cubic | 1 | 20 | gigabits/second | 6.108 | 5.245 | 5.052 |
| noq | syscall | publication | cubic | 2 | 20 | gigabits/second | 5.232 | 5.109 | 4.783 |
| s2n-quic | io_uring | publication | cubic | 7 | 20 | gigabits/second | 5.070 | 4.843 | 4.734 |
| XQUIC | syscall | publication | cubic | 4 | 20 | gigabits/second | 7.280 | 5.125 | 4.674 |
| s2n-quic | syscall | publication | cubic | 3 | 20 | gigabits/second | 5.115 | 4.652 | 4.514 |
| quic-zig | io_uring | publication | cubic | 1 | 20 | gigabits/second | 8.179 | 6.863 | 4.465 |
| XQUIC | io_uring | publication | cubic | 2 | 20 | gigabits/second | 4.509 | 4.224 | 4.119 |
| LSQUIC | io_uring | publication | cubic | 1 | 20 | gigabits/second | 10.701 | 3.623 | 3.509 |
| LSQUIC | syscall | publication | cubic | 3 | 20 | gigabits/second | 4.231 | 3.588 | 3.355 |
| Neqo | io_uring | publication | cubic | 2 | 20 | gigabits/second | 3.093 | 3.061 | 3.025 |
| Neqo | syscall | publication | cubic | 2 | 20 | gigabits/second | 3.054 | 2.964 | 2.948 |
| quic-zig | syscall | publication | cubic | 1 | 20 | gigabits/second | 7.751 | 1.873 | 1.651 |

### Multistream Upload

Client-to-server transfer split across concurrent streams.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | publication | cubic | 3 | 20 | gigabits/second | 26.568 | 25.704 | 25.112 |
| ngtcp2 | io_uring | publication | cubic | 3 | 20 | gigabits/second | 23.636 | 23.193 | 23.064 |
| quiche | syscall | publication | cubic | 5 | 20 | gigabits/second | 13.704 | 13.408 | 13.319 |
| quiche | io_uring | publication | cubic | 4 | 20 | gigabits/second | 12.532 | 12.176 | 11.944 |
| LSQUIC | syscall | publication | cubic | 5 | 20 | gigabits/second | 14.567 | 12.447 | 11.638 |
| picoquic | io_uring | publication | cubic | 6 | 20 | gigabits/second | 11.253 | 10.725 | 10.497 |
| TQUIC | syscall | publication | cubic | 3 | 20 | gigabits/second | 11.077 | 10.374 | 9.945 |
| TQUIC | io_uring | publication | cubic | 2 | 20 | gigabits/second | 9.560 | 9.265 | 9.204 |
| quic-zig | syscall | publication | cubic | 4 | 20 | gigabits/second | 9.450 | 8.980 | 8.931 |
| quic-zig | io_uring | publication | cubic | 1 | 20 | gigabits/second | 8.444 | 8.039 | 7.954 |
| mvfst | syscall | publication | cubic | 16 | 20 | gigabits/second | 7.903 | 7.836 | 7.728 |
| mvfst | io_uring | publication | cubic | 14 | 20 | gigabits/second | 7.187 | 7.155 | 7.137 |
| LSQUIC | io_uring | publication | cubic | 2 | 20 | gigabits/second | 14.292 | 6.942 | 6.382 |
| picoquic | syscall | publication | cubic | 2 | 20 | gigabits/second | 10.878 | 6.471 | 6.049 |
| s2n-quic | syscall | publication | cubic | 5 | 20 | gigabits/second | 5.494 | 5.343 | 5.263 |
| s2n-quic | io_uring | publication | cubic | 4 | 20 | gigabits/second | 5.414 | 5.059 | 4.822 |
| Quinn | io_uring | publication | cubic | 1 | 20 | gigabits/second | 4.002 | 3.884 | 3.799 |
| XQUIC | syscall | publication | cubic | 4 | 20 | gigabits/second | 3.187 | 2.964 | 2.939 |
| noq | io_uring | publication | cubic | 1 | 20 | gigabits/second | 3.381 | 3.265 | 2.752 |
| Neqo | io_uring | publication | cubic | 3 | 20 | gigabits/second | 2.584 | 2.513 | 2.457 |
| Neqo | syscall | publication | cubic | 3 | 20 | gigabits/second | 2.636 | 2.549 | 2.438 |
| Quinn | syscall | publication | cubic | 1 | 20 | gigabits/second | 3.451 | 2.986 | 2.238 |
| noq | syscall | publication | cubic | 1 | 20 | gigabits/second | 2.996 | 2.593 | 1.913 |
| XQUIC | io_uring | publication | cubic | 3 | 20 | gigabits/second | 1.458 | 1.104 | 1.083 |

### Request/Response

Small request/response exchanges on fresh bidirectional streams.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| picoquic | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 317,808 | 309,369 | 307,470 |
| picoquic | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 311,166 | 294,622 | 290,900 |
| ngtcp2 | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 126,453 | 123,465 | 122,793 |
| ngtcp2 | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 104,851 | 100,912 | 100,026 |
| TQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 85,849 | 85,048 | 84,868 |
| quiche | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 81,289 | 79,996 | 79,705 |
| TQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 80,290 | 78,668 | 78,303 |
| quiche | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 75,958 | 71,906 | 70,994 |
| XQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 63,648 | 61,184 | 60,629 |
| XQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 49,220 | 48,775 | 48,674 |
| Quinn | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 49,858 | 47,400 | 46,847 |
| Quinn | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 47,590 | 45,445 | 44,962 |
| noq | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 44,761 | 43,026 | 42,635 |
| noq | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 41,799 | 41,364 | 41,266 |
| s2n-quic | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 28,225 | 28,046 | 28,006 |
| s2n-quic | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 27,252 | 26,918 | 26,843 |
| Neqo | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 20,085 | 19,375 | 19,215 |
| quic-zig | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 18,380 | 17,767 | 17,630 |
| Neqo | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 17,529 | 17,463 | 17,449 |
| quic-zig | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 17,392 | 17,337 | 17,325 |
| LSQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 79,733 | 23,700 | 11,093 |
| LSQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 8,770 | 8,745 | 8,739 |
| mvfst | syscall | lifecycle smoke | cubic | 1 | 2 | requests/second | 5,243 | 5,160 | 5,142 |
| mvfst | io_uring | lifecycle smoke | cubic | 1 | 2 | requests/second | 5,103 | 5,046 | 5,033 |

### Stream Churn

Repeated stream open, send, receive, and finish lifecycle.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| picoquic | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 455,182 | 450,118 | 448,979 |
| picoquic | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 435,336 | 433,380 | 432,940 |
| LSQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 177,670 | 177,567 | 177,544 |
| ngtcp2 | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 163,810 | 162,706 | 162,457 |
| ngtcp2 | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 119,028 | 116,033 | 115,360 |
| TQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 97,261 | 95,975 | 95,686 |
| TQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 93,011 | 91,732 | 91,445 |
| LSQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 90,203 | 90,044 | 90,008 |
| quiche | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 82,605 | 79,947 | 79,349 |
| quiche | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 84,984 | 72,769 | 70,020 |
| XQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 62,501 | 55,778 | 54,265 |
| Quinn | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 48,638 | 47,029 | 46,667 |
| Quinn | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 45,784 | 45,466 | 45,394 |
| XQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 46,107 | 45,486 | 45,346 |
| noq | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 43,146 | 42,952 | 42,908 |
| noq | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 42,495 | 42,240 | 42,183 |
| s2n-quic | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 28,064 | 28,033 | 28,026 |
| s2n-quic | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 27,494 | 27,378 | 27,352 |
| quic-zig | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 21,699 | 20,459 | 20,180 |
| Neqo | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 18,872 | 18,124 | 17,956 |
| quic-zig | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 18,043 | 17,806 | 17,753 |
| Neqo | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 17,714 | 17,673 | 17,664 |
| mvfst | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 5,029 | 4,934 | 4,913 |
| mvfst | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 4,553 | 4,538 | 4,535 |

### Small Payload Messages

Tiny-message packet and API overhead.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| picoquic | io_uring | publication | cubic | 8 | 20 | messages/second | 1,333,087 | 1,270,304 | 1,232,688 |
| picoquic | syscall | publication | cubic | 5 | 20 | messages/second | 1,292,568 | 1,216,541 | 1,180,527 |
| TQUIC | syscall | publication | cubic | 5 | 20 | messages/second | 234,045 | 227,677 | 227,238 |
| TQUIC | io_uring | publication | cubic | 7 | 20 | messages/second | 224,657 | 219,109 | 215,913 |
| ngtcp2 | syscall | publication | cubic | 2 | 20 | messages/second | 100,821 | 97,095 | 94,882 |
| LSQUIC | syscall | publication | cubic | 1 | 20 | messages/second | 91,120 | 89,630 | 89,098 |
| quiche | syscall | publication | cubic | 2 | 20 | messages/second | 81,138 | 75,952 | 73,757 |
| quiche | io_uring | publication | cubic | 2 | 20 | messages/second | 69,855 | 67,866 | 67,306 |
| XQUIC | io_uring | publication | cubic | 3 | 20 | messages/second | 57,690 | 54,401 | 54,172 |
| Quinn | io_uring | publication | cubic | 2 | 20 | messages/second | 55,808 | 49,591 | 48,848 |
| XQUIC | syscall | publication | cubic | 13 | 20 | messages/second | 48,723 | 47,727 | 47,467 |
| noq | io_uring | publication | cubic | 2 | 20 | messages/second | 50,078 | 44,593 | 44,416 |
| noq | syscall | publication | cubic | 2 | 20 | messages/second | 49,011 | 44,779 | 43,956 |
| s2n-quic | io_uring | publication | cubic | 3 | 20 | messages/second | 41,687 | 39,577 | 38,838 |
| ngtcp2 | io_uring | publication | cubic | 1 | 20 | messages/second | 43,310 | 38,678 | 37,706 |
| Quinn | syscall | publication | cubic | 2 | 20 | messages/second | 54,459 | 50,432 | 36,566 |
| s2n-quic | syscall | publication | cubic | 5 | 20 | messages/second | 41,784 | 40,794 | 35,906 |
| LSQUIC | io_uring | publication | cubic | 1 | 20 | messages/second | 32,940 | 32,587 | 32,354 |
| Neqo | syscall | publication | cubic | 3 | 20 | messages/second | 15,498 | 14,205 | 13,843 |
| Neqo | io_uring | publication | cubic | 4 | 20 | messages/second | 14,628 | 14,256 | 13,632 |
| quic-zig | io_uring | publication | cubic | 1 | 20 | messages/second | 3,201 | 3,028 | 2,969 |
| quic-zig | syscall | publication | cubic | 1 | 20 | messages/second | 3,108 | 2,999 | 2,920 |
| mvfst | syscall | publication | cubic | 10 | 20 | messages/second | 2,639 | 2,604 | 2,583 |
| mvfst | io_uring | publication | cubic | 8 | 20 | messages/second | 2,592 | 2,551 | 2,512 |

### Loss Recovery

Deterministic impairment path covering loss recovery behavior.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | io_uring | publication | cubic | 3 | 20 | gigabits/second | 15.066 | 14.299 | 13.939 |
| ngtcp2 | syscall | publication | cubic | 3 | 20 | gigabits/second | 14.709 | 13.894 | 13.662 |
| LSQUIC | io_uring | publication | cubic | 1 | 20 | gigabits/second | 13.333 | 12.349 | 12.234 |
| LSQUIC | syscall | publication | cubic | 1 | 20 | gigabits/second | 13.039 | 12.206 | 11.394 |
| quiche | syscall | publication | cubic | 2 | 20 | gigabits/second | 8.904 | 8.582 | 8.514 |
| quiche | io_uring | publication | cubic | 2 | 20 | gigabits/second | 8.659 | 7.975 | 7.779 |
| mvfst | syscall | publication | cubic | 5 | 20 | gigabits/second | 6.331 | 6.210 | 6.124 |
| TQUIC | io_uring | publication | cubic | 2 | 20 | gigabits/second | 7.199 | 6.563 | 6.069 |
| TQUIC | syscall | publication | cubic | 2 | 20 | gigabits/second | 6.978 | 6.084 | 5.952 |
| quic-zig | syscall | publication | cubic | 1 | 20 | gigabits/second | 8.550 | 6.003 | 5.885 |
| quic-zig | io_uring | publication | cubic | 1 | 20 | gigabits/second | 7.649 | 5.478 | 5.438 |
| Neqo | io_uring | publication | cubic | 2 | 20 | gigabits/second | 5.232 | 5.100 | 5.050 |
| Neqo | syscall | publication | cubic | 2 | 20 | gigabits/second | 5.286 | 5.032 | 4.849 |
| Quinn | syscall | publication | cubic | 4 | 20 | gigabits/second | 5.672 | 5.328 | 4.691 |
| mvfst | io_uring | publication | cubic | 1 | 20 | gigabits/second | 6.200 | 4.691 | 4.645 |
| noq | syscall | publication | cubic | 3 | 20 | gigabits/second | 4.682 | 4.472 | 4.356 |
| s2n-quic | syscall | publication | cubic | 4 | 20 | gigabits/second | 5.436 | 4.618 | 4.224 |
| noq | io_uring | publication | cubic | 2 | 20 | gigabits/second | 4.597 | 4.416 | 4.091 |
| Quinn | io_uring | publication | cubic | 2 | 20 | gigabits/second | 5.799 | 5.143 | 3.972 |
| XQUIC | syscall | publication | cubic | 7 | 20 | gigabits/second | 3.871 | 3.546 | 3.412 |
| picoquic | io_uring | publication | cubic | 1 | 20 | gigabits/second | 5.384 | 4.217 | 3.335 |
| XQUIC | io_uring | publication | cubic | 3 | 20 | gigabits/second | 3.560 | 3.341 | 2.956 |
| picoquic | syscall | publication | cubic | 1 | 20 | gigabits/second | 4.477 | 3.294 | 2.914 |
| s2n-quic | io_uring | publication | cubic | 5 | 20 | gigabits/second | 5.488 | 4.237 | 2.281 |

### Flow Control

Small-window transfer pressure and flow-control update behavior.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | io_uring | publication | cubic | 5 | 20 | gigabits/second | 13.379 | 12.909 | 12.611 |
| ngtcp2 | syscall | publication | cubic | 2 | 20 | gigabits/second | 13.198 | 12.148 | 11.947 |
| LSQUIC | syscall | publication | cubic | 1 | 20 | gigabits/second | 10.814 | 10.597 | 10.266 |
| quiche | io_uring | publication | cubic | 4 | 20 | gigabits/second | 9.142 | 8.929 | 8.766 |
| LSQUIC | io_uring | publication | cubic | 1 | 20 | gigabits/second | 8.824 | 8.494 | 8.420 |
| quiche | syscall | publication | cubic | 2 | 20 | gigabits/second | 9.355 | 8.375 | 8.191 |
| picoquic | io_uring | publication | cubic | 1 | 20 | gigabits/second | 8.463 | 8.176 | 8.055 |
| picoquic | syscall | publication | cubic | 1 | 20 | gigabits/second | 7.327 | 6.901 | 6.413 |
| TQUIC | io_uring | publication | cubic | 5 | 20 | gigabits/second | 7.121 | 6.409 | 5.788 |
| mvfst | io_uring | publication | cubic | 7 | 20 | gigabits/second | 5.719 | 5.569 | 5.498 |
| mvfst | syscall | publication | cubic | 6 | 20 | gigabits/second | 5.411 | 5.250 | 5.174 |
| TQUIC | syscall | publication | cubic | 3 | 20 | gigabits/second | 6.852 | 5.104 | 4.803 |
| Quinn | syscall | publication | cubic | 5 | 20 | gigabits/second | 4.850 | 4.644 | 4.608 |
| Neqo | io_uring | publication | cubic | 1 | 20 | gigabits/second | 4.564 | 4.015 | 3.792 |
| Neqo | syscall | publication | cubic | 1 | 20 | gigabits/second | 3.992 | 3.836 | 3.648 |
| XQUIC | io_uring | publication | cubic | 2 | 20 | gigabits/second | 3.550 | 3.402 | 3.358 |
| XQUIC | syscall | publication | cubic | 2 | 20 | gigabits/second | 3.629 | 3.494 | 3.289 |
| s2n-quic | io_uring | publication | cubic | 2 | 20 | gigabits/second | 4.090 | 3.285 | 3.252 |
| noq | io_uring | publication | cubic | 5 | 20 | gigabits/second | 3.619 | 3.201 | 3.154 |
| s2n-quic | syscall | publication | cubic | 2 | 20 | gigabits/second | 4.250 | 3.445 | 3.082 |
| Quinn | io_uring | publication | cubic | 5 | 20 | gigabits/second | 4.721 | 4.053 | 2.808 |
| noq | syscall | publication | cubic | 4 | 20 | gigabits/second | 3.847 | 3.321 | 2.479 |
| quic-zig | io_uring | publication | cubic | 2 | 20 | gigabits/second | 2.889 | 1.271 | 1.067 |
| quic-zig | syscall | publication | cubic | 2 | 20 | gigabits/second | 2.017 | 1.224 | 0.912 |

### Connect

Full connection establishment plus stream creation.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| XQUIC | io_uring | publication | cubic | 17 | 20 | connections/second | 8,548 | 7,926 | 7,682 |
| LSQUIC | io_uring | publication | cubic | 17 | 20 | connections/second | 8,886 | 8,300 | 7,298 |
| Quinn | io_uring | publication | cubic | 13 | 20 | connections/second | 6,976 | 6,736 | 6,458 |
| TQUIC | io_uring | publication | cubic | 10 | 20 | connections/second | 6,905 | 6,603 | 6,021 |
| noq | io_uring | publication | cubic | 12 | 20 | connections/second | 6,376 | 6,038 | 5,550 |
| ngtcp2 | io_uring | publication | cubic | 17 | 20 | connections/second | 9,730 | 8,971 | 4,841 |
| s2n-quic | io_uring | publication | cubic | 12 | 20 | connections/second | 5,828 | 5,441 | 4,342 |
| quiche | io_uring | publication | cubic | 12 | 20 | connections/second | 5,749 | 5,400 | 4,230 |
| picoquic | io_uring | publication | cubic | 11 | 20 | connections/second | 4,276 | 3,751 | 3,372 |
| LSQUIC | syscall | publication | cubic | 7 | 20 | connections/second | 3,753 | 3,333 | 3,305 |
| XQUIC | syscall | publication | cubic | 7 | 20 | connections/second | 3,639 | 3,400 | 3,160 |
| noq | syscall | publication | cubic | 9 | 20 | connections/second | 3,216 | 3,098 | 3,027 |
| quic-zig | io_uring | publication | cubic | 13 | 20 | connections/second | 3,829 | 3,688 | 2,544 |
| s2n-quic | syscall | publication | cubic | 5 | 20 | connections/second | 2,705 | 2,537 | 2,422 |
| Quinn | syscall | publication | cubic | 3 | 20 | connections/second | 3,014 | 2,707 | 2,348 |
| TQUIC | syscall | publication | cubic | 12 | 20 | connections/second | 3,035 | 2,805 | 2,252 |
| quic-zig | syscall | publication | cubic | 6 | 20 | connections/second | 2,351 | 2,194 | 2,092 |
| ngtcp2 | syscall | publication | cubic | 3 | 20 | connections/second | 2,552 | 2,157 | 1,965 |
| picoquic | syscall | publication | cubic | 7 | 20 | connections/second | 2,180 | 1,972 | 1,602 |
| quiche | syscall | publication | cubic | 3 | 20 | connections/second | 1,963 | 1,682 | 1,593 |
| mvfst | io_uring | publication | cubic | 13 | 20 | connections/second | 997 | 938 | 934 |
| mvfst | syscall | publication | cubic | 13 | 20 | connections/second | 953 | 813 | 802 |
| Neqo | io_uring | publication | cubic | 7 | 20 | connections/second | 836 | 751 | 742 |
| Neqo | syscall | publication | cubic | 8 | 20 | connections/second | 907 | 756 | 694 |

### Resumed Connect

Session-ticket resumption proof for connection establishment.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| s2n-quic | syscall | capability smoke | cubic | 1 | 2 | connections/second | 6,903 | 6,824 | 6,807 |
| s2n-quic | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 5,264 | 4,511 | 4,341 |
| picoquic | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 3,374 | 3,340 | 3,332 |
| TQUIC | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 3,596 | 3,269 | 3,196 |
| LSQUIC | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 3,072 | 2,930 | 2,898 |
| ngtcp2 | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 2,884 | 2,755 | 2,726 |
| XQUIC | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 3,022 | 2,654 | 2,571 |
| quiche | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 2,582 | 2,349 | 2,296 |
| quiche | syscall | capability smoke | cubic | 1 | 2 | connections/second | 2,222 | 2,186 | 2,178 |
| LSQUIC | syscall | capability smoke | cubic | 1 | 2 | connections/second | 2,256 | 2,126 | 2,096 |
| Quinn | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 2,214 | 2,117 | 2,095 |
| ngtcp2 | syscall | capability smoke | cubic | 1 | 2 | connections/second | 2,109 | 1,943 | 1,905 |
| picoquic | syscall | capability smoke | cubic | 1 | 2 | connections/second | 2,079 | 1,931 | 1,898 |
| TQUIC | syscall | capability smoke | cubic | 1 | 2 | connections/second | 1,947 | 1,817 | 1,787 |
| XQUIC | syscall | capability smoke | cubic | 1 | 2 | connections/second | 1,912 | 1,678 | 1,626 |
| Quinn | syscall | capability smoke | cubic | 1 | 2 | connections/second | 1,586 | 1,579 | 1,577 |
| mvfst | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 1,661 | 1,588 | 1,572 |
| noq | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 1,668 | 1,556 | 1,531 |
| mvfst | syscall | capability smoke | cubic | 1 | 2 | connections/second | 1,514 | 1,505 | 1,503 |
| quic-zig | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 1,517 | 1,503 | 1,500 |
| noq | syscall | capability smoke | cubic | 1 | 2 | connections/second | 1,449 | 1,335 | 1,309 |
| quic-zig | syscall | capability smoke | cubic | 1 | 2 | connections/second | 1,321 | 1,310 | 1,308 |
| Neqo | io_uring | capability smoke | cubic | 1 | 2 | connections/second | 518 | 477 | 468 |
| Neqo | syscall | capability smoke | cubic | 1 | 2 | connections/second | 455 | 427 | 420 |

### 0-RTT request/response

Session resumption with early request/response data.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| picoquic | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 330,628 | 323,006 | 321,291 |
| picoquic | syscall | capability smoke | cubic | 1 | 2 | requests/second | 288,570 | 281,067 | 279,379 |
| ngtcp2 | syscall | capability smoke | cubic | 1 | 2 | requests/second | 105,273 | 103,312 | 102,871 |
| TQUIC | syscall | capability smoke | cubic | 1 | 2 | requests/second | 111,607 | 88,292 | 83,047 |
| TQUIC | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 86,988 | 79,229 | 77,483 |
| quiche | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 80,008 | 76,062 | 75,173 |
| quiche | syscall | capability smoke | cubic | 1 | 2 | requests/second | 71,327 | 68,595 | 67,980 |
| ngtcp2 | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 58,735 | 57,902 | 57,715 |
| XQUIC | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 57,489 | 51,522 | 50,179 |
| Quinn | syscall | capability smoke | cubic | 1 | 2 | requests/second | 49,635 | 49,614 | 49,609 |
| Quinn | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 51,534 | 45,970 | 44,718 |
| noq | syscall | capability smoke | cubic | 1 | 2 | requests/second | 44,100 | 43,806 | 43,739 |
| s2n-quic | syscall | capability smoke | cubic | 1 | 2 | requests/second | 37,019 | 37,012 | 37,010 |
| s2n-quic | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 32,330 | 30,700 | 30,334 |
| XQUIC | syscall | capability smoke | cubic | 1 | 2 | requests/second | 24,694 | 23,731 | 23,514 |
| noq | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 30,321 | 23,205 | 21,603 |
| Neqo | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 16,416 | 16,014 | 15,923 |
| Neqo | syscall | capability smoke | cubic | 1 | 2 | requests/second | 15,750 | 15,250 | 15,138 |
| LSQUIC | syscall | capability smoke | cubic | 1 | 2 | requests/second | 78,713 | 23,472 | 11,043 |
| quic-zig | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 10,795 | 10,460 | 10,385 |
| quic-zig | syscall | capability smoke | cubic | 1 | 2 | requests/second | 9,960 | 9,862 | 9,840 |
| LSQUIC | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 8,680 | 8,666 | 8,663 |
| mvfst | io_uring | capability smoke | cubic | 1 | 2 | requests/second | 3,534 | 3,514 | 3,510 |
| mvfst | syscall | capability smoke | cubic | 1 | 2 | requests/second | 3,241 | 3,074 | 3,036 |

### Datagram

Unreliable application DATAGRAM echo capability.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| quic-zig | io_uring | publication | cubic | 2 | 20 | DATAGRAMs/second | 2,257,737 | 2,111,065 | 2,107,138 |
| picoquic | syscall | publication | cubic | 5 | 20 | DATAGRAMs/second | 1,976,846 | 1,778,255 | 1,371,477 |
| ngtcp2 | syscall | publication | cubic | 3 | 20 | DATAGRAMs/second | 1,262,843 | 1,209,157 | 1,192,503 |
| ngtcp2 | io_uring | publication | cubic | 3 | 20 | DATAGRAMs/second | 1,255,595 | 1,191,075 | 1,162,631 |
| LSQUIC | syscall | publication | cubic | 1 | 20 | DATAGRAMs/second | 1,159,040 | 1,132,392 | 1,130,009 |
| TQUIC | syscall | publication | cubic | 2 | 20 | DATAGRAMs/second | 698,091 | 676,878 | 656,213 |
| TQUIC | io_uring | publication | cubic | 3 | 20 | DATAGRAMs/second | 679,479 | 641,102 | 633,439 |
| s2n-quic | syscall | publication | cubic | 28 | 20 | DATAGRAMs/second | 501,484 | 489,318 | 479,109 |
| picoquic | io_uring | publication | cubic | 1 | 20 | DATAGRAMs/second | 2,381,882 | 2,192,447 | 447,456 |
| s2n-quic | io_uring | publication | cubic | 15 | 20 | DATAGRAMs/second | 241,056 | 235,180 | 233,371 |
| Quinn | syscall | publication | cubic | 3 | 20 | DATAGRAMs/second | 2,926,484 | 221,582 | 214,953 |
| XQUIC | syscall | publication | cubic | 2 | 20 | DATAGRAMs/second | 204,900 | 184,948 | 184,042 |
| Neqo | io_uring | publication | cubic | 28 | 20 | DATAGRAMs/second | 203,477 | 183,876 | 177,335 |
| Neqo | syscall | publication | cubic | 24 | 20 | DATAGRAMs/second | 182,034 | 173,014 | 165,774 |
| Quinn | io_uring | publication | cubic | 2 | 20 | DATAGRAMs/second | 2,455,470 | 150,123 | 148,721 |
| quiche | io_uring | publication | cubic | 3 | 20 | DATAGRAMs/second | 3,456,774 | 121,618 | 121,559 |
| XQUIC | io_uring | publication | cubic | 1 | 20 | DATAGRAMs/second | 122,797 | 116,235 | 111,036 |
| quiche | syscall | publication | cubic | 2 | 20 | DATAGRAMs/second | 3,211,344 | 81,329 | 80,943 |
| noq | io_uring | publication | cubic | 1 | 20 | DATAGRAMs/second | 1,818,146 | 75,492 | 74,952 |
| noq | syscall | publication | cubic | 1 | 20 | DATAGRAMs/second | 1,789,090 | 72,483 | 52,913 |
| quic-zig | syscall | publication | cubic | 1 | 20 | DATAGRAMs/second | 2,350,949 | 1,777,380 | 39,210 |
| LSQUIC | io_uring | publication | cubic | 1 | 20 | DATAGRAMs/second | 1,176,188 | 981,012 | 38,300 |
| mvfst | io_uring | publication | cubic | 1 | 20 | DATAGRAMs/second | 321,882 | 17,189 | 16,487 |
| mvfst | syscall | publication | cubic | 1 | 20 | DATAGRAMs/second | 16,130 | 14,924 | 14,072 |

### Idle Footprint

Server RSS delta per held idle connection; lower is better.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| LSQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 184,320 | 210,534 | 216,433 |
| LSQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 206,848 | 237,978 | 244,982 |
| picoquic | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 352,256 | 355,533 | 356,270 |
| XQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 397,312 | 433,357 | 441,467 |
| ngtcp2 | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 538,624 | 622,182 | 640,983 |
| quiche | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 649,216 | 703,283 | 715,448 |
| TQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 768,000 | 802,406 | 810,148 |
| Quinn | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,044,480 | 1,054,310 | 1,056,522 |
| Quinn | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 997,376 | 1,120,256 | 1,147,904 |
| XQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,218,560 | 1,223,475 | 1,224,581 |
| ngtcp2 | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,251,328 | 1,252,966 | 1,253,335 |
| noq | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,286,144 | 1,302,528 | 1,306,214 |
| noq | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,335,296 | 1,368,064 | 1,375,437 |
| quic-zig | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,378,304 | 1,445,478 | 1,460,593 |
| quic-zig | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,392,640 | 1,458,176 | 1,472,922 |
| Neqo | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,417,216 | 1,489,306 | 1,505,526 |
| quiche | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,589,248 | 1,589,248 | 1,589,248 |
| Neqo | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,523,712 | 1,582,694 | 1,595,965 |
| TQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,609,728 | 1,721,139 | 1,746,207 |
| picoquic | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 1,550,336 | 1,771,520 | 1,821,286 |
| s2n-quic | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 2,314,240 | 2,363,392 | 2,374,451 |
| s2n-quic | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 2,359,296 | 2,464,154 | 2,487,747 |
| mvfst | io_uring | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 2,990,080 | 3,009,741 | 3,014,164 |
| mvfst | syscall | lifecycle smoke | cubic | 1 | 2 | bytes/connection | 3,999,744 | 4,083,302 | 4,102,103 |

### Close/Reset Cleanup

Graceful fresh-stream close and cleanup throughput.

| Library | Network | Tier | CC | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---|---|---:|---:|---|---:|---:|---:|
| picoquic | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 454,355 | 451,744 | 451,157 |
| picoquic | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 435,738 | 433,242 | 432,681 |
| LSQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 178,038 | 177,460 | 177,331 |
| ngtcp2 | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 166,824 | 166,268 | 166,143 |
| ngtcp2 | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 114,740 | 108,688 | 107,327 |
| TQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 96,397 | 93,276 | 92,574 |
| TQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 91,957 | 91,906 | 91,894 |
| LSQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 90,383 | 90,203 | 90,162 |
| quiche | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 83,262 | 82,813 | 82,712 |
| quiche | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 82,914 | 80,685 | 80,184 |
| XQUIC | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 70,753 | 65,103 | 63,832 |
| Quinn | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 49,617 | 47,496 | 47,019 |
| Quinn | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 50,304 | 46,954 | 46,201 |
| XQUIC | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 45,535 | 45,305 | 45,254 |
| noq | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 47,080 | 43,755 | 43,007 |
| noq | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 45,887 | 41,087 | 40,007 |
| s2n-quic | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 31,195 | 29,374 | 28,964 |
| s2n-quic | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 28,266 | 28,068 | 28,024 |
| Neqo | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 18,166 | 18,096 | 18,080 |
| quic-zig | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 18,041 | 17,969 | 17,953 |
| Neqo | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 18,037 | 17,858 | 17,818 |
| quic-zig | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 15,107 | 12,925 | 12,434 |
| mvfst | io_uring | lifecycle smoke | cubic | 1 | 2 | streams/second | 5,404 | 5,366 | 5,357 |
| mvfst | syscall | lifecycle smoke | cubic | 1 | 2 | streams/second | 5,083 | 5,079 | 5,079 |

## Caveats

- Publication-tier rows are the ranking-grade rows; lifecycle and capability rows are fixed smoke/proof rows unless explicitly promoted.
- Calibration and calibration-validation samples are published for auditability but excluded from the result tables.
- DATAGRAM rows report delivered unique echo rate; delivery/loss counters are in the raw sample TSV.
- `idle_footprint` reports server RSS delta per connection, where lower is better.
- Row-level caveats and full gate reasons are in [`publication-results.tsv`](results/loopback-full-matrix-20260527T052921Z/publication-results.tsv), [`row-stats.tsv`](results/loopback-full-matrix-20260527T052921Z/row-stats.tsv), [`publication-row-audit.tsv`](results/loopback-full-matrix-20260527T052921Z/publication-row-audit.tsv), and [`saturation-decisions.tsv`](results/loopback-full-matrix-20260527T052921Z/saturation-decisions.tsv).
- Raw samples are in [`adaptive-samples.tsv`](results/loopback-full-matrix-20260527T052921Z/adaptive-samples.tsv).
