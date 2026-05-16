# Latest Results

The adaptive publication runner samples each library/network/test row in randomized blocks until the row converges or reaches its bounded sample cap. Rows that remain noisy or nonstationary are retained with their measured distribution instead of being promoted as clean.

Client load is swept upward per row to find server saturation using as many client threads as needed within the configured limit. Tables are sorted by best p99 first; for the current rate and throughput metrics, higher is better.

The TCP+TLS sidecar is excluded from these QUIC tables. Full raw data and gate details are committed under [`results/full31`](results/full31/), with DATAGRAM addendum data under [`results/datagram-fairness-20260516`](results/datagram-fairness-20260516/).

## Results

### Download

Server-to-client bulk transfer; higher throughput is better.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | 1 | 45 | gigabits/second | 10.126 | 11.011 | 11.312 |
| LSQUIC | io_uring | 1 | 30 | gigabits/second | 5.861 | 8.526 | 8.863 |
| quiche | syscall | 2 | 35 | gigabits/second | 8.323 | 8.490 | 8.607 |
| LSQUIC | syscall | 3 | 35 | gigabits/second | 7.466 | 8.132 | 8.593 |
| ngtcp2 | io_uring | 1 | 30 | gigabits/second | 7.865 | 8.373 | 8.458 |
| quiche | io_uring | 1 | 40 | gigabits/second | 7.639 | 7.998 | 8.068 |
| quic-zig | syscall | 2 | 45 | gigabits/second | 7.017 | 7.229 | 7.767 |
| quic-zig | io_uring | 1 | 45 | gigabits/second | 6.472 | 6.809 | 7.149 |
| TQUIC | syscall | 5 | 50 | gigabits/second | 6.801 | 6.945 | 7.044 |
| picoquic | syscall | 1 | 20 | gigabits/second | 6.841 | 6.917 | 6.933 |
| TQUIC | io_uring | 2 | 25 | gigabits/second | 6.127 | 6.256 | 6.456 |
| picoquic | io_uring | 1 | 40 | gigabits/second | 6.125 | 6.369 | 6.431 |
| XQUIC | syscall | 1 | 40 | gigabits/second | 3.629 | 4.196 | 5.967 |
| mvfst | syscall | 2 | 30 | gigabits/second | 5.000 | 5.109 | 5.213 |
| mvfst | io_uring | 2 | 30 | gigabits/second | 4.524 | 4.617 | 4.733 |
| Quinn | syscall | 1 | 80 | gigabits/second | 3.826 | 4.133 | 4.280 |
| s2n-quic | io_uring | 1 | 120 | gigabits/second | 3.763 | 3.890 | 4.156 |
| noq | syscall | 1 | 45 | gigabits/second | 3.361 | 3.664 | 3.983 |
| s2n-quic | syscall | 1 | 30 | gigabits/second | 3.374 | 3.610 | 3.771 |
| Neqo | syscall | 1 | 45 | gigabits/second | 3.294 | 3.475 | 3.767 |
| noq | io_uring | 2 | 30 | gigabits/second | 3.364 | 3.494 | 3.602 |
| Quinn | io_uring | 1 | 50 | gigabits/second | 3.274 | 3.439 | 3.500 |
| Neqo | io_uring | 1 | 35 | gigabits/second | 3.147 | 3.208 | 3.491 |
| XQUIC | io_uring | 1 | 25 | gigabits/second | 1.781 | 1.867 | 1.905 |

### Upload

Client-to-server bulk transfer; higher throughput is better.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| TQUIC | io_uring | 2 | 60 | gigabits/second | 8.621 | 9.266 | 10.338 |
| ngtcp2 | syscall | 1 | 40 | gigabits/second | 8.126 | 9.343 | 9.645 |
| ngtcp2 | io_uring | 1 | 40 | gigabits/second | 7.386 | 8.513 | 9.089 |
| quic-zig | syscall | 1 | 40 | gigabits/second | 6.568 | 7.008 | 7.362 |
| quiche | syscall | 1 | 45 | gigabits/second | 6.464 | 7.087 | 7.195 |
| picoquic | syscall | 1 | 40 | gigabits/second | 6.203 | 6.757 | 6.890 |
| quic-zig | io_uring | 1 | 45 | gigabits/second | 6.082 | 6.549 | 6.828 |
| quiche | io_uring | 1 | 40 | gigabits/second | 5.988 | 6.622 | 6.732 |
| picoquic | io_uring | 1 | 40 | gigabits/second | 5.604 | 6.146 | 6.354 |
| s2n-quic | io_uring | 7 | 30 | gigabits/second | 6.188 | 6.258 | 6.288 |
| TQUIC | syscall | 1 | 40 | gigabits/second | 5.583 | 6.011 | 6.261 |
| LSQUIC | syscall | 1 | 40 | gigabits/second | 4.902 | 5.508 | 5.977 |
| LSQUIC | io_uring | 1 | 40 | gigabits/second | 4.545 | 5.149 | 5.506 |
| mvfst | syscall | 1 | 40 | gigabits/second | 3.875 | 4.304 | 4.692 |
| Quinn | syscall | 1 | 30 | gigabits/second | 4.001 | 4.274 | 4.620 |
| s2n-quic | syscall | 1 | 30 | gigabits/second | 3.704 | 4.348 | 4.524 |
| noq | syscall | 1 | 35 | gigabits/second | 3.327 | 3.594 | 4.000 |
| Neqo | io_uring | 1 | 40 | gigabits/second | 3.133 | 3.556 | 3.999 |
| mvfst | io_uring | 1 | 120 | gigabits/second | 3.427 | 3.728 | 3.964 |
| Neqo | syscall | 1 | 120 | gigabits/second | 3.295 | 3.567 | 3.957 |
| XQUIC | syscall | 1 | 30 | gigabits/second | 2.817 | 3.429 | 3.652 |
| Quinn | io_uring | 1 | 30 | gigabits/second | 3.325 | 3.513 | 3.575 |
| noq | io_uring | 1 | 30 | gigabits/second | 2.940 | 3.025 | 3.175 |
| XQUIC | io_uring | 1 | 40 | gigabits/second | 1.546 | 1.696 | 1.813 |

### Bidirectional

Simultaneous upload and download on one connection.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| LSQUIC | syscall | 1 | 30 | gigabits/second | 7.844 | 9.809 | 10.728 |
| ngtcp2 | syscall | 1 | 30 | gigabits/second | 7.170 | 8.964 | 9.771 |
| LSQUIC | io_uring | 1 | 35 | gigabits/second | 6.031 | 8.284 | 9.475 |
| quic-zig | syscall | 1 | 60 | gigabits/second | 7.445 | 8.401 | 9.359 |
| ngtcp2 | io_uring | 1 | 30 | gigabits/second | 6.458 | 8.261 | 8.526 |
| quic-zig | io_uring | 1 | 40 | gigabits/second | 6.601 | 7.430 | 7.506 |
| picoquic | syscall | 1 | 30 | gigabits/second | 5.371 | 6.507 | 6.852 |
| quiche | syscall | 1 | 40 | gigabits/second | 5.779 | 6.365 | 6.488 |
| picoquic | io_uring | 1 | 30 | gigabits/second | 4.871 | 6.073 | 6.159 |
| quiche | io_uring | 1 | 30 | gigabits/second | 4.633 | 5.547 | 5.993 |
| TQUIC | syscall | 1 | 40 | gigabits/second | 4.609 | 5.350 | 5.662 |
| mvfst | syscall | 1 | 120 | gigabits/second | 4.779 | 5.208 | 5.482 |
| TQUIC | io_uring | 1 | 40 | gigabits/second | 4.363 | 4.928 | 5.444 |
| s2n-quic | syscall | 2 | 25 | gigabits/second | 4.755 | 5.250 | 5.363 |
| XQUIC | syscall | 1 | 40 | gigabits/second | 3.317 | 4.386 | 5.129 |
| mvfst | io_uring | 1 | 30 | gigabits/second | 3.707 | 4.418 | 4.614 |
| noq | syscall | 1 | 55 | gigabits/second | 4.039 | 4.363 | 4.426 |
| Quinn | syscall | 1 | 40 | gigabits/second | 3.455 | 3.849 | 4.240 |
| noq | io_uring | 1 | 40 | gigabits/second | 3.647 | 3.999 | 4.092 |
| s2n-quic | io_uring | 1 | 40 | gigabits/second | 3.769 | 3.963 | 4.052 |
| Quinn | io_uring | 2 | 90 | gigabits/second | 3.375 | 3.563 | 3.949 |
| XQUIC | io_uring | 1 | 40 | gigabits/second | 3.056 | 3.615 | 3.935 |
| Neqo | syscall | 1 | 30 | gigabits/second | 3.268 | 3.495 | 3.589 |
| Neqo | io_uring | 1 | 45 | gigabits/second | 3.001 | 3.191 | 3.484 |

### Multistream Download

Server-to-client transfer split across concurrent streams.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | 1 | 30 | gigabits/second | 7.433 | 8.824 | 9.685 |
| ngtcp2 | io_uring | 1 | 30 | gigabits/second | 5.771 | 8.204 | 8.423 |
| LSQUIC | io_uring | 1 | 40 | gigabits/second | 4.159 | 5.238 | 7.874 |
| quiche | syscall | 1 | 30 | gigabits/second | 5.791 | 6.647 | 7.217 |
| picoquic | syscall | 1 | 35 | gigabits/second | 5.018 | 6.611 | 6.745 |
| LSQUIC | syscall | 1 | 30 | gigabits/second | 5.500 | 5.940 | 6.623 |
| picoquic | io_uring | 1 | 30 | gigabits/second | 4.980 | 6.282 | 6.448 |
| quic-zig | syscall | 1 | 30 | gigabits/second | 4.954 | 6.167 | 6.196 |
| quiche | io_uring | 1 | 35 | gigabits/second | 4.670 | 5.367 | 5.929 |
| quic-zig | io_uring | 1 | 40 | gigabits/second | 4.669 | 5.410 | 5.835 |
| TQUIC | syscall | 1 | 30 | gigabits/second | 4.446 | 5.383 | 5.636 |
| XQUIC | io_uring | 1 | 30 | gigabits/second | 4.286 | 5.424 | 5.563 |
| XQUIC | syscall | 1 | 40 | gigabits/second | 4.585 | 5.201 | 5.394 |
| TQUIC | io_uring | 1 | 40 | gigabits/second | 4.187 | 5.026 | 5.329 |
| mvfst | syscall | 1 | 65 | gigabits/second | 4.042 | 4.341 | 4.581 |
| Quinn | io_uring | 2 | 30 | gigabits/second | 3.935 | 4.370 | 4.476 |
| mvfst | io_uring | 3 | 35 | gigabits/second | 3.851 | 4.319 | 4.421 |
| Quinn | syscall | 1 | 40 | gigabits/second | 3.602 | 3.938 | 4.055 |
| s2n-quic | syscall | 1 | 50 | gigabits/second | 3.154 | 3.397 | 3.774 |
| noq | syscall | 1 | 40 | gigabits/second | 3.177 | 3.402 | 3.536 |
| s2n-quic | io_uring | 1 | 20 | gigabits/second | 2.880 | 3.003 | 3.069 |
| noq | io_uring | 1 | 20 | gigabits/second | 2.664 | 2.921 | 3.061 |
| Neqo | syscall | 1 | 30 | gigabits/second | 2.768 | 2.913 | 2.966 |
| Neqo | io_uring | 1 | 20 | gigabits/second | 2.693 | 2.752 | 2.787 |

### Multistream Upload

Client-to-server transfer split across concurrent streams.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | io_uring | 1 | 30 | gigabits/second | 6.232 | 8.064 | 9.216 |
| ngtcp2 | syscall | 1 | 40 | gigabits/second | 6.661 | 8.036 | 8.874 |
| quic-zig | syscall | 1 | 40 | gigabits/second | 5.658 | 6.273 | 6.845 |
| picoquic | syscall | 1 | 30 | gigabits/second | 5.319 | 6.238 | 6.657 |
| picoquic | io_uring | 1 | 30 | gigabits/second | 4.944 | 5.993 | 6.251 |
| quic-zig | io_uring | 1 | 30 | gigabits/second | 5.068 | 5.926 | 6.185 |
| LSQUIC | syscall | 1 | 30 | gigabits/second | 4.706 | 5.877 | 6.140 |
| quiche | syscall | 1 | 40 | gigabits/second | 5.356 | 5.829 | 6.001 |
| XQUIC | io_uring | 1 | 40 | gigabits/second | 4.457 | 5.516 | 5.895 |
| s2n-quic | syscall | 2 | 20 | gigabits/second | 5.239 | 5.458 | 5.629 |
| TQUIC | io_uring | 1 | 40 | gigabits/second | 4.416 | 5.312 | 5.621 |
| TQUIC | syscall | 1 | 40 | gigabits/second | 4.104 | 4.727 | 5.341 |
| quiche | io_uring | 1 | 35 | gigabits/second | 3.955 | 4.974 | 5.274 |
| s2n-quic | io_uring | 2 | 25 | gigabits/second | 4.769 | 4.985 | 5.129 |
| XQUIC | syscall | 1 | 60 | gigabits/second | 4.043 | 4.563 | 5.068 |
| LSQUIC | io_uring | 1 | 40 | gigabits/second | 3.946 | 4.733 | 5.005 |
| Quinn | syscall | 1 | 40 | gigabits/second | 3.944 | 4.218 | 4.313 |
| mvfst | syscall | 1 | 65 | gigabits/second | 3.567 | 3.907 | 4.063 |
| noq | syscall | 1 | 70 | gigabits/second | 3.192 | 3.431 | 3.714 |
| mvfst | io_uring | 1 | 40 | gigabits/second | 3.045 | 3.403 | 3.562 |
| Quinn | io_uring | 1 | 40 | gigabits/second | 3.193 | 3.418 | 3.475 |
| Neqo | syscall | 1 | 30 | gigabits/second | 2.960 | 3.266 | 3.474 |
| noq | io_uring | 1 | 20 | gigabits/second | 2.801 | 2.918 | 3.015 |
| Neqo | io_uring | 1 | 25 | gigabits/second | 2.744 | 2.944 | 3.012 |

### Request/Response

Small request/response exchanges on fresh bidirectional streams.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| picoquic | syscall | 2 | 20 | requests/second | 260,744 | 289,493 | 306,789 |
| picoquic | io_uring | 1 | 20 | requests/second | 213,560 | 224,405 | 284,147 |
| TQUIC | syscall | 2 | 20 | requests/second | 172,005 | 177,853 | 195,493 |
| TQUIC | io_uring | 4 | 30 | requests/second | 170,085 | 177,469 | 180,714 |
| ngtcp2 | syscall | 2 | 20 | requests/second | 157,570 | 170,688 | 177,972 |
| LSQUIC | syscall | 1 | 30 | requests/second | 96,775 | 155,070 | 159,570 |
| XQUIC | syscall | 1 | 20 | requests/second | 102,508 | 108,188 | 128,777 |
| XQUIC | io_uring | 2 | 20 | requests/second | 95,769 | 97,282 | 102,248 |
| ngtcp2 | io_uring | 1 | 20 | requests/second | 91,390 | 93,382 | 101,561 |
| quiche | syscall | 1 | 20 | requests/second | 84,102 | 86,132 | 100,182 |
| quiche | io_uring | 1 | 20 | requests/second | 74,602 | 77,146 | 78,441 |
| Quinn | syscall | 2 | 20 | requests/second | 66,513 | 72,457 | 77,953 |
| noq | io_uring | 1 | 30 | requests/second | 46,051 | 54,969 | 61,375 |
| noq | syscall | 1 | 20 | requests/second | 54,293 | 54,952 | 59,476 |
| LSQUIC | io_uring | 2 | 20 | requests/second | 54,188 | 55,113 | 55,474 |
| s2n-quic | syscall | 5 | 30 | requests/second | 49,795 | 54,074 | 55,169 |
| Quinn | io_uring | 1 | 20 | requests/second | 51,684 | 52,401 | 52,933 |
| s2n-quic | io_uring | 5 | 30 | requests/second | 44,364 | 47,647 | 49,271 |
| Neqo | syscall | 1 | 20 | requests/second | 20,354 | 20,974 | 21,534 |
| Neqo | io_uring | 1 | 20 | requests/second | 17,953 | 19,075 | 19,805 |
| quic-zig | syscall | 1 | 20 | requests/second | 17,759 | 18,048 | 18,200 |
| quic-zig | io_uring | 1 | 20 | requests/second | 16,838 | 17,499 | 17,745 |
| mvfst | syscall | 3 | 20 | requests/second | 8,859 | 9,123 | 9,265 |
| mvfst | io_uring | 1 | 50 | requests/second | 6,673 | 7,109 | 7,574 |

### Stream Churn

Repeated stream open, send, receive, and finish lifecycle.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| picoquic | io_uring | 3 | 20 | streams/second | 610,129 | 640,965 | 675,119 |
| picoquic | syscall | 1 | 30 | streams/second | 194,230 | 251,929 | 289,351 |
| TQUIC | syscall | 6 | 20 | streams/second | 260,269 | 262,930 | 264,437 |
| TQUIC | io_uring | 4 | 20 | streams/second | 218,170 | 229,525 | 239,596 |
| LSQUIC | syscall | 2 | 20 | streams/second | 223,368 | 228,331 | 229,835 |
| ngtcp2 | syscall | 1 | 20 | streams/second | 149,255 | 156,374 | 184,642 |
| XQUIC | syscall | 1 | 20 | streams/second | 106,542 | 111,082 | 130,863 |
| ngtcp2 | io_uring | 1 | 30 | streams/second | 101,399 | 111,677 | 118,579 |
| XQUIC | io_uring | 2 | 20 | streams/second | 98,695 | 107,770 | 110,614 |
| quiche | syscall | 1 | 35 | streams/second | 87,365 | 89,887 | 105,549 |
| Quinn | io_uring | 1 | 40 | streams/second | 52,666 | 56,338 | 82,139 |
| Quinn | syscall | 1 | 40 | streams/second | 63,230 | 70,832 | 80,713 |
| quiche | io_uring | 1 | 20 | streams/second | 75,763 | 78,080 | 79,703 |
| LSQUIC | io_uring | 3 | 20 | streams/second | 59,923 | 62,588 | 69,551 |
| noq | syscall | 1 | 20 | streams/second | 55,527 | 64,630 | 68,405 |
| s2n-quic | syscall | 3 | 30 | streams/second | 49,358 | 53,419 | 55,450 |
| noq | io_uring | 1 | 20 | streams/second | 46,360 | 47,195 | 51,493 |
| s2n-quic | io_uring | 5 | 30 | streams/second | 44,658 | 46,757 | 48,952 |
| Neqo | syscall | 2 | 30 | streams/second | 23,920 | 25,979 | 27,739 |
| Neqo | io_uring | 1 | 20 | streams/second | 18,266 | 19,395 | 20,074 |
| quic-zig | io_uring | 1 | 30 | streams/second | 17,246 | 18,727 | 19,859 |
| quic-zig | syscall | 1 | 20 | streams/second | 17,973 | 18,337 | 18,601 |
| mvfst | syscall | 2 | 20 | streams/second | 7,186 | 7,418 | 7,610 |
| mvfst | io_uring | 1 | 20 | streams/second | 6,620 | 6,991 | 7,210 |

### Small Payload Messages

Tiny-message packet and API overhead.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| picoquic | io_uring | 1 | 40 | messages/second | 238,660 | 245,876 | 315,286 |
| picoquic | syscall | 1 | 40 | messages/second | 195,472 | 235,626 | 309,092 |
| LSQUIC | syscall | 2 | 20 | messages/second | 224,512 | 228,402 | 230,792 |
| TQUIC | syscall | 2 | 20 | messages/second | 196,136 | 204,473 | 214,672 |
| ngtcp2 | syscall | 1 | 20 | messages/second | 148,638 | 154,262 | 156,983 |
| quiche | syscall | 3 | 20 | messages/second | 138,048 | 143,550 | 145,434 |
| ngtcp2 | io_uring | 3 | 20 | messages/second | 125,672 | 130,265 | 138,356 |
| XQUIC | syscall | 1 | 40 | messages/second | 107,160 | 116,644 | 132,827 |
| TQUIC | io_uring | 1 | 20 | messages/second | 110,253 | 113,171 | 113,336 |
| XQUIC | io_uring | 2 | 40 | messages/second | 99,234 | 106,420 | 112,214 |
| quiche | io_uring | 1 | 25 | messages/second | 75,743 | 81,122 | 93,899 |
| Quinn | syscall | 1 | 40 | messages/second | 63,129 | 64,324 | 75,604 |
| Quinn | io_uring | 1 | 30 | messages/second | 52,612 | 54,602 | 71,337 |
| noq | syscall | 2 | 20 | messages/second | 56,290 | 62,269 | 67,864 |
| LSQUIC | io_uring | 2 | 20 | messages/second | 59,112 | 61,452 | 67,427 |
| noq | io_uring | 1 | 30 | messages/second | 47,042 | 60,858 | 62,556 |
| s2n-quic | syscall | 2 | 20 | messages/second | 44,943 | 46,753 | 49,045 |
| s2n-quic | io_uring | 2 | 20 | messages/second | 40,415 | 41,905 | 42,791 |
| Neqo | syscall | 1 | 20 | messages/second | 20,213 | 20,876 | 21,301 |
| quic-zig | io_uring | 1 | 30 | messages/second | 17,249 | 17,919 | 19,021 |
| Neqo | io_uring | 1 | 20 | messages/second | 18,055 | 18,880 | 19,019 |
| quic-zig | syscall | 1 | 20 | messages/second | 17,985 | 18,627 | 18,846 |
| mvfst | io_uring | 3 | 25 | messages/second | 8,592 | 9,438 | 9,675 |
| mvfst | syscall | 2 | 20 | messages/second | 7,275 | 7,337 | 7,422 |

### Loss Recovery

Deterministic impairment path covering loss recovery behavior.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | 1 | 30 | gigabits/second | 6.982 | 8.581 | 8.929 |
| ngtcp2 | io_uring | 1 | 30 | gigabits/second | 6.343 | 8.186 | 8.365 |
| quiche | syscall | 1 | 30 | gigabits/second | 5.698 | 6.409 | 6.647 |
| quiche | io_uring | 1 | 30 | gigabits/second | 5.222 | 6.241 | 6.546 |
| picoquic | syscall | 1 | 30 | gigabits/second | 5.294 | 6.141 | 6.290 |
| LSQUIC | syscall | 1 | 30 | gigabits/second | 5.068 | 6.030 | 6.235 |
| LSQUIC | io_uring | 1 | 30 | gigabits/second | 5.158 | 5.584 | 6.170 |
| quic-zig | syscall | 1 | 30 | gigabits/second | 4.837 | 5.851 | 6.167 |
| XQUIC | io_uring | 1 | 35 | gigabits/second | 4.166 | 5.615 | 5.935 |
| picoquic | io_uring | 1 | 30 | gigabits/second | 4.480 | 5.443 | 5.919 |
| TQUIC | syscall | 1 | 40 | gigabits/second | 4.961 | 5.613 | 5.909 |
| TQUIC | io_uring | 1 | 40 | gigabits/second | 4.804 | 5.443 | 5.773 |
| XQUIC | syscall | 1 | 30 | gigabits/second | 4.547 | 5.383 | 5.422 |
| mvfst | syscall | 3 | 20 | gigabits/second | 4.197 | 4.396 | 4.716 |
| Quinn | syscall | 1 | 45 | gigabits/second | 3.595 | 4.293 | 4.449 |
| Neqo | syscall | 1 | 30 | gigabits/second | 3.801 | 4.210 | 4.405 |
| mvfst | io_uring | 5 | 20 | gigabits/second | 3.804 | 4.210 | 4.350 |
| Neqo | io_uring | 1 | 30 | gigabits/second | 3.944 | 4.148 | 4.327 |
| quic-zig | io_uring | 1 | 35 | gigabits/second | 3.290 | 4.039 | 4.115 |
| noq | syscall | 1 | 20 | gigabits/second | 3.040 | 3.409 | 3.533 |
| Quinn | io_uring | 1 | 20 | gigabits/second | 3.069 | 3.264 | 3.486 |
| s2n-quic | syscall | 1 | 20 | gigabits/second | 3.101 | 3.202 | 3.332 |
| s2n-quic | io_uring | 1 | 40 | gigabits/second | 3.042 | 3.185 | 3.311 |
| noq | io_uring | 2 | 20 | gigabits/second | 2.794 | 3.030 | 3.167 |

### Flow Control

Small-window transfer pressure and flow-control update behavior.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | 1 | 30 | gigabits/second | 5.842 | 8.124 | 8.712 |
| ngtcp2 | io_uring | 1 | 30 | gigabits/second | 5.046 | 7.587 | 8.072 |
| LSQUIC | io_uring | 1 | 40 | gigabits/second | 5.036 | 5.168 | 6.686 |
| picoquic | syscall | 1 | 35 | gigabits/second | 4.567 | 6.263 | 6.660 |
| LSQUIC | syscall | 1 | 20 | gigabits/second | 5.648 | 5.993 | 6.646 |
| quiche | syscall | 1 | 30 | gigabits/second | 4.898 | 5.689 | 6.373 |
| quiche | io_uring | 1 | 30 | gigabits/second | 4.521 | 6.020 | 6.262 |
| picoquic | io_uring | 1 | 30 | gigabits/second | 4.165 | 4.964 | 5.992 |
| quic-zig | syscall | 1 | 30 | gigabits/second | 1.048 | 4.896 | 5.165 |
| XQUIC | syscall | 1 | 40 | gigabits/second | 3.706 | 4.407 | 4.698 |
| quic-zig | io_uring | 1 | 30 | gigabits/second | 0.797 | 2.332 | 4.245 |
| XQUIC | io_uring | 1 | 20 | gigabits/second | 3.672 | 3.834 | 4.220 |
| mvfst | syscall | 1 | 30 | gigabits/second | 3.448 | 3.939 | 4.136 |
| Neqo | syscall | 1 | 40 | gigabits/second | 2.995 | 3.523 | 3.993 |
| TQUIC | syscall | 1 | 30 | gigabits/second | 3.338 | 3.729 | 3.981 |
| TQUIC | io_uring | 1 | 20 | gigabits/second | 3.152 | 3.515 | 3.870 |
| Neqo | io_uring | 1 | 40 | gigabits/second | 2.745 | 3.317 | 3.749 |
| mvfst | io_uring | 1 | 30 | gigabits/second | 3.023 | 3.316 | 3.533 |
| Quinn | syscall | 1 | 30 | gigabits/second | 2.851 | 3.263 | 3.504 |
| Quinn | io_uring | 1 | 40 | gigabits/second | 2.376 | 2.824 | 3.200 |
| s2n-quic | io_uring | 1 | 30 | gigabits/second | 2.255 | 2.613 | 2.889 |
| noq | syscall | 1 | 25 | gigabits/second | 2.517 | 2.777 | 2.841 |
| s2n-quic | syscall | 1 | 30 | gigabits/second | 2.390 | 2.644 | 2.695 |
| noq | io_uring | 1 | 20 | gigabits/second | 2.117 | 2.324 | 2.429 |

### Connect

Full connection establishment plus stream creation.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| ngtcp2 | syscall | 1 | 30 | connections/second | 2,083 | 2,633 | 2,801 |
| ngtcp2 | io_uring | 1 | 40 | connections/second | 2,061 | 2,385 | 2,786 |
| LSQUIC | syscall | 2 | 20 | connections/second | 2,417 | 2,496 | 2,713 |
| XQUIC | syscall | 1 | 30 | connections/second | 1,856 | 2,333 | 2,395 |
| TQUIC | syscall | 1 | 30 | connections/second | 1,440 | 1,808 | 2,161 |
| XQUIC | io_uring | 1 | 40 | connections/second | 1,641 | 1,883 | 2,091 |
| TQUIC | io_uring | 1 | 30 | connections/second | 1,603 | 1,981 | 2,021 |
| Quinn | syscall | 1 | 40 | connections/second | 1,506 | 1,879 | 1,920 |
| Quinn | io_uring | 1 | 35 | connections/second | 1,485 | 1,877 | 1,905 |
| noq | io_uring | 1 | 40 | connections/second | 1,382 | 1,675 | 1,815 |
| LSQUIC | io_uring | 1 | 40 | connections/second | 1,526 | 1,567 | 1,724 |
| noq | syscall | 1 | 40 | connections/second | 1,360 | 1,651 | 1,684 |
| quiche | io_uring | 1 | 30 | connections/second | 1,228 | 1,412 | 1,618 |
| quiche | syscall | 1 | 30 | connections/second | 1,186 | 1,473 | 1,604 |
| picoquic | syscall | 1 | 30 | connections/second | 1,159 | 1,456 | 1,497 |
| s2n-quic | io_uring | 1 | 30 | connections/second | 1,135 | 1,356 | 1,465 |
| picoquic | io_uring | 1 | 40 | connections/second | 1,026 | 1,379 | 1,405 |
| s2n-quic | syscall | 1 | 40 | connections/second | 1,135 | 1,378 | 1,401 |
| quic-zig | io_uring | 1 | 30 | connections/second | 1,040 | 1,306 | 1,349 |
| quic-zig | syscall | 1 | 20 | connections/second | 1,045 | 1,149 | 1,292 |
| Neqo | io_uring | 1 | 30 | connections/second | 383 | 462 | 505 |
| Neqo | syscall | 1 | 40 | connections/second | 385 | 463 | 466 |
| mvfst | io_uring | 1 | 40 | connections/second | 343 | 389 | 402 |
| mvfst | syscall | 1 | 40 | connections/second | 351 | 393 | 401 |

### Datagram

Unreliable application DATAGRAM echo capability.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| quiche | syscall | 1 | 30 | messages/second | 3,452,015 | 3,872,983 | 3,940,269 |
| quiche | io_uring | 1 | 30 | messages/second | 3,411,439 | 3,745,157 | 3,794,009 |
| quic-zig | syscall | 1 | 40 | messages/second | 225,887 | 254,681 | 269,515 |
| Quinn | syscall | 1 | 30 | messages/second | 196,594 | 225,396 | 254,477 |
| quic-zig | io_uring | 1 | 20 | messages/second | 200,780 | 209,318 | 212,550 |
| Quinn | io_uring | 1 | 25 | messages/second | 183,608 | 199,314 | 212,450 |
| noq | syscall | 1 | 35 | messages/second | 166,055 | 177,262 | 192,475 |
| noq | io_uring | 1 | 85 | messages/second | 156,943 | 175,685 | 188,647 |
| Neqo | syscall | 1 | 30 | messages/second | 128,410 | 137,865 | 152,597 |
| Neqo | io_uring | 1 | 30 | messages/second | 117,065 | 131,603 | 139,162 |
| s2n-quic | syscall | 1 | 50 | messages/second | 115,057 | 124,049 | 130,457 |
| s2n-quic | io_uring | 1 | 40 | messages/second | 104,491 | 115,432 | 122,533 |

### Close/Reset Cleanup

Graceful fresh-stream close and cleanup throughput.

| Library | Network | Client threads | Samples | Unit | p50 | p90 | p99 |
|---|---|---:|---:|---|---:|---:|---:|
| picoquic | io_uring | 1 | 30 | streams/second | 243,352 | 248,218 | 336,872 |
| picoquic | syscall | 1 | 40 | streams/second | 225,514 | 240,530 | 308,102 |
| TQUIC | syscall | 3 | 20 | streams/second | 236,586 | 244,869 | 247,770 |
| ngtcp2 | syscall | 1 | 30 | streams/second | 148,254 | 195,756 | 210,060 |
| LSQUIC | syscall | 1 | 40 | streams/second | 188,385 | 189,682 | 206,553 |
| XQUIC | syscall | 1 | 20 | streams/second | 106,200 | 112,312 | 132,963 |
| TQUIC | io_uring | 1 | 20 | streams/second | 111,943 | 113,191 | 113,904 |
| ngtcp2 | io_uring | 1 | 20 | streams/second | 101,140 | 104,125 | 111,266 |
| XQUIC | io_uring | 3 | 20 | streams/second | 101,037 | 105,990 | 107,675 |
| quiche | syscall | 1 | 20 | streams/second | 87,174 | 89,439 | 99,572 |
| quiche | io_uring | 1 | 20 | streams/second | 78,221 | 81,514 | 93,141 |
| LSQUIC | io_uring | 2 | 20 | streams/second | 59,125 | 61,892 | 70,535 |
| noq | syscall | 2 | 20 | streams/second | 58,217 | 62,406 | 66,089 |
| Quinn | syscall | 1 | 20 | streams/second | 62,602 | 63,989 | 64,553 |
| Quinn | io_uring | 1 | 20 | streams/second | 52,595 | 53,350 | 54,129 |
| noq | io_uring | 2 | 20 | streams/second | 49,065 | 51,682 | 53,487 |
| s2n-quic | syscall | 5 | 30 | streams/second | 49,453 | 50,856 | 52,380 |
| s2n-quic | io_uring | 5 | 30 | streams/second | 44,562 | 46,213 | 47,165 |
| Neqo | syscall | 1 | 20 | streams/second | 20,712 | 21,464 | 22,275 |
| quic-zig | syscall | 1 | 30 | streams/second | 18,244 | 20,201 | 21,091 |
| Neqo | io_uring | 1 | 20 | streams/second | 18,278 | 19,210 | 19,855 |
| quic-zig | io_uring | 1 | 30 | streams/second | 17,248 | 18,801 | 19,209 |
| mvfst | syscall | 3 | 20 | streams/second | 8,845 | 9,215 | 9,813 |
| mvfst | io_uring | 1 | 25 | streams/second | 6,629 | 7,054 | 7,165 |

## Caveats

- `idle_footprint` is omitted from the current table because this run captured only the old completion marker, not resource footprint. Rerun with the RSS sampler before publishing idle-footprint claims.
- `datagram` rows come from the addendum run with a shared 1,024-message outstanding cap and 65,536 echo operations. They are measured distributions, not a clean DATAGRAM leaderboard, because strict publication gates still marked the rows noisy or nonstationary.
- Unsupported capability rows are explicit unsupported markers, not crashes.
- Row-level caveats and full gate reasons are in [`publication-results.tsv`](results/full31/publication-results.tsv), [`row-stats.tsv`](results/full31/row-stats.tsv), [`publication-row-audit.tsv`](results/full31/publication-row-audit.tsv), and [`saturation-decisions.tsv`](results/full31/saturation-decisions.tsv).
- Raw samples are in [`adaptive-samples.tsv`](results/full31/adaptive-samples.tsv).
- DATAGRAM addendum gate reasons are in [`publication-results.tsv`](results/datagram-fairness-20260516/publication-results.tsv), [`row-stats.tsv`](results/datagram-fairness-20260516/row-stats.tsv), [`publication-row-audit.tsv`](results/datagram-fairness-20260516/publication-row-audit.tsv), and [`saturation-decisions.tsv`](results/datagram-fairness-20260516/saturation-decisions.tsv); raw samples are in [`adaptive-samples.tsv`](results/datagram-fairness-20260516/adaptive-samples.tsv), with notes in [`README.md`](results/datagram-fairness-20260516/README.md).
