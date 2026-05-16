#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

status=0

packet_sources=(
  rust-packet-ffi/src/lib.rs
  zig-packet-ffi/src/lib.zig
  perf.packet_engine.h
)

packet_forbidden='AsyncUdpSocket|std::net::UdpSocket|\btokio\b|\bmio\b|io_uring|\bsocket[[:space:]]*\(|\bbind[[:space:]]*\(|\bsendmsg[[:space:]]*\(|\brecvmsg[[:space:]]*\(|\bsendmmsg[[:space:]]*\(|\brecvmmsg[[:space:]]*\(|\bsendto[[:space:]]*\(|\brecvfrom[[:space:]]*\(|\bsend_to[[:space:]]*\(|\brecv_from[[:space:]]*\('
packet_hits="$(rg -n "$packet_forbidden" "${packet_sources[@]}" || true)"
if [[ -n "$packet_hits" ]]; then
  printf 'quicperf_io_boundary status=failed scope=packet_engine reason=adapter_owned_socket_io\n'
  printf '%s\n' "$packet_hits"
  status=1
fi

adapter_hits="$(
  rg -n '\b(socket|sendmsg|recvmsg|sendmmsg|recvmmsg|sendto|recvfrom)[[:space:]]*\(' perf*.h perf.cpp \
    | grep -v '^perf.networking.h:' \
    | grep -v '^perf.tcp.h:' \
    | grep -v '^perf.mvfst.h:[0-9]\+:.*\brecvmsg[[:space:]]*(' \
    | grep -v '^perf.mvfst.h:[0-9]\+:.*\brecvmmsg[[:space:]]*(' \
    || true
)"
if [[ -n "$adapter_hits" ]]; then
  printf 'quicperf_io_boundary status=failed scope=cpp_adapters reason=direct_socket_syscall_outside_networkhub\n'
  printf '%s\n' "$adapter_hits"
  status=1
fi

if [[ "$status" == "0" ]]; then
  printf 'quicperf_io_boundary status=ok cpp_networkhub_owns_udp_io=1 packet_engines_are_sans_io=1\n'
fi

exit "$status"
