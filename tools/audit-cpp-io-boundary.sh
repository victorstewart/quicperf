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

rust_runtime_forbidden='SystemTime::now|std::thread|thread::spawn|thread::sleep|tokio|mio::|UdpSocket|TcpStream|TcpListener|io_uring'
rust_runtime_hits="$(rg -n "$rust_runtime_forbidden" rust-packet-ffi/src/lib.rs || true)"
if [[ -n "$rust_runtime_hits" ]]; then
  printf 'quicperf_io_boundary status=failed scope=rust_packet_engine reason=private_clock_thread_or_io_runtime\n'
  printf '%s\n' "$rust_runtime_hits"
  status=1
fi

rust_instant_hits="$(rg -n 'Instant::now\(\)' rust-packet-ffi/src/lib.rs || true)"
rust_epoch_hits="$(printf '%s\n' "$rust_instant_hits" \
  | grep 'instant_epoch: Instant::now(), // QUICPERF_PRE_READY_INSTANT_EPOCH' || true)"
rust_test_instant_hits="$(printf '%s\n' "$rust_instant_hits" \
  | grep 'Instant::now(); // QUICPERF_TEST_ONLY_INSTANT' || true)"
rust_unclassified_instant_hits="$(printf '%s\n' "$rust_instant_hits" \
  | grep -v 'instant_epoch: Instant::now(), // QUICPERF_PRE_READY_INSTANT_EPOCH' \
  | grep -v 'Instant::now(); // QUICPERF_TEST_ONLY_INSTANT' || true)"
rust_test_module_line="$(rg -n '^mod caller_time_tests \{' rust-packet-ffi/src/lib.rs \
  | cut -d: -f1 || true)"
rust_proto_macro_line="$(rg -n '^macro_rules! proto_engine \{' rust-packet-ffi/src/lib.rs \
  | cut -d: -f1 || true)"
rust_test_markers_outside_module=""
while IFS=: read -r line _; do
  [[ -z "$line" ]] && continue
  if [[ -z "$rust_test_module_line" || -z "$rust_proto_macro_line" \
        || "$line" -le "$rust_test_module_line" || "$line" -ge "$rust_proto_macro_line" ]]; then
    rust_test_markers_outside_module+="${line}"$'\n'
  fi
done <<< "$rust_test_instant_hits"
if [[ "$(printf '%s\n' "$rust_epoch_hits" | grep -c . || true)" -ne 1 \
      || -n "$rust_unclassified_instant_hits" \
      || -n "$rust_test_markers_outside_module" ]]; then
  printf 'quicperf_io_boundary status=failed scope=rust_packet_engine reason=instant_epoch_policy_violation\n'
  printf '%s\n' "$rust_instant_hits"
  status=1
fi

zig_runtime_forbidden='clock_gettime|nanoTimestamp|std\.time\.|std\.Thread|posix\.(socket|bind|send|recv|poll|epoll)|io_uring'
zig_runtime_hits="$(rg -n "$zig_runtime_forbidden" zig-packet-ffi/src/lib.zig || true)"
if [[ -n "$zig_runtime_hits" ]]; then
  printf 'quicperf_io_boundary status=failed scope=zig_packet_engine reason=private_clock_thread_or_io_runtime\n'
  printf '%s\n' "$zig_runtime_hits"
  status=1
fi

zig_effective_source="${QUICPERF_QUIC_ZIG_EFFECTIVE_SOURCE:-}"
if [[ "$zig_effective_source" == "DISABLED" ]]; then
  zig_effective_source=""
fi
if [[ -n "$zig_effective_source" ]]; then
  zig_effective_sys="$zig_effective_source/src/sys.zig"
  if [[ ! -f "$zig_effective_sys" ]]; then
    printf 'quicperf_io_boundary status=failed scope=zig_effective_source reason=patched_clock_source_missing path=%s\n' "$zig_effective_sys"
    status=1
  else
    zig_effective_clock_hits="$(rg -n 'clock_gettime|std\.time\.nanoTimestamp|Instant::now|SystemTime::now' "$zig_effective_sys" || true)"
    if [[ -n "$zig_effective_clock_hits" ]]; then
      printf 'quicperf_io_boundary status=failed scope=zig_effective_source reason=private_clock_fallback\n'
      printf '%s\n' "$zig_effective_clock_hits"
      status=1
    fi
    if ! rg -q 'pub fn setCallerTimeNs\(now_ns: i64\)' "$zig_effective_sys" ||
       ! rg -q 'return caller_time_ns orelse @panic' "$zig_effective_sys"; then
      printf 'quicperf_io_boundary status=failed scope=zig_effective_source reason=caller_clock_injection_not_attested\n'
      status=1
    fi
  fi
fi

native_runtime_forbidden='\bclock_gettime[[:space:]]*\(|\bgettimeofday[[:space:]]*\(|::now[[:space:]]*\(|\b(epoll_create|epoll_create1|io_uring_queue_init|socket|sendmsg|recvmsg|sendmmsg|recvmmsg|sendto|recvfrom)[[:space:]]*\(|std::(thread|jthread)|pthread_create[[:space:]]*\('
native_runtime_hits="$(
  rg -n "$native_runtime_forbidden" src/adapters -g '*.{cpp,h}' \
    | grep -v '^src/adapters/mvfst_adapter.cpp:' \
    || true
)"
if [[ -n "$native_runtime_hits" ]]; then
  printf 'quicperf_io_boundary status=failed scope=native_adapters reason=private_clock_thread_or_io_runtime\n'
  printf '%s\n' "$native_runtime_hits"
  status=1
fi

if ! rg -q 'class ManualQuicEventBase final : public quic::QuicEventBase' \
    src/adapters/mvfst_adapter.cpp \
  || ! rg -q 'quicEventBase_->setNow\(nowRawNs\)' src/adapters/mvfst_adapter.cpp \
  || ! rg -q 'std::make_unique<MvfstNetworkSocket>' src/adapters/mvfst_adapter.cpp; then
  printf 'quicperf_io_boundary status=failed scope=mvfst reason=private_event_loop_not_fail_closed\n'
  status=1
fi

allocator_forbidden='jemalloc|mimalloc|tcmalloc|snmalloc'
allocator_hits="$(rg -ni "$allocator_forbidden" rust-packet-ffi zig-packet-ffi \
  -g '!target/**' -g '!zig-cache/**' -g '!zig-global-cache/**' -g '!zig-pkg/**' || true)"
if [[ -n "$allocator_hits" ]]; then
  printf 'quicperf_io_boundary status=failed scope=packet_engine reason=non_system_allocator\n'
  printf '%s\n' "$allocator_hits"
  status=1
fi
if ! rg -q '#\[global_allocator\][[:space:]]*$' rust-packet-ffi/src/lib.rs ||
   ! rg -q 'static GLOBAL_ALLOCATOR: std::alloc::System = std::alloc::System;' rust-packet-ffi/src/lib.rs ||
   ! rg -q 'std\.heap\.c_allocator' zig-packet-ffi/src/lib.zig; then
  printf 'quicperf_io_boundary status=failed scope=packet_engine reason=allocator_policy_not_explicit\n'
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

if ! rg -q 'ownedFileDescriptors\(\) const' src/core/packet_io.h \
    || ! rg -q 'attestRuntimeOwnership\(' src/main.cpp \
    || ! rg -q 'QUICPERF_RUNTIME_OWNERSHIP_AUDIT' src/main.cpp \
    || ! rg -q 'direct-socket-syscall' tests/runtime_ownership_contract.cpp \
    || ! rg -q 'static-liburing' tests/runtime_ownership_contract.cpp; then
  printf 'quicperf_io_boundary status=failed scope=runtime_ownership reason=behavioral_attestation_missing\n'
  status=1
fi

if ! rg -q '__wrap_clock_gettime' src/core/runtime_ownership.cpp \
    || ! rg -q '__wrap_gettimeofday' src/core/runtime_ownership.cpp \
    || ! rg -q '__wrap_time' src/core/runtime_ownership.cpp \
    || ! rg -q '__wrap_dlsym' src/core/runtime_ownership.cpp \
    || ! rg -q 'detectsClockBypass' tests/runtime_ownership_contract.cpp \
    || ! rg -q 'setRuntimeClockAnchor' tests/runtime_ownership_contract.cpp \
    || ! rg -q 'CLOCK_MONOTONIC_RAW' tests/runtime_ownership_contract.cpp \
    || ! rg -q 'CLOCK_REALTIME' tests/runtime_ownership_contract.cpp \
    || ! rg -q '__vdso_clock_gettime' tests/runtime_ownership_contract.cpp; then
  printf 'quicperf_io_boundary status=failed scope=runtime_ownership reason=virtual_clock_controls_missing\n'
  status=1
fi

if [[ "$status" == "0" ]]; then
  printf 'quicperf_io_boundary status=ok cpp_networkhub_owns_udp_io=1 packet_engines_are_sans_io=1 behavioral_fd_thread_attestation=1 behavioral_virtual_clock_attestation=1\n'
fi

exit "$status"
