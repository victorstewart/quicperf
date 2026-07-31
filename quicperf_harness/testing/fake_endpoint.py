"""Deterministic structured-protocol endpoint used by coordinator fault tests.

This module is deliberately executable (``python -m ...fake_endpoint``), but it
is never a production endpoint.  Production trials execute the frozen native
binary paths from the identity manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Any

from ..canonical import canonical_bytes
from ..protocol import MAX_PACKET, MessageType, SeqPacketChannel, encode_packet


def _raw_ns() -> int:
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)


def _sleep_until_raw(target_raw_ns: int) -> None:
    while (remaining_ns := target_raw_ns - _raw_ns()) > 0:
        time.sleep(min(0.001, remaining_ns / 1_000_000_000))


def _parse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("mode", choices=("describe", "worker"))
    parser.add_argument("--role", choices=("server", "client"))
    parser.add_argument("--control-fd", type=int)
    return parser.parse_args()


def _control_fd(arguments: argparse.Namespace) -> int:
    value = arguments.control_fd
    if value is None:
        text = os.environ.get("QUICPERF_CONTROL_FD")
        if text is None:
            raise SystemExit("missing --control-fd")
        value = int(text)
    return value


def _send_hello(channel: SeqPacketChannel, role: str) -> None:
    build_id = hashlib.sha256(b"quicperf-v2-fake-endpoint").digest()
    channel.send(
        MessageType.HELLO,
        {"role": role, "build_id": build_id, "control_version": 1},
    )
    channel.send(
        MessageType.CAPABILITIES,
        {
            "library": "fake_endpoint",
            "build_id": build_id,
            "protocol_version": 1,
            "roles": "server,client",
            "backends": "syscall,iouring",
            "scenarios": "all",
            "capabilities": "qpf2,batch64,reset",
            "effective_features": "common_core_only",
        },
    )


def _fault(behavior: str, point: str) -> None:
    if behavior == f"crash_{point}":
        os._exit(71)
    if behavior == f"hang_{point}":
        while True:
            time.sleep(60)


def _claim_late_arm_fault() -> bool:
    marker = os.environ.get("QUICPERF_FAKE_LATE_ARM_MARKER")
    if not marker:
        raise RuntimeError("late_arm_once requires a shared marker path")
    try:
        descriptor = os.open(
            marker,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
    except FileExistsError:
        return False
    os.close(descriptor)
    return True


def _trace(role: str, event: str, **fields: Any) -> None:
    path = os.environ.get("QUICPERF_FAKE_TRACE")
    if not path:
        return
    record = {"event": event, "pid": os.getpid(), "role": role, **fields}
    payload = canonical_bytes(record) + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        if os.write(descriptor, payload) != len(payload):
            raise RuntimeError("short fake trace write")
    finally:
        os.close(descriptor)


def _numerator(trial_id: bytes) -> int:
    return 1_000_000 + int.from_bytes(trial_id[:4], "big") % 100_000


def _bucket_units(trial_id: bytes) -> list[int]:
    numerator = _numerator(trial_id)
    quotient, remainder = divmod(numerator, 10)
    return [quotient + (index < remainder) for index in range(10)]


def _result(
    trial_id: bytes,
    config: dict[str, Any],
    role: str,
    start: int,
    end: int,
    actual_start: int | None = None,
    actual_end: int | None = None,
) -> str:
    actual_start = start if actual_start is None else actual_start
    actual_end = end if actual_end is None else actual_end
    numerator = 1_000_000 + int.from_bytes(trial_id[:4], "big") % 100_000
    bucket_units = _bucket_units(trial_id)
    bins = []
    for total in bucket_units:
        quotient, remainder = divmod(total, 20)
        bins.extend(
            {
                "blocked_events": 0,
                "validated_units": quotient + (index < remainder),
            }
            for index in range(20)
        )
    return canonical_bytes(
        {
            "schema_version": "quicperf.fake-result.v1",
            "trial_id": trial_id.hex(),
            "cell_id": config["cell_id"],
            "role": role,
            "backend": config["server_backend"] if role == "server" else config["reference_client_backend"],
            "scenario": config["scenario"],
            "path_profile": config["path_profile"],
            "global_start_raw_ns": start,
            "global_end_raw_ns": end,
            "actual_start_raw_ns": actual_start,
            "actual_end_raw_ns": actual_end,
            "numerator": numerator,
            "peer_numerator": numerator,
            "per_connection_validated_units": [[0, numerator]],
            "denominator_raw_ns": end - start,
            "termination_reason": "deadline_reached",
            "completed": numerator,
            "failed": 0,
            "duplicate": 0,
            "payload_errors": 0,
            "outstanding": 0,
            "in_flight": 0,
            "measurement_subwindows": bins,
            "work_cap_hits": 0,
            "byte_cap_hits": 0,
            "stream_cap_hits": 0,
            "stream_id_cap_hits": 0,
            "generator_starvation_events": 0,
            "flow_control_blocked_events": 0,
            "stream_credit_blocked_events": 0,
            "flow_control_write_blocked_events": 0,
            "socket_drops": 0,
            "client_cpu_fraction_of_quota_p95": "0.1",
            "effective_config_hash": hashlib.sha256(
                canonical_bytes(
                    {key: value for key, value in config.items() if key not in {"server_address", "server_port"}}
                )
            ).hexdigest(),
            "negotiated_settings_match": True,
            "negotiated": {
                "ack_delay_exponent": 3,
                "ack_frequency": False,
                "active_connection_id_limit": 2,
                "active_migration": False,
                "alpn": "qperf/2",
                "available": True,
                "congestion_controller": "cubic",
                "connection_id_bytes": 8,
                "connection_window_bytes": 67_108_864,
                "datagram_max_frame_size": 1_200,
                "evidence_source": "deterministic_fake_endpoint",
                "hostname_verified": role == "client",
                "initial_congestion_window_bytes": 13_500,
                "matches": True,
                "max_ack_delay_ns": 25_000_000,
                "max_bidi_streams": 256,
                "max_idle_timeout_ns": 30_000_000_000,
                "max_udp_payload_size": 1_350,
                "max_uni_streams": 256,
                "maximum_early_data_bytes": 4_096,
                "mismatch_reason": "",
                "one_use_tickets": True,
                "peer_certificate_verified": role == "client",
                "quic_version": 1,
                "stream_credit_replenish_below": 32,
                "stream_window_bytes": 67_108_864,
                "ticket_lifetime_ns": 300_000_000_000,
                "tls_cipher_suite": "TLS_AES_128_GCM_SHA256",
                "tls_key_exchange": "X25519",
                "tls_leaf_signature": "Ed25519",
                "tls_version": "TLSv1.3",
                "unavailable_fields": [],
            },
        }
    ).decode("utf-8")


def _describe(channel: SeqPacketChannel) -> int:
    _send_hello(channel, "describe")
    packet = channel.receive()
    if packet.message_type is not MessageType.SHUTDOWN:
        return 64
    channel.send(MessageType.SHUTDOWN_ACK, {})
    return 0


def _worker(channel: SeqPacketChannel, role: str, behavior: str) -> int:
    _send_hello(channel, role)
    _trace(role, "worker_start")
    _fault(behavior, "before_ready")
    udp: socket.socket | None = None
    while True:
        packet = channel.receive()
        if packet.message_type is MessageType.SHUTDOWN:
            _trace(role, "shutdown")
            channel.send(MessageType.SHUTDOWN_ACK, {})
            if udp is not None:
                udp.close()
            return 0
        if packet.message_type is not MessageType.CONFIG:
            return 64
        trial_id = packet.fields["trial_id"]
        config = json.loads(packet.fields["config_json"])
        backend = (
            config["server_backend"]
            if role == "server"
            else config["reference_client_backend"]
        )
        _trace(
            role,
            "config",
            backend=backend,
            lane=int(config.get("lane", 0)),
            scenario=config["scenario"],
            trial_id=trial_id.hex(),
        )
        if behavior == "unsupported":
            channel.send(
                MessageType.UNSUPPORTED,
                {"trial_id": trial_id, "reason": "fake_unsupported"},
            )
            return 0
        if behavior == "wrong_identity":
            trial_id = bytes((trial_id[0] ^ 0xFF,)) + trial_id[1:]
        if role == "server":
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
            udp.bind(("127.0.0.1", 0))
            channel.send(
                MessageType.BOUND,
                {"trial_id": trial_id, "udp_port": udp.getsockname()[1]},
            )
        channel.send(
            MessageType.READY,
            {
                "trial_id": trial_id,
                "pid": os.getpid(),
                "backend": backend,
                "raw_now_ns": _raw_ns(),
            },
        )
        while True:
            arm = channel.receive(expected_trial_id=trial_id)
            if arm.message_type is not MessageType.ARM:
                return 64
            if behavior == "late_arm_always" or (
                behavior == "late_arm_once" and _claim_late_arm_fault()
            ):
                delay_ns = int(
                    os.environ.get("QUICPERF_FAKE_LATE_ARM_DELAY_NS", "200000000")
                )
                time.sleep(delay_ns / 1_000_000_000)
            arm_observed_raw_ns = _raw_ns()
            if arm.fields["warmup_start_raw_ns"] > arm_observed_raw_ns:
                break
            _trace(
                role,
                "arm_rejected",
                trial_id=trial_id.hex(),
                raw_now_ns=arm_observed_raw_ns,
            )
            channel.send(
                MessageType.ARM_REJECTED,
                {
                    "trial_id": trial_id,
                    "raw_now_ns": arm_observed_raw_ns,
                    "reason": "arm_window_not_in_future",
                },
            )
        channel.send(
            MessageType.ARMED, {"trial_id": trial_id, "raw_now_ns": _raw_ns()}
        )
        _fault(behavior, "during_measurement")
        start = arm.fields["measurement_start_raw_ns"]
        end = arm.fields["measurement_end_raw_ns"]
        _sleep_until_raw(start)
        actual_start = start
        channel.send(
            MessageType.MEASUREMENT_STARTED,
            {"trial_id": trial_id, "raw_now_ns": actual_start},
        )
        for index, validated_units in enumerate(_bucket_units(trial_id)):
            target = start + (index + 1) * (end - start) // 10
            _sleep_until_raw(target)
            channel.send(
                MessageType.PROGRESS,
                {
                    "trial_id": trial_id,
                    "event_index": index,
                    "raw_now_ns": target,
                    "validated_units": validated_units,
                    "blocked": False,
                },
            )
        actual_end = end
        channel.send(
            MessageType.MEASUREMENT_STOPPED,
            {"trial_id": trial_id, "raw_now_ns": actual_end},
        )
        _fault(behavior, "during_completion")
        channel.send(
            MessageType.COMPLETION_ACK,
            {
                "trial_id": trial_id,
                "counters_json": json.dumps(
                    {
                        "application_bytes_or_operations": _numerator(trial_id),
                        "peer_application_bytes_or_operations": _numerator(trial_id),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            },
        )
        result = _result(
            trial_id,
            config,
            role,
            start,
            end,
            actual_start,
            actual_end,
        )
        if behavior == "corrupt_result":
            result = "{"
        if behavior == "oversize_result":
            channel.sock.send(b"x" * (MAX_PACKET + 1))
        elif behavior != "omit_result":
            channel.send(
                MessageType.RESULT,
                {"trial_id": trial_id, "result_json": result},
            )
            _trace(role, "result", trial_id=trial_id.hex())
            if behavior == "duplicate_result":
                channel.sock.send(
                    encode_packet(
                        MessageType.RESULT,
                        channel.send_sequence,
                        {"trial_id": trial_id, "result_json": result},
                    )
                )
        _fault(behavior, "after_peer_success")
        terminal = channel.receive()
        if terminal.message_type is MessageType.SHUTDOWN:
            _trace(role, "shutdown")
            channel.send(MessageType.SHUTDOWN_ACK, {})
            if udp is not None:
                udp.close()
                udp = None
            return 0
        if terminal.message_type is not MessageType.RESET:
            return 64
        reset_trial_id = terminal.fields["trial_id"]
        _trace(role, "reset", trial_id=reset_trial_id.hex())
        if udp is not None:
            udp.close()
            udp = None
        if behavior == "reset_failure":
            _trace(role, "reset_failure", trial_id=reset_trial_id.hex())
            channel.send(
                MessageType.ERROR,
                {"error_code": 72, "reason": "fake_reset_failure"},
            )
            while True:
                time.sleep(60)
        if reset_trial_id != trial_id:
            return 64
        channel.send(
            MessageType.RESET_ACK,
            {
                "trial_id": reset_trial_id,
                "live_connections": 0,
                "live_streams": 0,
                "live_tickets": 0,
                "work_inventory": 0,
            },
        )
        _trace(role, "reset_ack", trial_id=reset_trial_id.hex())


def main() -> int:
    arguments = _parse()
    behavior = os.environ.get("QUICPERF_FAKE_BEHAVIOR", "normal")
    if behavior.startswith("ignore_sigterm"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if behavior == "fork_descendant":
        if os.fork() == 0:
            while True:
                time.sleep(60)
    if behavior == "flood_logs":
        while True:
            os.write(1, b"fake-log-data\n" * 4096)
    sock = socket.socket(fileno=_control_fd(arguments))
    channel = SeqPacketChannel(sock)
    try:
        if arguments.mode == "describe":
            return _describe(channel)
        if arguments.role is None:
            return 64
        return _worker(channel, arguments.role, behavior)
    finally:
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
