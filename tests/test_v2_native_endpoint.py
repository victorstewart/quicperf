from __future__ import annotations

import socket
import subprocess
import json
import os
import re
import itertools
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path

from quicperf_harness.protocol import MessageType, SeqPacketChannel
from quicperf_harness.paths import ArmedTrace, NamespacePathController
from quicperf_harness.runner import _loss_trace_gate, _receive_result_stream


ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("QUICPERF_BIN_DIR", ROOT / "build" / "bin"))
_MONITOR_COUNTER = itertools.count()
_MONITOR_LOCK = threading.Lock()


def monitored_worker_command(path: Path, arguments: list[str], role: str) -> list[str]:
    monitor = os.environ.get("QUICPERF_RUNTIME_MONITOR_BIN")
    if not monitor:
        return [str(path), *arguments]
    report_root = os.environ.get("QUICPERF_RUNTIME_MONITOR_REPORT_DIR")
    if not report_root:
        raise RuntimeError(
            "QUICPERF_RUNTIME_MONITOR_REPORT_DIR is required with the runtime monitor"
        )
    with _MONITOR_LOCK:
        ordinal = next(_MONITOR_COUNTER)
    report = Path(report_root) / (
        f"{path.name}-{role}-{os.getpid()}-{ordinal:06d}.json"
    )
    return [
        monitor,
        "--report",
        str(report),
        "--",
        str(path),
        *arguments,
    ]


class NativeEndpointContractTests(unittest.TestCase):
    def describe(self, binary: str, expected_library: str) -> None:
        path = BIN / binary
        if not path.is_file():
            self.skipTest(f"{path} is not built")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        try:
            process = subprocess.Popen(
                [str(path), "describe", f"--control-fd={child.fileno()}"],
                pass_fds=(child.fileno(),),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            child.close()
            channel = SeqPacketChannel(parent)
            hello = channel.receive()
            capabilities = channel.receive()
            self.assertEqual(hello.message_type, MessageType.HELLO)
            self.assertEqual(hello.fields["role"], "describe")
            notes = subprocess.run(
                ["readelf", "-n", str(path)], check=True, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).stdout
            expected_build_id = re.search(r"Build ID:\s*([0-9a-fA-F]+)", notes)
            self.assertIsNotNone(expected_build_id)
            self.assertEqual(hello.fields["build_id"].hex(), expected_build_id.group(1).lower())
            self.assertEqual(capabilities.message_type, MessageType.CAPABILITIES)
            self.assertEqual(capabilities.fields["build_id"], hello.fields["build_id"])
            self.assertEqual(capabilities.fields["library"], expected_library)
            self.assertEqual(capabilities.fields["protocol_version"], 1)
            channel.send(MessageType.SHUTDOWN, {})
            self.assertEqual(channel.receive().message_type, MessageType.SHUTDOWN_ACK)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual((process.returncode, stdout, stderr), (0, "", ""))
        finally:
            parent.close()
            child.close()

    def test_rust_packet_endpoint(self) -> None:
        self.describe("quinnperf", "quinn")

    def test_zig_packet_endpoint(self) -> None:
        self.describe("quiczigperf", "quic_zig")

    def test_neqo_packet_endpoint(self) -> None:
        self.describe("neqoperf", "neqo")

    def test_every_named_endpoint_describes_itself(self) -> None:
        endpoints = {
            "ngtcp2perf": "ngtcp2",
            "lsperf": "lsquic",
            "tquicperf": "tquic",
            "quicheperf": "quiche",
            "picoperf": "picoquic",
            "xquicperf": "xquic",
            "quinnperf": "quinn",
            "s2nperf": "s2n_quic",
            "neqoperf": "neqo",
            "noqperf": "noq",
            "quiczigperf": "quic_zig",
            "mvfstperf": "mvfst",
            "tcpperf": "tcp_tls",
        }
        for binary, library in endpoints.items():
            with self.subTest(binary=binary):
                self.describe(binary, library)

    def _run_ngtcp2_workload(
        self,
        workload: dict[str, int | str],
        *,
        binary: str = "ngtcp2perf",
        server_binary: str | None = None,
        client_binary: str | None = None,
        client_workers: int = 2,
        reset: bool = False,
        exercise: bool = False,
        post_result_drain_s: float = 0.0,
        server_backend: str | None = None,
        client_backend: str | None = None,
        server_require_multishot_receive: bool = False,
        client_require_multishot_receive: bool = False,
        max_endpoint_rss_bytes: int | None = None,
        reject_stale_arm: bool = False,
    ) -> tuple[dict[str, object], dict[str, object]]:
        role_paths = {
            "server": BIN / (server_binary or binary),
            "client": BIN / (client_binary or binary),
        }
        for path in role_paths.values():
            if not path.is_file():
                self.skipTest(f"{path} is not built")
        allowed_cpus = tuple(sorted(os.sched_getaffinity(0)))
        if len(allowed_cpus) < client_workers + 1:
            self.skipTest(
                "native endpoint topology needs one server CPU and "
                f"{client_workers} client CPUs"
            )
        role_cpus = {
            "server": (allowed_cpus[0],),
            "client": allowed_cpus[1 : client_workers + 1],
        }
        namespace_path = (
            NamespacePathController(0, "native-endpoint-contract")
            if workload.get("path_profile") == "loss_recovery_v1"
            else None
        )

        processes: list[subprocess.Popen[str]] = []
        sockets: list[socket.socket] = []
        memory_stop = threading.Event()
        memory_thread: threading.Thread | None = None
        peak_rss: dict[int, int] = {}

        def sample_memory() -> None:
            page_size = os.sysconf("SC_PAGE_SIZE")
            while not memory_stop.wait(0.005):
                for process in processes:
                    try:
                        resident_pages = int(
                            Path(f"/proc/{process.pid}/statm").read_text().split()[1]
                        )
                    except (FileNotFoundError, IndexError, ValueError):
                        continue
                    peak_rss[process.pid] = max(
                        peak_rss.get(process.pid, 0), resident_pages * page_size
                    )

        def attest_memory() -> dict[int, int]:
            nonlocal memory_thread
            if memory_thread is None:
                return {}
            memory_stop.set()
            memory_thread.join()
            memory_thread = None
            assert max_endpoint_rss_bytes is not None
            self.assertTrue(peak_rss, "endpoint RSS sampler produced no observations")
            self.assertLessEqual(
                max(peak_rss.values()),
                max_endpoint_rss_bytes,
                peak_rss,
            )
            return dict(peak_rss)

        def launch(role: str) -> tuple[subprocess.Popen[str], socket.socket, SeqPacketChannel]:
            parent, child = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
            )
            def prepare_child() -> None:
                if namespace_path is not None:
                    namespace = namespace_path.network_namespace(role)
                    assert namespace is not None
                    descriptor = os.open(namespace, os.O_RDONLY | os.O_CLOEXEC)
                    try:
                        os.setns(descriptor, os.CLONE_NEWNET)
                    finally:
                        os.close(descriptor)
                os.sched_setaffinity(0, role_cpus[role])

            process = subprocess.Popen(
                monitored_worker_command(
                    role_paths[role],
                    ["worker", f"--role={role}", f"--control-fd={child.fileno()}"],
                    role,
                ),
                pass_fds=(child.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
                preexec_fn=prepare_child,
            )
            child.close()
            channel = SeqPacketChannel(parent)
            self.assertEqual(channel.receive().message_type, MessageType.HELLO)
            self.assertEqual(channel.receive().message_type, MessageType.CAPABILITIES)
            processes.append(process)
            sockets.append(parent)
            return process, parent, channel

        def config(role: str, peer_port: int) -> dict[str, object]:
            if namespace_path is None:
                bind_address = "127.0.0.1"
                peer_address = "0.0.0.0" if role == "server" else "127.0.0.1"
            else:
                bind_address, peer_address = namespace_path.endpoint_addresses(role)
            value: dict[str, object] = {
                "ack_delay_exponent": 3,
                "ack_frequency": False,
                "active_connection_id_limit": 2,
                "active_migration": False,
                "alpn": "qperf/2",
                "backend": (
                    server_backend if role == "server" else client_backend
                ) or str(workload.get("backend", "syscall")),
                "bind_address": bind_address,
                "bind_port": 0,
                "busy_polling": False,
                "calendar_unix_seconds": 1784376000,
                "certificate_path": str(ROOT / "tls/server.cert.pem"),
                "chain_path": str(ROOT / "tls/chain.cert.pem"),
                "common_pacing": True,
                "congestion_controller": "cubic",
                "connection_id_bytes": 8,
                "connection_window": 262144,
                "datagram_max_frame_size": 1200,
                "ecn": False,
                "event_loop_workers": 1 if role == "server" else client_workers,
                "idle_timeout_ms": 30000,
                "initial_congestion_window_bytes": 13500,
                "max_ack_delay_ns": 25000000,
                "max_bidi_streams": 64,
                "max_udp_payload_size": 1350,
                "max_uni_streams": 64,
                "path_profile": str(workload.get("path_profile", "loopback")),
                "peer_address": peer_address,
                "peer_port": peer_port,
                "pmtud": False,
                "private_key_path": str(ROOT / "tls/server.key.pem"),
                "quic_version": "0x00000001",
                "receive_timestamps": False,
                "require_multishot_receive": (
                    server_require_multishot_receive
                    if role == "server"
                    else client_require_multishot_receive
                ),
                "role": role,
                "schema_version": 2,
                "stream_credit_replenish_below": 32,
                "stream_window": 65536,
                "tls_cipher_suite": "TLS_AES_128_GCM_SHA256",
                "tls_hostname": "server.quicperf.test",
                "tls_key_exchange": "X25519",
                "tls_leaf_signature": "Ed25519",
                "tls_maximum_early_data_bytes": 4096,
                "tls_one_use_tickets": True,
                "tls_ticket_lifetime_ns": 300_000_000_000,
                "tls_verify_peer": role == "client",
                "tls_version": "TLSv1.3",
                "trace_seed": str(workload.get("trace_seed", "0" * 64)),
                "udp_gro": True,
                "udp_gso": True,
            }
            value.update(workload)
            return value

        trial_id = b"T" * 32
        cell_id = b"C" * 32
        try:
            if namespace_path is not None:
                namespace_path.create_session()
                namespace_path.prepare_trial("loss_recovery_v1")
            server, _, server_channel = launch("server")
            client, _, client_channel = launch("client")
            if max_endpoint_rss_bytes is not None:
                memory_thread = threading.Thread(
                    target=sample_memory,
                    name="quicperf-endpoint-rss",
                    daemon=True,
                )
                memory_thread.start()
            server_config = config("server", 0)
            server_channel.send(MessageType.CONFIG, {
                "trial_id": trial_id, "cell_id": cell_id,
                "config_json": json.dumps(server_config, sort_keys=True, separators=(",", ":")),
            })
            bound = server_channel.receive(expected_trial_id=trial_id)
            self.assertEqual(bound.message_type, MessageType.BOUND, bound.fields)
            self.assertEqual(
                server_channel.receive(expected_trial_id=trial_id).message_type,
                MessageType.READY,
            )
            client_config = config("client", int(bound.fields["udp_port"]))
            client_channel.send(MessageType.CONFIG, {
                "trial_id": trial_id, "cell_id": cell_id,
                "config_json": json.dumps(client_config, sort_keys=True, separators=(",", ":")),
            })
            self.assertEqual(
                client_channel.receive(expected_trial_id=trial_id).message_type,
                MessageType.READY,
            )
            if exercise:
                deadline = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) + 2_000_000_000
                exercise_fields = {
                    "trial_id": trial_id,
                    "exercise_deadline_raw_ns": deadline,
                }
                server_channel.send(MessageType.EXERCISE, exercise_fields)
                client_channel.send(MessageType.EXERCISE, exercise_fields)
                server_exercised = server_channel.receive(expected_trial_id=trial_id)
                client_exercised = client_channel.receive(expected_trial_id=trial_id)
                self.assertEqual(server_exercised.message_type, MessageType.EXERCISED)
                self.assertEqual(client_exercised.message_type, MessageType.EXERCISED)
                for packet in (server_exercised, client_exercised):
                    self.assertGreater(packet.fields["live_connections"], 0)
                    self.assertGreater(packet.fields["work_inventory"], 0)
                server_channel.send(MessageType.RESET, {"trial_id": trial_id})
                client_channel.send(MessageType.RESET, {"trial_id": trial_id})
                reset_packets = (
                    server_channel.receive(expected_trial_id=trial_id),
                    client_channel.receive(expected_trial_id=trial_id),
                )
                for packet in reset_packets:
                    self.assertEqual(packet.message_type, MessageType.RESET_ACK)
                    self.assertEqual(
                        tuple(packet.fields[field] for field in (
                            "live_connections", "live_streams", "live_tickets", "work_inventory"
                        )),
                        (0, 0, 0, 0),
                    )
                server_channel.send(MessageType.SHUTDOWN, {})
                client_channel.send(MessageType.SHUTDOWN, {})
                self.assertEqual(server_channel.receive().message_type, MessageType.SHUTDOWN_ACK)
                self.assertEqual(client_channel.receive().message_type, MessageType.SHUTDOWN_ACK)
                self.assertEqual(server.communicate(timeout=5), ("", ""))
                self.assertEqual(client.communicate(timeout=5), ("", ""))
                self.assertEqual((server.returncode, client.returncode), (0, 0))
                attest_memory()
                return server_exercised.fields, client_exercised.fields
            if reject_stale_arm:
                stale_warmup_start = (
                    time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) - 1
                )
                stale_measurement_start = (
                    stale_warmup_start
                    + int(workload["warmup_duration_ns"])
                )
                stale_arm = {
                    "trial_id": trial_id,
                    "warmup_start_raw_ns": stale_warmup_start,
                    "measurement_start_raw_ns": stale_measurement_start,
                    "measurement_end_raw_ns": (
                        stale_measurement_start
                        + int(workload["measurement_duration_ns"])
                    ),
                    "trace_epoch_raw_ns": stale_measurement_start,
                }
                server_channel.send(MessageType.ARM, stale_arm)
                client_channel.send(MessageType.ARM, stale_arm)
                for process, packet in (
                    (
                        server,
                        server_channel.receive(expected_trial_id=trial_id),
                    ),
                    (
                        client,
                        client_channel.receive(expected_trial_id=trial_id),
                    ),
                ):
                    self.assertEqual(
                        packet.message_type, MessageType.ARM_REJECTED
                    )
                    self.assertEqual(
                        packet.fields["reason"], "arm_window_not_in_future"
                    )
                    self.assertIsNone(process.poll())
            now = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            warmup_start = now + 200_000_000
            measurement_ns = int(workload["measurement_duration_ns"])
            measurement_start = warmup_start + int(workload["warmup_duration_ns"])
            measurement_end = measurement_start + measurement_ns
            arm = {
                "trial_id": trial_id,
                "warmup_start_raw_ns": warmup_start,
                "measurement_start_raw_ns": measurement_start,
                "measurement_end_raw_ns": measurement_end,
                "trace_epoch_raw_ns": measurement_start,
            }
            if namespace_path is not None:
                namespace_path.arm(
                    ArmedTrace(
                        measurement_start,
                        bytes.fromhex(str(workload["trace_seed"])),
                        (),
                    )
                )
            server_channel.send(MessageType.ARM, arm)
            client_channel.send(MessageType.ARM, arm)
            self.assertEqual(
                server_channel.receive(expected_trial_id=trial_id).message_type,
                MessageType.ARMED,
            )
            self.assertEqual(
                client_channel.receive(expected_trial_id=trial_id).message_type,
                MessageType.ARMED,
            )
            with ThreadPoolExecutor(max_workers=2) as executor:
                server_future = executor.submit(
                    _receive_result_stream,
                    server_channel,
                    source="server",
                    trial_id=trial_id,
                    start_timeout_ns=max(
                        2_000_000_000,
                        measurement_start
                        - time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                        + 2_000_000_000,
                    ),
                    measurement_ns=measurement_ns,
                    completion_bound_ns=30_000_000_000,
                )
                client_future = executor.submit(
                    _receive_result_stream,
                    client_channel,
                    source="client",
                    trial_id=trial_id,
                    start_timeout_ns=max(
                        2_000_000_000,
                        measurement_start
                        - time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                        + 2_000_000_000,
                    ),
                    measurement_ns=measurement_ns,
                    completion_bound_ns=30_000_000_000,
                )
                wait((server_future, client_future))
                client_result, _ = client_future.result()
                server_result, _ = server_future.result()
            if post_result_drain_s:
                time.sleep(post_result_drain_s)
            if reset:
                expected_inventory = {
                    "trial_id": trial_id,
                    "live_connections": 0,
                    "live_streams": 0,
                    "live_tickets": 0,
                    "work_inventory": 0,
                }
                server_channel.send(MessageType.RESET, {"trial_id": trial_id})
                client_channel.send(MessageType.RESET, {"trial_id": trial_id})
                server_reset = server_channel.receive(expected_trial_id=trial_id)
                client_reset = client_channel.receive(expected_trial_id=trial_id)
                self.assertEqual(server_reset.message_type, MessageType.RESET_ACK)
                self.assertEqual(client_reset.message_type, MessageType.RESET_ACK)
                self.assertEqual(server_reset.fields, expected_inventory)
                self.assertEqual(client_reset.fields, expected_inventory)
            server_channel.send(MessageType.SHUTDOWN, {})
            client_channel.send(MessageType.SHUTDOWN, {})
            self.assertEqual(server_channel.receive().message_type, MessageType.SHUTDOWN_ACK)
            self.assertEqual(client_channel.receive().message_type, MessageType.SHUTDOWN_ACK)
            self.assertEqual(server.communicate(timeout=5), ("", ""))
            self.assertEqual(client.communicate(timeout=5), ("", ""))
            self.assertEqual((server.returncode, client.returncode), (0, 0))
            observed_rss = attest_memory()
            if observed_rss:
                server_result["test_peak_rss_bytes"] = observed_rss[server.pid]
                client_result["test_peak_rss_bytes"] = observed_rss[client.pid]
            if namespace_path is not None:
                path_evidence = namespace_path.finish_trial()
                server_result["test_path_evidence"] = path_evidence
                client_result["test_path_evidence"] = path_evidence
            return server_result, client_result
        except BaseException as exc:
            diagnostics = []
            for process in processes:
                if process.poll() is None:
                    try:
                        stdout, stderr = process.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        stdout, stderr = process.communicate(timeout=5)
                else:
                    stdout, stderr = process.communicate(timeout=5)
                diagnostics.append((process.args, process.returncode, stdout, stderr))
            raise AssertionError({"cause": repr(exc), "processes": diagnostics}) from exc
        finally:
            memory_stop.set()
            if memory_thread is not None:
                memory_thread.join()
            for endpoint_socket in sockets:
                endpoint_socket.close()
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            if namespace_path is not None:
                namespace_path.cleanup()

    def test_native_workers_reject_late_arm_without_closing_channels(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload(
            {
                "active_streams_per_connection": 1,
                "bulk_chunk_bytes": 0,
                "connection_count": 2,
                "datagram_body_bytes": 0,
                "datagram_max_unreturned_per_connection": 0,
                "global_operation_slots": 0,
                "measurement_duration_ns": 100_000_000,
                "operation_body_bytes": 64,
                "progress_interval_ns": 10_000_000,
                "request_body_bytes": 0,
                "response_body_bytes": 0,
                "scenario": "small_payload_pps",
                "ticket_slots": 0,
                "warmup_duration_ns": 50_000_000,
            },
            reject_stale_arm=True,
        )
        self.assertGreater(server_result["numerator"], 0)
        self.assertGreater(client_result["tail"]["started_operations"], 0)

    def test_ngtcp2_small_payload_serializes_bounded_tail_evidence(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 2,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 100_000_000,
            "operation_body_bytes": 64,
            "progress_interval_ns": 10_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "small_payload_pps",
            "ticket_slots": 0,
            "warmup_duration_ns": 50_000_000,
        })
        self.assertEqual(server_result["tail_observation_ownership"], "receiver_terminals")
        self.assertEqual(client_result["tail_observation_ownership"], "sender_starts")
        self.assertEqual(len(server_result["measurement_subwindows"]), 200)
        self.assertEqual(
            sum(row["validated_units"] for row in server_result["measurement_subwindows"]),
            server_result["numerator"],
        )
        for result in (server_result, client_result):
            cpu_p95 = float(result["client_cpu_fraction_of_quota_p95"])
            self.assertGreaterEqual(cpu_p95, 0.0)
            self.assertLessEqual(cpu_p95, 1.0)
            for index, progress in enumerate(result["progress"]):
                private = result["measurement_subwindows"][
                    index * 20 : (index + 1) * 20
                ]
                self.assertEqual(
                    progress["validated_units"],
                    sum(row["validated_units"] for row in private),
                )
                self.assertEqual(
                    progress["blocked"],
                    any(row["blocked_events"] for row in private),
                )
        tail = server_result["tail"]
        self.assertEqual(tail["histogram_resolution_ns"], 1)
        self.assertGreater(tail["started_operations"], 0)
        self.assertLessEqual(len(tail["operations"]), 1024)
        self.assertLessEqual(len(tail["operations"]), tail["started_operations"])
        self.assertLessEqual(
            tail["started_operations"], client_result["tail"]["started_operations"]
        )
        self.assertEqual(
            [prefix["duration_seconds"] for prefix in tail["prefixes"]],
            [2, 5, 10, 20],
        )
        self.assertTrue(
            all(
                prefix["started_operations"]
                == prefix["successful_operations"]
                + prefix["failed_operations"]
                + prefix["censored_operations"]
                for prefix in tail["prefixes"]
            )
        )
        self.assertTrue(
            all(
                terminal["started_operations"] <= start["started_operations"]
                for terminal, start in zip(
                    tail["prefixes"],
                    client_result["tail"]["prefixes"],
                    strict=True,
                )
            )
        )
        keys = []
        for operation in tail["operations"]:
            self.assertEqual(
                operation["latency_ns"],
                operation["terminal_raw_ns"] - operation["start_raw_ns"],
            )
            keys.append((operation["start_raw_ns"], operation["operation_sequence"]))
        self.assertEqual(keys, sorted(keys))

    def test_ngtcp2_continuous_bulk_stops_and_completes(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "download",
            "ticket_slots": 0,
            "warmup_duration_ns": 200_000_000,
        })
        client_progress = [int(event["validated_units"]) for event in client_result["progress"]]
        self.assertEqual(len(client_progress), 10)
        self.assertGreaterEqual(
            sum(value > 0 for value in client_progress), 5,
            f"download did not remain active across the measurement: {client_progress}",
        )
        self.assertGreater(int(client_result["numerator"]), 1_048_576)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        for result in (server_result, client_result):
            self.assertTrue(result["negotiated_settings_match"])
            self.assertEqual(result["negotiated"]["unavailable_fields"], [])

    def test_cross_stream_stop_barrier_reconciles_exact_failed_pair(self) -> None:
        workload = {
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": 262_144,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 10_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 1_000_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "flow_control",
            "stream_window": 65_536,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }
        for repetition in range(3):
            with self.subTest(repetition=repetition):
                server_result, client_result = self._run_ngtcp2_workload(
                    workload,
                    server_binary="quicheperf",
                    client_binary="ngtcp2perf",
                    server_backend="syscall",
                    client_backend="iouring",
                )
                self.assertEqual(
                    server_result["termination_reason"], "deadline_reached"
                )
                self.assertEqual(
                    client_result["termination_reason"], "deadline_reached"
                )
                self.assertGreater(client_result["numerator"], 0)
                self.assertEqual(
                    server_result["numerator"], client_result["numerator"]
                )
                self.assertGreater(
                    sum(
                        int(result["flow_control_blocked_events"])
                        + int(result["stream_credit_blocked_events"])
                        + int(result["flow_control_write_blocked_events"])
                        for result in (server_result, client_result)
                    ),
                    0,
                )
                self.assertTrue(
                    any(
                        result["flow_control_recovery_evidence"]
                        for result in (server_result, client_result)
                    )
                )
                for result in (server_result, client_result):
                    self.assertEqual(
                        (
                            result["failed"],
                            result["outstanding"],
                            result["in_flight"],
                        ),
                        (0, 0, 0),
                    )

    def test_picoquic_upload_to_quiche_preserves_frozen_credit(self) -> None:
        workload = {
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 10_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 1_000_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "upload",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }
        for repetition in range(3):
            with self.subTest(repetition=repetition):
                server_result, client_result = self._run_ngtcp2_workload(
                    workload,
                    server_binary="quicheperf",
                    client_binary="picoperf",
                    server_backend="iouring",
                    client_backend="iouring",
                )
                self.assertGreater(server_result["numerator"], 0)
                self.assertEqual(
                    server_result["numerator"], client_result["peer_numerator"]
                )
                self.assertEqual(client_result["numerator"], 0)
                server_connections = server_result[
                    "per_connection_validated_units"
                ]
                self.assertEqual(len(server_connections), 16)
                self.assertEqual(
                    sum(units for _ordinal, units in server_connections),
                    server_result["numerator"],
                )
                for result in (server_result, client_result):
                    self.assertEqual(
                        (
                            result["flow_control_blocked_events"],
                            result["stream_credit_blocked_events"],
                            result["flow_control_write_blocked_events"],
                        ),
                        (0, 0, 0),
                        result,
                    )
                    self.assertEqual(
                        (
                            result["failed"],
                            result["outstanding"],
                            result["in_flight"],
                        ),
                        (0, 0, 0),
                    )

    def test_two_client_workers_accept_one_connection_capacity_point(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload(
            {
                "active_streams_per_connection": 1,
                "bulk_chunk_bytes": 262_144,
                "connection_count": 1,
                "connection_window": 67_108_864,
                "datagram_body_bytes": 0,
                "datagram_max_unreturned_per_connection": 0,
                "global_operation_slots": 0,
                "measurement_duration_ns": 500_000_000,
                "operation_body_bytes": 0,
                "progress_interval_ns": 50_000_000,
                "request_body_bytes": 0,
                "response_body_bytes": 0,
                "scenario": "bidi",
                "stream_window": 67_108_864,
                "ticket_slots": 0,
                "warmup_duration_ns": 250_000_000,
            },
            client_workers=2,
        )
        self.assertGreater(server_result["numerator"], 0)
        self.assertGreater(client_result["numerator"], 0)
        self.assertEqual(
            server_result["numerator"], client_result["peer_numerator"]
        )
        self.assertEqual(
            client_result["numerator"], server_result["peer_numerator"]
        )
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(
                (result["failed"], result["outstanding"], result["in_flight"]),
                (0, 0, 0),
            )

    def test_iouring_multishot_gro_preserves_stream_churn_progress(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "backend": "iouring",
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "max_bidi_streams": 256,
            "max_uni_streams": 256,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 1,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 0,
            "require_multishot_receive": True,
            "response_body_bytes": 0,
            "scenario": "stream_churn",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        })
        progress = [
            int(event["validated_units"])
            for event in client_result["progress"]
        ]
        self.assertTrue(all(value > 0 for value in progress), progress)
        self.assertGreater(client_result["numerator"], 400)
        self.assertEqual(server_result["numerator"], client_result["numerator"])

    def test_ngtcp2_loss_recovery_uses_exact_common_packet_filter(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "path_profile": "loss_recovery_v1",
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "loss_recovery",
            "ticket_slots": 0,
            "trace_seed": "0a" * 32,
            "warmup_duration_ns": 250_000_000,
        })
        for direction, result in enumerate((server_result, client_result)):
            self.assertEqual(result["loss_direction"], direction)
            self.assertEqual(
                result["loss_packets_considered"],
                result["loss_warmup_packets_considered"]
                + result["loss_measurement_packets_considered"],
            )
            self.assertEqual(
                result["loss_packets_dropped"],
                result["loss_warmup_packets_dropped"]
                + result["loss_measurement_packets_dropped"],
            )
            self.assertGreater(result["loss_measurement_packets_considered"], 0)
            self.assertGreater(result["loss_measurement_packets_dropped"], 0)
        self.assertGreater(
            server_result["transport_packets_lost"]
            + client_result["transport_packets_lost"],
            0,
        )
        path_evidence = server_result.pop("test_path_evidence")
        self.assertEqual(client_result.pop("test_path_evidence"), path_evidence)
        self.assertTrue(
            _loss_trace_gate(
                {
                    "scenario": "loss_recovery",
                    "path_profile": "loss_recovery_v1",
                    "trace_seed": "0a" * 32,
                },
                server_result,
                client_result,
                path_evidence,
            )
        )
        self.assertGreater(
            server_result["transport_timer_expirations"]
            + client_result["transport_timer_expirations"],
            0,
        )

    def test_tquic_loss_recovery_preserves_the_earliest_relative_timeout(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 5_000_000_000,
            "operation_body_bytes": 0,
            "path_profile": "loss_recovery_v1",
            "progress_interval_ns": 500_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "loss_recovery",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "trace_seed": "0a" * 32,
            "warmup_duration_ns": 500_000_000,
        }, server_binary="tquicperf", client_binary="picoperf",
           server_backend="iouring", client_backend="iouring")
        self.assertGreater(server_result["transport_timer_expirations"], 0)
        self.assertGreater(server_result["transport_packets_lost"], 0)
        self.assertGreater(server_result["numerator"], 0)
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(
                (result["failed"], result["outstanding"], result["in_flight"]),
                (0, 0, 0),
            )
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
        path_evidence = server_result.pop("test_path_evidence")
        self.assertEqual(client_result.pop("test_path_evidence"), path_evidence)
        self.assertTrue(
            _loss_trace_gate(
                {
                    "scenario": "loss_recovery",
                    "path_profile": "loss_recovery_v1",
                    "trace_seed": "0a" * 32,
                },
                server_result,
                client_result,
                path_evidence,
            )
        )

    def test_s2n_loss_recovery_exports_transport_evidence(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 5_000_000_000,
            "operation_body_bytes": 0,
            "path_profile": "loss_recovery_v1",
            "progress_interval_ns": 500_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "loss_recovery",
            "ticket_slots": 0,
            "trace_seed": "0b" * 32,
            "warmup_duration_ns": 500_000_000,
        }, server_binary="s2nperf")
        self.assertGreater(
            server_result["transport_packets_lost"],
            0,
        )
        self.assertGreater(
            server_result["transport_recovery_wakeups"]
            + client_result["transport_recovery_wakeups"],
            0,
        )
        path_evidence = server_result.pop("test_path_evidence")
        self.assertEqual(client_result.pop("test_path_evidence"), path_evidence)
        self.assertTrue(
            _loss_trace_gate(
                {
                    "scenario": "loss_recovery",
                    "path_profile": "loss_recovery_v1",
                    "trace_seed": "0b" * 32,
                },
                server_result,
                client_result,
                path_evidence,
            )
        )

    def test_s2n_flow_control_exports_block_and_recovery_evidence(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "flow_control",
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, binary="s2nperf")
        self.assertGreater(
            server_result["flow_control_blocked_events"]
            + server_result["stream_credit_blocked_events"],
            0,
        )
        self.assertTrue(
            server_result["flow_control_recovery_evidence"]
        )

    def test_tquic_flow_control_exports_block_and_recovery_evidence(self) -> None:
        server_result, _ = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "flow_control",
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="tquicperf", client_binary="ngtcp2perf",
           server_backend="iouring", client_backend="iouring")
        self.assertGreater(
            server_result["flow_control_blocked_events"]
            + server_result["stream_credit_blocked_events"],
            0,
        )
        self.assertTrue(server_result["flow_control_recovery_evidence"])

    def test_picoquic_flow_control_exports_block_and_recovery_evidence(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "backend": backend,
                    "bulk_chunk_bytes": 262_144,
                    "connection_count": 16,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 0,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 8,
                    "response_body_bytes": 0,
                    "scenario": "flow_control",
                    "ticket_slots": 0,
                    "warmup_duration_ns": 500_000_000,
                }, binary="picoperf")
                self.assertGreater(
                    server_result["flow_control_blocked_events"]
                    + server_result["stream_credit_blocked_events"]
                    + server_result["flow_control_write_blocked_events"]
                    + client_result["flow_control_blocked_events"]
                    + client_result["stream_credit_blocked_events"]
                    + client_result["flow_control_write_blocked_events"],
                    0,
                )
                self.assertTrue(
                    server_result["flow_control_recovery_evidence"]
                    or client_result["flow_control_recovery_evidence"]
                )

    def test_picoquic_flow_control_credit_recovers_with_strict_peers(self) -> None:
        peers = (
            ("ngtcp2perf", "syscall", "iouring", True),
            ("quinnperf", "iouring", "iouring", True),
            ("xquicperf", "syscall", "iouring", False),
        )
        for server_binary, server_backend, client_backend, exact_block_counters in peers:
            with self.subTest(server_binary=server_binary):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "bulk_chunk_bytes": 262_144,
                    "connection_count": 16,
                    "connection_window": 262_144,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 0,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 8,
                    "response_body_bytes": 0,
                    "scenario": "flow_control",
                    "stream_window": 65_536,
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, server_binary=server_binary, client_binary="picoperf",
                   server_backend=server_backend, client_backend=client_backend)
                self.assertGreater(client_result["numerator"], 0)
                self.assertEqual(server_result["numerator"], client_result["numerator"])
                if exact_block_counters:
                    self.assertGreater(
                        server_result["flow_control_blocked_events"]
                        + server_result["stream_credit_blocked_events"],
                        0,
                    )
                    self.assertTrue(server_result["flow_control_recovery_evidence"])
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(result["outstanding"], 0)
                    self.assertEqual(result["in_flight"], 0)
                    self.assertTrue(
                        result["negotiated_settings_match"], result["negotiated"]
                    )

    def test_common_flow_control_backpressure_covers_nonreporting_transports(self) -> None:
        for binary in ("lsperf", "mvfstperf", "noqperf", "xquicperf"):
            for backend in ("syscall", "iouring"):
                with self.subTest(binary=binary, backend=backend):
                    server_result, client_result = self._run_ngtcp2_workload({
                        "active_streams_per_connection": 1,
                        "bulk_chunk_bytes": 262_144,
                        "connection_count": 16,
                        "connection_window": 262_144,
                        "datagram_body_bytes": 0,
                        "datagram_max_unreturned_per_connection": 0,
                        "global_operation_slots": 0,
                        "measurement_duration_ns": 500_000_000,
                        "operation_body_bytes": 0,
                        "progress_interval_ns": 50_000_000,
                        "request_body_bytes": 8,
                        "response_body_bytes": 0,
                        "scenario": "flow_control",
                        "stream_window": 65_536,
                        "ticket_slots": 0,
                        "warmup_duration_ns": 500_000_000,
                    }, server_binary=binary, client_binary="ngtcp2perf",
                       server_backend=backend, client_backend="iouring",
                       client_require_multishot_receive=True)
                    self.assertGreater(
                        sum(
                            int(result["flow_control_blocked_events"])
                            + int(result["stream_credit_blocked_events"])
                            + int(result["flow_control_write_blocked_events"])
                            for result in (server_result, client_result)
                        ),
                        0,
                    )
                    self.assertTrue(any(
                        result["flow_control_recovery_evidence"]
                        for result in (server_result, client_result)
                    ))

    def test_ngtcp2_server_replenishes_picoquic_request_stream_credit(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 1_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 100_000_000,
            "request_body_bytes": 64,
            "response_body_bytes": 1_024,
            "scenario": "reqresp",
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="ngtcp2perf", client_binary="picoperf",
           server_backend="syscall", client_backend="iouring")
        self.assertGreater(client_result["numerator"], 16 * 64)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        self.assertEqual(client_result["stream_credit_blocked_events"], 0)
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(result["outstanding"], 0)
            self.assertEqual(result["in_flight"], 0)
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])

    def test_ngtcp2_reference_client_recovers_after_fast_s2n_blocks(self) -> None:
        window = 4 * 1024 * 1024
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": window,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "download",
            "stream_window": window,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="s2nperf", client_binary="ngtcp2perf",
           server_backend="syscall", client_backend="iouring")
        self.assertGreater(server_result["numerator"], 16 * window)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        self.assertGreater(
            sum(
                result["flow_control_blocked_events"]
                + result["stream_credit_blocked_events"]
                + result["flow_control_write_blocked_events"]
                for result in (server_result, client_result)
            ),
            0,
        )
        self.assertTrue(
            any(
                result["flow_control_recovery_evidence"]
                for result in (server_result, client_result)
            )
        )
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")

    def test_ngtcp2_stream_limit_wait_is_not_flow_control_frame_evidence(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "max_bidi_streams": 256,
            "max_uni_streams": 256,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 64,
            "response_body_bytes": 1_024,
            "scenario": "zero_rtt_reqresp",
            "stream_window": 67_108_864,
            "ticket_slots": 16,
            "warmup_duration_ns": 0,
        }, server_binary="noqperf", client_binary="ngtcp2perf",
           server_backend="iouring", client_backend="syscall")
        for result in (server_result, client_result):
            self.assertEqual(result["flow_control_blocked_events"], 0)
            self.assertEqual(result["stream_credit_blocked_events"], 0)
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(result["outstanding"], 0)
            self.assertEqual(result["in_flight"], 0)
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])

    def test_picoquic_publication_window_multistream_drains_pending_frames(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 8,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "multistream_upload",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, binary="picoperf")
        self.assertGreater(int(server_result["numerator"]), 0)
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(result["in_flight"], 0)
            self.assertEqual(result["outstanding"], 0)
            self.assertTrue(result["negotiated_settings_match"])
            self.assertEqual(result["negotiated"]["unavailable_fields"], [])

    def test_ngtcp2_multistream_scheduler_drains_against_s2n(self) -> None:
        for server_backend in ("syscall", "iouring"):
            with self.subTest(server_backend=server_backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 8,
                    "bulk_chunk_bytes": 262_144,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 0,
                    "measurement_duration_ns": 2_000_000_000,
                    "operation_body_bytes": 0,
                    "path_profile": "loopback",
                    "progress_interval_ns": 100_000_000,
                    "request_body_bytes": 8,
                    "response_body_bytes": 0,
                    "scenario": "multistream_upload",
                    "stream_window": 67_108_864,
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, server_binary="s2nperf", client_binary="ngtcp2perf",
                   server_backend=server_backend, client_backend="iouring")
                self.assertGreater(int(server_result["numerator"]), 0)
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(result["in_flight"], 0)
                    self.assertEqual(result["outstanding"], 0)
                    self.assertTrue(result["negotiated_settings_match"])
                    self.assertEqual(result["negotiated"]["unavailable_fields"], [])

    def test_s2n_publication_upload_keeps_progressing(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "max_bidi_streams": 256,
            "max_uni_streams": 256,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "path_profile": "loopback",
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "upload",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="s2nperf", client_binary="ngtcp2perf",
           server_backend="syscall", client_backend="iouring",
           client_require_multishot_receive=True)
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual((result["failed"], result["outstanding"],
                              result["in_flight"]), (0, 0, 0))
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
        self.assertTrue(all(
            event["validated_units"] > 0 for event in server_result["progress"]
        ), server_result["progress"])

    def test_quiczig_loss_recovery_exports_transport_evidence(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 5_000_000_000,
            "operation_body_bytes": 0,
            "path_profile": "loss_recovery_v1",
            "progress_interval_ns": 500_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "loss_recovery",
            "ticket_slots": 0,
            "trace_seed": "0c" * 32,
            "warmup_duration_ns": 500_000_000,
        }, server_binary="quiczigperf")
        self.assertGreater(server_result["transport_packets_lost"], 0)
        path_evidence = server_result.pop("test_path_evidence")
        self.assertEqual(client_result.pop("test_path_evidence"), path_evidence)
        self.assertTrue(
            _loss_trace_gate(
                {
                    "scenario": "loss_recovery",
                    "path_profile": "loss_recovery_v1",
                    "trace_seed": "0c" * 32,
                },
                server_result,
                client_result,
                path_evidence,
            )
        )

    def test_quiczig_negotiated_treatment_is_exact(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "download",
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, binary="quiczigperf")
        for result in (server_result, client_result):
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
            self.assertEqual(result["negotiated"]["unavailable_fields"], [])

    def test_quiczig_publication_multistream_download_keeps_progressing(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 8,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "max_bidi_streams": 256,
            "max_uni_streams": 256,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "multistream_download",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="quiczigperf", client_binary="ngtcp2perf",
           server_backend="syscall", client_backend="iouring",
           client_require_multishot_receive=True)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual((result["failed"], result["outstanding"],
                              result["in_flight"]), (0, 0, 0))
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
        self.assertTrue(all(
            event["validated_units"] > 0 for event in client_result["progress"]
        ), client_result["progress"])

    def test_quiche_negotiated_treatment_is_exact(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "download",
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, binary="quicheperf")
        for result in (server_result, client_result):
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
            self.assertEqual(result["negotiated"]["unavailable_fields"], [])

    def test_tquic_negotiated_treatment_is_exact(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "download",
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, binary="tquicperf", post_result_drain_s=0.1)
        for result in (server_result, client_result):
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
            self.assertEqual(result["negotiated"]["unavailable_fields"], [])

    def test_tquic_bidi_reserves_control_and_drains_retained_stream_bytes(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "backend": "iouring",
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "bidi",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, binary="tquicperf", post_result_drain_s=0.1)
        self.assertGreater(server_result["numerator"], 0)
        self.assertGreater(client_result["numerator"], 0)
        self.assertEqual(server_result["numerator"], client_result["peer_numerator"])
        self.assertEqual(client_result["numerator"], server_result["peer_numerator"])
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(
                (result["failed"], result["outstanding"], result["in_flight"]),
                (0, 0, 0),
            )
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])

    def test_tquic_releases_ticket_issuance_connections_before_resumed_cohort(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 0,
            "backend": "iouring",
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "resumed_connect",
            "ticket_slots": 16,
            "warmup_duration_ns": 0,
        }, binary="tquicperf", post_result_drain_s=0.1)
        self.assertGreater(client_result["numerator"], 0)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(
                (result["failed"], result["outstanding"], result["in_flight"]),
                (0, 0, 0),
            )
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
            self.assertEqual(result["negotiated"]["unavailable_fields"], [])

    def test_tquic_releases_ticket_issuance_connections_before_zero_rtt_cohort(
        self,
    ) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "backend": "iouring",
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 64,
            "response_body_bytes": 1_024,
            "scenario": "zero_rtt_reqresp",
            "stream_window": 67_108_864,
            "ticket_slots": 16,
            "trace_seed": (
                "5c10d116bc91789d891aa298fe0234ca"
                "20c4376fe10210615a5f06df174888e0"
            ),
            "warmup_duration_ns": 0,
        }, binary="tquicperf", post_result_drain_s=0.1)
        self.assertGreater(client_result["numerator"], 0)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(
                (result["failed"], result["outstanding"], result["in_flight"]),
                (0, 0, 0),
            )
            self.assertEqual(
                (
                    result["flow_control_blocked_events"],
                    result["stream_credit_blocked_events"],
                    result["flow_control_write_blocked_events"],
                ),
                (0, 0, 0),
            )
            self.assertTrue(
                result["negotiated_settings_match"],
                result["negotiated"],
            )
            self.assertEqual(result["negotiated"]["unavailable_fields"], [])

    def test_tquic_server_retires_picoquic_connect_churn(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 0,
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "connect",
            "ticket_slots": 0,
            "warmup_duration_ns": 0,
        }, server_binary="tquicperf", client_binary="picoperf")
        self.assertGreater(client_result["numerator"], 0)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        for result in (server_result, client_result):
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
            self.assertEqual(result["termination_reason"], "deadline_reached")

    def test_ngtcp2_client_replaces_quinn_zero_rtt_connections(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "backend": "iouring",
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 64,
            "response_body_bytes": 1_024,
            "scenario": "zero_rtt_reqresp",
            "ticket_slots": 16,
            "warmup_duration_ns": 0,
        }, server_binary="quinnperf", client_binary="ngtcp2perf",
           server_backend="syscall", client_backend="iouring")
        self.assertGreater(client_result["numerator"], 0)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        for result in (server_result, client_result):
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
            self.assertEqual(result["termination_reason"], "deadline_reached")

    def test_ngtcp2_iouring_client_drops_retired_zero_rtt_lifecycle_packets(self) -> None:
        workload = {
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "max_bidi_streams": 256,
            "max_uni_streams": 256,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 64,
            "response_body_bytes": 1_024,
            "scenario": "zero_rtt_reqresp",
            "stream_window": 67_108_864,
            "ticket_slots": 16,
            "warmup_duration_ns": 0,
        }
        for server_binary in ("lsperf", "mvfstperf"):
            for server_backend in ("syscall", "iouring"):
                with self.subTest(
                    server_binary=server_binary, server_backend=server_backend
                ):
                    server_result, client_result = self._run_ngtcp2_workload(
                        workload,
                        server_binary=server_binary,
                        client_binary="ngtcp2perf",
                        server_backend=server_backend,
                        client_backend="iouring",
                        client_require_multishot_receive=True,
                    )
                    self.assertGreater(server_result["numerator"], 0)
                    self.assertEqual(
                        server_result["numerator"], client_result["numerator"]
                    )
                    for result in (server_result, client_result):
                        self.assertEqual(
                            result["termination_reason"], "deadline_reached"
                        )
                        self.assertEqual(
                            (
                                result["failed"],
                                result["outstanding"],
                                result["in_flight"],
                            ),
                            (0, 0, 0),
                        )

    def test_picoquic_server_stream_churn_interoperates_with_ngtcp2(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 1,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "stream_churn",
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="picoperf", client_binary="ngtcp2perf",
           server_backend="iouring", client_backend="iouring")
        self.assertGreater(client_result["numerator"], 0)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        for result in (server_result, client_result):
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
            self.assertEqual(result["termination_reason"], "deadline_reached")

    def test_quiche_server_transport_parameters_interoperate_with_picoquic(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 0,
            "backend": "iouring",
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "resumed_connect",
            "ticket_slots": 16,
            "warmup_duration_ns": 0,
        }, server_binary="quicheperf", client_binary="picoperf",
           server_backend="iouring", client_backend="iouring")
        self.assertGreater(client_result["numerator"], 0)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        for result in (server_result, client_result):
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
            self.assertEqual(result["termination_reason"], "deadline_reached")

    def test_quiche_server_replaces_draining_zero_rtt_connections(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "max_bidi_streams": 256,
            "max_uni_streams": 256,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 64,
            "response_body_bytes": 1_024,
            "scenario": "zero_rtt_reqresp",
            "stream_window": 67_108_864,
            "ticket_slots": 16,
            "warmup_duration_ns": 0,
        }, server_binary="quicheperf", client_binary="picoperf",
           server_backend="syscall", client_backend="iouring",
           client_require_multishot_receive=True)
        progress = [
            int(event["validated_units"])
            for event in client_result["progress"]
        ]
        self.assertTrue(all(value > 0 for value in progress), progress)
        self.assertGreaterEqual(client_result["numerator"], 400)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(
                (result["failed"], result["outstanding"], result["in_flight"]),
                (0, 0, 0),
            )
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])

    def test_quiche_rotates_one_use_tickets_for_full_lifecycle_cohorts(self) -> None:
        for scenario in ("resumed_connect", "zero_rtt_reqresp"):
            with self.subTest(scenario=scenario):
                zero_rtt = scenario == "zero_rtt_reqresp"
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1 if zero_rtt else 0,
                    "backend": "iouring",
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 16,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 64 if zero_rtt else 0,
                    "response_body_bytes": 1_024 if zero_rtt else 0,
                    "scenario": scenario,
                    "stream_window": 67_108_864,
                    "ticket_slots": 16,
                    "warmup_duration_ns": 0,
                }, binary="quicheperf")
                self.assertGreater(client_result["numerator"], 0)
                self.assertEqual(
                    server_result["numerator"], client_result["numerator"]
                )
                for result in (server_result, client_result):
                    self.assertEqual(
                        result["termination_reason"], "deadline_reached", result
                    )
                    self.assertEqual(
                        (
                            result["failed"],
                            result["outstanding"],
                            result["in_flight"],
                        ),
                        (0, 0, 0),
                    )
                    self.assertTrue(
                        result["negotiated_settings_match"],
                        result["negotiated"],
                    )
                    self.assertEqual(
                        result["negotiated"]["unavailable_fields"], []
                    )
                    self.assertEqual(
                        (
                            result["flow_control_blocked_events"],
                            result["stream_credit_blocked_events"],
                            result["flow_control_write_blocked_events"],
                        ),
                        (0, 0, 0),
                        result,
                    )

    def test_multishard_client_lifecycle_completion_is_race_free(self) -> None:
        cases = (
            ("quicheperf", "zero_rtt_reqresp", "syscall"),
            ("quicheperf", "zero_rtt_reqresp", "iouring"),
            ("s2nperf", "zero_rtt_reqresp", "syscall"),
            ("picoperf", "resumed_connect", "iouring"),
        )
        for server_binary, scenario, backend in cases:
            with self.subTest(
                server_binary=server_binary, scenario=scenario, backend=backend
            ):
                zero_rtt = scenario == "zero_rtt_reqresp"
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1 if zero_rtt else 0,
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 16,
                    "max_bidi_streams": 256,
                    "max_uni_streams": 256,
                    "measurement_duration_ns": 2_000_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 200_000_000,
                    "request_body_bytes": 64 if zero_rtt else 0,
                    "response_body_bytes": 1_024 if zero_rtt else 0,
                    "scenario": scenario,
                    "stream_window": 67_108_864,
                    "ticket_slots": 16,
                    "warmup_duration_ns": 0,
                }, server_binary=server_binary, client_binary="ngtcp2perf",
                   server_backend=backend, client_backend="iouring",
                   client_require_multishot_receive=True)
                self.assertGreater(server_result["numerator"], 0)
                self.assertEqual(server_result["numerator"], client_result["numerator"])
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(
                        (result["failed"], result["outstanding"], result["in_flight"]),
                        (0, 0, 0),
                    )

    def test_lsquic_negotiated_treatment_is_exact(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "download",
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, binary="lsperf")
        for result in (server_result, client_result):
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
            self.assertEqual(result["negotiated"]["unavailable_fields"], [])

    def test_zero_application_close_interoperates_with_picoquic(self) -> None:
        workload = {
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 1,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "close_reset_cleanup",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }
        for server_binary in ("lsperf", "xquicperf", "tquicperf"):
            with self.subTest(server_binary=server_binary):
                server_result, client_result = self._run_ngtcp2_workload(
                    workload,
                    server_binary=server_binary,
                    client_binary="picoperf",
                    server_backend="iouring",
                    client_backend="iouring",
                )
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(
                        (result["failed"], result["outstanding"], result["in_flight"]),
                        (0, 0, 0),
                    )
                    self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
                self.assertTrue(all(client_result["cleanup_strata"]))
                self.assertEqual(server_result["numerator"], client_result["numerator"])

    def test_lsquic_retires_fresh_streams_and_echoes_datagrams(self) -> None:
        common = {
            "connection_count": 16,
            "connection_window": 67_108_864,
            "measurement_duration_ns": 100_000_000,
            "progress_interval_ns": 10_000_000,
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }
        workloads = {
            "reqresp": {
                "active_streams_per_connection": 1,
                "bulk_chunk_bytes": 0,
                "datagram_body_bytes": 0,
                "datagram_max_unreturned_per_connection": 0,
                "global_operation_slots": 16,
                "operation_body_bytes": 0,
                "request_body_bytes": 64,
                "response_body_bytes": 1_024,
            },
            "stream_churn": {
                "active_streams_per_connection": 1,
                "bulk_chunk_bytes": 0,
                "datagram_body_bytes": 0,
                "datagram_max_unreturned_per_connection": 0,
                "global_operation_slots": 16,
                "operation_body_bytes": 1,
                "request_body_bytes": 0,
                "response_body_bytes": 0,
            },
            "datagram": {
                "active_streams_per_connection": 0,
                "bulk_chunk_bytes": 0,
                "datagram_body_bytes": 64,
                "datagram_max_unreturned_per_connection": 128,
                "global_operation_slots": 2_048,
                "operation_body_bytes": 0,
                "request_body_bytes": 0,
                "response_body_bytes": 0,
            },
        }
        for scenario, shape in workloads.items():
            with self.subTest(scenario=scenario):
                server_result, client_result = self._run_ngtcp2_workload(
                    common | shape | {"scenario": scenario},
                    server_binary="lsperf",
                    client_binary="picoperf",
                    server_backend="iouring",
                    client_backend="iouring",
                )
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(
                        (result["failed"], result["outstanding"], result["in_flight"]),
                        (0, 0, 0),
                    )
                    self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
                self.assertGreater(server_result["numerator"], 0)
                self.assertEqual(server_result["numerator"], client_result["numerator"])

    def test_s2n_retires_fresh_streams_with_picoquic_client(self) -> None:
        common = {
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 10_000_000_000,
            "progress_interval_ns": 1_000_000_000,
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }
        workloads = {
            "reqresp": {
                "operation_body_bytes": 0,
                "request_body_bytes": 64,
                "response_body_bytes": 1_024,
            },
            "stream_churn": {
                "operation_body_bytes": 1,
                "request_body_bytes": 0,
                "response_body_bytes": 0,
            },
        }
        for scenario, shape in workloads.items():
            with self.subTest(scenario=scenario):
                server_result, client_result = self._run_ngtcp2_workload(
                    common | shape | {"scenario": scenario},
                    server_binary="s2nperf",
                    client_binary="picoperf",
                    server_backend="syscall",
                    client_backend="iouring",
                )
                self.assertEqual(server_result["numerator"], client_result["numerator"])
                self.assertGreater(client_result["numerator"], 0)
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(
                        (result["failed"], result["outstanding"], result["in_flight"]),
                        (0, 0, 0),
                    )
                    self.assertEqual(
                        (
                            result["flow_control_blocked_events"],
                            result["stream_credit_blocked_events"],
                            result["flow_control_write_blocked_events"],
                        ),
                        (0, 0, 0),
                    )
                self.assertTrue(
                    all(
                        observation["validated_units"] > 0
                        and not observation["blocked"]
                        for observation in client_result["progress"]
                    ),
                    client_result["progress"],
                )
                self.assertTrue(
                    all(
                        observation["validated_units"] == 0
                        and not observation["blocked"]
                        for observation in server_result["progress"]
                    ),
                    server_result["progress"],
                )

    def test_quinn_and_noq_negotiated_treatment_is_exact(self) -> None:
        for binary in ("quinnperf", "noqperf"):
            for backend in ("syscall", "iouring"):
                with self.subTest(binary=binary, backend=backend):
                    server_result, client_result = self._run_ngtcp2_workload({
                        "active_streams_per_connection": 1,
                        "backend": backend,
                        "bulk_chunk_bytes": 262_144,
                        "connection_count": 16,
                        "datagram_body_bytes": 0,
                        "datagram_max_unreturned_per_connection": 0,
                        "global_operation_slots": 0,
                        "measurement_duration_ns": 500_000_000,
                        "operation_body_bytes": 0,
                        "progress_interval_ns": 50_000_000,
                        "request_body_bytes": 8,
                        "response_body_bytes": 0,
                        "scenario": "download",
                        "ticket_slots": 0,
                        "warmup_duration_ns": 250_000_000,
                    }, binary=binary)
                    for result in (server_result, client_result):
                        self.assertTrue(
                            result["negotiated_settings_match"], result["negotiated"]
                        )
                        self.assertEqual(
                            result["negotiated"]["unavailable_fields"], []
                        )

    def test_noq_server_revisits_pacing_blocked_peer_stream_writes(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "download",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="noqperf", client_binary="picoperf")
        self.assertGreater(client_result["numerator"], 0, (server_result, client_result))
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])

    def test_noq_server_drives_bidirectional_streams_at_publication_cardinality(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "bidi",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="noqperf", client_binary="picoperf")
        self.assertGreater(server_result["numerator"], 0, (server_result, client_result))
        self.assertGreater(client_result["numerator"], 0, (server_result, client_result))
        self.assertEqual(server_result["numerator"], client_result["peer_numerator"])
        self.assertEqual(client_result["numerator"], server_result["peer_numerator"])
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual((result["failed"], result["outstanding"], result["in_flight"]), (0, 0, 0))

    def test_s2n_negotiated_treatment_is_exact(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "backend": backend,
                    "bulk_chunk_bytes": 262_144,
                    "connection_count": 16,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 0,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 8,
                    "response_body_bytes": 0,
                    "scenario": "download",
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, binary="s2nperf")
                for result in (server_result, client_result):
                    self.assertTrue(
                        result["negotiated_settings_match"], result["negotiated"]
                    )
                    self.assertEqual(
                        result["negotiated"]["unavailable_fields"], []
                    )

    def test_neqo_negotiated_treatment_is_exact_and_streams_make_progress(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "backend": backend,
                    "bulk_chunk_bytes": 262_144,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 0,
                    "measurement_duration_ns": 2_000_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 200_000_000,
                    "request_body_bytes": 8,
                    "response_body_bytes": 0,
                    "scenario": "upload",
                    "stream_window": 67_108_864,
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, binary="neqoperf")
                for result in (server_result, client_result):
                    self.assertTrue(
                        result["negotiated_settings_match"], result["negotiated"]
                    )
                    self.assertEqual(
                        result["negotiated"]["unavailable_fields"], []
                    )
                self.assertGreater(server_result["numerator"], 1_048_576)
                self.assertEqual(client_result["numerator"], 0)
                self.assertTrue(all(
                    event["validated_units"] > 0
                    for event in server_result["progress"]
                ))

    def test_neqo_multistream_send_buffer_is_bounded(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 8,
                    "bulk_chunk_bytes": 262_144,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 0,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 8,
                    "response_body_bytes": 0,
                    "scenario": "multistream_download",
                    "stream_window": 67_108_864,
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, binary="neqoperf")
                self.assertGreater(server_result["numerator"], 0)
                self.assertEqual(
                    server_result["numerator"], client_result["numerator"]
                )
                self.assertEqual(
                    server_result["peer_numerator"], client_result["numerator"]
                )
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(
                        (result["failed"], result["outstanding"], result["in_flight"]),
                        (0, 0, 0),
                    )

    def test_neqo_reqresp_drains_final_operation_before_stop(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 16,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 64,
                    "response_body_bytes": 1_024,
                    "scenario": "reqresp",
                    "stream_window": 67_108_864,
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, server_binary="neqoperf", client_binary="ngtcp2perf",
                   server_backend=backend, client_backend="iouring")
                self.assertGreater(server_result["numerator"], 0)
                self.assertEqual(
                    server_result["numerator"], client_result["numerator"]
                )
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(
                        (result["failed"], result["outstanding"], result["in_flight"]),
                        (0, 0, 0),
                    )

    def test_neqo_datagram_drain_terminally_classifies_unreturned_ids(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 0,
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 64,
                    "datagram_max_unreturned_per_connection": 128,
                    "global_operation_slots": 2_048,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 0,
                    "response_body_bytes": 0,
                    "scenario": "datagram",
                    "stream_window": 67_108_864,
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, server_binary="neqoperf", client_binary="picoperf",
                   server_backend=backend, client_backend="iouring")
                self.assertGreater(server_result["numerator"], 0)
                self.assertEqual(
                    server_result["numerator"], client_result["numerator"]
                )
                self.assertLessEqual(client_result["unreturned"], 2_048)
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(
                        (result["failed"], result["outstanding"], result["in_flight"]),
                        (0, 0, 0),
                    )

    def test_neqo_resumed_connect_retires_native_history_within_boundary(self) -> None:
        for repetition in range(5):
            with self.subTest(repetition=repetition):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 0,
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 16,
                    "measurement_duration_ns": 2_000_000_000,
                    "operation_body_bytes": 0,
                    "path_profile": "loopback",
                    "progress_interval_ns": 200_000_000,
                    "request_body_bytes": 0,
                    "response_body_bytes": 0,
                    "scenario": "resumed_connect",
                    "stream_window": 67_108_864,
                    "ticket_slots": 16,
                    "warmup_duration_ns": 0,
                }, server_binary="neqoperf", client_binary="picoperf",
                   server_backend="iouring", client_backend="iouring")
                self.assertGreater(server_result["completed"], 0)
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertLessEqual(
                        result["actual_end_raw_ns"] - result["global_end_raw_ns"],
                        2_000_000,
                    )
                    self.assertEqual(
                        (result["failed"], result["outstanding"], result["in_flight"]),
                        (0, 0, 0),
                    )

    def test_neqo_zero_rtt_generation_churn_reconciles_against_ngtcp2(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 16,
                    "measurement_duration_ns": 2_000_000_000,
                    "operation_body_bytes": 0,
                    "path_profile": "loopback",
                    "progress_interval_ns": 200_000_000,
                    "request_body_bytes": 64,
                    "response_body_bytes": 1_024,
                    "scenario": "zero_rtt_reqresp",
                    "stream_window": 67_108_864,
                    "ticket_slots": 16,
                    "warmup_duration_ns": 0,
                }, server_binary="neqoperf", client_binary="ngtcp2perf",
                   server_backend=backend, client_backend="iouring")
                self.assertGreater(server_result["numerator"], 0)
                self.assertEqual(server_result["numerator"], client_result["numerator"])
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(
                        (result["failed"], result["outstanding"], result["in_flight"]),
                        (0, 0, 0),
                    )

    def test_neqo_cleanup_retires_pre_control_replacements(self) -> None:
        for client in ("ngtcp2perf", "picoperf"):
            for backend in ("syscall", "iouring"):
                with self.subTest(client=client, backend=backend):
                    server_result, client_result = self._run_ngtcp2_workload({
                        "active_streams_per_connection": 1,
                        "bulk_chunk_bytes": 0,
                        "connection_count": 16,
                        "connection_window": 67_108_864,
                        "datagram_body_bytes": 0,
                        "datagram_max_unreturned_per_connection": 0,
                        "global_operation_slots": 16,
                        "measurement_duration_ns": 2_000_000_000,
                        "operation_body_bytes": 1,
                        "path_profile": "loopback",
                        "progress_interval_ns": 200_000_000,
                        "request_body_bytes": 0,
                        "response_body_bytes": 0,
                        "scenario": "close_reset_cleanup",
                        "stream_window": 67_108_864,
                        "ticket_slots": 0,
                        "warmup_duration_ns": 250_000_000,
                    }, server_binary="neqoperf", client_binary=client,
                       server_backend=backend, client_backend="iouring")
                    self.assertEqual(
                        server_result["numerator"], client_result["numerator"]
                    )
                    for result in (server_result, client_result):
                        self.assertEqual(result["termination_reason"], "deadline_reached")
                        self.assertTrue(
                            all(value >= 100 for value in result["cleanup_strata"]),
                            result["cleanup_strata"],
                        )
                        self.assertEqual(
                            (result["failed"], result["outstanding"], result["in_flight"]),
                            (0, 0, 0),
                        )

    def test_neqo_same_stack_parity_lifecycle_scenarios(self) -> None:
        cases = (
            ("connect", 0, 0, 0, 0),
            ("resumed_connect", 0, 0, 0, 0),
            ("zero_rtt_reqresp", 1, 64, 1_024, 0),
            ("close_reset_cleanup", 1, 0, 0, 1),
        )
        for backend in ("syscall", "iouring"):
            for (
                scenario,
                active_streams,
                request_bytes,
                response_bytes,
                operation_bytes,
            ) in cases:
                with self.subTest(backend=backend, scenario=scenario):
                    cleanup = scenario == "close_reset_cleanup"
                    server_result, client_result = self._run_ngtcp2_workload({
                        "active_streams_per_connection": active_streams,
                        "bulk_chunk_bytes": 0,
                        "connection_count": 16,
                        "connection_window": 67_108_864,
                        "datagram_body_bytes": 0,
                        "datagram_max_unreturned_per_connection": 0,
                        "global_operation_slots": 16,
                        "measurement_duration_ns": 500_000_000,
                        "operation_body_bytes": operation_bytes,
                        "progress_interval_ns": 50_000_000,
                        "request_body_bytes": request_bytes,
                        "response_body_bytes": response_bytes,
                        "scenario": scenario,
                        "stream_window": 67_108_864,
                        "ticket_slots": (
                            0 if scenario in ("connect", "close_reset_cleanup")
                            else 16
                        ),
                        "warmup_duration_ns": 250_000_000 if cleanup else 0,
                    }, binary="neqoperf", server_backend=backend,
                       client_backend="iouring")
                    self.assertGreater(client_result["numerator"], 0)
                    self.assertEqual(
                        server_result["numerator"], client_result["numerator"]
                    )
                    for result in (server_result, client_result):
                        self.assertEqual(
                            result["termination_reason"],
                            "deadline_reached",
                            result,
                        )
                        self.assertEqual(
                            (
                                result["failed"],
                                result["outstanding"],
                                result["in_flight"],
                            ),
                            (0, 0, 0),
                        )
                        self.assertTrue(
                            result["negotiated_settings_match"],
                            result["negotiated"],
                        )
                    if cleanup:
                        self.assertTrue(
                            all(
                                value >= 100
                                for value in client_result["cleanup_strata"]
                            ),
                            client_result["cleanup_strata"],
                        )

    def test_mvfst_negotiated_treatment_is_exact_and_streams_make_progress(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "backend": backend,
                    "bulk_chunk_bytes": 262_144,
                    "connection_count": 16,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 0,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 8,
                    "response_body_bytes": 0,
                    "scenario": "download",
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, binary="mvfstperf")
                for result in (server_result, client_result):
                    self.assertTrue(
                        result["negotiated_settings_match"], result["negotiated"]
                    )
                    self.assertEqual(
                        result["negotiated"]["unavailable_fields"], []
                    )
                self.assertGreater(client_result["numerator"], 1_048_576)
                self.assertEqual(server_result["numerator"], client_result["numerator"])
                self.assertTrue(all(
                    event["validated_units"] > 0
                    for event in client_result["progress"]
                ))

    def test_mvfst_picoquic_churn_drains_transport_before_completion(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "backend": backend,
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 16,
                    "measurement_duration_ns": 2_000_000_000,
                    "operation_body_bytes": 1,
                    "progress_interval_ns": 200_000_000,
                    "request_body_bytes": 0,
                    "response_body_bytes": 0,
                    "scenario": "stream_churn",
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, server_binary="mvfstperf", client_binary="picoperf")
                self.assertGreater(client_result["numerator"], 0)
                self.assertEqual(server_result["numerator"], client_result["numerator"])
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(result["outstanding"], 0)
                    self.assertEqual(result["in_flight"], 0)
                    self.assertTrue(
                        result["negotiated_settings_match"], result["negotiated"]
                    )

    def test_mvfst_same_stack_parity_lifecycle_scenarios(self) -> None:
        cases = (
            ("connect", 0, 0, 0, 0),
            ("resumed_connect", 0, 0, 0, 0),
            ("zero_rtt_reqresp", 1, 64, 1_024, 0),
            ("close_reset_cleanup", 1, 0, 0, 1),
        )
        for backend in ("syscall", "iouring"):
            for (
                scenario,
                active_streams,
                request_bytes,
                response_bytes,
                operation_bytes,
            ) in cases:
                with self.subTest(backend=backend, scenario=scenario):
                    cleanup = scenario == "close_reset_cleanup"
                    server_result, client_result = self._run_ngtcp2_workload({
                        "active_streams_per_connection": active_streams,
                        "bulk_chunk_bytes": 0,
                        "connection_count": 16,
                        "connection_window": 67_108_864,
                        "datagram_body_bytes": 0,
                        "datagram_max_unreturned_per_connection": 0,
                        "global_operation_slots": 16,
                        "measurement_duration_ns": 500_000_000,
                        "operation_body_bytes": operation_bytes,
                        "progress_interval_ns": 50_000_000,
                        "request_body_bytes": request_bytes,
                        "response_body_bytes": response_bytes,
                        "scenario": scenario,
                        "stream_window": 67_108_864,
                        "ticket_slots": (
                            0 if scenario in ("connect", "close_reset_cleanup")
                            else 16
                        ),
                        "warmup_duration_ns": 250_000_000 if cleanup else 0,
                    }, binary="mvfstperf", server_backend=backend,
                       client_backend="iouring")
                    self.assertGreater(client_result["numerator"], 0)
                    self.assertEqual(
                        server_result["numerator"], client_result["numerator"]
                    )
                    for result in (server_result, client_result):
                        self.assertEqual(
                            result["termination_reason"],
                            "deadline_reached",
                            result,
                        )
                        self.assertEqual(
                            (
                                result["failed"],
                                result["outstanding"],
                                result["in_flight"],
                            ),
                            (0, 0, 0),
                        )
                        self.assertTrue(
                            result["negotiated_settings_match"],
                            result["negotiated"],
                        )
                    if cleanup:
                        self.assertTrue(
                            all(
                                value >= 100
                                for value in client_result["cleanup_strata"]
                            ),
                            client_result["cleanup_strata"],
                        )

    def test_xquic_negotiated_treatment_is_exact_and_streams_make_progress(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "backend": backend,
                    "bulk_chunk_bytes": 262_144,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 0,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 8,
                    "response_body_bytes": 0,
                    "scenario": "download",
                    "stream_window": 67_108_864,
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, binary="xquicperf")
                for result in (server_result, client_result):
                    self.assertTrue(
                        result["negotiated_settings_match"], result["negotiated"]
                    )
                    self.assertEqual(
                        result["negotiated"]["unavailable_fields"], []
                    )
                self.assertGreater(client_result["numerator"], 1_048_576)
                self.assertEqual(server_result["numerator"], client_result["numerator"])
                self.assertTrue(all(
                    event["validated_units"] > 0
                    for event in client_result["progress"]
                ))

    def test_xquic_same_stack_lifecycle_scenarios(self) -> None:
        cases = (
            ("resumed_connect", 0, 0, 0, 0),
            ("zero_rtt_reqresp", 1, 64, 1_024, 0),
            ("close_reset_cleanup", 1, 0, 0, 1),
        )
        for scenario, active_streams, request_bytes, response_bytes, operation_bytes in cases:
            with self.subTest(scenario=scenario):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": active_streams,
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 16,
                    "max_bidi_streams": 256,
                    "max_uni_streams": 256,
                    "measurement_duration_ns": 2_000_000_000,
                    "operation_body_bytes": operation_bytes,
                    "progress_interval_ns": 200_000_000,
                    "request_body_bytes": request_bytes,
                    "response_body_bytes": response_bytes,
                    "scenario": scenario,
                    "stream_window": 67_108_864,
                    "ticket_slots": (
                        0 if scenario == "close_reset_cleanup" else 16
                    ),
                    "warmup_duration_ns": (
                        250_000_000 if scenario == "close_reset_cleanup" else 0
                    ),
                }, binary="xquicperf", server_backend="iouring",
                   client_backend="iouring", client_require_multishot_receive=True)
                self.assertGreater(client_result["numerator"], 0)
                self.assertEqual(server_result["numerator"], client_result["numerator"])
                for result in (server_result, client_result):
                    self.assertEqual(result["termination_reason"], "deadline_reached")
                    self.assertEqual(
                        (result["failed"], result["outstanding"], result["in_flight"]),
                        (0, 0, 0),
                    )
                    self.assertTrue(
                        result["negotiated_settings_match"], result["negotiated"]
                    )
                if scenario == "close_reset_cleanup":
                    self.assertTrue(all(client_result["cleanup_strata"]))

    def test_xquic_caps_picoquic_upload_admissions_at_the_frozen_cohort(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "upload",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="xquicperf", client_binary="picoperf",
           server_backend="iouring", client_backend="iouring")
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(
                (result["failed"], result["outstanding"], result["in_flight"]),
                (0, 0, 0),
            )
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
        self.assertGreater(server_result["numerator"], 1_048_576)

    def test_xquic_loss_recovery_preserves_the_frozen_native_cohort(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "path_profile": "loss_recovery_v1",
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "loss_recovery",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "trace_seed": "0a" * 32,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="xquicperf", client_binary="picoperf",
           server_backend="syscall", client_backend="iouring")
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(
                (result["failed"], result["outstanding"], result["in_flight"]),
                (0, 0, 0),
            )
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
        self.assertGreater(server_result["numerator"], 0)

    def test_xquic_replaces_picoquic_cleanup_connections_at_the_native_limit(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "connection_window": 67_108_864,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 1,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "close_reset_cleanup",
            "stream_window": 67_108_864,
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="xquicperf", client_binary="picoperf",
           server_backend="iouring", client_backend="iouring")
        for result in (server_result, client_result):
            self.assertEqual(result["termination_reason"], "deadline_reached")
            self.assertEqual(
                (result["failed"], result["outstanding"], result["in_flight"]),
                (0, 0, 0),
            )
            self.assertTrue(result["negotiated_settings_match"], result["negotiated"])
        self.assertTrue(all(client_result["cleanup_strata"]))
        self.assertEqual(server_result["numerator"], client_result["numerator"])

    def test_quiczig_flow_control_exports_block_and_recovery_evidence(self) -> None:
        server_result, _ = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 8,
            "response_body_bytes": 0,
            "scenario": "flow_control",
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, server_binary="quiczigperf")
        self.assertGreater(
            server_result["flow_control_blocked_events"]
            + server_result["stream_credit_blocked_events"],
            0,
        )
        self.assertTrue(server_result["flow_control_recovery_evidence"])

    def test_quiczig_resumed_connect_rotates_one_use_tickets(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 0,
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "resumed_connect",
            "ticket_slots": 16,
            "warmup_duration_ns": 0,
        }, binary="quiczigperf")
        self.assertEqual(server_result["termination_reason"], "deadline_reached")
        self.assertEqual(
            client_result["termination_reason"], "deadline_reached",
            (
                client_result["actual_start_raw_ns"] - client_result["global_start_raw_ns"],
                client_result["actual_end_raw_ns"] - client_result["global_end_raw_ns"],
            ),
        )
        self.assertGreater(server_result["numerator"], 0, (server_result, client_result))
        self.assertEqual(server_result["numerator"], client_result["numerator"])

    def test_quiczig_zero_rtt_reqresp_delivers_accepted_early_data(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 2_000_000_000,
            "operation_body_bytes": 0,
            "progress_interval_ns": 200_000_000,
            "request_body_bytes": 64,
            "response_body_bytes": 1_024,
            "scenario": "zero_rtt_reqresp",
            "ticket_slots": 16,
            "warmup_duration_ns": 0,
        }, binary="quiczigperf")
        self.assertEqual(server_result["termination_reason"], "deadline_reached")
        self.assertEqual(client_result["termination_reason"], "deadline_reached")
        self.assertGreater(server_result["numerator"], 0, (server_result, client_result))
        self.assertEqual(server_result["numerator"], client_result["numerator"])

    def _assert_close_reset_cleanup(
        self, binary: str, *, max_endpoint_rss_bytes: int | None = None
    ) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "backend": backend,
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 16,
                    "max_bidi_streams": 256,
                    "max_uni_streams": 256,
                    "measurement_duration_ns": 2_000_000_000,
                    "operation_body_bytes": 1,
                    "progress_interval_ns": 200_000_000,
                    "request_body_bytes": 0,
                    "response_body_bytes": 0,
                    "scenario": "close_reset_cleanup",
                    "stream_window": 67_108_864,
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, binary=binary, max_endpoint_rss_bytes=max_endpoint_rss_bytes)
                self.assertEqual(server_result["termination_reason"], "deadline_reached")
                self.assertEqual(client_result["termination_reason"], "deadline_reached")
                self.assertTrue(
                    all(value >= 100 for value in client_result["cleanup_strata"]),
                    client_result["cleanup_strata"],
                )
                self.assertEqual(
                    sum(client_result["cleanup_strata"]), client_result["numerator"]
                )
                self.assertEqual(server_result["numerator"], client_result["numerator"])

    def test_quiczig_close_reset_requires_all_peer_terminal_strata(self) -> None:
        self._assert_close_reset_cleanup("quiczigperf")

    def test_picoquic_close_reset_requires_all_peer_terminal_strata(self) -> None:
        self._assert_close_reset_cleanup("picoperf")

    def test_quiche_close_reset_requires_all_peer_terminal_strata(self) -> None:
        self._assert_close_reset_cleanup("quicheperf")

    def test_lsquic_cleanup_retains_peer_reset_after_read_error(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 16,
                    "measurement_duration_ns": 2_000_000_000,
                    "operation_body_bytes": 1,
                    "progress_interval_ns": 200_000_000,
                    "request_body_bytes": 0,
                    "response_body_bytes": 0,
                    "scenario": "close_reset_cleanup",
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, binary="lsperf", server_backend=backend,
                   client_backend="iouring")
                self.assertEqual(
                    server_result["numerator"], client_result["numerator"]
                )
                self.assertEqual(
                    sum(client_result["cleanup_strata"]),
                    client_result["numerator"],
                )
                self.assertTrue(
                    all(value >= 100 for value in client_result["cleanup_strata"]),
                    client_result["cleanup_strata"],
                )
                for result in (server_result, client_result):
                    self.assertEqual(
                        result["termination_reason"], "deadline_reached", result
                    )
                    self.assertTrue(
                        all(
                            observation["validated_units"] > 0
                            for observation in result["progress"]
                        ),
                        result["progress"],
                    )
                    self.assertEqual(
                        (
                            result["failed"],
                            result["outstanding"],
                            result["in_flight"],
                        ),
                        (0, 0, 0),
                    )

    def test_s2n_datagram_polling_tolerates_pending_connections(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 0,
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 64,
                    "datagram_max_unreturned_per_connection": 128,
                    "global_operation_slots": 2_048,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 0,
                    "response_body_bytes": 0,
                    "scenario": "datagram",
                    "stream_window": 67_108_864,
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, binary="s2nperf", server_backend=backend,
                   client_backend="iouring")
                self.assertGreater(client_result["numerator"], 0)
                self.assertEqual(
                    server_result["numerator"], client_result["numerator"]
                )
                for result in (server_result, client_result):
                    self.assertEqual(
                        result["termination_reason"], "deadline_reached"
                    )
                    self.assertEqual(
                        (result["failed"], result["outstanding"]),
                        (0, 0),
                    )

    def test_short_parity_cleanup_meets_frozen_strata(self) -> None:
        for binary in ("xquicperf", "quinnperf", "noqperf"):
            for backend in ("syscall", "iouring"):
                with self.subTest(binary=binary, backend=backend):
                    server_result, client_result = self._run_ngtcp2_workload({
                        "active_streams_per_connection": 1,
                        "bulk_chunk_bytes": 0,
                        "connection_count": 16,
                        "connection_window": 67_108_864,
                        "datagram_body_bytes": 0,
                        "datagram_max_unreturned_per_connection": 0,
                        "global_operation_slots": 16,
                        "measurement_duration_ns": 2_000_000_000,
                        "operation_body_bytes": 1,
                        "progress_interval_ns": 200_000_000,
                        "request_body_bytes": 0,
                        "response_body_bytes": 0,
                        "scenario": "close_reset_cleanup",
                        "stream_window": 67_108_864,
                        "ticket_slots": 0,
                        "warmup_duration_ns": 250_000_000,
                    }, binary=binary, server_backend=backend,
                       client_backend="iouring")
                    self.assertEqual(
                        server_result["numerator"], client_result["numerator"]
                    )
                    self.assertTrue(
                        all(
                            value >= 100
                            for value in client_result["cleanup_strata"]
                        ),
                        client_result,
                    )
                    for result in (server_result, client_result):
                        self.assertEqual(
                            result["termination_reason"],
                            "deadline_reached",
                            result,
                        )
                        self.assertEqual(
                            (
                                result["failed"],
                                result["outstanding"],
                                result["in_flight"],
                            ),
                            (0, 0, 0),
                        )

    def test_xquic_short_small_payload_reaches_deadline(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "bulk_chunk_bytes": 0,
                    "connection_count": 16,
                    "connection_window": 67_108_864,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 0,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 64,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 0,
                    "response_body_bytes": 0,
                    "scenario": "small_payload_pps",
                    "stream_window": 67_108_864,
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, binary="xquicperf", server_backend=backend,
                   client_backend="iouring")
                self.assertGreater(server_result["numerator"], 0)
                for result in (server_result, client_result):
                    self.assertEqual(
                        result["termination_reason"],
                        "deadline_reached",
                        result,
                    )
                    self.assertEqual(
                        (
                            result["failed"],
                            result["outstanding"],
                            result["in_flight"],
                        ),
                        (0, 0, 0),
                    )

    def test_s2n_short_multistream_upload_reaches_deadline(self) -> None:
        for repetition in range(3):
            for backend in ("syscall", "iouring"):
                with self.subTest(repetition=repetition, backend=backend):
                    server_result, client_result = self._run_ngtcp2_workload({
                        "active_streams_per_connection": 8,
                        "bulk_chunk_bytes": 262_144,
                        "connection_count": 16,
                        "connection_window": 67_108_864,
                        "datagram_body_bytes": 0,
                        "datagram_max_unreturned_per_connection": 0,
                        "global_operation_slots": 0,
                        "measurement_duration_ns": 500_000_000,
                        "operation_body_bytes": 0,
                        "progress_interval_ns": 50_000_000,
                        "request_body_bytes": 8,
                        "response_body_bytes": 0,
                        "scenario": "multistream_upload",
                        "stream_window": 67_108_864,
                        "ticket_slots": 0,
                        "warmup_duration_ns": 250_000_000,
                    }, binary="s2nperf", server_backend=backend,
                       client_backend="iouring")
                    self.assertGreater(server_result["numerator"], 0)
                    for result in (server_result, client_result):
                        self.assertEqual(
                            result["termination_reason"],
                            "deadline_reached",
                            result,
                        )
                        self.assertEqual(
                            (
                                result["failed"],
                                result["outstanding"],
                                result["in_flight"],
                            ),
                            (0, 0, 0),
                        )

    def test_quiche_flow_control_has_positive_strict_metric(self) -> None:
        for backend in ("syscall", "iouring"):
            with self.subTest(backend=backend):
                server_result, client_result = self._run_ngtcp2_workload({
                    "active_streams_per_connection": 1,
                    "bulk_chunk_bytes": 262_144,
                    "connection_count": 16,
                    "connection_window": 262_144,
                    "datagram_body_bytes": 0,
                    "datagram_max_unreturned_per_connection": 0,
                    "global_operation_slots": 0,
                    "measurement_duration_ns": 500_000_000,
                    "operation_body_bytes": 0,
                    "progress_interval_ns": 50_000_000,
                    "request_body_bytes": 8,
                    "response_body_bytes": 0,
                    "scenario": "flow_control",
                    "stream_window": 65_536,
                    "ticket_slots": 0,
                    "warmup_duration_ns": 250_000_000,
                }, binary="quicheperf", server_backend=backend,
                   client_backend="iouring")
                self.assertGreater(client_result["numerator"], 0, client_result)
                self.assertEqual(
                    server_result["numerator"], client_result["numerator"]
                )
                self.assertGreater(
                    server_result["flow_control_blocked_events"]
                    + server_result["stream_credit_blocked_events"],
                    0,
                    server_result,
                )
                self.assertTrue(server_result["flow_control_recovery_evidence"])

    def test_cleanup_reconciles_retired_counts_across_client_shards(self) -> None:
        workload = {
            "active_streams_per_connection": 1,
            "backend": "syscall",
            "bulk_chunk_bytes": 0,
            "connection_count": 16,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 16,
            "measurement_duration_ns": 250_000_000,
            "operation_body_bytes": 1,
            "progress_interval_ns": 25_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "close_reset_cleanup",
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }
        for binary in ("picoperf", "quicheperf"):
            for repetition in range(5):
                with self.subTest(binary=binary, repetition=repetition):
                    server_result, client_result = self._run_ngtcp2_workload(
                        workload, binary=binary
                    )
                    self.assertEqual(
                        server_result["numerator"], client_result["numerator"]
                    )
                    self.assertEqual(
                        sum(client_result["cleanup_strata"]),
                        client_result["numerator"],
                    )
                    self.assertTrue(
                        all(value >= 100 for value in client_result["cleanup_strata"]),
                        client_result["cleanup_strata"],
                    )

    def test_s2n_close_reset_requires_all_peer_terminal_strata(self) -> None:
        self._assert_close_reset_cleanup(
            "s2nperf", max_endpoint_rss_bytes=768 * 1024 * 1024
        )

    def test_ngtcp2_reset_ack_attests_zero_state_inventory(self) -> None:
        self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 2,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 100_000_000,
            "operation_body_bytes": 64,
            "progress_interval_ns": 10_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "small_payload_pps",
            "ticket_slots": 0,
            "warmup_duration_ns": 50_000_000,
        }, reset=True)

    def test_ngtcp2_untimed_exercise_attests_live_then_zero_state(self) -> None:
        self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 0,
            "connection_count": 2,
            "datagram_body_bytes": 0,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 0,
            "measurement_duration_ns": 100_000_000,
            "operation_body_bytes": 64,
            "progress_interval_ns": 10_000_000,
            "request_body_bytes": 0,
            "response_body_bytes": 0,
            "scenario": "small_payload_pps",
            "ticket_slots": 0,
            "warmup_duration_ns": 50_000_000,
        }, exercise=True)

    def test_ngtcp2_four_worker_client_establishes_idle_connections(self) -> None:
        server_result, client_result = self._run_ngtcp2_workload({
            "active_streams_per_connection": 1,
            "bulk_chunk_bytes": 262_144,
            "connection_count": 4,
            "datagram_body_bytes": 64,
            "datagram_max_unreturned_per_connection": 0,
            "global_operation_slots": 1,
            "measurement_duration_ns": 500_000_000,
            "operation_body_bytes": 1,
            "progress_interval_ns": 50_000_000,
            "request_body_bytes": 1,
            "response_body_bytes": 1,
            "scenario": "memory_curve",
            "ticket_slots": 0,
            "warmup_duration_ns": 250_000_000,
        }, client_workers=4)
        self.assertEqual(server_result["numerator"], client_result["numerator"])
        self.assertEqual(len(server_result["progress"]), 10)
        self.assertEqual(len(client_result["progress"]), 10)


if __name__ == "__main__":
    unittest.main()
