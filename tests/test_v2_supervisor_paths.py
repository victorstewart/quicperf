import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from quicperf_harness.manifest_collect import (
    ManifestCollectionError,
    _loaded_libraries,
    attest_process_libraries,
    mapped_process_libraries,
)
from quicperf_harness.runner import _terminate_active_processes
from quicperf_harness.lanes import (
    LaneCgroups,
    LaneError,
    client_limits,
    read_cgroup_snapshot,
)
from quicperf_harness.paths import (
    ArmedTrace,
    LoopbackPathController,
    PathError,
    TraceTransition,
    derive_trace_seed,
    loss_recovery_drop,
)
from quicperf_harness.supervisor import (
    SupervisionError,
    Supervisor,
    _enter_network_namespace,
)
from quicperf_harness.topology import (
    LaneTopology,
    PhysicalCore,
    TopologyError,
    allocate_lanes,
)


ROOT = Path(__file__).resolve().parents[1]


class SupervisorPathTests(unittest.TestCase):
    def test_child_closes_namespace_descriptor_after_setns(self):
        with (
            mock.patch("quicperf_harness.supervisor.os.setns") as setns,
            mock.patch("quicperf_harness.supervisor.os.close") as close,
        ):
            _enter_network_namespace(17)
        setns.assert_called_once_with(17, os.CLONE_NEWNET)
        close.assert_called_once_with(17)

        with (
            mock.patch(
                "quicperf_harness.supervisor.os.setns",
                side_effect=OSError("injected setns failure"),
            ),
            mock.patch("quicperf_harness.supervisor.os.close") as close,
            self.assertRaisesRegex(OSError, "injected setns failure"),
        ):
            _enter_network_namespace(19)
        close.assert_called_once_with(19)

    def test_live_mapped_library_attestation_is_exact_and_hash_checked(self):
        sleep = Path(shutil.which("sleep")).resolve()
        process = subprocess.Popen([str(sleep), "60"])
        try:
            expected = _loaded_libraries(ROOT, sleep)
            self.assertEqual(
                mapped_process_libraries(ROOT, process.pid, sleep), expected
            )
            attest_process_libraries(ROOT, process.pid, sleep, expected)
            forged = [dict(item) for item in expected]
            forged[0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(
                ManifestCollectionError, "differs from the frozen manifest"
            ):
                attest_process_libraries(ROOT, process.pid, sleep, forged)
        finally:
            process.terminate()
            process.wait(timeout=2)

    def test_live_executable_is_hashed_through_its_mapped_inode(self):
        sleep = Path(shutil.which("sleep")).resolve()
        true = Path(shutil.which("true")).resolve()
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "endpoint"
            shutil.copy2(sleep, executable)
            process = subprocess.Popen([str(executable), "60"])
            try:
                replacement = Path(temporary) / "replacement"
                shutil.copy2(true, replacement)
                os.replace(replacement, executable)
                with self.assertRaisesRegex(
                    ManifestCollectionError,
                    "deleted object|executable inode differs from the frozen binary",
                ):
                    mapped_process_libraries(ROOT, process.pid, executable)
            finally:
                process.terminate()
                process.wait(timeout=2)

    def test_cgroup_telemetry_is_exact_and_counter_regression_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            cgroup = Path(tmp)
            (cgroup / "cpu.stat").write_text(
                "usage_usec 10\nthrottled_usec 2\nnr_throttled 1\nnr_periods 3\n", encoding="ascii"
            )
            (cgroup / "memory.current").write_text("4096\n", encoding="ascii")
            (cgroup / "memory.peak").write_text("6144\n", encoding="ascii")
            (cgroup / "pids.current").write_text("1\n", encoding="ascii")
            before = read_cgroup_snapshot(cgroup)
            self.assertEqual(
                (before.cpu_usage_ns, before.cpu_throttled_ns, before.cpu_nr_throttled),
                (10_000, 2_000, 1),
            )
            (cgroup / "cpu.stat").write_text(
                "usage_usec 25\nthrottled_usec 2\nnr_throttled 1\nnr_periods 4\n", encoding="ascii"
            )
            (cgroup / "memory.current").write_text("8192\n", encoding="ascii")
            (cgroup / "memory.peak").write_text("12288\n", encoding="ascii")
            (cgroup / "pids.current").write_text("0\n", encoding="ascii")
            delta = read_cgroup_snapshot(cgroup).delta(before)
            self.assertEqual(
                delta,
                type(delta)(15_000, 0, 8192, 0, 12288),
            )
            with self.assertRaisesRegex(LaneError, "regressed"):
                before.delta(read_cgroup_snapshot(cgroup))

    def test_four_core_client_cgroup_uses_cpuset_without_cfs_quota(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "cgroup.controllers").write_text(
                "cpu cpuset memory pids\n", encoding="ascii"
            )
            (root / "cpuset.mems.effective").write_text("0\n", encoding="ascii")
            topology = LaneTopology(0, 2, (3, 4, 5, 6), (0, 1))
            server, client = LaneCgroups(root, topology).create()
            self.assertEqual((server / "cpuset.cpus").read_text(), "2")
            self.assertEqual((server / "cpu.max").read_text(), "max 100000")
            self.assertEqual((client / "cpuset.cpus").read_text(), "3,4,5,6")
            self.assertEqual((client / "cpu.max").read_text(), "max 100000")

    def test_persistent_worker_keys_receive_distinct_role_cgroup_leaves(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "cgroup.controllers").write_text(
                "cpu cpuset memory pids\n", encoding="ascii"
            )
            (root / "cpuset.mems.effective").write_text("0\n", encoding="ascii")
            groups = LaneCgroups(
                root, LaneTopology(0, 2, (3, 4), (0, 1))
            )
            fresh_server, fresh_client = groups.create()
            first = groups.create_worker("server", "ngtcp2perf/syscall")
            second = groups.create_worker("server", "quicheperf/iouring")
            repeated = groups.create_worker("server", "ngtcp2perf/syscall")
            client = groups.create_worker("client", "ngtcp2perf/iouring")
            self.assertIs(first, repeated)
            self.assertEqual(
                len({fresh_server, fresh_client, first, second, client}), 5
            )
            self.assertEqual(first.parent, second.parent)
            self.assertNotEqual(first.parent, client.parent)
            self.assertEqual((first / "cpuset.cpus").read_text(), "2")
            self.assertEqual((client / "cpuset.cpus").read_text(), "3,4")

    def test_stale_reaper_never_kills_a_live_coordinator_cgroup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = root / f"quicperf-v2-lane-0-{os.getpid()}"
            lane.mkdir()
            with self.assertRaisesRegex(LaneError, "live coordinator PID"):
                LaneCgroups.reap_stale(root)
            self.assertTrue(lane.is_dir())

    def test_process_group_term_kill_cleanup_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "endpoint"
            script.write_text(
                "#!/usr/bin/env python3\n"
                "import os, signal, subprocess, sys, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "subprocess.Popen([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            script.chmod(0o755)
            supervisor = Supervisor()
            managed = supervisor.spawn([str(script)], log_path=Path(tmp) / "endpoint.log", cwd=Path(tmp))
            time.sleep(0.05)
            started = time.monotonic()
            managed.terminate(term_seconds=0.05, kill_seconds=0.5)
            self.assertLess(time.monotonic() - started, 0.8)
            self.assertFalse(managed.alive())
            supervisor.cleanup()

    def test_parallel_lane_interrupt_cleanup_uses_one_shared_three_second_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "endpoint"
            script.write_text(
                "#!/usr/bin/env python3\n"
                "import signal,time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            script.chmod(0o755)
            supervisor = Supervisor()
            processes = [
                supervisor.spawn(
                    [str(script)],
                    log_path=Path(tmp) / f"endpoint-{index}.log",
                    cwd=Path(tmp),
                )
                for index in range(4)
            ]
            started = time.monotonic()
            _terminate_active_processes(
                {item.process.pid: item for item in processes},
                threading.Lock(),
            )
            self.assertLess(time.monotonic() - started, 3.4)
            self.assertTrue(all(not item.alive() for item in processes))
            supervisor.cleanup()

    def test_missing_binary_is_never_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(SupervisionError, "missing or nonexecutable"):
                Supervisor().spawn([str(Path(tmp) / "missing")], log_path=Path(tmp) / "log", cwd=Path(tmp))

    def test_endpoint_is_pinned_before_exec_to_exact_declared_cpu(self):
        cpu = min(os.sched_getaffinity(0))
        sleep = shutil.which("sleep")
        self.assertIsNotNone(sleep)
        with tempfile.TemporaryDirectory() as tmp, Supervisor() as supervisor:
            managed = supervisor.spawn(
                [str(sleep), "60"],
                log_path=Path(tmp) / "endpoint.log",
                cwd=Path(tmp),
                cpu_affinity=(cpu,),
            )
            allowed = next(
                line.split(":", 1)[1].strip()
                for line in Path(f"/proc/{managed.process.pid}/status").read_text().splitlines()
                if line.startswith("Cpus_allowed_list:")
            )
            self.assertEqual(allowed, str(cpu))

    def test_trace_seed_and_packet_drop_stream_are_deterministic_and_phase_separated(self):
        seed = derive_trace_seed(b"campaign", b"m" * 32, b"p" * 32)
        first = [loss_recovery_drop(seed, measurement=True, direction=0, packet_ordinal=index) for index in range(1_000)]
        second = [loss_recovery_drop(seed, measurement=True, direction=0, packet_ordinal=index) for index in range(1_000)]
        warmup = [loss_recovery_drop(seed, measurement=False, direction=0, packet_ordinal=index) for index in range(1_000)]
        self.assertEqual(first, second)
        self.assertNotEqual(first, warmup)
        self.assertGreater(sum(first), 0)

    def test_trace_must_be_armed_before_future_common_epoch(self):
        controller = LoopbackPathController()
        controller.create_session()
        controller.prepare_trial("loopback")
        now = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        trace = ArmedTrace(now + 10_000_000, b"s" * 32, (TraceTransition(0, 1, 1, 0),))
        controller.arm(trace)
        controller.cancel_arm()
        self.assertIsNone(controller.armed)
        controller.arm(trace)
        self.assertEqual(controller.apply_due(now), 0)
        self.assertEqual(controller.apply_due(now + 10_000_000), 1)
        self.assertEqual(
            controller.finish_trial(),
            {"profile": "loopback", "directions": {}},
        )
        controller.cleanup()
        self.assertFalse(controller.active)

    def test_non_loopback_profile_fails_closed_without_namespace_controller(self):
        controller = LoopbackPathController()
        controller.create_session()
        with self.assertRaisesRegex(
            PathError, "refusing to run a non-loopback treatment on loopback"
        ):
            controller.prepare_trial("loss_recovery_v1")
        controller.cleanup()

    def test_lane_allocation_enforces_physical_core_budget_and_disjointness(self):
        cores = tuple(PhysicalCore(0, index, (index, index + 16), 0) for index in range(12))
        lanes = allocate_lanes(cores, 2)
        self.assertEqual(len(lanes), 2)
        self.assertEqual(len({cpu for lane in lanes for cpu in (lane.server_cpu, *lane.client_cpus)}), 6)
        with self.assertRaises(TopologyError):
            allocate_lanes(cores[:7], 2)

        headroom = allocate_lanes(cores[:7], 1, client_cores_per_lane=4)
        self.assertEqual(len(headroom[0].client_cpus), 4)
        self.assertEqual(len(set(headroom[0].all_cpus())), 7)
        self.assertEqual(client_limits(2).cpu_max, "max 100000")
        self.assertEqual(client_limits(4).cpu_max, "max 100000")
        with self.assertRaises(TopologyError):
            allocate_lanes(cores, 1, client_cores_per_lane=3)
        with self.assertRaises(LaneError):
            client_limits(3)


if __name__ == "__main__":
    unittest.main()
