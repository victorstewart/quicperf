from __future__ import annotations

import json
import socket
import tempfile
import unittest
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from unittest import mock

from quicperf_harness.amd_stability import (
    AmdBoundarySnapshot,
    AmdContinuousMonitor,
    AmdMonitorCounterSample,
    AmdMonitorTransientError,
    AmdMonitorTemperatureSample,
    AmdProbeEvidence,
    AmdReference,
    AmdTemperatureSource,
    CONTINUOUS_MONITOR_BOUNDARY_POLICY_GUARD_NS,
    CONTINUOUS_MONITOR_BOUNDARY_SPIN_LEAD_NS,
    CONTINUOUS_MONITOR_SCHED_FIFO_PRIORITY,
    CONTINUOUS_MONITOR_SWITCH_INTERVAL_SECONDS,
    DEFAULT_POLICY_PATH,
    TEMPERATURE_WATCHDOG_COUNTER_MESSAGE,
    TEMPERATURE_WATCHDOG_COUNTER_SAMPLE,
    TEMPERATURE_WATCHDOG_MESSAGE,
    TEMPERATURE_WATCHDOG_SAMPLE,
    _continuous_monitor_wait_ns,
    _continuous_monitor_due_ns,
    _continuous_monitor_periodic_allowed,
    _continuous_temperature_reasons,
    _AmdPersistentPolicyReader,
    _write_exact,
    build_calibration_reference,
    evaluate_negative_control,
    evaluate_microblock_boundaries,
    evaluate_positive_probe,
    load_amd_provider_policy,
    read_cpu_model_and_flags,
    read_policy_readbacks,
    resolve_smt_control_cpus,
    resolve_temperature_source,
    verify_policy_readbacks,
    _AmdContinuousMonitorWorker,
)
from quicperf_harness.health import HealthError


CPU_MODEL = "AMD Ryzen 7 8845HS w/ Radeon 780M Graphics"


class AmdProviderPolicyTests(unittest.TestCase):
    @staticmethod
    def v21_policy():
        return replace(
            load_amd_provider_policy(cpu_model=CPU_MODEL),
            boundary_timestamp_semantics="observed_interval",
            interval_duration_error_max_fraction=Decimal("0.001"),
            phase_offset_max_ns=5_000_000,
            temperature_gap_max_ns=250_000_000,
        )

    def test_persistent_policy_reader_observes_live_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cpu_sysfs = Path(temporary)
            policy = cpu_sysfs / "cpufreq/policy2"
            policy.mkdir(parents=True)
            controls = {
                "affected_cpus": "2\n",
                "scaling_min_freq": "3800000\n",
                "scaling_max_freq": "3800000\n",
                "scaling_governor": "performance\n",
                "energy_performance_preference": "performance\n",
                "boost": "0\n",
            }
            for name, value in controls.items():
                (policy / name).write_text(value, encoding="ascii")
            template = read_policy_readbacks(
                (2,), cpu_sysfs=cpu_sysfs
            )
            reader = _AmdPersistentPolicyReader(
                template, cpu_sysfs=cpu_sysfs
            )
            try:
                self.assertEqual(reader.read(), template)
                (policy / "scaling_governor").write_text(
                    "powersave\n", encoding="ascii"
                )
                self.assertEqual(reader.read()[0].governor, "powersave")
            finally:
                reader.close()

    def test_continuous_monitor_preempts_priority_one_housekeeping(self) -> None:
        self.assertEqual(CONTINUOUS_MONITOR_SCHED_FIFO_PRIORITY, 51)
        self.assertEqual(CONTINUOUS_MONITOR_BOUNDARY_POLICY_GUARD_NS, 50_000_000)
        self.assertEqual(CONTINUOUS_MONITOR_BOUNDARY_SPIN_LEAD_NS, 10_000_000)

    def test_continuous_monitor_spins_before_exact_boundaries(self) -> None:
        due = 100_000_000
        self.assertEqual(_continuous_monitor_wait_ns(70_000_000, due, due), 20_000_000)
        self.assertEqual(_continuous_monitor_wait_ns(91_000_000, due, due), 0)
        self.assertEqual(
            _continuous_monitor_wait_ns(80_000_000, due, due + 1),
            20_000_000,
        )

    def test_continuous_monitor_defers_periodic_work_inside_boundary_lead(self) -> None:
        boundary = 100_000_000
        self.assertEqual(
            _continuous_monitor_due_ns(
                40_000_000, 70_000_000, 55_000_000, boundary
            ),
            50_000_000,
        )
        self.assertEqual(
            _continuous_monitor_due_ns(
                51_000_000, 70_000_000, 55_000_000, boundary
            ),
            70_000_000,
        )
        self.assertEqual(
            _continuous_monitor_due_ns(
                91_000_000, 110_000_000, 55_000_000, boundary
            ),
            boundary,
        )
        self.assertFalse(
            _continuous_monitor_periodic_allowed(
                60_000_000,
                boundary,
                CONTINUOUS_MONITOR_BOUNDARY_POLICY_GUARD_NS,
            )
        )
        self.assertTrue(
            _continuous_monitor_periodic_allowed(
                60_000_000,
                boundary,
                CONTINUOUS_MONITOR_BOUNDARY_SPIN_LEAD_NS,
            )
        )

    @staticmethod
    def evidence(
        *, duration: int = 120, ratio: float = 1.0, loop: int = 1000
    ) -> AmdProbeEvidence:
        samples = []
        aperf = mperf = 0
        for index in range(duration * 10 + 1):
            if index:
                mperf += 380_000_000
                aperf += int(380_000_000 * ratio)
            samples.append(AmdMonitorCounterSample(index * 100_000_000, aperf, mperf, 0))
        temperatures = tuple(
            AmdMonitorTemperatureSample(index * 20_000_000, 60_000, 0)
            for index in range(duration * 50 + 1)
        )
        return AmdProbeEvidence(
            start_raw_ns=0,
            end_raw_ns=duration * 1_000_000_000,
            monitor_cpu=0,
            counter_samples={2: tuple(samples)},
            temperature_samples=temperatures,
            loop_buckets={2: (loop,) * duration},
            helper_sha256="a" * 64,
        )

    def test_checked_in_allowlist_freezes_official_8845hs_contract(self) -> None:
        policy = load_amd_provider_policy(cpu_model=CPU_MODEL)
        self.assertEqual(policy.entry.product_name, "AMD Ryzen 7 8845HS")
        self.assertEqual(policy.entry.base_frequency_khz, 3_800_000)
        self.assertEqual(policy.entry.tjmax_millicelsius, 100_000)
        self.assertEqual(policy.positive_frequency_khz, 3_800_000)
        self.assertEqual(policy.negative_control_frequency_khz, 3_420_000)
        self.assertEqual(policy.measurement_ceiling_millicelsius, 80_000)
        self.assertEqual(
            policy.entry.official_source_sha256,
            "e64ce38835f11a31f236edc3eaaf2383b6591a4484fe430ef36735851f9aea43",
        )

    def test_non_allowlisted_model_and_policy_weakening_fail_closed(self) -> None:
        with self.assertRaisesRegex(HealthError, "does not allowlist"):
            load_amd_provider_policy(cpu_model="AMD Ryzen 7 8845H")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            document = json.loads(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))
            document["performance"]["active_window_ratio_minimum"] = "0.97"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(HealthError, "thresholds differ"):
                load_amd_provider_policy(cpu_model=CPU_MODEL, path=path)

    def test_cpu_records_require_one_exact_model_and_flag_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cpuinfo"
            record = (
                "processor : {cpu}\n"
                f"model name : {CPU_MODEL}\n"
                "flags : constant_tsc nonstop_tsc aperfmperf\n"
            )
            path.write_text(record.format(cpu=0) + "\n" + record.format(cpu=1), encoding="ascii")
            model, flags = read_cpu_model_and_flags(path)
            self.assertEqual(model, CPU_MODEL)
            self.assertTrue({"constant_tsc", "nonstop_tsc", "aperfmperf"}.issubset(flags))
            path.write_text(
                record.format(cpu=0) + "\n" + record.format(cpu=1).replace(" aperfmperf", ""),
                encoding="ascii",
            )
            with self.assertRaisesRegex(HealthError, "one exact model and flag set"):
                read_cpu_model_and_flags(path)

    def test_missing_temp_crit_uses_only_exact_allowlist_tjmax(self) -> None:
        policy = load_amd_provider_policy(cpu_model=CPU_MODEL)
        with tempfile.TemporaryDirectory() as temporary:
            hwmon = Path(temporary)
            device = hwmon / "hwmon3"
            device.mkdir()
            (device / "name").write_text("k10temp\n", encoding="ascii")
            (device / "temp1_label").write_text("Tctl\n", encoding="ascii")
            (device / "temp1_input").write_text("42000\n", encoding="ascii")
            source = resolve_temperature_source(policy, hwmon)
            self.assertEqual(source.tjmax_millicelsius, 100_000)
            self.assertEqual(source.tjmax_source, "exact_cpu_allowlist")
            (device / "temp1_crit").write_text("99000\n", encoding="ascii")
            with self.assertRaisesRegex(HealthError, "differs from the exact AMD allowlist"):
                resolve_temperature_source(policy, hwmon)

    def test_policy_readback_is_exact_for_every_measured_cpu(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cpu_sysfs = Path(temporary)
            policy = cpu_sysfs / "cpufreq/policy2"
            policy.mkdir(parents=True)
            for name, value in {
                "affected_cpus": "2 10\n",
                "scaling_min_freq": "3800000\n",
                "scaling_max_freq": "3800000\n",
                "scaling_governor": "performance\n",
                "energy_performance_preference": "performance\n",
                "boost": "0\n",
            }.items():
                (policy / name).write_text(value, encoding="ascii")
            readbacks = read_policy_readbacks((2, 10), cpu_sysfs)
            verify_policy_readbacks(readbacks, expected_frequency_khz=3_800_000)
            (policy / "scaling_max_freq").write_text("3801000\n", encoding="ascii")
            with self.assertRaisesRegex(HealthError, "frequency readback differs"):
                verify_policy_readbacks(
                    read_policy_readbacks((2, 10), cpu_sysfs),
                    expected_frequency_khz=3_800_000,
                )

    def test_smt_policy_expansion_controls_every_thread_of_each_measured_core(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cpu_sysfs = Path(temporary)
            for cpu, siblings in ((2, "2,10"), (3, "3,11"), (10, "2,10")):
                topology = cpu_sysfs / f"cpu{cpu}/topology"
                topology.mkdir(parents=True)
                (topology / "thread_siblings_list").write_text(
                    siblings + "\n", encoding="ascii"
                )
            self.assertEqual(
                resolve_smt_control_cpus((2, 3), cpu_sysfs),
                (2, 3, 10, 11),
            )
            with self.assertRaisesRegex(HealthError, "share a physical core"):
                resolve_smt_control_cpus((2, 10), cpu_sysfs)

    def test_policy_write_waits_for_delayed_sysfs_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "control"
            path.write_text("old\n", encoding="ascii")
            with (
                mock.patch.object(Path, "read_text", side_effect=("old", "new")),
                mock.patch(
                    "quicperf_harness.amd_stability.time.monotonic",
                    return_value=0.0,
                ),
                mock.patch(
                    "quicperf_harness.amd_stability.time.sleep"
                ) as sleep,
            ):
                _write_exact(path, "new")
            sleep.assert_called_once_with(0.01)

    def test_calibration_and_positive_probe_enforce_every_frozen_gate(self) -> None:
        policy = load_amd_provider_policy(cpu_model=CPU_MODEL)
        evidence = self.evidence()
        reference = build_calibration_reference(evidence, policy)
        decision = evaluate_positive_probe(
            evidence,
            policy,
            reference,
            evaluation_start_second=30,
            active_windows_minimum=850,
        )
        self.assertTrue(decision.passed, decision.reasons)
        self.assertEqual(decision.active_windows[2], 900)

        counters = list(evidence.counter_samples[2])
        sample = counters[501]
        counters[501] = AmdMonitorCounterSample(
            sample.raw_ns,
            counters[500].aperf + int(0.97 * (sample.mperf - counters[500].mperf)),
            sample.mperf,
            sample.monitor_cpu,
        )
        breached = AmdProbeEvidence(
            **{
                **evidence.__dict__,
                "counter_samples": {2: tuple(counters)},
            }
        )
        decision = evaluate_positive_probe(
            breached,
            policy,
            reference,
            evaluation_start_second=30,
            active_windows_minimum=850,
        )
        self.assertFalse(decision.passed)
        self.assertIn("cpu2_active_window_below_98_percent", decision.reasons)

    def test_negative_control_requires_ratio_and_loop_detection_per_core(self) -> None:
        policy = load_amd_provider_policy(cpu_model=CPU_MODEL)
        positive = self.evidence()
        reference = build_calibration_reference(positive, policy)
        negative = self.evidence(duration=2, ratio=0.9, loop=900)
        passed, reasons = evaluate_negative_control(negative, policy, reference)
        self.assertTrue(passed, reasons)
        loop_only_failure = self.evidence(duration=2, ratio=0.9, loop=1000)
        passed, reasons = evaluate_negative_control(loop_only_failure, policy, reference)
        self.assertFalse(passed)
        self.assertIn("cpu2_negative_loop_control_not_detected", reasons)

    def test_exact_microblock_boundaries_enforce_ratio_tctl_and_cgroup_counters(self) -> None:
        policy = load_amd_provider_policy(cpu_model=CPU_MODEL)
        reference = AmdReference({2: 1.0}, {2: 1000.0})
        start = AmdBoundarySnapshot(
            "trial:start",
            1_000_000_000,
            1_000_000_000,
            0,
            {2: (0, 0)},
            60_000,
            {"/lane/server": (4, 20)},
        )
        end = AmdBoundarySnapshot(
            "trial:end",
            2_000_000_000,
            2_000_000_000,
            0,
            {2: (3_800_000_000, 3_800_000_000)},
            61_000,
            {"/lane/server": (4, 20)},
        )
        passing = evaluate_microblock_boundaries(
            start,
            end,
            duration_ns=1_000_000_000,
            policy=policy,
            reference=reference,
        )
        self.assertTrue(passing.passed, passing.reasons)
        self.assertEqual(passing.active_cpus, (2,))
        self.assertEqual(passing.start_lateness_ns, 0)
        self.assertEqual(passing.end_lateness_ns, 0)

        throttled = AmdBoundarySnapshot(
            **{
                **end.__dict__,
                "cgroup_throttling": {"/lane/server": (5, 21)},
            }
        )
        failed = evaluate_microblock_boundaries(
            start,
            throttled,
            duration_ns=1_000_000_000,
            policy=policy,
            reference=reference,
        )
        self.assertIn(
            "cgroup_cpu_throttling_detected:/lane/server", failed.reasons
        )

        late = AmdBoundarySnapshot(
            **{**end.__dict__, "observed_raw_ns": end.target_raw_ns + 1_000_001}
        )
        failed = evaluate_microblock_boundaries(
            start,
            late,
            duration_ns=1_000_000_000,
            policy=policy,
            reference=reference,
        )
        self.assertIn("microblock_boundary_monitor_error", failed.reasons)

    def test_v21_boundary_uses_observed_interval_with_separate_phase_and_duration_bounds(
        self,
    ) -> None:
        policy = self.v21_policy()
        reference = AmdReference({2: 1.0}, {2: 1000.0})
        start = AmdBoundarySnapshot(
            "trial:start",
            1_000_000_000,
            999_000_000,
            0,
            {2: (0, 0)},
            60_000,
            {"/lane/server": (0, 0)},
        )
        end = AmdBoundarySnapshot(
            "trial:end",
            3_000_000_000,
            3_001_000_000,
            0,
            {2: (7_600_000_000, 7_600_000_000)},
            61_000,
            {"/lane/server": (0, 0)},
        )
        exact_bound = evaluate_microblock_boundaries(
            start,
            end,
            duration_ns=2_000_000_000,
            policy=policy,
            reference=reference,
        )
        self.assertTrue(exact_bound.passed, exact_bound.reasons)
        self.assertEqual(exact_bound.target_interval_ns, 2_000_000_000)
        self.assertEqual(exact_bound.observed_interval_ns, 2_002_000_000)
        self.assertEqual(exact_bound.interval_duration_error_ns, 2_000_000)

        phase_failure = evaluate_microblock_boundaries(
            start,
            AmdBoundarySnapshot(
                **{
                    **end.__dict__,
                    "observed_raw_ns": end.target_raw_ns + 5_000_001,
                }
            ),
            duration_ns=2_000_000_000,
            policy=policy,
            reference=reference,
        )
        self.assertIn(
            "microblock_boundary_phase_offset_exceeded",
            phase_failure.reasons,
        )

        duration_failure = evaluate_microblock_boundaries(
            start,
            AmdBoundarySnapshot(
                **{
                    **end.__dict__,
                    "observed_raw_ns": end.target_raw_ns + 1_000_001,
                }
            ),
            duration_ns=2_000_000_000,
            policy=policy,
            reference=reference,
        )
        self.assertNotIn(
            "microblock_boundary_phase_offset_exceeded",
            duration_failure.reasons,
        )
        self.assertIn(
            "microblock_boundary_interval_duration_error_exceeded",
            duration_failure.reasons,
        )

    def test_v21_activity_threshold_uses_actual_observed_interval(self) -> None:
        policy = self.v21_policy()
        reference = AmdReference({2: 1.0}, {2: 1000.0})
        start = AmdBoundarySnapshot(
            "trial:start",
            1_000_000_000,
            1_000_000_000,
            0,
            {2: (0, 0)},
            60_000,
            {"/lane/server": (0, 0)},
        )
        end = AmdBoundarySnapshot(
            "trial:end",
            2_000_000_000,
            2_001_000_000,
            0,
            {2: (190_000_000, 190_000_000)},
            60_000,
            {"/lane/server": (0, 0)},
        )
        evaluation = evaluate_microblock_boundaries(
            start,
            end,
            duration_ns=1_000_000_000,
            policy=policy,
            reference=reference,
        )
        self.assertTrue(evaluation.passed, evaluation.reasons)
        self.assertEqual(evaluation.active_cpus, ())

    def test_v21_keeps_thermal_and_throttling_gates_hard(self) -> None:
        policy = self.v21_policy()
        reference = AmdReference({2: 1.0}, {2: 1000.0})
        start = AmdBoundarySnapshot(
            "trial:start",
            1_000_000_000,
            1_000_000_000,
            0,
            {2: (0, 0)},
            60_000,
            {"/lane/server": (4, 20)},
        )
        end = AmdBoundarySnapshot(
            "trial:end",
            2_000_000_000,
            2_000_000_000,
            0,
            {2: (3_800_000_000, 3_800_000_000)},
            80_000,
            {"/lane/server": (5, 21)},
        )
        evaluation = evaluate_microblock_boundaries(
            start,
            end,
            duration_ns=1_000_000_000,
            policy=policy,
            reference=reference,
        )
        self.assertIn("microblock_tctl_thermal_headroom_breach", evaluation.reasons)
        self.assertIn(
            "cgroup_cpu_throttling_detected:/lane/server",
            evaluation.reasons,
        )

    def test_continuous_monitor_preserves_typed_transient_classification(self) -> None:
        policy = load_amd_provider_policy(cpu_model=CPU_MODEL)
        monitor = _AmdContinuousMonitorWorker(
            cpus=(2,),
            housekeeping_cpu=0,
            spin_helper=Path("/unused-spin.so"),
            policy=policy,
            reference=AmdReference({2: 1.0}, {2: 1000.0}),
            temperature_source=AmdTemperatureSource(
                Path("/unused"), 100_000, "exact_cpu_allowlist"
            ),
        )
        monitor._thread = mock.Mock()
        monitor._thread.is_alive.return_value = False
        monitor._error = AmdMonitorTransientError(
            "Tctl sampling cadence dropped out"
        )
        monitor._start_raw_ns = 0
        monitor._end_raw_ns = 100_000_000
        monitor._watchdog_counter_samples[2] = [
            AmdMonitorCounterSample(0, 0, 0, 0),
            AmdMonitorCounterSample(100_000_000, 380_000_000, 380_000_000, 0),
        ]
        monitor._temperature_samples = [
            AmdMonitorTemperatureSample(0, 60_000, 0),
            AmdMonitorTemperatureSample(20_000_000, 60_000, 0),
        ]
        evidence = monitor.stop()
        self.assertFalse(evidence["passed"])
        self.assertEqual(
            evidence["monitor_error"],
            {
                "type": "AmdMonitorTransientError",
                "message": "Tctl sampling cadence dropped out",
                "treatment_independent_transient": True,
            },
        )

    def test_temperature_watchdog_uses_only_reserved_monitor_sibling(self) -> None:
        monitor = _AmdContinuousMonitorWorker(
            cpus=(2,),
            housekeeping_cpu=7,
            spin_helper=Path("/unused-spin.so"),
            policy=load_amd_provider_policy(cpu_model=CPU_MODEL),
            reference=AmdReference({2: 1.0}, {2: 1000.0}),
            temperature_source=AmdTemperatureSource(
                Path("/unused"), 100_000, "exact_cpu_allowlist"
            ),
        )
        with mock.patch(
            "quicperf_harness.amd_stability.resolve_smt_control_cpus",
            return_value=(7, 15),
        ):
            self.assertEqual(monitor._temperature_watchdog_cpu(), 15)
        with mock.patch(
            "quicperf_harness.amd_stability.resolve_smt_control_cpus",
            return_value=(2, 7),
        ):
            with self.assertRaisesRegex(HealthError, "reserved SMT sibling"):
                monitor._temperature_watchdog_cpu()

    def test_process_watchdog_sample_satisfies_combined_tctl_cadence(self) -> None:
        monitor = _AmdContinuousMonitorWorker(
            cpus=(2,),
            housekeeping_cpu=7,
            spin_helper=Path("/unused-spin.so"),
            policy=load_amd_provider_policy(cpu_model=CPU_MODEL),
            reference=AmdReference({2: 1.0}, {2: 1000.0}),
            temperature_source=AmdTemperatureSource(
                Path("/unused"), 100_000, "exact_cpu_allowlist"
            ),
        )
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        monitor._temperature_socket = parent
        monitor._temperature_process = mock.Mock()
        monitor._temperature_process.poll.return_value = None
        monitor._temperature_watchdog_expected_cpu = 15
        monitor._temperature_fd = 123
        monitor._temperature_samples.append(
            AmdMonitorTemperatureSample(1_000_000, 60_000, 7)
        )
        child.send(
            TEMPERATURE_WATCHDOG_MESSAGE.pack(
                TEMPERATURE_WATCHDOG_SAMPLE,
                0,
                40_000_000,
                60_000,
                15,
            )
        )
        try:
            with (
                mock.patch(
                    "quicperf_harness.amd_stability.os.pread",
                    return_value=b"60000\n",
                ),
                mock.patch(
                    "quicperf_harness.amd_stability.time.clock_gettime_ns",
                    return_value=80_000_000,
                ),
            ):
                self.assertEqual(
                    monitor._sample_temperature(7), (60_000, 80_000_000)
                )
            self.assertEqual(
                monitor._watchdog_temperature_samples,
                [AmdMonitorTemperatureSample(40_000_000, 60_000, 15)],
            )
        finally:
            parent.close()
            child.close()
            monitor._temperature_socket = None
            monitor._temperature_process = None

    def test_combined_tctl_cadence_still_fails_when_both_paths_drop(self) -> None:
        monitor = _AmdContinuousMonitorWorker(
            cpus=(2,),
            housekeeping_cpu=7,
            spin_helper=Path("/unused-spin.so"),
            policy=load_amd_provider_policy(cpu_model=CPU_MODEL),
            reference=AmdReference({2: 1.0}, {2: 1000.0}),
            temperature_source=AmdTemperatureSource(
                Path("/unused"), 100_000, "exact_cpu_allowlist"
            ),
        )
        monitor._temperature_fd = 123
        monitor._temperature_samples.append(
            AmdMonitorTemperatureSample(1_000_000, 60_000, 7)
        )
        monitor._watchdog_temperature_samples.append(
            AmdMonitorTemperatureSample(40_000_000, 60_000, 15)
        )
        with (
            mock.patch(
                "quicperf_harness.amd_stability.os.pread",
                return_value=b"60000\n",
            ),
            mock.patch(
                "quicperf_harness.amd_stability.time.clock_gettime_ns",
                return_value=100_000_001,
            ),
        ):
            monitor._sample_temperature(7)
        self.assertEqual(
            _continuous_temperature_reasons(
                monitor._temperature_samples
                + monitor._watchdog_temperature_samples,
                start_raw_ns=1_000_000,
                end_raw_ns=100_000_001,
                policy=monitor.policy,
            ),
            ("tctl_monitor_dropout",),
        )

    def test_v21_combined_tctl_cadence_accepts_250_ms_and_rejects_more(
        self,
    ) -> None:
        policy = self.v21_policy()
        self.assertEqual(
            _continuous_temperature_reasons(
                (
                    AmdMonitorTemperatureSample(1, 60_000, 15),
                    AmdMonitorTemperatureSample(250_000_001, 60_000, 7),
                ),
                start_raw_ns=1,
                end_raw_ns=250_000_001,
                policy=policy,
            ),
            (),
        )
        self.assertEqual(
            _continuous_temperature_reasons(
                (
                    AmdMonitorTemperatureSample(1, 60_000, 15),
                    AmdMonitorTemperatureSample(250_000_002, 60_000, 7),
                ),
                start_raw_ns=1,
                end_raw_ns=250_000_002,
                policy=policy,
            ),
            ("tctl_monitor_dropout",),
        )
        self.assertEqual(
            _continuous_temperature_reasons(
                (AmdMonitorTemperatureSample(1, 80_000, 15),),
                start_raw_ns=1,
                end_raw_ns=1,
                policy=policy,
            ),
            ("tctl_thermal_headroom_breach",),
        )

    def test_delayed_watchdog_delivery_uses_observed_sample_timestamps(self) -> None:
        monitor = _AmdContinuousMonitorWorker(
            cpus=(2,),
            housekeeping_cpu=7,
            spin_helper=Path("/unused-spin.so"),
            policy=self.v21_policy(),
            reference=AmdReference({2: 1.0}, {2: 1000.0}),
            temperature_source=AmdTemperatureSource(
                Path("/unused"), 100_000, "exact_cpu_allowlist"
            ),
        )
        monitor._temperature_fd = 123
        monitor._watchdog_temperature_samples.append(
            AmdMonitorTemperatureSample(1_000_000, 60_000, 15)
        )
        with (
            mock.patch(
                "quicperf_harness.amd_stability.os.pread",
                return_value=b"60000\n",
            ),
            mock.patch(
                "quicperf_harness.amd_stability.time.clock_gettime_ns",
                return_value=388_843_362,
            ),
        ):
            self.assertEqual(
                monitor._sample_temperature(7), (60_000, 388_843_362)
            )
        monitor._watchdog_temperature_samples.extend(
            AmdMonitorTemperatureSample(raw_ns, 60_000, 15)
            for raw_ns in range(21_000_000, 388_000_000, 20_000_000)
        )
        self.assertEqual(
            _continuous_temperature_reasons(
                monitor._temperature_samples
                + monitor._watchdog_temperature_samples,
                start_raw_ns=1_000_000,
                end_raw_ns=388_843_362,
                policy=monitor.policy,
            ),
            (),
        )

    def test_process_watchdog_owns_continuous_counter_cadence(self) -> None:
        monitor = _AmdContinuousMonitorWorker(
            cpus=(2,),
            housekeeping_cpu=0,
            spin_helper=Path("/unused-spin.so"),
            policy=load_amd_provider_policy(cpu_model=CPU_MODEL),
            reference=AmdReference({2: 1.0}, {2: 1000.0}),
            temperature_source=AmdTemperatureSource(
                Path("/unused"), 100_000, "exact_cpu_allowlist"
            ),
        )
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        monitor._temperature_socket = parent
        monitor._temperature_process = mock.Mock()
        monitor._temperature_process.poll.return_value = None
        monitor._temperature_watchdog_expected_cpu = 15
        child.send(
            TEMPERATURE_WATCHDOG_COUNTER_MESSAGE.pack(
                TEMPERATURE_WATCHDOG_COUNTER_SAMPLE,
                0,
                1_000_000,
                1,
                1,
                2,
            )
        )
        child.send(
            TEMPERATURE_WATCHDOG_COUNTER_MESSAGE.pack(
                TEMPERATURE_WATCHDOG_COUNTER_SAMPLE,
                1,
                151_000_000,
                570_000_001,
                570_000_001,
                2,
            )
        )
        try:
            with mock.patch(
                "quicperf_harness.amd_stability.time.clock_gettime_ns",
                return_value=200_000_000,
            ):
                monitor._drain_temperature_watchdog()
            self.assertEqual(
                monitor._watchdog_counter_samples[2],
                [
                    AmdMonitorCounterSample(1_000_000, 1, 1, 15),
                    AmdMonitorCounterSample(
                        151_000_000,
                        570_000_001,
                        570_000_001,
                        15,
                    ),
                ],
            )
        finally:
            parent.close()
            child.close()
            monitor._temperature_socket = None
            monitor._temperature_process = None

    def test_process_watchdog_counter_dropout_remains_replayable(self) -> None:
        monitor = _AmdContinuousMonitorWorker(
            cpus=(2,),
            housekeeping_cpu=7,
            spin_helper=Path("/unused-spin.so"),
            policy=load_amd_provider_policy(cpu_model=CPU_MODEL),
            reference=AmdReference({2: 1.0}, {2: 1000.0}),
            temperature_source=AmdTemperatureSource(
                Path("/unused"), 100_000, "exact_cpu_allowlist"
            ),
        )
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        monitor._temperature_socket = parent
        monitor._temperature_process = mock.Mock()
        monitor._temperature_process.poll.return_value = None
        monitor._temperature_watchdog_expected_cpu = 15
        for sequence, raw_ns in ((0, 1_000_000), (1, 201_000_001)):
            child.send(
                TEMPERATURE_WATCHDOG_COUNTER_MESSAGE.pack(
                    TEMPERATURE_WATCHDOG_COUNTER_SAMPLE,
                    sequence,
                    raw_ns,
                    sequence + 1,
                    sequence + 1,
                    2,
                )
            )
        try:
            with mock.patch(
                "quicperf_harness.amd_stability.time.clock_gettime_ns",
                return_value=300_000_000,
            ):
                monitor._drain_temperature_watchdog()
            self.assertIsInstance(monitor._error, AmdMonitorTransientError)
            self.assertIn("gap_ns=200000001", str(monitor._error))
        finally:
            parent.close()
            child.close()
            monitor._temperature_socket = None
            monitor._temperature_process = None

    def test_continuous_monitor_schedule_surfaces_stored_typed_error(self) -> None:
        monitor = _AmdContinuousMonitorWorker(
            cpus=(2,),
            housekeeping_cpu=0,
            spin_helper=Path("/unused-spin.so"),
            policy=load_amd_provider_policy(cpu_model=CPU_MODEL),
            reference=AmdReference({2: 1.0}, {2: 1000.0}),
            temperature_source=AmdTemperatureSource(
                Path("/unused"), 100_000, "exact_cpu_allowlist"
            ),
        )
        monitor._error = AmdMonitorTransientError(
            "injected cadence dropout"
        )
        with self.assertRaisesRegex(
            AmdMonitorTransientError, "injected cadence dropout"
        ):
            monitor.schedule_interval(
                "token",
                100_000_000,
                200_000_000,
                cgroup_paths=(Path("/lane"),),
            )

    def test_continuous_monitor_cancels_only_unobserved_boundary_pair(self) -> None:
        monitor = _AmdContinuousMonitorWorker(
            cpus=(2,),
            housekeeping_cpu=0,
            spin_helper=Path("/unused-spin.so"),
            policy=load_amd_provider_policy(cpu_model=CPU_MODEL),
            reference=AmdReference({2: 1.0}, {2: 1000.0}),
            temperature_source=AmdTemperatureSource(
                Path("/unused"), 100_000, "exact_cpu_allowlist"
            ),
        )
        monitor._thread = mock.Mock()
        with mock.patch(
            "quicperf_harness.amd_stability.time.clock_gettime_ns",
            return_value=1_000_000,
        ):
            monitor.schedule_interval(
                "token",
                100_000_000,
                200_000_000,
                cgroup_paths=(Path("/lane"),),
            )
            monitor.cancel_interval("token")
        self.assertEqual(monitor._pending, [])
        self.assertEqual(monitor._boundary_events, {})
        self.assertEqual(monitor._boundary_cgroups, {})
        with self.assertRaisesRegex(HealthError, "cannot be cancelled"):
            monitor.cancel_interval("token")

    def test_continuous_monitor_restores_switch_interval_after_start_error(self) -> None:
        monitor = _AmdContinuousMonitorWorker(
            cpus=(2,),
            housekeeping_cpu=0,
            spin_helper=Path("/unused-spin.so"),
            policy=load_amd_provider_policy(cpu_model=CPU_MODEL),
            reference=AmdReference({2: 1.0}, {2: 1000.0}),
            temperature_source=AmdTemperatureSource(
                Path("/unused"), 100_000, "exact_cpu_allowlist"
            ),
        )

        def fail_start() -> None:
            monitor._error = HealthError("injected start failure")
            monitor._started.set()

        with (
            mock.patch.object(monitor, "_run", side_effect=fail_start),
            mock.patch(
                "quicperf_harness.amd_stability.sys.getswitchinterval",
                return_value=0.005,
            ),
            mock.patch(
                "quicperf_harness.amd_stability.sys.setswitchinterval"
            ) as set_interval,
        ):
            with self.assertRaisesRegex(HealthError, "injected start failure"):
                monitor.start()
        self.assertEqual(
            set_interval.call_args_list,
            [
                mock.call(CONTINUOUS_MONITOR_SWITCH_INTERVAL_SECONDS),
                mock.call(0.005),
            ],
        )


if __name__ == "__main__":
    unittest.main()
