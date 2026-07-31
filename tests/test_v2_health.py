from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from quicperf_harness.health import (
    AmdCounterSample,
    AmdPerfCounterReader,
    AmdTemperatureSample,
    HealthError,
    HealthSummary,
    LaneHealthMonitor,
    PerCpuNonOwnedClock,
    TrialLaneHealth,
    amd_k10temp_sources,
    evaluate_amd_delivered_performance,
    read_device_irq_counts,
    read_frequency_hz,
    swap_is_disabled,
    thermal_counter_paths,
)


class HealthTelemetryTests(unittest.TestCase):
    def test_trial_health_prepares_monitor_before_exact_interval_boundary(self) -> None:
        events: list[str] = []

        class Clock:
            def arm(self, server: Path, client: Path) -> None:
                self.assert_paths = (server, client)
                events.append("scheduler_arm")

            def close(self) -> None:
                pass

        class Monitor:
            def start(self) -> None:
                events.append("monitor_start")

            def stop(self) -> HealthSummary:
                return HealthSummary(3_800_000_000, 3_800_000_000, 0, False, 1)

        health = TrialLaneHealth(
            server_cpu=2,
            client_cpus=(4, 6),
            server_cgroup=Path("/server"),
            client_cgroup=Path("/client"),
            external_thermal_provider=True,
        )
        health._non_owned_clock = Clock()  # type: ignore[assignment]

        def clock_gettime_ns(_clock: int) -> int:
            events.append("clock")
            return 9_000_000

        with (
            mock.patch("quicperf_harness.health.LaneHealthMonitor", return_value=Monitor()),
            mock.patch.object(
                TrialLaneHealth,
                "_set_endpoints_frozen",
                side_effect=lambda frozen: events.append(f"frozen_{int(frozen)}"),
            ),
            mock.patch(
                "quicperf_harness.health.time.clock_gettime_ns",
                side_effect=clock_gettime_ns,
            ),
            mock.patch(
                "quicperf_harness.health.read_device_irq_counts",
                side_effect=lambda _cpus, _path: (
                    events.append("irq_baseline")
                    or {2: {55: 0}, 4: {55: 0}, 6: {55: 0}}
                ),
            ),
        ):
            health.arm(10_000_000)

        self.assertEqual(
            events,
            [
                "monitor_start",
                "frozen_1",
                "irq_baseline",
                "scheduler_arm",
                "frozen_0",
                "clock",
            ],
        )
        self.assertEqual(health._started_raw_ns, 10_000_000)
        health.close()

    def test_trial_health_rejects_baselines_completed_after_boundary(self) -> None:
        class Monitor:
            def start(self) -> None:
                pass

            def stop(self) -> HealthSummary:
                return HealthSummary(0, 1, 1, False, 1)

        with (
            mock.patch("quicperf_harness.health.LaneHealthMonitor", return_value=Monitor()),
            mock.patch.object(TrialLaneHealth, "_set_endpoints_frozen"),
            mock.patch(
                "quicperf_harness.health.time.clock_gettime_ns",
                return_value=10_000_001,
            ),
            mock.patch(
                "quicperf_harness.health.read_device_irq_counts",
                return_value={2: {}, 4: {}, 6: {}},
            ),
        ):
            health = TrialLaneHealth(
                server_cpu=2,
                client_cpus=(4, 6),
                server_cgroup=Path("/server"),
                client_cgroup=Path("/client"),
                external_thermal_provider=True,
            )
            health._non_owned_clock = mock.Mock()
            with self.assertRaisesRegex(
                HealthError, "baselines completed after interval start"
            ):
                health.arm(10_000_000)
            health.close()

    def test_amd_source_discovery_requires_tctl_critical_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            device = root / "hwmon3"
            device.mkdir()
            (device / "name").write_text("k10temp\n", encoding="ascii")
            (device / "temp1_label").write_text("Tctl\n", encoding="ascii")
            (device / "temp1_input").write_text("42000\n", encoding="ascii")
            with self.assertRaisesRegex(HealthError, "critical-temperature metadata"):
                amd_k10temp_sources(root)
            (device / "temp1_crit").write_text("100000\n", encoding="ascii")
            self.assertEqual(
                amd_k10temp_sources(root),
                ((device / "temp1_input").resolve(), (device / "temp1_crit").resolve()),
            )

    def test_amd_perf_reader_uses_one_nonmultiplexed_group_per_cpu(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event_source = Path(temporary)
            (event_source / "events").mkdir()
            (event_source / "type").write_text("13\n", encoding="ascii")
            (event_source / "events/aperf").write_text(
                "event=0x01\n", encoding="ascii"
            )
            (event_source / "events/mperf").write_text(
                "event=0x02\n", encoding="ascii"
            )
            opens: list[tuple[int, int, int, bool]] = []

            def perf_event_open(
                attributes: object, *, cpu: int, group_fd: int
            ) -> int:
                descriptor = 10 + len(opens)
                opens.append(
                    (
                        cpu,
                        attributes.config,  # type: ignore[attr-defined]
                        group_fd,
                        bool(attributes.flags & 1),  # type: ignore[attr-defined]
                    )
                )
                return descriptor

            payloads = (
                struct.pack("=7Q", 2, 100, 100, 456, 1010, 123, 1011),
                struct.pack("=7Q", 2, 200, 200, 1456, 1010, 1123, 1011),
            )
            with (
                mock.patch(
                    "quicperf_harness.health._perf_event_open",
                    side_effect=perf_event_open,
                ),
                mock.patch(
                    "quicperf_harness.health._perf_event_id",
                    side_effect=lambda descriptor: descriptor + 1000,
                ),
                mock.patch("quicperf_harness.health.fcntl.ioctl"),
                mock.patch(
                    "quicperf_harness.health.os.read", side_effect=payloads
                ),
                mock.patch("quicperf_harness.health.os.close") as close,
            ):
                with AmdPerfCounterReader((2,), event_source) as reader:
                    self.assertEqual(reader.read(), {2: (456, 123)})
                    self.assertEqual(reader.read(), {2: (1456, 1123)})

            self.assertEqual(opens, [(2, 1, -1, True), (2, 2, 10, False)])
            self.assertEqual(close.call_args_list, [mock.call(11), mock.call(10)])

    def test_amd_perf_reader_rejects_multiplexing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event_source = Path(temporary)
            (event_source / "events").mkdir()
            (event_source / "type").write_text("13\n", encoding="ascii")
            (event_source / "events/aperf").write_text(
                "event=0x01\n", encoding="ascii"
            )
            (event_source / "events/mperf").write_text(
                "event=0x02\n", encoding="ascii"
            )
            with (
                mock.patch(
                    "quicperf_harness.health._perf_event_open",
                    side_effect=(10, 11),
                ),
                mock.patch(
                    "quicperf_harness.health._perf_event_id",
                    side_effect=(1010, 1011),
                ),
                mock.patch("quicperf_harness.health.fcntl.ioctl"),
                mock.patch(
                    "quicperf_harness.health.os.read",
                    return_value=struct.pack(
                        "=7Q", 2, 100, 99, 456, 1010, 123, 1011
                    ),
                ),
                mock.patch("quicperf_harness.health.os.close"),
            ):
                with AmdPerfCounterReader((2,), event_source) as reader:
                    with self.assertRaisesRegex(HealthError, "was multiplexed"):
                        reader.read()

    def test_amd_delivered_performance_pass_and_negative_controls(self) -> None:
        counters = {
            2: (
                AmdCounterSample(0, 1_000, 1_000),
                AmdCounterSample(100_000_000, 2_000, 2_000),
            )
        }
        temperatures = tuple(
            AmdTemperatureSample(index * 20_000_000, 60_000)
            for index in range(6)
        )
        passing = evaluate_amd_delivered_performance(
            counter_samples=counters,
            active_windows={2: (True,)},
            cool_reference_ratios={2: 1.0},
            temperature_samples=temperatures,
            critical_millicelsius=100_000,
        )
        self.assertTrue(passing.passed, passing.reasons)
        self.assertEqual(passing.aggregate_fraction_of_reference, 1.0)

        clamped = evaluate_amd_delivered_performance(
            counter_samples={
                2: (
                    AmdCounterSample(0, 1_000, 1_000),
                    AmdCounterSample(100_000_000, 1_900, 2_000),
                )
            },
            active_windows={2: (True,)},
            cool_reference_ratios={2: 1.0},
            temperature_samples=temperatures,
            critical_millicelsius=100_000,
        )
        self.assertFalse(clamped.passed)
        self.assertIn("cpu2_active_window_below_98_percent", clamped.reasons)
        self.assertIn("aggregate_delivered_performance_below_99_percent", clamped.reasons)

        dropout = evaluate_amd_delivered_performance(
            counter_samples=counters,
            active_windows={2: (True,)},
            cool_reference_ratios={2: 1.0},
            temperature_samples=(temperatures[0], temperatures[3]),
            critical_millicelsius=100_000,
        )
        self.assertIn("tctl_sampling_dropout", dropout.reasons)

        hot = evaluate_amd_delivered_performance(
            counter_samples=counters,
            active_windows={2: (True,)},
            cool_reference_ratios={2: 1.0},
            temperature_samples=(AmdTemperatureSample(0, 80_000),),
            critical_millicelsius=100_000,
        )
        self.assertIn("tctl_thermal_headroom_breach", hot.reasons)

        discontinuity = evaluate_amd_delivered_performance(
            counter_samples={
                2: (
                    AmdCounterSample(0, 2_000, 2_000),
                    AmdCounterSample(100_000_000, 1_000, 1_000),
                )
            },
            active_windows={2: (True,)},
            cool_reference_ratios={2: 1.0},
            temperature_samples=temperatures,
            critical_millicelsius=100_000,
        )
        self.assertIn("cpu2_counter_discontinuity", discontinuity.reasons)

    def test_proc_interrupts_reads_numeric_device_irqs_by_cpu(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "interrupts"
            path.write_text(
                "           CPU0       CPU1       CPU2       CPU3\n"
                "  7:          1          2          3          4  IR-IO-APIC  7-fasteoi timer\n"
                " 55:         10         20         30         40  PCI-MSIX nvme0q1\n"
                " NMI:         9          9          9          9  Non-maskable interrupts\n",
                encoding="ascii",
            )
            self.assertEqual(
                read_device_irq_counts((3, 1), path),
                {1: {7: 2, 55: 20}, 3: {7: 4, 55: 40}},
            )
            with self.assertRaisesRegex(HealthError, "missing interrupt CPU"):
                read_device_irq_counts((4,), path)

    def test_frequency_thermal_and_swap_sources_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sys_cpu = root / "cpu"
            for cpu, frequency in ((2, 2_100_000), (7, 3_200_000)):
                cpufreq = sys_cpu / f"cpu{cpu}" / "cpufreq"
                cpufreq.mkdir(parents=True)
                (cpufreq / "scaling_cur_freq").write_text(str(frequency), encoding="ascii")
                thermal = sys_cpu / f"cpu{cpu}" / "thermal_throttle"
                thermal.mkdir()
                (thermal / "core_throttle_count").write_text("0", encoding="ascii")
            self.assertEqual(
                read_frequency_hz((2, 7), sys_cpu),
                {2: 2_100_000_000, 7: 3_200_000_000},
            )
            self.assertEqual(len(thermal_counter_paths((2, 7), sys_cpu)), 2)
            swaps = root / "swaps"
            swaps.write_text("Filename Type Size Used Priority\n", encoding="utf-8")
            self.assertTrue(swap_is_disabled(swaps))
            swaps.write_text(
                "Filename Type Size Used Priority\n/swap file 1 0 -2\n",
                encoding="utf-8",
            )
            self.assertFalse(swap_is_disabled(swaps))
            with self.assertRaisesRegex(HealthError, "no current-frequency"):
                read_frequency_hz((3,), sys_cpu)

    def test_monitor_records_extrema_and_thermal_delta(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sys_cpu = root / "cpu"
            cpufreq = sys_cpu / "cpu2" / "cpufreq"
            cpufreq.mkdir(parents=True)
            frequency = cpufreq / "scaling_cur_freq"
            frequency.write_text("2100000", encoding="ascii")
            thermal_dir = sys_cpu / "cpu2" / "thermal_throttle"
            thermal_dir.mkdir()
            thermal = thermal_dir / "core_throttle_count"
            thermal.write_text("4", encoding="ascii")
            swaps = root / "swaps"
            swaps.write_text("Filename Type Size Used Priority\n", encoding="utf-8")
            monitor = LaneHealthMonitor(
                (2,), interval_seconds=0.001, sys_cpu=sys_cpu, proc_swaps=swaps
            )
            monitor.start()
            replacement = frequency.with_suffix(".new")
            replacement.write_text("1900000", encoding="ascii")
            os.replace(replacement, frequency)
            replacement = thermal.with_suffix(".new")
            replacement.write_text("5", encoding="ascii")
            os.replace(replacement, thermal)
            summary = monitor.stop()
            self.assertEqual(summary.frequency_min_hz, 1_900_000_000)
            self.assertEqual(summary.frequency_max_hz, 2_100_000_000)
            self.assertEqual(summary.thermal_throttle_delta, 1)

    def test_external_thermal_provider_is_the_only_missing_counter_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sys_cpu = root / "cpu"
            cpufreq = sys_cpu / "cpu2" / "cpufreq"
            cpufreq.mkdir(parents=True)
            (cpufreq / "scaling_cur_freq").write_text("3800000", encoding="ascii")
            swaps = root / "swaps"
            swaps.write_text("Filename Type Size Used Priority\n", encoding="utf-8")
            with self.assertRaisesRegex(HealthError, "thermal-throttle"):
                LaneHealthMonitor((2,), sys_cpu=sys_cpu, proc_swaps=swaps)
            monitor = LaneHealthMonitor(
                (2,),
                sys_cpu=sys_cpu,
                proc_swaps=swaps,
                external_thermal_provider=True,
            )
            monitor.start()
            summary = monitor.stop()
            self.assertEqual(summary.thermal_throttle_delta, 0)
            self.assertFalse(summary.swap_active)
            self.assertGreaterEqual(summary.samples, 3)

    def test_unknown_bpf_scheduler_architecture_is_rejected(self) -> None:
        with mock.patch("quicperf_harness.health.platform.machine", return_value="mystery"):
            with self.assertRaisesRegex(HealthError, "unknown"):
                PerCpuNonOwnedClock((1,), Path("/unused"))

    def test_scheduler_program_and_tracepoint_start_are_frozen(self) -> None:
        self.assertEqual(
            len(PerCpuNonOwnedClock._program(17)),
            PerCpuNonOwnedClock._PROGRAM_INSTRUCTIONS * 8,
        )
        attr = PerCpuNonOwnedClock._tracepoint_attr(310)
        self.assertEqual(struct.unpack_from("=I", attr, 0)[0], 2)
        self.assertEqual(struct.unpack_from("=Q", attr, 8)[0], 310)
        self.assertEqual(struct.unpack_from("=Q", attr, 40)[0] & 1, 1)

    def test_scheduler_loads_one_program_for_each_cpu_attachment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tracepoint_id = Path(temporary) / "id"
            tracepoint_id.write_text("310\n", encoding="ascii")
            with (
                mock.patch.object(
                    PerCpuNonOwnedClock, "_create_map", return_value=11
                ),
                mock.patch.object(
                    PerCpuNonOwnedClock,
                    "_load_program",
                    side_effect=(21, 22),
                ) as load,
                mock.patch.object(
                    PerCpuNonOwnedClock,
                    "_attach",
                    side_effect=(31, 32),
                ) as attach,
                mock.patch("quicperf_harness.health.fcntl.ioctl"),
                mock.patch("quicperf_harness.health.os.close"),
            ):
                clock = PerCpuNonOwnedClock((2, 3), tracepoint_id)
                self.assertEqual(load.call_args_list, [mock.call(11), mock.call(11)])
                self.assertEqual(
                    attach.call_args_list,
                    [mock.call(2, 310, 21), mock.call(3, 310, 22)],
                )
                clock.close()

    def test_partial_endpoint_freeze_is_recovered_by_thawing_both(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = root / "server"
            client = root / "client"
            for cgroup in (server, client):
                cgroup.mkdir()
                (cgroup / "cgroup.freeze").write_text("0", encoding="ascii")
            health = TrialLaneHealth(
                server_cpu=2,
                client_cpus=(3, 4),
                server_cgroup=server,
                client_cgroup=client,
            )
            with (
                mock.patch.object(
                    TrialLaneHealth,
                    "_frozen_state",
                    side_effect=HealthError("injected freeze read failure"),
                ),
                self.assertRaisesRegex(HealthError, "injected freeze"),
            ):
                health._set_endpoints_frozen(True)
            self.assertFalse(health._endpoints_frozen)
            self.assertEqual(
                [
                    (cgroup / "cgroup.freeze").read_text(encoding="ascii")
                    for cgroup in (server, client)
                ],
                ["0", "0"],
            )

    def test_trial_health_counts_non_owned_scheduler_time_per_cpu(self) -> None:
        class FakeClock:
            def __init__(self, cpus: tuple[int, ...]):
                self.cpus = cpus

            def arm(self, _server: Path, _client: Path) -> None:
                pass

            def finish(self) -> dict[int, int]:
                values = {2: 100, 3: 0, 4: 100}
                return {cpu: values[cpu] for cpu in self.cpus}

            def close(self) -> None:
                pass

        class FakeMonitor:
            def __init__(self, _cpus: tuple[int, ...]):
                pass

            def start(self) -> None:
                pass

            def stop(self) -> HealthSummary:
                return HealthSummary(1_900_000_000, 3_200_000_000, 0, False, 10)

        irqs = (
            {2: {55: 10}, 3: {55: 20}, 4: {55: 30}},
            {2: {55: 10}, 3: {55: 21}, 4: {55: 30}},
        )
        with (
            mock.patch("quicperf_harness.health.PerCpuNonOwnedClock", FakeClock),
            mock.patch("quicperf_harness.health.LaneHealthMonitor", FakeMonitor),
            mock.patch.object(
                TrialLaneHealth, "_set_endpoints_frozen"
            ) as freezer,
            mock.patch(
                "quicperf_harness.health.read_device_irq_counts", side_effect=irqs
            ),
            mock.patch(
                "quicperf_harness.health.time.clock_gettime_ns",
                side_effect=(100, 1_100),
            ),
        ):
            with TrialLaneHealth(
                server_cpu=2,
                client_cpus=(3, 4),
                server_cgroup=Path("server"),
                client_cgroup=Path("client"),
            ) as health:
                health.arm(100)
                result = health.finish()
        self.assertEqual(
            freezer.call_args_list,
            [mock.call(True), mock.call(False), mock.call(True), mock.call(False)],
        )
        self.assertEqual(result.non_owned_cpu_ns, {2: 100, 3: 0, 4: 100})
        self.assertEqual(result.non_owned_cpu_fraction_max, 0.1)
        self.assertEqual(result.device_irq_deltas, {2: {}, 3: {55: 1}, 4: {}})
        self.assertEqual(result.health_samples, 10)

    def test_trial_health_accepts_four_core_headroom_treatment(self) -> None:
        health = TrialLaneHealth(
            server_cpu=2,
            client_cpus=(3, 4, 5, 6),
            server_cgroup=Path("server"),
            client_cgroup=Path("client"),
        )
        self.assertEqual(health.cpus, (2, 3, 4, 5, 6))
        health.close()
        with self.assertRaisesRegex(HealthError, "two or four disjoint"):
            TrialLaneHealth(
                server_cpu=2,
                client_cpus=(3, 3, 4, 5),
                server_cgroup=Path("server"),
                client_cgroup=Path("client"),
            )


if __name__ == "__main__":
    unittest.main()
