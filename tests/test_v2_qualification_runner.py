from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from quicperf_harness.canonical import canonical_bytes
from quicperf_harness.amd_stability import AmdMonitorTransientError, AmdReference
from quicperf_harness.identity import (
    analysis_plan_hash,
    campaign_id,
    schedule_hash,
    spec_hash,
)
from quicperf_harness.journal import Journal
from quicperf_harness.health import HealthError
from quicperf_harness.manifest import manifest_hash, validate_manifest
from quicperf_harness.qualification import QualificationError
from quicperf_harness.qualification_runner import (
    NativeSessionObservationSource,
    PhysicalQualificationUnavailable,
    QualificationInfrastructureTransient,
    _headroom_held_out,
    _headroom_screens,
    _headroom_endpoint_exception,
    _worker_endpoint_exception,
    run_qualification,
)
from quicperf_harness.runner import EndpointRunError
from quicperf_harness.spec import load_experiment_spec
from tests.test_v2_spec_identity import ROOT, manifest_fixture


PROFILE = ROOT / "profiles" / "v2" / "ci-smoke.json"


def make_run(root: Path, source_profile: Path = PROFILE) -> tuple[Path, object]:
    root.mkdir(parents=True, exist_ok=True)
    profile = json.loads(source_profile.read_text(encoding="utf-8"))
    if source_profile == PROFILE:
        profile["roles"]["servers"] = ["ngtcp2perf", "lsperf"]
        profile["backends"]["server"] = ["syscall", "iouring"]
        for workload in profile["workloads"]:
            workload["measurement_ns"] = 2_000_000_000
    profile_path = root / "profile.json"
    profile_path.write_bytes(canonical_bytes(profile))
    spec = load_experiment_spec(profile_path)

    manifest_value = manifest_fixture()
    first = manifest_value["binaries"][0]
    first["role"] = "server_reference_client"
    second = copy.deepcopy(first)
    second.update(
        {
            "name": "lsperf",
            "role": "server",
            "path": "/opt/quicperf/bin/lsperf",
            "sha256": "c" * 64,
            "elf_build_id": "1123456789abcdef",
        }
    )
    manifest_value["binaries"].append(second)
    helper = copy.deepcopy(first)
    helper.update(
        {
            "name": "quicperf-amd-stability-probe",
            "role": "coordinator",
            "path": "/opt/quicperf/bin/quicperf-amd-stability-probe",
            "sha256": "d" * 64,
            "elf_build_id": "2123456789abcdef",
        }
    )
    manifest_value["binaries"].append(helper)
    spin_helper = copy.deepcopy(first)
    spin_helper.update(
        {
            "name": "quicperf-monitor-spin",
            "role": "coordinator",
            "path": "/opt/quicperf/bin/quicperf-monitor-spin.so",
            "sha256": "e" * 64,
            "elf_build_id": "3123456789abcdef",
        }
    )
    manifest_value["binaries"].append(spin_helper)
    manifest = validate_manifest(manifest_value)
    schedule = {"schema_version": "qualification-runner-test.v1", "blocks": []}
    spec_digest = spec_hash(spec.raw)
    manifest_digest = manifest_hash(manifest)
    analysis_digest = analysis_plan_hash(spec.raw["analysis"])
    schedule_digest = schedule_hash(schedule)
    campaign_digest = campaign_id(
        spec_digest, manifest_digest, analysis_digest, schedule_digest
    )
    run_dir = root / "run"
    journal = Journal.create_run_directory(
        run_dir,
        spec_bytes=canonical_bytes(spec.raw),
        manifest_bytes=canonical_bytes(manifest.raw),
    )
    try:
        journal.create_campaign(
            campaign_id=campaign_digest,
            spec_hash=spec_digest,
            identity_manifest_hash=manifest_digest,
            analysis_plan_hash=analysis_digest,
            schedule_hash=schedule_digest,
            expected_cardinality=0,
            maximum_cardinality=0,
            retry_per_microblock=0,
            session_count=1,
            manifests={"schedule": (schedule_digest, schedule)},
        )
    finally:
        journal.close()
    return run_dir, spec


class DeterministicSource:
    def __init__(self, *, unavailable_stage: str | None = None, omit_one: bool = False):
        self.unavailable_stage = unavailable_stage
        self.omit_one = omit_one
        self.calls: list[tuple[str, str, list[dict[str, object]]]] = []

    @staticmethod
    def _values(request: dict[str, object]) -> dict[str, object]:
        phase = request["phase"]
        if phase == "reset_screen":
            return {
                "live_connections": 0,
                "live_streams": 0,
                "live_tickets": 0,
                "work_inventory": 0,
            }
        if phase == "endurance":
            return {
                "fd_count": 10,
                "memory_bytes": 100_000_000,
                "live_connections": 0,
                "live_streams": 0,
                "live_tickets": 0,
            }
        if phase == "reuse_parity":
            return {"rate": "1000"}
        if phase == "headroom_screen":
            server = 1 if request["server"] == "lsperf" else 0
            backend = 1 if request["backend"] == "iouring" else 0
            scenario = {
                "multistream_download": 0,
                "small_payload_pps": 1,
                "datagram": 2,
            }[request["scenario"]]
            return {
                "client_cpu_ns": 100_000_000 + server * 30_000_000
                + backend * 10_000_000 + scenario * 1_000_000,
                "wall_ns": 500_000_000,
            }
        if phase == "headroom_held_out":
            cores = int(request["client_cores"])
            return {
                "rate": str(1000 + int(request["block"])),
                "client_cpu_p95": "0.79",
                "client_cpu_ns": 300_000_000 * cores,
                "wall_ns": 500_000_000,
            }
        if phase == "lane_screen":
            server = 2 if request["server"] == "lsperf" else 1
            backend = 2 if request["backend"] == "iouring" else 1
            scale = server * backend
            return {
                "server_cpu_ns": 100_000_000 * scale,
                "client_cpu_ns": 50_000_000 * scale,
                "udp_packets": 10_000 * scale,
                "validated_units": 1_000_000 * scale,
                "timer_wakeups": 1000 * scale,
                "wall_ns": 500_000_000,
                "memory_bytes": 100_000_000,
            }
        if phase == "lane_held_out":
            block = int(request["block"])
            return {
                "per_lane": [
                    {
                        "lane": lane,
                        "rate": str(1000 + block),
                        "peak_memory_bytes": 100_000_000 + block,
                        "treatment_hash": request["treatment_hash"],
                    }
                    for lane in range(int(request["lanes"]))
                ]
            }
        if phase in {"window_screen", "window_held_out"}:
            server_offset = 1000 if request["server"] == "lsperf" else 0
            nested_seconds = int(request["nested_window_seconds"])
            reference_seconds = int(request["reference_window_seconds"])
            if phase == "window_screen":
                reference_rate = 1000 + server_offset
                nested_rate = reference_rate + (
                    200 if request["server"] == "lsperf" else 0
                )
            else:
                reference_rate = nested_rate = (
                    1000 + server_offset + int(request["block"])
                )
            return {
                "nested_numerator": nested_rate * nested_seconds,
                "nested_denominator_ns": nested_seconds * 1_000_000_000,
                "reference_numerator": reference_rate * reference_seconds,
                "reference_denominator_ns": reference_seconds * 1_000_000_000,
                "nested_classification": "valid",
                "reference_classification": "valid",
                "cap_hits": 0,
                "stalled": False,
            }
        if phase in {"tail_window_screen", "tail_window_held_out"}:
            eligible = (
                1_500
                if request["server"] == "ngtcp2perf"
                else 1_600
            )
            if phase == "tail_window_held_out":
                eligible = 1_100
            return {
                "prefixes": [
                    {
                        "duration_seconds": duration,
                        "eligible_operations": eligible,
                        "failed_or_censored_operations": 0,
                        "p99_ns": 1_000,
                        "validity_classification": "valid",
                        "capped_or_stalled": False,
                    }
                    for duration in (2, 5, 10, 20)
                ]
            }
        raise AssertionError(phase)

    def observe(self, *, kind, stage, stage_plan_hash, requests):
        if stage == self.unavailable_stage:
            raise PhysicalQualificationUnavailable(f"{stage} host resources unavailable")
        copied = [dict(item) for item in requests]
        self.calls.append((kind, stage, copied))
        observations = [
            {"request_id": item["request_id"], "values": self._values(item)}
            for item in requests
        ]
        observations.reverse()  # Response order must not define pairing.
        if self.omit_one and observations:
            observations.pop()
        return observations


class SessionTransientSource(DeterministicSource):
    def __init__(self, *, exhaust: bool = False):
        super().__init__()
        self.exhaust = exhaust
        self.primary_request_id: str | None = None

    def observe(self, *, kind, stage, stage_plan_hash, requests):
        copied = [dict(item) for item in requests]
        self.calls.append((kind, stage, copied))
        observations = []
        for index, item in enumerate(requests):
            if stage == "screens" and self.primary_request_id is None and index == 0:
                self.primary_request_id = str(item["request_id"])
            transient = stage == "screens" and index == 0
            if stage == "screens_retry" and self.exhaust:
                transient = True
            observations.append(
                {
                    "request_id": item["request_id"],
                    **(
                        {"infrastructure_transient": "external_cpu_or_irq_noise"}
                        if transient
                        else {"values": self._values(item)}
                    ),
                }
            )
        observations.reverse()
        return observations


class QualificationRunnerTests(unittest.TestCase):
    def test_all_four_producers_freeze_exact_counts_selection_and_pairing(self) -> None:
        cases = {
            "worker-reuse": (4356, 768),
            "client-headroom": (12, 12),
            "lane-interference": (16, 160),
            "window-qualification": (8, 160),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for kind, counts in cases.items():
                with self.subTest(kind=kind):
                    run_dir, _spec = make_run(root / kind)
                    source = DeterministicSource()
                    result = run_qualification(
                        run_dir=run_dir,
                        kind=kind,
                        artifact_store=root / "store",
                        observation_source=source,
                    )
                    self.assertTrue(result["qualified"], result)
                    self.assertEqual(
                        (result["screen_observations"], result["held_out_observations"]),
                        counts,
                    )
                    self.assertEqual(result["sample_rows_added"], 0)
                    with Journal(run_dir) as journal:
                        self.assertEqual(
                            journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0],
                            0,
                        )
                        raw = json.loads(
                            bytes(
                                journal.connection.execute(
                                    "SELECT content FROM artifact WHERE path=?",
                                    (result["journal_path"],),
                                ).fetchone()["content"]
                            )
                        )
                    self.assertEqual(raw["identity_hash"], result["identity_hash"])
                    self.assertEqual(raw["plan_hash"], result["plan_hash"])
                    self.assertEqual(
                        len(raw["observations"]["screens"]), counts[0]
                    )
                    self.assertEqual(
                        len(raw["observations"]["held_out"]), counts[1]
                    )
                    if kind == "client-headroom":
                        self.assertEqual(
                            raw["plan"]["selection"],
                            ["lsperf", "iouring", "datagram"],
                        )
                        self.assertEqual(
                            {item["client_cores"] for item in raw["plan"]["screen_requests"]},
                            {2},
                        )
                        self.assertEqual(
                            {item["client_cores"] for item in raw["plan"]["held_out_requests"]},
                            {2},
                        )
                        self.assertTrue(
                            all(
                                "position" not in item
                                for item in raw["plan"]["held_out_requests"]
                            )
                        )
                    elif kind == "worker-reuse":
                        reset = [
                            item
                            for item in raw["plan"]["screen_requests"]
                            if item["phase"] == "reset_screen"
                        ]
                        reset_chains: dict[str, list[int]] = {}
                        for item in reset:
                            reset_chains.setdefault(item["chain_id"], []).append(
                                item["cycle"]
                            )
                        self.assertTrue(reset_chains)
                        self.assertTrue(
                            all(
                                sorted(cycles) == list(range(1, 33))
                                for cycles in reset_chains.values()
                            )
                        )
                        endurance = [
                            item
                            for item in raw["plan"]["screen_requests"]
                            if item["phase"] == "endurance"
                        ]
                        endurance_chains: dict[str, list[int]] = {}
                        for item in endurance:
                            endurance_chains.setdefault(item["chain_id"], []).append(
                                item["cycle"]
                            )
                        self.assertTrue(endurance_chains)
                        self.assertTrue(
                            all(
                                sorted(cycles) == list(range(0, 1025))
                                for cycles in endurance_chains.values()
                            )
                        )
                    elif kind == "lane-interference":
                        self.assertTrue(
                            all(
                                cell[:2] == ["lsperf", "iouring"]
                                for cell in raw["plan"]["selection"].values()
                            )
                        )
                        self.assertTrue(
                            all(
                                len(item["values"]["per_lane"])
                                in {1, 2}
                                for item in raw["observations"]["held_out"]
                            )
                        )
                    elif kind == "window-qualification":
                        self.assertEqual(
                            set(raw["plan"]["selection"].values()), {"lsperf"}
                        )
                        self.assertTrue(
                            all(
                                item["duration_seconds"]
                                == item["reference_window_seconds"]
                                for item in raw["plan"]["screen_requests"]
                            )
                        )
                    elif kind == "worker-reuse":
                        self.assertEqual(
                            {
                                item["scenario_order"]
                                for item in raw["plan"]["held_out_requests"]
                            },
                            {"canonical", "reordered"},
                        )

    def test_raised_transient_replays_full_headroom_session(self) -> None:
        class RaisingSource(DeterministicSource):
            def observe(self, *, kind, stage, stage_plan_hash, requests):
                copied = [dict(item) for item in requests]
                self.calls.append((kind, stage, copied))
                if stage == "screens":
                    raise QualificationInfrastructureTransient(
                        str(requests[0]["request_id"]),
                        "host_stability_monitor_transient",
                        detail="boundary observed 1200000 ns late",
                    )
                observations = [
                    {"request_id": item["request_id"], "values": self._values(item)}
                    for item in requests
                ]
                observations.reverse()
                return observations

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir, _spec = make_run(root)
            source = RaisingSource()
            result = run_qualification(
                run_dir=run_dir,
                kind="client-headroom",
                artifact_store=root / "store",
                observation_source=source,
            )
            self.assertTrue(result["qualified"], result)
            self.assertEqual(
                [stage for _kind, stage, _requests in source.calls],
                ["screens", "screens_retry", "held_out_retry"],
            )
            primary = source.calls[0][2]
            retry = source.calls[1][2]
            self.assertEqual(len(primary), len(retry))
            self.assertEqual(
                {
                    (item["request_id"], item["retry_request_id"])
                    for item in primary
                },
                {
                    (item["primary_request_id"], item["request_id"])
                    for item in retry
                },
            )
            with Journal(run_dir) as journal:
                raw = json.loads(
                    bytes(
                        journal.connection.execute(
                            "SELECT content FROM artifact WHERE path=?",
                            (result["journal_path"],),
                        ).fetchone()["content"]
                    )
                )
            self.assertEqual(
                raw["session_attempts"][0]["transient"]["detail"],
                "boundary observed 1200000 ns late",
            )

    def test_missing_or_malformed_physical_observation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir, _spec = make_run(root)
            result = run_qualification(
                run_dir=run_dir,
                kind="client-headroom",
                artifact_store=root / "store",
                observation_source=DeterministicSource(omit_one=True),
            )
            self.assertEqual(result["status"], "not_qualified")
            self.assertFalse(result["qualified"])
            self.assertIn("missing 1 exact planned requests", result["reasons"][0])
            self.assertEqual(result["sample_rows_added"], 0)

    def test_unavailable_physical_execution_is_not_run_and_never_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir, _spec = make_run(root)
            result = run_qualification(
                run_dir=run_dir,
                kind="lane-interference",
                artifact_store=root / "store",
                observation_source=DeterministicSource(unavailable_stage="held_out"),
            )
            self.assertEqual(result["status"], "not_run")
            self.assertFalse(result["qualified"])
            self.assertIsNone(result["artifact_hash"])
            self.assertFalse((root / "store").exists())
            with Journal(run_dir) as journal:
                self.assertIsNone(
                    journal.connection.execute(
                        "SELECT 1 FROM artifact WHERE path='qualification/lane-interference.json'"
                    ).fetchone()
                )
                self.assertEqual(
                    journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0], 0
                )

    def test_publication_headroom_plan_uses_only_four_core_treatment(self) -> None:
        spec = load_experiment_spec(
            ROOT / "profiles" / "v2.3" / "publication.json"
        )
        identity = "12" * 32
        screens = _headroom_screens(spec, identity)
        selected = ("ngtcp2perf", "iouring", "datagram")
        held_out = _headroom_held_out(spec, identity, selected)
        self.assertEqual(len(screens), 36)
        self.assertEqual({item["client_cores"] for item in screens}, {4})
        self.assertEqual(len(held_out), 12)
        self.assertEqual({item["client_cores"] for item in held_out}, {4})
        self.assertEqual(
            [item["block"] for item in held_out],
            list(range(1, 13)),
        )
        self.assertTrue(all("position" not in item for item in held_out))

    def test_absent_driver_cli_path_is_auditable_not_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir, _spec = make_run(root)
            result = run_qualification(
                run_dir=run_dir,
                kind="worker-reuse",
                artifact_store=root / "store",
            )
            self.assertEqual(result["status"], "not_run")
            self.assertEqual(result["sample_rows_added"], 0)
            self.assertIsNotNone(result["journal_path"])
            self.assertIn("native qualification resources are unavailable", result["reasons"][0])
            cli = subprocess.run(
                [
                    str(ROOT / "tools" / "quicperfctl"),
                    "qualification",
                    "run",
                    "--kind",
                    "client-headroom",
                    "--run-dir",
                    str(run_dir),
                    "--artifact-store",
                    str(root / "store"),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(cli.returncode, 2, cli.stderr)
            cli_result = json.loads(cli.stdout)
            self.assertEqual(cli_result["status"], "not_run")
            self.assertIn("configured binary is missing", cli_result["reasons"][0])

    def test_host_stability_is_live_identity_bound_and_hardware_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir, _spec = make_run(root)
            calibration = {
                "schema_version": "quicperf.amd-calibration.v1",
                "provider": "amd_delivered_performance_v1",
                "passed": True,
                "reasons": [],
            }
            with mock.patch(
                "quicperf_harness.qualification_runner.run_amd_calibration",
                return_value=(
                    AmdReference({2: 1.0, 3: 1.0, 4: 1.0}, {2: 1000.0, 3: 1000.0, 4: 1000.0}),
                    calibration,
                ),
            ) as run, mock.patch(
                "quicperf_harness.qualification_runner.irq_policy_identity",
                return_value={"boot": {"monitor_cpu": 8}},
            ):
                result = run_qualification(
                    run_dir=run_dir,
                    kind="host-stability",
                    artifact_store=root / "store",
                )
            self.assertTrue(result["qualified"], result["reasons"])
            self.assertEqual(result["status"], "qualified")
            self.assertEqual(result["sample_rows_added"], 0)
            self.assertEqual(
                run.call_args.kwargs["helper"],
                Path("/opt/quicperf/bin/quicperf-amd-stability-probe"),
            )

            failed_run, _spec = make_run(root / "failed")
            with mock.patch(
                "quicperf_harness.qualification_runner.run_amd_calibration",
                side_effect=HealthError("injected Tctl breach"),
            ), mock.patch(
                "quicperf_harness.qualification_runner.irq_policy_identity",
                return_value={"boot": {"monitor_cpu": 8}},
            ):
                failed = run_qualification(
                    run_dir=failed_run,
                    kind="host-stability",
                    artifact_store=root / "failed-store",
                )
            self.assertFalse(failed["qualified"])
            self.assertEqual(failed["status"], "not_qualified")
            self.assertIn("injected Tctl breach", failed["reasons"][0])

    def test_native_qualification_session_runs_pre_continuous_and_post_amd_gates(self) -> None:
        context = SimpleNamespace(
            cpus=(2, 3, 4),
            housekeeping_cpu=8,
            helper=Path("/probe"),
            spin_helper=Path("/spin.so"),
            policy=object(),
            reference=object(),
            temperature_source=object(),
        )
        source = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(
                raw={"treatment": {"resources": {"client_physical_cores": 4}}}
            ),
            manifest=None,
            amd_context=context,
        )
        evaluation = SimpleNamespace(passed=True, reasons=())
        monitor = mock.MagicMock()
        monitor.stop.return_value = {"passed": True, "reasons": []}
        source.binary_paths = {}
        source.physical_cores = object()
        with (
            mock.patch(
                "quicperf_harness.qualification_runner.run_amd_session_probe",
                side_effect=((evaluation, {"probe": "pre"}), (evaluation, {"probe": "post"})),
            ) as probe,
            mock.patch(
                "quicperf_harness.qualification_runner.AmdContinuousMonitor",
                return_value=monitor,
            ) as monitor_type,
            mock.patch(
                "quicperf_harness.qualification_runner.allocate_lanes",
                return_value=[SimpleNamespace(housekeeping_cpus=(0, 1))],
            ),
            mock.patch(
                "quicperf_harness.qualification_runner.os.sched_getaffinity",
                return_value={0, 1},
            ),
            mock.patch(
                "quicperf_harness.qualification_runner.os.sched_setaffinity"
            ) as set_affinity,
        ):
            source.start_host_stability()
            evidence = source.finish_host_stability()
        self.assertEqual(probe.call_count, 2)
        monitor_type.assert_called_once()
        monitor.start.assert_called_once_with()
        monitor.stop.assert_called_once_with()
        self.assertEqual(
            set_affinity.call_args_list,
            [mock.call(0, (0, 1)), mock.call(0, frozenset({0, 1}))],
        )
        self.assertEqual(
            evidence,
            {
                "schema_version": "quicperf.amd-qualification-session.v1",
                "provider": "amd_delivered_performance_v1",
                "passed": True,
                "pre_probe": {"probe": "pre"},
                "continuous": {"passed": True, "reasons": []},
                "post_probe": {"probe": "post"},
            },
        )

    def test_native_qualification_keeps_dedicated_monitor_outside_housekeeping(
        self,
    ) -> None:
        topology = SimpleNamespace(housekeeping_cpus=(0, 1))
        ordinary = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(),
            manifest=None,
        )
        self.assertEqual(ordinary._coordinator_cpus((topology,)), (0, 1))
        monitored = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(),
            manifest=None,
            amd_context=SimpleNamespace(housekeeping_cpu=8),
        )
        self.assertEqual(monitored._coordinator_cpus((topology,)), (0, 1))
        with self.assertRaisesRegex(QualificationError, "no housekeeping CPU"):
            monitored._coordinator_cpus(
                (SimpleNamespace(housekeeping_cpus=()),)
            )

    def test_native_qualification_restores_affinity_when_pre_probe_fails(self) -> None:
        source = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(
                raw={"treatment": {"resources": {"client_physical_cores": 4}}}
            ),
            manifest=None,
            amd_context=SimpleNamespace(
                cpus=(2,),
                housekeeping_cpu=8,
                helper=Path("/probe"),
                spin_helper=Path("/spin.so"),
                policy=object(),
                reference=object(),
                temperature_source=object(),
            ),
        )
        source.binary_paths = {}
        source.physical_cores = object()
        with (
            mock.patch(
                "quicperf_harness.qualification_runner.allocate_lanes",
                return_value=[SimpleNamespace(housekeeping_cpus=(0, 1))],
            ),
            mock.patch(
                "quicperf_harness.qualification_runner.os.sched_getaffinity",
                return_value={0, 1},
            ),
            mock.patch(
                "quicperf_harness.qualification_runner.os.sched_setaffinity"
            ) as set_affinity,
            mock.patch(
                "quicperf_harness.qualification_runner.run_amd_session_probe",
                side_effect=HealthError("injected"),
            ),
        ):
            with self.assertRaisesRegex(QualificationError, "pre-qualification"):
                source.start_host_stability()
        self.assertEqual(
            set_affinity.call_args_list,
            [mock.call(0, (0, 1)), mock.call(0, frozenset({0, 1}))],
        )

    def test_native_session_monitor_transient_is_replayable_and_restores_affinity(
        self,
    ) -> None:
        source = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(
                raw={"treatment": {"resources": {"client_physical_cores": 4}}}
            ),
            manifest=None,
            amd_context=SimpleNamespace(
                cpus=(2,),
                housekeeping_cpu=8,
                helper=Path("/probe"),
                spin_helper=Path("/spin.so"),
                policy=object(),
                reference=object(),
                temperature_source=object(),
            ),
        )
        source.binary_paths = {}
        source.physical_cores = object()
        evaluation = SimpleNamespace(passed=True, reasons=())
        monitor = mock.MagicMock()
        monitor.start.side_effect = AmdMonitorTransientError("injected cadence gap")
        with (
            mock.patch(
                "quicperf_harness.qualification_runner.allocate_lanes",
                return_value=[SimpleNamespace(housekeeping_cpus=(0, 1))],
            ),
            mock.patch(
                "quicperf_harness.qualification_runner.os.sched_getaffinity",
                return_value={0, 1},
            ),
            mock.patch(
                "quicperf_harness.qualification_runner.os.sched_setaffinity"
            ) as set_affinity,
            mock.patch(
                "quicperf_harness.qualification_runner.run_amd_session_probe",
                return_value=(evaluation, {"probe": "pre"}),
            ),
            mock.patch(
                "quicperf_harness.qualification_runner.AmdContinuousMonitor",
                return_value=monitor,
            ),
        ):
            with self.assertRaises(QualificationInfrastructureTransient) as raised:
                source.start_host_stability()
        self.assertEqual(
            raised.exception.reason, "host_stability_monitor_transient"
        )
        self.assertEqual(
            set_affinity.call_args_list,
            [mock.call(0, (0, 1)), mock.call(0, frozenset({0, 1}))],
        )

    def test_native_session_stop_preserves_typed_monitor_transient(self) -> None:
        source = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(),
            manifest=None,
            amd_context=SimpleNamespace(),
        )
        continuous = {
            "passed": False,
            "reasons": ["monitor_error:injected cadence gap"],
            "monitor_error": {
                "type": "AmdMonitorTransientError",
                "message": "injected cadence gap",
                "treatment_independent_transient": True,
            },
        }
        source.amd_monitor = mock.MagicMock()
        source.amd_monitor.stop.return_value = continuous
        source.amd_evidence = {
            "schema_version": "quicperf.amd-qualification-session.v1",
            "provider": "amd_delivered_performance_v1",
            "passed": False,
            "pre_probe": {"probe": "pre"},
            "continuous": None,
            "post_probe": None,
        }
        source._session_previous_affinity = frozenset({0, 1})
        with mock.patch(
            "quicperf_harness.qualification_runner.os.sched_setaffinity"
        ) as set_affinity:
            with self.assertRaises(QualificationInfrastructureTransient) as raised:
                source.finish_host_stability()
        self.assertEqual(
            raised.exception.reason, "host_stability_monitor_transient"
        )
        self.assertEqual(source.amd_evidence["continuous"], continuous)
        set_affinity.assert_called_once_with(0, frozenset({0, 1}))

    def test_native_headroom_observation_preserves_equal_client_mixture(self) -> None:
        source = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(reference_clients=("ngtcp2perf", "picoperf")),
            manifest=None,
        )
        trials = [
            {
                "resource_telemetry": {"client_cpu_ns": 100},
                "runtime": {"trial_wall_ns": 1_000},
                "server_result": {"numerator": 10, "denominator_raw_ns": 1_000_000_000},
                "client_result": {"client_cpu_fraction_of_quota_p95": "0.60"},
            },
            {
                "resource_telemetry": {"client_cpu_ns": 300},
                "runtime": {"trial_wall_ns": 3_000},
                "server_result": {"numerator": 40, "denominator_raw_ns": 1_000_000_000},
                "client_result": {"client_cpu_fraction_of_quota_p95": "0.70"},
            },
        ]
        request = {
            "request_id": "r" * 64,
            "phase": "headroom_held_out",
            "server": "ngtcp2perf",
            "backend": "syscall",
            "scenario": "small_payload_pps",
            "client_cores": 2,
        }
        with mock.patch.object(source, "_headroom_trial", side_effect=trials) as run:
            result = source._observe_headroom(request)
        self.assertEqual(
            [call.kwargs["reference_client"] for call in run.call_args_list],
            ["ngtcp2perf", "picoperf"],
        )
        self.assertEqual(
            result["values"],
            {
                "client_cpu_ns": 400,
                "wall_ns": 4_000,
                "rate": "20",
                "client_cpu_p95": "0.7",
            },
        )

    def test_preallocated_retry_request_changes_native_trial_and_trace_identity(
        self,
    ) -> None:
        source = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(
                estimand="fixed_treatment_server",
                reference_client_backend="syscall",
            ),
            manifest=None,
        )
        source.binary_paths = {}
        source.cgroup_root = Path("/sys/fs/cgroup/quicperf-test")
        source.physical_cores = object()
        source._prepare_headroom = mock.MagicMock()
        source._trial_spec = mock.MagicMock(return_value=SimpleNamespace())
        topology = SimpleNamespace(housekeeping_cpus=(0, 1))
        cgroups = mock.MagicMock()
        cgroups.create.return_value = (Path("/server"), Path("/client"))
        path = mock.MagicMock()
        primary = {
            "request_id": "1" * 64,
            "retry_request_id": "2" * 64,
            "phase": "headroom_screen",
            "server": "ngtcp2perf",
            "backend": "syscall",
            "scenario": "small_payload_pps",
        }
        retry = {
            **primary,
            "request_id": primary["retry_request_id"],
            "primary_request_id": primary["request_id"],
            "attempt_slot": "retry",
        }
        with (
            mock.patch(
                "quicperf_harness.qualification_runner.allocate_lanes",
                return_value=[topology],
            ),
            mock.patch(
                "quicperf_harness.qualification_runner.LaneCgroups",
                return_value=cgroups,
            ),
            mock.patch(
                "quicperf_harness.qualification_runner.LoopbackPathController",
                return_value=path,
            ),
            mock.patch(
                "quicperf_harness.qualification_runner.os.sched_getaffinity",
                return_value={0, 1},
            ),
            mock.patch(
                "quicperf_harness.qualification_runner.os.sched_setaffinity"
            ),
            mock.patch(
                "quicperf_harness.qualification_runner._run_trial",
                return_value={"ok": True},
            ) as run,
        ):
            source._headroom_trial(
                primary, reference_client="ngtcp2perf", client_cores=2
            )
            source._headroom_trial(
                retry, reference_client="ngtcp2perf", client_cores=2
            )
        first, second = run.call_args_list
        self.assertNotEqual(
            first.kwargs["trial_row"]["trial_id"],
            second.kwargs["trial_row"]["trial_id"],
        )
        self.assertNotEqual(
            first.kwargs["cell_config"]["trace_seed"],
            second.kwargs["cell_config"]["trace_seed"],
        )

    def test_missing_native_health_counter_is_not_run_not_observed_failure(self) -> None:
        unavailable = _headroom_endpoint_exception(
            "r" * 64,
            EndpointRunError(
                "host_health_telemetry_unavailable:eligible CPUs expose no thermal-throttle counters"
            ),
        )
        self.assertIsInstance(unavailable, PhysicalQualificationUnavailable)
        invalid = _headroom_endpoint_exception(
            "r" * 64, EndpointRunError("unsupported:adapter rejected CONFIG")
        )
        self.assertNotIsInstance(invalid, PhysicalQualificationUnavailable)
        worker_unavailable = _worker_endpoint_exception(
            "w" * 64,
            EndpointRunError(
                "host_health_telemetry_unavailable:eligible CPUs expose no thermal-throttle counters"
            ),
        )
        self.assertIsInstance(worker_unavailable, PhysicalQualificationUnavailable)
        worker_invalid = _worker_endpoint_exception(
            "w" * 64, EndpointRunError("reuse_worker_reset_inventory_not_empty")
        )
        self.assertNotIsInstance(worker_invalid, PhysicalQualificationUnavailable)
        detailed = EndpointRunError(
            "external_cpu_or_irq_noise",
            detail='{"non_owned_cpu_ns":{"2":20000000}}',
            infrastructure_transient=True,
        )
        self.assertEqual(detailed.reason, "external_cpu_or_irq_noise")
        self.assertEqual(
            str(detailed),
            'external_cpu_or_irq_noise:{"non_owned_cpu_ns":{"2":20000000}}',
        )

    def test_native_worker_screens_project_reset_and_endurance_telemetry(self) -> None:
        source = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(),
            manifest=None,
        )
        context = mock.MagicMock()
        context.__enter__.return_value = (object(), (Path("server"), Path("client")), object(), object())
        requests = [
            {
                "request_id": "1" * 64,
                "phase": "reset_screen",
                "chain_id": "a" * 64,
                "cycle": 1,
                "scenario": "reqresp",
            },
            {
                "request_id": "2" * 64,
                "phase": "endurance",
                "chain_id": "b" * 64,
                "cycle": 0,
                "scenario": "datagram",
            },
        ]
        reset = {
            "server": {
                "live_connections": 0,
                "live_streams": 0,
                "live_tickets": 0,
                "work_inventory": 0,
            },
            "reference_client": {
                "live_connections": 0,
                "live_streams": 0,
                "live_tickets": 0,
                "work_inventory": 0,
            },
        }
        result = {
            "fd_count": 14,
            "inventories": {"created": {}, "reset": reset},
            "memory_bytes": 42_000_000,
            "pids": {"server": 101, "reference_client": 102},
        }
        with mock.patch.object(source, "_worker_resources", return_value=context), mock.patch.object(
            source, "_worker_trial", side_effect=(result, result)
        ) as run:
            observations = source._observe_worker_screens(requests)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            observations,
            [
                {
                    "request_id": "1" * 64,
                    "values": {
                        "live_connections": 0,
                        "live_streams": 0,
                        "live_tickets": 0,
                        "work_inventory": 0,
                    },
                },
                {
                    "request_id": "2" * 64,
                    "values": {
                        "fd_count": 14,
                        "memory_bytes": 42_000_000,
                        "live_connections": 0,
                        "live_streams": 0,
                        "live_tickets": 0,
                    },
                },
            ],
        )

    def test_native_worker_parity_preserves_requested_scenario_order(self) -> None:
        source = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(),
            manifest=None,
        )
        contexts: list[mock.MagicMock] = []

        def resources(*, pooled: bool):
            context = mock.MagicMock()
            context.__enter__.return_value = (
                object(),
                (Path("server"), Path("client")),
                object(),
                object() if pooled else None,
            )
            contexts.append(context)
            return context

        request = {
            "request_id": "3" * 64,
            "phase": "reuse_parity",
            "adapter": "ngtcp2perf",
            "backend": "syscall",
            "mode": "reused",
            "sentinel": "reqresp",
            "scenario_sequence": ["loss_recovery", "datagram", "reqresp", "multistream_download"],
        }
        results = [
            {"server_result": {"numerator": value, "denominator_raw_ns": 1_000_000_000}}
            for value in (10, 20, 30, 40)
        ]
        with mock.patch.object(source, "_worker_resources", side_effect=resources), mock.patch.object(
            source, "_worker_trial", side_effect=results
        ) as run:
            observations = source._observe_worker_parity([request])
        self.assertEqual(
            [call.kwargs["scenario"] for call in run.call_args_list],
            request["scenario_sequence"],
        )
        self.assertTrue(all(call.kwargs["pool"] is not None for call in run.call_args_list))
        self.assertEqual(observations[0]["values"]["rate"], "30")

    def test_native_lane_observation_aggregates_equal_client_mixture_per_lane(self) -> None:
        source = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(reference_clients=("ngtcp2perf", "picoperf")),
            manifest=None,
        )

        def result(units: int, wall: int, memory: int) -> dict[str, object]:
            counters = canonical_bytes(
                {
                    "application_bytes_or_operations": units,
                    "packets_received": 5,
                    "packets_sent": 7,
                    "packets_lost": 0,
                    "packets_retransmitted": 0,
                    "peer_application_bytes_or_operations": units,
                    "timer_expirations": 3,
                }
            ).decode("utf-8")
            return {
                "server_result": {
                    "numerator": units,
                    "denominator_raw_ns": wall,
                    "completion_counters_json": counters,
                },
                "client_result": {"completion_counters_json": counters},
                "resource_telemetry": {
                    "server_cpu_ns": 10,
                    "client_cpu_ns": 20,
                    "server_memory_peak_bytes": memory // 2,
                    "client_memory_peak_bytes": memory - memory // 2,
                },
                "runtime": {"trial_wall_ns": wall},
            }

        request = {
            "request_id": "4" * 64,
            "phase": "lane_held_out",
            "lanes": 2,
            "treatment_hash": "5" * 64,
        }
        treatments = [
            [result(100, 1_000_000_000, 1_000), result(200, 1_000_000_000, 2_000)],
            [result(400, 1_000_000_000, 3_000), result(800, 1_000_000_000, 4_000)],
        ]
        with mock.patch.object(source, "_lane_treatment", return_value=treatments):
            observation = source._observe_lane(request)
        self.assertEqual(
            observation["values"],
            {
                "per_lane": [
                    {
                        "lane": 0,
                        "rate": "200",
                        "peak_memory_bytes": 2_000,
                        "treatment_hash": "5" * 64,
                    },
                    {
                        "lane": 1,
                        "rate": "400",
                        "peak_memory_bytes": 3_000,
                        "treatment_hash": "5" * 64,
                    },
                ]
            },
        )

    def test_native_window_uses_exact_nested_bins_from_same_result_stream(self) -> None:
        source = NativeSessionObservationSource(
            root=ROOT,
            run_dir=ROOT / ".run" / "unused",
            campaign_id="c" * 64,
            spec=SimpleNamespace(),
            manifest=None,
        )
        client_bins = [
            {"blocked_events": 0, "validated_units": index + 1}
            for index in range(200)
        ]
        zero_bins = [
            {"blocked_events": 0, "validated_units": 0}
            for _ in range(200)
        ]
        endpoint_caps = {
            "work_cap_hits": 0,
            "byte_cap_hits": 0,
            "stream_cap_hits": 0,
            "stream_id_cap_hits": 0,
        }
        result = {
            "server_result": {
                "measurement_subwindows": zero_bins,
                "numerator": sum(range(1, 201)),
                **endpoint_caps,
            },
            "client_result": {
                "measurement_subwindows": client_bins,
                "numerator": 0,
                **endpoint_caps,
            },
        }
        request = {
            "scenario": "reqresp",
            "nested_window_seconds": 2,
            "reference_window_seconds": 10,
        }
        self.assertEqual(
            source._window_trial_values(request, result),
            (sum(range(1, 41)), sum(range(1, 201)), 0, "valid"),
        )
        request.update(
            {"nested_window_seconds": 5, "reference_window_seconds": 20}
        )
        self.assertEqual(
            source._window_trial_values(request, result),
            (sum(range(1, 51)), sum(range(1, 201)), 0, "valid"),
        )

        request.update(
            {
                "scenario": "small_payload_pps",
                "nested_window_seconds": 2,
                "reference_window_seconds": 10,
            }
        )
        sparse = [
            {"blocked_events": 0, "validated_units": 1}
            for _ in range(200)
        ]
        result["server_result"]["measurement_subwindows"] = sparse
        result["server_result"]["numerator"] = 200
        self.assertEqual(
            source._window_trial_values(request, result)[3],
            "resolution_limited",
        )
        sparse[0:4] = [
            {"blocked_events": 0, "validated_units": 0}
            for _ in range(4)
        ]
        result["server_result"]["numerator"] = 196
        self.assertEqual(
            source._window_trial_values(request, result)[3],
            "invalid_progress",
        )

        request.update(
            {
                "scenario": "upload",
                "nested_window_seconds": 2,
                "reference_window_seconds": 10,
            }
        )
        result["server_result"]["measurement_subwindows"] = zero_bins
        result["server_result"]["numerator"] = 0
        result["client_result"]["measurement_subwindows"] = [
            {"blocked_events": 1, "validated_units": 0}
            for _ in range(200)
        ]
        self.assertEqual(
            source._window_trial_values(request, result)[3],
            "valid",
        )


if __name__ == "__main__":
    unittest.main()
