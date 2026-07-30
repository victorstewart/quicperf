from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from quicperf_harness.canonical import canonical_bytes
from quicperf_harness.errors import InvalidConfigurationError
from quicperf_harness.legacy_parity import (
    BLOCKS,
    _analyze,
    _assert_legacy_translation,
    _expected_settings,
    _open_state,
    _record,
    _strict_observation,
    _v2_observation,
    build_plan,
    run_legacy_v2_parity,
)
from quicperf_harness.runner import HardwareUnqualifiedError
from quicperf_harness.spec import load_experiment_spec


ROOT = Path(__file__).resolve().parents[1]


class LegacyParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = load_experiment_spec(ROOT / "profiles/v2/parity-validation.json")
        self.manifest = SimpleNamespace(raw={"schema_version": "test-manifest"})

    def test_full_unqualified_host_parity_is_refused_before_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "parity"
            with self.assertRaisesRegex(
                InvalidConfigurationError, "cannot satisfy Milestone A"
            ):
                run_legacy_v2_parity(
                    root=Path(temporary),
                    profile=Path("unused"),
                    out_dir=output,
                    bin_dir=Path("unused"),
                    qualification_profile=Path("unused"),
                    qualification_run_dir=Path("unused"),
                    qualification_store=Path("unused"),
                    seed_text=None,
                    diagnostic_unqualified_host=True,
                )
            self.assertFalse(output.exists())

    def test_plan_freezes_384_cells_20_pairs_and_balanced_mode_order(self) -> None:
        plan = build_plan(
            spec=self.spec,
            manifest=self.manifest,
            seed=bytes.fromhex("12" * 32),
            lanes=2,
            diagnostic_authorization=None,
        )
        self.assertEqual(plan["planned_cells"], 384)
        self.assertEqual(plan["planned_pairs"], 7680)
        self.assertEqual(plan["numeric_cells"], 336)
        self.assertEqual(plan["invalid_classification_cells"], 48)
        pair_ids = set()
        lanes = set()
        execution_ordinals = set()
        for cell in plan["cells"]:
            self.assertEqual(len(cell["pairs"]), BLOCKS)
            self.assertEqual(
                sorted(pair["order"] for pair in cell["pairs"]),
                ["legacy_v2"] * 10 + ["v2_legacy"] * 10,
            )
            pair_ids.update(pair["pair_id"] for pair in cell["pairs"])
            lanes.update(pair["lane"] for pair in cell["pairs"])
            execution_ordinals.update(
                pair["execution_ordinal"] for pair in cell["pairs"]
            )
        self.assertEqual(len(pair_ids), 7680)
        self.assertEqual(lanes, {0, 1})
        self.assertEqual(execution_ordinals, set(range(7680)))

    def test_legacy_translation_preserves_exact_numeric_cell_treatment(self) -> None:
        plan = build_plan(
            spec=self.spec,
            manifest=self.manifest,
            seed=bytes.fromhex("23" * 32),
            lanes=2,
            diagnostic_authorization=None,
        )
        cell = next(
            item
            for item in plan["cells"]
            if item["scenario"] == "connect"
            and item["server"] == "ngtcp2perf"
            and item["backend"] == "syscall"
        )
        _assert_legacy_translation(
            profile=ROOT / "profiles/v2/parity-validation.json",
            spec=self.spec,
            cell=cell,
        )

    def test_strict_pair_has_distinct_requests_and_shared_trace_seed(self) -> None:
        plan = build_plan(
            spec=self.spec,
            manifest=self.manifest,
            seed=bytes.fromhex("24" * 32),
            lanes=1,
            diagnostic_authorization={"status": "not_qualified"},
        )
        cell = next(
            item
            for item in plan["cells"]
            if item["scenario"] == "connect"
            and item["server"] == "ngtcp2perf"
            and item["backend"] == "syscall"
        )
        pair = cell["pairs"][0]
        calls = []

        def lane_trial(request, **kwargs):
            calls.append((dict(request), dict(kwargs)))
            return {
                "treatment": {
                    "scenario": "connect",
                    "server_backend": "syscall",
                    "reference_client_backend": self.spec.reference_client_backend,
                    "path_profile": "loopback",
                    "trace_seed": pair["pair_id"],
                },
                "negotiated": {"settings_match": True},
                "completion_status": "valid",
                "validity_reasons": [],
                "metric": {
                    "name": "validated_operations_per_second",
                    "derived_decimal": "200",
                    "numerator": 100,
                },
            }

        source = SimpleNamespace(_lane_trial=lane_trial)
        common = {
            "source": source,
            "spec": self.spec,
            "cell": cell,
            "pair": pair,
            "topology": object(),
            "lane_cgroups": (Path("/cgroup/server"), Path("/cgroup/client")),
            "path": object(),
            "coordinator_affinity": (0,),
            "diagnostic": True,
        }
        legacy = _strict_observation(mode="legacy", **common)
        v2 = _strict_observation(mode="v2", **common)

        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0][0]["request_id"], calls[1][0]["request_id"])
        self.assertEqual(
            {call[0]["trace_seed"] for call in calls},
            {pair["pair_id"]},
        )
        for request, kwargs in calls:
            self.assertEqual(request["phase"], "legacy_v2_parity")
            self.assertEqual(request["duration_ms"], 500)
            self.assertTrue(kwargs["construct_sample"])
            self.assertTrue(kwargs["allow_client_headroom_failure"])
            self.assertTrue(kwargs["allow_resolution_limited"])
        self.assertEqual(legacy["status"], "complete")
        self.assertEqual(legacy["metric"], "connections_per_second")
        self.assertEqual(v2["status"], "complete")
        self.assertEqual(v2["metric"], "validated_operations_per_second")
        self.assertEqual(legacy["value_decimal"], v2["value_decimal"])
        self.assertEqual(
            legacy["detail"],
            "resolution_limited_retained_for_20_pair_parity",
        )
        self.assertEqual(legacy["detail"], v2["detail"])

    def test_cleanup_parity_uses_cardinality_sufficient_duration(self) -> None:
        plan = build_plan(
            spec=self.spec,
            manifest=self.manifest,
            seed=bytes.fromhex("26" * 32),
            lanes=1,
            diagnostic_authorization={"status": "not_qualified"},
        )
        cell = next(
            item
            for item in plan["cells"]
            if item["scenario"] == "close_reset_cleanup"
            and item["server"] == "ngtcp2perf"
            and item["backend"] == "syscall"
        )
        pair = cell["pairs"][0]
        calls = []

        def lane_trial(request, **_kwargs):
            calls.append(dict(request))
            return {
                "treatment": {
                    "scenario": "close_reset_cleanup",
                    "server_backend": "syscall",
                    "reference_client_backend": self.spec.reference_client_backend,
                    "path_profile": "loopback",
                    "trace_seed": pair["pair_id"],
                },
                "negotiated": {"settings_match": True},
                "completion_status": "valid",
                "validity_reasons": [],
                "metric": {
                    "name": "cleanup_geometric_mean_operations_per_second",
                    "derived_decimal": "200",
                    "numerator": 400,
                },
            }

        observation = _strict_observation(
            mode="v2",
            source=SimpleNamespace(_lane_trial=lane_trial),
            spec=self.spec,
            cell=cell,
            pair=pair,
            topology=object(),
            lane_cgroups=(Path("/cgroup/server"), Path("/cgroup/client")),
            path=object(),
            coordinator_affinity=(0,),
            diagnostic=True,
        )
        self.assertEqual(calls[0]["duration_ms"], 2_000)
        self.assertEqual(observation["measurement_ns"], 2_000_000_000)
        self.assertEqual(observation["status"], "complete")

    def test_strict_pair_propagates_nonretryable_hardware_failure(self) -> None:
        plan = build_plan(
            spec=self.spec,
            manifest=self.manifest,
            seed=bytes.fromhex("27" * 32),
            lanes=1,
            diagnostic_authorization=None,
        )
        cell = next(
            item
            for item in plan["cells"]
            if item["scenario"] == "connect"
            and item["server"] == "ngtcp2perf"
            and item["backend"] == "syscall"
        )
        with self.assertRaisesRegex(HardwareUnqualifiedError, "policy_drift"):
            _strict_observation(
                mode="v2",
                source=SimpleNamespace(
                    _lane_trial=mock.Mock(
                        side_effect=HardwareUnqualifiedError("policy_drift")
                    )
                ),
                spec=self.spec,
                cell=cell,
                pair=cell["pairs"][0],
                topology=object(),
                lane_cgroups=(Path("/cgroup/server"), Path("/cgroup/client")),
                path=object(),
                coordinator_affinity=(0,),
                diagnostic=False,
            )

    def test_v2_rejects_legacy_loss_model_without_endpoint_execution(self) -> None:
        plan = build_plan(
            spec=self.spec,
            manifest=self.manifest,
            seed=bytes.fromhex("25" * 32),
            lanes=1,
            diagnostic_authorization={"status": "not_qualified"},
        )
        cell = next(
            item
            for item in plan["cells"]
            if item["scenario"] == "loss_recovery"
            and item["server"] == "ngtcp2perf"
            and item["backend"] == "syscall"
        )
        pair = cell["pairs"][0]
        source = SimpleNamespace(_lane_trial=mock.Mock())
        rejected = _v2_observation(
            source=source,
            spec=self.spec,
            cell=cell,
            pair=pair,
            topology=object(),
            lane_cgroups=(Path("/cgroup/server"), Path("/cgroup/client")),
            path=object(),
            coordinator_affinity=(0,),
            diagnostic=True,
        )
        self.assertEqual(rejected["status"], "invalid")
        self.assertEqual(
            rejected["detail"], "legacy_periodic_loss_model_rejected"
        )
        source._lane_trial.assert_not_called()

    def test_complete_equal_rates_and_idle_rejection_pass(self) -> None:
        plan = build_plan(
            spec=self.spec,
            manifest=self.manifest,
            seed=bytes.fromhex("34" * 32),
            lanes=2,
            diagnostic_authorization=None,
        )
        rows = []
        for cell in plan["cells"]:
            numeric = cell["classification"] == "numeric_parity"
            idle_invalid = (
                cell["classification"]
                == "legacy_invalid_replaced_by_memory_curve"
            )
            scenario = cell["scenario"]
            bit_rate = scenario in {
                "download",
                "upload",
                "multistream_download",
                "multistream_upload",
                "bidi",
                "loss_recovery",
                "flow_control",
            }
            legacy_metric = (
                "throughput_gbps"
                if bit_rate
                else {
                    "connect": "connections_per_second",
                    "resumed_connect": "connections_per_second",
                    "reqresp": "requests_per_second",
                    "zero_rtt_reqresp": "requests_per_second",
                    "stream_churn": "streams_per_second",
                    "close_reset_cleanup": "streams_per_second",
                    "small_payload_pps": "messages_per_second",
                    "datagram": "datagrams_per_second",
                }.get(scenario, "memory")
            )
            v2_metric = (
                "validated_body_bits_per_second"
                if bit_rate
                else "cleanup_geometric_mean_operations_per_second"
                if scenario == "close_reset_cleanup"
                else "validated_operations_per_second"
            )
            settings = canonical_bytes(_expected_settings(self.spec, cell)).decode()
            for pair in cell["pairs"]:
                rows.append(
                    {
                        "pair_id": pair["pair_id"],
                        "mode": "legacy",
                        "status": "complete" if numeric else "invalid",
                        "value_decimal": "100" if numeric else "1",
                        "metric": legacy_metric,
                        "settings_json": settings,
                        "detail": (
                            ""
                            if numeric
                            else "requires_duration_mode_adapter_api"
                            if idle_invalid
                            else "legacy_periodic_loss_model_is_unsynchronized"
                        ),
                        "measurement_ns": 1_000_000_000 if numeric else 0,
                        "wall_ns": 1_000_000_000 if numeric else 0,
                    }
                )
                rows.append(
                    {
                        "pair_id": pair["pair_id"],
                        "mode": "v2",
                        "status": "complete" if numeric else "invalid",
                        "value_decimal": "100" if numeric else None,
                        "metric": v2_metric if numeric else None,
                        "settings_json": settings,
                        "detail": (
                            ""
                            if numeric
                            else "replaced_by_memory_curve"
                            if idle_invalid
                            else "legacy_periodic_loss_model_rejected"
                        ),
                        "measurement_ns": 1_000_000_000 if numeric else 0,
                        "wall_ns": 1_000_000_000 if numeric else 0,
                    }
                )
        artifact = _analyze(plan=plan, rows=rows, wall_ns=2 * 60 * 60 * 1_000_000_000)
        self.assertTrue(artifact["parity_passed"])
        self.assertTrue(artifact["milestone_a"]["passed"])
        self.assertEqual(artifact["status"], "qualified")
        self.assertEqual(artifact["completed_pairs"], 7680)
        plan["diagnostic_authorization"] = {
            "artifact_hash": "a" * 64,
            "artifact_kind": "client-headroom",
            "content_sha256": "b" * 64,
            "identity_hash": "c" * 64,
            "profile_hash": "d" * 64,
            "reasons": ["physical_failure"],
            "status": "not_qualified",
        }
        diagnostic = _analyze(
            plan=plan,
            rows=rows,
            wall_ns=2 * 60 * 60 * 1_000_000_000,
        )
        self.assertEqual(
            diagnostic["status"], "diagnostic_complete_nonpublication"
        )
        self.assertTrue(diagnostic["parity_passed"])
        self.assertFalse(diagnostic["milestone_a"]["passed"])

    def test_incomplete_diagnostic_parity_is_not_terminal_complete(self) -> None:
        plan = build_plan(
            spec=self.spec,
            manifest=self.manifest,
            seed=bytes.fromhex("56" * 32),
            lanes=1,
            diagnostic_authorization={
                "artifact_hash": "a" * 64,
                "artifact_kind": "client-headroom",
                "content_sha256": "b" * 64,
                "identity_hash": "c" * 64,
                "profile_hash": "d" * 64,
                "reasons": ["physical_failure"],
                "status": "not_qualified",
            },
        )
        artifact = _analyze(plan=plan, rows=[], wall_ns=1)
        self.assertEqual(artifact["status"], "diagnostic_failed_nonpublication")
        self.assertFalse(artifact["publication_qualified"])
        self.assertFalse(artifact["parity_passed"])
        self.assertIn("DIAGNOSTIC", artifact["watermark"])

    def test_committed_pair_mode_is_immutable(self) -> None:
        observation = {
            "status": "complete",
            "value_decimal": "1",
            "metric": "throughput_gbps",
            "settings": {},
            "detail": "",
            "measurement_ns": 500_000_000,
            "wall_ns": 600_000_000,
        }
        with tempfile.TemporaryDirectory() as directory:
            state = _open_state(Path(directory) / "journal.sqlite3", "a" * 64)
            try:
                _record(state, threading.Lock(), "b" * 64, "legacy", observation)
                with self.assertRaises(sqlite3.IntegrityError):
                    _record(state, threading.Lock(), "b" * 64, "legacy", observation)
            finally:
                state.close()


if __name__ == "__main__":
    unittest.main()
