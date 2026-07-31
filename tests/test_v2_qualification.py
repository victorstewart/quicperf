from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from quicperf_harness.canonical import canonical_bytes
from quicperf_harness.qualification import (
    EnduranceCheckpointEvidence,
    HeadroomPairEvidence,
    HeadroomScreenEvidence,
    LanePairEvidence,
    LaneScreenEvidence,
    LeakSlopeEvidence,
    QualificationArtifactBusyError,
    QualificationArtifactStore,
    QualificationDecision,
    QualificationError,
    ResetCycleEvidence,
    ReuseParityEvidence,
    WindowContrastEvidence,
    WindowPairEvidence,
    WindowScreenEvidence,
    build_qualification_identity,
    decode_qualification_artifact,
    encode_qualification_artifact,
    evaluate_client_headroom,
    evaluate_lane_interference,
    evaluate_window_equivalence,
    evaluate_worker_reuse,
    not_run,
    qualification_identity_hash,
    worker_reuse_eligible_scenario,
)
from quicperf_harness.manifest import validate_manifest
from quicperf_harness.spec import load_experiment_spec
from tests.test_v2_spec_identity import ROOT, manifest_fixture


HASH = "a" * 64


def identity(kind: str) -> dict[str, object]:
    common: dict[str, object] = {
        "binary_hashes": {"server": HASH},
        "dependency_hashes": {"lock": HASH},
        "source_hash": HASH,
        "host_policy_hash": HASH,
        "profile_hash": HASH,
        "analysis_plan_hash": HASH,
        "packet_protocol_hash": HASH,
        "workload_protocol_hash": HASH,
        "control_protocol_hash": HASH,
    }
    if kind == "worker-reuse":
        common["reset_protocol_hash"] = HASH
    if kind == "window-qualification":
        return {
            "adapter_binary_hashes": {"server": HASH},
            "library_hashes": {"libquic": HASH},
            "build_hash": HASH,
            "driver_hash": HASH,
            "workload_protocol_hash": HASH,
            "control_protocol_hash": HASH,
            "payload_policy_hash": HASH,
            "window_policy_hash": HASH,
            "resource_policy_hash": HASH,
            "path_policy_hash": HASH,
            "host_kernel_microcode_hash": HASH,
            "source_hash": HASH,
            "profile_hash": HASH,
            "analysis_plan_hash": HASH,
        }
    return common


class QualificationArtifactTests(unittest.TestCase):
    def test_frozen_identity_builder_covers_each_gate_and_is_field_sensitive(self) -> None:
        spec = load_experiment_spec(ROOT / "profiles" / "v2" / "ci-smoke.json")
        original = manifest_fixture()
        original["binaries"][0]["role"] = "server_reference_client"
        manifest = validate_manifest(original)
        for kind in (
            "worker-reuse",
            "lane-interference",
            "client-headroom",
            "window-qualification",
        ):
            with self.subTest(kind=kind):
                first = build_qualification_identity(kind, spec, manifest)
                self.assertEqual(first, build_qualification_identity(kind, spec, manifest))
                changed = manifest_fixture()
                changed["binaries"][0]["role"] = "server_reference_client"
                changed["host_policy"]["microcode"] = "0x124"
                second = build_qualification_identity(
                    kind, spec, validate_manifest(changed)
                )
                self.assertNotEqual(
                    qualification_identity_hash(kind, first),
                    qualification_identity_hash(kind, second),
                )
                changed_source = copy.deepcopy(original)
                changed_source["source"]["tree_sha256"] = "9" * 64
                third = build_qualification_identity(
                    kind, spec, validate_manifest(changed_source)
                )
                self.assertNotEqual(
                    qualification_identity_hash(kind, first),
                    qualification_identity_hash(kind, third),
                )

    def test_round_trip_is_canonical_content_addressed_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = QualificationArtifactStore(temporary)
            expected_identity = identity("worker-reuse")
            decision = QualificationDecision(
                "worker-reuse", "qualified", (), {"cycles": 1024}
            )
            first = store.store("worker-reuse", expected_identity, decision)
            second = store.store("worker-reuse", expected_identity, decision)
            self.assertEqual(first, second)
            self.assertEqual(first.path.name, f"{first.artifact_hash}.json")
            self.assertEqual(first.path.parent.name, first.identity_hash)
            self.assertEqual(first.path.read_bytes(), canonical_bytes(json.loads(first.path.read_bytes())) + b"\n")
            loaded = store.load("worker-reuse", expected_identity)
            self.assertTrue(loaded.decision.qualified)
            self.assertEqual(loaded.decision.evidence, {"cycles": 1024})

    def test_corrupt_old_schema_cross_identity_and_partial_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = QualificationArtifactStore(temporary)
            expected_identity = identity("client-headroom")
            decision = QualificationDecision(
                "client-headroom", "not_qualified", ("cpu",), {"max_cpu": "0.81"}
            )
            stored = store.store("client-headroom", expected_identity, decision)
            original = stored.path.read_bytes()
            stored.path.write_bytes(original.replace(b'"cpu"', b'"gpu"'))
            with self.assertRaisesRegex(QualificationError, "hash mismatch"):
                store.load("client-headroom", expected_identity)

            stored.path.write_bytes(original)
            document = json.loads(original)
            document["schema_version"] = 0
            stored.path.write_bytes(canonical_bytes(document) + b"\n")
            with self.assertRaisesRegex(QualificationError, "schema version"):
                store.load("client-headroom", expected_identity)

            stored.path.write_bytes(original)
            changed_identity = dict(expected_identity)
            changed_identity["host_policy_hash"] = "b" * 64
            changed_dir = (
                Path(temporary)
                / "client-headroom"
                / qualification_identity_hash("client-headroom", changed_identity)
            )
            changed_dir.mkdir()
            copied = changed_dir / stored.path.name
            copied.write_bytes(original)
            with self.assertRaisesRegex(QualificationError, "identity mismatch"):
                store.load("client-headroom", changed_identity)

            (stored.path.parent / ".partial.tmp").write_bytes(b"partial")
            with self.assertRaisesRegex(QualificationError, "exactly one"):
                store.load("client-headroom", expected_identity)

    def test_concurrent_lock_and_conflicting_decision_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = QualificationArtifactStore(temporary)
            expected_identity = identity("lane-interference")
            identity_hash = qualification_identity_hash(
                "lane-interference", expected_identity
            )
            lock = Path(temporary) / "lane-interference" / f"{identity_hash}.lock"
            lock.parent.mkdir(parents=True)
            lock.write_text("concurrent")
            decision = QualificationDecision(
                "lane-interference", "qualified", (), {"max_lanes": 2}
            )
            with self.assertRaises(QualificationArtifactBusyError):
                store.store("lane-interference", expected_identity, decision)
            lock.unlink()
            store.store("lane-interference", expected_identity, decision)
            failure = QualificationDecision(
                "lane-interference", "not_qualified", ("variance",), {"max_lanes": 1}
            )
            with self.assertRaisesRegex(QualificationError, "different decision"):
                store.store("lane-interference", expected_identity, failure)

    def test_identity_schema_and_not_run_cannot_be_reused(self) -> None:
        missing = identity("worker-reuse")
        del missing["reset_protocol_hash"]
        with self.assertRaisesRegex(QualificationError, "reset_protocol_hash"):
            encode_qualification_artifact(
                "worker-reuse",
                missing,
                QualificationDecision("worker-reuse", "qualified", (), {}),
            )
        decision = not_run("worker-reuse", "qualified host unavailable")
        with self.assertRaisesRegex(QualificationError, "pass/fail"):
            encode_qualification_artifact("worker-reuse", identity("worker-reuse"), decision)

    def test_failed_atomic_replace_leaves_no_partial_decision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = QualificationArtifactStore(temporary)
            expected_identity = identity("client-headroom")
            decision = QualificationDecision(
                "client-headroom", "qualified", (), {"paired_blocks": 12}
            )
            with mock.patch("quicperf_harness.qualification.os.replace", side_effect=OSError("full")):
                with self.assertRaisesRegex(QualificationError, "cannot store"):
                    store.store("client-headroom", expected_identity, decision)
            identity_hash = qualification_identity_hash(
                "client-headroom", expected_identity
            )
            kind_dir = Path(temporary) / "client-headroom"
            self.assertFalse((kind_dir / f"{identity_hash}.lock").exists())
            self.assertEqual(list((kind_dir / identity_hash).iterdir()), [])
            self.assertTrue(
                store.store("client-headroom", expected_identity, decision).decision.qualified
            )

    def test_decoder_rejects_noncanonical_and_wrong_kind(self) -> None:
        expected_identity = identity("worker-reuse")
        content, _, _ = encode_qualification_artifact(
            "worker-reuse",
            expected_identity,
            QualificationDecision("worker-reuse", "qualified", (), {"cycles": 1024}),
        )
        with self.assertRaisesRegex(QualificationError, "canonical"):
            decode_qualification_artifact(
                b" " + content,
                expected_kind="worker-reuse",
                expected_identity=expected_identity,
            )
        with self.assertRaises(QualificationError):
            decode_qualification_artifact(
                content,
                expected_kind="client-headroom",
                expected_identity=identity("client-headroom"),
            )


def passing_worker_evidence():
    reset = tuple(
        ResetCycleEvidence("a", "syscall", "reqresp", cycle, 0, 0, 0, 0)
        for cycle in range(1, 33)
    )
    endurance = tuple(
        EnduranceCheckpointEvidence(
            "a", "syscall", cycle, 10, 10, 0, 0, 0, 100_000_000, 100_500_000
        )
        for cycle in range(32, 1025, 32)
    )
    parity = tuple(
        ReuseParityEvidence("a", "syscall", sentinel, 12, "0.99", "1.01", "1")
        for sentinel in (
            "multistream_download",
            "reqresp",
            "datagram",
            "loss_recovery",
        )
    )
    leak = (LeakSlopeEvidence("a", "syscall", 100_000_000, "-1000", "1000"),)
    return reset, endurance, parity, leak


class WorkerReuseEvaluatorTests(unittest.TestCase):
    def test_fresh_process_scenarios_are_not_reset_eligible(self) -> None:
        self.assertTrue(worker_reuse_eligible_scenario("reqresp"))
        for scenario in (
            "connect",
            "resumed_connect",
            "zero_rtt_reqresp",
            "memory_curve",
        ):
            with self.subTest(scenario=scenario):
                self.assertFalse(worker_reuse_eligible_scenario(scenario))

    def evaluate(self, reset, endurance, parity, leak):
        return evaluate_worker_reuse(
            expected_reset_cells=(("a", "syscall", "reqresp"),),
            expected_adapter_backends=(("a", "syscall"),),
            reset_cycles=reset,
            endurance_checkpoints=endurance,
            parity=parity,
            leak_slopes=leak,
        )

    def test_exact_reset_endurance_parity_and_leak_thresholds_pass(self) -> None:
        decision = self.evaluate(*passing_worker_evidence())
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.evidence["reset_cycles"], 32)
        self.assertEqual(decision.evidence["endurance_checkpoints"], 32)

    def test_each_worker_subgate_fails_closed(self) -> None:
        reset, endurance, parity, leak = passing_worker_evidence()
        bad_reset = (replace(reset[0], live_streams=1),) + reset[1:]
        decision = self.evaluate(bad_reset, endurance, parity, leak)
        self.assertTrue(any("reset_state_not_empty" in item for item in decision.reasons))

        bad_endurance = (replace(endurance[0], fd_count=11),) + endurance[1:]
        decision = self.evaluate(reset, bad_endurance, parity, leak)
        self.assertTrue(any("endurance_fd" in item for item in decision.reasons))

        bad_parity = (replace(parity[0], interval_high_ratio="1.0200001"),) + parity[1:]
        decision = self.evaluate(reset, endurance, bad_parity, leak)
        self.assertTrue(any("reuse_parity_interval" in item for item in decision.reasons))

        wrong_confidence = (replace(parity[0], confidence_level="0.95"),) + parity[1:]
        decision = self.evaluate(reset, endurance, wrong_confidence, leak)
        self.assertTrue(any("reuse_parity_confidence" in item for item in decision.reasons))

        bad_leak = (replace(leak[0], interval_high_bytes_per_cycle="1024.1"),)
        decision = self.evaluate(reset, endurance, parity, bad_leak)
        self.assertTrue(any("leak_slope_interval" in item for item in decision.reasons))


def headroom_screens():
    return tuple(
        HeadroomScreenEvidence(
            server,
            "syscall",
            scenario,
            "0.9" if (server, scenario) == ("b", "datagram") else "0.5",
        )
        for server in ("a", "b")
        for scenario in ("multistream_download", "small_payload_pps", "datagram")
    )


class HeadroomAndLaneEvaluatorTests(unittest.TestCase):
    def test_headroom_uses_frozen_screen_and_strict_cpu_limit(self) -> None:
        held = HeadroomPairEvidence(
            "b", "syscall", "datagram", 12, 4, ("0.79",) * 12
        )
        decision = evaluate_client_headroom(
            servers=("a", "b"),
            backends=("syscall",),
            treatment_client_cores=4,
            screens=headroom_screens(),
            held_out=held,
        )
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.evidence["selected_cell"], ["b", "syscall", "datagram"])
        self.assertEqual(decision.evidence["treatment_client_cores"], 4)

        decision = evaluate_client_headroom(
            servers=("a", "b"),
            backends=("syscall",),
            treatment_client_cores=4,
            screens=headroom_screens(),
            held_out=replace(
                held,
                treatment_p95_cpu=("0.80",) + ("0.79",) * 11,
            ),
        )
        self.assertIn("headroom_treatment_cpu", decision.reasons)

        decision = evaluate_client_headroom(
            servers=("a", "b"),
            backends=("syscall",),
            treatment_client_cores=4,
            screens=headroom_screens(),
            held_out=replace(held, treatment_client_cores=2),
        )
        self.assertIn("headroom_treatment_core_count", decision.reasons)

    def test_lane_selection_and_all_interference_thresholds(self) -> None:
        scenarios = ("reqresp", "datagram", "multistream_download", "loss_recovery")
        screens = tuple(
            LaneScreenEvidence(
                server,
                "syscall",
                scenario,
                "2" if server == "b" else "1",
            )
            for server in ("a", "b")
            for scenario in scenarios
        )
        dimension_by_scenario = {
            "reqresp": "combined_endpoint_cpu",
            "datagram": "udp_packet_rate",
            "multistream_download": "validated_byte_rate",
            "loss_recovery": "timer_recovery_wakeups",
        }
        held = tuple(
            LanePairEvidence(
                dimension_by_scenario[scenario],
                "b",
                "syscall",
                scenario,
                20,
                "0.98",
                "1.02",
                "0.95",
                "1.05",
                "1",
                "1.25",
                "2",
                "2.5",
            )
            for scenario in scenarios
        )
        decision = evaluate_lane_interference(
            servers=("a", "b"), backends=("syscall",), screens=screens, held_out=held
        )
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.evidence["max_lanes"], 2)

        failed = (replace(held[0], two_lane_variance="1.2501"),) + held[1:]
        decision = evaluate_lane_interference(
            servers=("a", "b"), backends=("syscall",), screens=screens, held_out=failed
        )
        self.assertFalse(decision.qualified)
        self.assertEqual(decision.evidence["max_lanes"], 1)
        self.assertTrue(any("variance_inflation" in item for item in decision.reasons))


class WindowEvaluatorTests(unittest.TestCase):
    def passing_evidence(self):
        screens = (
            WindowScreenEvidence(
                "base", "syscall", "download", "100", "100", "valid", "valid", False, False, 2, 10
            ),
            WindowScreenEvidence(
                "selected", "syscall", "download", "103", "100", "valid", "valid", False, False, 2, 10
            ),
        )
        classifications = (("valid", "valid"),) * 20
        held = (
            WindowPairEvidence(
                "base", "syscall", "download", 20, "0.99", "1.01", "1", "1", classifications
            ),
            WindowPairEvidence(
                "selected", "syscall", "download", 20, "0.98", "1.02", "1.25", "1", classifications
            ),
        )
        contrasts = (
            WindowContrastEvidence(
                "syscall", "download", "selected", "base", 20, "0.98", "1.02"
            ),
        )
        return screens, held, contrasts

    def evaluate(self, screens, held, contrasts):
        return evaluate_window_equivalence(
            servers=("base", "selected"),
            backends=("syscall",),
            scenarios=("download",),
            baseline_server="base",
            screens=screens,
            held_out=held,
            contrasts=contrasts,
        )

    def test_window_screen_selection_and_held_out_boundaries_pass(self) -> None:
        decision = self.evaluate(*self.passing_evidence())
        self.assertTrue(decision.qualified)
        self.assertEqual(decision.evidence["selected_servers"], {"syscall/download": "selected"})
        self.assertEqual(decision.evidence["enabled_windows_seconds"], [2, 5])

    def test_window_semantics_variance_and_contrast_fail_closed(self) -> None:
        screens, held, contrasts = self.passing_evidence()
        bad_screens = (replace(screens[0], cap_hit=True), screens[1])
        bad_held = (held[0], replace(held[1], short_log_variance="1.2501"))
        bad_contrasts = (replace(contrasts[0], interval_high_ratio="1.0201"),)
        decision = self.evaluate(bad_screens, bad_held, bad_contrasts)
        self.assertFalse(decision.qualified)
        self.assertTrue(any("screen_semantics" in item for item in decision.reasons))
        self.assertTrue(any("variance_inflation" in item for item in decision.reasons))
        self.assertTrue(any("contrast_interval" in item for item in decision.reasons))
        self.assertEqual(decision.evidence["enabled_windows_seconds"], [10, 20])


if __name__ == "__main__":
    unittest.main()
