from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from quicperf_harness.canonical import canonical_bytes
from quicperf_harness.errors import IdentityMismatchError
from quicperf_harness.identity import (
    analysis_plan_hash,
    campaign_id,
    schedule_hash,
    spec_hash,
)
from quicperf_harness.journal import Journal
from quicperf_harness.manifest import manifest_hash, validate_manifest
from quicperf_harness.qualification import (
    QualificationDecision,
    QualificationError,
    build_qualification_identity,
    encode_qualification_artifact,
    qualification_identity_hash,
)
from quicperf_harness.qualification_commands import (
    EVIDENCE_SCHEMA_VERSION,
    acquire_qualification_artifact,
    qualification_status,
    store_qualification_evidence,
)
from quicperf_harness.spec import load_experiment_spec
from tests.test_v2_spec_identity import ROOT, manifest_fixture


PROFILE = ROOT / "profiles" / "v2" / "ci-smoke.json"
TAIL_PROFILE = ROOT / "profiles" / "v2" / "tail.json"


def make_run(
    root: Path, profile: Path = PROFILE
) -> tuple[Path, object, object, str]:
    root.mkdir(parents=True, exist_ok=True)
    spec = load_experiment_spec(profile)
    manifest_value = manifest_fixture()
    manifest_value["binaries"][0]["role"] = "server_reference_client"
    manifest = validate_manifest(manifest_value)
    schedule = {"schema_version": "qualification-command-test.v1", "blocks": []}
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
    return run_dir, spec, manifest, campaign_digest


def passing_worker_inputs(spec) -> dict[str, object]:
    adapter = spec.servers[0]
    backend = spec.server_backends[0]
    reset_cycles = [
        {
            "adapter": adapter,
            "backend": backend,
            "scenario": scenario,
            "cycle": cycle,
            "live_connections": 0,
            "live_streams": 0,
            "live_tickets": 0,
            "work_inventory": 0,
        }
        for scenario in spec.scenarios
        for cycle in range(1, 33)
    ]
    endurance = [
        {
            "adapter": adapter,
            "backend": backend,
            "cycle": cycle,
            "baseline_fd_count": 10,
            "fd_count": 10,
            "live_connections": 0,
            "live_streams": 0,
            "live_tickets": 0,
            "baseline_memory_bytes": 100_000_000,
            "reset_memory_bytes": 100_500_000,
        }
        for cycle in range(32, 1025, 32)
    ]
    parity = [
        {
            "adapter": adapter,
            "backend": backend,
            "sentinel": sentinel,
            "paired_blocks": 12,
            "interval_low_ratio": "0.99",
            "interval_high_ratio": "1.01",
            "reordered_ratio": "1",
            "confidence_level": "0.9",
        }
        for sentinel in (
            "multistream_download",
            "reqresp",
            "datagram",
            "loss_recovery",
        )
    ]
    return {
        "reset_cycles": reset_cycles,
        "endurance_checkpoints": endurance,
        "parity": parity,
        "leak_slopes": [
            {
                "adapter": adapter,
                "backend": backend,
                "baseline_memory_bytes": 100_000_000,
                "interval_low_bytes_per_cycle": "-1000",
                "interval_high_bytes_per_cycle": "1000",
                "confidence_level": "0.9",
            }
        ],
    }


def write_evidence(
    path: Path,
    identity_hash: str,
    inputs: dict[str, object],
    *,
    kind: str = "worker-reuse",
) -> None:
    path.write_bytes(
        canonical_bytes(
            {
                "schema_version": EVIDENCE_SCHEMA_VERSION,
                "artifact_kind": kind,
                "identity_hash": identity_hash,
                "inputs": inputs,
            }
        )
        + b"\n"
    )


class QualificationCommandTests(unittest.TestCase):
    def test_host_stability_cannot_be_imported_as_offline_evidence(self) -> None:
        with self.assertRaisesRegex(QualificationError, "live-only"):
            store_qualification_evidence(
                run_dir=Path("unused"),
                kind="host-stability",
                evidence_path=Path("unused.json"),
                artifact_store=Path("unused-store"),
            )

    def test_status_store_acquire_is_exact_idempotent_and_auditable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir, spec, manifest, _campaign = make_run(root)
            store = root / "qualification-store"
            identity = build_qualification_identity("worker-reuse", spec, manifest)
            identity_digest = qualification_identity_hash("worker-reuse", identity)
            evidence = root / "evidence.json"
            write_evidence(evidence, identity_digest, passing_worker_inputs(spec))

            missing = qualification_status(
                run_dir=run_dir,
                kind="worker-reuse",
                artifact_store=store,
            )
            self.assertEqual(missing["status"], "not_run")
            self.assertFalse(missing["qualified"])

            stored = store_qualification_evidence(
                run_dir=run_dir,
                kind="worker-reuse",
                evidence_path=evidence,
                artifact_store=store,
            )
            self.assertTrue(stored["qualified"])
            self.assertEqual(
                stored["artifact_hash"],
                store_qualification_evidence(
                    run_dir=run_dir,
                    kind="worker-reuse",
                    evidence_path=evidence,
                    artifact_store=store,
                )["artifact_hash"],
            )
            available = qualification_status(
                run_dir=run_dir,
                kind="worker-reuse",
                artifact_store=store,
            )
            self.assertTrue(available["stored"])
            self.assertFalse(available["acquired"])

            acquired = acquire_qualification_artifact(
                run_dir=run_dir,
                kind="worker-reuse",
                artifact_store=store,
            )
            self.assertTrue(acquired["qualified"])
            self.assertEqual(
                acquired["artifact_hash"],
                acquire_qualification_artifact(
                    run_dir=run_dir,
                    kind="worker-reuse",
                    artifact_store=store,
                )["artifact_hash"],
            )
            final = qualification_status(
                run_dir=run_dir,
                kind="worker-reuse",
                artifact_store=store,
            )
            self.assertTrue(final["stored"])
            self.assertTrue(final["acquired"])
            with Journal(run_dir) as journal:
                content = bytes(
                    journal.connection.execute(
                        "SELECT content FROM artifact WHERE path='qualification/worker-reuse.json'"
                    ).fetchone()["content"]
                )
            document = json.loads(content)
            self.assertEqual(
                document["evidence"]["input_sha256"],
                hashlib.sha256(evidence.read_bytes()).hexdigest(),
            )
            self.assertIn("reset_cycles", document["evidence"]["inputs"])

    def test_target_scope_is_not_caller_reducible_and_not_run_is_never_stored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir, spec, manifest, _campaign = make_run(root)
            identity = build_qualification_identity("worker-reuse", spec, manifest)
            identity_digest = qualification_identity_hash("worker-reuse", identity)
            inputs = passing_worker_inputs(spec)
            inputs["reset_cycles"] = inputs["reset_cycles"][:-1]
            evidence = root / "reduced.json"
            write_evidence(evidence, identity_digest, inputs)
            result = store_qualification_evidence(
                run_dir=run_dir,
                kind="worker-reuse",
                evidence_path=evidence,
                artifact_store=root / "store",
            )
            self.assertFalse(result["qualified"])
            self.assertTrue(any("missing_reset_cycle" in reason for reason in result["reasons"]))

            wrong = root / "wrong.json"
            write_evidence(wrong, "0" * 64, passing_worker_inputs(spec))
            with self.assertRaisesRegex(QualificationError, "identity mismatch"):
                store_qualification_evidence(
                    run_dir=run_dir,
                    kind="worker-reuse",
                    evidence_path=wrong,
                    artifact_store=root / "other-store",
                )
            self.assertFalse((root / "other-store").exists())

            noncanonical = root / "noncanonical.json"
            write_evidence(noncanonical, identity_digest, passing_worker_inputs(spec))
            noncanonical.write_bytes(noncanonical.read_bytes() + b" ")
            with self.assertRaisesRegex(QualificationError, "not canonical"):
                store_qualification_evidence(
                    run_dir=run_dir,
                    kind="worker-reuse",
                    evidence_path=noncanonical,
                    artifact_store=root / "noncanonical-store",
                )

            real_store = root / "real-store"
            real_store.mkdir()
            linked_store = root / "linked-store"
            linked_store.symlink_to(real_store, target_is_directory=True)
            with self.assertRaisesRegex(QualificationError, "real directory"):
                qualification_status(
                    run_dir=run_dir,
                    kind="worker-reuse",
                    artifact_store=linked_store,
                )

    def test_acquire_rejects_preexisting_different_valid_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir, spec, manifest, campaign_digest = make_run(root)
            identity = build_qualification_identity("worker-reuse", spec, manifest)
            identity_digest = qualification_identity_hash("worker-reuse", identity)
            evidence = root / "evidence.json"
            write_evidence(evidence, identity_digest, passing_worker_inputs(spec))
            store = root / "store"
            store_qualification_evidence(
                run_dir=run_dir,
                kind="worker-reuse",
                evidence_path=evidence,
                artifact_store=store,
            )
            conflicting, _hash, _identity = encode_qualification_artifact(
                "worker-reuse",
                identity,
                QualificationDecision(
                    "worker-reuse", "not_qualified", ("physical_failure",), {"x": 1}
                ),
            )
            with Journal(run_dir) as journal:
                journal.store_artifact(
                    campaign_digest,
                    "qualification/worker-reuse.json",
                    conflicting,
                    media_type="application/json",
                )
            with self.assertRaisesRegex(IdentityMismatchError, "different artifact bytes"):
                acquire_qualification_artifact(
                    run_dir=run_dir,
                    kind="worker-reuse",
                    artifact_store=store,
                )

    def test_every_gate_kind_has_a_complete_deterministic_command_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir, spec, manifest, _campaign = make_run(root)
            server = spec.servers[0]
            backend = spec.server_backends[0]
            cases = {
                "worker-reuse": passing_worker_inputs(spec),
                "client-headroom": {
                    "screens": [
                        {
                            "server": server,
                            "backend": backend,
                            "scenario": scenario,
                            "client_cpu_ns_per_wall_ns": pressure,
                        }
                        for scenario, pressure in (
                            ("multistream_download", "0.5"),
                            ("small_payload_pps", "0.6"),
                            ("datagram", "0.7"),
                        )
                    ],
                    "held_out": {
                        "server": server,
                        "backend": backend,
                        "scenario": "datagram",
                        "blocks": 12,
                        "treatment_client_cores": 2,
                        "treatment_p95_cpu": ["0.79"] * 12,
                    },
                },
                "lane-interference": {
                    "screens": [
                        {
                            "server": server,
                            "backend": backend,
                            "scenario": scenario,
                            "pressure": "1",
                        }
                        for scenario in (
                            "reqresp",
                            "datagram",
                            "multistream_download",
                            "loss_recovery",
                        )
                    ],
                    "held_out": [
                        {
                            "dimension": dimension,
                            "server": server,
                            "backend": backend,
                            "scenario": scenario,
                            "paired_blocks": 20,
                            "rate_interval_low_ratio": "0.99",
                            "rate_interval_high_ratio": "1.01",
                            "memory_interval_low_ratio": "0.99",
                            "memory_interval_high_ratio": "1.01",
                            "one_lane_variance": "1",
                            "two_lane_variance": "1.25",
                            "one_lane_ci_width": "1",
                            "two_lane_ci_width": "1.25",
                            "confidence_level": "0.9",
                        }
                        for dimension, scenario in (
                            ("combined_endpoint_cpu", "reqresp"),
                            ("udp_packet_rate", "datagram"),
                            ("validated_byte_rate", "multistream_download"),
                            ("timer_recovery_wakeups", "loss_recovery"),
                        )
                    ],
                },
                "window-qualification": {
                    "screens": [
                        {
                            "server": server,
                            "backend": backend,
                            "scenario": scenario,
                            "short_rate": "100",
                            "reference_rate": "100",
                            "short_classification": "valid",
                            "reference_classification": "valid",
                            "cap_hit": False,
                            "stalled": False,
                            "short_window_seconds": 2,
                            "reference_window_seconds": 10,
                        }
                        for scenario in spec.scenarios
                    ],
                    "held_out": [
                        {
                            "server": server,
                            "backend": backend,
                            "scenario": scenario,
                            "paired_blocks": 20,
                            "interval_low_ratio": "0.99",
                            "interval_high_ratio": "1.01",
                            "short_log_variance": "1",
                            "reference_log_variance": "1",
                            "classifications": [["valid", "valid"]] * 20,
                            "confidence_level": "0.9",
                        }
                        for scenario in spec.scenarios
                    ],
                    "contrasts": [],
                },
            }
            for kind, inputs in cases.items():
                with self.subTest(kind=kind):
                    identity = build_qualification_identity(kind, spec, manifest)
                    identity_digest = qualification_identity_hash(kind, identity)
                    evidence = root / f"{kind}.json"
                    write_evidence(evidence, identity_digest, inputs, kind=kind)
                    result = store_qualification_evidence(
                        run_dir=run_dir,
                        kind=kind,
                        evidence_path=evidence,
                        artifact_store=root / "store-all",
                    )
                    self.assertTrue(result["qualified"], result)

            tail_run, tail_spec, tail_manifest, _campaign = make_run(
                root / "tail", TAIL_PROFILE
            )
            prefixes = [
                {
                    "duration_seconds": duration,
                    "eligible_operations": 1_500,
                    "failed_or_censored_operations": 0,
                    "p99_ns": 1_000,
                    "validity_classification": "valid",
                    "capped_or_stalled": False,
                }
                for duration in (2, 5, 10, 20)
            ]
            tail_inputs = {
                "screens": [
                    {
                        "scenario": scenario,
                        "server": server,
                        "server_backend": backend,
                        "reference_client": client,
                        "prefixes": prefixes,
                    }
                    for scenario in tail_spec.scenarios
                    for server in tail_spec.servers
                    for backend in tail_spec.server_backends
                    for client in tail_spec.reference_clients
                ],
                "held_out": [
                    {
                        "scenario": scenario,
                        "server": "ngtcp2perf",
                        "server_backend": backend,
                        "reference_client": client,
                        "block": block,
                        "prefixes": [
                            {**prefix, "eligible_operations": 1_100}
                            for prefix in prefixes
                        ],
                    }
                    for scenario in tail_spec.scenarios
                    for backend in tail_spec.server_backends
                    for client in tail_spec.reference_clients
                    for block in range(1, 21)
                ],
            }
            tail_identity = build_qualification_identity(
                "tail-window", tail_spec, tail_manifest
            )
            tail_evidence = root / "tail-window.json"
            write_evidence(
                tail_evidence,
                qualification_identity_hash("tail-window", tail_identity),
                tail_inputs,
                kind="tail-window",
            )
            tail_result = store_qualification_evidence(
                run_dir=tail_run,
                kind="tail-window",
                evidence_path=tail_evidence,
                artifact_store=root / "store-all",
            )
            self.assertTrue(tail_result["qualified"], tail_result)

    def test_cli_exposes_qualification_and_nonpassing_status_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir, _spec, _manifest, _campaign = make_run(root)
            help_result = subprocess.run(
                [str(ROOT / "tools" / "quicperfctl"), "--help"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(help_result.returncode, 0)
            self.assertIn("qualification", help_result.stdout)
            status = subprocess.run(
                [
                    str(ROOT / "tools" / "quicperfctl"),
                    "qualification",
                    "status",
                    "--kind",
                    "worker-reuse",
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
            self.assertEqual(status.returncode, 2, status.stderr)
            self.assertEqual(json.loads(status.stdout)["status"], "not_run")


if __name__ == "__main__":
    unittest.main()
