from __future__ import annotations

import copy
from collections import Counter
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from quicperf_harness.canonical import canonical_bytes
from quicperf_harness.interoperability import (
    FAIL,
    PASS,
    InteroperabilityArtifactStore,
    InteroperabilityError,
    NativeInteroperabilityExecutor,
    POST_TRIAL_QUIESCENCE_SECONDS,
    build_interoperability_identity,
    interoperability_identity_hash,
    interoperability_plan_hash,
    plan_interoperability,
)
from quicperf_harness.manifest import validate_manifest
from quicperf_harness.runner import _native_interoperability_reasons
from quicperf_harness.spec import load_experiment_spec
from tests.test_v2_spec_identity import ROOT, manifest_fixture


def manifest_for(spec):
    value = manifest_fixture()
    prototype = value["binaries"][0]
    binaries = []
    for index, name in enumerate(sorted(set(spec.servers) | set(spec.reference_clients))):
        binary = copy.deepcopy(prototype)
        binary.update(
            {
                "name": name,
                "role": (
                    "server_reference_client"
                    if name in spec.reference_clients
                    else "server"
                ),
                "path": f"/opt/quicperf/bin/{name}",
                "sha256": f"{index + 16:064x}",
                "elf_build_id": f"{index + 16:016x}",
            }
        )
        binaries.append(binary)
    value["binaries"] = binaries
    return validate_manifest(value)


class InteroperabilityPlanTests(unittest.TestCase):
    def test_v23_plan_is_exactly_180_iouring_records_and_client_balanced(
        self,
    ):
        spec = load_experiment_spec(ROOT / "profiles/v2.3/publication.json")
        manifest = manifest_for(spec)
        identity = build_interoperability_identity(spec, manifest)
        planned = plan_interoperability(
            spec, interoperability_identity_hash(identity)
        )
        self.assertEqual(len(planned), 180)
        self.assertEqual({item.server_backend for item in planned}, {"iouring"})
        self.assertEqual(
            Counter(item.reference_client for item in planned),
            Counter({"ngtcp2perf": 90, "picoperf": 90}),
        )
        self.assertEqual(
            Counter((item.server, item.scenario) for item in planned),
            Counter(
                {
                    (server, scenario): 1
                    for server in spec.servers
                    for scenario in spec.scenarios
                }
            ),
        )

    def test_canonical_plan_is_exact_unique_deterministic_and_identity_ordered(self):
        spec = load_experiment_spec(ROOT / "profiles/v2/publication.json")
        manifest = manifest_for(spec)
        identity = build_interoperability_identity(spec, manifest)
        identity_hash = interoperability_identity_hash(identity)
        first = plan_interoperability(spec, identity_hash)
        second = plan_interoperability(spec, identity_hash)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 180)
        self.assertEqual({item.execution_order for item in first}, set(range(180)))
        self.assertEqual(len({item.tuple_id for item in first}), 180)
        self.assertEqual(
            {(item.server, item.scenario) for item in first},
            {
                (server, scenario)
                for server in spec.servers
                for scenario in spec.scenarios
            },
        )
        per_scenario = Counter(
            (item.scenario, item.reference_client, item.server_backend)
            for item in first
        )
        self.assertEqual(set(per_scenario.values()), {3})
        for server in spec.servers:
            per_server = Counter(
                (item.reference_client, item.server_backend)
                for item in first
                if item.server == server
            )
            self.assertEqual(set(per_server), {
                (client, backend)
                for client in spec.reference_clients
                for backend in spec.server_backends
            })
            self.assertEqual(set(per_server.values()), {3, 4})
        changed = copy.deepcopy(manifest_fixture())
        changed["source"]["tree_sha256"] = "9" * 64
        changed["binaries"] = json.loads(canonical_bytes(manifest.binaries))
        changed_manifest = validate_manifest(changed)
        changed_identity = build_interoperability_identity(spec, changed_manifest)
        changed_plan = plan_interoperability(
            spec, interoperability_identity_hash(changed_identity)
        )
        self.assertNotEqual(
            [item.tuple_id for item in first],
            [item.tuple_id for item in changed_plan],
        )

    def test_store_is_content_addressed_exact_and_retains_failing_records(self):
        spec = load_experiment_spec(ROOT / "profiles/v2/ci-smoke.json")
        manifest = manifest_for(spec)
        identity = build_interoperability_identity(spec, manifest)
        calls = []

        def execute(item):
            calls.append(item.tuple_id)
            if item.execution_order == 1:
                return FAIL, "semantic_oracle_failed", {"oracle": "failed"}
            return PASS, "semantic_oracle_passed", {"oracle": "passed"}

        with tempfile.TemporaryDirectory() as temporary:
            store = InteroperabilityArtifactStore(Path(temporary))
            artifact = store.refresh(spec, identity, execute)
            self.assertEqual(len(calls), 2)
            self.assertEqual((artifact.status, artifact.passed, artifact.failed), (FAIL, 1, 1))
            self.assertIsNotNone(artifact.path)
            loaded = store.load_optional(spec, identity)
            self.assertEqual(loaded, artifact)
            self.assertEqual(
                artifact.plan_hash,
                interoperability_plan_hash(
                    plan_interoperability(
                        spec, interoperability_identity_hash(identity)
                    )
                ),
            )
            content = artifact.path.read_bytes()
            document = json.loads(content)
            document["records"][0]["scenario"] = "wrong"
            artifact.path.write_bytes(canonical_bytes(document) + b"\n")
            with self.assertRaisesRegex(
                InteroperabilityError, "does not match its plan"
            ):
                store.load_optional(spec, identity)

    def test_checkpoint_resume_executes_only_missing_plan_suffix(self):
        spec = load_experiment_spec(ROOT / "profiles/v2/ci-smoke.json")
        manifest = manifest_for(spec)
        identity = build_interoperability_identity(spec, manifest)
        calls = []

        def interrupt(item):
            calls.append(item.tuple_id)
            if len(calls) == 2:
                raise KeyboardInterrupt
            return PASS, "semantic_oracle_passed", {"tuple": item.tuple_id}

        with tempfile.TemporaryDirectory() as temporary:
            store = InteroperabilityArtifactStore(Path(temporary))
            with self.assertRaises(KeyboardInterrupt):
                store.refresh(spec, identity, interrupt)
            resumed = []

            def finish(item):
                resumed.append(item.tuple_id)
                return PASS, "semantic_oracle_passed", {"tuple": item.tuple_id}

            artifact = store.refresh(spec, identity, finish)
            self.assertEqual(artifact.status, PASS)
            self.assertEqual(artifact.passed, 2)
            self.assertEqual(len(resumed), 1)

    def test_checkpoint_must_be_canonical_and_not_a_symlink(self):
        spec = load_experiment_spec(ROOT / "profiles/v2/ci-smoke.json")
        manifest = manifest_for(spec)
        identity = build_interoperability_identity(spec, manifest)

        calls = 0

        def interrupt(_item):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt
            return PASS, "passed", {}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = InteroperabilityArtifactStore(root)
            with self.assertRaises(KeyboardInterrupt):
                store.refresh(spec, identity, interrupt)
            identity_hash = interoperability_identity_hash(identity)
            checkpoint = root / identity_hash / "checkpoint.json.partial"
            checkpoint.write_bytes(checkpoint.read_bytes().replace(b'":', b'": '))
            with self.assertRaisesRegex(InteroperabilityError, "not canonical"):
                store.refresh(spec, identity, lambda _item: (PASS, "passed", {}))

            checkpoint.unlink()
            target = root / "checkpoint-target"
            target.write_bytes(b"{}\n")
            checkpoint.symlink_to(target)
            with self.assertRaisesRegex(InteroperabilityError, "path is invalid"):
                store.refresh(spec, identity, lambda _item: (PASS, "passed", {}))

    def test_publication_finalization_requires_the_frozen_balanced_artifact(self):
        spec = load_experiment_spec(ROOT / "profiles/v2/publication.json")
        manifest = manifest_for(spec)
        identity = build_interoperability_identity(spec, manifest)
        with tempfile.TemporaryDirectory() as temporary:
            artifact = InteroperabilityArtifactStore(Path(temporary)).refresh(
                spec,
                identity,
                lambda item: (
                    PASS,
                    "native_semantic_exercise_passed",
                    {"tuple_id": item.tuple_id},
                ),
            )
            content = artifact.path.read_bytes()

        class Connection:
            def execute(self, _query, _parameters):
                return SimpleNamespace(
                    fetchone=lambda: {
                        "content": content,
                        "sha256": artifact.artifact_hash,
                    }
                )

        journal = SimpleNamespace(connection=Connection())
        schedule = {
            "native_interoperability_artifact_sha256": artifact.artifact_hash
        }
        self.assertEqual(
            _native_interoperability_reasons(
                journal, "campaign", spec, manifest, schedule
            ),
            [],
        )
        schedule["native_interoperability_artifact_sha256"] = "0" * 64
        self.assertEqual(
            _native_interoperability_reasons(
                journal, "campaign", spec, manifest, schedule
            ),
            ["native_interoperability_schedule_identity_mismatch"],
        )

    def test_two_lane_batch_commits_records_in_frozen_plan_order(self):
        spec = load_experiment_spec(ROOT / "profiles/v2/ci-smoke.json")
        manifest = manifest_for(spec)
        identity = build_interoperability_identity(spec, manifest)

        class BatchExecutor:
            lane_count = 2

            def __init__(self):
                self.batches = []

            def __call__(self, item):
                raise AssertionError("scalar execution should not run")

            def execute_batch(self, items):
                self.batches.append(tuple(item.tuple_id for item in items))
                return [
                    (PASS, "semantic_oracle_passed", {"tuple": item.tuple_id})
                    for item in items
                ]

        execute = BatchExecutor()
        with tempfile.TemporaryDirectory() as temporary:
            artifact = InteroperabilityArtifactStore(Path(temporary)).refresh(
                spec, identity, execute
            )
        plan = plan_interoperability(
            spec, interoperability_identity_hash(identity)
        )
        self.assertEqual(execute.batches, [tuple(item.tuple_id for item in plan)])
        self.assertEqual(
            [record.tuple_id for record in artifact.records],
            [item.tuple_id for item in plan],
        )

    def test_native_executor_requires_semantic_result_and_uses_frozen_client(self):
        spec = load_experiment_spec(ROOT / "profiles/v2/ci-smoke.json")
        manifest = manifest_for(spec)
        identity = build_interoperability_identity(spec, manifest)
        planned = plan_interoperability(
            spec, interoperability_identity_hash(identity)
        )[0]
        calls = []

        class Source:
            def _lane_trial(self, request, **kwargs):
                calls.append((request, kwargs))
                return {
                    "completion_status": "valid",
                    "termination_reason": "deadline_reached",
                    "roles": {
                        "server_binary_sha256": "1" * 64,
                        "reference_client_binary_sha256": "2" * 64,
                    },
                    "treatment": {
                        "scenario": planned.scenario,
                        "server_backend": planned.server_backend,
                        "reference_client_backend": planned.reference_client_backend,
                        "server_config_hash": "3" * 64,
                        "reference_client_config_hash": "4" * 64,
                        "tls_hash": "5" * 64,
                        "path_hash": "6" * 64,
                    },
                    "negotiated": {"settings_match": True},
                    "units": {"completed": 1},
                    "telemetry": {
                        "cgroup_throttled_ns": 0,
                        "cgroup_nr_throttled": 0,
                    },
                    "runtime": {"measurement_ns": 2_000_000_000},
                }

        executor = NativeInteroperabilityExecutor(
            root=ROOT,
            run_dir=ROOT / ".run/unused",
            spec=spec,
            manifest=manifest,
            identity_hash=interoperability_identity_hash(identity),
        )
        self.assertEqual(executor.lane_count, 1)
        executor.source = Source()
        executor.resources = (["topology"], {0: "cgroup"}, {0: "path"}, (7,))
        status, reason, evidence = executor(planned)
        self.assertEqual((status, reason), (PASS, "native_semantic_exercise_passed"))
        self.assertEqual(evidence["completed"], 1)
        self.assertEqual(calls[0][1]["reference_client"], planned.reference_client)
        self.assertIs(calls[0][1]["external_thermal_provider"], True)
        self.assertIs(calls[0][1]["construct_sample"], True)
        self.assertIs(calls[0][1]["allow_client_headroom_failure"], True)
        self.assertEqual(calls[0][0]["server"], planned.server)
        self.assertEqual(calls[0][0]["backend"], planned.server_backend)
        with mock.patch(
            "quicperf_harness.interoperability.time.sleep"
        ) as quiesce:
            batch = executor.execute_batch((planned,))
        self.assertEqual(batch[0][0], PASS)
        quiesce.assert_called_once_with(POST_TRIAL_QUIESCENCE_SECONDS)

        class EmptySource(Source):
            def _lane_trial(self, request, **kwargs):
                result = super()._lane_trial(request, **kwargs)
                result["units"] = {"completed": 0}
                return result

        executor.source = EmptySource()
        status, reason, _evidence = executor(planned)
        self.assertEqual((status, reason), (FAIL, "native_result_semantic_attestation_failed"))


if __name__ == "__main__":
    unittest.main()
