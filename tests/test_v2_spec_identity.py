from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import tempfile
from types import MappingProxyType
import unittest

from quicperf_harness.canonical import canonical_sha256, load_strict
from quicperf_harness.errors import (
    IdentityMismatchError,
    ManifestValidationError,
    SpecValidationError,
)
from quicperf_harness.identity import (
    analysis_plan_hash,
    attempt_id,
    campaign_id,
    cell_id,
    identity_manifest_hash,
    microblock_id,
    schedule_basis_hash,
    schedule_hash,
    spec_hash,
    trial_id,
)
from quicperf_harness.manifest import manifest_hash, validate_manifest
from quicperf_harness.journal import Journal
from quicperf_harness.spec import load_experiment_spec, validate_experiment_spec


ROOT = Path(__file__).resolve().parents[1]


def manifest_fixture() -> dict:
    digest = "a" * 64
    path_content = {"delay_ns": 0, "loss_percent": "0", "name": "loopback"}
    topology = [
        {"package": 0, "core": index, "cpus": [index, index + 8], "numa_node": 0}
        for index in range(5)
    ]
    lane_layout = [{
        "lane": 0,
        "server_cpu": 2,
        "client_cpus": [3, 4],
        "housekeeping_cpus": [0, 1],
    }]
    return {
        "schema_version": "quicperf.manifest.v2",
        "source": {
            "tree_sha256": digest,
            "archive_sha256": "b" * 64,
            "git_commit": "c" * 40,
            "clean": True,
            "dirty_patch_sha256": None,
            "dirty_patch": None,
        },
        "binaries": [{
            "name": "ngtcp2perf",
            "role": "server",
            "path": "/opt/quicperf/bin/ngtcp2perf",
            "sha256": "d" * 64,
            "elf_build_id": "0123456789abcdef",
            "expected_loaded_libraries": [{
                "path": "/usr/lib/libc.so.6",
                "sha256": "e" * 64,
                "elf_build_id": "fedcba9876543210",
            }],
        }],
        "dependencies": [{
            "name": "ngtcp2",
            "revision": "v1.0.0",
            "content_sha256": "f" * 64,
            "lockfile_sha256": None,
        }],
        "toolchains": [{
            "name": "clang",
            "version": "22.1.8",
            "executable_sha256": "1" * 64,
            "effective_compile_flags": ["-O3", "-DNDEBUG", "-march=native", "-flto=auto"],
            "effective_link_flags": ["-flto=auto"],
        }],
        "protocols": {
            "adapter_abi_version": "qpf.adapter.v2",
            "control_protocol_version": "quicperf.control.v1",
            "workload_protocol_version": "QPF2",
            "capability_schema_version": "quicperf.capability.v2",
            "adapter_capabilities_sha256": "2" * 64,
        },
        "host_policy": {
            "kernel_release": "7.1.3",
            "microcode": "0x123",
            "cpu_model": "test-cpu",
            "cpu_stepping": "1",
            "topology": topology,
            "topology_sha256": canonical_sha256(topology),
            "numa_sha256": "4" * 64,
            "clocksource": "tsc",
            "cgroup_mode": "v2",
            "smt_policy": "no_lane_sibling_overlap",
            "governor": "performance",
            "epp": "performance",
            "frequency_min_khz": "3800000",
            "frequency_max_khz": "3800000",
            "turbo": False,
            "irq_affinity_sha256": "5" * 64,
            "offloads_sha256": "6" * 64,
            "sysctls_sha256": "7" * 64,
            "socket_policy_sha256": "8" * 64,
            "lane_layout": lane_layout,
            "lane_layout_sha256": canonical_sha256(lane_layout),
        },
        "path_profiles": [{
            "name": "loopback",
            "content_hash": canonical_sha256(path_content),
            "content": path_content,
        }],
    }


class ExperimentSpecTests(unittest.TestCase):
    def test_every_checked_in_v2_profile_loads_and_freezes(self) -> None:
        paths = sorted((ROOT / "profiles" / "v2").glob("*.json"))
        self.assertEqual(
            {path.name for path in paths},
            {
                "ci-smoke.json",
                "client-headroom-validation.json",
            },
        )
        paths.append(ROOT / "profiles/v2.3/publication.json")
        for path in paths:
            with self.subTest(path=path.name):
                spec = load_experiment_spec(path)
                self.assertIsInstance(spec.raw, MappingProxyType)
                with self.assertRaises(TypeError):
                    spec.raw["name"] = "changed"  # type: ignore[index]

    def test_v23_publication_is_exactly_frozen(self) -> None:
        v23_path = ROOT / "profiles/v2.3/publication.json"
        v23 = load_strict(v23_path)
        spec = load_experiment_spec(v23_path)
        self.assertEqual(spec.schema_version, "quicperf.experiment.v2.3")
        self.assertEqual(spec.server_backends, ("iouring",))
        self.assertEqual(
            (
                spec.expected_cardinality.planned_trials,
                spec.expected_cardinality.maximum_trial_ids,
                spec.expected_cardinality.committed_samples,
            ),
            (4_320, 8_640, 4_320),
        )
        runtime = spec.raw["methodology"]["runtime"]
        self.assertEqual(
            runtime["operational_session_timeout_ns"],
            10_800_000_000_000,
        )
        self.assertEqual(
            runtime["clean_start_conservative_budget_ns"],
            27_247_800_000_000,
        )
        self.assertEqual(runtime["suite_deadline_ns"], 30_000_000_000_000)
        evidence_path = ROOT / runtime["historical_evidence_artifact"]
        evidence = load_strict(evidence_path)
        self.assertEqual(
            hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            runtime["historical_evidence_sha256"],
        )
        self.assertEqual(
            evidence["v2.2_observed_session"]["termination_reason"],
            "runtime_session_wall_feasibility_budget_exhausted",
        )
        self.assertFalse(
            evidence["v2.2_observed_session"]["publication_sample_reuse"]
        )
        calibration = spec.raw["analysis"]["statistical_calibration"][
            "planning_result"
        ]
        self.assertEqual((calibration["raw_rows"], calibration["blocks"]), (24, 12))
        self.assertAlmostEqual(
            float(calibration["declared_effect_power"]["probability"]), 0.91504
        )
        self.assertAlmostEqual(
            float(calibration["equivalence"]["probability"]), 0.8668
        )
        self.assertAlmostEqual(
            float(calibration["twice_margin_power"]["probability"]), 0.93216
        )
        wrong_ceiling = copy.deepcopy(v23)
        wrong_ceiling["methodology"]["runtime"][
            "operational_session_timeout_ns"
        ] -= 1
        with self.assertRaisesRegex(
            SpecValidationError, "operational_session_timeout_ns"
        ):
            validate_experiment_spec(wrong_ceiling)

    def test_profile_identity_is_filename_and_order_independent(self) -> None:
        raw = load_strict(ROOT / "profiles" / "v2.3" / "publication.json")
        reordered = dict(reversed(tuple(raw.items())))
        self.assertEqual(spec_hash(raw), spec_hash(reordered))
        self.assertEqual(
            load_experiment_spec(raw).expected_cardinality.planned_trials,
            4320,
        )

    def test_unknown_missing_empty_and_wrong_decimal_fields_are_rejected(self) -> None:
        original = load_strict(ROOT / "profiles" / "v2.3" / "publication.json")
        mutations = []
        value = copy.deepcopy(original); value["surprise"] = True; mutations.append(value)
        value = copy.deepcopy(original); del value["timing"]; mutations.append(value)
        value = copy.deepcopy(original); value["roles"]["servers"][0] = ""; mutations.append(value)
        value = copy.deepcopy(original); value["analysis"]["alpha"] = "0.050"; mutations.append(value)
        value = copy.deepcopy(original); value["treatment"]["socket"]["receive_batch"] = 2**63; mutations.append(value)
        value = copy.deepcopy(original); value["treatment"]["socket"]["max_udp_payload_size"] = 1400; mutations.append(value)
        value = copy.deepcopy(original); value["schedule"]["worker_process_policy"] = "automatic"; mutations.append(value)
        for value in mutations:
            with self.subTest(mutation=len(mutations)), self.assertRaises(SpecValidationError):
                validate_experiment_spec(value)

    def test_cross_field_cardinality_path_and_lifecycle_errors_are_rejected(self) -> None:
        original = load_strict(ROOT / "profiles" / "v2.3" / "publication.json")
        value = copy.deepcopy(original)
        value["expected_cardinality"]["planned_trials"] = 4319
        value["expected_cardinality"]["committed_samples"] = 4319
        with self.assertRaisesRegex(SpecValidationError, "publication cardinality"):
            validate_experiment_spec(value)
        value = copy.deepcopy(original)
        value["workloads"][5]["path_profile"] = "loopback"
        with self.assertRaisesRegex(SpecValidationError, "loss_recovery requires"):
            validate_experiment_spec(value)
        value = copy.deepcopy(original)
        value["workloads"][12]["warmup_ns"] = 1
        with self.assertRaisesRegex(SpecValidationError, "zero warmup"):
            validate_experiment_spec(value)
        value = copy.deepcopy(original)
        value["treatment"]["resources"]["client_physical_cores"] = 2
        with self.assertRaisesRegex(SpecValidationError, "canonical resource treatment"):
            validate_experiment_spec(value)
        value = copy.deepcopy(original)
        value["schedule"]["lane_assignment"] = "hmac_then_minimum_balancing"
        with self.assertRaisesRegex(SpecValidationError, "one frozen execution lane"):
            validate_experiment_spec(value)
        value = copy.deepcopy(original)
        value["qualification"]["lane_interference_required"] = True
        with self.assertRaisesRegex(SpecValidationError, "single-lane publication"):
            validate_experiment_spec(value)


class ManifestTests(unittest.TestCase):
    def test_manifest_is_strict_content_addressed_and_frozen(self) -> None:
        model = validate_manifest(manifest_fixture())
        self.assertIsInstance(model.raw, MappingProxyType)
        self.assertEqual(manifest_hash(model), identity_manifest_hash(model.raw))
        with self.assertRaises(TypeError):
            model.host_policy["governor"] = "powersave"  # type: ignore[index]

    def test_runtime_observation_and_bad_path_content_hash_are_rejected(self) -> None:
        value = manifest_fixture()
        value["runtime_temperature_c"] = "40"
        with self.assertRaisesRegex(ManifestValidationError, "unknown fields"):
            validate_manifest(value)
        value = manifest_fixture()
        value["path_profiles"][0]["content_hash"] = "0" * 64
        with self.assertRaisesRegex(ManifestValidationError, "canonical path-profile content"):
            validate_manifest(value)

    def test_dirty_manifest_requires_and_hashes_exact_patch(self) -> None:
        value = manifest_fixture()
        patch = "diff --git a/a b/a\n+changed\n"
        value["source"].update({
            "clean": False,
            "dirty_patch": patch,
            "dirty_patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
        })
        validate_manifest(value)
        value["source"]["dirty_patch"] += "x"
        with self.assertRaisesRegex(ManifestValidationError, "exact dirty patch bytes"):
            validate_manifest(value)

    def test_manifest_accepts_four_client_cpus_and_rejects_other_widths(self) -> None:
        value = manifest_fixture()
        value["host_policy"]["lane_layout"][0]["client_cpus"] = [3, 4, 5, 6]
        value["host_policy"]["lane_layout_sha256"] = canonical_sha256(
            value["host_policy"]["lane_layout"]
        )
        validate_manifest(value)

        value["host_policy"]["lane_layout"][0]["client_cpus"] = [3, 4, 5]
        value["host_policy"]["lane_layout_sha256"] = canonical_sha256(
            value["host_policy"]["lane_layout"]
        )
        with self.assertRaisesRegex(ManifestValidationError, "two or four"):
            validate_manifest(value)


class CompleteIdentityChainTests(unittest.TestCase):
    def test_identity_chain_is_deterministic_and_field_sensitive(self) -> None:
        spec = {"schema": "v2", "x": 1}
        manifest = manifest_fixture()
        analysis = {"alpha": "0.05", "method": "exact_common_sign_max_abs_t"}
        sh = spec_hash(spec)
        mh = identity_manifest_hash(manifest)
        ah = analysis_plan_hash(analysis)
        basis = schedule_basis_hash(sh, mh, ah, bytes(range(32)))
        cell = cell_id({"scenario": "download", "backend": "syscall"})
        block = microblock_id(basis, {"row": 0, "position": 0}, "primary")
        trial = trial_id(basis, 1, block, cell, False)
        retry_block = microblock_id(basis, {"row": 0, "position": 0}, "retry")
        schedule = schedule_hash({"primary": block, "retry": retry_block})
        campaign = campaign_id(sh, mh, ah, schedule)
        attempt = attempt_id(trial, 0)
        values = (sh, mh, ah, basis, cell, block, trial, schedule, campaign, attempt)
        self.assertTrue(all(len(value) == 64 for value in values))
        self.assertNotEqual(block, retry_block)
        self.assertNotEqual(attempt, attempt_id(trial, 1))
        self.assertEqual(campaign, campaign_id(sh, mh, ah, schedule))

    def test_every_frozen_identity_field_rejects_resume_history_reuse(self) -> None:
        spec = load_strict(ROOT / "profiles" / "v2" / "ci-smoke.json")
        manifest = manifest_fixture()
        schedule = {"rows": [{"lane": 0, "trace_seed": "0" * 64}]}

        def update_path_hash(document: dict, index: int = 0) -> None:
            profile = document["path_profiles"][index]
            profile["content_hash"] = canonical_sha256(profile["content"])

        def dirty_patch(document: dict) -> None:
            patch = "diff --git a/provenance b/provenance\n+identity-change\n"
            document["source"].update(
                {
                    "clean": False,
                    "dirty_patch": patch,
                    "dirty_patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
                }
            )

        def change_topology(document: dict) -> None:
            document["host_policy"]["topology"][0]["core"] = 99
            document["host_policy"]["topology_sha256"] = canonical_sha256(
                document["host_policy"]["topology"]
            )

        def change_lane(document: dict) -> None:
            document["host_policy"]["lane_layout"][0]["server_cpu"] = 5
            document["host_policy"]["lane_layout_sha256"] = canonical_sha256(
                document["host_policy"]["lane_layout"]
            )

        manifest_mutations = {
            "source": lambda value: value["source"].__setitem__("tree_sha256", "9" * 64),
            "patch": dirty_patch,
            "binary": lambda value: value["binaries"][0].__setitem__("sha256", "9" * 64),
            "loaded_library": lambda value: value["binaries"][0][
                "expected_loaded_libraries"
            ][0].__setitem__("sha256", "9" * 64),
            "toolchain": lambda value: value["toolchains"][0].__setitem__(
                "version", "22.1.9"
            ),
            "flags": lambda value: value["toolchains"][0][
                "effective_compile_flags"
            ].append("-fno-omit-frame-pointer"),
            "dependency": lambda value: value["dependencies"][0].__setitem__(
                "revision", "v1.0.1"
            ),
            "capability": lambda value: value["protocols"].__setitem__(
                "adapter_capabilities_sha256", "9" * 64
            ),
            "protocol": lambda value: value["protocols"].__setitem__(
                "control_protocol_version", "quicperf.control.v2"
            ),
            "path": lambda value: (
                value["path_profiles"][0]["content"].__setitem__("delay_ns", 1),
                update_path_hash(value),
            ),
            "trace": lambda value: (
                value["path_profiles"][0]["content"].__setitem__(
                    "trace_sha256", "9" * 64
                ),
                update_path_hash(value),
            ),
            "hardware": lambda value: value["host_policy"].__setitem__(
                "cpu_model", "other-cpu"
            ),
            "topology": change_topology,
            "NUMA": lambda value: value["host_policy"].__setitem__(
                "numa_sha256", "9" * 64
            ),
            "kernel": lambda value: value["host_policy"].__setitem__(
                "kernel_release", "7.1.4"
            ),
            "microcode": lambda value: value["host_policy"].__setitem__(
                "microcode", "0x124"
            ),
            "cgroup": lambda value: value["host_policy"].__setitem__(
                "cgroup_mode", "v2-other"
            ),
            "SMT": lambda value: value["host_policy"].__setitem__(
                "smt_policy", "disabled"
            ),
            "governor": lambda value: value["host_policy"].__setitem__(
                "governor", "powersave"
            ),
            "turbo": lambda value: value["host_policy"].__setitem__("turbo", True),
            "IRQ": lambda value: value["host_policy"].__setitem__(
                "irq_affinity_sha256", "9" * 64
            ),
            "offload": lambda value: value["host_policy"].__setitem__(
                "offloads_sha256", "9" * 64
            ),
            "sysctl": lambda value: value["host_policy"].__setitem__(
                "sysctls_sha256", "9" * 64
            ),
            "lane": change_lane,
        }
        spec_mutations = {
            "spec": lambda value: value.__setitem__("name", "ci-smoke-identity-change"),
            "workload": lambda value: value["workloads"][0].__setitem__(
                "response_body_bytes", 2
            ),
            "TLS": lambda value: value["treatment"]["tls"].__setitem__(
                "hostname", "other.quicperf.test"
            ),
            "analysis": lambda value: value["analysis"].__setitem__("alpha", "0.04"),
        }
        schedule_mutations = {
            "schedule": lambda value: value["rows"].append(
                {"lane": 0, "trace_seed": "1" * 64}
            )
        }

        baseline_spec = validate_experiment_spec(spec)
        baseline_manifest = validate_manifest(manifest)
        baseline_hashes = {
            "spec_hash": spec_hash(baseline_spec.raw),
            "identity_manifest_hash": manifest_hash(baseline_manifest),
            "analysis_plan_hash": analysis_plan_hash(baseline_spec.raw["analysis"]),
            "schedule_hash": schedule_hash(schedule),
        }
        baseline_campaign = campaign_id(
            baseline_hashes["spec_hash"],
            baseline_hashes["identity_manifest_hash"],
            baseline_hashes["analysis_plan_hash"],
            baseline_hashes["schedule_hash"],
        )
        with tempfile.TemporaryDirectory() as temporary, Journal(
            Path(temporary) / "journal.sqlite3"
        ) as journal:
            journal.create_campaign(
                campaign_id=baseline_campaign,
                **baseline_hashes,
                expected_cardinality=0,
                maximum_cardinality=0,
                retry_per_microblock=0,
                manifests={
                    "identity": (baseline_hashes["identity_manifest_hash"], manifest),
                    "schedule": (baseline_hashes["schedule_hash"], schedule),
                },
                session_count=1,
            )
            journal.assert_identity(campaign_id=baseline_campaign, **baseline_hashes)

            cases = [
                (name, "manifest", mutation)
                for name, mutation in manifest_mutations.items()
            ] + [
                (name, "spec", mutation) for name, mutation in spec_mutations.items()
            ] + [
                (name, "schedule", mutation)
                for name, mutation in schedule_mutations.items()
            ]
            self.assertEqual(len(cases), 29)
            for name, kind, mutation in cases:
                with self.subTest(identity_field=name):
                    changed_spec = copy.deepcopy(spec)
                    changed_manifest = copy.deepcopy(manifest)
                    changed_schedule = copy.deepcopy(schedule)
                    target = {
                        "spec": changed_spec,
                        "manifest": changed_manifest,
                        "schedule": changed_schedule,
                    }[kind]
                    mutation(target)
                    changed_spec_model = validate_experiment_spec(changed_spec)
                    changed_manifest_model = validate_manifest(changed_manifest)
                    changed_hashes = {
                        "spec_hash": spec_hash(changed_spec_model.raw),
                        "identity_manifest_hash": manifest_hash(changed_manifest_model),
                        "analysis_plan_hash": analysis_plan_hash(
                            changed_spec_model.raw["analysis"]
                        ),
                        "schedule_hash": schedule_hash(changed_schedule),
                    }
                    changed_campaign = campaign_id(
                        changed_hashes["spec_hash"],
                        changed_hashes["identity_manifest_hash"],
                        changed_hashes["analysis_plan_hash"],
                        changed_hashes["schedule_hash"],
                    )
                    self.assertNotEqual(changed_campaign, baseline_campaign)
                    with self.assertRaises(IdentityMismatchError):
                        journal.assert_identity(
                            campaign_id=changed_campaign, **changed_hashes
                        )


if __name__ == "__main__":
    unittest.main()
