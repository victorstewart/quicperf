from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from quicperf_harness import cli
from quicperf_harness.cli import _capability_contract_check
from quicperf_harness.preflight import (
    PreflightInventory,
    PreflightStatus,
    cgroup_isolation_check,
    failed,
    passed,
    selected_path_checks,
    tls_material_check,
)
from quicperf_harness.paths import PathError
from quicperf_harness.manifest import validate_manifest
from quicperf_harness.spec import load_experiment_spec
from quicperf_harness.topology import LaneTopology
from quicperf_harness.runner import _attest_capabilities
from tests.test_v2_spec_identity import manifest_fixture


ROOT = Path(__file__).resolve().parents[1]


class PreflightInventoryTests(unittest.TestCase):
    def test_required_not_run_is_fail_closed_and_structured(self):
        inventory = PreflightInventory()
        inventory.add(passed("ready", "ready"))
        inventory.add(
            failed("blocked", "blocked_reason", "blocked by an exact prerequisite")
        )
        self.assertFalse(inventory.passed)
        self.assertEqual(
            inventory.summary(), {"PASS": 1, "FAIL": 1, "NOT_RUN": 0}
        )
        self.assertEqual(inventory.as_dicts()[1]["status"], "FAIL")
        with self.assertRaisesRegex(ValueError, "duplicate preflight check"):
            inventory.add(passed("ready", "duplicate"))

    def test_publication_reports_nonloopback_controller_as_not_run(self):
        spec = load_experiment_spec(ROOT / "profiles/v2/publication.json")
        with mock.patch(
            "quicperf_harness.preflight.NamespacePathController.create_session",
            side_effect=PathError("CAP_NET_ADMIN denied"),
        ):
            checks = {check.name: check for check in selected_path_checks(spec)}
        self.assertEqual(checks["path_controller:loopback"].status, PreflightStatus.PASS)
        loss = checks["path_controller:loss_recovery_v1"]
        self.assertEqual(loss.status, PreflightStatus.NOT_RUN)
        self.assertEqual(
            loss.reason, "persistent_namespace_qdisc_controller_unavailable"
        )


class ProductionContractTests(unittest.TestCase):
    def test_tls_preflight_verifies_chain_hostname_and_key(self):
        spec = load_experiment_spec(ROOT / "profiles/v2/ci-smoke.json")
        tls = dict(spec.raw["treatment"]["tls"])
        self.assertEqual(tls_material_check(ROOT, tls).status, PreflightStatus.PASS)
        tls["hostname"] = "not-server.quicperf.test"
        invalid = tls_material_check(ROOT, tls)
        self.assertEqual(invalid.status, PreflightStatus.FAIL)
        self.assertEqual(invalid.reason, "tls_chain_or_hostname_invalid")
        mismatched = tls_material_check(
            ROOT, spec.raw["treatment"]["tls"], private_key=Path("tls/client.key.pem")
        )
        self.assertEqual(mismatched.status, PreflightStatus.FAIL)
        self.assertEqual(mismatched.reason, "tls_private_key_mismatch")

    def test_capability_contract_is_role_and_backend_exact(self):
        spec = SimpleNamespace(
            server_backends=("syscall",),
            reference_client_backend="iouring",
            scenarios=("download",),
        )
        entry = {"role": "reference_client"}
        capabilities = {
            "roles": "describe,client",
            "backends": "syscall",
            "scenarios": "1",
        }
        accepted, detail = _capability_contract_check(entry, spec, capabilities)
        self.assertFalse(accepted)
        self.assertEqual(detail, "configured backends are not attested: iouring")
        capabilities["backends"] = "syscall,iouring"
        self.assertTrue(_capability_contract_check(entry, spec, capabilities)[0])

    def test_describe_is_a_control_role_not_an_advertised_endpoint_role(self):
        _attest_capabilities(
            {
                "roles": "server,client",
                "protocol_version": 1,
                "backends": "syscall,iouring",
                "scenarios": "all",
            },
            role="describe",
            required_backend=None,
            required_scenario=None,
        )

    def test_memory_curve_has_a_current_native_capability_id(self):
        spec = load_experiment_spec(ROOT / "profiles/v2/memory.json")
        entry = {"role": "server_reference_client"}
        capabilities = {
            "roles": "describe,server,client",
            "backends": "syscall,iouring",
            "scenarios": ",".join(str(value) for value in range(1, 16)),
        }
        accepted, detail = _capability_contract_check(entry, spec, capabilities)
        self.assertFalse(accepted)
        self.assertEqual(detail, "configured scenario IDs are not attested: 16")
        capabilities["scenarios"] += ",16"
        self.assertTrue(_capability_contract_check(entry, spec, capabilities)[0])

    def test_cgroup_probe_requires_creation_and_cleanup(self):
        topology = LaneTopology(0, 1, (2, 3), (4,))
        with tempfile.TemporaryDirectory(prefix="quicperf-preflight-test-") as temporary:
            root = Path(temporary)
            (root / "cgroup.controllers").write_text(
                "cpu cpuset memory pids", encoding="ascii"
            )
            (root / "cgroup.subtree_control").write_text(
                "cpu cpuset memory pids", encoding="ascii"
            )
            server = root / "server"
            client = root / "client"
            server.mkdir()
            client.mkdir()
            groups = mock.Mock()
            groups.create.return_value = (server, client)
            with mock.patch(
                "quicperf_harness.preflight.LaneCgroups", return_value=groups
            ):
                check = cgroup_isolation_check(topology, cgroup_root=root)
            self.assertEqual(check.status, PreflightStatus.PASS)
            groups.create.assert_called_once_with()
            groups.cleanup.assert_called_once_with()

    def test_cgroup_probe_rejects_available_but_undelegated_controller(self):
        topology = LaneTopology(0, 1, (2, 3), (4,))
        with tempfile.TemporaryDirectory(prefix="quicperf-preflight-test-") as temporary:
            root = Path(temporary)
            (root / "cgroup.controllers").write_text(
                "cpu cpuset memory pids", encoding="ascii"
            )
            (root / "cgroup.subtree_control").write_text(
                "cpu memory pids", encoding="ascii"
            )
            check = cgroup_isolation_check(topology, cgroup_root=root)
        self.assertEqual(check.status, PreflightStatus.FAIL)
        self.assertEqual(check.reason, "cgroup_v2_controllers_not_delegated")
        self.assertIn("cpuset", check.detail)

    def test_doctor_records_manifest_dependents_as_not_run(self):
        topology = LaneTopology(0, 1, (2, 3), (4,))
        with (
            mock.patch.object(cli, "collect_manifest", side_effect=RuntimeError("no manifest")),
            mock.patch.object(cli, "_statistical_calibration_reasons", return_value=[]),
            mock.patch.object(cli, "discover_physical_cores", return_value=()),
            mock.patch.object(cli, "allocate_lanes", return_value=(topology,)),
            mock.patch.object(cli, "swap_is_disabled", return_value=True),
            mock.patch.object(
                cli,
                "cgroup_isolation_check",
                return_value=passed("cgroup_v2_isolation", "probe passed"),
            ),
        ):
            result, exit_code = cli.doctor(
                ROOT / "profiles/v2/ci-smoke.json", None
            )
        checks = {check["check"]: check for check in result["checks"]}
        self.assertEqual(exit_code, cli.EXIT_INVALID)
        self.assertEqual(checks["source_build_policy"]["status"], "FAIL")
        self.assertEqual(checks["source_identity"]["status"], "NOT_RUN")
        self.assertEqual(checks["describe:ngtcp2perf"]["status"], "NOT_RUN")
        self.assertEqual(checks["native_interoperability"]["status"], "NOT_RUN")
        self.assertEqual(
            checks["native_interoperability"]["reason"], "manifest_unavailable"
        )
        self.assertFalse(result["passed"])

    def test_doctor_consumes_or_refreshes_exact_interoperability_artifact(self):
        topology = LaneTopology(0, 1, (2, 3), (4,))
        manifest = validate_manifest(manifest_fixture())
        artifact = SimpleNamespace(
            status="PASS",
            records=(object(), object()),
            passed=2,
            failed=0,
            artifact_hash="a" * 64,
        )
        def environment():
            return (
                mock.patch.object(cli, "collect_manifest", return_value=manifest),
                mock.patch.object(cli, "_statistical_calibration_reasons", return_value=[]),
                mock.patch.object(cli, "_describe_check", return_value=(True, "passed")),
                mock.patch.object(cli, "discover_physical_cores", return_value=()),
                mock.patch.object(cli, "allocate_lanes", return_value=(topology,)),
                mock.patch.object(cli, "swap_is_disabled", return_value=True),
                mock.patch.object(
                    cli,
                    "cgroup_isolation_check",
                    return_value=passed("cgroup_v2_isolation", "probe passed"),
                ),
                mock.patch.object(
                    cli, "tls_material_check", return_value=passed("tls_material", "passed")
                ),
                mock.patch.object(cli, "selected_path_checks", return_value=[]),
                mock.patch.object(
                    cli, "_assert_binary_unchanged", return_value=ROOT / "unused"
                ),
            )

        common = environment()
        with common[0], common[1], common[2], common[3], common[4], common[5], common[6], common[7], common[8], common[9], mock.patch.object(
            cli, "load_native_interoperability", return_value=artifact
        ) as load:
            result, exit_code = cli.doctor(
                ROOT / "profiles/v2/ci-smoke.json",
                None,
                phase="deterministic",
                interoperability_store=ROOT / ".data/test-store",
            )
        checks = {check["check"]: check for check in result["checks"]}
        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        self.assertEqual(result["phase"], "deterministic")
        self.assertEqual(checks["native_interoperability"]["status"], "PASS")
        load.assert_called_once()

        common = environment()
        with common[0], common[1], common[2], common[3], common[4], common[5], common[6], common[7], common[8], common[9], mock.patch.object(
            cli, "refresh_native_interoperability", return_value=artifact
        ) as refresh:
            result, exit_code = cli.doctor(
                ROOT / "profiles/v2/ci-smoke.json",
                None,
                phase="deterministic",
                refresh_interoperability=True,
                interoperability_store=ROOT / ".data/test-store",
            )
        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        refresh.assert_called_once()


if __name__ == "__main__":
    unittest.main()
