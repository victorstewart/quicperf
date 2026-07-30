from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import os
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

from quicperf_harness import host_policy
from quicperf_harness.lanes import CGROUP_ROOT_ENV, LaneError, delegated_cgroup_root
from quicperf_harness.manifest_collect import _turbo_enabled


def _state(
    *,
    governor: str = "performance",
    epp: str = "performance",
    turbo_value: str = "0",
    scaling_min_khz: str = "3800000",
    scaling_max_khz: str = "3800000",
    swaps: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": host_policy.STATE_SCHEMA,
        "boot_id": "boot-1",
        "swaps": [] if swaps is None else swaps,
        "cpu_policies": [
            {
                "path": "/sys/devices/system/cpu/cpufreq/policy0",
                "governor": governor,
                "epp": epp,
                "scaling_min_khz": scaling_min_khz,
                "scaling_max_khz": scaling_max_khz,
            }
        ],
        "turbo_controls": [
            {
                "path": "/sys/devices/system/cpu/cpufreq/boost",
                "value": turbo_value,
                "disabled_value": "0",
            }
        ],
        "irq_policy": {
            "boot": {
                "measured_cpus": [2, 3, 4, 5, 6, 10, 11, 12, 13, 14],
                "monitor_cpu": 7,
                "isolated_cpus": [2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15],
                "housekeeping_cpus": [0, 1, 9],
                "runtime_irq_cpus": [0, 1, 9],
                "isolcpus_flags": ["domain", "managed_irq"],
                "isolcpus_cpus": [2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15],
                "nohz_full_cpus": [2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15],
                "rcu_nocbs_cpus": [2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15],
                "irqaffinity_cpus": [0, 1, 9],
                "sysfs_isolated_cpus": [2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15],
                "sysfs_nohz_full_cpus": [2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15],
            },
            "default_affinity": {
                "path": "/proc/irq/default_smp_affinity",
                "value": "203",
                "target": "203",
            },
            "irqs": [
                {
                    "irq": 1,
                    "path": "/proc/irq/1/smp_affinity_list",
                    "affinity": "0-1,9",
                    "effective_affinity": "1",
                    "writable": True,
                    "target": "0-1,9",
                }
            ],
        },
    }


def _load_launcher() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "tools/run-publication-host"
    loader = importlib.machinery.SourceFileLoader("test_run_publication_host", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class _Input(io.StringIO):
    def __init__(self, value: str, *, tty: bool) -> None:
        super().__init__(value)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


class TurboPolicyTests(unittest.TestCase):
    def test_generic_amd_boost_control_is_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cpu = Path(temporary)
            boost = cpu / "cpufreq/boost"
            boost.parent.mkdir()
            boost.write_text("1\n", encoding="ascii")
            self.assertTrue(_turbo_enabled(cpu))
            boost.write_text("0\n", encoding="ascii")
            self.assertFalse(_turbo_enabled(cpu))

    def test_unknown_or_conflicting_turbo_state_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cpu = Path(temporary)
            self.assertTrue(_turbo_enabled(cpu))
            (cpu / "cpufreq").mkdir()
            (cpu / "intel_pstate").mkdir()
            (cpu / "cpufreq/boost").write_text("0\n", encoding="ascii")
            (cpu / "intel_pstate/no_turbo").write_text("0\n", encoding="ascii")
            self.assertTrue(_turbo_enabled(cpu))

    def test_temporary_policy_models_intel_no_turbo(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cpu = Path(temporary)
            no_turbo = cpu / "intel_pstate/no_turbo"
            no_turbo.parent.mkdir()
            no_turbo.write_text("0\n", encoding="ascii")
            self.assertEqual(
                host_policy._turbo_control_snapshot(cpu),
                [
                    {
                        "path": str(no_turbo.resolve()),
                        "value": "0",
                        "disabled_value": "1",
                    }
                ],
            )


class PlanTests(unittest.TestCase):
    def test_compliant_host_has_no_temporary_changes(self) -> None:
        state = _state()
        self.assertEqual(host_policy.publication_policy_change_lines(state), [])
        self.assertRegex(
            host_policy.publication_policy_plan_sha256(state), r"^[0-9a-f]{64}$"
        )

    def test_plan_lists_every_noncompliant_control(self) -> None:
        swap = {
            "path": "/dev/zram0",
            "type": "partition",
            "size_kib": 1024,
            "used_kib": 0,
            "priority": 100,
            "systemd_unit": "dev-zram0.swap",
        }
        lines = host_policy.publication_policy_change_lines(
            _state(
                governor="powersave",
                epp="balance_performance",
                turbo_value="1",
                swaps=[swap],
            )
        )
        self.assertEqual(len(lines), 4)
        self.assertTrue(any("disable swap /dev/zram0" in line for line in lines))
        self.assertTrue(any("set governor" in line for line in lines))
        self.assertTrue(any("set epp" in line for line in lines))
        self.assertTrue(any("set turbo" in line for line in lines))

    def test_plan_authorizes_exact_base_frequency_pin(self) -> None:
        lines = host_policy.publication_policy_change_lines(
            _state(scaling_min_khz="1100980", scaling_max_khz="3801000")
        )
        self.assertEqual(len(lines), 1)
        self.assertIn("pin frequency", lines[0])
        self.assertIn("min=max=3800000 kHz", lines[0])

    def test_plan_discloses_every_temporary_irq_change(self) -> None:
        state = _state()
        state["irq_policy"]["default_affinity"]["value"] = "ff"
        state["irq_policy"]["irqs"][0]["affinity"] = "0-7"
        state["irq_policy"]["irqs"][0]["effective_affinity"] = "2"
        lines = host_policy.publication_policy_change_lines(state)
        self.assertEqual(len(lines), 2)
        self.assertTrue(any("route irq-default" in line for line in lines))
        self.assertTrue(any("route irq " in line for line in lines))
        self.assertTrue(all("housekeeping CPUs" in line for line in lines))

    def test_prepare_rechecks_authorized_plan_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            host_policy.os, "geteuid", return_value=0
        ), mock.patch.object(host_policy, "snapshot", return_value=_state()), mock.patch.object(
            host_policy, "activate_delegated_controllers"
        ) as activate, mock.patch.object(host_policy, "_atomic_store") as store:
            with self.assertRaisesRegex(
                host_policy.HostPolicyError, "changed after operator authorization"
            ):
                host_policy.prepare(Path(temporary) / "state.json", "0" * 64)
        activate.assert_not_called()
        store.assert_not_called()


class FilesystemTransactionTests(unittest.TestCase):
    def test_verified_write_waits_for_delayed_sysfs_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "control"
            path.write_text("old\n", encoding="ascii")
            with (
                mock.patch.object(
                    host_policy, "_read", side_effect=("old", "new")
                ),
                mock.patch.object(host_policy.time, "monotonic", return_value=0.0),
                mock.patch.object(host_policy.time, "sleep") as sleep,
            ):
                host_policy._write_verified(path, "new")
            sleep.assert_called_once_with(0.01)
            self.assertEqual(path.read_text(encoding="ascii"), "new")

    def _host(
        self,
        root: Path,
        *,
        governor: str,
        epp: str,
        intel: bool = False,
    ) -> tuple[host_policy.HostPaths, Path, Path, Path]:
        cpu = root / "cpu"
        policy = cpu / "cpufreq/policy0"
        policy.mkdir(parents=True)
        (policy / "scaling_available_governors").write_text(
            "performance powersave schedutil\n", encoding="ascii"
        )
        (policy / "energy_performance_available_preferences").write_text(
            "performance balance_performance power\n", encoding="ascii"
        )
        governor_path = policy / "scaling_governor"
        epp_path = policy / "energy_performance_preference"
        (policy / "scaling_min_freq").write_text("3800000\n", encoding="ascii")
        (policy / "scaling_max_freq").write_text("3800000\n", encoding="ascii")
        governor_path.write_text(f"{governor}\n", encoding="ascii")
        epp_path.write_text(f"{epp}\n", encoding="ascii")
        turbo = (
            cpu / "intel_pstate/no_turbo" if intel else cpu / "cpufreq/boost"
        )
        turbo.parent.mkdir(parents=True, exist_ok=True)
        turbo.write_text("0\n" if intel else "1\n", encoding="ascii")
        (cpu / "online").write_text("0-15\n", encoding="ascii")
        (cpu / "isolated").write_text("2-8,10-15\n", encoding="ascii")
        (cpu / "nohz_full").write_text("2-8,10-15\n", encoding="ascii")
        for cpu_number in range(16):
            topology = cpu / f"cpu{cpu_number}/topology"
            topology.mkdir(parents=True)
            (topology / "physical_package_id").write_text("0\n", encoding="ascii")
            (topology / "core_id").write_text(
                f"{cpu_number % 8}\n", encoding="ascii"
            )
        cmdline = root / "cmdline"
        cmdline.write_text(
            "isolcpus=domain,managed_irq,2-8,10-15 nohz_full=2-8,10-15 "
            "rcu_nocbs=2-8,10-15 irqaffinity=0-1,9\n",
            encoding="ascii",
        )
        proc_irq = root / "irq"
        proc_irq.mkdir()
        (proc_irq / "default_smp_affinity").write_text("3\n", encoding="ascii")
        irq = proc_irq / "1"
        irq.mkdir()
        (irq / "smp_affinity_list").write_text("0-1\n", encoding="ascii")
        (irq / "effective_affinity_list").write_text("0\n", encoding="ascii")
        swaps = root / "swaps"
        swaps.write_text(
            "Filename Type Size Used Priority\n",
            encoding="utf-8",
        )
        boot_id = root / "boot_id"
        boot_id.write_text("boot-1\n", encoding="ascii")
        return (
            host_policy.HostPaths(
                cpu_sysfs=cpu,
                proc_swaps=swaps,
                boot_id=boot_id,
                cgroup_mount=root / "cgroup",
                proc_self_cgroup=root / "self.cgroup",
                proc_irq=proc_irq,
                proc_cmdline=cmdline,
            ),
            governor_path,
            epp_path,
            turbo,
        )

    def test_changed_controls_are_applied_and_exactly_restored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, governor, epp, turbo = self._host(
                root, governor="powersave", epp="balance_performance"
            )
            state = host_policy.snapshot(paths)
            digest = host_policy.publication_policy_plan_sha256(state)
            state_path = root / "state.json"
            with mock.patch.dict(
                os.environ, {CGROUP_ROOT_ENV: str(root / "cgroup")}
            ), mock.patch.object(
                host_policy, "activate_delegated_controllers"
            ), mock.patch.object(
                host_policy, "_verify_prepared", return_value={"status": "prepared"}
            ):
                host_policy.prepare(state_path, digest, paths)
            self.assertEqual(governor.read_text(encoding="ascii"), "performance")
            self.assertEqual(epp.read_text(encoding="ascii"), "performance")
            self.assertEqual(turbo.read_text(encoding="ascii"), "0")
            host_policy.restore(state_path, paths)
            self.assertEqual(governor.read_text(encoding="ascii"), "powersave")
            self.assertEqual(
                epp.read_text(encoding="ascii"), "balance_performance"
            )
            self.assertEqual(turbo.read_text(encoding="ascii"), "1")
            self.assertFalse(state_path.exists())

    def test_frequency_bounds_are_pinned_and_restored_in_safe_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _governor, _epp, turbo = self._host(
                root, governor="performance", epp="performance"
            )
            turbo.write_text("0\n", encoding="ascii")
            policy = paths.cpu_sysfs / "cpufreq/policy0"
            minimum = policy / "scaling_min_freq"
            maximum = policy / "scaling_max_freq"
            minimum.write_text("1100980\n", encoding="ascii")
            maximum.write_text("3801000\n", encoding="ascii")
            state = host_policy.snapshot(paths)
            digest = host_policy.publication_policy_plan_sha256(state)
            state_path = root / "state.json"
            with mock.patch.dict(
                os.environ, {CGROUP_ROOT_ENV: str(root / "cgroup")}
            ), mock.patch.object(
                host_policy, "activate_delegated_controllers"
            ), mock.patch.object(
                host_policy, "_verify_prepared", return_value={"status": "prepared"}
            ):
                host_policy.prepare(state_path, digest, paths)
            self.assertEqual(minimum.read_text(encoding="ascii"), "3800000")
            self.assertEqual(maximum.read_text(encoding="ascii"), "3800000")
            host_policy.restore(state_path, paths)
            self.assertEqual(minimum.read_text(encoding="ascii"), "1100980")
            self.assertEqual(maximum.read_text(encoding="ascii"), "3801000")

    def test_compliant_host_performs_no_control_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _governor, _epp, turbo = self._host(
                root, governor="performance", epp="performance"
            )
            turbo.write_text("0\n", encoding="ascii")
            (paths.proc_irq / "default_smp_affinity").write_text(
                "203\n", encoding="ascii"
            )
            (paths.proc_irq / "1/smp_affinity_list").write_text(
                "0-1,9\n", encoding="ascii"
            )
            (paths.proc_irq / "1/effective_affinity_list").write_text(
                "1\n", encoding="ascii"
            )
            state = host_policy.snapshot(paths)
            digest = host_policy.publication_policy_plan_sha256(state)
            state_path = root / "state.json"
            with mock.patch.dict(
                os.environ, {CGROUP_ROOT_ENV: str(root / "cgroup")}
            ), mock.patch.object(
                host_policy, "activate_delegated_controllers"
            ), mock.patch.object(
                host_policy, "_verify_prepared", return_value={"status": "prepared"}
            ), mock.patch.object(host_policy, "_write_verified") as write, mock.patch.object(
                host_policy, "_run"
            ) as run:
                host_policy.prepare(state_path, digest, paths)
                host_policy.restore(state_path, paths)
            write.assert_not_called()
            run.assert_not_called()

    def test_intel_no_turbo_is_applied_and_restored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _governor, _epp, no_turbo = self._host(
                root, governor="performance", epp="performance", intel=True
            )
            state = host_policy.snapshot(paths)
            digest = host_policy.publication_policy_plan_sha256(state)
            state_path = root / "state.json"
            with mock.patch.dict(
                os.environ, {CGROUP_ROOT_ENV: str(root / "cgroup")}
            ), mock.patch.object(
                host_policy, "activate_delegated_controllers"
            ), mock.patch.object(
                host_policy, "_verify_prepared", return_value={"status": "prepared"}
            ):
                host_policy.prepare(state_path, digest, paths)
            self.assertEqual(no_turbo.read_text(encoding="ascii"), "1")
            host_policy.restore(state_path, paths)
            self.assertEqual(no_turbo.read_text(encoding="ascii"), "0")

    def test_failed_preparation_restores_partial_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, governor, epp, turbo = self._host(
                root, governor="powersave", epp="balance_performance"
            )
            state = host_policy.snapshot(paths)
            digest = host_policy.publication_policy_plan_sha256(state)
            state_path = root / "state.json"
            with mock.patch.dict(
                os.environ, {CGROUP_ROOT_ENV: str(root / "cgroup")}
            ), mock.patch.object(
                host_policy, "activate_delegated_controllers"
            ), mock.patch.object(
                host_policy,
                "_verify_prepared",
                side_effect=host_policy.HostPolicyError("injected verification failure"),
            ):
                with self.assertRaisesRegex(
                    host_policy.HostPolicyError, "injected verification failure"
                ):
                    host_policy.prepare(state_path, digest, paths)
            self.assertEqual(governor.read_text(encoding="ascii"), "powersave")
            self.assertEqual(
                epp.read_text(encoding="ascii"), "balance_performance"
            )
            self.assertEqual(turbo.read_text(encoding="ascii"), "1")
            self.assertFalse(state_path.exists())

    def test_governor_restore_reproduces_coupled_original_epp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, governor, epp, _turbo = self._host(
                root, governor="powersave", epp="performance"
            )
            state = host_policy.snapshot(paths)
            digest = host_policy.publication_policy_plan_sha256(state)
            state_path = root / "state.json"
            original_write = host_policy._write_verified

            def coupled_write(path: Path, value: str) -> None:
                original_write(path, value)
                if path == governor and value == "powersave":
                    epp.write_text("balance_performance\n", encoding="ascii")

            with mock.patch.dict(
                os.environ, {CGROUP_ROOT_ENV: str(root / "cgroup")}
            ), mock.patch.object(
                host_policy, "activate_delegated_controllers"
            ), mock.patch.object(
                host_policy, "_verify_prepared", return_value={"status": "prepared"}
            ), mock.patch.object(
                host_policy, "_write_verified", side_effect=coupled_write
            ):
                host_policy.prepare(state_path, digest, paths)
                host_policy.restore(state_path, paths)
            self.assertEqual(governor.read_text(encoding="ascii"), "powersave")
            self.assertEqual(epp.read_text(encoding="ascii"), "performance")
            self.assertFalse(state_path.exists())

    def test_dual_turbo_controls_converge_as_one_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _governor, _epp, boost = self._host(
                root, governor="performance", epp="performance"
            )
            boost.write_text("0\n", encoding="ascii")
            no_turbo = paths.cpu_sysfs / "intel_pstate/no_turbo"
            no_turbo.parent.mkdir()
            no_turbo.write_text("0\n", encoding="ascii")
            state = host_policy.snapshot(paths)
            digest = host_policy.publication_policy_plan_sha256(state)
            state_path = root / "state.json"
            original_write = host_policy._write_verified

            def coupled_write(path: Path, value: str) -> None:
                original_write(path, value)
                if path == no_turbo:
                    boost.write_text("1\n", encoding="ascii")

            with mock.patch.dict(
                os.environ, {CGROUP_ROOT_ENV: str(root / "cgroup")}
            ), mock.patch.object(
                host_policy, "activate_delegated_controllers"
            ), mock.patch.object(
                host_policy, "_verify_prepared", return_value={"status": "prepared"}
            ), mock.patch.object(
                host_policy, "_write_verified", side_effect=coupled_write
            ):
                host_policy.prepare(state_path, digest, paths)
                self.assertEqual(boost.read_text(encoding="ascii"), "0")
                self.assertEqual(no_turbo.read_text(encoding="ascii"), "1")
                host_policy.restore(state_path, paths)
            self.assertEqual(boost.read_text(encoding="ascii"), "0")
            self.assertEqual(no_turbo.read_text(encoding="ascii"), "0")
            self.assertFalse(state_path.exists())

    def test_external_policy_conflict_refuses_before_restoration_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, governor, _epp, _turbo = self._host(
                root, governor="powersave", epp="balance_performance"
            )
            state = host_policy.snapshot(paths)
            digest = host_policy.publication_policy_plan_sha256(state)
            state_path = root / "state.json"
            with mock.patch.dict(
                os.environ, {CGROUP_ROOT_ENV: str(root / "cgroup")}
            ), mock.patch.object(
                host_policy, "activate_delegated_controllers"
            ), mock.patch.object(
                host_policy, "_verify_prepared", return_value={"status": "prepared"}
            ):
                host_policy.prepare(state_path, digest, paths)
            governor.write_text("schedutil\n", encoding="ascii")
            with mock.patch.object(host_policy, "_write_verified") as write:
                with self.assertRaisesRegex(
                    host_policy.HostPolicyError, "changed externally"
                ):
                    host_policy.restore(state_path, paths)
            write.assert_not_called()

    def test_irq_controls_are_applied_and_exactly_restored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _governor, _epp, turbo = self._host(
                root, governor="performance", epp="performance"
            )
            turbo.write_text("0\n", encoding="ascii")
            default = paths.proc_irq / "default_smp_affinity"
            affinity = paths.proc_irq / "1/smp_affinity_list"
            default.write_text("ff\n", encoding="ascii")
            affinity.write_text("0-7\n", encoding="ascii")
            (paths.proc_irq / "1/effective_affinity_list").write_text(
                "2\n", encoding="ascii"
            )
            state = host_policy.snapshot(paths)
            digest = host_policy.publication_policy_plan_sha256(state)
            state_path = root / "state.json"
            with mock.patch.dict(
                os.environ, {CGROUP_ROOT_ENV: str(root / "cgroup")}
            ), mock.patch.object(
                host_policy, "activate_delegated_controllers"
            ), mock.patch.object(
                host_policy, "_verify_prepared", return_value={"status": "prepared"}
            ):
                host_policy.prepare(state_path, digest, paths)
            self.assertEqual(default.read_text(encoding="ascii"), "203")
            self.assertEqual(affinity.read_text(encoding="ascii"), "0-1,9")
            host_policy.restore(state_path, paths)
            self.assertEqual(default.read_text(encoding="ascii"), "ff")
            self.assertEqual(affinity.read_text(encoding="ascii"), "0-7")
            self.assertFalse(state_path.exists())

    def test_missing_boot_isolation_fails_before_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _governor, _epp, _turbo = self._host(
                root, governor="performance", epp="performance"
            )
            paths.proc_cmdline.write_text("quiet\n", encoding="ascii")
            with self.assertRaisesRegex(
                host_policy.HostPolicyError, "requires a reboot"
            ):
                host_policy.snapshot(paths)

    def test_isolation_superset_may_include_only_spare_cores(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _governor, _epp, _turbo = self._host(
                root, governor="performance", epp="performance"
            )
            boot = host_policy.snapshot(paths)["irq_policy"]["boot"]
            self.assertTrue({7, 15} <= set(boot["isolated_cpus"]))
            self.assertEqual(boot["housekeeping_cpus"], [0, 1, 9])

        for housekeeping_cpu, isolated, irqaffinity in (
            (0, "0,2-8,10-15", "1,9"),
            (1, "1-8,10-15", "0,9"),
        ):
            with self.subTest(housekeeping_cpu=housekeeping_cpu), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                paths, _governor, _epp, _turbo = self._host(
                    root, governor="performance", epp="performance"
                )
                paths.proc_cmdline.write_text(
                    f"isolcpus=domain,managed_irq,{isolated} "
                    f"nohz_full={isolated} rcu_nocbs={isolated} "
                    f"irqaffinity={irqaffinity}\n",
                    encoding="ascii",
                )
                (paths.cpu_sysfs / "isolated").write_text(
                    f"{isolated}\n", encoding="ascii"
                )
                (paths.cpu_sysfs / "nohz_full").write_text(
                    f"{isolated}\n", encoding="ascii"
                )
                with self.assertRaisesRegex(
                    host_policy.HostPolicyError,
                    f"housekeeping_missing={housekeeping_cpu}",
                ):
                    host_policy.snapshot(paths)

    def test_read_only_managed_irq_confined_to_measured_cpu_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _governor, _epp, _turbo = self._host(
                root, governor="performance", epp="performance"
            )
            affinity = paths.proc_irq / "1/smp_affinity_list"
            affinity.write_text("2\n", encoding="ascii")
            affinity.chmod(0o444)
            (paths.proc_irq / "1/effective_affinity_list").write_text(
                "2\n", encoding="ascii"
            )
            state = host_policy.snapshot(paths)
            self.assertFalse(state["irq_policy"]["irqs"][0]["writable"])

    def test_irq_identity_excludes_dynamic_effective_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _governor, _epp, _turbo = self._host(
                root, governor="performance", epp="performance"
            )
            before = host_policy.irq_policy_identity(paths)
            effective = paths.proc_irq / "1/effective_affinity_list"
            effective.write_text("1\n", encoding="ascii")
            after = host_policy.irq_policy_identity(paths)
            self.assertEqual(before, after)
            self.assertNotIn("effective_affinity", after["irqs"][0])

            affinity = paths.proc_irq / "1/smp_affinity_list"
            affinity.write_text("1\n", encoding="ascii")
            self.assertNotEqual(after, host_policy.irq_policy_identity(paths))

    def test_read_only_managed_irq_mixed_affinity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _governor, _epp, _turbo = self._host(
                root, governor="performance", epp="performance"
            )
            affinity = paths.proc_irq / "1/smp_affinity_list"
            affinity.write_text("0-2\n", encoding="ascii")
            affinity.chmod(0o444)
            (paths.proc_irq / "1/effective_affinity_list").write_text(
                "2\n", encoding="ascii"
            )
            with self.assertRaisesRegex(
                host_policy.HostPolicyError, "unsafe mixed"
            ):
                host_policy.snapshot(paths)


class DelegatedCgroupTests(unittest.TestCase):
    def _tree(self, root: Path, *, subtree: str) -> tuple[Path, Path]:
        mount = root / "cgroup"
        unit = mount / "system.slice/quicperf-publication-host.service"
        coordinator = unit / "coordinator"
        coordinator.mkdir(parents=True)
        for path in (unit, coordinator):
            (path / "cgroup.controllers").write_text(
                "cpu cpuset memory pids\n", encoding="ascii"
            )
            (path / "cgroup.subtree_control").write_text(
                subtree if path == unit else "", encoding="ascii"
            )
        proc = root / "self.cgroup"
        proc.write_text(
            "0::/system.slice/quicperf-publication-host.service/coordinator\n",
            encoding="ascii",
        )
        return mount, proc

    def test_exact_enabled_unit_root_is_selected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mount, proc = self._tree(root, subtree="cpu cpuset memory pids\n")
            unit = mount / "system.slice/quicperf-publication-host.service"
            self.assertEqual(
                delegated_cgroup_root(
                    cgroup_mount=mount,
                    proc_self_cgroup=proc,
                    environment={"QUICPERF_CGROUP_ROOT": str(unit)},
                ),
                unit.resolve(),
            )

    def test_disabled_or_host_root_delegation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mount, proc = self._tree(root, subtree="cpu memory pids\n")
            unit = mount / "system.slice/quicperf-publication-host.service"
            with self.assertRaisesRegex(LaneError, "disabled=cpuset"):
                delegated_cgroup_root(
                    cgroup_mount=mount,
                    proc_self_cgroup=proc,
                    environment={"QUICPERF_CGROUP_ROOT": str(unit)},
                )
            with self.assertRaisesRegex(LaneError, "non-root child"):
                delegated_cgroup_root(
                    cgroup_mount=mount,
                    proc_self_cgroup=proc,
                    environment={"QUICPERF_CGROUP_ROOT": str(mount)},
                )


class LauncherConsentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.launcher = _load_launcher()

    def authorize(
        self,
        response: str,
        *,
        tty: bool,
        allowed_noninteractive: bool = False,
        changes: list[str] | None = None,
    ) -> tuple[bool, str]:
        output = io.StringIO()
        accepted = self.launcher._authorize_changes(
            ["disable swap /dev/zram0"] if changes is None else changes,
            allowed_noninteractive=allowed_noninteractive,
            input_stream=_Input(response, tty=tty),
            output_stream=output,
        )
        return accepted, output.getvalue()

    def test_interactive_operator_must_type_exact_yes(self) -> None:
        accepted, output = self.authorize("yes\n", tty=True)
        self.assertTrue(accepted)
        self.assertIn("disable swap /dev/zram0", output)
        for response in ("y\n", "YES\n", "no\n", ""):
            accepted, _output = self.authorize(response, tty=True)
            self.assertFalse(accepted)

    def test_noninteractive_launch_fails_closed_without_flag(self) -> None:
        accepted, output = self.authorize("", tty=False)
        self.assertFalse(accepted)
        self.assertIn("--allow-temporary-host-policy-changes", output)

    def test_explicit_noninteractive_flag_authorizes_one_invocation(self) -> None:
        accepted, output = self.authorize(
            "", tty=False, allowed_noninteractive=True
        )
        self.assertTrue(accepted)
        self.assertIn("authorized", output)

    def test_compliant_host_needs_no_consent_or_output(self) -> None:
        accepted, output = self.authorize("", tty=False, changes=[])
        self.assertTrue(accepted)
        self.assertEqual(output, "")

    def test_exclusive_lock_rejects_a_second_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            self.launcher, "LOCK", Path(temporary) / "launcher.lock"
        ):
            first = self.launcher._acquire_lock()
            try:
                with self.assertRaises(BlockingIOError):
                    self.launcher._acquire_lock()
            finally:
                os.close(first)

    def test_fallback_never_restores_an_active_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state.json"
            state.touch()
            with mock.patch.object(self.launcher, "STATE", state), mock.patch.object(
                self.launcher, "_unit_active", return_value=True
            ), mock.patch.object(self.launcher.subprocess, "run") as run:
                self.assertFalse(self.launcher._fallback_restore())
            run.assert_not_called()

    def test_activating_and_deactivating_units_are_treated_as_live(self) -> None:
        for active_state, expected in (
            ("activating", True),
            ("active", True),
            ("reloading", True),
            ("deactivating", True),
            ("inactive", False),
            ("failed", False),
        ):
            result = mock.Mock(
                returncode=0,
                stdout=f"LoadState=loaded\nActiveState={active_state}\n",
            )
            with self.subTest(active_state=active_state), mock.patch.object(
                self.launcher.subprocess, "run", return_value=result
            ):
                self.assertEqual(self.launcher._unit_active(), expected)

    def test_outer_interrupt_stops_unit_before_fallback_restore(self) -> None:
        command = [str(self.launcher.ROOT / "tools/quicperfctl"), "doctor"]
        stopped = mock.Mock(returncode=0)
        with mock.patch.object(
            self.launcher, "_unit_active", side_effect=[False, True, False]
        ), mock.patch.object(
            self.launcher, "_fallback_restore", side_effect=[True, True]
        ) as fallback, mock.patch.object(
            self.launcher, "snapshot", return_value=_state()
        ), mock.patch.object(
            self.launcher.subprocess,
            "run",
            side_effect=[KeyboardInterrupt, stopped],
        ) as run:
            status = self.launcher._run_locked(
                command, allow_temporary_host_policy_changes=False
            )
        self.assertEqual(status, 130)
        self.assertEqual(fallback.call_count, 2)
        self.assertEqual(run.call_count, 2)
        self.assertIn(
            "--property=CPUAffinity=0 1 2 3 4 5 6 9 10 11 12 13 14",
            run.call_args_list[0].args[0],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["/usr/bin/systemctl", "stop", self.launcher.UNIT_SERVICE],
        )

    def test_terminal_state_wins_over_stop_command_failure(self) -> None:
        failed_stop = mock.Mock(returncode=1)
        with mock.patch.object(
            self.launcher, "_unit_active", side_effect=[True, False]
        ), mock.patch.object(
            self.launcher.subprocess, "run", return_value=failed_stop
        ):
            self.assertTrue(self.launcher._stop_unit())


class TransactionTests(unittest.TestCase):
    plan_sha256 = "a" * 64

    def test_quicperf_exit_status_is_preserved_after_restoration(self) -> None:
        prepared = {"status": "prepared"}
        restored = {"status": "restored"}
        with mock.patch.object(host_policy, "prepare", return_value=prepared) as prepare, mock.patch.object(
            host_policy, "restore", return_value=restored
        ) as restore, mock.patch("quicperf_harness.cli.main", return_value=4) as quicperf:
            status = host_policy.run_quicperf(
                Path("state.json"), self.plan_sha256, ["--", "doctor"]
            )
        self.assertEqual(status, 4)
        prepare.assert_called_once_with(Path("state.json"), self.plan_sha256)
        quicperf.assert_called_once_with(["doctor"])
        restore.assert_called_once_with(Path("state.json"))

    def test_unexpected_coordinator_failure_still_restores(self) -> None:
        with mock.patch.object(
            host_policy, "prepare", return_value={"status": "prepared"}
        ), mock.patch.object(
            host_policy, "restore", return_value={"status": "restored"}
        ) as restore, mock.patch(
            "quicperf_harness.cli.main", side_effect=RuntimeError("injected")
        ):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                host_policy.run_quicperf(
                    Path("state.json"), self.plan_sha256, ["doctor"]
                )
        restore.assert_called_once_with(Path("state.json"))


if __name__ == "__main__":
    unittest.main()
