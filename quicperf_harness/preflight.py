"""Canonical production-preflight checks shared by coordinator surfaces."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

from .lanes import LaneCgroups, LaneError, delegated_cgroup_root
from .model import ExperimentSpecV2
from .paths import ArmedTrace, LoopbackPathController, NamespacePathController
from .topology import LaneTopology


class PreflightStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True, slots=True)
class PreflightCheck:
    name: str
    status: PreflightStatus
    detail: str
    reason: str | None = None
    required: bool = True

    def __post_init__(self) -> None:
        if not self.name or not self.detail:
            raise ValueError("preflight checks require a name and detail")
        if self.status is PreflightStatus.PASS and self.reason is not None:
            raise ValueError("passing preflight checks cannot have a failure reason")
        if self.status is not PreflightStatus.PASS and not self.reason:
            raise ValueError("failed or unexecuted preflight checks require a reason")

    @property
    def passed(self) -> bool:
        return self.status is PreflightStatus.PASS

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.name,
            "status": self.status.value,
            "passed": self.passed,
            "required": self.required,
            "reason": self.reason,
            "detail": self.detail,
        }


class PreflightInventory:
    """Ordered, unique checks with one fail-closed readiness decision."""

    def __init__(self) -> None:
        self._checks: list[PreflightCheck] = []
        self._names: set[str] = set()

    def add(self, check: PreflightCheck) -> None:
        if check.name in self._names:
            raise ValueError(f"duplicate preflight check: {check.name}")
        self._names.add(check.name)
        self._checks.append(check)

    def extend(self, checks: Iterable[PreflightCheck]) -> None:
        for check in checks:
            self.add(check)

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self._checks if check.required)

    def as_dicts(self) -> list[dict[str, Any]]:
        return [check.as_dict() for check in self._checks]

    def summary(self) -> dict[str, int]:
        return {
            status.value: sum(check.status is status for check in self._checks)
            for status in PreflightStatus
        }


def passed(name: str, detail: str) -> PreflightCheck:
    return PreflightCheck(name, PreflightStatus.PASS, detail)


def failed(name: str, reason: str, detail: str) -> PreflightCheck:
    return PreflightCheck(name, PreflightStatus.FAIL, detail, reason)


def not_run(name: str, reason: str, detail: str) -> PreflightCheck:
    return PreflightCheck(name, PreflightStatus.NOT_RUN, detail, reason)


def tls_material_check(
    root: Path, tls: Mapping[str, Any], *, private_key: Path = Path("tls/server.key.pem")
) -> PreflightCheck:
    """Verify trust, hostname, and leaf/private-key identity without exposing key data."""

    name = "tls_material"
    ca = (root / str(tls["ca_path"])).resolve()
    leaf = (root / str(tls["chain_path"])).resolve()
    key = (root / private_key).resolve()
    missing = [str(path) for path in (ca, leaf, key) if not path.is_file()]
    if missing:
        return failed(
            name,
            "tls_material_missing",
            f"missing required TLS file(s): {','.join(missing)}",
        )
    openssl = shutil.which("openssl")
    if openssl is None:
        return failed(name, "openssl_unavailable", "openssl is required for TLS preflight")

    def run(*arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [openssl, *arguments],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10.0,
        )

    hostname = str(tls["hostname"])
    try:
        verified = run(
            "verify", "-CAfile", str(ca), "-verify_hostname", hostname, str(leaf)
        )
        if verified.returncode != 0:
            detail = verified.stderr.decode("utf-8", errors="replace").strip()
            return failed(
                name,
                "tls_chain_or_hostname_invalid",
                detail or f"certificate verification failed for {hostname}",
            )
        leaf_key = run("x509", "-in", str(leaf), "-pubkey", "-noout")
        private_key_output = run("pkey", "-in", str(key), "-pubout")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return failed(name, "tls_verification_error", str(exc))
    if leaf_key.returncode != 0:
        return failed(
            name,
            "tls_leaf_invalid",
            leaf_key.stderr.decode("utf-8", errors="replace").strip()
            or "cannot read leaf certificate public key",
        )
    if private_key_output.returncode != 0:
        return failed(
            name,
            "tls_private_key_invalid",
            private_key_output.stderr.decode("utf-8", errors="replace").strip()
            or "cannot read server private key",
        )
    if leaf_key.stdout != private_key_output.stdout:
        return failed(
            name,
            "tls_private_key_mismatch",
            "server certificate and private key have different public keys",
        )
    return passed(
        name,
        f"chain, hostname {hostname}, and server private key identity verified",
    )


def selected_path_checks(spec: ExperimentSpecV2) -> list[PreflightCheck]:
    selected = sorted(
        {str(workload["path_profile"]) for workload in spec.raw["workloads"]}
    )
    checks: list[PreflightCheck] = []
    for profile in selected:
        name = f"path_controller:{profile}"
        if profile == "loopback":
            controller = LoopbackPathController()
            try:
                controller.create_session()
                controller.prepare_trial(profile)
            except Exception as exc:
                checks.append(
                    failed(name, "loopback_path_controller_failed", str(exc))
                )
            else:
                checks.append(
                    passed(name, "loopback path requires no namespace or qdisc treatment")
                )
            finally:
                controller.cleanup()
            continue
        controller = NamespacePathController(0, f"preflight:{spec.name}")
        error: Exception | None = None
        try:
            controller.create_session()
            controller.prepare_trial(profile)
            for role in ("server", "client"):
                controller.network_namespace(role)
                controller.endpoint_addresses(role)
            controller.arm(
                ArmedTrace(
                    time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                    + 100_000_000,
                    b"\0" * 32,
                    (),
                )
            )
            evidence = controller.finish_trial()
            if set(evidence.get("directions", {})) != {"0", "1"}:
                raise ValueError("path controller omitted directional qdisc evidence")
        except Exception as exc:
            error = exc
        finally:
            try:
                controller.cleanup()
            except Exception as exc:
                error = exc if error is None else RuntimeError(f"{error}; cleanup: {exc}")
        if error is not None:
            checks.append(
                not_run(
                    name,
                    "persistent_namespace_qdisc_controller_unavailable",
                    f"persistent namespace/qdisc path controller cannot execute: {error}",
                )
            )
        else:
            checks.append(
                passed(
                    name,
                    "persistent client/server/router namespaces and symmetric qdiscs verified",
                )
            )
    return checks


def cgroup_isolation_check(
    topology: LaneTopology,
    *,
    cgroup_root: Path | None = None,
) -> PreflightCheck:
    """Create and remove the exact empty lane hierarchy used by production runs."""

    name = "cgroup_v2_isolation"
    if cgroup_root is None:
        try:
            cgroup_root = delegated_cgroup_root()
        except LaneError as exc:
            return failed(name, "cgroup_v2_delegation_unavailable", str(exc))
    if not (cgroup_root / "cgroup.controllers").is_file():
        return failed(
            name,
            "cgroup_v2_unavailable",
            f"{cgroup_root} is not a cgroup-v2 delegation root",
        )
    required_controllers = {"cpu", "cpuset", "memory", "pids"}
    try:
        available = set(
            (cgroup_root / "cgroup.controllers")
            .read_text(encoding="ascii")
            .split()
        )
        delegated = set(
            (cgroup_root / "cgroup.subtree_control")
            .read_text(encoding="ascii")
            .split()
        )
    except OSError as exc:
        return failed(
            name,
            "cgroup_v2_controller_state_unreadable",
            f"cannot read cgroup-v2 controller state: {exc}",
        )
    missing = sorted(required_controllers - available)
    if missing:
        return failed(
            name,
            "cgroup_v2_controllers_unavailable",
            f"required cgroup-v2 controllers are unavailable: {','.join(missing)}",
        )
    undelegated = sorted(required_controllers - delegated)
    if undelegated:
        return failed(
            name,
            "cgroup_v2_controllers_not_delegated",
            f"required cgroup-v2 subtree controllers are not delegated: {','.join(undelegated)}",
        )
    groups = LaneCgroups(cgroup_root, topology)
    failure: Exception | None = None
    try:
        server, client = groups.create()
        if not server.is_dir() or not client.is_dir():
            raise RuntimeError("lane controller did not create both role cgroups")
    except Exception as exc:
        failure = exc
    try:
        groups.cleanup()
    except Exception as exc:
        if failure is None:
            failure = exc
        else:
            failure = RuntimeError(f"{failure}; cleanup failed: {exc}")
    if failure is not None:
        return failed(
            name,
            "cgroup_v2_isolation_unwritable",
            f"exact lane hierarchy probe failed: {failure}",
        )
    return passed(
        name,
        "exact writable cpu/cpuset/memory/pids lane hierarchy created and removed",
    )
