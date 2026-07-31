"""Canonical physical-observation producer for reusable qualification gates.

The physical driver is intentionally narrow: it receives immutable measurement
requests and returns primitive observations.  Cell selection, pairing,
inference, and qualification decisions remain coordinator-owned.  Qualification
observations are journal artifacts and are never inserted into ``sample``.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from decimal import Decimal, InvalidOperation
import hashlib
import math
import os
from pathlib import Path
import subprocess
import threading
from typing import Any, Mapping, Protocol, Sequence

from .canonical import canonical_bytes, loads_strict, normalize_decimal
from .amd_stability import (
    AmdContinuousMonitor,
    AmdMonitorTransientError,
    run_amd_calibration,
    run_amd_session_probe,
)
from .errors import IdentityMismatchError
from .identity import domain_hash
from .health import HealthError
from .host_policy import HostPolicyError, irq_policy_identity
from .journal import Journal
from .lanes import LaneCgroups, LaneError, delegated_cgroup_root
from .manifest_collect import ManifestCollectionError
from .paths import LoopbackPathController, NamespacePathController, PathError
from .planner import williams_rows
from .qualification import (
    HEADROOM_SCENARIOS,
    LANE_DIMENSIONS,
    WORKER_SENTINELS,
    QualificationArtifactStore,
    QualificationDecision,
    QualificationError,
    build_qualification_identity,
    encode_qualification_artifact,
    qualification_identity_hash,
    worker_reuse_eligible_scenario,
)
from .qualification_commands import evaluate_qualification_inputs
from .runner import (
    _ArmWindowCoordinator,
    EndpointRunError,
    _PEER_NUMERATOR_SCENARIOS,
    _WorkerPool,
    _arm_control_policy,
    _construct_tail_evidence,
    _amd_monitor_evidence_is_transient,
    _persisted_run_identity,
    _reattest_run_environment,
    _load_host_stability_context,
    _run_trial,
)
from .topology import TopologyError, allocate_lanes, discover_physical_cores
from .tail_window import (
    DURATION_LADDER_SECONDS,
    TailHeldOutBlock,
    TailPrefixObservation,
    TailScreenCell,
    plan_tail_window_qualification,
    screen_tail_window_qualification,
)
from .validity import INFRASTRUCTURE_TRANSIENT_REASONS


PLAN_SCHEMA_VERSION = "quicperf.qualification-plan.v1"
DRIVER_SCHEMA_VERSION = "quicperf.qualification-driver-observations.v2"
RUN_SCHEMA_VERSION = "quicperf.qualification-run.v2"
COMMAND_SCHEMA_VERSION = "quicperf.qualification-command.v1"
MAX_DRIVER_OUTPUT_BYTES = 64 * 1024 * 1024
DRIVER_TIMEOUT_SECONDS = 24 * 60 * 60
_T_CRITICAL_90 = {12: Decimal("1.795884819"), 20: Decimal("1.729132812")}


class QualificationObservationSource(Protocol):
    def observe(
        self,
        *,
        kind: str,
        stage: str,
        stage_plan_hash: str,
        requests: Sequence[Mapping[str, Any]],
    ) -> Sequence[Mapping[str, Any]]:
        """Return one raw observation for every exact request."""


class PhysicalQualificationUnavailable(Exception):
    """The requested external physical execution cannot run on this host."""


class QualificationInfrastructureTransient(Exception):
    """One exact qualification attempt hit a closed retryable host failure."""

    def __init__(
        self,
        request_id: str,
        reason: str,
        *,
        detail: str = "",
        stage: str | None = None,
        records: Sequence[Mapping[str, Any]] = (),
        stage_hashes: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(f"{request_id}: {reason}")
        self.request_id = request_id
        self.reason = reason
        self.detail = detail
        self.stage = stage
        self.records = tuple(dict(record) for record in records)
        self.stage_hashes = dict(stage_hashes or {})


class QualificationCollectionError(QualificationError):
    """Collection failed after producing evidence that must remain visible."""

    def __init__(
        self,
        message: str,
        *,
        stage: str,
        records: Sequence[Mapping[str, Any]],
        stage_hashes: Mapping[str, str],
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.records = tuple(dict(record) for record in records)
        self.stage_hashes = dict(stage_hashes)


def _endpoint_exception(
    qualification: str,
    request_id: str,
    error: EndpointRunError,
    *,
    allow_retry: bool = False,
) -> Exception:
    if error.reason.startswith("host_health_telemetry_unavailable:"):
        return PhysicalQualificationUnavailable(
            f"native {qualification} host telemetry is unavailable: "
            f"{error.reason.partition(':')[2]}"
        )
    if error.infrastructure_transient and allow_retry:
        if error.reason not in INFRASTRUCTURE_TRANSIENT_REASONS:
            return QualificationError(
                f"native {qualification} trial {request_id} reported an unknown "
                f"infrastructure transient: {error.reason}"
            )
        return QualificationInfrastructureTransient(
            request_id, error.reason, detail=error.detail
        )
    return QualificationError(
        f"native {qualification} trial {request_id} failed: {error}"
    )


def _headroom_endpoint_exception(
    request_id: str, error: EndpointRunError
) -> Exception:
    return _endpoint_exception("headroom", request_id, error, allow_retry=True)


def _worker_endpoint_exception(request_id: str, error: EndpointRunError) -> Exception:
    return _endpoint_exception("worker-reuse", request_id, error, allow_retry=True)


def _lane_endpoint_exception(request_id: str, error: EndpointRunError) -> Exception:
    return _endpoint_exception(
        "lane-interference", request_id, error, allow_retry=True
    )


def _parity_endpoint_exception(request_id: str, error: EndpointRunError) -> Exception:
    return _endpoint_exception(
        "legacy-v2-parity", request_id, error, allow_retry=True
    )


def _window_endpoint_exception(request_id: str, error: EndpointRunError) -> Exception:
    return _endpoint_exception(
        "window-qualification", request_id, error, allow_retry=True
    )


def _tail_window_endpoint_exception(
    request_id: str, error: EndpointRunError
) -> Exception:
    return _endpoint_exception(
        "tail-window", request_id, error, allow_retry=True
    )


class NativeSessionObservationSource:
    """Fail-closed native producer for exact physical qualification observations."""

    def __init__(
        self,
        *,
        root: Path,
        run_dir: Path,
        campaign_id: str,
        spec: Any,
        manifest: Any,
        amd_context: Any | None = None,
    ) -> None:
        self.root = root
        self.run_dir = run_dir
        self.campaign_id = campaign_id
        self.spec = spec
        self.manifest = manifest
        self.amd_context = amd_context
        self.amd_monitor: AmdContinuousMonitor | None = None
        self.amd_evidence: dict[str, Any] | None = None
        self.binary_paths: Mapping[str, Path] | None = None
        self.cgroup_root: Path | None = None
        self.physical_cores: Any = None
        self._session_previous_affinity: frozenset[int] | None = None

    def _coordinator_cpus(self, topologies: Sequence[Any]) -> tuple[int, ...]:
        housekeeping = {
            cpu
            for topology in topologies
            for cpu in topology.housekeeping_cpus
        }
        if not housekeeping:
            raise QualificationError(
                "qualification coordinator has no housekeeping CPU"
            )
        return tuple(sorted(housekeeping))

    def _reserve_monitor_cpu(self) -> None:
        if self.amd_context is None:
            return
        if self._session_previous_affinity is not None:
            raise QualificationError("AMD monitor CPU is already reserved")
        self._prepare_headroom()
        try:
            client_cores = int(
                self.spec.raw["treatment"]["resources"][
                    "client_physical_cores"
                ]
            )
            topology = allocate_lanes(
                self.physical_cores,
                1,
                client_cores_per_lane=client_cores,
            )[0]
            coordinator_cpus = self._coordinator_cpus((topology,))
            previous = frozenset(os.sched_getaffinity(0))
            os.sched_setaffinity(0, coordinator_cpus)
        except (TopologyError, OSError) as exc:
            raise PhysicalQualificationUnavailable(
                f"AMD monitor CPU reservation is unavailable: {exc}"
            ) from exc
        self._session_previous_affinity = previous

    def _restore_session_affinity(self) -> None:
        previous = self._session_previous_affinity
        if previous is None:
            return
        self._session_previous_affinity = None
        os.sched_setaffinity(0, previous)

    def start_host_stability(self) -> None:
        if self.amd_context is None:
            return
        self._reserve_monitor_cpu()
        context = self.amd_context
        try:
            try:
                evaluation, document = run_amd_session_probe(
                    cpus=context.cpus,
                    housekeeping_cpu=context.housekeeping_cpu,
                    helper=context.helper,
                    policy=context.policy,
                    reference=context.reference,
                    temperature_source=context.temperature_source,
                )
            except HealthError as exc:
                raise QualificationError(
                    f"AMD pre-qualification probe failed: {exc}"
                ) from exc
            self.amd_evidence = {
                "schema_version": "quicperf.amd-qualification-session.v1",
                "provider": "amd_delivered_performance_v1",
                "passed": False,
                "pre_probe": document,
                "continuous": None,
                "post_probe": None,
            }
            if not evaluation.passed:
                raise QualificationError(
                    "AMD pre-qualification probe failed: "
                    + ",".join(evaluation.reasons)
                )
            self.amd_monitor = AmdContinuousMonitor(
                cpus=context.cpus,
                housekeeping_cpu=context.housekeeping_cpu,
                spin_helper=context.spin_helper,
                policy=context.policy,
                reference=context.reference,
                temperature_source=context.temperature_source,
            )
            try:
                self.amd_monitor.start()
            except AmdMonitorTransientError as exc:
                raise QualificationInfrastructureTransient(
                    "qualification_session_monitor",
                    "host_stability_monitor_transient",
                ) from exc
            except HealthError as exc:
                raise QualificationError(
                    f"AMD qualification monitor failed to start: {exc}"
                ) from exc
        except BaseException:
            self.abort_host_stability()
            raise

    def finish_host_stability(self) -> Mapping[str, Any] | None:
        if self.amd_context is None:
            return None
        try:
            if self.amd_monitor is None or self.amd_evidence is None:
                raise QualificationError("AMD qualification monitor was not started")
            try:
                continuous = self.amd_monitor.stop()
            except AmdMonitorTransientError as exc:
                raise QualificationInfrastructureTransient(
                    "qualification_session_monitor",
                    "host_stability_monitor_transient",
                ) from exc
            except HealthError as exc:
                raise QualificationError(
                    f"AMD qualification monitor failed to stop: {exc}"
                ) from exc
            self.amd_monitor = None
            self.amd_evidence["continuous"] = continuous
            if not continuous["passed"]:
                if _amd_monitor_evidence_is_transient(continuous):
                    raise QualificationInfrastructureTransient(
                        "qualification_session_monitor",
                        "host_stability_monitor_transient",
                    )
                raise QualificationError(
                    "AMD qualification monitor failed: "
                    + ",".join(str(item) for item in continuous["reasons"])
                )
            context = self.amd_context
            try:
                evaluation, document = run_amd_session_probe(
                    cpus=context.cpus,
                    housekeeping_cpu=context.housekeeping_cpu,
                    helper=context.helper,
                    policy=context.policy,
                    reference=context.reference,
                    temperature_source=context.temperature_source,
                )
            except HealthError as exc:
                raise QualificationError(
                    f"AMD post-qualification probe failed: {exc}"
                ) from exc
            self.amd_evidence["post_probe"] = document
            if not evaluation.passed:
                raise QualificationError(
                    "AMD post-qualification probe failed: "
                    + ",".join(evaluation.reasons)
                )
            self.amd_evidence["passed"] = True
            return dict(self.amd_evidence)
        finally:
            self._restore_session_affinity()

    def abort_host_stability(self) -> None:
        try:
            if self.amd_monitor is not None:
                self.amd_monitor.stop()
        except HealthError:
            pass
        finally:
            self.amd_monitor = None
            self._restore_session_affinity()

    def _prepare_headroom(self) -> None:
        if self.binary_paths is not None:
            return
        try:
            self.binary_paths = _reattest_run_environment(
                self.root, self.spec, self.manifest
            )
            self.cgroup_root = delegated_cgroup_root()
            LaneCgroups.reap_stale(self.cgroup_root)
            self.physical_cores = discover_physical_cores()
        except (
            LaneError,
            ManifestCollectionError,
            TopologyError,
            OSError,
            ValueError,
        ) as exc:
            raise PhysicalQualificationUnavailable(
                f"native qualification resources are unavailable: {exc}"
            ) from exc

    @staticmethod
    def _mutable(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): NativeSessionObservationSource._mutable(item) for key, item in value.items()}
        if isinstance(value, tuple):
            return [NativeSessionObservationSource._mutable(item) for item in value]
        return value

    def _trial_spec(self, request: Mapping[str, Any]) -> Any:
        raw = self._mutable(self.spec.raw)
        if request["phase"] in {
            "headroom_screen",
            "lane_screen",
            "legacy_v2_parity",
            "legacy_v2_parity_invalid",
        }:
            scenario = str(request["scenario"])
            workloads = [item for item in raw["workloads"] if item["scenario"] == scenario]
            if len(workloads) != 1:
                raise QualificationError(
                    f"qualification scenario {scenario!r} is not uniquely frozen"
                )
            workloads[0]["measurement_ns"] = int(request["duration_ms"]) * 1_000_000
        elif request["phase"] in {"window_screen", "window_held_out"}:
            scenario = str(request["scenario"])
            workloads = [item for item in raw["workloads"] if item["scenario"] == scenario]
            if len(workloads) != 1:
                raise QualificationError(
                    f"qualification scenario {scenario!r} is not uniquely frozen"
                )
            workloads[0]["measurement_ns"] = int(request["duration_seconds"]) * 1_000_000_000
        elif request["phase"] in {"tail_window_screen", "tail_window_held_out"}:
            scenario = str(request["scenario"])
            workloads = [item for item in raw["workloads"] if item["scenario"] == scenario]
            if len(workloads) != 1:
                raise QualificationError(
                    f"qualification scenario {scenario!r} is not uniquely frozen"
                )
            workloads[0]["measurement_ns"] = 20_000_000_000
            workloads[0]["eligible_operation_limit"] = 0
        return replace(self.spec, raw=raw)

    def _headroom_trial(
        self,
        request: Mapping[str, Any],
        *,
        reference_client: str,
        client_cores: int,
    ) -> Mapping[str, Any]:
        self._prepare_headroom()
        assert self.binary_paths is not None
        assert self.cgroup_root is not None
        topology = allocate_lanes(
            self.physical_cores, 1, client_cores_per_lane=client_cores
        )[0]
        identity = canonical_bytes(
            {
                "campaign_id": self.campaign_id,
                "request_id": request["request_id"],
                "reference_client": reference_client,
            }
        )
        trial_id = domain_hash("qualification-native-trial", identity)
        cell_id = domain_hash("qualification-native-cell", identity)
        microblock_id = domain_hash("qualification-native-block", identity)
        trace_seed = domain_hash("qualification-native-trace", identity)
        trial_row = {
            "trial_id": trial_id,
            "cell_id": cell_id,
            "microblock_id": microblock_id,
            "session_number": 1,
        }
        cell = {
            "estimand": self.spec.estimand,
            "scenario": str(request["scenario"]),
            "path_profile": "loopback",
            "concurrency": 16,
            "server": str(request["server"]),
            "server_backend": str(request["backend"]),
            "reference_client": reference_client,
            "reference_client_backend": self.spec.reference_client_backend,
            "client_event_loop_workers": client_cores,
            "lane": 0,
            "trace_seed": trace_seed,
        }
        trial_spec = self._trial_spec(request)
        cgroups = LaneCgroups(self.cgroup_root, topology)
        path = LoopbackPathController()
        previous_affinity = os.sched_getaffinity(0)
        try:
            coordinator_cpus = self._coordinator_cpus((topology,))
            os.sched_setaffinity(0, coordinator_cpus)
            with ExitStack() as resources:
                resources.callback(os.sched_setaffinity, 0, previous_affinity)
                resources.callback(cgroups.cleanup)
                lane_cgroups = cgroups.create()
                path.create_session()
                resources.callback(path.cleanup)
                return _run_trial(
                    None,
                    root=self.root,
                    run_dir=self.run_dir,
                    campaign_id=self.campaign_id,
                    spec=trial_spec,
                    manifest=self.manifest,
                    trial_row=trial_row,
                    cell_config=cell,
                    binary_paths=self.binary_paths,
                    lane_topology=topology,
                    lane_cgroups=lane_cgroups,
                    path_controller=path,
                    endpoint_override=None,
                    endpoint_environment=None,
                    expected_coordinator_affinity=coordinator_cpus,
                    amd_monitor=self.amd_monitor,
                    construct_sample=False,
                    allow_client_headroom_failure=True,
                )
        except EndpointRunError as exc:
            raise _headroom_endpoint_exception(str(request["request_id"]), exc) from exc
        except (LaneError, PathError, TopologyError, OSError) as exc:
            raise PhysicalQualificationUnavailable(
                f"native headroom resources became unavailable: {exc}"
            ) from exc
        finally:
            os.sched_setaffinity(0, previous_affinity)

    def _observe_headroom(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        client_cores = int(request["client_cores"])
        trials = [
            self._headroom_trial(
                request, reference_client=client, client_cores=client_cores
            )
            for client in self.spec.reference_clients
        ]
        telemetry = [trial["resource_telemetry"] for trial in trials]
        if any(item is None for item in telemetry):
            raise QualificationError("native headroom trial omitted cgroup telemetry")
        client_cpu_ns = sum(int(item["client_cpu_ns"]) for item in telemetry)
        wall_ns = sum(int(trial["runtime"]["trial_wall_ns"]) for trial in trials)
        values: dict[str, Any] = {"client_cpu_ns": client_cpu_ns, "wall_ns": wall_ns}
        if request["phase"] == "headroom_held_out":
            rates = [
                Decimal(int(trial["server_result"]["numerator"]))
                * Decimal(1_000_000_000)
                / Decimal(int(trial["server_result"]["denominator_raw_ns"]))
                for trial in trials
            ]
            values["rate"] = normalize_decimal((rates[0] * rates[1]).sqrt())
            values["client_cpu_p95"] = normalize_decimal(
                max(
                    Decimal(str(trial["client_result"]["client_cpu_fraction_of_quota_p95"]))
                    for trial in trials
                )
            )
        return {"request_id": str(request["request_id"]), "values": values}

    @contextmanager
    def _worker_resources(self, *, pooled: bool):
        self._prepare_headroom()
        assert self.binary_paths is not None
        assert self.cgroup_root is not None
        client_cores = int(
            self.spec.raw["treatment"]["resources"][
                "client_physical_cores"
            ]
        )
        topology = allocate_lanes(
            self.physical_cores,
            1,
            client_cores_per_lane=client_cores,
        )[0]
        cgroups = LaneCgroups(self.cgroup_root, topology)
        path = NamespacePathController(
            0, f"qualification-worker:{self.campaign_id}"
        )
        active_processes: dict[int, Any] = {}
        active_processes_lock = threading.Lock()
        previous_affinity = os.sched_getaffinity(0)
        try:
            os.sched_setaffinity(0, self._coordinator_cpus((topology,)))
            with ExitStack() as resources:
                resources.callback(os.sched_setaffinity, 0, previous_affinity)
                resources.callback(cgroups.cleanup)
                lane_cgroups = cgroups.create()
                path.create_session()
                resources.callback(path.cleanup)
                pool = None
                if pooled:
                    pool = _WorkerPool(
                        root=self.root,
                        endpoint_override=None,
                        environment={},
                        active_processes=active_processes,
                        active_processes_lock=active_processes_lock,
                    )
                    resources.callback(pool.close)
                yield topology, lane_cgroups, path, pool
        except (LaneError, PathError, TopologyError, OSError) as exc:
            raise PhysicalQualificationUnavailable(
                f"native worker-reuse resources are unavailable: {exc}"
            ) from exc
        finally:
            os.sched_setaffinity(0, previous_affinity)

    def _worker_trial(
        self,
        request: Mapping[str, Any],
        *,
        scenario: str,
        sequence_position: int,
        topology: Any,
        lane_cgroups: tuple[Path, Path],
        path: NamespacePathController,
        pool: _WorkerPool | None,
        exercise_only: bool,
    ) -> Mapping[str, Any]:
        assert self.binary_paths is not None
        identity = canonical_bytes(
            {
                "campaign_id": self.campaign_id,
                "request_id": request["request_id"],
                "scenario": scenario,
                "sequence_position": sequence_position,
            }
        )
        trial_id = domain_hash("qualification-native-worker-trial", identity)
        cell_id = domain_hash("qualification-native-worker-cell", identity)
        trial_row = {
            "trial_id": trial_id,
            "cell_id": cell_id,
            "microblock_id": domain_hash("qualification-native-worker-block", identity),
            "session_number": 1,
        }
        cell = {
            "estimand": self.spec.estimand,
            "scenario": scenario,
            "path_profile": "loss_recovery_v1" if scenario == "loss_recovery" else "loopback",
            "concurrency": int(next(
                item["connections"]
                for item in self.spec.raw["workloads"]
                if item["scenario"] == scenario
            )),
            "server": str(request["adapter"]),
            "server_backend": str(request["backend"]),
            "reference_client": str(request["adapter"]),
            "reference_client_backend": str(request["backend"]),
            "client_event_loop_workers": len(topology.client_cpus),
            "lane": 0,
            "trace_seed": domain_hash("qualification-native-worker-trace", identity),
        }
        try:
            return _run_trial(
                None,
                root=self.root,
                run_dir=self.run_dir,
                campaign_id=self.campaign_id,
                spec=self.spec,
                manifest=self.manifest,
                trial_row=trial_row,
                cell_config=cell,
                binary_paths=self.binary_paths,
                lane_topology=topology,
                lane_cgroups=lane_cgroups,
                path_controller=path,
                endpoint_override=None,
                endpoint_environment=None,
                worker_pool=pool,
                expected_coordinator_affinity=self._coordinator_cpus((topology,)),
                amd_monitor=self.amd_monitor,
                construct_sample=False,
                exercise_only=exercise_only,
            )
        except EndpointRunError as exc:
            raise _worker_endpoint_exception(str(request["request_id"]), exc) from exc

    def _observe_worker_screens(
        self, requests: Sequence[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]:
        observations: list[Mapping[str, Any]] = []
        chain_pids: dict[str, Mapping[str, int]] = {}
        with self._worker_resources(pooled=True) as (topology, cgroups, path, pool):
            assert pool is not None
            for request in requests:
                result = self._worker_trial(
                    request,
                    scenario=str(request["scenario"]),
                    sequence_position=int(request["cycle"]),
                    topology=topology,
                    lane_cgroups=cgroups,
                    path=path,
                    pool=pool,
                    exercise_only=True,
                )
                chain_id = str(request["chain_id"])
                pids = result["pids"]
                if chain_id in chain_pids and chain_pids[chain_id] != pids:
                    raise QualificationError(
                        f"native worker chain {chain_id} changed endpoint PIDs"
                    )
                chain_pids.setdefault(chain_id, pids)
                reset = result["inventories"]["reset"]
                zero_state = {
                    field: sum(int(inventory[field]) for inventory in reset.values())
                    for field in (
                        "live_connections",
                        "live_streams",
                        "live_tickets",
                        "work_inventory",
                    )
                }
                if request["phase"] == "reset_screen":
                    values = zero_state
                else:
                    values = {
                        "fd_count": int(result["fd_count"]),
                        "memory_bytes": int(result["memory_bytes"]),
                        "live_connections": zero_state["live_connections"],
                        "live_streams": zero_state["live_streams"],
                        "live_tickets": zero_state["live_tickets"],
                    }
                observations.append(
                    {"request_id": str(request["request_id"]), "values": values}
                )
        return observations

    def _observe_worker_parity(
        self, requests: Sequence[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]:
        observations: list[Mapping[str, Any]] = []
        for request in requests:
            reused = request["mode"] == "reused"
            with self._worker_resources(pooled=reused) as (topology, cgroups, path, pool):
                sentinel_result = None
                for position, scenario in enumerate(request["scenario_sequence"]):
                    result = self._worker_trial(
                        request,
                        scenario=str(scenario),
                        sequence_position=position,
                        topology=topology,
                        lane_cgroups=cgroups,
                        path=path,
                        pool=pool,
                        exercise_only=False,
                    )
                    if scenario == request["sentinel"]:
                        sentinel_result = result
                if sentinel_result is None:
                    raise QualificationError("worker parity sequence omitted its sentinel")
                server = sentinel_result["server_result"]
                rate = (
                    Decimal(int(server["numerator"]))
                    * Decimal(1_000_000_000)
                    / Decimal(int(server["denominator_raw_ns"]))
                )
                observations.append(
                    {
                        "request_id": str(request["request_id"]),
                        "values": {"rate": normalize_decimal(rate)},
                    }
                )
        return observations

    @contextmanager
    def _lane_resources(self, lanes: int):
        self._prepare_headroom()
        assert self.binary_paths is not None
        assert self.cgroup_root is not None
        client_cores = int(
            self.spec.raw["treatment"]["resources"][
                "client_physical_cores"
            ]
        )
        topologies = allocate_lanes(
            self.physical_cores,
            lanes,
            client_cores_per_lane=client_cores,
        )
        previous_affinity = os.sched_getaffinity(0)
        try:
            housekeeping = self._coordinator_cpus(topologies)
            os.sched_setaffinity(0, housekeeping)
            with ExitStack() as resources:
                resources.callback(os.sched_setaffinity, 0, previous_affinity)
                lane_cgroups: dict[int, tuple[Path, Path]] = {}
                paths: dict[int, NamespacePathController] = {}
                for topology in topologies:
                    cgroups = LaneCgroups(self.cgroup_root, topology)
                    resources.callback(cgroups.cleanup)
                    lane_cgroups[topology.lane] = cgroups.create()
                    path = NamespacePathController(
                        topology.lane,
                        f"qualification-lane:{self.campaign_id}",
                    )
                    path.create_session()
                    resources.callback(path.cleanup)
                    paths[topology.lane] = path
                yield topologies, lane_cgroups, paths, housekeeping
        except (LaneError, PathError, TopologyError, OSError) as exc:
            raise PhysicalQualificationUnavailable(
                f"native lane-interference resources are unavailable: {exc}"
            ) from exc
        finally:
            os.sched_setaffinity(0, previous_affinity)

    def _lane_trial(
        self,
        request: Mapping[str, Any],
        *,
        reference_client: str,
        lane: int,
        topology: Any,
        lane_cgroups: tuple[Path, Path],
        path: NamespacePathController,
        coordinator_affinity: tuple[int, ...],
        barrier: threading.Barrier | None,
        shared_epoch: _ArmWindowCoordinator | None,
        external_thermal_provider: bool = False,
        construct_sample: bool = False,
        allow_client_headroom_failure: bool = False,
        allow_resolution_limited: bool = False,
    ) -> Mapping[str, Any]:
        assert self.binary_paths is not None
        identity = canonical_bytes(
            {
                "campaign_id": self.campaign_id,
                "request_id": request["request_id"],
                "reference_client": reference_client,
                "lane": lane,
            }
        )
        trial_id = domain_hash("qualification-native-lane-trial", identity)
        cell_id = domain_hash("qualification-native-lane-cell", identity)
        scenario = str(request["scenario"])
        path_profile = (
            str(request["path_profile"])
            if request["phase"] == "legacy_v2_parity_invalid"
            else "loss_recovery_v1"
            if scenario == "loss_recovery"
            else "loopback"
        )
        cell = {
            "estimand": self.spec.estimand,
            "scenario": scenario,
            "path_profile": path_profile,
            "concurrency": int(next(
                item["connections"]
                for item in self.spec.raw["workloads"]
                if item["scenario"] == scenario
            )),
            "server": str(request["server"]),
            "server_backend": str(request["backend"]),
            "reference_client": reference_client,
            "reference_client_backend": self.spec.reference_client_backend,
            "client_event_loop_workers": len(topology.client_cpus),
            "lane": lane,
            "trace_seed": domain_hash(
                "qualification-native-lane-trace",
                canonical_bytes(
                    {
                        "campaign_id": self.campaign_id,
                        "request_id": request["request_id"],
                        "reference_client": reference_client,
                    }
                ),
            ),
        }
        if "trace_seed" in request:
            cell["trace_seed"] = str(request["trace_seed"])
        try:
            return _run_trial(
                None,
                root=self.root,
                run_dir=self.run_dir,
                campaign_id=self.campaign_id,
                spec=self._trial_spec(request),
                manifest=self.manifest,
                trial_row={
                    "trial_id": trial_id,
                    "cell_id": cell_id,
                    "microblock_id": domain_hash("qualification-native-lane-block", identity),
                    "session_number": 1,
                },
                cell_config=cell,
                binary_paths=self.binary_paths,
                lane_topology=topology,
                lane_cgroups=lane_cgroups,
                path_controller=path,
                endpoint_override=None,
                endpoint_environment=None,
                expected_coordinator_affinity=coordinator_affinity,
                measurement_barrier=barrier,
                shared_measurement_epoch=shared_epoch,
                amd_monitor=self.amd_monitor,
                external_thermal_provider=external_thermal_provider,
                construct_sample=construct_sample,
                allow_client_headroom_failure=allow_client_headroom_failure,
                allow_resolution_limited=allow_resolution_limited,
            )
        except EndpointRunError as exc:
            classify = (
                _window_endpoint_exception
                if request["phase"] in {"window_screen", "window_held_out"}
                else _tail_window_endpoint_exception
                if request["phase"]
                in {"tail_window_screen", "tail_window_held_out"}
                else _parity_endpoint_exception
                if request["phase"]
                in {"legacy_v2_parity", "legacy_v2_parity_invalid"}
                else _lane_endpoint_exception
            )
            raise classify(str(request["request_id"]), exc) from exc

    def _lane_treatment(
        self, request: Mapping[str, Any]
    ) -> list[list[Mapping[str, Any]]]:
        lanes = int(request["lanes"])
        by_reference: list[list[Mapping[str, Any]]] = []
        for reference_client in self.spec.reference_clients:
            with self._lane_resources(lanes) as (
                topologies,
                lane_cgroups,
                paths,
                coordinator_affinity,
            ):
                shared_epoch: _ArmWindowCoordinator | None = None
                barrier = None
                if lanes > 1:
                    barrier = threading.Barrier(lanes)
                    shared_epoch = _ArmWindowCoordinator(
                        lanes,
                        _arm_control_policy(self.spec),
                    )
                with ThreadPoolExecutor(max_workers=lanes) as executor:
                    futures = [
                        executor.submit(
                            self._lane_trial,
                            request,
                            reference_client=reference_client,
                            lane=lane,
                            topology=topologies[lane],
                            lane_cgroups=lane_cgroups[lane],
                            path=paths[lane],
                            coordinator_affinity=coordinator_affinity,
                            barrier=barrier,
                            shared_epoch=shared_epoch,
                        )
                        for lane in range(lanes)
                    ]
                    by_reference.append([future.result() for future in futures])
        return by_reference

    @staticmethod
    def _lane_trial_counters(result: Mapping[str, Any]) -> Mapping[str, int]:
        server = result["server_result"]
        client = result["client_result"]
        try:
            server_counters = loads_strict(server["completion_counters_json"])
            client_counters = loads_strict(client["completion_counters_json"])
            telemetry = result["resource_telemetry"]
            if telemetry is None:
                raise ValueError("resource telemetry is absent")
            return {
                "server_cpu_ns": int(telemetry["server_cpu_ns"]),
                "client_cpu_ns": int(telemetry["client_cpu_ns"]),
                "udp_packets": int(server_counters["packets_sent"])
                + int(client_counters["packets_sent"]),
                "validated_units": int(server["numerator"]),
                "timer_wakeups": int(server_counters["timer_expirations"])
                + int(client_counters["timer_expirations"]),
                "wall_ns": int(result["runtime"]["trial_wall_ns"]),
                "measurement_ns": int(server["denominator_raw_ns"]),
                "memory_bytes": int(telemetry["server_memory_peak_bytes"])
                + int(telemetry["client_memory_peak_bytes"]),
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise QualificationError(f"native lane result telemetry is malformed: {exc}") from exc

    def _observe_lane(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        treatments = self._lane_treatment(request)
        lanes = int(request["lanes"])
        counters = [
            [self._lane_trial_counters(result) for result in reference]
            for reference in treatments
        ]
        if request["phase"] == "lane_screen":
            values = {
                field: sum(reference[0][field] for reference in counters)
                for field in (
                    "server_cpu_ns",
                    "client_cpu_ns",
                    "udp_packets",
                    "validated_units",
                    "timer_wakeups",
                    "wall_ns",
                    "memory_bytes",
                )
            }
        else:
            per_lane = []
            for lane in range(lanes):
                lane_values = [reference[lane] for reference in counters]
                rates = [
                    Decimal(value["validated_units"]) * Decimal(1_000_000_000)
                    / Decimal(value["measurement_ns"])
                    for value in lane_values
                ]
                rate = (
                    (rates[0] * rates[1]).sqrt()
                    if len(rates) == 2
                    else rates[0]
                )
                per_lane.append(
                    {
                        "lane": lane,
                        "rate": normalize_decimal(rate),
                        "peak_memory_bytes": sum(
                            value["memory_bytes"] for value in lane_values
                        ) // len(lane_values),
                        "treatment_hash": str(request["treatment_hash"]),
                    }
                )
            values = {"per_lane": per_lane}
        return {"request_id": str(request["request_id"]), "values": values}

    @staticmethod
    def _window_endpoint_bins(
        result: Mapping[str, Any], role: str
    ) -> list[tuple[int, int]]:
        rows = result.get("measurement_subwindows")
        if not isinstance(rows, list) or len(rows) != 200:
            raise QualificationError(
                f"native window {role} result omitted 200 exact measurement bins"
            )
        values: list[tuple[int, int]] = []
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping) or set(row) != {
                "blocked_events",
                "validated_units",
            }:
                raise QualificationError(
                    f"native window {role} bin {index} fields are malformed"
                )
            validated = row["validated_units"]
            blocked = row["blocked_events"]
            if (
                isinstance(validated, bool)
                or not isinstance(validated, int)
                or not 0 <= validated <= 0xFFFF_FFFF_FFFF_FFFF
                or isinstance(blocked, bool)
                or not isinstance(blocked, int)
                or not 0 <= blocked <= 0xFFFF_FFFF_FFFF_FFFF
            ):
                raise QualificationError(
                    f"native window {role} bin {index} counters are malformed"
                )
            values.append((validated, blocked))
        return values

    def _window_trial_values(
        self, request: Mapping[str, Any], result: Mapping[str, Any]
    ) -> tuple[int, int, int, str]:
        scenario = str(request["scenario"])
        server = self._window_endpoint_bins(result["server_result"], "server")
        client = self._window_endpoint_bins(
            result["client_result"], "reference_client"
        )
        if scenario == "bidi":
            bins = [
                (left[0] + right[0], left[1] + right[1])
                for left, right in zip(server, client, strict=True)
            ]
            expected_reference = int(result["server_result"]["numerator"]) + int(
                result["client_result"]["numerator"]
            )
        elif scenario in _PEER_NUMERATOR_SCENARIOS:
            bins = [
                (right[0], left[1] + right[1])
                for left, right in zip(server, client, strict=True)
            ]
            expected_reference = int(result["server_result"]["numerator"])
        else:
            bins = [
                (left[0], left[1] + right[1])
                for left, right in zip(server, client, strict=True)
            ]
            expected_reference = int(result["server_result"]["numerator"])
        reference = sum(value[0] for value in bins)
        if reference != expected_reference:
            raise QualificationError(
                "native window subwindows do not reconcile with the reference numerator"
            )
        nested_seconds = int(request["nested_window_seconds"])
        reference_seconds = int(request["reference_window_seconds"])
        scaled = nested_seconds * len(bins)
        if scaled % reference_seconds:
            raise QualificationError("nested window is not exact at native bin resolution")
        nested_rows = bins[: scaled // reference_seconds]
        nested = sum(value[0] for value in nested_rows)
        if len(nested_rows) % 10:
            raise QualificationError(
                "nested window cannot be divided into ten exact validity buckets"
            )
        bucket_size = len(nested_rows) // 10
        validity_buckets = [
            nested_rows[index : index + bucket_size]
            for index in range(0, len(nested_rows), bucket_size)
        ]
        stalled = any(
            sum(value[0] for value in bucket) == 0
            and sum(value[1] for value in bucket) == 0
            for bucket in validity_buckets
        )
        operation_scenarios = {
            "small_payload_pps",
            "datagram",
            "reqresp",
            "stream_churn",
            "close_reset_cleanup",
            "connect",
            "resumed_connect",
            "zero_rtt_reqresp",
        }
        if stalled:
            classification = "invalid_progress"
        elif scenario in operation_scenarios and nested < 400:
            classification = "resolution_limited"
        elif scenario == "flow_control":
            blocked_indexes = [
                index
                for index, bucket in enumerate(validity_buckets)
                if sum(value[1] for value in bucket) > 0
            ]
            recovered = bool(blocked_indexes) and any(
                sum(value[0] for value in bucket) > 0
                for bucket in validity_buckets[blocked_indexes[0] + 1 :]
            )
            classification = "valid" if recovered else "invalid_flow_control_recovery"
        else:
            classification = "valid"
        cap_hits = sum(
            int(endpoint[field])
            for endpoint in (result["server_result"], result["client_result"])
            for field in (
                "work_cap_hits",
                "byte_cap_hits",
                "stream_cap_hits",
                "stream_id_cap_hits",
            )
        )
        return nested, reference, cap_hits, classification

    def _observe_window(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        nested = 0
        reference = 0
        cap_hits = 0
        nested_classifications: list[str] = []
        for reference_client in self.spec.reference_clients:
            with self._lane_resources(1) as (
                topologies,
                lane_cgroups,
                paths,
                coordinator_affinity,
            ):
                result = self._lane_trial(
                    request,
                    reference_client=reference_client,
                    lane=0,
                    topology=topologies[0],
                    lane_cgroups=lane_cgroups[0],
                    path=paths[0],
                    coordinator_affinity=coordinator_affinity,
                    barrier=None,
                    shared_epoch=None,
                )
            (
                trial_nested,
                trial_reference,
                trial_cap_hits,
                trial_classification,
            ) = self._window_trial_values(request, result)
            nested += trial_nested
            reference += trial_reference
            cap_hits += trial_cap_hits
            nested_classifications.append(trial_classification)
        nested_classification = (
            "valid"
            if all(value == "valid" for value in nested_classifications)
            else "+".join(sorted(set(nested_classifications)))
        )
        values = {
            "nested_numerator": nested,
            "nested_denominator_ns": int(request["nested_window_seconds"])
            * 1_000_000_000,
            "reference_numerator": reference,
            "reference_denominator_ns": int(request["reference_window_seconds"])
            * 1_000_000_000,
            "nested_classification": nested_classification,
            "reference_classification": "valid",
            "cap_hits": cap_hits,
            "stalled": nested == 0
            or reference == 0
            or "invalid_progress" in nested_classifications,
        }
        return {"request_id": str(request["request_id"]), "values": values}

    def _observe_tail_window(
        self, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        with self._lane_resources(1) as (
            topologies,
            lane_cgroups,
            paths,
            coordinator_affinity,
        ):
            result = self._lane_trial(
                request,
                reference_client=str(request["reference_client"]),
                lane=0,
                topology=topologies[0],
                lane_cgroups=lane_cgroups[0],
                path=paths[0],
                coordinator_affinity=coordinator_affinity,
                barrier=None,
                shared_epoch=None,
            )
        tail = _construct_tail_evidence(
            str(request["scenario"]),
            "tail",
            result["server_result"],
            result["client_result"],
        )
        if tail is None:
            raise QualificationError("native tail-window trial omitted tail evidence")
        scenario = str(request["scenario"])
        endpoint = (
            result["server_result"]
            if scenario == "small_payload_pps"
            else result["client_result"]
        )
        bins = self._window_endpoint_bins(endpoint, "tail_owner")
        cap_hits = sum(
            int(value[field])
            for value in (result["server_result"], result["client_result"])
            for field in (
                "work_cap_hits",
                "byte_cap_hits",
                "stream_cap_hits",
                "stream_id_cap_hits",
                "generator_starvation_events",
            )
        )
        prefixes = []
        for prefix in tail["prefixes"]:
            duration = int(prefix["duration_seconds"])
            selected_bins = bins[: duration * 10]
            if len(selected_bins) != duration * 10 or len(selected_bins) % 10:
                raise QualificationError(
                    "native tail-window prefix is not exact at 100 ms bin resolution"
                )
            bucket_size = len(selected_bins) // 10
            buckets = [
                selected_bins[index : index + bucket_size]
                for index in range(0, len(selected_bins), bucket_size)
            ]
            stalled = any(
                sum(item[0] for item in bucket) == 0
                and sum(item[1] for item in bucket) == 0
                for bucket in buckets
            )
            p99_ns = int(prefix["p99_ns"])
            prefixes.append(
                {
                    "duration_seconds": duration,
                    "eligible_operations": int(prefix["successful_operations"]),
                    "failed_or_censored_operations": int(
                        prefix["failed_operations"]
                    )
                    + int(prefix["censored_operations"]),
                    "p99_ns": p99_ns,
                    "validity_classification": (
                        "valid"
                        if not cap_hits and not stalled and p99_ns > 0
                        else "invalid_cap_or_stall"
                    ),
                    "capped_or_stalled": bool(cap_hits or stalled),
                }
            )
        return {
            "request_id": str(request["request_id"]),
            "values": {"prefixes": prefixes},
        }

    def observe(
        self,
        *,
        kind: str,
        stage: str,
        stage_plan_hash: str,
        requests: Sequence[Mapping[str, Any]],
    ) -> Sequence[Mapping[str, Any]]:
        del stage_plan_hash
        if kind == "client-headroom":
            return [self._observe_headroom(request) for request in requests]
        if kind == "worker-reuse":
            if stage == "screens":
                return self._observe_worker_screens(requests)
            if stage == "held_out":
                return self._observe_worker_parity(requests)
            raise QualificationError(f"unknown worker-reuse stage {stage!r}")
        if kind == "lane-interference":
            return [self._observe_lane(request) for request in requests]
        if kind == "window-qualification":
            return [self._observe_window(request) for request in requests]
        if kind == "tail-window":
            return [self._observe_tail_window(request) for request in requests]
        raise QualificationError(f"unknown qualification kind {kind!r}")


class SubprocessObservationSource:
    """Bounded canonical JSON protocol for a host-specific physical driver."""

    def __init__(self, executable: Path) -> None:
        self.executable = executable

    def observe(
        self,
        *,
        kind: str,
        stage: str,
        stage_plan_hash: str,
        requests: Sequence[Mapping[str, Any]],
    ) -> Sequence[Mapping[str, Any]]:
        request = canonical_bytes(
            {
                "schema_version": PLAN_SCHEMA_VERSION,
                "artifact_kind": kind,
                "stage": stage,
                "stage_plan_hash": stage_plan_hash,
                "requests": list(requests),
            }
        ) + b"\n"
        try:
            completed = subprocess.run(
                [str(self.executable)],
                input=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=DRIVER_TIMEOUT_SECONDS,
            )
        except FileNotFoundError as exc:
            raise PhysicalQualificationUnavailable(
                f"physical qualification driver is unavailable: {self.executable}"
            ) from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PhysicalQualificationUnavailable(
                f"physical qualification driver could not complete: {exc}"
            ) from exc
        if completed.returncode == 75:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise PhysicalQualificationUnavailable(
                detail or "physical qualification driver reported unavailable"
            )
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise QualificationError(
                f"physical qualification driver failed with exit {completed.returncode}: "
                f"{detail[:512]}"
            )
        if len(completed.stdout) > MAX_DRIVER_OUTPUT_BYTES:
            raise QualificationError("physical qualification driver output exceeds 64 MiB")
        try:
            document = loads_strict(completed.stdout)
        except Exception as exc:
            raise QualificationError(
                f"physical qualification driver output is not strict JSON: {exc}"
            ) from exc
        if canonical_bytes(document) + b"\n" != completed.stdout:
            raise QualificationError("physical qualification driver output is not canonical")
        required = {
            "schema_version",
            "artifact_kind",
            "stage",
            "stage_plan_hash",
            "observations",
        }
        if not isinstance(document, Mapping) or set(document) != required:
            raise QualificationError("physical qualification driver response fields are invalid")
        if (
            document["schema_version"] != DRIVER_SCHEMA_VERSION
            or document["artifact_kind"] != kind
            or document["stage"] != stage
            or document["stage_plan_hash"] != stage_plan_hash
        ):
            raise IdentityMismatchError("physical qualification driver response identity mismatch")
        observations = document["observations"]
        if not isinstance(observations, Sequence) or isinstance(
            observations, (str, bytes, bytearray)
        ):
            raise QualificationError("physical qualification observations must be an array")
        return observations


def _request(identity_hash: str, phase: str, **coordinates: Any) -> dict[str, Any]:
    body = {"phase": phase, **coordinates}
    identity = bytes.fromhex(identity_hash)
    canonical = canonical_bytes(body)
    return {
        "request_id": domain_hash(
            "qualification-observation-request",
            identity,
            canonical,
        ),
        "retry_request_id": domain_hash(
            "qualification-observation-request-retry",
            identity,
            canonical,
        ),
        **body,
    }


def _session_attempt_requests(
    requests: Sequence[Mapping[str, Any]], attempt: str
) -> list[dict[str, Any]]:
    if attempt == "primary":
        return [dict(request) for request in requests]
    if attempt != "retry":
        raise QualificationError(f"unknown qualification session attempt {attempt!r}")
    result = []
    for request in requests:
        request_id = request.get("request_id")
        retry_id = request.get("retry_request_id")
        if (
            not isinstance(request_id, str)
            or not request_id
            or not isinstance(retry_id, str)
            or not retry_id
            or request_id == retry_id
        ):
            raise QualificationError(
                "qualification request lacks one distinct preallocated retry mate"
            )
        retry = dict(request)
        retry["request_id"] = retry_id
        retry["primary_request_id"] = request_id
        retry["attempt_slot"] = "retry"
        retry["status"] = "active"
        result.append(retry)
    return result


def _stage_hash(
    kind: str, identity_hash: str, stage: str, requests: Sequence[Mapping[str, Any]]
) -> str:
    return domain_hash(
        "qualification-observation-stage",
        kind.encode("ascii"),
        bytes.fromhex(identity_hash),
        stage.encode("ascii"),
        canonical_bytes(list(requests)),
    )


def _chain_id(identity_hash: str, phase: str, **coordinates: Any) -> str:
    return domain_hash(
        "qualification-observation-chain",
        bytes.fromhex(identity_hash),
        phase.encode("ascii"),
        canonical_bytes(coordinates),
    )


def _balanced_orders(
    identity_hash: str,
    domain: Mapping[str, Any],
    blocks: int,
    treatments: Sequence[str],
) -> dict[int, tuple[str, ...]]:
    """Assign balanced Williams orders to identity-randomized block numbers."""

    rows = williams_rows(tuple(treatments))
    ranked = sorted(
        (
            domain_hash(
                "qualification-treatment-order",
                bytes.fromhex(identity_hash),
                canonical_bytes(domain),
                block.to_bytes(4, "big"),
            ),
            block,
        )
        for block in range(1, blocks + 1)
    )
    return {
        block: rows[ordinal % len(rows)]
        for ordinal, (_digest, block) in enumerate(ranked)
    }


def _worker_plans(spec: Any, identity_hash: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    screens: list[dict[str, Any]] = []
    held_out: list[dict[str, Any]] = []
    for adapter in spec.servers:
        for backend in spec.server_backends:
            for scenario in filter(worker_reuse_eligible_scenario, spec.scenarios):
                chain_id = _chain_id(
                    identity_hash,
                    "reset_screen",
                    adapter=adapter,
                    backend=backend,
                    scenario=scenario,
                )
                for cycle in range(1, 33):
                    screens.append(
                        _request(
                            identity_hash,
                            "reset_screen",
                            adapter=adapter,
                            backend=backend,
                            scenario=scenario,
                            chain_id=chain_id,
                            cycle=cycle,
                        )
                    )
            endurance_chain_id = _chain_id(
                identity_hash,
                "endurance",
                adapter=adapter,
                backend=backend,
            )
            for cycle in range(0, 1025):
                screens.append(
                    _request(
                        identity_hash,
                        "endurance",
                        adapter=adapter,
                        backend=backend,
                        chain_id=endurance_chain_id,
                        cycle=cycle,
                        scenario=WORKER_SENTINELS[(max(cycle, 1) - 1) % len(WORKER_SENTINELS)],
                    )
                )
            for sentinel in WORKER_SENTINELS:
                treatment_labels = tuple(
                    f"{mode}/{scenario_order}"
                    for mode in ("fresh", "reused")
                    for scenario_order in ("canonical", "reordered")
                )
                orders = _balanced_orders(
                    identity_hash,
                    {
                        "gate": "worker-reuse",
                        "adapter": adapter,
                        "backend": backend,
                        "sentinel": sentinel,
                    },
                    12,
                    treatment_labels,
                )
                for block in range(1, 13):
                    for label in orders[block]:
                        mode, scenario_order = label.split("/", 1)
                        sequence = (
                            WORKER_SENTINELS
                            if scenario_order == "canonical"
                            else tuple(reversed(WORKER_SENTINELS))
                        )
                        held_out.append(
                            _request(
                                identity_hash,
                                "reuse_parity",
                                adapter=adapter,
                                backend=backend,
                                sentinel=sentinel,
                                block=block,
                                mode=mode,
                                scenario_order=scenario_order,
                                scenario_sequence=list(sequence),
                                position=orders[block].index(label),
                            )
                        )
    return screens, held_out


def _headroom_screens(spec: Any, identity_hash: str) -> list[dict[str, Any]]:
    client_cores = int(
        spec.raw["treatment"]["resources"]["client_physical_cores"]
    )
    return [
        _request(
            identity_hash,
            "headroom_screen",
            server=server,
            backend=backend,
            scenario=scenario,
            duration_ms=500,
            client_cores=client_cores,
        )
        for server in spec.servers
        for backend in spec.server_backends
        for scenario in HEADROOM_SCENARIOS
    ]


def _headroom_held_out(
    spec: Any,
    identity_hash: str,
    selected: tuple[str, str, str],
) -> list[dict[str, Any]]:
    server, backend, scenario = selected
    client_cores = int(
        spec.raw["treatment"]["resources"]["client_physical_cores"]
    )
    return [
        _request(
            identity_hash,
            "headroom_held_out",
            server=server,
            backend=backend,
            scenario=scenario,
            block=block,
            client_cores=client_cores,
        )
        for block in range(1, 13)
    ]


def _lane_screens(spec: Any, identity_hash: str) -> list[dict[str, Any]]:
    return [
        _request(
            identity_hash,
            "lane_screen",
            server=server,
            backend=backend,
            scenario=scenario,
            duration_ms=500,
            lanes=1,
        )
        for server in spec.servers
        for backend in spec.server_backends
        for scenario in LANE_DIMENSIONS.values()
    ]


def _lane_held_out(
    identity_hash: str, selected: Mapping[str, tuple[str, str, str]]
) -> list[dict[str, Any]]:
    requests = []
    for dimension, (server, backend, scenario) in sorted(selected.items()):
        orders = _balanced_orders(
            identity_hash,
            {
                "gate": "lane-interference",
                "dimension": dimension,
                "server": server,
                "backend": backend,
                "scenario": scenario,
            },
            20,
            ("1", "2"),
        )
        for block in range(1, 21):
            treatment_hash = domain_hash(
                "qualification-lane-treatment",
                bytes.fromhex(identity_hash),
                canonical_bytes(
                    {
                        "dimension": dimension,
                        "server": server,
                        "backend": backend,
                        "scenario": scenario,
                        "block": block,
                    }
                ),
            )
            for lanes_text in orders[block]:
                lanes = int(lanes_text)
                requests.append(
                    _request(
                        identity_hash,
                        "lane_held_out",
                        dimension=dimension,
                        server=server,
                        backend=backend,
                        scenario=scenario,
                        block=block,
                        lanes=lanes,
                        treatment_hash=treatment_hash,
                        position=orders[block].index(lanes_text),
                    )
                )
    return requests


def _window_duration(spec: Any, scenario: str) -> tuple[int, int]:
    workload = next(item for item in spec.raw["workloads"] if item["scenario"] == scenario)
    measurement_ns = int(workload["measurement_ns"])
    if measurement_ns == 2_000_000_000:
        return 2, 10
    if measurement_ns == 5_000_000_000:
        return 5, 20
    raise QualificationError(
        f"window qualification has no frozen reference for {measurement_ns} ns"
    )


def _window_screens(spec: Any, identity_hash: str) -> list[dict[str, Any]]:
    requests = []
    for server in spec.servers:
        for backend in spec.server_backends:
            for scenario in spec.scenarios:
                short, reference = _window_duration(spec, scenario)
                requests.append(
                    _request(
                        identity_hash,
                        "window_screen",
                        server=server,
                        backend=backend,
                        scenario=scenario,
                        nested_window_seconds=short,
                        reference_window_seconds=reference,
                        duration_seconds=reference,
                    )
                )
    return requests


def _window_held_out(
    spec: Any,
    identity_hash: str,
    selected: Mapping[tuple[str, str], str],
) -> list[dict[str, Any]]:
    requests = []
    baseline = "ngtcp2perf"
    for (backend, scenario), selected_server in sorted(selected.items()):
        short, reference = _window_duration(spec, scenario)
        for server in sorted({baseline, selected_server}, key=spec.servers.index):
            for block in range(1, 21):
                requests.append(
                    _request(
                        identity_hash,
                        "window_held_out",
                        server=server,
                        backend=backend,
                        scenario=scenario,
                        block=block,
                        nested_window_seconds=short,
                        reference_window_seconds=reference,
                        duration_seconds=reference,
                    )
                )
    return requests


def _tail_window_plans(
    identity_hash: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    basis = bytes.fromhex(
        domain_hash(
            "tail-window-qualification-schedule",
            bytes.fromhex(identity_hash),
        )
    )
    plan = plan_tail_window_qualification(
        campaign_seed=bytes.fromhex(identity_hash),
        schedule_basis_hash=basis,
    )

    def primary_requests(trials: Sequence[Any]) -> list[dict[str, Any]]:
        retry_ids = {
            (
                trial.phase,
                trial.scenario,
                trial.server,
                trial.server_backend,
                trial.reference_client,
                trial.block,
            ): trial.trial_id
            for trial in trials
            if trial.slot == "retry"
        }
        requests = []
        for trial in trials:
            if trial.slot != "primary":
                continue
            key = (
                trial.phase,
                trial.scenario,
                trial.server,
                trial.server_backend,
                trial.reference_client,
                trial.block,
            )
            requests.append(
                {
                    "request_id": trial.trial_id,
                    "retry_request_id": retry_ids[key],
                    "phase": (
                        "tail_window_screen"
                        if trial.phase == "screening"
                        else "tail_window_held_out"
                    ),
                    "scenario": trial.scenario,
                    "server": trial.server,
                    "backend": trial.server_backend,
                    "reference_client": trial.reference_client,
                    "block": trial.block,
                    "duration_seconds": 20,
                    "duration_prefixes_seconds": list(
                        trial.duration_prefixes_seconds
                    ),
                    "execution_order": trial.execution_order,
                    "williams_row": trial.williams_row,
                    "server_position": trial.server_position,
                    "status": trial.status,
                }
            )
        return sorted(requests, key=lambda item: int(item["execution_order"]))

    return primary_requests(plan.screening), primary_requests(plan.held_out)


def _tail_prefix_inputs(
    values: Mapping[str, Any], label: str
) -> list[dict[str, Any]]:
    prefixes = values.get("prefixes")
    if not isinstance(prefixes, Sequence) or isinstance(
        prefixes, (str, bytes, bytearray)
    ):
        raise QualificationError(f"{label}.prefixes must be an array")
    result = []
    required = {
        "duration_seconds",
        "eligible_operations",
        "failed_or_censored_operations",
        "p99_ns",
        "validity_classification",
        "capped_or_stalled",
    }
    for index, prefix in enumerate(prefixes):
        if not isinstance(prefix, Mapping) or set(prefix) != required:
            raise QualificationError(f"{label}.prefixes[{index}] fields are invalid")
        duration = _nonnegative_int(
            prefix["duration_seconds"],
            f"{label}.prefixes[{index}].duration_seconds",
            positive=True,
        )
        if duration not in DURATION_LADDER_SECONDS:
            raise QualificationError(f"{label} duration is outside the frozen ladder")
        classification = prefix["validity_classification"]
        capped = prefix["capped_or_stalled"]
        if not isinstance(classification, str) or not classification:
            raise QualificationError(f"{label} validity classification is invalid")
        if not isinstance(capped, bool):
            raise QualificationError(f"{label} capped/stalled flag is invalid")
        result.append(
            {
                "duration_seconds": duration,
                "eligible_operations": _nonnegative_int(
                    prefix["eligible_operations"],
                    f"{label}.prefixes[{index}].eligible_operations",
                ),
                "failed_or_censored_operations": _nonnegative_int(
                    prefix["failed_or_censored_operations"],
                    f"{label}.prefixes[{index}].failed_or_censored_operations",
                ),
                "p99_ns": _nonnegative_int(
                    prefix["p99_ns"],
                    f"{label}.prefixes[{index}].p99_ns",
                    positive=True,
                ),
                "validity_classification": classification,
                "capped_or_stalled": capped,
            }
        )
    if len(result) != 4 or {item["duration_seconds"] for item in result} != set(
        DURATION_LADDER_SECONDS
    ):
        raise QualificationError(f"{label} must contain each frozen prefix exactly once")
    return sorted(result, key=lambda item: int(item["duration_seconds"]))


def _tail_screen_selection(
    requests: Sequence[Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
]:
    inputs = []
    records = []
    for request in requests:
        values = observations[str(request["request_id"])]
        prefixes = _tail_prefix_inputs(values, "tail_window_screen")
        record = {
            "scenario": str(request["scenario"]),
            "server": str(request["server"]),
            "server_backend": str(request["backend"]),
            "reference_client": str(request["reference_client"]),
            "prefixes": prefixes,
        }
        records.append(record)
        inputs.append(
            TailScreenCell(
                scenario=record["scenario"],
                server=record["server"],
                server_backend=record["server_backend"],
                reference_client=record["reference_client"],
                prefixes=tuple(TailPrefixObservation(**item) for item in prefixes),
            )
        )
    nominations, servers, reasons = screen_tail_window_qualification(inputs)
    return {
        "nominations": nominations,
        "servers": servers,
        "reasons": reasons,
    }, records


def _tail_activate_held_out(
    maximum: Sequence[Mapping[str, Any]], selection: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected = selection["servers"]
    active: list[dict[str, Any]] = []
    frozen: list[dict[str, Any]] = []
    for original in maximum:
        request = dict(original)
        key = (
            str(request["scenario"]),
            str(request["backend"]),
            str(request["reference_client"]),
        )
        chosen = set(selected.get(key, ()))
        request["status"] = (
            "active" if str(request["server"]) in chosen else "not_selected"
        )
        frozen.append(request)
        if request["status"] == "active":
            active.append(request)
    return active, frozen


def _tail_inputs(
    screen_inputs: Sequence[Mapping[str, Any]],
    requests: Sequence[Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    held = []
    for request in requests:
        held.append(
            {
                "scenario": str(request["scenario"]),
                "server": str(request["server"]),
                "server_backend": str(request["backend"]),
                "reference_client": str(request["reference_client"]),
                "block": int(request["block"]),
                "prefixes": _tail_prefix_inputs(
                    observations[str(request["request_id"])],
                    "tail_window_held_out",
                ),
            }
        )
    return {"screens": list(screen_inputs), "held_out": held}


def _decimal(value: Any, label: str, *, positive: bool = False) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise QualificationError(f"{label} must be an integer or canonical decimal string")
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise QualificationError(f"{label} must be numeric") from exc
    if not result.is_finite() or (positive and result <= 0):
        raise QualificationError(f"{label} must be finite{' and positive' if positive else ''}")
    if isinstance(value, str):
        normalize_decimal(value)
    return result


def _nonnegative_int(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise QualificationError(f"{label} must be an integer")
    if value < (1 if positive else 0):
        raise QualificationError(f"{label} must be {'positive' if positive else 'nonnegative'}")
    return value


def _normalize_values(request: Mapping[str, Any], values: Any) -> dict[str, Any]:
    phase = str(request["phase"])
    if not isinstance(values, Mapping):
        raise QualificationError(f"{phase} values must be an object")
    if phase == "lane_held_out":
        if set(values) != {"per_lane"}:
            raise QualificationError("lane_held_out observation fields are invalid")
        per_lane = values["per_lane"]
        if not isinstance(per_lane, Sequence) or isinstance(
            per_lane, (str, bytes, bytearray)
        ):
            raise QualificationError("lane_held_out.per_lane must be an array")
        lanes = int(request["lanes"])
        if len(per_lane) != lanes:
            raise QualificationError("lane_held_out per-lane cardinality mismatch")
        normalized_lanes = []
        for index, item in enumerate(per_lane):
            if not isinstance(item, Mapping) or set(item) != {
                "lane",
                "rate",
                "peak_memory_bytes",
                "treatment_hash",
            }:
                raise QualificationError("lane_held_out per-lane fields are invalid")
            lane = _nonnegative_int(item["lane"], "lane_held_out.lane")
            if lane != index:
                raise QualificationError("lane_held_out lane identities are not exact")
            if item["treatment_hash"] != request["treatment_hash"]:
                raise QualificationError("lane_held_out treatment identity mismatch")
            normalized_lanes.append(
                {
                    "lane": lane,
                    "rate": normalize_decimal(
                        _decimal(item["rate"], "lane_held_out.rate", positive=True)
                    ),
                    "peak_memory_bytes": _nonnegative_int(
                        item["peak_memory_bytes"],
                        "lane_held_out.peak_memory_bytes",
                    ),
                    "treatment_hash": str(item["treatment_hash"]),
                }
            )
        return {"per_lane": normalized_lanes}
    if phase in {"tail_window_screen", "tail_window_held_out"}:
        if set(values) != {"prefixes"}:
            raise QualificationError(f"{phase} observation fields are invalid")
        return {"prefixes": _tail_prefix_inputs(values, phase)}
    if phase in {"window_screen", "window_held_out"}:
        expected = {
            "nested_numerator",
            "nested_denominator_ns",
            "reference_numerator",
            "reference_denominator_ns",
            "nested_classification",
            "reference_classification",
            "cap_hits",
            "stalled",
        }
        if set(values) != expected:
            raise QualificationError(f"{phase} observation fields are invalid")
        result = {
            field: _nonnegative_int(
                values[field],
                f"{phase}.{field}",
                positive=field in {
                    "nested_numerator",
                    "nested_denominator_ns",
                    "reference_numerator",
                    "reference_denominator_ns",
                },
            )
            for field in {
                "nested_numerator",
                "nested_denominator_ns",
                "reference_numerator",
                "reference_denominator_ns",
                "cap_hits",
            }
        }
        if result["nested_denominator_ns"] != int(
            request["nested_window_seconds"]
        ) * 1_000_000_000 or result["reference_denominator_ns"] != int(
            request["reference_window_seconds"]
        ) * 1_000_000_000:
            raise QualificationError(f"{phase} nested/reference duration mismatch")
        for field in ("nested_classification", "reference_classification"):
            if not isinstance(values[field], str) or not values[field]:
                raise QualificationError(f"{phase}.{field} must be nonempty")
            result[field] = values[field]
        if not isinstance(values["stalled"], bool):
            raise QualificationError(f"{phase}.stalled must be boolean")
        result["stalled"] = values["stalled"]
        return result
    schemas: dict[str, tuple[set[str], set[str], set[str]]] = {
        "reset_screen": (
            {"live_connections", "live_streams", "live_tickets", "work_inventory"},
            set(),
            set(),
        ),
        "endurance": (
            {"fd_count", "memory_bytes", "live_connections", "live_streams", "live_tickets"},
            set(),
            set(),
        ),
        "reuse_parity": (set(), {"rate"}, set()),
        "headroom_screen": ({"client_cpu_ns", "wall_ns"}, set(), set()),
        "headroom_held_out": (
            {"client_cpu_ns", "wall_ns"},
            {"rate", "client_cpu_p95"},
            set(),
        ),
        "lane_screen": (
            {
                "server_cpu_ns",
                "client_cpu_ns",
                "udp_packets",
                "validated_units",
                "timer_wakeups",
                "wall_ns",
                "memory_bytes",
            },
            set(),
            set(),
        ),
    }
    integer_fields, decimal_fields, other_fields = schemas[phase]
    expected = integer_fields | decimal_fields | other_fields
    if set(values) != expected:
        raise QualificationError(f"{phase} observation fields are invalid")
    normalized: dict[str, Any] = {}
    for field in integer_fields:
        normalized[field] = _nonnegative_int(
            values[field], f"{phase}.{field}", positive=field == "wall_ns"
        )
    for field in decimal_fields:
        normalized[field] = normalize_decimal(
            _decimal(values[field], f"{phase}.{field}", positive=True)
        )
    if "classification" in other_fields:
        classification = values["classification"]
        if not isinstance(classification, str) or not classification:
            raise QualificationError(f"{phase}.classification must be nonempty")
        normalized["classification"] = classification
    if "stalled" in other_fields:
        if not isinstance(values["stalled"], bool):
            raise QualificationError(f"{phase}.stalled must be boolean")
        normalized["stalled"] = values["stalled"]
    return normalized


def _collect(
    source: QualificationObservationSource,
    *,
    kind: str,
    identity_hash: str,
    stage: str,
    requests: Sequence[Mapping[str, Any]],
) -> tuple[
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
    dict[str, str],
]:
    records: list[dict[str, Any]] = []
    stage_hashes: dict[str, str] = {}

    def fail(message: str) -> None:
        raise QualificationCollectionError(
            message,
            stage=stage,
            records=records,
            stage_hashes=stage_hashes,
        )

    attempt = (
        "retry"
        if requests and all(request.get("attempt_slot") == "retry" for request in requests)
        else "primary"
    )
    if requests and any(
        request.get("attempt_slot") == "retry" for request in requests
    ) != (attempt == "retry"):
        fail("qualification stage mixes primary and retry session requests")

    def collect_attempt() -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        stage_plan_hash = _stage_hash(kind, identity_hash, stage, requests)
        stage_hashes[attempt] = stage_plan_hash
        try:
            returned = source.observe(
                kind=kind,
                stage=stage,
                stage_plan_hash=stage_plan_hash,
                requests=requests,
            )
        except QualificationInfrastructureTransient as exc:
            raise QualificationInfrastructureTransient(
                exc.request_id,
                exc.reason,
                detail=exc.detail,
                stage=stage,
                records=records,
                stage_hashes=stage_hashes,
            ) from exc
        if not isinstance(returned, Sequence) or isinstance(
            returned, (str, bytes, bytearray)
        ):
            fail("physical observation source must return an array")
        expected = {
            str(item["request_id"]): item for item in requests
        }
        completed: dict[str, dict[str, Any]] = {}
        transients: dict[str, str] = {}
        returned_ids: set[str] = set()
        for index, item in enumerate(returned):
            if not isinstance(item, Mapping):
                fail(f"observation {index} fields are invalid")
            fields = set(item)
            if fields not in (
                {"request_id", "values"},
                {"request_id", "infrastructure_transient"},
            ):
                fail(f"observation {index} fields are invalid")
            request_id = item["request_id"]
            if not isinstance(request_id, str) or request_id not in expected:
                fail(f"unexpected observation request ID at index {index}")
            if request_id in returned_ids:
                fail(f"duplicate observation request ID {request_id}")
            returned_ids.add(request_id)
            original_id = str(
                expected[request_id].get("primary_request_id", request_id)
            )
            if "values" in item:
                try:
                    values = _normalize_values(
                        expected[request_id], item["values"]
                    )
                except QualificationError as exc:
                    fail(str(exc))
                completed[request_id] = values
                record = {
                    "request_id": request_id,
                    "attempt": attempt,
                    "status": "completed",
                    "values": values,
                }
            else:
                reason = item["infrastructure_transient"]
                if (
                    not isinstance(reason, str)
                    or reason not in INFRASTRUCTURE_TRANSIENT_REASONS
                ):
                    fail(
                        f"observation {request_id} reported an invalid "
                        "infrastructure transient"
                    )
                transients[request_id] = reason
                record = {
                    "request_id": request_id,
                    "attempt": attempt,
                    "status": "infrastructure_transient",
                    "reason": reason,
                }
            if original_id != request_id:
                record["primary_request_id"] = original_id
            records.append(record)
        missing = sorted(set(expected) - returned_ids)
        if missing:
            fail(
                f"physical observation set is missing {len(missing)} exact "
                "planned requests"
            )
        return completed, transients

    completed, transient = collect_attempt()
    records.sort(
        key=lambda item: (
            str(item.get("primary_request_id", item["request_id"])),
            item["attempt"],
        )
    )
    if transient:
        request_id = sorted(transient)[0]
        raise QualificationInfrastructureTransient(
            request_id,
            transient[request_id],
            stage=stage,
            records=records,
            stage_hashes=stage_hashes,
        )
    return completed, records, stage_hashes


def _logical_observation_count(records: Sequence[Mapping[str, Any]]) -> int:
    return len(
        {
            str(record.get("primary_request_id", record["request_id"]))
            for record in records
            if record.get("status") == "completed"
        }
    )


def _value(
    requests: Sequence[Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
    **coordinates: Any,
) -> Mapping[str, Any]:
    matches = [
        item
        for item in requests
        if all(item.get(field) == value for field, value in coordinates.items())
    ]
    if len(matches) != 1:
        raise QualificationError(f"internal observation coordinate is not unique: {coordinates}")
    return observations[str(matches[0]["request_id"])]


def _as_text(value: float | Decimal) -> str:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise QualificationError("derived qualification statistic is nonfinite")
        value = Decimal(str(value))
    return normalize_decimal(value)


def _logs(values: Sequence[Decimal]) -> list[float]:
    if not values or any(value <= 0 for value in values):
        raise QualificationError("qualification log statistic requires positive values")
    return [math.log(float(value)) for value in values]


def _sample_variance(values: Sequence[float]) -> float:
    if len(values) < 2:
        raise QualificationError("qualification variance requires paired observations")
    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / (len(values) - 1)


def _paired_interval(first: Sequence[Decimal], second: Sequence[Decimal]) -> tuple[str, str]:
    if len(first) != len(second) or len(first) not in _T_CRITICAL_90:
        raise QualificationError("qualification pairing has the wrong frozen block count")
    differences = [a - b for a, b in zip(_logs(first), _logs(second), strict=True)]
    mean = sum(differences) / len(differences)
    variance = _sample_variance(differences)
    half = float(_T_CRITICAL_90[len(first)]) * math.sqrt(variance / len(differences))
    return _as_text(math.exp(mean - half)), _as_text(math.exp(mean + half))


def _geometric_ratio(first: Sequence[Decimal], second: Sequence[Decimal]) -> str:
    differences = [a - b for a, b in zip(_logs(first), _logs(second), strict=True)]
    return _as_text(math.exp(sum(differences) / len(differences)))


def _ci_width(values: Sequence[Decimal]) -> str:
    logs = _logs(values)
    variance = _sample_variance(logs)
    half = float(_T_CRITICAL_90[len(values)]) * math.sqrt(variance / len(values))
    return _as_text(2 * half)


def _worker_inputs(
    spec: Any,
    screens: Sequence[Mapping[str, Any]],
    screen_values: Mapping[str, Mapping[str, Any]],
    held_out: Sequence[Mapping[str, Any]],
    held_values: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    reset_cycles = []
    endurance = []
    parity = []
    leaks = []
    for adapter in spec.servers:
        for backend in spec.server_backends:
            for scenario in filter(worker_reuse_eligible_scenario, spec.scenarios):
                for cycle in range(1, 33):
                    value = _value(
                        screens,
                        screen_values,
                        phase="reset_screen",
                        adapter=adapter,
                        backend=backend,
                        scenario=scenario,
                        cycle=cycle,
                    )
                    reset_cycles.append(
                        {
                            "adapter": adapter,
                            "backend": backend,
                            "scenario": scenario,
                            "cycle": cycle,
                            **value,
                        }
                    )
            baseline = _value(
                screens,
                screen_values,
                phase="endurance",
                adapter=adapter,
                backend=backend,
                cycle=0,
            )
            if any(
                baseline[field]
                for field in ("live_connections", "live_streams", "live_tickets")
            ):
                raise QualificationError("worker endurance baseline has live state")
            memory: list[Decimal] = []
            for cycle in range(1, 1025):
                value = _value(
                    screens,
                    screen_values,
                    phase="endurance",
                    adapter=adapter,
                    backend=backend,
                    cycle=cycle,
                )
                memory.append(Decimal(value["memory_bytes"]))
                if cycle % 32 == 0:
                    endurance.append(
                        {
                            "adapter": adapter,
                            "backend": backend,
                            "cycle": cycle,
                            "baseline_fd_count": baseline["fd_count"],
                            "fd_count": value["fd_count"],
                            "live_connections": value["live_connections"],
                            "live_streams": value["live_streams"],
                            "live_tickets": value["live_tickets"],
                            "baseline_memory_bytes": baseline["memory_bytes"],
                            "reset_memory_bytes": value["memory_bytes"],
                        }
                    )
            x_mean = Decimal("512.5")
            y_mean = sum(memory, Decimal(0)) / Decimal(len(memory))
            sxx = sum((Decimal(index) - x_mean) ** 2 for index in range(1, 1025))
            slope = sum(
                (Decimal(index) - x_mean) * (value - y_mean)
                for index, value in enumerate(memory, 1)
            ) / sxx
            intercept = y_mean - slope * x_mean
            residual = sum(
                (value - intercept - slope * Decimal(index)) ** 2
                for index, value in enumerate(memory, 1)
            )
            standard_error = (residual / Decimal(1022) / sxx).sqrt()
            critical = Decimal("1.646")
            leaks.append(
                {
                    "adapter": adapter,
                    "backend": backend,
                    "baseline_memory_bytes": baseline["memory_bytes"],
                    "interval_low_bytes_per_cycle": normalize_decimal(slope - critical * standard_error),
                    "interval_high_bytes_per_cycle": normalize_decimal(slope + critical * standard_error),
                    "confidence_level": "0.9",
                }
            )
            for sentinel in WORKER_SENTINELS:
                fresh = []
                reused = []
                canonical_estimates = []
                reordered_estimates = []
                for block in range(1, 13):
                    rates = {
                        (mode, scenario_order): Decimal(
                            _value(
                                held_out,
                                held_values,
                                phase="reuse_parity",
                                adapter=adapter,
                                backend=backend,
                                sentinel=sentinel,
                                block=block,
                                mode=mode,
                                scenario_order=scenario_order,
                            )["rate"]
                        )
                        for mode in ("fresh", "reused")
                        for scenario_order in ("canonical", "reordered")
                    }
                    fresh.append(
                        (rates[("fresh", "canonical")] * rates[("fresh", "reordered")]).sqrt()
                    )
                    reused.append(
                        (rates[("reused", "canonical")] * rates[("reused", "reordered")]).sqrt()
                    )
                    canonical_estimates.append(
                        (rates[("fresh", "canonical")] * rates[("reused", "canonical")]).sqrt()
                    )
                    reordered_estimates.append(
                        (rates[("fresh", "reordered")] * rates[("reused", "reordered")]).sqrt()
                    )
                low, high = _paired_interval(reused, fresh)
                parity.append(
                    {
                        "adapter": adapter,
                        "backend": backend,
                        "sentinel": sentinel,
                        "paired_blocks": 12,
                        "interval_low_ratio": low,
                        "interval_high_ratio": high,
                        "reordered_ratio": _geometric_ratio(
                            reordered_estimates, canonical_estimates
                        ),
                        "confidence_level": "0.9",
                    }
                )
    return {
        "reset_cycles": reset_cycles,
        "endurance_checkpoints": endurance,
        "parity": parity,
        "leak_slopes": leaks,
    }


def _headroom_selection(
    spec: Any,
    requests: Sequence[Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
) -> tuple[tuple[str, str, str], list[dict[str, Any]]]:
    rank = {
        (server, backend, scenario): ordinal
        for ordinal, (server, backend, scenario) in enumerate(
            (s, b, c)
            for s in spec.servers
            for b in spec.server_backends
            for c in HEADROOM_SCENARIOS
        )
    }
    scored = []
    screens = []
    for request in requests:
        value = observations[str(request["request_id"])]
        pressure = Decimal(value["client_cpu_ns"]) / Decimal(value["wall_ns"])
        key = (request["server"], request["backend"], request["scenario"])
        scored.append((pressure, -rank[key], key))
        screens.append(
            {
                "server": key[0],
                "backend": key[1],
                "scenario": key[2],
                "client_cpu_ns_per_wall_ns": normalize_decimal(pressure),
            }
        )
    return max(scored)[2], screens


def _headroom_inputs(
    spec: Any,
    selected: tuple[str, str, str],
    screens: Sequence[Mapping[str, Any]],
    requests: Sequence[Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    treatment_cores = int(
        spec.raw["treatment"]["resources"]["client_physical_cores"]
    )
    treatment_p95 = []
    for block in range(1, 13):
        value = _value(
            requests,
            observations,
            phase="headroom_held_out",
            block=block,
            client_cores=treatment_cores,
        )
        treatment_p95.append(str(value["client_cpu_p95"]))
    return {
        "screens": list(screens),
        "held_out": {
            "server": selected[0],
            "backend": selected[1],
            "scenario": selected[2],
            "blocks": 12,
            "treatment_client_cores": treatment_cores,
            "treatment_p95_cpu": treatment_p95,
        },
    }


def _lane_pressure(scenario: str, value: Mapping[str, Any]) -> Decimal:
    wall = Decimal(value["wall_ns"])
    if scenario == "reqresp":
        return Decimal(value["server_cpu_ns"] + value["client_cpu_ns"]) / wall
    if scenario == "datagram":
        return Decimal(value["udp_packets"]) * Decimal(1_000_000_000) / wall
    if scenario == "multistream_download":
        return Decimal(value["validated_units"]) * Decimal(1_000_000_000) / wall
    if scenario == "loss_recovery":
        return Decimal(value["timer_wakeups"]) * Decimal(1_000_000_000) / wall
    raise QualificationError(f"unknown lane screen scenario {scenario!r}")


def _lane_selection(
    spec: Any,
    requests: Sequence[Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, tuple[str, str, str]], list[dict[str, Any]]]:
    rank = {
        (server, backend): ordinal
        for ordinal, (server, backend) in enumerate(
            (s, b) for s in spec.servers for b in spec.server_backends
        )
    }
    screens = []
    by_scenario: dict[str, list[tuple[Decimal, int, tuple[str, str, str]]]] = {}
    for request in requests:
        value = observations[str(request["request_id"])]
        scenario = str(request["scenario"])
        pressure = _lane_pressure(scenario, value)
        key = (str(request["server"]), str(request["backend"]), scenario)
        by_scenario.setdefault(scenario, []).append((pressure, -rank[key[:2]], key))
        screens.append(
            {
                "server": key[0],
                "backend": key[1],
                "scenario": key[2],
                "pressure": normalize_decimal(pressure),
            }
        )
    selected = {
        dimension: max(by_scenario[scenario])[2]
        for dimension, scenario in LANE_DIMENSIONS.items()
    }
    return selected, screens


def _lane_inputs(
    selected: Mapping[str, tuple[str, str, str]],
    screens: Sequence[Mapping[str, Any]],
    requests: Sequence[Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    held = []
    for dimension, cell in sorted(selected.items()):
        rates: dict[int, list[Decimal]] = {1: [], 2: []}
        memory: dict[int, list[Decimal]] = {1: [], 2: []}
        for block in range(1, 21):
            for lanes in (1, 2):
                value = _value(
                    requests,
                    observations,
                    phase="lane_held_out",
                    dimension=dimension,
                    block=block,
                    lanes=lanes,
                )
                per_lane = value["per_lane"]
                lane_rates = [Decimal(item["rate"]) for item in per_lane]
                lane_memory = [
                    Decimal(item["peak_memory_bytes"]) for item in per_lane
                ]
                rates[lanes].append(
                    Decimal(str(math.exp(sum(_logs(lane_rates)) / len(lane_rates))))
                )
                memory[lanes].append(
                    sum(lane_memory, Decimal(0)) / Decimal(len(lane_memory))
                )
        rate_low, rate_high = _paired_interval(rates[2], rates[1])
        memory_low, memory_high = _paired_interval(memory[2], memory[1])
        held.append(
            {
                "dimension": dimension,
                "server": cell[0],
                "backend": cell[1],
                "scenario": cell[2],
                "paired_blocks": 20,
                "rate_interval_low_ratio": rate_low,
                "rate_interval_high_ratio": rate_high,
                "memory_interval_low_ratio": memory_low,
                "memory_interval_high_ratio": memory_high,
                "one_lane_variance": _as_text(_sample_variance(_logs(rates[1]))),
                "two_lane_variance": _as_text(_sample_variance(_logs(rates[2]))),
                "one_lane_ci_width": _ci_width(rates[1]),
                "two_lane_ci_width": _ci_width(rates[2]),
                "confidence_level": "0.9",
            }
        )
    return {"screens": list(screens), "held_out": held}


def _window_selection(
    spec: Any,
    requests: Sequence[Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[tuple[str, str], str], list[dict[str, Any]]]:
    rank = {server: ordinal for ordinal, server in enumerate(spec.servers)}
    screens = []
    scored: dict[tuple[str, str], list[tuple[Decimal, int, str]]] = {}
    for server in spec.servers:
        for backend in spec.server_backends:
            for scenario in spec.scenarios:
                value = _value(
                    requests,
                    observations,
                    phase="window_screen",
                    server=server,
                    backend=backend,
                    scenario=scenario,
                )
                short_rate = (
                    Decimal(value["nested_numerator"])
                    * Decimal(1_000_000_000)
                    / Decimal(value["nested_denominator_ns"])
                )
                reference_rate = (
                    Decimal(value["reference_numerator"])
                    * Decimal(1_000_000_000)
                    / Decimal(value["reference_denominator_ns"])
                )
                scored.setdefault((backend, scenario), []).append(
                    ((short_rate / reference_rate).ln().copy_abs(), -rank[server], server)
                )
                short_seconds, reference_seconds = _window_duration(spec, scenario)
                screens.append(
                    {
                        "server": server,
                        "backend": backend,
                        "scenario": scenario,
                        "short_rate": normalize_decimal(short_rate),
                        "reference_rate": normalize_decimal(reference_rate),
                        "short_classification": value["nested_classification"],
                        "reference_classification": value["reference_classification"],
                        "cap_hit": bool(value["cap_hits"]),
                        "stalled": bool(value["stalled"]),
                        "short_window_seconds": short_seconds,
                        "reference_window_seconds": reference_seconds,
                    }
                )
    selected = {stratum: max(values)[2] for stratum, values in scored.items()}
    return selected, screens


def _window_inputs(
    spec: Any,
    selected: Mapping[tuple[str, str], str],
    screens: Sequence[Mapping[str, Any]],
    requests: Sequence[Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    baseline = "ngtcp2perf"
    held = []
    contrasts = []
    for (backend, scenario), selected_server in sorted(selected.items()):
        server_rates: dict[str, dict[str, list[Decimal]]] = {}
        for server in sorted({baseline, selected_server}, key=spec.servers.index):
            short_rates = []
            reference_rates = []
            classifications = []
            for block in range(1, 21):
                value = _value(
                    requests,
                    observations,
                    phase="window_held_out",
                    server=server,
                    backend=backend,
                    scenario=scenario,
                    block=block,
                )
                short_rates.append(
                    Decimal(value["nested_numerator"])
                    * Decimal(1_000_000_000)
                    / Decimal(value["nested_denominator_ns"])
                )
                reference_rates.append(
                    Decimal(value["reference_numerator"])
                    * Decimal(1_000_000_000)
                    / Decimal(value["reference_denominator_ns"])
                )
                short_classification = str(value["nested_classification"])
                reference_classification = str(value["reference_classification"])
                if value["cap_hits"] or value["stalled"]:
                    short_classification = "invalid_short_window"
                    reference_classification = "invalid_reference_window"
                classifications.append(
                    [short_classification, reference_classification]
                )
            low, high = _paired_interval(short_rates, reference_rates)
            held.append(
                {
                    "server": server,
                    "backend": backend,
                    "scenario": scenario,
                    "paired_blocks": 20,
                    "interval_low_ratio": low,
                    "interval_high_ratio": high,
                    "short_log_variance": _as_text(_sample_variance(_logs(short_rates))),
                    "reference_log_variance": _as_text(
                        _sample_variance(_logs(reference_rates))
                    ),
                    "classifications": classifications,
                    "confidence_level": "0.9",
                }
            )
            server_rates[server] = {
                "short": short_rates,
                "reference": reference_rates,
            }
        if selected_server != baseline:
            selected_contrast = [
                selected_short / baseline_short
                for selected_short, baseline_short in zip(
                    server_rates[selected_server]["short"],
                    server_rates[baseline]["short"],
                    strict=True,
                )
            ]
            reference_contrast = [
                selected_reference / baseline_reference
                for selected_reference, baseline_reference in zip(
                    server_rates[selected_server]["reference"],
                    server_rates[baseline]["reference"],
                    strict=True,
                )
            ]
            low, high = _paired_interval(selected_contrast, reference_contrast)
            contrasts.append(
                {
                    "backend": backend,
                    "scenario": scenario,
                    "selected_server": selected_server,
                    "baseline_server": baseline,
                    "paired_blocks": 20,
                    "interval_low_ratio": low,
                    "interval_high_ratio": high,
                    "confidence_level": "0.9",
                }
            )
    return {"screens": list(screens), "held_out": held, "contrasts": contrasts}


def _initial_plan(kind: str, spec: Any, identity_hash: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if kind == "worker-reuse":
        return _worker_plans(spec, identity_hash)
    if kind == "client-headroom":
        return _headroom_screens(spec, identity_hash), []
    if kind == "lane-interference":
        return _lane_screens(spec, identity_hash), []
    if kind == "window-qualification":
        return _window_screens(spec, identity_hash), []
    if kind == "tail-window":
        return _tail_window_plans(identity_hash)
    raise QualificationError(f"unknown qualification kind {kind!r}")


def _selection_document(kind: str, selection: Any) -> Any:
    if selection is None:
        return None
    if kind == "client-headroom":
        return list(selection)
    if kind == "lane-interference":
        return {name: list(cell) for name, cell in sorted(selection.items())}
    if kind == "window-qualification":
        return {
            f"{backend}/{scenario}": server
            for (backend, scenario), server in sorted(selection.items())
        }
    if kind == "tail-window":
        return {
            "nominations_seconds": dict(sorted(selection["nominations"].items())),
            "selected_servers": {
                f"{scenario}/{backend}/{client}": list(servers)
                for (scenario, backend, client), servers in sorted(
                    selection["servers"].items()
                )
            },
            "screening_reasons": list(selection["reasons"]),
        }
    return selection


def _completed_artifact(
    *,
    journal: Journal,
    campaign_id: str,
    kind: str,
    identity: Mapping[str, Any],
    decision: QualificationDecision,
    artifact_store: Path,
    run_content: bytes,
) -> tuple[str, str, str]:
    stored = QualificationArtifactStore(artifact_store).store(kind, identity, decision)
    decision_content, artifact_hash, identity_hash = encode_qualification_artifact(
        kind, identity, decision
    )
    if (artifact_hash, identity_hash) != (stored.artifact_hash, stored.identity_hash):
        raise QualificationError("stored qualification decision changed during production")
    existing = journal.connection.execute(
        "SELECT content FROM artifact WHERE campaign_id=? AND path=?",
        (campaign_id, f"qualification/{kind}.json"),
    ).fetchone()
    if existing is not None and bytes(existing["content"]) != decision_content:
        raise IdentityMismatchError(
            f"journal {kind} qualification is already bound to different artifact bytes"
        )
    run_sha = hashlib.sha256(run_content).hexdigest()
    run_path = f"qualification-runs/{kind}/{run_sha}.json"
    journal.store_artifacts(
        campaign_id,
        {
            run_path: (run_content, "application/json"),
            f"qualification/{kind}.json": (decision_content, "application/json"),
        }
    )
    return artifact_hash, str(stored.path), run_path


def _store_not_run(
    journal: Journal, campaign_id: str, kind: str, document: Mapping[str, Any]
) -> str:
    content = canonical_bytes(document) + b"\n"
    digest = hashlib.sha256(content).hexdigest()
    path = f"qualification-runs/{kind}/{digest}.json"
    journal.store_artifact(campaign_id, path, content, media_type="application/json")
    return path


def run_qualification(
    *,
    run_dir: Path,
    kind: str,
    artifact_store: Path,
    observation_source: QualificationObservationSource | None = None,
) -> dict[str, Any]:
    """Produce one exact-identity qualification from raw physical observations."""

    if kind == "host-stability":
        return _run_host_stability_qualification(
            run_dir=run_dir,
            artifact_store=artifact_store,
        )

    with Journal(run_dir) as journal:
        spec, manifest, _schedule = _persisted_run_identity(journal, run_dir)
        campaign = journal.connection.execute(
            "SELECT campaign_id FROM campaign"
        ).fetchone()
        if campaign is None:
            raise IdentityMismatchError("run journal has no campaign")
        campaign_id = str(campaign["campaign_id"])
        identity = build_qualification_identity(kind, spec, manifest)
        identity_hash = qualification_identity_hash(kind, identity)
        samples_before = int(
            journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0]
        )
        screens, initial_held_out = _initial_plan(kind, spec, identity_hash)
        held_out = list(initial_held_out)
        maximum_held_out: list[dict[str, Any]] | None = (
            list(initial_held_out) if kind == "tail-window" else None
        )
        selection: Any = None
        screen_records: list[dict[str, Any]] = []
        held_records: list[dict[str, Any]] = []
        stage_hashes: dict[str, dict[str, str]] = {}
        host_session_evidence: Mapping[str, Any] | None = None
        inputs: Mapping[str, Any] | None = None
        decision: QualificationDecision | None = None
        not_run_reason: str | None = None
        session_attempts: list[dict[str, Any]] = []
        amd_context = (
            _load_host_stability_context(journal, campaign_id, spec, manifest)
            if observation_source is None
            else None
        )

        for attempt in ("primary", "retry"):
            attempt_screens = _session_attempt_requests(screens, attempt)
            attempt_held_out: list[dict[str, Any]] = []
            attempt_screen_records: list[dict[str, Any]] = []
            attempt_held_records: list[dict[str, Any]] = []
            attempt_stage_hashes: dict[str, dict[str, str]] = {}
            attempt_selection: Any = None
            attempt_host_evidence: Mapping[str, Any] | None = None
            native_source: NativeSessionObservationSource | None = None
            source = observation_source
            if source is None:
                native_source = NativeSessionObservationSource(
                    root=Path(__file__).resolve().parents[1],
                    run_dir=run_dir,
                    campaign_id=campaign_id,
                    spec=spec,
                    manifest=manifest,
                    amd_context=amd_context,
                )
                source = native_source
            stage_suffix = "" if attempt == "primary" else "_retry"
            try:
                if native_source is not None:
                    native_source.start_host_stability()
                screen_values, attempt_screen_records, screen_hashes = _collect(
                    source,
                    kind=kind,
                    identity_hash=identity_hash,
                    stage=f"screens{stage_suffix}",
                    requests=attempt_screens,
                )
                attempt_stage_hashes["screens"] = screen_hashes
                if kind == "worker-reuse":
                    attempt_selection = None
                    held_out = list(initial_held_out)
                    screen_inputs = None
                elif kind == "client-headroom":
                    attempt_selection, screen_inputs = _headroom_selection(
                        spec, attempt_screens, screen_values
                    )
                    held_out = _headroom_held_out(
                        spec,
                        identity_hash,
                        attempt_selection,
                    )
                elif kind == "lane-interference":
                    attempt_selection, screen_inputs = _lane_selection(
                        spec, attempt_screens, screen_values
                    )
                    held_out = _lane_held_out(identity_hash, attempt_selection)
                elif kind == "window-qualification":
                    attempt_selection, screen_inputs = _window_selection(
                        spec, attempt_screens, screen_values
                    )
                    held_out = _window_held_out(
                        spec, identity_hash, attempt_selection
                    )
                else:
                    attempt_selection, screen_inputs = _tail_screen_selection(
                        attempt_screens, screen_values
                    )
                    held_out, maximum_held_out = _tail_activate_held_out(
                        initial_held_out, attempt_selection
                    )
                attempt_held_out = _session_attempt_requests(held_out, attempt)
                held_values, attempt_held_records, held_hashes = _collect(
                    source,
                    kind=kind,
                    identity_hash=identity_hash,
                    stage=f"held_out{stage_suffix}",
                    requests=attempt_held_out,
                )
                attempt_stage_hashes["held_out"] = held_hashes
                if native_source is not None:
                    attempt_host_evidence = native_source.finish_host_stability()
                if kind == "worker-reuse":
                    attempt_inputs = _worker_inputs(
                        spec,
                        attempt_screens,
                        screen_values,
                        attempt_held_out,
                        held_values,
                    )
                elif kind == "client-headroom":
                    attempt_inputs = _headroom_inputs(
                        spec,
                        attempt_selection,
                        screen_inputs,
                        attempt_held_out,
                        held_values,
                    )
                elif kind == "lane-interference":
                    attempt_inputs = _lane_inputs(
                        attempt_selection,
                        screen_inputs,
                        attempt_held_out,
                        held_values,
                    )
                elif kind == "window-qualification":
                    attempt_inputs = _window_inputs(
                        spec,
                        attempt_selection,
                        screen_inputs,
                        attempt_held_out,
                        held_values,
                    )
                else:
                    attempt_inputs = _tail_inputs(
                        screen_inputs, attempt_held_out, held_values
                    )
                decision = evaluate_qualification_inputs(kind, attempt_inputs, spec)
                session_attempts.append(
                    {
                        "attempt": attempt,
                        "status": "completed",
                        "stage_plan_hashes": attempt_stage_hashes,
                        "screen_request_count": len(attempt_screens),
                        "held_out_request_count": len(attempt_held_out),
                        "observations": {
                            "screens": attempt_screen_records,
                            "held_out": attempt_held_records,
                        },
                        "host_stability": attempt_host_evidence,
                    }
                )
                selection = attempt_selection
                screen_records = attempt_screen_records
                held_records = attempt_held_records
                stage_hashes = attempt_stage_hashes
                host_session_evidence = attempt_host_evidence
                inputs = attempt_inputs
                break
            except QualificationInfrastructureTransient as exc:
                if exc.stage == f"screens{stage_suffix}":
                    attempt_screen_records = list(exc.records)
                    attempt_stage_hashes["screens"] = exc.stage_hashes
                elif exc.stage == f"held_out{stage_suffix}":
                    attempt_held_records = list(exc.records)
                    attempt_stage_hashes["held_out"] = exc.stage_hashes
                if native_source is not None:
                    if native_source.amd_evidence is not None:
                        attempt_host_evidence = dict(native_source.amd_evidence)
                    native_source.abort_host_stability()
                session_attempts.append(
                    {
                        "attempt": attempt,
                        "status": "infrastructure_transient",
                        "stage_plan_hashes": attempt_stage_hashes,
                        "screen_request_count": len(attempt_screens),
                        "held_out_request_count": len(attempt_held_out),
                        "observations": {
                            "screens": attempt_screen_records,
                            "held_out": attempt_held_records,
                        },
                        "host_stability": attempt_host_evidence,
                        "transient": {
                            "request_id": exc.request_id,
                            "reason": exc.reason,
                            **({"detail": exc.detail} if exc.detail else {}),
                        },
                    }
                )
                if attempt == "primary":
                    continue
                selection = attempt_selection
                screen_records = attempt_screen_records
                held_records = attempt_held_records
                stage_hashes = attempt_stage_hashes
                host_session_evidence = attempt_host_evidence
                inputs = None
                decision = QualificationDecision(
                    kind,
                    "not_qualified",
                    (
                        "hardware_unqualified:"
                        "preallocated_complete_session_replay_exhausted:"
                        f"{exc.reason}",
                    ),
                    {
                        "physical_observation_validation": "failed",
                        "hardware_status": "hardware_unqualified",
                        "session_replay": "exhausted",
                    },
                )
                break
            except PhysicalQualificationUnavailable as exc:
                if native_source is not None:
                    native_source.abort_host_stability()
                reason = str(exc) or "physical qualification is unavailable"
                session_attempts.append(
                    {
                        "attempt": attempt,
                        "status": "not_run",
                        "stage_plan_hashes": attempt_stage_hashes,
                        "screen_request_count": len(attempt_screens),
                        "held_out_request_count": len(attempt_held_out),
                        "observations": {
                            "screens": attempt_screen_records,
                            "held_out": attempt_held_records,
                        },
                        "host_stability": attempt_host_evidence,
                        "reason": reason,
                    }
                )
                selection = attempt_selection
                screen_records = attempt_screen_records
                held_records = attempt_held_records
                stage_hashes = attempt_stage_hashes
                host_session_evidence = attempt_host_evidence
                not_run_reason = reason
                break
            except QualificationError as exc:
                if isinstance(exc, QualificationCollectionError):
                    if exc.stage == f"screens{stage_suffix}":
                        attempt_screen_records = list(exc.records)
                        attempt_stage_hashes["screens"] = exc.stage_hashes
                    elif exc.stage == f"held_out{stage_suffix}":
                        attempt_held_records = list(exc.records)
                        attempt_stage_hashes["held_out"] = exc.stage_hashes
                if native_source is not None:
                    native_source.abort_host_stability()
                session_attempts.append(
                    {
                        "attempt": attempt,
                        "status": "invalid",
                        "stage_plan_hashes": attempt_stage_hashes,
                        "screen_request_count": len(attempt_screens),
                        "held_out_request_count": len(attempt_held_out),
                        "observations": {
                            "screens": attempt_screen_records,
                            "held_out": attempt_held_records,
                        },
                        "host_stability": attempt_host_evidence,
                        "reason": str(exc),
                    }
                )
                selection = attempt_selection
                screen_records = attempt_screen_records
                held_records = attempt_held_records
                stage_hashes = attempt_stage_hashes
                host_session_evidence = attempt_host_evidence
                inputs = None
                decision = QualificationDecision(
                    kind,
                    "not_qualified",
                    (f"physical_observation_invalid:{exc}",),
                    {"physical_observation_validation": "failed"},
                )
                break

        if decision is None and not_run_reason is None:
            raise QualificationError("qualification session produced no terminal decision")

        if not_run_reason is not None:
            reason = not_run_reason
            plan = {
                "schema_version": PLAN_SCHEMA_VERSION,
                "artifact_kind": kind,
                "identity_hash": identity_hash,
                "screen_requests": screens,
                "selection": _selection_document(kind, selection),
                "held_out_requests": held_out,
            }
            if maximum_held_out is not None:
                plan["maximum_held_out_requests"] = maximum_held_out
            plan_hash = domain_hash("qualification-plan", canonical_bytes(plan))
            document = {
                "schema_version": RUN_SCHEMA_VERSION,
                "artifact_kind": kind,
                "identity_hash": identity_hash,
                "plan_hash": plan_hash,
                "status": "not_run",
                "reasons": [reason],
                "plan": plan,
                "stage_plan_hashes": stage_hashes,
                "observations": {
                    "screens": screen_records,
                    "held_out": held_records,
                },
                "session_attempts": session_attempts,
                "host_stability": host_session_evidence,
                "derived_inputs": None,
            }
            run_path = _store_not_run(journal, campaign_id, kind, document)
            journal.integrity_check()
            return {
                "schema_version": COMMAND_SCHEMA_VERSION,
                "operation": "run",
                "artifact_kind": kind,
                "status": "not_run",
                "qualified": False,
                "reasons": [reason],
                "identity_hash": identity_hash,
                "artifact_hash": None,
                "artifact_path": None,
                "journal_path": run_path,
                "plan_hash": plan_hash,
                "screen_observations": _logical_observation_count(screen_records),
                "held_out_observations": _logical_observation_count(held_records),
                "screen_attempt_records": len(screen_records),
                "held_out_attempt_records": len(held_records),
                "session_attempt_records": len(session_attempts),
                "sample_rows_added": 0,
            }
        plan = {
            "schema_version": PLAN_SCHEMA_VERSION,
            "artifact_kind": kind,
            "identity_hash": identity_hash,
            "screen_requests": screens,
            "selection": _selection_document(kind, selection),
            "held_out_requests": held_out,
        }
        if maximum_held_out is not None:
            plan["maximum_held_out_requests"] = maximum_held_out
        plan_hash = domain_hash("qualification-plan", canonical_bytes(plan))
        run_document = {
            "schema_version": RUN_SCHEMA_VERSION,
            "artifact_kind": kind,
            "identity_hash": identity_hash,
            "plan_hash": plan_hash,
            "status": decision.status,
            "reasons": list(decision.reasons),
            "plan": plan,
            "stage_plan_hashes": stage_hashes,
            "observations": {"screens": screen_records, "held_out": held_records},
            "session_attempts": session_attempts,
            "host_stability": host_session_evidence,
            "derived_inputs": inputs,
        }
        run_content = canonical_bytes(run_document) + b"\n"
        run_sha = hashlib.sha256(run_content).hexdigest()
        decision = replace(
            decision,
            evidence={
                "evaluation": decision.evidence,
                "plan_hash": plan_hash,
                "observation_artifact_sha256": run_sha,
                "screen_observations": _logical_observation_count(screen_records),
                "held_out_observations": _logical_observation_count(held_records),
                "screen_attempt_records": len(screen_records),
                "held_out_attempt_records": len(held_records),
                "session_attempt_records": len(session_attempts),
            },
        )
        artifact_hash, artifact_path, run_path = _completed_artifact(
            journal=journal,
            campaign_id=campaign_id,
            kind=kind,
            identity=identity,
            decision=decision,
            artifact_store=artifact_store,
            run_content=run_content,
        )
        samples_after = int(
            journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0]
        )
        if samples_after != samples_before:
            raise QualificationError("qualification execution changed benchmark samples")
        journal.integrity_check()
    return {
        "schema_version": COMMAND_SCHEMA_VERSION,
        "operation": "run",
        "artifact_kind": kind,
        "status": decision.status,
        "qualified": decision.qualified,
        "reasons": list(decision.reasons),
        "identity_hash": identity_hash,
        "artifact_hash": artifact_hash,
        "artifact_path": artifact_path,
        "journal_path": run_path,
        "plan_hash": plan_hash,
        "screen_observations": _logical_observation_count(screen_records),
        "held_out_observations": _logical_observation_count(held_records),
        "screen_attempt_records": len(screen_records),
        "held_out_attempt_records": len(held_records),
        "session_attempt_records": len(session_attempts),
        "sample_rows_added": 0,
    }


def _run_host_stability_qualification(
    *,
    run_dir: Path,
    artifact_store: Path,
) -> dict[str, Any]:
    kind = "host-stability"
    with Journal(run_dir) as journal:
        spec, manifest, _schedule = _persisted_run_identity(journal, run_dir)
        campaign = journal.connection.execute(
            "SELECT campaign_id FROM campaign"
        ).fetchone()
        if campaign is None:
            raise IdentityMismatchError("run journal has no campaign")
        campaign_id = str(campaign["campaign_id"])
        identity = build_qualification_identity(kind, spec, manifest)
        identity_hash = qualification_identity_hash(kind, identity)
        samples_before = int(
            journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0]
        )
        layout = tuple(manifest.host_policy["lane_layout"])
        measurement_cpus = tuple(
            sorted(
                {
                    int(cpu)
                    for lane in layout
                    for cpu in (int(lane["server_cpu"]), *map(int, lane["client_cpus"]))
                }
            )
        )
        housekeeping = tuple(
            sorted(
                {
                    int(cpu)
                    for lane in layout
                    for cpu in lane["housekeeping_cpus"]
                }
            )
        )
        if not measurement_cpus or not housekeeping or set(measurement_cpus) & set(housekeeping):
            raise QualificationError("host-stability lane CPU ownership is invalid")
        try:
            monitor_cpu = int(irq_policy_identity()["boot"]["monitor_cpu"])
        except (HostPolicyError, KeyError, TypeError, ValueError) as exc:
            raise QualificationError(f"live monitor CPU policy is invalid: {exc}") from exc
        helpers = [
            entry
            for entry in manifest.binaries
            if entry["name"] == "quicperf-amd-stability-probe"
            and entry["role"] == "coordinator"
        ]
        if len(helpers) != 1:
            raise QualificationError("manifest lacks one AMD stability helper")
        helper = Path(str(helpers[0]["path"]))
        try:
            reference, calibration = run_amd_calibration(
                cpus=measurement_cpus,
                housekeeping_cpu=monitor_cpu,
                helper=helper,
            )
            status = "qualified" if calibration["passed"] else "not_qualified"
            reasons = tuple(str(reason) for reason in calibration["reasons"])
            if not reasons and status != "qualified":
                reasons = ("amd_provider_failed_without_reason",)
        except HealthError as exc:
            reference = None
            status = "not_qualified"
            reasons = (f"amd_provider_error:{exc}",)
            calibration = {
                "schema_version": "quicperf.amd-calibration.v1",
                "provider": "amd_delivered_performance_v1",
                "passed": False,
                "reasons": list(reasons),
                "measurement_cpus": list(measurement_cpus),
                "housekeeping_cpu": monitor_cpu,
            }
        run_document = {
            "schema_version": RUN_SCHEMA_VERSION,
            "artifact_kind": kind,
            "identity_hash": identity_hash,
            "status": status,
            "reasons": list(reasons),
            "calibration": calibration,
        }
        run_content = canonical_bytes(run_document) + b"\n"
        run_sha = hashlib.sha256(run_content).hexdigest()
        decision = QualificationDecision(
            kind,
            status,
            reasons,
            {
                "provider": "amd_delivered_performance_v1",
                "observation_artifact_sha256": run_sha,
                "measurement_cpus": list(measurement_cpus),
                "housekeeping_cpu": monitor_cpu,
                "hardware_status": (
                    "qualified" if status == "qualified" else "hardware_unqualified"
                ),
                "reference": (
                    {
                        "ratio": {
                            str(cpu): format(value, ".17g")
                            for cpu, value in sorted(reference.ratio.items())
                        },
                        "loop_iterations": {
                            str(cpu): format(value, ".17g")
                            for cpu, value in sorted(reference.loop_iterations.items())
                        },
                    }
                    if reference is not None
                    else None
                ),
            },
        )
        artifact_hash, artifact_path, run_path = _completed_artifact(
            journal=journal,
            campaign_id=campaign_id,
            kind=kind,
            identity=identity,
            decision=decision,
            artifact_store=artifact_store,
            run_content=run_content,
        )
        samples_after = int(
            journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0]
        )
        if samples_after != samples_before:
            raise QualificationError("host-stability qualification changed benchmark samples")
        journal.integrity_check()
    return {
        "schema_version": COMMAND_SCHEMA_VERSION,
        "operation": "run",
        "artifact_kind": kind,
        "status": decision.status,
        "qualified": decision.qualified,
        "reasons": list(decision.reasons),
        "identity_hash": identity_hash,
        "artifact_hash": artifact_hash,
        "artifact_path": artifact_path,
        "journal_path": run_path,
        "plan_hash": None,
        "screen_observations": 0,
        "held_out_observations": 0,
        "screen_attempt_records": 0,
        "held_out_attempt_records": 0,
        "sample_rows_added": 0,
    }
