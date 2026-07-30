from __future__ import annotations

import gc
import hashlib
import hmac
import json
import math
import os
import secrets
import socket
import signal
import subprocess
import sys
import threading
import time
from array import array
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, replace
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .canonical import canonical_bytes, load_strict, loads_strict, normalize_decimal
from .amd_stability import (
    PROVIDER_VERSION as AMD_PROVIDER_VERSION,
    PROBE_START_LEAD_NS,
    AmdContinuousMonitor,
    AmdBoundaryMonitorTransientError,
    AmdMonitorTransientError,
    AmdProviderPolicy,
    AmdReference,
    AmdTemperatureSource,
    load_amd_provider_policy,
    read_cpu_model_and_flags,
    resolve_temperature_source,
    run_amd_session_probe,
    verify_cpu_prerequisites,
)
from .errors import IdentityMismatchError, IncompleteCampaignError, InvalidConfigurationError
from .identity import (
    analysis_plan_hash,
    campaign_id as make_campaign_id,
    domain_hash,
    identity_manifest_hash,
    microblock_id as make_microblock_id,
    schedule_hash as make_schedule_hash,
    schedule_basis_hash,
    spec_hash,
    trial_id as make_trial_id,
)
from .journal import ACTIVE_STATES, Journal, TERMINAL_STATES
from .interoperability import (
    PASS as INTEROPERABILITY_PASS,
    InteroperabilityError,
    build_interoperability_identity,
    decode_interoperability_artifact,
    interoperability_plan_cardinality,
    load_native_interoperability,
)
from .health import HealthError, TrialHealthResult, TrialLaneHealth
from .host_policy import HostPolicyError, irq_policy_identity
from .lanes import LaneCgroups, LaneError, delegated_cgroup_root, read_cgroup_snapshot
from .manifest import load_manifest, manifest_hash
from .manifest_collect import (
    ManifestCollectionError,
    attest_process_libraries,
    collect_manifest,
)
from .memory import (
    MemoryPoll,
    final_observation_median,
    memory_settling_time,
    plan_memory_campaign,
)
from .capacity import (
    CAPACITY_GRID,
    CapacityPoint,
    freeze_confirmation_branches,
    nominate_capacity,
    plan_capacity_search,
)
from .model import ExperimentSpecV2, ImmutableIdentityManifest
from .planner import (
    BALANCE_CONTROL_ESTIMAND,
    PublicationMicroblock,
    PublicationSchedule,
    assign_williams_rows,
    assign_noninferential_williams_rows,
    plan_publication,
    tagged_hash,
)
from .paths import (
    ArmedTrace,
    LoopbackPathController,
    NamespacePathController,
    PathError,
    loss_recovery_drop,
)
from .spec import load_experiment_spec
from .protocol import MessageType, Packet, ProtocolError, SeqPacketChannel
from .qualification import (
    ARTIFACT_KINDS,
    QualificationArtifactStore,
    QualificationError,
    build_qualification_identity,
    decode_qualification_artifact,
    qualification_identity_hash,
    worker_reuse_eligible_scenario,
)
from .renderer import RenderedAnalysis, render_analysis
from .scheduler import LaneItem, balanced_lane_assignments
from .supervisor import ManagedProcess, Supervisor
from .statistical_simulation import (
    frozen_analysis_calibration,
    load_artifact,
    require_publication_ready,
)
from .topology import (
    LaneTopology,
    TopologyError,
    discover_physical_cores,
)
from .validity import DurationSampleFacts, ProgressBucket, validate_duration_sample


class RunnerError(InvalidConfigurationError):
    pass


DIAGNOSTIC_UNQUALIFIED_HOST_SCHEMA = "quicperf.diagnostic-unqualified-host.v2"
DIAGNOSTIC_UNQUALIFIED_HOST_WATERMARK = "DIAGNOSTIC — NOT PUBLICATION DATA"
# Legacy V2 only: each serial session contains 9,504 seconds of validated
# inferential measurement, so the old >=75% useful-wall gate becomes
# impossible above 12,672 wall seconds. V2.1 never consults this limit.
PUBLICATION_SESSION_WALL_BUDGET_NS = 12_672 * 1_000_000_000
# Reserve the scheduled post-session probe plus explicit successful-path
# readback/serialization slack before admitting another epoch.
PUBLICATION_SESSION_POST_PROBE_OVERHEAD_RESERVE_NS = 5 * 1_000_000_000
PUBLICATION_SESSION_FINALIZATION_RESERVE_NS = (
    60 * 1_000_000_000
    + PROBE_START_LEAD_NS
    + PUBLICATION_SESSION_POST_PROBE_OVERHEAD_RESERVE_NS
)
TRIAL_ARM_LEAD_NS = 75_000_000
V21_ARM_LEAD_NS = 750_000_000
V21_ARM_PRE_SEND_GUARD_NS = 500_000_000
V21_ARM_PRE_SEND_REBASE_MAXIMUM = 2
V21_ARM_RETRY_BUDGET_PER_SESSION = 1
_QUALIFICATION_REQUIRED_FIELDS = {
    "host-stability": "host_stability_required",
    "worker-reuse": "worker_reuse_required",
    "lane-interference": "lane_interference_required",
    "client-headroom": "client_headroom_required",
    "window-qualification": "window_equivalence_required",
    "tail-window": "tail_window_required",
}
_PHYSICAL_QUALIFICATION_ORDER = (
    "host-stability",
    "client-headroom",
    "worker-reuse",
    "window-qualification",
    "tail-window",
    "lane-interference",
)

_PEER_NUMERATOR_SCENARIOS = frozenset(
    {
        "download",
        "multistream_download",
        "loss_recovery",
        "flow_control",
        "datagram",
        "reqresp",
        "stream_churn",
        "close_reset_cleanup",
        "connect",
        "resumed_connect",
        "zero_rtt_reqresp",
    }
)

V21_SCHEMA_VERSION = "quicperf.experiment.v2.1"
V22_SCHEMA_VERSION = "quicperf.experiment.v2.2"
V23_SCHEMA_VERSION = "quicperf.experiment.v2.3"
VERSIONED_PUBLICATION_SCHEMA_VERSIONS = frozenset(
    {V21_SCHEMA_VERSION, V22_SCHEMA_VERSION, V23_SCHEMA_VERSION}
)


def _publication_methodology(
    spec: ExperimentSpecV2,
) -> Mapping[str, Any] | None:
    if spec.schema_version not in VERSIONED_PUBLICATION_SCHEMA_VERSIONS:
        return None
    methodology = spec.raw.get("methodology")
    if not isinstance(methodology, Mapping):
        raise IdentityMismatchError(
            "versioned publication methodology identity is missing"
        )
    return methodology


@dataclass(frozen=True)
class _ArmControlPolicy:
    lead_ns: int
    pre_send_guard_ns: int
    pre_send_rebase_maximum: int
    retry_budget_per_session: int


def _arm_control_policy(spec: ExperimentSpecV2) -> _ArmControlPolicy:
    methodology = _publication_methodology(spec)
    if methodology is None:
        return _ArmControlPolicy(TRIAL_ARM_LEAD_NS, 10_000_000, 2, 1)
    control = methodology.get("control_plane")
    if not isinstance(control, Mapping):
        raise IdentityMismatchError(
            "versioned control-plane methodology is missing"
        )
    policy = _ArmControlPolicy(
        int(control["arm_lead_ns"]),
        int(control["pre_send_guard_ns"]),
        int(control["pre_send_rebase_maximum"]),
        int(control["late_arm_retry_budget_per_session"]),
    )
    if policy != _ArmControlPolicy(
        V21_ARM_LEAD_NS,
        V21_ARM_PRE_SEND_GUARD_NS,
        V21_ARM_PRE_SEND_REBASE_MAXIMUM,
        V21_ARM_RETRY_BUDGET_PER_SESSION,
    ):
        raise IdentityMismatchError(
            "versioned ARM control-plane policy differs"
        )
    return policy


def _apply_amd_methodology(
    spec: ExperimentSpecV2, policy: AmdProviderPolicy
) -> AmdProviderPolicy:
    methodology = _publication_methodology(spec)
    if methodology is None:
        return policy
    monitor = methodology.get("monitor")
    if not isinstance(monitor, Mapping):
        raise IdentityMismatchError(
            "versioned monitor methodology is missing"
        )
    return replace(
        policy,
        temperature_gap_max_ns=int(monitor["combined_tctl_gap_max_ns"]),
        boundary_timestamp_semantics=str(
            monitor["boundary_timestamp_semantics"]
        ),
        interval_duration_error_max_fraction=Decimal(
            str(monitor["interval_duration_error_max_fraction"])
        ),
        phase_offset_max_ns=int(monitor["phase_offset_max_ns"]),
    )


def _publication_session_budget_reached(
    spec: ExperimentSpecV2, diagnostic_unqualified_host: bool, wall_ns: int
) -> bool:
    budget_ns = _publication_session_budget_ns(spec)
    return (
        spec.campaign_kind == "publication"
        and budget_ns is not None
        and not diagnostic_unqualified_host
        and wall_ns >= budget_ns
    )


def _publication_session_budget_allows_block(
    spec: ExperimentSpecV2,
    diagnostic_unqualified_host: bool,
    wall_ns: int,
    block_arm_ns: int,
) -> bool:
    budget_ns = _publication_session_budget_ns(spec)
    return (
        spec.campaign_kind != "publication"
        or budget_ns is None
        or diagnostic_unqualified_host
        or wall_ns
        + block_arm_ns
        + PUBLICATION_SESSION_FINALIZATION_RESERVE_NS
        <= budget_ns
    )


def _publication_session_budget_ns(
    spec: ExperimentSpecV2,
) -> int | None:
    if spec.schema_version == V21_SCHEMA_VERSION:
        return None
    if spec.schema_version in {V22_SCHEMA_VERSION, V23_SCHEMA_VERSION}:
        methodology = _publication_methodology(spec)
        assert methodology is not None
        runtime = methodology["runtime"]
        assert isinstance(runtime, Mapping)
        return int(runtime["operational_session_timeout_ns"])
    return PUBLICATION_SESSION_WALL_BUDGET_NS


class EndpointRunError(RuntimeError):
    def __init__(
        self,
        reason: str,
        *,
        detail: str | None = None,
        infrastructure_transient: bool = False,
        terminal_state: str = "failed",
    ):
        super().__init__(reason if detail is None else f"{reason}:{detail}")
        self.reason = reason
        self.detail = detail
        self.infrastructure_transient = infrastructure_transient
        self.terminal_state = terminal_state


def _external_noise_detail(health: TrialHealthResult) -> str:
    return canonical_bytes(
        {
            "device_irq_deltas": {
                str(cpu): {str(irq): delta for irq, delta in deltas.items()}
                for cpu, deltas in health.device_irq_deltas.items()
                if deltas
            },
            "non_owned_cpu_fraction_max_decimal": normalize_decimal(
                Decimal(str(health.non_owned_cpu_fraction_max))
            ),
            "non_owned_cpu_ns": {
                str(cpu): value
                for cpu, value in health.non_owned_cpu_ns.items()
                if value
            },
        }
    ).decode()


class SessionReplayRequired(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _LocalizedMicroblockRetry(RuntimeError):
    def __init__(self, retry_block_id: str):
        super().__init__(retry_block_id)
        self.retry_block_id = retry_block_id


class HardwareUnqualifiedError(EndpointRunError):
    def __init__(self, reason: str):
        super().__init__(reason, terminal_state="invalid")


class _PublicationEpochFailure(RuntimeError):
    def __init__(
        self,
        *,
        block_id: str,
        root_trial_id: str,
        cell_ids: tuple[str, ...],
        error: EndpointRunError,
        collateral: bool,
    ):
        super().__init__(error.reason)
        self.block_id = block_id
        self.root_trial_id = root_trial_id
        self.cell_ids = cell_ids
        self.error = error
        self.collateral = collateral


def _publication_epoch_failure_decision(
    failures: Sequence[BaseException],
) -> tuple[str, BaseException]:
    if not failures:
        raise RunnerError("publication epoch failure decision has no failures")
    hardware = next(
        (failure for failure in failures if isinstance(failure, HardwareUnqualifiedError)),
        None,
    )
    if hardware is not None:
        return "hardware", hardware
    replay = next(
        (
            failure
            for failure in failures
            if isinstance(failure, SessionReplayRequired)
            or (
                isinstance(failure, _PublicationEpochFailure)
                and failure.error.infrastructure_transient
            )
        ),
        None,
    )
    if replay is not None:
        return "replay", replay
    unexpected = next(
        (
            failure
            for failure in failures
            if not isinstance(failure, _PublicationEpochFailure)
        ),
        None,
    )
    if unexpected is not None:
        return "unexpected", unexpected
    epoch_failures = tuple(
        failure
        for failure in failures
        if isinstance(failure, _PublicationEpochFailure)
    )
    root = next(
        (failure for failure in epoch_failures if not failure.collateral),
        epoch_failures[0],
    )
    return "deterministic", root


@dataclass(frozen=True)
class _AmdSessionContext:
    cpus: tuple[int, ...]
    housekeeping_cpu: int
    helper: Path
    spin_helper: Path
    policy: AmdProviderPolicy
    reference: AmdReference
    temperature_source: AmdTemperatureSource


def _amd_monitor_evidence_is_transient(evidence: Mapping[str, Any]) -> bool:
    error = evidence.get("monitor_error")
    return (
        evidence.get("passed") is False
        and isinstance(error, Mapping)
        and error.get("type") == AmdMonitorTransientError.__name__
        and error.get("treatment_independent_transient") is True
        and isinstance(error.get("message"), str)
        and bool(error["message"])
    )


_INFERENTIAL_CAMPAIGN_KINDS = frozenset(
    {"publication", "capacity", "memory", "tail"}
)


def _statistical_calibration_reasons(
    root: Path, campaign_kind: str, analysis: Mapping[str, Any]
) -> list[str]:
    path = root / "profiles" / "v2" / "statistical-simulation" / "calibration-v2.json"
    try:
        artifact = load_artifact(path)
        artifact_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        planning_name = (
            "memory_planning_envelope"
            if str(analysis["planning_log_ratio_sd"]) == "0.04"
            else "rate_planning_envelope"
        )
        expected = frozen_analysis_calibration(
            artifact, artifact_sha256, planning_name
        )
        if analysis.get("statistical_calibration") != expected:
            raise ValueError(
                "frozen analysis plan does not match the exact calibration artifact"
            )
        if campaign_kind in _INFERENTIAL_CAMPAIGN_KINDS:
            require_publication_ready(artifact)
    except ValueError as exc:
        return [f"statistical_calibration:{exc}"]
    return []


@dataclass(frozen=True)
class CreatedCampaign:
    campaign_id: str
    schedule_hash: str
    planned_trials: int
    maximum_trial_ids: int
    run_dir: Path


def _seed_bytes(seed: str | bytes | None) -> bytes:
    if seed is None:
        return secrets.token_bytes(32)
    if isinstance(seed, bytes):
        value = seed
    else:
        try:
            value = bytes.fromhex(seed)
        except ValueError as exc:
            raise RunnerError("campaign seed must be 64 hexadecimal characters") from exc
    if len(value) != 32:
        raise RunnerError("campaign seed must be exactly 256 bits")
    return value


def _cell_config(trial: Any) -> dict[str, Any]:
    return {
        "estimand": trial.estimand,
        "scenario": trial.scenario,
        "path_profile": trial.path_profile,
        "concurrency": trial.fixed_concurrency,
        "server": trial.server,
        "server_backend": trial.server_backend,
        "reference_client": trial.reference_client,
        "reference_client_backend": trial.reference_client_backend,
    }


_NATIVE_WORKLOAD_FIELDS = {
    **{
        scenario: (1, 262_144, 8, 0, 0, 0, 0, 0, 0)
        for scenario in ("download", "upload", "loss_recovery", "flow_control")
    },
    **{
        scenario: (8, 262_144, 8, 0, 0, 0, 0, 0, 0)
        for scenario in ("multistream_download", "multistream_upload")
    },
    "bidi": (1, 262_144, 0, 0, 0, 0, 0, 0, 0),
    "small_payload_pps": (1, 0, 0, 0, 64, 0, 0, 0, 0),
    "datagram": (0, 0, 0, 0, 0, 64, 128, 2_048, 0),
    "reqresp": (1, 0, 64, 1_024, 0, 0, 0, 16, 0),
    "stream_churn": (1, 0, 0, 0, 1, 0, 0, 16, 0),
    "close_reset_cleanup": (1, 0, 0, 0, 1, 0, 0, 16, 0),
    "connect": (0, 0, 0, 0, 0, 0, 0, 16, 0),
    "resumed_connect": (0, 0, 0, 0, 0, 0, 0, 16, 16),
    "zero_rtt_reqresp": (1, 0, 64, 1_024, 0, 0, 0, 16, 16),
    "memory_curve": (1, 262_144, 1, 1, 1, 64, 0, 1, 0),
}


def _endpoint_config(
    *,
    root: Path,
    spec: ExperimentSpecV2,
    workload: Mapping[str, Any],
    cell: Mapping[str, Any],
    role: str,
    backend: str,
    peer_port: int,
) -> dict[str, Any]:
    """Translate one frozen trial into the exact native worker CONFIG schema."""

    if role not in {"server", "client"} or backend not in {"syscall", "iouring"}:
        raise RunnerError("invalid endpoint role or backend")
    if role == "server" and peer_port != 0 or role == "client" and not 1 <= peer_port <= 65_535:
        raise RunnerError("invalid endpoint peer port")
    treatment = spec.raw["treatment"]
    transport = treatment["transport"]
    tls = treatment["tls"]
    socket_policy = treatment["socket"]
    connections = int(cell.get("concurrency", cell.get("connections", workload["connections"])))
    scenario = str(cell["scenario"])
    if scenario != workload["scenario"] or scenario not in _NATIVE_WORKLOAD_FIELDS:
        raise RunnerError("cell and workload scenarios must match a native workload contract")
    (
        active_streams,
        bulk_chunk_bytes,
        request_body_bytes,
        response_body_bytes,
        operation_body_bytes,
        datagram_body_bytes,
        datagram_unreturned,
        operation_slots,
        ticket_slots,
    ) = _NATIVE_WORKLOAD_FIELDS[scenario]
    client_workers = int(
        cell.get(
            "client_event_loop_workers",
            spec.raw["treatment"]["resources"]["client_physical_cores"],
        )
    )
    if client_workers not in {2, 4}:
        raise RunnerError("client event-loop treatment must use exactly two or four workers")
    return {
        "ack_delay_exponent": int(transport["ack_delay_exponent"]),
        "ack_frequency": bool(transport["ack_frequency"]),
        "active_connection_id_limit": int(transport["active_connection_id_limit"]),
        "active_migration": bool(transport["active_migration"]),
        "active_streams_per_connection": active_streams,
        "alpn": str(transport["alpn"]),
        "backend": backend,
        "bind_address": "127.0.0.1",
        "bind_port": 0,
        "bulk_chunk_bytes": bulk_chunk_bytes,
        "busy_polling": bool(socket_policy["busy_polling"]),
        "calendar_unix_seconds": int(tls["calendar_unix_seconds"]),
        "certificate_path": str((root / str(tls["chain_path"])).resolve()),
        "chain_path": str((root / str(tls["ca_path"])).resolve()),
        "common_pacing": bool(socket_policy["common_core_pacing"]),
        "congestion_controller": str(transport["congestion_controller"]),
        "connection_count": connections,
        "connection_window": int(workload["connection_window_bytes"]),
        "datagram_body_bytes": datagram_body_bytes,
        "datagram_max_unreturned_per_connection": datagram_unreturned,
        "datagram_max_frame_size": int(transport["datagram_max_frame_size"]),
        "ecn": bool(socket_policy["ecn"]),
        "event_loop_workers": 1 if role == "server" else client_workers,
        "global_operation_slots": operation_slots,
        "idle_timeout_ms": int(transport["max_idle_timeout_ns"]) // 1_000_000,
        "initial_congestion_window_bytes": int(transport["initial_congestion_window_bytes"]),
        "connection_id_bytes": int(transport["connection_id_bytes"]),
        "max_ack_delay_ns": int(transport["max_ack_delay_ns"]),
        "max_bidi_streams": int(transport["stream_credit_bidi"]),
        "max_udp_payload_size": int(transport["max_udp_payload_size"]),
        "max_uni_streams": int(transport["stream_credit_uni"]),
        "measurement_duration_ns": int(
            cell.get("measurement_duration_ns", workload["measurement_ns"])
        ),
        "operation_body_bytes": operation_body_bytes,
        "path_profile": str(cell.get("path_profile", workload["path_profile"])),
        "peer_address": "0.0.0.0" if role == "server" else "127.0.0.1",
        "peer_port": peer_port,
        "pmtud": bool(socket_policy["pmtud"]),
        "private_key_path": str((root / "tls" / "server.key.pem").resolve()),
        "progress_interval_ns": int(spec.raw["timing"]["progress_cadence_ns"]),
        "quic_version": str(transport["quic_version"]),
        "receive_timestamps": bool(socket_policy["receive_timestamps"]),
        "request_body_bytes": request_body_bytes,
        "require_multishot_receive": backend == "iouring",
        "response_body_bytes": response_body_bytes,
        "role": role,
        "scenario": scenario,
        "schema_version": 2,
        "stream_credit_replenish_below": int(transport["stream_credit_replenish_below"]),
        "stream_window": int(workload["stream_window_bytes"]),
        "ticket_slots": ticket_slots,
        "tls_cipher_suite": str(tls["cipher_suite"]),
        "tls_hostname": str(tls["hostname"]),
        "tls_key_exchange": str(tls["key_exchange"]),
        "tls_leaf_signature": str(tls["leaf_signature"]),
        "tls_maximum_early_data_bytes": int(tls["maximum_early_data_bytes"]),
        "tls_one_use_tickets": bool(tls["one_use_tickets"]),
        "tls_ticket_lifetime_ns": int(tls["ticket_lifetime_ns"]),
        "tls_verify_peer": bool(tls["verify"]) if role == "client" else False,
        "tls_version": str(tls["version"]),
        "trace_seed": str(cell.get("trace_seed", "0" * 64)),
        "udp_gro": bool(socket_policy["udp_gro"]),
        "udp_gso": bool(socket_policy["udp_gso"]),
        "warmup_duration_ns": int(workload["warmup_ns"]),
    }


def _trace_seed(
    spec: ExperimentSpecV2, campaign_seed: bytes, microblock_id: str, path_profile: str
) -> str:
    try:
        path_hash = next(
            bytes.fromhex(path.content_hash)
            for path in spec.paths
            if path.name == path_profile
        )
        block = bytes.fromhex(microblock_id)
    except (StopIteration, ValueError) as exc:
        raise RunnerError("trace identity references an unknown path or microblock") from exc
    if len(block) != 32 or len(path_hash) != 32:
        raise RunnerError("trace identity fields must be exactly 256 bits")
    return hmac.new(campaign_seed, block + path_hash, hashlib.sha256).hexdigest()


def _generic_schedule(
    spec: ExperimentSpecV2,
    seed: bytes,
    basis: bytes,
    *,
    tail_durations_seconds: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    paired_design = spec.campaign_kind == "tail" or spec.estimand == "symmetric_stack_pair"
    assignment_function = (
        assign_williams_rows if paired_design else assign_noninferential_williams_rows
    )
    assignments = assignment_function(spec.servers, seed) if len(spec.servers) > 1 else ()
    if not assignments:
        assignments = (
            type("Assignment", (), {
                "session": 1,
                "session_position": 0,
                "row_index": 0,
                "reference_client": spec.reference_clients[0],
                "server_order": spec.servers,
            })(),
        )
    blocks = []
    retry_count = int(spec.raw["schedule"]["dormant_retry_per_microblock"])
    for assignment in assignments:
        for scenario in spec.scenarios:
            logical = tagged_hash(
                "logical-microblock",
                basis,
                canonical_bytes({"session": assignment.session, "row": assignment.row_index, "scenario": scenario}),
            ).hex()
            superblock_id = (
                tagged_hash(
                    "session-paired-superblock",
                    basis,
                    canonical_bytes(
                        {"williams_row": assignment.row_index, "scenario": scenario}
                    ),
                ).hex()
                if paired_design
                else None
            )
            for slot in ("primary", "retry") if retry_count else ("primary",):
                microblock_id = tagged_hash("microblock", basis, bytes.fromhex(logical), slot.encode("ascii")).hex()
                trials = []
                ordinal = 0
                for position, server in enumerate(assignment.server_order):
                    backend_sequence = tuple(spec.server_backends)
                    if len(backend_sequence) == 2:
                        if (assignment.row_index + position) % 2:
                            backend_sequence = tuple(reversed(backend_sequence))
                        if paired_design and assignment.session == 2:
                            backend_sequence = tuple(reversed(backend_sequence))
                    for backend_order, backend in enumerate(backend_sequence):
                        reference = server if spec.estimand == "symmetric_stack_pair" else assignment.reference_client
                        cell_config = {
                            "estimand": spec.estimand,
                            "scenario": scenario,
                            "path_profile": "loss_recovery_v1" if scenario == "loss_recovery" else "loopback",
                            "concurrency": int(next(item["connections"] for item in spec.raw["workloads"] if item["scenario"] == scenario)),
                            "server": server,
                            "server_backend": backend,
                            "reference_client": reference,
                            "reference_client_backend": spec.reference_client_backend,
                        }
                        if tail_durations_seconds is not None:
                            cell_config["measurement_duration_ns"] = (
                                int(tail_durations_seconds[scenario])
                                * 1_000_000_000
                            )
                        cell_id = tagged_hash("cell", canonical_bytes(cell_config)).hex()
                        logical_trial_id = domain_hash("logical-trial", bytes.fromhex(logical), bytes.fromhex(cell_id))
                        trial_id = tagged_hash(
                            "trial",
                            basis,
                            assignment.session.to_bytes(4, "big"),
                            bytes.fromhex(microblock_id),
                            bytes.fromhex(cell_id),
                            b"\0",
                        ).hex()
                        trials.append({
                            "trial_id": trial_id,
                            "logical_trial_id": logical_trial_id,
                            "cell_id": cell_id,
                            "cell_config": cell_config,
                            "ordinal": ordinal,
                        })
                        ordinal += 1
                blocks.append({
                    "microblock_id": microblock_id,
                    "logical_id": logical,
                    "retry_for_logical": logical if slot == "retry" else None,
                    "slot": slot,
                    "session": assignment.session,
                    "superblock_id": superblock_id,
                    "williams_row": assignment.row_index,
                    "trace_seed": _trace_seed(
                        spec,
                        seed,
                        microblock_id,
                        "loss_recovery_v1" if scenario == "loss_recovery" else "loopback",
                    ),
                    "trials": trials,
                })
    return {"kind": spec.campaign_kind, "seed": seed.hex(), "basis": basis.hex(), "blocks": blocks}


def _memory_schedule(spec: ExperimentSpecV2, seed: bytes, basis: bytes) -> dict[str, Any]:
    primary = plan_memory_campaign(campaign_seed=seed, schedule_basis_hash=basis, servers=spec.servers, backends=spec.server_backends)
    grouped: dict[int, list[Any]] = {}
    for trial in primary:
        grouped.setdefault(trial.block_position, []).append(trial)
    blocks = []
    for block_position, members in sorted(grouped.items()):
        logical = tagged_hash("logical-memory-microblock", basis, block_position.to_bytes(4, "big")).hex()
        for slot in ("primary", "retry"):
            block_id = tagged_hash("memory-microblock", basis, bytes.fromhex(logical), slot.encode()).hex()
            trials = []
            for ordinal, member in enumerate(sorted(members, key=lambda item: (item.server_position, item.server_backend, item.n_order))):
                config = {
                    "estimand": "memory_curve",
                    "scenario": "memory_curve",
                    "path_profile": "loopback",
                    "connections": member.connections,
                    "block_position": member.block_position,
                    "williams_row": member.williams_row,
                    "n_order": member.n_order,
                    "server": member.server,
                    "server_backend": member.server_backend,
                    "reference_client": spec.reference_clients[0],
                    "reference_client_backend": spec.reference_client_backend,
                }
                cell = tagged_hash("cell", canonical_bytes(config)).hex()
                logical_trial = domain_hash("logical-trial", bytes.fromhex(logical), bytes.fromhex(cell))
                trial_id = tagged_hash("memory-trial", basis, bytes.fromhex(block_id), bytes.fromhex(cell)).hex()
                trials.append({"trial_id": trial_id, "logical_trial_id": logical_trial, "cell_id": cell, "cell_config": config, "ordinal": ordinal})
            superblock_id = tagged_hash(
                "memory-session-paired-superblock",
                basis,
                members[0].williams_row.to_bytes(4, "big"),
            ).hex()
            blocks.append({"microblock_id": block_id, "logical_id": logical, "retry_for_logical": logical if slot == "retry" else None, "slot": slot, "session": members[0].session, "superblock_id": superblock_id, "williams_row": members[0].williams_row, "trace_seed": _trace_seed(spec, seed, block_id, "loopback"), "trials": trials})
    return {"kind": "memory", "seed": seed.hex(), "basis": basis.hex(), "blocks": blocks}


def _publication_schedule_dict(
    schedule: PublicationSchedule,
    *,
    measurement_durations_ns: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    blocks = []
    for block in schedule.microblocks:
        trials = []
        for ordinal, trial in enumerate(block.trials):
            config = _cell_config(trial)
            cell_id = trial.cell_id
            trial_id = trial.trial_id
            if measurement_durations_ns is not None:
                config["measurement_duration_ns"] = int(
                    measurement_durations_ns[trial.scenario]
                )
                cell_id = domain_hash("cell", canonical_bytes(config))
                trial_id = make_trial_id(
                    schedule.schedule_basis_hash,
                    trial.session,
                    block.microblock_id,
                    cell_id,
                    False,
                )
            logical_trial = domain_hash(
                "logical-trial",
                bytes.fromhex(block.logical_id),
                bytes.fromhex(cell_id),
            )
            trials.append(
                {
                    "trial_id": trial_id,
                    "logical_trial_id": logical_trial,
                    "cell_id": cell_id,
                    "cell_config": config,
                    "ordinal": ordinal,
                }
            )
        blocks.append({
            "microblock_id": block.microblock_id,
            "logical_id": block.logical_id,
            "retry_for_logical": block.logical_id if block.slot == "retry" else None,
            "slot": block.slot,
            "session": block.session,
            "superblock_id": block.superblock_id,
            "williams_row": block.williams_row,
            "lane": block.lane,
            "parallel_epoch_id": block.parallel_epoch_id,
            "parallel_epoch_ordinal": block.parallel_epoch_ordinal,
            "parallel_lane_ordinal": block.parallel_lane_ordinal,
            "phase": (
                "parallel_balance_control"
                if block.estimand == BALANCE_CONTROL_ESTIMAND
                else "confirmatory"
            ),
            "trace_seed": block.trace_seed,
            "trials": trials,
        })
    return {"kind": "publication", "seed": schedule.campaign_seed, "basis": schedule.schedule_basis_hash, "blocks": blocks}


def _capacity_schedule(spec: ExperimentSpecV2, seed: bytes, basis: bytes) -> dict[str, Any]:
    basis_hex = basis.hex()
    search = plan_capacity_search(
        campaign_seed=seed,
        schedule_basis_hash=basis,
        servers=spec.servers,
        backends=spec.server_backends,
        scenarios=spec.scenarios,
    )
    search_groups: dict[tuple[int, str], list[Any]] = {}
    for trial in search.trials:
        search_groups.setdefault((trial.search_round, trial.scenario), []).append(trial)
    blocks: list[dict[str, Any]] = []
    for (search_round, scenario), members in sorted(search_groups.items()):
        session = 1 if search_round < 5 else 2
        coordinates = {
            "phase": "capacity_search",
            "search_round": search_round,
            "scenario": scenario,
        }
        logical = domain_hash("logical-microblock", basis, canonical_bytes(coordinates))
        for slot in ("primary", "retry"):
            block_id = make_microblock_id(basis_hex, coordinates, slot)
            trials = []
            for ordinal, member in enumerate(
                sorted(members, key=lambda item: (item.server_position, item.backend_order, item.server))
            ):
                config = {
                    "estimand": "capacity_frontier",
                    "phase": "exploratory",
                    "search_round": search_round,
                    "scenario": member.scenario,
                    "path_profile": "loopback",
                    "concurrency": member.concurrency,
                    "server": member.server,
                    "server_backend": member.server_backend,
                    "reference_client": member.reference_client,
                    "reference_client_backend": spec.reference_client_backend,
                }
                cell = domain_hash("cell", canonical_bytes(config))
                logical_trial = domain_hash("logical-trial", bytes.fromhex(logical), bytes.fromhex(cell))
                trials.append(
                    {
                        "trial_id": make_trial_id(basis_hex, session, block_id, cell, False),
                        "logical_trial_id": logical_trial,
                        "cell_id": cell,
                        "cell_config": config,
                        "ordinal": ordinal,
                    }
                )
            blocks.append(
                {
                    "microblock_id": block_id,
                    "logical_id": logical,
                    "retry_for_logical": logical if slot == "retry" else None,
                    "slot": slot,
                    "session": session,
                    "phase": "capacity_search",
                    "trace_seed": _trace_seed(spec, seed, block_id, "loopback"),
                    "trials": trials,
                }
            )

    for server in spec.servers:
        for backend in spec.server_backends:
            for scenario in spec.scenarios:
                group = domain_hash(
                    "capacity-branch-group",
                    basis,
                    canonical_bytes({"server": server, "server_backend": backend, "scenario": scenario}),
                )
                branches = freeze_confirmation_branches(
                    campaign_seed=seed,
                    schedule_basis_hash=basis,
                    server=server,
                    server_backend=backend,
                    scenario=scenario,
                )
                for branch in branches:
                    by_round_slot: dict[tuple[int, str], list[Any]] = {}
                    for member in branch.trials:
                        by_round_slot.setdefault((member.confirmation_round, member.slot), []).append(member)
                    for (round_index, slot), members in sorted(by_round_slot.items()):
                        first = members[0]
                        coordinates = {
                            "phase": "capacity_confirmation",
                            "branch_group": group,
                            "candidate": branch.candidate,
                            "round": round_index,
                        }
                        logical = domain_hash("logical-microblock", basis, canonical_bytes(coordinates))
                        block_id = make_microblock_id(basis_hex, coordinates, slot)
                        trials = []
                        for ordinal, member in enumerate(sorted(members, key=lambda item: item.order)):
                            config = {
                                "estimand": "capacity_frontier",
                                "phase": "confirmatory",
                                "branch_candidate": branch.candidate,
                                "confirmation_round": round_index,
                                "williams_row": first.williams_row,
                                "scenario": scenario,
                                "path_profile": "loopback",
                                "concurrency": member.concurrency,
                                "server": server,
                                "server_backend": backend,
                                "reference_client": member.reference_client,
                                "reference_client_backend": spec.reference_client_backend,
                            }
                            cell = domain_hash("cell", canonical_bytes(config))
                            logical_trial = domain_hash(
                                "logical-trial", bytes.fromhex(logical), bytes.fromhex(cell)
                            )
                            trials.append(
                                {
                                    "trial_id": make_trial_id(
                                        basis_hex, member.session, block_id, cell, False
                                    ),
                                    "logical_trial_id": logical_trial,
                                    "cell_id": cell,
                                    "cell_config": config,
                                    "ordinal": ordinal,
                                }
                            )
                        blocks.append(
                            {
                                "microblock_id": block_id,
                                "logical_id": logical,
                                "retry_for_logical": logical if slot == "retry" else None,
                                "slot": slot,
                                "session": first.session,
                                "superblock_id": domain_hash(
                                    "capacity-session-paired-superblock",
                                    basis,
                                    canonical_bytes(
                                        {
                                            "branch_group": group,
                                            "candidate": branch.candidate,
                                            "williams_row": first.williams_row,
                                        }
                                    ),
                                ),
                                "phase": "capacity_confirmation",
                                "branch_group": group,
                                "branch_candidate": branch.candidate,
                                "initial_status": "dormant_candidate",
                                "williams_row": first.williams_row,
                                "lane": first.lane,
                                "trace_seed": _trace_seed(spec, seed, block_id, "loopback"),
                                "trials": trials,
                            }
                        )
    return {"kind": "capacity", "seed": seed.hex(), "basis": basis.hex(), "blocks": blocks}


def _freeze_into_journal(
    journal: Journal,
    *,
    campaign: str,
    schedule: Mapping[str, Any],
    expected_cardinality: int,
    retry_per_microblock: int,
) -> None:
    cells: dict[str, Any] = {}
    primary_by_logical = {
        str(block["logical_id"]): str(block["microblock_id"])
        for block in schedule["blocks"]
        if block["slot"] == "primary"
    }
    blocks = []
    trials = []
    for ordinal, block in enumerate(schedule["blocks"]):
        retry_for = primary_by_logical.get(block["retry_for_logical"]) if block["slot"] == "retry" else None
        if block["slot"] == "retry" and retry_for is None:
            raise RunnerError("retry appeared before its primary microblock")
        blocks.append(
            {
                "microblock_id": block["microblock_id"],
                "session_number": block["session"],
                "ordinal": ordinal,
                "slot": block["slot"],
                "expected_trials": len(block["trials"]),
                "retry_for": retry_for,
                "phase": block.get("phase", "confirmatory"),
                "branch_group": block.get("branch_group"),
                "branch_candidate": block.get("branch_candidate"),
                "superblock_id": block.get("superblock_id"),
                "williams_row": block.get("williams_row"),
                "initial_status": block.get("initial_status"),
            }
        )
        for trial in block["trials"]:
            cells.setdefault(trial["cell_id"], trial["cell_config"])
            trials.append(
                {
                    "trial_id": trial["trial_id"],
                    "logical_trial_id": trial["logical_trial_id"],
                    "microblock_id": block["microblock_id"],
                    "cell_id": trial["cell_id"],
                    "ordinal": trial["ordinal"],
                }
            )
    journal.populate_schedule(campaign, cells=cells, microblocks=blocks, trials=trials)
    journal.freeze_schedule(campaign)


def _qualification_max_lanes(decision: Any) -> int | None:
    evidence = decision.evidence.get("evaluation", decision.evidence)
    value = evidence.get("max_lanes") if isinstance(evidence, Mapping) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _tail_qualification_durations(
    decision: Any, spec: ExperimentSpecV2
) -> dict[str, int]:
    if not decision.qualified:
        raise RunnerError("tail-window artifact is not qualified")
    evidence = decision.evidence.get("evaluation", decision.evidence)
    durations = (
        evidence.get("scenario_durations_seconds")
        if isinstance(evidence, Mapping)
        else None
    )
    if not isinstance(durations, Mapping) or set(durations) != set(spec.scenarios):
        raise RunnerError(
            "tail-window artifact does not select every frozen tail scenario"
        )
    result: dict[str, int] = {}
    for scenario in spec.scenarios:
        duration = durations[scenario]
        if isinstance(duration, bool) or not isinstance(duration, int):
            raise RunnerError(
                f"tail-window duration for {scenario} must be an integer"
            )
        if duration not in {2, 5, 10, 20}:
            raise RunnerError(
                f"tail-window duration for {scenario} is outside the frozen ladder"
            )
        result[scenario] = duration
    return result


def _load_tail_qualification(
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
    qualification_store: Path | None,
) -> tuple[dict[str, int] | None, Any | None]:
    if spec.campaign_kind != "tail" or qualification_store is None:
        return None, None
    stored = QualificationArtifactStore(qualification_store).load_optional(
        "tail-window", build_qualification_identity("tail-window", spec, manifest)
    )
    if stored is None:
        return None, None
    return _tail_qualification_durations(stored.decision, spec), stored


def diagnostic_host_failure_authorization(
    *,
    root: Path,
    profile: Path,
    bin_dir: Path | None,
    qualification_store: Path | None,
) -> dict[str, Any]:
    """Bind diagnostic execution to an observed exact-identity physical failure."""

    if qualification_store is None:
        raise RunnerError(
            "--diagnostic-unqualified-host requires a qualification artifact store"
        )
    spec = load_experiment_spec(profile)
    manifest = collect_manifest(root, spec, bin_dir=bin_dir)
    store = QualificationArtifactStore(qualification_store)
    for kind in _PHYSICAL_QUALIFICATION_ORDER:
        if not bool(spec.raw["qualification"][_QUALIFICATION_REQUIRED_FIELDS[kind]]):
            continue
        stored = store.load_optional(
            kind, build_qualification_identity(kind, spec, manifest)
        )
        if (
            stored is None
            or stored.decision.status != "not_qualified"
            or not stored.decision.reasons
        ):
            continue
        return {
            "artifact_hash": stored.artifact_hash,
            "artifact_kind": kind,
            "content_sha256": hashlib.sha256(stored.path.read_bytes()).hexdigest(),
            "identity_hash": stored.identity_hash,
            "profile_hash": spec_hash(spec.raw),
            "reasons": list(stored.decision.reasons),
            "status": stored.decision.status,
        }
    raise RunnerError(
        "--diagnostic-unqualified-host requires an exact-identity completed "
        "physical not-qualified decision"
    )


def _qualification_inventory(
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
    qualification_store: Path | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    store = (
        QualificationArtifactStore(qualification_store)
        if qualification_store is not None
        else None
    )
    inventory: list[dict[str, Any]] = []
    available: dict[str, Any] = {}
    for kind in sorted(ARTIFACT_KINDS):
        identity = build_qualification_identity(kind, spec, manifest)
        identity_hash = qualification_identity_hash(kind, identity)
        stored = store.load_optional(kind, identity) if store is not None else None
        required = bool(
            spec.raw["qualification"][_QUALIFICATION_REQUIRED_FIELDS[kind]]
        )
        if stored is None:
            inventory.append(
                {
                    "artifact_hash": None,
                    "content_sha256": None,
                    "identity_hash": identity_hash,
                    "kind": kind,
                    "qualified": False,
                    "reasons": ["exact_identity_artifact_missing"],
                    "required": required,
                    "status": "missing",
                }
            )
            continue
        available[kind] = stored
        inventory.append(
            {
                "artifact_hash": stored.artifact_hash,
                "content_sha256": hashlib.sha256(
                    stored.path.read_bytes()
                ).hexdigest(),
                "identity_hash": stored.identity_hash,
                "kind": kind,
                "qualified": stored.decision.qualified,
                "reasons": list(stored.decision.reasons),
                "required": required,
                "status": stored.decision.status,
            }
        )
    return inventory, available


def _diagnostic_manifest(
    *,
    authorization: Mapping[str, Any],
    qualifications: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": DIAGNOSTIC_UNQUALIFIED_HOST_SCHEMA,
        "authorization": dict(authorization),
        "conservative_defaults": {
            "execution_lanes": 1,
            "fixed_impaired_duration_ns": 20_000_000_000,
            "fixed_loopback_duration_ns": 10_000_000_000,
            "tail_duration_ns": 20_000_000_000,
            "worker_reuse": False,
        },
        "publication_qualified": False,
        "qualifications": [dict(item) for item in qualifications],
        "watermark": DIAGNOSTIC_UNQUALIFIED_HOST_WATERMARK,
    }


def _diagnostic_schedule_manifest(
    schedule: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    value = schedule.get("diagnostic_unqualified_host")
    if value is None:
        return None
    expected_fields = {
        "schema_version",
        "authorization",
        "conservative_defaults",
        "publication_qualified",
        "qualifications",
        "watermark",
    }
    authorization_fields = {
        "artifact_hash",
        "artifact_kind",
        "content_sha256",
        "identity_hash",
        "profile_hash",
        "reasons",
        "status",
    }
    qualification_fields = {
        "artifact_hash",
        "content_sha256",
        "identity_hash",
        "kind",
        "qualified",
        "reasons",
        "required",
        "status",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != expected_fields
        or value.get("schema_version") != DIAGNOSTIC_UNQUALIFIED_HOST_SCHEMA
        or value.get("watermark") != DIAGNOSTIC_UNQUALIFIED_HOST_WATERMARK
        or value.get("publication_qualified") is not False
        or not isinstance(value.get("authorization"), Mapping)
        or not isinstance(value.get("qualifications"), list)
        or not isinstance(value.get("conservative_defaults"), Mapping)
        or set(value["authorization"]) != authorization_fields
        or value["authorization"].get("artifact_kind")
        not in _PHYSICAL_QUALIFICATION_ORDER
        or value["authorization"].get("status") != "not_qualified"
        or not value["authorization"].get("reasons")
        or any(
            not isinstance(item, Mapping) or set(item) != qualification_fields
            for item in value["qualifications"]
        )
        or value["conservative_defaults"]
        != {
            "execution_lanes": 1,
            "fixed_impaired_duration_ns": 20_000_000_000,
            "fixed_loopback_duration_ns": 10_000_000_000,
            "tail_duration_ns": 20_000_000_000,
            "worker_reuse": False,
        }
    ):
        raise IdentityMismatchError(
            "diagnostic-unqualified-host schedule manifest is invalid"
        )
    return value


def _scheduled_lane_count(
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
    qualification_store: Path | None,
) -> tuple[int, Any | None]:
    assignment = spec.raw["schedule"]["lane_assignment"]
    if assignment == "single_lane":
        return 1, None
    if assignment == "hmac_then_minimum_balancing":
        if len(manifest.host_policy["lane_layout"]) < 2:
            if spec.raw["qualification"]["lane_interference_required"]:
                raise RunnerError(
                    "the frozen profile requires two physical lane layouts"
                )
            return 1, None
        if spec.campaign_kind == "qualification" and spec.name == "lane-interference-validation":
            return 2, None
        if qualification_store is None:
            return 2, None
        stored = QualificationArtifactStore(qualification_store).load_optional(
            "lane-interference",
            build_qualification_identity("lane-interference", spec, manifest),
        )
        if stored is None:
            return 2, None
        if not stored.decision.qualified:
            if spec.raw["qualification"]["lane_interference_required"]:
                raise RunnerError(
                    "lane-interference evidence does not qualify the required "
                    "two-lane treatment"
                )
            return 1, stored
        max_lanes = _qualification_max_lanes(stored.decision)
        if max_lanes not in {1, 2}:
            raise RunnerError("lane-interference artifact has an invalid max_lanes decision")
        if (
            spec.raw["qualification"]["lane_interference_required"]
            and max_lanes != 2
        ):
            raise RunnerError(
                "lane-interference evidence does not qualify the required "
                "two-lane treatment"
            )
        return max_lanes, stored
    raise RunnerError(f"unsupported frozen lane assignment {assignment!r}")


def _assign_missing_schedule_lanes(
    schedule: dict[str, Any], campaign_seed: bytes, lane_count: int
) -> None:
    missing = [block for block in schedule["blocks"] if "lane" not in block]
    if not missing:
        return
    assignments = balanced_lane_assignments(
        (
            LaneItem(
                str(block["microblock_id"]),
                (int(block["session"]), str(block["slot"])),
            )
            for block in missing
        ),
        campaign_seed,
        lane_count,
    )
    for block in missing:
        block["lane"] = assignments[str(block["microblock_id"])]


def _active_publication_epochs(
    block_schedule: Mapping[str, Mapping[str, Any]],
    block_ids: Sequence[str],
    *,
    session: int,
) -> tuple[tuple[int, tuple[tuple[int, str], ...]], ...]:
    grouped: dict[tuple[str, int], list[tuple[int, str]]] = {}
    epoch_ids: dict[tuple[str, int], str] = {}
    for block_id in block_ids:
        try:
            block = block_schedule[block_id]
            block_session = int(block["session"])
            slot = str(block["slot"])
            epoch_id = str(block["parallel_epoch_id"])
            epoch_ordinal = int(block["parallel_epoch_ordinal"])
            lane = int(block["lane"])
            lane_ordinal = int(block["parallel_lane_ordinal"])
        except (KeyError, TypeError, ValueError) as exc:
            raise IdentityMismatchError(
                "publication parallel epoch identity is malformed"
            ) from exc
        if (
            block_session != session
            or slot not in {"primary", "retry"}
            or len(epoch_id) != 64
            or any(character not in "0123456789abcdef" for character in epoch_id)
            or epoch_ordinal < 0
            or lane not in {0, 1}
            or lane_ordinal != 0
        ):
            raise IdentityMismatchError(
                "publication parallel epoch identity is invalid"
            )
        key = (slot, epoch_ordinal)
        grouped.setdefault(key, []).append((lane, block_id))
        previous = epoch_ids.setdefault(key, epoch_id)
        if previous != epoch_id:
            raise IdentityMismatchError(
                "publication parallel epoch IDs disagree"
            )
    if len({slot for slot, _ordinal in grouped}) > 1:
        raise IdentityMismatchError(
            "publication primary and retry epochs are active together"
        )
    result = []
    for (_slot, ordinal), members in sorted(grouped.items()):
        ordered = tuple(sorted(members))
        if len(ordered) != 2 or {lane for lane, _block_id in ordered} != {0, 1}:
            raise IdentityMismatchError(
                "publication parallel epoch is incomplete"
            )
        result.append((ordinal, ordered))
    return tuple(result)


def _publication_epoch_timing(
    block_schedule: Mapping[str, Mapping[str, Any]],
    block_arm_ns: Mapping[str, int],
    epoch_members: Sequence[tuple[int, str]],
    arm_lead_ns: int,
) -> tuple[int, int]:
    trial_counts = {
        len(block_schedule[block_id]["trials"])
        for _lane, block_id in epoch_members
    }
    if len(trial_counts) != 1 or not trial_counts or next(iter(trial_counts)) <= 0:
        raise IdentityMismatchError(
            "publication epoch blocks have unequal trial cardinality"
        )
    trial_count = next(iter(trial_counts))
    if any(
        block_arm_ns[block_id] % trial_count
        for _lane, block_id in epoch_members
    ):
        raise IdentityMismatchError(
            "publication epoch block arms are not uniform"
        )
    per_trial_arm_ns = max(
        block_arm_ns[block_id] // trial_count
        for _lane, block_id in epoch_members
    )
    return (
        max(
            block_arm_ns[block_id] + trial_count * arm_lead_ns
            for _lane, block_id in epoch_members
        ),
        per_trial_arm_ns,
    )


def _attest_versioned_historical_policy(
    root: Path, spec: ExperimentSpecV2
) -> bytes | None:
    methodology = _publication_methodology(spec)
    if methodology is None:
        return None
    monitor = methodology["monitor"]
    runtime = methodology["runtime"]
    assert isinstance(monitor, Mapping)
    assert isinstance(runtime, Mapping)
    relative = Path(str(runtime["historical_evidence_artifact"]))
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
        content = path.read_bytes()
    except (OSError, ValueError) as exc:
        raise RunnerError(
            f"versioned historical methodology evidence is unavailable: {exc}"
        ) from exc
    if (
        hashlib.sha256(content).hexdigest()
        != runtime["historical_evidence_sha256"]
    ):
        raise RunnerError(
            "versioned historical methodology evidence checksum differs"
        )
    try:
        document = loads_strict(content)
    except Exception as exc:
        raise RunnerError(
            f"versioned historical methodology evidence is invalid: {exc}"
        ) from exc
    valid = (
        isinstance(document, Mapping)
        and document.get("localized_transient_budget_per_session")
        == monitor["localized_transient_budget_per_session"]
    )
    if spec.schema_version == V21_SCHEMA_VERSION:
        valid = (
            valid
            and document.get("schema_version")
            == "quicperf.pre-v2.1-runtime-policy.v1"
            and document.get("operational_session_timeout_ns")
            == runtime["operational_session_timeout_ns"]
        )
    elif spec.schema_version in {V22_SCHEMA_VERSION, V23_SCHEMA_VERSION}:
        runtime_budget = (
            document.get("runtime_budget")
            if isinstance(document, Mapping)
            else None
        )
        scheduled_floor = (
            document.get("scheduled_campaign_floor")
            if isinstance(document, Mapping)
            else None
        )
        valid = (
            valid
            and document.get("schema_version")
            == {
                V22_SCHEMA_VERSION: "quicperf.pre-v2.2-runtime-policy.v1",
                V23_SCHEMA_VERSION: "quicperf.pre-v2.3-runtime-policy.v1",
            }[spec.schema_version]
            and isinstance(runtime_budget, Mapping)
            and isinstance(scheduled_floor, Mapping)
            and runtime_budget.get("operational_session_timeout_ns")
            == runtime["operational_session_timeout_ns"]
            and runtime_budget.get("deterministic_verification_budget_ns")
            == runtime["deterministic_verification_budget_ns"]
            and runtime_budget.get("admission_conservative_reservation_ns")
            == runtime["admission_conservative_reservation_ns"]
            and runtime_budget.get("analysis_finalization_export_budget_ns")
            == runtime["analysis_finalization_export_budget_ns"]
            and runtime_budget.get("clean_start_conservative_budget_ns")
            == runtime["clean_start_conservative_budget_ns"]
            and runtime_budget.get("suite_deadline_ns")
            == runtime["suite_deadline_ns"]
            and scheduled_floor.get("total_ns")
            == runtime["scheduled_campaign_floor_ns"]
        )
        if spec.schema_version == V23_SCHEMA_VERSION:
            v22_observation = document.get("v2.2_observed_session")
            valid = (
                valid
                and isinstance(v22_observation, Mapping)
                and v22_observation.get("session_wall_ns")
                == 8_363_071_232_433
                and v22_observation.get("committed_microblocks") == 173
                and v22_observation.get("unstarted_microblocks") == 7
                and v22_observation.get("termination_reason")
                == "runtime_session_wall_feasibility_budget_exhausted"
                and v22_observation.get("publication_sample_reuse") is False
            )
    if not valid:
        raise RunnerError(
            "versioned historical methodology evidence differs from the profile"
        )
    return content


def create_campaign(
    *,
    root: Path,
    profile: Path,
    run_dir: Path,
    seed: str | bytes | None = None,
    bin_dir: Path | None = None,
    qualification_store: Path | None = None,
    interoperability_store: Path | None = None,
    diagnostic_unqualified_host: bool = False,
    diagnostic_authorization: Mapping[str, Any] | None = None,
) -> CreatedCampaign:
    planning_started_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    planning_cpu_started_ns = time.process_time_ns()
    spec = load_experiment_spec(profile)
    methodology_evidence = _attest_versioned_historical_policy(root, spec)
    calibration_reasons = _statistical_calibration_reasons(
        root, spec.campaign_kind, spec.raw["analysis"]
    )
    if calibration_reasons:
        raise RunnerError(calibration_reasons[0])
    manifest = collect_manifest(root, spec, bin_dir=bin_dir)
    clean_required = bool(spec.raw["manifest_policy"]["clean_tree_required"])
    if clean_required and not manifest.source["clean"]:
        raise RunnerError("canonical campaign creation requires a clean source tree")
    interoperability_artifact = None
    if spec.campaign_kind == "publication":
        try:
            interoperability_artifact = load_native_interoperability(
                store_root=(
                    interoperability_store
                    or root / ".data" / "interoperability-v2"
                ),
                spec=spec,
                manifest=manifest,
            )
        except InteroperabilityError as exc:
            raise RunnerError(
                f"native interoperability artifact is invalid: {exc}"
            ) from exc
        if interoperability_artifact is None:
            raise RunnerError(
                "publication creation requires an exact-identity native interoperability artifact"
            )
        if (
            interoperability_artifact.status != INTEROPERABILITY_PASS
            or interoperability_artifact.passed
            != interoperability_plan_cardinality(spec)
            or interoperability_artifact.failed != 0
        ):
            raise RunnerError(
                "publication creation requires every balanced native "
                "interoperability preflight tuple to pass"
            )
    campaign_seed = _seed_bytes(seed)
    spec_digest = spec_hash(spec.raw)
    manifest_digest = manifest_hash(manifest)
    analysis_digest = analysis_plan_hash(spec.raw["analysis"])
    basis_digest = schedule_basis_hash(spec_digest, manifest_digest, analysis_digest, campaign_seed)
    basis = bytes.fromhex(basis_digest)
    qualification_inventory, qualification_artifacts = _qualification_inventory(
        spec, manifest, qualification_store
    )
    diagnostic_manifest = None
    if diagnostic_unqualified_host:
        if (
            not isinstance(diagnostic_authorization, Mapping)
            or diagnostic_authorization.get("artifact_kind")
            not in _PHYSICAL_QUALIFICATION_ORDER
            or diagnostic_authorization.get("status") != "not_qualified"
            or not isinstance(diagnostic_authorization.get("reasons"), list)
            or not diagnostic_authorization["reasons"]
        ):
            raise RunnerError(
                "diagnostic-unqualified-host execution lacks a frozen physical "
                "failure authorization"
            )
        lane_count = 1
        tail_durations = (
            {scenario: 20 for scenario in spec.scenarios}
            if spec.campaign_kind == "tail"
            else None
        )
        diagnostic_manifest = _diagnostic_manifest(
            authorization=diagnostic_authorization,
            qualifications=qualification_inventory,
        )
    else:
        lane_count, _lane_artifact = _scheduled_lane_count(
            spec, manifest, qualification_store
        )
        tail_durations, _tail_artifact = _load_tail_qualification(
            spec, manifest, qualification_store
        )

    if spec.campaign_kind == "publication":
        planned = plan_publication(
            campaign_seed=campaign_seed,
            schedule_basis_hash=basis,
            servers=spec.servers,
            scenarios=spec.scenarios,
            server_backends=spec.server_backends,
            reference_clients=spec.reference_clients,
            path_profile_hashes={
                path.name: bytes.fromhex(path.content_hash) for path in spec.paths
            },
            qualified_lane_count=lane_count,
        )
        diagnostic_durations = (
            {
                scenario: (
                    20_000_000_000
                    if scenario == "loss_recovery"
                    else 10_000_000_000
                )
                for scenario in spec.scenarios
            }
            if diagnostic_unqualified_host
            else None
        )
        schedule = _publication_schedule_dict(
            planned, measurement_durations_ns=diagnostic_durations
        )
    elif spec.campaign_kind == "memory":
        schedule = _memory_schedule(spec, campaign_seed, basis)
    elif spec.campaign_kind == "capacity":
        schedule = _capacity_schedule(spec, campaign_seed, basis)
    else:
        if (
            diagnostic_unqualified_host
            and spec.estimand == "symmetric_stack_pair"
        ):
            tail_durations = {
                scenario: 20 if scenario == "loss_recovery" else 10
                for scenario in spec.scenarios
            }
        schedule = _generic_schedule(
            spec,
            campaign_seed,
            basis,
            tail_durations_seconds=tail_durations,
        )
    _assign_missing_schedule_lanes(schedule, campaign_seed, lane_count)
    if interoperability_artifact is not None:
        schedule["native_interoperability_artifact_sha256"] = (
            interoperability_artifact.artifact_hash
        )
    if diagnostic_manifest is not None:
        schedule["diagnostic_unqualified_host"] = diagnostic_manifest
    schedule_digest = make_schedule_hash(schedule)

    primary_trials = sum(
        len(block["trials"])
        for block in schedule["blocks"]
        if block["slot"] == "primary"
        and block.get("phase") != "parallel_balance_control"
    )
    if spec.campaign_kind == "capacity":
        search_trials = sum(
            len(block["trials"])
            for block in schedule["blocks"]
            if block["slot"] == "primary" and block.get("phase") == "capacity_search"
        )
        branch_sizes: dict[tuple[str, int], int] = {}
        for block in schedule["blocks"]:
            if block["slot"] == "primary" and block.get("phase") == "capacity_confirmation":
                key = (str(block["branch_group"]), int(block["branch_candidate"]))
                branch_sizes[key] = branch_sizes.get(key, 0) + len(block["trials"])
        by_group: dict[str, list[int]] = {}
        for (group, _candidate), count in branch_sizes.items():
            by_group.setdefault(group, []).append(count)
        primary_trials = search_trials + sum(max(counts) for counts in by_group.values())
    maximum_ids = sum(len(block["trials"]) for block in schedule["blocks"])
    inferential_maximum_ids = sum(
        len(block["trials"])
        for block in schedule["blocks"]
        if block.get("phase") != "parallel_balance_control"
    )
    if (primary_trials, inferential_maximum_ids) != (
        spec.expected_cardinality.planned_trials,
        spec.expected_cardinality.maximum_trial_ids,
    ):
        raise RunnerError(
            f"frozen schedule cardinality mismatch: expected "
            f"{spec.expected_cardinality.planned_trials}/"
            f"{spec.expected_cardinality.maximum_trial_ids}, got "
            f"{primary_trials}/{inferential_maximum_ids}"
        )
    campaign_digest = make_campaign_id(spec_digest, manifest_digest, analysis_digest, schedule_digest)
    journal = Journal.create_run_directory(
        run_dir,
        spec_bytes=canonical_bytes(spec.raw),
        manifest_bytes=canonical_bytes(manifest.raw),
    )
    try:
        retry_count = int(spec.raw["schedule"]["dormant_retry_per_microblock"])
        manifests = {
            "identity": (manifest_digest, manifest.raw),
            "analysis": (analysis_digest, spec.raw["analysis"]),
            "schedule": (schedule_digest, schedule),
        }
        if diagnostic_manifest is not None:
            diagnostic_digest = hashlib.sha256(
                canonical_bytes(diagnostic_manifest)
            ).hexdigest()
            manifests["diagnostic-unqualified-host"] = (
                diagnostic_digest,
                diagnostic_manifest,
            )
        journal.create_campaign(
            campaign_id=campaign_digest,
            spec_hash=spec_digest,
            identity_manifest_hash=manifest_digest,
            analysis_plan_hash=analysis_digest,
            schedule_hash=schedule_digest,
            expected_cardinality=spec.expected_cardinality.committed_samples,
            manifests=manifests,
            session_count=spec.expected_cardinality.sessions,
            retry_per_microblock=retry_count,
            campaign_kind="capacity" if spec.campaign_kind == "capacity" else "fixed",
            maximum_cardinality=maximum_ids,
        )
        for kind, stored in sorted(qualification_artifacts.items()):
            journal.store_artifact(
                campaign_digest,
                f"qualification/{kind}.json",
                stored.path.read_bytes(),
                media_type="application/json",
            )
        if diagnostic_manifest is not None:
            journal.store_artifact(
                campaign_digest,
                "diagnostic-unqualified-host.json",
                canonical_bytes(diagnostic_manifest),
                media_type="application/json",
            )
            assert qualification_store is not None
            authorization = diagnostic_manifest["authorization"]
            authorization_path = (
                qualification_store
                / str(authorization["artifact_kind"])
                / str(authorization["identity_hash"])
                / f"{authorization['artifact_hash']}.json"
            )
            try:
                authorization_content = authorization_path.read_bytes()
            except OSError as exc:
                raise RunnerError(
                    "diagnostic host-failure authorization artifact is unavailable"
                ) from exc
            if (
                hashlib.sha256(authorization_content).hexdigest()
                != authorization["content_sha256"]
            ):
                raise RunnerError(
                    "diagnostic host-failure authorization checksum differs"
                )
            journal.store_artifact(
                campaign_digest,
                "qualification/diagnostic-physical-failure-authorization.json",
                authorization_content,
                media_type="application/json",
            )
        if interoperability_artifact is not None:
            assert interoperability_artifact.path is not None
            journal.store_artifact(
                campaign_digest,
                "qualification/native-interoperability.json",
                interoperability_artifact.path.read_bytes(),
                media_type="application/json",
            )
        _freeze_into_journal(
            journal,
            campaign=campaign_digest,
            schedule=schedule,
            expected_cardinality=spec.expected_cardinality.committed_samples,
            retry_per_microblock=retry_count,
        )
        journal.store_artifact(campaign_digest, "campaign-seed.bin", campaign_seed)
        if methodology_evidence is not None:
            journal.store_artifact(
                campaign_digest,
                "methodology/pre-v2.1-runtime-policy.json",
                methodology_evidence,
                media_type="application/json",
            )
        journal.store_artifact(
            campaign_digest,
            "runtime/planning.json",
            canonical_bytes(
                {
                    "schema_version": "quicperf.runtime.v1",
                    "campaign_id": campaign_digest,
                    "phase": "planning",
                    "runtime": {
                        "wall_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                        - planning_started_raw_ns,
                        "cpu_ns": time.process_time_ns() - planning_cpu_started_ns,
                    },
                }
            ),
            media_type="application/json",
        )
        journal.integrity_check()
    finally:
        journal.close()
    return CreatedCampaign(campaign_digest, schedule_digest, primary_trials, maximum_ids, run_dir)


def campaign_identity(journal: Journal) -> dict[str, Any]:
    row = journal.connection.execute("SELECT * FROM campaign").fetchone()
    if row is None:
        raise RunnerError("journal contains no campaign")
    return dict(row)


def campaign_status(run_dir: Path) -> dict[str, Any]:
    with Journal(run_dir, writable=False) as journal:
        campaign = campaign_identity(journal)
        state_counts = {
            row["state"]: row["count"]
            for row in journal.connection.execute("SELECT state, COUNT(*) AS count FROM trial GROUP BY state ORDER BY state")
        }
        sessions = [dict(row) for row in journal.connection.execute(
            "SELECT s.session_number, s.status, "
            "SUM(CASE WHEN m.slot='primary' AND m.status NOT IN "
            "('dormant_candidate','not_selected') AND "
            "m.phase!='parallel_balance_control' THEN 1 ELSE 0 END) AS planned, "
            "SUM(CASE WHEN t.warmup=0 AND EXISTS(SELECT 1 FROM committed_sample cs "
            "WHERE cs.logical_trial_id=t.logical_trial_id) AND "
            "m.phase!='parallel_balance_control' THEN 1 ELSE 0 END) AS committed "
            "FROM session s LEFT JOIN microblock m ON m.campaign_id=s.campaign_id "
            "AND m.session_number=s.session_number LEFT JOIN trial t ON "
            "t.microblock_id=m.microblock_id AND m.slot='primary' AND m.status "
            "NOT IN ('dormant_candidate','not_selected') GROUP BY "
            "s.session_number, s.status ORDER BY s.session_number"
        )]
        committed = int(
            journal.connection.execute(
                """
                SELECT COUNT(*) FROM committed_sample s
                JOIN trial t USING(trial_id)
                JOIN microblock m USING(microblock_id)
                WHERE m.phase!='parallel_balance_control'
                """
            ).fetchone()[0]
        )
        if campaign["campaign_kind"] == "capacity":
            expected = int(journal.connection.execute(
                "SELECT COUNT(*) FROM trial t JOIN microblock m USING(microblock_id) "
                "WHERE t.campaign_id=? AND m.slot='primary' AND m.status NOT IN "
                "('dormant_candidate','not_selected') AND t.warmup=0",
                (campaign["campaign_id"],),
            ).fetchone()[0])
            unfinished = int(journal.connection.execute(
                "SELECT COUNT(*) FROM microblock WHERE campaign_id=? AND status IN "
                "('active','dormant_candidate')",
                (campaign["campaign_id"],),
            ).fetchone()[0])
        else:
            expected = int(campaign["expected_cardinality"])
            unfinished = int(committed != expected)
        overall_status = (
            "nonpublishable"
            if any(item["status"] == "nonpublishable" for item in sessions)
            else "complete"
            if committed == expected and unfinished == 0
            else "incomplete"
        )
        return {
            "campaign_id": campaign["campaign_id"],
            "status": overall_status,
            "expected_samples": expected,
            "committed_samples": committed,
            "trial_states": state_counts,
            "sessions": sessions,
        }


def _persisted_run_identity(journal: Journal, run_dir: Path) -> tuple[ExperimentSpecV2, ImmutableIdentityManifest, dict[str, Any]]:
    spec = load_experiment_spec(run_dir / "spec.json")
    manifest = load_manifest(run_dir / "manifest.json")
    spec_digest = spec_hash(spec.raw)
    manifest_digest = manifest_hash(manifest)
    analysis_digest = analysis_plan_hash(spec.raw["analysis"])
    row = journal.connection.execute(
        "SELECT manifest_hash, canonical_json FROM manifest WHERE kind='schedule'"
    ).fetchone()
    if row is None:
        raise IdentityMismatchError("run journal has no frozen schedule")
    schedule = loads_strict(row["canonical_json"])
    schedule_digest = make_schedule_hash(schedule)
    if schedule_digest != row["manifest_hash"]:
        raise IdentityMismatchError("stored schedule content does not match its identity")
    campaign_digest = make_campaign_id(spec_digest, manifest_digest, analysis_digest, schedule_digest)
    journal.assert_identity(
        campaign_id=campaign_digest,
        spec_hash=spec_digest,
        identity_manifest_hash=manifest_digest,
        analysis_plan_hash=analysis_digest,
        schedule_hash=schedule_digest,
    )
    if canonical_bytes(spec.raw) != (run_dir / "spec.json").read_bytes():
        raise IdentityMismatchError("spec.json is not the exact frozen canonical document")
    if canonical_bytes(manifest.raw) != (run_dir / "manifest.json").read_bytes():
        raise IdentityMismatchError("manifest.json is not the exact frozen canonical document")
    return spec, manifest, schedule


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _binary_entries(manifest: ImmutableIdentityManifest) -> dict[str, Mapping[str, Any]]:
    return {str(item["name"]): item for item in manifest.binaries}


def _frozen_lane(manifest: ImmutableIdentityManifest, lane: int) -> LaneTopology:
    matches = [item for item in manifest.host_policy["lane_layout"] if int(item["lane"]) == lane]
    if len(matches) != 1:
        raise IdentityMismatchError(f"frozen lane {lane} is absent or duplicated")
    item = matches[0]
    return LaneTopology(
        lane,
        int(item["server_cpu"]),
        tuple(int(cpu) for cpu in item["client_cpus"]),
        tuple(int(cpu) for cpu in item["housekeeping_cpus"]),
    )


def _reattest_run_environment(
    root: Path,
    spec: ExperimentSpecV2,
    frozen: ImmutableIdentityManifest,
) -> dict[str, Path]:
    entries = _binary_entries(frozen)
    binary_parents = {Path(str(entry["path"])).parent for entry in entries.values()}
    if len(binary_parents) != 1:
        raise IdentityMismatchError("frozen endpoint binaries do not share one attested directory")
    observed = collect_manifest(root, spec, bin_dir=next(iter(binary_parents)))
    if canonical_bytes(observed.raw) != canonical_bytes(frozen.raw):
        raise IdentityMismatchError("current source/build/binary/host identity differs from the frozen run")
    return {name: _assert_binary_unchanged(entry) for name, entry in entries.items()}


def _assert_binary_unchanged(entry: Mapping[str, Any]) -> Path:
    path = Path(str(entry["path"]))
    if not path.is_file() or not os.access(path, os.X_OK):
        raise IdentityMismatchError(f"frozen binary is missing or nonexecutable: {path}")
    if _sha256_file(path) != entry["sha256"]:
        raise IdentityMismatchError(f"frozen binary changed: {path}")
    return path


def _expect(
    channel: SeqPacketChannel,
    expected: MessageType,
    *,
    timeout_ns: int,
    trial_id: bytes | None = None,
) -> Packet:
    channel.sock.settimeout(timeout_ns / 1_000_000_000)
    try:
        packet = channel.receive(expected_trial_id=trial_id)
    except socket.timeout as exc:
        raise EndpointRunError(f"timeout_waiting_for_{expected.name.lower()}") from exc
    except (OSError, ProtocolError) as exc:
        raise EndpointRunError(f"control_protocol_error:{exc}") from exc
    if packet.message_type is MessageType.UNSUPPORTED:
        raise EndpointRunError(
            f"unsupported:{packet.fields['reason']}", terminal_state="unsupported"
        )
    if packet.message_type is MessageType.ERROR:
        raise EndpointRunError(f"endpoint_error:{packet.fields['reason']}")
    if packet.message_type is MessageType.ARM_REJECTED:
        raise EndpointRunError(
            "arm_control_window_rejected",
            detail=canonical_bytes(
                {
                    "reason": str(packet.fields["reason"]),
                    "raw_now_ns": int(packet.fields["raw_now_ns"]),
                }
            ).decode("utf-8"),
            infrastructure_transient=True,
            terminal_state="invalid",
        )
    if packet.message_type is not expected:
        raise EndpointRunError(
            f"out_of_order_message:{packet.message_type.name.lower()}_while_waiting_for_{expected.name.lower()}"
        )
    return packet


def _send(channel: SeqPacketChannel, message_type: MessageType, fields: dict[str, Any]) -> None:
    try:
        channel.send(message_type, fields)
    except (OSError, ProtocolError) as exc:
        raise EndpointRunError(f"control_protocol_error:{exc}") from exc


def _attest_hello(
    channel: SeqPacketChannel,
    *,
    role: str,
    timeout_ns: int,
    expected_build_id: str | None,
    required_backend: str | None = None,
    required_scenario: str | None = None,
) -> Mapping[str, Any]:
    hello = _expect(channel, MessageType.HELLO, timeout_ns=timeout_ns)
    if hello.fields["role"] != role or hello.fields["control_version"] != 1:
        raise EndpointRunError("hello_attestation_mismatch")
    if expected_build_id is not None and hello.fields["build_id"].hex() != expected_build_id:
        raise EndpointRunError("endpoint_build_id_mismatch")
    capabilities = _expect(channel, MessageType.CAPABILITIES, timeout_ns=timeout_ns)
    if capabilities.fields["build_id"] != hello.fields["build_id"]:
        raise EndpointRunError("capability_build_id_mismatch")
    _attest_capabilities(
        capabilities.fields,
        role=role,
        required_backend=required_backend,
        required_scenario=required_scenario,
    )
    return capabilities.fields


SCENARIO_CAPABILITY_IDS = {
    "download": "1",
    "upload": "2",
    "multistream_download": "3",
    "multistream_upload": "4",
    "bidi": "5",
    "loss_recovery": "6",
    "flow_control": "7",
    "small_payload_pps": "8",
    "datagram": "9",
    "reqresp": "10",
    "stream_churn": "11",
    "close_reset_cleanup": "12",
    "connect": "13",
    "resumed_connect": "14",
    "zero_rtt_reqresp": "15",
    "memory_curve": "16",
}


def _attest_capabilities(
    capabilities: Mapping[str, Any],
    *,
    role: str,
    required_backend: str | None,
    required_scenario: str | None,
) -> None:
    # ``describe`` is a control-plane process role.  CAPABILITIES.roles lists
    # the operational endpoint roles that this binary can later start.
    if role != "describe" and role not in str(capabilities["roles"]).split(","):
        raise EndpointRunError("endpoint_role_not_attested")
    if capabilities["protocol_version"] != 1:
        raise EndpointRunError("endpoint_protocol_version_mismatch")
    if required_backend is not None and required_backend not in str(capabilities["backends"]).split(","):
        raise EndpointRunError("required_backend_not_attested", terminal_state="unsupported")
    if required_scenario is not None:
        advertised_scenarios = str(capabilities["scenarios"]).split(",")
        if (
            "all" not in advertised_scenarios
            and SCENARIO_CAPABILITY_IDS.get(required_scenario)
            not in advertised_scenarios
        ):
            raise EndpointRunError("required_scenario_not_attested", terminal_state="unsupported")


def _endpoint_command(
    binary: Path,
    role: str,
    override: tuple[str, ...] | None,
) -> list[str]:
    if override is not None:
        return [*override, "worker", f"--role={role}"]
    return [str(binary), "worker", f"--role={role}"]


def _worker_reuse_eligible(campaign_kind: str, scenario: str) -> bool:
    return campaign_kind != "memory" and worker_reuse_eligible_scenario(scenario)


def _persistent_worker_enabled(
    spec: ExperimentSpecV2, *, diagnostic_unqualified_host: bool = False
) -> bool:
    """Return the frozen process treatment; reset integrity is checked per trial."""

    return (
        not diagnostic_unqualified_host
        and spec.raw["schedule"]["worker_process_policy"] == "persistent_reset"
    )


@dataclass(frozen=True)
class _WorkerKey:
    binary: str
    role: str
    backend: str
    lane: int
    cpuset: tuple[int, ...]
    cgroup: str
    network_namespace: str


@dataclass
class _WorkerSession:
    key: _WorkerKey
    managed: ManagedProcess
    channel: SeqPacketChannel
    capabilities: Mapping[str, Any]
    generation: int
    in_use: bool = True


class _WorkerPool:
    """Exact-placement persistent workers for reuse-qualified steady-state trials."""

    def __init__(
        self,
        *,
        root: Path,
        endpoint_override: tuple[str, ...] | None,
        environment: Mapping[str, str],
        active_processes: dict[int, ManagedProcess],
        active_processes_lock: threading.Lock,
    ) -> None:
        self.root = root
        self.endpoint_override = endpoint_override
        self.environment = dict(environment)
        self.active_processes = active_processes
        self.active_processes_lock = active_processes_lock
        self.supervisor = Supervisor()
        self.sessions: dict[_WorkerKey, _WorkerSession] = {}
        self.lock = threading.Lock()
        self.next_generation = 1

    @staticmethod
    def key(
        *,
        binary: Path,
        role: str,
        backend: str,
        lane: int,
        cpuset: Iterable[int] | None,
        cgroup: Path | None,
        network_namespace: Path | None = None,
    ) -> _WorkerKey:
        return _WorkerKey(
            str(binary.resolve()),
            role,
            backend,
            lane,
            tuple(sorted(set(cpuset or ()))),
            "" if cgroup is None else str(cgroup.resolve()),
            "" if network_namespace is None else str(network_namespace.resolve()),
        )

    def _register(self, managed: ManagedProcess) -> None:
        with self.active_processes_lock:
            self.active_processes[managed.process.pid] = managed

    def _retire(self, session: _WorkerSession, *, terminate: bool) -> None:
        managed = session.managed
        if terminate and managed.process.poll() is None:
            try:
                managed.terminate()
            except Exception as exc:
                raise EndpointRunError(
                    "reuse_worker_survived_bounded_cleanup"
                ) from exc
        if managed.process.poll() is None:
            raise EndpointRunError("reuse_worker_is_still_alive_during_retirement")
        with self.active_processes_lock:
            self.active_processes.pop(managed.process.pid, None)
        managed.close()
        try:
            self.supervisor.processes.remove(managed)
        except ValueError:
            pass

    def _shutdown_idle(self, session: _WorkerSession) -> None:
        if session.in_use:
            raise EndpointRunError("reuse_worker_is_active_during_shutdown")
        managed = session.managed
        try:
            _send(session.channel, MessageType.SHUTDOWN, {})
            _expect(
                session.channel,
                MessageType.SHUTDOWN_ACK,
                timeout_ns=1_000_000_000,
            )
            try:
                return_code = managed.process.wait(timeout=1.0)
            except subprocess.TimeoutExpired as exc:
                raise EndpointRunError(
                    "reuse_worker_did_not_exit_after_shutdown_ack"
                ) from exc
            if return_code != 0:
                raise EndpointRunError(
                    f"reuse_worker_nonzero_exit:{return_code}"
                )
        except BaseException:
            self._retire(session, terminate=True)
            raise
        self._retire(session, terminate=False)

    def acquire(
        self,
        *,
        binary: Path,
        entry: Mapping[str, Any],
        role: str,
        backend: str,
        scenario: str,
        lane: int,
        cpuset: Iterable[int] | None,
        cgroup: Path | None,
        network_namespace: Path | None,
        log_path: Path,
        timeout_ns: int,
    ) -> _WorkerSession:
        key = self.key(
            binary=binary,
            role=role,
            backend=backend,
            lane=lane,
            cpuset=cpuset,
            cgroup=cgroup,
            network_namespace=network_namespace,
        )
        with self.lock:
            session = self.sessions.get(key)
            if session is not None:
                if session.in_use:
                    raise EndpointRunError("worker_reuse_key_is_already_active")
                if not session.managed.alive():
                    self.sessions.pop(key)
                    self._retire(session, terminate=False)
                    raise EndpointRunError("reuse_worker_exited_between_trials")
                _attest_capabilities(
                    session.capabilities,
                    role=role,
                    required_backend=backend,
                    required_scenario=scenario,
                )
                session.in_use = True
                return session

            placement_conflicts = tuple(
                existing
                for existing_key, existing in self.sessions.items()
                if key.cgroup
                and existing_key != key
                and existing_key.cgroup == key.cgroup
            )
            if any(existing.in_use for existing in placement_conflicts):
                raise EndpointRunError("reuse_worker_cgroup_is_already_active")
            for existing in placement_conflicts:
                self.sessions.pop(existing.key)
                self._shutdown_idle(existing)

            managed = self.supervisor.spawn(
                _endpoint_command(binary, role, self.endpoint_override),
                log_path=log_path,
                cwd=self.root,
                environment=self.environment,
                pass_control_argument=True,
                cpu_affinity=cpuset,
                cgroup=cgroup,
                network_namespace=network_namespace,
            )
            self._register(managed)
            session = _WorkerSession(
                key,
                managed,
                SeqPacketChannel(managed.control),
                {},
                self.next_generation,
            )
            self.next_generation += 1
            self.sessions[key] = session
            try:
                session.capabilities = _attest_hello(
                    session.channel,
                    role=role,
                    timeout_ns=timeout_ns,
                    expected_build_id=(
                        None
                        if self.endpoint_override is not None
                        else str(entry["elf_build_id"])
                    ),
                    required_backend=backend,
                    required_scenario=scenario,
                )
                if self.endpoint_override is None:
                    attest_process_libraries(
                        self.root,
                        managed.process.pid,
                        binary,
                        entry["expected_loaded_libraries"],
                    )
            except ManifestCollectionError as exc:
                try:
                    self._retire(session, terminate=True)
                finally:
                    if not session.managed.alive():
                        self.sessions.pop(key, None)
                raise EndpointRunError(
                    f"loaded_library_attestation_failed:{exc}",
                    terminal_state="invalid",
                ) from exc
            except BaseException:
                try:
                    self._retire(session, terminate=True)
                finally:
                    if not session.managed.alive():
                        self.sessions.pop(key, None)
                raise
            return session

    @staticmethod
    def _inventory(packet: Packet) -> dict[str, int]:
        return {
            field: int(packet.fields[field])
            for field in (
                "live_connections",
                "live_streams",
                "live_tickets",
                "work_inventory",
            )
        }

    def _receive_reset(self, session: _WorkerSession, trial_id: bytes) -> Mapping[str, int]:
        if not session.in_use or not session.managed.alive():
            raise EndpointRunError("reuse_worker_not_alive_at_reset")
        acknowledgement = _expect(
            session.channel,
            MessageType.RESET_ACK,
            timeout_ns=2_000_000_000,
            trial_id=trial_id,
        )
        inventory = self._inventory(acknowledgement)
        if any(inventory.values()):
            raise EndpointRunError("reuse_worker_reset_inventory_not_empty")
        if not session.managed.alive():
            raise EndpointRunError("reuse_worker_exited_after_reset_ack")
        return inventory

    def reset(self, session: _WorkerSession, trial_id: bytes) -> Mapping[str, int]:
        _send(session.channel, MessageType.RESET, {"trial_id": trial_id})
        return self._receive_reset(session, trial_id)

    def exercise_and_reset(
        self,
        server: _WorkerSession,
        client: _WorkerSession,
        trial_id: bytes,
        *,
        deadline_raw_ns: int,
    ) -> Mapping[str, Mapping[str, Mapping[str, int]]]:
        sessions = {"server": server, "reference_client": client}
        fields = {
            "trial_id": trial_id,
            "exercise_deadline_raw_ns": deadline_raw_ns,
        }
        for session in sessions.values():
            if not session.in_use or not session.managed.alive():
                raise EndpointRunError("reuse_worker_not_alive_at_exercise")
            _send(session.channel, MessageType.EXERCISE, fields)
        created: dict[str, Mapping[str, int]] = {}
        for role, session in sessions.items():
            packet = _expect(
                session.channel,
                MessageType.EXERCISED,
                timeout_ns=5_000_000_000,
                trial_id=trial_id,
            )
            inventory = self._inventory(packet)
            if inventory["live_connections"] <= 0 or inventory["work_inventory"] <= 0:
                raise EndpointRunError(f"reuse_worker_{role}_exercise_created_no_live_work")
            created[role] = inventory
        for session in sessions.values():
            _send(session.channel, MessageType.RESET, {"trial_id": trial_id})
        reset = {
            role: self._receive_reset(session, trial_id)
            for role, session in sessions.items()
        }
        return {"created": created, "reset": reset}

    def release(self, session: _WorkerSession) -> None:
        if not session.in_use:
            raise EndpointRunError("reuse_worker_double_release")
        session.in_use = False

    def abort(self, session: _WorkerSession) -> None:
        with self.lock:
            if not session.in_use:
                return
            self._retire(session, terminate=True)
            session.in_use = False
            if self.sessions.get(session.key) is session:
                self.sessions.pop(session.key)

    def abandon_terminated(self) -> None:
        """Forget workers already handled by the shared bounded interrupt cleanup."""

        with self.lock:
            sessions = tuple(self.sessions.values())
            self.sessions.clear()
        for session in sessions:
            if session.managed.process.poll() is None:
                raise EndpointRunError("active_reuse_worker_missing_from_shared_cleanup")
            self._retire(session, terminate=False)

    def close(self) -> None:
        with self.lock:
            sessions = tuple(self.sessions.values())
            self.sessions.clear()
        failures: list[str] = []
        for session in sessions:
            managed = session.managed
            try:
                if session.in_use:
                    managed.terminate()
                else:
                    _send(session.channel, MessageType.SHUTDOWN, {})
                    _expect(
                        session.channel,
                        MessageType.SHUTDOWN_ACK,
                        timeout_ns=1_000_000_000,
                    )
                    try:
                        return_code = managed.process.wait(timeout=1.0)
                    except subprocess.TimeoutExpired as exc:
                        raise EndpointRunError(
                            "reuse_worker_did_not_exit_after_shutdown_ack"
                        ) from exc
                    if return_code != 0:
                        raise EndpointRunError(
                            f"reuse_worker_nonzero_exit:{return_code}"
                        )
            except BaseException as exc:
                failures.append(str(exc))
                try:
                    self._retire(session, terminate=True)
                except BaseException as cleanup_exc:
                    failures.append(str(cleanup_exc))
            else:
                self._retire(session, terminate=False)
        if failures:
            raise EndpointRunError(";".join(failures))


def _receive_result_stream(
    channel: SeqPacketChannel,
    *,
    source: str,
    trial_id: bytes,
    start_timeout_ns: int,
    measurement_ns: int,
    completion_bound_ns: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    started = _expect(
        channel,
        MessageType.MEASUREMENT_STARTED,
        timeout_ns=start_timeout_ns,
        trial_id=trial_id,
    )
    events = [
        {
            "source": source,
            "event_sequence": 0,
            "event_type": "measurement_started",
            "raw_time_ns": started.fields["raw_now_ns"],
            "payload": {},
        }
    ]
    progress: list[dict[str, Any]] = []
    while True:
        channel.sock.settimeout((measurement_ns + completion_bound_ns + 2_000_000_000) / 1_000_000_000)
        try:
            packet = channel.receive(expected_trial_id=trial_id)
        except socket.timeout as exc:
            raise EndpointRunError("timeout_waiting_for_measurement_completion") from exc
        except (OSError, ProtocolError) as exc:
            raise EndpointRunError(f"control_protocol_error:{exc}") from exc
        if packet.message_type is MessageType.PROGRESS:
            expected_index = len(progress)
            if packet.fields["event_index"] != expected_index:
                raise EndpointRunError("progress_sequence_mismatch")
            progress.append(packet.fields)
            events.append(
                {
                    "source": source,
                    "event_sequence": expected_index + 1,
                    "event_type": "progress",
                    "raw_time_ns": packet.fields["raw_now_ns"],
                    "payload": {
                        "validated_units": packet.fields["validated_units"],
                        "blocked": packet.fields["blocked"],
                    },
                }
            )
            continue
        if packet.message_type is not MessageType.MEASUREMENT_STOPPED:
            raise EndpointRunError(f"out_of_order_message:{packet.message_type.name.lower()}")
        stopped = packet
        break
    if len(progress) != 10:
        raise EndpointRunError("progress_coverage_is_not_exactly_ten_buckets")
    completion = _expect(
        channel, MessageType.COMPLETION_ACK, timeout_ns=completion_bound_ns, trial_id=trial_id
    )
    result_packet = _expect(
        channel, MessageType.RESULT, timeout_ns=5_000_000_000, trial_id=trial_id
    )
    try:
        result = loads_strict(result_packet.fields["result_json"])
    except Exception as exc:
        raise EndpointRunError(f"malformed_result:{exc}") from exc
    if not isinstance(result, dict) or result.get("trial_id") != trial_id.hex():
        raise EndpointRunError("result_identity_mismatch")
    _expand_endpoint_tail_rows(result)
    result["progress"] = progress
    result["measurement_started_raw_ns"] = started.fields["raw_now_ns"]
    result["measurement_stopped_raw_ns"] = stopped.fields["raw_now_ns"]
    result["completion_counters_json"] = completion.fields["counters_json"]
    return result, events


def _measurement_started_timeout_ns(
    measurement_start_raw_ns: int, now_raw_ns: int
) -> int:
    return max(
        2_000_000_000,
        measurement_start_raw_ns - now_raw_ns + 2_000_000_000,
    )


def _expand_endpoint_tail_rows(result: dict[str, Any]) -> None:
    """Expand the bounded native RESULT wire form into strict result objects."""
    tail = result.get("tail")
    if not isinstance(tail, dict) or not isinstance(tail.get("operations"), list):
        return
    rows = tail["operations"]
    if not rows or isinstance(rows[0], Mapping):
        return
    base = result.get("global_start_raw_ns")
    if isinstance(base, bool) or not isinstance(base, int) or not 0 <= base <= 0xFFFF_FFFF_FFFF_FFFF:
        raise EndpointRunError("malformed_tail_wire_base")
    expanded: list[dict[str, int]] = []
    for row in rows:
        if not isinstance(row, list) or len(row) != 3:
            raise EndpointRunError("malformed_tail_wire_row")
        sequence = _nonnegative_u64(row[0], "wire.operation_sequence")
        start_offset = _nonnegative_u64(row[1], "wire.start_offset_ns")
        latency = _nonnegative_u64(row[2], "wire.latency_ns")
        if base + start_offset > 0xFFFF_FFFF_FFFF_FFFF:
            raise EndpointRunError("malformed_tail_wire_start_overflow")
        start = base + start_offset
        if start + latency > 0xFFFF_FFFF_FFFF_FFFF:
            raise EndpointRunError("malformed_tail_wire_terminal_overflow")
        expanded.append(
            {
                "operation_sequence": sequence,
                "start_raw_ns": start,
                "terminal_raw_ns": start + latency,
                "latency_ns": latency,
            }
        )
    tail["operations"] = expanded


def _decimal_rate(numerator: int, denominator: int) -> str:
    with localcontext() as context:
        context.prec = 40
        value = Decimal(numerator) * Decimal(1_000_000_000) / Decimal(denominator)
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return normalize_decimal(text or "0")


def _decimal_text(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return normalize_decimal(text or "0")


def _cleanup_evidence(
    server_result: Mapping[str, Any],
    client_result: Mapping[str, Any],
    denominator_raw_ns: int,
) -> dict[str, Any]:
    raw = client_result.get("cleanup_strata")
    if (
        not isinstance(raw, list)
        or len(raw) != 4
        or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in raw)
    ):
        raise EndpointRunError("malformed_close_reset_cleanup_strata")
    counts = tuple(int(value) for value in raw)
    if min(counts) < 100:
        raise EndpointRunError("close_reset_cleanup_stratum_below_100")
    total = sum(counts)
    if (
        total != int(client_result["numerator"])
        or total != int(server_result["numerator"])
    ):
        raise EndpointRunError("close_reset_cleanup_strata_do_not_reconcile")
    if denominator_raw_ns <= 0:
        raise EndpointRunError("close_reset_cleanup_denominator_is_zero")
    labels = ("fin", "reset_stream", "stop_sending", "connection_close")
    with localcontext() as context:
        context.prec = 50
        scale = Decimal(1_000_000_000) / Decimal(denominator_raw_ns)
        product = Decimal(1)
        for count in counts:
            product *= Decimal(count)
        aggregate = product.sqrt().sqrt() * scale
        strata = {
            label: {
                "completed": count,
                "operations_per_second_decimal": _decimal_text(Decimal(count) * scale),
            }
            for label, count in zip(labels, counts, strict=True)
        }
    return {
        "strata": strata,
        "aggregate_geometric_mean_operations_per_second_decimal": _decimal_text(aggregate),
    }


_NEGOTIATED_BOOLEAN_FIELDS = frozenset(
    {
        "ack_frequency",
        "active_migration",
        "available",
        "hostname_verified",
        "matches",
        "one_use_tickets",
        "peer_certificate_verified",
    }
)
_NEGOTIATED_INTEGER_FIELDS = frozenset(
    {
        "ack_delay_exponent",
        "active_connection_id_limit",
        "connection_id_bytes",
        "connection_window_bytes",
        "datagram_max_frame_size",
        "initial_congestion_window_bytes",
        "max_ack_delay_ns",
        "max_bidi_streams",
        "max_idle_timeout_ns",
        "max_udp_payload_size",
        "max_uni_streams",
        "maximum_early_data_bytes",
        "quic_version",
        "stream_credit_replenish_below",
        "stream_window_bytes",
        "ticket_lifetime_ns",
    }
)
_NEGOTIATED_STRING_FIELDS = frozenset(
    {
        "alpn",
        "congestion_controller",
        "evidence_source",
        "mismatch_reason",
        "tls_cipher_suite",
        "tls_key_exchange",
        "tls_leaf_signature",
        "tls_version",
    }
)
_NEGOTIATED_FIELDS = (
    _NEGOTIATED_BOOLEAN_FIELDS
    | _NEGOTIATED_INTEGER_FIELDS
    | _NEGOTIATED_STRING_FIELDS
    | {"unavailable_fields"}
)


def _endpoint_negotiated(result: Mapping[str, Any], role: str) -> dict[str, Any]:
    value = result.get("negotiated")
    if not isinstance(value, Mapping) or set(value) != _NEGOTIATED_FIELDS:
        raise EndpointRunError(f"malformed_negotiated_settings:{role}")
    if any(not isinstance(value[field], bool) for field in _NEGOTIATED_BOOLEAN_FIELDS):
        raise EndpointRunError(f"malformed_negotiated_settings:{role}")
    if any(
        isinstance(value[field], bool)
        or not isinstance(value[field], int)
        or not 0 <= value[field] <= 0xFFFF_FFFF_FFFF_FFFF
        for field in _NEGOTIATED_INTEGER_FIELDS
    ):
        raise EndpointRunError(f"malformed_negotiated_settings:{role}")
    if any(not isinstance(value[field], str) for field in _NEGOTIATED_STRING_FIELDS):
        raise EndpointRunError(f"malformed_negotiated_settings:{role}")
    unavailable = value["unavailable_fields"]
    if (
        not isinstance(unavailable, list)
        or any(not isinstance(field, str) or not field for field in unavailable)
        or unavailable != sorted(set(unavailable))
    ):
        raise EndpointRunError(f"malformed_negotiated_settings:{role}")
    if bool(result.get("negotiated_settings_match")) != value["matches"]:
        raise EndpointRunError(f"negotiated_settings_summary_mismatch:{role}")
    return dict(value)


_TAIL_SCENARIOS = frozenset(
    {
        "small_payload_pps",
        "datagram",
        "reqresp",
        "stream_churn",
        "close_reset_cleanup",
        "connect",
        "resumed_connect",
        "zero_rtt_reqresp",
    }
)

_LOSS_PREFIX_LOCK = threading.Lock()
_LOSS_PREFIX_CACHE: OrderedDict[
    tuple[bytes, bool, int], array[int]
] = OrderedDict()


def _expected_loss_drops(
    trace_seed: bytes, *, measurement: bool, direction: int, packet_count: int
) -> int:
    if packet_count < 0 or packet_count > 0xFFFF_FFFF:
        raise EndpointRunError("loss_trace_packet_count_is_out_of_range")
    key = (trace_seed, measurement, direction)
    with _LOSS_PREFIX_LOCK:
        prefix = _LOSS_PREFIX_CACHE.get(key)
        if prefix is None:
            prefix = array("I", [0])
            _LOSS_PREFIX_CACHE[key] = prefix
        else:
            _LOSS_PREFIX_CACHE.move_to_end(key)
        while len(_LOSS_PREFIX_CACHE) > 8:
            _LOSS_PREFIX_CACHE.popitem(last=False)
        while len(prefix) <= packet_count:
            ordinal = len(prefix) - 1
            prefix.append(
                prefix[-1]
                + int(
                    loss_recovery_drop(
                        trace_seed,
                        measurement=measurement,
                        direction=direction,
                        packet_ordinal=ordinal,
                    )
                )
            )
        return int(prefix[packet_count])


def _loss_trace_gate(
    config: Mapping[str, Any],
    server_result: Mapping[str, Any],
    client_result: Mapping[str, Any],
    path_evidence: Mapping[str, Any],
) -> bool:
    fields = (
        "loss_packets_considered",
        "loss_packets_dropped",
        "loss_warmup_packets_considered",
        "loss_warmup_packets_dropped",
        "loss_measurement_packets_considered",
        "loss_measurement_packets_dropped",
    )
    if config["scenario"] != "loss_recovery":
        return (
            config["path_profile"] == "loopback"
            and path_evidence.get("profile") == "loopback"
            and path_evidence.get("directions") == {}
            and all(
            int(result.get(field, 0)) == 0
            for result in (server_result, client_result)
            for field in fields
            )
        )
    if config["path_profile"] != "loss_recovery_v1":
        return False
    try:
        trace_seed = bytes.fromhex(str(config["trace_seed"]))
    except (KeyError, ValueError) as exc:
        raise EndpointRunError("malformed_loss_trace_seed") from exc
    if len(trace_seed) != 32:
        raise EndpointRunError("malformed_loss_trace_seed")
    if (
        path_evidence.get("profile") != "loss_recovery_v1"
        or path_evidence.get("trace_seed") != trace_seed.hex()
        or not isinstance(path_evidence.get("trace_epoch_raw_ns"), int)
        or int(path_evidence["trace_epoch_raw_ns"]) <= 0
    ):
        return False
    directions = path_evidence.get("directions")
    if not isinstance(directions, Mapping) or set(directions) != {"0", "1"}:
        return False
    queue_fields = {"bytes", "packets", "drops", "overlimits", "requeues"}
    for direction in (0, 1):
        counters = directions[str(direction)]
        if not isinstance(counters, Mapping) or set(counters) != queue_fields:
            return False
        try:
            qdisc = {
                field: _nonnegative_u64(counters.get(field), f"qdisc_{field}")
                for field in queue_fields
            }
        except EndpointRunError:
            return False
        if qdisc["packets"] == 0 or qdisc["bytes"] == 0 or qdisc["drops"] != 0:
            return False
    for direction, result in enumerate((server_result, client_result)):
        if result.get("loss_direction") != direction:
            return False
        counters = {
            field: _nonnegative_u64(result.get(field), field) for field in fields
        }
        if (
            counters["loss_packets_considered"]
            != counters["loss_warmup_packets_considered"]
            + counters["loss_measurement_packets_considered"]
            or counters["loss_packets_dropped"]
            != counters["loss_warmup_packets_dropped"]
            + counters["loss_measurement_packets_dropped"]
            or counters["loss_warmup_packets_considered"] == 0
            or counters["loss_measurement_packets_considered"] == 0
            or counters["loss_measurement_packets_dropped"] == 0
        ):
            return False
        for measurement, prefix in (
            (False, "loss_warmup"),
            (True, "loss_measurement"),
        ):
            if counters[f"{prefix}_packets_dropped"] != _expected_loss_drops(
                trace_seed,
                measurement=measurement,
                direction=direction,
                packet_count=counters[f"{prefix}_packets_considered"],
            ):
                return False
    transport_loss = sum(
        _nonnegative_u64(result.get("transport_packets_lost"), "transport_packets_lost")
        for result in (server_result, client_result)
    )
    recovery_timers = sum(
        _nonnegative_u64(
            result.get("transport_timer_expirations"),
            "transport_timer_expirations",
        )
        for result in (server_result, client_result)
    )
    return transport_loss > 0 and recovery_timers > 0


def _nonnegative_u64(value: Any, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF
    ):
        raise EndpointRunError(f"malformed_tail_observations:{label}")
    return value


def _endpoint_tail(
    result: Mapping[str, Any], *, role: str, expected_ownership: str
) -> dict[str, Any]:
    ownership = result.get("tail_observation_ownership")
    tail = result.get("tail")
    if ownership != expected_ownership or not isinstance(tail, Mapping):
        raise EndpointRunError(f"tail_ownership_mismatch:{role}")
    required = {
        "started_operations",
        "failed_operations",
        "censored_operations",
        "prefixes",
        "histogram_resolution_ns",
        "operations",
    }
    if (
        set(tail) != required
        or not isinstance(tail["operations"], list)
        or not isinstance(tail["prefixes"], list)
    ):
        raise EndpointRunError(f"malformed_tail_observations:{role}")
    prefix_required = {
        "duration_seconds",
        "started_operations",
        "successful_operations",
        "failed_operations",
        "censored_operations",
        "p99_ns",
    }
    prefixes = []
    for index, prefix in enumerate(tail["prefixes"]):
        if not isinstance(prefix, Mapping) or set(prefix) != prefix_required:
            raise EndpointRunError(f"malformed_tail_observations:{role}.prefixes")
        values = {
            field: _nonnegative_u64(
                prefix[field], f"{role}.prefixes[{index}].{field}"
            )
            for field in prefix_required
        }
        if values["duration_seconds"] not in {2, 5, 10, 20} or (
            values["started_operations"]
            != values["successful_operations"]
            + values["failed_operations"]
            + values["censored_operations"]
        ):
            raise EndpointRunError(f"malformed_tail_observations:{role}.prefixes")
        if values["successful_operations"] > 0 and values["p99_ns"] == 0:
            raise EndpointRunError(f"malformed_tail_observations:{role}.prefixes")
        prefixes.append(values)
    if len(prefixes) != 4 or {
        prefix["duration_seconds"] for prefix in prefixes
    } != {2, 5, 10, 20}:
        raise EndpointRunError(f"malformed_tail_observations:{role}.prefixes")
    operations: list[dict[str, int]] = []
    seen: set[int] = set()
    previous: tuple[int, int] | None = None
    if len(tail["operations"]) > 1_024:
        raise EndpointRunError(f"tail_observation_bound_exceeded:{role}")
    for item in tail["operations"]:
        if not isinstance(item, Mapping) or set(item) != {
            "operation_sequence",
            "start_raw_ns",
            "terminal_raw_ns",
            "latency_ns",
        }:
            raise EndpointRunError(f"malformed_tail_observations:{role}")
        sequence = _nonnegative_u64(
            item["operation_sequence"], f"{role}.operation_sequence"
        )
        start = _nonnegative_u64(item["start_raw_ns"], f"{role}.start_raw_ns")
        terminal = _nonnegative_u64(
            item["terminal_raw_ns"], f"{role}.terminal_raw_ns"
        )
        latency = _nonnegative_u64(item["latency_ns"], f"{role}.latency_ns")
        order = (start, sequence)
        if (
            sequence in seen
            or (previous is not None and order <= previous)
            or terminal < start
            or terminal - start != latency
        ):
            raise EndpointRunError(f"malformed_tail_observations:{role}")
        seen.add(sequence)
        previous = order
        operations.append(
            {
                "operation_sequence": sequence,
                "start_raw_ns": start,
                "terminal_raw_ns": terminal,
                "latency_ns": latency,
            }
        )
    return {
        "started_operations": _nonnegative_u64(
            tail["started_operations"], f"{role}.started_operations"
        ),
        "failed_operations": _nonnegative_u64(
            tail["failed_operations"], f"{role}.failed_operations"
        ),
        "censored_operations": _nonnegative_u64(
            tail["censored_operations"], f"{role}.censored_operations"
        ),
        "histogram_resolution_ns": _nonnegative_u64(
            tail["histogram_resolution_ns"], f"{role}.histogram_resolution_ns"
        ),
        "prefixes": sorted(prefixes, key=lambda item: item["duration_seconds"]),
        "operations": operations,
    }


def _construct_tail_evidence(
    scenario: str,
    campaign_kind: str,
    server_result: Mapping[str, Any],
    client_result: Mapping[str, Any],
) -> dict[str, Any] | None:
    if campaign_kind != "tail":
        return None
    if scenario not in _TAIL_SCENARIOS:
        raise EndpointRunError("tail_campaign_scenario_mismatch")
    if scenario == "small_payload_pps":
        starts = _endpoint_tail(
            client_result,
            role="reference_client",
            expected_ownership="sender_starts",
        )
        terminals = _endpoint_tail(
            server_result,
            role="server",
            expected_ownership="receiver_terminals",
        )
        if starts["operations"]:
            raise EndpointRunError(
                "small_payload_sender_emitted_terminal_observations"
            )
        successful = terminals["prefixes"][-1]["successful_operations"]
        failed = terminals["failed_operations"]
        if successful > starts["started_operations"] or (
            failed > starts["started_operations"] - successful
        ):
            raise EndpointRunError("small_payload_terminal_counters_exceed_starts")
        tail = {
            "started_operations": starts["started_operations"],
            "failed_operations": failed,
            "censored_operations": (
                starts["started_operations"] - successful - failed
            ),
            "histogram_resolution_ns": max(
                starts["histogram_resolution_ns"],
                terminals["histogram_resolution_ns"],
            ),
            "prefixes": [],
            "operations": terminals["operations"],
        }
        for start, terminal in zip(
            starts["prefixes"], terminals["prefixes"], strict=True
        ):
            prefix_successful = terminal["successful_operations"]
            prefix_failed = terminal["failed_operations"]
            prefix_started = start["started_operations"]
            if (
                start["duration_seconds"] != terminal["duration_seconds"]
                or prefix_successful > prefix_started
                or prefix_failed > prefix_started - prefix_successful
            ):
                raise EndpointRunError(
                    "small_payload_prefix_terminal_counters_exceed_starts"
                )
            tail["prefixes"].append(
                {
                    **terminal,
                    "started_operations": prefix_started,
                    "censored_operations": (
                        prefix_started - prefix_successful - prefix_failed
                    ),
                }
            )
    else:
        tail = _endpoint_tail(
            client_result,
            role="reference_client",
            expected_ownership="complete",
        )
        if (
            server_result.get("tail_observation_ownership") != "none"
            or server_result.get("tail") is not None
        ):
            raise EndpointRunError("tail_ownership_mismatch:server")
    if tail["histogram_resolution_ns"] <= 0:
        raise EndpointRunError(
            "malformed_tail_observations:histogram_resolution_ns"
        )
    accounted = (
        len(tail["operations"])
        + tail["failed_operations"]
        + tail["censored_operations"]
    )
    if tail["started_operations"] < accounted:
        raise EndpointRunError("tail_operation_counters_do_not_reconcile")
    return tail


def _fixed_window_progress(
    *,
    scenario: str,
    numerator: int,
    measurement_start_raw_ns: int,
    measurement_end_raw_ns: int,
    server_result: Mapping[str, Any],
    client_result: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    """Validate the exact private window and return its ten public buckets."""

    if (
        measurement_start_raw_ns <= 0
        or measurement_end_raw_ns <= measurement_start_raw_ns
    ):
        raise EndpointRunError("coordinator_measurement_boundaries_are_invalid")
    duration = measurement_end_raw_ns - measurement_start_raw_ns
    endpoint_bins: dict[str, tuple[tuple[int, int], ...]] = {}
    for role, result in (
        ("server", server_result),
        ("reference_client", client_result),
    ):
        if (
            result.get("global_start_raw_ns") != measurement_start_raw_ns
            or result.get("global_end_raw_ns") != measurement_end_raw_ns
            or result.get("denominator_raw_ns") != duration
        ):
            raise EndpointRunError(f"{role}_measurement_boundaries_mismatch_arm")
        if (
            result.get("measurement_started_raw_ns")
            != result.get("actual_start_raw_ns")
            or result.get("measurement_stopped_raw_ns")
            != result.get("actual_end_raw_ns")
        ):
            raise EndpointRunError(f"{role}_measurement_wire_times_do_not_reconcile")
        rows = result.get("measurement_subwindows")
        if not isinstance(rows, list) or len(rows) != 200:
            raise EndpointRunError(f"{role}_private_window_bin_count_is_not_200")
        bins: list[tuple[int, int]] = []
        for index, row in enumerate(rows):
            if (
                not isinstance(row, Mapping)
                or set(row) != {"blocked_events", "validated_units"}
            ):
                raise EndpointRunError(
                    f"{role}_private_window_bin_{index}_is_malformed"
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
                raise EndpointRunError(
                    f"{role}_private_window_bin_{index}_counter_is_invalid"
                )
            bins.append((validated, blocked))
        progress = result.get("progress")
        if not isinstance(progress, list) or len(progress) != 10:
            raise EndpointRunError(f"{role}_progress_bucket_count_is_not_ten")
        stopped = result["measurement_stopped_raw_ns"]
        for index, item in enumerate(progress):
            if not isinstance(item, Mapping):
                raise EndpointRunError(f"{role}_progress_bucket_{index}_is_malformed")
            private = bins[index * 20 : (index + 1) * 20]
            raw_now = item.get("raw_now_ns")
            boundary = measurement_start_raw_ns + (index + 1) * duration // 10
            if (
                item.get("event_index") != index
                or isinstance(raw_now, bool)
                or not isinstance(raw_now, int)
                or not boundary <= raw_now <= stopped
                or item.get("validated_units")
                != sum(value[0] for value in private)
                or item.get("blocked")
                is not any(value[1] != 0 for value in private)
            ):
                raise EndpointRunError(
                    f"{role}_progress_bucket_{index}_does_not_reconcile"
                )
        endpoint_bins[role] = tuple(bins)

    server = endpoint_bins["server"]
    client = endpoint_bins["reference_client"]
    if scenario == "bidi":
        owner = tuple(
            (left[0] + right[0], left[1] + right[1])
            for left, right in zip(server, client, strict=True)
        )
    elif scenario in _PEER_NUMERATOR_SCENARIOS:
        owner = client
    else:
        owner = server
    if sum(value[0] for value in owner) != numerator:
        raise EndpointRunError("private_window_bins_do_not_reconcile_with_numerator")
    return tuple(
        {
            "validated_units": sum(value[0] for value in owner[index : index + 20]),
            "blocked": any(
                server[position][1] != 0 or client[position][1] != 0
                for position in range(index, index + 20)
            ),
        }
        for index in range(0, 200, 20)
    )


def _construct_sample(
    *,
    campaign_id: str,
    session: int,
    microblock_id: str,
    trial_id: str,
    attempt_id: str,
    cell_id: str,
    config: Mapping[str, Any],
    server_result: Mapping[str, Any],
    client_result: Mapping[str, Any],
    server_binary_sha256: str,
    client_binary_sha256: str,
    server_config_hash: str,
    client_config_hash: str,
    spec: ExperimentSpecV2,
    path_evidence: Mapping[str, Any],
    resource_telemetry: Mapping[str, int] | None = None,
    memory_observation: Mapping[str, Any] | None = None,
    allow_client_headroom_failure: bool = False,
    allow_resolution_limited: bool = False,
    measurement_start_raw_ns: int,
    measurement_end_raw_ns: int,
) -> dict[str, Any]:
    if (
        server_result.get("cell_id") != cell_id
        or client_result.get("cell_id") != cell_id
        or server_result.get("scenario") != config["scenario"]
        or client_result.get("scenario") != config["scenario"]
        or server_result.get("effective_config_hash") != server_config_hash
        or client_result.get("effective_config_hash") != client_config_hash
    ):
        raise EndpointRunError("result_treatment_identity_mismatch")
    scenario = str(config["scenario"])
    server_uses_peer_numerator = scenario in _PEER_NUMERATOR_SCENARIOS
    numerator = (
        int(server_result["numerator"]) + int(client_result["numerator"])
        if scenario == "bidi"
        else int(server_result["numerator"])
    )
    if scenario == "memory_curve":
        if memory_observation is None:
            raise EndpointRunError("memory_observation_missing")
        numerator = int(memory_observation["final_median_bytes"])
    denominator = int(server_result["denominator_raw_ns"])
    cleanup = (
        _cleanup_evidence(server_result, client_result, denominator)
        if scenario == "close_reset_cleanup"
        else None
    )
    operation_scenarios = {
        "small_payload_pps", "datagram", "reqresp", "stream_churn",
        "close_reset_cleanup", "connect", "resumed_connect", "zero_rtt_reqresp",
    }
    flow_control = scenario == "flow_control"
    if scenario == "memory_curve":
        memory_progress = list(memory_observation["polls"])[-10:]
        if len(memory_progress) != 10:
            raise EndpointRunError("memory_observation_has_insufficient_polls")
        progress_rows = tuple(
            {"validated_units": int(item["cgroup_memory_current_bytes"]), "blocked": False}
            for item in memory_progress
        )
    elif scenario == "bidi":
        progress_rows = _fixed_window_progress(
            scenario=scenario,
            numerator=numerator,
            measurement_start_raw_ns=measurement_start_raw_ns,
            measurement_end_raw_ns=measurement_end_raw_ns,
            server_result=server_result,
            client_result=client_result,
        )
    else:
        progress_rows = _fixed_window_progress(
            scenario=scenario,
            numerator=numerator,
            measurement_start_raw_ns=measurement_start_raw_ns,
            measurement_end_raw_ns=measurement_end_raw_ns,
            server_result=server_result,
            client_result=client_result,
        )
    progress = tuple(
        ProgressBucket(int(item["validated_units"]), "transport_blocked" if item["blocked"] else "")
        for item in progress_rows
    )
    try:
        server_completion = loads_strict(str(server_result["completion_counters_json"]))
        client_completion = loads_strict(str(client_result["completion_counters_json"]))
        counters_reconciled = (
            isinstance(server_completion, Mapping)
            and isinstance(client_completion, Mapping)
            and int(server_completion["application_bytes_or_operations"])
            == int(client_completion["peer_application_bytes_or_operations"])
            and int(client_completion["application_bytes_or_operations"])
            == int(server_completion["peer_application_bytes_or_operations"])
        )
    except (KeyError, TypeError, ValueError):
        counters_reconciled = False
    global_start = int(server_result["global_start_raw_ns"])
    global_end = int(server_result["global_end_raw_ns"])
    timing_limit = max(2_000_000, denominator // 1_000)
    timing_gate_passed = (
        denominator > 0
        and global_end - global_start == denominator
        and int(client_result["denominator_raw_ns"]) == denominator
        and int(client_result["global_start_raw_ns"]) == global_start
        and int(client_result["global_end_raw_ns"]) == global_end
        and all(
            global_start <= int(result["actual_start_raw_ns"]) <= global_start + timing_limit
            and global_end <= int(result["actual_end_raw_ns"]) <= global_end + timing_limit
            for result in (server_result, client_result)
        )
    )
    cap_total = lambda field: int(server_result[field]) + int(client_result[field])
    completion_gate_passed = counters_reconciled and all(
        int(server_result.get(field, 0)) + int(client_result.get(field, 0)) == 0
        for field in ("failed", "duplicate", "outstanding", "in_flight", "payload_errors")
    )
    flow_control_blocked_events = sum(
        int(result.get("flow_control_blocked_events", 0))
        for result in (server_result, client_result)
    )
    stream_credit_blocked_events = sum(
        int(result.get("stream_credit_blocked_events", 0))
        for result in (server_result, client_result)
    )
    flow_control_write_blocked_events = sum(
        int(result.get("flow_control_write_blocked_events", 0))
        for result in (server_result, client_result)
    )
    flow_control_recovery_evidence = any(
        bool(result.get("flow_control_recovery_evidence", False))
        for result in (server_result, client_result)
    )
    server_negotiated = _endpoint_negotiated(server_result, "server")
    client_negotiated = _endpoint_negotiated(client_result, "reference_client")
    facts = DurationSampleFacts(
        scenario=scenario,
        termination_reason=(
            "deadline_reached"
            if server_result["termination_reason"] == "deadline_reached"
            and client_result["termination_reason"] == "deadline_reached"
            else "endpoint_termination_mismatch"
        ),
        numerator=numerator,
        denominator_raw_ns=denominator,
        integer_operation_rate=config["scenario"] in operation_scenarios,
        useful_work_available_full_interval=True,
        work_cap_hits=cap_total("work_cap_hits"),
        byte_cap_hits=cap_total("byte_cap_hits"),
        stream_cap_hits=cap_total("stream_cap_hits"),
        stream_id_cap_hits=cap_total("stream_id_cap_hits"),
        generator_starvation_events=cap_total("generator_starvation_events"),
        counters_reconciled=counters_reconciled,
        endpoint_config_hashes_match=True,
        timing_gate_passed=timing_gate_passed,
        trace_gate_passed=_loss_trace_gate(
            config, server_result, client_result, path_evidence
        ),
        completion_gate_passed=completion_gate_passed,
        progress_buckets=progress,
        client_cpu_fraction_of_quota_p95=float(client_result["client_cpu_fraction_of_quota_p95"]),
        socket_drops=cap_total("socket_drops"),
        negotiated_settings_match=bool(
            server_negotiated["matches"] and client_negotiated["matches"]
        ),
        data_blocked_frames=flow_control_blocked_events,
        stream_data_blocked_frames=stream_credit_blocked_events,
        flow_control_write_blocked_events=flow_control_write_blocked_events,
        flow_control_blocked_raw_ns=0,
        flow_control_block_evidence=flow_control
        and (
            flow_control_blocked_events
            + stream_credit_blocked_events
            + flow_control_write_blocked_events
            > 0
        ),
        flow_control_recovery_evidence=flow_control and flow_control_recovery_evidence,
    )
    validity = validate_duration_sample(facts)
    blocking_reasons = tuple(
        reason
        for reason in validity.reasons
        if not (
            allow_client_headroom_failure
            and reason == "reference_client_headroom_failed"
        )
    )
    blocking_censoring = tuple(
        reason
        for reason in validity.censoring
        if not (allow_resolution_limited and reason == "resolution_limited")
    )
    if blocking_reasons or blocking_censoring:
        reason = ",".join((*blocking_reasons, *blocking_censoring)) or "sample_invalid"
        raise EndpointRunError(
            reason,
            detail=canonical_bytes(
                {
                    "client_progress": [
                        {
                            "blocked": bool(item["blocked"]),
                            "validated_units": int(item["validated_units"]),
                        }
                        for item in client_result["progress"][:10]
                    ],
                    "client_transport_blocking": {
                        "data_blocked_frames": int(
                            client_result.get("flow_control_blocked_events", 0)
                        ),
                        "stream_data_blocked_frames": int(
                            client_result.get("stream_credit_blocked_events", 0)
                        ),
                        "write_blocked_events": int(
                            client_result.get("flow_control_write_blocked_events", 0)
                        ),
                    },
                    "client_validated_units_by_connection": list(
                        client_result.get("per_connection_validated_units", ())
                    ),
                    "flow_control_blocked_events": flow_control_blocked_events,
                    "flow_control_write_blocked_events":
                        flow_control_write_blocked_events,
                    "server_progress": [
                        {
                            "blocked": bool(item["blocked"]),
                            "validated_units": int(item["validated_units"]),
                        }
                        for item in server_result["progress"][:10]
                    ],
                    "server_transport_blocking": {
                        "data_blocked_frames": int(
                            server_result.get("flow_control_blocked_events", 0)
                        ),
                        "stream_data_blocked_frames": int(
                            server_result.get("stream_credit_blocked_events", 0)
                        ),
                        "write_blocked_events": int(
                            server_result.get("flow_control_write_blocked_events", 0)
                        ),
                    },
                    "server_validated_units_by_connection": list(
                        server_result.get("per_connection_validated_units", ())
                    ),
                    "stream_credit_blocked_events": stream_credit_blocked_events,
                }
            ).decode(),
        )
    start = global_start
    end = global_end
    digest_zero = "0" * 64
    path_hash = next(path.content_hash for path in spec.paths if path.name == config["path_profile"])
    if scenario == "memory_curve":
        metric_name = "memory_current_bytes"
        metric_units = "bytes"
        metric_numerator = numerator
        metric_denominator = 1
        metric_value = str(numerator)
    elif scenario == "close_reset_cleanup":
        metric_name = "cleanup_geometric_mean_operations_per_second"
        metric_units = "operations_per_second"
        metric_numerator = numerator
        metric_denominator = denominator
        assert cleanup is not None
        metric_value = cleanup[
            "aggregate_geometric_mean_operations_per_second_decimal"
        ]
    else:
        metric_name = "validated_operations_per_second" if scenario in operation_scenarios else "validated_body_bits_per_second"
        metric_units = "operations_per_second" if scenario in operation_scenarios else "bits_per_second"
        metric_numerator = numerator if scenario in operation_scenarios else numerator * 8
        metric_denominator = denominator
        metric_value = _decimal_rate(metric_numerator, denominator)
    resources = dict(resource_telemetry or {})
    path_directions = path_evidence.get("directions", {})
    queue_drops = (
        sum(int(path_directions[str(direction)]["drops"]) for direction in (0, 1))
        if isinstance(path_directions, Mapping)
        and set(path_directions) == {"0", "1"}
        else 0
    )
    tail = _construct_tail_evidence(
        scenario, spec.campaign_kind, server_result, client_result
    )
    return {
        "schema_version": "quicperf.result.v2",
        "identities": {
            "campaign_id": campaign_id,
            "session_id": domain_hash("session", bytes.fromhex(campaign_id), session.to_bytes(4, "big")),
            "microblock_id": microblock_id,
            "trial_id": trial_id,
            "attempt_id": attempt_id,
            "cell_id": cell_id,
        },
        "roles": {
            "server_binary_sha256": server_binary_sha256,
            "reference_client_binary_sha256": client_binary_sha256,
            "server_role": "server",
            "reference_client_role": "reference_client",
        },
        "treatment": {
            "server_config_hash": server_config_hash,
            "reference_client_config_hash": client_config_hash,
            "scenario": config["scenario"],
            "server_backend": config["server_backend"],
            "reference_client_backend": config["reference_client_backend"],
            "path_profile": config["path_profile"],
            "path_hash": path_hash,
            "trace_seed": str(config.get("trace_seed", digest_zero)),
            "tls_hash": hashlib.sha256(canonical_bytes(spec.raw["treatment"]["tls"])).hexdigest(),
            "resource_hash": hashlib.sha256(canonical_bytes(spec.raw["treatment"]["resources"])).hexdigest(),
        },
        "timestamps": {
            "global_start_raw_ns": start,
            "global_end_raw_ns": end,
            "server_start_raw_ns": int(server_result["actual_start_raw_ns"]),
            "server_end_raw_ns": int(server_result["actual_end_raw_ns"]),
            "client_start_raw_ns": int(client_result["actual_start_raw_ns"]),
            "client_end_raw_ns": int(client_result["actual_end_raw_ns"]),
        },
        "metric": {
            "name": metric_name,
            "units": metric_units,
            "orientation": "higher_is_better",
            "numerator": metric_numerator,
            "denominator": metric_denominator,
            "derived_decimal": metric_value,
        },
        "termination_reason": "deadline_reached",
        "units": {
            "completed": 0 if scenario == "memory_curve" else numerator,
            **{
                key: int(server_result[key]) + int(client_result[key])
                for key in ("failed", "duplicate", "outstanding", "in_flight")
            },
        },
        "caps": {
            "work": cap_total("work_cap_hits"),
            "bytes": cap_total("byte_cap_hits"),
            "streams": cap_total("stream_cap_hits"),
            "stream_ids": cap_total("stream_id_cap_hits"),
            "generator_starvation": cap_total("generator_starvation_events"),
        },
        "progress": [
            {"index": index, "numerator": bucket.completed_units, "blocked_reason": bucket.blocked_reason or None}
            for index, bucket in enumerate(progress)
        ],
        "backpressure_ns": 0,
        "telemetry": {
            "client_cpu_ns": resources.get("client_cpu_ns", 0),
            "server_cpu_ns": resources.get("server_cpu_ns", 0),
            "client_cpu_p95_decimal": str(client_result["client_cpu_fraction_of_quota_p95"]),
            "client_memory_bytes": resources.get("client_memory_bytes", 0),
            "server_memory_bytes": resources.get("server_memory_bytes", 0),
            "queue_drops": queue_drops,
            "socket_drops": int(server_result["socket_drops"]) + int(client_result["socket_drops"]),
            "thermal_throttle_delta": resources.get("thermal_throttle_delta", 0),
            "frequency_min_hz": resources.get("frequency_min_hz", 0),
            "frequency_max_hz": resources.get("frequency_max_hz", 0),
            "swap_active": bool(resources.get("swap_active", 0)),
            "health_samples": resources.get("health_samples", 0),
            "non_owned_cpu_fraction_max_decimal": str(
                resources.get("non_owned_cpu_fraction_max_decimal", "0")
            ),
            "device_irq_delta": resources.get("device_irq_delta", 0),
            "cgroup_throttled_ns": resources.get("cgroup_throttled_ns", 0),
            "cgroup_nr_throttled": resources.get("cgroup_nr_throttled", 0),
        },
        "negotiated": {
            "settings_match": bool(
                server_negotiated["matches"] and client_negotiated["matches"]
            ),
            "server": server_negotiated,
            "reference_client": client_negotiated,
        },
        "endpoint_diagnostics": {
            "server_validated_units_by_connection": list(
                server_result.get("per_connection_validated_units", ())
            ),
            "reference_client_validated_units_by_connection": list(
                client_result.get("per_connection_validated_units", ())
            ),
            "server_transport_blocking": {
                "data_blocked_frames": int(
                    server_result.get("flow_control_blocked_events", 0)
                ),
                "stream_data_blocked_frames": int(
                    server_result.get("stream_credit_blocked_events", 0)
                ),
                "write_blocked_events": int(
                    server_result.get("flow_control_write_blocked_events", 0)
                ),
            },
            "reference_client_transport_blocking": {
                "data_blocked_frames": int(
                    client_result.get("flow_control_blocked_events", 0)
                ),
                "stream_data_blocked_frames": int(
                    client_result.get("stream_credit_blocked_events", 0)
                ),
                "write_blocked_events": int(
                    client_result.get("flow_control_write_blocked_events", 0)
                ),
            },
        },
        "tail": tail,
        "cleanup": cleanup,
        "memory": dict(memory_observation) if memory_observation is not None else None,
        "completion_status": "valid",
        "validity_reasons": [],
    }


def _smaps_rollup(pid: int) -> tuple[int, int]:
    try:
        rows = {
            fields[0].rstrip(":"): int(fields[1]) * 1024
            for line in Path(f"/proc/{pid}/smaps_rollup").read_text(
                encoding="ascii"
            ).splitlines()
            if len(fields := line.split()) >= 3 and fields[2] == "kB"
        }
    except (OSError, ValueError) as exc:
        raise EndpointRunError(f"memory_smaps_rollup_unavailable:{exc}") from exc
    if "Pss" not in rows or "Private_Dirty" not in rows:
        raise EndpointRunError("memory_smaps_rollup_missing_required_fields")
    return rows["Pss"], rows["Private_Dirty"]


def _collect_memory_observation(
    cgroup: Path, server_pid: int, connections: int, stop: threading.Event
) -> dict[str, Any]:
    """Poll fresh-process server memory at the frozen 100 ms cadence."""

    epoch = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    values: list[MemoryPoll] = []
    polls: list[dict[str, int]] = []
    settled_at: float | None = None
    for index in range(171):
        target = epoch + index * 100_000_000
        while True:
            remaining = target - time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            if remaining <= 0:
                break
            if stop.wait(min(0.02, remaining / 1_000_000_000)):
                raise EndpointRunError("memory_polling_cancelled")
        actual = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        snapshot = read_cgroup_snapshot(cgroup)
        pss, private_dirty = _smaps_rollup(server_pid)
        values.append(MemoryPoll(index / 10.0, snapshot.memory_current_bytes))
        polls.append(
            {
                "elapsed_ns": actual - epoch,
                "cgroup_memory_current_bytes": snapshot.memory_current_bytes,
                "pss_bytes": pss,
                "private_dirty_bytes": private_dirty,
            }
        )
        if index >= 50 and index % 10 == 0:
            settled_at = memory_settling_time(values)
            if settled_at is not None and index / 10.0 >= settled_at + 2.0:
                break
            if index == 150 and settled_at is None:
                raise EndpointRunError("memory_curve_did_not_settle_by_15_seconds")
    if settled_at is None:
        raise EndpointRunError("memory_curve_settling_evidence_missing")
    final = final_observation_median(values, settled_at)
    return {
        "connections": connections,
        "settled_at_ns": int(round(settled_at * 1_000_000_000)),
        "final_median_bytes": int(final),
        "polls": polls,
    }


def _cgroup_processes(path: Path) -> frozenset[int]:
    try:
        values = (path / "cgroup.procs").read_text(encoding="ascii").split()
        pids = frozenset(int(value) for value in values)
    except (OSError, ValueError) as exc:
        raise EndpointRunError(f"cgroup_process_attestation_unavailable:{exc}") from exc
    if any(pid <= 0 for pid in pids):
        raise EndpointRunError("cgroup_process_attestation_invalid")
    return pids


@dataclass(frozen=True)
class _MeasurementJournalSnapshot:
    connection_changes: int
    external_data_version: int


def _measurement_journal_snapshot(journal: Journal) -> _MeasurementJournalSnapshot:
    return _MeasurementJournalSnapshot(
        journal.connection.total_changes,
        int(journal.connection.execute("PRAGMA data_version").fetchone()[0]),
    )


def _measurement_journal_writes(
    journal: Journal, before: _MeasurementJournalSnapshot
) -> int:
    own_changes = journal.connection.total_changes - before.connection_changes
    external_changed = int(
        journal.connection.execute("PRAGMA data_version").fetchone()[0]
    ) != before.external_data_version
    if own_changes < 0:
        raise EndpointRunError("journal_change_counter_regressed", terminal_state="invalid")
    writes = own_changes + int(external_changed)
    if writes:
        raise EndpointRunError(
            "journal_mutation_during_measurement", terminal_state="invalid"
        )
    return writes


@dataclass(frozen=True)
class _TrialJournalRecord:
    """Publication journal ownership for an otherwise reusable native trial cycle."""

    journal: Journal | None
    attempt_id: str

    @classmethod
    def begin(cls, journal: Journal | None, trial_id: str) -> "_TrialJournalRecord":
        if journal is None:
            return cls(
                None,
                domain_hash("journal-free-native-trial-attempt", bytes.fromhex(trial_id)),
            )
        attempt_id = journal.ensure_attempt(trial_id)
        journal.transition_attempt(attempt_id, "starting")
        return cls(journal, attempt_id)

    def transition(self, state: str) -> None:
        if self.journal is not None:
            self.journal.transition_attempt(self.attempt_id, state)

    def measurement_snapshot(self) -> _MeasurementJournalSnapshot | None:
        if self.journal is None:
            return None
        return _measurement_journal_snapshot(self.journal)

    def measurement_writes(
        self, snapshot: _MeasurementJournalSnapshot | None
    ) -> int:
        if self.journal is None:
            if snapshot is not None:
                raise EndpointRunError("journal_free_trial_has_journal_snapshot")
            return 0
        if snapshot is None:
            raise EndpointRunError("journaled_trial_has_no_measurement_snapshot")
        return _measurement_journal_writes(self.journal, snapshot)

    def append_events(self, events: Iterable[Mapping[str, Any]]) -> None:
        if self.journal is None:
            return
        for event in events:
            self.journal.append_event(self.attempt_id, **event)


def _measurement_barrier_wait(
    barrier: threading.Barrier | None, phase: str
) -> int:
    if barrier is None:
        return 0
    started_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    try:
        barrier.wait(timeout=30.0)
    except threading.BrokenBarrierError as exc:
        raise EndpointRunError(
            f"parallel_measurement_barrier_failed:{phase}",
            terminal_state="invalid",
        ) from exc
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) - started_raw_ns


def _rebased_arm_window(
    policy: _ArmControlPolicy, warmup_start_raw_ns: int, observed_raw_ns: int
) -> int | None:
    if warmup_start_raw_ns - observed_raw_ns >= policy.pre_send_guard_ns:
        return None
    return observed_raw_ns + policy.lead_ns


class _ArmWindowCoordinator:
    """Keep concurrent lanes on one rebased pre-send ARM window."""

    def __init__(
        self,
        parties: int,
        policy: _ArmControlPolicy,
        *,
        parallel_arm_ns: int | None = None,
    ) -> None:
        if parties < 2 or parallel_arm_ns is not None and parallel_arm_ns <= 0:
            raise RunnerError("shared ARM-window coordinator is invalid")
        self.policy = policy
        self.parallel_arm_ns = parallel_arm_ns
        self.warmup_start_raw_ns = 0
        self._stale_participants: set[int] = set()
        self._guard_rebased = False
        self._lock = threading.Lock()
        self._begin = threading.Barrier(parties, action=self._begin_window)
        self._guard_arrive = threading.Barrier(parties)
        self._guard_release = threading.Barrier(
            parties, action=self._resolve_guard
        )

    def _begin_window(self) -> None:
        self.warmup_start_raw_ns = (
            time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            + self.policy.lead_ns
        )

    def begin_window(self) -> int:
        try:
            self._begin.wait(timeout=30.0)
        except threading.BrokenBarrierError as exc:
            raise EndpointRunError(
                "parallel_arm_window_failed:begin", terminal_state="invalid"
            ) from exc
        return self.warmup_start_raw_ns

    def _resolve_guard(self) -> None:
        with self._lock:
            self._guard_rebased = bool(self._stale_participants)
            self._stale_participants.clear()
        if self._guard_rebased:
            self.warmup_start_raw_ns = (
                time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                + self.policy.lead_ns
            )

    def guard(self, participant: int, *, stale: bool) -> tuple[bool, int]:
        if stale:
            with self._lock:
                self._stale_participants.add(participant)
        try:
            self._guard_arrive.wait(timeout=30.0)
            self._guard_release.wait(timeout=30.0)
        except threading.BrokenBarrierError as exc:
            raise EndpointRunError(
                "parallel_arm_window_failed:guard", terminal_state="invalid"
            ) from exc
        return self._guard_rebased, self.warmup_start_raw_ns

    def abort(self) -> None:
        for barrier in (self._begin, self._guard_arrive, self._guard_release):
            barrier.abort()


def _parallel_scheduled_padding_ns(
    shared_measurement_epoch: _ArmWindowCoordinator | None,
    own_arm_ns: int,
) -> int:
    if shared_measurement_epoch is None:
        return 0
    parallel_arm_ns = shared_measurement_epoch.parallel_arm_ns
    if parallel_arm_ns is None:
        return 0
    if (
        type(parallel_arm_ns) is not int
        or own_arm_ns <= 0
        or parallel_arm_ns < own_arm_ns
    ):
        raise EndpointRunError("shared_measurement_epoch_arm_is_invalid")
    return parallel_arm_ns - own_arm_ns


def _intrinsic_nonmeasurement_overhead_ns(
    *,
    trial_wall_ns: int,
    warmup_ns: int,
    measurement_ns: int,
    arm_lead_ns: int,
    parallel_scheduled_padding_ns: int,
) -> int:
    overhead_ns = (
        trial_wall_ns
        - warmup_ns
        - measurement_ns
        - arm_lead_ns
        - parallel_scheduled_padding_ns
    )
    if overhead_ns < 0:
        raise EndpointRunError("trial_wall_time_shorter_than_armed_intervals")
    return overhead_ns


def _attest_coordinator_affinity(
    lane_topologies: Mapping[int, LaneTopology],
    *,
    reserved_cpus: Sequence[int] = (),
) -> tuple[int, ...]:
    frozen_housekeeping = {
        cpu
        for topology in lane_topologies.values()
        for cpu in topology.housekeeping_cpus
    }
    reserved = set(reserved_cpus)
    endpoints = {
        cpu
        for topology in lane_topologies.values()
        for cpu in (topology.server_cpu, *topology.client_cpus)
    }
    if not frozen_housekeeping or frozen_housekeeping & endpoints:
        raise RunnerError("frozen housekeeping CPUs overlap endpoint CPUs")
    if not reserved <= frozen_housekeeping:
        raise RunnerError("reserved monitor CPUs are not frozen housekeeping CPUs")
    expected = frozen_housekeeping - reserved
    if not expected:
        raise RunnerError("reserved monitor CPUs leave no coordinator CPU")
    actual = set(os.sched_getaffinity(0))
    if actual != expected:
        raise RunnerError(
            "coordinator affinity differs from the exact frozen housekeeping set"
        )
    return tuple(sorted(actual))


def _run_trial(
    journal: Journal | None,
    *,
    root: Path,
    run_dir: Path,
    campaign_id: str,
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
    trial_row: Mapping[str, Any],
    cell_config: Mapping[str, Any],
    binary_paths: Mapping[str, Path],
    lane_topology: LaneTopology | None,
    lane_cgroups: tuple[Path, Path] | None,
    path_controller: LoopbackPathController | NamespacePathController | None,
    endpoint_override: tuple[str, ...] | None,
    endpoint_environment: Mapping[str, str] | None,
    worker_pool: _WorkerPool | None = None,
    expected_coordinator_affinity: tuple[int, ...] | None = None,
    measurement_barrier: threading.Barrier | None = None,
    shared_measurement_epoch: _ArmWindowCoordinator | None = None,
    active_processes: dict[int, ManagedProcess] | None = None,
    active_processes_lock: threading.Lock | None = None,
    amd_monitor: AmdContinuousMonitor | None = None,
    external_thermal_provider: bool = False,
    construct_sample: bool = True,
    exercise_only: bool = False,
    allow_client_headroom_failure: bool = False,
    allow_resolution_limited: bool = False,
) -> dict[str, Any]:
    trial_wall_started_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    coordinator_cpu_started_ns = time.process_time_ns()
    trial_id = str(trial_row["trial_id"])
    cell_id = str(trial_row["cell_id"])
    trial_bytes = bytes.fromhex(trial_id)
    journal_record = _TrialJournalRecord.begin(journal, trial_id)
    attempt_id = journal_record.attempt_id
    entries = _binary_entries(manifest)
    server_entry = entries[str(cell_config["server"])]
    client_entry = entries[str(cell_config["reference_client"])]
    server_binary = binary_paths[str(cell_config["server"])]
    client_binary = binary_paths[str(cell_config["reference_client"])]
    timeout = spec.raw["timing"]["timeouts"]
    workload = next(item for item in spec.raw["workloads"] if item["scenario"] == cell_config["scenario"])
    config = dict(cell_config)
    measurement_ns = int(
        config.get("measurement_duration_ns", workload["measurement_ns"])
    )
    if measurement_ns <= 0:
        raise EndpointRunError("measurement_duration_is_not_positive")
    config["cell_id"] = cell_id
    config["treatment"] = spec.raw["treatment"]
    if endpoint_override is None:
        server_wire_config = _endpoint_config(
            root=root,
            spec=spec,
            workload=workload,
            cell=config,
            role="server",
            backend=str(config["server_backend"]),
            peer_port=0,
        )
    else:
        server_wire_config = config
    environment = dict(endpoint_environment or {})
    reuse_trial = worker_pool is not None and _worker_reuse_eligible(
        spec.campaign_kind, str(config["scenario"])
    )
    if exercise_only and (not reuse_trial or construct_sample or journal is not None):
        raise RunnerError(
            "untimed worker exercise requires a journal-free reusable raw trial"
        )
    with ExitStack() as trial_resources:
        measurement_cycle_complete = measurement_barrier is None
        amd_microblock_evaluation = None

        def abort_measurement_cycle() -> None:
            if not measurement_cycle_complete and measurement_barrier is not None:
                measurement_barrier.abort()
            if (
                not measurement_cycle_complete
                and shared_measurement_epoch is not None
            ):
                shared_measurement_epoch.abort()

        trial_resources.callback(abort_measurement_cycle)
        if path_controller is not None:
            trial_resources.callback(path_controller.reset_trial)
            try:
                path_controller.prepare_trial(str(config["path_profile"]))
            except PathError as exc:
                raise EndpointRunError(
                    f"path_prepare_failed:{exc}", terminal_state="invalid"
                ) from exc
        try:
            server_namespace = (
                None
                if path_controller is None
                else path_controller.network_namespace("server")
            )
            client_namespace = (
                None
                if path_controller is None
                else path_controller.network_namespace("client")
            )
            server_addresses = (
                ("127.0.0.1", "0.0.0.0")
                if path_controller is None
                else path_controller.endpoint_addresses("server")
            )
            client_addresses = (
                ("127.0.0.1", "127.0.0.1")
                if path_controller is None
                else path_controller.endpoint_addresses("client")
            )
        except PathError as exc:
            raise EndpointRunError(
                f"path_endpoint_placement_failed:{exc}", terminal_state="invalid"
            ) from exc
        if endpoint_override is None:
            server_wire_config["bind_address"] = server_addresses[0]
            server_wire_config["peer_address"] = server_addresses[1]
        lane_health = None
        health: TrialHealthResult | None = None
        if lane_topology is not None and lane_cgroups is not None:
            try:
                lane_health = trial_resources.enter_context(
                    TrialLaneHealth(
                        server_cpu=lane_topology.server_cpu,
                        client_cpus=lane_topology.client_cpus,
                        server_cgroup=lane_cgroups[0],
                        client_cgroup=lane_cgroups[1],
                        external_thermal_provider=(
                            external_thermal_provider or amd_monitor is not None
                        ),
                    )
                )
            except HealthError as exc:
                if amd_monitor is not None:
                    raise HardwareUnqualifiedError(
                        f"host_health_telemetry_unavailable:{exc}"
                    ) from exc
                raise EndpointRunError(
                    f"host_health_telemetry_unavailable:{exc}", terminal_state="invalid"
                ) from exc
        server_session: _WorkerSession | None = None
        client_session: _WorkerSession | None = None
        if reuse_trial:
            assert worker_pool is not None
            lane = int(config.get("lane", 0))
            server_session = worker_pool.acquire(
                binary=server_binary,
                entry=server_entry,
                role="server",
                backend=str(config["server_backend"]),
                scenario=str(config["scenario"]),
                lane=lane,
                cpuset=None if lane_topology is None else (lane_topology.server_cpu,),
                cgroup=None if lane_cgroups is None else lane_cgroups[0],
                network_namespace=server_namespace,
                log_path=run_dir / "logs" / trial_id / attempt_id / "server.log",
                timeout_ns=int(timeout["describe_ns"]),
            )
            trial_resources.callback(worker_pool.abort, server_session)
            client_session = worker_pool.acquire(
                binary=client_binary,
                entry=client_entry,
                role="client",
                backend=str(config["reference_client_backend"]),
                scenario=str(config["scenario"]),
                lane=lane,
                cpuset=None if lane_topology is None else lane_topology.client_cpus,
                cgroup=None if lane_cgroups is None else lane_cgroups[1],
                network_namespace=client_namespace,
                log_path=(
                    run_dir
                    / "logs"
                    / trial_id
                    / attempt_id
                    / "reference_client.log"
                ),
                timeout_ns=int(timeout["describe_ns"]),
            )
            trial_resources.callback(worker_pool.abort, client_session)
            server = server_session.managed
            client = client_session.managed
            server_channel = server_session.channel
            client_channel = client_session.channel
        else:
            supervisor = trial_resources.enter_context(Supervisor())
            server = supervisor.spawn(
                _endpoint_command(server_binary, "server", endpoint_override),
                log_path=run_dir / "logs" / trial_id / attempt_id / "server.log",
                cwd=root,
                environment=environment,
                pass_control_argument=True,
                cpu_affinity=None if lane_topology is None else (lane_topology.server_cpu,),
                cgroup=None if lane_cgroups is None else lane_cgroups[0],
                network_namespace=server_namespace,
            )
            if active_processes is not None and active_processes_lock is not None:
                with active_processes_lock:
                    active_processes[server.process.pid] = server

                def unregister_server() -> None:
                    with active_processes_lock:
                        active_processes.pop(server.process.pid, None)

                trial_resources.callback(unregister_server)
            client = supervisor.spawn(
                _endpoint_command(client_binary, "client", endpoint_override),
                log_path=(
                    run_dir
                    / "logs"
                    / trial_id
                    / attempt_id
                    / "reference_client.log"
                ),
                cwd=root,
                environment=environment,
                pass_control_argument=True,
                cpu_affinity=None if lane_topology is None else lane_topology.client_cpus,
                cgroup=None if lane_cgroups is None else lane_cgroups[1],
                network_namespace=client_namespace,
            )
            if active_processes is not None and active_processes_lock is not None:
                with active_processes_lock:
                    active_processes[client.process.pid] = client

                def unregister_client() -> None:
                    with active_processes_lock:
                        active_processes.pop(client.process.pid, None)

                trial_resources.callback(unregister_client)
            server_channel = SeqPacketChannel(server.control)
            client_channel = SeqPacketChannel(client.control)
        expected_server_build = None if endpoint_override else str(server_entry["elf_build_id"])
        expected_client_build = None if endpoint_override else str(client_entry["elf_build_id"])
        def attest_endpoint_mappings() -> None:
            if endpoint_override is not None:
                return
            try:
                attest_process_libraries(
                    root,
                    server.process.pid,
                    server_binary,
                    server_entry["expected_loaded_libraries"],
                )
                attest_process_libraries(
                    root,
                    client.process.pid,
                    client_binary,
                    client_entry["expected_loaded_libraries"],
                )
            except ManifestCollectionError as exc:
                raise EndpointRunError(
                    f"loaded_library_attestation_failed:{exc}",
                    terminal_state="invalid",
                ) from exc
        if not reuse_trial:
            _attest_hello(
                server_channel, role="server", timeout_ns=int(timeout["describe_ns"]),
                expected_build_id=expected_server_build,
                required_backend=str(config["server_backend"]),
                required_scenario=str(config["scenario"]),
            )
            _attest_hello(
                client_channel, role="client", timeout_ns=int(timeout["describe_ns"]),
                expected_build_id=expected_client_build,
                required_backend=str(config["reference_client_backend"]),
                required_scenario=str(config["scenario"]),
            )
            attest_endpoint_mappings()
        try:
            cgroup_before = (
                None
                if lane_cgroups is None
                else tuple(read_cgroup_snapshot(path) for path in lane_cgroups)
            )
            baseline_cgroup_pids = (
                None
                if lane_cgroups is None or not reuse_trial
                else tuple(_cgroup_processes(path) for path in lane_cgroups)
            )
        except LaneError as exc:
            if amd_monitor is not None:
                raise HardwareUnqualifiedError(
                    f"cgroup_telemetry_unavailable:{exc}"
                ) from exc
            raise EndpointRunError(f"cgroup_telemetry_unavailable:{exc}") from exc
        if baseline_cgroup_pids is not None and baseline_cgroup_pids != (
            frozenset({server.process.pid}),
            frozenset({client.process.pid}),
        ):
            raise EndpointRunError("reuse_worker_cgroup_baseline_mismatch")
        _send(server_channel,
            MessageType.CONFIG,
            {"trial_id": trial_bytes, "cell_id": bytes.fromhex(cell_id), "config_json": canonical_bytes(server_wire_config).decode("utf-8")},
        )
        bound = _expect(server_channel, MessageType.BOUND, timeout_ns=5_000_000_000, trial_id=trial_bytes)
        if endpoint_override is None:
            client_config = _endpoint_config(
                root=root,
                spec=spec,
                workload=workload,
                cell=config,
                role="client",
                backend=str(config["reference_client_backend"]),
                peer_port=int(bound.fields["udp_port"]),
            )
            client_config["bind_address"] = client_addresses[0]
            client_config["peer_address"] = client_addresses[1]
        else:
            client_config = dict(config)
            client_config["server_address"] = "127.0.0.1"
            client_config["server_port"] = bound.fields["udp_port"]
        _send(client_channel,
            MessageType.CONFIG,
            {"trial_id": trial_bytes, "cell_id": bytes.fromhex(cell_id), "config_json": canonical_bytes(client_config).decode("utf-8")},
        )
        server_ready = _expect(server_channel, MessageType.READY, timeout_ns=5_000_000_000, trial_id=trial_bytes)
        client_ready = _expect(client_channel, MessageType.READY, timeout_ns=5_000_000_000, trial_id=trial_bytes)
        if not reuse_trial:
            attest_endpoint_mappings()
        if (
            int(server_ready.fields["pid"]) != server.process.pid
            or int(client_ready.fields["pid"]) != client.process.pid
        ):
            raise EndpointRunError("endpoint_pid_attestation_mismatch")
        if server_ready.fields["backend"] != config["server_backend"] or client_ready.fields["backend"] != config["reference_client_backend"]:
            raise EndpointRunError("effective_backend_mismatch")
        if expected_coordinator_affinity is not None and tuple(
            sorted(os.sched_getaffinity(0))
        ) != expected_coordinator_affinity:
            raise EndpointRunError(
                "coordinator_affinity_changed_before_measurement",
                terminal_state="invalid",
            )
        journal_record.transition("ready")
        if exercise_only:
            assert worker_pool is not None
            assert server_session is not None and client_session is not None
            if lane_health is not None:
                try:
                    lane_health.arm(
                        time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) + 5_000_000
                    )
                except HealthError as exc:
                    raise EndpointRunError(
                        f"host_health_telemetry_unavailable:{exc}",
                        terminal_state="invalid",
                    ) from exc
            inventories = worker_pool.exercise_and_reset(
                server_session,
                client_session,
                trial_bytes,
                deadline_raw_ns=(
                    time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) + 2_000_000_000
                ),
            )
            try:
                fd_count = sum(
                    len(tuple(Path(f"/proc/{managed.process.pid}/fd").iterdir()))
                    for managed in (server, client)
                )
                cgroup_after = (
                    None
                    if lane_cgroups is None
                    else tuple(read_cgroup_snapshot(path) for path in lane_cgroups)
                )
            except (LaneError, OSError) as exc:
                raise EndpointRunError(
                    f"reuse_worker_post_reset_telemetry_unavailable:{exc}"
                ) from exc
            if lane_cgroups is not None:
                assert cgroup_after is not None and cgroup_before is not None
                if tuple(_cgroup_processes(path) for path in lane_cgroups) != (
                    frozenset({server.process.pid}),
                    frozenset({client.process.pid}),
                ):
                    raise EndpointRunError("reuse_worker_zero_state_process_mismatch")
                cgroup_deltas = tuple(
                    after.delta(before)
                    for before, after in zip(cgroup_before, cgroup_after, strict=True)
                )
                throttled_ns = sum(delta.cpu_throttled_ns for delta in cgroup_deltas)
                nr_throttled = sum(delta.cpu_nr_throttled for delta in cgroup_deltas)
                if throttled_ns or nr_throttled:
                    raise EndpointRunError(
                        "cgroup_cpu_throttling_detected", terminal_state="invalid"
                    )
                memory_bytes = sum(item.memory_current_bytes for item in cgroup_after)
            else:
                memory_bytes = sum(
                    int(Path(f"/proc/{managed.process.pid}/statm").read_text().split()[1])
                    * os.sysconf("SC_PAGE_SIZE")
                    for managed in (server, client)
                )
            if lane_health is not None:
                try:
                    health = lane_health.finish()
                except HealthError as exc:
                    raise EndpointRunError(
                        f"host_health_telemetry_unavailable:{exc}",
                        terminal_state="invalid",
                    ) from exc
                if any(health.device_irq_deltas.values()) or (
                    health.non_owned_cpu_fraction_max >= 0.01
                ):
                    raise EndpointRunError(
                        "external_cpu_or_irq_noise",
                        detail=_external_noise_detail(health),
                        infrastructure_transient=True,
                    )
                if health.thermal_throttle_delta:
                    raise EndpointRunError("thermal_throttle", terminal_state="invalid")
                if health.swap_active:
                    raise EndpointRunError("swap_activity", terminal_state="invalid")
            worker_pool.release(server_session)
            worker_pool.release(client_session)
            journal_record.transition("validated_provisional")
            return {
                "fd_count": fd_count,
                "inventories": inventories,
                "memory_bytes": memory_bytes,
                "pids": {
                    "server": server.process.pid,
                    "reference_client": client.process.pid,
                },
                "trial_id": trial_id,
            }
        arm_policy = _arm_control_policy(spec)
        parallel_peer_wait_ns = _measurement_barrier_wait(
            measurement_barrier, "before_arm"
        )
        if shared_measurement_epoch is None:
            warmup_start = (
                time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                + arm_policy.lead_ns
            )
        else:
            warmup_start = shared_measurement_epoch.begin_window()
        parallel_scheduled_padding_ns = _parallel_scheduled_padding_ns(
            shared_measurement_epoch,
            int(workload["warmup_ns"]) + measurement_ns,
        )
        arm_rebases = 0
        while True:
            measurement_start = warmup_start + int(workload["warmup_ns"])
            measurement_end = measurement_start + measurement_ns
            amd_interval_scheduled = False
            path_armed = False

            def cancel_arm_side_effects() -> None:
                nonlocal amd_interval_scheduled, path_armed
                if amd_interval_scheduled and amd_monitor is not None:
                    try:
                        amd_monitor.cancel_interval(trial_id)
                    except HealthError as exc:
                        raise HardwareUnqualifiedError(
                            f"amd_monitor_boundary_cancel_failed:{exc}"
                        ) from exc
                    amd_interval_scheduled = False
                if path_armed and path_controller is not None:
                    path_controller.cancel_arm()
                    path_armed = False

            if amd_monitor is not None:
                if lane_cgroups is None:
                    raise HardwareUnqualifiedError(
                        "amd_provider_missing_measurement_cgroups"
                    )
                try:
                    amd_monitor.schedule_interval(
                        trial_id,
                        measurement_start,
                        measurement_end,
                        cgroup_paths=lane_cgroups,
                    )
                    amd_interval_scheduled = True
                except HealthError as exc:
                    if isinstance(exc, AmdMonitorTransientError):
                        if (
                            spec.schema_version
                            in VERSIONED_PUBLICATION_SCHEMA_VERSIONS
                            and not isinstance(
                                exc, AmdBoundaryMonitorTransientError
                            )
                        ):
                            raise HardwareUnqualifiedError(
                                f"amd_continuous_monitor_evidence_lost:{exc}"
                            ) from exc
                        raise EndpointRunError(
                            (
                                "host_stability_interval_transient"
                                if spec.schema_version
                                in VERSIONED_PUBLICATION_SCHEMA_VERSIONS
                                else "host_stability_monitor_transient"
                            ),
                            detail=str(exc),
                            infrastructure_transient=True,
                            terminal_state="invalid",
                        ) from exc
                    raise HardwareUnqualifiedError(
                        f"amd_monitor_boundary_schedule_failed:{exc}"
                    ) from exc
            if path_controller is not None:
                try:
                    path_controller.arm(
                        ArmedTrace(
                            measurement_start,
                            bytes.fromhex(str(config["trace_seed"])),
                            (),
                        )
                    )
                    path_armed = True
                except (PathError, ValueError) as exc:
                    cancel_arm_side_effects()
                    raise EndpointRunError(
                        f"path_arm_failed:{exc}", terminal_state="invalid"
                    ) from exc
            observed_before_send = time.clock_gettime_ns(
                time.CLOCK_MONOTONIC_RAW
            )
            rebased_start = _rebased_arm_window(
                arm_policy, warmup_start, observed_before_send
            )
            if shared_measurement_epoch is not None:
                rebased, coordinated_start = shared_measurement_epoch.guard(
                    int(config.get("lane", 0)),
                    stale=rebased_start is not None,
                )
                rebased_start = coordinated_start if rebased else None
            if rebased_start is not None:
                cancel_arm_side_effects()
                arm_rebases += 1
                if arm_rebases > arm_policy.pre_send_rebase_maximum:
                    raise EndpointRunError(
                        "arm_control_pre_send_rebase_exhausted",
                        terminal_state="invalid",
                    )
                warmup_start = rebased_start
                continue
            arm_fields = {
                "trial_id": trial_bytes,
                "warmup_start_raw_ns": warmup_start,
                "measurement_start_raw_ns": measurement_start,
                "measurement_end_raw_ns": measurement_end,
                "trace_epoch_raw_ns": measurement_start,
            }
            try:
                _send(server_channel, MessageType.ARM, arm_fields)
                _send(client_channel, MessageType.ARM, arm_fields)
                server_armed = _expect(
                    server_channel,
                    MessageType.ARMED,
                    timeout_ns=2_000_000_000,
                    trial_id=trial_bytes,
                )
                client_armed = _expect(
                    client_channel,
                    MessageType.ARMED,
                    timeout_ns=2_000_000_000,
                    trial_id=trial_bytes,
                )
            except EndpointRunError as exc:
                if exc.reason != "arm_control_window_rejected":
                    raise
                cancel_arm_side_effects()
                raise
            if (
                max(
                    int(server_armed.fields["raw_now_ns"]),
                    int(client_armed.fields["raw_now_ns"]),
                    time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
                )
                >= warmup_start
            ):
                raise EndpointRunError(
                    "arm_control_ack_crossed_warmup_boundary",
                    terminal_state="invalid",
                )
            break

        # Both endpoints accepted the same still-future window.  Freeze all
        # durable attempt state before taking the no-write measurement snapshot.
        journal_record.transition("armed")
        journal_record.transition("measuring")
        parallel_peer_wait_ns += _measurement_barrier_wait(
            measurement_barrier, "after_journal_freeze"
        )
        measurement_journal = journal_record.measurement_snapshot()
        if (
            time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            >= warmup_start
        ):
            raise EndpointRunError(
                "arm_control_journal_freeze_crossed_warmup_boundary",
                terminal_state="invalid",
            )
        memory_observation: dict[str, Any] | None = None
        memory_result: list[dict[str, Any]] = []
        memory_errors: list[BaseException] = []
        memory_stop: threading.Event | None = None
        memory_thread: threading.Thread | None = None
        if spec.campaign_kind == "memory":
            if lane_cgroups is None:
                raise EndpointRunError("memory_campaign_requires_server_cgroup")
            memory_stop = threading.Event()

            def collect_memory() -> None:
                try:
                    memory_result.append(
                        _collect_memory_observation(
                            lane_cgroups[0],
                            server.process.pid,
                            int(config["connections"]),
                            memory_stop,
                        )
                    )
                except BaseException as exc:
                    memory_errors.append(exc)

            memory_thread = threading.Thread(
                target=collect_memory,
                name=f"quicperf-memory-{trial_id[:12]}",
                daemon=True,
            )
            memory_thread.start()
            trial_resources.callback(memory_thread.join, 1.0)
            trial_resources.callback(memory_stop.set)
        if lane_health is not None:
            try:
                lane_health.arm(warmup_start)
            except HealthError as exc:
                raise EndpointRunError(
                    f"host_health_telemetry_unavailable:{exc}", terminal_state="invalid"
                ) from exc
        measurement_started_timeout_ns = _measurement_started_timeout_ns(
            measurement_start,
            time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
        )
        server_result, server_events = _receive_result_stream(
            server_channel, source="server", trial_id=trial_bytes,
            start_timeout_ns=measurement_started_timeout_ns,
            measurement_ns=measurement_ns, completion_bound_ns=int(spec.raw["timing"]["completion_bound_ns"]),
        )
        client_result, client_events = _receive_result_stream(
            client_channel, source="reference_client", trial_id=trial_bytes,
            start_timeout_ns=measurement_started_timeout_ns,
            measurement_ns=measurement_ns, completion_bound_ns=int(spec.raw["timing"]["completion_bound_ns"]),
        )
        if lane_health is not None:
            try:
                health = lane_health.finish()
            except HealthError as exc:
                if amd_monitor is not None:
                    raise HardwareUnqualifiedError(
                        f"host_health_telemetry_unavailable:{exc}"
                    ) from exc
                raise EndpointRunError(
                    f"host_health_telemetry_unavailable:{exc}", terminal_state="invalid"
                ) from exc
        if amd_monitor is not None:
            try:
                amd_microblock_evaluation = amd_monitor.finish_interval(
                    trial_id,
                    duration_ns=measurement_ns,
                )
            except HealthError as exc:
                if isinstance(exc, AmdMonitorTransientError):
                    if (
                        spec.schema_version
                        in VERSIONED_PUBLICATION_SCHEMA_VERSIONS
                        and not isinstance(
                            exc, AmdBoundaryMonitorTransientError
                        )
                    ):
                        raise HardwareUnqualifiedError(
                            f"amd_continuous_monitor_evidence_lost:{exc}"
                        ) from exc
                    raise EndpointRunError(
                        (
                            "host_stability_interval_transient"
                            if spec.schema_version
                            in VERSIONED_PUBLICATION_SCHEMA_VERSIONS
                            else "host_stability_monitor_transient"
                        ),
                        detail=str(exc),
                        infrastructure_transient=True,
                        terminal_state="invalid",
                    ) from exc
                raise HardwareUnqualifiedError(
                    f"amd_monitor_boundary_collection_failed:{exc}"
                ) from exc
            if not amd_microblock_evaluation.passed:
                boundary_monitor_reasons = {
                    "microblock_boundary_monitor_error",
                    "microblock_boundary_phase_offset_exceeded",
                    "microblock_boundary_interval_duration_error_exceeded",
                }
                reasons = set(amd_microblock_evaluation.reasons)
                if reasons and reasons <= boundary_monitor_reasons:
                    raise EndpointRunError(
                        (
                            "host_stability_interval_transient"
                            if spec.schema_version
                            in VERSIONED_PUBLICATION_SCHEMA_VERSIONS
                            else "host_stability_monitor_transient"
                        ),
                        detail=canonical_bytes(
                            {
                                "reasons": list(amd_microblock_evaluation.reasons),
                                "start_lateness_ns": (
                                    amd_microblock_evaluation.start_lateness_ns
                                ),
                                "end_lateness_ns": (
                                    amd_microblock_evaluation.end_lateness_ns
                                ),
                                "target_interval_ns": (
                                    amd_microblock_evaluation.target_interval_ns
                                ),
                                "observed_interval_ns": (
                                    amd_microblock_evaluation.observed_interval_ns
                                ),
                                "interval_duration_error_ns": (
                                    amd_microblock_evaluation.interval_duration_error_ns
                                ),
                            }
                        ).decode("utf-8"),
                        infrastructure_transient=True,
                        terminal_state="invalid",
                    )
                raise HardwareUnqualifiedError(
                    "amd_microblock_stability_violation:"
                    + ",".join(amd_microblock_evaluation.reasons)
                )
        parallel_peer_wait_ns += _measurement_barrier_wait(
            measurement_barrier, "after_result"
        )
        measurement_error: EndpointRunError | None = None
        try:
            journal_writes_during_measurement = journal_record.measurement_writes(
                measurement_journal
            )
        except EndpointRunError as exc:
            journal_writes_during_measurement = 1
            measurement_error = exc
        parallel_peer_wait_ns += _measurement_barrier_wait(
            measurement_barrier, "after_attestation"
        )
        measurement_cycle_complete = True
        if measurement_error is not None:
            raise measurement_error
        if expected_coordinator_affinity is not None and tuple(
            sorted(os.sched_getaffinity(0))
        ) != expected_coordinator_affinity:
            raise EndpointRunError(
                "coordinator_affinity_changed_during_measurement",
                terminal_state="invalid",
            )
        if memory_thread is not None:
            memory_thread.join(timeout=18.0)
            if memory_thread.is_alive():
                raise EndpointRunError("memory_polling_exceeded_17_second_bound")
            if memory_errors:
                error = memory_errors[0]
                if isinstance(error, EndpointRunError):
                    raise error
                raise EndpointRunError(f"memory_polling_failed:{error}") from error
            if len(memory_result) != 1:
                raise EndpointRunError("memory_polling_produced_no_observation")
            memory_observation = memory_result[0]
        if not reuse_trial:
            attest_endpoint_mappings()
        try:
            cgroup_active = (
                None
                if lane_cgroups is None
                else tuple(read_cgroup_snapshot(path) for path in lane_cgroups)
            )
        except LaneError as exc:
            if amd_monitor is not None:
                raise HardwareUnqualifiedError(
                    f"cgroup_telemetry_unavailable:{exc}"
                ) from exc
            raise EndpointRunError(f"cgroup_telemetry_unavailable:{exc}") from exc
        if baseline_cgroup_pids is not None and tuple(
            _cgroup_processes(path) for path in lane_cgroups or ()
        ) != baseline_cgroup_pids:
            raise EndpointRunError("reuse_worker_cgroup_process_growth")
        journal_record.transition("draining")
        journal_record.append_events((*server_events, *client_events))
        reset_inventories: dict[str, Mapping[str, int]] | None = None
        if reuse_trial:
            assert worker_pool is not None
            assert server_session is not None and client_session is not None
            reset_inventories = {
                "server": worker_pool.reset(server_session, trial_bytes),
                "reference_client": worker_pool.reset(client_session, trial_bytes),
            }
        else:
            _send(server_channel, MessageType.SHUTDOWN, {})
            _send(client_channel, MessageType.SHUTDOWN, {})
            _expect(server_channel, MessageType.SHUTDOWN_ACK, timeout_ns=1_000_000_000)
            _expect(client_channel, MessageType.SHUTDOWN_ACK, timeout_ns=1_000_000_000)
            for managed, role in ((server, "server"), (client, "reference_client")):
                try:
                    return_code = managed.process.wait(timeout=1.0)
                except subprocess.TimeoutExpired as exc:
                    raise EndpointRunError(f"{role}_did_not_exit_after_shutdown_ack") from exc
                if return_code != 0:
                    raise EndpointRunError(f"{role}_nonzero_exit:{return_code}")
        try:
            path_evidence = (
                {"profile": "loopback", "directions": {}}
                if path_controller is None
                else path_controller.finish_trial()
            )
        except PathError as exc:
            raise EndpointRunError(
                f"path_evidence_failed:{exc}", terminal_state="invalid"
            ) from exc
        journal_record.append_events(
            (
                {
                    "source": "path_controller",
                    "event_sequence": 0,
                    "event_type": "path_evidence",
                    "raw_time_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
                    "payload": path_evidence,
                },
            )
        )
        resource_telemetry = None
        if lane_cgroups is not None:
            try:
                cgroup_after = tuple(read_cgroup_snapshot(path) for path in lane_cgroups)
                if cgroup_before is None or cgroup_active is None:
                    raise LaneError("cgroup telemetry baseline is unavailable")
                server_delta = cgroup_after[0].delta(cgroup_before[0])
                client_delta = cgroup_after[1].delta(cgroup_before[1])
            except LaneError as exc:
                if amd_monitor is not None:
                    raise HardwareUnqualifiedError(
                        f"cgroup_telemetry_unavailable:{exc}"
                    ) from exc
                raise EndpointRunError(f"cgroup_telemetry_unavailable:{exc}") from exc
            if reuse_trial:
                if baseline_cgroup_pids is None or tuple(
                    _cgroup_processes(path) for path in lane_cgroups
                ) != baseline_cgroup_pids:
                    raise EndpointRunError("reuse_worker_zero_state_process_mismatch")
                if (
                    cgroup_after[0].pids_current != len(baseline_cgroup_pids[0])
                    or cgroup_after[1].pids_current != len(baseline_cgroup_pids[1])
                ):
                    raise EndpointRunError("reuse_worker_cgroup_pid_count_changed")
            elif cgroup_after[0].pids_current or cgroup_after[1].pids_current:
                raise EndpointRunError("endpoint_cgroup_not_empty_after_shutdown")
            throttled_ns = (
                server_delta.cpu_throttled_ns + client_delta.cpu_throttled_ns
            )
            nr_throttled = (
                server_delta.cpu_nr_throttled + client_delta.cpu_nr_throttled
            )
            if throttled_ns or nr_throttled:
                if amd_monitor is not None:
                    raise HardwareUnqualifiedError(
                        "cgroup_cpu_throttling_detected"
                    )
                raise EndpointRunError(
                    "cgroup_cpu_throttling_detected", terminal_state="invalid"
                )
            resource_telemetry = {
                "server_cpu_ns": server_delta.cpu_usage_ns,
                "client_cpu_ns": client_delta.cpu_usage_ns,
                "server_memory_bytes": cgroup_active[0].memory_current_bytes,
                "client_memory_bytes": cgroup_active[1].memory_current_bytes,
                "server_memory_peak_bytes": cgroup_active[0].memory_peak_bytes,
                "client_memory_peak_bytes": cgroup_active[1].memory_peak_bytes,
                "cgroup_throttled_ns": throttled_ns,
                "cgroup_nr_throttled": nr_throttled,
            }
        if lane_health is not None:
            assert health is not None
            if any(health.device_irq_deltas.values()) or (
                health.non_owned_cpu_fraction_max >= 0.01
            ):
                raise EndpointRunError(
                    "external_cpu_or_irq_noise",
                    detail=_external_noise_detail(health),
                    infrastructure_transient=True,
                )
            if health.thermal_throttle_delta:
                raise EndpointRunError("thermal_throttle", terminal_state="invalid")
            if health.swap_active:
                if amd_monitor is not None:
                    raise HardwareUnqualifiedError("swap_activity")
                raise EndpointRunError("swap_activity", terminal_state="invalid")
            if resource_telemetry is None:
                resource_telemetry = {}
            resource_telemetry.update(
                {
                    "thermal_throttle_delta": health.thermal_throttle_delta,
                    "frequency_min_hz": health.frequency_min_hz,
                    "frequency_max_hz": health.frequency_max_hz,
                    "swap_active": int(health.swap_active),
                    "health_samples": health.health_samples,
                    "non_owned_cpu_fraction_max_decimal": normalize_decimal(
                        Decimal(str(health.non_owned_cpu_fraction_max))
                    ),
                    "device_irq_delta": sum(
                        sum(per_cpu.values())
                        for per_cpu in health.device_irq_deltas.values()
                    ),
                }
            )
        journal_record.transition("validating")
        if endpoint_override is None:
            server_config_hash = hashlib.sha256(
                canonical_bytes(server_wire_config)
            ).hexdigest()
            client_config_hash = hashlib.sha256(
                canonical_bytes(client_config)
            ).hexdigest()
        else:
            translated_hash = hashlib.sha256(canonical_bytes(config)).hexdigest()
            server_config_hash = translated_hash
            client_config_hash = translated_hash
        trial_wall_ns = (
            time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) - trial_wall_started_raw_ns
        )
        warmup_ns = int(workload["warmup_ns"])
        nonmeasurement_overhead_ns = _intrinsic_nonmeasurement_overhead_ns(
            trial_wall_ns=trial_wall_ns,
            warmup_ns=warmup_ns,
            measurement_ns=measurement_ns,
            arm_lead_ns=arm_policy.lead_ns,
            parallel_scheduled_padding_ns=parallel_scheduled_padding_ns,
        )
        runtime = {
            "scenario": str(config["scenario"]),
            "trial_wall_ns": trial_wall_ns,
            "warmup_ns": warmup_ns,
            "measurement_ns": measurement_ns,
            "parallel_peer_wait_ns": parallel_peer_wait_ns,
            "parallel_scheduled_padding_ns": parallel_scheduled_padding_ns,
            "nonmeasurement_overhead_ns": nonmeasurement_overhead_ns,
            "coordinator_cpu_ns": time.process_time_ns() - coordinator_cpu_started_ns,
            "coordinator_affinity": list(
                expected_coordinator_affinity
                if expected_coordinator_affinity is not None
                else sorted(os.sched_getaffinity(0))
            ),
            "measurement_control_packets": len(server_events) + len(client_events),
            "journal_writes_during_measurement": journal_writes_during_measurement,
            "worker_lifecycle": {
                "policy": "persistent_reset" if reuse_trial else "fresh_process",
                "server_generation": (
                    server_session.generation
                    if server_session is not None
                    else None
                ),
                "reference_client_generation": (
                    client_session.generation
                    if client_session is not None
                    else None
                ),
                "reset_inventory": reset_inventories,
            },
        }
        sample = _construct_sample(
            campaign_id=campaign_id,
            session=int(trial_row["session_number"]),
            microblock_id=str(trial_row["microblock_id"]),
            trial_id=trial_id,
            attempt_id=attempt_id,
            cell_id=cell_id,
            config=config,
            server_result=server_result,
            client_result=client_result,
            server_binary_sha256=str(server_entry["sha256"]),
            client_binary_sha256=str(client_entry["sha256"]),
            server_config_hash=server_config_hash,
            client_config_hash=client_config_hash,
            spec=spec,
            path_evidence=path_evidence,
            resource_telemetry=resource_telemetry,
            memory_observation=memory_observation,
            allow_client_headroom_failure=allow_client_headroom_failure,
            allow_resolution_limited=allow_resolution_limited,
            measurement_start_raw_ns=measurement_start,
            measurement_end_raw_ns=measurement_end,
        )
        journal_record.transition("validated_provisional")
        if reuse_trial:
            assert worker_pool is not None
            assert server_session is not None and client_session is not None
            worker_pool.release(server_session)
            worker_pool.release(client_session)
        if not construct_sample:
            return {
                "attempt_id": attempt_id,
                "cell_id": cell_id,
                "client_config_hash": client_config_hash,
                "client_result": client_result,
                "memory_observation": memory_observation,
                "path_evidence": path_evidence,
                "resource_telemetry": resource_telemetry,
                "reset_inventories": reset_inventories,
                "runtime": runtime,
                "server_config_hash": server_config_hash,
                "server_result": server_result,
                "trial_id": trial_id,
            }
        sample["runtime"] = runtime
        return sample


def _maybe_activate_capacity_confirmation(
    journal: Journal,
    campaign_id: str,
    basis_hex: str,
) -> dict[str, int] | None:
    dormant = journal.connection.execute(
        """
        SELECT COUNT(*) FROM microblock
        WHERE campaign_id=? AND phase='capacity_confirmation'
          AND status='dormant_candidate'
        """,
        (campaign_id,),
    ).fetchone()[0]
    if not dormant:
        return None
    missing = journal.connection.execute(
        """
        SELECT COUNT(*) FROM trial t JOIN microblock m USING(microblock_id)
        LEFT JOIN committed_sample s ON s.logical_trial_id=t.logical_trial_id
        WHERE t.campaign_id=? AND m.phase='capacity_search'
          AND m.slot='primary' AND s.trial_id IS NULL
        """,
        (campaign_id,),
    ).fetchone()[0]
    if missing:
        return None
    grouped: dict[tuple[str, str, str], list[CapacityPoint]] = {}
    rows = journal.connection.execute(
        """
        SELECT c.canonical_config, s.sample_json
        FROM trial t JOIN microblock m USING(microblock_id)
        JOIN cell c ON c.campaign_id=t.campaign_id AND c.cell_id=t.cell_id
        JOIN committed_sample s ON s.logical_trial_id=t.logical_trial_id
        WHERE t.campaign_id=? AND m.phase='capacity_search' AND m.slot='primary'
        ORDER BY t.logical_trial_id
        """,
        (campaign_id,),
    )
    for row in rows:
        config = loads_strict(row["canonical_config"])
        sample = loads_strict(row["sample_json"])
        key = (config["server"], config["server_backend"], config["scenario"])
        grouped.setdefault(key, []).append(
            CapacityPoint(
                concurrency=int(config["concurrency"]),
                reference_client=str(config["reference_client"]),
                rate=float(sample["metric"]["derived_decimal"]),
                valid=sample["completion_status"] == "valid",
                client_headroom_valid=float(sample["telemetry"]["client_cpu_p95_decimal"]) < 0.8,
            )
        )
    selections: dict[str, int | None] = {}
    basis = bytes.fromhex(basis_hex)
    for (server, backend, scenario), points in sorted(grouped.items()):
        group = domain_hash(
            "capacity-branch-group",
            basis,
            canonical_bytes({"server": server, "server_backend": backend, "scenario": scenario}),
        )
        selections[group] = nominate_capacity(points).candidate
    return journal.select_capacity_branches(campaign_id, selections)


def _attest_frozen_lane_count(
    journal: Journal,
    campaign_id: str,
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
    lane_count: int,
) -> None:
    """Refuse unqualified parallel execution before any endpoint is launched."""

    if lane_count <= 1:
        return
    if lane_count > 2:
        raise RunnerError("v2 supports at most two execution lanes")
    if spec.campaign_kind == "qualification" and spec.name == "lane-interference-validation":
        return
    row = journal.connection.execute(
        "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path=?",
        (campaign_id, "qualification/lane-interference.json"),
    ).fetchone()
    if row is None:
        raise RunnerError(
            "two-lane execution requires an acquired exact-identity lane-interference artifact"
        )
    content = bytes(row["content"])
    if hashlib.sha256(content).hexdigest() != row["sha256"]:
        raise RunnerError("lane-interference artifact checksum mismatch")
    try:
        decision, _artifact_hash, _identity_hash = decode_qualification_artifact(
            content,
            expected_kind="lane-interference",
            expected_identity=build_qualification_identity(
                "lane-interference", spec, manifest
            ),
        )
    except QualificationError as exc:
        raise RunnerError(f"lane-interference artifact is invalid: {exc}") from exc
    max_lanes = _qualification_max_lanes(decision)
    if not decision.qualified or max_lanes is None:
        raise RunnerError("lane-interference artifact does not qualify parallel lanes")
    if max_lanes < lane_count:
        raise RunnerError(
            f"lane-interference artifact permits {max_lanes} lane(s), not {lane_count}"
        )


def _attest_tail_durations(
    journal: Journal,
    campaign_id: str,
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
    schedule: Mapping[str, Any],
) -> None:
    if spec.campaign_kind != "tail":
        return
    diagnostic = _diagnostic_schedule_manifest(schedule)
    if diagnostic is not None:
        for block in schedule["blocks"]:
            for trial in block["trials"]:
                if (
                    trial["cell_config"].get("measurement_duration_ns")
                    != 20_000_000_000
                ):
                    raise IdentityMismatchError(
                        "diagnostic tail schedule does not use the frozen "
                        "20-second duration"
                    )
        return
    row = journal.connection.execute(
        "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path=?",
        (campaign_id, "qualification/tail-window.json"),
    ).fetchone()
    if row is None:
        raise RunnerError(
            "tail execution requires an acquired exact-identity tail-window artifact"
        )
    content = bytes(row["content"])
    if hashlib.sha256(content).hexdigest() != row["sha256"]:
        raise RunnerError("tail-window artifact checksum mismatch")
    try:
        decision, _artifact_hash, _identity_hash = decode_qualification_artifact(
            content,
            expected_kind="tail-window",
            expected_identity=build_qualification_identity(
                "tail-window", spec, manifest
            ),
        )
        durations = _tail_qualification_durations(decision, spec)
    except QualificationError as exc:
        raise RunnerError(f"tail-window artifact is invalid: {exc}") from exc
    for block in schedule["blocks"]:
        for trial in block["trials"]:
            cell = trial["cell_config"]
            scenario = str(cell["scenario"])
            expected = durations[scenario] * 1_000_000_000
            if cell.get("measurement_duration_ns") != expected:
                raise IdentityMismatchError(
                    "frozen tail schedule does not match its qualified scenario durations"
                )


def _attest_diagnostic_defaults(
    journal: Journal,
    campaign_id: str,
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
    schedule: Mapping[str, Any],
) -> bool:
    diagnostic = _diagnostic_schedule_manifest(schedule)
    if diagnostic is None:
        return False
    authorization = diagnostic["authorization"]
    authorization_row = journal.connection.execute(
        "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path=?",
        (
            campaign_id,
            "qualification/diagnostic-physical-failure-authorization.json",
        ),
    ).fetchone()
    if authorization_row is None:
        raise IdentityMismatchError(
            "diagnostic host-failure authorization artifact is missing"
        )
    authorization_content = bytes(authorization_row["content"])
    try:
        authorization_document = loads_strict(authorization_content)
    except Exception as exc:
        raise IdentityMismatchError(
            "diagnostic host-failure authorization artifact is invalid"
        ) from exc
    if (
        not isinstance(authorization_document, Mapping)
        or not isinstance(authorization_document.get("identity"), Mapping)
    ):
        raise IdentityMismatchError(
            "diagnostic host-failure authorization artifact is invalid"
        )
    try:
        authorization_decision, authorization_hash, authorization_identity = (
            decode_qualification_artifact(
                authorization_content,
                expected_kind=str(authorization["artifact_kind"]),
                expected_identity=authorization_document["identity"],
            )
        )
    except (KeyError, QualificationError) as exc:
        raise IdentityMismatchError(
            "diagnostic host-failure authorization artifact is invalid"
        ) from exc
    if (
        hashlib.sha256(authorization_content).hexdigest()
        != authorization_row["sha256"]
        or authorization_row["sha256"] != authorization["content_sha256"]
        or not isinstance(authorization_document, Mapping)
        or canonical_bytes(authorization_document) + b"\n"
        != authorization_content
        or authorization_document.get("artifact_hash")
        != authorization["artifact_hash"]
        or authorization_document.get("artifact_kind")
        != authorization["artifact_kind"]
        or authorization_document.get("identity_hash")
        != authorization["identity_hash"]
        or authorization_document.get("status") != "not_qualified"
        or authorization_document.get("qualified") is not False
        or authorization_document.get("reasons") != authorization["reasons"]
        or authorization_document["identity"].get("profile_hash")
        != authorization["profile_hash"]
        or authorization_hash != authorization["artifact_hash"]
        or authorization_identity != authorization["identity_hash"]
        or authorization_decision.status != "not_qualified"
        or list(authorization_decision.reasons) != authorization["reasons"]
    ):
        raise IdentityMismatchError(
            "diagnostic host-failure authorization evidence differs"
        )
    if {
        int(block.get("lane", 0))
        for block in schedule["blocks"]
    } != {0}:
        raise IdentityMismatchError(
            "diagnostic-unqualified-host execution must use exactly one lane"
        )
    qualification_rows = diagnostic["qualifications"]
    if (
        any(not isinstance(item, Mapping) for item in qualification_rows)
        or {str(item.get("kind")) for item in qualification_rows}
        != set(ARTIFACT_KINDS)
        or len(qualification_rows) != len(ARTIFACT_KINDS)
    ):
        raise IdentityMismatchError(
            "diagnostic qualification inventory is incomplete or duplicated"
        )
    for item in qualification_rows:
        kind = str(item["kind"])
        identity = build_qualification_identity(kind, spec, manifest)
        if (
            item.get("identity_hash")
            != qualification_identity_hash(kind, identity)
            or item.get("required")
            is not bool(
                spec.raw["qualification"][_QUALIFICATION_REQUIRED_FIELDS[kind]]
            )
        ):
            raise IdentityMismatchError(
                f"diagnostic {kind} qualification identity differs"
            )
        row = journal.connection.execute(
            "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path=?",
            (campaign_id, f"qualification/{kind}.json"),
        ).fetchone()
        if item.get("artifact_hash") is None:
            if (
                row is not None
                or item.get("content_sha256") is not None
                or item.get("status") != "missing"
                or item.get("qualified") is not False
                or item.get("reasons") != ["exact_identity_artifact_missing"]
            ):
                raise IdentityMismatchError(
                    f"diagnostic missing {kind} qualification evidence differs"
                )
            continue
        if row is None:
            raise IdentityMismatchError(
                f"diagnostic {kind} qualification artifact is missing"
            )
        content = bytes(row["content"])
        if (
            hashlib.sha256(content).hexdigest() != row["sha256"]
            or row["sha256"] != item.get("content_sha256")
        ):
            raise IdentityMismatchError(
                f"diagnostic {kind} qualification artifact checksum differs"
            )
        try:
            decision, artifact_hash, identity_hash = decode_qualification_artifact(
                content,
                expected_kind=kind,
                expected_identity=identity,
            )
        except QualificationError as exc:
            raise IdentityMismatchError(
                f"diagnostic {kind} qualification artifact is invalid"
            ) from exc
        if (
            artifact_hash != item.get("artifact_hash")
            or identity_hash != item.get("identity_hash")
            or decision.status != item.get("status")
            or decision.qualified is not item.get("qualified")
            or list(decision.reasons) != item.get("reasons")
        ):
            raise IdentityMismatchError(
                f"diagnostic {kind} qualification decision differs"
            )
    if spec.campaign_kind == "publication" or spec.estimand == "symmetric_stack_pair":
        for block in schedule["blocks"]:
            for trial in block["trials"]:
                cell = trial["cell_config"]
                expected = (
                    10_000_000_000
                    if cell["path_profile"] == "loopback"
                    else 20_000_000_000
                )
                if cell.get("measurement_duration_ns") != expected:
                    raise IdentityMismatchError(
                        "diagnostic fixed schedule duration differs"
                    )
    return True


def _load_host_stability_context(
    journal: Journal,
    campaign_id: str,
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
) -> _AmdSessionContext | None:
    if not spec.raw["qualification"]["host_stability_required"]:
        return None
    row = journal.connection.execute(
        "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path=?",
        (campaign_id, "qualification/host-stability.json"),
    ).fetchone()
    if row is None:
        raise RunnerError(
            "session execution requires an acquired exact-identity host-stability artifact"
        )
    content = bytes(row["content"])
    if hashlib.sha256(content).hexdigest() != row["sha256"]:
        raise RunnerError("host-stability artifact checksum mismatch")
    try:
        decision, _artifact_hash, _identity_hash = decode_qualification_artifact(
            content,
            expected_kind="host-stability",
            expected_identity=build_qualification_identity(
                "host-stability", spec, manifest
            ),
        )
    except QualificationError as exc:
        raise RunnerError(f"host-stability artifact is invalid: {exc}") from exc
    if not decision.qualified:
        raise RunnerError(
            "host-stability artifact marks this exact identity hardware_unqualified"
        )
    evidence = decision.evidence
    if (
        evidence.get("provider") != AMD_PROVIDER_VERSION
        or evidence.get("hardware_status") != "qualified"
    ):
        raise RunnerError("host-stability artifact provider decision is invalid")
    layout = tuple(manifest.host_policy["lane_layout"])
    cpus = tuple(
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
                for cpu in map(int, lane["housekeeping_cpus"])
            }
        )
    )
    try:
        monitor_cpu = int(irq_policy_identity()["boot"]["monitor_cpu"])
    except (HostPolicyError, KeyError, TypeError, ValueError) as exc:
        raise RunnerError(f"live monitor CPU policy is invalid: {exc}") from exc
    try:
        monitor_core = next(
            core
            for core in discover_physical_cores(respect_process_affinity=False)
            if monitor_cpu in core.cpus
        )
    except (OSError, StopIteration, TopologyError, ValueError) as exc:
        raise RunnerError("live monitor CPU has no physical core") from exc
    if (
        not cpus
        or not housekeeping
        or set(cpus) & set(housekeeping)
        or set(monitor_core.cpus) & (set(cpus) | set(housekeeping))
        or evidence.get("measurement_cpus") != list(cpus)
        or evidence.get("housekeeping_cpu") != monitor_cpu
    ):
        raise RunnerError("host-stability artifact CPU ownership differs from the manifest")
    raw_reference = evidence.get("reference")
    if not isinstance(raw_reference, Mapping) or set(raw_reference) != {
        "ratio",
        "loop_iterations",
    }:
        raise RunnerError("host-stability artifact reference is missing")

    def decode_reference(field: str) -> dict[int, float]:
        raw = raw_reference[field]
        if not isinstance(raw, Mapping):
            raise RunnerError(f"host-stability {field} reference is malformed")
        try:
            result = {int(cpu): float(value) for cpu, value in raw.items()}
        except (TypeError, ValueError) as exc:
            raise RunnerError(
                f"host-stability {field} reference is malformed"
            ) from exc
        if set(result) != set(cpus) or any(
            not math.isfinite(value) or value <= 0 for value in result.values()
        ):
            raise RunnerError(f"host-stability {field} reference CPU set is invalid")
        return result

    helpers = [
        entry
        for entry in manifest.binaries
        if entry["name"] == "quicperf-amd-stability-probe"
        and entry["role"] == "coordinator"
    ]
    if len(helpers) != 1:
        raise RunnerError("manifest lacks one AMD stability helper")
    helper = _assert_binary_unchanged(helpers[0])
    spin_helpers = [
        entry
        for entry in manifest.binaries
        if entry["name"] == "quicperf-monitor-spin"
        and entry["role"] == "coordinator"
    ]
    if len(spin_helpers) != 1:
        raise RunnerError("manifest lacks one AMD monitor spin helper")
    spin_helper = _assert_binary_unchanged(spin_helpers[0])
    try:
        cpu_model, _flags = read_cpu_model_and_flags()
        policy = _apply_amd_methodology(
            spec, load_amd_provider_policy(cpu_model=cpu_model)
        )
        verify_cpu_prerequisites(policy)
        temperature_source = resolve_temperature_source(policy)
    except HealthError as exc:
        raise RunnerError(f"live AMD session prerequisites failed: {exc}") from exc
    return _AmdSessionContext(
        cpus,
        monitor_cpu,
        helper,
        spin_helper,
        policy,
        AmdReference(
            decode_reference("ratio"),
            decode_reference("loop_iterations"),
        ),
        temperature_source,
    )


def _terminate_active_processes(
    active_processes: dict[int, ManagedProcess],
    lock: threading.Lock,
) -> None:
    """Apply one shared two-second TERM / one-second KILL deadline."""

    with lock:
        processes = tuple(active_processes.values())
    for managed in processes:
        if managed.process.poll() is None:
            try:
                os.killpg(managed.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    term_deadline = time.monotonic() + 2.0
    for managed in processes:
        if managed.process.poll() is None:
            try:
                managed.process.wait(timeout=max(0.0, term_deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
    survivors = tuple(
        managed for managed in processes if managed.process.poll() is None
    )
    for managed in survivors:
        try:
            os.killpg(managed.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    kill_deadline = time.monotonic() + 1.0
    for managed in survivors:
        if managed.process.poll() is None:
            try:
                managed.process.wait(timeout=max(0.0, kill_deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
    if any(managed.process.poll() is None for managed in survivors):
        raise EndpointRunError("endpoint_process_group_survived_interrupt_cleanup")


@contextmanager
def _automatic_gc_suspended() -> Iterable[None]:
    """Keep coordinator GC from preempting a cadence-attested hardware probe."""

    was_enabled = gc.isenabled()
    if was_enabled:
        gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def run_campaign_session(
    *,
    root: Path,
    run_dir: Path,
    session: int,
    endpoint_override: Iterable[str] | None = None,
    endpoint_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Resume and execute one frozen session transactionally.

    ``endpoint_override`` exists only for deterministic fake-endpoint tests; the
    command surface never exposes it.
    """

    session_wall_started_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    session_cpu_started_ns = time.process_time_ns()
    observed_runtimes: list[Mapping[str, Any]] = []
    runtime_lane_count = 1
    accumulated_session_wall_ns = 0
    runtime_state_started_raw_ns: int | None = None

    def runtime_summary() -> dict[str, Any]:
        now_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        wall_ns = accumulated_session_wall_ns + (
            now_raw_ns - runtime_state_started_raw_ns
            if runtime_state_started_raw_ns is not None
            else 0
        )
        measurements = [int(item["measurement_ns"]) for item in observed_runtimes]
        steady_runtimes = [
            item
            for item in observed_runtimes
            if item.get("scenario")
            not in {"connect", "resumed_connect", "zero_rtt_reqresp", "memory_curve"}
        ]
        overheads = sorted(
            int(item["nonmeasurement_overhead_ns"]) for item in steady_runtimes
        )
        if overheads:
            middle = len(overheads) // 2
            median = (
                overheads[middle]
                if len(overheads) % 2
                else (overheads[middle - 1] + overheads[middle]) // 2
            )
            p95 = overheads[(95 * len(overheads) + 99) // 100 - 1]
        else:
            median = p95 = 0
        useful_ns = sum(measurements)
        lane_wall_capacity_ns = wall_ns * runtime_lane_count
        with localcontext() as context:
            context.prec = 40
            useful_fraction = (
                normalize_decimal(
                    Decimal(useful_ns) / Decimal(lane_wall_capacity_ns)
                )
                if lane_wall_capacity_ns
                else "0"
            )
        return {
            "session_wall_ns": wall_ns,
            "coordinator_cpu_ns": time.process_time_ns() - session_cpu_started_ns,
            "successful_trial_count": len(observed_runtimes),
            "steady_state_trial_count": len(steady_runtimes),
            "useful_measurement_ns": useful_ns,
            "qualified_lane_count": runtime_lane_count,
            "lane_wall_capacity_ns": lane_wall_capacity_ns,
            "useful_wall_fraction_decimal": useful_fraction,
            "nonmeasurement_overhead_median_ns": median,
            "nonmeasurement_overhead_p95_ns": p95,
            "journal_writes_during_measurement": sum(
                int(item["journal_writes_during_measurement"])
                for item in observed_runtimes
            ),
        }

    def publication_budget_reached() -> bool:
        return _publication_session_budget_reached(
            spec,
            diagnostic_unqualified_host,
            int(runtime_summary()["session_wall_ns"]),
        )

    override = tuple(endpoint_override) if endpoint_override is not None else None
    with Journal(run_dir) as journal:
        spec, manifest, schedule = _persisted_run_identity(journal, run_dir)
        campaign = campaign_identity(journal)
        campaign_id = str(campaign["campaign_id"])

        def refresh_observed_runtimes() -> None:
            observed_runtimes.clear()
            rows = journal.connection.execute(
                """
                SELECT s.sample_json FROM committed_sample s
                JOIN trial t USING(trial_id)
                JOIN microblock m USING(microblock_id)
                WHERE t.campaign_id=? AND m.session_number=?
                ORDER BY m.ordinal, t.ordinal
                """,
                (campaign_id, session),
            )
            for row in rows:
                sample = loads_strict(str(row["sample_json"]))
                if (
                    not isinstance(sample, Mapping)
                    or not isinstance(sample.get("runtime"), Mapping)
                    or not isinstance(sample["runtime"].get("scenario"), str)
                ):
                    raise IdentityMismatchError(
                        "committed sample runtime evidence is missing or malformed"
                    )
                observed_runtimes.append(sample["runtime"])

        if session < 1 or session > int(spec.expected_cardinality.sessions):
            raise RunnerError(f"session must be in [1, {spec.expected_cardinality.sessions}]")
        block_schedule = {
            str(block["microblock_id"]): block for block in schedule["blocks"]
        }
        workloads = {
            str(workload["scenario"]): workload
            for workload in spec.raw["workloads"]
        }
        arm_control_policy = _arm_control_policy(spec)
        block_arm_ns = {
            str(block["microblock_id"]): sum(
                int(
                    trial["cell_config"].get(
                        "measurement_duration_ns",
                        workloads[str(trial["cell_config"]["scenario"])][
                            "measurement_ns"
                        ],
                    )
                )
                + int(
                    workloads[str(trial["cell_config"]["scenario"])]["warmup_ns"]
                )
                for trial in block["trials"]
            )
            for block in schedule["blocks"]
        }
        block_scheduled_ns = {
            str(block["microblock_id"]): block_arm_ns[
                str(block["microblock_id"])
            ]
            + len(block["trials"]) * arm_control_policy.lead_ns
            for block in schedule["blocks"]
        }
        runtime_lane_count = len(
            {
                int(block.get("lane", 0))
                for block in schedule["blocks"]
                if int(block["session"]) == session
            }
        ) or 1
        diagnostic_unqualified_host = _attest_diagnostic_defaults(
            journal, campaign_id, spec, manifest, schedule
        )
        _attest_frozen_lane_count(
            journal, campaign_id, spec, manifest, runtime_lane_count
        )
        _attest_tail_durations(
            journal, campaign_id, spec, manifest, schedule
        )
        session_row = journal.connection.execute(
            "SELECT status FROM session WHERE campaign_id=? AND session_number=?",
            (campaign_id, session),
        ).fetchone()
        active_blocks = journal.connection.execute(
            """
            SELECT COUNT(*) FROM microblock
            WHERE campaign_id=? AND session_number=? AND status='active'
            """,
            (campaign_id, session),
        ).fetchone()[0]
        if (
            session_row is not None
            and session_row["status"] in {"complete", "nonpublishable"}
            and active_blocks == 0
        ):
            document, artifact_error = _runtime_artifact(
                journal, campaign_id, f"runtime/session-{session}.json"
            )
            if artifact_error is not None or document is None:
                raise IdentityMismatchError(
                    "terminal session runtime artifact is missing or invalid"
                )
            if (
                document.get("campaign_id") != campaign_id
                or document.get("session") != session
                or document.get("status") != session_row["status"]
                or not isinstance(document.get("runtime"), Mapping)
            ):
                raise IdentityMismatchError(
                    "terminal session runtime artifact identity differs"
                )
            committed = journal.connection.execute(
                """
                SELECT COUNT(*) FROM microblock
                WHERE campaign_id=? AND session_number=? AND status='committed'
                """,
                (campaign_id, session),
            ).fetchone()[0]
            failed = journal.connection.execute(
                """
                SELECT COUNT(*) FROM microblock
                WHERE campaign_id=? AND session_number=? AND status='failed'
                """,
                (campaign_id, session),
            ).fetchone()[0]
            return {
                "status": str(session_row["status"]),
                "committed_microblocks": int(committed),
                "failed_microblocks": int(failed),
                "remaining_microblocks": 0,
                "recovery": {"untouched": 0, "retried": 0, "retry_failed": 0},
                "runtime": dict(document["runtime"]),
                "already_terminal": True,
            }
        if campaign["status"] == "hardware_unqualified":
            raise RunnerError(
                "campaign is hardware_unqualified; no further session may execute"
            )

        amd_context = (
            None
            if override is not None or diagnostic_unqualified_host
            else _load_host_stability_context(
                journal, campaign_id, spec, manifest
            )
        )

        try:
            runtime_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()
        except OSError as exc:
            raise RunnerError(f"runtime boot identity is unavailable: {exc}") from exc
        if not runtime_boot_id:
            raise RunnerError("runtime boot identity is empty")
        runtime_state_path = f"runtime/session-{session}-state.json"
        state_row = journal.connection.execute(
            "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path=?",
            (campaign_id, runtime_state_path),
        ).fetchone()
        if state_row is not None:
            state_content = bytes(state_row["content"])
            if hashlib.sha256(state_content).hexdigest() != state_row["sha256"]:
                raise IdentityMismatchError("session runtime state checksum differs")
            try:
                state = loads_strict(state_content)
            except Exception as exc:
                raise IdentityMismatchError(
                    "session runtime state is malformed"
                ) from exc
            if (
                not isinstance(state, Mapping)
                or canonical_bytes(state) != state_content
                or set(state)
                != {
                    "schema_version",
                    "campaign_id",
                    "session",
                    "boot_id",
                    "accumulated_wall_ns",
                    "active_started_raw_ns",
                }
                or state.get("schema_version") != "quicperf.runtime-state.v1"
                or state.get("campaign_id") != campaign_id
                or state.get("session") != session
                or state.get("boot_id") != runtime_boot_id
                or type(state.get("accumulated_wall_ns")) is not int
                or state["accumulated_wall_ns"] < 0
                or (
                    state.get("active_started_raw_ns") is not None
                    and (
                        type(state["active_started_raw_ns"]) is not int
                        or state["active_started_raw_ns"] < 0
                        or state["active_started_raw_ns"] > session_wall_started_raw_ns
                    )
                )
            ):
                raise IdentityMismatchError("session runtime state identity differs")
            accumulated_session_wall_ns = int(state["accumulated_wall_ns"])
            if state["active_started_raw_ns"] is not None:
                accumulated_session_wall_ns += (
                    session_wall_started_raw_ns - int(state["active_started_raw_ns"])
                )
        runtime_state_started_raw_ns = session_wall_started_raw_ns

        def store_runtime_state() -> None:
            journal.store_artifact(
                campaign_id,
                runtime_state_path,
                canonical_bytes(
                    {
                        "schema_version": "quicperf.runtime-state.v1",
                        "campaign_id": campaign_id,
                        "session": session,
                        "boot_id": runtime_boot_id,
                        "accumulated_wall_ns": accumulated_session_wall_ns,
                        "active_started_raw_ns": runtime_state_started_raw_ns,
                    }
                ),
                media_type="application/json",
            )

        def close_runtime_state() -> None:
            nonlocal accumulated_session_wall_ns, runtime_state_started_raw_ns
            if runtime_state_started_raw_ns is not None:
                now_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
                if now_raw_ns < runtime_state_started_raw_ns:
                    raise RunnerError("session runtime clock regressed")
                accumulated_session_wall_ns += now_raw_ns - runtime_state_started_raw_ns
                runtime_state_started_raw_ns = None
                store_runtime_state()

        store_runtime_state()
        resources = ExitStack()
        persistent_worker_policy = _persistent_worker_enabled(
            spec,
            diagnostic_unqualified_host=diagnostic_unqualified_host,
        )
        if override is None:
            binary_paths = _reattest_run_environment(root, spec, manifest)
            cgroup_root = delegated_cgroup_root()
            LaneCgroups.reap_stale(cgroup_root)
            lane_ids = {
                int(block.get("lane", 0))
                for block in schedule["blocks"]
                if int(block["session"]) == session
            }
            lane_topologies = {lane: _frozen_lane(manifest, lane) for lane in lane_ids}
            previous_affinity = os.sched_getaffinity(0)
            housekeeping = {
                cpu for topology in lane_topologies.values() for cpu in topology.housekeeping_cpus
            }
            reserved_monitor_cpus: tuple[int, ...] = ()
            if not housekeeping:
                raise RunnerError("campaign coordinator has no housekeeping CPU")
            os.sched_setaffinity(0, housekeeping)
            resources.callback(os.sched_setaffinity, 0, previous_affinity)
            expected_coordinator_affinity = _attest_coordinator_affinity(
                lane_topologies,
                reserved_cpus=reserved_monitor_cpus,
            )
            lane_groups: dict[int, tuple[Path, Path]] = {}
            lane_worker_groups: dict[
                int, dict[tuple[str, str, str], Path]
            ] = {}
            lane_paths: dict[
                int, LoopbackPathController | NamespacePathController
            ] = {}
            needs_namespace_path = any(
                str(workload["path_profile"]) != "loopback"
                for workload in spec.raw["workloads"]
            )
            for lane, topology in sorted(lane_topologies.items()):
                cgroups = LaneCgroups(cgroup_root, topology)
                resources.callback(cgroups.cleanup)
                lane_groups[lane] = cgroups.create()
                lane_worker_groups[lane] = {}
                if persistent_worker_policy:
                    for server in spec.servers:
                        for backend in spec.server_backends:
                            lane_worker_groups[lane][
                                ("server", server, backend)
                            ] = cgroups.create_worker(
                                "server", f"{server}/{backend}"
                            )
                    for client in spec.reference_clients:
                        backend = spec.reference_client_backend
                        lane_worker_groups[lane][
                            ("reference_client", client, backend)
                        ] = cgroups.create_worker(
                            "client", f"{client}/{backend}"
                        )
                path = (
                    NamespacePathController(lane, campaign_id)
                    if needs_namespace_path
                    else LoopbackPathController()
                )
                path.create_session()
                resources.callback(path.cleanup)
                lane_paths[lane] = path
        else:
            binary_paths = {
                name: Path(str(entry["path"]))
                for name, entry in _binary_entries(manifest).items()
            }
            lane_topologies = {}
            lane_groups = {}
            lane_worker_groups = {}
            lane_paths = {}
            expected_coordinator_affinity = None
        amd_monitor: AmdContinuousMonitor | None = None
        amd_monitor_stopped = False
        amd_session_evidence: dict[str, Any] = {
            "schema_version": "quicperf.amd-session-stability.v1",
            "provider": AMD_PROVIDER_VERSION,
            "campaign_id": campaign_id,
            "session": session,
            "passed": False,
            "reasons": [],
            "pre_probe": None,
            "replay_pre_probes": [],
            "replayed_attempts": [],
            "continuous": None,
            "post_probe": None,
        }
        try:
            recovery: dict[str, Any] = {
                "untouched": 0,
                "retried": 0,
                "retry_failed": 0,
            }
            interrupted = journal.connection.execute(
                """
                SELECT COUNT(*) FROM microblock m JOIN trial t USING(microblock_id)
                LEFT JOIN attempt a USING(trial_id)
                WHERE m.campaign_id=? AND m.session_number=? AND m.status='active'
                  AND (t.state!='planned' OR (a.state IS NOT NULL AND a.state!='planned'))
                """,
                (campaign_id, session),
            ).fetchone()[0]
            if interrupted:
                replay = journal.activate_session_retry(
                    campaign_id, session, "coordinator_interruption"
                )
                recovery["session_replay"] = replay
                if replay["status"] == "retry_activated":
                    recovery["retried"] = int(replay["activated"])
                else:
                    recovery["retry_failed"] = 1
            if recovery["retry_failed"]:
                refresh_observed_runtimes()
                close_runtime_state()
                runtime = runtime_summary()
                journal.store_artifact(
                    campaign_id,
                    f"runtime/session-{session}.json",
                    canonical_bytes(
                        {
                            "schema_version": "quicperf.runtime.v1",
                            "campaign_id": campaign_id,
                            "session": session,
                            "status": "nonpublishable",
                            "runtime": runtime,
                        }
                    ),
                    media_type="application/json",
                )
                return {
                    "status": "nonpublishable",
                    "committed_microblocks": 0,
                    "recovery": recovery,
                    "runtime": runtime,
                }
            active_processes: dict[int, ManagedProcess] = {}
            active_processes_lock = threading.Lock()
            worker_pool: _WorkerPool | None = None
            journal.set_session_status(campaign_id, session, "running")
            committed_blocks = 0
            failed_cells: set[str] = set()
            failed_cells_lock = threading.Lock()

            def refresh_failed_cells() -> None:
                rows = journal.connection.execute(
                    """
                    SELECT DISTINCT t.cell_id
                    FROM microblock m JOIN trial t USING(microblock_id)
                    WHERE m.campaign_id=? AND m.session_number=?
                      AND m.status='failed'
                      AND EXISTS (
                          SELECT 1
                          FROM trial root_trial
                          JOIN attempt root_attempt USING(trial_id)
                          WHERE root_trial.microblock_id=m.microblock_id
                            AND root_attempt.termination_reason IS NOT NULL
                            AND root_attempt.termination_reason
                                != 'suppressed_deterministic_failure'
                      )
                    """,
                    (campaign_id, session),
                )
                with failed_cells_lock:
                    failed_cells.clear()
                    failed_cells.update(str(row["cell_id"]) for row in rows)

            refresh_failed_cells()

            def stop_amd_monitor() -> dict[str, Any] | None:
                nonlocal amd_monitor_stopped
                if amd_monitor is None:
                    return None
                if not amd_monitor_stopped:
                    amd_session_evidence["continuous"] = amd_monitor.stop()
                    amd_monitor_stopped = True
                value = amd_session_evidence["continuous"]
                return dict(value) if isinstance(value, Mapping) else None

            def hardware_unqualified_result(reason: str) -> dict[str, Any]:
                try:
                    _terminate_active_processes(
                        active_processes, active_processes_lock
                    )
                except EndpointRunError as cleanup_error:
                    amd_session_evidence["reasons"].append(
                        f"cleanup_error:{cleanup_error.reason}"
                    )
                if worker_pool is not None:
                    try:
                        worker_pool.abandon_terminated()
                    except EndpointRunError as cleanup_error:
                        amd_session_evidence["reasons"].append(
                            f"cleanup_error:{cleanup_error.reason}"
                        )
                try:
                    stop_amd_monitor()
                except HealthError as monitor_error:
                    amd_session_evidence["reasons"].append(
                        f"monitor_stop_error:{monitor_error}"
                    )
                amd_session_evidence["reasons"].insert(0, reason)
                invalidation = journal.invalidate_session_hardware(
                    campaign_id,
                    session,
                    reason,
                    amd_session_evidence,
                )
                refresh_observed_runtimes()
                close_runtime_state()
                runtime = runtime_summary()
                journal.store_artifact(
                    campaign_id,
                    f"runtime/session-{session}.json",
                    canonical_bytes(
                        {
                            "schema_version": "quicperf.runtime.v1",
                            "campaign_id": campaign_id,
                            "session": session,
                            "status": "nonpublishable",
                            "runtime": runtime,
                        }
                    ),
                    media_type="application/json",
                )
                return {
                    "status": "nonpublishable",
                    "hardware_status": "hardware_unqualified",
                    "committed_microblocks": 0,
                    "failed_microblocks": int(
                        invalidation["failed_active_microblocks"]
                    ),
                    "remaining_microblocks": 0,
                    "recovery": recovery,
                    "runtime": runtime,
                    "hardware_invalidation": invalidation,
                }

            def restart_amd_monitor_after_transient(
                reason: str, prior_monitor: Mapping[str, Any] | None
            ) -> None:
                nonlocal amd_monitor, amd_monitor_stopped
                if amd_context is None:
                    raise HardwareUnqualifiedError(
                        "amd_monitor_transient_without_provider"
                    )
                amd_session_evidence["replayed_attempts"].append(
                    {
                        "reason": reason,
                        "continuous": (
                            None if prior_monitor is None else dict(prior_monitor)
                        ),
                    }
                )
                amd_session_evidence["continuous"] = None
                amd_monitor = None
                amd_monitor_stopped = False
                try:
                    replay_evaluation, replay_probe = run_amd_session_probe(
                        cpus=amd_context.cpus,
                        housekeeping_cpu=amd_context.housekeeping_cpu,
                        helper=amd_context.helper,
                        policy=amd_context.policy,
                        reference=amd_context.reference,
                        temperature_source=amd_context.temperature_source,
                    )
                except HealthError as probe_error:
                    raise HardwareUnqualifiedError(
                        f"amd_replay_pre_session_probe_error:{probe_error}"
                    ) from probe_error
                amd_session_evidence["replay_pre_probes"].append(replay_probe)
                if not replay_evaluation.passed:
                    raise HardwareUnqualifiedError(
                        "amd_replay_pre_session_probe_failed:"
                        + ",".join(replay_evaluation.reasons)
                    )
                amd_monitor = AmdContinuousMonitor(
                    cpus=amd_context.cpus,
                    housekeeping_cpu=amd_context.housekeeping_cpu,
                    spin_helper=amd_context.spin_helper,
                    policy=amd_context.policy,
                    reference=amd_context.reference,
                    temperature_source=amd_context.temperature_source,
                )
                try:
                    amd_monitor.start()
                except AmdMonitorTransientError as monitor_error:
                    raise HardwareUnqualifiedError(
                        f"amd_monitor_second_transient:{monitor_error}"
                    ) from monitor_error
                except HealthError as monitor_error:
                    raise HardwareUnqualifiedError(
                        f"amd_replay_monitor_start_failed:{monitor_error}"
                    ) from monitor_error

            if amd_context is not None:
                try:
                    pre_evaluation, pre_document = run_amd_session_probe(
                        cpus=amd_context.cpus,
                        housekeeping_cpu=amd_context.housekeeping_cpu,
                        helper=amd_context.helper,
                        policy=amd_context.policy,
                        reference=amd_context.reference,
                        temperature_source=amd_context.temperature_source,
                    )
                    amd_session_evidence["pre_probe"] = pre_document
                except HealthError as exc:
                    amd_session_evidence["pre_probe"] = {
                        "passed": False,
                        "reasons": [f"probe_error:{exc}"],
                    }
                    return hardware_unqualified_result(
                        f"amd_pre_session_probe_error:{exc}"
                    )
                if not pre_evaluation.passed:
                    return hardware_unqualified_result(
                        "amd_pre_session_probe_failed:"
                        + ",".join(pre_evaluation.reasons)
                    )
                amd_monitor = AmdContinuousMonitor(
                    cpus=amd_context.cpus,
                    housekeeping_cpu=amd_context.housekeeping_cpu,
                    spin_helper=amd_context.spin_helper,
                    policy=amd_context.policy,
                    reference=amd_context.reference,
                    temperature_source=amd_context.temperature_source,
                )
                try:
                    amd_monitor.start()
                except AmdMonitorTransientError as exc:
                    if (
                        spec.schema_version
                        in VERSIONED_PUBLICATION_SCHEMA_VERSIONS
                    ):
                        raise HardwareUnqualifiedError(
                            f"amd_continuous_monitor_start_failed:{exc}"
                        ) from exc
                    prior_monitor = stop_amd_monitor()
                    replay = journal.activate_session_retry(
                        campaign_id,
                        session,
                        "host_stability_monitor_transient",
                    )
                    recovery["session_replay"] = replay
                    if replay["status"] == "retry_exhausted":
                        return hardware_unqualified_result(
                            f"amd_monitor_second_transient:{exc}"
                        )
                    restart_amd_monitor_after_transient(
                        "host_stability_monitor_transient", prior_monitor
                    )
                except HealthError as exc:
                    return hardware_unqualified_result(
                        f"amd_continuous_monitor_start_failed:{exc}"
                    )
            if persistent_worker_policy:
                worker_pool = _WorkerPool(
                    root=root,
                    endpoint_override=override,
                    environment=dict(endpoint_environment or {}),
                    active_processes=active_processes,
                    active_processes_lock=active_processes_lock,
                )
                resources.callback(worker_pool.close)
            measurement_barrier: threading.Barrier | None = None
            shared_measurement_epoch: _ArmWindowCoordinator | None = None
            session_abort = threading.Event()
            budget_exhaustion = threading.Event()
            deterministic_publication_failure = threading.Event()
            session_replay_reason: dict[str, str] = {}

            def publication_budget_allows(block_id: str) -> bool:
                return _publication_session_budget_allows_block(
                    spec,
                    diagnostic_unqualified_host,
                    int(runtime_summary()["session_wall_ns"]),
                    block_scheduled_ns[block_id],
                )

            def execute_block(
                lane_journal: Journal,
                block_id: str,
                *,
                epoch_abort: threading.Event | None = None,
            ) -> tuple[int, list[Mapping[str, Any]]]:
                members = lane_journal.connection.execute(
                    """
                    SELECT t.*, m.session_number, c.canonical_config
                    FROM trial t JOIN microblock m USING(microblock_id)
                    JOIN cell c ON c.campaign_id=t.campaign_id AND c.cell_id=t.cell_id
                    WHERE t.microblock_id=? ORDER BY t.ordinal
                    """,
                    (block_id,),
                ).fetchall()
                with failed_cells_lock:
                    suppress = any(
                        str(member["cell_id"]) in failed_cells for member in members
                    )
                if suppress:
                    lane_journal.fail_microblock(
                        block_id, "suppressed_deterministic_failure"
                    )
                    return 0, []
                samples: dict[str, Any] = {}
                runtimes: list[Mapping[str, Any]] = []
                try:
                    for member in members:
                        if epoch_abort is not None and epoch_abort.is_set():
                            raise _PublicationEpochFailure(
                                block_id=block_id,
                                root_trial_id=str(member["trial_id"]),
                                cell_ids=tuple(
                                    str(item["cell_id"]) for item in members
                                ),
                                error=EndpointRunError(
                                    "parallel_epoch_peer_cancelled",
                                    terminal_state="invalid",
                                ),
                                collateral=True,
                            )
                        if session_abort.is_set():
                            if deterministic_publication_failure.is_set():
                                lane_journal.fail_microblock(
                                    block_id,
                                    "parallel_epoch_peer_deterministic_failure",
                                    terminal_state="invalid",
                                    root_trial_id=str(member["trial_id"]),
                                )
                                return 0, []
                            if "hardware_unqualified" in session_replay_reason:
                                raise HardwareUnqualifiedError(
                                    session_replay_reason["hardware_unqualified"]
                                )
                            raise SessionReplayRequired(
                                session_replay_reason.get(
                                    "reason",
                                    "treatment_independent_monitor_transient",
                                )
                            )
                        config = loads_strict(member["canonical_config"])
                        frozen_block = block_schedule[block_id]
                        config["trace_seed"] = frozen_block.get(
                            "trace_seed", "0" * 64
                        )
                        lane = int(frozen_block.get("lane", 0))
                        config["lane"] = lane
                        if "williams_row" in frozen_block:
                            config["williams_row"] = int(
                                frozen_block["williams_row"]
                            )
                        trial_cgroups = lane_groups.get(lane)
                        if (
                            worker_pool is not None
                            and _worker_reuse_eligible(
                                spec.campaign_kind, str(config["scenario"])
                            )
                            and override is None
                        ):
                            placements = lane_worker_groups[lane]
                            try:
                                trial_cgroups = (
                                    placements[
                                        (
                                            "server",
                                            str(config["server"]),
                                            str(config["server_backend"]),
                                        )
                                    ],
                                    placements[
                                        (
                                            "reference_client",
                                            str(config["reference_client"]),
                                            str(config["reference_client_backend"]),
                                        )
                                    ],
                                )
                            except KeyError as exc:
                                raise RunnerError(
                                    "persistent worker cgroup placement is not frozen"
                                ) from exc
                        sample = _run_trial(
                            lane_journal,
                            root=root,
                            run_dir=run_dir,
                            campaign_id=campaign_id,
                            spec=spec,
                            manifest=manifest,
                            trial_row=member,
                            cell_config=config,
                            binary_paths=binary_paths,
                            lane_topology=lane_topologies.get(lane),
                            lane_cgroups=trial_cgroups,
                            path_controller=lane_paths.get(lane),
                            endpoint_override=override,
                            endpoint_environment=endpoint_environment,
                            worker_pool=worker_pool,
                            expected_coordinator_affinity=expected_coordinator_affinity,
                            measurement_barrier=measurement_barrier,
                            shared_measurement_epoch=shared_measurement_epoch,
                            active_processes=active_processes,
                            active_processes_lock=active_processes_lock,
                            amd_monitor=amd_monitor,
                            external_thermal_provider=diagnostic_unqualified_host,
                            allow_client_headroom_failure=diagnostic_unqualified_host,
                        )
                        samples[str(member["trial_id"])] = sample
                        runtimes.append(sample["runtime"])
                    lane_journal.commit_microblock(block_id, samples)
                    return 1, runtimes
                except HardwareUnqualifiedError as exc:
                    if epoch_abort is not None:
                        epoch_abort.set()
                        if measurement_barrier is not None:
                            measurement_barrier.abort()
                        raise
                    with failed_cells_lock:
                        session_replay_reason["hardware_unqualified"] = exc.reason
                    session_abort.set()
                    raise
                except EndpointRunError as exc:
                    if epoch_abort is not None:
                        epoch_abort.set()
                        if measurement_barrier is not None:
                            measurement_barrier.abort()
                        raise _PublicationEpochFailure(
                            block_id=block_id,
                            root_trial_id=str(member["trial_id"]),
                            cell_ids=tuple(
                                str(item["cell_id"]) for item in members
                            ),
                            error=exc,
                            collateral=(
                                exc.reason.startswith(
                                    "parallel_measurement_barrier_failed:"
                                )
                                or exc.reason == "parallel_epoch_peer_cancelled"
                            ),
                        ) from exc
                    if exc.infrastructure_transient:
                        if exc.reason == "arm_control_window_rejected":
                            localized = lane_journal.activate_microblock_retry(
                                campaign_id,
                                block_id,
                                reason=exc.reason,
                                detail=exc.detail,
                                aggregate_maximum=(
                                    arm_control_policy.retry_budget_per_session
                                ),
                            )
                            status = str(localized["status"])
                            if status == "aggregate_transient_budget_exhausted":
                                lane_journal.fail_microblock(
                                    block_id,
                                    "arm_control_retry_budget_exhausted",
                                    terminal_state="invalid",
                                    root_trial_id=str(member["trial_id"]),
                                    root_detail=exc.detail,
                                )
                                deterministic_publication_failure.set()
                                session_abort.set()
                                recovery["arm_control_budget_exhausted"] = int(
                                    localized["localized_transients"]
                                )
                                return 0, []
                            recovery["arm_control_window_rejections"] = int(
                                recovery.get(
                                    "arm_control_window_rejections", 0
                                )
                            ) + 1
                            if status == "retry_activated":
                                raise _LocalizedMicroblockRetry(
                                    str(localized["retry_microblock_id"])
                                ) from exc
                            if status == "retry_exhausted":
                                recovery["arm_control_retry_exhausted"] = int(
                                    recovery.get(
                                        "arm_control_retry_exhausted", 0
                                    )
                                ) + 1
                                deterministic_publication_failure.set()
                                session_abort.set()
                                return 0, []
                            raise RunnerError(
                                "ARM control-plane retry made no transition"
                            )
                        methodology = _publication_methodology(spec)
                        if (
                            methodology is not None
                            and exc.reason
                            == "host_stability_interval_transient"
                        ):
                            monitor_methodology = methodology["monitor"]
                            assert isinstance(monitor_methodology, Mapping)
                            transient_budget = int(
                                monitor_methodology[
                                    "localized_transient_budget_per_session"
                                ]
                            )
                            localized = (
                                lane_journal.activate_microblock_retry(
                                    campaign_id,
                                    block_id,
                                    reason=exc.reason,
                                    detail=exc.detail,
                                    aggregate_maximum=transient_budget,
                                )
                            )
                            status = str(localized["status"])
                            if status == "aggregate_transient_budget_exhausted":
                                lane_journal.fail_microblock(
                                    block_id,
                                    "host_stability_monitor_transient_budget_exhausted",
                                    terminal_state="invalid",
                                    root_trial_id=str(member["trial_id"]),
                                    root_detail=exc.detail,
                                )
                                deterministic_publication_failure.set()
                                session_abort.set()
                                recovery["localized_monitor_budget_exhausted"] = (
                                    int(
                                        localized[
                                            "localized_transients"
                                        ]
                                    )
                                )
                                return 0, []
                            recovery["localized_monitor_transients"] = int(
                                recovery.get(
                                    "localized_monitor_transients", 0
                                )
                            ) + 1
                            if status == "retry_activated":
                                raise _LocalizedMicroblockRetry(
                                    str(localized["retry_microblock_id"])
                                ) from exc
                            if status == "retry_exhausted":
                                recovery["localized_monitor_retry_exhausted"] = (
                                    int(
                                        recovery.get(
                                            "localized_monitor_retry_exhausted",
                                            0,
                                        )
                                    )
                                    + 1
                                )
                                deterministic_publication_failure.set()
                                session_abort.set()
                                return 0, []
                            raise RunnerError(
                                "localized monitor retry made no transition"
                            )
                        with failed_cells_lock:
                            session_replay_reason.setdefault("reason", exc.reason)
                        session_abort.set()
                        raise SessionReplayRequired(exc.reason) from exc
                    if session_abort.is_set():
                        if deterministic_publication_failure.is_set():
                            lane_journal.fail_microblock(
                                block_id,
                                "parallel_epoch_peer_deterministic_failure",
                                terminal_state="invalid",
                                root_trial_id=str(member["trial_id"]),
                                root_detail=exc.detail,
                            )
                            return 0, []
                        if "hardware_unqualified" in session_replay_reason:
                            raise HardwareUnqualifiedError(
                                session_replay_reason["hardware_unqualified"]
                            ) from exc
                        raise SessionReplayRequired(
                            session_replay_reason.get(
                                "reason", "treatment_independent_monitor_transient"
                            )
                        ) from exc
                    else:
                        with failed_cells_lock:
                            failed_cells.update(
                                str(member["cell_id"]) for member in members
                            )
                        lane_journal.fail_microblock(
                            block_id,
                            exc.reason,
                            terminal_state=exc.terminal_state,
                            root_trial_id=str(member["trial_id"]),
                            root_detail=exc.detail,
                        )
                        if spec.campaign_kind == "publication":
                            deterministic_publication_failure.set()
                            session_abort.set()
                    return 0, []
                except BaseException:
                    if epoch_abort is not None:
                        epoch_abort.set()
                        if measurement_barrier is not None:
                            measurement_barrier.abort()
                    raise

            def execute_lane(
                lane: int,
                block_ids: list[str],
                *,
                enforce_independent_budget: bool = True,
                epoch_abort: threading.Event | None = None,
            ) -> tuple[int, list[Mapping[str, Any]]]:
                count = 0
                runtimes: list[Mapping[str, Any]] = []
                with journal._lane_writer() as lane_journal:
                    pending_block_ids = list(block_ids)
                    while pending_block_ids:
                        block_id = pending_block_ids.pop(0)
                        if session_abort.is_set():
                            break
                        if enforce_independent_budget and (
                            publication_budget_reached()
                            or not publication_budget_allows(block_id)
                        ):
                            budget_exhaustion.set()
                            session_abort.set()
                            break
                        try:
                            added, observed = execute_block(
                                lane_journal,
                                block_id,
                                epoch_abort=epoch_abort,
                            )
                        except _LocalizedMicroblockRetry as retry:
                            pending_block_ids.insert(0, retry.retry_block_id)
                            continue
                        count += added
                        runtimes.extend(observed)
                return count, runtimes

            def execute_publication_epoch_lane(
                lane: int,
                block_id: str,
                epoch_abort: threading.Event,
            ) -> tuple[int, list[Mapping[str, Any]]]:
                try:
                    return execute_lane(
                        lane,
                        [block_id],
                        enforce_independent_budget=False,
                        epoch_abort=epoch_abort,
                    )
                except BaseException:
                    epoch_abort.set()
                    if measurement_barrier is not None:
                        measurement_barrier.abort()
                    raise

            while True:
                session_abort.clear()
                deterministic_publication_failure.clear()
                session_replay_reason.clear()
                if budget_exhaustion.is_set() or publication_budget_reached():
                    expired = journal.connection.execute(
                        """
                        SELECT microblock_id FROM microblock
                        WHERE campaign_id=? AND session_number=? AND status='active'
                        ORDER BY ordinal, CASE slot WHEN 'primary' THEN 0 ELSE 1 END
                        """,
                        (campaign_id, session),
                    ).fetchall()
                    for block in expired:
                        journal.fail_microblock(
                            str(block["microblock_id"]),
                            "runtime_session_wall_feasibility_budget_exhausted",
                            terminal_state="invalid",
                        )
                blocks = journal.connection.execute(
                    """
                    SELECT microblock_id FROM microblock
                    WHERE campaign_id=? AND session_number=? AND status='active'
                    ORDER BY ordinal, CASE slot WHEN 'primary' THEN 0 ELSE 1 END
                    """,
                    (campaign_id, session),
                ).fetchall()
                if not blocks:
                    if spec.campaign_kind == "capacity":
                        selection = _maybe_activate_capacity_confirmation(
                            journal, campaign_id, str(schedule["basis"])
                        )
                        if selection is not None and selection["active"]:
                            continue
                    if amd_context is not None:
                        try:
                            continuous = stop_amd_monitor()
                        except HealthError as exc:
                            raise HardwareUnqualifiedError(
                                f"amd_continuous_monitor_stop_failed:{exc}"
                            ) from exc
                        if continuous is None:
                            raise HardwareUnqualifiedError(
                                "amd_continuous_monitor_failed:missing_evidence"
                            )
                        if not continuous.get("passed", False):
                            if _amd_monitor_evidence_is_transient(continuous):
                                if (
                                    spec.schema_version
                                    in VERSIONED_PUBLICATION_SCHEMA_VERSIONS
                                ):
                                    raise HardwareUnqualifiedError(
                                        "amd_continuous_monitor_evidence_lost"
                                    )
                                replay = journal.activate_session_retry(
                                    campaign_id,
                                    session,
                                    "host_stability_monitor_transient",
                                )
                                recovery["session_replay"] = replay
                                refresh_observed_runtimes()
                                if replay["status"] == "retry_exhausted":
                                    raise HardwareUnqualifiedError(
                                        "amd_monitor_second_transient"
                                    )
                                restart_amd_monitor_after_transient(
                                    "host_stability_monitor_transient",
                                    continuous,
                                )
                                refresh_failed_cells()
                                continue
                            reasons = [
                                str(item)
                                for item in continuous.get("reasons", [])
                            ]
                            raise HardwareUnqualifiedError(
                                "amd_continuous_monitor_failed:"
                                + ",".join(reasons or ["missing_evidence"])
                            )
                    break
                by_lane: dict[int, list[str]] = {}
                active_block_ids: list[str] = []
                for block in blocks:
                    block_id = str(block["microblock_id"])
                    if block_id not in block_schedule:
                        raise IdentityMismatchError(
                            f"active microblock {block_id} is absent from frozen schedule"
                        )
                    lane = int(block_schedule[block_id].get("lane", 0))
                    if override is None and lane not in lane_groups:
                        raise IdentityMismatchError(
                            f"frozen lane {lane} has no active resource controller"
                        )
                    by_lane.setdefault(lane, []).append(block_id)
                    active_block_ids.append(block_id)
                publication_epochs = (
                    _active_publication_epochs(
                        block_schedule,
                        active_block_ids,
                        session=session,
                    )
                    if (
                        spec.campaign_kind == "publication"
                        and runtime_lane_count == 2
                    )
                    else None
                )
                if publication_epochs is not None:
                    remaining_scheduled_ns = sum(
                        _publication_epoch_timing(
                            block_schedule,
                            block_arm_ns,
                            epoch_members,
                            arm_control_policy.lead_ns,
                        )[0]
                        for _epoch_ordinal, epoch_members in publication_epochs
                    )
                    if not _publication_session_budget_allows_block(
                        spec,
                        diagnostic_unqualified_host,
                        int(runtime_summary()["session_wall_ns"]),
                        remaining_scheduled_ns,
                    ):
                        budget_exhaustion.set()
                        session_abort.set()
                        for block_id in active_block_ids:
                            journal.fail_microblock(
                                block_id,
                                "runtime_session_remaining_wall_feasibility_budget_exhausted",
                                terminal_state="invalid",
                            )
                        continue
                if len(by_lane) > 1 and publication_epochs is None:
                    shared_measurement_epoch = _ArmWindowCoordinator(
                        len(by_lane), arm_control_policy
                    )
                    measurement_barrier = threading.Barrier(len(by_lane))
                else:
                    measurement_barrier = None
                    shared_measurement_epoch = None
                try:
                    if len(by_lane) == 1:
                        lane, lane_block_ids = next(iter(by_lane.items()))
                        added, observed = execute_lane(lane, lane_block_ids)
                        committed_blocks += added
                        observed_runtimes.extend(observed)
                    elif publication_epochs is not None:
                        executor = ThreadPoolExecutor(
                            max_workers=2,
                            thread_name_prefix="quicperf-epoch",
                        )
                        try:
                            for _epoch_ordinal, epoch_members in publication_epochs:
                                if session_abort.is_set():
                                    break
                                (
                                    epoch_scheduled_ns,
                                    parallel_arm_ns,
                                ) = _publication_epoch_timing(
                                    block_schedule,
                                    block_arm_ns,
                                    epoch_members,
                                    arm_control_policy.lead_ns,
                                )
                                if publication_budget_reached() or not (
                                    _publication_session_budget_allows_block(
                                        spec,
                                        diagnostic_unqualified_host,
                                        int(runtime_summary()["session_wall_ns"]),
                                        epoch_scheduled_ns,
                                    )
                                ):
                                    budget_exhaustion.set()
                                    session_abort.set()
                                    break
                                shared_measurement_epoch = _ArmWindowCoordinator(
                                    2,
                                    arm_control_policy,
                                    parallel_arm_ns=parallel_arm_ns,
                                )
                                measurement_barrier = threading.Barrier(2)
                                epoch_abort = threading.Event()
                                futures = [
                                    executor.submit(
                                        execute_publication_epoch_lane,
                                        lane,
                                        block_id,
                                        epoch_abort,
                                    )
                                    for lane, block_id in epoch_members
                                ]
                                epoch_failures: list[BaseException] = []
                                for future in futures:
                                    try:
                                        added, observed = future.result()
                                    except BaseException as exc:
                                        epoch_failures.append(exc)
                                    else:
                                        committed_blocks += added
                                        observed_runtimes.extend(observed)
                                measurement_barrier = None
                                shared_measurement_epoch = None
                                if not epoch_failures:
                                    continue
                                decision, failure = (
                                    _publication_epoch_failure_decision(
                                        epoch_failures
                                    )
                                )
                                if decision == "hardware":
                                    if not isinstance(
                                        failure, HardwareUnqualifiedError
                                    ):
                                        raise RunnerError(
                                            "publication epoch hardware "
                                            "decision has an invalid failure"
                                        )
                                    with failed_cells_lock:
                                        session_replay_reason[
                                            "hardware_unqualified"
                                        ] = failure.reason
                                    session_abort.set()
                                    raise failure
                                if decision == "replay":
                                    reason = (
                                        failure.reason
                                        if isinstance(
                                            failure, SessionReplayRequired
                                        )
                                        else failure.error.reason
                                    )
                                    with failed_cells_lock:
                                        session_replay_reason.setdefault(
                                            "reason", reason
                                        )
                                    session_abort.set()
                                    raise SessionReplayRequired(reason)
                                if decision == "unexpected":
                                    raise failure
                                if (
                                    decision != "deterministic"
                                    or not isinstance(
                                        failure, _PublicationEpochFailure
                                    )
                                ):
                                    raise RunnerError(
                                        "publication epoch failure decision "
                                        "is invalid"
                                    )
                                with failed_cells_lock:
                                    failed_cells.update(failure.cell_ids)
                                journal.fail_microblock(
                                    failure.block_id,
                                    failure.error.reason,
                                    terminal_state=failure.error.terminal_state,
                                    root_trial_id=failure.root_trial_id,
                                    root_detail=failure.error.detail,
                                )
                                failures_by_block = {
                                    item.block_id: item
                                    for item in epoch_failures
                                    if isinstance(
                                        item, _PublicationEpochFailure
                                    )
                                }
                                for _lane, block_id in epoch_members:
                                    if block_id == failure.block_id:
                                        continue
                                    status = journal.connection.execute(
                                        """
                                        SELECT status FROM microblock
                                        WHERE microblock_id=?
                                        """,
                                        (block_id,),
                                    ).fetchone()
                                    if (
                                        status is None
                                        or status["status"] != "active"
                                    ):
                                        continue
                                    collateral = failures_by_block.get(
                                        block_id
                                    )
                                    root_trial_id = (
                                        collateral.root_trial_id
                                        if collateral is not None
                                        else str(
                                            block_schedule[block_id][
                                                "trials"
                                            ][0]["trial_id"]
                                        )
                                    )
                                    if (
                                        collateral is not None
                                        and not collateral.collateral
                                    ):
                                        journal.fail_microblock(
                                            block_id,
                                            collateral.error.reason,
                                            terminal_state=(
                                                collateral.error.terminal_state
                                            ),
                                            root_trial_id=root_trial_id,
                                            root_detail=(
                                                collateral.error.detail
                                            ),
                                        )
                                    else:
                                        journal.fail_microblock(
                                            block_id,
                                            "parallel_epoch_peer_deterministic_failure",
                                            terminal_state="invalid",
                                            root_trial_id=root_trial_id,
                                        )
                                deterministic_publication_failure.set()
                                session_abort.set()
                                break
                        except BaseException:
                            try:
                                if measurement_barrier is not None:
                                    measurement_barrier.abort()
                                _terminate_active_processes(
                                    active_processes, active_processes_lock
                                )
                            finally:
                                executor.shutdown(wait=True, cancel_futures=True)
                            raise
                        else:
                            executor.shutdown(wait=True)
                    else:
                        executor = ThreadPoolExecutor(
                            max_workers=len(by_lane),
                            thread_name_prefix="quicperf-lane",
                        )
                        try:
                            futures = [
                                executor.submit(execute_lane, lane, block_ids)
                                for lane, block_ids in sorted(by_lane.items())
                            ]
                            for future in as_completed(futures):
                                added, observed = future.result()
                                committed_blocks += added
                                observed_runtimes.extend(observed)
                        except BaseException:
                            try:
                                _terminate_active_processes(
                                    active_processes, active_processes_lock
                                )
                            finally:
                                executor.shutdown(wait=True, cancel_futures=True)
                            raise
                        else:
                            executor.shutdown(wait=True)
                    if deterministic_publication_failure.is_set():
                        remaining = journal.connection.execute(
                            """
                            SELECT microblock_id FROM microblock
                            WHERE campaign_id=? AND session_number=?
                              AND status='active'
                            ORDER BY ordinal
                            """,
                            (campaign_id, session),
                        ).fetchall()
                        for pending in remaining:
                            journal.fail_microblock(
                                str(pending["microblock_id"]),
                                "publication_stopped_after_deterministic_failure",
                                terminal_state="invalid",
                            )
                except HardwareUnqualifiedError:
                    if measurement_barrier is not None:
                        measurement_barrier.abort()
                    _terminate_active_processes(
                        active_processes, active_processes_lock
                    )
                    if worker_pool is not None:
                        worker_pool.abandon_terminated()
                    raise
                except SessionReplayRequired as exc:
                    if measurement_barrier is not None:
                        measurement_barrier.abort()
                    _terminate_active_processes(
                        active_processes, active_processes_lock
                    )
                    if worker_pool is not None:
                        worker_pool.abandon_terminated()
                    replay = journal.activate_session_retry(
                        campaign_id,
                        session,
                        session_replay_reason.get("reason", exc.reason),
                    )
                    recovery["session_replay"] = replay
                    refresh_observed_runtimes()
                    if replay["status"] == "retry_exhausted":
                        active_retry_blocks = journal.connection.execute(
                            """
                            SELECT microblock_id FROM microblock
                            WHERE campaign_id=? AND session_number=?
                              AND slot='retry' AND status='active'
                            ORDER BY ordinal
                            """,
                            (campaign_id, session),
                        ).fetchall()
                        for retry_block in active_retry_blocks:
                            journal.fail_microblock(
                                str(retry_block["microblock_id"]),
                                f"session_replay_exhausted:{exc.reason}",
                                terminal_state="invalid",
                            )
                        if exc.reason == "host_stability_monitor_transient":
                            raise HardwareUnqualifiedError(
                                "amd_monitor_second_transient"
                            ) from exc
                        break
                    if exc.reason == "host_stability_monitor_transient":
                        try:
                            prior_monitor = stop_amd_monitor()
                        except HealthError as monitor_error:
                            prior_monitor = {
                                "passed": False,
                                "reasons": [f"monitor_stop_error:{monitor_error}"],
                            }
                        restart_amd_monitor_after_transient(
                            exc.reason, prior_monitor
                        )
                    refresh_failed_cells()
                    continue
                except KeyboardInterrupt:
                    cleanup_error: EndpointRunError | None = None
                    try:
                        _terminate_active_processes(
                            active_processes, active_processes_lock
                        )
                        if worker_pool is not None:
                            worker_pool.abandon_terminated()
                    except EndpointRunError as exc:
                        cleanup_error = exc
                    finally:
                        replay = journal.activate_session_retry(
                            campaign_id, session, "coordinator_interruption"
                        )
                        recovery["session_replay"] = replay
                        journal.set_session_status(campaign_id, session, "interrupted")
                        close_runtime_state()
                    if cleanup_error is not None:
                        raise cleanup_error
                    raise
            if amd_context is not None:
                try:
                    continuous = stop_amd_monitor()
                except HealthError as exc:
                    raise HardwareUnqualifiedError(
                        f"amd_continuous_monitor_stop_failed:{exc}"
                    ) from exc
                if continuous is None or not continuous.get("passed", False):
                    reasons = (
                        []
                        if continuous is None
                        else [str(item) for item in continuous.get("reasons", [])]
                    )
                    raise HardwareUnqualifiedError(
                        "amd_continuous_monitor_failed:"
                        + ",".join(reasons or ["missing_evidence"])
                    )
                failed_before_post_probe = int(
                    journal.connection.execute(
                        """
                        SELECT COUNT(*) FROM microblock
                        WHERE campaign_id=? AND session_number=?
                          AND status='failed'
                        """,
                        (campaign_id, session),
                    ).fetchone()[0]
                )
                if failed_before_post_probe:
                    amd_session_evidence["post_probe"] = {
                        "status": "NOT_RUN",
                        "passed": False,
                        "reasons": ["session_already_nonpublication"],
                    }
                    amd_session_evidence["reasons"].append(
                        "session_already_nonpublication"
                    )
                    journal.store_artifact(
                        campaign_id,
                        f"qualification/host-stability-session-{session}.json",
                        canonical_bytes(amd_session_evidence),
                        media_type="application/json",
                    )
                else:
                    try:
                        with _automatic_gc_suspended():
                            post_evaluation, post_document = run_amd_session_probe(
                                cpus=amd_context.cpus,
                                housekeeping_cpu=amd_context.housekeeping_cpu,
                                helper=amd_context.helper,
                                policy=amd_context.policy,
                                reference=amd_context.reference,
                                temperature_source=amd_context.temperature_source,
                            )
                        amd_session_evidence["post_probe"] = post_document
                    except HealthError as exc:
                        amd_session_evidence["post_probe"] = {
                            "passed": False,
                            "reasons": [f"probe_error:{exc}"],
                        }
                        raise HardwareUnqualifiedError(
                            f"amd_post_session_probe_error:{exc}"
                        ) from exc
                    if not post_evaluation.passed:
                        raise HardwareUnqualifiedError(
                            "amd_post_session_probe_failed:"
                            + ",".join(post_evaluation.reasons)
                        )
                    amd_session_evidence["passed"] = True
                    journal.store_artifact(
                        campaign_id,
                        f"qualification/host-stability-session-{session}.json",
                        canonical_bytes(amd_session_evidence),
                        media_type="application/json",
                    )
            remaining = journal.connection.execute(
                """
                SELECT COUNT(*) FROM microblock
                WHERE campaign_id=? AND session_number=? AND status='active'
                """,
                (campaign_id, session),
            ).fetchone()[0]
            failed = journal.connection.execute(
                "SELECT COUNT(*) FROM microblock WHERE campaign_id=? AND session_number=? AND status='failed'",
                (campaign_id, session),
            ).fetchone()[0]
            committed = journal.connection.execute(
                "SELECT COUNT(*) FROM microblock WHERE campaign_id=? AND session_number=? AND status='committed'",
                (campaign_id, session),
            ).fetchone()[0]
            status = "nonpublishable" if failed else "complete" if remaining == 0 else "interrupted"
            journal.set_session_status(campaign_id, session, status)
            refresh_observed_runtimes()
            close_runtime_state()
            runtime = runtime_summary()
            journal.store_artifact(
                campaign_id,
                f"runtime/session-{session}.json",
                canonical_bytes(
                    {
                        "schema_version": "quicperf.runtime.v1",
                        "campaign_id": campaign_id,
                        "session": session,
                        "status": status,
                        "runtime": runtime,
                    }
                ),
                media_type="application/json",
            )
            return {
                "status": status,
                "committed_microblocks": int(committed),
                "failed_microblocks": int(failed),
                "remaining_microblocks": int(remaining),
                "recovery": recovery,
                "runtime": runtime,
            }
        except HardwareUnqualifiedError as exc:
            return hardware_unqualified_result(exc.reason)
        finally:
            resources.close()


def _write_status(run_dir: Path, value: Mapping[str, Any]) -> None:
    content = canonical_bytes(value)
    path = run_dir / "status.json"
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def analyze_campaign(run_dir: Path) -> dict[str, Any]:
    with Journal(run_dir) as journal:
        spec, _manifest, schedule = _persisted_run_identity(journal, run_dir)
        campaign = campaign_identity(journal)
        campaign_id = str(campaign["campaign_id"])
        diagnostic_manifest = _diagnostic_schedule_manifest(schedule)
        render_started_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        render_cpu_started_ns = time.process_time_ns()
        rendered = render_analysis(
            journal,
            campaign_id,
            spec.campaign_kind,
            preflight_reasons=_statistical_calibration_reasons(
                Path(__file__).resolve().parents[1],
                spec.campaign_kind,
                spec.raw["analysis"],
            ),
            diagnostic_manifest=diagnostic_manifest,
            methodology=_publication_methodology(spec),
        )
        render_runtime = {
            "wall_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            - render_started_raw_ns,
            "cpu_ns": time.process_time_ns() - render_cpu_started_ns,
        }
        render_runtime["sixty_second_budget_passed"] = (
            render_runtime["wall_ns"] <= 60_000_000_000
        )
        media_types = {
            ".tsv": "text/tab-separated-values",
            ".md": "text/markdown",
            ".json": "application/json",
        }
        artifacts = dict(rendered.artifacts)
        artifacts["runtime/render.json"] = canonical_bytes(
            {
                "schema_version": "quicperf.runtime.v1",
                "campaign_id": campaign_id,
                "phase": "analysis_render",
                "runtime": render_runtime,
            }
        )
        journal.store_artifacts(
            campaign_id,
            {
                path: (content, next(media for suffix, media in media_types.items() if path.endswith(suffix)))
                for path, content in artifacts.items()
            },
            campaign_status=(
                "hardware_unqualified"
                if campaign["status"] == "hardware_unqualified"
                else "analyzed"
                if rendered.complete
                else "analysis_incomplete"
            ),
        )
        checksums = journal.export(campaign_id, run_dir)
        status = campaign_status(run_dir)
        result = {
            **status,
            "analysis_complete": rendered.complete,
            "publication_valid": rendered.publication_valid,
            "analysis_reasons": list(rendered.reasons),
            "artifact_checksums": checksums,
            "runtime": render_runtime,
            "watermark": (
                DIAGNOSTIC_UNQUALIFIED_HOST_WATERMARK
                if diagnostic_manifest is not None
                else None
            ),
        }
        _write_status(run_dir, result)
        return result


def _stored_analysis(journal: Journal, campaign_id: str) -> dict[str, Any]:
    row = journal.connection.execute(
        "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path='analysis.json'",
        (campaign_id,),
    ).fetchone()
    if row is None:
        raise IncompleteCampaignError("campaign must be analyzed before finalize")
    content = bytes(row["content"])
    if hashlib.sha256(content).hexdigest() != row["sha256"]:
        raise IdentityMismatchError("stored analysis artifact checksum mismatch")
    value = loads_strict(content)
    if not isinstance(value, dict) or value.get("campaign_id") != campaign_id:
        raise IdentityMismatchError("stored analysis identity mismatch")
    return value


def _qualification_reasons(
    journal: Journal,
    campaign_id: str,
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
) -> list[str]:
    reasons = []
    required = {
        "host_stability_required": "host-stability",
        "worker_reuse_required": "worker-reuse",
        "lane_interference_required": "lane-interference",
        "client_headroom_required": "client-headroom",
        "window_equivalence_required": "window-qualification",
        "tail_window_required": "tail-window",
    }
    for field, artifact_name in required.items():
        if not spec.raw["qualification"][field]:
            continue
        row = journal.connection.execute(
            "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path=?",
            (campaign_id, f"qualification/{artifact_name}.json"),
        ).fetchone()
        if row is None:
            reasons.append(f"{artifact_name}_not_run")
            continue
        content = bytes(row["content"])
        if hashlib.sha256(content).hexdigest() != row["sha256"]:
            reasons.append(f"{artifact_name}_artifact_corrupt")
            continue
        try:
            decision, _artifact_hash, _identity_hash = decode_qualification_artifact(
                content,
                expected_kind=artifact_name,
                expected_identity=build_qualification_identity(artifact_name, spec, manifest),
            )
        except QualificationError:
            reasons.append(f"{artifact_name}_artifact_invalid")
            continue
        if not decision.qualified:
            reasons.append(f"{artifact_name}_not_qualified")
    if spec.raw["qualification"]["host_stability_required"]:
        for session in range(1, int(spec.expected_cardinality.sessions) + 1):
            path = f"qualification/host-stability-session-{session}.json"
            row = journal.connection.execute(
                "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path=?",
                (campaign_id, path),
            ).fetchone()
            if row is None:
                reasons.append(f"host-stability_session_{session}_not_run")
                continue
            content = bytes(row["content"])
            if hashlib.sha256(content).hexdigest() != row["sha256"]:
                reasons.append(f"host-stability_session_{session}_artifact_corrupt")
                continue
            try:
                document = loads_strict(content)
            except Exception:
                reasons.append(f"host-stability_session_{session}_artifact_invalid")
                continue
            if (
                not isinstance(document, Mapping)
                or canonical_bytes(document) != content
                or document.get("schema_version")
                != "quicperf.amd-session-stability.v1"
                or document.get("provider") != AMD_PROVIDER_VERSION
                or document.get("campaign_id") != campaign_id
                or document.get("session") != session
                or document.get("passed") is not True
                or document.get("reasons") != []
                or not isinstance(document.get("pre_probe"), Mapping)
                or not isinstance(document.get("continuous"), Mapping)
                or not isinstance(document.get("post_probe"), Mapping)
            ):
                reasons.append(f"host-stability_session_{session}_artifact_invalid")
    return reasons


def _native_interoperability_reasons(
    journal: Journal,
    campaign_id: str,
    spec: ExperimentSpecV2,
    manifest: ImmutableIdentityManifest,
    schedule: Mapping[str, Any],
) -> list[str]:
    if spec.campaign_kind != "publication":
        return []
    row = journal.connection.execute(
        "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path=?",
        (campaign_id, "qualification/native-interoperability.json"),
    ).fetchone()
    if row is None:
        return ["native_interoperability_artifact_missing"]
    content = bytes(row["content"])
    if hashlib.sha256(content).hexdigest() != row["sha256"]:
        return ["native_interoperability_artifact_corrupt"]
    try:
        artifact = decode_interoperability_artifact(
            content,
            spec=spec,
            identity=build_interoperability_identity(spec, manifest),
        )
    except InteroperabilityError:
        return ["native_interoperability_artifact_invalid"]
    if schedule.get("native_interoperability_artifact_sha256") != artifact.artifact_hash:
        return ["native_interoperability_schedule_identity_mismatch"]
    expected = interoperability_plan_cardinality(spec)
    if (
        artifact.status != INTEROPERABILITY_PASS
        or len(artifact.records) != expected
        or artifact.passed != expected
        or artifact.failed != 0
    ):
        return ["native_interoperability_preflight_incomplete_or_failed"]
    return []


def _runtime_artifact(
    journal: Journal, campaign_id: str, path: str
) -> tuple[Mapping[str, Any] | None, str | None]:
    row = journal.connection.execute(
        "SELECT content, sha256 FROM artifact WHERE campaign_id=? AND path=?",
        (campaign_id, path),
    ).fetchone()
    if row is None:
        return None, f"{path.replace('/', '_').replace('.', '_')}_not_run"
    content = bytes(row["content"])
    if hashlib.sha256(content).hexdigest() != row["sha256"]:
        return None, f"{path.replace('/', '_').replace('.', '_')}_corrupt"
    try:
        document = loads_strict(content)
    except Exception:
        return None, f"{path.replace('/', '_').replace('.', '_')}_invalid"
    if not isinstance(document, Mapping) or canonical_bytes(document) != content:
        return None, f"{path.replace('/', '_').replace('.', '_')}_invalid"
    return document, None


def _runtime_gate_reasons(
    journal: Journal,
    campaign_id: str,
    sessions: int,
    spec: ExperimentSpecV2,
) -> list[str]:
    """Validate the frozen publication wall-time/useful-time runtime gates."""

    reasons: list[str] = []
    session_wall: list[int] = []
    required_integer_fields = {
        "session_wall_ns",
        "coordinator_cpu_ns",
        "successful_trial_count",
        "steady_state_trial_count",
        "useful_measurement_ns",
        "qualified_lane_count",
        "lane_wall_capacity_ns",
        "nonmeasurement_overhead_median_ns",
        "nonmeasurement_overhead_p95_ns",
        "journal_writes_during_measurement",
    }
    for session in range(1, sessions + 1):
        document, error = _runtime_artifact(
            journal, campaign_id, f"runtime/session-{session}.json"
        )
        if error is not None:
            reasons.append(error)
            continue
        assert document is not None
        runtime = document.get("runtime")
        if (
            document.get("schema_version") != "quicperf.runtime.v1"
            or document.get("campaign_id") != campaign_id
            or document.get("session") != session
            or document.get("status") != "complete"
            or not isinstance(runtime, Mapping)
            or set(runtime)
            != required_integer_fields | {"useful_wall_fraction_decimal"}
            or any(
                type(runtime.get(field)) is not int or runtime[field] < 0
                for field in required_integer_fields
            )
        ):
            reasons.append(f"runtime_session_{session}_invalid")
            continue
        wall_ns = int(runtime["session_wall_ns"])
        useful_ns = int(runtime["useful_measurement_ns"])
        lane_capacity_ns = int(runtime["lane_wall_capacity_ns"])
        lane_count = int(runtime["qualified_lane_count"])
        state, state_error = _runtime_artifact(
            journal, campaign_id, f"runtime/session-{session}-state.json"
        )
        try:
            current_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()
        except OSError:
            current_boot_id = ""
        if (
            state_error is not None
            or state is None
            or set(state)
            != {
                "schema_version",
                "campaign_id",
                "session",
                "boot_id",
                "accumulated_wall_ns",
                "active_started_raw_ns",
            }
            or state.get("schema_version") != "quicperf.runtime-state.v1"
            or state.get("campaign_id") != campaign_id
            or state.get("session") != session
            or not current_boot_id
            or state.get("boot_id") != current_boot_id
            or state.get("active_started_raw_ns") is not None
            or state.get("accumulated_wall_ns") != wall_ns
        ):
            reasons.append(f"runtime_session_{session}_state_invalid")
        with localcontext() as context:
            context.prec = 40
            expected_fraction = (
                normalize_decimal(Decimal(useful_ns) / Decimal(lane_capacity_ns))
                if lane_capacity_ns
                else "0"
            )
        session_wall.append(wall_ns)
        if lane_count != 1:
            reasons.append(f"runtime_session_{session}_one_lane_identity_mismatch")
        session_budget_ns = _publication_session_budget_ns(spec)
        if session_budget_ns is not None and wall_ns > session_budget_ns:
            reasons.append(
                f"runtime_session_{session}_wall_feasibility_budget_failed"
            )
        if lane_capacity_ns != wall_ns * lane_count:
            reasons.append(f"runtime_session_{session}_lane_capacity_mismatch")
        if runtime["useful_wall_fraction_decimal"] != expected_fraction:
            reasons.append(f"runtime_session_{session}_useful_time_mismatch")
        if (
            spec.schema_version
            not in VERSIONED_PUBLICATION_SCHEMA_VERSIONS
            and useful_ns * 4 < lane_capacity_ns * 3
        ):
            reasons.append(f"runtime_session_{session}_useful_time_below_75_percent")
        if int(runtime["nonmeasurement_overhead_median_ns"]) > 250_000_000:
            reasons.append(f"runtime_session_{session}_median_overhead_budget_failed")
        if int(runtime["nonmeasurement_overhead_p95_ns"]) > 750_000_000:
            reasons.append(f"runtime_session_{session}_p95_overhead_budget_failed")
        if int(runtime["journal_writes_during_measurement"]) != 0:
            reasons.append(f"runtime_session_{session}_journal_write_gate_failed")
    campaign_session_budget_ns = _publication_session_budget_ns(spec)
    if (
        campaign_session_budget_ns is not None
        and len(session_wall) == sessions
        and sum(session_wall) > sessions * campaign_session_budget_ns
    ):
        reasons.append("runtime_campaign_wall_feasibility_budget_failed")

    render, error = _runtime_artifact(journal, campaign_id, "runtime/render.json")
    if error is not None:
        reasons.append(error)
    else:
        assert render is not None
        runtime = render.get("runtime")
        if (
            render.get("schema_version") != "quicperf.runtime.v1"
            or render.get("campaign_id") != campaign_id
            or render.get("phase") != "analysis_render"
            or not isinstance(runtime, Mapping)
            or set(runtime)
            != {"wall_ns", "cpu_ns", "sixty_second_budget_passed"}
            or type(runtime.get("wall_ns")) is not int
            or runtime["wall_ns"] < 0
            or type(runtime.get("cpu_ns")) is not int
            or runtime["cpu_ns"] < 0
            or type(runtime.get("sixty_second_budget_passed")) is not bool
        ):
            reasons.append("runtime_render_invalid")
        elif (
            int(runtime["wall_ns"]) > 60_000_000_000
            or runtime["sixty_second_budget_passed"] is not True
        ):
            reasons.append("runtime_render_sixty_second_budget_failed")
    return reasons


def finalize_campaign(run_dir: Path) -> dict[str, Any]:
    with Journal(run_dir) as journal:
        spec, manifest, schedule = _persisted_run_identity(journal, run_dir)
        campaign = campaign_identity(journal)
        campaign_id = str(campaign["campaign_id"])
        diagnostic = _attest_diagnostic_defaults(
            journal, campaign_id, spec, manifest, schedule
        )
        reasons: list[str] = []
        completion_reasons: list[str] = []
        hardware_unqualified = campaign["status"] == "hardware_unqualified"
        if hardware_unqualified:
            reasons.append("hardware_unqualified")
            completion_reasons.append("hardware_unqualified")
        try:
            journal.assert_exact_cardinality(campaign_id)
        except Exception as exc:
            reason = f"cardinality:{exc}"
            reasons.append(reason)
            completion_reasons.append(reason)
        sessions = journal.connection.execute(
            "SELECT session_number, status FROM session WHERE campaign_id=? ORDER BY session_number",
            (campaign_id,),
        ).fetchall()
        if len(sessions) != spec.expected_cardinality.sessions or any(row["status"] != "complete" for row in sessions):
            reasons.append("sessions_incomplete_or_nonpublishable")
            completion_reasons.append("sessions_incomplete_or_nonpublishable")
        try:
            analysis = _stored_analysis(journal, campaign_id)
        except IncompleteCampaignError as exc:
            analysis = {"publication_valid": False}
            reasons.append(str(exc))
            completion_reasons.append(str(exc))
        if analysis.get("complete") is not True:
            completion_reasons.append("analysis_incomplete")
        if analysis.get("publication_valid") is not True:
            reasons.append("analysis_nonpublishable")
        if not manifest.source["clean"]:
            reasons.append("nonpublication_dirty_source")
            completion_reasons.append("nonpublication_dirty_source")
        if spec.campaign_kind not in {"publication", "capacity", "memory", "tail"}:
            reasons.append("diagnostic_campaign_kind")
        if spec.campaign_kind == "publication" and not diagnostic:
            reasons.extend(
                _runtime_gate_reasons(
                    journal,
                    campaign_id,
                    spec.expected_cardinality.sessions,
                    spec,
                )
            )
        qualification_reasons = _qualification_reasons(
            journal, campaign_id, spec, manifest
        )
        reasons.extend(qualification_reasons)
        interoperability_reasons = _native_interoperability_reasons(
            journal, campaign_id, spec, manifest, schedule
        )
        reasons.extend(interoperability_reasons)
        statistical_reasons = _statistical_calibration_reasons(
            Path(__file__).resolve().parents[1],
            spec.campaign_kind,
            spec.raw["analysis"],
        )
        reasons.extend(statistical_reasons)
        completion_reasons.extend(interoperability_reasons)
        completion_reasons.extend(statistical_reasons)
        if diagnostic:
            reasons.append("diagnostic_unqualified_host")
        reasons = sorted(set(reasons))
        completion_reasons = sorted(set(completion_reasons))
        qualified = not reasons and not diagnostic
        finalization_status = (
            "publication_qualified"
            if qualified
            else "diagnostic_complete_nonpublication"
            if diagnostic and not completion_reasons
            else "hardware_unqualified"
            if hardware_unqualified
            else "nonpublishable"
        )
        journal.set_campaign_status(campaign_id, finalization_status)
        checksums = journal.export(campaign_id, run_dir)
        result = {
            **campaign_status(run_dir),
            "finalized": True,
            "publication_valid": qualified,
            "finalization_status": finalization_status,
            "finalization_reasons": reasons,
            "diagnostic_completion_reasons": completion_reasons,
            "artifact_checksums": checksums,
            "watermark": (
                DIAGNOSTIC_UNQUALIFIED_HOST_WATERMARK if diagnostic else None
            ),
        }
        _write_status(run_dir, result)
        return result


def export_campaign(run_dir: Path) -> dict[str, str]:
    with Journal(run_dir) as journal:
        _spec, _manifest, _schedule = _persisted_run_identity(journal, run_dir)
        campaign = campaign_identity(journal)
        return journal.export(str(campaign["campaign_id"]), run_dir)
