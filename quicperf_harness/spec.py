"""Strict loading and semantic validation for ExperimentSpecV2."""

from __future__ import annotations

from collections.abc import Mapping, Sequence, Set
from decimal import Decimal
from pathlib import Path, PurePosixPath
import re
from typing import Any, NoReturn

from .canonical import canonical_sha256, load_strict, loads_strict, normalize_decimal
from .errors import SpecValidationError
from .model import ExpectedCardinality, ExperimentSpecV2, PathProfile, freeze_json


SCHEMA_VERSION = "quicperf.experiment.v2"
SCHEMA_VERSION_V21 = "quicperf.experiment.v2.1"
SCHEMA_VERSION_V22 = "quicperf.experiment.v2.2"
SCHEMA_VERSION_V23 = "quicperf.experiment.v2.3"
VERSIONED_SCHEMA_VERSIONS = frozenset(
    {SCHEMA_VERSION_V21, SCHEMA_VERSION_V22, SCHEMA_VERSION_V23}
)
IOURING_ONLY_SCHEMA_VERSIONS = frozenset(
    {SCHEMA_VERSION_V22, SCHEMA_VERSION_V23}
)
SUPPORTED_SCHEMA_VERSIONS = frozenset(
    {SCHEMA_VERSION, *VERSIONED_SCHEMA_VERSIONS}
)
CONTROL_VERSION = "quicperf.control.v1"
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

PUBLICATION_SERVERS = (
    "ngtcp2perf", "lsperf", "tquicperf", "quicheperf", "picoperf", "xquicperf",
    "quinnperf", "s2nperf", "neqoperf", "noqperf", "quiczigperf", "mvfstperf",
)
REFERENCE_CLIENTS = ("ngtcp2perf", "picoperf")
PUBLICATION_SCENARIOS = (
    "download", "upload", "multistream_download", "multistream_upload", "bidi",
    "loss_recovery", "flow_control", "small_payload_pps", "datagram", "reqresp",
    "stream_churn", "close_reset_cleanup", "connect", "resumed_connect",
    "zero_rtt_reqresp",
)
CAPACITY_SCENARIOS = (
    "download", "upload", "bidi", "small_payload_pps", "datagram", "reqresp", "connect",
)
TAIL_SCENARIOS = (
    "small_payload_pps", "datagram", "reqresp", "stream_churn", "close_reset_cleanup",
    "connect", "resumed_connect", "zero_rtt_reqresp",
)
INFRASTRUCTURE_TRANSIENT_REASONS = (
    "external_cpu_or_irq_noise", "host_stability_monitor_transient",
    "coordinator_interruption",
    "journal_busy_timeout", "path_control_failure_before_endpoint_start",
)
V21_INFRASTRUCTURE_TRANSIENT_REASONS = (
    "external_cpu_or_irq_noise",
    "coordinator_interruption",
    "journal_busy_timeout",
    "path_control_failure_before_endpoint_start",
    "host_stability_interval_transient",
    "arm_control_window_rejected",
)

TOP_LEVEL = {
    "schema_version", "control_protocol_version", "name", "campaign_kind", "estimand",
    "roles", "workloads", "backends", "paths", "treatment", "timing", "schedule",
    "analysis", "manifest_policy", "validity", "retry", "expected_cardinality",
    "qualification",
}
TOP_LEVEL_V21 = TOP_LEVEL | {"methodology"}


def _fail(path: str, message: str) -> NoReturn:
    raise SpecValidationError(f"{path}: {message}")


def _object(
    value: Any,
    path: str,
    required: Set[str],
    optional: Set[str] = frozenset(),
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(path, "must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        _fail(path, f"missing fields: {', '.join(sorted(missing))}")
    if unknown:
        _fail(path, f"unknown fields: {', '.join(sorted(unknown))}")
    return value


def _array(value: Any, path: str, *, nonempty: bool = True) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)):
        _fail(path, "must be an array")
    if nonempty and not value:
        _fail(path, "must not be empty")
    return value


def _string(value: Any, path: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        _fail(path, "must be a string")
    if nonempty and not value:
        _fail(path, "must not be empty")
    if value.strip() != value or "\x00" in value:
        _fail(path, "contains forbidden whitespace or NUL")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail(path, "must be valid UTF-8 text")
    return value


def _identifier(value: Any, path: str) -> str:
    identifier = _string(value, path)
    if not IDENTIFIER.fullmatch(identifier):
        _fail(path, "must be a lowercase canonical identifier")
    return identifier


def _integer(value: Any, path: str, *, minimum: int = 0, maximum: int = (1 << 63) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(path, "must be an integer")
    if not minimum <= value <= maximum:
        _fail(path, f"must be in [{minimum}, {maximum}]")
    return value


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        _fail(path, "must be a boolean")
    return value


def _decimal(value: Any, path: str, *, positive: bool = False, maximum: Decimal | None = None) -> str:
    if not isinstance(value, str):
        _fail(path, "must be a normalized decimal string")
    try:
        normalized = normalize_decimal(value)
        decimal = Decimal(normalized)
    except Exception as exc:
        _fail(path, str(exc))
    if positive and decimal <= 0:
        _fail(path, "must be positive")
    if maximum is not None and decimal > maximum:
        _fail(path, f"must be at most {maximum}")
    return normalized


def _enum(value: Any, path: str, allowed: set[str]) -> str:
    string = _string(value, path)
    if string not in allowed:
        _fail(path, f"must be one of: {', '.join(sorted(allowed))}")
    return string


def _unique_identifiers(value: Any, path: str) -> tuple[str, ...]:
    result = tuple(_identifier(item, f"{path}[{index}]") for index, item in enumerate(_array(value, path)))
    if len(set(result)) != len(result):
        _fail(path, "must not contain duplicates")
    return result


def _safe_path(value: Any, path: str) -> str:
    text = _string(value, path)
    parts = PurePosixPath(text).parts
    if ".." in parts or text.endswith("/") or "//" in text:
        _fail(path, "must be a normalized path without parent traversal")
    return text


def _validate_workload(item: Any, index: int, paths: set[str]) -> Mapping[str, Any]:
    path = f"$.workloads[{index}]"
    obj = _object(item, path, {
        "scenario", "path_profile", "connections", "streams_per_connection",
        "request_body_bytes", "response_body_bytes", "message_body_bytes",
        "datagram_body_bytes", "application_chunk_bytes", "measurement_ns", "warmup_ns",
        "operation_slots", "concurrency_grid", "connection_count_grid",
        "connection_window_bytes", "stream_window_bytes", "ticket_chains",
        "eligible_operation_limit", "datagram_unreturned_per_connection",
        "datagram_unreturned_aggregate",
    })
    scenario = _identifier(obj["scenario"], f"{path}.scenario")
    path_name = _identifier(obj["path_profile"], f"{path}.path_profile")
    if path_name not in paths:
        _fail(f"{path}.path_profile", "does not name a declared path")
    for field in (
        "connections", "streams_per_connection", "request_body_bytes", "response_body_bytes",
        "message_body_bytes", "datagram_body_bytes", "application_chunk_bytes",
        "measurement_ns", "operation_slots", "connection_window_bytes", "stream_window_bytes",
    ):
        _integer(obj[field], f"{path}.{field}", minimum=1)
    _integer(obj["warmup_ns"], f"{path}.warmup_ns", minimum=0)
    grid = tuple(_integer(v, f"{path}.concurrency_grid[{i}]", minimum=1)
                 for i, v in enumerate(_array(obj["concurrency_grid"], f"{path}.concurrency_grid")))
    if len(set(grid)) != len(grid) or tuple(sorted(grid)) != grid:
        _fail(f"{path}.concurrency_grid", "must be unique and ascending")
    connection_grid = tuple(
        _integer(v, f"{path}.connection_count_grid[{i}]", minimum=0)
        for i, v in enumerate(_array(obj["connection_count_grid"], f"{path}.connection_count_grid"))
    )
    if len(set(connection_grid)) != len(connection_grid) or tuple(sorted(connection_grid)) != connection_grid:
        _fail(f"{path}.connection_count_grid", "must be unique and ascending")
    for field in (
        "ticket_chains", "eligible_operation_limit", "datagram_unreturned_per_connection",
        "datagram_unreturned_aggregate",
    ):
        _integer(obj[field], f"{path}.{field}", minimum=0)
    if scenario == "loss_recovery" and path_name != "loss_recovery_v1":
        _fail(f"{path}.path_profile", "loss_recovery requires loss_recovery_v1")
    if scenario != "loss_recovery" and path_name == "loss_recovery_v1":
        _fail(f"{path}.path_profile", "loss_recovery_v1 is exclusive to loss_recovery")
    if scenario == "datagram" and obj["datagram_body_bytes"] != 64:
        _fail(f"{path}.datagram_body_bytes", "canonical DATAGRAM bodies are 64 bytes")
    if scenario == "datagram" and (
        obj["datagram_unreturned_per_connection"], obj["datagram_unreturned_aggregate"]
    ) != (128, 2048):
        _fail(path, "datagram requires 128 unreturned IDs per connection and 2,048 aggregate")
    if scenario != "datagram" and (
        obj["datagram_unreturned_per_connection"] or obj["datagram_unreturned_aggregate"]
    ):
        _fail(path, "DATAGRAM outstanding limits are invalid for non-DATAGRAM workloads")
    if scenario == "reqresp" and (obj["request_body_bytes"], obj["response_body_bytes"]) != (64, 1024):
        _fail(path, "reqresp requires a 64-byte request and 1024-byte response")
    if scenario in {"connect", "resumed_connect", "zero_rtt_reqresp"}:
        if obj["warmup_ns"] != 0 or obj["operation_slots"] != 16:
            _fail(path, "lifecycle workloads require zero warmup and 16 operation slots")
    expected_tickets = 16 if scenario in {"resumed_connect", "zero_rtt_reqresp"} else 0
    if obj["ticket_chains"] != expected_tickets:
        _fail(path, f"{scenario} requires exactly {expected_tickets} seeded ticket chains")
    expected_windows = (262144, 65536) if scenario == "flow_control" else (67108864, 67108864)
    if (obj["connection_window_bytes"], obj["stream_window_bytes"]) != expected_windows:
        _fail(path, f"{scenario} requires connection/stream windows {expected_windows}")
    if scenario == "memory_curve":
        if connection_grid != (0, 64, 256, 1024):
            _fail(f"{path}.connection_count_grid", "memory_curve requires N={0,64,256,1024}")
    elif connection_grid != (obj["connections"],):
        _fail(f"{path}.connection_count_grid", "must contain only the fixed connection treatment")
    return obj


def validate_experiment_spec(data: Any) -> ExperimentSpecV2:
    if not isinstance(data, Mapping):
        _fail("$", "must be an object")
    schema_version = data.get("schema_version")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        _fail(
            "$.schema_version",
            "must equal one of "
            + ", ".join(repr(value) for value in sorted(SUPPORTED_SCHEMA_VERSIONS)),
        )
    root = _object(
        data,
        "$",
        TOP_LEVEL_V21 if schema_version in VERSIONED_SCHEMA_VERSIONS else TOP_LEVEL,
    )
    if root["control_protocol_version"] != CONTROL_VERSION:
        _fail("$.control_protocol_version", f"must equal {CONTROL_VERSION!r}")
    name = _identifier(root["name"], "$.name")
    campaign_kind = _enum(root["campaign_kind"], "$.campaign_kind", {
        "publication", "capacity", "memory", "tail", "diagnostic", "qualification", "ci",
    })
    estimand = _enum(root["estimand"], "$.estimand", {
        "fixed_treatment_server", "capacity_frontier", "memory_curve", "tail_latency",
        "symmetric_stack_pair", "behavioral_validation",
    })
    methodology: Mapping[str, Any] | None = None
    if schema_version in VERSIONED_SCHEMA_VERSIONS:
        if campaign_kind != "publication":
            _fail(
                "$.schema_version",
                f"{schema_version} is defined only for publication campaigns",
            )
        methodology = _object(
            root["methodology"],
            "$.methodology",
            {"version", "control_plane", "monitor", "runtime"},
        )
        expected_methodology_version = {
            SCHEMA_VERSION_V21: "2.1",
            SCHEMA_VERSION_V22: "2.2",
            SCHEMA_VERSION_V23: "2.3",
        }[schema_version]
        if methodology["version"] != expected_methodology_version:
            _fail(
                "$.methodology.version",
                f"must equal {expected_methodology_version!r}",
            )
        control_plane = _object(
            methodology["control_plane"],
            "$.methodology.control_plane",
            {
                "arm_lead_ns",
                "pre_send_guard_ns",
                "pre_send_rebase_maximum",
                "late_arm_retry_budget_per_session",
                "live_monitoring_contract",
            },
        )
        if (
            _integer(
                control_plane["arm_lead_ns"],
                "$.methodology.control_plane.arm_lead_ns",
                minimum=500_000_000,
            )
            != 750_000_000
        ):
            _fail(
                "$.methodology.control_plane.arm_lead_ns",
                "must equal the frozen 750 ms lead",
            )
        if (
            _integer(
                control_plane["pre_send_guard_ns"],
                "$.methodology.control_plane.pre_send_guard_ns",
                minimum=1,
            )
            != 500_000_000
        ):
            _fail(
                "$.methodology.control_plane.pre_send_guard_ns",
                "must equal the frozen 500 ms guard",
            )
        if (
            _integer(
                control_plane["pre_send_rebase_maximum"],
                "$.methodology.control_plane.pre_send_rebase_maximum",
                minimum=1,
            )
            != 2
        ):
            _fail(
                "$.methodology.control_plane.pre_send_rebase_maximum",
                "must equal the frozen two-rebase bound",
            )
        if (
            _integer(
                control_plane["late_arm_retry_budget_per_session"],
                "$.methodology.control_plane.late_arm_retry_budget_per_session",
                minimum=1,
            )
            != 1
        ):
            _fail(
                "$.methodology.control_plane.late_arm_retry_budget_per_session",
                "must equal the frozen one-microblock session budget",
            )
        if (
            _string(
                control_plane["live_monitoring_contract"],
                "$.methodology.control_plane.live_monitoring_contract",
            )
            != "passive_service_events_no_live_journal_polling"
        ):
            _fail(
                "$.methodology.control_plane.live_monitoring_contract",
                "must require passive service events and prohibit live journal polling",
            )
        monitor = _object(
            methodology["monitor"],
            "$.methodology.monitor",
            {
                "boundary_timestamp_semantics",
                "interval_duration_error_max_fraction",
                "phase_offset_max_ns",
                "combined_tctl_gap_max_ns",
                "localized_transient_budget_per_session",
            },
        )
        if monitor["boundary_timestamp_semantics"] != "observed_interval":
            _fail(
                "$.methodology.monitor.boundary_timestamp_semantics",
                "must equal 'observed_interval'",
            )
        if (
            _decimal(
                monitor["interval_duration_error_max_fraction"],
                "$.methodology.monitor.interval_duration_error_max_fraction",
                positive=True,
                maximum=Decimal("0.001"),
            )
            != "0.001"
        ):
            _fail(
                "$.methodology.monitor.interval_duration_error_max_fraction",
                "must equal the frozen 0.001 bound",
            )
        phase_offset_max_ns = _integer(
            monitor["phase_offset_max_ns"],
            "$.methodology.monitor.phase_offset_max_ns",
            minimum=1,
        )
        if phase_offset_max_ns > 5_000_000:
            _fail(
                "$.methodology.monitor.phase_offset_max_ns",
                "must not exceed the frozen conservative 5 ms cap",
            )
        if (
            _integer(
                monitor["combined_tctl_gap_max_ns"],
                "$.methodology.monitor.combined_tctl_gap_max_ns",
                minimum=1,
            )
            != 250_000_000
        ):
            _fail(
                "$.methodology.monitor.combined_tctl_gap_max_ns",
                "must equal the frozen 250 ms bound",
            )
        _integer(
            monitor["localized_transient_budget_per_session"],
            "$.methodology.monitor.localized_transient_budget_per_session",
            minimum=0,
            maximum=12,
        )
        runtime_fields = {
            "useful_time_publication_gate",
            "operational_session_timeout_ns",
            "historical_evidence_artifact",
            "historical_evidence_sha256",
        }
        if schema_version in IOURING_ONLY_SCHEMA_VERSIONS:
            runtime_fields |= {
                "deterministic_verification_budget_ns",
                "admission_conservative_reservation_ns",
                "analysis_finalization_export_budget_ns",
                "scheduled_campaign_floor_ns",
                "clean_start_conservative_budget_ns",
                "suite_deadline_ns",
            }
        runtime_methodology = _object(
            methodology["runtime"],
            "$.methodology.runtime",
            runtime_fields,
        )
        if runtime_methodology["useful_time_publication_gate"] is not False:
            _fail(
                "$.methodology.runtime.useful_time_publication_gate",
                "must be false for versioned publication methodology",
            )
        operational_session_timeout_ns = _integer(
            runtime_methodology["operational_session_timeout_ns"],
            "$.methodology.runtime.operational_session_timeout_ns",
            minimum=1,
        )
        if schema_version in IOURING_ONLY_SCHEMA_VERSIONS:
            operational_timeout, clean_start, suite_deadline = {
                SCHEMA_VERSION_V22: (
                    8_400_000_000_000,
                    22_447_800_000_000,
                    25_200_000_000_000,
                ),
                SCHEMA_VERSION_V23: (
                    10_800_000_000_000,
                    27_247_800_000_000,
                    30_000_000_000_000,
                ),
            }[schema_version]
            frozen_runtime = {
                "operational_session_timeout_ns": operational_timeout,
                "deterministic_verification_budget_ns": 1_200_000_000_000,
                "admission_conservative_reservation_ns": 3_847_800_000_000,
                "analysis_finalization_export_budget_ns": 600_000_000_000,
                "scheduled_campaign_floor_ns": 13_921_000_000_000,
                "clean_start_conservative_budget_ns": clean_start,
                "suite_deadline_ns": suite_deadline,
            }
            for field, expected in frozen_runtime.items():
                if (
                    _integer(
                        runtime_methodology[field],
                        f"$.methodology.runtime.{field}",
                        minimum=1,
                    )
                    != expected
                ):
                    _fail(
                        f"$.methodology.runtime.{field}",
                        f"must equal the frozen {expected} ns value",
                    )
            if (
                2 * operational_session_timeout_ns
                + runtime_methodology["deterministic_verification_budget_ns"]
                + runtime_methodology["admission_conservative_reservation_ns"]
                + runtime_methodology[
                    "analysis_finalization_export_budget_ns"
                ]
                != runtime_methodology["clean_start_conservative_budget_ns"]
            ):
                _fail(
                    "$.methodology.runtime.clean_start_conservative_budget_ns",
                    "does not equal the frozen phase sum",
                )
            if (
                runtime_methodology["clean_start_conservative_budget_ns"]
                > runtime_methodology["suite_deadline_ns"]
            ):
                _fail(
                    "$.methodology.runtime.suite_deadline_ns",
                    "must cover the conservative clean-start budget",
                )
        _safe_path(
            runtime_methodology["historical_evidence_artifact"],
            "$.methodology.runtime.historical_evidence_artifact",
        )
        if not SHA256.fullmatch(
            _string(
                runtime_methodology["historical_evidence_sha256"],
                "$.methodology.runtime.historical_evidence_sha256",
            )
        ):
            _fail(
                "$.methodology.runtime.historical_evidence_sha256",
                "must be a lowercase SHA-256 digest",
            )
    required_estimand = {
        "publication": "fixed_treatment_server", "capacity": "capacity_frontier",
        "memory": "memory_curve", "tail": "tail_latency", "diagnostic": "symmetric_stack_pair",
        "qualification": "behavioral_validation", "ci": "behavioral_validation",
    }[campaign_kind]
    if estimand != required_estimand:
        _fail("$.estimand", f"{campaign_kind} campaigns require {required_estimand}")

    roles = _object(root["roles"], "$.roles", {"servers", "reference_clients"})
    servers = _unique_identifiers(roles["servers"], "$.roles.servers")
    clients = _unique_identifiers(roles["reference_clients"], "$.roles.reference_clients")
    backends = _object(root["backends"], "$.backends", {"server", "reference_client"})
    server_backends = _unique_identifiers(backends["server"], "$.backends.server")
    if not set(server_backends) <= {"syscall", "iouring"}:
        _fail("$.backends.server", "only syscall and iouring are supported by the common driver")
    client_backend = _enum(backends["reference_client"], "$.backends.reference_client", {"syscall", "iouring"})
    if schema_version in IOURING_ONLY_SCHEMA_VERSIONS and (
        server_backends != ("iouring",) or client_backend != "iouring"
    ):
        _fail(
            "$.backends",
            "versioned one-backend publication preflight and trials require iouring only",
        )

    path_models: list[PathProfile] = []
    path_names: set[str] = set()
    for index, item in enumerate(_array(root["paths"], "$.paths")):
        path = f"$.paths[{index}]"
        obj = _object(item, path, {
            "name", "content_hash", "trace_policy", "trace_seed_derivation",
            "one_way_delay_ns", "loss_percent", "dynamic",
        })
        path_name = _identifier(obj["name"], f"{path}.name")
        if path_name in path_names:
            _fail(f"{path}.name", "duplicate path profile")
        path_names.add(path_name)
        digest = _string(obj["content_hash"], f"{path}.content_hash")
        if not SHA256.fullmatch(digest):
            _fail(f"{path}.content_hash", "must be a lowercase full SHA-256 digest")
        trace_policy = _enum(obj["trace_policy"], f"{path}.trace_policy", {"none", "deterministic_hmac"})
        seed_rule = _enum(obj["trace_seed_derivation"], f"{path}.trace_seed_derivation", {
            "none", "campaign_microblock_path_hmac_sha256",
        })
        delay = _integer(obj["one_way_delay_ns"], f"{path}.one_way_delay_ns", minimum=0)
        loss = _decimal(obj["loss_percent"], f"{path}.loss_percent", maximum=Decimal("100"))
        dynamic = _boolean(obj["dynamic"], f"{path}.dynamic")
        path_content = {key: value for key, value in obj.items() if key != "content_hash"}
        if canonical_sha256(path_content) != digest:
            _fail(f"{path}.content_hash", "does not match canonical path-profile content")
        if (trace_policy == "none") != (seed_rule == "none"):
            _fail(path, "trace policy and trace seed derivation must both be enabled or disabled")
        if path_name == "loopback" and (delay != 0 or loss != "0" or dynamic):
            _fail(path, "loopback must have zero delay/loss and be static")
        if path_name == "loss_recovery_v1" and (
            delay != 10_000_000 or loss != "1" or not dynamic or trace_policy != "deterministic_hmac"
        ):
            _fail(path, "loss_recovery_v1 must freeze 10 ms delay and deterministic 1% loss")
        path_models.append(PathProfile(path_name, digest, trace_policy, seed_rule, delay, loss, dynamic))

    workloads = tuple(_validate_workload(item, i, path_names)
                      for i, item in enumerate(_array(root["workloads"], "$.workloads")))
    scenarios = tuple(item["scenario"] for item in workloads)
    if len(set(scenarios)) != len(scenarios):
        _fail("$.workloads", "scenario entries must be unique")

    treatment = _object(root["treatment"], "$.treatment", {"transport", "tls", "socket", "resources"})
    transport = _object(treatment["transport"], "$.treatment.transport", {
        "quic_version", "alpn", "congestion_controller", "initial_congestion_window_bytes",
        "max_udp_payload_size", "max_ack_delay_ns", "ack_delay_exponent",
        "ack_frequency", "active_migration", "active_connection_id_limit",
        "connection_id_bytes", "max_idle_timeout_ns", "stream_credit_bidi",
        "stream_credit_uni", "stream_credit_replenish_below", "connection_window_bytes",
        "stream_window_bytes", "datagram_max_frame_size",
    })
    for field in (
        "initial_congestion_window_bytes", "max_udp_payload_size", "max_ack_delay_ns",
        "ack_delay_exponent", "active_connection_id_limit", "connection_id_bytes",
        "max_idle_timeout_ns", "stream_credit_bidi", "stream_credit_uni",
        "stream_credit_replenish_below", "connection_window_bytes", "stream_window_bytes",
        "datagram_max_frame_size",
    ):
        _integer(transport[field], f"$.treatment.transport.{field}", minimum=1)
    _string(transport["quic_version"], "$.treatment.transport.quic_version")
    _string(transport["alpn"], "$.treatment.transport.alpn")
    _identifier(transport["congestion_controller"], "$.treatment.transport.congestion_controller")
    _boolean(transport["ack_frequency"], "$.treatment.transport.ack_frequency")
    _boolean(transport["active_migration"], "$.treatment.transport.active_migration")

    tls = _object(treatment["tls"], "$.treatment.tls", {
        "version", "cipher_suite", "key_exchange", "leaf_signature", "ca_path", "chain_path",
        "hostname", "verify", "calendar_unix_seconds", "ticket_lifetime_ns",
        "maximum_early_data_bytes", "one_use_tickets",
    })
    for field in ("version", "cipher_suite", "key_exchange", "leaf_signature", "hostname"):
        _string(tls[field], f"$.treatment.tls.{field}")
    _safe_path(tls["ca_path"], "$.treatment.tls.ca_path")
    _safe_path(tls["chain_path"], "$.treatment.tls.chain_path")
    for field in ("verify", "one_use_tickets"):
        _boolean(tls[field], f"$.treatment.tls.{field}")
    _integer(tls["ticket_lifetime_ns"], "$.treatment.tls.ticket_lifetime_ns", minimum=1)
    _integer(tls["calendar_unix_seconds"], "$.treatment.tls.calendar_unix_seconds", minimum=1)
    _integer(tls["maximum_early_data_bytes"], "$.treatment.tls.maximum_early_data_bytes", minimum=0)

    socket = _object(treatment["socket"], "$.treatment.socket", {
        "ipv4", "mtu", "receive_batch", "send_batch", "requested_send_buffer_bytes",
        "requested_receive_buffer_bytes", "buffer_pool_size", "application_buffer_bytes",
        "reuse_port", "pmtud", "udp_gso", "udp_gro", "ecn", "receive_timestamps",
        "busy_polling", "common_core_pacing",
    })
    for field in ("mtu", "receive_batch", "send_batch", "requested_send_buffer_bytes",
                  "requested_receive_buffer_bytes", "buffer_pool_size", "application_buffer_bytes"):
        _integer(socket[field], f"$.treatment.socket.{field}", minimum=1)
    for field in ("ipv4", "reuse_port", "pmtud", "udp_gso", "udp_gro", "ecn",
                  "receive_timestamps", "busy_polling", "common_core_pacing"):
        _boolean(socket[field], f"$.treatment.socket.{field}")

    resources = _object(treatment["resources"], "$.treatment.resources", {
        "server_cpu_max", "client_cpu_max", "server_memory_max_bytes", "client_memory_max_bytes",
        "swap_max_bytes", "pids_max", "server_physical_cores", "client_physical_cores",
        "numa_policy", "smt_overlap", "cgroup_v2", "irq_exclusion", "governor", "epp",
        "turbo",
    })
    for field in ("server_cpu_max", "client_cpu_max", "numa_policy", "governor", "epp"):
        _string(resources[field], f"$.treatment.resources.{field}")
    for field in ("server_memory_max_bytes", "client_memory_max_bytes", "swap_max_bytes", "pids_max",
                  "server_physical_cores", "client_physical_cores"):
        _integer(resources[field], f"$.treatment.resources.{field}", minimum=0)
    for field in ("smt_overlap", "cgroup_v2", "irq_exclusion", "turbo"):
        _boolean(resources[field], f"$.treatment.resources.{field}")

    timing = _object(root["timing"], "$.timing", {"progress_cadence_ns", "completion_bound_ns", "timeouts"})
    _integer(timing["progress_cadence_ns"], "$.timing.progress_cadence_ns", minimum=1)
    _integer(timing["completion_bound_ns"], "$.timing.completion_bound_ns", minimum=1)
    timeouts = _object(timing["timeouts"], "$.timing.timeouts", {
        "describe_ns", "ready_ns", "arm_ns", "start_ack_ns", "drain_ns", "result_ns", "terminate_ns",
    })
    for field, value in timeouts.items():
        _integer(value, f"$.timing.timeouts.{field}", minimum=1)

    schedule = _object(root["schedule"], "$.schedule", {
        "sessions", "williams_rows", "microblock_construction", "campaign_seed_derivation",
        "backend_order", "reference_client_assignment", "lane_assignment",
        "worker_process_policy", "maximum_schedule_frozen",
        "dormant_retry_per_microblock", "confirmation_branches",
    })
    sessions = _integer(schedule["sessions"], "$.schedule.sessions", minimum=1)
    rows = _integer(schedule["williams_rows"], "$.schedule.williams_rows", minimum=1)
    for field in ("microblock_construction", "campaign_seed_derivation", "backend_order",
                  "reference_client_assignment", "lane_assignment",
                  "worker_process_policy"):
        _string(schedule[field], f"$.schedule.{field}")
    if (
        schema_version in IOURING_ONLY_SCHEMA_VERSIONS
        and schedule["backend_order"] != "single_iouring_invariant"
    ):
        _fail(
            "$.schedule.backend_order",
            "versioned one-backend publication requires the sole iouring backend order",
        )
    if schedule["worker_process_policy"] not in {
        "fresh_process",
        "persistent_reset",
    }:
        _fail(
            "$.schedule.worker_process_policy",
            "must be fresh_process or persistent_reset",
        )
    _boolean(schedule["maximum_schedule_frozen"], "$.schedule.maximum_schedule_frozen")
    _integer(schedule["dormant_retry_per_microblock"], "$.schedule.dormant_retry_per_microblock", minimum=0, maximum=1)
    _integer(schedule["confirmation_branches"], "$.schedule.confirmation_branches", minimum=0)

    analysis = _object(root["analysis"], "$.analysis", {
        "primary_family", "baseline", "alpha", "practical_margin", "multiplicity",
        "orientation", "sign_patterns", "planning_log_ratio_sd", "minimum_power",
        "statistical_calibration",
    })
    _string(analysis["primary_family"], "$.analysis.primary_family")
    _identifier(analysis["baseline"], "$.analysis.baseline")
    _decimal(analysis["alpha"], "$.analysis.alpha", positive=True, maximum=Decimal("1"))
    _decimal(analysis["practical_margin"], "$.analysis.practical_margin", positive=True)
    _enum(analysis["multiplicity"], "$.analysis.multiplicity", {"exact_common_sign_max_abs_t", "none"})
    _enum(analysis["orientation"], "$.analysis.orientation", {"positive_is_better"})
    _integer(analysis["sign_patterns"], "$.analysis.sign_patterns", minimum=1)
    _decimal(analysis["planning_log_ratio_sd"], "$.analysis.planning_log_ratio_sd", positive=True)
    _decimal(analysis["minimum_power"], "$.analysis.minimum_power", positive=True, maximum=Decimal("1"))
    calibration = _object(
        analysis["statistical_calibration"],
        "$.analysis.statistical_calibration",
        {
            "artifact_sha256", "algorithm_version", "campaigns_per_condition",
            "implementation_calibration_passed", "profile_design_power_gate_passed",
            "publication_analysis_permitted", "independence_planning_result",
            "planning_result",
        },
    )
    digest = _string(
        calibration["artifact_sha256"],
        "$.analysis.statistical_calibration.artifact_sha256",
    )
    if not SHA256.fullmatch(digest):
        _fail("$.analysis.statistical_calibration.artifact_sha256", "must be a SHA-256 digest")
    _string(calibration["algorithm_version"], "$.analysis.statistical_calibration.algorithm_version")
    _integer(
        calibration["campaigns_per_condition"],
        "$.analysis.statistical_calibration.campaigns_per_condition",
        minimum=25_000,
    )
    for field in (
        "implementation_calibration_passed", "profile_design_power_gate_passed",
        "publication_analysis_permitted",
    ):
        _boolean(calibration[field], f"$.analysis.statistical_calibration.{field}")
    for planning_field in ("independence_planning_result", "planning_result"):
        planning_path = f"$.analysis.statistical_calibration.{planning_field}"
        planning = _object(
            calibration[planning_field],
            planning_path,
            {
                "blocks", "raw_rows", "campaigns", "critical_value_simulation",
                "cross_session_correlation", "declared_effect",
                "declared_effect_power", "equivalence", "family_size", "margin",
                "name", "raw_session_paired_log_ratio_sd", "passed",
                "standard_error", "superblock_variance_formula",
                "twice_margin_effect", "twice_margin_power",
            },
        )
        for field in ("blocks", "raw_rows", "campaigns", "family_size"):
            _integer(planning[field], f"{planning_path}.{field}", minimum=1)
        _identifier(planning["name"], f"{planning_path}.name")
        _string(planning["standard_error"], f"{planning_path}.standard_error")
        _string(
            planning["superblock_variance_formula"],
            f"{planning_path}.superblock_variance_formula",
        )
        _boolean(planning["passed"], f"{planning_path}.passed")
        for field in (
            "cross_session_correlation", "declared_effect", "margin",
            "raw_session_paired_log_ratio_sd", "twice_margin_effect",
        ):
            _decimal(
                planning[field],
                f"{planning_path}.{field}",
                positive=field != "cross_session_correlation",
            )
        critical = _object(
            planning["critical_value_simulation"],
            f"{planning_path}.critical_value_simulation",
            {"minimum", "mean", "empirical_95th", "maximum"},
        )
        for field in ("minimum", "mean", "empirical_95th", "maximum"):
            _decimal(critical[field], f"{planning_path}.critical_value_simulation.{field}", positive=True)
        for result_name in ("equivalence", "declared_effect_power", "twice_margin_power"):
            result_path = f"{planning_path}.{result_name}"
            result = _object(
                planning[result_name], result_path,
                {"count", "probability", "one_sided_95_exact_binomial_lower"},
            )
            _integer(result["count"], f"{result_path}.count")
            for field in ("probability", "one_sided_95_exact_binomial_lower"):
                _decimal(result[field], f"{result_path}.{field}", maximum=Decimal("1"))

    manifest_policy = _object(root["manifest_policy"], "$.manifest_policy", {
        "clean_tree_required", "allow_diagnostic_dirty", "hash_loaded_libraries",
        "require_release_policy", "require_exact_effective_commands",
    })
    for field, value in manifest_policy.items():
        _boolean(value, f"$.manifest_policy.{field}")
    validity = _object(root["validity"], "$.validity", {
        "client_cpu_p95_max", "integer_operation_minimum", "subwindows", "reject_socket_drops",
        "reject_cap_hits", "reject_generator_starvation", "require_progress_or_blocked",
        "require_negotiated_match", "require_zero_cgroup_throttling",
    })
    _decimal(validity["client_cpu_p95_max"], "$.validity.client_cpu_p95_max", positive=True, maximum=Decimal("1"))
    for field in ("integer_operation_minimum", "subwindows"):
        _integer(validity[field], f"$.validity.{field}", minimum=1)
    for field in ("reject_socket_drops", "reject_cap_hits", "reject_generator_starvation",
                  "require_progress_or_blocked", "require_negotiated_match",
                  "require_zero_cgroup_throttling"):
        _boolean(validity[field], f"$.validity.{field}")
    retry = _object(root["retry"], "$.retry", {"maximum", "scope", "closed_reasons", "preallocated"})
    _integer(retry["maximum"], "$.retry.maximum", minimum=0, maximum=1)
    _enum(
        retry["scope"],
        "$.retry.scope",
        {"complete_session", "localized_interval_and_complete_session", "none"},
    )
    reason_values = _array(
        retry["closed_reasons"], "$.retry.closed_reasons", nonempty=bool(retry["maximum"])
    )
    reasons = tuple(
        _identifier(item, f"$.retry.closed_reasons[{index}]")
        for index, item in enumerate(reason_values)
    )
    if len(reasons) != len(set(reasons)):
        _fail("$.retry.closed_reasons", "must not contain duplicates")
    _boolean(retry["preallocated"], "$.retry.preallocated")

    expected = _object(root["expected_cardinality"], "$.expected_cardinality", {
        "planned_trials", "maximum_trial_ids", "committed_samples", "sessions", "williams_rows",
    })
    expected_model = ExpectedCardinality(*(
        _integer(expected[field], f"$.expected_cardinality.{field}", minimum=1)
        for field in ("planned_trials", "maximum_trial_ids", "committed_samples", "sessions", "williams_rows")
    ))
    if expected_model.maximum_trial_ids < expected_model.planned_trials:
        _fail("$.expected_cardinality", "maximum_trial_ids cannot be below planned_trials")
    if expected_model.committed_samples > expected_model.planned_trials:
        _fail("$.expected_cardinality", "committed_samples cannot exceed planned_trials")
    if (expected_model.sessions, expected_model.williams_rows) != (sessions, rows):
        _fail("$.expected_cardinality", "session and Williams counts must match schedule")

    qualification = _object(root["qualification"], "$.qualification", {
        "host_stability_required", "worker_reuse_required", "lane_interference_required", "client_headroom_required",
        "window_equivalence_required", "tail_window_required",
    })
    for field, value in qualification.items():
        _boolean(value, f"$.qualification.{field}")

    if campaign_kind in {"publication", "capacity", "memory", "tail"}:
        if not qualification["host_stability_required"]:
            _fail("$.qualification.host_stability_required", "canonical campaigns require host stability")
        if validity["subwindows"] != 10:
            _fail(
                "$.validity.subwindows",
                "canonical campaigns require exactly ten public progress buckets",
            )
        if servers != PUBLICATION_SERVERS or clients != REFERENCE_CLIENTS:
            _fail("$.roles", "canonical campaigns require the fixed 12 servers and two reference clients")
        canonical_server_backends = (
            ("iouring",)
            if schema_version in IOURING_ONLY_SCHEMA_VERSIONS
            else ("syscall", "iouring")
        )
        if (
            server_backends != canonical_server_backends
            or client_backend != "iouring"
        ):
            _fail(
                "$.backends",
                "canonical campaign backend treatment differs",
            )
        if not manifest_policy["clean_tree_required"]:
            _fail("$.manifest_policy.clean_tree_required", "canonical campaigns require a clean tree")
        frozen_transport = {
            "quic_version": "0x00000001", "alpn": "qperf/2", "congestion_controller": "cubic",
            "initial_congestion_window_bytes": 13500, "max_udp_payload_size": 1350,
            "max_ack_delay_ns": 25000000, "ack_delay_exponent": 3, "ack_frequency": False,
            "active_migration": False, "active_connection_id_limit": 2, "connection_id_bytes": 8,
            "max_idle_timeout_ns": 30000000000, "stream_credit_bidi": 256,
            "stream_credit_uni": 256, "stream_credit_replenish_below": 32,
            "connection_window_bytes": 67108864, "stream_window_bytes": 67108864,
            "datagram_max_frame_size": 1200,
        }
        if dict(transport) != frozen_transport:
            _fail("$.treatment.transport", "canonical transport treatment differs from the frozen policy")
        frozen_tls = {
            "version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256",
            "key_exchange": "X25519", "leaf_signature": "Ed25519",
            "ca_path": "tls/chain.cert.pem", "chain_path": "tls/server.cert.pem",
            "hostname": "server.quicperf.test", "verify": True,
            "calendar_unix_seconds": 1784376000,
            "ticket_lifetime_ns": 300000000000, "maximum_early_data_bytes": 4096,
            "one_use_tickets": True,
        }
        if dict(tls) != frozen_tls:
            _fail("$.treatment.tls", "canonical TLS treatment differs from the frozen policy")
        frozen_socket = {
            "ipv4": True, "mtu": 1500, "receive_batch": 64, "send_batch": 64,
            "requested_send_buffer_bytes": 16777216,
            "requested_receive_buffer_bytes": 16777216, "buffer_pool_size": 4096,
            "application_buffer_bytes": 262144, "reuse_port": False, "pmtud": False,
            "udp_gso": True, "udp_gro": True, "ecn": False, "receive_timestamps": False,
            "busy_polling": False, "common_core_pacing": True,
        }
        if dict(socket) != frozen_socket:
            _fail("$.treatment.socket", "canonical socket treatment differs from the frozen policy")
        frozen_resources = {
            "server_cpu_max": "max 100000", "client_cpu_max": "max 100000",
            "server_memory_max_bytes": 8589934592, "client_memory_max_bytes": 8589934592,
            "swap_max_bytes": 0, "pids_max": 1024, "server_physical_cores": 1,
            "client_physical_cores": 4 if campaign_kind == "publication" else 2,
            "numa_policy": "single_node", "smt_overlap": False,
            "cgroup_v2": True, "irq_exclusion": True, "governor": "performance",
            "epp": "performance", "turbo": False,
        }
        if dict(resources) != frozen_resources:
            _fail("$.treatment.resources", "canonical resource treatment differs from the frozen policy")
        expected_retry_reasons = (
            V21_INFRASTRUCTURE_TRANSIENT_REASONS
            if schema_version in VERSIONED_SCHEMA_VERSIONS
            else INFRASTRUCTURE_TRANSIENT_REASONS
        )
        expected_retry_scope = (
            "localized_interval_and_complete_session"
            if schema_version in VERSIONED_SCHEMA_VERSIONS
            else "complete_session"
        )
        if reasons != expected_retry_reasons or retry["scope"] != expected_retry_scope:
            _fail("$.retry", "canonical campaigns require the exact infrastructure-transient policy")
        if not schedule["maximum_schedule_frozen"] or retry["maximum"] != 1:
            _fail("$.schedule", "canonical maximum schedules and one dormant retry must be frozen")
        expected_worker_policy = (
            "fresh_process" if campaign_kind == "memory" else "persistent_reset"
        )
        if schedule["worker_process_policy"] != expected_worker_policy:
            _fail(
                "$.schedule.worker_process_policy",
                f"{campaign_kind} requires {expected_worker_policy}",
            )
    if campaign_kind == "publication":
        if scenarios != PUBLICATION_SCENARIOS:
            _fail("$.workloads", "publication scenarios or their canonical order differ")
        if schedule["lane_assignment"] != "single_lane":
            _fail("$.schedule.lane_assignment", "publication requires one frozen execution lane")
        if qualification["lane_interference_required"]:
            _fail(
                "$.qualification.lane_interference_required",
                "single-lane publication cannot require a two-lane interference treatment",
            )
        if (sessions, rows) != (2, 12):
            _fail("$.schedule", "publication requires two sessions and 12 Williams rows")
        expected_publication_cardinality = (
            (4320, 8640, 4320)
            if schema_version in IOURING_ONLY_SCHEMA_VERSIONS
            else (8640, 17280, 8640)
        )
        if (
            expected_model.planned_trials,
            expected_model.maximum_trial_ids,
            expected_model.committed_samples,
        ) != expected_publication_cardinality:
            _fail(
                "$.expected_cardinality",
                "publication cardinality must be "
                + "/".join(str(value) for value in expected_publication_cardinality),
            )
        for index, workload in enumerate(workloads):
            scenario = workload["scenario"]
            expected_measurement = 5000000000 if scenario == "loss_recovery" else 2000000000
            expected_warmup = 0 if scenario in {"connect", "resumed_connect", "zero_rtt_reqresp"} else (
                500000000 if scenario == "loss_recovery" else 250000000
            )
            if workload["measurement_ns"] != expected_measurement or workload["warmup_ns"] != expected_warmup:
                _fail(f"$.workloads[{index}]", "publication measurement/warmup window differs")
            if tuple(workload["concurrency_grid"]) != (16,):
                _fail(f"$.workloads[{index}].concurrency_grid", "publication treatment is fixed at 16")
    elif campaign_kind == "capacity" and scenarios != CAPACITY_SCENARIOS:
        _fail("$.workloads", "capacity profile must contain the exact seven-scenario set")
    elif campaign_kind == "tail" and scenarios != TAIL_SCENARIOS:
        _fail("$.workloads", "tail profile must contain the exact eight-scenario set")
    if campaign_kind == "capacity":
        for index, workload in enumerate(workloads):
            if tuple(workload["concurrency_grid"]) != (1, 2, 4, 8, 16):
                _fail(f"$.workloads[{index}].concurrency_grid", "capacity grid must be 1,2,4,8,16")
        if schedule["confirmation_branches"] != 5:
            _fail("$.schedule.confirmation_branches", "capacity requires five frozen branches")
    if campaign_kind == "memory":
        if scenarios != ("memory_curve",) or expected_model.planned_trials != 2304:
            _fail("$", "memory profile requires memory_curve and 2,304 planned N-points")
    if campaign_kind == "tail":
        if (
            expected_model.planned_trials,
            expected_model.maximum_trial_ids,
            expected_model.committed_samples,
        ) != (4608, 9216, 4608):
            _fail("$.expected_cardinality", "tail cardinality must be 4608/9216/4608")
        if any(workload["eligible_operation_limit"] != 1024 for workload in workloads):
            _fail("$.workloads", "tail inference requires exactly 1,024 operations per block")
    if schedule["dormant_retry_per_microblock"] != retry["maximum"] or retry["preallocated"] != bool(retry["maximum"]):
        _fail("$.retry", "retry count and preallocation must match the frozen schedule")
    if retry["maximum"] and not reasons:
        _fail("$.retry.closed_reasons", "retry-enabled profiles need a closed reason set")

    frozen = freeze_json(root)
    assert isinstance(frozen, Mapping)
    return ExperimentSpecV2(
        str(schema_version), CONTROL_VERSION, name, campaign_kind, estimand, servers, clients,
        scenarios, server_backends, client_backend, tuple(path_models), expected_model, frozen,
    )


def load_experiment_spec(source: str | bytes | bytearray | Path | Mapping[str, Any]) -> ExperimentSpecV2:
    if isinstance(source, Mapping):
        data = source
    elif isinstance(source, Path):
        data = load_strict(source)
    elif isinstance(source, (bytes, bytearray)):
        data = loads_strict(source)
    elif isinstance(source, str):
        stripped = source.lstrip()
        data = loads_strict(source) if stripped.startswith(("{", "[")) else load_strict(source)
    else:
        _fail("$", "spec source must be a mapping, JSON document, or path")
    return validate_experiment_spec(data)
