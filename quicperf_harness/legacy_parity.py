"""Fresh legacy/V2 migration parity and Milestone-A evidence."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from decimal import Decimal
import csv
import fcntl
from functools import lru_cache
import hashlib
import hmac
import math
import os
from pathlib import Path
import sqlite3
import subprocess
import threading
import time
from typing import Any, Mapping, Sequence

from .canonical import canonical_bytes, loads_strict, normalize_decimal
from .errors import IdentityMismatchError, InvalidConfigurationError
from .identity import domain_hash, spec_hash
from .journal import Journal
from .legacy import translate_legacy
from .manifest import manifest_hash
from .manifest_collect import collect_manifest
from .qualification import QualificationArtifactStore, build_qualification_identity
from .qualification_runner import NativeSessionObservationSource
from .runner import (
    HardwareUnqualifiedError,
    _qualification_max_lanes,
    _load_host_stability_context,
)
from .spec import load_experiment_spec


SCHEMA = "quicperf.legacy-v2-parity.v2"
PLAN_SCHEMA = "quicperf.legacy-v2-parity-plan.v1"
WATERMARK = "DIAGNOSTIC — NOT PUBLICATION DATA"
BLOCKS = 20
T90_DF19 = 1.729132812
NUMERIC_LOWER = 0.97
NUMERIC_UPPER = 1.03
IDLE_SCENARIO = "idle_footprint"
PARITY_MEASUREMENT_NS = 500_000_000
MILESTONE_A_NS = 3 * 60 * 60 * 1_000_000_000 + 30 * 60 * 1_000_000_000


@dataclass(frozen=True)
class ParityExecution:
    artifact: Mapping[str, Any]
    artifact_path: Path


def _seed_bytes(value: str | None) -> bytes:
    if value is None:
        return os.urandom(32)
    try:
        parsed = bytes.fromhex(value)
    except ValueError as exc:
        raise InvalidConfigurationError("parity seed must be 64 hexadecimal digits") from exc
    if len(parsed) != 32:
        raise InvalidConfigurationError("parity seed must be exactly 256 bits")
    return parsed


def _pair_order(seed: bytes, cell: Mapping[str, Any]) -> tuple[str, ...]:
    ranked = sorted(
        range(BLOCKS),
        key=lambda block: hmac.new(
            seed,
            canonical_bytes({"cell": cell, "block": block}),
            hashlib.sha256,
        ).digest(),
    )
    legacy_first = set(ranked[: BLOCKS // 2])
    return tuple("legacy_v2" if block in legacy_first else "v2_legacy" for block in range(BLOCKS))


def build_plan(
    *,
    spec: Any,
    manifest: Any,
    seed: bytes,
    lanes: int,
    diagnostic_authorization: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if spec.name != "parity-validation":
        raise InvalidConfigurationError("legacy parity requires the parity-validation profile")
    if lanes not in {1, 2}:
        raise InvalidConfigurationError("legacy parity requires one or two lanes")
    cells = []
    scenarios = (*spec.scenarios, IDLE_SCENARIO)
    for server in spec.servers:
        for backend in spec.server_backends:
            for scenario in scenarios:
                cell = {
                    "server": server,
                    "backend": backend,
                    "scenario": scenario,
                    "classification": (
                        "legacy_invalid_replaced_by_memory_curve"
                        if scenario == IDLE_SCENARIO
                        else "legacy_unsynchronized_loss_model"
                        if scenario == "loss_recovery"
                        else "numeric_parity"
                    ),
                }
                orders = _pair_order(seed, cell)
                pairs = []
                for block, order in enumerate(orders):
                    identity = canonical_bytes(
                        {"seed": seed.hex(), "cell": cell, "block": block}
                    )
                    pairs.append(
                        {
                            "pair_id": domain_hash("legacy-v2-parity-pair", identity),
                            "block": block,
                            "order": order,
                            "execution_ordinal": None,
                            "lane": None,
                        }
                    )
                cells.append({**cell, "pairs": pairs})
    ranked_pairs = sorted(
        (
            hmac.new(
                seed,
                b"execution-order\0" + bytes.fromhex(str(pair["pair_id"])),
                hashlib.sha256,
            ).digest(),
            pair,
        )
        for cell in cells
        for pair in cell["pairs"]
    )
    for execution_ordinal, (_, pair) in enumerate(ranked_pairs):
        pair["execution_ordinal"] = execution_ordinal
        pair["lane"] = execution_ordinal % lanes
    numeric = sum(cell["classification"] == "numeric_parity" for cell in cells)
    invalid = len(cells) - numeric
    if (len(cells), numeric, invalid) != (384, 336, 48):
        raise InvalidConfigurationError("parity plan is not the frozen 384-cell matrix")
    return {
        "schema_version": PLAN_SCHEMA,
        "seed": seed.hex(),
        "profile_hash": spec_hash(spec.raw),
        "manifest_hash": manifest_hash(manifest),
        "lanes": lanes,
        "blocks_per_cell": BLOCKS,
        "planned_cells": len(cells),
        "planned_pairs": len(cells) * BLOCKS,
        "numeric_cells": numeric,
        "invalid_classification_cells": invalid,
        "diagnostic_authorization": (
            None if diagnostic_authorization is None else dict(diagnostic_authorization)
        ),
        "cells": cells,
    }


def _write_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb", closefd=True) as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _open_state(path: Path, plan_hash: str) -> sqlite3.Connection:
    existed = path.exists()
    connection = sqlite3.connect(path, timeout=30, check_same_thread=False)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata(
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS observation(
          pair_id TEXT NOT NULL,
          mode TEXT NOT NULL CHECK(mode IN ('legacy','v2')),
          status TEXT NOT NULL,
          value_decimal TEXT,
          metric TEXT,
          settings_json TEXT NOT NULL,
          detail TEXT NOT NULL,
          measurement_ns INTEGER NOT NULL,
          wall_ns INTEGER NOT NULL,
          PRIMARY KEY(pair_id, mode)
        );
        """
    )
    row = connection.execute(
        "SELECT value FROM metadata WHERE key='plan_hash'"
    ).fetchone()
    if row is None:
        if existed:
            raise IdentityMismatchError("parity state omitted its plan identity")
        connection.execute(
            "INSERT INTO metadata(key,value) VALUES('plan_hash',?)", (plan_hash,)
        )
        connection.commit()
    elif row[0] != plan_hash:
        raise IdentityMismatchError("parity state is bound to a different plan")
    return connection


def _expected_settings(spec: Any, cell: Mapping[str, Any]) -> dict[str, Any]:
    scenario = str(cell["scenario"])
    if scenario == IDLE_SCENARIO:
        return {
            "server": str(cell["server"]),
            "backend": str(cell["backend"]),
            "client_backend": str(spec.reference_client_backend),
            "scenario": scenario,
            "path_profile": "loopback",
            "logical_connections": 16,
            "client_physical_cores": 2,
            "replacement": "memory_curve",
        }
    if scenario == "loss_recovery":
        return {
            "server": str(cell["server"]),
            "backend": str(cell["backend"]),
            "client_backend": str(spec.reference_client_backend),
            "scenario": scenario,
            "path_profile": "loopback",
            "logical_connections": 16,
            "client_physical_cores": 2,
            "legacy_loss_model": "periodic_packet_drop",
            "replacement": "seeded_quic_packet_loss",
        }
    workload = next(item for item in spec.raw["workloads"] if item["scenario"] == scenario)
    return {
        "server": str(cell["server"]),
        "backend": str(cell["backend"]),
        "client_backend": str(spec.reference_client_backend),
        "scenario": scenario,
        "path_profile": (
            "loss_recovery_v1" if scenario == "loss_recovery" else "loopback"
        ),
        "logical_connections": int(workload["connections"]),
        "client_physical_cores": 2,
        "application_chunk_bytes": int(workload["application_chunk_bytes"]),
        "connection_window_bytes": int(workload["connection_window_bytes"]),
        "stream_window_bytes": int(workload["stream_window_bytes"]),
        "congestion_controller": str(
            spec.raw["treatment"]["transport"]["congestion_controller"]
        ),
        "tls_verify": bool(spec.raw["treatment"]["tls"]["verify"]),
        "tls_leaf_signature": str(spec.raw["treatment"]["tls"]["leaf_signature"]),
    }


def _legacy_metric_value(metric: str, value: str) -> Decimal:
    parsed = Decimal(value)
    if not parsed.is_finite() or parsed <= 0:
        raise ValueError("legacy metric is not finite and positive")
    return parsed * Decimal(1_000_000_000) if metric == "throughput_gbps" else parsed


def _metric_family(scenario: str, mode: str, metric: str) -> str | None:
    bit_rate_scenarios = {
        "download",
        "upload",
        "multistream_download",
        "multistream_upload",
        "bidi",
        "loss_recovery",
        "flow_control",
    }
    if scenario in bit_rate_scenarios:
        expected = (
            "throughput_gbps"
            if mode == "legacy"
            else "validated_body_bits_per_second"
        )
        return "body_bits_per_second" if metric == expected else None
    legacy_operations = {
        "connect": "connections_per_second",
        "resumed_connect": "connections_per_second",
        "reqresp": "requests_per_second",
        "zero_rtt_reqresp": "requests_per_second",
        "stream_churn": "streams_per_second",
        "close_reset_cleanup": "streams_per_second",
        "small_payload_pps": "messages_per_second",
        "datagram": "datagrams_per_second",
    }
    expected = (
        legacy_operations.get(scenario)
        if mode == "legacy"
        else (
            "cleanup_geometric_mean_operations_per_second"
            if scenario == "close_reset_cleanup"
            else "validated_operations_per_second"
        )
    )
    return "operations_per_second" if metric == expected else None


def _legacy_invalid_observation(
    *,
    root: Path,
    bin_dir: Path,
    spec: Any,
    cell: Mapping[str, Any],
    pair: Mapping[str, Any],
    topology: Any,
    out_dir: Path,
) -> dict[str, Any]:
    scenario = str(cell["scenario"])
    if scenario not in {IDLE_SCENARIO, "loss_recovery"}:
        raise InvalidConfigurationError(
            "the retained positional legacy path is restricted to classified invalid cells"
        )
    workload = (
        None
        if scenario == IDLE_SCENARIO
        else next(item for item in spec.raw["workloads"] if item["scenario"] == scenario)
    )
    duration_ns = PARITY_MEASUREMENT_NS
    environment = dict(os.environ)
    environment.update(
        {
            "QUICPERF_BIN_DIR": str(bin_dir),
            "QUICPERF_OUT_DIR": str(out_dir),
            "QUICPERF_BINARIES": str(cell["server"]),
            "QUICPERF_SCENARIOS": scenario,
            "QUICPERF_NETWORKS": str(cell["backend"]),
            "QUICPERF_CLIENT_NETWORK": str(spec.reference_client_backend),
            "QUICPERF_PATH_PROFILES": "loopback",
            "QUICPERF_REPEAT": "1",
            "QUICPERF_WARMUP": "0",
            "QUICPERF_RANDOMIZE_ORDER": "0",
            "QUICPERF_RANDOM_SEED": str(int(str(pair["pair_id"])[:16], 16)),
            "QUICPERF_MEASURE_MODE": "duration",
            "QUICPERF_TARGET_DURATION_MS": str(duration_ns // 1_000_000),
            "QUICPERF_TARGET_WARMUP_MS": str(
                0 if workload is None else int(workload["warmup_ns"]) // 1_000_000
            ),
            "QUICPERF_CLIENT_THREADS": "16",
            "QUICPERF_SERVER_CONNECTIONS": (
                "32" if scenario in {"resumed_connect", "zero_rtt_reqresp"} else "16"
            ),
            "QUICPERF_TARGET_CONNECTIONS": "1",
            "QUICPERF_CLIENT_CPU_LIST": ",".join(map(str, topology.client_cpus)),
            "QUICPERF_SERVER_CPU": str(topology.server_cpu),
            "QUICPERF_PORT_SLOT_OFFSET": str(256 * int(pair["lane"])),
            "QUICPERF_CONGESTION_PROFILE": "cubic",
            "QUICPERF_TLS_VERIFY_MODE": "chain",
            "QUICPERF_TLS_CERT_PROFILE": "ed25519",
            "QUICPERF_TLS_CERT": str(root / "tls/server.cert.pem"),
            "QUICPERF_TLS_KEY": str(root / "tls/server.key.pem"),
            "QUICPERF_TLS_CHAIN": str(root / "tls/chain.cert.pem"),
            "QUICPERF_TIMEOUT": "45s",
            "QUICPERF_SERVER_STOP_TIMEOUT": "60s",
        }
    )
    if workload is not None:
        environment.update(
            {
                "QUICPERF_TEST_BYTES": str(max(1, int(workload["application_chunk_bytes"]))),
                "QUICPERF_STREAMS_IN_FLIGHT": str(
                    max(1, int(workload["streams_per_connection"]))
                ),
                "QUICPERF_REQUEST_BYTES": str(int(workload["request_body_bytes"])),
                "QUICPERF_RESPONSE_BYTES": str(int(workload["response_body_bytes"])),
                "QUICPERF_MESSAGE_BYTES": str(int(workload["message_body_bytes"])),
            }
        )
    started = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    try:
        completed = subprocess.run(
            [str(root / "tools/run-benchmarks.sh")],
            cwd=root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "failed",
            "value_decimal": None,
            "metric": None,
            "settings": {},
            "detail": f"legacy timeout:{exc}",
            "measurement_ns": duration_ns,
            "wall_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) - started,
        }
    wall_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) - started
    if completed.returncode != 0:
        return {
            "status": "failed",
            "value_decimal": None,
            "metric": None,
            "settings": {},
            "detail": completed.stdout[-8192:],
            "measurement_ns": duration_ns,
            "wall_ns": wall_ns,
        }
    try:
        rows = list(
            csv.DictReader((out_dir / "raw-samples.tsv").open(), delimiter="\t")
        )
        summaries = list(
            csv.DictReader((out_dir / "summary.tsv").open(), delimiter="\t")
        )
    except (OSError, csv.Error) as exc:
        return {
            "status": "invalid",
            "value_decimal": None,
            "metric": None,
            "settings": {},
            "detail": f"legacy output unreadable:{exc}",
            "measurement_ns": duration_ns,
            "wall_ns": wall_ns,
        }
    if scenario == IDLE_SCENARIO:
        classified = (
            len(rows) == 1
            and not summaries
            and rows[0].get("status") == "unsupported"
            and rows[0].get("reason") == "requires_duration_mode_adapter_api"
        )
        return {
            "status": "invalid",
            "value_decimal": None,
            "metric": rows[0].get("metric") if len(rows) == 1 else None,
            "settings": _expected_settings(spec, cell) if classified else {},
            "detail": (
                "requires_duration_mode_adapter_api"
                if classified
                else "legacy idle invalidity classification differs"
            ),
            "measurement_ns": 0,
            "wall_ns": wall_ns,
        }
    if len(rows) != 1 or len(summaries) != 1:
        return {
            "status": "invalid",
            "value_decimal": None,
            "metric": None,
            "settings": {},
            "detail": (
                f"legacy raw/summary cardinality was {len(rows)}/{len(summaries)}"
            ),
            "measurement_ns": duration_ns,
            "wall_ns": wall_ns,
        }
    row = rows[0]
    summary = summaries[0]
    expected = _expected_settings(spec, cell)
    expected_server_connections = (
        32 if scenario in {"resumed_connect", "zero_rtt_reqresp"} else 16
    )
    try:
        observed_ok = all(
            (
                summary["binary"] == str(cell["server"]),
                summary["scenario"] == scenario,
                summary["network"] == str(spec.reference_client_backend),
                summary["network_profile"] == str(spec.reference_client_backend),
                summary["path_profile"] == expected["path_profile"],
                int(summary["client_threads"]) == 16,
                int(summary["server_connections"]) == expected_server_connections,
                summary["build_profile"] == "native-lto",
                summary["window_profile"]
                == ("flow-control-small" if scenario == "flow_control" else "default"),
                int(summary["app_chunk"]) == 262_144,
                summary["congestion_profile"] == "cubic",
                summary["tls_verify_mode"] == "chain",
                summary["tls_cert_profile"] == "ed25519",
                "cc=cubic" in summary["adapter_features"].split("|"),
                row["status"] == "ok",
            )
        )
    except (KeyError, TypeError, ValueError):
        observed_ok = False
    try:
        server_log = Path(row["server_log"]).read_text()
    except (KeyError, OSError):
        observed_ok = False
    else:
        observed_ok &= (
            "quicperf_server_ready library=" in server_log
            and f" network={cell['backend']} " in server_log
        )
    try:
        value = _legacy_metric_value(row["metric"], row["value"])
    except (KeyError, ValueError, ArithmeticError) as exc:
        observed_ok = False
        value = None
        detail = str(exc)
    else:
        detail = "" if observed_ok else "legacy effective settings differ"
    if scenario == "loss_recovery" and observed_ok:
        return {
            "status": "invalid",
            "value_decimal": normalize_decimal(value),
            "metric": row.get("metric"),
            "settings": expected,
            "detail": "legacy_periodic_loss_model_is_unsynchronized",
            "measurement_ns": duration_ns,
            "wall_ns": wall_ns,
        }
    return {
        "status": "complete" if observed_ok else "invalid",
        "value_decimal": None if value is None else normalize_decimal(value),
        "metric": row.get("metric"),
        "settings": expected if observed_ok else {},
        "detail": detail,
        "measurement_ns": duration_ns,
        "wall_ns": wall_ns,
    }


@lru_cache(maxsize=None)
def _translated_legacy_cell(
    profile: str, server: str, backend: str, scenario: str
) -> Any:
    return load_experiment_spec(
        translate_legacy(
            Path(profile),
            {
                "QUICPERF_BINARIES": server,
                "QUICPERF_REFERENCE_CLIENTS": server,
                "QUICPERF_SCENARIOS": scenario,
                "QUICPERF_NETWORKS": backend,
            },
        )
    )


def _assert_legacy_translation(
    *, profile: Path, spec: Any, cell: Mapping[str, Any]
) -> None:
    server = str(cell["server"])
    backend = str(cell["backend"])
    scenario = str(cell["scenario"])
    translated = _translated_legacy_cell(
        str(profile.resolve()), server, backend, scenario
    )
    workload = next(
        item for item in spec.raw["workloads"] if item["scenario"] == scenario
    )
    if (
        translated.servers != (server,)
        or translated.reference_clients != (server,)
        or translated.scenarios != (scenario,)
        or translated.server_backends != (backend,)
        or translated.reference_client_backend != spec.reference_client_backend
        or tuple(translated.raw["workloads"]) != (workload,)
        or translated.raw["paths"] != spec.raw["paths"]
        or translated.raw["treatment"] != spec.raw["treatment"]
    ):
        raise IdentityMismatchError(
            "legacy translation does not preserve the frozen parity treatment"
        )


def _legacy_metric_name(scenario: str) -> str:
    if scenario in {
        "download",
        "upload",
        "multistream_download",
        "multistream_upload",
        "bidi",
        "flow_control",
    }:
        return "throughput_gbps"
    return {
        "connect": "connections_per_second",
        "resumed_connect": "connections_per_second",
        "reqresp": "requests_per_second",
        "zero_rtt_reqresp": "requests_per_second",
        "stream_churn": "streams_per_second",
        "close_reset_cleanup": "streams_per_second",
        "small_payload_pps": "messages_per_second",
        "datagram": "datagrams_per_second",
    }[scenario]


def _strict_observation(
    *,
    mode: str,
    source: NativeSessionObservationSource,
    spec: Any,
    cell: Mapping[str, Any],
    pair: Mapping[str, Any],
    topology: Any,
    lane_cgroups: tuple[Path, Path],
    path: Any,
    coordinator_affinity: tuple[int, ...],
    diagnostic: bool,
) -> dict[str, Any]:
    scenario = str(cell["scenario"])
    if scenario in {IDLE_SCENARIO, "loss_recovery"}:
        raise InvalidConfigurationError(
            "strict numeric parity cannot execute a classified invalid cell"
        )
    measurement_ns = (
        2_000_000_000
        if scenario == "close_reset_cleanup"
        else PARITY_MEASUREMENT_NS
    )
    request_id = domain_hash(
        "legacy-v2-parity-observation",
        canonical_bytes({"pair_id": pair["pair_id"], "mode": mode}),
    )
    request = {
        "request_id": request_id,
        "phase": "legacy_v2_parity",
        "duration_ms": measurement_ns // 1_000_000,
        "scenario": scenario,
        "server": str(cell["server"]),
        "backend": str(cell["backend"]),
        "trace_seed": str(pair["pair_id"]),
    }
    started = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    try:
        sample = source._lane_trial(
            request,
            reference_client=str(cell["server"]),
            lane=int(pair["lane"]),
            topology=topology,
            lane_cgroups=lane_cgroups,
            path=path,
            coordinator_affinity=coordinator_affinity,
            barrier=None,
            shared_epoch=None,
            external_thermal_provider=diagnostic,
            construct_sample=True,
            allow_client_headroom_failure=diagnostic,
            allow_resolution_limited=True,
        )
    except HardwareUnqualifiedError:
        raise
    except Exception as exc:
        detail = str(exc)
        return {
            "status": "failed",
            "value_decimal": None,
            "metric": None,
            "settings": {},
            "detail": detail,
            "measurement_ns": measurement_ns,
            "wall_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) - started,
        }
    treatment = sample.get("treatment", {})
    negotiated = sample.get("negotiated", {})
    valid = all(
        (
            treatment.get("scenario") == scenario,
            treatment.get("server_backend") == str(cell["backend"]),
            treatment.get("reference_client_backend")
            == str(spec.reference_client_backend),
            treatment.get("path_profile") == "loopback",
            treatment.get("trace_seed") == str(pair["pair_id"]),
            negotiated.get("settings_match") is True,
            sample.get("completion_status") == "valid",
            not sample.get("validity_reasons"),
        )
    )
    metric = sample.get("metric", {})
    try:
        value = Decimal(str(metric["derived_decimal"]))
        if not value.is_finite() or value <= 0:
            raise ValueError("strict metric is not finite and positive")
        numerator = int(metric["numerator"])
    except (KeyError, TypeError, ValueError, ArithmeticError) as exc:
        valid = False
        value = None
        detail = str(exc)
    else:
        resolution_limited = (
            scenario
            in {
                "small_payload_pps",
                "datagram",
                "reqresp",
                "stream_churn",
                "close_reset_cleanup",
                "connect",
                "resumed_connect",
                "zero_rtt_reqresp",
            }
            and numerator < 400
        )
        detail = (
            "resolution_limited_retained_for_20_pair_parity"
            if valid and resolution_limited
            else ""
            if valid
            else "strict effective settings differ or sample is invalid"
        )
    return {
        "status": "complete" if valid else "invalid",
        "value_decimal": None if value is None else normalize_decimal(value),
        "metric": (
            _legacy_metric_name(scenario)
            if mode == "legacy"
            else metric.get("name")
        ),
        "settings": _expected_settings(spec, cell) if valid else {},
        "detail": detail,
        "measurement_ns": measurement_ns,
        "wall_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) - started,
    }


def _legacy_observation(
    *,
    root: Path,
    profile: Path,
    bin_dir: Path,
    source: NativeSessionObservationSource,
    spec: Any,
    cell: Mapping[str, Any],
    pair: Mapping[str, Any],
    topology: Any,
    lane_cgroups: tuple[Path, Path],
    path: Any,
    coordinator_affinity: tuple[int, ...],
    diagnostic: bool,
    out_dir: Path,
) -> dict[str, Any]:
    if str(cell["scenario"]) in {IDLE_SCENARIO, "loss_recovery"}:
        return _legacy_invalid_observation(
            root=root,
            bin_dir=bin_dir,
            spec=spec,
            cell=cell,
            pair=pair,
            topology=topology,
            out_dir=out_dir,
        )
    _assert_legacy_translation(profile=profile, spec=spec, cell=cell)
    return _strict_observation(
        mode="legacy",
        source=source,
        spec=spec,
        cell=cell,
        pair=pair,
        topology=topology,
        lane_cgroups=lane_cgroups,
        path=path,
        coordinator_affinity=coordinator_affinity,
        diagnostic=diagnostic,
    )


def _v2_observation(
    *,
    source: NativeSessionObservationSource,
    spec: Any,
    cell: Mapping[str, Any],
    pair: Mapping[str, Any],
    topology: Any,
    lane_cgroups: tuple[Path, Path],
    path: Any,
    coordinator_affinity: tuple[int, ...],
    diagnostic: bool,
) -> dict[str, Any]:
    scenario = str(cell["scenario"])
    if scenario == IDLE_SCENARIO:
        return {
            "status": "invalid",
            "value_decimal": None,
            "metric": None,
            "settings": _expected_settings(spec, cell),
            "detail": "replaced_by_memory_curve",
            "measurement_ns": 0,
            "wall_ns": 0,
        }
    if scenario == "loss_recovery":
        return {
            "status": "invalid",
            "value_decimal": None,
            "metric": None,
            "settings": _expected_settings(spec, cell),
            "detail": "legacy_periodic_loss_model_rejected",
            "measurement_ns": 0,
            "wall_ns": 0,
        }
    return _strict_observation(
        mode="v2",
        source=source,
        spec=spec,
        cell=cell,
        pair=pair,
        topology=topology,
        lane_cgroups=lane_cgroups,
        path=path,
        coordinator_affinity=coordinator_affinity,
        diagnostic=diagnostic,
    )


def _record(
    state: sqlite3.Connection,
    lock: threading.Lock,
    pair_id: str,
    mode: str,
    observation: Mapping[str, Any],
) -> None:
    with lock:
        state.execute(
            """
            INSERT INTO observation(
              pair_id,mode,status,value_decimal,metric,settings_json,detail,
              measurement_ns,wall_ns
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                pair_id,
                mode,
                observation["status"],
                observation["value_decimal"],
                observation["metric"],
                canonical_bytes(observation["settings"]).decode(),
                observation["detail"],
                int(observation["measurement_ns"]),
                int(observation["wall_ns"]),
            ),
        )
        state.commit()


def _analyze(
    *,
    plan: Mapping[str, Any],
    rows: Sequence[sqlite3.Row],
    wall_ns: int,
    host_stability_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    observations = {
        (str(row["pair_id"]), str(row["mode"])): row for row in rows
    }
    cell_results = []
    parity_passed = True
    completed_pairs = 0
    useful_ns = 0
    for cell in plan["cells"]:
        numeric = cell["classification"] == "numeric_parity"
        logs = []
        reasons = []
        resolution_limited_pairs = 0
        for pair in cell["pairs"]:
            legacy = observations.get((pair["pair_id"], "legacy"))
            v2 = observations.get((pair["pair_id"], "v2"))
            if legacy is None or v2 is None:
                reasons.append(f"missing_pair:{pair['block']}")
                continue
            completed_pairs += 1
            if cell["classification"] == "legacy_invalid_replaced_by_memory_curve":
                if (
                    str(legacy["status"]) != "invalid"
                    or str(legacy["detail"])
                    != "requires_duration_mode_adapter_api"
                    or str(v2["status"]) != "invalid"
                    or str(v2["detail"]) != "replaced_by_memory_curve"
                ):
                    reasons.append(f"idle_not_rejected:{pair['block']}")
                continue
            if cell["classification"] == "legacy_unsynchronized_loss_model":
                if (
                    str(legacy["status"]) != "invalid"
                    or str(legacy["detail"])
                    != "legacy_periodic_loss_model_is_unsynchronized"
                    or str(v2["status"]) != "invalid"
                    or str(v2["detail"])
                    != "legacy_periodic_loss_model_rejected"
                ):
                    reasons.append(f"legacy_loss_model_not_rejected:{pair['block']}")
                else:
                    useful_ns += int(legacy["measurement_ns"])
                continue
            if str(legacy["status"]) != "complete" or str(v2["status"]) != "complete":
                reasons.append(f"status:{pair['block']}")
                continue
            if (
                str(legacy["detail"])
                == "resolution_limited_retained_for_20_pair_parity"
                or str(v2["detail"])
                == "resolution_limited_retained_for_20_pair_parity"
            ):
                resolution_limited_pairs += 1
            if str(legacy["settings_json"]) != str(v2["settings_json"]):
                reasons.append(f"settings:{pair['block']}")
                continue
            legacy_family = _metric_family(
                str(cell["scenario"]), "legacy", str(legacy["metric"])
            )
            v2_family = _metric_family(
                str(cell["scenario"]), "v2", str(v2["metric"])
            )
            if legacy_family is None or legacy_family != v2_family:
                reasons.append(f"metric_family:{pair['block']}")
                continue
            try:
                legacy_value = float(str(legacy["value_decimal"]))
                v2_value = float(str(v2["value_decimal"]))
                if (
                    not math.isfinite(legacy_value)
                    or not math.isfinite(v2_value)
                    or legacy_value <= 0
                    or v2_value <= 0
                ):
                    raise ValueError("nonpositive or nonfinite metric")
                logs.append(math.log(v2_value / legacy_value))
            except (TypeError, ValueError, ZeroDivisionError):
                reasons.append(f"metric:{pair['block']}")
            else:
                useful_ns += int(legacy["measurement_ns"]) + int(v2["measurement_ns"])
        lower = upper = None
        if numeric and len(logs) == BLOCKS:
            mean = sum(logs) / BLOCKS
            variance = sum((value - mean) ** 2 for value in logs) / (BLOCKS - 1)
            half = T90_DF19 * math.sqrt(variance / BLOCKS)
            lower, upper = math.exp(mean - half), math.exp(mean + half)
            if lower < NUMERIC_LOWER or upper > NUMERIC_UPPER:
                reasons.append("ratio_interval_outside_0.97_1.03")
        elif numeric:
            reasons.append(f"complete_numeric_pairs:{len(logs)}")
        passed = not reasons
        parity_passed &= passed
        cell_results.append(
            {
                "server": cell["server"],
                "backend": cell["backend"],
                "scenario": cell["scenario"],
                "classification": cell["classification"],
                "passed": passed,
                "reasons": sorted(set(reasons)),
                "complete_pairs": len(logs) if numeric else BLOCKS - len(reasons),
                "resolution_limited_pairs": resolution_limited_pairs,
                "ratio_interval_90": (
                    None
                    if lower is None or upper is None
                    else [
                        normalize_decimal(Decimal(str(lower))),
                        normalize_decimal(Decimal(str(upper))),
                    ]
                ),
            }
        )
    diagnostic = plan["diagnostic_authorization"] is not None
    plan_complete = completed_pairs == int(plan["planned_pairs"])
    milestone_passed = (
        not diagnostic
        and plan_complete
        and parity_passed
        and wall_ns <= MILESTONE_A_NS
        and useful_ns * 4 >= wall_ns * int(plan["lanes"]) * 3
    )
    return {
        "schema_version": SCHEMA,
        "status": (
            "diagnostic_complete_nonpublication"
            if diagnostic and plan_complete and parity_passed
            else "diagnostic_failed_nonpublication"
            if diagnostic
            else "qualified"
            if parity_passed and milestone_passed
            else "not_qualified"
        ),
        "publication_qualified": False,
        "watermark": WATERMARK if diagnostic else None,
        "plan_hash": hashlib.sha256(canonical_bytes(plan)).hexdigest(),
        "planned_cells": int(plan["planned_cells"]),
        "planned_pairs": int(plan["planned_pairs"]),
        "completed_pairs": completed_pairs,
        "parity_passed": parity_passed,
        "milestone_a": {
            "passed": milestone_passed,
            "wall_ns": wall_ns,
            "limit_ns": MILESTONE_A_NS,
            "useful_measurement_ns": useful_ns,
            "useful_measurement_fraction": normalize_decimal(
                Decimal(useful_ns)
                / Decimal(max(1, wall_ns * int(plan["lanes"])))
            ),
        },
        "diagnostic_authorization": plan["diagnostic_authorization"],
        "host_stability_evidence": (
            None
            if host_stability_evidence is None
            else dict(host_stability_evidence)
        ),
        "cells": cell_results,
    }


def run_legacy_v2_parity(
    *,
    root: Path,
    profile: Path,
    out_dir: Path,
    bin_dir: Path,
    qualification_profile: Path,
    qualification_run_dir: Path,
    qualification_store: Path,
    seed_text: str | None,
    diagnostic_unqualified_host: bool,
) -> ParityExecution:
    if diagnostic_unqualified_host:
        raise InvalidConfigurationError(
            "full unqualified-host parity is disabled because it cannot satisfy "
            "Milestone A; use a bounded targeted diagnostic instead"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    lock_file = (out_dir / "run.lock").open("a+b")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise InvalidConfigurationError("legacy parity run is already active") from exc
    spec = load_experiment_spec(profile)
    manifest = collect_manifest(root, spec, bin_dir=bin_dir)
    if not bool(manifest.source["clean"]):
        raise IdentityMismatchError("legacy parity requires a clean source identity")
    existing_plan_path = out_dir / "plan.json"
    existing_plan = (
        loads_strict(existing_plan_path.read_bytes())
        if existing_plan_path.exists()
        else None
    )
    seed = _seed_bytes(
        str(existing_plan["seed"])
        if seed_text is None and isinstance(existing_plan, Mapping)
        else seed_text
    )
    amd_context = None
    qualification_spec = load_experiment_spec(qualification_profile)
    qualification_manifest = collect_manifest(
        root, qualification_spec, bin_dir=bin_dir
    )
    stored = QualificationArtifactStore(qualification_store).load_optional(
        "lane-interference",
        build_qualification_identity(
            "lane-interference", qualification_spec, qualification_manifest
        ),
    )
    if stored is None or not stored.decision.qualified:
        raise InvalidConfigurationError(
            "qualified parity requires exact two-lane qualification"
        )
    lanes = int(_qualification_max_lanes(stored.decision) or 0)
    if lanes != 2:
        raise InvalidConfigurationError(
            "qualified parity requires exactly two execution lanes"
        )
    with Journal(qualification_run_dir) as qualification_journal:
        campaign = qualification_journal.connection.execute(
            "SELECT campaign_id FROM campaign"
        ).fetchone()
        if campaign is None:
            raise IdentityMismatchError(
                "qualification journal has no campaign identity"
            )
        amd_context = _load_host_stability_context(
            qualification_journal,
            str(campaign["campaign_id"]),
            qualification_spec,
            qualification_manifest,
        )
    plan = build_plan(
        spec=spec,
        manifest=manifest,
        seed=seed,
        lanes=lanes,
        diagnostic_authorization=None,
    )
    plan_content = canonical_bytes(plan) + b"\n"
    if existing_plan is None:
        _write_new(existing_plan_path, plan_content)
    elif canonical_bytes(existing_plan) != canonical_bytes(plan):
        raise IdentityMismatchError("legacy parity plan identity differs")
    plan_hash = hashlib.sha256(canonical_bytes(plan)).hexdigest()
    state = _open_state(out_dir / "journal.sqlite3", plan_hash)
    state.row_factory = sqlite3.Row
    started_row = state.execute(
        "SELECT value FROM metadata WHERE key='started_raw_ns'"
    ).fetchone()
    if started_row is None:
        started_raw_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        state.execute(
            "INSERT INTO metadata(key,value) VALUES('started_raw_ns',?)",
            (str(started_raw_ns),),
        )
        state.commit()
    else:
        started_raw_ns = int(started_row[0])
    present = {
        (str(row[0]), str(row[1]))
        for row in state.execute("SELECT pair_id,mode FROM observation")
    }
    source = NativeSessionObservationSource(
        root=root,
        run_dir=out_dir,
        campaign_id=domain_hash("legacy-v2-parity-campaign", bytes.fromhex(plan_hash)),
        spec=spec,
        manifest=manifest,
        amd_context=amd_context,
    )
    write_lock = threading.Lock()
    tasks_by_lane: list[list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = [
        [] for _ in range(lanes)
    ]
    for cell in plan["cells"]:
        for pair in cell["pairs"]:
            tasks_by_lane[int(pair["lane"])].append((cell, pair))
    for lane_tasks in tasks_by_lane:
        lane_tasks.sort(key=lambda item: int(item[1]["execution_ordinal"]))
    monitor_active = False
    host_stability_evidence = None
    try:
        if amd_context is not None:
            source.start_host_stability()
            monitor_active = True
        with source._lane_resources(lanes) as (
            topologies,
            lane_cgroups,
            paths,
            coordinator_affinity,
        ):
            def execute_lane(lane: int) -> None:
                topology = topologies[lane]
                for cell, pair in tasks_by_lane[lane]:
                    order = (
                        ("legacy", "v2")
                        if pair["order"] == "legacy_v2"
                        else ("v2", "legacy")
                    )
                    for mode in order:
                        key = (str(pair["pair_id"]), mode)
                        if key in present:
                            continue
                        if mode == "legacy":
                            observation = _legacy_observation(
                                root=root,
                                profile=profile,
                                bin_dir=bin_dir,
                                source=source,
                                spec=spec,
                                cell=cell,
                                pair=pair,
                                topology=topology,
                                lane_cgroups=lane_cgroups[lane],
                                path=paths[lane],
                                coordinator_affinity=coordinator_affinity,
                                diagnostic=diagnostic_unqualified_host,
                                out_dir=out_dir / "legacy" / str(pair["pair_id"]),
                            )
                        else:
                            observation = _v2_observation(
                                source=source,
                                spec=spec,
                                cell=cell,
                                pair=pair,
                                topology=topology,
                                lane_cgroups=lane_cgroups[lane],
                                path=paths[lane],
                                coordinator_affinity=coordinator_affinity,
                                diagnostic=diagnostic_unqualified_host,
                            )
                        _record(
                            state,
                            write_lock,
                            str(pair["pair_id"]),
                            mode,
                            observation,
                        )

            with ThreadPoolExecutor(max_workers=lanes) as executor:
                futures = [executor.submit(execute_lane, lane) for lane in range(lanes)]
                for future in futures:
                    future.result()
        if monitor_active:
            host_stability_evidence = source.finish_host_stability()
            monitor_active = False
    finally:
        if monitor_active:
            source.abort_host_stability()
    rows = list(
        state.execute(
            """
            SELECT pair_id,mode,status,value_decimal,metric,settings_json,detail,
                   measurement_ns,wall_ns
            FROM observation ORDER BY pair_id,mode
            """
        )
    )
    wall_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) - started_raw_ns
    artifact = _analyze(
        plan=plan,
        rows=rows,
        wall_ns=wall_ns,
        host_stability_evidence=host_stability_evidence,
    )
    content = canonical_bytes(artifact) + b"\n"
    digest = hashlib.sha256(content).hexdigest()
    artifact_path = out_dir / "artifacts" / f"{digest}.json"
    if artifact_path.exists():
        if artifact_path.read_bytes() != content:
            raise IdentityMismatchError("legacy parity artifact path collision")
    else:
        _write_new(artifact_path, content)
    state.close()
    return ParityExecution(artifact=artifact, artifact_path=artifact_path)
