#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import random
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from quicperf_stats import RowStats, Sample, StatsConfig, format_float, metric_higher_is_better, row_stats, scenario_metric_name


DURATION_SCENARIOS = {
    "download",
    "upload",
    "multistream_download",
    "multistream_upload",
    "bidi",
    "loss_recovery",
    "flow_control",
    "small_payload_pps",
    "datagram",
    "reqresp",
    "stream_churn",
    "close_reset_cleanup",
    "zero_rtt_reqresp",
}
COUNT_SCENARIOS = {"connect", "resumed_connect", "idle_footprint"}
BYTE_SCENARIOS = {
    "download",
    "upload",
    "multistream_download",
    "multistream_upload",
    "bidi",
    "loss_recovery",
    "flow_control",
}
OPERATION_SCENARIOS = {"datagram", "small_payload_pps", "reqresp", "stream_churn", "zero_rtt_reqresp", "close_reset_cleanup"}

DEFAULT_PUBLICATION_SAMPLES = 20
DEFAULT_PUBLICATION_WARMUP = 1
DEFAULT_PUBLICATION_BLOCKS = 5
DEFAULT_LOOPBACK_DURATION_MS = 2000
DEFAULT_IMPAIRED_DURATION_MS = 5000
DEFAULT_MAX_CLIENT_THREADS = 16
DEFAULT_SCOUT_GRID = (1, 2, 4, 8, 16)
DEFAULT_SCOUT_SAMPLES = 3
DEFAULT_SCOUT_LOOPBACK_DURATION_MS = 1000
DEFAULT_SCOUT_IMPAIRED_DURATION_MS = 2000
DEFAULT_IDLE_HOLD_MS = 5000
DEFAULT_COUNT_PUBLICATION_CONNECTION_CAP = 128
SCOUT_CACHE_VERSION = 1
DEFAULT_SCOUT_CACHE_RELATIVE = Path("profiles/fixed-design/default-scout")
SCOUT_CACHE_REQUIRED_FILES = ("benchmark-plan.tsv", "saturation-scout.tsv")
SCOUT_CACHE_OPTIONAL_FILES = ("scout-samples.tsv", "scout-environment.txt")
SCOUT_CACHE_METADATA = "scout-cache-metadata.json"
BENCHMARK_FINGERPRINT_PATTERNS = (
    "CMakeLists.txt",
    "depofiles/*.DepoFile",
    "perf.cpp",
    "perf*.h",
    "rust-packet-ffi/Cargo.lock",
    "rust-packet-ffi/Cargo.toml",
    "rust-packet-ffi/src/**/*.rs",
    "tools/quicperf_fixed_design.py",
    "tools/quicperf_stats.py",
    "tools/run-adaptive-publication-suite.py",
    "tools/run-benchmarks.sh",
    "tools/run-fixed-publication-suite.py",
    "tools/run-saturation-scout.py",
    "zig-packet-ffi/build.zig.zon",
    "zig-packet-ffi/src/**/*.zig",
)

PLAN_FIELDS = [
    "binary",
    "scenario",
    "network",
    "path_profile",
    "status",
    "reason",
    "client_threads",
    "mode",
    "duration_ms",
    "work_units",
    "samples",
    "warmup",
    "block_count",
    "target_bytes",
    "target_operations",
    "target_connections",
    "idle_hold_ms",
    "timeout_sec",
    "selected_threads",
    "best_threads",
]


@dataclass(frozen=True)
class PlanRow:
    binary: str
    scenario: str
    network: str
    path_profile: str
    client_threads: int
    mode: str
    duration_ms: int
    work_units: int
    samples: int
    warmup: int
    block_count: int
    target_bytes: int = 0
    target_operations: int = 0
    target_connections: int = 0
    idle_hold_ms: int = DEFAULT_IDLE_HOLD_MS
    timeout_sec: int = 0
    status: str = "ok"
    reason: str = ""
    selected_threads: int = 0
    best_threads: int = 0

    def validate(self) -> None:
        if self.status != "ok":
            return
        if self.client_threads <= 0:
            raise ValueError(f"{self.binary}/{self.scenario}: client_threads must be positive")
        if self.client_threads > DEFAULT_MAX_CLIENT_THREADS:
            raise ValueError(
                f"{self.binary}/{self.scenario}: client_threads {self.client_threads} exceeds max {DEFAULT_MAX_CLIENT_THREADS}"
            )
        if self.mode not in {"duration", "work"}:
            raise ValueError(f"{self.binary}/{self.scenario}: mode must be duration or work")
        if self.samples <= 0:
            raise ValueError(f"{self.binary}/{self.scenario}: samples must be positive")
        if self.block_count <= 0:
            raise ValueError(f"{self.binary}/{self.scenario}: block_count must be positive")
        if self.samples % self.block_count != 0:
            raise ValueError(f"{self.binary}/{self.scenario}: samples must divide evenly by block_count")
        if self.mode == "duration" and self.duration_ms <= 0:
            raise ValueError(f"{self.binary}/{self.scenario}: duration mode requires duration_ms")

    @property
    def samples_per_block(self) -> int:
        return max(1, self.samples // max(1, self.block_count))

    @property
    def group(self) -> tuple[str, str, str, str]:
        return (self.binary, self.scenario, self.network, self.path_profile)


@dataclass(frozen=True)
class ScoutPoint:
    binary: str
    scenario: str
    network: str
    path_profile: str
    threads: int
    status: str
    reason: str
    metric: str
    median: float
    samples: int
    out_dir: str = ""
    run_order: int = 0


@dataclass(frozen=True)
class ScoutSelection:
    status: str
    selected_threads: int
    best_threads: int
    reason: str


@dataclass(frozen=True)
class ScheduledRun:
    row: PlanRow
    block_index: int
    repeat: int
    warmup: int
    order: int


def split_words(value: str) -> list[str]:
    return [item for item in value.split() if item]


def unique_preserve(items: Iterable[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_scout_cache_dir(root: Path) -> Path:
    return root / DEFAULT_SCOUT_CACHE_RELATIVE


def scout_cache_scope(
    *,
    binaries: Iterable[str],
    scenarios: Iterable[str],
    networks: Iterable[str],
    path_profiles: Iterable[str],
    grid: Iterable[int],
    samples: int,
    loopback_duration_ms: int,
    impaired_duration_ms: int,
    congestion_profile: str = "",
) -> dict[str, object]:
    return {
        "binaries": list(binaries),
        "scenarios": list(scenarios),
        "networks": list(networks),
        "path_profiles": list(path_profiles),
        "grid": [int(item) for item in grid],
        "samples": int(samples),
        "loopback_duration_ms": int(loopback_duration_ms),
        "impaired_duration_ms": int(impaired_duration_ms),
        "congestion_profile": congestion_profile,
    }


def _fingerprint_files(root: Path) -> list[Path]:
    files: list[Path] = []
    seen = set()
    for pattern in BENCHMARK_FINGERPRINT_PATTERNS:
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if rel in seen:
                continue
            seen.add(rel)
            files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def benchmark_fingerprint(root: Path, scope: dict[str, object]) -> tuple[str, list[dict[str, str]]]:
    file_records: list[dict[str, str]] = []
    digest = hashlib.sha256()
    digest.update(f"quicperf-scout-cache-v{SCOUT_CACHE_VERSION}\n".encode())
    digest.update(json.dumps(scope, sort_keys=True, separators=(",", ":")).encode())
    digest.update(b"\n")
    for path in _fingerprint_files(root):
        rel = path.relative_to(root).as_posix()
        content = path.read_bytes()
        file_hash = hashlib.sha256(content).hexdigest()
        file_records.append({"path": rel, "sha256": file_hash})
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(file_hash.encode())
        digest.update(b"\n")
    return digest.hexdigest(), file_records


def load_scout_cache_metadata(cache_dir: Path) -> dict[str, object] | None:
    path = cache_dir / SCOUT_CACHE_METADATA
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def validate_scout_cache(cache_dir: Path, fingerprint: str, scope: dict[str, object]) -> tuple[bool, str]:
    metadata = load_scout_cache_metadata(cache_dir)
    if metadata is None:
        return False, "missing_metadata"
    if metadata.get("cache_version") != SCOUT_CACHE_VERSION:
        return False, "cache_version_changed"
    if metadata.get("fingerprint") != fingerprint:
        return False, "fingerprint_changed"
    if metadata.get("scope") != scope:
        return False, "scope_changed"
    for name in SCOUT_CACHE_REQUIRED_FILES:
        if not (cache_dir / name).is_file():
            return False, f"missing_{name}"
    try:
        rows = load_plan(cache_dir / "benchmark-plan.tsv")
    except Exception as exc:
        return False, f"invalid_plan:{exc}"
    if any(row.status == "failed" for row in rows):
        return False, "failed_plan_rows"
    return True, "ok"


def write_scout_cache(
    cache_dir: Path,
    scout_dir: Path,
    *,
    fingerprint: str,
    scope: dict[str, object],
    source_run: str,
    file_records: list[dict[str, str]],
) -> None:
    for name in SCOUT_CACHE_REQUIRED_FILES:
        if not (scout_dir / name).is_file():
            raise FileNotFoundError(scout_dir / name)
    rows = load_plan(scout_dir / "benchmark-plan.tsv")
    failed = [row for row in rows if row.status == "failed"]
    if failed:
        first = failed[0]
        raise ValueError(f"cannot cache failed scout plan row {first.binary}/{first.scenario}/{first.network}")

    cache_dir.mkdir(parents=True, exist_ok=True)
    for name in (*SCOUT_CACHE_REQUIRED_FILES, *SCOUT_CACHE_OPTIONAL_FILES):
        src = scout_dir / name
        if src.exists():
            shutil.copyfile(src, cache_dir / name)
    metadata = {
        "cache_version": SCOUT_CACHE_VERSION,
        "created_utc": utc_iso(),
        "source_run": source_run,
        "fingerprint": fingerprint,
        "scope": scope,
        "fingerprint_files": file_records,
    }
    (cache_dir / SCOUT_CACHE_METADATA).write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def materialize_scout_cache(cache_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in (*SCOUT_CACHE_REQUIRED_FILES, *SCOUT_CACHE_OPTIONAL_FILES, SCOUT_CACHE_METADATA):
        src = cache_dir / name
        if src.exists():
            shutil.copyfile(src, out_dir / name)


def write_environment_file(
    root: Path,
    path: Path,
    *,
    label: str,
    run_id: str,
    commit: str,
    env_sig: str,
    machine_sig: str,
) -> None:
    prefix = f"quicperf_{label}_environment"
    with path.open("w", encoding="utf-8") as handle:
        handle.write(f"{prefix} date_utc={utc_iso()}\n")
        handle.write(f"{prefix} run_id={run_id}\n")
        handle.write(f"{prefix} git_commit={commit}\n")
        handle.write(f"{prefix} env_hash={env_sig} machine_hash={machine_sig}\n")
        handle.write(f"{prefix} variables\n")
        for key, value in sorted(os.environ.items()):
            if key.startswith("QUICPERF_"):
                handle.write(f"{key}={value}\n")
        for command in (["git", "status", "--short"], ["git", "rev-parse", "HEAD"]):
            completed = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
            handle.write(f"{prefix} command={' '.join(command)}\n")
            handle.write(completed.stdout)


def scenario_mode(scenario: str) -> str:
    if scenario in DURATION_SCENARIOS:
        return "duration"
    return "work"


def default_duration_ms(scenario: str, path_profile: str) -> int:
    if path_profile != "loopback" or scenario == "loss_recovery":
        return DEFAULT_IMPAIRED_DURATION_MS
    return DEFAULT_LOOPBACK_DURATION_MS


def default_timeout_sec(row: PlanRow) -> int:
    if row.timeout_sec > 0:
        return row.timeout_sec
    if row.mode == "duration":
        return max(15, int(math.ceil((row.duration_ms / 1000.0) * 4.0 + 10.0)))
    if row.scenario == "idle_footprint":
        return max(15, int(math.ceil((row.idle_hold_ms / 1000.0) * 2.0 + 10.0)))
    return 180


def target_env(row: PlanRow) -> dict[str, str]:
    byte_units = row.target_bytes or row.work_units
    operation_units = row.target_operations or row.work_units
    env = {
        "QUICPERF_MEASURE_MODE": row.mode,
        "QUICPERF_TARGET_DURATION_MS": str(row.duration_ms),
        "QUICPERF_TARGET_WARMUP_MS": "0",
        "QUICPERF_TARGET_OPERATIONS": str(operation_units),
        "QUICPERF_TARGET_BYTES": str(byte_units),
        "QUICPERF_IDLE_HOLD_MS": str(row.idle_hold_ms),
    }
    connection_units = row.target_connections or row.work_units
    if connection_units > 0:
        env["QUICPERF_TARGET_CONNECTIONS"] = str(connection_units)
    if byte_units > 0 and (row.target_bytes or row.scenario in BYTE_SCENARIOS):
        env[scenario_bytes_env(row.scenario)] = str(byte_units)
    if operation_units > 0 and (row.target_operations or row.scenario in OPERATION_SCENARIOS):
        env["QUICPERF_SCENARIO_OPERATIONS"] = str(operation_units)
    if row.target_connections and row.scenario in {"connect", "resumed_connect", "idle_footprint"}:
        env["QUICPERF_TARGET_CONNECTIONS"] = str(row.target_connections)
        multiplier = 2 if row.scenario in {"resumed_connect", "zero_rtt_reqresp"} else 1
        env["QUICPERF_SERVER_CONNECTIONS"] = str(row.client_threads * row.target_connections * multiplier)
    return env


def scenario_bytes_env(scenario: str) -> str:
    if scenario == "multistream_download":
        return "QUICPERF_MULTISTREAM_DOWNLOAD_TEST_BYTES"
    if scenario == "multistream_upload":
        return "QUICPERF_MULTISTREAM_UPLOAD_TEST_BYTES"
    if scenario == "bidi":
        return "QUICPERF_BIDI_TEST_BYTES"
    if scenario == "flow_control":
        return "QUICPERF_FLOW_CONTROL_TEST_BYTES"
    if scenario == "loss_recovery":
        return "QUICPERF_LOSS_RECOVERY_TEST_BYTES"
    return "QUICPERF_TEST_BYTES"


def plan_row_from_dict(row: dict[str, str]) -> PlanRow:
    def as_int(name: str, default: int = 0) -> int:
        value = row.get(name, "")
        return int(value) if value not in {"", None} else default

    mode = row.get("mode") or scenario_mode(row["scenario"])
    path_profile = row.get("path_profile", "loopback") or "loopback"
    duration_default = default_duration_ms(row["scenario"], path_profile) if mode == "duration" else 0
    return PlanRow(
        binary=row["binary"],
        scenario=row["scenario"],
        network=row["network"],
        path_profile=path_profile,
        status=row.get("status", "ok") or "ok",
        reason=row.get("reason", ""),
        client_threads=as_int("client_threads", as_int("selected_threads", 0)),
        mode=mode,
        duration_ms=as_int("duration_ms", duration_default),
        work_units=as_int("work_units", 0),
        samples=as_int("samples", DEFAULT_PUBLICATION_SAMPLES),
        warmup=as_int("warmup", DEFAULT_PUBLICATION_WARMUP),
        block_count=as_int("block_count", DEFAULT_PUBLICATION_BLOCKS),
        target_bytes=as_int("target_bytes", 0),
        target_operations=as_int("target_operations", 0),
        target_connections=as_int("target_connections", 0),
        idle_hold_ms=as_int("idle_hold_ms", DEFAULT_IDLE_HOLD_MS),
        timeout_sec=as_int("timeout_sec", 0),
        selected_threads=as_int("selected_threads", 0),
        best_threads=as_int("best_threads", 0),
    )


def load_plan(path: Path) -> list[PlanRow]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = [plan_row_from_dict(row) for row in csv.DictReader(handle, delimiter="\t")]
    for row in rows:
        row.validate()
    return rows


def write_plan(path: Path, rows: Iterable[PlanRow]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=PLAN_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "binary": row.binary,
                "scenario": row.scenario,
                "network": row.network,
                "path_profile": row.path_profile,
                "status": row.status,
                "reason": row.reason,
                "client_threads": row.client_threads or "",
                "mode": row.mode,
                "duration_ms": row.duration_ms or "",
                "work_units": row.work_units or "",
                "samples": row.samples,
                "warmup": row.warmup,
                "block_count": row.block_count,
                "target_bytes": row.target_bytes or "",
                "target_operations": row.target_operations or "",
                "target_connections": row.target_connections or "",
                "idle_hold_ms": row.idle_hold_ms or "",
                "timeout_sec": row.timeout_sec or "",
                "selected_threads": row.selected_threads or row.client_threads or "",
                "best_threads": row.best_threads or "",
            })


def fixed_schedule(rows: list[PlanRow], seed: int) -> list[ScheduledRun]:
    runnable = [row for row in rows if row.status == "ok"]
    for row in runnable:
        row.validate()
    max_blocks = max((row.block_count for row in runnable), default=0)
    rng = random.Random(seed)
    schedule: list[ScheduledRun] = []
    order = 0
    for block_index in range(1, max_blocks + 1):
        block_rows = [row for row in runnable if row.block_count >= block_index]
        network_rank = {"syscall": block_index % 2, "iouring": (block_index + 1) % 2}
        rng.shuffle(block_rows)
        block_rows.sort(key=lambda row: (network_rank.get(row.network, 2), rng.random()))
        for row in block_rows:
            order += 1
            schedule.append(
                ScheduledRun(
                    row=row,
                    block_index=block_index,
                    repeat=row.samples_per_block,
                    warmup=row.warmup if block_index == 1 else 0,
                    order=order,
                )
            )
    return schedule


def select_scout_threads(
    points: list[ScoutPoint],
    *,
    within_best: float = 0.02,
    next_step_improvement: float = 0.02,
) -> ScoutSelection:
    ok = sorted((point for point in points if point.status == "ok" and point.samples > 0 and point.median >= 0.0), key=lambda item: item.threads)
    if not ok:
        failed = next((point for point in points if point.status not in {"ok", "unsupported"}), None)
        unsupported = next((point for point in points if point.status == "unsupported"), None)
        point = failed or unsupported
        if point:
            return ScoutSelection(point.status, 0, 0, point.reason or point.status)
        return ScoutSelection("failed", 0, 0, "no_successful_scout_points")

    metric = ok[0].metric or scenario_metric_name(ok[0].scenario)
    higher_is_better = metric_higher_is_better(metric)
    best = max(ok, key=lambda item: item.median) if higher_is_better else min(ok, key=lambda item: item.median)
    if higher_is_better:
        threshold = best.median * (1.0 - within_best)
        within = lambda value: value >= threshold
        improvement = lambda current, nxt: (nxt / current) - 1.0 if current > 0.0 else (math.inf if nxt > 0.0 else 0.0)
    else:
        threshold = best.median * (1.0 + within_best)
        within = lambda value: value <= threshold
        improvement = lambda current, nxt: (current / nxt) - 1.0 if nxt > 0.0 else (math.inf if current > 0.0 else 0.0)

    fallback = next((point for point in ok if within(point.median)), best)
    for index, point in enumerate(ok):
        if not within(point.median):
            continue
        nxt = ok[index + 1] if index + 1 < len(ok) else None
        if nxt is None or improvement(point.median, nxt.median) < next_step_improvement:
            return ScoutSelection(
                "ok",
                point.threads,
                best.threads,
                f"within_{within_best:.3f}_of_best_next_lt_{next_step_improvement:.3f}",
            )
    return ScoutSelection("ok", fallback.threads, best.threads, f"within_{within_best:.3f}_of_best")


def target_connections_for_duration(
    point: ScoutPoint | None,
    target_duration_ms: int,
    max_total_connections: int = DEFAULT_COUNT_PUBLICATION_CONNECTION_CAP,
) -> int:
    if point is None or point.status != "ok" or point.median <= 0.0 or point.threads <= 0:
        return 1
    total_connections = point.median * (target_duration_ms / 1000.0)
    if max_total_connections > 0:
        total_connections = min(total_connections, float(max_total_connections))
    return max(1, int(math.ceil(total_connections / point.threads)))


def audit_reason_is_noisy(reason: str) -> bool:
    if not reason:
        return False
    noisy_prefixes = (
        "p50_ci_width_",
        "p80_p20_",
        "block_median_ratio_",
        "drift_",
        "outliers_",
        "persistent_",
        "severe_",
    )
    return any(item.startswith(noisy_prefixes) for item in reason.split(";") if item)


def fixed_status(samples: list[Sample], stats: RowStats, required_samples: int) -> tuple[str, str, str, str]:
    bad = [sample for sample in samples if sample.phase != "warmup" and sample.status not in {"", "ok"}]
    if any(sample.status == "unsupported" for sample in bad):
        return "unsupported", "clean", "unsupported", next((sample.reason for sample in bad if sample.reason), "unsupported")
    if bad or stats.status == "failed":
        reason = ";".join(item for item in [stats.reason, *(sample.reason for sample in bad if sample.reason)] if item)
        return "failed", "clean", "failed", reason or "measurement_failed"
    if stats.n < required_samples:
        return "failed", "clean", "failed", f"samples_{stats.n}_lt_{required_samples}"
    if audit_reason_is_noisy(stats.reason):
        return "complete", "noisy", "inconclusive", stats.reason
    if stats.p99_status != "claimable":
        return "complete", "tail_insufficient", "publishable", stats.reason
    return "complete", "clean", "publishable", stats.reason


def row_stats_config(row: PlanRow, bootstrap_iters: int, seed: int) -> StatsConfig:
    return StatsConfig(
        min_blocks=row.block_count,
        min_samples=row.samples,
        max_samples=row.samples,
        bootstrap_iters=bootstrap_iters,
        bootstrap_seed=seed,
        high_variance_min_blocks=row.block_count + 1,
        high_variance_min_samples=row.samples + 1,
        severe_high_variance_min_blocks=row.block_count + 1,
        severe_high_variance_min_samples=row.samples + 1,
    )


def scout_point_from_samples(
    binary: str,
    scenario: str,
    network: str,
    path_profile: str,
    threads: int,
    samples: list[Sample],
    status: str = "",
    reason: str = "",
    out_dir: str = "",
    run_order: int = 0,
) -> ScoutPoint:
    terminal = next(
        (
            sample
            for sample in samples
            if sample.binary == binary
            and sample.scenario == scenario
            and sample.network == network
            and sample.path_profile == path_profile
            and sample.client_threads == threads
            and sample.status not in {"", "ok"}
        ),
        None,
    )
    if terminal:
        terminal_status = "unsupported" if terminal.status == "unsupported" else "failed"
        terminal_reason = terminal.reason or terminal.status
        metric = terminal.metric or scenario_metric_name(scenario)
        return ScoutPoint(
            binary,
            scenario,
            network,
            path_profile,
            threads,
            terminal_status,
            terminal_reason,
            metric,
            0.0,
            0,
            terminal.out_dir,
            run_order,
        )
    measured = [
        sample
        for sample in samples
        if sample.binary == binary
        and sample.scenario == scenario
        and sample.network == network
        and sample.path_profile == path_profile
        and sample.client_threads == threads
        and sample.measured
    ]
    metric = measured[0].metric if measured else scenario_metric_name(scenario)
    if measured:
        stats = row_stats(measured, StatsConfig(min_blocks=1, min_samples=1, bootstrap_iters=200))
        return ScoutPoint(binary, scenario, network, path_profile, threads, "ok", "", metric, stats.median, stats.n, out_dir, run_order)
    terminal_status = "unsupported" if status == "unsupported" else "failed"
    return ScoutPoint(binary, scenario, network, path_profile, threads, terminal_status, reason or status or "no_samples", metric, 0.0, 0, out_dir, run_order)


def format_status_row(row: PlanRow, stats: RowStats, measurement_status: str, audit_status: str, publication_status: str, reason: str) -> dict[str, str]:
    return {
        "binary": row.binary,
        "scenario": row.scenario,
        "network": row.network,
        "path_profile": row.path_profile,
        "client_threads": str(row.client_threads),
        "metric": scenario_metric_name(row.scenario),
        "mode": row.mode,
        "duration_ms": str(row.duration_ms or ""),
        "work_units": str(row.work_units or ""),
        "samples": str(stats.n),
        "blocks": str(stats.blocks),
        "p50": format_float(stats.median),
        "p50_ci95_low": format_float(stats.ci95_low),
        "p50_ci95_high": format_float(stats.ci95_high),
        "p50_ci95_relative_width": format_float(stats.ci95_rel_width),
        "p20": format_float(stats.p20),
        "p80": format_float(stats.p80),
        "p20_p80_ratio": format_float(stats.p20_p80_ratio),
        "p90": format_float(stats.p90),
        "p99": format_float(stats.p99),
        "p99_status": stats.p99_status,
        "block_median_ratio": format_float(stats.block_median_ratio),
        "drift_relative": format_float(stats.drift_rel),
        "outlier_count": str(stats.outlier_count),
        "measurement_status": measurement_status,
        "audit_status": audit_status,
        "publication_status": publication_status,
        "reason": reason,
    }
