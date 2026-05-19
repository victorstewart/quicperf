#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import os
import random
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from quicperf_stats import (
    GroupKey,
    RowKey,
    RowStats,
    Sample,
    SaturationDecision,
    StatsConfig,
    bootstrap_stat_distribution,
    compare_rows,
    format_float,
    group_samples,
    load_samples,
    median,
    quantile,
    row_stats,
    saturation_decision,
    scenario_metric_name,
    write_samples,
)


SIDECAR_EXCLUDED_BINARIES = {"tcpperf"}


@dataclass(frozen=True)
class Target:
    binary: str
    scenario: str
    network: str
    path_profile: str
    threads: int

    @property
    def group(self) -> tuple[str, str, str, str]:
        return (self.binary, self.scenario, self.network, self.path_profile)


@dataclass
class RunnerConfig:
    block_size: int
    min_blocks: int
    min_samples: int
    confirm_blocks: int
    confirm_min_samples: int
    max_samples: int
    bootstrap_iters: int
    warmup: int
    max_threads: int
    max_rounds: int
    random_seed: int
    saturation_tolerance: float
    saturation_min_incremental_improvement: float
    saturation_probability: float
    saturation_sentinels: int
    high_variance_min_blocks: int
    high_variance_min_samples: int
    high_variance_improvement_min: float
    severe_high_variance_min_blocks: int
    severe_high_variance_min_samples: int
    severe_block_median_ratio_max: float
    severe_p20_p80_max: float
    severe_drift_rel_max: float
    severe_outlier_blocks_min: int

    def stats_config(self) -> StatsConfig:
        return StatsConfig(
            min_blocks=self.min_blocks,
            min_samples=self.min_samples,
            confirm_min_samples=self.confirm_min_samples,
            max_samples=self.max_samples,
            bootstrap_iters=self.bootstrap_iters,
            bootstrap_seed=self.random_seed,
            saturation_tolerance=self.saturation_tolerance,
            saturation_min_incremental_improvement=self.saturation_min_incremental_improvement,
            saturation_probability=self.saturation_probability,
            saturation_sentinels=self.saturation_sentinels,
            high_variance_min_blocks=self.high_variance_min_blocks,
            high_variance_min_samples=self.high_variance_min_samples,
            high_variance_improvement_min=self.high_variance_improvement_min,
            severe_high_variance_min_blocks=self.severe_high_variance_min_blocks,
            severe_high_variance_min_samples=self.severe_high_variance_min_samples,
            severe_block_median_ratio_max=self.severe_block_median_ratio_max,
            severe_p20_p80_max=self.severe_p20_p80_max,
            severe_drift_rel_max=self.severe_drift_rel_max,
            severe_outlier_blocks_min=self.severe_outlier_blocks_min,
        )

    def confirm_stats_config(self) -> StatsConfig:
        return StatsConfig(
            min_blocks=max(1, self.confirm_blocks),
            min_samples=self.confirm_min_samples,
            confirm_min_samples=self.confirm_min_samples,
            max_samples=max(self.confirm_min_samples, self.confirm_blocks * self.block_size),
            bootstrap_iters=self.bootstrap_iters,
            bootstrap_seed=self.random_seed + 17,
            p20_p80_max=1.15,
            block_median_ratio_max=1.10,
            drift_rel_max=0.03,
            saturation_tolerance=self.saturation_tolerance,
            saturation_min_incremental_improvement=self.saturation_min_incremental_improvement,
            saturation_probability=self.saturation_probability,
            saturation_sentinels=self.saturation_sentinels,
            high_variance_min_blocks=max(1, self.confirm_blocks),
            high_variance_min_samples=self.confirm_min_samples,
            high_variance_improvement_min=self.high_variance_improvement_min,
            severe_high_variance_min_blocks=self.severe_high_variance_min_blocks,
            severe_high_variance_min_samples=self.severe_high_variance_min_samples,
            severe_block_median_ratio_max=self.severe_block_median_ratio_max,
            severe_p20_p80_max=self.severe_p20_p80_max,
            severe_drift_rel_max=self.severe_drift_rel_max,
            severe_outlier_blocks_min=self.severe_outlier_blocks_min,
        )


@dataclass
class BlockResult:
    target: Target
    phase: str
    block_id: str
    status: str
    reason: str
    out_dir: Path
    returncode: int


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def split_words(value: str) -> list[str]:
    return [item for item in value.split() if item]


def unique_preserve(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def env_int_any(names: tuple[str, ...], default: int) -> int:
    for name in names:
        if name in os.environ:
            return env_int(name, default)
    return default


def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def git_commit(root: Path) -> str:
    try:
        completed = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        return completed.stdout.strip()
    except OSError:
        return ""


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def machine_hash() -> str:
    parts = []
    for command in (["uname", "-a"], ["lscpu"]):
        try:
            completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
            parts.append(completed.stdout)
        except OSError:
            pass
    return hash_text("\n".join(parts))


def env_hash() -> str:
    return hash_text("\n".join(f"{key}={value}" for key, value in sorted(os.environ.items()) if key.startswith("QUICPERF_")))


def discover_binaries(root: Path) -> list[str]:
    configured = os.environ.get("QUICPERF_BINARIES")
    if configured:
        return unique_preserve(split_words(configured))
    bin_dir = Path(os.environ.get("QUICPERF_BIN_DIR", root / "build" / "bin"))
    return sorted(path.name for path in bin_dir.glob("*perf") if os.access(path, os.X_OK))


def load_config() -> RunnerConfig:
    block_size = env_int("QUICPERF_ADAPTIVE_BLOCK_SIZE", 5)
    confirm_blocks = env_int("QUICPERF_ADAPTIVE_CONFIRM_BLOCKS", 2)
    return RunnerConfig(
        block_size=block_size,
        min_blocks=env_int("QUICPERF_ADAPTIVE_MIN_BLOCKS", 4),
        min_samples=env_int("QUICPERF_ADAPTIVE_MIN_SAMPLES", 20),
        confirm_blocks=confirm_blocks,
        confirm_min_samples=env_int("QUICPERF_ADAPTIVE_CONFIRM_SAMPLES", confirm_blocks * block_size),
        max_samples=env_int("QUICPERF_ADAPTIVE_MAX_SAMPLES", 120),
        bootstrap_iters=env_int("QUICPERF_ADAPTIVE_BOOTSTRAP_ITERS", 5000),
        warmup=env_int("QUICPERF_ADAPTIVE_WARMUP", 1),
        max_threads=env_int("QUICPERF_SATURATION_MAX_THREADS", 32),
        max_rounds=env_int("QUICPERF_ADAPTIVE_MAX_ROUNDS", 10000),
        random_seed=env_int_any(("QUICPERF_ADAPTIVE_RANDOM_SEED", "QUICPERF_RANDOM_SEED"), os.getpid()),
        saturation_tolerance=env_float("QUICPERF_SATURATION_TOLERANCE", 0.01),
        saturation_min_incremental_improvement=env_float("QUICPERF_SATURATION_MIN_INCREMENTAL_IMPROVEMENT", 0.01),
        saturation_probability=env_float("QUICPERF_SATURATION_CONFIDENCE", 0.95),
        saturation_sentinels=env_int("QUICPERF_SATURATION_SENTINELS", 1),
        high_variance_min_blocks=env_int("QUICPERF_ADAPTIVE_HIGH_VARIANCE_MIN_BLOCKS", 8),
        high_variance_min_samples=env_int("QUICPERF_ADAPTIVE_HIGH_VARIANCE_MIN_SAMPLES", 40),
        high_variance_improvement_min=env_float("QUICPERF_ADAPTIVE_HIGH_VARIANCE_IMPROVEMENT_MIN", 0.10),
        severe_high_variance_min_blocks=env_int("QUICPERF_ADAPTIVE_SEVERE_HIGH_VARIANCE_MIN_BLOCKS", 6),
        severe_high_variance_min_samples=env_int("QUICPERF_ADAPTIVE_SEVERE_HIGH_VARIANCE_MIN_SAMPLES", 30),
        severe_block_median_ratio_max=env_float("QUICPERF_ADAPTIVE_SEVERE_BLOCK_MEDIAN_RATIO_MAX", 1.25),
        severe_p20_p80_max=env_float("QUICPERF_ADAPTIVE_SEVERE_P20_P80_MAX", 1.50),
        severe_drift_rel_max=env_float("QUICPERF_ADAPTIVE_SEVERE_DRIFT_REL_MAX", 0.08),
        severe_outlier_blocks_min=env_int("QUICPERF_ADAPTIVE_SEVERE_OUTLIER_BLOCKS_MIN", 2),
    )


def unsupported_reason(output: str) -> str:
    match = re.search(r"status=unsupported reason=(\S+)", output)
    return match.group(1) if match else ""


def failure_reason(output: str, returncode: int) -> str:
    match = re.search(r"quicperf_run_result .* status=(client_failed|server_failed|thread_check_failed)(?: reason=(\S+))?(?:\s|$)", output)
    if match:
        return match.group(2) or match.group(1)
    if "quicperf_outlier_gate status=failed" in output:
        return "outlier_gate_failed"
    if returncode != 0:
        return f"exit_{returncode}"
    return ""


def run_block(
    root: Path,
    out_root: Path,
    samples_path: Path,
    target: Target,
    *,
    phase: str,
    round_index: int,
    block_ordinal: int,
    cfg: RunnerConfig,
    publication_id: str,
    commit: str,
    env_sig: str,
    machine_sig: str,
    warmup: int,
) -> BlockResult:
    block_id = f"r{round_index:03d}b{block_ordinal:05d}t{target.threads}"
    out_dir = out_root / "blocks" / f"{block_id}-{target.binary}-{target.scenario}-{target.network}-{target.path_profile}"
    env = os.environ.copy()
    env.update(
        {
            "QUICPERF_BINARIES": target.binary,
            "QUICPERF_SCENARIOS": target.scenario,
            "QUICPERF_NETWORKS": target.network,
            "QUICPERF_PATH_PROFILES": target.path_profile,
            "QUICPERF_CLIENT_THREADS": str(target.threads),
            "QUICPERF_SERVER_CONNECTIONS": str(target.threads),
            "QUICPERF_REPEAT": str(cfg.block_size),
            "QUICPERF_WARMUP": str(warmup),
            "QUICPERF_RANDOMIZE_ORDER": "0",
            "QUICPERF_RANDOM_SEED": str(cfg.random_seed + block_ordinal),
            "QUICPERF_OUT_DIR": str(out_dir),
            "QUICPERF_RUN_LABEL_PREFIX": f"{block_id}-",
            "QUICPERF_SAMPLE_PHASE": phase,
            "QUICPERF_APPEND_SAMPLES_TSV": str(samples_path),
            "QUICPERF_PUBLICATION_ID": publication_id,
            "QUICPERF_ADAPTIVE_ROUND": str(round_index),
            "QUICPERF_ADAPTIVE_BLOCK_ID": block_id,
            "QUICPERF_GIT_COMMIT": commit,
            "QUICPERF_ENV_HASH": env_sig,
            "QUICPERF_MACHINE_HASH": machine_sig,
            "QUICPERF_OUTLIER_GATE_MODE": "off",
        }
    )
    env[f"QUICPERF_{target.scenario.upper()}_CLIENT_THREADS"] = str(target.threads)
    completed = subprocess.run(
        [str(root / "tools" / "run-benchmarks.sh")],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "adaptive-block.stdout").write_text(completed.stdout, encoding="utf-8")
    reason = unsupported_reason(completed.stdout)
    if reason:
        return BlockResult(target, phase, block_id, "unsupported", reason, out_dir, completed.returncode)
    reason = failure_reason(completed.stdout, completed.returncode)
    if reason:
        return BlockResult(target, phase, block_id, "failed", reason, out_dir, completed.returncode)
    return BlockResult(target, phase, block_id, "ok", "", out_dir, completed.returncode)


def samples_for_target(samples: list[Sample], target: Target, phase: str | None = None) -> list[Sample]:
    out = [
        sample for sample in samples
        if sample.binary == target.binary
        and sample.scenario == target.scenario
        and sample.network == target.network
        and sample.path_profile == target.path_profile
        and sample.client_threads == target.threads
        and sample.metric
        and (phase is None or sample.phase == phase)
    ]
    return out


def group_target_key(target: Target) -> tuple[str, str, str, str]:
    return target.binary, target.scenario, target.network, target.path_profile


def target_from_key(key: RowKey) -> Target:
    return Target(key.binary, key.scenario, key.network, key.path_profile, key.client_threads)


def group_metric(samples: list[Sample], group: tuple[str, str, str, str]) -> str:
    for sample in samples:
        if (sample.binary, sample.scenario, sample.network, sample.path_profile) == group and sample.metric:
            return sample.metric
    return scenario_metric_name(group[1])


def group_adapter_features(samples: list[Sample], group: tuple[str, str, str, str]) -> str:
    for sample in samples:
        if (
            (sample.binary, sample.scenario, sample.network, sample.path_profile) == group
            and sample.adapter_features
        ):
            return sample.adapter_features
    return ""


def adapter_feature_value(features: str, name: str) -> str:
    prefix = f"{name}="
    for item in features.split("|"):
        if item.startswith(prefix):
            return item[len(prefix):]
    return ""


def parse_block_target(block_dir: Path, networks: list[str], path_profiles: list[str]) -> tuple[str, Target] | None:
    name = block_dir.name
    if "-" not in name:
        return None
    block_id, rest = name.split("-", 1)
    match = re.match(r"^r\d+b\d+t(\d+)$", block_id)
    if not match:
        return None
    threads = int(match.group(1))
    for path_profile in sorted(path_profiles, key=len, reverse=True):
        path_suffix = f"-{path_profile}"
        if not rest.endswith(path_suffix):
            continue
        without_path = rest[: -len(path_suffix)]
        for network in sorted(networks, key=len, reverse=True):
            network_suffix = f"-{network}"
            if not without_path.endswith(network_suffix):
                continue
            binary_scenario = without_path[: -len(network_suffix)]
            if "-" not in binary_scenario:
                return None
            binary, scenario = binary_scenario.split("-", 1)
            return block_id, Target(binary, scenario, network, path_profile, threads)
    return None


def parse_block_ordinal(block_id: str) -> int:
    match = re.match(r"^r\d+b(\d+)t\d+$", block_id)
    return int(match.group(1)) if match else 0


def parse_block_round(block_id: str) -> int:
    match = re.match(r"^r(\d+)b\d+t\d+$", block_id)
    return int(match.group(1)) if match else 0


def block_terminal_status(stdout: str) -> tuple[str, str]:
    reason = unsupported_reason(stdout)
    if reason:
        return "unsupported", reason
    reason = failure_reason(stdout, 0)
    if reason:
        return reason, reason
    if reason:
        return "failed", reason
    if "Segmentation fault" in stdout:
        return "server_failed", "exit_139"
    return "", ""


def load_block_failures(out_root: Path, networks: list[str], path_profiles: list[str]) -> dict[Target, str]:
    failures: dict[Target, str] = {}
    blocks = out_root / "blocks"
    if not blocks.exists():
        return failures
    for block_dir in blocks.iterdir():
        if not block_dir.is_dir():
            continue
        parsed = parse_block_target(block_dir, networks, path_profiles)
        if not parsed:
            continue
        _block_id, target = parsed
        stdout_path = block_dir / "adaptive-block.stdout"
        if not stdout_path.exists():
            continue
        status, reason = block_terminal_status(stdout_path.read_text(encoding="utf-8", errors="replace"))
        if status and status != "unsupported":
            failures[target] = reason or status
    return failures


def resume_positions(out_root: Path, samples: list[Sample], networks: list[str], path_profiles: list[str]) -> tuple[int, int]:
    max_round = max((sample.round for sample in samples), default=0)
    max_ordinal = max((parse_block_ordinal(sample.block_id) for sample in samples), default=0)
    blocks = out_root / "blocks"
    if blocks.exists():
        for block_dir in blocks.iterdir():
            if not block_dir.is_dir():
                continue
            parsed = parse_block_target(block_dir, networks, path_profiles)
            if not parsed:
                continue
            block_id, _target = parsed
            max_round = max(max_round, parse_block_round(block_id))
            max_ordinal = max(max_ordinal, parse_block_ordinal(block_id))
    return max_round, max_ordinal


def initialize_resume_state(
    *,
    binaries: list[str],
    scenarios: list[str],
    networks: list[str],
    path_profiles: list[str],
    samples: list[Sample],
    block_failures: dict[Target, str],
    cfg: RunnerConfig,
) -> tuple[dict[Target, str], dict[Target, str], dict[tuple[str, str, str, str], str], set[Target]]:
    row_state: dict[Target, str] = {}
    row_reason: dict[Target, str] = {}
    group_state: dict[tuple[str, str, str, str], str] = {}
    active: set[Target] = set()
    samples_by_group: dict[tuple[str, str, str, str], list[Sample]] = defaultdict(list)
    for sample in samples:
        samples_by_group[(sample.binary, sample.scenario, sample.network, sample.path_profile)].append(sample)

    for binary in binaries:
        for scenario in scenarios:
            for network in networks:
                for path_profile in path_profiles:
                    group = (binary, scenario, network, path_profile)
                    group_state[group] = "active"
                    group_samples_list = samples_by_group.get(group, [])
                    terminal_samples = [
                        sample for sample in group_samples_list
                        if sample.status == "unsupported" or sample.status not in ("", "ok")
                    ]
                    matching_block_failures = {target: reason for target, reason in block_failures.items() if target.group == group}
                    if any(sample.status == "unsupported" for sample in terminal_samples):
                        target = Target(binary, scenario, network, path_profile, terminal_samples[0].client_threads or 1)
                        row_state[target] = "unsupported"
                        row_reason[target] = terminal_samples[0].reason or "unsupported"
                        group_state[group] = "unsupported"
                        continue
                    if terminal_samples:
                        target = Target(binary, scenario, network, path_profile, terminal_samples[0].client_threads or 1)
                        row_state[target] = terminal_samples[0].status or "failed"
                        row_reason[target] = terminal_samples[0].reason or terminal_samples[0].status or "failed"
                        group_state[group] = "failed"
                        continue
                    if matching_block_failures:
                        target, reason = sorted(matching_block_failures.items(), key=lambda item: item[0].threads)[0]
                        row_state[target] = "failed"
                        row_reason[target] = reason
                        group_state[group] = "failed"
                        continue

                    grouped_rows = {
                        target_from_key(key): row_samples
                        for key, row_samples in group_samples(group_samples_list).items()
                        if key.binary == binary and key.scenario == scenario and key.network == network and key.path_profile == path_profile
                    }
                    if not grouped_rows:
                        target = Target(binary, scenario, network, path_profile, 1)
                        row_state[target] = "active"
                        active.add(target)
                        continue
                    for target, row_samples in grouped_rows.items():
                        stats = row_stats([sample for sample in row_samples if sample.phase == "discovery"], cfg.stats_config())
                        if stats.status == "ready":
                            row_state[target] = "ready"
                        elif stats.n >= cfg.max_samples:
                            row_state[target] = stats.status if stats.status.startswith("not_ready") else "not_ready_max_samples"
                            row_reason[target] = stats.reason
                        else:
                            row_state[target] = "active"
                            active.add(target)
    return row_state, row_reason, group_state, active


def recompute_discovery_stats(samples: list[Sample], cfg: RunnerConfig) -> dict[Target, RowStats]:
    stats_cfg = cfg.stats_config()
    rows = {}
    for key, row_samples in group_samples([sample for sample in samples if sample.phase == "discovery"]).items():
        rows[target_from_key(key)] = row_stats(row_samples, stats_cfg)
    return rows


def build_group_samples(samples: list[Sample], group: tuple[str, str, str, str], phase: str | None = "discovery") -> dict[int, list[Sample]]:
    by_threads: dict[int, list[Sample]] = defaultdict(list)
    for sample in samples:
        if (sample.binary, sample.scenario, sample.network, sample.path_profile) != group:
            continue
        if phase is not None and sample.phase != phase:
            continue
        if sample.metric:
            by_threads[sample.client_threads].append(sample)
    return dict(by_threads)


def compute_group_decision(
    samples: list[Sample],
    group: tuple[str, str, str, str],
    row_state: dict[Target, str],
    cfg: RunnerConfig,
) -> SaturationDecision:
    sample_map = build_group_samples(samples, group, "discovery")
    stats_map: dict[int, RowStats] = {}
    for threads, thread_samples in sample_map.items():
        stats_map[threads] = row_stats(thread_samples, cfg.stats_config())
    decision = saturation_decision(stats_map, sample_map, cfg.stats_config())
    if decision.decision_status == "ready":
        return decision
    tested = sorted({target.threads for target in row_state if target.group == group})
    if tested and tested[-1] >= cfg.max_threads:
        decision.decision_status = "not_ready"
        decision.edge_status = "edge"
        reason = "max_threads_reached"
        decision.reason = f"{decision.reason};{reason}" if decision.reason else reason
    return decision


def write_row_stats(path: Path, samples: list[Sample], cfg: RunnerConfig) -> dict[tuple[RowKey, str], RowStats]:
    rows: dict[tuple[RowKey, str], RowStats] = {}
    fields = [
        "binary",
        "scenario",
        "network",
        "path_profile",
        "client_threads",
        "metric",
        "phase",
        "samples",
        "blocks",
        "median",
        "p50_ci95_low",
        "p50_ci95_high",
        "p50_ci95_relative_width",
        "p20",
        "p80",
        "p20_p80_ratio",
        "p90",
        "p99",
        "p99_status",
        "mad_relative",
        "block_median_ratio",
        "drift_relative",
        "lag1_autocorr",
        "outlier_count",
        "convergence_status",
        "reason",
    ]
    grouped = group_samples(samples)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=fields)
        writer.writeheader()
        for key in sorted(grouped, key=lambda item: (item.binary, item.scenario, item.network, item.path_profile, item.client_threads, item.metric)):
            for phase in ("discovery", "confirm", "combined"):
                if phase == "combined":
                    phase_samples = [sample for sample in grouped[key] if sample.phase in ("discovery", "confirm")]
                    stats_cfg = cfg.stats_config()
                else:
                    phase_samples = [sample for sample in grouped[key] if sample.phase == phase]
                    stats_cfg = cfg.confirm_stats_config() if phase == "confirm" else cfg.stats_config()
                if not phase_samples:
                    continue
                stats = row_stats(phase_samples, stats_cfg)
                rows[(key, phase)] = stats
                writer.writerow({
                    "binary": key.binary,
                    "scenario": key.scenario,
                    "network": key.network,
                    "path_profile": key.path_profile,
                    "client_threads": key.client_threads,
                    "metric": key.metric,
                    "phase": phase,
                    "samples": stats.n,
                    "blocks": stats.blocks,
                    "median": format_float(stats.median),
                    "p50_ci95_low": format_float(stats.ci95_low),
                    "p50_ci95_high": format_float(stats.ci95_high),
                    "p50_ci95_relative_width": format_float(stats.ci95_rel_width),
                    "p20": format_float(stats.p20),
                    "p80": format_float(stats.p80),
                    "p20_p80_ratio": format_float(stats.p20_p80_ratio),
                    "p90": format_float(stats.p90),
                    "p99": format_float(stats.p99),
                    "p99_status": stats.p99_status,
                    "mad_relative": format_float(stats.mad_rel),
                    "block_median_ratio": format_float(stats.block_median_ratio),
                    "drift_relative": format_float(stats.drift_rel),
                    "lag1_autocorr": format_float(stats.lag1_autocorr),
                    "outlier_count": stats.outlier_count,
                    "convergence_status": stats.status,
                    "reason": stats.reason,
                })
    return rows


def confirm_status(discovery: RowStats | None, confirm: RowStats | None, combined: RowStats | None, scenario: str, cfg: RunnerConfig) -> tuple[str, str]:
    if discovery is None:
        return "not_ready", "missing_discovery_stats"
    if confirm is None:
        return "not_ready", "missing_confirm_stats"
    if combined is None:
        return "not_ready", "missing_combined_stats"
    reasons = []
    if confirm.n < cfg.confirm_min_samples:
        reasons.append(f"confirm_samples_{confirm.n}_lt_{cfg.confirm_min_samples}")
    practical_delta = cfg.stats_config().ci_width_limit(scenario) * 1.5
    if confirm.ci95_rel_width > practical_delta:
        reasons.append(f"confirm_p50_ci_width_{confirm.ci95_rel_width:.4f}_gt_{practical_delta:.4f}")
    if discovery.median > 0.0:
        delta = abs((confirm.median / discovery.median) - 1.0)
        in_ci = discovery.ci95_low <= confirm.median <= discovery.ci95_high
        if not in_ci and delta > practical_delta:
            reasons.append(f"confirm_median_delta_{delta:.4f}_gt_{practical_delta:.4f}")
    if confirm.p20_p80_ratio > cfg.stats_config().p20_p80_max:
        reasons.append(f"confirm_p80_p20_{confirm.p20_p80_ratio:.4f}_gt_{cfg.stats_config().p20_p80_max:.4f}")
    if confirm.status in {"not_ready_infra_failure", "not_ready_outlier", "not_ready_nonstationary", "not_ready_high_variance"}:
        reasons.append(f"confirm_{confirm.status}")
    if combined.status != "ready":
        reasons.append(f"combined_{combined.status}")
    return ("ready", "") if not reasons else ("not_ready", ";".join(reasons))


def write_saturation_decisions(path: Path, decisions: dict[tuple[str, str, str, str], SaturationDecision], samples: list[Sample]) -> None:
    fields = [
        "binary",
        "scenario",
        "network",
        "path_profile",
        "metric",
        "selected_threads",
        "best_threads",
        "boundary_threads",
        "selection_probability_within_tolerance",
        "best_p50",
        "selected_p50",
        "selected_vs_best_ratio",
        "selected_vs_best_ci95_low",
        "selected_vs_best_ci95_high",
        "plateau_sentinel_count",
        "edge_status",
        "decision_status",
        "reason",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=fields)
        writer.writeheader()
        for group in sorted(decisions):
            binary, scenario, network, path_profile = group
            decision = decisions[group]
            writer.writerow({
                "binary": binary,
                "scenario": scenario,
                "network": network,
                "path_profile": path_profile,
                "metric": group_metric(samples, group),
                "selected_threads": decision.selected_threads or "",
                "best_threads": decision.best_threads or "",
                "boundary_threads": decision.boundary_threads or "",
                "selection_probability_within_tolerance": format_float(decision.selection_probability_within_tolerance),
                "best_p50": format_float(decision.best_p50),
                "selected_p50": format_float(decision.selected_p50),
                "selected_vs_best_ratio": format_float(decision.selected_vs_best_ratio),
                "selected_vs_best_ci95_low": format_float(decision.selected_vs_best_ci95_low),
                "selected_vs_best_ci95_high": format_float(decision.selected_vs_best_ci95_high),
                "plateau_sentinel_count": decision.plateau_sentinel_count,
                "edge_status": decision.edge_status,
                "decision_status": decision.decision_status,
                "reason": decision.reason,
            })


def curve_role(threads: int, decision: SaturationDecision) -> str:
    roles = []
    if threads == 1:
        roles.append("baseline_1c1s")
    if decision.selected_threads and threads < decision.selected_threads:
        roles.append("pre_saturation")
    if decision.selected_threads and threads == decision.selected_threads:
        roles.append("selected_saturation")
    if decision.best_threads and threads == decision.best_threads and threads != decision.selected_threads:
        roles.append("best_capacity")
    if decision.boundary_threads and threads == decision.boundary_threads:
        roles.append("plateau_sentinel")
    if decision.selected_threads and threads > decision.selected_threads:
        roles.append("post_selected")
    return "+".join(roles) if roles else "curve"


def write_publication_tables(
    out_root: Path,
    samples: list[Sample],
    row_stats_map: dict[tuple[RowKey, str], RowStats],
    decisions: dict[tuple[str, str, str, str], SaturationDecision],
    cfg: RunnerConfig,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    curve_path = out_root / "publication-curve.tsv"
    audit_path = out_root / "publication-row-audit.tsv"
    results_path = out_root / "publication-results.tsv"
    curve_fields = [
        "binary",
        "scenario",
        "network",
        "path_profile",
        "adapter_features",
        "congestion_controller",
        "metric",
        "client_threads",
        "curve_role",
        "phase",
        "samples",
        "blocks",
        "p50",
        "p90",
        "p99",
        "p99_status",
        "p50_ci95_low",
        "p50_ci95_high",
        "p50_ci95_relative_width",
        "p20",
        "p80",
        "p20_p80_ratio",
        "convergence_status",
        "reason",
    ]
    result_rows = []
    audit_rows = []
    grouped = group_samples(samples)
    with curve_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=curve_fields)
        writer.writeheader()
        for key in sorted(grouped, key=lambda item: (item.binary, item.scenario, item.network, item.path_profile, item.client_threads, item.metric)):
            decision = decisions.get((key.binary, key.scenario, key.network, key.path_profile), SaturationDecision(0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, "", "not_ready", "missing_decision"))
            adapter_features = group_adapter_features(samples, (key.binary, key.scenario, key.network, key.path_profile))
            congestion_controller = adapter_feature_value(adapter_features, "cc")
            for phase in ("discovery", "confirm", "combined"):
                stats = row_stats_map.get((key, phase))
                if not stats:
                    continue
                writer.writerow({
                    "binary": key.binary,
                    "scenario": key.scenario,
                    "network": key.network,
                    "path_profile": key.path_profile,
                    "adapter_features": adapter_features,
                    "congestion_controller": congestion_controller,
                    "metric": key.metric,
                    "client_threads": key.client_threads,
                    "curve_role": curve_role(key.client_threads, decision),
                    "phase": phase,
                    "samples": stats.n,
                    "blocks": stats.blocks,
                    "p50": format_float(stats.median),
                    "p90": format_float(stats.p90),
                    "p99": format_float(stats.p99),
                    "p99_status": stats.p99_status,
                    "p50_ci95_low": format_float(stats.ci95_low),
                    "p50_ci95_high": format_float(stats.ci95_high),
                    "p50_ci95_relative_width": format_float(stats.ci95_rel_width),
                    "p20": format_float(stats.p20),
                    "p80": format_float(stats.p80),
                    "p20_p80_ratio": format_float(stats.p20_p80_ratio),
                    "convergence_status": stats.status,
                    "reason": stats.reason,
                })

    audit_fields = [
        "binary",
        "scenario",
        "network",
        "path_profile",
        "adapter_features",
        "congestion_controller",
        "metric",
        "client_threads",
        "publication_role",
        "discovery_status",
        "confirm_status",
        "combined_status",
        "combined_samples",
        "combined_p50",
        "combined_p50_ci95_low",
        "combined_p50_ci95_high",
        "combined_p50_ci95_relative_width",
        "combined_p20_p80_ratio",
        "publication_status",
        "reason",
    ]
    result_fields = [
        "binary",
        "scenario",
        "network",
        "path_profile",
        "adapter_features",
        "congestion_controller",
        "publication_status",
        "metric",
        "selected_threads",
        "best_threads",
        "boundary_threads",
        "discovery_p50",
        "confirm_p50",
        "combined_p50",
        "combined_p50_ci95_low",
        "combined_p50_ci95_high",
        "combined_p50_ci95_relative_width",
        "p90",
        "p99",
        "p99_status",
        "selection_probability_within_tolerance",
        "selected_vs_best_ratio",
        "edge_status",
        "reason",
    ]
    for group, decision in sorted(decisions.items()):
        binary, scenario, network, path_profile = group
        metric = group_metric(samples, group)
        adapter_features = group_adapter_features(samples, group)
        congestion_controller = adapter_feature_value(adapter_features, "cc")
        publication_threads = set()
        if decision.selected_threads:
            publication_threads.update(range(1, decision.selected_threads + 1))
            publication_threads.add(decision.best_threads)
            publication_threads.add(decision.boundary_threads)
        publication_threads.discard(0)
        not_ready = []
        selected_discovery = selected_confirm = selected_combined = None
        for threads in sorted(publication_threads):
            key = RowKey(binary, scenario, network, path_profile, threads, metric)
            discovery = row_stats_map.get((key, "discovery"))
            confirm = row_stats_map.get((key, "confirm"))
            combined = row_stats_map.get((key, "combined"))
            c_status, c_reason = confirm_status(discovery, confirm, combined, scenario, cfg)
            pub_status = "ready" if discovery and discovery.status == "ready" and c_status == "ready" and combined and combined.status == "ready" else "not_ready"
            reason = ";".join(item for item in [discovery.reason if discovery else "missing_discovery", c_reason, combined.reason if combined else "missing_combined"] if item)
            if pub_status != "ready":
                not_ready.append(f"t{threads}:{reason}")
            if threads == decision.selected_threads:
                selected_discovery = discovery
                selected_confirm = confirm
                selected_combined = combined
            audit_rows.append({
                "binary": binary,
                "scenario": scenario,
                "network": network,
                "path_profile": path_profile,
                "adapter_features": adapter_features,
                "congestion_controller": congestion_controller,
                "metric": metric,
                "client_threads": str(threads),
                "publication_role": curve_role(threads, decision),
                "discovery_status": discovery.status if discovery else "missing",
                "confirm_status": c_status,
                "combined_status": combined.status if combined else "missing",
                "combined_samples": str(combined.n) if combined else "",
                "combined_p50": format_float(combined.median if combined else None),
                "combined_p50_ci95_low": format_float(combined.ci95_low if combined else None),
                "combined_p50_ci95_high": format_float(combined.ci95_high if combined else None),
                "combined_p50_ci95_relative_width": format_float(combined.ci95_rel_width if combined else None),
                "combined_p20_p80_ratio": format_float(combined.p20_p80_ratio if combined else None),
                "publication_status": pub_status,
                "reason": reason,
            })
        decision_ready = decision.decision_status == "ready"
        publication_status = "ready" if decision_ready and not not_ready and selected_combined else "not_ready"
        result_rows.append({
            "binary": binary,
            "scenario": scenario,
            "network": network,
            "path_profile": path_profile,
            "adapter_features": adapter_features,
            "congestion_controller": congestion_controller,
            "publication_status": publication_status,
            "metric": metric,
            "selected_threads": str(decision.selected_threads or ""),
            "best_threads": str(decision.best_threads or ""),
            "boundary_threads": str(decision.boundary_threads or ""),
            "discovery_p50": format_float(selected_discovery.median if selected_discovery else None),
            "confirm_p50": format_float(selected_confirm.median if selected_confirm else None),
            "combined_p50": format_float(selected_combined.median if selected_combined else None),
            "combined_p50_ci95_low": format_float(selected_combined.ci95_low if selected_combined else None),
            "combined_p50_ci95_high": format_float(selected_combined.ci95_high if selected_combined else None),
            "combined_p50_ci95_relative_width": format_float(selected_combined.ci95_rel_width if selected_combined else None),
            "p90": format_float(selected_combined.p90 if selected_combined else None),
            "p99": format_float(selected_combined.p99 if selected_combined else None),
            "p99_status": selected_combined.p99_status if selected_combined else "",
            "selection_probability_within_tolerance": format_float(decision.selection_probability_within_tolerance),
            "selected_vs_best_ratio": format_float(decision.selected_vs_best_ratio),
            "edge_status": decision.edge_status,
            "reason": ";".join(item for item in [decision.reason, ";".join(not_ready)] if item),
        })

    with audit_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=audit_fields)
        writer.writeheader()
        writer.writerows(audit_rows)
    with results_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=result_fields)
        writer.writeheader()
        writer.writerows(result_rows)
    return result_rows, audit_rows


def write_pairwise(path: Path, samples: list[Sample], results: list[dict[str, str]], cfg: RunnerConfig) -> None:
    selected = [row for row in results if row.get("publication_status") == "ready" and row.get("binary") not in SIDECAR_EXCLUDED_BINARIES]
    by_group: dict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in selected:
        by_group[(row["scenario"], row["network"], row["path_profile"], row["metric"])].append(row)
    sample_groups = group_samples([sample for sample in samples if sample.phase in ("discovery", "confirm")])
    fields = ["scenario", "network", "path_profile", "metric", "binary_a", "binary_b", "a_p50", "b_p50", "a_vs_b_median_ratio", "a_vs_b_ci95_low", "a_vs_b_ci95_high", "relation"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=fields)
        writer.writeheader()
        for group in sorted(by_group):
            rows = sorted(by_group[group], key=lambda row: row["binary"])
            for index, a_row in enumerate(rows):
                for b_row in rows[index + 1:]:
                    a_key = RowKey(a_row["binary"], a_row["scenario"], a_row["network"], a_row["path_profile"], int(a_row["selected_threads"]), a_row["metric"])
                    b_key = RowKey(b_row["binary"], b_row["scenario"], b_row["network"], b_row["path_profile"], int(b_row["selected_threads"]), b_row["metric"])
                    stats = compare_rows(sample_groups.get(a_key, []), sample_groups.get(b_key, []), cfg.stats_config())
                    writer.writerow({
                        "scenario": group[0],
                        "network": group[1],
                        "path_profile": group[2],
                        "metric": group[3],
                        "binary_a": a_row["binary"],
                        "binary_b": b_row["binary"],
                        "a_p50": format_float(stats.a_median),
                        "b_p50": format_float(stats.b_median),
                        "a_vs_b_median_ratio": format_float(stats.median_ratio),
                        "a_vs_b_ci95_low": format_float(stats.ci95_low),
                        "a_vs_b_ci95_high": format_float(stats.ci95_high),
                        "relation": stats.relation,
                    })


def write_rankings(out_root: Path, samples: list[Sample], results: list[dict[str, str]], decisions: dict[tuple[str, str, str, str], SaturationDecision], cfg: RunnerConfig) -> None:
    ranking_rows = [row for row in results if row.get("publication_status") == "ready" and row.get("binary") not in SIDECAR_EXCLUDED_BINARIES]
    by_comparator: dict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in ranking_rows:
        by_comparator[(row["scenario"], row["network"], row["path_profile"], row["metric"])].append(row)

    sample_groups = group_samples([sample for sample in samples if sample.phase in ("discovery", "confirm")])
    by_row_path = out_root / "rankings-by-row.tsv"
    overall_path = out_root / "rankings-overall.tsv"
    bands_path = out_root / "rankings-rank-bands.tsv"
    by_row_records = []
    weights = (0.60, 0.25, 0.15)
    for comparator, rows in sorted(by_comparator.items()):
        selected_values = {row["binary"]: float(row.get("combined_p50", "0") or "0") for row in rows}
        if not selected_values:
            continue
        best_capacity = max(selected_values.values())
        selected_threads = {row["binary"]: int(row.get("selected_threads", "0") or "0") for row in rows}
        min_threads = min(thread for thread in selected_threads.values() if thread > 0) if selected_threads else 1
        for row in rows:
            binary = row["binary"]
            decision = decisions.get((binary, row["scenario"], row["network"], row["path_profile"]))
            capacity_index = selected_values[binary] / best_capacity if best_capacity > 0.0 else 0.0
            curve_values = []
            if decision and decision.selected_threads:
                for threads in range(1, decision.selected_threads + 1):
                    key = RowKey(binary, row["scenario"], row["network"], row["path_profile"], threads, row["metric"])
                    values = [sample.value or 0.0 for sample in sample_groups.get(key, []) if sample.measured]
                    if values:
                        curve_values.append(median(values))
            own_best = max(curve_values) if curve_values else selected_values[binary]
            curve_efficiency = sum(min(value / own_best, 1.0) for value in curve_values) / len(curve_values) if curve_values and own_best > 0.0 else 0.0
            client_count_efficiency = min_threads / selected_threads[binary] if selected_threads[binary] > 0 else 0.0
            score = 100.0 * ((weights[0] * capacity_index) + (weights[1] * curve_efficiency) + (weights[2] * client_count_efficiency))
            by_row_records.append({
                "binary": binary,
                "scenario": row["scenario"],
                "network": row["network"],
                "path_profile": row["path_profile"],
                "metric": row["metric"],
                "capacity_index": format_float(capacity_index),
                "curve_efficiency": format_float(curve_efficiency),
                "client_count_efficiency": format_float(client_count_efficiency),
                "score": format_float(score),
                "selected_threads": row["selected_threads"],
                "combined_p50": row["combined_p50"],
            })

    with by_row_path.open("w", encoding="utf-8", newline="") as handle:
        fields = ["binary", "scenario", "network", "path_profile", "metric", "capacity_index", "curve_efficiency", "client_count_efficiency", "score", "selected_threads", "combined_p50"]
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=fields)
        writer.writeheader()
        writer.writerows(by_row_records)

    scores_by_binary: dict[str, list[float]] = defaultdict(list)
    for row in by_row_records:
        scores_by_binary[row["binary"]].append(float(row["score"]))
    point_scores = {binary: sum(values) / len(values) for binary, values in scores_by_binary.items() if values}

    score_draws = bootstrap_scores(samples, results, decisions, cfg, weights)
    rank_draws: dict[str, list[int]] = defaultdict(list)
    for draw in score_draws:
        ordered = sorted(draw.items(), key=lambda item: (-item[1], item[0]))
        for rank, (binary, _score) in enumerate(ordered, start=1):
            rank_draws[binary].append(rank)

    overall_rows = []
    for binary, score in sorted(point_scores.items(), key=lambda item: (-item[1], item[0])):
        draws = [draw.get(binary, score) for draw in score_draws if binary in draw]
        ranks = rank_draws.get(binary, [])
        overall_rows.append({
            "binary": binary,
            "score_median": format_float(quantile(draws, 0.50) if draws else score),
            "score_ci95_low": format_float(quantile(draws, 0.025) if draws else score),
            "score_ci95_high": format_float(quantile(draws, 0.975) if draws else score),
            "rank_low": str(min(ranks) if ranks else ""),
            "rank_high": str(max(ranks) if ranks else ""),
            "rank_status": "stable" if ranks and min(ranks) == max(ranks) else "band",
        })

    with overall_path.open("w", encoding="utf-8", newline="") as handle:
        fields = ["rank", "binary", "score_median", "score_ci95_low", "score_ci95_high", "rank_low", "rank_high", "rank_status"]
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=fields)
        writer.writeheader()
        for rank, row in enumerate(overall_rows, start=1):
            item = {"rank": rank}
            item.update(row)
            writer.writerow(item)
    with bands_path.open("w", encoding="utf-8", newline="") as handle:
        fields = ["binary", "score_median", "score_ci95_low", "score_ci95_high", "rank_low", "rank_high", "rank_status"]
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=fields)
        writer.writeheader()
        writer.writerows(overall_rows)


def bootstrap_scores(
    samples: list[Sample],
    results: list[dict[str, str]],
    decisions: dict[tuple[str, str, str, str], SaturationDecision],
    cfg: RunnerConfig,
    weights: tuple[float, float, float],
) -> list[dict[str, float]]:
    ranking_rows = [row for row in results if row.get("publication_status") == "ready" and row.get("binary") not in SIDECAR_EXCLUDED_BINARIES]
    if not ranking_rows:
        return []
    iters = max(1, min(cfg.bootstrap_iters, 2000))
    sample_groups = group_samples([sample for sample in samples if sample.phase in ("discovery", "confirm")])
    dist_cache: dict[RowKey, list[float]] = {}

    def dist_for(key: RowKey) -> list[float]:
        if key not in dist_cache:
            row_samples = sample_groups.get(key, [])
            seed = int(hashlib.sha256(str(key).encode("utf-8")).hexdigest()[:16], 16) ^ cfg.random_seed
            dist = bootstrap_stat_distribution(row_samples, median, iters, seed)
            if not dist:
                dist = [0.0] * iters
            if len(dist) < iters:
                dist.extend([dist[-1]] * (iters - len(dist)))
            dist_cache[key] = dist[:iters]
        return dist_cache[key]

    by_comparator: dict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in ranking_rows:
        by_comparator[(row["scenario"], row["network"], row["path_profile"], row["metric"])].append(row)

    draws: list[dict[str, float]] = []
    for index in range(iters):
        component_scores: dict[str, list[float]] = defaultdict(list)
        for comparator, rows in by_comparator.items():
            selected_values = {}
            selected_threads = {}
            for row in rows:
                threads = int(row.get("selected_threads", "0") or "0")
                selected_threads[row["binary"]] = threads
                key = RowKey(row["binary"], row["scenario"], row["network"], row["path_profile"], threads, row["metric"])
                selected_values[row["binary"]] = dist_for(key)[index]
            best_capacity = max(selected_values.values()) if selected_values else 0.0
            positive_threads = [thread for thread in selected_threads.values() if thread > 0]
            min_threads = min(positive_threads) if positive_threads else 1
            for row in rows:
                binary = row["binary"]
                decision = decisions.get((binary, row["scenario"], row["network"], row["path_profile"]))
                capacity_index = selected_values[binary] / best_capacity if best_capacity > 0.0 else 0.0
                curve_values = []
                if decision and decision.selected_threads:
                    for threads in range(1, decision.selected_threads + 1):
                        key = RowKey(binary, row["scenario"], row["network"], row["path_profile"], threads, row["metric"])
                        curve_values.append(dist_for(key)[index])
                own_best = max(curve_values) if curve_values else selected_values[binary]
                curve_efficiency = sum(min(value / own_best, 1.0) for value in curve_values) / len(curve_values) if curve_values and own_best > 0.0 else 0.0
                client_count_efficiency = min_threads / selected_threads[binary] if selected_threads[binary] > 0 else 0.0
                score = 100.0 * ((weights[0] * capacity_index) + (weights[1] * curve_efficiency) + (weights[2] * client_count_efficiency))
                component_scores[binary].append(score)
        draws.append({binary: sum(values) / len(values) for binary, values in component_scores.items() if values})
    return draws


def write_summary(path: Path, publication_id: str, cfg: RunnerConfig, results: list[dict[str, str]], audit_rows: list[dict[str, str]], samples_path: Path) -> None:
    ready_results = [row for row in results if row.get("publication_status") == "ready"]
    not_ready_results = [row for row in results if row.get("publication_status") != "ready"]
    with path.open("w", encoding="utf-8") as handle:
        handle.write("# Adaptive Publication Run\n\n")
        handle.write(f"- Publication ID: `{publication_id}`\n")
        handle.write(f"- Status: {'ready' if not not_ready_results and results else 'not_ready'}\n")
        handle.write(f"- Adaptive samples: `{samples_path.name}`\n")
        handle.write(f"- Block size: {cfg.block_size}\n")
        handle.write(f"- Discovery minimum: {cfg.min_blocks} blocks / {cfg.min_samples} samples\n")
        handle.write(f"- Discovery maximum: {cfg.max_samples} samples\n")
        handle.write(f"- Confirmatory holdout: {cfg.confirm_blocks} blocks / {cfg.confirm_min_samples} samples\n")
        handle.write(f"- Bootstrap iterations: {cfg.bootstrap_iters}\n")
        handle.write(f"- Ready result rows: {len(ready_results)}\n")
        handle.write(f"- Not-ready result rows: {len(not_ready_results)}\n")
        handle.write(f"- Audited publication rows: {len(audit_rows)}\n")
        if not_ready_results:
            handle.write("\n## Not Ready Results\n\n")
            handle.write("| Binary | Scenario | Network | Path | Selected | Reason |\n")
            handle.write("|---|---|---|---|---:|---|\n")
            for row in not_ready_results:
                handle.write(f"| `{row['binary']}` | `{row['scenario']}` | `{row['network']}` | `{row.get('path_profile', 'loopback')}` | {row.get('selected_threads', '')} | {row.get('reason', '')} |\n")


def main() -> int:
    root = repo_root()
    cfg = load_config()
    publication_id = os.environ.get("QUICPERF_PUBLICATION_ID", f"adaptive-{utc_stamp()}-{os.getpid()}")
    out_root = Path(os.environ.get("QUICPERF_ADAPTIVE_OUT_DIR", root / ".run" / publication_id))
    out_root.mkdir(parents=True, exist_ok=True)
    samples_path = out_root / "adaptive-samples.tsv"
    resume = os.environ.get("QUICPERF_ADAPTIVE_RESUME", "0") == "1" and samples_path.exists()
    if not resume:
        write_samples(samples_path, [], append=False)

    binaries = discover_binaries(root)
    scenarios = unique_preserve(split_words(os.environ.get("QUICPERF_ADAPTIVE_SCENARIOS", os.environ.get("QUICPERF_SCENARIOS", "download upload connect"))))
    networks = unique_preserve(split_words(os.environ.get("QUICPERF_ADAPTIVE_NETWORKS", os.environ.get("QUICPERF_NETWORKS", "syscall iouring"))))
    commit = git_commit(root)
    env_sig = env_hash()
    machine_sig = machine_hash()
    randomizer = random.Random(cfg.random_seed)

    path_profiles = unique_preserve(split_words(os.environ.get("QUICPERF_ADAPTIVE_PATH_PROFILES", os.environ.get("QUICPERF_PATH_PROFILES", os.environ.get("QUICPERF_PATH_PROFILE", "loopback")))))
    decisions: dict[tuple[str, str, str, str], SaturationDecision] = {}
    start_round = 1
    block_ordinal = 0
    if resume:
        existing_samples = load_samples(samples_path)
        block_failures = load_block_failures(out_root, networks, path_profiles)
        last_round, block_ordinal = resume_positions(out_root, existing_samples, networks, path_profiles)
        start_round = last_round + 1
        row_state, row_reason, group_state, active = initialize_resume_state(
            binaries=binaries,
            scenarios=scenarios,
            networks=networks,
            path_profiles=path_profiles,
            samples=existing_samples,
            block_failures=block_failures,
            cfg=cfg,
        )
    else:
        row_state = {}
        row_reason = {}
        group_state = {}
        active = set()
        for binary in binaries:
            for scenario in scenarios:
                for network in networks:
                    for path_profile in path_profiles:
                        group = (binary, scenario, network, path_profile)
                        group_state[group] = "active"
                        target = Target(binary, scenario, network, path_profile, 1)
                        active.add(target)
                        row_state[target] = "active"

    environment_path = out_root / "adaptive-environment.txt"
    with environment_path.open("w", encoding="utf-8") as handle:
        handle.write(f"quicperf_adaptive_environment date_utc={utc_iso()}\n")
        handle.write(f"quicperf_adaptive_environment publication_id={publication_id}\n")
        handle.write(f"quicperf_adaptive_environment git_commit={commit}\n")
        handle.write(f"quicperf_adaptive_environment env_hash={env_sig} machine_hash={machine_sig}\n")
        handle.write("quicperf_adaptive_environment variables\n")
        for key, value in sorted(os.environ.items()):
            if key.startswith("QUICPERF_"):
                handle.write(f"{key}={value}\n")

    print(
        "quicperf_adaptive_run "
        f"out_dir={out_root} binaries=\"{' '.join(binaries)}\" scenarios=\"{' '.join(scenarios)}\" "
        f"networks=\"{' '.join(networks)}\" path_profiles=\"{' '.join(path_profiles)}\" block_size={cfg.block_size} min_samples={cfg.min_samples} "
        f"max_samples={cfg.max_samples} confirm_blocks={cfg.confirm_blocks} random_seed={cfg.random_seed} "
        f"saturation_min_incremental_improvement={cfg.saturation_min_incremental_improvement:.3f} "
        f"high_variance_min_blocks={cfg.high_variance_min_blocks} "
        f"high_variance_min_samples={cfg.high_variance_min_samples} "
        f"high_variance_improvement_min={cfg.high_variance_improvement_min:.3f} "
        f"severe_high_variance_min_blocks={cfg.severe_high_variance_min_blocks} "
        f"severe_high_variance_min_samples={cfg.severe_high_variance_min_samples} "
        f"severe_block_median_ratio_max={cfg.severe_block_median_ratio_max:.3f} "
        f"severe_p20_p80_max={cfg.severe_p20_p80_max:.3f} "
        f"severe_drift_rel_max={cfg.severe_drift_rel_max:.3f} "
        f"severe_outlier_blocks_min={cfg.severe_outlier_blocks_min} "
        f"resume={int(resume)} start_round={start_round} block_ordinal={block_ordinal} active_rows={len(active)}"
    )

    for round_index in range(start_round, cfg.max_rounds + 1):
        if not active:
            break
        round_targets = list(active)
        randomizer.shuffle(round_targets)
        for target in round_targets:
            if row_state.get(target) != "active":
                continue
            block_ordinal += 1
            target_samples = samples_for_target(load_samples(samples_path), target, "discovery")
            warmup = cfg.warmup if not target_samples else 0
            result = run_block(
                root,
                out_root,
                samples_path,
                target,
                phase="discovery",
                round_index=round_index,
                block_ordinal=block_ordinal,
                cfg=cfg,
                publication_id=publication_id,
                commit=commit,
                env_sig=env_sig,
                machine_sig=machine_sig,
                warmup=warmup,
            )
            if result.status != "ok":
                row_state[target] = result.status
                row_reason[target] = result.reason
                active.discard(target)
                group_state[target.group] = result.status
                print(f"quicperf_adaptive_block target={target} status={result.status} reason={result.reason}")
        samples = load_samples(samples_path)
        discovery_stats = recompute_discovery_stats(samples, cfg)
        for target in list(active):
            stats = discovery_stats.get(target)
            if not stats:
                continue
            if stats.status == "ready":
                row_state[target] = "ready"
                active.discard(target)
            elif stats.status == "not_ready_high_variance":
                row_state[target] = "not_ready_high_variance"
                row_reason[target] = stats.reason
                active.discard(target)
            elif stats.n >= cfg.max_samples:
                row_state[target] = stats.status if stats.status.startswith("not_ready") else "not_ready_max_samples"
                row_reason[target] = stats.reason
                active.discard(target)

        for group in list(group_state):
            if group_state[group] in {"ready", "unsupported", "failed", "not_ready"}:
                continue
            tested = sorted(target.threads for target in row_state if target.group == group)
            group_active = any(target.group == group and row_state.get(target) == "active" for target in row_state)
            if group_active:
                continue
            terminal = [target for target in row_state if target.group == group and row_state.get(target) in {"unsupported", "failed"}]
            if terminal:
                group_state[group] = row_state[terminal[0]]
                continue
            bounded_not_ready = [
                target for target in row_state
                if target.group == group and row_state.get(target, "").startswith("not_ready")
            ]
            if bounded_not_ready:
                decision = compute_group_decision(samples, group, row_state, cfg)
                reason = ";".join(
                    f"t{target.threads}:{row_reason.get(target, row_state.get(target, 'not_ready'))}"
                    for target in sorted(bounded_not_ready, key=lambda item: item.threads)
                )
                decision.decision_status = "not_ready"
                decision.edge_status = "not_ready"
                decision.reason = f"{decision.reason};{reason}" if decision.reason and reason else (decision.reason or reason)
                decisions[group] = decision
                group_state[group] = "not_ready"
                continue
            decision = compute_group_decision(samples, group, row_state, cfg)
            decisions[group] = decision
            if decision.decision_status == "ready":
                group_state[group] = "ready"
                continue
            if tested and tested[-1] < cfg.max_threads:
                next_target = Target(group[0], group[1], group[2], group[3], tested[-1] + 1)
                if next_target not in row_state:
                    row_state[next_target] = "active"
                    active.add(next_target)
                    continue
            group_state[group] = "not_ready"
        print(f"quicperf_adaptive_round round={round_index} active_rows={len(active)} samples={sum(1 for sample in samples if sample.measured)}")

    samples = load_samples(samples_path)
    for group in list(group_state):
        if group not in decisions and group_state[group] not in {"unsupported", "failed"}:
            decisions[group] = compute_group_decision(samples, group, row_state, cfg)
        elif group not in decisions:
            decisions[group] = SaturationDecision(
                selected_threads=0,
                best_threads=0,
                boundary_threads=0,
                selection_probability_within_tolerance=0.0,
                best_p50=0.0,
                selected_p50=0.0,
                selected_vs_best_ratio=0.0,
                selected_vs_best_ci95_low=0.0,
                selected_vs_best_ci95_high=0.0,
                plateau_sentinel_count=0,
                edge_status=group_state[group],
                decision_status=group_state[group],
                reason=next((row_reason[target] for target in row_reason if target.group == group), group_state[group]),
            )

    confirm_targets = set()
    for group, decision in decisions.items():
        if decision.selected_threads <= 0:
            continue
        for threads in range(1, decision.selected_threads + 1):
            confirm_targets.add(Target(group[0], group[1], group[2], group[3], threads))
        for threads in (decision.best_threads, decision.boundary_threads):
            if threads > 0:
                confirm_targets.add(Target(group[0], group[1], group[2], group[3], threads))
    confirm_targets = {target for target in confirm_targets if group_state.get(target.group) == "ready"}

    for confirm_round in range(1, cfg.confirm_blocks + 1):
        targets = list(confirm_targets)
        randomizer.shuffle(targets)
        for target in targets:
            block_ordinal += 1
            run_block(
                root,
                out_root,
                samples_path,
                target,
                phase="confirm",
                round_index=confirm_round,
                block_ordinal=block_ordinal,
                cfg=cfg,
                publication_id=publication_id,
                commit=commit,
                env_sig=env_sig,
                machine_sig=machine_sig,
                warmup=0,
            )
        if targets:
            print(f"quicperf_adaptive_confirm round={confirm_round} rows={len(targets)}")

    samples = load_samples(samples_path)
    row_stats_map = write_row_stats(out_root / "row-stats.tsv", samples, cfg)
    write_saturation_decisions(out_root / "saturation-decisions.tsv", decisions, samples)
    results, audit_rows = write_publication_tables(out_root, samples, row_stats_map, decisions, cfg)
    write_pairwise(out_root / "pairwise-comparisons.tsv", samples, results, cfg)
    write_rankings(out_root, samples, results, decisions, cfg)
    write_summary(out_root / "adaptive-run-summary.md", publication_id, cfg, results, audit_rows, samples_path)
    print(f"quicperf_adaptive_summary path={out_root / 'adaptive-run-summary.md'} status=complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
