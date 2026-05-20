#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import math
import random
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


SAMPLE_FIELDS = [
    "publication_id",
    "round",
    "block_id",
    "sample_id",
    "binary",
    "library",
    "scenario",
    "network",
    "path_profile",
    "client_threads",
    "server_connections",
    "adapter_features",
    "metric",
    "value",
    "phase",
    "status",
    "reason",
    "started_utc",
    "ended_utc",
    "duration_sec",
    "run_order",
    "random_seed",
    "out_dir",
    "client_log",
    "server_log",
    "git_commit",
    "env_hash",
    "machine_hash",
    "datagram_sent",
    "datagram_received",
    "datagram_lost",
    "datagram_delivery_ratio",
    "udp_packets_sent",
    "udp_packets_received",
    "udp_send_syscalls",
    "udp_recv_polls",
    "datagrams_per_udp_packet",
]


RESULT_RE = re.compile(
    r"quicperf_result library=(\S+) scenario=(\S+) role=client network=(\S+) "
    r".*?threads=(\d+) .*?build_profile=(\S+) window_profile=(\S+) "
    r"congestion_profile=(\S+) network_profile=(\S+)(?: path_profile=(\S+))? app_chunk=(\d+) "
    r"server_connections=(\d+) tls_verify_mode=(\S+) tls_cert_profile=(\S+) "
    r"adapter_features=(\S+) initial_cwnd_packets=(\d+) ack_frequency_packets=(\d+) "
    r"socket_sndbuf_requested=(\d+) socket_sndbuf_effective=(-?\d+) "
    r"socket_rcvbuf_requested=(\d+) socket_rcvbuf_effective=(-?\d+) "
    r".*?(throughput_gbps|connections_per_second|requests_per_second|streams_per_second|messages_per_second|datagrams_per_second|server_rss_delta_bytes_per_connection)=([0-9.]+)"
)

LOWER_IS_BETTER_METRICS = {"server_rss_delta_bytes_per_connection"}


def metric_higher_is_better(metric: str) -> bool:
    return metric not in LOWER_IS_BETTER_METRICS


@dataclass(frozen=True)
class RowKey:
    binary: str
    scenario: str
    network: str
    path_profile: str
    client_threads: int
    metric: str


@dataclass(frozen=True)
class GroupKey:
    binary: str
    scenario: str
    network: str
    path_profile: str
    metric: str


@dataclass
class Sample:
    publication_id: str
    round: int
    block_id: str
    sample_id: str
    binary: str
    library: str
    scenario: str
    network: str
    path_profile: str
    client_threads: int
    server_connections: int
    metric: str
    value: float | None
    phase: str
    status: str
    reason: str
    started_utc: str
    ended_utc: str
    duration_sec: float
    run_order: int
    random_seed: str
    out_dir: str
    client_log: str
    server_log: str
    git_commit: str
    env_hash: str
    machine_hash: str
    datagram_sent: int = 0
    datagram_received: int = 0
    datagram_lost: int = 0
    datagram_delivery_ratio: float = 0.0
    udp_packets_sent: int = 0
    udp_packets_received: int = 0
    udp_send_syscalls: int = 0
    udp_recv_polls: int = 0
    datagrams_per_udp_packet: float = 0.0
    adapter_features: str = ""

    @property
    def row_key(self) -> RowKey:
        return RowKey(self.binary, self.scenario, self.network, self.path_profile, self.client_threads, self.metric)

    @property
    def group_key(self) -> GroupKey:
        return GroupKey(self.binary, self.scenario, self.network, self.path_profile, self.metric)

    @property
    def measured(self) -> bool:
        return self.status == "ok" and self.phase != "warmup" and self.value is not None and self.value > 0.0


@dataclass
class StatsConfig:
    min_blocks: int = 4
    min_samples: int = 20
    confirm_min_samples: int = 10
    max_samples: int = 120
    bootstrap_iters: int = 5000
    bootstrap_seed: int = 1
    p20_p80_max: float = 1.15
    p20_p80_preferred: float = 1.10
    block_median_ratio_max: float = 1.10
    drift_rel_max: float = 0.03
    datagram_delivery_ratio_min: float = 0.995
    high_variance_min_blocks: int = 8
    high_variance_min_samples: int = 40
    high_variance_improvement_min: float = 0.10
    severe_high_variance_min_blocks: int = 6
    severe_high_variance_min_samples: int = 30
    severe_block_median_ratio_max: float = 1.25
    severe_p20_p80_max: float = 1.50
    severe_drift_rel_max: float = 0.08
    severe_outlier_blocks_min: int = 2
    outlier_mad_z: float = 12.0
    p99_min_samples: int = 300
    saturation_tolerance: float = 0.01
    saturation_min_incremental_improvement: float = 0.01
    saturation_probability: float = 0.95
    saturation_sentinels: int = 1

    def ci_width_limit(self, scenario: str) -> float:
        if scenario in {"download", "upload", "multistream_download", "multistream_upload", "bidi"}:
            return 0.03
        if scenario in {"loss_recovery", "loss_download", "loss_reqresp"}:
            return 0.08
        return 0.05


@dataclass
class RowStats:
    n: int
    blocks: int
    median: float
    p90: float
    p99: float
    p99_status: str
    ci95_low: float
    ci95_high: float
    ci95_rel_width: float
    p20: float
    p80: float
    p20_p80_ratio: float
    mad_rel: float
    block_median_min: float
    block_median_max: float
    block_median_ratio: float
    drift_rel: float
    lag1_autocorr: float
    outlier_count: int
    status: str
    reason: str


@dataclass
class PairwiseStats:
    a_median: float
    b_median: float
    median_ratio: float
    ci95_low: float
    ci95_high: float
    relation: str


@dataclass
class SaturationDecision:
    selected_threads: int
    best_threads: int
    boundary_threads: int
    selection_probability_within_tolerance: float
    best_p50: float
    selected_p50: float
    selected_vs_best_ratio: float
    selected_vs_best_ci95_low: float
    selected_vs_best_ci95_high: float
    plateau_sentinel_count: int
    edge_status: str
    decision_status: str
    reason: str


def _stable_seed(parts: Iterable[object]) -> int:
    data = "|".join(str(part) for part in parts)
    return int(hashlib.sha256(data.encode("utf-8")).hexdigest()[:16], 16)


def stable_seed(parts: Iterable[object]) -> int:
    return _stable_seed(parts)


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: object, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(str(value)))
    except (TypeError, ValueError):
        return default


def median(values: Iterable[float]) -> float:
    items = sorted(float(value) for value in values)
    if not items:
        return 0.0
    return statistics.median(items)


def quantile(values: Iterable[float], q: float) -> float:
    items = sorted(float(value) for value in values)
    if not items:
        return 0.0
    if q > 1.0:
        q /= 100.0
    q = max(0.0, min(1.0, q))
    if len(items) == 1:
        return items[0]
    position = (len(items) - 1) * q
    low = int(math.floor(position))
    high = int(math.ceil(position))
    if low == high:
        return items[low]
    fraction = position - low
    return items[low] + ((items[high] - items[low]) * fraction)


def bad_tail_quantile(values: Iterable[float], q: float, metric: str) -> float:
    if q > 1.0:
        q /= 100.0
    q = max(0.0, min(1.0, q))
    if metric_higher_is_better(metric):
        q = 1.0 - q
    return quantile(values, q)


def empirical_order_stat(values: Iterable[float], q: float) -> float:
    items = sorted(float(value) for value in values)
    if not items:
        return 0.0
    if q > 1.0:
        q /= 100.0
    index = max(0, min(len(items) - 1, math.ceil(q * len(items)) - 1))
    return items[index]


def scenario_metric_name(scenario: str) -> str:
    if scenario in {"connect", "resumed_connect"}:
        return "connections_per_second"
    if scenario in {"reqresp", "zero_rtt_reqresp"}:
        return "requests_per_second"
    if scenario in {"stream_churn", "close_reset_cleanup"}:
        return "streams_per_second"
    if scenario == "small_payload_pps":
        return "messages_per_second"
    if scenario == "datagram":
        return "datagrams_per_second"
    if scenario == "idle_footprint":
        return "server_rss_delta_bytes_per_connection"
    return "throughput_gbps"


def flat_bootstrap_ci(values: list[float], stat_fn: Callable[[list[float]], float], iters: int, seed: int | str) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    if len(values) == 1 or iters <= 0:
        value = stat_fn(values)
        return value, value
    rng = random.Random(seed)
    stats = []
    for _ in range(iters):
        draw = [rng.choice(values) for _ in values]
        stats.append(stat_fn(draw))
    return quantile(stats, 0.025), quantile(stats, 0.975)


def hierarchical_bootstrap_ci(samples: list[Sample], stat_fn: Callable[[list[float]], float], iters: int, seed: int | str) -> tuple[float, float]:
    measured = [sample for sample in samples if sample.measured]
    if not measured:
        return 0.0, 0.0
    blocks: dict[str, list[float]] = defaultdict(list)
    for sample in measured:
        block = sample.block_id or f"sample:{sample.sample_id}"
        blocks[block].append(float(sample.value or 0.0))
    block_values = [values for _, values in sorted(blocks.items()) if values]
    flat_values = [value for values in block_values for value in values]
    if len(block_values) <= 1 or iters <= 0:
        return flat_bootstrap_ci(flat_values, stat_fn, iters, seed)
    rng = random.Random(seed)
    stats = []
    for _ in range(iters):
        draw: list[float] = []
        for _ in block_values:
            draw.extend(rng.choice(block_values))
        stats.append(stat_fn(draw))
    return quantile(stats, 0.025), quantile(stats, 0.975)


def load_samples(path: Path | str) -> list[Sample]:
    sample_path = Path(path)
    if not sample_path.exists():
        return []
    samples: list[Sample] = []
    with sample_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for row in reader:
            value_text = row.get("value", "")
            samples.append(
                Sample(
                    publication_id=row.get("publication_id", ""),
                    round=_safe_int(row.get("round")),
                    block_id=row.get("block_id", ""),
                    sample_id=row.get("sample_id", ""),
                    binary=row.get("binary", ""),
                    library=row.get("library", ""),
                    scenario=row.get("scenario", ""),
                    network=row.get("network", ""),
                    path_profile=row.get("path_profile", "loopback") or "loopback",
                    client_threads=_safe_int(row.get("client_threads")),
                    server_connections=_safe_int(row.get("server_connections")),
                    adapter_features=row.get("adapter_features", ""),
                    metric=row.get("metric", ""),
                    value=_safe_float(value_text) if value_text != "" else None,
                    phase=row.get("phase", ""),
                    status=row.get("status", ""),
                    reason=row.get("reason", ""),
                    started_utc=row.get("started_utc", ""),
                    ended_utc=row.get("ended_utc", ""),
                    duration_sec=_safe_float(row.get("duration_sec")),
                    run_order=_safe_int(row.get("run_order")),
                    random_seed=row.get("random_seed", ""),
                    out_dir=row.get("out_dir", ""),
                    client_log=row.get("client_log", ""),
                    server_log=row.get("server_log", ""),
                    git_commit=row.get("git_commit", ""),
                    env_hash=row.get("env_hash", ""),
                    machine_hash=row.get("machine_hash", ""),
                    datagram_sent=_safe_int(row.get("datagram_sent")),
                    datagram_received=_safe_int(row.get("datagram_received")),
                    datagram_lost=_safe_int(row.get("datagram_lost")),
                    datagram_delivery_ratio=_safe_float(row.get("datagram_delivery_ratio")),
                    udp_packets_sent=_safe_int(row.get("udp_packets_sent")),
                    udp_packets_received=_safe_int(row.get("udp_packets_received")),
                    udp_send_syscalls=_safe_int(row.get("udp_send_syscalls")),
                    udp_recv_polls=_safe_int(row.get("udp_recv_polls")),
                    datagrams_per_udp_packet=_safe_float(row.get("datagrams_per_udp_packet")),
                )
            )
    return samples


def write_samples(path: Path | str, samples: list[Sample], append: bool = False) -> None:
    sample_path = Path(path)
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not append or not sample_path.exists() or sample_path.stat().st_size == 0
    with sample_path.open("a" if append else "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=SAMPLE_FIELDS, lineterminator="\n")
        if write_header:
            writer.writeheader()
        for sample in samples:
            writer.writerow(sample_to_row(sample))


def sample_to_row(sample: Sample) -> dict[str, str]:
    return {
        "publication_id": sample.publication_id,
        "round": str(sample.round),
        "block_id": sample.block_id,
        "sample_id": sample.sample_id,
        "binary": sample.binary,
        "library": sample.library,
        "scenario": sample.scenario,
        "network": sample.network,
        "path_profile": sample.path_profile,
        "client_threads": str(sample.client_threads),
        "server_connections": str(sample.server_connections),
        "adapter_features": sample.adapter_features,
        "metric": sample.metric,
        "value": f"{sample.value:.9f}" if sample.value is not None else "",
        "phase": sample.phase,
        "status": sample.status,
        "reason": sample.reason,
        "started_utc": sample.started_utc,
        "ended_utc": sample.ended_utc,
        "duration_sec": f"{sample.duration_sec:.6f}",
        "run_order": str(sample.run_order),
        "random_seed": sample.random_seed,
        "out_dir": sample.out_dir,
        "client_log": sample.client_log,
        "server_log": sample.server_log,
        "git_commit": sample.git_commit,
        "env_hash": sample.env_hash,
        "machine_hash": sample.machine_hash,
        "datagram_sent": str(sample.datagram_sent),
        "datagram_received": str(sample.datagram_received),
        "datagram_lost": str(sample.datagram_lost),
        "datagram_delivery_ratio": f"{sample.datagram_delivery_ratio:.9f}",
        "udp_packets_sent": str(sample.udp_packets_sent),
        "udp_packets_received": str(sample.udp_packets_received),
        "udp_send_syscalls": str(sample.udp_send_syscalls),
        "udp_recv_polls": str(sample.udp_recv_polls),
        "datagrams_per_udp_packet": f"{sample.datagrams_per_udp_packet:.9f}",
    }


def group_samples(samples: list[Sample]) -> dict[RowKey, list[Sample]]:
    groups: dict[RowKey, list[Sample]] = defaultdict(list)
    for sample in samples:
        if sample.metric:
            groups[sample.row_key].append(sample)
    return dict(groups)


def parse_client_log_samples(
    client_log: Path,
    *,
    publication_id: str = "",
    round_index: int = 0,
    block_id: str = "",
    sample_id: str = "",
    phase: str = "discovery",
    status: str = "ok",
    reason: str = "",
    started_utc: str = "",
    ended_utc: str = "",
    duration_sec: float = 0.0,
    run_order: int = 0,
    random_seed: str = "",
    out_dir: str = "",
    server_log: str = "",
    git_commit: str = "",
    env_hash: str = "",
    machine_hash: str = "",
) -> list[Sample]:
    path = Path(client_log)
    stem = path.name.removesuffix(".client.log")
    binary = ""
    if ".warmup" in path.name:
        return []
    parts = stem.split("-", 3)
    if parts:
        binary = parts[0]

    samples: list[Sample] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = RESULT_RE.search(line)
        if not match:
            continue
        (
            library,
            scenario,
            network,
            client_threads,
            _build_profile,
            _window_profile,
            _congestion_profile,
            _network_profile,
            path_profile,
            _app_chunk,
            server_connections,
            _tls_verify_mode,
            _tls_cert_profile,
            _adapter_features,
            _initial_cwnd_packets,
            _ack_frequency_packets,
            _socket_sndbuf_requested,
            _socket_sndbuf_effective,
            _socket_rcvbuf_requested,
            _socket_rcvbuf_effective,
            metric,
            value,
        ) = match.groups()
        result_fields = dict(re.findall(r"([A-Za-z0-9_]+)=([^ ]+)", line))
        samples.append(
            Sample(
                publication_id=publication_id,
                round=round_index,
                block_id=block_id,
                sample_id=sample_id or path.stem,
                binary=binary,
                library=library,
                scenario=scenario,
                network=network,
                path_profile=path_profile or "loopback",
                client_threads=int(client_threads),
                server_connections=int(server_connections),
                adapter_features=_adapter_features,
                metric=metric,
                value=float(value),
                phase=phase,
                status=status,
                reason=reason,
                started_utc=started_utc,
                ended_utc=ended_utc,
                duration_sec=duration_sec,
                run_order=run_order,
                random_seed=random_seed,
                out_dir=out_dir,
                client_log=str(path),
                server_log=server_log,
                git_commit=git_commit,
                env_hash=env_hash,
                machine_hash=machine_hash,
                datagram_sent=_safe_int(result_fields.get("datagram_sent")),
                datagram_received=_safe_int(result_fields.get("datagram_received")),
                datagram_lost=_safe_int(result_fields.get("datagram_lost")),
                datagram_delivery_ratio=_safe_float(result_fields.get("datagram_delivery_ratio")),
                udp_packets_sent=_safe_int(result_fields.get("udp_packets_sent")),
                udp_packets_received=_safe_int(result_fields.get("udp_packets_received")),
                udp_send_syscalls=_safe_int(result_fields.get("udp_send_syscalls")),
                udp_recv_polls=_safe_int(result_fields.get("udp_recv_polls")),
                datagrams_per_udp_packet=_safe_float(result_fields.get("datagrams_per_udp_packet")),
            )
        )
    return samples


def row_stats(samples: list[Sample], config: StatsConfig | None = None) -> RowStats:
    cfg = config or StatsConfig()
    measured = [sample for sample in samples if sample.measured]
    values = [float(sample.value or 0.0) for sample in measured]
    blocks: dict[str, list[float]] = defaultdict(list)
    for sample in measured:
        blocks[sample.block_id or f"sample:{sample.sample_id}"].append(float(sample.value or 0.0))
    ordered_blocks = [(block_id, items) for block_id, items in sorted(blocks.items()) if items]
    block_medians = [median(items) for _, items in ordered_blocks]
    n = len(values)
    block_count = len(block_medians)

    if not values:
        bad = [sample for sample in samples if sample.status not in ("ok", "")]
        reason = bad[0].reason if bad and bad[0].reason else "no_measured_samples"
        status = "failed" if bad else "not_ready"
        return RowStats(
            n=0,
            blocks=0,
            median=0.0,
            p90=0.0,
            p99=0.0,
            p99_status="insufficient_order_stat_support",
            ci95_low=0.0,
            ci95_high=0.0,
            ci95_rel_width=0.0,
            p20=0.0,
            p80=0.0,
            p20_p80_ratio=0.0,
            mad_rel=0.0,
            block_median_min=0.0,
            block_median_max=0.0,
            block_median_ratio=0.0,
            drift_rel=0.0,
            lag1_autocorr=0.0,
            outlier_count=0,
            status=status,
            reason=reason,
        )

    med = median(values)
    p20 = quantile(values, 0.20)
    p80 = quantile(values, 0.80)
    p20_p80_ratio = (p80 / p20) if p20 > 0.0 else 0.0
    metric = samples[0].metric if samples else ""
    p90 = bad_tail_quantile(values, 0.90, metric)
    p99 = bad_tail_quantile(values, 0.99, metric)
    p99_status = "claimable" if n >= cfg.p99_min_samples else "insufficient_order_stat_support"
    mad = median(abs(value - med) for value in values)
    mad_rel = (mad / med) if med > 0.0 else 0.0
    outlier_count = _outlier_count(values, med, mad, cfg)
    outlier_block_count = _outlier_block_count(ordered_blocks, med, mad, cfg)
    block_median_min = min(block_medians) if block_medians else med
    block_median_max = max(block_medians) if block_medians else med
    block_median_ratio = (block_median_max / block_median_min) if block_median_min > 0.0 else 0.0
    drift_rel = _drift_rel(block_medians)
    lag1 = _lag1_autocorr(values)
    seed = _stable_seed([samples[0].row_key, cfg.bootstrap_seed])
    ci_low, ci_high = hierarchical_bootstrap_ci(measured, median, cfg.bootstrap_iters, seed)
    ci_rel = ((ci_high - ci_low) / med) if med > 0.0 else 0.0

    reasons = []
    infra_failures = [sample for sample in samples if sample.phase != "warmup" and sample.status not in ("ok", "")]
    if infra_failures:
        reasons.append(f"infra_failures_{len(infra_failures)}")
    if block_count < cfg.min_blocks:
        reasons.append(f"blocks_{block_count}_lt_{cfg.min_blocks}")
    if n < cfg.min_samples:
        reasons.append(f"samples_{n}_lt_{cfg.min_samples}")
    ci_limit = cfg.ci_width_limit(samples[0].scenario)
    if n >= cfg.min_samples and ci_rel > ci_limit:
        reasons.append(f"p50_ci_width_{ci_rel:.4f}_gt_{ci_limit:.4f}")
    if p20_p80_ratio > cfg.p20_p80_max:
        reasons.append(f"p80_p20_{p20_p80_ratio:.4f}_gt_{cfg.p20_p80_max:.4f}")
    if block_median_ratio > cfg.block_median_ratio_max:
        reasons.append(f"block_median_ratio_{block_median_ratio:.4f}_gt_{cfg.block_median_ratio_max:.4f}")
    if abs(drift_rel) > cfg.drift_rel_max:
        reasons.append(f"drift_{drift_rel:.4f}_gt_{cfg.drift_rel_max:.4f}")
    if outlier_count:
        reasons.append(f"outliers_{outlier_count}")
    if samples[0].scenario == "datagram":
        delivery_ratios = [
            sample.datagram_delivery_ratio
            for sample in measured
            if sample.datagram_sent > 0 or sample.datagram_received > 0
        ]
        if delivery_ratios and min(delivery_ratios) < cfg.datagram_delivery_ratio_min:
            reasons.append(
                f"datagram_delivery_ratio_{min(delivery_ratios):.4f}_lt_{cfg.datagram_delivery_ratio_min:.4f}"
            )
    high_variance_reasons = _high_variance_reasons(
        ordered_blocks,
        p20_p80_ratio,
        block_median_ratio,
        drift_rel,
        outlier_count,
        outlier_block_count,
        cfg,
    )

    if high_variance_reasons:
        reasons.extend(high_variance_reasons)

    if infra_failures:
        status = "failed"
    elif block_count < cfg.min_blocks or n < cfg.min_samples:
        status = "not_ready"
    else:
        status = "converged"

    return RowStats(
        n=n,
        blocks=block_count,
        median=med,
        p90=p90,
        p99=p99,
        p99_status=p99_status,
        ci95_low=ci_low,
        ci95_high=ci_high,
        ci95_rel_width=ci_rel,
        p20=p20,
        p80=p80,
        p20_p80_ratio=p20_p80_ratio,
        mad_rel=mad_rel,
        block_median_min=block_median_min,
        block_median_max=block_median_max,
        block_median_ratio=block_median_ratio,
        drift_rel=drift_rel,
        lag1_autocorr=lag1,
        outlier_count=outlier_count,
        status=status,
        reason=";".join(reasons),
    )


def _outlier_count(values: list[float], med: float, mad: float, cfg: StatsConfig) -> int:
    if not values:
        return 0
    if any(value <= 0.0 for value in values):
        return sum(1 for value in values if value <= 0.0)
    if mad <= 0.0:
        return 0
    scale = 1.4826 * mad
    return sum(1 for value in values if abs(value - med) / scale > cfg.outlier_mad_z)


def _outlier_block_count(
    ordered_blocks: list[tuple[str, list[float]]],
    med: float,
    mad: float,
    cfg: StatsConfig,
) -> int:
    if not ordered_blocks:
        return 0
    if any(value <= 0.0 for _, values in ordered_blocks for value in values):
        return sum(1 for _, values in ordered_blocks if any(value <= 0.0 for value in values))
    if mad <= 0.0:
        return 0
    scale = 1.4826 * mad
    return sum(
        1
        for _, values in ordered_blocks
        if any(abs(value - med) / scale > cfg.outlier_mad_z for value in values)
    )


def _drift_rel(block_medians: list[float]) -> float:
    if len(block_medians) < 4:
        return 0.0
    midpoint = len(block_medians) // 2
    first = median(block_medians[:midpoint])
    second = median(block_medians[midpoint:])
    if first <= 0.0:
        return 0.0
    return (second / first) - 1.0


def _ratio(values: list[float]) -> float:
    positive = [value for value in values if value > 0.0]
    if not positive:
        return 0.0
    return max(positive) / min(positive)


def _p80_p20_ratio(values: list[float]) -> float:
    if not values:
        return 0.0
    p20 = quantile(values, 0.20)
    p80 = quantile(values, 0.80)
    return (p80 / p20) if p20 > 0.0 else 0.0


def _not_improving(first: float, recent: float, improvement_min: float) -> bool:
    if first <= 0.0:
        return True
    return recent >= first * (1.0 - improvement_min)


def _high_variance_reasons(
    ordered_blocks: list[tuple[str, list[float]]],
    p20_p80_ratio: float,
    block_median_ratio: float,
    drift_rel: float,
    outlier_count: int,
    outlier_block_count: int,
    cfg: StatsConfig,
) -> list[str]:
    block_count = len(ordered_blocks)
    sample_count = sum(len(values) for _, values in ordered_blocks)
    severe = _severe_high_variance_reasons(
        block_count,
        sample_count,
        p20_p80_ratio,
        block_median_ratio,
        drift_rel,
        outlier_block_count,
        cfg,
    )
    if severe:
        return severe

    if block_count < cfg.high_variance_min_blocks or sample_count < cfg.high_variance_min_samples:
        return []

    midpoint = block_count // 2
    first_blocks = ordered_blocks[:midpoint]
    recent_blocks = ordered_blocks[midpoint:]
    first_medians = [median(values) for _, values in first_blocks if values]
    recent_medians = [median(values) for _, values in recent_blocks if values]
    first_values = [value for _, values in first_blocks for value in values]
    recent_values = [value for _, values in recent_blocks for value in values]

    first_block_ratio = _ratio(first_medians)
    recent_block_ratio = _ratio(recent_medians)
    first_spread_ratio = _p80_p20_ratio(first_values)
    recent_spread_ratio = _p80_p20_ratio(recent_values)

    reasons: list[str] = []
    if (
        block_median_ratio > cfg.block_median_ratio_max
        and recent_block_ratio > cfg.block_median_ratio_max
        and _not_improving(first_block_ratio, recent_block_ratio, cfg.high_variance_improvement_min)
    ):
        reasons.append(
            f"persistent_block_median_ratio_recent_{recent_block_ratio:.4f}_gt_{cfg.block_median_ratio_max:.4f}"
        )
    if (
        p20_p80_ratio > cfg.p20_p80_max
        and recent_spread_ratio > cfg.p20_p80_max
        and _not_improving(first_spread_ratio, recent_spread_ratio, cfg.high_variance_improvement_min)
    ):
        reasons.append(f"persistent_p80_p20_recent_{recent_spread_ratio:.4f}_gt_{cfg.p20_p80_max:.4f}")
    if abs(drift_rel) > cfg.drift_rel_max:
        reasons.append(f"persistent_drift_{drift_rel:.4f}_gt_{cfg.drift_rel_max:.4f}")
    if outlier_count:
        reasons.append(f"persistent_outliers_{outlier_count}")
    return reasons


def _severe_high_variance_reasons(
    block_count: int,
    sample_count: int,
    p20_p80_ratio: float,
    block_median_ratio: float,
    drift_rel: float,
    outlier_block_count: int,
    cfg: StatsConfig,
) -> list[str]:
    if (
        block_count < cfg.severe_high_variance_min_blocks
        or sample_count < cfg.severe_high_variance_min_samples
    ):
        return []

    reasons: list[str] = []
    if block_median_ratio > cfg.severe_block_median_ratio_max:
        reasons.append(
            f"severe_block_median_ratio_{block_median_ratio:.4f}_gt_{cfg.severe_block_median_ratio_max:.4f}"
        )
    if p20_p80_ratio > cfg.severe_p20_p80_max:
        reasons.append(f"severe_p80_p20_{p20_p80_ratio:.4f}_gt_{cfg.severe_p20_p80_max:.4f}")
    if abs(drift_rel) > cfg.severe_drift_rel_max:
        reasons.append(f"severe_drift_{drift_rel:.4f}_gt_{cfg.severe_drift_rel_max:.4f}")
    if outlier_block_count >= cfg.severe_outlier_blocks_min:
        reasons.append(f"severe_outlier_blocks_{outlier_block_count}_gte_{cfg.severe_outlier_blocks_min}")
    return reasons


def _lag1_autocorr(values: list[float]) -> float:
    if len(values) < 3:
        return 0.0
    mean = sum(values) / len(values)
    denominator = sum((value - mean) ** 2 for value in values)
    if denominator <= 0.0:
        return 0.0
    numerator = sum((values[index] - mean) * (values[index - 1] - mean) for index in range(1, len(values)))
    return numerator / denominator


def bootstrap_stat_distribution(samples: list[Sample], stat_fn: Callable[[list[float]], float], iters: int, seed: int | str) -> list[float]:
    measured = [sample for sample in samples if sample.measured]
    values = [float(sample.value or 0.0) for sample in measured]
    if not values:
        return []
    if len(values) == 1 or iters <= 0:
        return [stat_fn(values)]
    blocks: dict[str, list[float]] = defaultdict(list)
    for sample in measured:
        blocks[sample.block_id or f"sample:{sample.sample_id}"].append(float(sample.value or 0.0))
    block_values = [items for _, items in sorted(blocks.items()) if items]
    rng = random.Random(seed)
    stats = []
    if len(block_values) <= 1:
        for _ in range(iters):
            stats.append(stat_fn([rng.choice(values) for _ in values]))
        return stats
    for _ in range(iters):
        draw: list[float] = []
        for _ in block_values:
            draw.extend(rng.choice(block_values))
        stats.append(stat_fn(draw))
    return stats


def compare_rows(a_samples: list[Sample], b_samples: list[Sample], config: StatsConfig | None = None) -> PairwiseStats:
    cfg = config or StatsConfig()
    a_values = [float(sample.value or 0.0) for sample in a_samples if sample.measured]
    b_values = [float(sample.value or 0.0) for sample in b_samples if sample.measured]
    a_median = median(a_values)
    b_median = median(b_values)
    if a_median <= 0.0 or b_median <= 0.0:
        return PairwiseStats(a_median, b_median, 0.0, 0.0, 0.0, "insufficient")
    metric = a_samples[0].metric if a_samples else (b_samples[0].metric if b_samples else "")
    higher_is_better = metric_higher_is_better(metric)
    seed = _stable_seed(["pair", a_samples[0].row_key if a_samples else "", b_samples[0].row_key if b_samples else "", cfg.bootstrap_seed])
    a_dist = bootstrap_stat_distribution(a_samples, median, cfg.bootstrap_iters, seed)
    b_dist = bootstrap_stat_distribution(b_samples, median, cfg.bootstrap_iters, seed + 1)
    count = min(len(a_dist), len(b_dist))
    ratios = [a_dist[index] / b_dist[index] for index in range(count) if b_dist[index] > 0.0]
    if not ratios:
        return PairwiseStats(a_median, b_median, a_median / b_median, 0.0, 0.0, "insufficient")
    low = quantile(ratios, 0.025)
    high = quantile(ratios, 0.975)
    if higher_is_better and low > 1.01:
        relation = "win"
    elif higher_is_better and high < (1.0 / 1.01):
        relation = "loss"
    elif not higher_is_better and high < (1.0 / 1.01):
        relation = "win"
    elif not higher_is_better and low > 1.01:
        relation = "loss"
    else:
        relation = "statistical_tie"
    return PairwiseStats(a_median, b_median, a_median / b_median, low, high, relation)


def saturation_decision(
    group_stats: dict[int, RowStats],
    group_samples: dict[int, list[Sample]],
    config: StatsConfig | None = None,
) -> SaturationDecision:
    cfg = config or StatsConfig()
    scenario = ""
    for samples in group_samples.values():
        if samples:
            scenario = samples[0].scenario
            break
    if scenario == "idle_footprint":
        stats = group_stats.get(1)
        if not stats or stats.status != "converged" or stats.median <= 0.0:
            return SaturationDecision(0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, "no_converged_rows", "not_ready", "idle_footprint_requires_converged_1c1s_row")
        return SaturationDecision(
            selected_threads=1,
            best_threads=1,
            boundary_threads=1,
            selection_probability_within_tolerance=1.0,
            best_p50=stats.median,
            selected_p50=stats.median,
            selected_vs_best_ratio=1.0,
            selected_vs_best_ci95_low=1.0,
            selected_vs_best_ci95_high=1.0,
            plateau_sentinel_count=cfg.saturation_sentinels,
            edge_status="fixed",
            decision_status="converged",
            reason="fixed_1c1s_idle_resource_row",
        )

    converged_threads = sorted(thread for thread, stats in group_stats.items() if stats.status == "converged" and stats.median > 0.0)
    if not converged_threads:
        return SaturationDecision(0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, "no_converged_rows", "not_ready", "no_converged_rows")

    boundary_threads = 0
    plateau_reason = ""
    previous_thread = converged_threads[0]
    for thread in converged_threads[1:]:
        previous_p50 = group_stats[previous_thread].median
        current_p50 = group_stats[thread].median
        improvement = (current_p50 / previous_p50) - 1.0 if previous_p50 > 0.0 else 0.0
        if improvement <= cfg.saturation_min_incremental_improvement:
            boundary_threads = thread
            plateau_reason = (
                f"incremental_improvement_{improvement * 100.0:.2f}pct_le_"
                f"{cfg.saturation_min_incremental_improvement * 100.0:.2f}pct"
            )
            break
        previous_thread = thread

    curve_threads = [thread for thread in converged_threads if boundary_threads == 0 or thread <= boundary_threads]
    best_threads = max(curve_threads, key=lambda thread: group_stats[thread].median)
    best_p50 = group_stats[best_threads].median
    selected_threads = best_threads
    selected_probability = 1.0
    selected_ratio_low = 1.0
    selected_ratio_high = 1.0

    for thread in curve_threads:
        if thread == best_threads:
            probability, low, high = 1.0, 1.0, 1.0
        else:
            probability, low, high = _prob_within_tolerance(group_samples[thread], group_samples[best_threads], cfg)
        if probability >= cfg.saturation_probability:
            selected_threads = thread
            selected_probability = probability
            selected_ratio_low = low
            selected_ratio_high = high
            break

    sentinel_count = 1 if boundary_threads else 0

    edge = "ok"
    status = "converged"
    reasons = []
    if boundary_threads == 0:
        edge = "edge"
        status = "not_ready"
        reasons.append("no_incremental_plateau")
    elif plateau_reason:
        reasons.append(plateau_reason)
    if selected_probability < cfg.saturation_probability:
        selected_threads = best_threads
        selected_probability = 1.0
        selected_ratio_low = 1.0
        selected_ratio_high = 1.0
        reasons.append("selected_best_due_low_within_tolerance_confidence")

    selected_p50 = group_stats[selected_threads].median
    return SaturationDecision(
        selected_threads=selected_threads,
        best_threads=best_threads,
        boundary_threads=boundary_threads,
        selection_probability_within_tolerance=selected_probability,
        best_p50=best_p50,
        selected_p50=selected_p50,
        selected_vs_best_ratio=(selected_p50 / best_p50) if best_p50 > 0.0 else 0.0,
        selected_vs_best_ci95_low=selected_ratio_low,
        selected_vs_best_ci95_high=selected_ratio_high,
        plateau_sentinel_count=sentinel_count,
        edge_status=edge,
        decision_status=status,
        reason=";".join(reasons),
    )


def _prob_within_tolerance(a_samples: list[Sample], best_samples: list[Sample], cfg: StatsConfig) -> tuple[float, float, float]:
    seed = _stable_seed(["within", a_samples[0].row_key if a_samples else "", best_samples[0].row_key if best_samples else "", cfg.bootstrap_seed])
    a_dist = bootstrap_stat_distribution(a_samples, median, cfg.bootstrap_iters, seed)
    b_dist = bootstrap_stat_distribution(best_samples, median, cfg.bootstrap_iters, seed + 1)
    ratios = [a_dist[index] / b_dist[index] for index in range(min(len(a_dist), len(b_dist))) if b_dist[index] > 0.0]
    if not ratios:
        return 0.0, 0.0, 0.0
    threshold = 1.0 - cfg.saturation_tolerance
    probability = sum(1 for ratio in ratios if ratio >= threshold) / len(ratios)
    return probability, quantile(ratios, 0.025), quantile(ratios, 0.975)


def format_float(value: float | int | str | None, digits: int = 6) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return ""
    return f"{float(value):.{digits}f}"
