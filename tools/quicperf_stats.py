#!/usr/bin/env python3
from __future__ import annotations

import csv
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


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
        return self.status == "ok" and self.phase != "warmup" and self.value is not None and self.value >= 0.0


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
