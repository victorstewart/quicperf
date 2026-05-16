#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import fcntl
import json
import math
import os
import statistics
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_5G_INPUT = ROOT / ".data" / "public-cellular" / "ucc-5g" / "5G-production-dataset.zip"
DEFAULT_4G_INPUT = ROOT / ".data" / "public-cellular" / "ucc-4g" / "LTE_Dataset.zip"
DEFAULT_5GOPHERS_INPUT = ROOT / ".data" / "public-cellular" / "5gophers" / "5Gophers-v1.0.zip"
DEFAULT_INPUT = DEFAULT_5G_INPUT
DEFAULT_OUTPUT = ROOT / "profiles" / "network" / "cellular-dynamics-profiles.json"


@dataclass
class Sample:
    timestamp_ms: int
    downlink_bps: int
    uplink_bps: int
    rtt_ms: float | None = None
    jitter_ms: float | None = None
    loss_percent: float | None = None
    speed_kph: float | None = None
    cell_id: str | None = None
    state: str | None = None


def clean(value: Any) -> str:
    return str(value or "").strip()


def parse_float(value: Any) -> float | None:
    text = clean(value)
    if not text or text == "-":
        return None
    try:
        return float(text)
    except ValueError:
        return None


def parse_int(value: Any) -> int | None:
    parsed = parse_float(value)
    if parsed is None:
        return None
    return int(parsed)


def parse_ucc_timestamp(value: str) -> int:
    parsed = datetime.strptime(value, "%Y.%m.%d_%H.%M.%S")
    return int(parsed.timestamp() * 1000)


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(pct / 100.0 * len(ordered)) - 1))
    return float(ordered[index])


def median_int(values: list[int], fallback: int) -> int:
    return int(statistics.median(values)) if values else fallback


def read_ucc_csv(handle: Iterable[str], *, bitrate_unit: str = "kbps") -> list[Sample]:
    scale = {"bps": 1, "kbps": 1_000, "mbps": 1_000_000}[bitrate_unit]
    reader = csv.DictReader(handle)
    samples: list[Sample] = []
    for row in reader:
        timestamp = clean(row.get("Timestamp"))
        dl = parse_float(row.get("DL_bitrate"))
        ul = parse_float(row.get("UL_bitrate"))
        if not timestamp or dl is None or ul is None:
            continue
        samples.append(
            Sample(
                timestamp_ms=parse_ucc_timestamp(timestamp),
                downlink_bps=max(1_000, int(dl * scale)),
                uplink_bps=max(1_000, int(ul * scale)),
                rtt_ms=parse_float(row.get("PINGAVG")),
                jitter_ms=parse_float(row.get("PINGSTDEV")),
                loss_percent=parse_float(row.get("PINGLOSS")),
                speed_kph=parse_float(row.get("Speed")),
                cell_id=clean(row.get("RAWCELLID") or row.get("CellID")) or None,
                state=clean(row.get("State")) or None,
            )
        )
    return samples


def read_ucc_5g_csv(handle: Iterable[str], *, bitrate_unit: str = "kbps") -> list[Sample]:
    return read_ucc_csv(handle, bitrate_unit=bitrate_unit)


def read_ucc_4g_csv(handle: Iterable[str], *, bitrate_unit: str = "kbps") -> list[Sample]:
    return read_ucc_csv(handle, bitrate_unit=bitrate_unit)


def read_5gophers_walking_csv(handle: Iterable[str]) -> list[Sample]:
    reader = csv.DictReader(handle)
    samples: list[Sample] = []
    for index, row in enumerate(reader):
        if clean(row.get("radio_type")).upper() != "5G":
            continue
        downlink_mbps = parse_float(row.get("throughput_mbps"))
        if downlink_mbps is None:
            continue
        seq_num = parse_int(row.get("seq_num"))
        samples.append(
            Sample(
                timestamp_ms=((seq_num if seq_num is not None else index) - 1) * 1000,
                downlink_bps=max(1_000, int(downlink_mbps * 1_000_000)),
                uplink_bps=1_000,
                cell_id=clean(row.get("anonymized_mCid")) or None,
                state=clean(row.get("primitive_handoff_type") or row.get("nrStatus")) or None,
            )
        )
    return samples


def read_normalized_csv(path: Path) -> list[Sample]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        samples: list[Sample] = []
        for index, row in enumerate(reader):
            timestamp_ms = parse_int(row.get("timestamp_ms"))
            time_s = parse_float(row.get("time_s"))
            if timestamp_ms is None:
                timestamp_ms = int((time_s if time_s is not None else index) * 1000)
            downlink = parse_float(row.get("downlink_bps"))
            if downlink is None:
                downlink = (parse_float(row.get("downlink_mbps")) or 0.0) * 1_000_000
            uplink = parse_float(row.get("uplink_bps"))
            if uplink is None:
                uplink = (parse_float(row.get("uplink_mbps")) or 0.0) * 1_000_000
            samples.append(
                Sample(
                    timestamp_ms=timestamp_ms,
                    downlink_bps=max(1_000, int(downlink)),
                    uplink_bps=max(1_000, int(uplink)),
                    rtt_ms=parse_float(row.get("rtt_ms")),
                    jitter_ms=parse_float(row.get("jitter_ms")),
                    loss_percent=parse_float(row.get("loss_percent")),
                    speed_kph=parse_float(row.get("speed_kph")),
                    cell_id=clean(row.get("cell_id")) or None,
                    state=clean(row.get("state")) or None,
                )
            )
        return samples


def load_samples(args: argparse.Namespace) -> tuple[list[Sample], str]:
    if args.format == "normalized":
        path = Path(args.input)
        return read_normalized_csv(path), display_path(path)
    archive = Path(args.input)
    with zipfile.ZipFile(archive) as zf:
        member = args.member
        if not member:
            if args.format == "5gophers":
                candidates = [
                    name
                    for name in zf.namelist()
                    if name.endswith("/All-Carriers/03-User-Mobility/walking-trace.csv")
                ]
            elif args.format == "ucc-4g":
                mobility = args.mobility.strip().lower()
                candidates = [
                    name
                    for name in zf.namelist()
                    if name.startswith(f"Dataset/{mobility}/") and name.endswith(".csv")
                ]
            else:
                mobility = args.mobility.strip()
                candidates = [
                    name
                    for name in zf.namelist()
                    if name.startswith(f"5G-production-dataset/Download/{mobility}/") and name.endswith(".csv")
                ]
            if not candidates:
                raise SystemExit(f"no {args.format} CSV files found for mobility {args.mobility!r} in {archive}")
            member = max(candidates, key=lambda name: zf.getinfo(name).file_size)
        with zf.open(member, "r") as raw:
            text = (line.decode("utf-8", errors="replace") for line in raw)
            if args.format == "5gophers":
                return read_5gophers_walking_csv(text), f"{display_path(archive)}!{member}"
            if args.format == "ucc-4g":
                return read_ucc_4g_csv(text, bitrate_unit=args.bitrate_unit), f"{display_path(archive)}!{member}"
            return read_ucc_5g_csv(text, bitrate_unit=args.bitrate_unit), f"{display_path(archive)}!{member}"


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def collapse_by_second(samples: list[Sample]) -> list[Sample]:
    buckets: dict[int, list[Sample]] = {}
    for sample in samples:
        buckets.setdefault(sample.timestamp_ms // 1000, []).append(sample)
    collapsed = []
    for second in sorted(buckets):
        rows = buckets[second]
        rtts = [row.rtt_ms for row in rows if row.rtt_ms is not None]
        jitters = [row.jitter_ms for row in rows if row.jitter_ms is not None]
        losses = [row.loss_percent for row in rows if row.loss_percent is not None]
        speeds = [row.speed_kph for row in rows if row.speed_kph is not None]
        collapsed.append(
            Sample(
                timestamp_ms=second * 1000,
                downlink_bps=max(row.downlink_bps for row in rows),
                uplink_bps=max(row.uplink_bps for row in rows),
                rtt_ms=statistics.median(rtts) if rtts else None,
                jitter_ms=statistics.median(jitters) if jitters else None,
                loss_percent=statistics.median(losses) if losses else None,
                speed_kph=statistics.median(speeds) if speeds else None,
                cell_id=next((row.cell_id for row in reversed(rows) if row.cell_id), None),
                state=next((row.state for row in reversed(rows) if row.state), None),
            )
        )
    return collapsed


def select_window(samples: list[Sample], max_steps: int, mode: str) -> list[Sample]:
    if len(samples) <= max_steps:
        return samples
    if mode == "first":
        return samples[:max_steps]
    if mode == "last":
        return samples[-max_steps:]
    if mode == "lowest-median-downlink":
        best_start = 0
        best_value = None
        for start in range(0, len(samples) - max_steps + 1):
            window = samples[start : start + max_steps]
            value = statistics.median(sample.downlink_bps for sample in window)
            if best_value is None or value < best_value:
                best_value = value
                best_start = start
        return samples[best_start : best_start + max_steps]
    if mode == "highest-median-downlink":
        best_start = 0
        best_value = None
        for start in range(0, len(samples) - max_steps + 1):
            window = samples[start : start + max_steps]
            value = statistics.median(sample.downlink_bps for sample in window)
            if best_value is None or value > best_value:
                best_value = value
                best_start = start
        return samples[best_start : best_start + max_steps]
    best_start = 0
    best_score = None
    for start in range(0, len(samples) - max_steps + 1):
        window = samples[start : start + max_steps]
        values = [sample.downlink_bps for sample in window]
        mean = statistics.fmean(values)
        spread = statistics.pstdev(values) / mean if mean > 0.0 else 0.0
        score = spread + (max(values) / max(min(values), 1)) / 10.0
        if best_score is None or score > best_score:
            best_score = score
            best_start = start
    return samples[best_start : best_start + max_steps]


def filled_series(samples: list[Sample], attr: str, fallback: float) -> list[float]:
    values: list[float] = []
    last = fallback
    for sample in samples:
        value = getattr(sample, attr)
        if value is not None:
            last = float(value)
        values.append(last)
    return values


def step_duration_ms(current: Sample, next_sample: Sample | None, default_ms: int) -> int:
    if next_sample is None:
        return default_ms
    delta = next_sample.timestamp_ms - current.timestamp_ms
    if delta <= 0:
        return default_ms
    return max(10, min(delta, default_ms * 5))


def effective_uplink_bps(sample: Sample, args: argparse.Namespace) -> int:
    if args.uplink_policy == "measured":
        return max(args.min_bps, sample.uplink_bps)
    return max(args.min_uplink_bps, sample.uplink_bps, int(sample.downlink_bps * args.uplink_ratio))


def build_profile(samples: list[Sample], args: argparse.Namespace, source_path: str) -> dict[str, Any]:
    if not samples:
        raise SystemExit("no usable samples")
    collapsed = collapse_by_second(samples)
    window = select_window(collapsed, args.max_steps, args.window)
    rtts = [sample.rtt_ms for sample in window if sample.rtt_ms is not None and sample.rtt_ms > 0.0]
    jitters = [sample.jitter_ms for sample in window if sample.jitter_ms is not None and sample.jitter_ms >= 0.0]
    losses = [sample.loss_percent for sample in window if sample.loss_percent is not None and sample.loss_percent >= 0.0]
    downlinks = [sample.downlink_bps for sample in window if sample.downlink_bps > 0]
    uplinks = [effective_uplink_bps(sample, args) for sample in window]

    base_rtt_ms = statistics.median(rtts) if rtts else args.default_rtt_ms
    base_jitter_ms = statistics.median(jitters) if jitters else args.default_jitter_ms
    base_loss = statistics.median(losses) if losses else args.default_loss_percent
    rtt_series = filled_series(window, "rtt_ms", base_rtt_ms)
    jitter_series = filled_series(window, "jitter_ms", base_jitter_ms)
    loss_series = filled_series(window, "loss_percent", base_loss)

    trace = []
    previous_cell = window[0].cell_id
    for index, sample in enumerate(window):
        duration = step_duration_ms(sample, window[index + 1] if index + 1 < len(window) else None, args.step_ms)
        downlink = max(args.min_bps, sample.downlink_bps)
        uplink = effective_uplink_bps(sample, args)
        loss = max(0.0, min(100.0, loss_series[index]))
        rtt = max(1.0, rtt_series[index])
        jitter = max(0.0, jitter_series[index])
        cell_changed = previous_cell is not None and sample.cell_id is not None and sample.cell_id != previous_cell
        if cell_changed and args.handover_outage_ms > 0:
            trace.append(
                {
                    "duration_ms": args.handover_outage_ms,
                    "downlink_bps": args.min_bps,
                    "uplink_bps": args.min_bps,
                    "one_way_delay_us": int(max(base_rtt_ms, rtt) * 1000),
                    "one_way_jitter_us": int(max(base_jitter_ms, jitter) * 1000),
                    "loss_percent": 100.0,
                    "queue_bdp": args.handover_queue_bdp,
                    "event": "handover-outage",
                }
            )
        previous_cell = sample.cell_id or previous_cell
        if args.zero_as_outage and sample.downlink_bps <= args.zero_outage_bps:
            loss = max(loss, args.zero_outage_loss_percent)
            downlink = max(args.min_bps, sample.downlink_bps)
            uplink = max(args.min_bps, sample.uplink_bps)
        trace.append(
            {
                "duration_ms": duration,
                "downlink_bps": downlink,
                "uplink_bps": uplink,
                "one_way_delay_us": int(rtt * 500),
                "one_way_jitter_us": int(jitter * 1000),
                "loss_percent": loss,
                "queue_bdp": args.queue_bdp,
            }
        )

    description = args.description or f"Public cellular trace replay derived from {args.source_name}"
    return {
        "kind": "namespace",
        "description": description,
        "source": {
            "name": args.source_name,
            "url": args.source_url,
            "input": source_path,
            "generator": "tools/quicperf_cellular_profiles.py",
            "generated_utc": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "window": args.window,
            "uplink_policy": args.uplink_policy,
            "uplink_ratio": args.uplink_ratio,
            "samples_in_input": len(samples),
            "samples_after_collapse": len(collapsed),
            "samples_in_profile": len(window),
        },
        "one_way_delay_us": int(base_rtt_ms * 500),
        "one_way_jitter_us": int(base_jitter_ms * 1000),
        "jitter_correlation_percent": args.jitter_correlation_percent,
        "loss_percent": base_loss,
        "loss_correlation_percent": args.loss_correlation_percent,
        "downlink_bps": median_int(downlinks, args.min_bps),
        "uplink_bps": median_int(uplinks, args.min_bps),
        "queue_bdp": args.queue_bdp,
        "mtu_bytes": 1500,
        "trace": trace,
    }


def merge_profile(output: Path, name: str, profile: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lock_path = output.with_suffix(output.suffix + ".lock")
    with lock_path.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        payload: dict[str, Any] = {"profiles": {}}
        if output.exists():
            with output.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        profiles = payload.setdefault("profiles", {})
        profiles[name] = profile
        tmp_path = output.with_suffix(output.suffix + f".tmp.{os.getpid()}")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        tmp_path.replace(output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate quicperf cellular-dynamics path profiles from public traces")
    parser.add_argument("--format", choices=("ucc-5g", "ucc-4g", "5gophers", "normalized"), default="ucc-5g")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--member", help="UCC zip member to ingest")
    parser.add_argument("--mobility", default="Driving")
    parser.add_argument("--bitrate-unit", choices=("bps", "kbps", "mbps"), default="kbps")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--name", required=True)
    parser.add_argument("--description")
    parser.add_argument("--source-name")
    parser.add_argument("--source-url")
    parser.add_argument(
        "--window",
        choices=("first", "last", "most-variable", "lowest-median-downlink", "highest-median-downlink"),
        default="most-variable",
    )
    parser.add_argument("--max-steps", type=int, default=90)
    parser.add_argument("--step-ms", type=int, default=1000)
    parser.add_argument("--min-bps", type=int, default=64_000)
    parser.add_argument("--uplink-policy", choices=("ratio", "measured"), default="ratio")
    parser.add_argument("--uplink-ratio", type=float, default=0.20)
    parser.add_argument("--min-uplink-bps", type=int, default=1_000_000)
    parser.add_argument("--default-rtt-ms", type=float, default=40.0)
    parser.add_argument("--default-jitter-ms", type=float, default=5.0)
    parser.add_argument("--default-loss-percent", type=float, default=0.05)
    parser.add_argument("--queue-bdp", type=float, default=1.5)
    parser.add_argument("--jitter-correlation-percent", type=int, default=35)
    parser.add_argument("--loss-correlation-percent", type=int, default=25)
    parser.add_argument("--handover-outage-ms", type=int, default=250)
    parser.add_argument("--handover-queue-bdp", type=float, default=0.25)
    parser.add_argument("--zero-as-outage", action="store_true")
    parser.add_argument("--zero-outage-bps", type=int, default=128_000)
    parser.add_argument("--zero-outage-loss-percent", type=float, default=35.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.input is None:
        if args.format == "ucc-4g":
            args.input = DEFAULT_4G_INPUT
        elif args.format == "5gophers":
            args.input = DEFAULT_5GOPHERS_INPUT
        else:
            args.input = DEFAULT_5G_INPUT
    if args.source_name is None:
        if args.format == "ucc-4g":
            args.source_name = "UCC 4G LTE dataset"
        elif args.format == "5gophers":
            args.source_name = "5Gophers v1.0 dataset"
        else:
            args.source_name = "UCC 5G production dataset"
    if args.source_url is None:
        if args.format == "ucc-4g":
            args.source_url = "https://www.ucc.ie/en/misl/research/datasets/ivid_4g_lte_dataset/"
        elif args.format == "5gophers":
            args.source_url = "https://networking.umn.edu/5gophers"
        else:
            args.source_url = "https://github.com/uccmisl/5Gdataset"
    samples, source_path = load_samples(args)
    profile = build_profile(samples, args, source_path)
    merge_profile(args.output, args.name, profile)
    print(f"quicperf_cellular_profile_generated name={args.name} samples={profile['source']['samples_in_profile']} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
