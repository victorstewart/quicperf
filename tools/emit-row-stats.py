#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path

from quicperf_stats import StatsConfig, format_float, group_samples, load_samples, row_stats


FIELDS = [
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


def emit(samples_path: Path, output_path: Path, cfg: StatsConfig, confirm_cfg: StatsConfig) -> None:
    grouped = group_samples(load_samples(samples_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=FIELDS)
        writer.writeheader()
        for key in sorted(grouped, key=lambda item: (item.binary, item.scenario, item.network, item.path_profile, item.client_threads, item.metric)):
            for phase in ("discovery", "confirm", "combined"):
                if phase == "combined":
                    phase_samples = [sample for sample in grouped[key] if sample.phase in {"discovery", "confirm"}]
                else:
                    phase_samples = [sample for sample in grouped[key] if sample.phase == phase]
                if not phase_samples:
                    continue
                stats = row_stats(phase_samples, confirm_cfg if phase == "confirm" else cfg)
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit row-stats.tsv from adaptive-samples.tsv")
    parser.add_argument("samples", type=Path, help="adaptive-samples.tsv")
    parser.add_argument("-o", "--output", type=Path, default=Path("row-stats.tsv"))
    parser.add_argument("--min-blocks", type=int, default=4)
    parser.add_argument("--min-samples", type=int, default=20)
    parser.add_argument("--max-samples", type=int, default=120)
    parser.add_argument("--bootstrap-iters", type=int, default=5000)
    parser.add_argument("--bootstrap-seed", type=int, default=1)
    parser.add_argument("--block-size", type=int, default=5)
    parser.add_argument("--confirm-blocks", type=int, default=2)
    parser.add_argument("--confirm-samples", type=int, default=10)
    args = parser.parse_args()
    cfg = StatsConfig(
        min_blocks=args.min_blocks,
        min_samples=args.min_samples,
        max_samples=args.max_samples,
        bootstrap_iters=args.bootstrap_iters,
        bootstrap_seed=args.bootstrap_seed,
    )
    confirm_cfg = StatsConfig(
        min_blocks=max(1, args.confirm_blocks),
        min_samples=args.confirm_samples,
        confirm_min_samples=args.confirm_samples,
        max_samples=max(args.confirm_samples, args.confirm_blocks * args.block_size),
        bootstrap_iters=args.bootstrap_iters,
        bootstrap_seed=args.bootstrap_seed + 17,
    )
    emit(
        args.samples,
        args.output,
        cfg,
        confirm_cfg,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
