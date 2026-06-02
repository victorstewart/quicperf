#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import importlib.util
import os
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from quicperf_fixed_design import (
    PlanRow,
    default_timeout_sec,
    fixed_schedule,
    fixed_status,
    format_status_row,
    load_plan,
    row_stats_config,
    target_env,
    write_environment_file,
)
from quicperf_stats import RowKey, Sample, compare_rows, format_float, group_samples, load_samples, row_stats, scenario_metric_name, write_samples


def load_adaptive_module(root: Path):
    path = root / "tools" / "run-adaptive-publication-suite.py"
    spec = importlib.util.spec_from_file_location("run_adaptive_publication_suite", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def verify_binaries(root: Path, rows: list[PlanRow]) -> list[str]:
    bin_dir = Path(os.environ.get("QUICPERF_BIN_DIR", root / "build" / "bin"))
    missing = []
    for binary in sorted({row.binary for row in rows if row.status == "ok"}):
        path = Path(binary) if "/" in binary else bin_dir / binary
        if not path.is_file() or not os.access(path, os.X_OK):
            missing.append(binary)
    return missing

def samples_for_plan(samples: list[Sample], row: PlanRow) -> list[Sample]:
    return [
        sample
        for sample in samples
        if sample.binary == row.binary
        and sample.scenario == row.scenario
        and sample.network == row.network
        and sample.path_profile == row.path_profile
        and sample.client_threads == row.client_threads
        and sample.phase == "publication"
    ]


def write_fixed_tables(out_root: Path, rows: list[PlanRow], samples: list[Sample], bootstrap_iters: int, seed: int) -> list[dict[str, str]]:
    row_stats_path = out_root / "row-stats.tsv"
    audit_path = out_root / "publication-row-audit.tsv"
    results_path = out_root / "publication-results.tsv"
    fields = [
        "binary",
        "scenario",
        "network",
        "path_profile",
        "client_threads",
        "metric",
        "mode",
        "duration_ms",
        "work_units",
        "samples",
        "blocks",
        "p50",
        "p50_ci95_low",
        "p50_ci95_high",
        "p50_ci95_relative_width",
        "p20",
        "p80",
        "p20_p80_ratio",
        "p90",
        "p99",
        "p99_status",
        "block_median_ratio",
        "drift_relative",
        "outlier_count",
        "measurement_status",
        "audit_status",
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
        "measurement_status",
        "audit_status",
        "publication_status",
        "metric",
        "selected_threads",
        "mode",
        "duration_ms",
        "work_units",
        "samples",
        "blocks",
        "p50",
        "p50_ci95_low",
        "p50_ci95_high",
        "p50_ci95_relative_width",
        "p90",
        "p99",
        "p99_status",
        "reason",
    ]
    grouped = group_samples(samples)
    result_rows: list[dict[str, str]] = []
    stats_by_key: dict[RowKey, list[Sample]] = defaultdict(list)
    with row_stats_path.open("w", encoding="utf-8", newline="") as stats_handle, audit_path.open("w", encoding="utf-8", newline="") as audit_handle:
        stats_writer = csv.DictWriter(stats_handle, delimiter="\t", fieldnames=fields)
        audit_writer = csv.DictWriter(audit_handle, delimiter="\t", fieldnames=fields)
        stats_writer.writeheader()
        audit_writer.writeheader()
        for index, plan_row in enumerate(rows):
            row_samples = samples_for_plan(samples, plan_row)
            cfg = row_stats_config(plan_row, bootstrap_iters, seed + index)
            stats = row_stats(row_samples, cfg)
            if plan_row.status != "ok":
                measurement_status = "unsupported" if plan_row.status == "unsupported" else "failed"
                audit_status = "clean"
                publication_status = measurement_status
                reason = plan_row.reason or plan_row.status
            else:
                measurement_status, audit_status, publication_status, reason = fixed_status(row_samples, stats, plan_row.samples)
            status_row = format_status_row(plan_row, stats, measurement_status, audit_status, publication_status, reason)
            stats_writer.writerow(status_row)
            audit_writer.writerow(status_row)
            metric = next((sample.metric for sample in row_samples if sample.metric), scenario_metric_name(plan_row.scenario))
            key = RowKey(plan_row.binary, plan_row.scenario, plan_row.network, plan_row.path_profile, plan_row.client_threads, metric)
            stats_by_key[key] = row_samples
            adapter_features = next((sample.adapter_features for sample in row_samples if sample.adapter_features), "")
            cc = ""
            for item in adapter_features.split("|"):
                if item.startswith("cc="):
                    cc = item[3:]
            result_rows.append({
                "binary": plan_row.binary,
                "scenario": plan_row.scenario,
                "network": plan_row.network,
                "path_profile": plan_row.path_profile,
                "adapter_features": adapter_features,
                "congestion_controller": cc,
                "measurement_status": measurement_status,
                "audit_status": audit_status,
                "publication_status": publication_status,
                "metric": metric,
                "selected_threads": str(plan_row.client_threads),
                "mode": plan_row.mode,
                "duration_ms": str(plan_row.duration_ms or ""),
                "work_units": str(plan_row.work_units or ""),
                "samples": str(stats.n),
                "blocks": str(stats.blocks),
                "p50": format_float(stats.median),
                "p50_ci95_low": format_float(stats.ci95_low),
                "p50_ci95_high": format_float(stats.ci95_high),
                "p50_ci95_relative_width": format_float(stats.ci95_rel_width),
                "p90": format_float(stats.p90),
                "p99": format_float(stats.p99),
                "p99_status": stats.p99_status,
                "reason": reason,
            })
    with results_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=result_fields)
        writer.writeheader()
        writer.writerows(result_rows)
    write_pairwise(out_root / "pairwise-comparisons.tsv", result_rows, grouped, bootstrap_iters, seed)
    return result_rows


def write_pairwise(path: Path, rows: list[dict[str, str]], grouped: dict[RowKey, list[Sample]], bootstrap_iters: int, seed: int) -> None:
    fields = ["scenario", "network", "path_profile", "metric", "binary_a", "binary_b", "a_p50", "b_p50", "a_vs_b_median_ratio", "a_vs_b_ci95_low", "a_vs_b_ci95_high", "relation"]
    selected = [row for row in rows if row.get("publication_status") == "publishable" and row.get("metric")]
    by_group: dict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in selected:
        by_group[(row["scenario"], row["network"], row["path_profile"], row["metric"])].append(row)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=fields)
        writer.writeheader()
        for group, group_rows in sorted(by_group.items()):
            ordered = sorted(group_rows, key=lambda row: row["binary"])
            for index, a in enumerate(ordered):
                for b in ordered[index + 1:]:
                    a_key = RowKey(a["binary"], a["scenario"], a["network"], a["path_profile"], int(a["selected_threads"]), a["metric"])
                    b_key = RowKey(b["binary"], b["scenario"], b["network"], b["path_profile"], int(b["selected_threads"]), b["metric"])
                    stats = compare_rows(grouped.get(a_key, []), grouped.get(b_key, []))
                    writer.writerow({
                        "scenario": group[0],
                        "network": group[1],
                        "path_profile": group[2],
                        "metric": group[3],
                        "binary_a": a["binary"],
                        "binary_b": b["binary"],
                        "a_p50": format_float(stats.a_median),
                        "b_p50": format_float(stats.b_median),
                        "a_vs_b_median_ratio": format_float(stats.median_ratio),
                        "a_vs_b_ci95_low": format_float(stats.ci95_low),
                        "a_vs_b_ci95_high": format_float(stats.ci95_high),
                        "relation": stats.relation,
                    })


def write_summary(path: Path, publication_id: str, rows: list[dict[str, str]], samples_path: Path) -> None:
    publishable = sum(1 for row in rows if row.get("publication_status") == "publishable")
    inconclusive = sum(1 for row in rows if row.get("publication_status") == "inconclusive")
    failed = sum(1 for row in rows if row.get("publication_status") == "failed")
    unsupported = sum(1 for row in rows if row.get("publication_status") == "unsupported")
    with path.open("w", encoding="utf-8") as handle:
        handle.write("# Fixed Publication Run\n\n")
        handle.write(f"- Publication ID: `{publication_id}`\n")
        handle.write(f"- Samples: `{samples_path.name}`\n")
        handle.write(f"- Publishable rows: {publishable}\n")
        handle.write(f"- Inconclusive rows: {inconclusive}\n")
        handle.write(f"- Failed rows: {failed}\n")
        handle.write(f"- Unsupported rows: {unsupported}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a fixed-design quicperf publication plan.")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--publication-id", default=os.environ.get("QUICPERF_PUBLICATION_ID", ""))
    parser.add_argument("--random-seed", type=int, default=int(os.environ.get("QUICPERF_RANDOM_SEED", str(os.getpid()))))
    parser.add_argument("--bootstrap-iters", type=int, default=int(os.environ.get("QUICPERF_FIXED_BOOTSTRAP_ITERS", "5000")))
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    adaptive = load_adaptive_module(root)
    publication_id = args.publication_id or f"fixed-{utc_stamp()}-{os.getpid()}"
    out_root = args.out_dir or Path(os.environ.get("QUICPERF_FIXED_OUT_DIR", root / ".run" / publication_id))
    out_root.mkdir(parents=True, exist_ok=True)

    rows = load_plan(args.plan)
    shutil.copyfile(args.plan, out_root / "benchmark-plan.tsv")
    missing = verify_binaries(root, rows)
    if missing:
        print(f"quicperf_fixed_preflight status=failed reason=missing_binaries binaries=\"{' '.join(missing)}\"")
        return 2

    samples_path = out_root / "adaptive-samples.tsv"
    write_samples(samples_path, [], append=False)
    commit = adaptive.git_commit(root)
    env_sig = adaptive.env_hash()
    machine_sig = adaptive.machine_hash()
    write_environment_file(
        root,
        out_root / "fixed-environment.txt",
        label="fixed",
        run_id=publication_id,
        commit=commit,
        env_sig=env_sig,
        machine_sig=machine_sig,
    )

    schedule = fixed_schedule(rows, args.random_seed)
    with (out_root / "fixed-schedule.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow(["order", "block", "binary", "scenario", "network", "path_profile", "client_threads", "repeat", "warmup", "mode", "duration_ms", "work_units"])
        for item in schedule:
            writer.writerow([item.order, item.block_index, item.row.binary, item.row.scenario, item.row.network, item.row.path_profile, item.row.client_threads, item.repeat, item.warmup, item.row.mode, item.row.duration_ms, item.row.work_units])

    cfg = adaptive.load_config()
    block_ordinal = 0
    print(f"quicperf_fixed_run out_dir={out_root} rows={len(rows)} scheduled_blocks={len(schedule)} random_seed={args.random_seed}")
    for item in schedule:
        block_ordinal += 1
        target = adaptive.Target(item.row.binary, item.row.scenario, item.row.network, item.row.path_profile, item.row.client_threads)
        result = adaptive.run_block(
            root,
            out_root,
            samples_path,
            target,
            phase="publication",
            round_index=item.block_index,
            block_ordinal=block_ordinal,
            cfg=cfg,
            publication_id=publication_id,
            commit=commit,
            env_sig=env_sig,
            machine_sig=machine_sig,
            warmup=item.warmup,
            repeat=item.repeat,
            env_overrides=target_env(item.row),
            timeout_sec=default_timeout_sec(item.row),
        )
        print(
            "quicperf_fixed_block "
            f"order={item.order} block={item.block_index} target={target} "
            f"status={result.status} reason={result.reason or '-'}"
        )

    samples = load_samples(samples_path)
    result_rows = write_fixed_tables(out_root, rows, samples, args.bootstrap_iters, args.random_seed)
    write_summary(out_root / "fixed-run-summary.md", publication_id, result_rows, samples_path)
    failed = sum(1 for row in result_rows if row.get("publication_status") == "failed")
    print(f"quicperf_fixed_summary path={out_root / 'fixed-run-summary.md'} failed_rows={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
