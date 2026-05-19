#!/usr/bin/env python3
import argparse
import csv
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from quicperf_stats import bad_tail_quantile, parse_client_log_samples, quantile


@dataclass
class CombinedRow:
    binary: str
    scenario: str
    network: str
    path_profile: str
    threads: int
    status: str
    reason: str
    metric: str = ""
    samples: int = 0
    min_value: float = 0.0
    p50: float = 0.0
    p90: float = 0.0
    p99: float = 0.0
    max_value: float = 0.0
    spread_ratio: float = 0.0
    out_dir: str = ""


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def fnum(row: dict[str, str], key: str) -> float:
    try:
        return float(row.get(key, "0") or "0")
    except ValueError:
        return 0.0


def relative_to_root(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def resolve_out_dir(repo_root: Path, row: dict[str, str]) -> Path | None:
    raw = row.get("out_dir", "")
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = repo_root / path
    return path


def raw_values(out_dir: Path, expected_metric: str) -> list[float]:
    values = []
    if not out_dir.exists():
        return values
    for path in sorted(out_dir.glob("*.client.log")):
        if ".warmup." in path.name:
            continue
        for sample in parse_client_log_samples(path):
            if sample.metric == expected_metric and sample.value is not None:
                values.append(sample.value)
    return values


def link_client_logs(source: Path, target: Path, label: str) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for index, path in enumerate(sorted(source.glob("*.client.log")), start=1):
        if ".warmup." in path.name:
            continue
        destination = target / f"{label}.{index:04d}.{path.name}"
        if destination.exists():
            continue
        try:
            os.link(path, destination)
        except OSError:
            try:
                destination.symlink_to(path.resolve())
            except OSError:
                shutil.copy2(path, destination)


def row_sort_key(row: CombinedRow) -> tuple[str, str, str, str, int]:
    return (row.binary, row.scenario, row.network, row.path_profile, row.threads)


def incremental_plateau_reason(previous: CombinedRow | None, row: CombinedRow, min_improvement: float) -> str:
    if previous is None or row.status != "ok" or previous.p50 <= 0.0:
        return ""
    improvement = (row.p50 / previous.p50) - 1.0
    if improvement > min_improvement:
        return ""
    return f"incremental_improvement_{improvement * 100.0:.2f}pct_le_{min_improvement * 100.0:.2f}pct"


def normalize_group(group: list[CombinedRow], min_improvement: float) -> list[CombinedRow]:
    normalized = []
    previous_ok: CombinedRow | None = None
    stopped = False
    for source in sorted(group, key=lambda row: row.threads):
        row = CombinedRow(**source.__dict__)
        if stopped:
            if row.status == "ok":
                row.status = "plateau"
                row.reason = "lower_thread_count_plateau"
            normalized.append(row)
            continue
        if row.status == "ok":
            reason = incremental_plateau_reason(previous_ok, row, min_improvement)
            if reason:
                row.status = "plateau"
                row.reason = reason
                stopped = True
            else:
                previous_ok = row
        elif row.status == "plateau":
            stopped = True
        normalized.append(row)
    return normalized


def selected_row(group: list[CombinedRow], tolerance: float) -> tuple[str, CombinedRow | None, CombinedRow | None, str, CombinedRow | None]:
    ok = [row for row in group if row.status == "ok"]
    if not ok:
        reason = next((row.reason for row in group if row.status != "ok"), "no_successful_rows")
        status = "failed" if any(row.status == "failed" for row in group) else "unsupported"
        boundary = next((row for row in group if row.status != "ok"), None)
        return status, None, None, reason, boundary

    first_ok_index = next(index for index, row in enumerate(group) if row.status == "ok")
    lower_blocked = next((row for row in group[:first_ok_index] if row.status not in ("ok", "plateau")), None)
    curve: list[CombinedRow] = []
    for row in group[first_ok_index:]:
        if row.status == "ok":
            curve.append(row)
            continue
        if row.status == "plateau" and row.p50 > 0.0:
            curve.append(row)
        break

    best = max(curve, key=lambda row: row.p50)
    threshold = best.p50 * (1.0 - tolerance)
    selected = next(row for row in sorted(curve, key=lambda row: row.threads) if row.p50 >= threshold)
    last_ok_threads = max(row.threads for row in ok)
    boundary = next((row for row in group if row.threads > last_ok_threads and row.status != "ok"), None)

    if lower_blocked:
        reason = f"lower_thread_count_{lower_blocked.status}"
        if lower_blocked.reason:
            reason += f"_{lower_blocked.reason}"
        return "bounded", selected, best, reason, lower_blocked
    if boundary and boundary.status == "plateau":
        return "plateau", selected, best, boundary.reason, boundary
    if boundary:
        return "bounded", selected, best, boundary.reason, boundary
    if best.threads == max(row.threads for row in group) and len(ok) > 1:
        return "edge", selected, best, "best_at_max_thread_count", None
    return "ok", selected, best, "", None


def combine_rows(repo_root: Path, combined_root: Path, sweep_dirs: list[Path]) -> list[CombinedRow]:
    grouped: dict[tuple[str, str, str, str, int], list[tuple[Path, dict[str, str]]]] = {}
    for sweep_dir in sweep_dirs:
        samples_path = sweep_dir / "saturation-samples.tsv"
        if not samples_path.exists():
            continue
        for row in read_rows(samples_path):
            try:
                key = (row["binary"], row["scenario"], row["network"], row.get("path_profile", "loopback") or "loopback", int(row["threads"]))
            except (KeyError, ValueError):
                continue
            grouped.setdefault(key, []).append((sweep_dir, row))

    combined_rows = []
    for key, source_rows in sorted(grouped.items()):
        binary, scenario, network, path_profile, threads = key
        metric = next((row.get("metric", "") for _, row in source_rows if row.get("metric")), "")
        target_dir = combined_root / f"{binary}-{scenario}-{network}-{path_profile}-t{threads}"
        values: list[float] = []
        source_statuses = []
        source_reasons = []
        for sweep_dir, row in source_rows:
            status = row.get("status", "")
            source_statuses.append(status)
            if row.get("reason"):
                source_reasons.append(row["reason"])
            if status not in ("ok", "plateau") or fnum(row, "samples") <= 0 or not metric:
                continue
            out_dir = resolve_out_dir(repo_root, row)
            if not out_dir:
                continue
            label = sweep_dir.name
            values.extend(raw_values(out_dir, metric))
            link_client_logs(out_dir, target_dir, label)

        if values:
            values.sort()
            min_value = values[0]
            max_value = values[-1]
            combined_rows.append(CombinedRow(
                binary=binary,
                scenario=scenario,
                network=network,
                path_profile=path_profile,
                threads=threads,
                status="ok",
                reason="",
                metric=metric,
                samples=len(values),
                min_value=min_value,
                p50=quantile(values, 0.50),
                p90=bad_tail_quantile(values, 0.90, metric),
                p99=bad_tail_quantile(values, 0.99, metric),
                max_value=max_value,
                spread_ratio=(max_value / min_value) if min_value > 0.0 else 0.0,
                out_dir=relative_to_root(repo_root, target_dir),
            ))
            continue

        if any(status == "failed" for status in source_statuses):
            status = "failed"
        elif any(status == "blocked" for status in source_statuses):
            status = "blocked"
        elif any(status == "unsupported" for status in source_statuses):
            status = "unsupported"
        else:
            status = "plateau"
        reason = next((item for item in source_reasons if item), f"combined_no_samples_{status}")
        combined_rows.append(CombinedRow(binary, scenario, network, path_profile, threads, status, reason, metric=metric))
    return combined_rows


def write_samples(path: Path, rows: list[CombinedRow]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow(["binary", "scenario", "network", "path_profile", "threads", "status", "reason", "metric", "samples", "min", "p50", "p90", "p99", "max", "spread_ratio", "out_dir"])
        for row in sorted(rows, key=row_sort_key):
            writer.writerow([
                row.binary,
                row.scenario,
                row.network,
                row.path_profile,
                row.threads,
                row.status,
                row.reason,
                row.metric,
                row.samples,
                f"{row.min_value:.6f}",
                f"{row.p50:.6f}",
                f"{row.p90:.6f}",
                f"{row.p99:.6f}",
                f"{row.max_value:.6f}",
                f"{row.spread_ratio:.6f}",
                row.out_dir,
            ])


def write_summary(path: Path, rows: list[CombinedRow], tolerance: float) -> None:
    groups: dict[tuple[str, str, str, str], list[CombinedRow]] = {}
    for row in rows:
        groups.setdefault((row.binary, row.scenario, row.network, row.path_profile), []).append(row)

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow([
            "binary",
            "scenario",
            "network",
            "path_profile",
            "status",
            "metric",
            "selected_threads",
            "selected_samples",
            "selected_min",
            "selected_p50",
            "selected_p90",
            "selected_p99",
            "selected_max",
            "selected_spread_ratio",
            "best_threads",
            "best_p50",
            "boundary_threads",
            "boundary_status",
            "boundary_reason",
            "reason",
        ])
        for key in sorted(groups):
            status, selected, best, reason, boundary = selected_row(sorted(groups[key], key=lambda row: row.threads), tolerance)
            boundary_threads = boundary.threads if boundary else ""
            boundary_status = boundary.status if boundary else ""
            boundary_reason = boundary.reason if boundary else ""
            if selected and best:
                writer.writerow([
                    *key,
                    status,
                    selected.metric,
                    selected.threads,
                    selected.samples,
                    f"{selected.min_value:.6f}",
                    f"{selected.p50:.6f}",
                    f"{selected.p90:.6f}",
                    f"{selected.p99:.6f}",
                    f"{selected.max_value:.6f}",
                    f"{selected.spread_ratio:.6f}",
                    best.threads,
                    f"{best.p50:.6f}",
                    boundary_threads,
                    boundary_status,
                    boundary_reason,
                    reason,
                ])
            else:
                writer.writerow([
                    *key,
                    status,
                    best.metric if best else "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    best.threads if best else "",
                    f"{best.p50:.6f}" if best else "",
                    boundary_threads,
                    boundary_status,
                    boundary_reason,
                    reason,
                ])


def write_environment(repo_root: Path, combined_root: Path, sweep_dirs: list[Path]) -> None:
    with (combined_root / "sweep-environment.txt").open("w", encoding="utf-8") as handle:
        handle.write(f"quicperf_combined_environment date_utc={datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        handle.write("quicperf_combined_environment source_sweeps\n")
        for sweep_dir in sweep_dirs:
            handle.write(f"{relative_to_root(repo_root, sweep_dir)}\n")
        handle.write("quicperf_combined_environment variables\n")
        for key, value in sorted(os.environ.items()):
            if key.startswith("QUICPERF_"):
                handle.write(f"{key}={value}\n")
        for command in (["git", "rev-parse", "HEAD"], ["git", "status", "--short"]):
            completed = subprocess.run(command, cwd=repo_root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
            handle.write(f"quicperf_combined_environment command={' '.join(command)}\n")
            handle.write(completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("combined_root", type=Path)
    parser.add_argument("sweep", nargs="+", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    combined_root = args.combined_root
    if not combined_root.is_absolute():
        combined_root = repo_root / combined_root
    if combined_root.exists():
        if not args.force:
            print(f"combined output already exists: {combined_root}", file=sys.stderr)
            return 2
        shutil.rmtree(combined_root)
    combined_root.mkdir(parents=True, exist_ok=True)

    sweep_dirs = []
    for sweep in args.sweep:
        path = sweep if sweep.is_absolute() else repo_root / sweep
        if not (path / "saturation-samples.tsv").exists():
            print(f"missing saturation samples: {path}", file=sys.stderr)
            return 2
        sweep_dirs.append(path)

    min_improvement = float(os.environ.get("QUICPERF_SATURATION_MIN_INCREMENTAL_IMPROVEMENT", "0.01"))
    tolerance = float(os.environ.get("QUICPERF_SATURATION_TOLERANCE", "0.01"))
    rows = combine_rows(repo_root, combined_root, sweep_dirs)

    groups: dict[tuple[str, str, str, str], list[CombinedRow]] = {}
    for row in rows:
        groups.setdefault((row.binary, row.scenario, row.network, row.path_profile), []).append(row)
    normalized = []
    for group in groups.values():
        normalized.extend(normalize_group(group, min_improvement))

    write_samples(combined_root / "saturation-samples.tsv", normalized)
    write_summary(combined_root / "saturation-summary.tsv", normalized, tolerance)
    write_environment(repo_root, combined_root, sweep_dirs)
    print(f"combined_saturation_samples path={combined_root / 'saturation-samples.tsv'} sweeps={len(sweep_dirs)} rows={len(normalized)}")
    print(f"combined_saturation_summary path={combined_root / 'saturation-summary.tsv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
