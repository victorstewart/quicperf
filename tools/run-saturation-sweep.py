#!/usr/bin/env python3
import csv
import os
import random
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class SweepRow:
    binary: str
    scenario: str
    network: str
    path_profile: str
    threads: int
    status: str
    reason: str
    metric: str = ""
    p50: float = 0.0
    p90: float = 0.0
    p99: float = 0.0
    samples: int = 0
    min_value: float = 0.0
    max_value: float = 0.0
    spread_ratio: float = 0.0
    out_dir: str = ""


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


def binaries(root: Path) -> list[str]:
    configured = os.environ.get("QUICPERF_BINARIES")
    if configured:
        return unique_preserve(split_words(configured))
    bin_dir = Path(os.environ.get("QUICPERF_BIN_DIR", root / "build" / "bin"))
    return sorted(path.name for path in bin_dir.glob("*perf") if os.access(path, os.X_OK))


def parse_summary(path: Path) -> dict[str, str] | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for row in reader:
            return row
    return None


def load_existing_samples(path: Path) -> dict[tuple[str, str, str, str, int], SweepRow]:
    rows: dict[tuple[str, str, str, str, int], SweepRow] = {}
    if not path.exists():
        return rows

    with path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for row in reader:
            try:
                threads = int(row["threads"])
                p50 = float(row.get("p50", "0") or "0")
                p90 = float(row.get("p90", "0") or "0")
                p99 = float(row.get("p99", "0") or "0")
                samples = int(row.get("samples", "0") or "0")
                min_value = float(row.get("min", "0") or "0")
                max_value = float(row.get("max", "0") or "0")
                spread_ratio = float(row.get("spread_ratio", "0") or "0")
            except (KeyError, ValueError):
                continue
            sample = SweepRow(
                binary=row.get("binary", ""),
                scenario=row.get("scenario", ""),
                network=row.get("network", ""),
                path_profile=row.get("path_profile", "loopback") or "loopback",
                threads=threads,
                status=row.get("status", ""),
                reason=row.get("reason", ""),
                metric=row.get("metric", ""),
                p50=p50,
                p90=p90,
                p99=p99,
                samples=samples,
                min_value=min_value,
                max_value=max_value,
                spread_ratio=spread_ratio,
                out_dir=row.get("out_dir", ""),
            )
            rows[(sample.binary, sample.scenario, sample.network, sample.path_profile, sample.threads)] = sample
    return rows


def unsupported_reason(output: str) -> str:
    match = re.search(r"status=unsupported reason=(\S+)", output)
    return match.group(1) if match else ""


def failure_reason(output: str, returncode: int) -> str:
    match = re.search(r"quicperf_run_result .* status=(client_failed|server_failed|thread_check_failed)(?:\s|$)", output)
    if match:
        return match.group(1)
    if "quicperf_outlier_gate status=failed" in output:
        return "outlier_gate_failed"
    if returncode != 0:
        return f"exit_{returncode}"
    return ""


def incremental_plateau_reason(previous: SweepRow | None, row: SweepRow, min_improvement: float) -> str:
    if previous is None or row.status != "ok" or previous.p50 <= 0.0:
        return ""
    improvement = (row.p50 / previous.p50) - 1.0
    if improvement > min_improvement:
        return ""
    return f"incremental_improvement_{improvement * 100.0:.2f}pct_le_{min_improvement * 100.0:.2f}pct"


def run_one(root: Path, sweep_root: Path, binary: str, scenario: str, network: str, path_profile: str, threads: int) -> SweepRow:
    out_dir = sweep_root / f"{binary}-{scenario}-{network}-{path_profile}-t{threads}"
    env = os.environ.copy()
    env.update(
        {
            "QUICPERF_BINARIES": binary,
            "QUICPERF_SCENARIOS": scenario,
            "QUICPERF_NETWORKS": network,
            "QUICPERF_PATH_PROFILES": path_profile,
            "QUICPERF_CLIENT_THREADS": str(threads),
            "QUICPERF_SERVER_CONNECTIONS": str(threads),
            "QUICPERF_REPEAT": env.get("QUICPERF_SATURATION_REPEAT", env.get("QUICPERF_REPEAT", "3")),
            "QUICPERF_WARMUP": env.get("QUICPERF_SATURATION_WARMUP", env.get("QUICPERF_WARMUP", "1")),
            "QUICPERF_RANDOMIZE_ORDER": env.get("QUICPERF_SATURATION_RANDOMIZE_ORDER", env.get("QUICPERF_RANDOMIZE_ORDER", "1")),
            "QUICPERF_OUT_DIR": str(out_dir),
        }
    )
    env[f"QUICPERF_{scenario.upper()}_CLIENT_THREADS"] = str(threads)
    completed = subprocess.run(
        [str(root / "tools" / "run-benchmarks.sh")],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    (out_dir / "sweep.stdout").write_text(completed.stdout, encoding="utf-8")

    row = parse_summary(out_dir / "summary.tsv")
    if row:
        reason = failure_reason(completed.stdout, completed.returncode)
        expected_samples = int(env["QUICPERF_REPEAT"])
        actual_samples = int(row.get("samples", "0"))
        if not reason and actual_samples != expected_samples:
            reason = f"incomplete_samples_{actual_samples}_of_{expected_samples}"
        return SweepRow(
            binary=binary,
            scenario=scenario,
            network=network,
            path_profile=row.get("path_profile", path_profile) or path_profile,
            threads=threads,
            status="failed" if reason else "ok",
            reason=reason,
            metric=row["metric"],
            p50=float(row["p50"]),
            p90=float(row["p90"]),
            p99=float(row["p99"]),
            samples=actual_samples,
            min_value=float(row.get("min", "0") or "0"),
            max_value=float(row.get("max", "0") or "0"),
            spread_ratio=(float(row.get("max", "0") or "0") / float(row.get("min", "0") or "0")) if float(row.get("min", "0") or "0") > 0.0 else 0.0,
            out_dir=str(out_dir),
        )

    reason = unsupported_reason(completed.stdout)
    if reason:
        return SweepRow(binary, scenario, network, path_profile, threads, "unsupported", reason, out_dir=str(out_dir))
    reason = failure_reason(completed.stdout, completed.returncode)
    return SweepRow(binary, scenario, network, path_profile, threads, "failed", reason or f"exit_{completed.returncode}", out_dir=str(out_dir))


def selected_row(rows: list[SweepRow], tolerance: float) -> tuple[str, SweepRow | None, SweepRow | None, str, SweepRow | None]:
    ok = [row for row in rows if row.status == "ok"]
    if not ok:
        reason = next((row.reason for row in rows if row.status != "ok"), "no_successful_rows")
        status = "failed" if any(row.status == "failed" for row in rows) else "unsupported"
        boundary = next((row for row in rows if row.status != "ok"), None)
        return status, None, None, reason, boundary

    first_ok_index = next(index for index, row in enumerate(rows) if row.status == "ok")
    lower_blocked = next((row for row in rows[:first_ok_index] if row.status not in ("ok", "plateau")), None)
    curve: list[SweepRow] = []
    for row in rows[first_ok_index:]:
        if row.status == "ok":
            curve.append(row)
            continue
        if row.status == "plateau" and row.p50 > 0.0:
            curve.append(row)
        break
    best = max(curve, key=lambda row: row.p50)
    threshold = best.p50 * (1.0 - tolerance)
    selected = next(row for row in sorted(curve, key=lambda row: row.threads) if row.p50 >= threshold)
    plateau = [
        row for row in rows
        if row.status == "plateau" and row.threads > max(ok_row.threads for ok_row in ok)
    ]
    if lower_blocked:
        reason = f"lower_thread_count_{lower_blocked.status}"
        if lower_blocked.reason:
            reason += f"_{lower_blocked.reason}"
        return "bounded", selected, best, reason, lower_blocked
    if plateau:
        return "plateau", selected, best, plateau[0].reason, plateau[0]
    blocked = [
        row for row in rows
        if row.status not in ("ok", "plateau") and row.threads > max(ok_row.threads for ok_row in ok)
    ]
    if blocked:
        return "bounded", selected, best, blocked[0].reason, blocked[0]
    if best.threads == max(row.threads for row in rows) and len(ok) > 1:
        return "edge", selected, best, "best_at_max_thread_count", None
    return "ok", selected, best, "", None


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    sweep_root = Path(os.environ.get("QUICPERF_SATURATION_OUT_DIR", root / ".run" / f"quicperf-saturation-{stamp}-{os.getpid()}"))
    sweep_root.mkdir(parents=True, exist_ok=True)

    thread_counts = [int(item) for item in split_words(os.environ.get("QUICPERF_SATURATION_THREADS", "1 2 4 8"))]
    scenarios = unique_preserve(split_words(os.environ.get("QUICPERF_SATURATION_SCENARIOS", os.environ.get("QUICPERF_SCENARIOS", "download upload connect"))))
    networks = unique_preserve(split_words(os.environ.get("QUICPERF_SATURATION_NETWORKS", os.environ.get("QUICPERF_NETWORKS", "syscall"))))
    path_profiles = unique_preserve(split_words(os.environ.get("QUICPERF_SATURATION_PATH_PROFILES", os.environ.get("QUICPERF_PATH_PROFILES", os.environ.get("QUICPERF_PATH_PROFILE", "loopback")))))
    tolerance = float(os.environ.get("QUICPERF_SATURATION_TOLERANCE", "0.01"))
    min_incremental_improvement = float(os.environ.get("QUICPERF_SATURATION_MIN_INCREMENTAL_IMPROVEMENT", "0.01"))
    stop_after_blocked = os.environ.get("QUICPERF_SATURATION_STOP_AFTER_BLOCKED", "0") == "1"
    max_pre_ok_failures = int(os.environ.get("QUICPERF_SATURATION_MAX_PRE_OK_FAILURES", "0"))
    resume = os.environ.get("QUICPERF_SATURATION_RESUME", "0") == "1"
    randomize_groups = os.environ.get("QUICPERF_SATURATION_RANDOMIZE_GROUPS", "1") == "1"
    random_seed = int(os.environ.get("QUICPERF_RANDOM_SEED", str(os.getpid())))
    selected_binaries = binaries(root)

    group_order = [
        (binary, scenario, network, path_profile)
        for binary in selected_binaries
        for scenario in scenarios
        for network in networks
        for path_profile in path_profiles
    ]
    if randomize_groups:
        random.Random(random_seed).shuffle(group_order)

    environment_path = sweep_root / "sweep-environment.txt"
    with environment_path.open("w", encoding="utf-8") as handle:
        handle.write(f"quicperf_saturation_environment date_utc={datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        handle.write(f"quicperf_saturation_environment randomize_groups={int(randomize_groups)} random_seed={random_seed}\n")
        handle.write("quicperf_saturation_environment variables\n")
        for key, value in sorted(os.environ.items()):
            if key.startswith("QUICPERF_"):
                handle.write(f"{key}={value}\n")
        for command in (["git", "rev-parse", "HEAD"], ["git", "status", "--short"]):
            try:
                completed = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
                handle.write(f"quicperf_saturation_environment command={' '.join(command)}\n")
                handle.write(completed.stdout)
            except OSError as exc:
                handle.write(f"quicperf_saturation_environment command_failed={' '.join(command)} error={exc}\n")

    print(
        "quicperf_saturation_run "
        f"out_dir={sweep_root} binaries=\"{' '.join(selected_binaries)}\" "
        f"scenarios=\"{' '.join(scenarios)}\" networks=\"{' '.join(networks)}\" path_profiles=\"{' '.join(path_profiles)}\" "
        f"threads=\"{' '.join(str(t) for t in thread_counts)}\" tolerance={tolerance:.3f} "
        f"min_incremental_improvement={min_incremental_improvement:.3f} "
        f"max_pre_ok_failures={max_pre_ok_failures} "
        f"randomize_groups={int(randomize_groups)} random_seed={random_seed}"
    )

    selections: list[tuple[str, str, str, str, str, SweepRow | None, SweepRow | None, str, SweepRow | None]] = []

    samples_path = sweep_root / "saturation-samples.tsv"
    existing_rows = load_existing_samples(samples_path) if resume else {}
    write_header = not resume or not samples_path.exists() or samples_path.stat().st_size == 0
    mode = "a" if resume and samples_path.exists() else "w"
    with samples_path.open(mode, encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        if write_header:
            writer.writerow(["binary", "scenario", "network", "path_profile", "threads", "status", "reason", "metric", "samples", "min", "p50", "p90", "p99", "max", "spread_ratio", "out_dir"])
        handle.flush()
        for binary, scenario, network, path_profile in group_order:
            group: list[SweepRow] = []
            stop_after_unsupported = False
            stop_after_failed = False
            stop_after_plateau = False
            pre_ok_failures = 0
            for threads in thread_counts:
                write_sample = False
                if stop_after_unsupported:
                    row = SweepRow(binary, scenario, network, path_profile, threads, "unsupported", "lower_thread_count_unsupported")
                    write_sample = True
                elif stop_after_failed:
                    row = SweepRow(binary, scenario, network, path_profile, threads, "blocked", "lower_thread_count_failed")
                    write_sample = True
                elif stop_after_plateau:
                    row = SweepRow(binary, scenario, network, path_profile, threads, "plateau", "lower_thread_count_plateau")
                    write_sample = True
                else:
                    key = (binary, scenario, network, path_profile, threads)
                    row = existing_rows.get(key)
                    if row is None:
                        row = run_one(root, sweep_root, binary, scenario, network, path_profile, threads)
                        write_sample = True
                    previous_ok = next((previous for previous in reversed(group) if previous.status == "ok"), None)
                    reason = incremental_plateau_reason(previous_ok, row, min_incremental_improvement)
                    if reason:
                        row = SweepRow(
                            row.binary,
                            row.scenario,
                            row.network,
                            row.path_profile,
                            row.threads,
                            "plateau",
                            reason,
                            row.metric,
                            row.p50,
                            row.p90,
                            row.p99,
                            row.samples,
                            row.min_value,
                            row.max_value,
                            row.spread_ratio,
                            row.out_dir,
                        )
                if write_sample:
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
                    handle.flush()
                group.append(row)
                print(
                    "quicperf_saturation_sample "
                    f"binary={row.binary} scenario={row.scenario} network={row.network} path_profile={row.path_profile} "
                    f"threads={row.threads} status={row.status} reason={row.reason or '-'} "
                    f"metric={row.metric or '-'} samples={row.samples} min={row.min_value:.6f} "
                    f"p50={row.p50:.6f} p90={row.p90:.6f} p99={row.p99:.6f} "
                    f"max={row.max_value:.6f} spread_ratio={row.spread_ratio:.6f} "
                    f"out_dir={row.out_dir or '-'}"
                )
                if row.status == "unsupported":
                    stop_after_unsupported = True
                if row.status == "plateau":
                    stop_after_plateau = True
                if row.status == "ok":
                    pre_ok_failures = 0
                elif not any(previous.status == "ok" for previous in group):
                    if row.status == "failed":
                        pre_ok_failures += 1
                    if max_pre_ok_failures > 0 and pre_ok_failures >= max_pre_ok_failures:
                        stop_after_failed = True
                if (
                    stop_after_blocked
                    and row.status == "failed"
                    and any(previous.status == "ok" for previous in group)
                ):
                    stop_after_failed = True
            status, selected, best, reason, boundary = selected_row(group, tolerance)
            selections.append((binary, scenario, network, path_profile, status, selected, best, reason, boundary))

    summary_path = sweep_root / "saturation-summary.tsv"
    with summary_path.open("w", encoding="utf-8", newline="") as handle:
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
        for binary, scenario, network, path_profile, status, selected, best, reason, boundary in selections:
            boundary_threads = boundary.threads if boundary else ""
            boundary_status = boundary.status if boundary else ""
            boundary_reason = boundary.reason if boundary else ""
            if selected and best:
                writer.writerow([
                    binary,
                    scenario,
                    network,
                    path_profile,
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
                print(
                    "quicperf_saturation_selected "
                    f"binary={binary} scenario={scenario} network={network} path_profile={path_profile} status={status} "
                    f"metric={selected.metric} selected_threads={selected.threads} "
                    f"selected_samples={selected.samples} selected_p50={selected.p50:.6f} "
                    f"selected_spread_ratio={selected.spread_ratio:.6f} best_threads={best.threads} "
                    f"best_p50={best.p50:.6f} "
                    f"boundary_threads={boundary_threads or '-'} "
                    f"boundary_status={boundary_status or '-'} "
                    f"boundary_reason={boundary_reason or '-'} "
                    f"reason={reason or '-'}"
                )
            else:
                best_threads = best.threads if best else ""
                best_p50 = f"{best.p50:.6f}" if best else ""
                metric = best.metric if best else ""
                writer.writerow([
                    binary,
                    scenario,
                    network,
                    path_profile,
                    status,
                    metric,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    best_threads,
                    best_p50,
                    boundary_threads,
                    boundary_status,
                    boundary_reason,
                    reason,
                ])
                print(
                    "quicperf_saturation_selected "
                    f"binary={binary} scenario={scenario} network={network} path_profile={path_profile} status={status} "
                    f"boundary_threads={boundary_threads or '-'} "
                    f"boundary_status={boundary_status or '-'} "
                    f"boundary_reason={boundary_reason or '-'} reason={reason}"
                )

    print(f"quicperf_saturation_samples path={samples_path}")
    print(f"quicperf_saturation_summary path={summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
