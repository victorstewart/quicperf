#!/usr/bin/env python3
import csv
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def env_value(name: str, default: str) -> str:
    return os.environ.get(name, default)


def read_tsv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def split_words(value: str) -> list[str]:
    return [item for item in value.split() if item]


def copy_publication_results(publication_root: Path, combined_dir: Path) -> Path:
    path = publication_root / "publication-results.tsv"
    source = combined_dir / "publication-results.tsv"
    if source.exists():
        shutil.copyfile(source, path)
    else:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, delimiter="\t")
            writer.writerow([
                "binary",
                "scenario",
                "network",
                "selection_status",
                "publication_status",
                "metric",
                "selected_threads",
                "selected_samples",
                "selected_p50",
                "selected_p90",
                "selected_p99",
                "best_threads",
                "best_p50",
                "audited_rows",
                "not_ready_rows",
                "spread_low_pct",
                "spread_high_pct",
                "selected_p50_ci95_relative_width",
                "selected_middle_spread_ratio",
                "selected_spread_low",
                "selected_spread_high",
                "max_audited_p50_ci95_relative_width",
                "max_audited_p50_ci95_row_threads",
                "max_audited_middle_spread_ratio",
                "max_audited_middle_spread_row_threads",
                "reason",
            ])
    return path


def copy_publication_curve(publication_root: Path, combined_dir: Path) -> Path:
    path = publication_root / "publication-curve.tsv"
    source = combined_dir / "publication-curve.tsv"
    if source.exists():
        shutil.copyfile(source, path)
    else:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, delimiter="\t")
            writer.writerow([
                "binary",
                "scenario",
                "network",
                "selection_status",
                "metric",
                "client_threads",
                "curve_role",
                "row_status",
                "samples",
                "p50",
                "p90",
                "p99",
                "p50_ci95_relative_width",
                "spread_low_pct",
                "spread_high_pct",
                "spread_low",
                "spread_high",
                "middle_spread_ratio",
                "selected_threads",
                "best_threads",
                "boundary_threads",
                "boundary_status",
                "publication_status",
                "reason",
            ])
    return path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    if os.environ.get("QUICPERF_FIXED_PUBLICATION_COMPAT", "0") != "1":
        print("quicperf_publication_suite mode=adaptive runner=tools/run-adaptive-publication-suite.py", flush=True)
        adaptive_env = os.environ.copy()
        if "QUICPERF_PUBLICATION_OUT_DIR" in adaptive_env and "QUICPERF_ADAPTIVE_OUT_DIR" not in adaptive_env:
            adaptive_env["QUICPERF_ADAPTIVE_OUT_DIR"] = adaptive_env["QUICPERF_PUBLICATION_OUT_DIR"]
        if "QUICPERF_PUBLICATION_TEST_BYTES" in adaptive_env and "QUICPERF_TEST_BYTES" not in adaptive_env:
            adaptive_env["QUICPERF_TEST_BYTES"] = adaptive_env["QUICPERF_PUBLICATION_TEST_BYTES"]
        if "QUICPERF_PUBLICATION_WARMUP" in adaptive_env and "QUICPERF_ADAPTIVE_WARMUP" not in adaptive_env:
            adaptive_env["QUICPERF_ADAPTIVE_WARMUP"] = adaptive_env["QUICPERF_PUBLICATION_WARMUP"]
        return subprocess.run([str(root / "tools" / "run-adaptive-publication-suite.py")], cwd=root, env=adaptive_env).returncode

    print("quicperf_publication_suite mode=fixed_compat status=compatibility_only", flush=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    publication_root = Path(env_value("QUICPERF_PUBLICATION_OUT_DIR", str(root / ".run" / f"quicperf-publication-{stamp}-{os.getpid()}")))
    publication_root.mkdir(parents=True, exist_ok=True)

    sweep_count = int(env_value("QUICPERF_PUBLICATION_SWEEPS", "3"))
    repeat = env_value("QUICPERF_PUBLICATION_REPEAT", "10")
    warmup = env_value("QUICPERF_PUBLICATION_WARMUP", "2")
    bytes_per_sample = env_value("QUICPERF_PUBLICATION_TEST_BYTES", "1073741824")
    seed_base = int(env_value("QUICPERF_RANDOM_SEED", str(os.getpid())))
    fail_on_not_ready = env_value("QUICPERF_PUBLICATION_FAIL_ON_NOT_READY", "1") == "1"
    source_sweeps = [Path(item) for item in split_words(env_value("QUICPERF_PUBLICATION_SOURCE_SWEEPS", ""))]

    common_env = os.environ.copy()
    common_env.setdefault("QUICPERF_TEST_BYTES", bytes_per_sample)
    common_env.setdefault("QUICPERF_WINDOW_PROFILE", "large")
    common_env.setdefault("QUICPERF_SATURATION_REPEAT", repeat)
    common_env.setdefault("QUICPERF_SATURATION_WARMUP", warmup)
    common_env.setdefault("QUICPERF_SATURATION_TOLERANCE", "0.01")
    common_env.setdefault("QUICPERF_SATURATION_MIN_INCREMENTAL_IMPROVEMENT", "0.01")
    common_env.setdefault("QUICPERF_SATURATION_THREADS", " ".join(str(item) for item in range(1, 33)))
    common_env.setdefault("QUICPERF_SATURATION_SCENARIOS", "download upload connect")
    common_env.setdefault("QUICPERF_SATURATION_NETWORKS", "syscall iouring")
    common_env.setdefault("QUICPERF_SATURATION_STOP_AFTER_BLOCKED", "1")
    common_env.setdefault("QUICPERF_SATURATION_RANDOMIZE_GROUPS", "1")
    common_env.setdefault("QUICPERF_SATURATION_RANDOMIZE_ORDER", "1")
    common_env.setdefault("QUICPERF_OUTLIER_GATE_MODE", env_value("QUICPERF_PUBLICATION_OUTLIER_GATE_MODE", "p20_p80"))
    common_env.setdefault("QUICPERF_OUTLIER_SPREAD_RATIO", env_value("QUICPERF_PUBLICATION_OUTLIER_SPREAD_RATIO", "10.00"))
    common_env.setdefault("QUICPERF_TIMEOUT", "360s")

    sweep_dirs = []
    ready = True
    for source in source_sweeps:
        source_path = source if source.is_absolute() else root / source
        if not (source_path / "saturation-samples.tsv").exists():
            print(f"publication_source_sweep_missing path={source_path}")
            ready = False
            continue
        sweep_dirs.append(source_path)
        print(f"publication_source_sweep path={source_path}")

    for index in range(len(sweep_dirs) + 1, sweep_count + 1):
        sweep_dir = publication_root / f"sweep-{index:02d}"
        sweep_dirs.append(sweep_dir)
        env = common_env.copy()
        env["QUICPERF_SATURATION_OUT_DIR"] = str(sweep_dir)
        env["QUICPERF_RANDOM_SEED"] = str(seed_base + index)
        print(f"publication_sweep_start index={index} out_dir={sweep_dir} repeat={env['QUICPERF_SATURATION_REPEAT']} bytes={env['QUICPERF_TEST_BYTES']} seed={env['QUICPERF_RANDOM_SEED']}")
        with (publication_root / f"sweep-{index:02d}.stdout").open("w", encoding="utf-8") as stdout:
            completed = subprocess.run([str(root / "tools" / "run-saturation-sweep.py")], cwd=root, env=env, stdout=stdout, stderr=subprocess.STDOUT)
        if completed.returncode != 0:
            print(f"publication_sweep_failed index={index} returncode={completed.returncode}")
            ready = False
            continue

    completed_sweeps = [path for path in sweep_dirs if (path / "saturation-samples.tsv").exists()]
    combined_dir = publication_root / "combined"
    if completed_sweeps:
        combine = subprocess.run(
            [str(root / "tools" / "combine-saturation-sweeps.py"), "--force", str(combined_dir), *[str(path) for path in completed_sweeps]],
            cwd=root,
            env=common_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        (publication_root / "combined.combine.stdout").write_text(combine.stdout, encoding="utf-8")
        print(combine.stdout, end="")
        if combine.returncode != 0:
            print(f"publication_combine_failed returncode={combine.returncode}")
            ready = False

    if completed_sweeps and (combined_dir / "saturation-samples.tsv").exists():
        repeat_count = int(repeat)
        default_min_samples = str(repeat_count * len(completed_sweeps))
        audit_command = [
            str(root / "tools" / "audit-publication-run.py"),
            str(combined_dir),
            "--min-samples",
            env_value("QUICPERF_PUBLICATION_MIN_SAMPLES", default_min_samples),
            "--max-ci-relative-width",
            env_value("QUICPERF_PUBLICATION_MAX_CI_RELATIVE_WIDTH", "0.20"),
            "--max-middle-spread-ratio",
            env_value("QUICPERF_PUBLICATION_MAX_MIDDLE_SPREAD_RATIO", "2.00"),
        ]
        if fail_on_not_ready:
            audit_command.append("--fail-on-not-ready")
        audit = subprocess.run(audit_command, cwd=root, env=common_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (publication_root / "combined.audit.stdout").write_text(audit.stdout, encoding="utf-8")
        print(audit.stdout, end="")
        if audit.returncode != 0 or "status=not_ready" in audit.stdout:
            ready = False

    results_path = copy_publication_results(publication_root, combined_dir)
    curve_path = copy_publication_curve(publication_root, combined_dir)
    summary_path = publication_root / "publication-summary.md"
    with summary_path.open("w", encoding="utf-8") as handle:
        handle.write("# Publication Suite\n\n")
        handle.write(f"- Status: {'ready' if ready else 'not_ready'}\n")
        handle.write(f"- Sweeps requested: {sweep_count}\n")
        handle.write(f"- Sweeps completed: {len(completed_sweeps)}\n")
        handle.write(f"- Repeat: {repeat}\n")
        handle.write(f"- Warmup: {warmup}\n")
        handle.write(f"- Bytes per transfer sample: {bytes_per_sample}\n")
        handle.write(f"- Combined dataset: `{combined_dir.name}`\n")
        handle.write(f"- Result stability: `{results_path.name}`\n")
        handle.write(f"- Client-count curve: `{curve_path.name}`\n")

    print(f"publication_suite out_dir={publication_root} status={'ready' if ready else 'not_ready'} results={results_path} curve={curve_path}")
    return 1 if fail_on_not_ready and not ready else 0


if __name__ == "__main__":
    raise SystemExit(main())
