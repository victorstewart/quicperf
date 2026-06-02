#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import importlib.util
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from quicperf_fixed_design import (
    DEFAULT_PUBLICATION_BLOCKS,
    DEFAULT_PUBLICATION_SAMPLES,
    DEFAULT_PUBLICATION_WARMUP,
    DEFAULT_MAX_CLIENT_THREADS,
    DEFAULT_SCOUT_GRID,
    DEFAULT_SCOUT_IMPAIRED_DURATION_MS,
    DEFAULT_SCOUT_LOOPBACK_DURATION_MS,
    DEFAULT_SCOUT_SAMPLES,
    PlanRow,
    ScoutPoint,
    benchmark_fingerprint,
    default_duration_ms,
    default_scout_cache_dir,
    default_timeout_sec,
    materialize_scout_cache,
    scenario_mode,
    scout_cache_scope,
    scout_point_from_samples,
    select_scout_threads,
    split_words,
    target_env,
    target_connections_for_duration,
    unique_preserve,
    validate_scout_cache,
    write_environment_file,
    write_plan,
    write_scout_cache,
)
from quicperf_stats import load_samples, write_samples


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


def discover_binaries(root: Path, configured: str) -> list[str]:
    if configured:
        return unique_preserve(split_words(configured))
    bin_dir = Path(os.environ.get("QUICPERF_BIN_DIR", root / "build" / "bin"))
    return sorted(path.name for path in bin_dir.glob("*perf") if os.access(path, os.X_OK) and path.name != "tcpperf")


def scout_duration_ms(path_profile: str, loopback_ms: int, impaired_ms: int) -> int:
    return loopback_ms if path_profile == "loopback" else impaired_ms


def write_scout_rows(path: Path, points: list[ScoutPoint]) -> None:
    fields = ["run_order", "binary", "scenario", "network", "path_profile", "threads", "status", "reason", "metric", "samples", "p50", "out_dir"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, delimiter="\t", fieldnames=fields)
        writer.writeheader()
        for point in points:
            writer.writerow({
                "run_order": point.run_order,
                "binary": point.binary,
                "scenario": point.scenario,
                "network": point.network,
                "path_profile": point.path_profile,
                "threads": point.threads,
                "status": point.status,
                "reason": point.reason,
                "metric": point.metric,
                "samples": point.samples,
                "p50": f"{point.median:.6f}",
                "out_dir": point.out_dir,
            })


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded non-publication saturation scout and emit a fixed publication plan.")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--binaries", default=os.environ.get("QUICPERF_BINARIES", ""))
    parser.add_argument("--scenarios", default=os.environ.get("QUICPERF_SCENARIOS", "download upload connect"))
    parser.add_argument("--networks", default=os.environ.get("QUICPERF_NETWORKS", "syscall iouring"))
    parser.add_argument("--path-profiles", default=os.environ.get("QUICPERF_PATH_PROFILES", os.environ.get("QUICPERF_PATH_PROFILE", "loopback")))
    parser.add_argument("--grid", default=" ".join(str(item) for item in DEFAULT_SCOUT_GRID))
    parser.add_argument("--samples", type=int, default=int(os.environ.get("QUICPERF_SCOUT_SAMPLES", str(DEFAULT_SCOUT_SAMPLES))))
    parser.add_argument("--loopback-duration-ms", type=int, default=int(os.environ.get("QUICPERF_SCOUT_LOOPBACK_DURATION_MS", str(DEFAULT_SCOUT_LOOPBACK_DURATION_MS))))
    parser.add_argument("--impaired-duration-ms", type=int, default=int(os.environ.get("QUICPERF_SCOUT_IMPAIRED_DURATION_MS", str(DEFAULT_SCOUT_IMPAIRED_DURATION_MS))))
    parser.add_argument("--random-seed", type=int, default=int(os.environ.get("QUICPERF_RANDOM_SEED", str(os.getpid()))))
    parser.add_argument("--cache-mode", choices=("auto", "refresh", "off"), default=os.environ.get("QUICPERF_SCOUT_CACHE_MODE", "auto"))
    parser.add_argument("--cache-dir", type=Path, default=None)
    parser.add_argument("--record-default-cache-from", type=Path, default=None)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    adaptive = load_adaptive_module(root)
    cache_dir = args.cache_dir or Path(os.environ.get("QUICPERF_SCOUT_CACHE_DIR", default_scout_cache_dir(root)))
    out_root = args.out_dir or Path(os.environ.get("QUICPERF_SCOUT_OUT_DIR", root / ".run" / f"scout-{utc_stamp()}-{os.getpid()}"))

    binaries = discover_binaries(root, args.binaries)
    scenarios = unique_preserve(split_words(args.scenarios))
    networks = unique_preserve(split_words(args.networks))
    path_profiles = unique_preserve(split_words(args.path_profiles))
    grid = [int(item) for item in split_words(args.grid)]
    if any(item <= 0 for item in grid):
        parser.error("--grid entries must be positive")
    if any(item > DEFAULT_MAX_CLIENT_THREADS for item in grid):
        parser.error(f"--grid entries must be <= {DEFAULT_MAX_CLIENT_THREADS}")
    scope = scout_cache_scope(
        binaries=binaries,
        scenarios=scenarios,
        networks=networks,
        path_profiles=path_profiles,
        grid=grid,
        samples=args.samples,
        loopback_duration_ms=args.loopback_duration_ms,
        impaired_duration_ms=args.impaired_duration_ms,
        congestion_profile=os.environ.get("QUICPERF_CONGESTION_PROFILE", ""),
    )
    fingerprint, file_records = benchmark_fingerprint(root, scope)
    if args.record_default_cache_from is not None:
        source = args.record_default_cache_from.resolve()
        write_scout_cache(
            cache_dir,
            source,
            fingerprint=fingerprint,
            scope=scope,
            source_run=source.name,
            file_records=file_records,
        )
        print(
            "quicperf_scout_cache_recorded "
            f"cache_dir={cache_dir} source={source} fingerprint={fingerprint}"
        )
        return 0

    if args.cache_mode == "auto":
        valid, reason = validate_scout_cache(cache_dir, fingerprint, scope)
        if valid:
            materialize_scout_cache(cache_dir, out_root)
            print(
                "quicperf_scout_cache "
                f"status=hit cache_dir={cache_dir} out_dir={out_root} fingerprint={fingerprint}"
            )
            print(f"quicperf_scout_summary scout={out_root / 'saturation-scout.tsv'} plan={out_root / 'benchmark-plan.tsv'}")
            return 0
        print(
            "quicperf_scout_cache "
            f"status=miss cache_dir={cache_dir} reason={reason} fingerprint={fingerprint}"
        )
    elif args.cache_mode == "refresh":
        print(
            "quicperf_scout_cache "
            f"status=refresh cache_dir={cache_dir} fingerprint={fingerprint}"
        )
    else:
        print("quicperf_scout_cache status=off")

    out_root.mkdir(parents=True, exist_ok=True)
    samples_path = out_root / "scout-samples.tsv"
    write_samples(samples_path, [], append=False)

    commit = adaptive.git_commit(root)
    env_sig = adaptive.env_hash()
    machine_sig = adaptive.machine_hash()
    write_environment_file(
        root,
        out_root / "scout-environment.txt",
        label="scout",
        run_id=out_root.name,
        commit=commit,
        env_sig=env_sig,
        machine_sig=machine_sig,
    )
    cfg = adaptive.load_config()

    print(
        "quicperf_scout_run "
        f"out_dir={out_root} binaries=\"{' '.join(binaries)}\" scenarios=\"{' '.join(scenarios)}\" "
        f"networks=\"{' '.join(networks)}\" path_profiles=\"{' '.join(path_profiles)}\" "
        f"grid=\"{' '.join(str(item) for item in grid)}\" samples={args.samples}"
    )

    block_ordinal = 0
    points: list[ScoutPoint] = []
    for binary in binaries:
        for scenario in scenarios:
            for network in networks:
                for path_profile in path_profiles:
                    for threads in grid:
                        mode = scenario_mode(scenario)
                        plan_row = PlanRow(
                            binary=binary,
                            scenario=scenario,
                            network=network,
                            path_profile=path_profile,
                            client_threads=threads,
                            mode=mode,
                            duration_ms=scout_duration_ms(path_profile, args.loopback_duration_ms, args.impaired_duration_ms),
                            work_units=0,
                            samples=args.samples,
                            warmup=0,
                            block_count=1,
                        )
                        block_ordinal += 1
                        target = adaptive.Target(binary, scenario, network, path_profile, threads)
                        result = adaptive.run_block(
                            root,
                            out_root,
                            samples_path,
                            target,
                            phase="scout",
                            round_index=0,
                            block_ordinal=block_ordinal,
                            cfg=cfg,
                            publication_id=f"scout-{out_root.name}",
                            commit=commit,
                            env_sig=env_sig,
                            machine_sig=machine_sig,
                            warmup=0,
                            repeat=args.samples,
                            env_overrides=target_env(plan_row),
                            timeout_sec=default_timeout_sec(plan_row),
                        )
                        samples = load_samples(samples_path)
                        point = scout_point_from_samples(binary, scenario, network, path_profile, threads, samples, result.status, result.reason, str(result.out_dir), block_ordinal)
                        points.append(point)
                        print(
                            "quicperf_scout_point "
                            f"binary={binary} scenario={scenario} network={network} path_profile={path_profile} "
                            f"threads={threads} status={point.status} samples={point.samples} p50={point.median:.6f} "
                            f"reason={point.reason or '-'}"
                        )

    write_scout_rows(out_root / "saturation-scout.tsv", points)

    plan_rows: list[PlanRow] = []
    for binary in binaries:
        for scenario in scenarios:
            for network in networks:
                for path_profile in path_profiles:
                    group_points = [
                        point
                        for point in points
                        if point.binary == binary
                        and point.scenario == scenario
                        and point.network == network
                        and point.path_profile == path_profile
                    ]
                    selection = select_scout_threads(group_points)
                    selected_threads = selection.selected_threads or 0
                    selected_point = next((point for point in group_points if point.threads == selected_threads), None)
                    mode = scenario_mode(scenario)
                    target_connections = (
                        target_connections_for_duration(selected_point, 2000)
                        if scenario in {"connect", "resumed_connect"}
                        else 0
                    )
                    plan_rows.append(
                        PlanRow(
                            binary=binary,
                            scenario=scenario,
                            network=network,
                            path_profile=path_profile,
                            status=selection.status,
                            reason=selection.reason,
                            client_threads=selected_threads,
                            mode=mode,
                            duration_ms=default_duration_ms(scenario, path_profile) if mode == "duration" else 0,
                            work_units=target_connections,
                            samples=DEFAULT_PUBLICATION_SAMPLES,
                            warmup=DEFAULT_PUBLICATION_WARMUP,
                            block_count=DEFAULT_PUBLICATION_BLOCKS,
                            target_connections=target_connections,
                            selected_threads=selected_threads,
                            best_threads=selection.best_threads,
                        )
                    )
                    print(
                        "quicperf_scout_selected "
                        f"binary={binary} scenario={scenario} network={network} path_profile={path_profile} "
                        f"status={selection.status} selected_threads={selection.selected_threads or '-'} "
                        f"best_threads={selection.best_threads or '-'} target_connections={target_connections or '-'} "
                        f"reason={selection.reason or '-'}"
                    )

    write_plan(out_root / "benchmark-plan.tsv", plan_rows)
    if args.cache_mode != "off" and not any(row.status == "failed" for row in plan_rows):
        write_scout_cache(
            cache_dir,
            out_root,
            fingerprint=fingerprint,
            scope=scope,
            source_run=out_root.name,
            file_records=file_records,
        )
        print(
            "quicperf_scout_cache "
            f"status=stored cache_dir={cache_dir} fingerprint={fingerprint}"
        )
    print(f"quicperf_scout_summary scout={out_root / 'saturation-scout.tsv'} plan={out_root / 'benchmark-plan.tsv'}")
    return 1 if any(row.status == "failed" for row in plan_rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
