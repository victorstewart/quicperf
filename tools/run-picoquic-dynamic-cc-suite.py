#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUN_BENCHMARKS = ROOT / "tools" / "run-benchmarks.sh"

DEFAULT_PROFILES = [
    "cellular-public-5g-lte-switching",
    "cellular-public-5g-lte-holdout-switching",
]
DEFAULT_CONTROLLERS = ["bbr", "cubic", "bbr1", "newreno"]
DEFAULT_SCENARIOS = ["connect", "download"]
DEFAULT_PACKET_TRAIN_MODES = ["off"]
DEFAULT_NETWORK = "iouring"
ROW_ENV_KEYS = (
    "QUICPERF_BINARIES",
    "QUICPERF_NETWORKS",
    "QUICPERF_PATH_PROFILES",
    "QUICPERF_SCENARIOS",
    "QUICPERF_CONGESTION_PROFILE",
    "QUICPERF_PICOQUIC_PACKET_TRAIN",
    "QUICPERF_UDP_GSO",
    "QUICPERF_REPEAT",
    "QUICPERF_WARMUP",
    "QUICPERF_TEST_BYTES",
    "QUICPERF_TIMEOUT",
    "QUICPERF_PATH_TIME_SCALE",
    "QUICPERF_RANDOM_SEED",
    "QUICPERF_OUT_DIR",
    "QUICPERF_SAMPLE_PHASE",
    "QUICPERF_RUN_LABEL_PREFIX",
    "QUICPERF_BIN_DIR",
)


@dataclass(frozen=True)
class MatrixRow:
    row_id: int
    profile: str
    controller: str
    scenario: str
    packet_train: str


def split_values(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        result.extend(part for part in value.split() if part)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a Picoquic-only CC matrix over dynamic cellular path schedules. "
            "Controllers may be built-in static CC names or future Picoquic BBRv3-derived variants."
        )
    )
    parser.add_argument("--profiles", nargs="+", default=DEFAULT_PROFILES)
    parser.add_argument("--controllers", nargs="+", default=DEFAULT_CONTROLLERS)
    parser.add_argument("--scenarios", nargs="+", default=DEFAULT_SCENARIOS)
    parser.add_argument("--packet-train-modes", nargs="+", default=DEFAULT_PACKET_TRAIN_MODES)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--warmup", type=int, default=0)
    parser.add_argument("--test-bytes", type=int, default=32 * 1024 * 1024 * 1024)
    parser.add_argument("--timeout", default="2700s")
    parser.add_argument("--path-time-scale", type=float, default=None)
    parser.add_argument("--network", default=DEFAULT_NETWORK, choices=("syscall", "iouring"))
    parser.add_argument("--seed", type=int, default=20260516)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--bin-dir", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_false", dest="execute", help="print the matrix without executing rows")
    parser.add_argument("--execute", action="store_true", help="execute rows instead of printing the matrix only")
    parser.set_defaults(execute=False)
    return parser.parse_args()


def matrix_rows(profiles: list[str], controllers: list[str], scenarios: list[str], packet_train_modes: list[str]) -> list[MatrixRow]:
    rows: list[MatrixRow] = []
    row_id = 0
    for profile in profiles:
        for scenario in scenarios:
            for packet_train in packet_train_modes:
                for controller in controllers:
                    row_id += 1
                    rows.append(
                        MatrixRow(
                            row_id=row_id,
                            profile=profile,
                            controller=controller,
                            scenario=scenario,
                            packet_train=packet_train,
                        )
                    )
    return rows


def suite_out_dir(args: argparse.Namespace) -> Path:
    if args.out_dir is not None:
        return args.out_dir
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return ROOT / ".run" / f"picoquic-dynamic-cc-{stamp}"


def row_out_dir(base: Path, row: MatrixRow) -> Path:
    return base / f"{row.row_id:03d}-{row.profile}-{row.scenario}-train-{row.packet_train}-{row.controller}"


def row_env(args: argparse.Namespace, row: MatrixRow, out_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "QUICPERF_BINARIES": "picoperf",
            "QUICPERF_NETWORKS": args.network,
            "QUICPERF_PATH_PROFILES": row.profile,
            "QUICPERF_SCENARIOS": row.scenario,
            "QUICPERF_CONGESTION_PROFILE": row.controller,
            "QUICPERF_PICOQUIC_PACKET_TRAIN": "1" if row.packet_train == "on" else "0",
            "QUICPERF_UDP_GSO": "1" if row.packet_train == "on" else "0",
            "QUICPERF_REPEAT": str(args.repeat),
            "QUICPERF_WARMUP": str(args.warmup),
            "QUICPERF_TEST_BYTES": str(args.test_bytes),
            "QUICPERF_TIMEOUT": args.timeout,
            "QUICPERF_RANDOM_SEED": str(args.seed + row.row_id),
            "QUICPERF_OUT_DIR": str(row_out_dir(out_dir, row)),
            "QUICPERF_SAMPLE_PHASE": "dynamic_cc",
            "QUICPERF_RUN_LABEL_PREFIX": f"{row.controller}-train-{row.packet_train}-",
        }
    )
    if args.bin_dir is not None:
        env["QUICPERF_BIN_DIR"] = str(args.bin_dir)
    if args.path_time_scale is not None:
        env["QUICPERF_PATH_TIME_SCALE"] = str(args.path_time_scale)
    return env


def command_for_row(args: argparse.Namespace, row: MatrixRow, out_dir: Path) -> list[str]:
    env = row_env(args, row, out_dir)
    prefixes = [
        f"{key}={shlex.quote(env[key])}"
        for key in ROW_ENV_KEYS
        if key in env
    ]
    return [*prefixes, shlex.quote(str(RUN_BENCHMARKS))]


def write_matrix(path: Path, rows: list[MatrixRow], out_dir: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("row_id", "profile", "scenario", "packet_train", "controller", "out_dir"),
            delimiter="\t",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "row_id": row.row_id,
                    "profile": row.profile,
                    "scenario": row.scenario,
                    "packet_train": row.packet_train,
                    "controller": row.controller,
                    "out_dir": str(row_out_dir(out_dir, row)),
                }
            )


def execute_row(args: argparse.Namespace, row: MatrixRow, out_dir: Path) -> int:
    env = row_env(args, row, out_dir)
    completed = subprocess.run([str(RUN_BENCHMARKS)], cwd=ROOT, env=env, check=False)
    return int(completed.returncode)


def main() -> int:
    args = parse_args()
    args.profiles = split_values(args.profiles)
    args.controllers = split_values(args.controllers)
    args.scenarios = split_values(args.scenarios)
    args.packet_train_modes = split_values(args.packet_train_modes)
    invalid_packet_train_modes = sorted(set(args.packet_train_modes) - {"off", "on"})
    if invalid_packet_train_modes:
        print(f"invalid packet train mode(s): {' '.join(invalid_packet_train_modes)}", file=sys.stderr)
        return 2
    if args.repeat < 1:
        print("--repeat must be >= 1", file=sys.stderr)
        return 2
    if args.warmup < 0:
        print("--warmup must be >= 0", file=sys.stderr)
        return 2
    if args.path_time_scale is not None and args.path_time_scale < 0.0:
        print("--path-time-scale must be >= 0", file=sys.stderr)
        return 2

    out_dir = suite_out_dir(args)
    rows = matrix_rows(args.profiles, args.controllers, args.scenarios, args.packet_train_modes)
    write_matrix(out_dir / "matrix.tsv", rows, out_dir)

    print(
        "quicperf_picoquic_dynamic_cc_suite "
        f"mode={'execute' if args.execute else 'dry-run'} rows={len(rows)} out_dir={out_dir} "
        f"profiles={' '.join(args.profiles)} controllers={' '.join(args.controllers)} "
        f"scenarios={' '.join(args.scenarios)} packet_train_modes={' '.join(args.packet_train_modes)}"
    )

    failed = 0
    for row in rows:
        if args.execute:
            print(
                "quicperf_picoquic_dynamic_cc_row "
                f"row_id={row.row_id} profile={row.profile} scenario={row.scenario} "
                f"packet_train={row.packet_train} controller={row.controller} status=running",
                flush=True,
            )
            rc = execute_row(args, row, out_dir)
            status = "ok" if rc == 0 else f"exit_{rc}"
            if rc != 0:
                failed = 1
            print(
                "quicperf_picoquic_dynamic_cc_row "
                f"row_id={row.row_id} profile={row.profile} scenario={row.scenario} "
                f"packet_train={row.packet_train} controller={row.controller} status={status}",
                flush=True,
            )
        else:
            print(
                "quicperf_picoquic_dynamic_cc_command "
                f"row_id={row.row_id} profile={row.profile} scenario={row.scenario} "
                f"packet_train={row.packet_train} controller={row.controller} "
                f"command={' '.join(command_for_row(args, row, out_dir))}"
            )
    return failed


if __name__ == "__main__":
    raise SystemExit(main())
