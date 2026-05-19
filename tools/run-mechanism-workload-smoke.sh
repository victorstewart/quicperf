#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${QUICPERF_BIN_DIR:-$root/build/bin}"
out_dir="${QUICPERF_MECHANISM_SMOKE_OUT_DIR:-$root/.run/mechanism-smoke-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
log="$out_dir/run.stdout"

all_primary_binaries="${QUICPERF_MECHANISM_SMOKE_BINARIES:-ngtcp2perf lsperf tquicperf quicheperf picoperf xquicperf quinnperf s2nperf neqoperf noqperf quiczigperf mvfstperf}"
production_scenarios="${QUICPERF_MECHANISM_SMOKE_SCENARIOS:-reqresp stream_churn multistream_download multistream_upload bidi small_payload_pps loss_recovery flow_control idle_footprint close_reset_cleanup}"
networks="${QUICPERF_MECHANISM_SMOKE_NETWORKS:-syscall iouring}"
path_profiles="${QUICPERF_MECHANISM_SMOKE_PATH_PROFILES:-${QUICPERF_PATH_PROFILES:-${QUICPERF_PATH_PROFILE:-loopback}}}"
repeat="${QUICPERF_MECHANISM_SMOKE_REPEAT:-1}"
warmup="${QUICPERF_MECHANISM_SMOKE_WARMUP:-0}"
test_bytes="${QUICPERF_MECHANISM_SMOKE_TEST_BYTES:-4096}"
operations="${QUICPERF_MECHANISM_SMOKE_OPERATIONS:-4}"
streams_in_flight="${QUICPERF_MECHANISM_SMOKE_STREAMS_IN_FLIGHT:-4}"
idle_hold_ms="${QUICPERF_MECHANISM_SMOKE_IDLE_HOLD_MS:-50}"
timeout_s="${QUICPERF_MECHANISM_SMOKE_TIMEOUT:-45s}"
server_stop_timeout="${QUICPERF_MECHANISM_SMOKE_SERVER_STOP_TIMEOUT:-60s}"

mkdir -p "$out_dir"

for binary in $all_primary_binaries; do
	if [[ ! -x "$bin_dir/$binary" ]]; then
		printf 'mechanism_smoke status=failed reason=missing_binary binary=%s path=%s\n' "$binary" "$bin_dir/$binary"
		exit 2
	fi
done

set +e
QUICPERF_OUT_DIR="$out_dir/run" \
QUICPERF_BINARIES="$all_primary_binaries" \
QUICPERF_SCENARIOS="$production_scenarios" \
QUICPERF_NETWORKS="$networks" \
QUICPERF_PATH_PROFILES="$path_profiles" \
QUICPERF_REPEAT="$repeat" \
QUICPERF_WARMUP="$warmup" \
QUICPERF_TEST_BYTES="$test_bytes" \
QUICPERF_MULTISTREAM_DOWNLOAD_TEST_BYTES="$test_bytes" \
QUICPERF_MULTISTREAM_UPLOAD_TEST_BYTES="$test_bytes" \
QUICPERF_BIDI_TEST_BYTES="$test_bytes" \
QUICPERF_LOSS_RECOVERY_TEST_BYTES="$test_bytes" \
QUICPERF_FLOW_CONTROL_TEST_BYTES="$test_bytes" \
QUICPERF_SCENARIO_OPERATIONS="$operations" \
QUICPERF_STREAMS_IN_FLIGHT="$streams_in_flight" \
QUICPERF_IDLE_HOLD_MS="$idle_hold_ms" \
QUICPERF_TIMEOUT="$timeout_s" \
QUICPERF_SERVER_STOP_TIMEOUT="$server_stop_timeout" \
QUICPERF_RANDOMIZE_ORDER="${QUICPERF_MECHANISM_SMOKE_RANDOMIZE_ORDER:-1}" \
"$root/tools/run-benchmarks.sh" >"$log" 2>&1
run_status=$?
set -e

python3 - "$out_dir/run/summary.tsv" "$all_primary_binaries" "$production_scenarios" "$networks" "$path_profiles" "$repeat" "$log" <<'PY'
import csv
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
binaries = sys.argv[2].split()
scenarios = sys.argv[3].split()
networks = sys.argv[4].split()
path_profiles = sys.argv[5].split()
repeat = int(sys.argv[6])
log_path = Path(sys.argv[7])

rows = []
if summary_path.exists():
    with summary_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))

by_key = {
    (row.get("binary"), row.get("scenario"), row.get("network"), row.get("path_profile") or "loopback"): row
    for row in rows
}

missing = []
short = []
for binary in binaries:
    for scenario in scenarios:
        for network in networks:
            for path_profile in path_profiles:
                row = by_key.get((binary, scenario, network, path_profile))
                if row is None:
                    missing.append(f"{binary}/{scenario}/{network}/{path_profile}")
                    continue
                try:
                    samples = int(row.get("samples", "0") or "0")
                except ValueError:
                    samples = 0
                if samples < repeat:
                    short.append(f"{binary}/{scenario}/{network}/{path_profile}:{samples}_of_{repeat}")

log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
bad_markers = []
for marker in ("status=unsupported", "status=client_failed", "status=server_failed", "status=thread_check_failed"):
    if marker in log_text:
        bad_markers.append(marker)

if missing or short or bad_markers:
    if missing:
        print(f"mechanism_smoke status=failed reason=missing_rows count={len(missing)} rows={','.join(missing[:20])}")
    if short:
        print(f"mechanism_smoke status=failed reason=short_rows count={len(short)} rows={','.join(short[:20])}")
    if bad_markers:
        print(f"mechanism_smoke status=failed reason=bad_run_markers markers={','.join(bad_markers)}")
    raise SystemExit(1)

print(f"mechanism_smoke validation=passed summary={summary_path} rows={len(rows)}")
PY
validation_status=$?

if (( run_status != 0 || validation_status != 0 )); then
	printf 'mechanism_smoke status=failed run_status=%d validation_status=%d out_dir=%s log=%s\n' "$run_status" "$validation_status" "$out_dir/run" "$log"
	exit 3
fi

printf 'mechanism_smoke status=passed out_dir=%s summary=%s log=%s\n' "$out_dir/run" "$out_dir/run/summary.tsv" "$log"
