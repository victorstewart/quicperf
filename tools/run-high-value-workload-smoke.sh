#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${QUICPERF_BIN_DIR:-$root/build/bin}"
out_dir="${QUICPERF_HIGH_VALUE_SMOKE_OUT_DIR:-$root/.run/high-value-smoke-$(date -u +%Y%m%dT%H%M%SZ)-$$}"

primary_binaries="${QUICPERF_HIGH_VALUE_SMOKE_BINARIES:-ngtcp2perf lsperf tquicperf quicheperf picoperf xquicperf quinnperf s2nperf neqoperf noqperf quiczigperf mvfstperf}"
capability_scenarios="${QUICPERF_HIGH_VALUE_CAPABILITY_SCENARIOS:-resumed_connect zero_rtt_reqresp datagram}"
networks="${QUICPERF_HIGH_VALUE_SMOKE_NETWORKS:-syscall iouring}"
path_profiles="${QUICPERF_HIGH_VALUE_SMOKE_PATH_PROFILES:-${QUICPERF_PATH_PROFILES:-${QUICPERF_PATH_PROFILE:-loopback}}}"
repeat="${QUICPERF_HIGH_VALUE_SMOKE_REPEAT:-1}"
warmup="${QUICPERF_HIGH_VALUE_SMOKE_WARMUP:-0}"
test_bytes="${QUICPERF_HIGH_VALUE_SMOKE_TEST_BYTES:-4096}"
operations="${QUICPERF_HIGH_VALUE_SMOKE_OPERATIONS:-4}"
streams_in_flight="${QUICPERF_HIGH_VALUE_SMOKE_STREAMS_IN_FLIGHT:-4}"
idle_hold_ms="${QUICPERF_HIGH_VALUE_SMOKE_IDLE_HOLD_MS:-50}"
timeout_s="${QUICPERF_HIGH_VALUE_SMOKE_TIMEOUT:-45s}"

mkdir -p "$out_dir"

for binary in $primary_binaries; do
	if [[ ! -x "$bin_dir/$binary" ]]; then
		printf 'high_value_smoke status=failed reason=missing_binary binary=%s path=%s\n' "$binary" "$bin_dir/$binary"
		exit 2
	fi
done

production_out="$out_dir/production"
QUICPERF_MECHANISM_SMOKE_OUT_DIR="$production_out" \
QUICPERF_MECHANISM_SMOKE_BINARIES="$primary_binaries" \
QUICPERF_MECHANISM_SMOKE_NETWORKS="$networks" \
QUICPERF_MECHANISM_SMOKE_PATH_PROFILES="$path_profiles" \
QUICPERF_MECHANISM_SMOKE_REPEAT="$repeat" \
QUICPERF_MECHANISM_SMOKE_WARMUP="$warmup" \
QUICPERF_MECHANISM_SMOKE_TEST_BYTES="$test_bytes" \
QUICPERF_MECHANISM_SMOKE_OPERATIONS="$operations" \
QUICPERF_MECHANISM_SMOKE_STREAMS_IN_FLIGHT="$streams_in_flight" \
QUICPERF_MECHANISM_SMOKE_IDLE_HOLD_MS="$idle_hold_ms" \
QUICPERF_MECHANISM_SMOKE_TIMEOUT="$timeout_s" \
"$root/tools/run-mechanism-workload-smoke.sh"

capability_out="$out_dir/capability"
capability_log="$out_dir/capability.stdout"
set +e
QUICPERF_OUT_DIR="$capability_out" \
QUICPERF_BINARIES="$primary_binaries" \
QUICPERF_SCENARIOS="$capability_scenarios" \
QUICPERF_NETWORKS="$networks" \
QUICPERF_PATH_PROFILES="$path_profiles" \
QUICPERF_REPEAT="$repeat" \
QUICPERF_WARMUP="$warmup" \
QUICPERF_TEST_BYTES="$test_bytes" \
QUICPERF_SCENARIO_OPERATIONS="$operations" \
QUICPERF_STREAMS_IN_FLIGHT="$streams_in_flight" \
QUICPERF_IDLE_HOLD_MS="$idle_hold_ms" \
QUICPERF_TIMEOUT="$timeout_s" \
QUICPERF_RANDOMIZE_ORDER="${QUICPERF_HIGH_VALUE_SMOKE_RANDOMIZE_ORDER:-1}" \
"$root/tools/run-benchmarks.sh" >"$capability_log" 2>&1
capability_status=$?
set -e

python3 - "$capability_out/summary.tsv" "$capability_log" "$primary_binaries" "$capability_scenarios" "$networks" "$path_profiles" "$repeat" <<'PY'
import csv
import re
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])
binaries = sys.argv[3].split()
scenarios = sys.argv[4].split()
networks = sys.argv[5].split()
path_profiles = sys.argv[6].split()
repeat = int(sys.argv[7])

rows = []
if summary_path.exists():
    with summary_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))

summary = {
    (row.get("binary"), row.get("scenario"), row.get("network"), row.get("path_profile") or "loopback"): row
    for row in rows
}
log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""

unsupported = set()
unsupported_re = re.compile(r"quicperf_run_result binary=(\S+) scenario=(\S+) network=(\S+)(?: path_profile=(\S+))? .*status=unsupported(?:\s|$)")
for match in unsupported_re.finditer(log_text):
    binary, scenario, network, path_profile = match.groups()
    unsupported.add((binary, scenario, network, path_profile or "loopback"))

bad_markers = []
for marker in ("status=client_failed", "status=server_failed", "status=thread_check_failed"):
    if marker in log_text:
        bad_markers.append(marker)

datagram_must_pass = {"neqoperf", "noqperf", "quicheperf", "quiczigperf", "quinnperf", "s2nperf"}
missing = []
short = []
unexpected_unsupported = []
for binary in binaries:
    for scenario in scenarios:
        for network in networks:
            for path_profile in path_profiles:
                key = (binary, scenario, network, path_profile)
                row = summary.get(key)
                if row is not None:
                    try:
                        samples = int(row.get("samples", "0") or "0")
                    except ValueError:
                        samples = 0
                    if samples < repeat:
                        short.append(f"{binary}/{scenario}/{network}/{path_profile}:{samples}_of_{repeat}")
                    continue
                if key in unsupported:
                    if scenario == "datagram" and binary in datagram_must_pass:
                        unexpected_unsupported.append(f"{binary}/{scenario}/{network}/{path_profile}")
                    continue
                missing.append(f"{binary}/{scenario}/{network}/{path_profile}")

if missing or short or unexpected_unsupported or bad_markers:
    if missing:
        print(f"high_value_capability_smoke status=failed reason=missing_rows count={len(missing)} rows={','.join(missing[:20])}")
    if short:
        print(f"high_value_capability_smoke status=failed reason=short_rows count={len(short)} rows={','.join(short[:20])}")
    if unexpected_unsupported:
        print(f"high_value_capability_smoke status=failed reason=unexpected_unsupported count={len(unexpected_unsupported)} rows={','.join(unexpected_unsupported[:20])}")
    if bad_markers:
        print(f"high_value_capability_smoke status=failed reason=bad_run_markers markers={','.join(bad_markers)}")
    raise SystemExit(1)

print(f"high_value_capability_smoke validation=passed summary={summary_path} successful_rows={len(rows)} unsupported_rows={len(unsupported)}")
PY
validation_status=$?

if (( capability_status != 0 || validation_status != 0 )); then
	printf 'high_value_smoke status=failed phase=capability run_status=%d validation_status=%d out_dir=%s log=%s\n' "$capability_status" "$validation_status" "$capability_out" "$capability_log"
	exit 3
fi

printf 'high_value_smoke status=passed out_dir=%s production_summary=%s capability_summary=%s capability_log=%s\n' \
	"$out_dir" "$production_out/run/summary.tsv" "$capability_out/summary.tsv" "$capability_log"
