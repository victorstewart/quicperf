#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${QUICPERF_BIN_DIR:-$root/build/bin}"
repeat="${QUICPERF_REPEAT:-5}"
warmup="${QUICPERF_WARMUP:-1}"
networks="${QUICPERF_NETWORKS:-syscall}"
path_profiles="${QUICPERF_PATH_PROFILES:-${QUICPERF_PATH_PROFILE:-loopback}}"
scenarios="${QUICPERF_SCENARIOS:-download}"
default_bytes="${QUICPERF_TEST_BYTES:-1073741824}"
bidi_bytes="${QUICPERF_BIDI_TEST_BYTES:-67108864}"
flow_control_bytes="${QUICPERF_FLOW_CONTROL_TEST_BYTES:-16777216}"
loss_recovery_bytes="${QUICPERF_LOSS_RECOVERY_TEST_BYTES:-67108864}"
multistream_download_bytes="${QUICPERF_MULTISTREAM_DOWNLOAD_TEST_BYTES:-67108864}"
multistream_upload_bytes="${QUICPERF_MULTISTREAM_UPLOAD_TEST_BYTES:-67108864}"
timeout_s="${QUICPERF_TIMEOUT:-180s}"
server_start_delay="${QUICPERF_SERVER_START_DELAY:-0.5}"
server_ready_timeout="${QUICPERF_SERVER_READY_TIMEOUT:-5}"
server_stop_timeout="${QUICPERF_SERVER_STOP_TIMEOUT:-10s}"
idle_resource_sample_interval="${QUICPERF_IDLE_RESOURCE_SAMPLE_INTERVAL:-0.01}"
randomize_order="${QUICPERF_RANDOMIZE_ORDER:-1}"
random_seed="${QUICPERF_RANDOM_SEED:-$(date -u +%s)}"
build_profile="${QUICPERF_BUILD_PROFILE:-native-lto}"
window_profile="${QUICPERF_WINDOW_PROFILE:-default}"
congestion_profile="${QUICPERF_CONGESTION_PROFILE:-default-bbr}"
tls_verify_mode="${QUICPERF_TLS_VERIFY_MODE:-${QUICPERF_TLS_VERIFY:-disabled}}"
tls_cert_profile="${QUICPERF_TLS_CERT_PROFILE:-ed25519}"
outlier_spread_ratio="${QUICPERF_OUTLIER_SPREAD_RATIO:-10}"
outlier_gate_mode="${QUICPERF_OUTLIER_GATE_MODE:-minmax}"
sample_phase="${QUICPERF_SAMPLE_PHASE:-discovery}"
append_samples_tsv="${QUICPERF_APPEND_SAMPLES_TSV:-}"
run_label_prefix="${QUICPERF_RUN_LABEL_PREFIX:-}"
network_path_helper="$root/tools/quicperf_network_path.py"
path_variation="${QUICPERF_PATH_VARIATION:-1}"
path_time_scale="${QUICPERF_PATH_TIME_SCALE:-1.0}"

select_server_cpu() {
  python3 - <<'PY'
from pathlib import Path
import os
import sys

def online_cpus():
    text = Path("/sys/devices/system/cpu/online").read_text().strip()
    cpus = set()
    for part in text.split(","):
        if "-" in part:
            start, end = (int(x) for x in part.split("-", 1))
            cpus.update(range(start, end + 1))
        elif part:
            cpus.add(int(part))
    return cpus

def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(2)

records = []
try:
    online = online_cpus()
except Exception:
    online = set(range(os.cpu_count() or 1))

for cpu_dir in sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*"), key=lambda p: int(p.name[3:])):
    cpu = int(cpu_dir.name[3:])
    if cpu not in online:
        continue
    package_path = cpu_dir / "topology" / "physical_package_id"
    core_path = cpu_dir / "topology" / "core_id"
    if not package_path.exists() or not core_path.exists():
        continue
    try:
        package = int(package_path.read_text().strip())
        core = int(core_path.read_text().strip())
    except ValueError:
        continue
    records.append((package, core, cpu))

if not records:
    fail("quicperf_cpu_selection_failed reason=no_online_cpu_topology")

physical = {}
for package, core, cpu in records:
    physical.setdefault((package, core), cpu)

ordered = [(package, core, cpu) for (package, core), cpu in physical.items()]
ordered.sort()
by_cpu = {cpu: (package, core) for package, core, cpu in records}

server_req = os.environ.get("QUICPERF_SERVER_CPU")

def parse_cpu(value, name):
    try:
        cpu = int(value)
    except ValueError:
        fail(f"quicperf_cpu_selection_failed reason=invalid_{name} value={value!r}")
    if cpu not in by_cpu:
        fail(f"quicperf_cpu_selection_failed reason={name}_not_online_or_missing_topology cpu={cpu}")
    return cpu

if server_req:
    server_cpu = parse_cpu(server_req, "server_cpu")
else:
    candidates = [entry for entry in ordered if entry[2] != 0]
    server_cpu = (candidates[1] if len(candidates) > 1 else candidates[0])[2] if candidates else ordered[0][2]

server_key = by_cpu[server_cpu]
print(f"{server_cpu} {server_key[0]}:{server_key[1]}")
PY
}

read -r server_cpu server_core < <(select_server_cpu)

out_dir="${QUICPERF_OUT_DIR:-$root/.run/quicperf-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
mkdir -p "$out_dir"
run_meta_path="$out_dir/run-meta.tsv"
printf 'run_label\tphase\tbinary\tscenario\tnetwork\tpath_profile\tclient_threads\tserver_connections\tstatus\treason\tstarted_utc\tended_utc\tduration_sec\tserver_log\tclient_log\trun_order\n' >"$run_meta_path"

append_run_meta() {
  local run_label="$1"
  local phase="$2"
  local binary="$3"
  local scenario="$4"
  local network="$5"
  local path_profile="$6"
  local client_threads="$7"
  local server_connections="$8"
  local status="$9"
  local reason="${10}"
  local started_utc="${11}"
  local ended_utc="${12}"
  local duration_sec="${13}"
  local server_log="${14}"
  local client_log="${15}"
  local run_order="${16}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$run_label" "$phase" "$binary" "$scenario" "$network" "$path_profile" "$client_threads" \
    "$server_connections" "$status" "$reason" "$started_utc" "$ended_utc" \
    "$duration_sec" "$server_log" "$client_log" "$run_order" >>"$run_meta_path"
}

declare -a active_path_states=()

cleanup_path_state() {
  local state="$1"
  [[ -n "$state" && -e "$state" ]] || return 0
  "$network_path_helper" cleanup --state "$state" >/dev/null 2>&1 || true
}

cleanup_all_paths() {
  local state
  for state in "${active_path_states[@]:-}"; do
    cleanup_path_state "$state"
  done
}

trap cleanup_all_paths EXIT
trap 'cleanup_all_paths; exit 130' INT
trap 'cleanup_all_paths; exit 143' TERM

setup_path_profile() {
  local profile="$1"
  local run_id="$2"
  local state="$3"
  local env_path="$4"
  local log_path="$5"
  local -a args=(setup --profile "$profile" --run-id "$run_id" --state "$state" --trace-time-scale "$path_time_scale")
  if [[ "$path_variation" != "1" ]]; then
    args+=(--no-variation)
  fi
  if ! "$network_path_helper" "${args[@]}" >"$env_path" 2>"$log_path"; then
    return 1
  fi
  active_path_states+=("$state")
  # shellcheck disable=SC1090
  source "$env_path"
}

snapshot_path_profile() {
  local state="$1"
  local output="$2"
  [[ -n "$state" && -e "$state" ]] || return 0
  "$network_path_helper" snapshot --state "$state" --output "$output" >/dev/null 2>&1 || true
}

wait_for_server_ready() {
  local server_pid="$1"
  local server_log="$2"
  local ready_timeout="$3"
  python3 - "$server_pid" "$server_log" "$ready_timeout" <<'PY'
import os
import sys
import time
from pathlib import Path

pid = int(sys.argv[1])
log_path = Path(sys.argv[2])
timeout = float(sys.argv[3])
deadline = time.monotonic() + timeout
offset = 0

while True:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        raise SystemExit(1)
    except PermissionError:
        pass

    try:
        text = log_path.read_text(errors="replace")
    except FileNotFoundError:
        text = ""
    if "quicperf_server_ready " in text[offset:]:
        raise SystemExit(0)
    offset = max(0, len(text) - 4096)

    if time.monotonic() >= deadline:
        raise SystemExit(2)
    time.sleep(0.01)
PY
}

proc_rss_bytes() {
  local pid="$1"
  awk '/^VmRSS:/ { printf "%.0f\n", $2 * 1024; found=1; exit } END { if (!found) exit 1 }' "/proc/$pid/status"
}

sample_server_rss_peak() {
  local pid="$1"
  local peak="$2"
  local output="$3"
  printf '%s\n' "$peak" >"$output"
  while true; do
    local current
    if ! current="$(proc_rss_bytes "$pid" 2>/dev/null)"; then
      break
    fi
    if (( current > peak )); then
      peak="$current"
      printf '%s\n' "$peak" >"$output"
    fi
    sleep "$idle_resource_sample_interval"
  done
  printf '%s\n' "$peak" >"$output"
}

append_idle_resource_metric() {
  local client_log="$1"
  local connections="$2"
  local baseline="$3"
  local peak="$4"
  local delta=0
  if (( peak > baseline )); then
    delta=$((peak - baseline))
  fi
  local per_connection
  per_connection="$(awk -v delta="$delta" -v connections="$connections" 'BEGIN { if (connections > 0) printf "%.6f", delta / connections; else printf "0.000000" }')"
  local base_line
  base_line="$(grep -E 'quicperf_result .*scenario=idle_footprint .*role=client ' "$client_log" | tail -n 1 || true)"
  if [[ -z "$base_line" ]]; then
    return 1
  fi
  printf '%s server_rss_baseline_bytes=%s server_rss_peak_bytes=%s server_rss_delta_bytes=%s server_rss_delta_bytes_per_connection=%s\n' \
    "$base_line" "$baseline" "$peak" "$delta" "$per_connection" >>"$client_log"
}

if [[ -n "${QUICPERF_BINARIES:-}" ]]; then
  read -r -a binaries <<<"$QUICPERF_BINARIES"
else
  binaries=("$bin_dir"/*perf)
fi

if [[ "$randomize_order" == "1" ]]; then
  mapfile -t binaries < <(printf '%s\n' "${binaries[@]}" | QUICPERF_RANDOM_SEED="$random_seed" python3 -c '
import os
import random
import sys
items = [line.rstrip("\n") for line in sys.stdin if line.rstrip("\n")]
random.Random(int(os.environ["QUICPERF_RANDOM_SEED"])).shuffle(items)
print("\n".join(items))
')
fi

for path_profile in $path_profiles; do
  if ! "$network_path_helper" show "$path_profile" >/dev/null; then
    echo "quicperf_run_result path_profile=$path_profile status=invalid_path_profile"
    exit 2
  fi
done

{
  printf 'quicperf_environment date_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'quicperf_environment kernel=%s\n' "$(uname -a)"
  printf 'quicperf_environment command=%q' "$0"
  printf ' %q' "$@"
  printf '\n'
  printf 'quicperf_environment variables\n'
  env | sort | grep '^QUICPERF_' || true
  printf 'quicperf_environment lscpu_begin\n'
  lscpu || true
  printf 'quicperf_environment lscpu_end\n'
  printf 'quicperf_environment sysctl_begin\n'
  sysctl net.core.rmem_max net.core.wmem_max net.ipv4.tcp_congestion_control net.ipv4.tcp_available_congestion_control 2>/dev/null || true
  printf 'quicperf_environment sysctl_end\n'
} >"$out_dir/environment.txt"

port_slot_offset="${QUICPERF_PORT_SLOT_OFFSET:-}"
port_policy="random_per_sample"
if [[ -n "${QUICPERF_SERVER_PORT:-}" ]]; then
  port_policy="fixed:${QUICPERF_SERVER_PORT}"
elif [[ -n "$port_slot_offset" ]]; then
  port_policy="slot_offset:$port_slot_offset"
fi
echo "quicperf_run out_dir=$out_dir bytes=$default_bytes multistream_download_bytes=$multistream_download_bytes multistream_upload_bytes=$multistream_upload_bytes bidi_bytes=$bidi_bytes flow_control_bytes=$flow_control_bytes loss_recovery_bytes=$loss_recovery_bytes repeat=$repeat warmup=$warmup scenarios=\"$scenarios\" networks=\"$networks\" path_profiles=\"$path_profiles\" build_profile=$build_profile window_profile=$window_profile congestion_profile=$congestion_profile tls_verify_mode=$tls_verify_mode tls_cert_profile=$tls_cert_profile randomize_order=$randomize_order random_seed=$random_seed port_policy=$port_policy outlier_gate_mode=$outlier_gate_mode outlier_spread_ratio=$outlier_spread_ratio server_cpu=$server_cpu server_core=$server_core server_cpu_policy=pinned_low_noise_physical_core client_cpu_policy=unpinned server_start_delay=$server_start_delay server_ready_timeout=$server_ready_timeout server_stop_timeout=$server_stop_timeout"
run_failed=0
run_ordinal=0
declare -A used_auto_ports=()

random_u32() {
  od -An -N4 -tu4 /dev/urandom | tr -d ' '
}

port_block_free() {
  local first="$1"
  local width="$2"
  local port
  for ((port = first; port < first + width; ++port)); do
    if [[ -n "${used_auto_ports[$port]:-}" ]]; then
      return 1
    fi
    if udp_port_in_use "$port"; then
      return 1
    fi
  done
  return 0
}

udp_port_in_use() {
  local port="$1"
  local port_hex local_addr local_port ignored file
  printf -v port_hex '%04X' "$port"
  for file in /proc/net/udp /proc/net/udp6; do
    [[ -r "$file" ]] || continue
    while read -r ignored local_addr ignored; do
      [[ "$local_addr" == "local_address" ]] && continue
      local_port="${local_addr##*:}"
      if [[ "${local_port^^}" == "$port_hex" ]]; then
        return 0
      fi
    done <"$file"
  done
  return 1
}

reserve_port_block() {
  local first="$1"
  local width="$2"
  local port
  for ((port = first; port < first + width; ++port)); do
    used_auto_ports[$port]=1
  done
}

choose_auto_port_block() {
  local result_var="$1"
  local min="$2"
  local max="$3"
  local width="$4"
  local span=$((max - min + 1))
  local seed candidate attempt
  if ((span < width)); then
    echo "quicperf_port_selection_failed reason=range_too_small min=$min max=$max width=$width" >&2
    exit 2
  fi
  for ((attempt = 0; attempt < 128; ++attempt)); do
    seed="$(random_u32)"
    candidate=$((min + seed % (span - width + 1)))
    if port_block_free "$candidate" "$width"; then
      reserve_port_block "$candidate" "$width"
      printf -v "$result_var" '%s' "$candidate"
      return
    fi
  done
  for ((candidate = min; candidate <= max - width + 1; ++candidate)); do
    if port_block_free "$candidate" "$width"; then
      reserve_port_block "$candidate" "$width"
      printf -v "$result_var" '%s' "$candidate"
      return
    fi
  done
  echo "quicperf_port_selection_failed reason=no_unused_port_block min=$min max=$max width=$width" >&2
  exit 2
}

client_threads_for_scenario() {
  local scenario="$1"
  local fallback="${QUICPERF_CLIENT_THREADS:-1}"
  case "$scenario" in
    connect) echo "${QUICPERF_CONNECT_CLIENT_THREADS:-$fallback}" ;;
    download) echo "${QUICPERF_DOWNLOAD_CLIENT_THREADS:-$fallback}" ;;
    upload) echo "${QUICPERF_UPLOAD_CLIENT_THREADS:-$fallback}" ;;
    reqresp) echo "${QUICPERF_REQRESP_CLIENT_THREADS:-$fallback}" ;;
    stream_churn) echo "${QUICPERF_STREAM_CHURN_CLIENT_THREADS:-$fallback}" ;;
    multistream_download) echo "${QUICPERF_MULTISTREAM_DOWNLOAD_CLIENT_THREADS:-$fallback}" ;;
    multistream_upload) echo "${QUICPERF_MULTISTREAM_UPLOAD_CLIENT_THREADS:-$fallback}" ;;
    bidi) echo "${QUICPERF_BIDI_CLIENT_THREADS:-$fallback}" ;;
    small_payload_pps) echo "${QUICPERF_SMALL_PAYLOAD_PPS_CLIENT_THREADS:-$fallback}" ;;
    loss_recovery) echo "${QUICPERF_LOSS_RECOVERY_CLIENT_THREADS:-$fallback}" ;;
    flow_control) echo "${QUICPERF_FLOW_CONTROL_CLIENT_THREADS:-$fallback}" ;;
    resumed_connect) echo "${QUICPERF_RESUMED_CONNECT_CLIENT_THREADS:-$fallback}" ;;
    zero_rtt_reqresp) echo "${QUICPERF_ZERO_RTT_REQRESP_CLIENT_THREADS:-$fallback}" ;;
    datagram) echo "${QUICPERF_DATAGRAM_CLIENT_THREADS:-$fallback}" ;;
    idle_footprint) echo "${QUICPERF_IDLE_FOOTPRINT_CLIENT_THREADS:-$fallback}" ;;
    close_reset_cleanup) echo "${QUICPERF_CLOSE_RESET_CLEANUP_CLIENT_THREADS:-$fallback}" ;;
    *) echo "$fallback" ;;
  esac
}

test_bytes_for_scenario() {
  local scenario="$1"
  case "$scenario" in
    bidi) echo "$bidi_bytes" ;;
    flow_control) echo "$flow_control_bytes" ;;
    loss_recovery) echo "$loss_recovery_bytes" ;;
    multistream_download) echo "$multistream_download_bytes" ;;
    multistream_upload) echo "$multistream_upload_bytes" ;;
    *) echo "$default_bytes" ;;
  esac
}

require_thread_log() {
  local role="$1"
  local phase="$2"
  local expected="$3"
  local log="$4"
  if ! grep -Eq "quicperf_thread_check .*role=${role} .*phase=${phase} .*expected_threads=${expected} .*threads=${expected} .*status=ok" "$log"; then
    echo "quicperf_thread_check role=$role phase=$phase expected_threads=$expected status=missing_or_failed log=$log"
    return 1
  fi
}

for bin in "${binaries[@]}"; do
  [[ "$bin" = /* ]] || bin="$bin_dir/$bin"
  name="$(basename "$bin")"

  if [[ ! -x "$bin" ]]; then
    continue
  fi

  for scenario in $scenarios; do
    client_threads="$(client_threads_for_scenario "$scenario")"
    bytes="$(test_bytes_for_scenario "$scenario")"
    server_connections="${QUICPERF_SERVER_CONNECTIONS:-$client_threads}"
    case "$scenario" in
      download|upload|connect|reqresp|stream_churn|multistream_download|multistream_upload|bidi|small_payload_pps|loss_recovery|flow_control|resumed_connect|zero_rtt_reqresp|datagram|idle_footprint|close_reset_cleanup) ;;
      *)
        echo "quicperf_run_result binary=$name scenario=$scenario status=invalid_scenario"
        run_failed=1
        continue
        ;;
    esac

    if (( client_threads != server_connections )); then
      echo "quicperf_run_result binary=$name scenario=$scenario client_threads=$client_threads server_connections=$server_connections status=invalid reason=server_connections_must_match_client_threads"
      run_failed=1
      continue
    fi

    for network in $networks; do
      case "$network" in
        syscall|iouring) ;;
        gso_gro|udp_gso_gro)
          echo "quicperf_run_result binary=$name scenario=$scenario network=$network status=unsupported reason=udp_gso_gro_is_default_on_iouring"
          continue
          ;;
        *)
          echo "quicperf_run_result binary=$name scenario=$scenario network=$network status=invalid_network"
          run_failed=1
          continue
          ;;
      esac

      if [[ "$name" == "tcpperf" && "$network" == "iouring" ]]; then
        echo "quicperf_run_result binary=$name scenario=$scenario network=$network status=unsupported reason=tcp_tls_syscall_only"
        continue
      fi

      for path_profile in $path_profiles; do
      sample_run=0
      total_runs=$((warmup + repeat))
      for ((attempt = 1; attempt <= total_runs; ++attempt)); do
        run_ordinal=$((run_ordinal + 1))
        if [[ -n "${QUICPERF_SERVER_PORT:-}" ]]; then
          server_port="$QUICPERF_SERVER_PORT"
        elif [[ -n "$port_slot_offset" ]]; then
          port_slot=$(((port_slot_offset + run_ordinal - 1) % 512))
          server_port=$((10000 + port_slot * 64))
        else
          choose_auto_port_block server_port 10000 39999 1
        fi
        if [[ -n "${QUICPERF_CLIENT_BASE_PORT:-}" ]]; then
          client_base_port="$QUICPERF_CLIENT_BASE_PORT"
        elif [[ -n "$port_slot_offset" ]]; then
          port_slot=$(((port_slot_offset + run_ordinal - 1) % 512))
          client_base_port=$((45000 + port_slot * 32))
        else
          choose_auto_port_block client_base_port 45000 65535 "$client_threads"
        fi
        if (( attempt <= warmup )); then
          run_label="${run_label_prefix}warmup-${attempt}"
          attempt_phase="warmup"
          server_log="$out_dir/${name}-${scenario}-${network}-${path_profile}-${run_label}.server.warmup.log"
          client_log="$out_dir/${name}-${scenario}-${network}-${path_profile}-${run_label}.client.warmup.log"
        else
          sample_run=$((sample_run + 1))
          run_label="${run_label_prefix}${sample_run}"
          attempt_phase="$sample_phase"
          server_log="$out_dir/${name}-${scenario}-${network}-${path_profile}-${run_label}.server.log"
          client_log="$out_dir/${name}-${scenario}-${network}-${path_profile}-${run_label}.client.log"
	        fi
	        run_started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	        run_start_ns="$(date +%s%N)"

	        path_run_id="${name}-${scenario}-${network}-${path_profile}-${run_ordinal}-$$"
	        path_state="$out_dir/${name}-${scenario}-${network}-${path_profile}-${run_label}.path.json"
	        path_env="$out_dir/${name}-${scenario}-${network}-${path_profile}-${run_label}.path.env"
	        path_log="$out_dir/${name}-${scenario}-${network}-${path_profile}-${run_label}.path.log"
	        path_snapshot="$out_dir/${name}-${scenario}-${network}-${path_profile}-${run_label}.path.snapshot.txt"
	        if ! setup_path_profile "$path_profile" "$path_run_id" "$path_state" "$path_env" "$path_log"; then
	          run_ended_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	          run_end_ns="$(date +%s%N)"
	          duration_ns=$((run_end_ns - run_start_ns))
	          duration_sec="$(printf '%s.%09d' $((duration_ns / 1000000000)) $((duration_ns % 1000000000)))"
	          append_run_meta "$run_label" "$attempt_phase" "$name" "$scenario" "$network" "$path_profile" "$client_threads" "$server_connections" "path_failed" "path_setup_failed" "$run_started_utc" "$run_ended_utc" "$duration_sec" "$server_log" "$client_log" "$run_ordinal"
	          echo "quicperf_run_result binary=$name scenario=$scenario network=$network path_profile=$path_profile run=$run_label status=path_failed reason=path_setup_failed"
	          sed "s/^/path: /" "$path_log" 2>/dev/null || true
	          run_failed=1
	          break
	        fi
	        server_address_arg="$QUICPERF_SERVER_ADDRESS"
	        server_local_address="$QUICPERF_SERVER_ADDRESS"
	        server_remote_address="$QUICPERF_CLIENT_ADDRESS"
	        client_local_address="$QUICPERF_CLIENT_ADDRESS"
	        client_remote_address="$QUICPERF_SERVER_ADDRESS"
	        server_prefix=()
	        client_prefix=()
	        if [[ "$QUICPERF_PATH_KIND" == "namespace" ]]; then
	          server_prefix=(ip netns exec "$QUICPERF_SERVER_NAMESPACE")
	          client_prefix=(ip netns exec "$QUICPERF_CLIENT_NAMESPACE")
	        fi

	        QUICPERF_SCENARIO="$scenario" QUICPERF_TEST_BYTES="$bytes" QUICPERF_SERVER_PORT="$server_port" QUICPERF_BUILD_PROFILE="$build_profile" QUICPERF_WINDOW_PROFILE="$window_profile" QUICPERF_CONGESTION_PROFILE="$congestion_profile" QUICPERF_TLS_VERIFY_MODE="$tls_verify_mode" QUICPERF_TLS_CERT_PROFILE="$tls_cert_profile" QUICPERF_NETWORK_PROFILE="$network" QUICPERF_PATH_PROFILE="$path_profile" QUICPERF_PATH_RTT_US="$QUICPERF_PATH_RTT_US" QUICPERF_PATH_DOWNLINK_BPS="$QUICPERF_PATH_DOWNLINK_BPS" QUICPERF_PATH_UPLINK_BPS="$QUICPERF_PATH_UPLINK_BPS" QUICPERF_PATH_MAX_RATE_BPS="$QUICPERF_PATH_MAX_RATE_BPS" QUICPERF_LOCAL_ADDRESS="$server_local_address" QUICPERF_REMOTE_ADDRESS="$server_remote_address" QUICPERF_SERVER_CONNECTIONS="$server_connections" "${server_prefix[@]}" taskset -c "$server_cpu" "$bin" server "$network" "$server_address_arg" "$scenario" >"$server_log" 2>&1 &
	        server_pid=$!
	        set +e
	        wait_for_server_ready "$server_pid" "$server_log" "$server_ready_timeout"
	        server_ready_status=$?
	        set -e

	        if (( server_ready_status == 2 )); then
	          kill "$server_pid" 2>/dev/null || true
	          wait "$server_pid" 2>/dev/null || true
	          run_ended_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	          run_end_ns="$(date +%s%N)"
	          duration_ns=$((run_end_ns - run_start_ns))
	          duration_sec="$(printf '%s.%09d' $((duration_ns / 1000000000)) $((duration_ns % 1000000000)))"
		          snapshot_path_profile "$path_state" "$path_snapshot"
		          cleanup_path_state "$path_state"
		          append_run_meta "$run_label" "$attempt_phase" "$name" "$scenario" "$network" "$path_profile" "$client_threads" "$server_connections" "server_failed" "server_ready_timeout" "$run_started_utc" "$run_ended_utc" "$duration_sec" "$server_log" "$client_log" "$run_ordinal"
		          echo "quicperf_run_result binary=$name scenario=$scenario network=$network path_profile=$path_profile run=$run_label status=server_failed reason=server_ready_timeout"
	          sed "s/^/server: /" "$server_log"
	          run_failed=1
	          break
	        fi

	        if ! kill -0 "$server_pid" 2>/dev/null; then
          set +e
          wait "$server_pid" 2>/dev/null
          server_early_status=$?
          set -e
          if (( server_early_status == 77 )) || grep -q 'status=unsupported' "$server_log"; then
            reason="$(grep -Eo 'reason=[^ ]+' "$server_log" | head -n 1 | cut -d= -f2-)"
            [[ -n "$reason" ]] || reason="scenario_unsupported"
            run_ended_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            run_end_ns="$(date +%s%N)"
            duration_ns=$((run_end_ns - run_start_ns))
            duration_sec="$(printf '%s.%09d' $((duration_ns / 1000000000)) $((duration_ns % 1000000000)))"
            snapshot_path_profile "$path_state" "$path_snapshot"
            cleanup_path_state "$path_state"
            append_run_meta "$run_label" "$attempt_phase" "$name" "$scenario" "$network" "$path_profile" "$client_threads" "$server_connections" "unsupported" "$reason" "$run_started_utc" "$run_ended_utc" "$duration_sec" "$server_log" "$client_log" "$run_ordinal"
            echo "quicperf_run_result binary=$name scenario=$scenario network=$network path_profile=$path_profile run=$run_label status=unsupported reason=$reason"
            sed "s/^/server: /" "$server_log"
            break
          fi
          run_ended_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          run_end_ns="$(date +%s%N)"
          duration_ns=$((run_end_ns - run_start_ns))
          duration_sec="$(printf '%s.%09d' $((duration_ns / 1000000000)) $((duration_ns % 1000000000)))"
          snapshot_path_profile "$path_state" "$path_snapshot"
          cleanup_path_state "$path_state"
          append_run_meta "$run_label" "$attempt_phase" "$name" "$scenario" "$network" "$path_profile" "$client_threads" "$server_connections" "server_failed" "server_failed" "$run_started_utc" "$run_ended_utc" "$duration_sec" "$server_log" "$client_log" "$run_ordinal"
          echo "quicperf_run_result binary=$name scenario=$scenario network=$network path_profile=$path_profile run=$run_label status=server_failed"
          sed "s/^/server: /" "$server_log"
          run_failed=1
          break
        fi

        idle_server_rss_baseline_bytes=0
        idle_server_rss_peak_bytes=0
        idle_rss_peak_file=""
        idle_rss_sampler_pid=""
        if [[ "$scenario" == "idle_footprint" ]]; then
          idle_server_rss_baseline_bytes="$(proc_rss_bytes "$server_pid" 2>/dev/null || printf '0')"
          idle_server_rss_peak_bytes="$idle_server_rss_baseline_bytes"
          idle_rss_peak_file="$out_dir/${name}-${scenario}-${network}-${run_label}.server-rss-peak"
          sample_server_rss_peak "$server_pid" "$idle_server_rss_peak_bytes" "$idle_rss_peak_file" &
          idle_rss_sampler_pid=$!
        fi

        set +e
        QUICPERF_SCENARIO="$scenario" QUICPERF_TEST_BYTES="$bytes" QUICPERF_SERVER_PORT="$server_port" QUICPERF_CLIENT_THREADS="$client_threads" QUICPERF_CLIENT_BASE_PORT="$client_base_port" QUICPERF_BUILD_PROFILE="$build_profile" QUICPERF_WINDOW_PROFILE="$window_profile" QUICPERF_CONGESTION_PROFILE="$congestion_profile" QUICPERF_TLS_VERIFY_MODE="$tls_verify_mode" QUICPERF_TLS_CERT_PROFILE="$tls_cert_profile" QUICPERF_NETWORK_PROFILE="$network" QUICPERF_PATH_PROFILE="$path_profile" QUICPERF_PATH_RTT_US="$QUICPERF_PATH_RTT_US" QUICPERF_PATH_DOWNLINK_BPS="$QUICPERF_PATH_DOWNLINK_BPS" QUICPERF_PATH_UPLINK_BPS="$QUICPERF_PATH_UPLINK_BPS" QUICPERF_PATH_MAX_RATE_BPS="$QUICPERF_PATH_MAX_RATE_BPS" QUICPERF_LOCAL_ADDRESS="$client_local_address" QUICPERF_REMOTE_ADDRESS="$client_remote_address" QUICPERF_SERVER_CONNECTIONS="$server_connections" timeout "$timeout_s" "${client_prefix[@]}" "$bin" client "$network" "$server_address_arg" "$scenario" >"$client_log" 2>&1
        client_status=$?
        if [[ -n "$idle_rss_sampler_pid" ]]; then
          kill "$idle_rss_sampler_pid" 2>/dev/null || true
          wait "$idle_rss_sampler_pid" 2>/dev/null || true
          if [[ -s "$idle_rss_peak_file" ]]; then
            idle_server_rss_peak_bytes="$(cat "$idle_rss_peak_file")"
          fi
        fi
        set -e

        if (( client_status != 0 )); then
          kill "$server_pid" 2>/dev/null || true
          wait "$server_pid" 2>/dev/null || true
          if (( client_status == 77 )) || grep -q 'status=unsupported' "$client_log"; then
            reason="$(grep -Eo 'reason=[^ ]+' "$client_log" | head -n 1 | cut -d= -f2-)"
            [[ -n "$reason" ]] || reason="scenario_unsupported"
            run_ended_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            run_end_ns="$(date +%s%N)"
            duration_ns=$((run_end_ns - run_start_ns))
            duration_sec="$(printf '%s.%09d' $((duration_ns / 1000000000)) $((duration_ns % 1000000000)))"
            snapshot_path_profile "$path_state" "$path_snapshot"
            cleanup_path_state "$path_state"
            append_run_meta "$run_label" "$attempt_phase" "$name" "$scenario" "$network" "$path_profile" "$client_threads" "$server_connections" "unsupported" "$reason" "$run_started_utc" "$run_ended_utc" "$duration_sec" "$server_log" "$client_log" "$run_ordinal"
            echo "quicperf_run_result binary=$name scenario=$scenario network=$network path_profile=$path_profile run=$run_label status=unsupported reason=$reason"
            sed "s/^/client: /" "$client_log"
            break
          fi
          run_ended_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          run_end_ns="$(date +%s%N)"
          duration_ns=$((run_end_ns - run_start_ns))
          duration_sec="$(printf '%s.%09d' $((duration_ns / 1000000000)) $((duration_ns % 1000000000)))"
          snapshot_path_profile "$path_state" "$path_snapshot"
          cleanup_path_state "$path_state"
          append_run_meta "$run_label" "$attempt_phase" "$name" "$scenario" "$network" "$path_profile" "$client_threads" "$server_connections" "client_failed" "exit_$client_status" "$run_started_utc" "$run_ended_utc" "$duration_sec" "$server_log" "$client_log" "$run_ordinal"
          echo "quicperf_run_result binary=$name scenario=$scenario network=$network path_profile=$path_profile run=$run_label status=client_failed exit=$client_status"
          sed "s/^/client: /" "$client_log"
          run_failed=1
          break
        fi

        server_status=complete
        if ! timeout "$server_stop_timeout" tail --pid="$server_pid" -f /dev/null >/dev/null 2>&1; then
          kill "$server_pid" 2>/dev/null || true
          wait "$server_pid" 2>/dev/null || true
          server_status=stopped_after_client
        else
          wait "$server_pid"
        fi
        thread_failure_reason=""
        if ! require_thread_log client harness_ready "$client_threads" "$client_log"; then
          thread_failure_reason="missing_client_harness_ready"
        elif ! require_thread_log client complete 1 "$client_log"; then
          thread_failure_reason="missing_client_complete"
        elif ! require_thread_log server complete 1 "$server_log"; then
          thread_failure_reason="missing_server_complete"
        fi
        if [[ -n "$thread_failure_reason" ]]; then
          run_ended_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          run_end_ns="$(date +%s%N)"
          duration_ns=$((run_end_ns - run_start_ns))
          duration_sec="$(printf '%s.%09d' $((duration_ns / 1000000000)) $((duration_ns % 1000000000)))"
          snapshot_path_profile "$path_state" "$path_snapshot"
          cleanup_path_state "$path_state"
          append_run_meta "$run_label" "$attempt_phase" "$name" "$scenario" "$network" "$path_profile" "$client_threads" "$server_connections" "thread_check_failed" "$thread_failure_reason" "$run_started_utc" "$run_ended_utc" "$duration_sec" "$server_log" "$client_log" "$run_ordinal"
          echo "quicperf_run_result binary=$name scenario=$scenario network=$network path_profile=$path_profile run=$run_label status=thread_check_failed reason=$thread_failure_reason"
          sed "s/^/client: /" "$client_log"
          sed "s/^/server: /" "$server_log"
          run_failed=1
          break
        fi
        if [[ "$scenario" == "idle_footprint" ]]; then
          if ! append_idle_resource_metric "$client_log" "$server_connections" "$idle_server_rss_baseline_bytes" "$idle_server_rss_peak_bytes"; then
            run_ended_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            run_end_ns="$(date +%s%N)"
            duration_ns=$((run_end_ns - run_start_ns))
            duration_sec="$(printf '%s.%09d' $((duration_ns / 1000000000)) $((duration_ns % 1000000000)))"
            append_run_meta "$run_label" "$attempt_phase" "$name" "$scenario" "$network" "$client_threads" "$server_connections" "client_failed" "missing_idle_result_line" "$run_started_utc" "$run_ended_utc" "$duration_sec" "$server_log" "$client_log" "$run_ordinal"
            echo "quicperf_run_result binary=$name scenario=$scenario network=$network run=$run_label status=client_failed reason=missing_idle_result_line"
            sed "s/^/client: /" "$client_log"
            sed "s/^/server: /" "$server_log"
            run_failed=1
            break
          fi
        fi
        sed "s/^/client: /" "$client_log"
        sed "s/^/server: /" "$server_log"
        run_ended_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        run_end_ns="$(date +%s%N)"
        duration_ns=$((run_end_ns - run_start_ns))
        duration_sec="$(printf '%s.%09d' $((duration_ns / 1000000000)) $((duration_ns % 1000000000)))"
        snapshot_path_profile "$path_state" "$path_snapshot"
        cleanup_path_state "$path_state"
        append_run_meta "$run_label" "$attempt_phase" "$name" "$scenario" "$network" "$path_profile" "$client_threads" "$server_connections" "ok" "" "$run_started_utc" "$run_ended_utc" "$duration_sec" "$server_log" "$client_log" "$run_ordinal"
        echo "quicperf_run_result binary=$name scenario=$scenario network=$network path_profile=$path_profile run=$run_label status=ok server_status=$server_status"
      done
    done
  done
done
done

PYTHONPATH="$root/tools${PYTHONPATH:+:$PYTHONPATH}" python3 - "$out_dir" "$outlier_spread_ratio" "$outlier_gate_mode" <<'PY'
from pathlib import Path
from collections import defaultdict
import csv
import os
import re
import sys
from quicperf_stats import RESULT_RE, Sample, parse_client_log_samples, quantile, scenario_metric_name, write_samples

out_dir = Path(sys.argv[1])
outlier_spread_ratio = float(sys.argv[2])
outlier_gate_mode = sys.argv[3]
result = RESULT_RE
groups = defaultdict(list)
outlier_failures = []
meta_by_client_log = {}

meta_path = out_dir / "run-meta.tsv"
if meta_path.exists():
    with meta_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for row in reader:
            if row.get("client_log"):
                meta_by_client_log[str(Path(row["client_log"]))] = row

for path in sorted(out_dir.glob("*.client.log")):
    stem = path.name.removesuffix(".client.log")
    binary = meta_by_client_log.get(str(path), {}).get("binary") or stem.split("-", 1)[0]

    for line in path.read_text(errors="replace").splitlines():
        match = result.search(line)
        if not match:
            continue
        (
            library,
            scenario,
            network,
            client_threads,
            build_profile,
            window_profile,
            congestion_profile,
            network_profile,
            path_profile,
            app_chunk,
            server_connections,
            tls_verify_mode,
            tls_cert_profile,
            adapter_features,
            initial_cwnd_packets,
            ack_frequency_packets,
            socket_sndbuf_requested,
            socket_sndbuf_effective,
            socket_rcvbuf_requested,
            socket_rcvbuf_effective,
            metric,
            value,
        ) = match.groups()
        groups[
            (
                binary,
	                library,
	                scenario,
	                network,
	                path_profile or "loopback",
	                client_threads,
	                build_profile,
	                window_profile,
	                congestion_profile,
	                network_profile,
	                app_chunk,
                server_connections,
                tls_verify_mode,
                tls_cert_profile,
                adapter_features,
                initial_cwnd_packets,
                ack_frequency_packets,
                socket_sndbuf_requested,
                socket_sndbuf_effective,
                socket_rcvbuf_requested,
                socket_rcvbuf_effective,
                metric,
            )
        ].append(float(value))

summary_path = out_dir / "summary.tsv"
with summary_path.open("w", encoding="utf-8") as summary:
    summary.write("binary\tlibrary\tscenario\tnetwork\tpath_profile\tclient_threads\tbuild_profile\twindow_profile\tcongestion_profile\tnetwork_profile\tapp_chunk\tserver_connections\ttls_verify_mode\ttls_cert_profile\tadapter_features\tinitial_cwnd_packets\tack_frequency_packets\tsocket_sndbuf_requested\tsocket_sndbuf_effective\tsocket_rcvbuf_requested\tsocket_rcvbuf_effective\tmetric\tsamples\tmin\tp50\tp90\tp99\tmax\n")

    for key in sorted(groups):
        values = sorted(groups[key])
        if not values:
            continue

        (
            binary,
            library,
            scenario,
            network,
            path_profile,
            client_threads,
            build_profile,
            window_profile,
            congestion_profile,
            network_profile,
            app_chunk,
            server_connections,
            tls_verify_mode,
            tls_cert_profile,
            adapter_features,
            initial_cwnd_packets,
            ack_frequency_packets,
            socket_sndbuf_requested,
            socket_sndbuf_effective,
            socket_rcvbuf_requested,
            socket_rcvbuf_effective,
            metric,
        ) = key
        outlier_low = values[0]
        outlier_high = values[-1]
        outlier_low_label = "min"
        outlier_high_label = "max"
        percentile_mode = re.fullmatch(r"p(\d+)_p(\d+)", outlier_gate_mode)
        if outlier_gate_mode in {"off", "none", "disabled"}:
            pass
        elif percentile_mode:
            low_pct = int(percentile_mode.group(1))
            high_pct = int(percentile_mode.group(2))
            if not (0 < low_pct < high_pct < 100):
                print(f"quicperf_outlier_gate status=failed reason=invalid_mode mode={outlier_gate_mode}")
                raise SystemExit(3)
            if len(values) >= 10:
                outlier_low = quantile(values, low_pct / 100.0)
                outlier_high = quantile(values, high_pct / 100.0)
                outlier_low_label = f"p{low_pct}"
                outlier_high_label = f"p{high_pct}"
        elif outlier_gate_mode != "minmax":
            print(f"quicperf_outlier_gate status=failed reason=invalid_mode mode={outlier_gate_mode}")
            raise SystemExit(3)
        if outlier_gate_mode not in {"off", "none", "disabled"} and len(values) >= 3 and outlier_low > 0 and outlier_high / outlier_low > outlier_spread_ratio:
            outlier_failures.append((key, outlier_low_label, outlier_low, outlier_high_label, outlier_high, outlier_high / outlier_low))
        row = {
            "binary": binary,
            "library": library,
            "scenario": scenario,
            "network": network,
            "path_profile": path_profile,
            "client_threads": client_threads,
            "metric": metric,
            "samples": len(values),
            "min": values[0],
            "p50": quantile(values, 0.50),
            "p90": quantile(values, 0.90),
            "p99": quantile(values, 0.99),
            "max": values[-1],
        }
        summary.write(
            f"{binary}\t{library}\t{scenario}\t{network}\t{path_profile}\t{client_threads}\t"
            f"{build_profile}\t{window_profile}\t{congestion_profile}\t{network_profile}\t"
            f"{app_chunk}\t{server_connections}\t{tls_verify_mode}\t{tls_cert_profile}\t"
            f"{adapter_features}\t{initial_cwnd_packets}\t{ack_frequency_packets}\t"
            f"{socket_sndbuf_requested}\t{socket_sndbuf_effective}\t"
            f"{socket_rcvbuf_requested}\t{socket_rcvbuf_effective}\t{metric}\t{row['samples']}\t"
            f"{row['min']:.6f}\t{row['p50']:.6f}\t"
            f"{row['p90']:.6f}\t{row['p99']:.6f}\t{row['max']:.6f}\n"
        )
        print(
            f"quicperf_summary binary={binary} library={library} scenario={scenario} "
            f"network={network} path_profile={path_profile} client_threads={client_threads} build_profile={build_profile} "
            f"window_profile={window_profile} congestion_profile={congestion_profile} "
            f"network_profile={network_profile} app_chunk={app_chunk} server_connections={server_connections} "
            f"tls_verify_mode={tls_verify_mode} tls_cert_profile={tls_cert_profile} "
            f"adapter_features={adapter_features} initial_cwnd_packets={initial_cwnd_packets} "
            f"ack_frequency_packets={ack_frequency_packets} "
            f"socket_sndbuf_requested={socket_sndbuf_requested} socket_sndbuf_effective={socket_sndbuf_effective} "
            f"socket_rcvbuf_requested={socket_rcvbuf_requested} socket_rcvbuf_effective={socket_rcvbuf_effective} "
            f"metric={metric} samples={row['samples']} "
            f"min={row['min']:.6f} p50={row['p50']:.6f} "
            f"p90={row['p90']:.6f} p99={row['p99']:.6f} max={row['max']:.6f}"
        )

print(f"quicperf_summary_file path={summary_path}")

publication_id = os.environ.get("QUICPERF_PUBLICATION_ID", "")
round_index = int(os.environ.get("QUICPERF_ADAPTIVE_ROUND", "0") or "0")
block_id = os.environ.get("QUICPERF_ADAPTIVE_BLOCK_ID", "") or os.environ.get("QUICPERF_RUN_LABEL_PREFIX", "").strip("-") or out_dir.name
phase = os.environ.get("QUICPERF_SAMPLE_PHASE", "discovery")
random_seed = os.environ.get("QUICPERF_RANDOM_SEED", "")
git_commit = os.environ.get("QUICPERF_GIT_COMMIT", "")
env_hash = os.environ.get("QUICPERF_ENV_HASH", "")
machine_hash = os.environ.get("QUICPERF_MACHINE_HASH", "")

raw_samples = []
for path in sorted(out_dir.glob("*.client.log")):
    if ".warmup." in path.name:
        continue
    meta = meta_by_client_log.get(str(path), {})
    if meta.get("status", "ok") != "ok":
        continue
    raw_samples.extend(parse_client_log_samples(
        path,
        publication_id=publication_id,
        round_index=round_index,
        block_id=block_id,
        sample_id=f"{block_id}:{path.stem}",
        phase=meta.get("phase", phase) or phase,
        status=meta.get("status", "ok") or "ok",
        reason=meta.get("reason", ""),
        started_utc=meta.get("started_utc", ""),
        ended_utc=meta.get("ended_utc", ""),
        duration_sec=float(meta.get("duration_sec", "0") or "0"),
        run_order=int(meta.get("run_order", "0") or "0"),
        random_seed=random_seed,
        out_dir=str(out_dir),
        server_log=meta.get("server_log", ""),
        git_commit=git_commit,
        env_hash=env_hash,
        machine_hash=machine_hash,
    ))
for meta in sorted(meta_by_client_log.values(), key=lambda row: int(row.get("run_order", "0") or "0")):
    status = meta.get("status", "ok") or "ok"
    if status == "ok":
        continue
    scenario = meta.get("scenario", "")
    raw_samples.append(
        Sample(
            publication_id=publication_id,
            round=round_index,
            block_id=block_id,
            sample_id=f"{block_id}:{Path(meta.get('client_log', '')).stem or meta.get('run_label', '')}",
            binary=meta.get("binary", ""),
            library=meta.get("binary", ""),
            scenario=scenario,
            network=meta.get("network", ""),
            path_profile=meta.get("path_profile", "loopback") or "loopback",
            client_threads=int(meta.get("client_threads", "0") or "0"),
            server_connections=int(meta.get("server_connections", "0") or "0"),
            metric=scenario_metric_name(scenario),
            value=None,
            phase=meta.get("phase", phase) or phase,
            status=status,
            reason=meta.get("reason", "") or status,
            started_utc=meta.get("started_utc", ""),
            ended_utc=meta.get("ended_utc", ""),
            duration_sec=float(meta.get("duration_sec", "0") or "0"),
            run_order=int(meta.get("run_order", "0") or "0"),
            random_seed=random_seed,
            out_dir=str(out_dir),
            client_log=meta.get("client_log", ""),
            server_log=meta.get("server_log", ""),
            git_commit=git_commit,
            env_hash=env_hash,
            machine_hash=machine_hash,
        )
    )

raw_samples_path = out_dir / "raw-samples.tsv"
write_samples(raw_samples_path, raw_samples, append=False)
print(f"quicperf_raw_samples_file path={raw_samples_path} samples={len(raw_samples)}")

append_samples_tsv = os.environ.get("QUICPERF_APPEND_SAMPLES_TSV", "")
if append_samples_tsv:
    if raw_samples:
        write_samples(append_samples_tsv, raw_samples, append=True)
    print(f"quicperf_adaptive_samples_appended path={append_samples_tsv} samples={len(raw_samples)}")
if outlier_failures:
    for key, low_label, low, high_label, high, spread in outlier_failures:
        print(
            "quicperf_outlier_gate status=failed "
            f"binary={key[0]} library={key[1]} scenario={key[2]} network={key[3]} path_profile={key[4]} "
            f"metric={key[-1]} mode={outlier_gate_mode} {low_label}={low:.6f} "
            f"{high_label}={high:.6f} spread={spread:.3f} limit={outlier_spread_ratio:.3f}"
        )
    raise SystemExit(3)
PY

exit "$run_failed"
