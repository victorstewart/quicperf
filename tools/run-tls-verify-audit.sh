#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${QUICPERF_BIN_DIR:-$root/build/bin}"
out_root="${QUICPERF_TLS_AUDIT_OUT_DIR:-$root/.run/tls-verify-audit-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
network="${QUICPERF_TLS_AUDIT_NETWORK:-syscall}"
scenario="${QUICPERF_TLS_AUDIT_SCENARIO:-connect}"
all_binaries="${QUICPERF_TLS_AUDIT_BINARIES-ngtcp2perf lsperf tquicperf quicheperf picoperf xquicperf quinnperf s2nperf neqoperf noqperf quiczigperf mvfstperf tcpperf}"
negative_binaries="${QUICPERF_TLS_AUDIT_NEGATIVE_BINARIES-quinnperf s2nperf neqoperf noqperf quiczigperf mvfstperf}"

mkdir -p "$out_root"

audit_tsv="$out_root/tls-verify-audit.tsv"
printf 'binary\tphase\texpectation\tstatus\tout_dir\tlog\n' >"$audit_tsv"
audit_failed=0

require_binary() {
  local name="$1"
  if [[ ! -x "$bin_dir/$name" ]]; then
    printf 'tls_verify_audit status=failed reason=missing_binary binary=%s path=%s\n' "$name" "$bin_dir/$name"
    exit 2
  fi
}

for binary in $all_binaries $negative_binaries; do
  require_binary "$binary"
done

wrong_dir="$out_root/wrong-ca"
mkdir -p "$wrong_dir"
wrong_key="$wrong_dir/wrong-root.key.pem"
wrong_chain="$wrong_dir/wrong-root.chain.pem"
openssl genpkey -algorithm ED25519 -out "$wrong_key" >/dev/null 2>&1
openssl req -new -x509 -key "$wrong_key" -out "$wrong_chain" -days 3650 \
  -subj "/CN=quicperf-wrong-root-ed25519" \
  -addext "basicConstraints=critical,CA:true,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

validate_positive_summary() {
  python3 - "$1" "$all_binaries" "$scenario" "$network" "$audit_tsv" "$positive_out" "$positive_log" <<'PY'
import csv
import sys
from pathlib import Path

summary = Path(sys.argv[1])
expected = sys.argv[2].split()
scenario = sys.argv[3]
network = sys.argv[4]
audit_tsv = Path(sys.argv[5])
out_dir = sys.argv[6]
log = sys.argv[7]
rows = []
if summary.exists():
    with summary.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))

failed = []
audit_rows = []
for binary in expected:
    match = [
        row for row in rows
        if row.get("binary") == binary
        and row.get("scenario") == scenario
        and row.get("network") == network
    ]
    if not match:
        failed.append(binary)
        audit_rows.append((binary, "missing"))
        continue
    row = match[0]
    if row.get("tls_verify_mode") != "chain" or row.get("tls_cert_profile") != "ed25519" or int(row.get("samples", "0")) < 1:
        failed.append(binary)
        audit_rows.append((binary, "bad_summary"))
    else:
        audit_rows.append((binary, "pass"))

with audit_tsv.open("a", encoding="utf-8") as handle:
    for binary, status in audit_rows:
        handle.write(f"{binary}\tpositive_chain\tmust_pass\t{status}\t{out_dir}\t{log}\n")

if failed:
    print(f"tls_verify_audit status=failed phase=positive failed={','.join(failed)}")
    raise SystemExit(1)
PY
}

positive_out="$out_root/positive-chain"
positive_log="$out_root/positive-chain.stdout"
set +e
QUICPERF_OUT_DIR="$positive_out" \
QUICPERF_BINARIES="$all_binaries" \
QUICPERF_SCENARIOS="$scenario" \
QUICPERF_NETWORKS="$network" \
QUICPERF_REPEAT=1 \
QUICPERF_WARMUP=0 \
QUICPERF_TEST_BYTES=1 \
QUICPERF_TIMEOUT="${QUICPERF_TLS_AUDIT_TIMEOUT:-30s}" \
QUICPERF_RANDOMIZE_ORDER=0 \
QUICPERF_TLS_VERIFY_MODE=chain \
QUICPERF_TLS_CERT_PROFILE=ed25519 \
"$root/tools/run-benchmarks.sh" >"$positive_log" 2>&1
positive_status=$?
set -e
if ! validate_positive_summary "$positive_out/summary.tsv"; then
  audit_failed=1
fi
if (( positive_status != 0 )); then
  audit_failed=1
  printf 'tls_verify_audit status=failed phase=positive run_status=%d out_dir=%s log=%s\n' "$positive_status" "$positive_out" "$positive_log"
fi

for binary in $negative_binaries; do
  negative_out="$out_root/negative-wrong-chain-$binary"
  negative_log="$out_root/negative-wrong-chain-$binary.stdout"
  set +e
  QUICPERF_OUT_DIR="$negative_out" \
  QUICPERF_BINARIES="$binary" \
  QUICPERF_SCENARIOS="$scenario" \
  QUICPERF_NETWORKS="$network" \
  QUICPERF_REPEAT=1 \
  QUICPERF_WARMUP=0 \
  QUICPERF_TEST_BYTES=1 \
  QUICPERF_TIMEOUT="${QUICPERF_TLS_AUDIT_TIMEOUT:-30s}" \
  QUICPERF_RANDOMIZE_ORDER=0 \
  QUICPERF_TLS_VERIFY_MODE=chain \
  QUICPERF_TLS_CERT_PROFILE=ed25519-wrong-chain-negative-control \
  QUICPERF_TLS_CHAIN="$wrong_chain" \
  "$root/tools/run-benchmarks.sh" >"$negative_log" 2>&1
  status=$?
  set -e

  if (( status == 0 )); then
    printf '%s\tnegative_wrong_chain\tmust_fail\tunexpected_pass\t%s\t%s\n' "$binary" "$negative_out" "$negative_log" >>"$audit_tsv"
    printf 'tls_verify_audit status=failed phase=negative_wrong_chain binary=%s reason=unexpected_pass out_dir=%s log=%s\n' "$binary" "$negative_out" "$negative_log"
    audit_failed=1
    continue
  fi
  printf '%s\tnegative_wrong_chain\tmust_fail\trejected\t%s\t%s\n' "$binary" "$negative_out" "$negative_log" >>"$audit_tsv"
done

if (( audit_failed != 0 )); then
  printf 'tls_verify_audit status=failed path=%s positive_out=%s wrong_chain=%s\n' "$audit_tsv" "$positive_out" "$wrong_chain"
  exit 3
fi

printf 'tls_verify_audit status=passed path=%s positive_out=%s wrong_chain=%s\n' "$audit_tsv" "$positive_out" "$wrong_chain"
