#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import math
import os
import re
import shlex
import socket
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
NETWORK_PATH = ROOT / "tools" / "quicperf_network_path.py"


def load_network_path_module():
    spec = importlib.util.spec_from_file_location("quicperf_network_path", NETWORK_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {NETWORK_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


network_path = load_network_path_module()


TCP_RECEIVER = r"""
import json
import socket
import sys
import time

addr = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, port, 0, 0))
s.listen(1)
print("READY", flush=True)
conn, peer = s.accept()
start = time.monotonic()
total = 0
while True:
    data = conn.recv(262144)
    if not data:
        break
    total += len(data)
end = time.monotonic()
conn.close()
s.close()
seconds = max(end - start, 1e-9)
print(json.dumps({
    "role": "tcp_receiver",
    "bytes": total,
    "seconds": seconds,
    "throughput_bps": total * 8 / seconds,
    "peer": str(peer),
}), flush=True)
"""


TCP_SENDER = r"""
import json
import socket
import sys
import time

addr = sys.argv[1]
port = int(sys.argv[2])
nbytes = int(sys.argv[3])
chunk = int(sys.argv[4])
payload = b"\0" * chunk
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.connect((addr, port, 0, 0))
left = nbytes
start = time.monotonic()
while left > 0:
    n = min(left, chunk)
    s.sendall(payload[:n])
    left -= n
s.shutdown(socket.SHUT_WR)
s.close()
end = time.monotonic()
seconds = max(end - start, 1e-9)
print(json.dumps({
    "role": "tcp_sender",
    "bytes": nbytes,
    "seconds": seconds,
    "throughput_bps": nbytes * 8 / seconds,
}), flush=True)
"""


UDP_RECEIVER = r"""
import json
import socket
import struct
import sys
import time

addr = sys.argv[1]
port = int(sys.argv[2])
duration = float(sys.argv[3])
linger = float(sys.argv[4])
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
s.bind((addr, port, 0, 0))
s.settimeout(0.1)
print("READY", flush=True)
start = time.monotonic()
deadline = start + duration + linger
first = None
last = None
received = 0
bytes_received = 0
seen = set()
duplicates = 0
while time.monotonic() < deadline:
    try:
        data, _peer = s.recvfrom(65535)
    except TimeoutError:
        continue
    now = time.monotonic()
    if first is None:
        first = now
    last = now
    bytes_received += len(data)
    if len(data) >= 8:
        seq = struct.unpack("!Q", data[:8])[0]
        if seq in seen:
            duplicates += 1
        else:
            seen.add(seq)
            received += 1
s.close()
seconds = max(duration, (last or start) - start, 1e-9)
print(json.dumps({
    "role": "udp_receiver",
    "received": received,
    "duplicates": duplicates,
    "bytes": bytes_received,
    "seconds": seconds,
    "throughput_bps": bytes_received * 8 / seconds,
}), flush=True)
"""


UDP_SENDER = r"""
import json
import socket
import struct
import sys
import time

addr = sys.argv[1]
port = int(sys.argv[2])
duration = float(sys.argv[3])
rate_bps = float(sys.argv[4])
payload_bytes = int(sys.argv[5])
payload_bytes = max(payload_bytes, 16)
pps = max(rate_bps / (payload_bytes * 8), 1.0)
count = max(int(duration * pps), 1)
interval = 1.0 / pps
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024 * 1024)
pad = b"\0" * (payload_bytes - 8)
start = time.monotonic()
next_send = start
sent = 0
for seq in range(count):
    packet = struct.pack("!Q", seq) + pad
    sock.sendto(packet, (addr, port, 0, 0))
    sent += 1
    next_send += interval
    sleep_for = next_send - time.monotonic()
    if sleep_for > 0:
        time.sleep(sleep_for)
end = time.monotonic()
sock.close()
seconds = max(end - start, 1e-9)
print(json.dumps({
    "role": "udp_sender",
    "sent": sent,
    "bytes": sent * payload_bytes,
    "seconds": seconds,
    "target_bps": rate_bps,
    "throughput_bps": sent * payload_bytes * 8 / seconds,
}), flush=True)
"""


@dataclass
class ProbeResult:
    status: str
    data: dict[str, Any]
    stdout: str
    stderr: str


def run(command: list[str], *, timeout: float | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(f"command failed rc={completed.returncode}: {shlex.join(command)}\n{completed.stderr}")
    return completed


def ns_prefix(namespace: str | None) -> list[str]:
    if namespace:
        return ["ip", "netns", "exec", namespace]
    return []


def start_python(namespace: str | None, code: str, args: list[str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [*ns_prefix(namespace), sys.executable, "-u", "-c", code, *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def wait_ready(process: subprocess.Popen[str], timeout: float = 5.0) -> str:
    deadline = time.monotonic() + timeout
    captured = []
    while time.monotonic() < deadline:
        if process.poll() is not None:
            out, err = process.communicate(timeout=0.1)
            raise RuntimeError(f"probe exited before READY stdout={''.join(captured) + out} stderr={err}")
        assert process.stdout is not None
        line = process.stdout.readline()
        if line:
            captured.append(line)
            if line.strip() == "READY":
                return "".join(captured)
        else:
            time.sleep(0.01)
    process.kill()
    raise TimeoutError("probe did not become ready")


def parse_last_json(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return json.loads(line)
    raise ValueError(f"no JSON result found in stdout: {stdout!r}")


def collect_process(process: subprocess.Popen[str], timeout: float) -> tuple[int, str, str]:
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return 124, stdout, stderr
    return process.returncode or 0, stdout, stderr


def run_tcp_probe(
    *,
    direction: str,
    receiver_ns: str | None,
    receiver_addr: str,
    sender_ns: str | None,
    bytes_to_send: int,
    port: int,
    timeout: float,
    artifact_dir: Path,
) -> ProbeResult:
    receiver = start_python(receiver_ns, TCP_RECEIVER, [receiver_addr, str(port)])
    ready = wait_ready(receiver)
    sender = start_python(sender_ns, TCP_SENDER, [receiver_addr, str(port), str(bytes_to_send), str(262144)])
    sender_rc, sender_out, sender_err = collect_process(sender, timeout)
    receiver_rc, receiver_out, receiver_err = collect_process(receiver, timeout)

    artifact_dir.joinpath(f"tcp-{direction}.sender.log").write_text(sender_out + sender_err, encoding="utf-8")
    artifact_dir.joinpath(f"tcp-{direction}.receiver.log").write_text(ready + receiver_out + receiver_err, encoding="utf-8")

    if sender_rc != 0 or receiver_rc != 0:
        return ProbeResult(
            "fail",
            {"sender_rc": sender_rc, "receiver_rc": receiver_rc},
            sender_out + receiver_out,
            sender_err + receiver_err,
        )
    data = parse_last_json(receiver_out)
    sender_data = parse_last_json(sender_out)
    data["sender_throughput_bps"] = sender_data["throughput_bps"]
    data["sender_seconds"] = sender_data["seconds"]
    data["direction"] = direction
    return ProbeResult("ok", data, sender_out + receiver_out, sender_err + receiver_err)


def run_udp_probe(
    *,
    direction: str,
    receiver_ns: str | None,
    receiver_addr: str,
    sender_ns: str | None,
    duration: float,
    rate_bps: float,
    payload_bytes: int,
    port: int,
    timeout: float,
    artifact_dir: Path,
) -> ProbeResult:
    receiver = start_python(receiver_ns, UDP_RECEIVER, [receiver_addr, str(port), str(duration), str(1.0)])
    ready = wait_ready(receiver)
    sender = start_python(sender_ns, UDP_SENDER, [receiver_addr, str(port), str(duration), str(rate_bps), str(payload_bytes)])
    sender_rc, sender_out, sender_err = collect_process(sender, timeout)
    receiver_rc, receiver_out, receiver_err = collect_process(receiver, timeout)

    artifact_dir.joinpath(f"udp-{direction}.sender.log").write_text(sender_out + sender_err, encoding="utf-8")
    artifact_dir.joinpath(f"udp-{direction}.receiver.log").write_text(ready + receiver_out + receiver_err, encoding="utf-8")

    if sender_rc != 0 or receiver_rc != 0:
        return ProbeResult(
            "fail",
            {"sender_rc": sender_rc, "receiver_rc": receiver_rc},
            sender_out + receiver_out,
            sender_err + receiver_err,
        )
    receiver_data = parse_last_json(receiver_out)
    sender_data = parse_last_json(sender_out)
    sent = int(sender_data["sent"])
    received = int(receiver_data["received"])
    loss_percent = 100.0 * max(sent - received, 0) / sent if sent else 100.0
    receiver_data.update(
        {
            "direction": direction,
            "sent": sent,
            "sender_throughput_bps": sender_data["throughput_bps"],
            "target_bps": sender_data["target_bps"],
            "loss_percent": loss_percent,
        }
    )
    return ProbeResult("ok", receiver_data, sender_out + receiver_out, sender_err + receiver_err)


def parse_ping(output: str) -> dict[str, float | int | str]:
    transmitted = received = None
    loss_percent = None
    rtt_min = rtt_avg = rtt_max = rtt_mdev = None
    samples = [float(match.group(1)) for match in re.finditer(r"time[=<]([0-9.]+)\s*ms", output)]
    for line in output.splitlines():
        if "packets transmitted" in line and "packet loss" in line:
            parts = [part.strip() for part in line.split(",")]
            transmitted = int(parts[0].split()[0])
            received = int(parts[1].split()[0])
            loss_percent = float(parts[2].split("%", 1)[0])
        if "min/avg/max" in line and "=" in line:
            values = line.split("=", 1)[1].strip().split()[0].split("/")
            rtt_min, rtt_avg, rtt_max, rtt_mdev = (float(value) for value in values[:4])
    if transmitted is None or received is None or loss_percent is None:
        raise ValueError(f"could not parse ping summary: {output!r}")
    result: dict[str, float | int | str] = {
        "transmitted": transmitted,
        "received": received,
        "loss_percent": loss_percent,
    }
    if rtt_avg is not None:
        result.update(
            {
                "rtt_min_ms": rtt_min,
                "rtt_avg_ms": rtt_avg,
                "rtt_max_ms": rtt_max,
                "rtt_mdev_ms": rtt_mdev,
            }
        )
    if samples:
        result["rtt_samples"] = len(samples)
        result["rtt_p50_ms"] = median(samples)
        result["rtt_p90_ms"] = percentile(samples, 90.0)
        result["rtt_p99_ms"] = percentile(samples, 99.0)
    return result


def run_ping_probe(
    *,
    namespace: str | None,
    address: str,
    count: int,
    interval: float,
    timeout: float,
    artifact_path: Path,
) -> ProbeResult:
    command = [*ns_prefix(namespace), "ping", "-6", "-c", str(count), "-i", str(interval), "-W", "2", address]
    completed = run(command, timeout=timeout)
    output = (completed.stdout or "") + (completed.stderr or "")
    artifact_path.write_text(output, encoding="utf-8")
    try:
        data = parse_ping(output)
    except ValueError as exc:
        return ProbeResult("fail", {"error": str(exc), "returncode": completed.returncode}, completed.stdout, completed.stderr)
    return ProbeResult("ok" if int(data["received"]) > 0 else "fail", data, completed.stdout, completed.stderr)


def weighted_trace_rate(profile: dict[str, Any], key: str) -> int:
    trace = profile.get("trace", [])
    if not trace:
        return int(profile[key])
    total_ms = sum(int(step["duration_ms"]) for step in trace)
    if total_ms <= 0:
        return int(profile[key])
    return int(sum(int(step["duration_ms"]) * int(step[key]) for step in trace) / total_ms)


def weighted_trace_float(profile: dict[str, Any], key: str, fallback: float) -> float:
    trace = profile.get("trace", [])
    if not trace:
        return fallback
    total_ms = sum(int(step["duration_ms"]) for step in trace)
    if total_ms <= 0:
        return fallback
    return float(sum(int(step["duration_ms"]) * float(step.get(key, fallback)) for step in trace) / total_ms)


def trace_max_float(profile: dict[str, Any], key: str, fallback: float) -> float:
    values = [fallback]
    values.extend(float(step[key]) for step in profile.get("trace", []) if key in step)
    return max(values)


def weighted_trace_rtt_us(profile: dict[str, Any]) -> int:
    trace = profile.get("trace", [])
    if not trace:
        return network_path.rtt_us(profile)
    total_ms = sum(int(step["duration_ms"]) for step in trace)
    if total_ms <= 0:
        return network_path.rtt_us(profile)
    weighted = 0.0
    for step in trace:
        dynamic_profile = network_path.trace_step_profile(profile, step)
        weighted += int(step["duration_ms"]) * network_path.rtt_us(dynamic_profile)
    return int(weighted / total_ms)


def trace_rtt_values_ms(profile: dict[str, Any]) -> list[float]:
    trace = profile.get("trace", [])
    if not trace:
        return [network_path.rtt_us(profile) / 1000.0]
    return [network_path.rtt_us(network_path.trace_step_profile(profile, step)) / 1000.0 for step in trace]


def profile_expectations(profile: dict[str, Any]) -> dict[str, Any]:
    if profile["kind"] == "loopback":
        return {"kind": "loopback"}
    base_loss = float(profile.get("loss_percent", 0.0))
    one_way_loss = weighted_trace_float(profile, "loss_percent", base_loss)
    max_one_way_loss = trace_max_float(profile, "loss_percent", base_loss)
    base_jitter_ms = int(profile.get("one_way_jitter_us", 0)) / 1000.0
    one_way_jitter_ms = weighted_trace_float(profile, "one_way_jitter_us", float(profile.get("one_way_jitter_us", 0))) / 1000.0
    one_way_jitter_max_ms = trace_max_float(profile, "one_way_jitter_us", float(profile.get("one_way_jitter_us", 0))) / 1000.0
    rtt_values = trace_rtt_values_ms(profile)
    roundtrip_loss = 100.0 * (1.0 - (1.0 - one_way_loss / 100.0) ** 2)
    roundtrip_loss_max = 100.0 * (1.0 - (1.0 - max_one_way_loss / 100.0) ** 2)
    rtt_us = weighted_trace_rtt_us(profile)
    downlink_bps = int(profile["downlink_bps"])
    uplink_bps = int(profile["uplink_bps"])
    min_rate = profile_min_rate_bps(profile) or min(downlink_bps, uplink_bps)
    ping_serialization_max_ms = 2.0 * 128 * 8 / max(min_rate, 1) * 1000.0
    return {
        "kind": "namespace",
        "rtt_ms": rtt_us / 1000.0,
        "base_one_way_jitter_ms": base_jitter_ms,
        "one_way_jitter_ms": one_way_jitter_ms,
        "one_way_jitter_max_ms": one_way_jitter_max_ms,
        "rtt_dynamic_range_ms": max(rtt_values) - min(rtt_values),
        "ping_serialization_max_ms": ping_serialization_max_ms,
        "one_way_loss_percent": one_way_loss,
        "one_way_loss_max_percent": max_one_way_loss,
        "roundtrip_loss_percent": roundtrip_loss,
        "roundtrip_loss_max_percent": roundtrip_loss_max,
        "downlink_bps": downlink_bps,
        "uplink_bps": uplink_bps,
        "downlink_trace_avg_bps": weighted_trace_rate(profile, "downlink_bps"),
        "uplink_trace_avg_bps": weighted_trace_rate(profile, "uplink_bps"),
        "downlink_bdp_bytes": math.ceil(downlink_bps * rtt_us / 8_000_000),
        "uplink_bdp_bytes": math.ceil(uplink_bps * rtt_us / 8_000_000),
        "downlink_queue_packets": network_path.queue_packets(profile, downlink_bps),
        "uplink_queue_packets": network_path.queue_packets(profile, uplink_bps),
        "max_rate_bps": network_path.max_rate_bps(profile),
        "bdp_window_bytes": network_path.bdp_window_bytes(profile),
    }


def median(values: list[float]) -> float:
    return float(statistics.median(values)) if values else 0.0


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(pct / 100.0 * len(ordered)) - 1))
    return float(ordered[index])


def bad_tail_percentile(values: list[float], pct: float, *, higher_is_better: bool) -> float:
    return percentile(values, 100.0 - pct if higher_is_better else pct)


def probe_metric_higher_is_better(key: str) -> bool:
    return key in {"throughput_bps", "target_bps", "sent"}


def summarize_probe_results(results: list[ProbeResult], key: str) -> dict[str, Any]:
    values = [float(result.data[key]) for result in results if result.status == "ok" and key in result.data]
    if not values:
        return {"samples": len(results), "ok_samples": 0}
    mean = float(statistics.fmean(values))
    stdev = float(statistics.stdev(values)) if len(values) > 1 else 0.0
    higher_is_better = probe_metric_higher_is_better(key)
    return {
        "samples": len(results),
        "ok_samples": len(values),
        "min": min(values),
        "p50": median(values),
        "p90": bad_tail_percentile(values, 90.0, higher_is_better=higher_is_better),
        "p99": bad_tail_percentile(values, 99.0, higher_is_better=higher_is_better),
        "max": max(values),
        "mean": mean,
        "stdev": stdev,
        "cv": stdev / mean if mean > 0.0 else 0.0,
    }


def ok_values(results: list[ProbeResult], key: str) -> list[float]:
    return [float(result.data[key]) for result in results if result.status == "ok" and key in result.data]


def profile_average_rate_bps(expectations: dict[str, Any], direction: str) -> float:
    key = "downlink_trace_avg_bps" if direction == "downlink" else "uplink_trace_avg_bps"
    return float(expectations.get(key) or expectations[f"{direction}_bps"])


def profile_peak_rate_bps(profile: dict[str, Any], direction: str) -> float:
    key = "downlink_bps" if direction == "downlink" else "uplink_bps"
    rates = [int(profile[key])]
    rates.extend(int(step[key]) for step in profile.get("trace", []))
    return float(max(rates))


def clamp_int(value: float, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def choose_tcp_bytes(profile: dict[str, Any], expectations: dict[str, Any], direction: str, args: argparse.Namespace) -> int:
    if args.tcp_bytes > 0:
        return int(args.tcp_bytes)
    if profile["kind"] == "loopback":
        return int(args.tcp_max_bytes)
    average_bps = profile_average_rate_bps(expectations, direction)
    target = average_bps * float(args.tcp_target_seconds) / 8.0
    trace = profile.get("trace", [])
    if trace:
        key = "downlink_bps" if direction == "downlink" else "uplink_bps"
        min_rate = min(int(step[key]) for step in trace)
        target = min(target, min_rate * float(args.tcp_target_seconds) * 4.0 / 8.0)
    return clamp_int(target, int(args.tcp_min_bytes), int(args.tcp_max_bytes))


def qdisc_json(namespace: str, device: str) -> list[dict[str, Any]]:
    completed = run([*ns_prefix(namespace), "tc", "-j", "-s", "qdisc", "show", "dev", device], check=True)
    return json.loads(completed.stdout or "[]")


def collect_qdisc_state(state: dict[str, Any]) -> dict[str, Any]:
    if state["kind"] != "namespace":
        return {}
    router_ns = state["router_ns"]
    return {
        "downlink": qdisc_json(router_ns, network_path.ROUTER_CLIENT_IFACE),
        "uplink": qdisc_json(router_ns, network_path.ROUTER_SERVER_IFACE),
    }


def qdisc_netem_observed(entries: list[dict[str, Any]]) -> dict[str, Any]:
    netem = next((entry for entry in entries if entry.get("kind") == "netem"), None)
    if not netem:
        return {"present": False}
    options = netem.get("options", {})
    delay = options.get("delay", {})
    loss = options.get("loss-random", {})
    rate = options.get("rate", {})
    return {
        "present": True,
        "limit_packets": int(options.get("limit", 0)),
        "one_way_delay_us": int(round(float(delay.get("delay", 0.0)) * 1_000_000)),
        "one_way_jitter_us": int(round(float(delay.get("jitter", 0.0)) * 1_000_000)),
        "loss_percent": float(loss.get("loss", 0.0)) * 100.0,
        "rate_bps": int(round(float(rate.get("rate", 0.0)) * 8.0)),
        "bytes": int(netem.get("bytes", 0)),
        "packets": int(netem.get("packets", 0)),
        "drops": int(netem.get("drops", 0)),
        "overlimits": int(netem.get("overlimits", 0)),
        "backlog": int(netem.get("backlog", 0)),
        "qlen": int(netem.get("qlen", 0)),
    }


def expected_qdisc_configs(profile: dict[str, Any], direction: str) -> list[dict[str, Any]]:
    key = "downlink_bps" if direction == "downlink" else "uplink_bps"
    configs = []
    sources: list[tuple[str, dict[str, Any], int]] = [("base", profile, int(profile[key]))]
    for index, step in enumerate(profile.get("trace", [])):
        dynamic_profile = network_path.trace_step_profile(profile, step)
        sources.append((f"trace[{index}]", dynamic_profile, int(step[key])))
    seen = set()
    for source, dynamic_profile, rate_bps in sources:
        config = {
            "source": source,
            "rate_bps": rate_bps,
            "one_way_delay_us": int(dynamic_profile.get("one_way_delay_us", 0)),
            "one_way_jitter_us": int(dynamic_profile.get("one_way_jitter_us", 0)),
            "loss_percent": float(dynamic_profile.get("loss_percent", 0.0)),
            "limit_packets": network_path.queue_packets(dynamic_profile, rate_bps),
        }
        key_tuple = (
            config["rate_bps"],
            config["one_way_delay_us"],
            config["one_way_jitter_us"],
            round(config["loss_percent"], 6),
            config["limit_packets"],
        )
        if key_tuple not in seen:
            seen.add(key_tuple)
            configs.append(config)
    return configs


def qdisc_config_matches(observed: dict[str, Any], expected: dict[str, Any]) -> bool:
    if not observed.get("present"):
        return False
    rate_tolerance = max(1_000, int(expected["rate_bps"] * 0.01))
    loss_tolerance = max(0.01, abs(float(expected["loss_percent"])) * 0.05)
    return (
        abs(int(observed["rate_bps"]) - int(expected["rate_bps"])) <= rate_tolerance
        and abs(int(observed["one_way_delay_us"]) - int(expected["one_way_delay_us"])) <= 250
        and abs(int(observed["one_way_jitter_us"]) - int(expected["one_way_jitter_us"])) <= 250
        and abs(float(observed["loss_percent"]) - float(expected["loss_percent"])) <= loss_tolerance
        and int(observed["limit_packets"]) == int(expected["limit_packets"])
    )


def validate_qdisc_snapshot(profile: dict[str, Any], qdiscs: dict[str, Any]) -> dict[str, Any]:
    if profile["kind"] == "loopback":
        return {"status": "ok", "directions": {}, "reasons": []}
    reasons = []
    directions: dict[str, Any] = {}
    for direction in ("downlink", "uplink"):
        observed = qdisc_netem_observed(qdiscs.get(direction, []))
        expected = expected_qdisc_configs(profile, direction)
        match = next((config for config in expected if qdisc_config_matches(observed, config)), None)
        if match is None:
            reasons.append(f"{direction}_qdisc_mismatch")
        directions[direction] = {
            "observed": observed,
            "matched": match is not None,
            "matched_expected": match,
            "expected_config_count": len(expected),
            "expected_first": expected[0] if expected else {},
        }
    return {"status": "fail" if reasons else "ok", "directions": directions, "reasons": reasons}


def summarize_numbers(values: list[float], *, higher_is_better: bool = False) -> dict[str, Any]:
    if not values:
        return {"samples": 0}
    return {
        "samples": len(values),
        "min": min(values),
        "p50": median(values),
        "p90": bad_tail_percentile(values, 90.0, higher_is_better=higher_is_better),
        "p99": bad_tail_percentile(values, 99.0, higher_is_better=higher_is_better),
        "max": max(values),
        "mean": float(statistics.fmean(values)),
    }


def profile_trace_audit(profile: dict[str, Any]) -> dict[str, Any]:
    if profile["kind"] == "loopback":
        return {"kind": "loopback"}
    steps = profile.get("trace", [])
    dynamic_profiles = [network_path.trace_step_profile(profile, step) for step in steps]
    downlink_rates = [int(step["downlink_bps"]) for step in steps] or [int(profile["downlink_bps"])]
    uplink_rates = [int(step["uplink_bps"]) for step in steps] or [int(profile["uplink_bps"])]
    losses = [float(step.get("loss_percent", profile.get("loss_percent", 0.0))) for step in steps] or [
        float(profile.get("loss_percent", 0.0))
    ]
    rtts = [network_path.rtt_us(dynamic) / 1000.0 for dynamic in dynamic_profiles] or [network_path.rtt_us(profile) / 1000.0]
    downlink_queues = [
        network_path.queue_packets(dynamic, int(step["downlink_bps"])) for dynamic, step in zip(dynamic_profiles, steps)
    ] or [network_path.queue_packets(profile, int(profile["downlink_bps"]))]
    uplink_queues = [
        network_path.queue_packets(dynamic, int(step["uplink_bps"])) for dynamic, step in zip(dynamic_profiles, steps)
    ] or [network_path.queue_packets(profile, int(profile["uplink_bps"]))]
    return {
        "kind": "namespace",
        "trace_steps": len(steps),
        "trace_duration_ms": sum(int(step["duration_ms"]) for step in steps),
        "handover_outage_steps": sum(1 for step in steps if step.get("event") == "handover-outage"),
        "loss_100_percent_steps": sum(1 for loss in losses if loss >= 100.0),
        "downlink_rate_bps": summarize_numbers([float(value) for value in downlink_rates], higher_is_better=True),
        "uplink_rate_bps": summarize_numbers([float(value) for value in uplink_rates], higher_is_better=True),
        "rtt_ms": summarize_numbers([float(value) for value in rtts]),
        "loss_percent": summarize_numbers(losses),
        "downlink_queue_packets": summarize_numbers([float(value) for value in downlink_queues]),
        "uplink_queue_packets": summarize_numbers([float(value) for value in uplink_queues]),
    }


def validate_probe_repeatability(label: str, results: list[ProbeResult], key: str, warnings: list[str]) -> None:
    values = ok_values(results, key)
    if len(values) < 3:
        return
    mean = statistics.fmean(values)
    if mean <= 0.0:
        return
    cv = statistics.stdev(values) / mean
    if cv > 0.35:
        warnings.append(f"{label}_repeatability_cv_high observed={cv:.3f} threshold=0.350")


def validate_tcp_rate(
    label: str,
    expected_peak_bps: float,
    expected_average_bps: float,
    results: list[ProbeResult],
    failures: list[str],
    warnings: list[str],
    warn_low_baseline: bool = True,
) -> None:
    values = ok_values(results, "throughput_bps")
    if not values or expected_peak_bps <= 0.0:
        return
    observed = median(values)
    if observed > expected_peak_bps * 1.25:
        failures.append(f"{label}_above_shaped_rate observed_bps={observed:.0f} peak_bps={expected_peak_bps:.0f}")
    elif warn_low_baseline and expected_average_bps <= 1_000_000_000 and observed < expected_average_bps * 0.35:
        warnings.append(
            f"{label}_below_plausible_baseline observed_bps={observed:.0f} expected_avg_bps={expected_average_bps:.0f}"
        )


def validate_udp_probe(
    label: str,
    expected_loss_percent: float,
    results: list[ProbeResult],
    failures: list[str],
    warnings: list[str],
) -> None:
    rates = ok_values(results, "throughput_bps")
    targets = ok_values(results, "target_bps")
    losses = ok_values(results, "loss_percent")
    sent_counts = ok_values(results, "sent")
    if rates and targets:
        observed = median(rates)
        target = median(targets)
        if observed > target * 1.25:
            failures.append(f"{label}_above_sender_rate observed_bps={observed:.0f} target_bps={target:.0f}")
        elif observed < target * 0.50 and median(losses) < 10.0:
            warnings.append(f"{label}_below_sender_rate observed_bps={observed:.0f} target_bps={target:.0f}")
    if losses and (not sent_counts or median(sent_counts) >= 50.0):
        observed_loss = median(losses)
        tolerance = max(2.0, expected_loss_percent * 4.0)
        if observed_loss > expected_loss_percent + tolerance:
            warnings.append(f"{label}_loss_above_tolerance observed={observed_loss:.3f} expected={expected_loss_percent:.3f}")


def classify_profile(
    profile: dict[str, Any],
    expectations: dict[str, Any],
    qdisc_before: dict[str, Any] | None,
    qdisc_after: dict[str, Any] | None,
    ping: ProbeResult | None,
    tcp_down: list[ProbeResult],
    tcp_up: list[ProbeResult],
    udp_down: list[ProbeResult],
    udp_up: list[ProbeResult],
) -> tuple[str, list[str]]:
    if profile["kind"] == "loopback":
        return "ok", ["loopback has no qdisc validation"]

    failures: list[str] = []
    warnings: list[str] = []

    for label, qdisc_validation in (("qdisc_before", qdisc_before), ("qdisc_after", qdisc_after)):
        if qdisc_validation is None:
            failures.append(f"{label}_missing")
        elif qdisc_validation.get("status") != "ok":
            failures.extend(f"{label}_{reason}" for reason in qdisc_validation.get("reasons", []))

    if ping is None or ping.status != "ok":
        failures.append("ping_failed")
    else:
        if "rtt_avg_ms" in ping.data:
            expected = float(expectations["rtt_ms"])
            jitter = float(expectations.get("one_way_jitter_max_ms", expectations["one_way_jitter_ms"]))
            dynamic_range = float(expectations.get("rtt_dynamic_range_ms", 0.0))
            serialization = float(expectations.get("ping_serialization_max_ms", 0.0))
            tolerance = max(5.0, expected * 0.35 + jitter * 2.0 + serialization)
            observed = float(ping.data["rtt_avg_ms"])
            if abs(observed - expected) > tolerance:
                warnings.append(f"rtt_avg_outside_tolerance observed={observed:.3f} expected={expected:.3f} tolerance={tolerance:.3f}")
            if "rtt_mdev_ms" in ping.data:
                observed_mdev = float(ping.data["rtt_mdev_ms"])
                mdev_limit = max(5.0, jitter * 4.0 + dynamic_range * 0.75 + expected * 0.10 + serialization)
                if observed_mdev > mdev_limit:
                    warnings.append(f"rtt_mdev_above_tolerance observed={observed_mdev:.3f} threshold={mdev_limit:.3f}")
        expected_loss = float(expectations["roundtrip_loss_max_percent"])
        observed_loss = float(ping.data["loss_percent"])
        loss_tolerance = max(2.0, expected_loss * 3.0)
        if observed_loss > expected_loss + loss_tolerance:
            warnings.append(f"loss_above_tolerance observed={observed_loss:.3f} expected={expected_loss:.3f}")

    for label, results in (("tcp_downlink", tcp_down), ("tcp_uplink", tcp_up), ("udp_downlink", udp_down), ("udp_uplink", udp_up)):
        ok = [result for result in results if result.status == "ok"]
        if not ok:
            failures.append(f"{label}_failed")

    validate_tcp_rate(
        "tcp_downlink",
        profile_peak_rate_bps(profile, "downlink"),
        profile_average_rate_bps(expectations, "downlink"),
        tcp_down,
        failures,
        warnings,
        warn_low_baseline=len(profile.get("trace", [])) <= 1,
    )
    validate_tcp_rate(
        "tcp_uplink",
        profile_peak_rate_bps(profile, "uplink"),
        profile_average_rate_bps(expectations, "uplink"),
        tcp_up,
        failures,
        warnings,
        warn_low_baseline=len(profile.get("trace", [])) <= 1,
    )
    validate_udp_probe("udp_downlink", float(expectations["one_way_loss_max_percent"]), udp_down, failures, warnings)
    validate_udp_probe("udp_uplink", float(expectations["one_way_loss_max_percent"]), udp_up, failures, warnings)

    if len(profile.get("trace", [])) <= 1:
        for label, results in (
            ("tcp_downlink", tcp_down),
            ("tcp_uplink", tcp_up),
            ("udp_downlink", udp_down),
            ("udp_uplink", udp_up),
        ):
            validate_probe_repeatability(label, results, "throughput_bps", warnings)

    if failures:
        return "fail", failures + warnings
    if warnings:
        return "warn", warnings
    return "ok", []


def profile_addresses(state: dict[str, Any]) -> tuple[str | None, str | None, str, str]:
    if state["kind"] == "loopback":
        return None, None, "::1", "::1"
    return state["client_ns"], state["server_ns"], state["client_address"], state["server_address"]


def setup_profile(profile_name: str, run_id: str, profile_dir: Path, no_variation: bool) -> dict[str, Any]:
    profile = network_path.profile_by_name(profile_name)
    state_path = profile_dir / "path.json"
    if profile["kind"] == "loopback":
        return network_path.loopback_state(profile, state_path)
    return network_path.setup_namespace(profile, run_id, state_path, not no_variation)


def cleanup_profile(state: dict[str, Any]) -> None:
    network_path.cleanup_state(state, quiet=True)


def choose_udp_rate(profile: dict[str, Any], direction: str, fraction: float, min_bps: int, max_bps: int) -> float:
    if profile["kind"] == "loopback":
        return float(min(max_bps, 100_000_000))
    key = "downlink_bps" if direction == "downlink" else "uplink_bps"
    avg = weighted_trace_rate(profile, key)
    target = min(max_bps, int(avg * fraction))
    trace = profile.get("trace", [])
    if trace:
        min_rate = min(int(step[key]) for step in trace)
        target = min(target, int(min_rate * 0.80))
    return float(max(min_bps, target))


def choose_udp_payload_bytes(profile: dict[str, Any], direction: str, duration: float, args: argparse.Namespace) -> int:
    if profile["kind"] == "loopback" or not profile.get("trace"):
        return int(args.udp_payload_bytes)
    key = "downlink_bps" if direction == "downlink" else "uplink_bps"
    min_rate = min(int(step[key]) for step in profile["trace"])
    max_payload = int(min_rate * duration / 8.0 / 4.0)
    return max(16, min(int(args.udp_payload_bytes), max_payload))


def profile_min_rate_bps(profile: dict[str, Any]) -> int | None:
    if profile["kind"] == "loopback":
        return None
    rates = [int(profile["downlink_bps"]), int(profile["uplink_bps"])]
    for step in profile.get("trace", []):
        rates.append(int(step["downlink_bps"]))
        rates.append(int(step["uplink_bps"]))
    return min(rates)


def choose_ping_interval(profile: dict[str, Any], args: argparse.Namespace) -> float:
    min_rate = profile_min_rate_bps(profile)
    if min_rate is None or min_rate <= 0:
        return float(args.ping_interval)
    estimated_ping_bytes = 128
    serialization_interval = estimated_ping_bytes * 8 / min_rate
    return max(float(args.ping_interval), serialization_interval * 1.25)


def active_benchmark_processes() -> list[str]:
    completed = run(["ps", "-eo", "pid,ppid,pgid,stat,etime,cmd"])
    current = os.getpid()
    bad = []
    needles = (
        "/root/quicperf/build/bin/",
        "/root/quicperf/tools/run-benchmarks.sh",
        "run-adaptive-publication-suite.py",
        "build-picoperf-wan/bin/",
    )
    for line in completed.stdout.splitlines():
        if str(current) in line and "quicperf_network_validate.py" in line:
            continue
        if any(needle in line for needle in needles):
            bad.append(line)
    return bad


def host_preflight_snapshot(out_dir: Path) -> dict[str, Any]:
    load1, load5, load15 = os.getloadavg()
    cpus = os.cpu_count() or 1
    commands = {
        "uptime": ["uptime"],
        "ip_netns": ["ip", "netns", "list"],
        "tc_qdisc": ["tc", "-s", "qdisc", "show"],
        "top_processes": ["ps", "-eo", "pid,ppid,stat,etime,pcpu,pmem,cmd", "--sort=-pcpu"],
    }
    lines = [
        f"timestamp_utc={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n",
        f"loadavg_1={load1:.3f} loadavg_5={load5:.3f} loadavg_15={load15:.3f} cpus={cpus} loadavg_1_per_core={load1 / cpus:.4f}\n",
    ]
    for label, command in commands.items():
        completed = run(command)
        lines.append(f"\n# {label}: {shlex.join(command)}\n")
        output = completed.stdout or ""
        if label == "top_processes":
            output = "\n".join(output.splitlines()[:40]) + "\n"
        lines.append(output)
        if completed.stderr:
            lines.append(completed.stderr)
    out_dir.joinpath("host-preflight.txt").write_text("".join(lines), encoding="utf-8")
    return {
        "loadavg_1": load1,
        "loadavg_5": load5,
        "loadavg_15": load15,
        "cpus": cpus,
        "loadavg_1_per_core": load1 / cpus,
    }


def idle_host_blockers(args: argparse.Namespace, preflight: dict[str, Any]) -> list[str]:
    blockers = []
    active = active_benchmark_processes()
    if active:
        (args.out_dir / "blocked-processes.txt").write_text("\n".join(active) + "\n", encoding="utf-8")
        blockers.append("active_benchmark_processes")
    load_per_core = float(preflight["loadavg_1_per_core"])
    if load_per_core > args.max_loadavg_per_core:
        blockers.append(f"loadavg_per_core_high observed={load_per_core:.4f} threshold={args.max_loadavg_per_core:.4f}")
    return blockers


def resolve_profile_names(spec: str) -> list[str]:
    if spec in {"all", "all-non-loopback"}:
        profiles = network_path.load_profiles()
        names = sorted(profiles)
        if spec == "all-non-loopback":
            names = [name for name in names if profiles[name].get("kind") != "loopback"]
        return names
    return spec.split()


def validate_profile(profile_name: str, args: argparse.Namespace, run_id: str, base_port: int) -> dict[str, Any]:
    profile_dir = args.out_dir / profile_name
    profile_dir.mkdir(parents=True, exist_ok=True)
    profile = network_path.profile_by_name(profile_name)
    profile_dir.joinpath("profile.json").write_text(json.dumps(profile, indent=2, sort_keys=True), encoding="utf-8")
    profile_dir.joinpath("expectations.json").write_text(json.dumps(profile_expectations(profile), indent=2, sort_keys=True), encoding="utf-8")

    state: dict[str, Any] | None = None
    tcp_down: list[ProbeResult] = []
    tcp_up: list[ProbeResult] = []
    udp_down: list[ProbeResult] = []
    udp_up: list[ProbeResult] = []
    ping: ProbeResult | None = None
    expectations = profile_expectations(profile)
    qdisc_before_validation: dict[str, Any] | None = None
    qdisc_after_validation: dict[str, Any] | None = None
    tcp_down_bytes = choose_tcp_bytes(profile, expectations, "downlink", args)
    tcp_up_bytes = choose_tcp_bytes(profile, expectations, "uplink", args)
    udp_down_rate = choose_udp_rate(profile, "downlink", args.udp_rate_fraction, args.udp_min_bps, args.udp_max_bps)
    udp_up_rate = choose_udp_rate(profile, "uplink", args.udp_rate_fraction, args.udp_min_bps, args.udp_max_bps)
    udp_down_payload = choose_udp_payload_bytes(profile, "downlink", args.udp_seconds, args)
    udp_up_payload = choose_udp_payload_bytes(profile, "uplink", args.udp_seconds, args)
    ping_interval = choose_ping_interval(profile, args)
    profile_dir.joinpath("trace-audit.json").write_text(json.dumps(profile_trace_audit(profile), indent=2, sort_keys=True), encoding="utf-8")
    try:
        state = setup_profile(profile_name, run_id, profile_dir, args.no_variation)
        profile_dir.joinpath("state.json").write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        qdisc_before = collect_qdisc_state(state)
        profile_dir.joinpath("qdisc-before.json").write_text(json.dumps(qdisc_before, indent=2, sort_keys=True), encoding="utf-8")
        qdisc_before_validation = validate_qdisc_snapshot(profile, qdisc_before)
        profile_dir.joinpath("qdisc-before-validation.json").write_text(
            json.dumps(qdisc_before_validation, indent=2, sort_keys=True), encoding="utf-8"
        )
        network_path.snapshot_state(state, profile_dir / "snapshot-before.txt")
        network_path.snapshot_state(state, profile_dir / "snapshot.txt")
        client_ns, server_ns, client_addr, server_addr = profile_addresses(state)

        ping = run_ping_probe(
            namespace=client_ns,
            address=server_addr,
            count=args.ping_count,
            interval=ping_interval,
            timeout=args.probe_timeout,
            artifact_path=profile_dir / "ping.txt",
        )

        for sample in range(args.samples):
            port = base_port + sample * 10
            tcp_down.append(
                run_tcp_probe(
                    direction=f"downlink-{sample + 1}",
                    receiver_ns=client_ns,
                    receiver_addr=client_addr,
                    sender_ns=server_ns,
                    bytes_to_send=tcp_down_bytes,
                    port=port,
                    timeout=args.probe_timeout,
                    artifact_dir=profile_dir,
                )
            )
            tcp_up.append(
                run_tcp_probe(
                    direction=f"uplink-{sample + 1}",
                    receiver_ns=server_ns,
                    receiver_addr=server_addr,
                    sender_ns=client_ns,
                    bytes_to_send=tcp_up_bytes,
                    port=port + 1,
                    timeout=args.probe_timeout,
                    artifact_dir=profile_dir,
                )
            )
            udp_down.append(
                run_udp_probe(
                    direction=f"downlink-{sample + 1}",
                    receiver_ns=client_ns,
                    receiver_addr=client_addr,
                    sender_ns=server_ns,
                    duration=args.udp_seconds,
                    rate_bps=udp_down_rate,
                    payload_bytes=udp_down_payload,
                    port=port + 2,
                    timeout=args.probe_timeout,
                    artifact_dir=profile_dir,
                )
            )
            udp_up.append(
                run_udp_probe(
                    direction=f"uplink-{sample + 1}",
                    receiver_ns=server_ns,
                    receiver_addr=server_addr,
                    sender_ns=client_ns,
                    duration=args.udp_seconds,
                    rate_bps=udp_up_rate,
                    payload_bytes=udp_up_payload,
                    port=port + 3,
                    timeout=args.probe_timeout,
                    artifact_dir=profile_dir,
                )
            )
        qdisc_after = collect_qdisc_state(state)
        profile_dir.joinpath("qdisc-after.json").write_text(json.dumps(qdisc_after, indent=2, sort_keys=True), encoding="utf-8")
        qdisc_after_validation = validate_qdisc_snapshot(profile, qdisc_after)
        profile_dir.joinpath("qdisc-after-validation.json").write_text(
            json.dumps(qdisc_after_validation, indent=2, sort_keys=True), encoding="utf-8"
        )
        network_path.snapshot_state(state, profile_dir / "snapshot-after.txt")
    finally:
        if state is not None:
            cleanup_profile(state)

    status, reasons = classify_profile(
        profile, expectations, qdisc_before_validation, qdisc_after_validation, ping, tcp_down, tcp_up, udp_down, udp_up
    )
    result = {
        "profile": profile_name,
        "status": status,
        "reasons": reasons,
        "expectations": expectations,
        "probe_config": {
            "tcp_downlink_bytes": tcp_down_bytes,
            "tcp_uplink_bytes": tcp_up_bytes,
            "udp_downlink_target_bps": udp_down_rate,
            "udp_uplink_target_bps": udp_up_rate,
            "udp_downlink_payload_bytes": udp_down_payload,
            "udp_uplink_payload_bytes": udp_up_payload,
            "ping_interval": ping_interval,
        },
        "qdisc_before": qdisc_before_validation or {},
        "qdisc_after": qdisc_after_validation or {},
        "ping": ping.data if ping else {},
        "tcp_downlink_bps": summarize_probe_results(tcp_down, "throughput_bps"),
        "tcp_uplink_bps": summarize_probe_results(tcp_up, "throughput_bps"),
        "udp_downlink_bps": summarize_probe_results(udp_down, "throughput_bps"),
        "udp_uplink_bps": summarize_probe_results(udp_up, "throughput_bps"),
        "udp_downlink_target_bps": summarize_probe_results(udp_down, "target_bps"),
        "udp_uplink_target_bps": summarize_probe_results(udp_up, "target_bps"),
        "udp_downlink_packets_sent": summarize_probe_results(udp_down, "sent"),
        "udp_uplink_packets_sent": summarize_probe_results(udp_up, "sent"),
        "udp_downlink_loss_percent": summarize_probe_results(udp_down, "loss_percent"),
        "udp_uplink_loss_percent": summarize_probe_results(udp_up, "loss_percent"),
    }
    profile_dir.joinpath("result.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return result


def write_summary(path: Path, results: list[dict[str, Any]]) -> None:
    fields = [
        "profile",
        "status",
        "reason",
        "expected_rtt_ms",
        "expected_ping_serialization_max_ms",
        "ping_rtt_avg_ms",
        "ping_rtt_p50_ms",
        "ping_rtt_p90_ms",
        "ping_rtt_p99_ms",
        "ping_interval_s",
        "expected_roundtrip_loss_percent",
        "expected_roundtrip_loss_max_percent",
        "ping_loss_percent",
        "tcp_downlink_bytes",
        "tcp_uplink_bytes",
        "tcp_downlink_gbps_p50",
        "tcp_downlink_gbps_p90",
        "tcp_downlink_gbps_p99",
        "tcp_uplink_gbps_p50",
        "tcp_uplink_gbps_p90",
        "tcp_uplink_gbps_p99",
        "udp_downlink_gbps_p50",
        "udp_downlink_gbps_p90",
        "udp_downlink_gbps_p99",
        "udp_downlink_target_gbps_p50",
        "udp_downlink_payload_bytes",
        "udp_uplink_gbps_p50",
        "udp_uplink_gbps_p90",
        "udp_uplink_gbps_p99",
        "udp_uplink_target_gbps_p50",
        "udp_uplink_payload_bytes",
        "udp_downlink_loss_percent_p50",
        "udp_downlink_packets_sent_p50",
        "udp_downlink_loss_percent_p90",
        "udp_downlink_loss_percent_p99",
        "udp_uplink_loss_percent_p50",
        "udp_uplink_packets_sent_p50",
        "udp_uplink_loss_percent_p90",
        "udp_uplink_loss_percent_p99",
        "downlink_queue_packets",
        "uplink_queue_packets",
        "bdp_window_bytes",
        "qdisc_before_status",
        "qdisc_after_status",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for result in results:
            exp = result["expectations"]
            ping = result["ping"]
            row = {
                "profile": result["profile"],
                "status": result["status"],
                "reason": ";".join(result["reasons"]),
                "expected_rtt_ms": exp.get("rtt_ms", ""),
                "expected_ping_serialization_max_ms": exp.get("ping_serialization_max_ms", ""),
                "ping_rtt_avg_ms": ping.get("rtt_avg_ms", ""),
                "ping_rtt_p50_ms": ping.get("rtt_p50_ms", ""),
                "ping_rtt_p90_ms": ping.get("rtt_p90_ms", ""),
                "ping_rtt_p99_ms": ping.get("rtt_p99_ms", ""),
                "ping_interval_s": result["probe_config"].get("ping_interval", ""),
                "expected_roundtrip_loss_percent": exp.get("roundtrip_loss_percent", ""),
                "expected_roundtrip_loss_max_percent": exp.get("roundtrip_loss_max_percent", ""),
                "ping_loss_percent": ping.get("loss_percent", ""),
                "tcp_downlink_bytes": result["probe_config"].get("tcp_downlink_bytes", ""),
                "tcp_uplink_bytes": result["probe_config"].get("tcp_uplink_bytes", ""),
                "tcp_downlink_gbps_p50": result["tcp_downlink_bps"].get("p50", 0.0) / 1_000_000_000,
                "tcp_downlink_gbps_p90": result["tcp_downlink_bps"].get("p90", 0.0) / 1_000_000_000,
                "tcp_downlink_gbps_p99": result["tcp_downlink_bps"].get("p99", 0.0) / 1_000_000_000,
                "tcp_uplink_gbps_p50": result["tcp_uplink_bps"].get("p50", 0.0) / 1_000_000_000,
                "tcp_uplink_gbps_p90": result["tcp_uplink_bps"].get("p90", 0.0) / 1_000_000_000,
                "tcp_uplink_gbps_p99": result["tcp_uplink_bps"].get("p99", 0.0) / 1_000_000_000,
                "udp_downlink_gbps_p50": result["udp_downlink_bps"].get("p50", 0.0) / 1_000_000_000,
                "udp_downlink_gbps_p90": result["udp_downlink_bps"].get("p90", 0.0) / 1_000_000_000,
                "udp_downlink_gbps_p99": result["udp_downlink_bps"].get("p99", 0.0) / 1_000_000_000,
                "udp_downlink_target_gbps_p50": result["udp_downlink_target_bps"].get("p50", 0.0) / 1_000_000_000,
                "udp_downlink_payload_bytes": result["probe_config"].get("udp_downlink_payload_bytes", ""),
                "udp_uplink_gbps_p50": result["udp_uplink_bps"].get("p50", 0.0) / 1_000_000_000,
                "udp_uplink_gbps_p90": result["udp_uplink_bps"].get("p90", 0.0) / 1_000_000_000,
                "udp_uplink_gbps_p99": result["udp_uplink_bps"].get("p99", 0.0) / 1_000_000_000,
                "udp_uplink_target_gbps_p50": result["udp_uplink_target_bps"].get("p50", 0.0) / 1_000_000_000,
                "udp_uplink_payload_bytes": result["probe_config"].get("udp_uplink_payload_bytes", ""),
                "udp_downlink_loss_percent_p50": result["udp_downlink_loss_percent"].get("p50", ""),
                "udp_downlink_packets_sent_p50": result["udp_downlink_packets_sent"].get("p50", ""),
                "udp_downlink_loss_percent_p90": result["udp_downlink_loss_percent"].get("p90", ""),
                "udp_downlink_loss_percent_p99": result["udp_downlink_loss_percent"].get("p99", ""),
                "udp_uplink_loss_percent_p50": result["udp_uplink_loss_percent"].get("p50", ""),
                "udp_uplink_packets_sent_p50": result["udp_uplink_packets_sent"].get("p50", ""),
                "udp_uplink_loss_percent_p90": result["udp_uplink_loss_percent"].get("p90", ""),
                "udp_uplink_loss_percent_p99": result["udp_uplink_loss_percent"].get("p99", ""),
                "downlink_queue_packets": exp.get("downlink_queue_packets", ""),
                "uplink_queue_packets": exp.get("uplink_queue_packets", ""),
                "bdp_window_bytes": exp.get("bdp_window_bytes", ""),
                "qdisc_before_status": result["qdisc_before"].get("status", ""),
                "qdisc_after_status": result["qdisc_after"].get("status", ""),
            }
            writer.writerow(row)


def parse_args() -> argparse.Namespace:
    default_out = ROOT / ".run" / f"network-profile-validation-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    parser = argparse.ArgumentParser(description="Validate quicperf namespace-backed WAN network profiles")
    parser.add_argument("--profiles", default="dc-fabric-10g dc-fabric-1ms lte-good lte-congested 5g-sub6-good 5g-mmwave-bursty")
    parser.add_argument("--out-dir", type=Path, default=default_out)
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--ping-count", type=int, default=40)
    parser.add_argument("--ping-interval", type=float, default=0.02)
    parser.add_argument("--tcp-bytes", type=int, default=0, help="fixed TCP bytes per probe; 0 chooses bytes from profile rate")
    parser.add_argument("--tcp-target-seconds", type=float, default=3.0)
    parser.add_argument("--tcp-min-bytes", type=int, default=4 * 1024)
    parser.add_argument("--tcp-max-bytes", type=int, default=128 * 1024 * 1024)
    parser.add_argument("--udp-seconds", type=float, default=1.0)
    parser.add_argument("--udp-rate-fraction", type=float, default=0.25)
    parser.add_argument("--udp-min-bps", type=int, default=1_000)
    parser.add_argument("--udp-max-bps", type=int, default=50_000_000)
    parser.add_argument("--udp-payload-bytes", type=int, default=1200)
    parser.add_argument("--probe-timeout", type=float, default=90.0)
    parser.add_argument("--base-port", type=int, default=42000)
    parser.add_argument("--no-variation", action="store_true")
    parser.add_argument("--require-idle-host", action="store_true")
    parser.add_argument("--max-loadavg-per-core", type=float, default=0.50)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    preflight = host_preflight_snapshot(args.out_dir)

    if args.require_idle_host:
        blockers = idle_host_blockers(args, preflight)
        if blockers:
            (args.out_dir / "blocked-reasons.txt").write_text("\n".join(blockers) + "\n", encoding="utf-8")
            print(
                f"quicperf_network_validation_blocked reason={','.join(blockers)} path={args.out_dir / 'blocked-reasons.txt'}"
            )
            return 3

    profiles = resolve_profile_names(args.profiles)
    manifest = {
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "profiles": profiles,
        "samples": args.samples,
        "tcp_bytes": args.tcp_bytes,
        "tcp_target_seconds": args.tcp_target_seconds,
        "tcp_min_bytes": args.tcp_min_bytes,
        "tcp_max_bytes": args.tcp_max_bytes,
        "udp_seconds": args.udp_seconds,
        "udp_rate_fraction": args.udp_rate_fraction,
        "udp_min_bps": args.udp_min_bps,
        "udp_max_bps": args.udp_max_bps,
        "no_variation": args.no_variation,
        "preflight": preflight,
    }
    (args.out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    results = []
    for index, profile in enumerate(profiles):
        run_id = f"validate-{profile}-{int(time.time())}-{os.getpid()}-{index}"
        print(f"quicperf_network_validation_profile profile={profile} status=started", flush=True)
        result = validate_profile(profile, args, run_id, args.base_port + index * 100)
        results.append(result)
        print(
            f"quicperf_network_validation_profile profile={profile} status={result['status']} reasons={','.join(result['reasons'])}",
            flush=True,
        )

    write_summary(args.out_dir / "summary.tsv", results)
    (args.out_dir / "results.json").write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    failed = [result for result in results if result["status"] == "fail"]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
