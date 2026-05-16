#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE_PATH = ROOT / "profiles" / "network" / "wan-profiles.json"
CLIENT_IFACE = "qpc0"
SERVER_IFACE = "qps0"
ROUTER_CLIENT_IFACE = "qprc0"
ROUTER_SERVER_IFACE = "qprs0"


class NetworkPathError(RuntimeError):
    pass


def run(command: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    if check and completed.returncode != 0:
        output = "\n".join(part for part in [completed.stdout, completed.stderr] if part)
        raise NetworkPathError(f"command failed rc={completed.returncode}: {shlex.join(command)}\n{output}")
    return completed


def run_ns(namespace: str, command: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return run(["ip", "netns", "exec", namespace, *command], check=check, capture=capture)


def load_profile_file(path: Path) -> dict[str, dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict):
        raise NetworkPathError(f"invalid profile file: {path}")
    return profiles


def load_profiles(path: Path = DEFAULT_PROFILE_PATH) -> dict[str, dict[str, Any]]:
    if path != DEFAULT_PROFILE_PATH:
        return load_profile_file(path)
    merged: dict[str, dict[str, Any]] = {}
    profile_files = [DEFAULT_PROFILE_PATH]
    profile_files.extend(sorted(candidate for candidate in DEFAULT_PROFILE_PATH.parent.glob("*.json") if candidate != DEFAULT_PROFILE_PATH))
    for profile_path in profile_files:
        for name, profile in load_profile_file(profile_path).items():
            if name in merged:
                raise NetworkPathError(f"duplicate path profile {name!r} in {profile_path}")
            merged[name] = profile
    return merged


def profile_by_name(name: str) -> dict[str, Any]:
    profiles = load_profiles()
    if name not in profiles:
        known = " ".join(sorted(profiles))
        raise NetworkPathError(f"unknown path profile {name!r}; known profiles: {known}")
    profile = dict(profiles[name])
    profile["name"] = name
    validate_profile(profile)
    return profile


def validate_profile(profile: dict[str, Any]) -> None:
    kind = profile.get("kind")
    if kind not in {"loopback", "namespace"}:
        raise NetworkPathError(f"profile {profile.get('name', '<unknown>')} has invalid kind {kind!r}")
    if kind == "loopback":
        return
    for key in ("one_way_delay_us", "downlink_bps", "uplink_bps", "queue_bdp", "mtu_bytes"):
        if key not in profile:
            raise NetworkPathError(f"profile {profile['name']} missing {key}")
    if int(profile["downlink_bps"]) <= 0 or int(profile["uplink_bps"]) <= 0:
        raise NetworkPathError(f"profile {profile['name']} must have positive rates")
    if int(profile["mtu_bytes"]) < 576:
        raise NetworkPathError(f"profile {profile['name']} mtu_bytes is too small")
    for step in profile.get("trace", []):
        for key in ("duration_ms", "downlink_bps", "uplink_bps"):
            if int(step.get(key, 0)) <= 0:
                raise NetworkPathError(f"profile {profile['name']} has invalid trace step {step!r}")
        for key in ("one_way_delay_us", "one_way_jitter_us", "jitter_correlation_percent", "loss_correlation_percent"):
            if key in step and int(step[key]) < 0:
                raise NetworkPathError(f"profile {profile['name']} has invalid trace step {step!r}")
        if "loss_percent" in step and not 0.0 <= float(step["loss_percent"]) <= 100.0:
            raise NetworkPathError(f"profile {profile['name']} has invalid trace step {step!r}")
        if "queue_bdp" in step and float(step["queue_bdp"]) <= 0.0:
            raise NetworkPathError(f"profile {profile['name']} has invalid trace step {step!r}")


def max_rate_bps(profile: dict[str, Any]) -> int:
    rates = [int(profile.get("downlink_bps", 0)), int(profile.get("uplink_bps", 0))]
    for step in profile.get("trace", []):
        rates.append(int(step["downlink_bps"]))
        rates.append(int(step["uplink_bps"]))
    return max(rates)


def rtt_us(profile: dict[str, Any]) -> int:
    return int(profile.get("rtt_us", int(profile.get("one_way_delay_us", 0)) * 2))


def trace_step_profile(profile: dict[str, Any], step: dict[str, Any]) -> dict[str, Any]:
    dynamic = dict(profile)
    for key in (
        "one_way_delay_us",
        "one_way_jitter_us",
        "jitter_correlation_percent",
        "loss_percent",
        "loss_correlation_percent",
        "queue_bdp",
        "mtu_bytes",
    ):
        if key in step:
            dynamic[key] = step[key]
    return dynamic


def max_rtt_us(profile: dict[str, Any]) -> int:
    rtts = [rtt_us(profile)]
    for step in profile.get("trace", []):
        rtts.append(rtt_us(trace_step_profile(profile, step)))
    return max(rtts)


def bdp_window_bytes(profile: dict[str, Any]) -> int:
    rate = max_rate_bps(profile)
    rtt = max_rtt_us(profile)
    if rate <= 0 or rtt <= 0:
        return 0
    bdp = math.ceil(rate * rtt / 8_000_000)
    return max(1 * 1024 * 1024, min(512 * 1024 * 1024, bdp * 4))


def namespace_names(profile: dict[str, Any], run_id: str) -> dict[str, str]:
    digest = hashlib.sha1(f"{profile['name']}:{run_id}".encode("utf-8")).hexdigest()[:8]
    subnet = max(1, int(digest[:4], 16))
    return {
        "id": digest,
        "client_ns": f"qpc-{digest}",
        "server_ns": f"qps-{digest}",
        "router_ns": f"qpr-{digest}",
        "client_host_if": f"qpc{digest}",
        "router_client_host_if": f"qrc{digest}",
        "server_host_if": f"qps{digest}",
        "router_server_host_if": f"qrs{digest}",
        "client_address": f"2001:db8:120:{subnet:x}::2",
        "router_client_address": f"2001:db8:120:{subnet:x}::1",
        "server_address": f"2001:db8:121:{subnet:x}::2",
        "router_server_address": f"2001:db8:121:{subnet:x}::1",
    }


def rate_arg(rate_bps: int) -> str:
    return f"{int(rate_bps)}bit"


def time_arg(us: int) -> str:
    if us % 1000 == 0:
        return f"{us // 1000}ms"
    return f"{us}us"


def queue_packets(profile: dict[str, Any], rate_bps: int) -> int:
    queue_bdp = float(profile.get("queue_bdp", 1.0))
    mtu = int(profile.get("mtu_bytes", 1500))
    bytes_for_queue = max(rate_bps * rtt_us(profile) * queue_bdp / 8_000_000, mtu * 32)
    return max(32, int(math.ceil(bytes_for_queue / mtu)))


def netem_args(profile: dict[str, Any], rate_bps: int) -> list[str]:
    delay = int(profile.get("one_way_delay_us", 0))
    jitter = int(profile.get("one_way_jitter_us", 0))
    jitter_corr = int(profile.get("jitter_correlation_percent", 0))
    loss = float(profile.get("loss_percent", 0.0))
    loss_corr = int(profile.get("loss_correlation_percent", 0))
    args = ["qdisc", "replace", "dev", "", "root", "netem"]
    if delay > 0:
        args.extend(["delay", time_arg(delay)])
        if jitter > 0:
            args.append(time_arg(jitter))
            if jitter_corr > 0:
                args.append(f"{jitter_corr}%")
            args.extend(["distribution", "normal"])
    if loss > 0.0:
        args.extend(["loss", f"{loss:.4f}%"])
        if loss_corr > 0:
            args.append(f"{loss_corr}%")
    args.extend(["rate", rate_arg(rate_bps), "limit", str(queue_packets(profile, rate_bps))])
    return args


def tc_replace_command(namespace: str, device: str, profile: dict[str, Any], rate_bps: int) -> list[str]:
    args = netem_args(profile, rate_bps)
    args[3] = device
    return ["ip", "netns", "exec", namespace, "tc", *args]


def apply_tc(profile: dict[str, Any], state: dict[str, Any], downlink_bps: int, uplink_bps: int) -> None:
    router_ns = state["router_ns"]
    run(tc_replace_command(router_ns, ROUTER_CLIENT_IFACE, profile, downlink_bps))
    run(tc_replace_command(router_ns, ROUTER_SERVER_IFACE, profile, uplink_bps))


def iface_mac(namespace: str, device: str) -> str:
    completed = run_ns(namespace, ["cat", f"/sys/class/net/{device}/address"], capture=True)
    mac = (completed.stdout or "").strip()
    if not mac:
        raise NetworkPathError(f"could not read mac address for {namespace}:{device}")
    return mac


def add_static_neighbor(namespace: str, device: str, address: str, mac: str) -> None:
    run_ns(namespace, ["ip", "-6", "neigh", "replace", address, "lladdr", mac, "dev", device, "nud", "permanent"])


def configure_static_neighbors(names: dict[str, str]) -> dict[str, str]:
    client_mac = iface_mac(names["client_ns"], CLIENT_IFACE)
    server_mac = iface_mac(names["server_ns"], SERVER_IFACE)
    router_client_mac = iface_mac(names["router_ns"], ROUTER_CLIENT_IFACE)
    router_server_mac = iface_mac(names["router_ns"], ROUTER_SERVER_IFACE)

    add_static_neighbor(names["client_ns"], CLIENT_IFACE, names["router_client_address"], router_client_mac)
    add_static_neighbor(names["router_ns"], ROUTER_CLIENT_IFACE, names["client_address"], client_mac)
    add_static_neighbor(names["server_ns"], SERVER_IFACE, names["router_server_address"], router_server_mac)
    add_static_neighbor(names["router_ns"], ROUTER_SERVER_IFACE, names["server_address"], server_mac)

    return {
        "client_mac": client_mac,
        "server_mac": server_mac,
        "router_client_mac": router_client_mac,
        "router_server_mac": router_server_mac,
    }


def plan_commands(profile: dict[str, Any], run_id: str) -> dict[str, Any]:
    names = namespace_names(profile, run_id)
    if profile["kind"] == "loopback":
        return {"profile": profile["name"], "kind": "loopback", "commands": []}
    return {
        "profile": profile["name"],
        "kind": "namespace",
        "names": names,
        "tc": {
            "downlink": tc_replace_command(names["router_ns"], ROUTER_CLIENT_IFACE, profile, int(profile["downlink_bps"])),
            "uplink": tc_replace_command(names["router_ns"], ROUTER_SERVER_IFACE, profile, int(profile["uplink_bps"])),
        },
        "static_neighbors": True,
        "trace": profile.get("trace", []),
    }


def write_env(state: dict[str, Any]) -> None:
    env = {
        "QUICPERF_PATH_KIND": state["kind"],
        "QUICPERF_PATH_PROFILE": state["profile"],
        "QUICPERF_PATH_RTT_US": str(state.get("rtt_us", 0)),
        "QUICPERF_PATH_DOWNLINK_BPS": str(state.get("downlink_bps", 0)),
        "QUICPERF_PATH_UPLINK_BPS": str(state.get("uplink_bps", 0)),
        "QUICPERF_PATH_MAX_RATE_BPS": str(state.get("max_rate_bps", 0)),
        "QUICPERF_PATH_BDP_WINDOW_BYTES": str(state.get("bdp_window_bytes", 0)),
        "QUICPERF_SERVER_NAMESPACE": state.get("server_ns", ""),
        "QUICPERF_CLIENT_NAMESPACE": state.get("client_ns", ""),
        "QUICPERF_SERVER_ADDRESS": state.get("server_address", "loopback"),
        "QUICPERF_CLIENT_ADDRESS": state.get("client_address", "loopback"),
        "QUICPERF_ROUTER_NAMESPACE": state.get("router_ns", ""),
    }
    for key, value in env.items():
        print(f"{key}={shlex.quote(str(value))}")


def loopback_state(profile: dict[str, Any], state_path: Path | None = None) -> dict[str, Any]:
    state = {
        "kind": "loopback",
        "profile": profile["name"],
        "rtt_us": 0,
        "downlink_bps": 0,
        "uplink_bps": 0,
        "max_rate_bps": 0,
        "bdp_window_bytes": 0,
    }
    if state_path:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    return state


def setup_namespace(profile: dict[str, Any], run_id: str, state_path: Path, start_variation: bool) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise NetworkPathError("namespace path profiles require root or CAP_NET_ADMIN")
    names = namespace_names(profile, run_id)
    cleanup_state({**names, "kind": "namespace"}, quiet=True)
    try:
        for ns in (names["client_ns"], names["server_ns"], names["router_ns"]):
            run(["ip", "netns", "add", ns])

        run(["ip", "link", "add", names["client_host_if"], "type", "veth", "peer", "name", names["router_client_host_if"]])
        run(["ip", "link", "add", names["server_host_if"], "type", "veth", "peer", "name", names["router_server_host_if"]])
        run(["ip", "link", "set", names["client_host_if"], "netns", names["client_ns"]])
        run(["ip", "link", "set", names["router_client_host_if"], "netns", names["router_ns"]])
        run(["ip", "link", "set", names["server_host_if"], "netns", names["server_ns"]])
        run(["ip", "link", "set", names["router_server_host_if"], "netns", names["router_ns"]])

        run_ns(names["client_ns"], ["ip", "link", "set", names["client_host_if"], "name", CLIENT_IFACE])
        run_ns(names["server_ns"], ["ip", "link", "set", names["server_host_if"], "name", SERVER_IFACE])
        run_ns(names["router_ns"], ["ip", "link", "set", names["router_client_host_if"], "name", ROUTER_CLIENT_IFACE])
        run_ns(names["router_ns"], ["ip", "link", "set", names["router_server_host_if"], "name", ROUTER_SERVER_IFACE])

        for ns in (names["client_ns"], names["server_ns"], names["router_ns"]):
            run_ns(ns, ["ip", "link", "set", "lo", "up"])

        run_ns(names["client_ns"], ["ip", "-6", "addr", "add", f"{names['client_address']}/64", "dev", CLIENT_IFACE, "nodad"])
        run_ns(names["router_ns"], ["ip", "-6", "addr", "add", f"{names['router_client_address']}/64", "dev", ROUTER_CLIENT_IFACE, "nodad"])
        run_ns(names["server_ns"], ["ip", "-6", "addr", "add", f"{names['server_address']}/64", "dev", SERVER_IFACE, "nodad"])
        run_ns(names["router_ns"], ["ip", "-6", "addr", "add", f"{names['router_server_address']}/64", "dev", ROUTER_SERVER_IFACE, "nodad"])

        run_ns(names["client_ns"], ["ip", "link", "set", CLIENT_IFACE, "up"])
        run_ns(names["server_ns"], ["ip", "link", "set", SERVER_IFACE, "up"])
        run_ns(names["router_ns"], ["ip", "link", "set", ROUTER_CLIENT_IFACE, "up"])
        run_ns(names["router_ns"], ["ip", "link", "set", ROUTER_SERVER_IFACE, "up"])

        run_ns(names["router_ns"], ["sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1"])
        run_ns(names["client_ns"], ["ip", "-6", "route", "add", "default", "via", names["router_client_address"], "dev", CLIENT_IFACE])
        run_ns(names["server_ns"], ["ip", "-6", "route", "add", "default", "via", names["router_server_address"], "dev", SERVER_IFACE])
        static_neighbors = configure_static_neighbors(names)

        apply_tc(profile, names, int(profile["downlink_bps"]), int(profile["uplink_bps"]))

        state = {
            **names,
            **static_neighbors,
            "kind": "namespace",
            "profile": profile["name"],
            "rtt_us": rtt_us(profile),
            "downlink_bps": int(profile["downlink_bps"]),
            "uplink_bps": int(profile["uplink_bps"]),
            "max_rate_bps": max_rate_bps(profile),
            "bdp_window_bytes": bdp_window_bytes(profile),
            "state_path": str(state_path),
        }
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")

        if start_variation and len(profile.get("trace", [])) > 1:
            log_path = state_path.with_suffix(".variation.log")
            log = log_path.open("ab")
            proc = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "vary", "--state", str(state_path)],
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            state["variation_pid"] = proc.pid
            state["variation_log"] = str(log_path)
            state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        return state
    except Exception:
        cleanup_state({**names, "kind": "namespace"}, quiet=True)
        raise


def read_state(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def cleanup_state(state: dict[str, Any], quiet: bool = False) -> None:
    pid = state.get("variation_pid")
    if pid:
        try:
            os.killpg(int(pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            try:
                os.kill(int(pid), signal.SIGTERM)
            except OSError:
                pass
    if state.get("kind") != "namespace":
        return
    for ns_key in ("client_ns", "server_ns", "router_ns"):
        ns = state.get(ns_key)
        if not ns:
            continue
        completed = run(["ip", "netns", "delete", ns], check=False, capture=True)
        if completed.returncode != 0 and not quiet and "No such file" not in (completed.stderr or ""):
            print(completed.stderr or completed.stdout, file=sys.stderr)
    for link_key in ("client_host_if", "server_host_if", "router_client_host_if", "router_server_host_if"):
        link = state.get(link_key)
        if link:
            run(["ip", "link", "delete", link], check=False, capture=True)


def snapshot_state(state: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append(json.dumps(state, indent=2, sort_keys=True))
    if state.get("kind") == "namespace":
        for ns in (state["client_ns"], state["router_ns"], state["server_ns"]):
            for command in (["ip", "addr"], ["ip", "-6", "route"], ["tc", "-s", "qdisc"]):
                completed = run_ns(ns, command, check=False, capture=True)
                lines.append(f"\n# {ns}: {shlex.join(command)}\n")
                lines.append(completed.stdout or "")
                if completed.stderr:
                    lines.append(completed.stderr)
    output.write_text("".join(lines), encoding="utf-8")


def vary(state_path: Path) -> int:
    state = read_state(state_path)
    profile = profile_by_name(state["profile"])
    trace = profile.get("trace", [])
    if len(trace) <= 1:
        return 0
    stop = False

    def handle_stop(_signum: int, _frame: Any) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)
    while not stop:
        for step in trace:
            if stop:
                break
            dynamic_profile = trace_step_profile(profile, step)
            apply_tc(dynamic_profile, state, int(step["downlink_bps"]), int(step["uplink_bps"]))
            time.sleep(max(0.01, int(step["duration_ms"]) / 1000.0))
    return 0


def command_setup(args: argparse.Namespace) -> int:
    profile = profile_by_name(args.profile)
    if args.dry_run:
        print(json.dumps(plan_commands(profile, args.run_id), indent=2, sort_keys=True))
        return 0
    if profile["kind"] == "loopback":
        state = loopback_state(profile, args.state)
    else:
        state = setup_namespace(profile, args.run_id, args.state, not args.no_variation)
    write_env(state)
    return 0


def command_cleanup(args: argparse.Namespace) -> int:
    if args.state.exists():
        cleanup_state(read_state(args.state))
    return 0


def command_snapshot(args: argparse.Namespace) -> int:
    snapshot_state(read_state(args.state), args.output)
    return 0


def command_show(args: argparse.Namespace) -> int:
    profile = profile_by_name(args.profile)
    print(json.dumps(profile, indent=2, sort_keys=True))
    return 0


def command_list(_args: argparse.Namespace) -> int:
    for name in sorted(load_profiles()):
        print(name)
    return 0


def command_vary(args: argparse.Namespace) -> int:
    return vary(args.state)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create and manage quicperf namespace-backed path profiles")
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list")
    list_parser.set_defaults(func=command_list)

    show_parser = sub.add_parser("show")
    show_parser.add_argument("profile")
    show_parser.set_defaults(func=command_show)

    setup_parser = sub.add_parser("setup")
    setup_parser.add_argument("--profile", required=True)
    setup_parser.add_argument("--run-id", required=True)
    setup_parser.add_argument("--state", type=Path, required=True)
    setup_parser.add_argument("--dry-run", action="store_true")
    setup_parser.add_argument("--no-variation", action="store_true")
    setup_parser.set_defaults(func=command_setup)

    cleanup_parser = sub.add_parser("cleanup")
    cleanup_parser.add_argument("--state", type=Path, required=True)
    cleanup_parser.set_defaults(func=command_cleanup)

    snapshot_parser = sub.add_parser("snapshot")
    snapshot_parser.add_argument("--state", type=Path, required=True)
    snapshot_parser.add_argument("--output", type=Path, required=True)
    snapshot_parser.set_defaults(func=command_snapshot)

    vary_parser = sub.add_parser("vary")
    vary_parser.add_argument("--state", type=Path, required=True)
    vary_parser.set_defaults(func=command_vary)

    args = parser.parse_args()
    try:
        return int(args.func(args))
    except NetworkPathError as exc:
        print(f"quicperf_network_path_error reason={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
