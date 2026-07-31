from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class PathError(RuntimeError):
    pass


@dataclass(frozen=True)
class TraceTransition:
    offset_ns: int
    downlink_bps: int
    uplink_bps: int
    one_way_delay_us: int


@dataclass(frozen=True)
class ArmedTrace:
    epoch_raw_ns: int
    seed: bytes
    transitions: tuple[TraceTransition, ...]

    def intended_times(self) -> tuple[int, ...]:
        return tuple(self.epoch_raw_ns + transition.offset_ns for transition in self.transitions)


def derive_trace_seed(campaign_seed: bytes, microblock_id: bytes, path_profile_hash: bytes) -> bytes:
    if not campaign_seed or len(microblock_id) != 32 or len(path_profile_hash) != 32:
        raise PathError("invalid trace identity")
    return hmac.new(campaign_seed, microblock_id + path_profile_hash, hashlib.sha256).digest()


def loss_recovery_drop(trace_seed: bytes, *, measurement: bool, direction: int, packet_ordinal: int) -> bool:
    if len(trace_seed) != 32 or direction not in {0, 1} or packet_ordinal < 0 or packet_ordinal > 0xFFFF_FFFF_FFFF_FFFF:
        raise PathError("invalid loss decision input")
    message = b"loss-recovery-v1\0" + bytes((int(measurement), direction)) + struct.pack("!Q", packet_ordinal)
    digest = hmac.new(trace_seed, message, hashlib.sha256).digest()
    return int.from_bytes(digest, "big") % 100 == 0


class LoopbackPathController:
    def __init__(self) -> None:
        self.armed: ArmedTrace | None = None
        self.active = False
        self.events: list[tuple[int, int]] = []

    def create_session(self) -> None:
        if self.active:
            raise PathError("path session already exists")
        self.active = True

    def prepare_trial(self, profile: str) -> None:
        if not self.active:
            raise PathError("path session does not exist")
        if profile != "loopback":
            raise PathError(
                "persistent namespace/qdisc path controller is unavailable; "
                "refusing to run a non-loopback treatment on loopback"
            )

    def network_namespace(self, _role: str) -> Path | None:
        return None

    def endpoint_addresses(self, role: str) -> tuple[str, str]:
        if role not in {"server", "client"}:
            raise PathError("invalid endpoint path role")
        return ("127.0.0.1", "0.0.0.0") if role == "server" else (
            "127.0.0.1",
            "127.0.0.1",
        )

    def arm(self, trace: ArmedTrace) -> None:
        if not self.active or trace.epoch_raw_ns < time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW):
            raise PathError("trace must be armed before a future epoch")
        self.armed = trace

    def cancel_arm(self) -> None:
        self.armed = None
        self.events.clear()

    def apply_due(self, now_raw_ns: int) -> int:
        if self.armed is None:
            raise PathError("trace is not armed")
        applied = len(self.events)
        while applied < len(self.armed.transitions):
            intended = self.armed.epoch_raw_ns + self.armed.transitions[applied].offset_ns
            if intended > now_raw_ns:
                break
            self.events.append((intended, now_raw_ns))
            applied += 1
        return applied

    def finish_trial(self) -> dict[str, Any]:
        return {"profile": "loopback", "directions": {}}

    def reset_trial(self) -> None:
        self.armed = None
        self.events.clear()

    def cleanup(self) -> None:
        self.reset_trial()
        self.active = False


class NamespacePathController:
    """One persistent two-endpoint/router namespace path owned by a lane."""

    _NAME = re.compile(r"^qpv2-(?P<pid>[1-9][0-9]*)-(?P<lane>[0-9]+)-[0-9a-f]{8}-[csr]$")

    def __init__(self, lane: int, ownership: str) -> None:
        if lane < 0 or not ownership:
            raise PathError("invalid namespace path identity")
        token = hashlib.sha256(f"{ownership}:{lane}".encode("utf-8")).hexdigest()[:8]
        prefix = f"qpv2-{os.getpid()}-{lane}-{token}"
        self.names = {
            "client": f"{prefix}-c",
            "server": f"{prefix}-s",
            "router": f"{prefix}-r",
        }
        subnet = int(token[:2], 16)
        self.addresses = {
            "client": f"10.192.{subnet}.2",
            "router_client": f"10.192.{subnet}.1",
            "server": f"10.193.{subnet}.2",
            "router_server": f"10.193.{subnet}.1",
        }
        interface_token = token[:6]
        self.interfaces = {
            "client": f"q{interface_token}c",
            "router_client": f"q{interface_token}rc",
            "server": f"q{interface_token}s",
            "router_server": f"q{interface_token}rs",
        }
        self.active = False
        self.profile: str | None = None
        self.armed: ArmedTrace | None = None
        self.baseline: dict[int, dict[str, int]] | None = None
        self.events: list[tuple[int, int]] = []

    @staticmethod
    def _binary(name: str) -> str:
        value = shutil.which(name)
        if value is None:
            raise PathError(f"required path tool is missing: {name}")
        return value

    @classmethod
    def _run(
        cls, command: list[str], *, capture: bool = False, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                command,
                check=False,
                text=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PathError(f"path command failed to execute: {command[0]}: {exc}") from exc
        if check and result.returncode != 0:
            reason = result.stderr.strip() or f"exit {result.returncode}"
            raise PathError(f"path command failed: {' '.join(command)}: {reason}")
        return result

    @classmethod
    def reap_stale(cls) -> None:
        ip = cls._binary("ip")
        listing = cls._run([ip, "netns", "list"], capture=True)
        groups: dict[tuple[int, int, str], list[str]] = {}
        for line in listing.stdout.splitlines():
            name = line.split(maxsplit=1)[0]
            matched = cls._NAME.fullmatch(name)
            if matched is None:
                continue
            pid = int(matched.group("pid"))
            lane = int(matched.group("lane"))
            token = name.rsplit("-", 2)[-2]
            groups.setdefault((pid, lane, token), []).append(name)
        for (pid, _lane, _token), names in groups.items():
            if Path(f"/proc/{pid}").exists():
                continue
            for name in sorted(names, reverse=True):
                cls._run([ip, "netns", "delete", name], check=False)

    def _ip(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return self._run([self._binary("ip"), *arguments], check=check)

    def _in(self, namespace: str, *command: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
        return self._run(
            [self._binary("ip"), "netns", "exec", namespace, *command],
            capture=capture,
        )

    def create_session(self) -> None:
        if self.active:
            raise PathError("path session already exists")
        self.reap_stale()
        created: list[str] = []
        try:
            for name in self.names.values():
                self._ip("netns", "add", name)
                created.append(name)
            self._ip(
                "link", "add", self.interfaces["client"], "type", "veth",
                "peer", "name", self.interfaces["router_client"],
            )
            self._ip(
                "link", "set", self.interfaces["client"], "netns",
                self.names["client"],
            )
            self._ip(
                "link", "set", self.interfaces["router_client"], "netns",
                self.names["router"],
            )
            self._ip(
                "link", "add", self.interfaces["server"], "type", "veth",
                "peer", "name", self.interfaces["router_server"],
            )
            self._ip(
                "link", "set", self.interfaces["server"], "netns",
                self.names["server"],
            )
            self._ip(
                "link", "set", self.interfaces["router_server"], "netns",
                self.names["router"],
            )
            for namespace in self.names.values():
                self._ip("-n", namespace, "link", "set", "lo", "up")
            assignments = (
                ("client", self.interfaces["client"], self.addresses["client"]),
                ("router", self.interfaces["router_client"], self.addresses["router_client"]),
                ("server", self.interfaces["server"], self.addresses["server"]),
                ("router", self.interfaces["router_server"], self.addresses["router_server"]),
            )
            for role, interface, address in assignments:
                namespace = self.names[role]
                self._ip("-n", namespace, "addr", "add", f"{address}/24", "dev", interface)
                self._ip("-n", namespace, "link", "set", interface, "mtu", "1500", "up")
            self._ip(
                "-n", self.names["client"], "route", "add", "default", "via",
                self.addresses["router_client"],
            )
            self._ip(
                "-n", self.names["server"], "route", "add", "default", "via",
                self.addresses["router_server"],
            )
            self._in(
                self.names["router"], self._binary("sysctl"), "-q", "-w",
                "net.ipv4.ip_forward=1",
            )
            self._replace_qdiscs()
        except BaseException:
            for interface in self.interfaces.values():
                self._ip("link", "delete", interface, check=False)
            for name in reversed(created):
                self._ip("netns", "delete", name, check=False)
            raise
        self.active = True

    def _replace_qdiscs(self) -> None:
        tc = self._binary("tc")
        for interface in (
            self.interfaces["router_client"],
            self.interfaces["router_server"],
        ):
            self._in(
                self.names["router"], tc, "qdisc", "replace", "dev", interface,
                "root", "netem", "delay", "10ms", "limit", "100000",
            )

    def prepare_trial(self, profile: str) -> None:
        if not self.active:
            raise PathError("path session does not exist")
        if self.profile is not None:
            raise PathError("previous path trial was not reset")
        if profile not in {"loopback", "loss_recovery_v1"}:
            raise PathError(f"unsupported path profile {profile!r}")
        self.profile = profile

    def network_namespace(self, role: str) -> Path | None:
        if role not in {"server", "client"}:
            raise PathError("invalid endpoint path role")
        if self.profile != "loss_recovery_v1":
            return None
        path = Path("/run/netns") / self.names[role]
        if not path.exists():
            raise PathError("owned network namespace disappeared")
        return path

    def endpoint_addresses(self, role: str) -> tuple[str, str]:
        if role not in {"server", "client"}:
            raise PathError("invalid endpoint path role")
        if self.profile != "loss_recovery_v1":
            return ("127.0.0.1", "0.0.0.0") if role == "server" else (
                "127.0.0.1",
                "127.0.0.1",
            )
        return (
            (self.addresses["server"], "0.0.0.0")
            if role == "server"
            else (self.addresses["client"], self.addresses["server"])
        )

    def _qdisc_counters(self) -> dict[int, dict[str, int]]:
        tc = self._binary("tc")
        result: dict[int, dict[str, int]] = {}
        for direction, interface in (
            (0, self.interfaces["router_client"]),
            (1, self.interfaces["router_server"]),
        ):
            raw = self._in(
                self.names["router"], tc, "-s", "-j", "qdisc", "show",
                "dev", interface, capture=True,
            ).stdout
            try:
                rows = json.loads(raw)
                row = next(item for item in rows if item.get("kind") == "netem")
                stats = row.get("stats", row)
                result[direction] = {
                    key: int(stats.get(key, 0))
                    for key in ("bytes", "packets", "drops", "overlimits", "requeues")
                }
            except (KeyError, StopIteration, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PathError("qdisc counter evidence is malformed") from exc
        return result

    def arm(self, trace: ArmedTrace) -> None:
        if (
            not self.active
            or self.profile not in {"loopback", "loss_recovery_v1"}
            or trace.epoch_raw_ns < time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            or len(trace.seed) != 32
        ):
            raise PathError("trace must be armed before a future namespace epoch")
        self.armed = trace
        self.baseline = (
            self._qdisc_counters()
            if self.profile == "loss_recovery_v1"
            else None
        )

    def cancel_arm(self) -> None:
        self.armed = None
        self.baseline = None
        self.events.clear()

    def apply_due(self, now_raw_ns: int) -> int:
        if self.armed is None:
            raise PathError("trace is not armed")
        applied = len(self.events)
        while applied < len(self.armed.transitions):
            intended = self.armed.epoch_raw_ns + self.armed.transitions[applied].offset_ns
            if intended > now_raw_ns:
                break
            self.events.append((intended, now_raw_ns))
            applied += 1
        return applied

    def finish_trial(self) -> dict[str, Any]:
        if self.profile != "loss_recovery_v1" or self.armed is None or self.baseline is None:
            return {"profile": self.profile or "loopback", "directions": {}}
        current = self._qdisc_counters()
        directions: dict[str, dict[str, int]] = {}
        for direction in (0, 1):
            delta = {
                key: current[direction][key] - self.baseline[direction][key]
                for key in current[direction]
            }
            if any(value < 0 for value in delta.values()):
                raise PathError("qdisc counters regressed during trial")
            directions[str(direction)] = delta
        return {
            "profile": "loss_recovery_v1",
            "trace_epoch_raw_ns": self.armed.epoch_raw_ns,
            "trace_seed": self.armed.seed.hex(),
            "directions": directions,
            "transitions": [
                {"intended_raw_ns": intended, "actual_raw_ns": actual}
                for intended, actual in self.events
            ],
        }

    def reset_trial(self) -> None:
        self.profile = None
        self.armed = None
        self.baseline = None
        self.events.clear()

    def cleanup(self) -> None:
        self.reset_trial()
        if not self.active:
            return
        failures: list[str] = []
        for name in reversed(tuple(self.names.values())):
            result = self._ip("netns", "delete", name, check=False)
            if result.returncode != 0:
                failures.append(result.stderr.strip() or f"failed to delete {name}")
        self.active = False
        remaining = [
            name for name in self.names.values()
            if (Path("/run/netns") / name).exists()
        ]
        if remaining or failures:
            detail = "; ".join((*failures, *(f"still present: {name}" for name in remaining)))
            raise PathError(f"owned namespace cleanup failed: {detail}")
