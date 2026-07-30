"""Audited canonical endpoint capability matrix.

This module records the capability contract observed from the configured adapter
``describe`` endpoints.  The live audit deliberately compares exact sets: a
newly missing capability fails instead of silently shrinking result coverage,
and newly advertised support fails until its behavioral contract is reviewed.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Collection, Iterable, Mapping, Sequence

from .planner import CANONICAL_SERVERS, PUBLICATION_SCENARIOS, SERVER_BACKENDS
from .protocol import MessageType, SeqPacketChannel


PUBLICATION_SCENARIO_IDS = {
    scenario: str(index)
    for index, scenario in enumerate(PUBLICATION_SCENARIOS, start=1)
}


class CapabilityAuditError(RuntimeError):
    pass


@dataclass(frozen=True)
class AdapterContract:
    library: str
    roles: frozenset[str]
    backends: frozenset[str]
    scenario_ids: frozenset[str]
    contract_test: str
    contract_source: str
    scenario_blockers: Mapping[str, str]
    endpoint_blocker: str = ""


@dataclass(frozen=True)
class CapabilitySnapshot:
    binary: str
    library: str
    roles: frozenset[str]
    backends: frozenset[str]
    scenario_ids: frozenset[str]
    build_id: str = ""
    effective_features: frozenset[str] = frozenset()


@dataclass(frozen=True)
class MatrixCell:
    server: str
    scenario: str
    server_backend: str
    advertised: bool
    blocker: str
    contract_test: str
    contract_source: str


_ALL_ROLES = frozenset({"server", "client"})
_ALL_BACKENDS = frozenset(SERVER_BACKENDS)


def _ids(*values: int) -> frozenset[str]:
    return frozenset(str(value) for value in values)


def _features(value: str) -> frozenset[str]:
    return frozenset(value.split(","))


_CPP_FEATURES = (
    "common_cpp_packet_io,borrowed_packet_batch_64,ipv4,quic_v1,tls_1_3,"
    "qperf_2_alpn,bidirectional_stream"
)
EXPECTED_EFFECTIVE_FEATURES: Mapping[str, frozenset[str]] = {
    "ngtcp2perf": _features(
        "common_cpp_packet_io,borrowed_packet_batch_64,ipv4,quic_v1,tls_1_3,"
        "tls_aes_128_gcm_sha256,x25519,qperf_2_alpn,bidirectional_stream,"
        "unidirectional_stream,datagram,resumption,early_data,post_bind_local_address,"
        "reset_stream,stop_sending,connection_close,peer_terminal_facts,"
        "exact_retransmission_counter_unavailable"
    ),
    "lsperf": _features(
        "common_cpp_packet_io,borrowed_packet_batch_64,ipv4,quic_v1,tls_1_3,"
        "tls_aes_128_gcm_sha256,x25519,qperf_2_alpn,bidirectional_stream,datagram,"
        "resumption,early_data,post_bind_local_address,reset_stream,stop_sending,"
        "connection_close,peer_terminal_facts,unidirectional_stream_unavailable,"
        "transport_loss_retransmission_counters"
    ),
    "tquicperf": _features(
        _CPP_FEATURES + ",unidirectional_stream,datagram,resumption,early_data,"
        "post_bind_local_address,reset_stream,stop_sending,connection_close,"
        "caller_supplied_raw_time,peer_terminal_facts,transport_loss_counter,"
        "recovery_probe_counter,flow_control_blocked_counters,synthetic_address_token_clock,"
        "exact_retransmission_counter_unavailable"
    ),
    "quicheperf": _features(
        _CPP_FEATURES + ",unidirectional_stream,datagram,resumption,early_data,"
        "post_bind_local_address,reset_stream,stop_sending,connection_close,"
        "peer_terminal_facts,exact_transport_counters"
    ),
    "picoperf": _features(
        _CPP_FEATURES + ",unidirectional_stream,datagram,resumption,early_data,"
        "post_bind_local_address,reset_stream,stop_sending,connection_close,"
        "peer_terminal_facts,flow_control_blocked_counters"
    ),
    "xquicperf": _features(
        "common_cpp_packet_io,borrowed_packet_batch_64,ipv4,quic_v1,tls_1_3,"
        "tls_aes_128_gcm_sha256,x25519,qperf_2_alpn,bidirectional_stream,"
        "unidirectional_stream,datagram,resumption,early_data,post_bind_local_address,"
        "connection_close,application_error_reset,application_error_stop_sending,"
        "peer_terminal_facts,transport_loss_counter,"
        "exact_retransmission_counter_unavailable"
    ),
    "quinnperf": _features(
        "common_cpp_packet_io,borrowed_packet_batch_64,caller_supplied_raw_time,"
        "runtime_threads_none,ipv4,quic_v1,tls_1_3,qperf_2_alpn,canonical_tls_hostname,"
        "ca_verified_peer,post_bind_local_address,bidirectional_stream,unidirectional_stream,"
        "datagram,resumption,early_data,reset_stream,stop_sending,connection_close,"
        "peer_terminal_facts,transport_loss_counter,recovery_probe_counter,"
        "flow_control_blocked_counters"
    ),
    "s2nperf": _features(
        "common_cpp_packet_io,borrowed_packet_batch_64,caller_supplied_raw_time,"
        "runtime_threads_none,ipv4,quic_v1,tls_1_3,qperf_2_alpn,canonical_tls_hostname,"
        "ca_verified_peer,post_bind_local_address,bidirectional_stream,unidirectional_stream,"
        "datagram,resumption,early_data,reset_stream,stop_sending,connection_close,"
        "peer_terminal_facts,"
        "transport_loss_counter,recovery_probe_counter,flow_control_blocked_counters"
    ),
    "neqoperf": _features(
        "common_cpp_packet_io,borrowed_packet_batch_64,caller_supplied_raw_time,"
        "runtime_threads_none,ipv4,quic_v1,tls_1_3,qperf_2_alpn,canonical_tls_hostname,"
        "ca_verified_peer,post_bind_local_address,bidirectional_stream,unidirectional_stream,"
        "datagram,resumption,early_data,reset_stream,stop_sending,connection_close,"
        "peer_terminal_facts,transport_loss_counter,recovery_probe_counter,"
        "flow_control_blocked_counters"
    ),
    "noqperf": _features(
        "common_cpp_packet_io,borrowed_packet_batch_64,caller_supplied_raw_time,"
        "runtime_threads_none,ipv4,quic_v1,tls_1_3,qperf_2_alpn,canonical_tls_hostname,"
        "ca_verified_peer,post_bind_local_address,bidirectional_stream,unidirectional_stream,"
        "datagram,resumption,early_data,reset_stream,stop_sending,connection_close,"
        "peer_terminal_facts,transport_loss_counter,recovery_probe_counter,"
        "flow_control_blocked_counters"
    ),
    "quiczigperf": _features(
        "common_cpp_packet_io,borrowed_packet_batch_64,caller_supplied_raw_time,"
        "runtime_threads_none,ipv4,quic_v1,tls_1_3,qperf_2_alpn,canonical_tls_hostname,"
        "ca_verified_peer,post_bind_local_address,bidirectional_stream,unidirectional_stream,"
        "datagram,resumption,early_data,reset_stream,stop_sending,connection_close,"
        "peer_terminal_facts,"
        "transport_loss_counter,flow_control_blocked_counters,"
        "resumed_lifecycle_successor_one_use_tickets"
    ),
    "mvfstperf": _features(
        "common_cpp_packet_io,borrowed_packet_batch_64,caller_supplied_raw_time,"
        "runtime_threads_none,ipv4,quic_v1,tls_1_3,tls_aes_128_gcm_sha256,x25519,"
        "qperf_2_alpn,canonical_tls_hostname,ca_verified_peer,post_bind_local_address,"
        "bidirectional_stream,unidirectional_stream,datagram,resumption,early_data,"
        "reset_stream,stop_sending,connection_close,peer_terminal_facts,"
        "transport_loss_counter,recovery_probe_counter,flow_control_blocked_counters,"
        "fd_free_manual_quic_eventbase,frozen_fizz_calendar_clock"
    ),
}


ADAPTER_CONTRACTS: Mapping[str, AdapterContract] = {
    "ngtcp2perf": AdapterContract(
        "ngtcp2", _ALL_ROLES, _ALL_BACKENDS, _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_ngtcp2_adapter_contract", "tests/ngtcp2_adapter_contract.cpp", {},
    ),
    "lsperf": AdapterContract(
        "lsquic", _ALL_ROLES, _ALL_BACKENDS,
        _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_lsquic_adapter_contract", "tests/native_packet_adapter_contract.cpp", {},
    ),
    "tquicperf": AdapterContract(
        "tquic", _ALL_ROLES, _ALL_BACKENDS,
        _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_tquic_adapter_contract", "tests/native_packet_adapter_contract.cpp",
        {},
    ),
    "quicheperf": AdapterContract(
        "quiche", _ALL_ROLES, _ALL_BACKENDS,
        _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_quiche_adapter_contract",
        "tests/test_v2_native_endpoint.py::test_quiche_close_reset_requires_all_peer_terminal_strata",
        {},
    ),
    "picoperf": AdapterContract(
        "picoquic", _ALL_ROLES, _ALL_BACKENDS,
        _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_picoquic_adapter_contract",
        "tests/test_v2_native_endpoint.py::test_picoquic_flow_control_exports_block_and_recovery_evidence;"
        "tests/test_v2_native_endpoint.py::test_picoquic_close_reset_requires_all_peer_terminal_strata",
        {},
    ),
    "xquicperf": AdapterContract(
        "xquic", _ALL_ROLES, _ALL_BACKENDS,
        _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_xquic_adapter_contract", "tests/native_packet_adapter_contract.cpp", {},
    ),
    "quinnperf": AdapterContract(
        "quinn", _ALL_ROLES, _ALL_BACKENDS,
        _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_quinn_adapter_contract", "tests/native_packet_adapter_contract.cpp", {},
    ),
    "s2nperf": AdapterContract(
        "s2n_quic", _ALL_ROLES, _ALL_BACKENDS, _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_s2n_adapter_contract", "tests/native_packet_adapter_contract.cpp",
        {},
    ),
    "neqoperf": AdapterContract(
        "neqo", _ALL_ROLES, _ALL_BACKENDS,
        _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_neqo_adapter_contract", "tests/native_packet_adapter_contract.cpp", {},
    ),
    "noqperf": AdapterContract(
        "noq", _ALL_ROLES, _ALL_BACKENDS,
        _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_noq_adapter_contract", "tests/native_packet_adapter_contract.cpp", {},
    ),
    "quiczigperf": AdapterContract(
        "quic_zig", _ALL_ROLES, _ALL_BACKENDS,
        _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_quiczig_adapter_contract", "tests/native_packet_adapter_contract.cpp",
        {},
    ),
    "mvfstperf": AdapterContract(
        "mvfst", _ALL_ROLES, _ALL_BACKENDS,
        _ids(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
        "quicperf_mvfst_adapter_contract", "tests/native_packet_adapter_contract.cpp", {},
    ),
}


def canonical_matrix() -> tuple[MatrixCell, ...]:
    if tuple(ADAPTER_CONTRACTS) != CANONICAL_SERVERS:
        raise CapabilityAuditError("adapter contract order does not match canonical server order")
    cells: list[MatrixCell] = []
    for server in CANONICAL_SERVERS:
        contract = ADAPTER_CONTRACTS[server]
        unknown_blockers = set(contract.scenario_blockers) - set(PUBLICATION_SCENARIOS)
        if unknown_blockers:
            raise CapabilityAuditError(
                f"{server} has blockers for unknown scenarios: {sorted(unknown_blockers)}"
            )
        stale_blockers = {
            scenario for scenario in contract.scenario_blockers
            if PUBLICATION_SCENARIO_IDS[scenario] in contract.scenario_ids
        }
        if stale_blockers:
            raise CapabilityAuditError(
                f"{server} has blockers for advertised scenarios: {sorted(stale_blockers)}"
            )
        for scenario in PUBLICATION_SCENARIOS:
            scenario_id = PUBLICATION_SCENARIO_IDS[scenario]
            for backend in SERVER_BACKENDS:
                advertised = (
                    {"server", "client"}.issubset(contract.roles)
                    and backend in contract.backends
                    and scenario_id in contract.scenario_ids
                )
                blocker = ""
                if not advertised:
                    blocker = contract.endpoint_blocker or contract.scenario_blockers.get(scenario, "")
                    if not blocker:
                        blocker = f"unexplained_contract_gap:{server}:{scenario}:{backend}"
                cells.append(MatrixCell(
                    server, scenario, backend, advertised, blocker,
                    contract.contract_test, contract.contract_source,
                ))
    if len(cells) != 360 or len({(cell.server, cell.scenario, cell.server_backend) for cell in cells}) != 360:
        raise CapabilityAuditError("canonical capability matrix is not exactly 12x15x2")
    unexplained = [cell for cell in cells if not cell.advertised and cell.blocker.startswith("unexplained_")]
    if unexplained:
        first = unexplained[0]
        raise CapabilityAuditError(
            f"unexplained capability gap: {first.server}/{first.scenario}/{first.server_backend}"
        )
    return tuple(cells)


def expected_snapshots() -> Mapping[str, CapabilitySnapshot]:
    return {
        binary: CapabilitySnapshot(
            binary=binary,
            library=contract.library,
            roles=contract.roles,
            backends=contract.backends,
            scenario_ids=contract.scenario_ids,
            effective_features=EXPECTED_EFFECTIVE_FEATURES[binary],
        )
        for binary, contract in ADAPTER_CONTRACTS.items()
    }


def audit_snapshots(
    snapshots: Mapping[str, CapabilitySnapshot],
    contract_tests: Collection[str],
) -> tuple[MatrixCell, ...]:
    errors: list[str] = []
    expected = expected_snapshots()
    if set(snapshots) != set(expected):
        errors.append(
            f"binary_set expected={sorted(expected)} actual={sorted(snapshots)}"
        )
    for binary in CANONICAL_SERVERS:
        actual = snapshots.get(binary)
        if actual is None:
            continue
        wanted = expected[binary]
        for field in ("library", "roles", "backends", "scenario_ids", "effective_features"):
            if getattr(actual, field) != getattr(wanted, field):
                errors.append(
                    f"{binary}:{field} expected={getattr(wanted, field)!r} actual={getattr(actual, field)!r}"
                )
        test = ADAPTER_CONTRACTS[binary].contract_test
        if test not in contract_tests:
            errors.append(f"{binary}:missing_cmake_contract_test:{test}")
    matrix = canonical_matrix()
    if errors:
        raise CapabilityAuditError("; ".join(errors))
    return matrix


def _comma_set(value: object) -> frozenset[str]:
    text = str(value)
    if text in {"", "none"}:
        return frozenset()
    return frozenset(part for part in text.split(",") if part and part != "none")


def describe_binary(path: Path, *, timeout_seconds: float = 5.0) -> CapabilitySnapshot:
    parent, child = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    process: subprocess.Popen[str] | None = None
    try:
        parent.settimeout(timeout_seconds)
        process = subprocess.Popen(
            [str(path), "describe", f"--control-fd={child.fileno()}"],
            pass_fds=(child.fileno(),),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        child.close()
        channel = SeqPacketChannel(parent)
        hello = channel.receive()
        capabilities = channel.receive()
        if hello.message_type is not MessageType.HELLO or hello.fields["role"] != "describe":
            raise CapabilityAuditError(f"{path.name}: malformed HELLO")
        if capabilities.message_type is not MessageType.CAPABILITIES:
            raise CapabilityAuditError(f"{path.name}: missing CAPABILITIES")
        if capabilities.fields["build_id"] != hello.fields["build_id"]:
            raise CapabilityAuditError(f"{path.name}: capability build ID mismatch")
        channel.send(MessageType.SHUTDOWN, {})
        if channel.receive().message_type is not MessageType.SHUTDOWN_ACK:
            raise CapabilityAuditError(f"{path.name}: missing SHUTDOWN_ACK")
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        if process.returncode or stdout or stderr:
            raise CapabilityAuditError(
                f"{path.name}: describe exit={process.returncode} stdout={stdout!r} stderr={stderr!r}"
            )
        fields = capabilities.fields
        return CapabilitySnapshot(
            binary=path.name,
            library=str(fields["library"]),
            roles=_comma_set(fields["roles"]),
            backends=_comma_set(fields["backends"]),
            scenario_ids=_comma_set(fields["scenarios"]),
            build_id=hello.fields["build_id"].hex(),
            effective_features=_comma_set(fields["effective_features"]),
        )
    finally:
        parent.close()
        child.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()


def live_snapshots(bin_dir: Path) -> Mapping[str, CapabilitySnapshot]:
    missing = [binary for binary in CANONICAL_SERVERS if not (bin_dir / binary).is_file()]
    if missing:
        raise CapabilityAuditError(f"missing endpoint binaries: {','.join(missing)}")
    return {binary: describe_binary(bin_dir / binary) for binary in CANONICAL_SERVERS}


def cmake_contract_tests(build_dir: Path) -> frozenset[str]:
    completed = subprocess.run(
        ["ctest", "--test-dir", str(build_dir), "--show-only=json-v1"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode:
        raise CapabilityAuditError(
            f"ctest inventory failed: {completed.stderr.strip()}"
        )
    try:
        value = json.loads(completed.stdout)
        return frozenset(str(test["name"]) for test in value["tests"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise CapabilityAuditError("ctest returned malformed JSON inventory") from exc


def matrix_tsv(cells: Iterable[MatrixCell], snapshots: Mapping[str, CapabilitySnapshot]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
    writer.writerow((
        "server", "library", "scenario", "server_backend", "server_role_attested",
        "client_role_attested", "advertised", "build_id", "behavioral_contract_test",
        "behavioral_contract_source", "effective_features", "blocker",
    ))
    for cell in cells:
        snapshot = snapshots[cell.server]
        writer.writerow((
            cell.server, snapshot.library, cell.scenario, cell.server_backend,
            int("server" in snapshot.roles), int("client" in snapshot.roles),
            int(cell.advertised), snapshot.build_id, cell.contract_test,
            cell.contract_source, ",".join(sorted(snapshot.effective_features)), cell.blocker,
        ))
    return stream.getvalue()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit the canonical 360-cell capability matrix")
    parser.add_argument("--bin-dir", type=Path, default=Path("build/bin"))
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--out", type=Path)
    arguments = parser.parse_args(argv)
    try:
        snapshots = live_snapshots(arguments.bin_dir)
        build_dir = arguments.build_dir or arguments.bin_dir.parent
        cells = audit_snapshots(snapshots, cmake_contract_tests(build_dir))
        output = matrix_tsv(cells, snapshots)
    except CapabilityAuditError as exc:
        print(f"capability matrix audit failed: {exc}", file=sys.stderr)
        return 1
    if arguments.out is None:
        sys.stdout.write(output)
    else:
        arguments.out.write_text(output, encoding="utf-8")
    advertised = sum(cell.advertised for cell in cells)
    print(
        f"capability matrix audit passed: cells={len(cells)} advertised={advertised} unsupported={len(cells) - advertised}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
