"""Canonical command surface for the quicperf v2 coordinator."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence

from .canonical import canonical_bytes
from .errors import HarnessError, IdentityMismatchError, InvalidConfigurationError
from .legacy import translate_legacy
from .legacy_parity import run_legacy_v2_parity
from .interoperability import (
    FAIL as INTEROPERABILITY_FAIL,
    interoperability_check_detail,
    interoperability_plan_cardinality,
    load_native_interoperability,
    refresh_native_interoperability,
)
from .manifest_collect import (
    ManifestCollectionError,
    attest_process_libraries,
    collect_manifest,
)
from .protocol import MessageType, SeqPacketChannel
from .preflight import (
    PreflightInventory,
    cgroup_isolation_check,
    failed,
    not_run,
    passed,
    selected_path_checks,
    tls_material_check,
)
from .qualification import (
    ARTIFACT_KINDS,
    QualificationArtifactStore,
    build_qualification_identity,
)
from .qualification_commands import (
    acquire_qualification_artifact,
    qualification_status,
    store_qualification_evidence,
)
from .qualification_runner import SubprocessObservationSource, run_qualification
from .runner import (
    EndpointRunError,
    SCENARIO_CAPABILITY_IDS,
    _assert_binary_unchanged,
    _attest_hello,
    _statistical_calibration_reasons,
    analyze_campaign,
    campaign_status,
    create_campaign,
    export_campaign,
    finalize_campaign,
    run_campaign_session,
)
from .suite import (
    DEFAULT_CAMPAIGNS,
    suite_plan,
    suite_resume,
    suite_run,
    suite_status,
)
from .spec import load_experiment_spec
from .supervisor import Supervisor
from .topology import allocate_lanes, discover_physical_cores, swap_is_disabled


EXIT_SUCCESS = 0
EXIT_NONPUBLISHABLE = 2
EXIT_INCOMPLETE = 3
EXIT_INVALID = 4
EXIT_INTERNAL = 5
EXIT_INTERRUPT = 130


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def _emit(value: Any) -> None:
    sys.stdout.buffer.write(canonical_bytes(value) + b"\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="quicperfctl")
    parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser("doctor")
    doctor.add_argument("--profile", type=Path, required=True)
    doctor.add_argument("--bin-dir", type=Path)
    doctor.add_argument(
        "--phase", choices=("all", "deterministic", "physical"), default="all"
    )
    doctor.add_argument("--refresh-interoperability", action="store_true")
    doctor.add_argument("--interoperability-store", type=Path)
    doctor.add_argument("--qualification-store", type=Path)

    for kind in ("campaign", "capacity", "memory", "tail"):
        surface = commands.add_parser(kind)
        operations = surface.add_subparsers(dest="operation", required=True)
        create = operations.add_parser("create")
        create.add_argument("--profile", type=Path, required=True)
        create.add_argument("--out", type=Path, required=True)
        create.add_argument("--seed")
        create.add_argument("--bin-dir", type=Path)
        create.add_argument("--qualification-store", type=Path)
        create.add_argument("--interoperability-store", type=Path)
        run = operations.add_parser("run")
        run.add_argument("--run-dir", type=Path, required=True)
        run.add_argument("--session", type=int, choices=(1, 2), required=True)
        for operation in ("analyze", "finalize"):
            subcommand = operations.add_parser(operation)
            subcommand.add_argument("--run-dir", type=Path, required=True)
        if kind == "campaign":
            status = operations.add_parser("status")
            status.add_argument("--run-dir", type=Path, required=True)

    export = commands.add_parser("export")
    export.add_argument("--run-dir", type=Path, required=True)

    suite = commands.add_parser("suite")
    suite_commands = suite.add_subparsers(dest="operation", required=True)
    suite_plan_command = suite_commands.add_parser("plan")
    suite_run_command = suite_commands.add_parser("run")
    suite_run_command.add_argument("--out", type=Path, required=True)
    suite_run_command.add_argument("--seed")
    suite_run_command.add_argument(
        "--diagnostic-unqualified-host", action="store_true"
    )
    for option in (suite_run_command, suite_commands.add_parser("resume")):
        if option is not suite_run_command:
            option.add_argument("--suite-dir", type=Path, required=True)
        option.add_argument("--bin-dir", type=Path)
        option.add_argument("--qualification-store", type=Path)
        option.add_argument("--interoperability-store", type=Path)
    suite_status_command = suite_commands.add_parser("status")
    suite_status_command.add_argument("--suite-dir", type=Path, required=True)

    qualification = commands.add_parser("qualification")
    qualification_commands = qualification.add_subparsers(dest="operation", required=True)
    for operation in ("run", "store", "acquire", "status"):
        subcommand = qualification_commands.add_parser(operation)
        subcommand.add_argument("--kind", choices=sorted(ARTIFACT_KINDS), required=True)
        subcommand.add_argument("--run-dir", type=Path, required=True)
        subcommand.add_argument("--artifact-store", type=Path, required=True)
        if operation == "store":
            subcommand.add_argument("--evidence", type=Path, required=True)
        if operation == "run":
            subcommand.add_argument("--driver", type=Path)

    legacy = commands.add_parser("legacy")
    legacy_commands = legacy.add_subparsers(dest="operation", required=True)
    translate = legacy_commands.add_parser("translate")
    translate.add_argument("--base-profile", type=Path, required=True)
    translate.add_argument("--out", type=Path, required=True)
    translate.add_argument("--set", action="append", default=[], metavar="NAME=VALUE")
    parity = legacy_commands.add_parser("parity")
    parity.add_argument("--profile", type=Path, required=True)
    parity.add_argument("--out", type=Path, required=True)
    parity.add_argument("--bin-dir", type=Path, required=True)
    parity.add_argument("--qualification-profile", type=Path, required=True)
    parity.add_argument("--qualification-run-dir", type=Path, required=True)
    parity.add_argument("--qualification-store", type=Path, required=True)
    parity.add_argument("--seed")
    parity.add_argument("--diagnostic-unqualified-host", action="store_true")
    return parser


def _capability_contract_check(
    entry: Any, spec: Any, capabilities: Any
) -> tuple[bool, str]:
    binary_role = str(entry["role"])
    required_roles = set()
    required_backends = set()
    if binary_role in {"server", "server_reference_client"}:
        required_roles.add("server")
        required_backends.update(spec.server_backends)
    if binary_role in {"reference_client", "server_reference_client"}:
        required_roles.add("client")
        required_backends.add(spec.reference_client_backend)

    advertised_roles = set(str(capabilities["roles"]).split(","))
    missing_roles = sorted(required_roles - advertised_roles)
    if missing_roles:
        return False, f"configured roles are not attested: {','.join(missing_roles)}"
    advertised_backends = set(str(capabilities["backends"]).split(","))
    missing_backends = sorted(required_backends - advertised_backends)
    if missing_backends:
        return False, f"configured backends are not attested: {','.join(missing_backends)}"
    try:
        required_scenarios = {SCENARIO_CAPABILITY_IDS[scenario] for scenario in spec.scenarios}
    except KeyError as exc:
        return False, f"scenario has no native capability ID: {exc.args[0]}"
    advertised_scenarios = set(str(capabilities["scenarios"]).split(","))
    if "all" not in advertised_scenarios:
        missing_scenarios = sorted(
            required_scenarios - advertised_scenarios, key=int
        )
        if missing_scenarios:
            return False, (
                "configured scenario IDs are not attested: "
                + ",".join(missing_scenarios)
            )
    return True, "configured roles, backends, and scenario IDs are attested"


def _describe_check(root: Path, path: Path, entry: Any, spec: Any) -> tuple[bool, str]:
    try:
        with tempfile.TemporaryDirectory(prefix="quicperf-doctor-") as temporary:
            with Supervisor() as supervisor:
                managed = supervisor.spawn(
                    [str(path), "describe"],
                    log_path=Path(temporary) / f"{entry['name']}.log",
                    cwd=root,
                    pass_control_argument=True,
                )
                channel = SeqPacketChannel(managed.control)
                capabilities = _attest_hello(
                    channel,
                    role="describe",
                    timeout_ns=int(spec.raw["timing"]["timeouts"]["describe_ns"]),
                    expected_build_id=str(entry["elf_build_id"]),
                )
                passed_contract, detail = _capability_contract_check(
                    entry, spec, capabilities
                )
                if not passed_contract:
                    return False, detail
                attest_process_libraries(
                    root,
                    managed.process.pid,
                    path,
                    entry["expected_loaded_libraries"],
                )
                channel.send(MessageType.SHUTDOWN, {})
                packet = channel.receive()
                if packet.message_type is not MessageType.SHUTDOWN_ACK:
                    return False, "describe did not acknowledge shutdown"
        return True, "structured HELLO/CAPABILITIES/SHUTDOWN contract passed"
    except Exception as exc:
        return False, str(exc)


def doctor(
    profile: Path,
    bin_dir: Path | None,
    *,
    phase: str = "all",
    refresh_interoperability: bool = False,
    interoperability_store: Path | None = None,
    qualification_store: Path | None = None,
) -> tuple[dict[str, Any], int]:
    root = _root()
    spec = load_experiment_spec(profile)
    inventory = PreflightInventory()
    calibration_reasons = _statistical_calibration_reasons(
        root, spec.campaign_kind, spec.raw["analysis"]
    )
    inventory.add(
        passed("statistical_calibration", "publication analysis calibrated")
        if not calibration_reasons
        else failed(
            "statistical_calibration",
            "statistical_calibration_failed",
            calibration_reasons[0],
        )
    )
    manifest = None
    try:
        manifest = collect_manifest(root, spec, bin_dir=bin_dir)
    except Exception as exc:
        inventory.add(
            failed(
                "source_build_policy",
                "manifest_collection_failed",
                str(exc),
            )
        )
        inventory.add(
            not_run(
                "source_identity",
                "manifest_unavailable",
                "source cleanliness cannot be evaluated without a valid manifest",
            )
        )
    else:
        inventory.add(
            passed(
                "source_build_policy",
                "source, dependency, toolchain, effective build policy, and binary identities collected",
            )
        )
        clean_required = bool(
            spec.raw["manifest_policy"]["clean_tree_required"]
        )
        clean = bool(manifest.source["clean"])
        inventory.add(
            passed(
                "source_identity",
                "clean source tree"
                if clean
                else "dirty source tree is allowed by the selected profile",
            )
            if clean or not clean_required
            else failed(
                "source_identity", "dirty_source_tree", "dirty source tree"
            )
        )

    if manifest is None:
        for name in sorted(set(spec.servers) | set(spec.reference_clients)):
            inventory.add(
                not_run(
                    f"describe:{name}",
                    "manifest_unavailable",
                    "native describe/capability attestation requires a valid binary manifest",
                )
            )
    else:
        for entry in manifest.binaries:
            if entry["role"] not in {
                "server", "reference_client", "server_reference_client"
            }:
                continue
            name = f"describe:{entry['name']}"
            try:
                path = _assert_binary_unchanged(entry)
                contract_passed, detail = _describe_check(
                    root, path, entry, spec
                )
            except Exception as exc:
                contract_passed, detail = False, str(exc)
            inventory.add(
                passed(name, detail)
                if contract_passed
                else failed(name, "native_describe_contract_failed", detail)
            )

    topology = None
    try:
        client_cores = int(
            spec.raw["treatment"]["resources"]["client_physical_cores"]
        )
        lanes = allocate_lanes(
            discover_physical_cores(),
            1,
            client_cores_per_lane=client_cores,
        )
        topology = lanes[0]
        inventory.add(
            passed(
                "physical_core_isolation",
                f"one lane with {client_cores} client cores resolved on "
                f"CPUs {topology.all_cpus()}",
            )
        )
    except Exception as exc:
        inventory.add(
            failed("physical_core_isolation", "lane_topology_unavailable", str(exc))
        )
    swap_disabled = swap_is_disabled()
    inventory.add(
        passed("swap_disabled", "no active swap")
        if swap_disabled
        else failed("swap_disabled", "swap_active", "swap is active")
    )
    inventory.add(
        cgroup_isolation_check(topology)
        if topology is not None
        else not_run(
            "cgroup_v2_isolation",
            "lane_topology_unavailable",
            "exact cgroup lane probe requires a resolved physical lane",
        )
    )
    raw_resolution = time.clock_getres(time.CLOCK_MONOTONIC_RAW)
    mono_resolution = time.clock_getres(time.CLOCK_MONOTONIC)
    clock_ok = raw_resolution <= 1e-6 and mono_resolution <= 1e-6
    clock_detail = f"raw={raw_resolution:g}s monotonic={mono_resolution:g}s"
    inventory.add(
        passed("clock_resolution", clock_detail)
        if clock_ok
        else failed("clock_resolution", "clock_resolution_too_coarse", clock_detail)
    )
    tls = spec.raw["treatment"]["tls"]
    inventory.add(tls_material_check(root, tls))
    if "iouring" in spec.server_backends:
        disabled_path = Path("/proc/sys/kernel/io_uring_disabled")
        try:
            disabled = int(disabled_path.read_text().strip())
        except (OSError, ValueError) as exc:
            inventory.add(
                failed("io_uring", "io_uring_policy_unreadable", str(exc))
            )
        else:
            detail = f"kernel io_uring_disabled={disabled}"
            inventory.add(
                passed("io_uring", detail)
                if disabled != 2
                else failed("io_uring", "io_uring_disabled", detail)
            )
    resources = spec.raw["treatment"]["resources"]
    for field in ("governor", "epp", "turbo"):
        name = f"host_policy:{field}"
        if manifest is None:
            inventory.add(
                not_run(
                    name,
                    "manifest_unavailable",
                    "host policy cannot be compared without a valid manifest",
                )
            )
            continue
        expected = resources[field]
        actual = manifest.host_policy[field]
        detail = f"expected={expected} observed={actual}"
        inventory.add(
            passed(name, detail)
            if expected == actual
            else failed(name, "host_policy_mismatch", detail)
        )
    for field in ("frequency_min_khz", "frequency_max_khz"):
        name = f"host_policy:{field}"
        if manifest is None:
            inventory.add(
                not_run(
                    name,
                    "manifest_unavailable",
                    "host frequency cannot be compared without a valid manifest",
                )
            )
            continue
        actual = manifest.host_policy[field]
        detail = f"expected=3800000 observed={actual}"
        inventory.add(
            passed(name, detail)
            if actual == "3800000"
            else failed(name, "host_policy_mismatch", detail)
        )
    inventory.add(
        not_run(
            "host_policy:irq_exclusion",
            "manifest_unavailable",
            "IRQ exclusion requires a valid host-policy manifest",
        )
        if manifest is None
        else passed(
            "host_policy:irq_exclusion",
            "boot isolation and default/writable IRQ routing exclude measured "
            "CPUs; isolated managed queues are subject to the zero-delta "
            "timed-interval gate",
        )
    )
    if phase != "deterministic":
        if manifest is None:
            inventory.add(
                not_run(
                    "host_stability",
                    "manifest_unavailable",
                    "host stability requires a valid current-binary manifest",
                )
            )
        else:
            try:
                identity = build_qualification_identity(
                    "host-stability", spec, manifest
                )
                stored = QualificationArtifactStore(
                    qualification_store or root / ".data/qualification-v2"
                ).load_optional("host-stability", identity)
            except Exception as exc:
                inventory.add(
                    failed(
                        "host_stability",
                        "host_stability_artifact_invalid",
                        str(exc),
                    )
                )
            else:
                if stored is None:
                    inventory.add(
                        not_run(
                            "host_stability",
                            "exact_identity_host_stability_artifact_missing",
                            "the live AMD provider has not qualified this boot/build/policy identity",
                        )
                    )
                elif not stored.decision.qualified:
                    inventory.add(
                        failed(
                            "host_stability",
                            "hardware_unqualified",
                            "; ".join(stored.decision.reasons),
                        )
                    )
                else:
                    inventory.add(
                        passed(
                            "host_stability",
                            "amd_delivered_performance_v1 calibration and controls passed",
                        )
                    )
    inventory.extend(selected_path_checks(spec))
    store = interoperability_store or root / ".data" / "interoperability-v2"
    if manifest is None:
        inventory.add(
            not_run(
                "native_interoperability",
                "manifest_unavailable",
                "native interoperability requires a valid current-binary manifest",
            )
        )
    elif (
        refresh_interoperability
        and bool(spec.raw["manifest_policy"]["clean_tree_required"])
        and not bool(manifest.source["clean"])
    ):
        inventory.add(
            not_run(
                "native_interoperability",
                "clean_source_identity_required",
                "interoperability refresh refused before the release source identity is clean",
            )
        )
    else:
        try:
            artifact = (
                refresh_native_interoperability(
                    root=root,
                    store_root=store,
                    spec=spec,
                    manifest=manifest,
                )
                if refresh_interoperability
                else load_native_interoperability(
                    store_root=store,
                    spec=spec,
                    manifest=manifest,
                )
            )
        except Exception as exc:
            inventory.add(
                failed(
                    "native_interoperability",
                    "native_interoperability_artifact_invalid"
                    if not refresh_interoperability
                    else "native_interoperability_refresh_failed",
                    str(exc),
                )
            )
        else:
            if artifact is None:
                combinations = interoperability_plan_cardinality(spec)
                inventory.add(
                    not_run(
                        "native_interoperability",
                        "exact_identity_interoperability_artifact_missing",
                        f"{combinations} selected current-binary tuples require an immutable refresh",
                    )
                )
            elif artifact.status == INTEROPERABILITY_FAIL:
                inventory.add(
                    failed(
                        "native_interoperability",
                        "native_interoperability_tuple_failed",
                        interoperability_check_detail(artifact),
                    )
                )
            else:
                inventory.add(
                    passed(
                        "native_interoperability",
                        interoperability_check_detail(artifact),
                    )
                )
    preflight_passed = inventory.passed
    return {
        "schema_version": "quicperf.doctor.v2",
        "profile": spec.name,
        "phase": phase,
        "passed": preflight_passed,
        "checks": inventory.as_dicts(),
        "summary": inventory.summary(),
        "publication_status": "preflight_passed" if preflight_passed else "preflight_failed",
    }, EXIT_SUCCESS if preflight_passed else EXIT_INVALID


def _expected_kind(command: str) -> str | None:
    return {"capacity": "capacity", "memory": "memory", "tail": "tail"}.get(command)


def _dispatch(arguments: argparse.Namespace) -> int:
    root = _root()
    if arguments.command == "doctor":
        result, code = doctor(
            arguments.profile,
            arguments.bin_dir,
            phase=arguments.phase,
            refresh_interoperability=arguments.refresh_interoperability,
            interoperability_store=arguments.interoperability_store,
            qualification_store=arguments.qualification_store,
        )
        _emit(result)
        return code
    if arguments.command == "export":
        _emit({"checksums": export_campaign(arguments.run_dir)})
        return EXIT_SUCCESS
    if arguments.command == "suite":
        if arguments.operation == "plan":
            _emit(suite_plan(root=root))
            return EXIT_SUCCESS
        if arguments.operation == "run":
            result = suite_run(
                root=root,
                suite_dir=arguments.out,
                seed=arguments.seed,
                bin_dir=arguments.bin_dir,
                qualification_store=arguments.qualification_store,
                interoperability_store=arguments.interoperability_store,
                campaign_names=DEFAULT_CAMPAIGNS,
                diagnostic_unqualified_host=arguments.diagnostic_unqualified_host,
            )
        elif arguments.operation == "resume":
            result = suite_resume(
                root=root,
                suite_dir=arguments.suite_dir,
                bin_dir=arguments.bin_dir,
                qualification_store=arguments.qualification_store,
                interoperability_store=arguments.interoperability_store,
            )
        else:
            result = suite_status(root=root, suite_dir=arguments.suite_dir)
        _emit(result)
        return (
            EXIT_NONPUBLISHABLE
            if result.get("diagnostic_unqualified_host")
            and result.get("terminal")
            else EXIT_INCOMPLETE
            if result.get("diagnostic_unqualified_host")
            else EXIT_SUCCESS
        )
    if arguments.command == "qualification":
        if arguments.operation == "run":
            result = run_qualification(
                run_dir=arguments.run_dir,
                kind=arguments.kind,
                artifact_store=arguments.artifact_store,
                observation_source=(
                    SubprocessObservationSource(arguments.driver)
                    if arguments.driver is not None
                    else None
                ),
            )
        elif arguments.operation == "store":
            result = store_qualification_evidence(
                run_dir=arguments.run_dir,
                kind=arguments.kind,
                evidence_path=arguments.evidence,
                artifact_store=arguments.artifact_store,
            )
        elif arguments.operation == "acquire":
            result = acquire_qualification_artifact(
                run_dir=arguments.run_dir,
                kind=arguments.kind,
                artifact_store=arguments.artifact_store,
            )
        else:
            result = qualification_status(
                run_dir=arguments.run_dir,
                kind=arguments.kind,
                artifact_store=arguments.artifact_store,
            )
        _emit(result)
        return EXIT_SUCCESS if result["qualified"] else EXIT_NONPUBLISHABLE
    if arguments.command == "legacy":
        if arguments.operation == "parity":
            execution = run_legacy_v2_parity(
                root=root,
                profile=arguments.profile,
                out_dir=arguments.out,
                bin_dir=arguments.bin_dir,
                qualification_profile=arguments.qualification_profile,
                qualification_run_dir=arguments.qualification_run_dir,
                qualification_store=arguments.qualification_store,
                seed_text=arguments.seed,
                diagnostic_unqualified_host=arguments.diagnostic_unqualified_host,
            )
            _emit(
                {
                    **execution.artifact,
                    "artifact_path": str(execution.artifact_path),
                }
            )
            return (
                EXIT_NONPUBLISHABLE
                if execution.artifact["status"]
                == "diagnostic_complete_nonpublication"
                else EXIT_SUCCESS
                if execution.artifact["status"] == "qualified"
                else EXIT_NONPUBLISHABLE
            )
        assignments = {}
        for item in arguments.set:
            if "=" not in item:
                raise InvalidConfigurationError("--set requires NAME=VALUE")
            name, value = item.split("=", 1)
            if not name or name in assignments:
                raise InvalidConfigurationError("legacy assignments must be nonempty and unique")
            assignments[name] = value
        content = translate_legacy(arguments.base_profile, assignments)
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(arguments.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        _emit({"translated_profile": str(arguments.out), "bytes": len(content), "executed": False})
        return EXIT_SUCCESS

    expected_kind = _expected_kind(arguments.command)
    if arguments.operation == "create":
        spec = load_experiment_spec(arguments.profile)
        if expected_kind is not None and spec.campaign_kind != expected_kind:
            raise InvalidConfigurationError(
                f"{arguments.command} create requires a {expected_kind} profile"
            )
        if arguments.command == "campaign" and spec.campaign_kind in {"capacity", "memory", "tail"}:
            raise InvalidConfigurationError(f"use quicperfctl {spec.campaign_kind} create for this profile")
        created = create_campaign(
            root=root,
            profile=arguments.profile,
            run_dir=arguments.out,
            seed=arguments.seed,
            bin_dir=arguments.bin_dir,
            qualification_store=arguments.qualification_store,
            interoperability_store=arguments.interoperability_store,
        )
        _emit(
            {
                "campaign_id": created.campaign_id,
                "schedule_hash": created.schedule_hash,
                "planned_trials": created.planned_trials,
                "maximum_trial_ids": created.maximum_trial_ids,
                "run_dir": str(created.run_dir),
            }
        )
        return EXIT_SUCCESS
    if arguments.operation == "status":
        _emit(campaign_status(arguments.run_dir))
        return EXIT_SUCCESS
    if arguments.operation == "run":
        result = run_campaign_session(root=root, run_dir=arguments.run_dir, session=arguments.session)
        _emit(result)
        return EXIT_SUCCESS if result["status"] == "complete" else EXIT_NONPUBLISHABLE if result["status"] == "nonpublishable" else EXIT_INCOMPLETE
    if arguments.operation == "analyze":
        result = analyze_campaign(arguments.run_dir)
        _emit(result)
        if not result["analysis_complete"]:
            return EXIT_INCOMPLETE
        return EXIT_SUCCESS if result["publication_valid"] else EXIT_NONPUBLISHABLE
    if arguments.operation == "finalize":
        result = finalize_campaign(arguments.run_dir)
        _emit(result)
        return EXIT_SUCCESS if result["publication_valid"] else EXIT_NONPUBLISHABLE
    raise InvalidConfigurationError("unknown command")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        return _dispatch(arguments)
    except KeyboardInterrupt:
        sys.stderr.write("quicperfctl: interrupted; journal remains safely resumable\n")
        return EXIT_INTERRUPT
    except (HarnessError, ManifestCollectionError, EndpointRunError) as exc:
        code = getattr(exc, "exit_code", EXIT_INVALID if isinstance(exc, ManifestCollectionError) else EXIT_INTERNAL)
        sys.stderr.write(f"quicperfctl: {exc}\n")
        return int(code)
    except Exception as exc:
        if arguments.debug:
            raise
        sys.stderr.write(f"quicperfctl: internal error: {exc}\n")
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
