"""Crash-safe coordinator for explicitly selected v2 publication estimands."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
from typing import Any, Iterator, Mapping

from .amd_stability import PROBE_START_LEAD_NS
from .canonical import canonical_bytes, load_strict, loads_strict
from .errors import InvalidConfigurationError
from .identity import domain_hash
from .interoperability import (
    POST_TRIAL_QUIESCENCE_NS,
    interoperability_plan_cardinality,
)
from .journal import Journal
from .planner import PUBLICATION_BALANCE_CONTROL_TRIALS
from .runner import (
    _arm_control_policy,
    _diagnostic_schedule_manifest,
    analyze_campaign,
    campaign_identity,
    campaign_status,
    create_campaign,
    finalize_campaign,
    run_campaign_session,
)
from .spec import load_experiment_spec


SUITE_SCHEMA_VERSION = "quicperf.publication-suite.v10"

_QUALIFICATION_FIELDS = (
    ("host-stability", "host_stability_required"),
    ("client-headroom", "client_headroom_required"),
    ("lane-interference", "lane_interference_required"),
    ("worker-reuse", "worker_reuse_required"),
    ("window-qualification", "window_equivalence_required"),
    ("tail-window", "tail_window_required"),
)


class SuiteError(InvalidConfigurationError):
    pass


@dataclass(frozen=True)
class SuiteCampaign:
    name: str
    profile: str
    run_directory: str


CAMPAIGNS = (
    SuiteCampaign(
        "fixed_treatment", "profiles/v2.3/publication.json", "fixed"
    ),
)
DEFAULT_CAMPAIGNS = ("fixed_treatment",)
_AMD_POLICY_PATH = Path("profiles/v2/host-stability/amd-delivered-performance-v1.json")


def _selected_campaigns(names: tuple[str, ...]) -> tuple[SuiteCampaign, ...]:
    catalog = {entry.name: entry for entry in CAMPAIGNS}
    if not names:
        raise SuiteError("suite must select at least one confirmatory campaign")
    if len(set(names)) != len(names):
        raise SuiteError("suite campaign selection contains duplicates")
    unknown = sorted(set(names) - set(catalog))
    if unknown:
        raise SuiteError(f"unknown suite campaign: {', '.join(unknown)}")
    selected = tuple(entry for entry in CAMPAIGNS if entry.name in names)
    if tuple(entry.name for entry in selected) != names:
        raise SuiteError("suite campaigns must use canonical estimand order")
    return selected


def _seed(seed: str | None) -> bytes:
    if seed is None:
        return secrets.token_bytes(32)
    try:
        value = bytes.fromhex(seed)
    except ValueError as exc:
        raise SuiteError("suite seed must be 64 lowercase hexadecimal characters") from exc
    if len(value) != 32 or seed != value.hex():
        raise SuiteError("suite seed must be 64 lowercase hexadecimal characters")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _amd_session_probe_ns(root: Path) -> int:
    policy = load_strict(root / _AMD_POLICY_PATH)
    try:
        seconds = policy["performance"]["session_probe_seconds"]
    except (KeyError, TypeError) as exc:
        raise SuiteError("AMD session probe timing is unavailable") from exc
    if type(seconds) is not int or seconds <= 0:
        raise SuiteError("AMD session probe timing is invalid")
    return seconds * 1_000_000_000 + PROBE_START_LEAD_NS


def _primary_admission_timing(
    *,
    interoperability_measurement_ns: int,
    interoperability_warmup_ns: int,
    interoperability_quiescence_ns: int,
    interoperability_tuples: int,
    include_lane_interference: bool,
    arm_lead_ns: int,
) -> dict[str, Any]:
    interop_lead_ns = interoperability_tuples * arm_lead_ns
    interop_ns = (
        interoperability_measurement_ns
        + interoperability_warmup_ns
        + interoperability_quiescence_ns
        + interop_lead_ns
    )
    gates: dict[str, Any] = {
        "native_interoperability": {
            "request_groups": interoperability_tuples,
            "arm_groups": interoperability_tuples,
            "lane_trials": interoperability_tuples,
            "components_ns": {
                "arm_lead": interop_lead_ns,
                "warmup": interoperability_warmup_ns,
                "measurement": interoperability_measurement_ns,
                "quiescence": interoperability_quiescence_ns,
            },
            "normal_ns": interop_ns,
            "bounded_max_ns": interop_ns,
            "reservation_ns": interop_ns,
        },
        "host_stability": {
            "normal_ns": 302_600_000_000,
            "bounded_max_ns": 2_642_600_000_000,
            "reservation_ns": 2_642_600_000_000,
        },
        "client_headroom": {
            "request_groups": {"screen": 72, "held": 12},
            "arm_groups": 168,
            "lane_trials": 168,
            "normal_ns": 295_100_000_000,
            "bounded_max_ns": 529_950_000_000,
            "reservation_ns": 590_200_000_000,
        },
    }
    if include_lane_interference:
        gates["lane_interference"] = {
            "request_groups": {"screen": 96, "held": 160},
            "arm_groups": 512,
            "lane_trials": 672,
            "normal_ns": 1_294_900_000_000,
            "bounded_max_ns": 2_529_550_000_000,
            "reservation_ns": 2_589_800_000_000,
        }
    return {
        "schema_version": "quicperf.admission-timing.v1",
        "scope": "nominal_scheduled_intervals",
        "excludes": [
            "setup",
            "teardown",
            "control_latency",
            "scheduler_oversleep",
            "external_restarts",
        ],
        "gates": gates,
        "totals_ns": {
            "normal": sum(int(gate["normal_ns"]) for gate in gates.values()),
            "bounded_current_flow": sum(
                int(gate["bounded_max_ns"]) for gate in gates.values()
            ),
            "conservative_reservation": sum(
                int(gate["reservation_ns"]) for gate in gates.values()
            ),
        },
    }


def _timing_plan(
    root: Path, campaigns: tuple[SuiteCampaign, ...]
) -> dict[str, Any]:
    entries = []
    total_measurement_ns = 0
    total_balance_control_measurement_ns = 0
    total_warmup_ns = 0
    required_qualifications: set[str] = set()
    interoperability_tuples = 0
    interoperability_measurement_ns = 0
    interoperability_warmup_ns = 0
    interoperability_quiescence_ns = 0
    fixed_lane_interference_required = False
    fixed_operational_timeout_ns: int | None = None
    fixed_runtime_policy: Mapping[str, Any] | None = None
    fixed_arm_lead_ns = 0
    session_probe_ns = _amd_session_probe_ns(root)
    for entry in campaigns:
        spec = load_experiment_spec(root / entry.profile)
        arm_lead_ns = _arm_control_policy(spec).lead_ns
        if entry.name == "fixed_treatment":
            fixed_arm_lead_ns = arm_lead_ns
        execution_lanes = (
            1
            if spec.raw["schedule"]["lane_assignment"] == "single_lane"
            else 2
        )
        workloads = tuple(spec.raw["workloads"])
        planned = spec.expected_cardinality.planned_trials
        if planned % len(workloads):
            raise SuiteError(
                f"{entry.name} trials are not balanced across its scenarios"
            )
        trials_per_scenario = planned // len(workloads)
        measurement_ns = trials_per_scenario * sum(
            int(workload["measurement_ns"]) for workload in workloads
        )
        warmup_ns = trials_per_scenario * sum(
            int(workload["warmup_ns"]) for workload in workloads
        )
        balance_control_trials = (
            PUBLICATION_BALANCE_CONTROL_TRIALS
            if entry.name == "fixed_treatment" and execution_lanes == 2
            else 0
        )
        balance_control_measurement_ns = (
            balance_control_trials * 2_000_000_000
        )
        scheduled_trials = planned + balance_control_trials
        scheduled_measurement_ns = (
            measurement_ns + balance_control_measurement_ns
        )
        arm_floor_ns = (
            scheduled_measurement_ns + warmup_ns + execution_lanes - 1
        ) // execution_lanes
        parallel_wait_ns = 0
        if entry.name == "fixed_treatment" and execution_lanes == 2:
            trials_per_block = len(spec.servers) * len(spec.server_backends)
            blocks_per_scenario = trials_per_scenario // trials_per_block
            workload_arms = {
                str(workload["scenario"]): int(workload["measurement_ns"])
                + int(workload["warmup_ns"])
                for workload in workloads
            }
            loss_block_ns = (
                workload_arms["loss_recovery"] * trials_per_block
            )
            bridge_block_ns = max(
                arm * trials_per_block
                for scenario, arm in workload_arms.items()
                if scenario != "loss_recovery"
            )
            parallel_wait_ns = (
                blocks_per_scenario * (loss_block_ns - bridge_block_ns)
            ) // 2
        arm_critical_path_ns = arm_floor_ns + parallel_wait_ns
        arm_lead_floor_ns = (
            (scheduled_trials + execution_lanes - 1) // execution_lanes
        ) * arm_lead_ns
        campaign_probe_ns = (
            2
            * int(spec.expected_cardinality.sessions)
            * session_probe_ns
            if spec.raw["qualification"]["host_stability_required"]
            else 0
        )
        total_measurement_ns += measurement_ns
        total_balance_control_measurement_ns += (
            balance_control_measurement_ns
        )
        total_warmup_ns += warmup_ns
        required = [
            name
            for name, field in _QUALIFICATION_FIELDS
            if bool(spec.raw["qualification"][field])
        ]
        required_qualifications.update(required)
        if entry.name == "fixed_treatment":
            methodology = spec.raw.get("methodology")
            if not isinstance(methodology, Mapping):
                raise SuiteError(
                    "fixed-treatment profile lacks versioned methodology"
                )
            runtime_policy = methodology.get("runtime")
            if not isinstance(runtime_policy, Mapping):
                raise SuiteError(
                    "fixed-treatment profile lacks runtime methodology"
                )
            fixed_operational_timeout_ns = int(
                runtime_policy["operational_session_timeout_ns"]
            )
            fixed_runtime_policy = runtime_policy
            fixed_lane_interference_required = bool(
                spec.raw["qualification"]["lane_interference_required"]
            )
            interoperability_tuples = interoperability_plan_cardinality(spec)
            interoperability_measurement_ns = len(spec.servers) * sum(
                int(workload["measurement_ns"]) for workload in workloads
            )
            interoperability_warmup_ns = len(spec.servers) * sum(
                int(workload["warmup_ns"]) for workload in workloads
            )
            interoperability_quiescence_ns = (
                interoperability_tuples * POST_TRIAL_QUIESCENCE_NS
            )
        entries.append(
            {
                "name": entry.name,
                "execution_lanes": execution_lanes,
                "planned_trials": planned,
                "balance_control_trials": balance_control_trials,
                "scheduled_trials": scheduled_trials,
                "measurement_ns": measurement_ns,
                "balance_control_measurement_ns": (
                    balance_control_measurement_ns
                ),
                "scheduled_measurement_ns": scheduled_measurement_ns,
                "warmup_ns": warmup_ns,
                "arm_floor_ns": arm_floor_ns,
                "parallel_wait_ns": parallel_wait_ns,
                "arm_critical_path_ns": arm_critical_path_ns,
                "arm_lead_floor_ns": arm_lead_floor_ns,
                "session_probe_ns": campaign_probe_ns,
                "scheduled_floor_ns": (
                    arm_critical_path_ns
                    + arm_lead_floor_ns
                    + campaign_probe_ns
                ),
                "parallel_pairing": (
                    "family_disjoint_loss_bridge"
                    if entry.name == "fixed_treatment" and execution_lanes == 2
                    else "serial_williams_order"
                    if entry.name == "fixed_treatment"
                    else "hmac_balanced_lower_bound"
                ),
                "worker_process_policy": spec.raw["schedule"][
                    "worker_process_policy"
                ],
                "measurement_window_scope": "exact_frozen_profile_window",
                "required_qualifications": required,
            }
        )
    has_fixed_treatment = any(
        entry.name == "fixed_treatment" for entry in campaigns
    )
    primary_admission = (
        _primary_admission_timing(
            interoperability_measurement_ns=interoperability_measurement_ns,
            interoperability_warmup_ns=interoperability_warmup_ns,
            interoperability_quiescence_ns=interoperability_quiescence_ns,
            interoperability_tuples=interoperability_tuples,
            include_lane_interference=fixed_lane_interference_required,
            arm_lead_ns=fixed_arm_lead_ns,
        )
        if has_fixed_treatment
        else None
    )
    fixed_treatment_floor_ns = (
        next(
            int(entry["scheduled_floor_ns"])
            for entry in entries
            if entry["name"] == "fixed_treatment"
        )
        if has_fixed_treatment
        else None
    )
    plan = {
        "execution_lanes": {
            str(entry["name"]): int(entry["execution_lanes"])
            for entry in entries
        },
        "campaigns": entries,
        "measurement_ns": total_measurement_ns,
        "balance_control_measurement_ns": (
            total_balance_control_measurement_ns
        ),
        "scheduled_measurement_ns": (
            total_measurement_ns + total_balance_control_measurement_ns
        ),
        "warmup_ns": total_warmup_ns,
        "arm_floor_ns": sum(
            int(entry["arm_floor_ns"]) for entry in entries
        ),
        "parallel_wait_ns": sum(
            int(entry["parallel_wait_ns"]) for entry in entries
        ),
        "arm_critical_path_ns": sum(
            int(entry["arm_critical_path_ns"]) for entry in entries
        ),
        "arm_lead_floor_ns": sum(
            int(entry["arm_lead_floor_ns"]) for entry in entries
        ),
        "session_probe_ns": sum(
            int(entry["session_probe_ns"]) for entry in entries
        ),
        "scheduled_floor_ns": (
            sum(int(entry["scheduled_floor_ns"]) for entry in entries)
        ),
        "required_qualifications": [
            name
            for name, _field in _QUALIFICATION_FIELDS
            if name in required_qualifications
        ],
        "primary_admission": primary_admission,
        "fixed_treatment_operational_session_timeout_ns": (
            fixed_operational_timeout_ns if has_fixed_treatment else None
        ),
        "fixed_treatment_operational_timeout_publication_gate": (
            (
                fixed_runtime_policy is not None
                and "suite_deadline_ns" in fixed_runtime_policy
            )
            if has_fixed_treatment
            else None
        ),
        "fixed_treatment_total_operational_timeout_ns": (
            2 * fixed_operational_timeout_ns
            if fixed_operational_timeout_ns is not None
            else None
        ),
        "fixed_treatment_operational_margin_above_scheduled_floor_ns": (
            2 * fixed_operational_timeout_ns
            - fixed_treatment_floor_ns
            if fixed_treatment_floor_ns is not None
            and fixed_operational_timeout_ns is not None
            else None
        ),
        "fixed_treatment_normal_end_to_end_floor_ns": (
            fixed_treatment_floor_ns
            + int(primary_admission["totals_ns"]["normal"])
            if fixed_treatment_floor_ns is not None
            and primary_admission is not None
            else None
        ),
        "fixed_treatment_conservative_end_to_end_estimate_ns": (
            int(fixed_runtime_policy["clean_start_conservative_budget_ns"])
            if fixed_runtime_policy is not None
            else None
        ),
        "deterministic_verification_budget_ns": (
            int(fixed_runtime_policy["deterministic_verification_budget_ns"])
            if fixed_runtime_policy is not None
            else None
        ),
        "analysis_finalization_export_budget_ns": (
            int(
                fixed_runtime_policy[
                    "analysis_finalization_export_budget_ns"
                ]
            )
            if fixed_runtime_policy is not None
            else None
        ),
        "clean_start_conservative_budget_ns": (
            int(fixed_runtime_policy["clean_start_conservative_budget_ns"])
            if fixed_runtime_policy is not None
            else None
        ),
        "suite_deadline_ns": (
            int(fixed_runtime_policy["suite_deadline_ns"])
            if fixed_runtime_policy is not None
            else None
        ),
    }
    if fixed_runtime_policy is not None and primary_admission is not None:
        calculated_clean_start_ns = (
            int(fixed_runtime_policy["deterministic_verification_budget_ns"])
            + int(primary_admission["totals_ns"]["conservative_reservation"])
            + 2 * int(fixed_runtime_policy["operational_session_timeout_ns"])
            + int(
                fixed_runtime_policy[
                    "analysis_finalization_export_budget_ns"
                ]
            )
        )
        frozen_clean_start_ns = int(
            fixed_runtime_policy["clean_start_conservative_budget_ns"]
        )
        suite_deadline_ns = int(fixed_runtime_policy["suite_deadline_ns"])
        if (
            int(primary_admission["totals_ns"]["conservative_reservation"])
            != int(
                fixed_runtime_policy[
                    "admission_conservative_reservation_ns"
                ]
            )
            or fixed_treatment_floor_ns
            != int(fixed_runtime_policy["scheduled_campaign_floor_ns"])
            or calculated_clean_start_ns != frozen_clean_start_ns
        ):
            raise SuiteError(
                "suite conservative timing derivation differs from its "
                "frozen versioned identity"
            )
        if calculated_clean_start_ns > suite_deadline_ns:
            raise SuiteError(
                "suite conservative timing derivation exceeds the frozen "
                "hard deadline"
            )
    return plan


def _suite_path(suite_dir: Path) -> Path:
    return suite_dir / "suite.json"


def _write_state(suite_dir: Path, state: Mapping[str, Any]) -> None:
    content = canonical_bytes(state)
    path = _suite_path(suite_dir)
    temporary = suite_dir / f".suite.json.tmp-{os.getpid()}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(suite_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _load_state(suite_dir: Path) -> dict[str, Any]:
    path = _suite_path(suite_dir)
    if not path.is_file() or path.is_symlink():
        raise SuiteError(f"suite state is unavailable: {path}")
    try:
        state = load_strict(path)
    except Exception as exc:
        raise SuiteError(f"suite state is not strict JSON: {exc}") from exc
    if not isinstance(state, dict) or canonical_bytes(state) != path.read_bytes():
        raise SuiteError("suite state is not canonical")
    if (
        set(state)
        != {
            "schema_version",
            "phase",
            "suite_seed",
            "creation_inputs",
            "timing_plan",
            "campaigns",
        }
        or state.get("schema_version") != SUITE_SCHEMA_VERSION
        or state.get("phase") not in {"freezing", "frozen"}
        or not isinstance(state.get("suite_seed"), str)
        or len(state["suite_seed"]) != 64
        or any(character not in "0123456789abcdef" for character in state["suite_seed"])
        or not isinstance(state.get("campaigns"), list)
        or not 1 <= len(state["campaigns"]) <= len(CAMPAIGNS)
        or not isinstance(state.get("timing_plan"), Mapping)
    ):
        raise SuiteError("suite state fields are invalid")
    campaign_fields = {
        "name",
        "profile",
        "profile_sha256",
        "run_directory",
        "seed",
        "campaign_id",
        "schedule_hash",
        "planned_trials",
        "maximum_trial_ids",
    }
    for item in state["campaigns"]:
        if (
            not isinstance(item, dict)
            or set(item) != campaign_fields
            or not all(
                isinstance(item[field], str) and bool(item[field])
                for field in ("name", "profile", "run_directory")
            )
            or any(
                not isinstance(item[field], str)
                or len(item[field]) != 64
                or any(character not in "0123456789abcdef" for character in item[field])
                for field in ("profile_sha256", "seed")
            )
        ):
            raise SuiteError("suite campaign fields are invalid")
        frozen_values = (
            item["campaign_id"],
            item["schedule_hash"],
            item["planned_trials"],
            item["maximum_trial_ids"],
        )
        if all(value is None for value in frozen_values):
            if state["phase"] == "frozen":
                raise SuiteError("frozen suite contains an unfrozen campaign")
            continue
        if (
            not isinstance(item["campaign_id"], str)
            or len(item["campaign_id"]) != 64
            or any(character not in "0123456789abcdef" for character in item["campaign_id"])
            or not isinstance(item["schedule_hash"], str)
            or len(item["schedule_hash"]) != 64
            or any(character not in "0123456789abcdef" for character in item["schedule_hash"])
            or type(item["planned_trials"]) is not int
            or item["planned_trials"] <= 0
            or type(item["maximum_trial_ids"]) is not int
            or item["maximum_trial_ids"] < item["planned_trials"]
        ):
            raise SuiteError("suite frozen campaign identity is invalid")
    _selected_campaigns(tuple(str(item["name"]) for item in state["campaigns"]))
    return state


@contextmanager
def _suite_lock(suite_dir: Path, *, create: bool) -> Iterator[None]:
    if create:
        suite_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    elif not suite_dir.is_dir() or suite_dir.is_symlink():
        raise SuiteError(f"suite directory is unavailable: {suite_dir}")
    descriptor = os.open(
        suite_dir / ".coordinator.lock",
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC,
        0o600,
    )
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SuiteError("another suite coordinator owns this run") from exc
        yield
    finally:
        os.close(descriptor)


def _resolved(path: Path | None) -> str | None:
    return None if path is None else str(path.resolve())


def _initial_state(
    root: Path,
    seed: bytes,
    *,
    campaign_names: tuple[str, ...] = DEFAULT_CAMPAIGNS,
    bin_dir: Path | None = None,
    qualification_store: Path | None = None,
    interoperability_store: Path | None = None,
) -> dict[str, Any]:
    campaigns = []
    selected = _selected_campaigns(campaign_names)
    for entry in selected:
        profile = root / entry.profile
        if not profile.is_file() or profile.is_symlink():
            raise SuiteError(f"suite profile is unavailable: {profile}")
        campaigns.append(
            {
                "name": entry.name,
                "profile": entry.profile,
                "profile_sha256": _sha256(profile),
                "run_directory": entry.run_directory,
                "seed": domain_hash(
                    "publication-suite-campaign-seed",
                    seed,
                    entry.name.encode("ascii"),
                ),
                "campaign_id": None,
                "schedule_hash": None,
                "planned_trials": None,
                "maximum_trial_ids": None,
            }
        )
    return {
        "schema_version": SUITE_SCHEMA_VERSION,
        "phase": "freezing",
        "suite_seed": seed.hex(),
        "creation_inputs": {
            "root": str(root.resolve()),
            "bin_dir": _resolved(bin_dir),
            "qualification_store": _resolved(qualification_store),
            "interoperability_store": _resolved(interoperability_store),
        },
        "timing_plan": _timing_plan(root, selected),
        "campaigns": campaigns,
    }


def _verify_profiles(root: Path, state: Mapping[str, Any]) -> None:
    inputs = state.get("creation_inputs")
    if (
        not isinstance(inputs, Mapping)
        or set(inputs)
        != {
            "root",
            "bin_dir",
            "qualification_store",
            "interoperability_store",
        }
        or inputs.get("root") != str(root.resolve())
        or any(
            value is not None and not isinstance(value, str)
            for key, value in inputs.items()
            if key
            in {"bin_dir", "qualification_store", "interoperability_store"}
        )
    ):
        raise SuiteError("suite creation inputs or repository root differ")
    campaigns = state["campaigns"]
    selected = _selected_campaigns(
        tuple(str(item.get("name")) for item in campaigns)
    )
    expected = [
        (entry.name, entry.profile, entry.run_directory) for entry in selected
    ]
    actual = [
        (item.get("name"), item.get("profile"), item.get("run_directory"))
        for item in campaigns
        if isinstance(item, Mapping)
    ]
    if actual != expected or len(actual) != len(campaigns):
        raise SuiteError("suite campaign order or identity differs")
    for item in campaigns:
        profile = root / str(item["profile"])
        if not profile.is_file() or _sha256(profile) != item.get("profile_sha256"):
            raise SuiteError(f"suite profile identity changed: {profile}")
    if state.get("timing_plan") != _timing_plan(root, selected):
        raise SuiteError("suite timing plan differs from its frozen profiles")


def _creation_path(
    state: Mapping[str, Any], name: str, supplied: Path | None
) -> Path | None:
    frozen = state["creation_inputs"][name]
    if supplied is not None and str(supplied.resolve()) != frozen:
        raise SuiteError(f"suite {name} differs from the frozen creation input")
    return None if frozen is None else Path(str(frozen))


def _recover_created(
    run_dir: Path, *, diagnostic_unqualified_host: bool
) -> dict[str, Any] | None:
    if not run_dir.exists():
        return None
    try:
        with Journal(run_dir, writable=False) as journal:
            campaign = campaign_identity(journal)
            schedule = journal.connection.execute(
                "SELECT manifest_hash, canonical_json FROM manifest "
                "WHERE kind='schedule'"
            ).fetchone()
            if schedule is None:
                raise SuiteError(f"suite campaign lacks a frozen schedule: {run_dir}")
            schedule_document = loads_strict(str(schedule["canonical_json"]))
            if (
                _diagnostic_schedule_manifest(schedule_document) is not None
            ) != diagnostic_unqualified_host:
                raise SuiteError(
                    f"suite campaign diagnostic mode differs: {run_dir}"
                )
            planned = int(campaign["expected_cardinality"])
            maximum = int(
                journal.connection.execute("SELECT COUNT(*) FROM trial").fetchone()[0]
            )
        return {
            "campaign_id": str(campaign["campaign_id"]),
            "schedule_hash": str(schedule["manifest_hash"]),
            "planned_trials": planned,
            "maximum_trial_ids": maximum,
        }
    except SuiteError:
        raise
    except Exception as exc:
        raise SuiteError(f"suite campaign recovery failed for {run_dir}: {exc}") from exc


def _freeze(
    *,
    root: Path,
    suite_dir: Path,
    state: dict[str, Any],
    qualification_store: Path | None,
    interoperability_store: Path | None,
    bin_dir: Path | None,
) -> dict[str, Any]:
    _verify_profiles(root, state)
    bin_dir = _creation_path(state, "bin_dir", bin_dir)
    qualification_store = _creation_path(
        state, "qualification_store", qualification_store
    )
    interoperability_store = _creation_path(
        state, "interoperability_store", interoperability_store
    )
    for item in state["campaigns"]:
        run_dir = suite_dir / str(item["run_directory"])
        recovered = _recover_created(
            run_dir,
            diagnostic_unqualified_host=False,
        )
        if item["campaign_id"] is None:
            if recovered is None:
                created = create_campaign(
                    root=root,
                    profile=root / str(item["profile"]),
                    run_dir=run_dir,
                    seed=str(item["seed"]),
                    bin_dir=bin_dir,
                    qualification_store=qualification_store,
                    interoperability_store=interoperability_store,
                )
                recovered = {
                    "campaign_id": created.campaign_id,
                    "schedule_hash": created.schedule_hash,
                    "planned_trials": created.planned_trials,
                    "maximum_trial_ids": created.maximum_trial_ids,
                }
            item.update(recovered)
            _write_state(suite_dir, state)
        elif recovered is None or any(
            recovered[field] != item[field]
            for field in (
                "campaign_id",
                "schedule_hash",
                "planned_trials",
                "maximum_trial_ids",
            )
        ):
            raise SuiteError(f"suite campaign identity changed: {run_dir}")
    state["phase"] = "frozen"
    _write_state(suite_dir, state)
    return state


def _campaign_report(suite_dir: Path, item: Mapping[str, Any]) -> dict[str, Any]:
    run_dir = suite_dir / str(item["run_directory"])
    status = campaign_status(run_dir)
    with Journal(run_dir, writable=False) as journal:
        campaign = campaign_identity(journal)
    return {
        "name": item["name"],
        "run_dir": str(run_dir),
        "campaign_id": item["campaign_id"],
        "schedule_hash": item["schedule_hash"],
        "campaign_state": campaign["status"],
        **status,
    }


def suite_status(*, root: Path, suite_dir: Path) -> dict[str, Any]:
    state = _load_state(suite_dir)
    _verify_profiles(root, state)
    reports = []
    for item in state["campaigns"]:
        if item["campaign_id"] is None:
            reports.append(
                {
                    "name": item["name"],
                    "run_dir": str(suite_dir / str(item["run_directory"])),
                    "status": "not_frozen",
                }
            )
        else:
            reports.append(_campaign_report(suite_dir, item))
    terminal = all(
        report.get("campaign_state")
        in {"publication_qualified", "nonpublishable", "hardware_unqualified"}
        for report in reports
    )
    return {
        "schema_version": SUITE_SCHEMA_VERSION,
        "phase": state["phase"],
        "suite_dir": str(suite_dir),
        "terminal": terminal,
        "diagnostic_unqualified_host": False,
        "watermark": None,
        "timing_plan": state["timing_plan"],
        "campaigns": reports,
    }


def suite_plan(
    *, root: Path, campaign_names: tuple[str, ...] = DEFAULT_CAMPAIGNS
) -> dict[str, Any]:
    selected = _selected_campaigns(campaign_names)
    return {
        "schema_version": "quicperf.publication-suite-plan.v1",
        "campaigns": [entry.name for entry in selected],
        "timing_plan": _timing_plan(root, selected),
    }


def _execute_frozen(*, root: Path, suite_dir: Path, state: Mapping[str, Any]) -> None:
    campaigns = state.get("campaigns")
    if (
        state.get("phase") != "frozen"
        or not isinstance(campaigns, list)
        or not campaigns
        or any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("campaign_id"), str)
            for item in campaigns
        )
    ):
        raise SuiteError("suite execution requires every campaign identity to be frozen")
    for item in campaigns:
        run_dir = suite_dir / str(item["run_directory"])
        with Journal(run_dir, writable=False) as journal:
            sessions = [
                int(row["session_number"])
                for row in journal.connection.execute(
                    "SELECT session_number FROM session ORDER BY session_number"
                )
            ]
        for session in sessions:
            with Journal(run_dir, writable=False) as journal:
                if campaign_identity(journal)["status"] == "hardware_unqualified":
                    break
            status = campaign_status(run_dir)
            session_status = next(
                row["status"]
                for row in status["sessions"]
                if int(row["session_number"]) == session
            )
            if session_status not in {"complete", "nonpublishable"}:
                run_campaign_session(root=root, run_dir=run_dir, session=session)
        analyze_campaign(run_dir)
        finalize_campaign(run_dir)


def suite_run(
    *,
    root: Path,
    suite_dir: Path,
    seed: str | None,
    qualification_store: Path | None = None,
    interoperability_store: Path | None = None,
    bin_dir: Path | None = None,
    campaign_names: tuple[str, ...] = DEFAULT_CAMPAIGNS,
    diagnostic_unqualified_host: bool = False,
) -> dict[str, Any]:
    if diagnostic_unqualified_host:
        raise SuiteError(
            "full unqualified-host suites are disabled because they cannot produce "
            "publication evidence; v2.3 stops nonpublication without fallback"
        )
    with _suite_lock(suite_dir, create=True):
        state = _initial_state(
            root,
            _seed(seed),
            campaign_names=campaign_names,
            bin_dir=bin_dir,
            qualification_store=qualification_store,
            interoperability_store=interoperability_store,
        )
        _write_state(suite_dir, state)
        state = _freeze(
            root=root,
            suite_dir=suite_dir,
            state=state,
            qualification_store=qualification_store,
            interoperability_store=interoperability_store,
            bin_dir=bin_dir,
        )
        _execute_frozen(root=root, suite_dir=suite_dir, state=state)
        return suite_status(root=root, suite_dir=suite_dir)


def suite_resume(
    *,
    root: Path,
    suite_dir: Path,
    qualification_store: Path | None = None,
    interoperability_store: Path | None = None,
    bin_dir: Path | None = None,
) -> dict[str, Any]:
    with _suite_lock(suite_dir, create=False):
        state = _load_state(suite_dir)
        if state["phase"] == "freezing":
            state = _freeze(
                root=root,
                suite_dir=suite_dir,
                state=state,
                qualification_store=qualification_store,
                interoperability_store=interoperability_store,
                bin_dir=bin_dir,
            )
        else:
            _verify_profiles(root, state)
        _execute_frozen(root=root, suite_dir=suite_dir, state=state)
        return suite_status(root=root, suite_dir=suite_dir)
