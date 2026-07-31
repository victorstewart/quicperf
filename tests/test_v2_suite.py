from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from quicperf_harness.runner import CreatedCampaign
from quicperf_harness.suite import (
    CAMPAIGNS,
    SuiteError,
    _execute_frozen,
    _creation_path,
    _freeze,
    _initial_state,
    _load_state,
    suite_run,
    suite_plan,
    _verify_profiles,
    _write_state,
)

ROOT = Path(__file__).resolve().parents[1]


class PublicationSuiteTests(unittest.TestCase):
    @staticmethod
    def root(path: Path) -> Path:
        for entry in CAMPAIGNS:
            profile = path / entry.profile
            profile.parent.mkdir(parents=True, exist_ok=True)
            profile.write_bytes((ROOT / entry.profile).read_bytes())
        amd_policy = Path(
            "profiles/v2/host-stability/amd-delivered-performance-v1.json"
        )
        target = path / amd_policy
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / amd_policy).read_bytes())
        return path

    def test_initial_state_freezes_exact_order_profiles_and_distinct_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(Path(temporary))
            state = _initial_state(
                root,
                bytes.fromhex("12" * 32),
                campaign_names=tuple(entry.name for entry in CAMPAIGNS),
            )
            self.assertEqual(state["phase"], "freezing")
            self.assertEqual(
                [item["name"] for item in state["campaigns"]],
                [entry.name for entry in CAMPAIGNS],
            )
            self.assertEqual(
                len({item["seed"] for item in state["campaigns"]}),
                len(CAMPAIGNS),
            )
            _verify_profiles(root, state)
            self.assertIsNone(_creation_path(state, "bin_dir", None))
            with self.assertRaisesRegex(SuiteError, "differs from the frozen"):
                _creation_path(state, "bin_dir", root / "different-build")
            (root / CAMPAIGNS[0].profile).write_bytes(b"{}")
            with self.assertRaisesRegex(SuiteError, "profile identity changed"):
                _verify_profiles(root, state)

    def test_freeze_recovers_one_created_campaign_then_creates_all_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self.root(base / "root")
            suite_dir = base / "suite"
            suite_dir.mkdir()
            state = _initial_state(
                root,
                bytes.fromhex("34" * 32),
                campaign_names=tuple(entry.name for entry in CAMPAIGNS),
            )
            first = state["campaigns"][0]
            first.update(
                {
                    "campaign_id": "1" * 64,
                    "schedule_hash": "2" * 64,
                    "planned_trials": 10,
                    "maximum_trial_ids": 20,
                }
            )
            _write_state(suite_dir, state)

            def recover(path: Path, *, diagnostic_unqualified_host: bool):
                self.assertFalse(diagnostic_unqualified_host)
                if path.name == first["run_directory"]:
                    return {
                        field: first[field]
                        for field in (
                            "campaign_id",
                            "schedule_hash",
                            "planned_trials",
                            "maximum_trial_ids",
                        )
                    }
                return None

            created_names: list[str] = []

            def create(**kwargs):
                name = kwargs["run_dir"].name
                created_names.append(name)
                index = created_names.index(name) + 3
                return CreatedCampaign(
                    f"{index:x}" * 64,
                    f"{index + 5:x}" * 64,
                    100 + index,
                    200 + index,
                    kwargs["run_dir"],
                )

            with (
                mock.patch("quicperf_harness.suite._recover_created", side_effect=recover),
                mock.patch("quicperf_harness.suite.create_campaign", side_effect=create),
            ):
                frozen = _freeze(
                    root=root,
                    suite_dir=suite_dir,
                    state=state,
                    qualification_store=None,
                    interoperability_store=None,
                    bin_dir=None,
                )
            self.assertEqual(frozen["phase"], "frozen")
            self.assertEqual(
                created_names,
                [entry.run_directory for entry in CAMPAIGNS[1:]],
            )
            self.assertTrue(all(item["campaign_id"] for item in frozen["campaigns"]))
            self.assertEqual(_load_state(suite_dir), frozen)

    def test_execution_refuses_any_partially_frozen_suite(self) -> None:
        with self.assertRaisesRegex(SuiteError, "every campaign identity"):
            _execute_frozen(
                root=Path("/unused"),
                suite_dir=Path("/unused"),
                state={"phase": "freezing", "campaigns": []},
            )

    def test_default_suite_selects_only_fixed_treatment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(Path(temporary))
            state = _initial_state(root, bytes.fromhex("78" * 32))
            self.assertEqual(
                [item["name"] for item in state["campaigns"]],
                ["fixed_treatment"],
            )
            self.assertEqual(
                state["timing_plan"]["measurement_ns"],
                9_504_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["balance_control_measurement_ns"],
                0,
            )
            self.assertEqual(
                state["timing_plan"]["scheduled_measurement_ns"],
                9_504_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["warmup_ns"],
                936_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["execution_lanes"],
                {"fixed_treatment": 1},
            )
            self.assertEqual(
                state["timing_plan"]["arm_floor_ns"],
                10_440_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["parallel_wait_ns"],
                0,
            )
            self.assertEqual(
                state["timing_plan"]["arm_critical_path_ns"],
                10_440_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["arm_lead_floor_ns"],
                3_240_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["session_probe_ns"],
                241_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["scheduled_floor_ns"],
                13_921_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"][
                    "fixed_treatment_operational_session_timeout_ns"
                ],
                10_800_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"][
                    "fixed_treatment_operational_timeout_publication_gate"
                ],
                True,
            )
            self.assertEqual(
                state["timing_plan"][
                    "fixed_treatment_total_operational_timeout_ns"
                ],
                21_600_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"][
                    "fixed_treatment_operational_margin_above_scheduled_floor_ns"
                ],
                7_679_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["required_qualifications"],
                ["host-stability", "client-headroom"],
            )
            self.assertNotIn(
                "lane_interference",
                state["timing_plan"]["primary_admission"]["gates"],
            )
            self.assertEqual(
                state["timing_plan"]["primary_admission"]["gates"][
                    "native_interoperability"
                ]["normal_ns"],
                615_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["primary_admission"]["totals_ns"],
                {
                    "normal": 1_212_700_000_000,
                    "bounded_current_flow": 3_787_550_000_000,
                    "conservative_reservation": 3_847_800_000_000,
                },
            )
            self.assertEqual(
                state["timing_plan"]["campaigns"][0]["worker_process_policy"],
                "persistent_reset",
            )
            self.assertEqual(
                state["timing_plan"]["campaigns"][0]["parallel_pairing"],
                "serial_williams_order",
            )
            self.assertEqual(
                state["timing_plan"]["campaigns"][0]["balance_control_trials"],
                0,
            )
            self.assertEqual(
                state["timing_plan"][
                    "fixed_treatment_normal_end_to_end_floor_ns"
                ],
                15_133_700_000_000,
            )
            self.assertEqual(
                state["timing_plan"][
                    "fixed_treatment_conservative_end_to_end_estimate_ns"
                ],
                27_247_800_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["deterministic_verification_budget_ns"],
                1_200_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"][
                    "analysis_finalization_export_budget_ns"
                ],
                600_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["clean_start_conservative_budget_ns"],
                27_247_800_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["suite_deadline_ns"],
                30_000_000_000_000,
            )
            self.assertEqual(
                state["timing_plan"]["suite_deadline_ns"]
                - state["timing_plan"][
                    "clean_start_conservative_budget_ns"
                ],
                2_752_200_000_000,
            )

    def test_full_unqualified_host_suite_is_refused_before_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                SuiteError, "cannot produce publication evidence"
            ):
                suite_run(
                    root=Path(temporary),
                    suite_dir=Path(temporary) / "suite",
                    seed="78" * 32,
                    diagnostic_unqualified_host=True,
                )
            self.assertFalse((Path(temporary) / "suite").exists())

    def test_plan_is_read_only_and_rejects_out_of_scope_campaigns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(Path(temporary))
            plan = suite_plan(root=root)
            self.assertEqual(plan["campaigns"], ["fixed_treatment"])
            with self.assertRaisesRegex(SuiteError, "unknown suite campaign"):
                suite_plan(
                    root=root,
                    campaign_names=("fixed_treatment", "memory_curve"),
                )
            self.assertEqual(
                sorted(
                    str(path.relative_to(root))
                    for path in root.rglob("*")
                    if path.is_file()
                ),
                sorted(
                    [entry.profile for entry in CAMPAIGNS]
                    + [
                        "profiles/v2/host-stability/"
                        "amd-delivered-performance-v1.json"
                    ]
                ),
            )

    def test_state_loader_rejects_unknown_and_partially_frozen_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = self.root(base / "root")
            suite_dir = base / "suite"
            suite_dir.mkdir()
            state = _initial_state(root, bytes.fromhex("56" * 32))
            state["unexpected"] = True
            _write_state(suite_dir, state)
            with self.assertRaisesRegex(SuiteError, "state fields"):
                _load_state(suite_dir)
            del state["unexpected"]
            state["phase"] = "frozen"
            _write_state(suite_dir, state)
            with self.assertRaisesRegex(SuiteError, "unfrozen campaign"):
                _load_state(suite_dir)


if __name__ == "__main__":
    unittest.main()
