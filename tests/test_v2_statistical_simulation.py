from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path
import random
import unittest

import quicperf_harness.statistical_simulation as simulation
from quicperf_harness.statistics import paired_max_t_intervals


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = (
    ROOT
    / "profiles"
    / "v2"
    / "statistical-simulation"
    / "calibration-v2.json"
)


class ExactSimulationKernelTests(unittest.TestCase):
    def test_all_pairs_generator_returns_complete_family(self) -> None:
        vectors = simulation._all_pairs_vectors(random.Random(731))
        self.assertEqual(len(vectors), simulation.ALL_PAIRS_CONTRASTS)
        self.assertTrue(all(len(vector) == simulation.BLOCKS for vector in vectors))

    def test_accelerated_kernel_matches_the_publication_implementation(self) -> None:
        rng = random.Random(884422)
        for family_size in (1, 3, 11, 66):
            vectors = tuple(
                tuple(rng.gauss(0.0, 0.025) for _ in range(12))
                for _ in range(family_size)
            )
            accelerated = simulation._exact_max_t_critical(vectors)
            production = paired_max_t_intervals(
                {
                    f"contrast-{index}": vector
                    for index, vector in enumerate(vectors)
                },
                variance_envelope=None,
            ).critical_value
            self.assertAlmostEqual(accelerated, production, places=12)

    def test_publication_run_rejects_less_than_twenty_five_thousand_campaigns(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 25000 campaigns"):
            simulation.run_calibration(campaigns_per_condition=24_999)

    def test_condition_inventory_covers_every_frozen_stress(self) -> None:
        self.assertEqual(
            simulation.CONDITION_NAMES,
            (
                "iid_lognormal",
                "iid_familywise_null",
                "iid_all_pairs_familywise_null",
                "heteroskedastic_implementations",
                "block_and_session_drift",
                "ar1_time_effects",
                "order_effects",
                "predecessor_effects",
                "skewed_log_effects",
                "heavy_tailed_log_effects",
                "lower_is_better_metrics",
                "invalid_failed_censored_rows",
                "caps_and_quantization",
                "reference_client_and_session_interactions",
                "cross_session_rho_0_coverage",
                "cross_session_rho_0_25_coverage",
                "cross_session_rho_0_50_stress",
            ),
        )

    def test_exact_binomial_lower_bound_matches_closed_form_all_success(self) -> None:
        self.assertAlmostEqual(
            simulation.exact_binomial_lower_bound(10, 10),
            0.05 ** (1.0 / 10.0),
            places=14,
        )
        self.assertEqual(simulation.exact_binomial_lower_bound(0, 10), 0.0)

    def test_seeded_condition_replays_bit_for_bit(self) -> None:
        selected = (
            simulation.CONDITIONS[0],
            simulation.CONDITIONS[1],
            simulation.CONDITIONS[-1],
        )
        first = [
            simulation.simulate_condition(spec, campaigns=32, seed="unit-seed")
            for spec in selected
        ]
        second = [
            simulation.simulate_condition(spec, campaigns=32, seed="unit-seed")
            for spec in selected
        ]
        self.assertEqual(
            simulation.artifact_bytes({"conditions": first}),
            simulation.artifact_bytes({"conditions": second}),
        )


class ValidityAndReplaySimulationTests(unittest.TestCase):
    @staticmethod
    def valid_rows() -> tuple[simulation.TrialObservation, ...]:
        return tuple(
            simulation.TrialObservation(f"trial-{index:02d}", index / 1000.0)
            for index in range(12)
        )

    def test_identical_resume_rows_do_not_change_the_estimate(self) -> None:
        rows = self.valid_rows()
        self.assertEqual(
            simulation.deduplicated_complete_mean(rows),
            simulation.deduplicated_complete_mean(rows + rows),
        )
        conflict = rows + (
            simulation.TrialObservation("trial-00", math.log(1.2)),
        )
        with self.assertRaisesRegex(ValueError, "conflicting replay"):
            simulation.deduplicated_complete_mean(conflict)

    def test_invalid_failed_censored_and_cap_rows_never_produce_an_estimate(self) -> None:
        for status in ("invalid", "failed", "censored"):
            rows = list(self.valid_rows())
            rows[4] = simulation.TrialObservation("trial-04", 0.004, status=status)
            self.assertIsNone(simulation.deduplicated_complete_mean(rows))
        rows = list(self.valid_rows())
        rows[4] = simulation.TrialObservation("trial-04", 0.004, capped=True)
        self.assertIsNone(simulation.deduplicated_complete_mean(rows))


class FrozenCalibrationArtifactTests(unittest.TestCase):
    def test_every_profile_freezes_the_exact_selected_planning_result(self) -> None:
        artifact = simulation.load_artifact(ARTIFACT)
        digest = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
        for profile_path in sorted((ROOT / "profiles" / "v2").glob("*.json")):
            profile = json.loads(profile_path.read_bytes())
            analysis = profile["analysis"]
            planning_name = (
                "memory_planning_envelope"
                if analysis["planning_log_ratio_sd"] == "0.04"
                else "rate_planning_envelope"
            )
            self.assertEqual(
                analysis["statistical_calibration"],
                simulation.frozen_analysis_calibration(
                    artifact, digest, planning_name
                ),
                profile_path.name,
            )

    def test_frozen_artifact_distinguishes_calibration_from_design_failure(self) -> None:
        artifact = simulation.load_artifact(ARTIFACT)
        self.assertEqual(artifact["campaigns_per_condition"], 25_000)
        self.assertEqual(
            tuple(condition["name"] for condition in artifact["conditions"]),
            simulation.CONDITION_NAMES,
        )
        self.assertTrue(artifact["implementation_calibration_passed"])
        self.assertTrue(artifact["profile_design_power_gate_passed"])
        self.assertTrue(artifact["publication_analysis_permitted"])
        self.assertTrue(artifact["passed"])
        self.assertTrue(
            artifact["reproducibility"][
                "same_seed_and_input_reproduce_bit_for_bit"
            ]
        )

        iid = artifact["conditions"][0]["coverage"]["count"] / 25_000
        family_error = (
            artifact["conditions"][1]["familywise_type_i_error"]["count"]
            / 25_000
        )
        self.assertGreaterEqual(iid, 0.935)
        self.assertLessEqual(iid, 0.965)
        self.assertLessEqual(family_error, 0.055)
        for gate in artifact["planning"]:
            self.assertEqual(gate["family_size"], 11)
            self.assertTrue(gate["passed"])
            for result in (
                gate["equivalence"],
                gate["declared_effect_power"],
                gate["twice_margin_power"],
            ):
                self.assertGreaterEqual(result["count"] / 25_000, 0.80)
                self.assertGreaterEqual(
                    float(result["one_sided_95_exact_binomial_lower"]), 0.80
                )
        for legacy in artifact["legacy_12_row_failure_reference"]:
            self.assertTrue(legacy["failure_reproduced"])
            self.assertLess(legacy["equivalence"]["count"] / 25_000, 0.80)
            self.assertLess(
                legacy["declared_effect_power"]["count"] / 25_000, 0.80
            )
        simulation.require_publication_ready(artifact)

    def test_artifact_validator_rejects_policy_weakening_and_count_tampering(self) -> None:
        artifact = simulation.load_artifact(ARTIFACT)
        weakened = copy.deepcopy(artifact)
        weakened["thresholds"]["maximum_familywise_type_i_error"] = "0.06"
        with self.assertRaisesRegex(ValueError, "frozen pass thresholds"):
            simulation.validate_artifact(weakened)

        tampered = copy.deepcopy(artifact)
        tampered["conditions"][0]["coverage"]["count"] = 1
        tampered["conditions"][0]["passed"] = True
        with self.assertRaisesRegex(ValueError, "inconsistent coverage counts"):
            simulation.validate_artifact(tampered)


if __name__ == "__main__":
    unittest.main()
