from __future__ import annotations

import math
import unittest
from unittest import mock

import quicperf_harness.statistics as statistics_module
from quicperf_harness.memory import MemoryPoint, fit_memory_curve
from quicperf_harness.statistics import (
    MEMORY_MARGIN,
    MEMORY_SUPERBLOCK_SD_ENVELOPE,
    RATE_MARGIN,
    RATE_SUPERBLOCK_SD_ENVELOPE,
    classify_practical_interval,
    geometric_mean,
    hc2_wild_max_t_sensitivity,
    nearest_rank,
    normal_planning_probabilities,
    paired_log_differences,
    paired_max_t_intervals,
    paired_server_contrasts,
    pair_session_superblocks,
    superblock_sd_envelope,
    tail_block_p99,
    wilson_upper_bound,
)


class PairedInferenceTests(unittest.TestCase):
    def test_log_orientation_and_contrast_construction(self) -> None:
        faster = (2.0, 4.0)
        slower = (1.0, 2.0)
        expected = (math.log(2.0), math.log(2.0))
        self.assertEqual(
            paired_log_differences(faster, slower, higher_is_better=True), expected
        )
        self.assertEqual(
            paired_log_differences(slower, faster, higher_is_better=False), expected
        )
        values = {"a": (2.0,) * 12, "b": (1.0,) * 12, "c": (4.0,) * 12}
        self.assertEqual(len(paired_server_contrasts(values, higher_is_better=True)), 3)
        self.assertEqual(
            set(
                paired_server_contrasts(
                    values, higher_is_better=True, baseline="b"
                )
            ),
            {"a/b", "c/b"},
        )

    def test_exact_common_sign_family_and_classifications(self) -> None:
        result = paired_max_t_intervals(
            {
                "better": (math.log(1.10),) * 12,
                "same": (0.0,) * 12,
                "worse": (math.log(0.90),) * 12,
            }
        )
        self.assertEqual(result.permutations, 4096)
        self.assertEqual(result.critical_value, 0.0)
        classifications = {item.contrast: item.classification for item in result.intervals}
        self.assertEqual(
            classifications,
            {"better": "superior", "same": "equivalent", "worse": "inferior"},
        )
        self.assertEqual(
            classify_practical_interval(-RATE_MARGIN * 1.1, RATE_MARGIN * 0.5),
            "inconclusive",
        )

    def test_noisy_family_is_finite_and_reproducible(self) -> None:
        contrasts = {
            "a": tuple(0.01 + (index - 5.5) * 0.001 for index in range(12)),
            "b": tuple(-0.005 + ((index * 5) % 12 - 5.5) * 0.001 for index in range(12)),
        }
        first = paired_max_t_intervals(contrasts)
        second = paired_max_t_intervals(contrasts)
        self.assertTrue(math.isfinite(first.critical_value))
        self.assertGreater(first.critical_value, 0.0)
        self.assertEqual(first, second)

        variance_miss = paired_max_t_intervals(
            {"wide": tuple(0.20 + (index - 5.5) * 0.01 for index in range(12))}
        ).intervals[0]
        self.assertTrue(variance_miss.variance_miss)
        self.assertEqual(variance_miss.classification, "inconclusive")

    def test_hc2_common_wild_sign_sensitivity(self) -> None:
        clients = tuple(
            -0.5 if (row + session) % 2 else 0.5
            for session in range(2)
            for row in range(12)
        )
        sessions = (-0.5,) * 12 + (0.5,) * 12
        clusters = tuple(range(12)) * 2
        response = tuple(
            0.01 + 0.08 * client + 0.003 * ((index % 3) - 1)
            for index, client in enumerate(clients)
        )
        with mock.patch.object(
            statistics_module,
            "_inverse",
            wraps=statistics_module._inverse,
        ) as inverse:
            result = hc2_wild_max_t_sensitivity(
                {"server/baseline": response}, clients, sessions, clusters
            )
        self.assertEqual(inverse.call_count, 1)
        self.assertEqual(result.permutations, 4096)
        statuses = {item.effect: item.status for item in result.intervals}
        self.assertEqual(statuses["client"], "reference_client_sensitive")
        self.assertEqual(statuses["session"], "invariance_supported")

    def test_raw_session_rows_pair_into_exact_superblocks(self) -> None:
        raw = tuple(float(row + 10 * session) for session in (1, 2) for row in range(12))
        sessions = (1,) * 12 + (2,) * 12
        rows = tuple(range(12)) * 2
        self.assertEqual(
            pair_session_superblocks(raw, sessions, rows),
            tuple(float(row + 15) for row in range(12)),
        )
        with self.assertRaisesRegex(ValueError, "duplicate session member"):
            pair_session_superblocks(raw, sessions, rows[:-1] + (10,))

    def test_superblock_variance_envelope_uses_planning_correlation(self) -> None:
        self.assertAlmostEqual(
            RATE_SUPERBLOCK_SD_ENVELOPE,
            superblock_sd_envelope(0.025, 0.25),
        )
        self.assertAlmostEqual(
            MEMORY_SUPERBLOCK_SD_ENVELOPE,
            superblock_sd_envelope(0.040, 0.25),
        )


class MetricAndPlanningTests(unittest.TestCase):
    def test_tail_rank_geometric_mean_and_one_sided_wilson(self) -> None:
        self.assertEqual(nearest_rank(tuple(range(1024)), 0.99), 1013)
        operations = tuple((index, index, float(index)) for index in reversed(range(1024)))
        self.assertEqual(tail_block_p99(operations), 1013.0)
        self.assertAlmostEqual(geometric_mean((1.0, 4.0)), 2.0)
        self.assertAlmostEqual(wilson_upper_bound(0, 1024), 0.00263517, places=8)

    def test_frozen_variance_envelopes_clear_planning_thresholds(self) -> None:
        rate_null = normal_planning_probabilities(
            effect=0.0,
            standard_deviation=0.025,
            critical_value=2.5,
            margin=RATE_MARGIN,
        )
        rate_effect = normal_planning_probabilities(
            effect=math.log(1.06),
            standard_deviation=0.025,
            critical_value=2.5,
            margin=RATE_MARGIN,
        )
        memory_null = normal_planning_probabilities(
            effect=0.0,
            standard_deviation=0.040,
            critical_value=2.5,
            margin=MEMORY_MARGIN,
        )
        memory_effect = normal_planning_probabilities(
            effect=math.log(1.10),
            standard_deviation=0.040,
            critical_value=2.5,
            margin=MEMORY_MARGIN,
        )
        self.assertGreaterEqual(rate_null.equivalence_probability, 0.80)
        self.assertGreaterEqual(rate_effect.directional_detection_probability, 0.80)
        self.assertGreaterEqual(memory_null.equivalence_probability, 0.80)
        self.assertGreaterEqual(memory_effect.directional_detection_probability, 0.80)

    def test_memory_fit_claim_and_misfit_gates(self) -> None:
        good = fit_memory_curve(
            tuple(MemoryPoint(n, 1_000_000.0 + 1000.0 * n) for n in (0, 64, 256, 1024))
        )
        self.assertEqual(good.status, "claimable")
        self.assertAlmostEqual(good.intercept, 1_000_000.0)
        self.assertAlmostEqual(good.bytes_per_connection, 1000.0)
        bad = fit_memory_curve(
            (
                MemoryPoint(0, 1_000_000.0),
                MemoryPoint(64, 1_064_000.0),
                MemoryPoint(256, 2_000_000.0),
                MemoryPoint(1024, 2_024_000.0),
            )
        )
        self.assertEqual(bad.status, "inconclusive")
        self.assertIn("model_misfit", bad.reason)


if __name__ == "__main__":
    unittest.main()
