from __future__ import annotations

import unittest

from quicperf_harness.memory import MemoryPoll, final_observation_median, memory_settling_time
from quicperf_harness.validity import (
    DurationSampleFacts,
    ProgressBucket,
    assess_row_resolution,
    classify_failure,
    retry_allowed,
    validate_duration_sample,
)


def valid_facts(**overrides: object) -> DurationSampleFacts:
    values: dict[str, object] = {
        "scenario": "download",
        "termination_reason": "deadline_reached",
        "numerator": 100_000,
        "denominator_raw_ns": 2_000_000_000,
        "integer_operation_rate": False,
        "progress_buckets": tuple(ProgressBucket(1) for _ in range(10)),
        "client_cpu_fraction_of_quota_p95": 0.79,
    }
    values.update(overrides)
    return DurationSampleFacts(**values)


class DurationValidityTests(unittest.TestCase):
    def test_clean_duration_sample_is_publication_valid(self) -> None:
        result = validate_duration_sample(valid_facts())
        self.assertTrue(result.valid)
        self.assertTrue(result.publication_valid)
        self.assertEqual(result.reasons, ())
        self.assertEqual(result.censoring, ())

    def test_cap_stall_headroom_and_settings_are_causal_failures(self) -> None:
        result = validate_duration_sample(
            valid_facts(
                work_cap_hits=1,
                generator_starvation_events=1,
                progress_buckets=(ProgressBucket(0),),
                client_cpu_fraction_of_quota_p95=0.80,
                negotiated_settings_match=False,
            )
        )
        self.assertFalse(result.valid)
        self.assertIn("work_cap_hit", result.reasons)
        self.assertIn("generator_starvation", result.reasons)
        self.assertIn("progress_stall_without_cause", result.reasons)
        self.assertIn("reference_client_headroom_failed", result.reasons)
        self.assertIn("negotiated_setting_mismatch", result.reasons)
        self.assertIn("finite_work_cap", result.censoring)

    def test_operation_resolution_is_retained_but_nonclaimable(self) -> None:
        result = validate_duration_sample(
            valid_facts(numerator=399, integer_operation_rate=True)
        )
        self.assertTrue(result.valid)
        self.assertFalse(result.publication_valid)
        self.assertEqual(result.censoring, ("resolution_limited",))

    def test_flow_control_requires_block_and_recovery_evidence(self) -> None:
        missing = validate_duration_sample(valid_facts(scenario="flow_control"))
        self.assertIn("missing_flow_control_block_evidence", missing.reasons)
        self.assertIn("missing_flow_control_recovery_evidence", missing.reasons)
        valid = validate_duration_sample(
            valid_facts(
                scenario="flow_control",
                data_blocked_frames=1,
                flow_control_block_evidence=True,
                flow_control_recovery_evidence=True,
            )
        )
        self.assertTrue(valid.publication_valid)
        common_backpressure = validate_duration_sample(
            valid_facts(
                scenario="flow_control",
                flow_control_write_blocked_events=1,
                flow_control_block_evidence=True,
                flow_control_recovery_evidence=True,
            )
        )
        self.assertTrue(common_backpressure.publication_valid)
        ordinary = validate_duration_sample(valid_facts(data_blocked_frames=1))
        self.assertIn("unexpected_flow_control_blocking", ordinary.reasons)

    def test_metric_magnitude_does_not_change_causal_validity(self) -> None:
        low = validate_duration_sample(valid_facts(numerator=1))
        high = validate_duration_sample(valid_facts(numerator=10**18))
        self.assertEqual(low, high)

    def test_retry_policy_is_closed_and_single_use(self) -> None:
        self.assertEqual(classify_failure("thermal_throttle"), "terminal")
        self.assertFalse(retry_allowed("thermal_throttle", 0))
        self.assertEqual(classify_failure("host_power_policy_change"), "terminal")
        self.assertFalse(retry_allowed("host_power_policy_change", 0))
        self.assertEqual(classify_failure("timeout"), "terminal")
        self.assertFalse(retry_allowed("timeout", 0))


class ResolutionAndMemorySettlingTests(unittest.TestCase):
    def test_row_resolution_reports_quantum_and_zero_width(self) -> None:
        result = assess_row_resolution(
            (400, 404, 408, 412), interval_low=1.0, interval_high=1.0
        )
        self.assertEqual(result.distinct_numerators, 4)
        self.assertEqual(result.gcd_quantum, 4)
        self.assertIn("resolution_limited", result.labels)
        self.assertIn("unexplained_zero_variance", result.labels)
        self.assertFalse(result.publication_valid)
        externally_limited = assess_row_resolution(
            (1000, 1000),
            interval_low=1.0,
            interval_high=1.0,
            verified_external_rate_limit=True,
        )
        self.assertNotIn("unexplained_zero_variance", externally_limited.labels)

    def test_memory_settle_and_exact_final_twenty_polls(self) -> None:
        polls = tuple(
            MemoryPoll(index / 10.0, 1_000_000 if index >= 20 else 900_000 + index * 5_000)
            for index in range(71)
        )
        settled = memory_settling_time(polls)
        self.assertEqual(settled, 5.0)
        final = tuple(
            MemoryPoll(index / 10.0, 1_000_000 + index)
            for index in range(51, 71)
        )
        self.assertEqual(final_observation_median(final, 5.0), 1_000_060.5)


if __name__ == "__main__":
    unittest.main()
