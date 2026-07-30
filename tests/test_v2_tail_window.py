from __future__ import annotations

import collections
import math
import unittest

from quicperf_harness.planner import CANONICAL_SERVERS, REFERENCE_CLIENTS, SERVER_BACKENDS
from quicperf_harness.tail_window import (
    DURATION_LADDER_SECONDS,
    HELD_OUT_SIGN_PATTERNS,
    PrefixEvidence,
    TAIL_SCENARIOS,
    TailHeldOutBlock,
    TailPrefixObservation,
    TailScreenCell,
    activate_held_out,
    analyze_tail_window_qualification,
    exact_twenty_block_simultaneous_intervals,
    nominate_screening_duration,
    plan_tail_window_qualification,
    qualify_stratum_duration,
    scenario_duration,
    selected_servers,
)


class TailWindowPlanTests(unittest.TestCase):
    def test_frozen_cardinality_identity_and_nested_prefixes(self) -> None:
        plan = plan_tail_window_qualification(
            campaign_seed=b"tail-window-seed",
            schedule_basis_hash=bytes(range(32)),
        )
        screening_primary = [trial for trial in plan.screening if trial.slot == "primary"]
        held_primary = [trial for trial in plan.held_out if trial.slot == "primary"]
        self.assertEqual(len(screening_primary), 384)
        self.assertEqual(len(plan.screening), 768)
        self.assertEqual(len(held_primary), 7_680)
        self.assertEqual(len(plan.held_out), 15_360)
        self.assertEqual(HELD_OUT_SIGN_PATTERNS, 1_048_576)
        self.assertEqual(
            {trial.duration_prefixes_seconds for trial in (*plan.screening, *plan.held_out)},
            {DURATION_LADDER_SECONDS},
        )
        self.assertEqual(
            len({trial.trial_id for trial in (*plan.screening, *plan.held_out)}),
            len(plan.screening) + len(plan.held_out),
        )
        self.assertEqual(
            sorted(trial.execution_order for trial in screening_primary),
            list(range(384)),
        )
        for scenario in TAIL_SCENARIOS:
            for backend in SERVER_BACKENDS:
                for client in REFERENCE_CLIENTS:
                    rows = [
                        trial
                        for trial in held_primary
                        if (trial.scenario, trial.server_backend, trial.reference_client)
                        == (scenario, backend, client)
                    ]
                    self.assertEqual(len(rows), 12 * 20)
                    by_block = collections.defaultdict(list)
                    for trial in rows:
                        by_block[trial.block].append(trial)
                    self.assertEqual(set(by_block), set(range(1, 21)))
                    for members in by_block.values():
                        self.assertEqual({item.server for item in members}, set(CANONICAL_SERVERS))
                        self.assertEqual(
                            sorted(item.server_position for item in members),
                            list(range(12)),
                        )
                        self.assertEqual(len({item.williams_row for item in members}), 1)

    def test_screening_nomination_selection_and_activation_are_mechanical(self) -> None:
        failed = PrefixEvidence(100, 0.02, True)
        passed = PrefixEvidence(1_400, 0.001, True)
        cells = [{2: failed, 5: passed, 10: passed, 20: passed} for _ in range(48)]
        self.assertEqual(nominate_screening_duration(cells), 5)

        evidence = {
            server: PrefixEvidence(
                1_500 - index,
                0.001,
                True,
                p99_log_ratio_to_twenty_seconds=(0.02 if server == "picoperf" else 0.0),
            )
            for index, server in enumerate(CANONICAL_SERVERS)
        }
        chosen = selected_servers(evidence)
        self.assertEqual(chosen, ("ngtcp2perf", "picoperf", "mvfstperf"))

        plan = plan_tail_window_qualification(
            campaign_seed=b"tail-window-seed",
            schedule_basis_hash=bytes(range(32)),
        )
        selected = {
            (scenario, backend, client): chosen
            for scenario in TAIL_SCENARIOS
            for backend in SERVER_BACKENDS
            for client in REFERENCE_CLIENTS
        }
        activated = activate_held_out(plan, selected)
        statuses = collections.Counter(trial.status for trial in activated.held_out)
        self.assertEqual(statuses["active"], 8 * 2 * 2 * 3 * 20)
        self.assertEqual(statuses["dormant"], statuses["active"])

    def test_held_out_duration_requires_interval_and_validity_for_every_cell(self) -> None:
        margin = math.log(1.02)
        cells = [
            {
                5: PrefixEvidence(1_100, 0.001, True, interval_low=-margin / 2, interval_high=margin / 2),
                10: PrefixEvidence(1_100, 0.001, True, interval_low=-margin / 2, interval_high=margin / 2),
                20: PrefixEvidence(1_100, 0.001, True),
            }
            for _ in range(3)
        ]
        self.assertEqual(qualify_stratum_duration(5, cells), 5)
        cells[1][5] = PrefixEvidence(1_100, 0.001, True, interval_low=-margin * 2, interval_high=0.0)
        self.assertEqual(qualify_stratum_duration(5, cells), 10)
        cells[1][10] = PrefixEvidence(1_000, 0.001, True)
        self.assertEqual(qualify_stratum_duration(5, cells), 20)
        cells[1][20] = PrefixEvidence(1_100, 0.001, True, capped_or_stalled=True)
        self.assertIsNone(qualify_stratum_duration(5, cells))

    def test_exact_twenty_block_common_sign_intervals_and_scenario_maximum(self) -> None:
        first = tuple((index - 9.5) / 10_000 for index in range(20))
        second = tuple(-value * 0.7 + 0.0001 for value in first)
        result = exact_twenty_block_simultaneous_intervals(
            {"server-a/2s": first, "server-b/5s": second}
        )
        self.assertEqual(result.sign_patterns, 1_048_576)
        self.assertEqual(result.alpha, 0.10)
        self.assertTrue(math.isfinite(result.critical_value))
        self.assertGreater(result.critical_value, 0.0)
        self.assertEqual(
            tuple(interval.contrast for interval in result.intervals),
            ("server-a/2s", "server-b/5s"),
        )
        self.assertTrue(
            all(interval.low_log_ratio <= interval.mean_log_ratio <= interval.high_log_ratio
                for interval in result.intervals)
        )
        strata = {
            (backend, client): 5
            for backend in SERVER_BACKENDS
            for client in REFERENCE_CLIENTS
        }
        strata[("iouring", "picoperf")] = 10
        self.assertEqual(scenario_duration(strata), 10)
        strata[("iouring", "picoperf")] = None
        self.assertIsNone(scenario_duration(strata))

    def test_complete_screen_selection_and_held_out_analysis_passes(self) -> None:
        def prefixes(eligible: int) -> tuple[TailPrefixObservation, ...]:
            return tuple(
                TailPrefixObservation(duration, eligible, 0, 1_000, "valid")
                for duration in DURATION_LADDER_SECONDS
            )

        screens = tuple(
            TailScreenCell(
                scenario,
                server,
                backend,
                client,
                prefixes(1_500 if server == "ngtcp2perf" else 1_600),
            )
            for scenario in TAIL_SCENARIOS
            for server in CANONICAL_SERVERS
            for backend in SERVER_BACKENDS
            for client in REFERENCE_CLIENTS
        )
        held = tuple(
            TailHeldOutBlock(
                scenario,
                "ngtcp2perf",
                backend,
                client,
                block,
                prefixes(1_100),
            )
            for scenario in TAIL_SCENARIOS
            for backend in SERVER_BACKENDS
            for client in REFERENCE_CLIENTS
            for block in range(1, 21)
        )
        result = analyze_tail_window_qualification(screens, held)
        self.assertTrue(result.passed, result.reasons)
        self.assertEqual(set(result.screening_nominations.values()), {2})
        self.assertEqual(set(result.selected_servers_by_stratum.values()), {("ngtcp2perf",)})
        self.assertEqual(set(result.stratum_durations.values()), {2})
        self.assertEqual(set(result.scenario_durations.values()), {2})
        self.assertTrue(
            all(item.sign_patterns == 1_048_576 for item in result.interval_results.values())
        )

        with self.assertRaisesRegex(ValueError, "exact 384-cell"):
            analyze_tail_window_qualification(screens[:-1], held)


if __name__ == "__main__":
    unittest.main()
