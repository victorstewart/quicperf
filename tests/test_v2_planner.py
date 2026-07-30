from __future__ import annotations

import collections
import hashlib
import hmac
import unittest

from quicperf_harness.capacity import (
    CAPACITY_GRID,
    CapacityPoint,
    NeighborInterval,
    activate_confirmation_branch,
    confirm_nomination,
    freeze_confirmation_branches,
    nominate_capacity,
    plan_capacity_search,
)
from quicperf_harness.canonical import canonical_bytes
from quicperf_harness.errors import IdentityMismatchError
from quicperf_harness.identity import domain_hash
from quicperf_harness.memory import MEMORY_N_VALUES, memory_orders, plan_memory_campaign
from quicperf_harness.planner import (
    BALANCE_CONTROL_ESTIMAND,
    CANONICAL_SERVERS,
    CANONICAL_PATH_HASHES,
    PUBLICATION_SCENARIOS,
    ONE_BACKEND_SERVER_BACKENDS,
    audit_publication_schedule,
    ordered_predecessor_counts,
    plan_publication,
    williams_base,
    williams_rows,
)
from quicperf_harness.scheduler import (
    MicroblockOutcome,
    ScheduleError,
    select_inferential_microblocks,
)
from quicperf_harness.runner import (
    _active_publication_epochs,
    _publication_schedule_dict,
)


SEED = b"deterministic-v2-test-seed"
BASIS = bytes(range(32))


class WilliamsPlannerTests(unittest.TestCase):
    def test_exact_williams_construction_and_balance(self) -> None:
        self.assertEqual(
            williams_base(12),
            (0, 1, 11, 2, 10, 3, 9, 4, 8, 5, 7, 6),
        )
        rows = williams_rows(CANONICAL_SERVERS)
        for position in range(12):
            self.assertEqual({row[position] for row in rows}, set(CANONICAL_SERVERS))
        predecessors = ordered_predecessor_counts(rows)
        self.assertEqual(len(predecessors), 12 * 11)
        self.assertEqual(set(predecessors.values()), {1})

    def test_canonical_one_lane_publication_cardinality_and_audit(self) -> None:
        schedule = plan_publication(
            campaign_seed=SEED,
            schedule_basis_hash=BASIS,
            qualified_lane_count=1,
        )
        audit = audit_publication_schedule(schedule)
        self.assertTrue(schedule.publication_eligible)
        self.assertTrue(audit.valid, audit.reasons)
        self.assertEqual(len(schedule.primary_microblocks), 360)
        self.assertEqual(len(schedule.retry_microblocks), 360)
        self.assertEqual(len(schedule.balance_control_microblocks), 0)
        self.assertEqual(len(schedule.primary_trials), 8_640)
        self.assertEqual(len(schedule.retry_trials), 8_640)
        self.assertEqual(audit.primary_per_session, (4_320, 4_320))
        self.assertTrue(
            all(
                block.lane == 0
                and block.parallel_epoch_id is None
                and block.parallel_epoch_ordinal is None
                and block.parallel_lane_ordinal is None
                for block in schedule.microblocks
            )
        )

        frozen = _publication_schedule_dict(schedule)
        self.assertEqual(len(frozen["blocks"]), 720)
        self.assertEqual(
            sum(len(block["trials"]) for block in frozen["blocks"]),
            17_280,
        )
        self.assertEqual(
            collections.Counter(
                (block["slot"], block["phase"]) for block in frozen["blocks"]
            ),
            {
                ("primary", "confirmatory"): 360,
                ("retry", "confirmatory"): 360,
            },
        )

    def test_v22_iouring_only_cardinality_balance_and_session_pairing(
        self,
    ) -> None:
        schedule = plan_publication(
            campaign_seed=SEED,
            schedule_basis_hash=BASIS,
            qualified_lane_count=1,
            server_backends=ONE_BACKEND_SERVER_BACKENDS,
        )
        audit = audit_publication_schedule(schedule)
        self.assertTrue(schedule.publication_eligible)
        self.assertTrue(audit.valid, audit.reasons)
        self.assertEqual(len(schedule.primary_microblocks), 360)
        self.assertEqual(len(schedule.retry_microblocks), 360)
        self.assertEqual(len(schedule.primary_trials), 4_320)
        self.assertEqual(len(schedule.retry_trials), 4_320)
        self.assertEqual(audit.primary_per_session, (2_160, 2_160))
        self.assertEqual(
            {
                trial.server_backend
                for trial in schedule.primary_trials
            },
            {"iouring"},
        )
        strata = collections.Counter(
            (
                trial.server,
                trial.scenario,
                trial.server_backend,
                trial.reference_client,
            )
            for trial in schedule.primary_trials
        )
        self.assertEqual(set(strata.values()), {12})
        family_rows = collections.Counter(
            (
                trial.server,
                trial.scenario,
                trial.server_backend,
            )
            for trial in schedule.primary_trials
        )
        self.assertEqual(set(family_rows.values()), {24})
        pairs = collections.defaultdict(list)
        for block in schedule.primary_microblocks:
            pairs[block.superblock_id].append(block)
        self.assertEqual(len(pairs), 180)
        self.assertTrue(
            all(
                len(pair) == 2
                and {block.session for block in pair} == {1, 2}
                and len(
                    {
                        block.reference_client
                        for block in pair
                    }
                )
                == 2
                for pair in pairs.values()
            )
        )

    def test_two_lane_publication_epoch_balance_and_audit(self) -> None:
        schedule = plan_publication(
            campaign_seed=SEED,
            schedule_basis_hash=BASIS,
            qualified_lane_count=2,
        )
        audit = audit_publication_schedule(schedule)
        self.assertTrue(schedule.publication_eligible)
        self.assertTrue(audit.valid, audit.reasons)
        self.assertEqual(len(schedule.primary_microblocks), 360)
        self.assertEqual(len(schedule.retry_microblocks), 360)
        self.assertEqual(len(schedule.balance_control_microblocks), 48)
        self.assertEqual(len(schedule.primary_trials), 8_640)
        self.assertEqual(len(schedule.retry_trials), 8_640)
        self.assertEqual(audit.primary_per_session, (4_320, 4_320))
        for block in schedule.microblocks:
            expected_trace_seed = hmac.new(
                SEED,
                bytes.fromhex(block.microblock_id)
                + CANONICAL_PATH_HASHES[block.path_profile],
                hashlib.sha256,
            ).hexdigest()
            self.assertEqual(block.trace_seed, expected_trace_seed)

        strata = collections.Counter(
            (trial.server, trial.scenario, trial.server_backend, trial.reference_client)
            for trial in schedule.primary_trials
        )
        self.assertEqual(set(strata.values()), {12})
        backend_first = collections.Counter(
            (trial.server, trial.scenario, trial.server_backend)
            for trial in schedule.primary_trials
            if trial.backend_order == 0
        )
        self.assertEqual(set(backend_first.values()), {12})
        for session in (1, 2):
            clients = collections.Counter(
                block.reference_client
                for block in schedule.primary_microblocks
                if block.session == session
            )
            self.assertEqual(set(clients.values()), {90})
            for slot in ("primary", "retry"):
                lanes = collections.Counter(
                    block.lane
                    for block in schedule.microblocks
                    if block.session == session and block.slot == slot
                )
                self.assertLessEqual(max(lanes.values()) - min(lanes.values()), 1)
                members = [
                    block
                    for block in schedule.microblocks
                    if block.session == session and block.slot == slot
                ]
                epochs = collections.defaultdict(list)
                for block in members:
                    epochs[block.parallel_epoch_ordinal].append(block)
                self.assertEqual(set(epochs), set(range(96)))
                self.assertTrue(
                    all(
                        len(epoch) == 2
                        and {block.lane for block in epoch} == {0, 1}
                        and len({block.parallel_epoch_id for block in epoch}) == 1
                        and len(
                            {
                                (block.estimand, block.scenario)
                                for block in epoch
                            }
                        )
                        == 2
                        for epoch in epochs.values()
                    )
                )
                self.assertEqual(
                    sum(
                        len(
                            {
                                (
                                    block.scenario == "loss_recovery",
                                    block.scenario
                                    in {
                                        "connect",
                                        "resumed_connect",
                                        "zero_rtt_reqresp",
                                    },
                                )
                                for block in epoch
                            }
                        )
                        > 1
                        for epoch in epochs.values()
                    ),
                    12,
                )
                for scenario in PUBLICATION_SCENARIOS:
                    for client in ("ngtcp2perf", "picoperf"):
                        self.assertEqual(
                            [
                                sum(
                                    block.scenario == scenario
                                    and block.estimand
                                    != BALANCE_CONTROL_ESTIMAND
                                    and block.reference_client == client
                                    for block in members
                                    if block.lane == lane
                                )
                                for lane in range(2)
                            ],
                            [3, 3],
                        )

        peer_servers = collections.defaultdict(collections.Counter)
        peer_backends = collections.defaultdict(collections.Counter)
        peer_clients = collections.defaultdict(collections.Counter)
        peer_treatments = collections.defaultdict(collections.Counter)
        peer_offsets = collections.defaultdict(collections.Counter)
        for session in (1, 2):
            epochs = collections.defaultdict(list)
            for block in schedule.microblocks:
                if block.session == session and block.slot == "primary":
                    epochs[block.parallel_epoch_ordinal].append(block)
            for left, right in epochs.values():
                for block, peer in ((left, right), (right, left)):
                    if block.estimand == BALANCE_CONTROL_ESTIMAND:
                        continue
                    peer_offsets[block.scenario][
                        (peer.williams_row - block.williams_row) % 12
                    ] += 1
                    for trial, peer_trial in zip(
                        block.trials, peer.trials, strict=True
                    ):
                        key = (
                            trial.scenario,
                            trial.server,
                            trial.server_backend,
                        )
                        peer_servers[key][peer_trial.server] += 1
                        peer_backends[key][peer_trial.server_backend] += 1
                        peer_clients[key][peer_trial.reference_client] += 1
                        peer_treatments[key][
                            (
                                peer_trial.server,
                                peer_trial.server_backend,
                            )
                        ] += 1
        self.assertEqual(
            set(map(tuple, (counts.values() for counts in peer_offsets.values()))),
            {(2,) * 12},
        )
        self.assertEqual(
            {tuple(sorted(counts.values())) for counts in peer_servers.values()},
            {(2,) * 12},
        )
        self.assertEqual(
            {tuple(sorted(counts.values())) for counts in peer_backends.values()},
            {(12, 12)},
        )
        self.assertEqual(
            {tuple(sorted(counts.values())) for counts in peer_clients.values()},
            {(12, 12)},
        )
        self.assertEqual(
            {tuple(sorted(counts.values())) for counts in peer_treatments.values()},
            {(1,) * 24},
        )

        pairs = collections.defaultdict(list)
        for block in schedule.primary_microblocks:
            pairs[block.superblock_id].append(block)
        self.assertEqual(len(pairs), 180)
        for pair in pairs.values():
            self.assertEqual({block.session for block in pair}, {1, 2})
            first, second = sorted(pair, key=lambda block: block.session)
            self.assertEqual(first.server_order, second.server_order)
            self.assertNotEqual(first.reference_client, second.reference_client)
            self.assertNotEqual(first.trace_seed, second.trace_seed)
            first_orders = {
                (trial.server, trial.server_backend): trial.backend_order
                for trial in first.trials
            }
            second_orders = {
                (trial.server, trial.server_backend): trial.backend_order
                for trial in second.trials
            }
            self.assertEqual(
                second_orders,
                {key: 1 - order for key, order in first_orders.items()},
            )

        session_one = [
            block.williams_row
            for block in schedule.primary_microblocks
            if block.session == 1 and block.scenario == PUBLICATION_SCENARIOS[0]
        ]
        session_two = [
            block.williams_row
            for block in schedule.primary_microblocks
            if block.session == 2 and block.scenario == PUBLICATION_SCENARIOS[0]
        ]
        self.assertEqual(set(session_one), set(range(12)))
        self.assertEqual(set(session_two), set(range(12)))

    def test_active_publication_epochs_require_complete_frozen_pairs(self) -> None:
        frozen = _publication_schedule_dict(
            plan_publication(
                campaign_seed=SEED,
                schedule_basis_hash=BASIS,
                qualified_lane_count=2,
            )
        )
        phase_counts = collections.Counter(
            (block["slot"], block["phase"]) for block in frozen["blocks"]
        )
        self.assertEqual(
            phase_counts,
            {
                ("primary", "confirmatory"): 360,
                ("retry", "confirmatory"): 360,
                ("primary", "parallel_balance_control"): 24,
                ("retry", "parallel_balance_control"): 24,
            },
        )
        self.assertEqual(
            sum(len(block["trials"]) for block in frozen["blocks"]),
            18_432,
        )
        self.assertTrue(
            all(
                trial["cell_config"]["estimand"] == BALANCE_CONTROL_ESTIMAND
                for block in frozen["blocks"]
                if block["phase"] == "parallel_balance_control"
                for trial in block["trials"]
            )
        )
        by_id = {
            str(block["microblock_id"]): block for block in frozen["blocks"]
        }
        primary = [
            block_id
            for block_id, block in by_id.items()
            if block["session"] == 1 and block["slot"] == "primary"
        ]
        epochs = _active_publication_epochs(by_id, primary, session=1)
        self.assertEqual(len(epochs), 96)
        self.assertEqual([ordinal for ordinal, _members in epochs], list(range(96)))
        self.assertTrue(
            all(
                tuple(lane for lane, _block_id in members) == (0, 1)
                for _ordinal, members in epochs
            )
        )

        with self.assertRaisesRegex(
            IdentityMismatchError, "publication parallel epoch is incomplete"
        ):
            _active_publication_epochs(by_id, primary[1:], session=1)

        retry = next(
            block_id
            for block_id, block in by_id.items()
            if block["session"] == 1 and block["slot"] == "retry"
        )
        with self.assertRaisesRegex(
            IdentityMismatchError,
            "primary and retry epochs are active together",
        ):
            _active_publication_epochs(
                by_id, primary + [retry], session=1
            )

    def test_diagnostic_durations_participate_in_every_publication_cell_id(self) -> None:
        planned = plan_publication(
            campaign_seed=SEED,
            schedule_basis_hash=BASIS,
            qualified_lane_count=1,
        )
        durations = {
            scenario: (
                20_000_000_000
                if scenario == "loss_recovery"
                else 10_000_000_000
            )
            for scenario in PUBLICATION_SCENARIOS
        }
        frozen = _publication_schedule_dict(
            planned, measurement_durations_ns=durations
        )
        trials = [
            trial
            for block in frozen["blocks"]
            for trial in block["trials"]
        ]
        self.assertEqual(len(trials), 17_280)
        self.assertEqual(
            len({trial["trial_id"] for trial in trials}), len(trials)
        )
        self.assertEqual(
            len({trial["logical_trial_id"] for trial in trials}), 8_640
        )
        for trial in trials:
            config = trial["cell_config"]
            self.assertEqual(
                config["measurement_duration_ns"],
                durations[config["scenario"]],
            )
            self.assertEqual(
                trial["cell_id"],
                domain_hash("cell", canonical_bytes(config)),
            )

    def test_schedule_is_reproducible_and_seed_changes_only_assignment(self) -> None:
        first = plan_publication(
            campaign_seed=SEED,
            schedule_basis_hash=BASIS,
            qualified_lane_count=2,
        )
        same = plan_publication(
            campaign_seed=SEED,
            schedule_basis_hash=BASIS,
            qualified_lane_count=2,
        )
        changed = plan_publication(
            campaign_seed=b"another-v2-seed",
            schedule_basis_hash=BASIS,
            qualified_lane_count=2,
        )
        self.assertEqual(first.canonical_bytes(), same.canonical_bytes())
        self.assertEqual(first.schedule_hash, same.schedule_hash)
        self.assertNotEqual(first.schedule_hash, changed.schedule_hash)
        treatment = lambda schedule: collections.Counter(
            (trial.server, trial.server_backend, trial.scenario, trial.reference_client)
            for trial in schedule.primary_trials
        )
        self.assertEqual(treatment(first), treatment(changed))

    def test_subset_and_odd_designs_are_diagnostic(self) -> None:
        schedule = plan_publication(
            campaign_seed=SEED,
            schedule_basis_hash=BASIS,
            servers=CANONICAL_SERVERS[:3],
            scenarios=("custom", "download"),
        )
        self.assertFalse(schedule.publication_eligible)
        self.assertEqual(len(schedule.primary_trials), 2 * 3 * 2 * 3 * 2)

    def test_partial_microblock_exclusion_and_complete_retry(self) -> None:
        partial = MicroblockOutcome(
            "a", "primary-a", "primary", "committed", ("one",), ("one", "two")
        )
        original = MicroblockOutcome(
            "b", "primary-b", "primary", "superseded_incomplete_microblock"
        )
        retry = MicroblockOutcome(
            "b", "retry-b", "retry", "committed", ("r1", "r2"), ("r1", "r2")
        )
        selected = select_inferential_microblocks((partial, original, retry))
        self.assertNotIn("a", selected)
        self.assertEqual(selected["b"], retry)
        with self.assertRaises(ScheduleError):
            select_inferential_microblocks(
                (
                    MicroblockOutcome("c", "p", "primary", "committed", ("x",), ("x",)),
                    MicroblockOutcome("c", "r", "retry", "committed", ("y",), ("y",)),
                )
            )


class CapacityAndMemoryPlanTests(unittest.TestCase):
    def test_exploratory_capacity_is_complete_and_balanced(self) -> None:
        plan = plan_capacity_search(campaign_seed=SEED, schedule_basis_hash=BASIS)
        self.assertEqual(len(plan.trials), 12 * 2 * 7 * 10)
        cells = collections.Counter(
            (
                trial.server,
                trial.server_backend,
                trial.scenario,
                trial.reference_client,
                trial.concurrency,
            )
            for trial in plan.trials
        )
        self.assertEqual(set(cells.values()), {1})
        self.assertEqual({trial.phase for trial in plan.trials}, {"exploratory"})

    def test_capacity_nomination_and_frozen_confirmation_branches(self) -> None:
        observations = [
            CapacityPoint(concurrency, client, rate, True)
            for concurrency, rate in zip(CAPACITY_GRID, (10.0, 20.0, 30.0, 29.5, 29.0), strict=True)
            for client in ("ngtcp2perf", "picoperf")
        ]
        nomination = nominate_capacity(observations)
        self.assertEqual(nomination.candidate, 4)
        branches = freeze_confirmation_branches(
            campaign_seed=SEED,
            schedule_basis_hash=BASIS,
            server="ngtcp2perf",
            server_backend="syscall",
            scenario="download",
            qualified_lane_count=2,
        )
        self.assertEqual([branch.candidate for branch in branches], list(CAPACITY_GRID))
        self.assertEqual([len(branch.trials) for branch in branches], [96, 144, 144, 144, 96])
        for branch in branches:
            primary = [trial for trial in branch.trials if trial.slot == "primary"]
            counts = collections.Counter(trial.concurrency for trial in primary)
            self.assertEqual(set(counts.values()), {24})
            clients = collections.Counter(trial.reference_client for trial in primary)
            self.assertEqual(clients["ngtcp2perf"], len(primary) // 2)
            self.assertEqual(clients["picoperf"], len(primary) // 2)
            self.assertEqual(len({trial.microblock_id for trial in primary}), 24)
        activated = activate_confirmation_branch(branches, 4)
        self.assertEqual(
            [branch.status for branch in activated],
            ["not_selected", "not_selected", "active", "not_selected", "not_selected"],
        )

        margin = 0.02
        self.assertEqual(
            confirm_nomination(
                4,
                {
                    2: NeighborInterval(2, -0.01, 0.01),
                    8: NeighborInterval(8, -0.01, 0.01),
                },
                practical_margin=margin,
            ).status,
            "confirmed",
        )
        self.assertEqual(
            confirm_nomination(
                4,
                {
                    2: NeighborInterval(2, -0.01, 0.01),
                    8: NeighborInterval(8, -0.05, -0.03),
                },
                practical_margin=margin,
            ).reason,
            "under_bracketed",
        )
        self.assertEqual(
            confirm_nomination(
                16,
                {8: NeighborInterval(8, 0.03, 0.04)},
                practical_margin=margin,
            ).status,
            "right_censored",
        )

    def test_memory_plan_has_exact_balanced_n_grid(self) -> None:
        orders = memory_orders(SEED)
        for position in range(4):
            counts = collections.Counter(order[position] for order in orders)
            self.assertEqual(set(counts), set(MEMORY_N_VALUES))
            self.assertEqual(set(counts.values()), {3})
        trials = plan_memory_campaign(campaign_seed=SEED, schedule_basis_hash=BASIS)
        self.assertEqual(len(trials), 2_304)
        cells = collections.Counter(
            (trial.server, trial.server_backend, trial.connections) for trial in trials
        )
        self.assertEqual(set(cells.values()), {24})
        self.assertEqual(len({trial.trial_id for trial in trials}), 2_304)


if __name__ == "__main__":
    unittest.main()
