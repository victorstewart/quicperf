from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from quicperf_harness.journal import (
    CardinalityError,
    IdentityMismatchError,
    IllegalTransitionError,
    Journal,
    JournalError,
    JournalLockedError,
    SCHEMA_VERSION,
    StorageError,
    derive_attempt_id,
    domain_hash,
)


def hid(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


IDENTITY = {
    "campaign_id": hid("campaign"),
    "spec_hash": hid("spec"),
    "identity_manifest_hash": hid("manifest"),
    "analysis_plan_hash": hid("analysis"),
    "schedule_hash": hid("schedule"),
}


class InjectedFault(RuntimeError):
    pass


class Fault:
    def __init__(self, point: str | None = None):
        self.point = point
        self.seen: list[str] = []

    def __call__(self, point: str) -> None:
        self.seen.append(point)
        if point == self.point:
            raise InjectedFault(point)


class JournalTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def make_journal(
        self,
        *,
        count: int = 2,
        fault: Fault | None = None,
        freeze: bool = True,
        retry: bool = True,
    ) -> tuple[Journal, list[str], list[str], str, str]:
        journal = Journal(self.root / "journal.sqlite3", fault_injector=fault)
        self.addCleanup(journal.close)
        journal.create_campaign(
            **IDENTITY,
            expected_cardinality=count,
            manifests={"identity": (hid("identity-doc"), {"host": "fixed"})},
            session_count=1,
        )
        cell = hid("cell")
        primary = hid("primary-block")
        retry_block = hid("retry-block")
        journal.add_cell(IDENTITY["campaign_id"], cell, {"backend": "syscall"})
        journal.add_microblock(
            campaign_id=IDENTITY["campaign_id"],
            microblock_id=primary,
            session_number=1,
            ordinal=0,
            slot="primary",
            expected_trials=count,
        )
        if retry:
            journal.add_microblock(
                campaign_id=IDENTITY["campaign_id"],
                microblock_id=retry_block,
                session_number=1,
                ordinal=0,
                slot="retry",
                retry_for=primary,
                expected_trials=count,
            )
        primary_trials: list[str] = []
        retry_trials: list[str] = []
        for index in range(count):
            trial = hid(f"primary-trial-{index}")
            primary_trials.append(trial)
            journal.add_trial(
                campaign_id=IDENTITY["campaign_id"],
                trial_id=trial,
                microblock_id=primary,
                cell_id=cell,
                ordinal=index,
            )
            if retry:
                retry_trial = hid(f"retry-trial-{index}")
                retry_trials.append(retry_trial)
                journal.add_trial(
                    campaign_id=IDENTITY["campaign_id"],
                    trial_id=retry_trial,
                    logical_trial_id=trial,
                    microblock_id=retry_block,
                    cell_id=cell,
                    ordinal=index,
                )
        if freeze:
            journal.freeze_schedule(IDENTITY["campaign_id"])
        return journal, primary_trials, retry_trials, primary, retry_block

    def advance(self, journal: Journal, trial_id: str, through: str) -> str:
        attempt = journal.ensure_attempt(trial_id)
        states = (
            "starting",
            "ready",
            "armed",
            "measuring",
            "draining",
            "validating",
            "validated_provisional",
        )
        for state in states:
            journal.transition_attempt(attempt, state, raw_time_ns=100)
            if state == through:
                break
        return attempt

    def make_block_journal(
        self, blocks: int, *, fault: Fault | None = None
    ) -> tuple[Journal, list[tuple[str, str, str, str]]]:
        journal = Journal(
            self.root / "block-journal.sqlite3", fault_injector=fault
        )
        self.addCleanup(journal.close)
        journal.create_campaign(
            **IDENTITY,
            expected_cardinality=blocks,
            manifests={"identity": (hid("identity-doc"), {"host": "fixed"})},
            session_count=1,
        )
        cell = hid("block-cell")
        journal.add_cell(
            IDENTITY["campaign_id"], cell, {"backend": "syscall"}
        )
        result = []
        for ordinal in range(blocks):
            primary = hid(f"block-primary-{ordinal}")
            retry = hid(f"block-retry-{ordinal}")
            trial = hid(f"block-trial-{ordinal}")
            retry_trial = hid(f"block-retry-trial-{ordinal}")
            journal.add_microblock(
                campaign_id=IDENTITY["campaign_id"],
                microblock_id=primary,
                session_number=1,
                ordinal=ordinal,
                slot="primary",
                expected_trials=1,
            )
            journal.add_microblock(
                campaign_id=IDENTITY["campaign_id"],
                microblock_id=retry,
                session_number=1,
                ordinal=ordinal,
                slot="retry",
                retry_for=primary,
                expected_trials=1,
            )
            journal.add_trial(
                campaign_id=IDENTITY["campaign_id"],
                trial_id=trial,
                microblock_id=primary,
                cell_id=cell,
                ordinal=0,
            )
            journal.add_trial(
                campaign_id=IDENTITY["campaign_id"],
                trial_id=retry_trial,
                logical_trial_id=trial,
                microblock_id=retry,
                cell_id=cell,
                ordinal=0,
            )
            result.append((primary, retry, trial, retry_trial))
        journal.freeze_schedule(IDENTITY["campaign_id"])
        return journal, result


class SchemaAndIdentityTests(JournalTestCase):
    def test_domain_hash_is_length_delimited_and_attempt_is_stable(self) -> None:
        left = domain_hash("tag", b"a", b"bc")
        right = domain_hash("tag", b"ab", b"c")
        self.assertNotEqual(left, right)
        trial = hid("trial")
        self.assertEqual(derive_attempt_id(trial), derive_attempt_id(trial, 0))
        self.assertNotEqual(derive_attempt_id(trial, 0), derive_attempt_id(trial, 1))

    def test_required_tables_pragmas_and_integrity(self) -> None:
        journal = Journal(self.root / "journal.sqlite3")
        self.addCleanup(journal.close)
        tables = {
            row[0]
            for row in journal.connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table'"
            )
        }
        self.assertTrue(
            {
                "schema_meta",
                "campaign",
                "session",
                "manifest",
                "cell",
                "microblock",
                "trial",
                "attempt",
                "event",
                "sample",
                "artifact",
            }.issubset(tables)
        )
        self.assertEqual(journal.connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(journal.connection.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(journal.connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(journal.connection.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
        journal.integrity_check()

    def test_complete_session_retry_preserves_but_excludes_primary_samples(self) -> None:
        journal, primary_trials, retry_trials, primary, retry = self.make_journal(
            count=1
        )
        self.advance(journal, primary_trials[0], "validated_provisional")
        journal.commit_microblock(primary, {primary_trials[0]: {"value": 1}})
        replay = journal.activate_session_retry(
            IDENTITY["campaign_id"], 1, "coordinator_interruption"
        )
        self.assertEqual(replay["status"], "retry_activated")
        self.assertEqual(replay["activated"], 1)
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id=?", (primary,)
            ).fetchone()[0],
            "superseded",
        )
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id=?", (retry,)
            ).fetchone()[0],
            "active",
        )
        self.assertEqual(
            journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0], 0
        )
        self.assertEqual(
            journal.connection.execute("SELECT COUNT(*) FROM committed_sample").fetchone()[0],
            0,
        )
        self.advance(journal, retry_trials[0], "validated_provisional")
        journal.commit_microblock(retry, {retry_trials[0]: {"value": 2}})
        self.assertEqual(
            journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0], 1
        )
        self.assertEqual(
            journal.connection.execute("SELECT COUNT(*) FROM committed_sample").fetchone()[0],
            1,
        )
        journal.assert_exact_cardinality(IDENTITY["campaign_id"])
        journal.integrity_check()

    def test_complete_session_retry_includes_failed_primary_blocks(self) -> None:
        journal, primary_trials, _retry_trials, primary, retry = self.make_journal(
            count=1
        )
        self.advance(journal, primary_trials[0], "measuring")
        journal.fail_microblock(
            primary,
            "deterministic_failure",
            root_trial_id=primary_trials[0],
            root_detail='{"counter":7}',
        )

        replay = journal.activate_session_retry(
            IDENTITY["campaign_id"], 1, "host_stability_monitor_transient"
        )

        self.assertEqual(replay["status"], "retry_activated")
        self.assertEqual(replay["activated"], 1)
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id=?", (primary,)
            ).fetchone()[0],
            "superseded",
        )
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id=?", (retry,)
            ).fetchone()[0],
            "active",
        )
        journal.integrity_check()

    def test_microblock_failure_preserves_root_detail_and_marks_collateral(self) -> None:
        journal, primary_trials, _retry_trials, primary, _retry = self.make_journal(
            count=3
        )
        self.advance(journal, primary_trials[0], "validated_provisional")
        self.advance(journal, primary_trials[1], "measuring")

        journal.fail_microblock(
            primary,
            "unexpected_flow_control_blocking",
            terminal_state="invalid",
            root_trial_id=primary_trials[1],
            root_detail='{"data_blocked":3,"stream_data_blocked":5}',
        )

        rows = journal.connection.execute(
            """
            SELECT t.trial_id, t.state, a.termination_reason, a.details_json
            FROM trial t JOIN attempt a USING(trial_id)
            WHERE t.microblock_id=? ORDER BY t.ordinal
            """,
            (primary,),
        ).fetchall()
        self.assertEqual([row["state"] for row in rows], ["failed", "invalid", "failed"])
        self.assertEqual(
            [row["termination_reason"] for row in rows],
            [
                "collateral_microblock_failure",
                "unexpected_flow_control_blocking",
                "collateral_microblock_failure",
            ],
        )
        details = [json.loads(row["details_json"]) for row in rows]
        self.assertEqual(
            details[1],
            {
                "endpoint_detail": '{"data_blocked":3,"stream_data_blocked":5}',
                "microblock_failure_role": "root",
                "root_termination_reason": "unexpected_flow_control_blocking",
                "root_trial_id": primary_trials[1],
            },
        )
        for index in (0, 2):
            self.assertEqual(details[index]["microblock_failure_role"], "collateral")
            self.assertEqual(details[index]["root_trial_id"], primary_trials[1])
            self.assertNotIn("endpoint_detail", details[index])
        journal.integrity_check()

    def test_hardware_invalidation_preserves_evidence_and_excludes_whole_session(self) -> None:
        journal, primary_trials, _retry_trials, primary, retry = self.make_journal(
            count=1
        )
        self.advance(journal, primary_trials[0], "validated_provisional")
        journal.commit_microblock(primary, {primary_trials[0]: {"value": 1}})
        result = journal.invalidate_session_hardware(
            IDENTITY["campaign_id"],
            1,
            "tctl_thermal_headroom_breach",
            {"provider": "amd_delivered_performance_v1", "passed": False},
        )
        self.assertEqual(result["status"], "hardware_unqualified")
        self.assertEqual(result["excluded_committed_microblocks"], 1)
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id=?", (primary,)
            ).fetchone()[0],
            "superseded",
        )
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id=?", (retry,)
            ).fetchone()[0],
            "dormant",
        )
        self.assertEqual(
            journal.connection.execute("SELECT COUNT(*) FROM committed_sample").fetchone()[0],
            0,
        )
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM campaign WHERE campaign_id=?",
                (IDENTITY["campaign_id"],),
            ).fetchone()[0],
            "hardware_unqualified",
        )
        artifact = journal.connection.execute(
            "SELECT content FROM artifact WHERE campaign_id=? AND path=?",
            (
                IDENTITY["campaign_id"],
                "runtime/session-1-hardware-unqualified.json",
            ),
        ).fetchone()
        self.assertIsNotNone(artifact)
        self.assertIn(b'tctl_thermal_headroom_breach', bytes(artifact[0]))
        journal.integrity_check()

    def test_identity_resume_is_exact_and_idempotent(self) -> None:
        journal, *_ = self.make_journal()
        journal.assert_identity(**IDENTITY)
        journal.freeze_schedule(IDENTITY["campaign_id"])
        for field in IDENTITY:
            changed = dict(IDENTITY)
            changed[field] = hid("different-" + field)
            with self.subTest(field=field), self.assertRaises(IdentityMismatchError):
                journal.assert_identity(**changed)

    def test_run_directory_is_exclusive_and_fixed(self) -> None:
        run_dir = self.root / "run"
        journal = Journal.create_run_directory(
            run_dir, spec_bytes=b"{}\n", manifest_bytes=b"{}\n"
        )
        self.addCleanup(journal.close)
        self.assertEqual((run_dir / "spec.json").read_bytes(), b"{}\n")
        self.assertEqual((run_dir / "manifest.json").read_bytes(), b"{}\n")
        self.assertTrue((run_dir / "logs").is_dir())
        self.assertTrue((run_dir / "artifacts").is_dir())
        with self.assertRaises(FileExistsError):
            Journal.create_run_directory(run_dir, spec_bytes=b"x", manifest_bytes=b"y")

    def test_second_coordinator_is_rejected_but_reader_is_allowed(self) -> None:
        journal = Journal(self.root / "journal.sqlite3")
        self.addCleanup(journal.close)
        with self.assertRaises(JournalLockedError):
            Journal(self.root / "journal.sqlite3")
        reader = Journal(self.root / "journal.sqlite3", writable=False)
        self.addCleanup(reader.close)
        self.assertEqual(
            reader.connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION
        )

    def test_failed_migration_rolls_back_and_releases_lock(self) -> None:
        path = self.root / "journal.sqlite3"
        fault = Fault("migration.1.statement.6")
        with self.assertRaises(InjectedFault):
            Journal(path, fault_injector=fault)
        raw = sqlite3.connect(path)
        try:
            self.assertEqual(raw.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(
                raw.execute(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name != 'sqlite_sequence'"
                ).fetchone()[0],
                0,
            )
        finally:
            raw.close()
        reopened = Journal(path)
        self.addCleanup(reopened.close)
        reopened.integrity_check()

    def test_busy_writer_is_a_storage_failure_without_partial_write(self) -> None:
        journal, *_ = self.make_journal()
        blocker = sqlite3.connect(journal.path, isolation_level=None)
        self.addCleanup(blocker.close)
        blocker.execute("BEGIN IMMEDIATE")
        journal.connection.execute("PRAGMA busy_timeout=1")
        with self.assertRaises(sqlite3.OperationalError):
            journal.store_artifact(IDENTITY["campaign_id"], "blocked.tsv", b"no")
        blocker.execute("ROLLBACK")
        self.assertEqual(
            journal.connection.execute(
                "SELECT COUNT(*) FROM artifact WHERE path = 'blocked.tsv'"
            ).fetchone()[0],
            0,
        )

    def test_foreign_key_corruption_is_detected(self) -> None:
        journal, *_ = self.make_journal()
        path = journal.path
        journal.close()
        raw = sqlite3.connect(path)
        try:
            raw.execute("PRAGMA foreign_keys=OFF")
            raw.execute(
                """
                INSERT INTO event(
                    attempt_id, source, event_sequence, event_type, raw_time_ns, payload_json
                ) VALUES (?, 'corruptor', 0, 'BAD', 0, '{}')
                """,
                (hid("missing-attempt"),),
            )
            raw.commit()
        finally:
            raw.close()
        reopened = Journal(path)
        self.addCleanup(reopened.close)
        with self.assertRaises(StorageError):
            reopened.integrity_check()


class TransitionAndCommitTests(JournalTestCase):
    def test_every_transition_is_durable_and_forbidden_skips_fail(self) -> None:
        fault = Fault()
        journal, trials, _, _, _ = self.make_journal(count=1, fault=fault)
        attempt = journal.ensure_attempt(trials[0])
        with self.assertRaises(IllegalTransitionError):
            journal.transition_attempt(attempt, "measuring")
        states = (
            "starting",
            "ready",
            "armed",
            "measuring",
            "draining",
            "validating",
            "validated_provisional",
        )
        old = "planned"
        for state in states:
            fault.point = f"transition.{state}.before_commit"
            with self.subTest(state=state, side="before"), self.assertRaises(InjectedFault):
                journal.transition_attempt(attempt, state)
            self.assertEqual(
                journal.connection.execute(
                    "SELECT state FROM attempt WHERE attempt_id = ?", (attempt,)
                ).fetchone()[0],
                old,
            )
            fault.point = f"transition.{state}.after_commit"
            with self.subTest(state=state, side="after"), self.assertRaises(InjectedFault):
                journal.transition_attempt(attempt, state)
            self.assertEqual(
                journal.connection.execute(
                    "SELECT state FROM attempt WHERE attempt_id = ?", (attempt,)
                ).fetchone()[0],
                state,
            )
            old = state
        fault.point = None

    def test_duplicate_events_and_events_after_commit_are_rejected(self) -> None:
        journal, trials, _, primary, _ = self.make_journal(count=1)
        attempt = self.advance(journal, trials[0], "validated_provisional")
        journal.append_event(
            attempt,
            source="server",
            event_sequence=0,
            event_type="READY",
            raw_time_ns=1,
            payload={"text": "hostile\nline\tstill data"},
        )
        with self.assertRaises(sqlite3.IntegrityError):
            journal.append_event(
                attempt,
                source="server",
                event_sequence=0,
                event_type="READY",
                raw_time_ns=1,
                payload={},
            )
        journal.commit_microblock(primary, {trials[0]: {"value": 1}})
        with self.assertRaises(sqlite3.IntegrityError):
            journal.append_event(
                attempt,
                source="server",
                event_sequence=1,
                event_type="LATE",
                raw_time_ns=2,
                payload={},
            )

    def test_microblock_commit_is_atomic_and_samples_are_immutable(self) -> None:
        fault = Fault("microblock.commit.after_sample")
        journal, trials, _, primary, _ = self.make_journal(fault=fault)
        for trial in trials:
            self.advance(journal, trial, "validated_provisional")
        samples = {trial: {"metric": "rate", "raw": index} for index, trial in enumerate(trials)}
        with self.assertRaises(InjectedFault):
            journal.commit_microblock(primary, samples, committed_ns=999)
        self.assertEqual(journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0], 0)
        self.assertEqual(
            {row[0] for row in journal.connection.execute("SELECT state FROM attempt")},
            {"validated_provisional"},
        )
        fault.point = None
        journal.commit_microblock(primary, samples, committed_ns=999)
        self.assertEqual(journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0], 2)
        journal.commit_microblock(primary, samples, committed_ns=999)
        journal.assert_exact_cardinality(IDENTITY["campaign_id"])
        with self.assertRaises(sqlite3.IntegrityError):
            journal.connection.execute("UPDATE sample SET sample_json = '{}' ")
        with self.assertRaises(sqlite3.IntegrityError):
            journal.connection.execute("DELETE FROM sample")
        with self.assertRaises(sqlite3.IntegrityError):
            journal.connection.execute("UPDATE attempt SET details_json = '{}' ")

    def test_direct_individual_commit_and_frozen_schedule_mutation_are_rejected(self) -> None:
        journal, trials, _, primary, _ = self.make_journal(count=1)
        attempt = self.advance(journal, trials[0], "validated_provisional")
        with self.assertRaises(sqlite3.IntegrityError):
            journal.connection.execute(
                "UPDATE attempt SET state = 'committed' WHERE attempt_id = ?", (attempt,)
            )
        with self.assertRaises(sqlite3.IntegrityError):
            journal.connection.execute(
                "UPDATE trial SET state = 'committed' WHERE trial_id = ?", (trials[0],)
            )
        with self.assertRaises(sqlite3.IntegrityError):
            journal.connection.execute(
                "UPDATE microblock SET status = 'committed' WHERE microblock_id = ?", (primary,)
            )
        with self.assertRaises(sqlite3.IntegrityError):
            journal.connection.execute(
                "UPDATE trial SET cell_id = ? WHERE trial_id = ?", (hid("other"), trials[0])
            )
        with self.assertRaises(sqlite3.IntegrityError):
            journal.connection.execute(
                "UPDATE campaign SET schedule_frozen = 0 WHERE campaign_id = ?",
                (IDENTITY["campaign_id"],),
            )

    def test_zero_multiple_and_mismatched_result_cardinality_cannot_commit(self) -> None:
        journal, trials, _, primary, _ = self.make_journal()
        for trial in trials:
            self.advance(journal, trial, "validated_provisional")
        with self.assertRaises(CardinalityError):
            journal.commit_microblock(primary, {})
        with self.assertRaises(CardinalityError):
            journal.commit_microblock(primary, {trials[0]: {}, hid("extra"): {}})
        with self.assertRaises(CardinalityError):
            journal.commit_microblock(primary, {trials[0]: {}, trials[1]: {}, hid("extra"): {}})
        self.assertEqual(journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0], 0)

    def test_freeze_requires_exact_primary_and_complete_preallocated_retry(self) -> None:
        journal, *_ = self.make_journal(count=2, freeze=False, retry=False)
        with self.assertRaises(CardinalityError):
            journal.freeze_schedule(IDENTITY["campaign_id"])


class RecoveryTests(JournalTestCase):
    def test_localized_retry_transition_rolls_back_atomically(self) -> None:
        fault = Fault()
        journal, blocks = self.make_block_journal(1, fault=fault)
        primary, retry, trial, _retry_trial = blocks[0]
        self.advance(journal, trial, "measuring")
        fault.point = "microblock.retry.before_commit"

        with self.assertRaises(InjectedFault):
            journal.activate_microblock_retry(
                IDENTITY["campaign_id"],
                primary,
                reason="host_stability_interval_transient",
                detail=None,
                aggregate_maximum=2,
            )

        self.assertEqual(
            dict(
                journal.connection.execute(
                    "SELECT microblock_id, status FROM microblock"
                )
            ),
            {primary: "active", retry: "dormant"},
        )
        self.assertEqual(
            journal.connection.execute(
                "SELECT state FROM trial WHERE trial_id=?", (trial,)
            ).fetchone()[0],
            "measuring",
        )
        journal.integrity_check()

    def test_localized_retry_preserves_prior_committed_microblocks(self) -> None:
        journal, blocks = self.make_block_journal(2)
        first_primary, _first_retry, first_trial, _ = blocks[0]
        second_primary, second_retry, second_trial, _ = blocks[1]
        self.advance(journal, first_trial, "validated_provisional")
        journal.commit_microblock(first_primary, {first_trial: {"value": 1}})
        self.advance(journal, second_trial, "measuring")

        result = journal.activate_microblock_retry(
            IDENTITY["campaign_id"],
            second_primary,
            reason="host_stability_interval_transient",
            detail="late boundary",
            aggregate_maximum=2,
        )

        self.assertEqual(result["status"], "retry_activated")
        self.assertEqual(result["retry_microblock_id"], second_retry)
        self.assertEqual(result["localized_transients"], 1)
        self.assertEqual(
            journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0],
            1,
        )
        journal.integrity_check()

    def test_localized_retry_failure_is_immediately_terminal(self) -> None:
        journal, blocks = self.make_block_journal(2)
        first_primary, _first_retry, first_trial, _ = blocks[0]
        second_primary, second_retry, second_trial, second_retry_trial = blocks[1]
        self.advance(journal, first_trial, "validated_provisional")
        journal.commit_microblock(first_primary, {first_trial: {"value": 1}})
        self.advance(journal, second_trial, "measuring")
        journal.activate_microblock_retry(
            IDENTITY["campaign_id"],
            second_primary,
            reason="host_stability_interval_transient",
            detail=None,
            aggregate_maximum=2,
        )
        self.advance(journal, second_retry_trial, "measuring")

        result = journal.activate_microblock_retry(
            IDENTITY["campaign_id"],
            second_retry,
            reason="host_stability_interval_transient",
            detail=None,
            aggregate_maximum=2,
        )

        self.assertEqual(result["status"], "retry_exhausted")
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM session WHERE session_number=1"
            ).fetchone()[0],
            "nonpublishable",
        )
        self.assertEqual(
            journal.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0],
            1,
        )
        journal.integrity_check()

    def test_localized_retry_aggregate_budget_counts_only_local_transients(
        self,
    ) -> None:
        journal, blocks = self.make_block_journal(2)
        first_primary, _first_retry, first_trial, _ = blocks[0]
        second_primary, second_retry, second_trial, _ = blocks[1]
        journal.connection.execute(
            "UPDATE session SET infrastructure_failures=7"
        )
        self.advance(journal, first_trial, "measuring")
        first = journal.activate_microblock_retry(
            IDENTITY["campaign_id"],
            first_primary,
            reason="host_stability_interval_transient",
            detail=None,
            aggregate_maximum=1,
        )
        self.assertEqual(first["status"], "retry_activated")
        self.advance(journal, second_trial, "measuring")

        exhausted = journal.activate_microblock_retry(
            IDENTITY["campaign_id"],
            second_primary,
            reason="host_stability_interval_transient",
            detail=None,
            aggregate_maximum=1,
        )

        self.assertEqual(
            exhausted,
            {
                "status": "aggregate_transient_budget_exhausted",
                "localized_transients": 1,
            },
        )
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id=?",
                (second_primary,),
            ).fetchone()[0],
            "active",
        )
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id=?",
                (second_retry,),
            ).fetchone()[0],
            "dormant",
        )
        journal.integrity_check()

    def test_untouched_primary_resumes_without_history(self) -> None:
        journal, _, _, primary, retry = self.make_journal()
        result = journal.recover(IDENTITY["campaign_id"])
        self.assertEqual(result, {"untouched": 1, "retried": 0, "retry_failed": 0})
        statuses = dict(
            journal.connection.execute("SELECT microblock_id, status FROM microblock")
        )
        self.assertEqual(statuses[primary], "active")
        self.assertEqual(statuses[retry], "dormant")

    def test_partial_primary_is_immutable_history_and_activates_whole_retry(self) -> None:
        journal, primary_trials, retry_trials, primary, retry = self.make_journal()
        attempt = self.advance(journal, primary_trials[0], "measuring")
        result = journal.recover(IDENTITY["campaign_id"])
        self.assertEqual(result["retried"], 1)
        self.assertEqual(
            journal.connection.execute(
                "SELECT state FROM attempt WHERE attempt_id = ?", (attempt,)
            ).fetchone()[0],
            "interrupted",
        )
        self.assertEqual(
            {row[0] for row in journal.connection.execute(
                "SELECT state FROM trial WHERE microblock_id = ?", (primary,)
            )},
            {"superseded_incomplete_microblock"},
        )
        statuses = dict(journal.connection.execute("SELECT microblock_id, status FROM microblock"))
        self.assertEqual(statuses[primary], "superseded")
        self.assertEqual(statuses[retry], "active")
        with self.assertRaises(sqlite3.IntegrityError):
            journal.connection.execute(
                "UPDATE attempt SET termination_reason = 'rewritten' WHERE attempt_id = ?",
                (attempt,),
            )
        second = journal.recover(IDENTITY["campaign_id"])
        self.assertEqual(second, {"untouched": 1, "retried": 0, "retry_failed": 0})
        self.assertEqual(
            [
                row[0]
                for row in journal.connection.execute(
                    "SELECT logical_trial_id FROM trial WHERE microblock_id = ? ORDER BY ordinal",
                    (retry,),
                )
            ],
            primary_trials,
        )
        self.assertEqual(len(retry_trials), len(primary_trials))

    def test_interrupted_retry_is_second_failure_and_nonpublishable(self) -> None:
        journal, primary_trials, retry_trials, _, retry = self.make_journal()
        self.advance(journal, primary_trials[0], "ready")
        journal.recover(IDENTITY["campaign_id"])
        self.advance(journal, retry_trials[0], "armed")
        result = journal.recover(IDENTITY["campaign_id"])
        self.assertEqual(result["retry_failed"], 1)
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id = ?", (retry,)
            ).fetchone()[0],
            "failed",
        )
        session = journal.connection.execute(
            "SELECT status, infrastructure_failures FROM session"
        ).fetchone()
        self.assertEqual(tuple(session), ("nonpublishable", 2))

    def test_recovery_transaction_rolls_back_on_storage_fault(self) -> None:
        fault = Fault()
        journal, primary_trials, _, primary, retry = self.make_journal(fault=fault)
        self.advance(journal, primary_trials[0], "measuring")
        fault.point = "recovery.before_commit"
        with self.assertRaises(InjectedFault):
            journal.recover(IDENTITY["campaign_id"])
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id = ?", (primary,)
            ).fetchone()[0],
            "active",
        )
        self.assertEqual(
            journal.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id = ?", (retry,)
            ).fetchone()[0],
            "dormant",
        )


class ExportTests(JournalTestCase):
    def committed_journal(self, fault: Fault | None = None) -> Journal:
        journal, trials, _, primary, _ = self.make_journal(count=1, fault=fault)
        attempt = self.advance(journal, trials[0], "validated_provisional")
        journal.append_event(
            attempt,
            source="client",
            event_sequence=0,
            event_type="RESULT",
            raw_time_ns=42,
            payload={"z": "x\ny", "a": 1},
        )
        journal.commit_microblock(primary, {trials[0]: {"raw": 7, "unit": "bytes"}})
        journal.store_artifact(
            IDENTITY["campaign_id"],
            "quality-audit.tsv",
            b"status\npublication_valid\n",
            media_type="text/tab-separated-values",
        )
        return journal

    def test_exports_and_checksums_are_byte_deterministic_and_ignore_stale_files(self) -> None:
        journal = self.committed_journal()
        first = journal.export(IDENTITY["campaign_id"], self.root)
        schedule_rows = (
            self.root / "artifacts" / "schedule.tsv"
        ).read_text(encoding="utf-8").splitlines()
        self.assertEqual(schedule_rows[0].split("\t")[5], "phase")
        self.assertEqual(
            {row.split("\t")[5] for row in schedule_rows[1:]},
            {"confirmatory"},
        )
        exported = {
            path.name: path.read_bytes()
            for path in (self.root / "artifacts").iterdir()
            if path.is_file() and not path.name.startswith("stale")
        }
        (self.root / "artifacts" / "stale-client.log").write_text("forged sample")
        second = journal.export(IDENTITY["campaign_id"], self.root)
        self.assertEqual(first, second)
        self.assertEqual(
            exported,
            {
                path.name: path.read_bytes()
                for path in (self.root / "artifacts").iterdir()
                if path.is_file() and not path.name.startswith("stale")
            },
        )
        checksum_lines = (self.root / "artifacts" / "checksums.sha256").read_text().splitlines()
        self.assertEqual(checksum_lines, sorted(checksum_lines, key=lambda line: line.split("  ", 1)[1]))
        for line in checksum_lines:
            digest, relative = line.split("  ", 1)
            self.assertEqual(
                digest,
                hashlib.sha256((self.root / "artifacts" / relative).read_bytes()).hexdigest(),
            )

    def test_export_fault_leaves_no_temporary_file_and_preserves_old_file(self) -> None:
        fault = Fault()
        journal = self.committed_journal(fault)
        journal.export(IDENTITY["campaign_id"], self.root)
        old = (self.root / "artifacts" / "samples.tsv").read_bytes()
        fault.point = "export.samples.tsv.before_rename"
        with self.assertRaises(InjectedFault):
            journal.export(IDENTITY["campaign_id"], self.root)
        self.assertEqual((self.root / "artifacts" / "samples.tsv").read_bytes(), old)
        self.assertEqual(list((self.root / "artifacts").glob(".*.tmp-*")), [])

    def test_hostile_artifact_paths_are_rejected(self) -> None:
        journal = self.committed_journal()
        for path in ("../escape", "/absolute", "a\\b"):
            with self.subTest(path=path), self.assertRaises(JournalError):
                journal.store_artifact(IDENTITY["campaign_id"], path, b"x")


if __name__ == "__main__":
    unittest.main()
