from __future__ import annotations

import errno
import hashlib
import os
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from quicperf_harness.canonical import loads_strict
from quicperf_harness.journal import (
    _MIGRATION_2_STATEMENTS,
    _SCHEMA_STATEMENTS,
    CardinalityError,
    Journal,
    JournalLockedError,
    SCHEMA_VERSION,
    StorageError,
)


def hid(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


IDENTITY = {
    "campaign_id": hid("fault-campaign"),
    "spec_hash": hid("fault-spec"),
    "identity_manifest_hash": hid("fault-manifest"),
    "analysis_plan_hash": hid("fault-analysis"),
    "schedule_hash": hid("fault-schedule"),
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


class JournalFaultTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def make_journal(
        self,
        directory: Path,
        fault: Fault | None = None,
        *,
        count: int = 2,
    ) -> tuple[Journal, list[str], list[str], str, str]:
        journal = Journal(directory / "journal.sqlite3", fault_injector=fault)
        journal.create_campaign(
            **IDENTITY,
            expected_cardinality=count,
            maximum_cardinality=2 * count,
            manifests={"identity": (hid("fault-identity-document"), {"host": "fixed"})},
            session_count=1,
        )
        cell = hid("fault-cell")
        primary = hid("fault-primary")
        retry = hid("fault-retry")
        journal.add_cell(IDENTITY["campaign_id"], cell, {"backend": "syscall"})
        journal.add_microblock(
            campaign_id=IDENTITY["campaign_id"],
            microblock_id=primary,
            session_number=1,
            ordinal=0,
            slot="primary",
            expected_trials=count,
        )
        journal.add_microblock(
            campaign_id=IDENTITY["campaign_id"],
            microblock_id=retry,
            session_number=1,
            ordinal=0,
            slot="retry",
            retry_for=primary,
            expected_trials=count,
        )
        primary_trials: list[str] = []
        retry_trials: list[str] = []
        for ordinal in range(count):
            trial = hid(f"fault-primary-trial-{ordinal}")
            retry_trial = hid(f"fault-retry-trial-{ordinal}")
            primary_trials.append(trial)
            retry_trials.append(retry_trial)
            journal.add_trial(
                campaign_id=IDENTITY["campaign_id"],
                trial_id=trial,
                microblock_id=primary,
                cell_id=cell,
                ordinal=ordinal,
            )
            journal.add_trial(
                campaign_id=IDENTITY["campaign_id"],
                trial_id=retry_trial,
                logical_trial_id=trial,
                microblock_id=retry,
                cell_id=cell,
                ordinal=ordinal,
            )
        journal.freeze_schedule(IDENTITY["campaign_id"])
        return journal, primary_trials, retry_trials, primary, retry

    def test_detailed_microblock_failure_is_atomic_at_every_transaction_boundary(
        self,
    ) -> None:
        for index, boundary in enumerate(
            ("before_begin", "after_begin", "before_commit", "after_commit")
        ):
            with self.subTest(boundary=boundary):
                directory = self.root / f"detailed-failure-{index}"
                directory.mkdir()
                fault = Fault()
                journal, trials, _, primary, _ = self.make_journal(
                    directory, fault, count=3
                )
                self.advance(journal, trials[0], "validated_provisional")
                self.advance(journal, trials[1], "measuring")
                before = [
                    tuple(row)
                    for row in journal.connection.execute(
                        """
                        SELECT t.state, a.state, a.termination_reason, a.details_json
                        FROM trial t LEFT JOIN attempt a USING(trial_id)
                        WHERE t.microblock_id=? ORDER BY t.ordinal
                        """,
                        (primary,),
                    )
                ]
                fault.point = f"microblock.fail.{boundary}"
                with self.assertRaises(InjectedFault):
                    journal.fail_microblock(
                        primary,
                        "unexpected_flow_control_blocking",
                        root_trial_id=trials[1],
                        root_detail='{"data_blocked":3}',
                    )
                journal.close()

                reopened = Journal(directory / "journal.sqlite3")
                try:
                    after = [
                        tuple(row)
                        for row in reopened.connection.execute(
                            """
                            SELECT t.state, a.state, a.termination_reason, a.details_json
                            FROM trial t LEFT JOIN attempt a USING(trial_id)
                            WHERE t.microblock_id=? ORDER BY t.ordinal
                            """,
                            (primary,),
                        )
                    ]
                    if boundary == "after_commit":
                        self.assertNotEqual(after, before)
                        self.assertEqual(
                            [row[2] for row in after],
                            [
                                "collateral_microblock_failure",
                                "unexpected_flow_control_blocking",
                                "collateral_microblock_failure",
                            ],
                        )
                    else:
                        self.assertEqual(after, before)
                    reopened.integrity_check()
                finally:
                    reopened.close()

    @staticmethod
    def advance(journal: Journal, trial: str, through: str) -> str:
        attempt = journal.ensure_attempt(trial)
        for state in (
            "starting",
            "ready",
            "armed",
            "measuring",
            "draining",
            "validating",
            "validated_provisional",
        ):
            journal.transition_attempt(attempt, state, raw_time_ns=100)
            if state == through:
                return attempt
        raise AssertionError(f"unknown state {through}")

    def test_migration_fault_after_every_schema_statement_leaves_version_zero(self) -> None:
        for index in range(len(_SCHEMA_STATEMENTS)):
            with self.subTest(statement=index):
                path = self.root / f"migration-{index}.sqlite3"
                with self.assertRaises(InjectedFault):
                    Journal(path, fault_injector=Fault(f"migration.1.statement.{index}"))
                raw = sqlite3.connect(path)
                try:
                    self.assertEqual(raw.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                    self.assertEqual(raw.execute("PRAGMA user_version").fetchone()[0], 0)
                    self.assertEqual(
                        raw.execute(
                            "SELECT COUNT(*) FROM sqlite_schema "
                            "WHERE type IN ('table','trigger') AND name NOT LIKE 'sqlite_%'"
                        ).fetchone()[0],
                        0,
                    )
                finally:
                    raw.close()

    @staticmethod
    def make_legacy_v1(path: Path) -> None:
        journal = Journal(path)
        journal.close()
        raw = sqlite3.connect(path)
        try:
            raw.execute("DROP TRIGGER frozen_microblock_identity")
            raw.execute("ALTER TABLE microblock DROP COLUMN williams_row")
            raw.execute("ALTER TABLE microblock DROP COLUMN superblock_id")
            raw.execute(
                """
                CREATE TRIGGER frozen_microblock_identity
                BEFORE UPDATE OF campaign_id, microblock_id, session_number, ordinal, slot,
                                 retry_for, phase, branch_group, branch_candidate,
                                 expected_trials ON microblock
                WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = OLD.campaign_id) = 1
                BEGIN
                    SELECT RAISE(ABORT, 'schedule is frozen');
                END
                """
            )
            for trigger in (
                "no_event_after_terminal",
                "immutable_manifest_insert_after_freeze",
                "immutable_transition_table_insert_after_initialization",
                "immutable_schema_meta_update",
                "immutable_schema_meta_delete",
                "immutable_schema_meta_insert_after_initialization",
            ):
                raw.execute(f"DROP TRIGGER {trigger}")
            raw.execute(
                """
                CREATE TRIGGER no_event_after_commit
                BEFORE INSERT ON event
                WHEN (SELECT state FROM attempt WHERE attempt_id = NEW.attempt_id) = 'committed'
                BEGIN
                    SELECT RAISE(ABORT, 'committed attempt accepts no events');
                END
                """
            )
            raw.execute(
                "UPDATE schema_meta SET value='1' WHERE key='schema_version'"
            )
            raw.execute("PRAGMA user_version=1")
            raw.commit()
        finally:
            raw.close()

    def test_v1_through_current_migration_is_atomic_at_every_v2_statement(self) -> None:
        for index in range(len(_MIGRATION_2_STATEMENTS)):
            with self.subTest(statement=index):
                path = self.root / f"v1-migration-{index}.sqlite3"
                self.make_legacy_v1(path)
                with self.assertRaises(InjectedFault):
                    Journal(path, fault_injector=Fault(f"migration.2.statement.{index}"))
                raw = sqlite3.connect(path)
                try:
                    self.assertEqual(raw.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                    self.assertEqual(raw.execute("PRAGMA user_version").fetchone()[0], 1)
                    self.assertEqual(
                        raw.execute(
                            "SELECT value FROM schema_meta WHERE key='schema_version'"
                        ).fetchone()[0],
                        "1",
                    )
                    self.assertIsNotNone(
                        raw.execute(
                            "SELECT 1 FROM sqlite_schema WHERE type='trigger' "
                            "AND name='no_event_after_commit'"
                        ).fetchone()
                    )
                finally:
                    raw.close()

        path = self.root / "v1-migration-success.sqlite3"
        self.make_legacy_v1(path)
        migrated = Journal(path)
        try:
            migrated.integrity_check()
            self.assertEqual(
                migrated.connection.execute("PRAGMA user_version").fetchone()[0],
                SCHEMA_VERSION,
            )
        finally:
            migrated.close()

    def test_run_directory_storage_faults_remove_partial_directory(self) -> None:
        points = (
            "run_directory.before_create",
            "run_directory.after_create",
            "run_directory.after_logs",
            "run_directory.after_artifacts",
            "run_directory.spec.json.before_open",
            "run_directory.spec.json.after_write",
            "run_directory.spec.json.before_fsync",
            "run_directory.spec.json.after_fsync",
            "run_directory.manifest.json.before_open",
            "run_directory.manifest.json.after_write",
            "run_directory.manifest.json.before_fsync",
            "run_directory.manifest.json.after_fsync",
            "run_directory.before_fsync",
            "run_directory.after_fsync",
            "run_directory.after_journal",
        )
        for index, point in enumerate(points):
            with self.subTest(point=point):
                run_dir = self.root / f"run-{index}"
                with self.assertRaises(InjectedFault):
                    Journal.create_run_directory(
                        run_dir,
                        spec_bytes=b"{}\n",
                        manifest_bytes=b"{}\n",
                        fault_injector=Fault(point),
                    )
                self.assertFalse(run_dir.exists())

    def test_lane_writers_are_derived_only_from_live_lock_owner(self) -> None:
        directory = self.root / "lane-writers"
        directory.mkdir()
        journal, *_ = self.make_journal(directory)
        reader = Journal(directory, writable=False)
        try:
            with self.assertRaises(JournalLockedError):
                with reader._lane_writer():
                    pass
            with journal._lane_writer() as first:
                first.store_artifact(
                    IDENTITY["campaign_id"], "lane-0.json", b"{}", media_type="application/json"
                )
                with self.assertRaises(JournalLockedError):
                    with first._lane_writer():
                        pass
                with journal._lane_writer() as second:
                    self.assertIsNot(first.connection, second.connection)
                    self.assertEqual(
                        second.connection.execute(
                            "SELECT COUNT(*) FROM artifact WHERE campaign_id=?",
                            (IDENTITY["campaign_id"],),
                        ).fetchone()[0],
                        1,
                    )
                with self.assertRaises(JournalLockedError):
                    Journal(directory)
            with self.assertRaises(JournalLockedError):
                Journal(directory)
            journal.integrity_check()
        finally:
            reader.close()
            journal.close()
        with self.assertRaises(JournalLockedError):
            with journal._lane_writer():
                pass

    def test_fork_cannot_inherit_lane_writer_authority(self) -> None:
        directory = self.root / "forked-lane-writer"
        directory.mkdir()
        journal, *_ = self.make_journal(directory)
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                try:
                    with journal._lane_writer():
                        result = b"bypassed"
                except JournalLockedError:
                    result = b"rejected"
                os.write(write_fd, result)
            finally:
                os.close(write_fd)
                os._exit(0)
        os.close(write_fd)
        try:
            self.assertEqual(os.read(read_fd, 32), b"rejected")
            _, status = os.waitpid(child, 0)
            self.assertEqual(status, 0)
            with journal._lane_writer() as writer:
                writer.integrity_check()
        finally:
            os.close(read_fd)
            journal.close()

    def test_lane_threads_use_distinct_serialized_sqlite_writers(self) -> None:
        directory = self.root / "threaded-lane-writers"
        directory.mkdir()
        journal, *_ = self.make_journal(directory)
        barrier = threading.Barrier(2)
        failures: list[BaseException] = []

        def lane(index: int) -> None:
            try:
                with journal._lane_writer() as writer:
                    barrier.wait(timeout=2)
                    writer.store_artifact(
                        IDENTITY["campaign_id"],
                        f"lane-{index}.json",
                        f'{{"lane":{index}}}'.encode(),
                        media_type="application/json",
                    )
            except BaseException as exc:
                failures.append(exc)

        threads = [threading.Thread(target=lane, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        try:
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(failures, [])
            self.assertEqual(
                journal.connection.execute(
                    "SELECT COUNT(*) FROM artifact WHERE path LIKE 'lane-%.json'"
                ).fetchone()[0],
                2,
            )
            journal.integrity_check()
        finally:
            journal.close()

    def test_real_sigkill_preserves_wal_and_recovers_whole_microblock(self) -> None:
        directory = self.root / "sigkill-wal"
        directory.mkdir()
        journal, primary_trials, retry_trials, primary, retry = self.make_journal(
            directory
        )
        journal.close()
        child_code = """
import sys
import time
from quicperf_harness.journal import Journal

journal = Journal(sys.argv[1])
attempt = journal.ensure_attempt(sys.argv[2])
for state in ("starting", "ready", "armed", "measuring"):
    journal.transition_attempt(attempt, state, raw_time_ns=100)
print(attempt, flush=True)
time.sleep(30)
"""
        process = subprocess.Popen(
            [sys.executable, "-c", child_code, str(directory), primary_trials[0]],
            cwd=Path(__file__).resolve().parents[1],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert process.stdout is not None
            ready, _, _ = select.select([process.stdout], [], [], 5)
            self.assertTrue(ready, "child did not durably enter measuring within five seconds")
            attempt = process.stdout.readline().strip()
            self.assertEqual(len(attempt), 64)
            os.kill(process.pid, signal.SIGKILL)
            self.assertEqual(process.wait(timeout=5), -signal.SIGKILL)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

        reopened = Journal(directory)
        try:
            self.assertEqual(
                reopened.connection.execute(
                    "SELECT state FROM attempt WHERE attempt_id=?", (attempt,)
                ).fetchone()[0],
                "measuring",
            )
            self.assertEqual(
                reopened.recover(IDENTITY["campaign_id"]),
                {"untouched": 0, "retried": 1, "retry_failed": 0},
            )
            statuses = dict(
                reopened.connection.execute(
                    "SELECT microblock_id, status FROM microblock"
                )
            )
            self.assertEqual(statuses[primary], "superseded")
            self.assertEqual(statuses[retry], "active")
            self.assertEqual(
                reopened.connection.execute(
                    "SELECT state FROM attempt WHERE attempt_id=?", (attempt,)
                ).fetchone()[0],
                "interrupted",
            )
            self.assertEqual(
                reopened.connection.execute(
                    "SELECT COUNT(*) FROM trial WHERE microblock_id=? AND state='planned'",
                    (retry,),
                ).fetchone()[0],
                len(retry_trials),
            )
            reopened.integrity_check()
        finally:
            reopened.close()

    def test_real_concurrent_reader_is_allowed_and_second_coordinator_rejected(self) -> None:
        directory = self.root / "process-lock"
        directory.mkdir()
        journal, *_ = self.make_journal(directory)
        child_code = """
import sys
from quicperf_harness.journal import Journal, JournalLockedError

reader = Journal(sys.argv[1], writable=False)
try:
    reader.connection.execute("SELECT COUNT(*) FROM campaign").fetchone()
finally:
    reader.close()
try:
    Journal(sys.argv[1])
except JournalLockedError:
    print("reader-ok writer-rejected")
    raise SystemExit(0)
raise SystemExit(3)
"""
        try:
            completed = subprocess.run(
                [sys.executable, "-c", child_code, str(directory)],
                cwd=Path(__file__).resolve().parents[1],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "reader-ok writer-rejected")
            journal.integrity_check()
        finally:
            journal.close()

    def test_os_fsync_failure_removes_partial_run_directory(self) -> None:
        run_dir = self.root / "fsync-enospc"
        failure = OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
        with mock.patch("quicperf_harness.journal.os.fsync", side_effect=failure):
            with self.assertRaisesRegex(OSError, "No space left on device"):
                Journal.create_run_directory(
                    run_dir, spec_bytes=b"{}\n", manifest_bytes=b"{}\n"
                )
        self.assertFalse(run_dir.exists())

    def test_commit_errno_and_sqlite_full_roll_back_without_partial_artifact(self) -> None:
        directory = self.root / "storage-errors"
        directory.mkdir()
        fault = Fault()
        journal, *_ = self.make_journal(directory, fault)
        try:
            def fail_commit(point: str) -> None:
                if point == "artifact.store.before_commit":
                    raise OSError(errno.EIO, os.strerror(errno.EIO))

            journal._fault_injector = fail_commit
            with self.assertRaisesRegex(OSError, "Input/output error"):
                journal.store_artifact(
                    IDENTITY["campaign_id"], "commit-error.bin", b"not durable"
                )
            self.assertEqual(
                journal.connection.execute(
                    "SELECT COUNT(*) FROM artifact WHERE path='commit-error.bin'"
                ).fetchone()[0],
                0,
            )

            journal._fault_injector = None
            page_count = int(
                journal.connection.execute("PRAGMA page_count").fetchone()[0]
            )
            journal.connection.execute(f"PRAGMA max_page_count={page_count}")
            with self.assertRaises(sqlite3.OperationalError):
                journal.store_artifact(
                    IDENTITY["campaign_id"], "sqlite-full.bin", b"x" * (8 * 1024 * 1024)
                )
            self.assertEqual(
                journal.connection.execute(
                    "SELECT COUNT(*) FROM artifact WHERE path='sqlite-full.bin'"
                ).fetchone()[0],
                0,
            )
            journal.integrity_check()
        finally:
            journal.close()

    def test_all_primary_transaction_families_are_atomic_at_each_boundary(self) -> None:
        cell = hid("transaction-cell")
        primary = hid("transaction-primary")
        retry = hid("transaction-retry")
        trial = hid("transaction-trial")
        retry_trial = hid("transaction-retry-trial")

        def create_empty(directory: Path, fault: Fault) -> Journal:
            return Journal(directory / "journal.sqlite3", fault_injector=fault)

        def create_campaign_only(directory: Path, fault: Fault) -> Journal:
            journal = create_empty(directory, fault)
            journal.create_campaign(
                **IDENTITY,
                expected_cardinality=1,
                maximum_cardinality=2,
                retry_per_microblock=1,
                manifests={
                    "identity": (hid("transaction-identity"), {"host": "fixed"})
                },
                session_count=1,
            )
            return journal

        cells = {cell: {"backend": "syscall"}}
        blocks = [
            {
                "microblock_id": primary,
                "session_number": 1,
                "ordinal": 0,
                "slot": "primary",
                "expected_trials": 1,
            },
            {
                "microblock_id": retry,
                "session_number": 1,
                "ordinal": 0,
                "slot": "retry",
                "retry_for": primary,
                "expected_trials": 1,
            },
        ]
        trials = [
            {
                "trial_id": trial,
                "logical_trial_id": trial,
                "microblock_id": primary,
                "cell_id": cell,
                "ordinal": 0,
            },
            {
                "trial_id": retry_trial,
                "logical_trial_id": trial,
                "microblock_id": retry,
                "cell_id": cell,
                "ordinal": 0,
            },
        ]

        def populated(directory: Path, fault: Fault, *, frozen: bool = True) -> Journal:
            journal = create_campaign_only(directory, fault)
            journal.populate_schedule(
                IDENTITY["campaign_id"], cells=cells, microblocks=blocks, trials=trials
            )
            if frozen:
                journal.freeze_schedule(IDENTITY["campaign_id"])
            return journal

        def campaign_case(directory: Path, fault: Fault):
            journal = create_empty(directory, fault)

            def action() -> None:
                journal.create_campaign(
                    **IDENTITY,
                    expected_cardinality=0,
                    maximum_cardinality=0,
                    retry_per_microblock=0,
                    manifests={
                        "identity": (hid("transaction-empty"), {"host": "fixed"})
                    },
                    session_count=1,
                )

            return journal, action, lambda current: current.connection.execute(
                "SELECT COUNT(*) FROM campaign"
            ).fetchone()[0]

        def populate_case(directory: Path, fault: Fault):
            journal = create_campaign_only(directory, fault)
            action = lambda: journal.populate_schedule(
                IDENTITY["campaign_id"], cells=cells, microblocks=blocks, trials=trials
            )
            snapshot = lambda current: tuple(
                current.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("cell", "microblock", "trial")
            )
            return journal, action, snapshot

        def freeze_case(directory: Path, fault: Fault):
            journal = populated(directory, fault, frozen=False)
            action = lambda: journal.freeze_schedule(IDENTITY["campaign_id"])
            snapshot = lambda current: current.connection.execute(
                "SELECT schedule_frozen FROM campaign"
            ).fetchone()[0]
            return journal, action, snapshot

        def attempt_case(directory: Path, fault: Fault):
            journal = populated(directory, fault)
            action = lambda: journal.ensure_attempt(trial)
            snapshot = lambda current: current.connection.execute(
                "SELECT COUNT(*) FROM attempt"
            ).fetchone()[0]
            return journal, action, snapshot

        def event_case(directory: Path, fault: Fault):
            journal = populated(directory, fault)
            attempt = journal.ensure_attempt(trial)
            journal.transition_attempt(attempt, "starting", raw_time_ns=100)
            action = lambda: journal.append_event(
                attempt,
                source="server",
                event_sequence=0,
                event_type="READY",
                raw_time_ns=100,
                payload={},
            )
            snapshot = lambda current: current.connection.execute(
                "SELECT COUNT(*) FROM event"
            ).fetchone()[0]
            return journal, action, snapshot

        def failure_case(directory: Path, fault: Fault):
            journal = populated(directory, fault)
            action = lambda: journal.fail_microblock(primary, "deterministic failure")

            def snapshot(current: Journal):
                return (
                    current.connection.execute(
                        "SELECT status FROM microblock WHERE microblock_id=?", (primary,)
                    ).fetchone()[0],
                    current.connection.execute(
                        "SELECT status FROM session"
                    ).fetchone()[0],
                    current.connection.execute(
                        "SELECT state FROM trial WHERE trial_id=?", (trial,)
                    ).fetchone()[0],
                )

            return journal, action, snapshot

        def session_case(directory: Path, fault: Fault):
            journal = populated(directory, fault)
            action = lambda: journal.set_session_status(
                IDENTITY["campaign_id"], 1, "running"
            )
            snapshot = lambda current: current.connection.execute(
                "SELECT status FROM session"
            ).fetchone()[0]
            return journal, action, snapshot

        def campaign_status_case(directory: Path, fault: Fault):
            journal = populated(directory, fault)
            action = lambda: journal.set_campaign_status(
                IDENTITY["campaign_id"], "analyzed"
            )
            snapshot = lambda current: current.connection.execute(
                "SELECT status FROM campaign"
            ).fetchone()[0]
            return journal, action, snapshot

        def artifact_case(directory: Path, fault: Fault):
            journal = populated(directory, fault)
            action = lambda: journal.store_artifact(
                IDENTITY["campaign_id"], "one.bin", b"one"
            )
            snapshot = lambda current: current.connection.execute(
                "SELECT COUNT(*) FROM artifact"
            ).fetchone()[0]
            return journal, action, snapshot

        def artifact_generation_case(directory: Path, fault: Fault):
            journal = populated(directory, fault)
            action = lambda: journal.store_artifacts(
                IDENTITY["campaign_id"],
                {
                    "one.bin": (b"one", "application/octet-stream"),
                    "two.bin": (b"two", "application/octet-stream"),
                },
                campaign_status="analyzed",
            )
            snapshot = lambda current: (
                current.connection.execute("SELECT COUNT(*) FROM artifact").fetchone()[0],
                current.connection.execute("SELECT status FROM campaign").fetchone()[0],
            )
            return journal, action, snapshot

        cases = {
            "campaign.create": campaign_case,
            "schedule.populate": populate_case,
            "schedule.freeze": freeze_case,
            "attempt.ensure": attempt_case,
            "event.append": event_case,
            "microblock.fail": failure_case,
            "session.status": session_case,
            "campaign.status": campaign_status_case,
            "artifact.store": artifact_case,
            "artifact.store_generation": artifact_generation_case,
        }
        for case_index, (point, factory) in enumerate(cases.items()):
            for boundary in (
                "before_begin",
                "after_begin",
                "before_commit",
                "after_commit",
            ):
                with self.subTest(point=point, boundary=boundary):
                    directory = self.root / f"write-{case_index}-{boundary}"
                    directory.mkdir()
                    fault = Fault()
                    journal, action, snapshot = factory(directory, fault)
                    before = snapshot(journal)
                    fault.point = f"{point}.{boundary}"
                    with self.assertRaises(InjectedFault):
                        action()
                    journal.close()
                    reopened = Journal(directory)
                    try:
                        after = snapshot(reopened)
                        if boundary == "after_commit":
                            self.assertNotEqual(after, before)
                        else:
                            self.assertEqual(after, before)
                        reopened.integrity_check()
                    finally:
                        reopened.close()

    def test_artifact_generation_rolls_back_at_each_member_write(self) -> None:
        directory = self.root / "artifact-generation-member"
        directory.mkdir()
        fault = Fault()
        journal, *_ = self.make_journal(directory, fault)
        try:
            journal.store_artifact(
                IDENTITY["campaign_id"], "existing.bin", b"existing"
            )
            fault.point = "artifact.store_generation.after_artifact"
            with self.assertRaises(InjectedFault):
                journal.store_artifacts(
                    IDENTITY["campaign_id"],
                    {
                        "one.bin": (b"one", "application/octet-stream"),
                        "two.bin": (b"two", "application/octet-stream"),
                    },
                    campaign_status="analyzed",
                )
            self.assertEqual(
                [
                    tuple(row)
                    for row in journal.connection.execute(
                        "SELECT path, content FROM artifact ORDER BY path"
                    )
                ],
                [("existing.bin", b"existing")],
            )
            self.assertEqual(
                journal.connection.execute(
                    "SELECT status FROM campaign"
                ).fetchone()[0],
                "planned",
            )
            journal.integrity_check()
        finally:
            journal.close()

    def test_transition_fault_boundaries_are_restart_idempotent(self) -> None:
        points = (
            "transition.ready.before",
            "transition.ready.before_begin",
            "transition.ready.after_begin",
            "transition.ready.before_commit",
            "transition.ready.after_commit",
            "transition.ready.after",
        )
        for index, point in enumerate(points):
            with self.subTest(point=point):
                directory = self.root / f"transition-{index}"
                directory.mkdir()
                fault = Fault()
                journal, trials, _, _, _ = self.make_journal(directory, fault)
                attempt = self.advance(journal, trials[0], "starting")
                fault.point = point
                with self.assertRaises(InjectedFault):
                    journal.transition_attempt(attempt, "ready", raw_time_ns=101)
                journal.close()
                reopened = Journal(directory)
                try:
                    durable = point in {"transition.ready.after_commit", "transition.ready.after"}
                    expected = "ready" if durable else "starting"
                    self.assertEqual(
                        reopened.connection.execute(
                            "SELECT state FROM attempt WHERE attempt_id=?", (attempt,)
                        ).fetchone()[0],
                        expected,
                    )
                    reopened.transition_attempt(attempt, "ready", raw_time_ns=101)
                    self.assertEqual(
                        reopened.connection.execute("SELECT COUNT(*) FROM attempt").fetchone()[0],
                        1,
                    )
                    reopened.assert_identity(**IDENTITY)
                finally:
                    reopened.close()

    def test_microblock_commit_fault_boundaries_never_leave_partial_samples(self) -> None:
        points = (
            "transition.committed.before",
            "microblock.commit.before_begin",
            "microblock.commit.after_begin",
            "microblock.commit.after_states",
            "microblock.commit.after_sample",
            "microblock.commit.before_commit",
            "microblock.commit.after_commit",
            "transition.committed.after",
        )
        for index, point in enumerate(points):
            with self.subTest(point=point):
                directory = self.root / f"commit-{index}"
                directory.mkdir()
                fault = Fault()
                journal, trials, _, primary, _ = self.make_journal(directory, fault)
                for trial in trials:
                    self.advance(journal, trial, "validated_provisional")
                samples = {trial: {"raw": ordinal} for ordinal, trial in enumerate(trials)}
                fault.point = point
                with self.assertRaises(InjectedFault):
                    journal.commit_microblock(primary, samples, committed_ns=999)
                journal.close()
                reopened = Journal(directory)
                try:
                    durable = point in {
                        "microblock.commit.after_commit",
                        "transition.committed.after",
                    }
                    self.assertEqual(
                        reopened.connection.execute("SELECT COUNT(*) FROM sample").fetchone()[0],
                        2 if durable else 0,
                    )
                    reopened.commit_microblock(primary, samples, committed_ns=999)
                    reopened.assert_exact_cardinality(IDENTITY["campaign_id"])
                    reopened.integrity_check()
                finally:
                    reopened.close()

    def test_recovery_fault_boundaries_activate_exactly_one_complete_retry(self) -> None:
        points = (
            "recovery.before_begin",
            "recovery.after_begin",
            "recovery.before_commit",
            "recovery.after_commit",
        )
        for index, point in enumerate(points):
            with self.subTest(point=point):
                directory = self.root / f"recovery-{index}"
                directory.mkdir()
                fault = Fault()
                journal, primary_trials, retry_trials, primary, retry = self.make_journal(
                    directory, fault
                )
                self.advance(journal, primary_trials[0], "measuring")
                fault.point = point
                with self.assertRaises(InjectedFault):
                    journal.recover(IDENTITY["campaign_id"])
                journal.close()
                reopened = Journal(directory)
                try:
                    reopened.recover(IDENTITY["campaign_id"])
                    statuses = dict(
                        reopened.connection.execute(
                            "SELECT microblock_id, status FROM microblock"
                        )
                    )
                    self.assertEqual(statuses[primary], "superseded")
                    self.assertEqual(statuses[retry], "active")
                    self.assertEqual(
                        reopened.connection.execute(
                            "SELECT COUNT(*) FROM attempt WHERE state='interrupted'"
                        ).fetchone()[0],
                        1,
                    )
                    self.assertEqual(
                        reopened.connection.execute(
                            "SELECT COUNT(*) FROM trial WHERE microblock_id=? AND state='planned'",
                            (retry,),
                        ).fetchone()[0],
                        len(retry_trials),
                    )
                    reopened.integrity_check()
                finally:
                    reopened.close()

    def test_hardware_invalidation_faults_preserve_atomic_archived_evidence(self) -> None:
        points = (
            "session.hardware_unqualified.before_begin",
            "session.hardware_unqualified.after_begin",
            "session.hardware_unqualified.before_commit",
            "session.hardware_unqualified.after_commit",
        )
        for index, point in enumerate(points):
            with self.subTest(point=point):
                directory = self.root / f"hardware-unqualified-{index}"
                directory.mkdir()
                fault = Fault()
                journal, primary_trials, _retry_trials, primary, _retry = (
                    self.make_journal(directory, fault)
                )
                for trial in primary_trials:
                    self.advance(journal, trial, "validated_provisional")
                samples = {
                    trial: {"preserved": ordinal + 1}
                    for ordinal, trial in enumerate(primary_trials)
                }
                journal.commit_microblock(primary, samples)
                fault.point = point
                with self.assertRaises(InjectedFault):
                    journal.invalidate_session_hardware(
                        IDENTITY["campaign_id"],
                        1,
                        "tctl_thermal_headroom_breach",
                        {"provider": "amd_delivered_performance_v1"},
                    )
                journal.close()
                reopened = Journal(directory)
                try:
                    durable = point == "session.hardware_unqualified.after_commit"
                    self.assertEqual(
                        reopened.connection.execute(
                            "SELECT COUNT(*) FROM committed_sample"
                        ).fetchone()[0],
                        0 if durable else 2,
                    )
                    reopened.invalidate_session_hardware(
                        IDENTITY["campaign_id"],
                        1,
                        "tctl_thermal_headroom_breach",
                        {"provider": "amd_delivered_performance_v1"},
                    )
                    artifact = reopened.connection.execute(
                        """
                        SELECT content FROM artifact
                        WHERE campaign_id=? AND path=?
                        """,
                        (
                            IDENTITY["campaign_id"],
                            "runtime/session-1-hardware-unqualified.json",
                        ),
                    ).fetchone()
                    self.assertIsNotNone(artifact)
                    content = bytes(artifact[0])
                    document = loads_strict(content)
                    preserved = {
                        loads_strict(row["sample_json"])["preserved"]
                        for row in document["journal_evidence"]
                        if row["sample_json"] is not None
                    }
                    self.assertEqual(preserved, {1, 2})
                    self.assertEqual(
                        reopened.connection.execute(
                            "SELECT COUNT(*) FROM committed_sample"
                        ).fetchone()[0],
                        0,
                    )
                    reopened.integrity_check()
                finally:
                    reopened.close()

    def test_lane_scoped_recovery_does_not_interrupt_another_active_lane(self) -> None:
        directory = self.root / "scoped-lane-recovery"
        directory.mkdir()
        journal = Journal(directory / "journal.sqlite3")
        campaign = IDENTITY["campaign_id"]
        journal.create_campaign(
            **IDENTITY,
            expected_cardinality=2,
            maximum_cardinality=4,
            manifests={"identity": (hid("scoped-identity"), {"host": "fixed"})},
            session_count=1,
        )
        cell = hid("scoped-cell")
        journal.add_cell(campaign, cell, {"backend": "syscall"})
        blocks: list[tuple[str, str, str, str]] = []
        for lane in range(2):
            primary = hid(f"scoped-primary-{lane}")
            retry = hid(f"scoped-retry-{lane}")
            trial = hid(f"scoped-trial-{lane}")
            retry_trial = hid(f"scoped-retry-trial-{lane}")
            journal.add_microblock(
                campaign_id=campaign,
                microblock_id=primary,
                session_number=1,
                ordinal=lane,
                slot="primary",
                expected_trials=1,
            )
            journal.add_microblock(
                campaign_id=campaign,
                microblock_id=retry,
                session_number=1,
                ordinal=lane,
                slot="retry",
                retry_for=primary,
                expected_trials=1,
            )
            journal.add_trial(
                campaign_id=campaign,
                trial_id=trial,
                microblock_id=primary,
                cell_id=cell,
                ordinal=0,
            )
            journal.add_trial(
                campaign_id=campaign,
                trial_id=retry_trial,
                logical_trial_id=trial,
                microblock_id=retry,
                cell_id=cell,
                ordinal=0,
            )
            blocks.append((primary, retry, trial, retry_trial))
        journal.freeze_schedule(campaign)
        first_attempt = self.advance(journal, blocks[0][2], "measuring")
        second_attempt = self.advance(journal, blocks[1][2], "measuring")
        result = journal.recover(campaign, microblock_id=blocks[0][0])
        self.assertEqual(result, {"untouched": 0, "retried": 1, "retry_failed": 0})
        states = dict(
            journal.connection.execute(
                "SELECT microblock_id, status FROM microblock"
            )
        )
        self.assertEqual(states[blocks[0][0]], "superseded")
        self.assertEqual(states[blocks[0][1]], "active")
        self.assertEqual(states[blocks[1][0]], "active")
        self.assertEqual(states[blocks[1][1]], "dormant")
        self.assertEqual(
            journal.connection.execute(
                "SELECT state FROM attempt WHERE attempt_id=?", (first_attempt,)
            ).fetchone()[0],
            "interrupted",
        )
        self.assertEqual(
            journal.connection.execute(
                "SELECT state FROM attempt WHERE attempt_id=?", (second_attempt,)
            ).fetchone()[0],
            "measuring",
        )
        journal.integrity_check()
        journal.close()

    def test_terminal_attempts_reject_late_events_and_policy_mutation(self) -> None:
        terminal_states = (
            "unsupported",
            "invalid",
            "failed",
            "interrupted",
            "cancelled",
            "superseded_incomplete_microblock",
        )
        for index, terminal in enumerate(terminal_states):
            with self.subTest(state=terminal):
                directory = self.root / f"terminal-{index}"
                directory.mkdir()
                journal, trials, _, _, _ = self.make_journal(directory)
                try:
                    attempt = self.advance(journal, trials[0], "starting")
                    journal.transition_attempt(attempt, terminal)
                    with self.assertRaises(sqlite3.IntegrityError):
                        journal.append_event(
                            attempt,
                            source="server",
                            event_sequence=0,
                            event_type="LATE",
                            raw_time_ns=1,
                            payload={},
                        )
                finally:
                    journal.close()

        directory = self.root / "policy"
        directory.mkdir()
        journal, *_ = self.make_journal(directory)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                journal.connection.execute(
                    "INSERT INTO state_transition(from_state,to_state) VALUES ('committed','planned')"
                )
            with self.assertRaises(sqlite3.IntegrityError):
                journal.connection.execute(
                    "UPDATE schema_meta SET value='forged' WHERE key='product'"
                )
            with self.assertRaises(sqlite3.IntegrityError):
                journal.connection.execute(
                    "INSERT INTO manifest(campaign_id,kind,manifest_hash,canonical_json) "
                    "VALUES (?, 'late', ?, '{}')",
                    (IDENTITY["campaign_id"], hid("late")),
                )
        finally:
            journal.close()

    def test_integrity_and_export_reject_application_checksum_corruption(self) -> None:
        directory = self.root / "corrupt"
        directory.mkdir()
        journal, trials, _, primary, _ = self.make_journal(directory)
        try:
            attempts = [
                self.advance(journal, trial, "validated_provisional") for trial in trials
            ]
            journal.connection.execute(
                "INSERT INTO microblock_commit_guard(microblock_id) VALUES (?)", (primary,)
            )
            for trial, attempt in zip(trials, attempts):
                journal.connection.execute(
                    "UPDATE attempt SET state='committed', ended_ns=999 WHERE attempt_id=?",
                    (attempt,),
                )
                journal.connection.execute(
                    "UPDATE trial SET state='committed' WHERE trial_id=?", (trial,)
                )
                journal.connection.execute(
                    "INSERT INTO sample(trial_id,logical_trial_id,attempt_id,sample_json,"
                    "sample_sha256,committed_ns) VALUES (?,?,?,?,?,999)",
                    (trial, trial, attempt, '{"raw":1}', "0" * 64),
                )
            journal.connection.execute(
                "UPDATE microblock SET status='committed' WHERE microblock_id=?", (primary,)
            )
            journal.connection.execute(
                "DELETE FROM microblock_commit_guard WHERE microblock_id=?", (primary,)
            )
            with self.assertRaises(StorageError):
                journal.integrity_check()
            with self.assertRaises(StorageError):
                journal.export(IDENTITY["campaign_id"], directory)
        finally:
            journal.close()

    def test_export_faults_leave_no_temp_and_rerender_byte_identically(self) -> None:
        directory = self.root / "export"
        directory.mkdir()
        fault = Fault()
        journal, trials, _, primary, _ = self.make_journal(directory, fault)
        for trial in trials:
            self.advance(journal, trial, "validated_provisional")
        journal.commit_microblock(primary, {trial: {"raw": 1} for trial in trials})
        journal.export(IDENTITY["campaign_id"], directory)
        baseline = {
            path.relative_to(directory / "artifacts").as_posix(): path.read_bytes()
            for path in (directory / "artifacts").rglob("*")
            if path.is_file()
        }
        try:
            for point in (
                "export.schedule.tsv.before_write",
                "export.schedule.tsv.before_fsync",
                "export.schedule.tsv.before_rename",
                "export.schedule.tsv.after_replace",
                "export.schedule.tsv.before_directory_fsync",
                "export.schedule.tsv.after_directory_fsync",
                "export.schedule.tsv.after_rename",
            ):
                with self.subTest(point=point):
                    fault.point = point
                    with self.assertRaises(InjectedFault):
                        journal.export(IDENTITY["campaign_id"], directory)
                    self.assertEqual(list((directory / "artifacts").glob(".*.tmp-*")), [])
                    fault.point = None
                    journal.export(IDENTITY["campaign_id"], directory)
                    observed = {
                        path.relative_to(directory / "artifacts").as_posix(): path.read_bytes()
                        for path in (directory / "artifacts").rglob("*")
                        if path.is_file()
                    }
                    self.assertEqual(observed, baseline)
        finally:
            journal.close()


if __name__ == "__main__":
    unittest.main()
