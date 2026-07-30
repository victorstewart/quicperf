"""Transactional journal and deterministic export for the v2 harness.

The SQLite database is the only authority for execution state.  Files below a
run directory are outputs: neither recovery nor export reads them to infer what
happened.
"""

from __future__ import annotations

import contextlib
import csv
import fcntl
import hashlib
import io
import json
import os
import shutil
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_bytes, loads_strict
from .errors import HarnessError, IdentityMismatchError
from .identity import attempt_id as _identity_attempt_id
from .identity import domain_hash


SCHEMA_VERSION = 4
SQLITE_BUSY_TIMEOUT_MS = 5_000

ACTIVE_STATES = (
    "planned",
    "starting",
    "ready",
    "armed",
    "measuring",
    "draining",
    "validating",
    "validated_provisional",
)
TERMINAL_STATES = (
    "committed",
    "unsupported",
    "invalid",
    "failed",
    "interrupted",
    "cancelled",
    "superseded_incomplete_microblock",
)
ALL_STATES = ACTIVE_STATES + TERMINAL_STATES

_FORWARD_STATES = (
    "planned",
    "starting",
    "ready",
    "armed",
    "measuring",
    "draining",
    "validating",
    "validated_provisional",
    "committed",
)
_FAILURE_STATES = (
    "unsupported",
    "invalid",
    "failed",
    "interrupted",
    "cancelled",
)

_REQUIRED_TABLES = {
    "schema_meta",
    "campaign",
    "session",
    "manifest",
    "cell",
    "microblock",
    "trial",
    "state_transition",
    "attempt",
    "event",
    "sample",
    "artifact",
    "microblock_commit_guard",
}

_REQUIRED_TRIGGERS = {
    "attempt_state_transition",
    "campaign_cannot_unfreeze",
    "frozen_cell_delete",
    "frozen_cell_insert",
    "frozen_cell_update",
    "frozen_microblock_delete",
    "frozen_microblock_identity",
    "frozen_microblock_insert",
    "frozen_trial_delete",
    "frozen_trial_identity",
    "frozen_trial_insert",
    "guarded_attempt_commit",
    "guarded_microblock_commit",
    "guarded_sample_insert",
    "guarded_trial_commit",
    "immutable_attempt_identity",
    "immutable_campaign_identity",
    "immutable_committed_microblock_delete",
    "immutable_committed_microblock_update",
    "immutable_event_delete",
    "immutable_event_update",
    "immutable_manifest_delete",
    "immutable_manifest_insert_after_freeze",
    "immutable_manifest_update",
    "immutable_sample_delete",
    "immutable_sample_update",
    "immutable_schema_meta_delete",
    "immutable_schema_meta_insert_after_initialization",
    "immutable_schema_meta_update",
    "immutable_terminal_attempt",
    "immutable_terminal_trial",
    "immutable_transition_table_delete",
    "immutable_transition_table_insert_after_initialization",
    "immutable_transition_table_update",
    "no_event_after_terminal",
    "trial_state_transition",
    "undeletable_terminal_attempt",
    "undeletable_terminal_trial",
}


class JournalError(HarnessError):
    """Base class for journal failures."""


class JournalLockedError(JournalError):
    """Another coordinator owns the database writer lock."""


class IllegalTransitionError(JournalError):
    """An attempt or trial requested a forbidden state transition."""


class CardinalityError(JournalError):
    """The frozen or committed schedule has the wrong cardinality."""


class StorageError(JournalError):
    """SQLite integrity or durable-file output failed."""


FaultInjector = Callable[[str], None]


def _canonical_json(value: Any) -> str:
    try:
        return canonical_bytes(value).decode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise JournalError(f"value is not canonical JSON: {exc}") from exc


def _require_hash_id(name: str, value: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise JournalError(f"{name} must be a 64-character SHA-256 hex digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise JournalError(f"{name} must be a SHA-256 hex digest") from exc
    return value.lower()


def derive_attempt_id(trial_id: str, attempt_number: int = 0) -> str:
    _require_hash_id("trial_id", trial_id)
    return _identity_attempt_id(trial_id, attempt_number)


def _transition_rows() -> tuple[tuple[str, str], ...]:
    rows: list[tuple[str, str]] = []
    for current, following in zip(_FORWARD_STATES, _FORWARD_STATES[1:]):
        rows.append((current, following))
    for state in ACTIVE_STATES:
        for terminal in _FAILURE_STATES:
            rows.append((state, terminal))
        rows.append((state, "superseded_incomplete_microblock"))
    return tuple(dict.fromkeys(rows))


_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE campaign (
        campaign_id TEXT PRIMARY KEY,
        singleton INTEGER NOT NULL DEFAULT 1 UNIQUE CHECK(singleton = 1),
        spec_hash TEXT NOT NULL,
        identity_manifest_hash TEXT NOT NULL,
        analysis_plan_hash TEXT NOT NULL,
        schedule_hash TEXT NOT NULL,
        campaign_kind TEXT NOT NULL DEFAULT 'fixed',
        expected_cardinality INTEGER NOT NULL CHECK(expected_cardinality >= 0),
        maximum_cardinality INTEGER NOT NULL CHECK(maximum_cardinality >= expected_cardinality),
        retry_per_microblock INTEGER NOT NULL DEFAULT 1 CHECK(retry_per_microblock IN (0, 1)),
        schedule_frozen INTEGER NOT NULL DEFAULT 0 CHECK(schedule_frozen IN (0, 1)),
        status TEXT NOT NULL DEFAULT 'created',
        created_ns INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE session (
        campaign_id TEXT NOT NULL REFERENCES campaign(campaign_id),
        session_number INTEGER NOT NULL CHECK(session_number > 0),
        status TEXT NOT NULL DEFAULT 'planned',
        infrastructure_failures INTEGER NOT NULL DEFAULT 0
            CHECK(infrastructure_failures >= 0),
        PRIMARY KEY(campaign_id, session_number)
    )
    """,
    """
    CREATE TABLE manifest (
        campaign_id TEXT NOT NULL REFERENCES campaign(campaign_id),
        kind TEXT NOT NULL,
        manifest_hash TEXT NOT NULL,
        canonical_json TEXT NOT NULL,
        PRIMARY KEY(campaign_id, kind)
    )
    """,
    """
    CREATE TABLE cell (
        campaign_id TEXT NOT NULL REFERENCES campaign(campaign_id),
        cell_id TEXT NOT NULL,
        canonical_config TEXT NOT NULL,
        PRIMARY KEY(campaign_id, cell_id)
    )
    """,
    """
    CREATE TABLE microblock (
        campaign_id TEXT NOT NULL REFERENCES campaign(campaign_id),
        microblock_id TEXT PRIMARY KEY,
        session_number INTEGER NOT NULL,
        ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
        slot TEXT NOT NULL CHECK(slot IN ('primary', 'retry')),
        retry_for TEXT REFERENCES microblock(microblock_id),
        phase TEXT NOT NULL DEFAULT 'confirmatory',
        branch_group TEXT,
        branch_candidate INTEGER,
        superblock_id TEXT,
        williams_row INTEGER CHECK(williams_row IS NULL OR williams_row >= 0),
        expected_trials INTEGER NOT NULL CHECK(expected_trials > 0),
        status TEXT NOT NULL CHECK(status IN
            ('active', 'dormant', 'dormant_candidate', 'not_selected',
             'committed', 'superseded', 'failed')),
        UNIQUE(campaign_id, session_number, ordinal, slot),
        FOREIGN KEY(campaign_id, session_number)
            REFERENCES session(campaign_id, session_number),
        CHECK((slot = 'primary' AND retry_for IS NULL) OR
              (slot = 'retry' AND retry_for IS NOT NULL)),
        CHECK((branch_group IS NULL AND branch_candidate IS NULL) OR
              (branch_group IS NOT NULL AND branch_candidate IS NOT NULL))
    )
    """,
    """
    CREATE TABLE trial (
        campaign_id TEXT NOT NULL REFERENCES campaign(campaign_id),
        trial_id TEXT PRIMARY KEY,
        logical_trial_id TEXT NOT NULL,
        microblock_id TEXT NOT NULL REFERENCES microblock(microblock_id),
        cell_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
        warmup INTEGER NOT NULL DEFAULT 0 CHECK(warmup IN (0, 1)),
        state TEXT NOT NULL DEFAULT 'planned',
        UNIQUE(campaign_id, trial_id),
        UNIQUE(microblock_id, ordinal),
        FOREIGN KEY(campaign_id, cell_id) REFERENCES cell(campaign_id, cell_id)
    )
    """,
    """
    CREATE TABLE state_transition (
        from_state TEXT NOT NULL,
        to_state TEXT NOT NULL,
        PRIMARY KEY(from_state, to_state)
    )
    """,
    """
    CREATE TABLE attempt (
        attempt_id TEXT PRIMARY KEY,
        trial_id TEXT NOT NULL REFERENCES trial(trial_id),
        attempt_number INTEGER NOT NULL CHECK(attempt_number >= 0),
        state TEXT NOT NULL DEFAULT 'planned',
        started_ns INTEGER,
        ended_ns INTEGER,
        termination_reason TEXT,
        details_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(trial_id, attempt_number),
        UNIQUE(trial_id)
    )
    """,
    """
    CREATE TABLE event (
        attempt_id TEXT NOT NULL REFERENCES attempt(attempt_id),
        source TEXT NOT NULL,
        event_sequence INTEGER NOT NULL CHECK(event_sequence >= 0),
        event_type TEXT NOT NULL,
        raw_time_ns INTEGER NOT NULL,
        payload_json TEXT NOT NULL,
        PRIMARY KEY(attempt_id, source, event_sequence)
    )
    """,
    """
    CREATE TABLE sample (
        trial_id TEXT PRIMARY KEY REFERENCES trial(trial_id),
        logical_trial_id TEXT NOT NULL UNIQUE,
        attempt_id TEXT NOT NULL UNIQUE REFERENCES attempt(attempt_id),
        sample_json TEXT NOT NULL,
        sample_sha256 TEXT NOT NULL,
        committed_ns INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE artifact (
        campaign_id TEXT NOT NULL REFERENCES campaign(campaign_id),
        path TEXT NOT NULL,
        media_type TEXT NOT NULL,
        content BLOB NOT NULL,
        sha256 TEXT NOT NULL,
        PRIMARY KEY(campaign_id, path)
    )
    """,
    """
    CREATE TABLE microblock_commit_guard (
        microblock_id TEXT PRIMARY KEY REFERENCES microblock(microblock_id)
    )
    """,
    """
    CREATE INDEX trial_microblock_idx ON trial(microblock_id, ordinal)
    """,
    """
    CREATE INDEX attempt_state_idx ON attempt(state)
    """,
    """
    CREATE TRIGGER attempt_state_transition
    BEFORE UPDATE OF state ON attempt
    WHEN OLD.state != NEW.state AND NOT EXISTS (
        SELECT 1 FROM state_transition
        WHERE from_state = OLD.state AND to_state = NEW.state
    )
    BEGIN
        SELECT RAISE(ABORT, 'illegal attempt state transition');
    END
    """,
    """
    CREATE TRIGGER guarded_attempt_commit
    BEFORE UPDATE OF state ON attempt
    WHEN NEW.state = 'committed' AND NOT EXISTS (
        SELECT 1 FROM trial t JOIN microblock_commit_guard g
          ON g.microblock_id = t.microblock_id
        WHERE t.trial_id = OLD.trial_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'attempt commit requires whole-microblock transaction');
    END
    """,
    """
    CREATE TRIGGER trial_state_transition
    BEFORE UPDATE OF state ON trial
    WHEN OLD.state != NEW.state AND NOT EXISTS (
        SELECT 1 FROM state_transition
        WHERE from_state = OLD.state AND to_state = NEW.state
    )
    BEGIN
        SELECT RAISE(ABORT, 'illegal trial state transition');
    END
    """,
    """
    CREATE TRIGGER guarded_trial_commit
    BEFORE UPDATE OF state ON trial
    WHEN NEW.state = 'committed' AND NOT EXISTS (
        SELECT 1 FROM microblock_commit_guard
        WHERE microblock_id = OLD.microblock_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'trial commit requires whole-microblock transaction');
    END
    """,
    """
    CREATE TRIGGER guarded_sample_insert
    BEFORE INSERT ON sample
    WHEN NOT EXISTS (
        SELECT 1 FROM trial t JOIN attempt a ON a.trial_id = t.trial_id
        JOIN microblock_commit_guard g ON g.microblock_id = t.microblock_id
        WHERE t.trial_id = NEW.trial_id
          AND t.logical_trial_id = NEW.logical_trial_id
          AND a.attempt_id = NEW.attempt_id
          AND a.state = 'committed'
          AND t.state = 'committed'
    )
    BEGIN
        SELECT RAISE(ABORT, 'sample insert requires matching whole-microblock commit');
    END
    """,
    f"""
    CREATE TRIGGER immutable_terminal_attempt
    BEFORE UPDATE ON attempt
    WHEN OLD.state IN ({','.join(repr(state) for state in TERMINAL_STATES)})
    BEGIN
        SELECT RAISE(ABORT, 'terminal attempt is immutable');
    END
    """,
    f"""
    CREATE TRIGGER undeletable_terminal_attempt
    BEFORE DELETE ON attempt
    WHEN OLD.state IN ({','.join(repr(state) for state in TERMINAL_STATES)})
    BEGIN
        SELECT RAISE(ABORT, 'terminal attempt is immutable');
    END
    """,
    f"""
    CREATE TRIGGER immutable_terminal_trial
    BEFORE UPDATE ON trial
    WHEN OLD.state IN ({','.join(repr(state) for state in TERMINAL_STATES)})
    BEGIN
        SELECT RAISE(ABORT, 'terminal trial is immutable');
    END
    """,
    f"""
    CREATE TRIGGER undeletable_terminal_trial
    BEFORE DELETE ON trial
    WHEN OLD.state IN ({','.join(repr(state) for state in TERMINAL_STATES)})
    BEGIN
        SELECT RAISE(ABORT, 'terminal trial is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_sample_update
    BEFORE UPDATE ON sample
    BEGIN
        SELECT RAISE(ABORT, 'committed sample is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_sample_delete
    BEFORE DELETE ON sample
    WHEN NOT EXISTS (
        SELECT 1 FROM trial t JOIN microblock m USING(microblock_id)
        WHERE t.trial_id=OLD.trial_id AND m.status='superseded'
    )
    BEGIN
        SELECT RAISE(ABORT, 'committed sample is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_committed_microblock_update
    BEFORE UPDATE ON microblock
    WHEN OLD.status = 'committed' AND NEW.status != 'superseded'
    BEGIN
        SELECT RAISE(ABORT, 'committed microblock is immutable');
    END
    """,
    """
    CREATE VIEW IF NOT EXISTS committed_sample AS
    SELECT s.* FROM sample s
    JOIN trial t ON t.trial_id = s.trial_id
    JOIN microblock m ON m.microblock_id = t.microblock_id
    WHERE m.status = 'committed'
    """,
    """
    CREATE TRIGGER immutable_committed_microblock_delete
    BEFORE DELETE ON microblock
    WHEN OLD.status = 'committed'
    BEGIN
        SELECT RAISE(ABORT, 'committed microblock is immutable');
    END
    """,
    """
    CREATE TRIGGER guarded_microblock_commit
    BEFORE UPDATE OF status ON microblock
    WHEN NEW.status = 'committed' AND NOT EXISTS (
        SELECT 1 FROM microblock_commit_guard WHERE microblock_id = OLD.microblock_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'microblock commit requires whole-microblock transaction');
    END
    """,
    f"""
    CREATE TRIGGER no_event_after_terminal
    BEFORE INSERT ON event
    WHEN (SELECT state FROM attempt WHERE attempt_id = NEW.attempt_id)
         IN ({','.join(repr(state) for state in TERMINAL_STATES)})
    BEGIN
        SELECT RAISE(ABORT, 'terminal attempt accepts no events');
    END
    """,
    """
    CREATE TRIGGER immutable_event_update
    BEFORE UPDATE ON event
    BEGIN
        SELECT RAISE(ABORT, 'events are append-only');
    END
    """,
    """
    CREATE TRIGGER immutable_event_delete
    BEFORE DELETE ON event
    BEGIN
        SELECT RAISE(ABORT, 'events are append-only');
    END
    """,
    """
    CREATE TRIGGER immutable_campaign_identity
    BEFORE UPDATE OF campaign_id, spec_hash, identity_manifest_hash,
                     analysis_plan_hash, schedule_hash, campaign_kind,
                     expected_cardinality, maximum_cardinality
    ON campaign
    BEGIN
        SELECT RAISE(ABORT, 'campaign identity is immutable');
    END
    """,
    """
    CREATE TRIGGER campaign_cannot_unfreeze
    BEFORE UPDATE OF schedule_frozen ON campaign
    WHEN OLD.schedule_frozen = 1 AND NEW.schedule_frozen != 1
    BEGIN
        SELECT RAISE(ABORT, 'schedule cannot be unfrozen');
    END
    """,
    """
    CREATE TRIGGER immutable_manifest_update
    BEFORE UPDATE ON manifest
    BEGIN
        SELECT RAISE(ABORT, 'manifest is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_manifest_delete
    BEFORE DELETE ON manifest
    BEGIN
        SELECT RAISE(ABORT, 'manifest is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_manifest_insert_after_freeze
    BEFORE INSERT ON manifest
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = NEW.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'frozen manifest set is immutable');
    END
    """,
    """
    CREATE TRIGGER frozen_cell_insert
    BEFORE INSERT ON cell
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = NEW.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'schedule is frozen');
    END
    """,
    """
    CREATE TRIGGER frozen_cell_update
    BEFORE UPDATE ON cell
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = OLD.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'schedule is frozen');
    END
    """,
    """
    CREATE TRIGGER frozen_cell_delete
    BEFORE DELETE ON cell
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = OLD.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'schedule is frozen');
    END
    """,
    """
    CREATE TRIGGER frozen_microblock_insert
    BEFORE INSERT ON microblock
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = NEW.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'schedule is frozen');
    END
    """,
    """
    CREATE TRIGGER frozen_microblock_identity
    BEFORE UPDATE OF campaign_id, microblock_id, session_number, ordinal, slot,
                     retry_for, phase, branch_group, branch_candidate,
                     superblock_id, williams_row,
                     expected_trials ON microblock
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = OLD.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'schedule is frozen');
    END
    """,
    """
    CREATE TRIGGER frozen_microblock_delete
    BEFORE DELETE ON microblock
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = OLD.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'schedule is frozen');
    END
    """,
    """
    CREATE TRIGGER frozen_trial_insert
    BEFORE INSERT ON trial
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = NEW.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'schedule is frozen');
    END
    """,
    """
    CREATE TRIGGER frozen_trial_identity
    BEFORE UPDATE OF campaign_id, trial_id, logical_trial_id, microblock_id,
                     cell_id, ordinal, warmup ON trial
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = OLD.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'schedule is frozen');
    END
    """,
    """
    CREATE TRIGGER frozen_trial_delete
    BEFORE DELETE ON trial
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = OLD.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'schedule is frozen');
    END
    """,
    """
    CREATE TRIGGER immutable_attempt_identity
    BEFORE UPDATE OF attempt_id, trial_id, attempt_number ON attempt
    BEGIN
        SELECT RAISE(ABORT, 'attempt identity is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_transition_table_update
    BEFORE UPDATE ON state_transition
    BEGIN
        SELECT RAISE(ABORT, 'state transitions are immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_transition_table_insert_after_initialization
    BEFORE INSERT ON state_transition
    WHEN EXISTS (SELECT 1 FROM schema_meta WHERE key = 'schema_version')
    BEGIN
        SELECT RAISE(ABORT, 'state transitions are immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_transition_table_delete
    BEFORE DELETE ON state_transition
    BEGIN
        SELECT RAISE(ABORT, 'state transitions are immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_schema_meta_update
    BEFORE UPDATE ON schema_meta
    BEGIN
        SELECT RAISE(ABORT, 'schema metadata is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_schema_meta_delete
    BEFORE DELETE ON schema_meta
    BEGIN
        SELECT RAISE(ABORT, 'schema metadata is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_schema_meta_insert_after_initialization
    BEFORE INSERT ON schema_meta
    WHEN (SELECT COUNT(*) FROM schema_meta) >= 2
    BEGIN
        SELECT RAISE(ABORT, 'schema metadata is immutable');
    END
    """,
)

_MIGRATION_2_STATEMENTS = (
    "UPDATE schema_meta SET value = '2' WHERE key = 'schema_version' AND value = '1'",
    "DROP TRIGGER no_event_after_commit",
    f"""
    CREATE TRIGGER no_event_after_terminal
    BEFORE INSERT ON event
    WHEN (SELECT state FROM attempt WHERE attempt_id = NEW.attempt_id)
         IN ({','.join(repr(state) for state in TERMINAL_STATES)})
    BEGIN
        SELECT RAISE(ABORT, 'terminal attempt accepts no events');
    END
    """,
    """
    CREATE TRIGGER immutable_manifest_insert_after_freeze
    BEFORE INSERT ON manifest
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = NEW.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'frozen manifest set is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_transition_table_insert_after_initialization
    BEFORE INSERT ON state_transition
    WHEN EXISTS (SELECT 1 FROM schema_meta WHERE key = 'schema_version')
    BEGIN
        SELECT RAISE(ABORT, 'state transitions are immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_schema_meta_update
    BEFORE UPDATE ON schema_meta
    BEGIN
        SELECT RAISE(ABORT, 'schema metadata is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_schema_meta_delete
    BEFORE DELETE ON schema_meta
    BEGIN
        SELECT RAISE(ABORT, 'schema metadata is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_schema_meta_insert_after_initialization
    BEFORE INSERT ON schema_meta
    WHEN (SELECT COUNT(*) FROM schema_meta) >= 2
    BEGIN
        SELECT RAISE(ABORT, 'schema metadata is immutable');
    END
    """,
)

_MIGRATION_3_STATEMENTS = (
    "DROP TRIGGER immutable_schema_meta_update",
    "ALTER TABLE microblock ADD COLUMN superblock_id TEXT",
    "ALTER TABLE microblock ADD COLUMN williams_row INTEGER CHECK(williams_row IS NULL OR williams_row >= 0)",
    "DROP TRIGGER frozen_microblock_identity",
    """
    CREATE TRIGGER frozen_microblock_identity
    BEFORE UPDATE OF campaign_id, microblock_id, session_number, ordinal, slot,
                     retry_for, phase, branch_group, branch_candidate,
                     superblock_id, williams_row, expected_trials ON microblock
    WHEN (SELECT schedule_frozen FROM campaign WHERE campaign_id = OLD.campaign_id) = 1
    BEGIN
        SELECT RAISE(ABORT, 'schedule is frozen');
    END
    """,
    "UPDATE schema_meta SET value = '3' WHERE key = 'schema_version' AND value = '2'",
    """
    CREATE TRIGGER immutable_schema_meta_update
    BEFORE UPDATE ON schema_meta
    BEGIN
        SELECT RAISE(ABORT, 'schema metadata is immutable');
    END
    """,
)

_MIGRATION_4_STATEMENTS = (
    "DROP TRIGGER immutable_schema_meta_update",
    "DROP TRIGGER immutable_committed_microblock_update",
    "DROP TRIGGER immutable_sample_delete",
    """
    CREATE TRIGGER immutable_committed_microblock_update
    BEFORE UPDATE ON microblock
    WHEN OLD.status = 'committed' AND NEW.status != 'superseded'
    BEGIN
        SELECT RAISE(ABORT, 'committed microblock is immutable');
    END
    """,
    """
    CREATE TRIGGER immutable_sample_delete
    BEFORE DELETE ON sample
    WHEN NOT EXISTS (
        SELECT 1 FROM trial t JOIN microblock m USING(microblock_id)
        WHERE t.trial_id=OLD.trial_id AND m.status='superseded'
    )
    BEGIN
        SELECT RAISE(ABORT, 'committed sample is immutable');
    END
    """,
    """
    CREATE VIEW IF NOT EXISTS committed_sample AS
    SELECT s.* FROM sample s
    JOIN trial t ON t.trial_id = s.trial_id
    JOIN microblock m ON m.microblock_id = t.microblock_id
    WHERE m.status = 'committed'
    """,
    "UPDATE schema_meta SET value = '4' WHERE key = 'schema_version' AND value = '3'",
    """
    CREATE TRIGGER immutable_schema_meta_update
    BEFORE UPDATE ON schema_meta
    BEGIN
        SELECT RAISE(ABORT, 'schema metadata is immutable');
    END
    """,
)


class Journal:
    """One locked writer or an unlocked read-only view of a v2 journal."""

    def __init__(
        self,
        path: os.PathLike[str] | str,
        *,
        writable: bool = True,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        candidate = Path(path)
        self.path = candidate / "journal.sqlite3" if candidate.suffix != ".sqlite3" else candidate
        self.path = self.path.resolve()
        self.writable = writable
        self._fault_injector = fault_injector
        self._lock_fd: int | None = None
        self._lock_owner: Journal | None = None
        self._owner_pid = os.getpid()
        self._derived_writers: set[Journal] = set()
        self._owner_guard = threading.RLock()
        self._closed = False
        self._temp_sequence = 0

        if writable:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._lock_fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                os.close(self._lock_fd)
                self._lock_fd = None
                raise JournalLockedError(f"journal writer already active: {self.path}") from exc
            self.connection = sqlite3.connect(
                self.path,
                timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
                isolation_level=None,
            )
        else:
            if not self.path.is_file():
                raise StorageError(f"journal does not exist: {self.path}")
            self.connection = sqlite3.connect(
                f"{self.path.as_uri()}?mode=ro",
                uri=True,
                timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
                isolation_level=None,
            )
        self.connection.row_factory = sqlite3.Row
        try:
            self._configure()
            if writable:
                self._migrate()
            else:
                version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
                if version != SCHEMA_VERSION:
                    raise StorageError(
                        f"unsupported journal schema {version}; expected {SCHEMA_VERSION}"
                    )
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> Journal:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        owner = self._lock_owner
        guard = owner._owner_guard if owner is not None else self._owner_guard
        with guard:
            if self._closed:
                return
            self._closed = True
            if owner is None:
                for writer in tuple(self._derived_writers):
                    writer.close()
            with contextlib.suppress(Exception):
                self.connection.close()
            if owner is not None:
                owner._derived_writers.discard(self)
                self._lock_owner = None
                return
            if self._lock_fd is not None:
                with contextlib.suppress(OSError):
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                    os.close(self._lock_fd)
                self._lock_fd = None

    @contextlib.contextmanager
    def _lane_writer(self):
        """Yield a separate writer connection derived from this flock owner.

        This is deliberately internal.  It permits qualified lanes belonging
        to one coordinator to use independent SQLite connections without
        providing a lock-bypass constructor to another coordinator or process.
        """

        with self._owner_guard:
            self._require_lock_owner()
            writer = object.__new__(Journal)
            writer.path = self.path
            writer.writable = True
            writer._fault_injector = self._fault_injector
            writer._lock_fd = None
            writer._lock_owner = self
            writer._owner_pid = self._owner_pid
            writer._derived_writers = set()
            writer._owner_guard = threading.RLock()
            writer._closed = False
            writer._temp_sequence = 0
            writer.connection = sqlite3.connect(
                self.path,
                timeout=SQLITE_BUSY_TIMEOUT_MS / 1000,
                isolation_level=None,
                check_same_thread=False,
            )
            writer.connection.row_factory = sqlite3.Row
            try:
                writer._configure()
            except BaseException:
                writer.connection.close()
                raise
            self._derived_writers.add(writer)
        try:
            yield writer
        finally:
            writer.close()

    def _require_lock_owner(self) -> None:
        if (
            self._closed
            or not self.writable
            or self._lock_owner is not None
            or self._lock_fd is None
        ):
            raise JournalLockedError("lane writers require the live coordinator lock owner")
        if os.getpid() != self._owner_pid:
            raise JournalLockedError("a fork cannot inherit coordinator writer authority")
        try:
            descriptor = os.fstat(self._lock_fd)
            path = os.stat(self.path)
            if (descriptor.st_dev, descriptor.st_ino) != (path.st_dev, path.st_ino):
                raise JournalLockedError("coordinator lock no longer names the journal")
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            raise JournalLockedError("coordinator no longer owns the journal lock") from exc

    def _fault(self, point: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(point)

    def _configure(self) -> None:
        self.connection.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        self.connection.execute("PRAGMA foreign_keys=ON")
        if self.writable:
            mode = str(self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0])
            if mode.lower() != "wal":
                raise StorageError(f"could not enable SQLite WAL mode: {mode}")
            self.connection.execute("PRAGMA synchronous=FULL")

    @contextlib.contextmanager
    def _transaction(self, point: str):
        if not self.writable:
            raise StorageError("read-only journal cannot write")
        self._fault(f"{point}.before_begin")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._fault(f"{point}.after_begin")
            yield
            self._fault(f"{point}.before_commit")
            self.connection.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                self.connection.execute("ROLLBACK")
            raise
        self._fault(f"{point}.after_commit")

    def _migrate(self) -> None:
        version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise StorageError(
                f"journal schema {version} is newer than supported {SCHEMA_VERSION}"
            )
        if version == SCHEMA_VERSION:
            return
        try:
            if version == 0:
                with self._transaction("migration.1"):
                    for index, statement in enumerate(_SCHEMA_STATEMENTS):
                        self.connection.execute(statement)
                        self._fault(f"migration.1.statement.{index}")
                    self.connection.executemany(
                        "INSERT INTO state_transition(from_state, to_state) VALUES (?, ?)",
                        _transition_rows(),
                    )
                    self.connection.executemany(
                        "INSERT INTO schema_meta(key, value) VALUES (?, ?)",
                        (("schema_version", str(SCHEMA_VERSION)), ("product", "quicperf-v2")),
                    )
                    self.connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                return
            if version == 1:
                with self._transaction("migration.2"):
                    for index, statement in enumerate(_MIGRATION_2_STATEMENTS):
                        self.connection.execute(statement)
                        self._fault(f"migration.2.statement.{index}")
                    changed = self.connection.execute(
                        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                    ).fetchone()
                    if changed is None or changed[0] != "2":
                        raise StorageError("schema v1 metadata does not match the migration input")
                    self.connection.execute("PRAGMA user_version=2")
                version = 2
            if version == 2:
                with self._transaction("migration.3"):
                    for index, statement in enumerate(_MIGRATION_3_STATEMENTS):
                        self.connection.execute(statement)
                        self._fault(f"migration.3.statement.{index}")
                    changed = self.connection.execute(
                        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                    ).fetchone()
                    if changed is None or changed[0] != "3":
                        raise StorageError("schema v2 metadata does not match the migration input")
                    self.connection.execute("PRAGMA user_version=3")
                version = 3
            if version == 3:
                with self._transaction("migration.4"):
                    for index, statement in enumerate(_MIGRATION_4_STATEMENTS):
                        self.connection.execute(statement)
                        self._fault(f"migration.4.statement.{index}")
                    changed = self.connection.execute(
                        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                    ).fetchone()
                    if changed is None or changed[0] != str(SCHEMA_VERSION):
                        raise StorageError("schema v3 metadata does not match the migration input")
                    self.connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                return
            raise StorageError(f"no migration path from journal schema {version}")
        except sqlite3.Error as exc:
            raise StorageError(f"journal migration failed: {exc}") from exc

    @classmethod
    def create_run_directory(
        cls,
        run_dir: os.PathLike[str] | str,
        *,
        spec_bytes: bytes,
        manifest_bytes: bytes,
        fault_injector: FaultInjector | None = None,
    ) -> Journal:
        """Exclusively create the fixed run-directory skeleton and journal."""

        root = Path(run_dir)

        def fault(point: str) -> None:
            if fault_injector is not None:
                fault_injector(point)

        fault("run_directory.before_create")
        root.mkdir(parents=True, exist_ok=False)
        try:
            fault("run_directory.after_create")
            (root / "logs").mkdir()
            fault("run_directory.after_logs")
            (root / "artifacts").mkdir()
            fault("run_directory.after_artifacts")
            for name, content in (("spec.json", spec_bytes), ("manifest.json", manifest_bytes)):
                path = root / name
                fault(f"run_directory.{name}.before_open")
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(fd, "wb", closefd=True) as stream:
                        stream.write(content)
                        fault(f"run_directory.{name}.after_write")
                        stream.flush()
                        fault(f"run_directory.{name}.before_fsync")
                        os.fsync(stream.fileno())
                        fault(f"run_directory.{name}.after_fsync")
                except BaseException:
                    with contextlib.suppress(OSError):
                        os.close(fd)
                    raise
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fault("run_directory.before_fsync")
                os.fsync(directory_fd)
                fault("run_directory.after_fsync")
            finally:
                os.close(directory_fd)
            journal = cls(root, fault_injector=fault_injector)
            try:
                fault("run_directory.after_journal")
            except BaseException:
                journal.close()
                raise
            return journal
        except BaseException:
            shutil.rmtree(root, ignore_errors=True)
            raise

    def create_campaign(
        self,
        *,
        campaign_id: str,
        spec_hash: str,
        identity_manifest_hash: str,
        analysis_plan_hash: str,
        schedule_hash: str,
        expected_cardinality: int,
        manifests: Mapping[str, tuple[str, Any]],
        session_count: int,
        retry_per_microblock: int = 1,
        campaign_kind: str = "fixed",
        maximum_cardinality: int | None = None,
    ) -> None:
        ids = {
            "campaign_id": _require_hash_id("campaign_id", campaign_id),
            "spec_hash": _require_hash_id("spec_hash", spec_hash),
            "identity_manifest_hash": _require_hash_id(
                "identity_manifest_hash", identity_manifest_hash
            ),
            "analysis_plan_hash": _require_hash_id("analysis_plan_hash", analysis_plan_hash),
            "schedule_hash": _require_hash_id("schedule_hash", schedule_hash),
        }
        if expected_cardinality < 0 or session_count <= 0 or retry_per_microblock not in {0, 1}:
            raise CardinalityError("expected cardinality must be nonnegative and sessions positive")
        if campaign_kind not in {"fixed", "capacity"}:
            raise JournalError("campaign kind must be fixed or capacity")
        if maximum_cardinality is None:
            maximum_cardinality = expected_cardinality * (1 + retry_per_microblock)
        if maximum_cardinality < expected_cardinality:
            raise CardinalityError("maximum cardinality is below planned cardinality")
        with self._transaction("campaign.create"):
            self.connection.execute(
                """
                INSERT INTO campaign(
                    campaign_id, spec_hash, identity_manifest_hash, analysis_plan_hash,
                    schedule_hash, campaign_kind, expected_cardinality,
                    maximum_cardinality, retry_per_microblock, created_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *ids.values(), campaign_kind, expected_cardinality,
                    maximum_cardinality, retry_per_microblock, time.time_ns(),
                ),
            )
            self.connection.executemany(
                "INSERT INTO session(campaign_id, session_number) VALUES (?, ?)",
                ((ids["campaign_id"], number) for number in range(1, session_count + 1)),
            )
            for kind, (manifest_hash, value) in sorted(manifests.items()):
                if not kind:
                    raise JournalError("manifest kind must be nonempty")
                self.connection.execute(
                    """
                    INSERT INTO manifest(campaign_id, kind, manifest_hash, canonical_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        ids["campaign_id"],
                        kind,
                        _require_hash_id("manifest_hash", manifest_hash),
                        _canonical_json(value),
                    ),
                )

    def assert_identity(
        self,
        *,
        campaign_id: str,
        spec_hash: str,
        identity_manifest_hash: str,
        analysis_plan_hash: str,
        schedule_hash: str,
    ) -> None:
        self.integrity_check()
        expected = tuple(
            _require_hash_id(name, value)
            for name, value in (
                ("campaign_id", campaign_id),
                ("spec_hash", spec_hash),
                ("identity_manifest_hash", identity_manifest_hash),
                ("analysis_plan_hash", analysis_plan_hash),
                ("schedule_hash", schedule_hash),
            )
        )
        row = self.connection.execute(
            """
            SELECT campaign_id, spec_hash, identity_manifest_hash,
                   analysis_plan_hash, schedule_hash
            FROM campaign
            """
        ).fetchone()
        if row is None or tuple(row) != expected:
            raise IdentityMismatchError("run directory identity does not match this campaign")

    def add_cell(self, campaign_id: str, cell_id: str, config: Any) -> None:
        with self._transaction("schedule.add_cell"):
            self.connection.execute(
                "INSERT INTO cell(campaign_id, cell_id, canonical_config) VALUES (?, ?, ?)",
                (
                    _require_hash_id("campaign_id", campaign_id),
                    _require_hash_id("cell_id", cell_id),
                    _canonical_json(config),
                ),
            )

    def add_microblock(
        self,
        *,
        campaign_id: str,
        microblock_id: str,
        session_number: int,
        ordinal: int,
        slot: str,
        expected_trials: int,
        retry_for: str | None = None,
        phase: str = "confirmatory",
        branch_group: str | None = None,
        branch_candidate: int | None = None,
        superblock_id: str | None = None,
        williams_row: int | None = None,
        initial_status: str | None = None,
    ) -> None:
        if slot not in {"primary", "retry"}:
            raise JournalError("microblock slot must be primary or retry")
        if (slot == "retry") != (retry_for is not None):
            raise JournalError("retry microblocks require exactly one retry_for")
        if (branch_group is None) != (branch_candidate is None):
            raise JournalError("capacity branch group and candidate must appear together")
        status = initial_status or ("active" if slot == "primary" else "dormant")
        if status not in {"active", "dormant", "dormant_candidate"}:
            raise JournalError("invalid initial microblock status")
        with self._transaction("schedule.add_microblock"):
            self.connection.execute(
                """
                INSERT INTO microblock(
                    campaign_id, microblock_id, session_number, ordinal, slot,
                    retry_for, phase, branch_group, branch_candidate,
                    superblock_id, williams_row, expected_trials, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _require_hash_id("campaign_id", campaign_id),
                    _require_hash_id("microblock_id", microblock_id),
                    session_number,
                    ordinal,
                    slot,
                    _require_hash_id("retry_for", retry_for) if retry_for else None,
                    phase,
                    branch_group,
                    branch_candidate,
                    _require_hash_id("superblock_id", superblock_id)
                    if superblock_id else None,
                    williams_row,
                    expected_trials,
                    status,
                ),
            )

    def add_trial(
        self,
        *,
        campaign_id: str,
        trial_id: str,
        microblock_id: str,
        cell_id: str,
        ordinal: int,
        logical_trial_id: str | None = None,
        warmup: bool = False,
    ) -> None:
        trial_id = _require_hash_id("trial_id", trial_id)
        logical_trial_id = _require_hash_id(
            "logical_trial_id", logical_trial_id or trial_id
        )
        with self._transaction("schedule.add_trial"):
            self.connection.execute(
                """
                INSERT INTO trial(
                    campaign_id, trial_id, logical_trial_id, microblock_id,
                    cell_id, ordinal, warmup
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _require_hash_id("campaign_id", campaign_id),
                    trial_id,
                    logical_trial_id,
                    _require_hash_id("microblock_id", microblock_id),
                    _require_hash_id("cell_id", cell_id),
                    ordinal,
                    int(warmup),
                ),
            )

    def populate_schedule(
        self,
        campaign_id: str,
        *,
        cells: Mapping[str, Any],
        microblocks: Sequence[Mapping[str, Any]],
        trials: Sequence[Mapping[str, Any]],
    ) -> None:
        """Insert a complete prevalidated maximum schedule in one transaction."""

        campaign_id = _require_hash_id("campaign_id", campaign_id)
        cell_rows = [
            (campaign_id, _require_hash_id("cell_id", cell), _canonical_json(config))
            for cell, config in sorted(cells.items())
        ]
        block_rows = []
        for block in microblocks:
            slot = str(block["slot"])
            retry_for = block.get("retry_for")
            if slot not in {"primary", "retry"} or (slot == "retry") != (retry_for is not None):
                raise JournalError("invalid bulk microblock slot/retry identity")
            branch_group = block.get("branch_group")
            branch_candidate = block.get("branch_candidate")
            if (branch_group is None) != (branch_candidate is None):
                raise JournalError("capacity branch group and candidate must appear together")
            initial = str(block.get("initial_status") or ("active" if slot == "primary" else "dormant"))
            if initial not in {"active", "dormant", "dormant_candidate"}:
                raise JournalError("invalid bulk microblock status")
            block_rows.append(
                (
                    campaign_id,
                    _require_hash_id("microblock_id", str(block["microblock_id"])),
                    int(block["session_number"]),
                    int(block["ordinal"]),
                    slot,
                    _require_hash_id("retry_for", str(retry_for)) if retry_for else None,
                    str(block.get("phase", "confirmatory")),
                    branch_group,
                    branch_candidate,
                    _require_hash_id("superblock_id", str(block["superblock_id"]))
                    if block.get("superblock_id") else None,
                    int(block["williams_row"])
                    if block.get("williams_row") is not None else None,
                    int(block["expected_trials"]),
                    initial,
                )
            )
        trial_rows = [
            (
                campaign_id,
                _require_hash_id("trial_id", str(trial["trial_id"])),
                _require_hash_id("logical_trial_id", str(trial["logical_trial_id"])),
                _require_hash_id("microblock_id", str(trial["microblock_id"])),
                _require_hash_id("cell_id", str(trial["cell_id"])),
                int(trial["ordinal"]),
                int(bool(trial.get("warmup", False))),
            )
            for trial in trials
        ]
        with self._transaction("schedule.populate"):
            self.connection.executemany(
                "INSERT INTO cell(campaign_id, cell_id, canonical_config) VALUES (?, ?, ?)",
                cell_rows,
            )
            self.connection.executemany(
                """
                INSERT INTO microblock(
                    campaign_id, microblock_id, session_number, ordinal, slot,
                    retry_for, phase, branch_group, branch_candidate,
                    superblock_id, williams_row, expected_trials, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                block_rows,
            )
            self.connection.executemany(
                """
                INSERT INTO trial(
                    campaign_id, trial_id, logical_trial_id, microblock_id,
                    cell_id, ordinal, warmup
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                trial_rows,
            )

    def freeze_schedule(self, campaign_id: str) -> None:
        campaign_id = _require_hash_id("campaign_id", campaign_id)
        with self._transaction("schedule.freeze"):
            campaign = self.connection.execute(
                """
                SELECT campaign_kind, expected_cardinality, maximum_cardinality,
                       retry_per_microblock, schedule_frozen
                FROM campaign WHERE campaign_id = ?
                """,
                (campaign_id,),
            ).fetchone()
            if campaign is None:
                raise JournalError("unknown campaign")
            if campaign["schedule_frozen"]:
                self._validate_frozen_schedule(
                    campaign_id, campaign["campaign_kind"], campaign["expected_cardinality"],
                    campaign["maximum_cardinality"], campaign["retry_per_microblock"]
                )
                return
            self._validate_frozen_schedule(
                campaign_id, campaign["campaign_kind"], campaign["expected_cardinality"],
                campaign["maximum_cardinality"], campaign["retry_per_microblock"]
            )
            self.connection.execute(
                "UPDATE campaign SET schedule_frozen = 1, status = 'planned' WHERE campaign_id = ?",
                (campaign_id,),
            )

    def _validate_frozen_schedule(
        self,
        campaign_id: str,
        campaign_kind: str,
        expected: int,
        maximum: int,
        retry_per_microblock: int,
    ) -> None:
        blocks = self.connection.execute(
            """
            SELECT microblock_id, slot, retry_for, expected_trials
            FROM microblock WHERE campaign_id = ? ORDER BY microblock_id
            """,
            (campaign_id,),
        ).fetchall()
        primary = [row for row in blocks if row["slot"] == "primary"]
        retry_by_primary: dict[str, list[sqlite3.Row]] = {}
        for row in blocks:
            if row["slot"] == "retry":
                retry_by_primary.setdefault(row["retry_for"], []).append(row)
        for block in blocks:
            actual = self.connection.execute(
                "SELECT COUNT(*) FROM trial WHERE microblock_id = ?",
                (block["microblock_id"],),
            ).fetchone()[0]
            if actual != block["expected_trials"]:
                raise CardinalityError(
                    f"microblock {block['microblock_id']} planned {block['expected_trials']} "
                    f"trials but contains {actual}"
                )
        for block in primary:
            retries = retry_by_primary.get(block["microblock_id"], [])
            if len(retries) != retry_per_microblock:
                raise CardinalityError(
                    f"primary microblock {block['microblock_id']} needs {retry_per_microblock} preallocated retries"
                )
            if retry_per_microblock == 0:
                continue
            primary_members = self.connection.execute(
                """
                SELECT logical_trial_id, cell_id, ordinal, warmup FROM trial
                WHERE microblock_id = ? ORDER BY logical_trial_id, ordinal, warmup
                """,
                (block["microblock_id"],),
            ).fetchall()
            retry_members = self.connection.execute(
                """
                SELECT logical_trial_id, cell_id, ordinal, warmup FROM trial
                WHERE microblock_id = ? ORDER BY logical_trial_id, ordinal, warmup
                """,
                (retries[0]["microblock_id"],),
            ).fetchall()
            if [tuple(row) for row in primary_members] != [tuple(row) for row in retry_members]:
                raise CardinalityError("retry microblock does not reproduce the complete primary")
        primary_count = self.connection.execute(
            """
            SELECT COUNT(*) FROM trial t JOIN microblock m USING(microblock_id)
            WHERE t.campaign_id = ? AND m.slot = 'primary' AND t.warmup = 0
              AND m.phase != 'parallel_balance_control'
            """,
            (campaign_id,),
        ).fetchone()[0]
        maximum_count = self.connection.execute(
            "SELECT COUNT(*) FROM trial WHERE campaign_id=? AND warmup=0",
            (campaign_id,),
        ).fetchone()[0]
        if maximum_count != maximum:
            raise CardinalityError(
                f"maximum schedule contains {maximum_count} trial IDs; expected {maximum}"
            )
        if campaign_kind != "capacity" and primary_count != expected:
            raise CardinalityError(
                f"expected {expected} primary samples but schedule contains {primary_count}"
            )
        if campaign_kind == "capacity":
            active_primary = self.connection.execute(
                """
                SELECT COUNT(*) FROM trial t JOIN microblock m USING(microblock_id)
                WHERE t.campaign_id=? AND m.slot='primary' AND m.status='active'
                  AND m.phase='capacity_search' AND t.warmup=0
                """,
                (campaign_id,),
            ).fetchone()[0]
            if active_primary <= 0 or active_primary >= expected:
                raise CardinalityError("capacity schedule has invalid exploratory cardinality")

    def ensure_attempt(self, trial_id: str, attempt_number: int = 0) -> str:
        trial_id = _require_hash_id("trial_id", trial_id)
        attempt_id = derive_attempt_id(trial_id, attempt_number)
        with self._transaction("attempt.ensure"):
            trial = self.connection.execute(
                "SELECT state, microblock_id FROM trial WHERE trial_id = ?", (trial_id,)
            ).fetchone()
            if trial is None:
                raise JournalError("unknown trial")
            block = self.connection.execute(
                "SELECT status FROM microblock WHERE microblock_id = ?",
                (trial["microblock_id"],),
            ).fetchone()
            if trial["state"] != "planned" or block["status"] != "active":
                existing = self.connection.execute(
                    "SELECT attempt_id FROM attempt WHERE trial_id = ? AND attempt_number = ?",
                    (trial_id, attempt_number),
                ).fetchone()
                if existing is not None and existing["attempt_id"] == attempt_id:
                    return attempt_id
                raise IllegalTransitionError("attempt can start only for an active planned trial")
            self.connection.execute(
                """
                INSERT INTO attempt(attempt_id, trial_id, attempt_number)
                VALUES (?, ?, ?)
                ON CONFLICT(trial_id, attempt_number) DO NOTHING
                """,
                (attempt_id, trial_id, attempt_number),
            )
            row = self.connection.execute(
                "SELECT attempt_id FROM attempt WHERE trial_id = ? AND attempt_number = ?",
                (trial_id, attempt_number),
            ).fetchone()
            if row["attempt_id"] != attempt_id:
                raise IdentityMismatchError("stored attempt identity differs")
        return attempt_id

    def transition_attempt(
        self,
        attempt_id: str,
        new_state: str,
        *,
        raw_time_ns: int | None = None,
        termination_reason: str | None = None,
        details: Any | None = None,
    ) -> None:
        attempt_id = _require_hash_id("attempt_id", attempt_id)
        if new_state not in ALL_STATES:
            raise IllegalTransitionError(f"unknown trial state {new_state!r}")
        self._fault(f"transition.{new_state}.before")
        timestamp = time.time_ns() if raw_time_ns is None else raw_time_ns
        try:
            with self._transaction(f"transition.{new_state}"):
                row = self.connection.execute(
                    "SELECT trial_id, state FROM attempt WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
                if row is None:
                    raise JournalError("unknown attempt")
                if row["state"] == new_state:
                    return
                fields = ["state = ?"]
                values: list[Any] = [new_state]
                if new_state == "starting":
                    fields.append("started_ns = ?")
                    values.append(timestamp)
                if new_state in TERMINAL_STATES:
                    fields.append("ended_ns = ?")
                    values.append(timestamp)
                if termination_reason is not None:
                    fields.append("termination_reason = ?")
                    values.append(termination_reason)
                if details is not None:
                    fields.append("details_json = ?")
                    values.append(_canonical_json(details))
                values.append(attempt_id)
                self.connection.execute(
                    f"UPDATE attempt SET {', '.join(fields)} WHERE attempt_id = ?", values
                )
                self.connection.execute(
                    "UPDATE trial SET state = ? WHERE trial_id = ?",
                    (new_state, row["trial_id"]),
                )
        except sqlite3.IntegrityError as exc:
            raise IllegalTransitionError(str(exc)) from exc
        self._fault(f"transition.{new_state}.after")

    def append_event(
        self,
        attempt_id: str,
        *,
        source: str,
        event_sequence: int,
        event_type: str,
        raw_time_ns: int,
        payload: Any,
    ) -> None:
        if not source or not event_type:
            raise JournalError("event source and type must be nonempty")
        with self._transaction("event.append"):
            self.connection.execute(
                """
                INSERT INTO event(
                    attempt_id, source, event_sequence, event_type, raw_time_ns, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    _require_hash_id("attempt_id", attempt_id),
                    source,
                    event_sequence,
                    event_type,
                    raw_time_ns,
                    _canonical_json(payload),
                ),
            )

    def commit_microblock(
        self,
        microblock_id: str,
        samples: Mapping[str, Any],
        *,
        committed_ns: int | None = None,
    ) -> None:
        """Atomically commit all validated attempts and measured samples."""

        microblock_id = _require_hash_id("microblock_id", microblock_id)
        timestamp = time.time_ns() if committed_ns is None else committed_ns
        self._fault("transition.committed.before")
        try:
            with self._transaction("microblock.commit"):
                block = self.connection.execute(
                    "SELECT status, expected_trials FROM microblock WHERE microblock_id = ?",
                    (microblock_id,),
                ).fetchone()
                if block is None:
                    raise JournalError("unknown microblock")
                if block["status"] == "committed":
                    stored = {
                        row["trial_id"]: row["sample_json"]
                        for row in self.connection.execute(
                            """
                            SELECT s.trial_id, s.sample_json FROM sample s
                            JOIN trial t ON t.trial_id = s.trial_id
                            WHERE t.microblock_id = ?
                            """,
                            (microblock_id,),
                        )
                    }
                    canonical_given = {key: _canonical_json(value) for key, value in samples.items()}
                    if stored == canonical_given:
                        return
                    raise IdentityMismatchError("committed microblock cannot be changed")
                if block["status"] != "active":
                    raise IllegalTransitionError(
                        f"microblock is {block['status']}, not active"
                    )
                members = self.connection.execute(
                    """
                    SELECT t.trial_id, t.logical_trial_id, t.warmup, t.state,
                           a.attempt_id, a.state AS attempt_state
                    FROM trial t LEFT JOIN attempt a ON a.trial_id = t.trial_id
                    WHERE t.microblock_id = ? ORDER BY t.ordinal
                    """,
                    (microblock_id,),
                ).fetchall()
                if len(members) != block["expected_trials"]:
                    raise CardinalityError("microblock member cardinality changed")
                if any(
                    row["state"] != "validated_provisional"
                    or row["attempt_state"] != "validated_provisional"
                    for row in members
                ):
                    raise IllegalTransitionError("every microblock member must validate first")
                measured = [row for row in members if not row["warmup"]]
                expected_ids = {row["trial_id"] for row in measured}
                if set(samples) != expected_ids:
                    missing = sorted(expected_ids - set(samples))
                    extra = sorted(set(samples) - expected_ids)
                    raise CardinalityError(
                        f"sample cardinality mismatch; missing={missing}, extra={extra}"
                    )
                self.connection.execute(
                    "INSERT INTO microblock_commit_guard(microblock_id) VALUES (?)",
                    (microblock_id,),
                )
                for row in members:
                    self.connection.execute(
                        "UPDATE attempt SET state = 'committed', ended_ns = ? WHERE attempt_id = ?",
                        (timestamp, row["attempt_id"]),
                    )
                    self.connection.execute(
                        "UPDATE trial SET state = 'committed' WHERE trial_id = ?",
                        (row["trial_id"],),
                    )
                self._fault("microblock.commit.after_states")
                for row in measured:
                    canonical = _canonical_json(samples[row["trial_id"]])
                    self.connection.execute(
                        """
                        INSERT INTO sample(
                            trial_id, logical_trial_id, attempt_id, sample_json,
                            sample_sha256, committed_ns
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            row["trial_id"],
                            row["logical_trial_id"],
                            row["attempt_id"],
                            canonical,
                            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                            timestamp,
                        ),
                    )
                    self._fault("microblock.commit.after_sample")
                self.connection.execute(
                    "UPDATE microblock SET status = 'committed' WHERE microblock_id = ?",
                    (microblock_id,),
                )
                self.connection.execute(
                    "DELETE FROM microblock_commit_guard WHERE microblock_id = ?",
                    (microblock_id,),
                )
        except sqlite3.IntegrityError as exc:
            raise CardinalityError(str(exc)) from exc
        self._fault("transition.committed.after")

    def activate_microblock_retry(
        self,
        campaign_id: str,
        microblock_id: str,
        *,
        reason: str,
        detail: str | None,
        aggregate_maximum: int,
    ) -> dict[str, Any]:
        """Atomically localize one interval transient to its frozen mate."""

        campaign_id = _require_hash_id("campaign_id", campaign_id)
        microblock_id = _require_hash_id("microblock_id", microblock_id)
        if not reason or "\x00" in reason:
            raise JournalError("microblock retry reason must be nonempty")
        if (
            detail is not None
            and (not isinstance(detail, str) or "\x00" in detail)
        ):
            raise JournalError("microblock retry detail is invalid")
        if type(aggregate_maximum) is not int or aggregate_maximum < 0:
            raise JournalError(
                "microblock retry aggregate maximum must be nonnegative"
            )
        try:
            with self._transaction("microblock.retry"):
                block = self.connection.execute(
                    """
                    SELECT * FROM microblock
                    WHERE campaign_id=? AND microblock_id=? AND status='active'
                    """,
                    (campaign_id, microblock_id),
                ).fetchone()
                if block is None:
                    raise JournalError(
                        "microblock retry requires one active block"
                    )
                localized_failures = int(
                    self.connection.execute(
                        """
                        SELECT COUNT(DISTINCT t.microblock_id)
                        FROM attempt a
                        JOIN trial t USING(trial_id)
                        JOIN microblock m USING(microblock_id)
                        WHERE m.campaign_id=? AND m.session_number=?
                          AND a.termination_reason=?
                        """,
                        (campaign_id, block["session_number"], reason),
                    ).fetchone()[0]
                )
                if (
                    block["slot"] != "retry"
                    and localized_failures >= aggregate_maximum
                ):
                    return {
                        "status": "aggregate_transient_budget_exhausted",
                        "localized_transients": localized_failures,
                    }
                committed = int(
                    self.connection.execute(
                        """
                        SELECT COUNT(*) FROM trial
                        WHERE microblock_id=? AND state='committed'
                        """,
                        (microblock_id,),
                    ).fetchone()[0]
                )
                if committed:
                    raise StorageError(
                        "partial committed microblock violates atomicity"
                    )
                now = time.time_ns()
                details_json = _canonical_json(
                    {
                        "localized_infrastructure_transient": reason,
                        "detail": detail,
                    }
                )
                self.connection.execute(
                    f"""
                    UPDATE attempt SET state='interrupted', ended_ns=?,
                        termination_reason=COALESCE(termination_reason, ?),
                        details_json=?
                    WHERE trial_id IN (
                        SELECT trial_id FROM trial WHERE microblock_id=?
                    ) AND state IN ({','.join(repr(state) for state in ACTIVE_STATES)})
                    """,
                    (now, reason, details_json, microblock_id),
                )
                self.connection.execute(
                    f"""
                    UPDATE trial SET state='superseded_incomplete_microblock'
                    WHERE microblock_id=?
                      AND state IN ({','.join(repr(state) for state in ACTIVE_STATES)})
                    """,
                    (microblock_id,),
                )
                self.connection.execute(
                    """
                    UPDATE session SET
                        infrastructure_failures=infrastructure_failures+1
                    WHERE campaign_id=? AND session_number=?
                    """,
                    (campaign_id, block["session_number"]),
                )
                if block["slot"] == "retry":
                    self.connection.execute(
                        """
                        UPDATE microblock SET status='failed'
                        WHERE microblock_id=?
                        """,
                        (microblock_id,),
                    )
                    self.connection.execute(
                        """
                        UPDATE session SET status='nonpublishable'
                        WHERE campaign_id=? AND session_number=?
                        """,
                        (campaign_id, block["session_number"]),
                    )
                    return {
                        "status": "retry_exhausted",
                        "localized_transients": localized_failures + 1,
                    }
                retry = self.connection.execute(
                    """
                    SELECT microblock_id FROM microblock
                    WHERE retry_for=? AND status='dormant'
                    """,
                    (microblock_id,),
                ).fetchall()
                if len(retry) != 1:
                    raise StorageError(
                        "preallocated microblock retry is not exact"
                    )
                retry_id = str(retry[0]["microblock_id"])
                self.connection.execute(
                    """
                    UPDATE microblock SET status='superseded'
                    WHERE microblock_id=?
                    """,
                    (microblock_id,),
                )
                self.connection.execute(
                    """
                    UPDATE microblock SET status='active'
                    WHERE microblock_id=?
                    """,
                    (retry_id,),
                )
                return {
                    "status": "retry_activated",
                    "retry_microblock_id": retry_id,
                    "localized_transients": localized_failures + 1,
                }
        except sqlite3.IntegrityError as exc:
            raise StorageError(
                f"localized microblock retry failed: {exc}"
            ) from exc

    def recover(
        self, campaign_id: str, *, microblock_id: str | None = None
    ) -> dict[str, int]:
        """Interrupt unfinished work and atomically activate complete retries.

        ``microblock_id`` scopes live lane recovery so one lane cannot
        interrupt another lane's concurrently active block. Startup recovery
        omits it and audits every active block.
        """

        campaign_id = _require_hash_id("campaign_id", campaign_id)
        if microblock_id is not None:
            microblock_id = _require_hash_id("microblock_id", microblock_id)
        result = {"untouched": 0, "retried": 0, "retry_failed": 0}
        try:
            with self._transaction("recovery"):
                blocks = self.connection.execute(
                    """
                    SELECT * FROM microblock
                    WHERE campaign_id = ? AND status = 'active'
                      AND (? IS NULL OR microblock_id = ?)
                    ORDER BY session_number, ordinal, slot
                    """,
                    (campaign_id, microblock_id, microblock_id),
                ).fetchall()
                if microblock_id is not None and not blocks:
                    raise JournalError("unknown or inactive recovery microblock")
                for block in blocks:
                    started = self.connection.execute(
                        """
                        SELECT COUNT(*) FROM trial t LEFT JOIN attempt a ON a.trial_id = t.trial_id
                        WHERE t.microblock_id = ?
                          AND (t.state != 'planned' OR (a.state IS NOT NULL AND a.state != 'planned'))
                        """,
                        (block["microblock_id"],),
                    ).fetchone()[0]
                    if started == 0:
                        result["untouched"] += 1
                        continue
                    committed = self.connection.execute(
                        """
                        SELECT COUNT(*) FROM trial
                        WHERE microblock_id = ? AND state = 'committed'
                        """,
                        (block["microblock_id"],),
                    ).fetchone()[0]
                    if committed:
                        raise StorageError("partial committed microblock violates atomicity")
                    self.connection.execute(
                        f"""
                        UPDATE attempt SET state = 'interrupted', ended_ns = ?,
                            termination_reason = COALESCE(termination_reason, 'coordinator_restart')
                        WHERE trial_id IN (
                            SELECT trial_id FROM trial WHERE microblock_id = ?
                        ) AND state IN ({','.join(repr(state) for state in ACTIVE_STATES)})
                        """,
                        (time.time_ns(), block["microblock_id"]),
                    )
                    self.connection.execute(
                        f"""
                        UPDATE trial SET state = 'superseded_incomplete_microblock'
                        WHERE microblock_id = ?
                          AND state IN ({','.join(repr(state) for state in ACTIVE_STATES)})
                        """,
                        (block["microblock_id"],),
                    )
                    if block["slot"] == "primary":
                        retry = self.connection.execute(
                            """
                            SELECT microblock_id, status FROM microblock
                            WHERE retry_for = ?
                            """,
                            (block["microblock_id"],),
                        ).fetchall()
                        if len(retry) != 1 or retry[0]["status"] != "dormant":
                            raise StorageError("preallocated retry is missing or already consumed")
                        self.connection.execute(
                            "UPDATE microblock SET status = 'superseded' WHERE microblock_id = ?",
                            (block["microblock_id"],),
                        )
                        self.connection.execute(
                            "UPDATE microblock SET status = 'active' WHERE microblock_id = ?",
                            (retry[0]["microblock_id"],),
                        )
                        self.connection.execute(
                            """
                            UPDATE session SET infrastructure_failures = infrastructure_failures + 1
                            WHERE campaign_id = ? AND session_number = ?
                            """,
                            (campaign_id, block["session_number"]),
                        )
                        result["retried"] += 1
                    else:
                        self.connection.execute(
                            "UPDATE microblock SET status = 'failed' WHERE microblock_id = ?",
                            (block["microblock_id"],),
                        )
                        self.connection.execute(
                            """
                            UPDATE session SET status = 'nonpublishable',
                                infrastructure_failures = infrastructure_failures + 1
                            WHERE campaign_id = ? AND session_number = ?
                            """,
                            (campaign_id, block["session_number"]),
                        )
                        result["retry_failed"] += 1
        except sqlite3.IntegrityError as exc:
            raise StorageError(f"recovery failed: {exc}") from exc
        return result

    def activate_session_retry(
        self,
        campaign_id: str,
        session_number: int,
        reason: str,
    ) -> dict[str, int | str]:
        """Supersede one complete session and activate only its frozen retry mates."""

        campaign_id = _require_hash_id("campaign_id", campaign_id)
        if type(session_number) is not int or session_number <= 0:
            raise JournalError("session retry requires a positive session number")
        if not reason or "\x00" in reason:
            raise JournalError("session retry reason must be nonempty")
        session = self.connection.execute(
            """
            SELECT infrastructure_failures FROM session
            WHERE campaign_id=? AND session_number=?
            """,
            (campaign_id, session_number),
        ).fetchone()
        if session is None:
            raise JournalError("unknown retry session")
        attempt_number = int(session["infrastructure_failures"]) + 1
        evidence_rows = self.connection.execute(
            """
            SELECT m.microblock_id, m.ordinal, m.status, t.trial_id,
                   t.logical_trial_id, t.state, s.sample_json, s.sample_sha256
            FROM microblock m JOIN trial t USING(microblock_id)
            LEFT JOIN sample s ON s.trial_id=t.trial_id
            WHERE m.campaign_id=? AND m.session_number=? AND m.slot='primary'
              AND m.status IN ('active','committed','failed','superseded')
            ORDER BY m.ordinal, t.ordinal
            """,
            (campaign_id, session_number),
        ).fetchall()
        evidence = {
            "schema_version": "quicperf.session-replay-evidence.v1",
            "campaign_id": campaign_id,
            "session": session_number,
            "replay_attempt": attempt_number,
            "reason": reason,
            "primary_evidence": [dict(row) for row in evidence_rows],
        }
        self.store_artifact(
            campaign_id,
            f"runtime/session-{session_number}-replay-{attempt_number}.json",
            canonical_bytes(evidence),
            media_type="application/json",
        )
        if int(session["infrastructure_failures"]) >= 1:
            active_retries = self.connection.execute(
                """
                SELECT microblock_id FROM microblock
                WHERE campaign_id=? AND session_number=?
                  AND slot='retry' AND status='active'
                ORDER BY ordinal
                """,
                (campaign_id, session_number),
            ).fetchall()
            for block in active_retries:
                self.fail_microblock(
                    str(block["microblock_id"]),
                    f"session_replay_exhausted:{reason}",
                    terminal_state="invalid",
                )
            self.set_session_status(campaign_id, session_number, "nonpublishable")
            return {
                "status": "retry_exhausted",
                "activated": 0,
                "superseded": 0,
                "replay_attempt": attempt_number,
            }
        try:
            with self._transaction("session.replay"):
                primary = self.connection.execute(
                    """
                    SELECT microblock_id, status FROM microblock
                    WHERE campaign_id=? AND session_number=? AND slot='primary'
                      AND status IN ('active','committed','failed')
                    ORDER BY ordinal
                    """,
                    (campaign_id, session_number),
                ).fetchall()
                if not primary:
                    raise IllegalTransitionError("session replay has no selected primary blocks")
                retries = self.connection.execute(
                    """
                    SELECT r.microblock_id, r.retry_for, r.status
                    FROM microblock r JOIN microblock p ON p.microblock_id=r.retry_for
                    WHERE p.campaign_id=? AND p.session_number=?
                      AND p.status IN ('active','committed','failed')
                    ORDER BY p.ordinal
                    """,
                    (campaign_id, session_number),
                ).fetchall()
                if (
                    len(retries) != len(primary)
                    or any(row["status"] != "dormant" for row in retries)
                    or {row["retry_for"] for row in retries}
                    != {row["microblock_id"] for row in primary}
                ):
                    raise StorageError(
                        "complete-session replay lacks one dormant preallocated mate per block"
                    )
                now = time.time_ns()
                active_ids = [
                    row["microblock_id"] for row in primary if row["status"] == "active"
                ]
                for microblock_id in active_ids:
                    self.connection.execute(
                        f"""
                        UPDATE attempt SET state='interrupted', ended_ns=?,
                            termination_reason=COALESCE(termination_reason, ?)
                        WHERE trial_id IN (
                            SELECT trial_id FROM trial WHERE microblock_id=?
                        ) AND state IN ({','.join(repr(state) for state in ACTIVE_STATES)})
                        """,
                        (now, reason, microblock_id),
                    )
                    self.connection.execute(
                        f"""
                        UPDATE trial SET state='superseded_incomplete_microblock'
                        WHERE microblock_id=?
                          AND state IN ({','.join(repr(state) for state in ACTIVE_STATES)})
                        """,
                        (microblock_id,),
                    )
                self.connection.execute(
                    """
                    UPDATE microblock SET status=CASE status
                        WHEN 'committed' THEN 'superseded'
                        ELSE 'superseded' END
                    WHERE campaign_id=? AND session_number=? AND slot='primary'
                      AND status IN ('active','committed','failed')
                    """,
                    (campaign_id, session_number),
                )
                self.connection.execute(
                    """
                    DELETE FROM sample WHERE trial_id IN (
                        SELECT t.trial_id FROM trial t JOIN microblock m USING(microblock_id)
                        WHERE m.campaign_id=? AND m.session_number=?
                          AND m.slot='primary' AND m.status='superseded'
                    )
                    """,
                    (campaign_id, session_number),
                )
                self.connection.execute(
                    """
                    UPDATE microblock SET status='active'
                    WHERE microblock_id IN (
                        SELECT r.microblock_id FROM microblock r
                        JOIN microblock p ON p.microblock_id=r.retry_for
                        WHERE p.campaign_id=? AND p.session_number=?
                          AND p.status = 'superseded'
                    ) AND status='dormant'
                    """,
                    (campaign_id, session_number),
                )
                activated = self.connection.execute("SELECT changes()").fetchone()[0]
                if activated != len(retries):
                    raise StorageError("complete-session retry activation was not exact")
                self.connection.execute(
                    """
                    UPDATE session SET infrastructure_failures=infrastructure_failures+1,
                        status='running'
                    WHERE campaign_id=? AND session_number=?
                    """,
                    (campaign_id, session_number),
                )
        except sqlite3.IntegrityError as exc:
            raise StorageError(f"complete-session replay failed: {exc}") from exc
        return {
            "status": "retry_activated",
            "activated": int(activated),
            "superseded": len(primary),
            "replay_attempt": attempt_number,
        }

    def fail_microblock(
        self,
        microblock_id: str,
        reason: str,
        *,
        terminal_state: str = "failed",
        root_trial_id: str | None = None,
        root_detail: str | None = None,
    ) -> None:
        """Atomically make every uncommitted member terminal without a retry.

        This is for adapter, protocol, workload, capability, and other
        deterministic failures.  Infrastructure-transient interruption uses
        :meth:`recover` and the preallocated complete retry instead.
        """

        microblock_id = _require_hash_id("microblock_id", microblock_id)
        if not reason or "\x00" in reason:
            raise JournalError("microblock failure reason must be nonempty")
        if root_trial_id is not None:
            root_trial_id = _require_hash_id("root_trial_id", root_trial_id)
        elif root_detail is not None:
            raise JournalError("root detail requires a root trial")
        if terminal_state not in {"failed", "invalid", "unsupported", "cancelled"}:
            raise JournalError("invalid deterministic terminal state")
        try:
            with self._transaction("microblock.fail"):
                block = self.connection.execute(
                    "SELECT campaign_id, session_number, status FROM microblock WHERE microblock_id = ?",
                    (microblock_id,),
                ).fetchone()
                if block is None:
                    raise JournalError("unknown microblock")
                if block["status"] == "failed":
                    return
                if block["status"] != "active":
                    raise IllegalTransitionError(
                        f"microblock is {block['status']}, not active"
                    )
                trials = self.connection.execute(
                    "SELECT trial_id, state FROM trial WHERE microblock_id = ? ORDER BY ordinal",
                    (microblock_id,),
                ).fetchall()
                if root_trial_id is not None:
                    root_trial = next(
                        (
                            trial
                            for trial in trials
                            if trial["trial_id"] == root_trial_id
                        ),
                        None,
                    )
                    if root_trial is None:
                        raise JournalError("root trial is not a member of the microblock")
                    if root_trial["state"] in TERMINAL_STATES:
                        raise JournalError("root trial is already terminal")
                now = time.time_ns()
                for trial in trials:
                    if trial["state"] in TERMINAL_STATES:
                        continue
                    row = self.connection.execute(
                        "SELECT attempt_id, state FROM attempt WHERE trial_id = ?",
                        (trial["trial_id"],),
                    ).fetchone()
                    if row is None:
                        generated = derive_attempt_id(trial["trial_id"], 0)
                        self.connection.execute(
                            "INSERT INTO attempt(attempt_id, trial_id, attempt_number) VALUES (?, ?, 0)",
                            (generated, trial["trial_id"]),
                        )
                        row = {"attempt_id": generated, "state": "planned"}
                    is_root = (
                        root_trial_id is not None
                        and trial["trial_id"] == root_trial_id
                    )
                    if root_trial_id is None:
                        state = terminal_state
                        termination_reason = reason
                        details = {"microblock_failure": reason}
                    elif is_root:
                        state = terminal_state
                        termination_reason = reason
                        details = {
                            "endpoint_detail": root_detail,
                            "microblock_failure_role": "root",
                            "root_termination_reason": reason,
                            "root_trial_id": root_trial_id,
                        }
                    else:
                        state = "failed"
                        termination_reason = "collateral_microblock_failure"
                        details = {
                            "microblock_failure_role": "collateral",
                            "root_termination_reason": reason,
                            "root_trial_id": root_trial_id,
                        }
                    self.connection.execute(
                        """
                        UPDATE attempt SET state=?, ended_ns=?,
                            termination_reason=?, details_json=?
                        WHERE attempt_id=?
                        """,
                        (
                            state,
                            now,
                            termination_reason,
                            _canonical_json(details),
                            row["attempt_id"],
                        ),
                    )
                    self.connection.execute(
                        "UPDATE trial SET state=? WHERE trial_id=?",
                        (state, trial["trial_id"]),
                    )
                self.connection.execute(
                    "UPDATE microblock SET status='failed' WHERE microblock_id=?",
                    (microblock_id,),
                )
                self.connection.execute(
                    """
                    UPDATE session SET status='nonpublishable'
                    WHERE campaign_id=? AND session_number=?
                    """,
                    (block["campaign_id"], block["session_number"]),
                )
        except sqlite3.IntegrityError as exc:
            raise IllegalTransitionError(str(exc)) from exc

    def invalidate_session_hardware(
        self,
        campaign_id: str,
        session_number: int,
        reason: str,
        evidence: Mapping[str, Any],
    ) -> dict[str, int | str]:
        """Atomically preserve and exclude a complete hardware-invalid session."""

        campaign_id = _require_hash_id("campaign_id", campaign_id)
        if type(session_number) is not int or session_number <= 0:
            raise JournalError("hardware invalidation requires a positive session number")
        if not reason or "\x00" in reason:
            raise JournalError("hardware invalidation reason must be nonempty")
        if not isinstance(evidence, Mapping):
            raise JournalError("hardware invalidation evidence must be an object")
        path = f"runtime/session-{session_number}-hardware-unqualified.json"
        existing = self.connection.execute(
            """
            SELECT a.content, a.sha256, c.status AS campaign_status,
                   s.status AS session_status
            FROM artifact a JOIN campaign c USING(campaign_id)
            JOIN session s USING(campaign_id)
            WHERE a.campaign_id=? AND a.path=? AND s.session_number=?
            """,
            (campaign_id, path, session_number),
        ).fetchone()
        if existing is not None:
            content = bytes(existing["content"])
            if hashlib.sha256(content).hexdigest() != existing["sha256"]:
                raise StorageError("hardware invalidation artifact checksum mismatch")
            try:
                document = loads_strict(content)
            except Exception as exc:
                raise StorageError("hardware invalidation artifact is malformed") from exc
            if (
                not isinstance(document, Mapping)
                or canonical_bytes(document) != content
                or document.get("schema_version")
                != "quicperf.hardware-unqualified-session.v1"
                or document.get("campaign_id") != campaign_id
                or document.get("session") != session_number
                or document.get("reason") != reason
                or existing["campaign_status"] != "hardware_unqualified"
                or existing["session_status"] != "nonpublishable"
            ):
                raise IdentityMismatchError(
                    "existing hardware invalidation differs from this request"
                )
            return {
                "status": "hardware_unqualified",
                "excluded_committed_microblocks": 0,
                "failed_active_microblocks": 0,
                "artifact_path": path,
            }
        rows = self.connection.execute(
            """
            SELECT m.microblock_id, m.ordinal, m.slot, m.status,
                   t.trial_id, t.logical_trial_id, t.state,
                   a.attempt_id, a.state AS attempt_state,
                   s.sample_json, s.sample_sha256
            FROM microblock m JOIN trial t USING(microblock_id)
            LEFT JOIN attempt a USING(trial_id)
            LEFT JOIN sample s USING(trial_id)
            WHERE m.campaign_id=? AND m.session_number=?
            ORDER BY m.ordinal, CASE m.slot WHEN 'primary' THEN 0 ELSE 1 END,
                     t.ordinal
            """,
            (campaign_id, session_number),
        ).fetchall()
        if not rows:
            raise JournalError("unknown or empty hardware-invalid session")
        document = {
            "schema_version": "quicperf.hardware-unqualified-session.v1",
            "campaign_id": campaign_id,
            "session": session_number,
            "reason": reason,
            "provider_evidence": dict(evidence),
            "journal_evidence": [dict(row) for row in rows],
        }
        content = canonical_bytes(document)
        digest = hashlib.sha256(content).hexdigest()
        excluded = 0
        failed = 0
        now = time.time_ns()
        try:
            with self._transaction("session.hardware_unqualified"):
                self.connection.execute(
                    """
                    INSERT INTO artifact(campaign_id, path, media_type, content, sha256)
                    VALUES (?, ?, 'application/json', ?, ?)
                    ON CONFLICT(campaign_id, path) DO UPDATE SET
                        media_type=excluded.media_type,
                        content=excluded.content,
                        sha256=excluded.sha256
                    """,
                    (campaign_id, path, content, digest),
                )
                blocks = self.connection.execute(
                    """
                    SELECT microblock_id, status FROM microblock
                    WHERE campaign_id=? AND session_number=?
                      AND status IN ('active','committed')
                    ORDER BY ordinal, CASE slot WHEN 'primary' THEN 0 ELSE 1 END
                    """,
                    (campaign_id, session_number),
                ).fetchall()
                for block in blocks:
                    microblock_id = str(block["microblock_id"])
                    if block["status"] == "committed":
                        self.connection.execute(
                            "UPDATE microblock SET status='superseded' WHERE microblock_id=?",
                            (microblock_id,),
                        )
                        self.connection.execute(
                            """
                            DELETE FROM sample WHERE trial_id IN (
                                SELECT trial_id FROM trial WHERE microblock_id=?
                            )
                            """,
                            (microblock_id,),
                        )
                        excluded += 1
                        continue
                    trials = self.connection.execute(
                        "SELECT trial_id, state FROM trial WHERE microblock_id=? ORDER BY ordinal",
                        (microblock_id,),
                    ).fetchall()
                    for trial in trials:
                        if trial["state"] in TERMINAL_STATES:
                            continue
                        attempt = self.connection.execute(
                            "SELECT attempt_id FROM attempt WHERE trial_id=?",
                            (trial["trial_id"],),
                        ).fetchone()
                        if attempt is None:
                            attempt_id = derive_attempt_id(str(trial["trial_id"]), 0)
                            self.connection.execute(
                                """
                                INSERT INTO attempt(
                                    attempt_id, trial_id, attempt_number, state,
                                    ended_ns, termination_reason, details_json
                                ) VALUES (?, ?, 0, 'invalid', ?, ?, ?)
                                """,
                                (
                                    attempt_id,
                                    trial["trial_id"],
                                    now,
                                    reason,
                                    _canonical_json({"hardware_unqualified": reason}),
                                ),
                            )
                        else:
                            self.connection.execute(
                                """
                                UPDATE attempt SET state='invalid', ended_ns=?,
                                    termination_reason=?, details_json=?
                                WHERE attempt_id=?
                                """,
                                (
                                    now,
                                    reason,
                                    _canonical_json({"hardware_unqualified": reason}),
                                    attempt["attempt_id"],
                                ),
                            )
                        self.connection.execute(
                            "UPDATE trial SET state='invalid' WHERE trial_id=?",
                            (trial["trial_id"],),
                        )
                    self.connection.execute(
                        "UPDATE microblock SET status='failed' WHERE microblock_id=?",
                        (microblock_id,),
                    )
                    failed += 1
                self.connection.execute(
                    """
                    UPDATE session SET status='nonpublishable'
                    WHERE campaign_id=? AND session_number=?
                    """,
                    (campaign_id, session_number),
                )
                self.connection.execute(
                    "UPDATE campaign SET status='hardware_unqualified' WHERE campaign_id=?",
                    (campaign_id,),
                )
        except sqlite3.IntegrityError as exc:
            raise IllegalTransitionError(
                f"hardware session invalidation failed: {exc}"
            ) from exc
        return {
            "status": "hardware_unqualified",
            "excluded_committed_microblocks": excluded,
            "failed_active_microblocks": failed,
            "artifact_path": path,
        }

    def set_session_status(
        self, campaign_id: str, session_number: int, status: str
    ) -> None:
        if status not in {"planned", "running", "complete", "nonpublishable", "interrupted"}:
            raise JournalError("invalid session status")
        with self._transaction("session.status"):
            cursor = self.connection.execute(
                "UPDATE session SET status=? WHERE campaign_id=? AND session_number=?",
                (status, _require_hash_id("campaign_id", campaign_id), session_number),
            )
            if cursor.rowcount != 1:
                raise JournalError("unknown session")

    def set_campaign_status(self, campaign_id: str, status: str) -> None:
        if not status or "\x00" in status:
            raise JournalError("campaign status must be nonempty")
        with self._transaction("campaign.status"):
            cursor = self.connection.execute(
                "UPDATE campaign SET status=? WHERE campaign_id=?",
                (status, _require_hash_id("campaign_id", campaign_id)),
            )
            if cursor.rowcount != 1:
                raise JournalError("unknown campaign")

    def select_capacity_branches(
        self, campaign_id: str, selections: Mapping[str, int | None]
    ) -> dict[str, int]:
        """Atomically activate the mechanically nominated held-out branches."""

        campaign_id = _require_hash_id("campaign_id", campaign_id)
        result = {"active": 0, "dormant": 0, "not_selected": 0, "failed_groups": 0}
        with self._transaction("capacity.select_branches"):
            campaign = self.connection.execute(
                "SELECT campaign_kind FROM campaign WHERE campaign_id=?",
                (campaign_id,),
            ).fetchone()
            if campaign is None or campaign["campaign_kind"] != "capacity":
                raise JournalError("branch selection requires a capacity campaign")
            missing_search = self.connection.execute(
                """
                SELECT COUNT(*) FROM trial t JOIN microblock m USING(microblock_id)
                LEFT JOIN committed_sample s ON s.logical_trial_id=t.logical_trial_id
                WHERE t.campaign_id=? AND m.phase='capacity_search'
                  AND m.slot='primary' AND s.trial_id IS NULL
                """,
                (campaign_id,),
            ).fetchone()[0]
            if missing_search:
                raise IllegalTransitionError("capacity search is incomplete")
            groups = {
                row[0]
                for row in self.connection.execute(
                    """
                    SELECT DISTINCT branch_group FROM microblock
                    WHERE campaign_id=? AND phase='capacity_confirmation'
                    """,
                    (campaign_id,),
                )
            }
            if groups != set(selections):
                raise CardinalityError("capacity nomination does not cover every frozen branch group")
            candidates = {
                group: {
                    int(row[0])
                    for row in self.connection.execute(
                        """
                        SELECT DISTINCT branch_candidate FROM microblock
                        WHERE campaign_id=? AND branch_group=?
                        """,
                        (campaign_id, group),
                    )
                }
                for group in groups
            }
            for group, candidate in sorted(selections.items()):
                if candidate is not None and candidate not in candidates[group]:
                    raise CardinalityError("capacity nomination is outside the frozen grid")
                rows = self.connection.execute(
                    """
                    SELECT microblock_id, slot, branch_candidate, status FROM microblock
                    WHERE campaign_id=? AND branch_group=?
                    """,
                    (campaign_id, group),
                ).fetchall()
                if any(row["status"] != "dormant_candidate" for row in rows):
                    raise IllegalTransitionError("capacity branch selection is already frozen")
                if candidate is None:
                    self.connection.execute(
                        "UPDATE microblock SET status='not_selected' WHERE campaign_id=? AND branch_group=?",
                        (campaign_id, group),
                    )
                    result["not_selected"] += len(rows)
                    result["failed_groups"] += 1
                    continue
                for row in rows:
                    status = (
                        "active"
                        if row["branch_candidate"] == candidate and row["slot"] == "primary"
                        else "dormant"
                        if row["branch_candidate"] == candidate
                        else "not_selected"
                    )
                    self.connection.execute(
                        "UPDATE microblock SET status=? WHERE microblock_id=?",
                        (status, row["microblock_id"]),
                    )
                    result[status] += 1
            self.connection.execute(
                "UPDATE campaign SET status=? WHERE campaign_id=?",
                (
                    "capacity_selection_failed"
                    if result["failed_groups"]
                    else "capacity_confirmation",
                    campaign_id,
                ),
            )
            if result["failed_groups"]:
                self.connection.execute(
                    "UPDATE session SET status='nonpublishable' WHERE campaign_id=?",
                    (campaign_id,),
                )
            else:
                self.connection.execute(
                    """
                    UPDATE session SET status='planned'
                    WHERE campaign_id=? AND EXISTS (
                        SELECT 1 FROM microblock m
                        WHERE m.campaign_id=session.campaign_id
                          AND m.session_number=session.session_number
                          AND m.status='active'
                    )
                    """,
                    (campaign_id,),
                )
        return result

    def assert_exact_cardinality(self, campaign_id: str) -> None:
        campaign_id = _require_hash_id("campaign_id", campaign_id)
        campaign = self.connection.execute(
            """
            SELECT campaign_kind, expected_cardinality, schedule_frozen
            FROM campaign WHERE campaign_id = ?
            """,
            (campaign_id,),
        ).fetchone()
        if campaign is None or not campaign["schedule_frozen"]:
            raise CardinalityError("campaign schedule is absent or not frozen")
        expected = campaign["expected_cardinality"]
        rows = self.connection.execute(
            """
            SELECT s.logical_trial_id FROM committed_sample s
            JOIN trial t ON t.trial_id = s.trial_id
            JOIN microblock m USING(microblock_id)
            WHERE t.campaign_id = ?
              AND m.phase != 'parallel_balance_control'
            ORDER BY s.logical_trial_id
            """,
            (campaign_id,),
        ).fetchall()
        if len(rows) != len({row[0] for row in rows}):
            raise CardinalityError("campaign contains duplicate committed logical samples")
        if campaign["campaign_kind"] != "capacity" and len(rows) != expected:
            raise CardinalityError(
                f"campaign has {len(rows)} committed logical samples; expected {expected}"
            )
        primary = {
            row[0]
            for row in self.connection.execute(
                """
                SELECT t.logical_trial_id FROM trial t JOIN microblock m USING(microblock_id)
                WHERE t.campaign_id = ? AND m.slot = 'primary'
                  AND t.warmup = 0
                  AND m.phase != 'parallel_balance_control'
                """,
                (campaign_id,),
            )
        }
        if campaign["campaign_kind"] != "capacity" and primary != {row[0] for row in rows}:
            raise CardinalityError("committed samples do not cover the frozen logical schedule")
        if campaign["campaign_kind"] == "capacity":
            unfinished = self.connection.execute(
                """
                SELECT COUNT(*) FROM microblock
                WHERE campaign_id=? AND status IN ('active','dormant_candidate')
                """,
                (campaign_id,),
            ).fetchone()[0]
            missing_selected = self.connection.execute(
                """
                SELECT COUNT(*) FROM trial t JOIN microblock m USING(microblock_id)
                LEFT JOIN committed_sample s ON s.logical_trial_id=t.logical_trial_id
                WHERE t.campaign_id=?
                  AND m.status IN ('committed','superseded')
                  AND m.phase IN ('capacity_search','capacity_confirmation')
                  AND m.slot='primary' AND s.trial_id IS NULL
                """,
                (campaign_id,),
            ).fetchone()[0]
            if unfinished or missing_selected:
                raise CardinalityError(
                    f"capacity campaign has unfinished={unfinished}, missing_selected={missing_selected}"
                )
        partial = self.connection.execute(
            """
            SELECT m.microblock_id, COUNT(s.trial_id) AS samples,
                   SUM(CASE WHEN t.warmup = 0 THEN 1 ELSE 0 END) AS expected
            FROM microblock m JOIN trial t USING(microblock_id)
            LEFT JOIN sample s ON s.trial_id = t.trial_id
            WHERE m.campaign_id = ?
            GROUP BY m.microblock_id
            HAVING samples != 0 AND samples != expected
            """,
            (campaign_id,),
        ).fetchone()
        if partial is not None:
            raise CardinalityError(f"partial microblock {partial['microblock_id']} has samples")

    def integrity_check(self) -> None:
        """Verify SQLite and the journal's application-level invariants."""

        try:
            rows = [row[0] for row in self.connection.execute("PRAGMA integrity_check")]
            if rows != ["ok"]:
                raise StorageError("SQLite integrity check failed: " + "; ".join(rows))
            if self.connection.execute("PRAGMA foreign_key_check").fetchall():
                raise StorageError("SQLite foreign-key check failed")

            schema = self.connection.execute(
                "SELECT type, name FROM sqlite_schema WHERE type IN ('table', 'trigger')"
            ).fetchall()
            tables = {row["name"] for row in schema if row["type"] == "table"}
            triggers = {row["name"] for row in schema if row["type"] == "trigger"}
            missing_tables = sorted(_REQUIRED_TABLES - tables)
            missing_triggers = sorted(_REQUIRED_TRIGGERS - triggers)
            if missing_tables or missing_triggers:
                raise StorageError(
                    f"journal schema objects missing: tables={missing_tables}, "
                    f"triggers={missing_triggers}"
                )

            metadata = dict(self.connection.execute("SELECT key, value FROM schema_meta"))
            expected_metadata = {
                "product": "quicperf-v2",
                "schema_version": str(SCHEMA_VERSION),
            }
            if metadata != expected_metadata:
                raise StorageError("journal schema metadata differs from the frozen schema")
            transitions = {
                tuple(row)
                for row in self.connection.execute(
                    "SELECT from_state, to_state FROM state_transition"
                )
            }
            if transitions != set(_transition_rows()):
                raise StorageError("journal state transition table differs from the frozen policy")
            if self.connection.execute(
                "SELECT 1 FROM microblock_commit_guard LIMIT 1"
            ).fetchone():
                raise StorageError("orphaned microblock commit guard")

            self._check_canonical_json_columns()
            for row in self.connection.execute(
                "SELECT trial_id, attempt_number, attempt_id FROM attempt"
            ):
                if derive_attempt_id(row["trial_id"], row["attempt_number"]) != row["attempt_id"]:
                    raise StorageError(f"attempt identity mismatch: {row['attempt_id']}")
            for row in self.connection.execute(
                "SELECT trial_id, sample_json, sample_sha256 FROM sample"
            ):
                observed = hashlib.sha256(row["sample_json"].encode("utf-8")).hexdigest()
                if observed != row["sample_sha256"]:
                    raise StorageError(f"committed sample checksum mismatch: {row['trial_id']}")
            for row in self.connection.execute(
                "SELECT path, content, sha256 FROM artifact"
            ):
                _safe_artifact_path(row["path"])
                observed = hashlib.sha256(bytes(row["content"])).hexdigest()
                if observed != row["sha256"]:
                    raise StorageError(f"stored artifact checksum mismatch: {row['path']}")

            inconsistent = self.connection.execute(
                """
                SELECT t.trial_id FROM trial t LEFT JOIN attempt a USING(trial_id)
                WHERE t.state NOT IN ({states})
                   OR a.state NOT IN ({states})
                   OR (a.attempt_id IS NULL AND t.state NOT IN
                       ('planned', 'superseded_incomplete_microblock'))
                   OR (a.attempt_id IS NOT NULL AND a.state != t.state
                       AND NOT (a.state = 'interrupted'
                                AND t.state = 'superseded_incomplete_microblock'))
                LIMIT 1
                """.format(states=",".join(repr(state) for state in ALL_STATES))
            ).fetchone()
            if inconsistent is not None:
                raise StorageError(f"attempt/trial state mismatch: {inconsistent['trial_id']}")
            inconsistent = self.connection.execute(
                """
                SELECT t.trial_id FROM trial t
                JOIN microblock m USING(microblock_id)
                LEFT JOIN sample s USING(trial_id)
                LEFT JOIN attempt a USING(trial_id)
                WHERE (s.trial_id IS NOT NULL AND
                       (t.state != 'committed' OR a.state != 'committed'
                        OR m.status != 'committed'
                        OR s.logical_trial_id != t.logical_trial_id
                        OR s.attempt_id != a.attempt_id))
                   OR (t.state = 'committed' AND m.status = 'committed'
                       AND t.warmup = 0 AND s.trial_id IS NULL)
                   OR (t.warmup = 1 AND s.trial_id IS NOT NULL)
                   OR (m.status = 'committed' AND t.state != 'committed')
                   OR (t.state = 'committed'
                       AND m.status NOT IN ('committed','superseded'))
                LIMIT 1
                """
            ).fetchone()
            if inconsistent is not None:
                raise StorageError(f"committed microblock invariant failed: {inconsistent['trial_id']}")
            inconsistent = self.connection.execute(
                """
                SELECT m.microblock_id FROM microblock m
                LEFT JOIN trial t USING(microblock_id)
                GROUP BY m.microblock_id, m.expected_trials
                HAVING COUNT(t.trial_id) != m.expected_trials
                LIMIT 1
                """
            ).fetchone()
            if inconsistent is not None:
                raise StorageError(
                    f"microblock member cardinality changed: {inconsistent['microblock_id']}"
                )
        except StorageError:
            raise
        except (sqlite3.DatabaseError, JournalError, UnicodeError, ValueError) as exc:
            raise StorageError(f"journal integrity validation failed: {exc}") from exc

    def _check_canonical_json_columns(self) -> None:
        columns = (
            ("manifest", "rowid", "canonical_json"),
            ("cell", "rowid", "canonical_config"),
            ("attempt", "attempt_id", "details_json"),
            ("event", "rowid", "payload_json"),
            ("sample", "trial_id", "sample_json"),
        )
        for table, identity, column in columns:
            for row in self.connection.execute(
                f"SELECT {identity} AS identity, {column} AS document FROM {table}"
            ):
                try:
                    value = loads_strict(row["document"])
                    canonical = canonical_bytes(value).decode("utf-8")
                except HarnessError as exc:
                    raise StorageError(
                        f"invalid canonical JSON in {table}.{column} at {row['identity']}: {exc}"
                    ) from exc
                if canonical != row["document"]:
                    raise StorageError(
                        f"noncanonical JSON in {table}.{column} at {row['identity']}"
                    )

    def store_artifact(
        self,
        campaign_id: str,
        path: str,
        content: bytes,
        *,
        media_type: str = "application/octet-stream",
    ) -> None:
        relative = _safe_artifact_path(path)
        if relative in {"schedule.tsv", "samples.tsv", "events.jsonl", "checksums.sha256"}:
            raise JournalError(f"artifact path {relative!r} is reserved")
        if not isinstance(content, bytes):
            raise JournalError("artifact content must be bytes")
        digest = hashlib.sha256(content).hexdigest()
        with self._transaction("artifact.store"):
            self.connection.execute(
                """
                INSERT INTO artifact(campaign_id, path, media_type, content, sha256)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(campaign_id, path) DO UPDATE SET
                    media_type = excluded.media_type,
                    content = excluded.content,
                    sha256 = excluded.sha256
                """,
                (
                    _require_hash_id("campaign_id", campaign_id),
                    relative,
                    media_type,
                    content,
                    digest,
                ),
            )

    def store_artifacts(
        self,
        campaign_id: str,
        artifacts: Mapping[str, tuple[bytes, str]],
        *,
        campaign_status: str | None = None,
    ) -> None:
        """Atomically replace one complete derived-artifact generation."""

        campaign_id = _require_hash_id("campaign_id", campaign_id)
        normalized: list[tuple[str, bytes, str, str]] = []
        for path, (content, media_type) in sorted(artifacts.items()):
            relative = _safe_artifact_path(path)
            if relative in {"schedule.tsv", "samples.tsv", "events.jsonl", "checksums.sha256"}:
                raise JournalError(f"artifact path {relative!r} is reserved")
            if not isinstance(content, bytes) or not media_type:
                raise JournalError("artifact content must be bytes and media type nonempty")
            normalized.append((relative, content, media_type, hashlib.sha256(content).hexdigest()))
        with self._transaction("artifact.store_generation"):
            for relative, content, media_type, digest in normalized:
                self.connection.execute(
                    """
                    INSERT INTO artifact(campaign_id, path, media_type, content, sha256)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(campaign_id, path) DO UPDATE SET
                        media_type=excluded.media_type,
                        content=excluded.content,
                        sha256=excluded.sha256
                    """,
                    (campaign_id, relative, media_type, content, digest),
                )
                self._fault("artifact.store_generation.after_artifact")
            if campaign_status is not None:
                self.connection.execute(
                    "UPDATE campaign SET status=? WHERE campaign_id=?",
                    (campaign_status, campaign_id),
                )

    def export(self, campaign_id: str, run_dir: os.PathLike[str] | str | None = None) -> dict[str, str]:
        """Export sorted database records through fsync + atomic rename."""

        campaign_id = _require_hash_id("campaign_id", campaign_id)
        self.integrity_check()
        root = Path(run_dir) if run_dir is not None else self.path.parent
        artifacts_dir = root / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        payloads: dict[str, bytes] = {
            "schedule.tsv": self._schedule_tsv(campaign_id),
            "samples.tsv": self._samples_tsv(campaign_id),
            "events.jsonl": self._events_jsonl(campaign_id),
        }
        for row in self.connection.execute(
            "SELECT path, content, sha256 FROM artifact WHERE campaign_id = ? ORDER BY path",
            (campaign_id,),
        ):
            content = bytes(row["content"])
            if hashlib.sha256(content).hexdigest() != row["sha256"]:
                raise StorageError(f"stored artifact checksum mismatch: {row['path']}")
            payloads[_safe_artifact_path(row["path"])] = content
        checksums: dict[str, str] = {}
        for relative in sorted(payloads):
            checksums[relative] = hashlib.sha256(payloads[relative]).hexdigest()
            self._atomic_write(artifacts_dir / relative, payloads[relative])
        checksum_bytes = "".join(
            f"{digest}  {relative}\n" for relative, digest in sorted(checksums.items())
        ).encode("utf-8")
        self._atomic_write(artifacts_dir / "checksums.sha256", checksum_bytes)
        return checksums

    def _schedule_tsv(self, campaign_id: str) -> bytes:
        headers = (
            "campaign_id",
            "session",
            "microblock_id",
            "microblock_ordinal",
            "slot",
            "phase",
            "microblock_status",
            "trial_id",
            "logical_trial_id",
            "cell_id",
            "trial_ordinal",
            "warmup",
            "trial_state",
        )
        rows = self.connection.execute(
            """
            SELECT t.campaign_id, m.session_number, m.microblock_id, m.ordinal,
                   m.slot, m.phase, m.status, t.trial_id, t.logical_trial_id, t.cell_id,
                   t.ordinal, t.warmup, t.state
            FROM trial t JOIN microblock m USING(microblock_id)
            WHERE t.campaign_id = ?
            ORDER BY m.session_number, m.ordinal,
                     CASE m.slot WHEN 'primary' THEN 0 ELSE 1 END, t.ordinal, t.trial_id
            """,
            (campaign_id,),
        ).fetchall()
        return _tsv(headers, (tuple(row) for row in rows))

    def _samples_tsv(self, campaign_id: str) -> bytes:
        headers = (
            "campaign_id",
            "session",
            "microblock_id",
            "trial_id",
            "logical_trial_id",
            "attempt_id",
            "sample_sha256",
            "sample_json",
        )
        rows = self.connection.execute(
            """
            SELECT t.campaign_id, m.session_number, m.microblock_id, s.trial_id,
                   s.logical_trial_id, s.attempt_id, s.sample_sha256, s.sample_json
            FROM committed_sample s JOIN trial t ON t.trial_id = s.trial_id
            JOIN microblock m ON m.microblock_id = t.microblock_id
            WHERE t.campaign_id = ?
            ORDER BY s.logical_trial_id, s.trial_id
            """,
            (campaign_id,),
        ).fetchall()
        return _tsv(headers, (tuple(row) for row in rows))

    def _events_jsonl(self, campaign_id: str) -> bytes:
        lines = []
        rows = self.connection.execute(
            """
            SELECT e.attempt_id, e.source, e.event_sequence, e.event_type,
                   e.raw_time_ns, e.payload_json
            FROM event e JOIN attempt a USING(attempt_id)
            JOIN trial t USING(trial_id)
            WHERE t.campaign_id = ?
            ORDER BY e.attempt_id, e.source, e.event_sequence
            """,
            (campaign_id,),
        )
        for row in rows:
            value = {
                "attempt_id": row["attempt_id"],
                "event_sequence": row["event_sequence"],
                "event_type": row["event_type"],
                "payload": json.loads(row["payload_json"]),
                "raw_time_ns": row["raw_time_ns"],
                "source": row["source"],
            }
            lines.append(_canonical_json(value).encode("utf-8") + b"\n")
        return b"".join(lines)

    def _atomic_write(self, path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._temp_sequence += 1
        temp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{self._temp_sequence}")
        self._fault(f"export.{path.name}.before_write")
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(content)
                stream.flush()
                self._fault(f"export.{path.name}.before_fsync")
                os.fsync(stream.fileno())
            self._fault(f"export.{path.name}.before_rename")
            os.replace(temp, path)
            self._fault(f"export.{path.name}.after_replace")
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self._fault(f"export.{path.name}.before_directory_fsync")
                os.fsync(directory_fd)
                self._fault(f"export.{path.name}.after_directory_fsync")
            finally:
                os.close(directory_fd)
            self._fault(f"export.{path.name}.after_rename")
        finally:
            with contextlib.suppress(FileNotFoundError):
                temp.unlink()


def _safe_artifact_path(path: str) -> str:
    candidate = PurePosixPath(path)
    if (
        not path
        or candidate.is_absolute()
        or ".." in candidate.parts
        or "." in candidate.parts
        or "\\" in path
    ):
        raise JournalError(f"unsafe artifact path: {path!r}")
    return candidate.as_posix()


def _tsv(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


__all__ = [
    "ALL_STATES",
    "ACTIVE_STATES",
    "TERMINAL_STATES",
    "SCHEMA_VERSION",
    "Journal",
    "JournalError",
    "JournalLockedError",
    "IdentityMismatchError",
    "IllegalTransitionError",
    "CardinalityError",
    "StorageError",
    "derive_attempt_id",
    "domain_hash",
]
