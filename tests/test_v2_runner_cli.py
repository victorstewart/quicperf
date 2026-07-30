import gc
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor as RealThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest import mock

from quicperf_harness.errors import IdentityMismatchError
from quicperf_harness.journal import Journal
from quicperf_harness.lanes import CgroupSnapshot
from quicperf_harness.manifest_collect import collect_manifest
from quicperf_harness.qualification import (
    QualificationArtifactStore,
    QualificationDecision,
    build_qualification_identity,
)
from quicperf_harness.renderer import (
    RenderError,
    _capacity_artifacts,
    _cleanup_artifact,
    _comparisons,
    _memory_artifacts,
    _tail_artifacts,
    reject_mixed_leaderboard,
    render_analysis,
)
from quicperf_harness.topology import PhysicalCore
from quicperf_harness.runner import (
    DIAGNOSTIC_UNQUALIFIED_HOST_WATERMARK,
    EndpointRunError,
    HardwareUnqualifiedError,
    PUBLICATION_SESSION_FINALIZATION_RESERVE_NS,
    PUBLICATION_SESSION_WALL_BUDGET_NS,
    RunnerError,
    V21_ARM_LEAD_NS,
    V21_ARM_PRE_SEND_GUARD_NS,
    _ArmControlPolicy,
    _amd_monitor_evidence_is_transient,
    _arm_control_policy,
    _automatic_gc_suspended,
    _attest_frozen_lane_count,
    _attest_coordinator_affinity,
    _collect_memory_observation,
    _cleanup_evidence,
    _construct_tail_evidence,
    _endpoint_config,
    _endpoint_negotiated,
    _expected_loss_drops,
    _generic_schedule,
    _fixed_window_progress,
    _loss_trace_gate,
    _measurement_started_timeout_ns,
    _intrinsic_nonmeasurement_overhead_ns,
    _NATIVE_WORKLOAD_FIELDS,
    _parallel_scheduled_padding_ns,
    _persisted_run_identity,
    _PublicationEpochFailure,
    _publication_epoch_failure_decision,
    _publication_session_budget_allows_block,
    _publication_session_budget_reached,
    _rebased_arm_window,
    _run_trial,
    _runtime_gate_reasons,
    _tail_qualification_durations,
    _TrialJournalRecord,
    _WorkerPool,
    _worker_reuse_eligible,
    analyze_campaign,
    campaign_status,
    create_campaign,
    diagnostic_host_failure_authorization,
    finalize_campaign,
    run_campaign_session,
    campaign_identity,
)
from quicperf_harness.spec import load_experiment_spec
from quicperf_harness.statistical_simulation import (
    frozen_analysis_calibration,
    load_artifact,
)
from quicperf_harness.topology import LaneTopology


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profiles" / "v2" / "ci-smoke.json"
FAKE = (sys.executable, "-m", "quicperf_harness.testing.fake_endpoint")
BIN = Path(os.environ.get("QUICPERF_BIN_DIR", ROOT / "build" / "bin"))


def window_endpoint(
    start: int, end: int, validated_units: int, *, blocked: bool = False
) -> dict[str, object]:
    quotient, remainder = divmod(validated_units, 200)
    bins = [
        {
            "validated_units": quotient + (index < remainder),
            "blocked_events": int(blocked and index == 0),
        }
        for index in range(200)
    ]
    return {
        "global_start_raw_ns": start,
        "global_end_raw_ns": end,
        "denominator_raw_ns": end - start,
        "actual_start_raw_ns": start,
        "actual_end_raw_ns": end,
        "measurement_started_raw_ns": start,
        "measurement_stopped_raw_ns": end,
        "measurement_subwindows": bins,
        "progress": [
            {
                "event_index": index,
                "raw_now_ns": start + (index + 1) * (end - start) // 10,
                "validated_units": sum(
                    row["validated_units"]
                    for row in bins[index * 20 : (index + 1) * 20]
                ),
                "blocked": blocked and index == 0,
            }
            for index in range(10)
        ],
    }


class RunnerLifecycleTests(unittest.TestCase):
    @staticmethod
    def trace(path: Path) -> list[dict[str, object]]:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    @staticmethod
    def failure_reasons(run_dir: Path) -> list[tuple[str, str]]:
        with Journal(run_dir) as journal:
            return [
                (str(row["microblock_id"]), str(row["termination_reason"]))
                for row in journal.connection.execute(
                    """
                    SELECT m.microblock_id, a.termination_reason
                    FROM microblock m JOIN trial t USING(microblock_id)
                    JOIN attempt a USING(trial_id)
                    WHERE m.status='failed'
                    ORDER BY m.ordinal, t.ordinal
                    """
                )
            ]

    def test_progress_attributes_sender_blocking_to_receiver_owned_work(self) -> None:
        start, end = 100, 2_100
        self.assertEqual(
            _fixed_window_progress(
                scenario="upload",
                numerator=0,
                measurement_start_raw_ns=start,
                measurement_end_raw_ns=end,
                server_result=window_endpoint(start, end, 0),
                client_result=window_endpoint(start, end, 0, blocked=True),
            )[0],
            {"validated_units": 0, "blocked": True},
        )

    def test_fixed_window_reconciles_server_client_and_bidi_ownership(self) -> None:
        start, end = 100, 5_000_000_100
        server = window_endpoint(start, end, 300)
        client = window_endpoint(start, end, 700)
        self.assertEqual(
            sum(
                row["validated_units"]
                for row in _fixed_window_progress(
                    scenario="upload",
                    numerator=300,
                    measurement_start_raw_ns=start,
                    measurement_end_raw_ns=end,
                    server_result=server,
                    client_result=client,
                )
            ),
            300,
        )
        self.assertEqual(
            sum(
                row["validated_units"]
                for row in _fixed_window_progress(
                    scenario="download",
                    numerator=700,
                    measurement_start_raw_ns=start,
                    measurement_end_raw_ns=end,
                    server_result=server,
                    client_result=client,
                )
            ),
            700,
        )
        self.assertEqual(
            sum(
                row["validated_units"]
                for row in _fixed_window_progress(
                    scenario="bidi",
                    numerator=1_000,
                    measurement_start_raw_ns=start,
                    measurement_end_raw_ns=end,
                    server_result=server,
                    client_result=client,
                )
            ),
            1_000,
        )

    def test_fixed_window_rejects_malformed_or_misaggregated_evidence(self) -> None:
        start, end = 100, 2_000_000_100
        mutations = []
        missing_bin = window_endpoint(start, end, 200)
        missing_bin["measurement_subwindows"] = missing_bin[
            "measurement_subwindows"
        ][:-1]
        mutations.append(missing_bin)
        wrong_denominator = window_endpoint(start, end, 200)
        wrong_denominator["denominator_raw_ns"] = end - start - 1
        mutations.append(wrong_denominator)
        wrong_progress = window_endpoint(start, end, 200)
        wrong_progress["progress"][0]["validated_units"] += 1
        mutations.append(wrong_progress)
        for result in mutations:
            with self.subTest(result=result), self.assertRaises(EndpointRunError):
                _fixed_window_progress(
                    scenario="upload",
                    numerator=200,
                    measurement_start_raw_ns=start,
                    measurement_end_raw_ns=end,
                    server_result=result,
                    client_result=window_endpoint(start, end, 200),
                )

    def test_fake_endpoint_sleep_handles_deadline_crossing(self) -> None:
        from quicperf_harness.testing import fake_endpoint

        with (
            mock.patch.object(fake_endpoint, "_raw_ns", side_effect=(99, 101)),
            mock.patch.object(fake_endpoint.time, "sleep") as sleep,
        ):
            fake_endpoint._sleep_until_raw(100)
        sleep.assert_called_once_with(1e-9)

    def test_trial_health_stops_before_endpoint_teardown(self) -> None:
        source = (ROOT / "quicperf_harness" / "runner.py").read_text()
        measured = source[
            source.index("        server_result, server_events = _receive_result_stream(") :
            source.index('        journal_record.transition("validating")')
        ]
        self.assertEqual(measured.count("health = lane_health.finish()"), 1)
        self.assertLess(
            measured.index("health = lane_health.finish()"),
            measured.index("_send(server_channel, MessageType.SHUTDOWN"),
        )

    def test_native_trial_record_can_be_exact_and_journal_free(self) -> None:
        first = _TrialJournalRecord.begin(None, "a" * 64)
        second = _TrialJournalRecord.begin(None, "a" * 64)
        other = _TrialJournalRecord.begin(None, "b" * 64)
        self.assertEqual(first.attempt_id, second.attempt_id)
        self.assertNotEqual(first.attempt_id, other.attempt_id)
        self.assertEqual(first.measurement_writes(first.measurement_snapshot()), 0)
        first.transition("ready")
        first.append_events(({"source": "server"},))

        journal = mock.Mock()
        journal.ensure_attempt.return_value = "c" * 64
        journaled = _TrialJournalRecord.begin(journal, "a" * 64)
        journaled.transition("ready")
        journaled.append_events(({"source": "server"},))
        journal.ensure_attempt.assert_called_once_with("a" * 64)
        self.assertEqual(
            journal.transition_attempt.call_args_list,
            [mock.call("c" * 64, "starting"), mock.call("c" * 64, "ready")],
        )
        journal.append_event.assert_called_once_with("c" * 64, source="server")

    def test_only_typed_amd_monitor_dropout_is_session_replayable(self) -> None:
        transient = {
            "passed": False,
            "monitor_error": {
                "type": "AmdMonitorTransientError",
                "message": "Tctl sampling cadence dropped out",
                "treatment_independent_transient": True,
            },
        }
        self.assertTrue(_amd_monitor_evidence_is_transient(transient))
        for mutation in (
            {"passed": True},
            {"monitor_error": {**transient["monitor_error"], "type": "HealthError"}},
            {
                "monitor_error": {
                    **transient["monitor_error"],
                    "treatment_independent_transient": False,
                }
            },
            {"monitor_error": {**transient["monitor_error"], "message": ""}},
        ):
            with self.subTest(mutation=mutation):
                evidence = {**transient, **mutation}
                self.assertFalse(_amd_monitor_evidence_is_transient(evidence))

    def test_post_probe_gc_suspension_restores_prior_state(self) -> None:
        was_enabled = gc.isenabled()
        try:
            gc.enable()
            with _automatic_gc_suspended():
                self.assertFalse(gc.isenabled())
            self.assertTrue(gc.isenabled())

            with self.assertRaisesRegex(RuntimeError, "probe failed"):
                with _automatic_gc_suspended():
                    self.assertFalse(gc.isenabled())
                    raise RuntimeError("probe failed")
            self.assertTrue(gc.isenabled())

            gc.disable()
            with _automatic_gc_suspended():
                self.assertFalse(gc.isenabled())
            self.assertFalse(gc.isenabled())
        finally:
            if was_enabled:
                gc.enable()
            else:
                gc.disable()

    def test_v21_arm_guard_rebases_an_injected_300_ms_delay(self) -> None:
        spec = load_experiment_spec(
            ROOT / "profiles" / "v2.1" / "publication.json"
        )
        policy = _arm_control_policy(spec)
        self.assertEqual(policy.lead_ns, V21_ARM_LEAD_NS)
        self.assertEqual(
            policy.pre_send_guard_ns, V21_ARM_PRE_SEND_GUARD_NS
        )
        injected_delay_ns = 300_000_000
        self.assertGreater(injected_delay_ns, 75_000_000)
        initial_now = 10_000_000_000
        initial_window = initial_now + policy.lead_ns
        observed = initial_now + injected_delay_ns
        rebased = _rebased_arm_window(policy, initial_window, observed)
        self.assertEqual(rebased, observed + policy.lead_ns)
        self.assertIsNone(
            _rebased_arm_window(
                policy,
                rebased,
                observed + policy.lead_ns - policy.pre_send_guard_ns,
            )
        )

    def test_abandoned_terminated_workers_are_not_shutdown_twice(self) -> None:
        pool = _WorkerPool(
            root=ROOT,
            endpoint_override=None,
            environment={},
            active_processes={},
            active_processes_lock=threading.Lock(),
        )
        session = mock.Mock()
        session.managed.process.poll.return_value = -15
        pool.sessions[object()] = session
        with mock.patch.object(pool, "_retire") as retire:
            pool.abandon_terminated()
            pool.close()
        retire.assert_called_once_with(session, terminate=False)

    def test_reuse_worker_rejects_nonempty_reset_inventory(self) -> None:
        session = mock.Mock()
        session.in_use = True
        session.managed.alive.return_value = True
        acknowledgement = mock.Mock(
            fields={
                "live_connections": 1,
                "live_streams": 0,
                "live_tickets": 0,
                "work_inventory": 0,
            }
        )
        with (
            mock.patch("quicperf_harness.runner._send"),
            mock.patch(
                "quicperf_harness.runner._expect",
                return_value=acknowledgement,
            ),
            self.assertRaisesRegex(
                EndpointRunError, "reuse_worker_reset_inventory_not_empty"
            ),
        ):
            _WorkerPool.reset(object.__new__(_WorkerPool), session, b"t" * 32)

    def test_reuse_worker_retires_idle_namespace_conflict_before_spawn(self) -> None:
        pool = _WorkerPool(
            root=ROOT,
            endpoint_override=None,
            environment={},
            active_processes={},
            active_processes_lock=threading.Lock(),
        )
        binary = ROOT / "build" / "bin" / "neqoperf"
        cgroup = Path("/sys/fs/cgroup/quicperf/server/neqo/syscall")
        old_key = pool.key(
            binary=binary,
            role="server",
            backend="syscall",
            lane=0,
            cpuset=(2,),
            cgroup=cgroup,
            network_namespace=None,
        )
        old = mock.Mock(key=old_key, in_use=False)
        pool.sessions[old_key] = old
        managed = mock.Mock()
        managed.process.pid = 1234
        channel = mock.Mock()
        pool.supervisor = mock.Mock()
        pool.supervisor.spawn.return_value = managed

        with (
            mock.patch.object(pool, "_shutdown_idle") as shutdown,
            mock.patch(
                "quicperf_harness.runner.SeqPacketChannel",
                return_value=channel,
            ),
            mock.patch(
                "quicperf_harness.runner._attest_hello",
                return_value={"roles": "server"},
            ),
            mock.patch("quicperf_harness.runner.attest_process_libraries"),
        ):
            replacement = pool.acquire(
                binary=binary,
                entry={
                    "elf_build_id": "a" * 64,
                    "expected_loaded_libraries": [],
                },
                role="server",
                backend="syscall",
                scenario="loss_recovery",
                lane=0,
                cpuset=(2,),
                cgroup=cgroup,
                network_namespace=Path("/run/netns/quicperf-server"),
                log_path=Path("/tmp/unused.log"),
                timeout_ns=1_000_000_000,
            )

        shutdown.assert_called_once_with(old)
        self.assertNotIn(old_key, pool.sessions)
        self.assertIs(pool.sessions[replacement.key], replacement)
        self.assertEqual(
            replacement.key.network_namespace,
            "/run/netns/quicperf-server",
        )

    def create_worker_reuse(
        self,
        root: Path,
        *,
        name: str,
        acquire: bool,
        persistent: bool = True,
        lifecycle_scenarios: bool = False,
        arm_retry: bool = False,
    ) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        profile = json.loads(PROFILE.read_bytes())
        profile["name"] = name
        profile["qualification"]["worker_reuse_required"] = True
        profile["schedule"]["worker_process_policy"] = (
            "persistent_reset" if persistent else "fresh_process"
        )
        if arm_retry:
            for workload in profile["workloads"]:
                workload["warmup_ns"] = 250_000_000
            profile["schedule"]["dormant_retry_per_microblock"] = 1
            profile["retry"] = {
                "maximum": 1,
                "scope": "localized_interval_and_complete_session",
                "closed_reasons": ["arm_control_window_rejected"],
                "preallocated": True,
            }
            profile["expected_cardinality"]["maximum_trial_ids"] = (
                2 * profile["expected_cardinality"]["planned_trials"]
            )
        if name == "worker-reuse-validation":
            profile["campaign_kind"] = "qualification"
        if lifecycle_scenarios:
            for workload, scenario, tickets in zip(
                profile["workloads"],
                ("connect", "resumed_connect"),
                (0, 16),
                strict=True,
            ):
                workload["scenario"] = scenario
                workload["warmup_ns"] = 0
                workload["operation_slots"] = 16
                workload["ticket_chains"] = tickets
        profile_path = root / "profile.json"
        profile_path.write_text(
            json.dumps(profile, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        run_dir = root / "run"
        create_campaign(
            root=ROOT,
            profile=profile_path,
            run_dir=run_dir,
            seed="35" * 32,
            bin_dir=BIN,
        )
        if acquire:
            with Journal(run_dir) as journal:
                spec, manifest, _schedule = _persisted_run_identity(journal, run_dir)
                campaign = campaign_identity(journal)
                stored = QualificationArtifactStore(root / "qualification-store").store(
                    "worker-reuse",
                    build_qualification_identity("worker-reuse", spec, manifest),
                    QualificationDecision("worker-reuse", "qualified", (), {}),
                )
                journal.store_artifact(
                    str(campaign["campaign_id"]),
                    "qualification/worker-reuse.json",
                    stored.path.read_bytes(),
                    media_type="application/json",
                )
        return run_dir

    def test_negotiated_evidence_is_strict_and_summary_reconciles(self):
        # Reuse the fake endpoint's exact evidence shape without accepting a
        # configured-value shortcut in production code.
        from quicperf_harness.testing.fake_endpoint import _result

        result = json.loads(
            _result(
                bytes.fromhex("01" * 32),
                {
                    "cell_id": "02" * 32,
                    "server_backend": "syscall",
                    "reference_client_backend": "syscall",
                    "scenario": "download",
                    "path_profile": "loopback",
                },
                "client",
                1,
                2,
            )
        )
        self.assertTrue(_endpoint_negotiated(result, "reference_client")["matches"])
        result["negotiated"]["unknown"] = 1
        with self.assertRaisesRegex(EndpointRunError, "malformed_negotiated_settings"):
            _endpoint_negotiated(result, "reference_client")
        result["negotiated"].pop("unknown")
        result["negotiated"]["matches"] = False
        with self.assertRaisesRegex(
            EndpointRunError, "negotiated_settings_summary_mismatch"
        ):
            _endpoint_negotiated(result, "reference_client")

    def test_tail_evidence_merges_split_small_payload_ownership(self):
        def prefixes(successful: int, censored: int):
            return [
                {
                    "duration_seconds": duration,
                    "started_operations": successful + censored,
                    "successful_operations": successful,
                    "failed_operations": 0,
                    "censored_operations": censored,
                    "p99_ns": 25 if successful else 0,
                }
                for duration in (2, 5, 10, 20)
            ]

        operation = {
            "operation_sequence": 7,
            "start_raw_ns": 100,
            "terminal_raw_ns": 125,
            "latency_ns": 25,
        }
        client = {
            "tail_observation_ownership": "sender_starts",
            "tail": {
                "started_operations": 2_002,
                "failed_operations": 0,
                "censored_operations": 0,
                "prefixes": prefixes(0, 2_002),
                "histogram_resolution_ns": 1,
                "operations": [],
            },
        }
        server = {
            "tail_observation_ownership": "receiver_terminals",
            "tail": {
                "started_operations": 2_000,
                "failed_operations": 0,
                "censored_operations": 3,
                "prefixes": prefixes(1_997, 3),
                "histogram_resolution_ns": 1,
                "operations": [operation],
            },
        }
        merged = _construct_tail_evidence(
            "small_payload_pps", "tail", server, client
        )
        self.assertEqual(merged["started_operations"], 2_002)
        self.assertEqual(merged["censored_operations"], 5)
        self.assertEqual(merged["operations"], [operation])

    def test_tail_evidence_rejects_unbounded_or_unsorted_native_results(self):
        def prefixes(started: int):
            return [
                {
                    "duration_seconds": duration,
                    "started_operations": started,
                    "successful_operations": started,
                    "failed_operations": 0,
                    "censored_operations": 0,
                    "p99_ns": 1,
                }
                for duration in (2, 5, 10, 20)
            ]

        operation = lambda sequence, start: {
            "operation_sequence": sequence,
            "start_raw_ns": start,
            "terminal_raw_ns": start + 1,
            "latency_ns": 1,
        }
        server = {"tail_observation_ownership": "none", "tail": None}
        client = {
            "tail_observation_ownership": "complete",
            "tail": {
                "started_operations": 2,
                "failed_operations": 0,
                "censored_operations": 0,
                "prefixes": prefixes(2),
                "histogram_resolution_ns": 1,
                "operations": [operation(2, 20), operation(1, 10)],
            },
        }
        with self.assertRaisesRegex(EndpointRunError, "malformed_tail_observations"):
            _construct_tail_evidence("reqresp", "tail", server, client)

        client["tail"]["started_operations"] = 1_025
        client["tail"]["prefixes"] = prefixes(1_025)
        client["tail"]["operations"] = [
            operation(sequence, sequence + 1) for sequence in range(1_025)
        ]
        with self.assertRaisesRegex(EndpointRunError, "tail_observation_bound_exceeded"):
            _construct_tail_evidence("reqresp", "tail", server, client)

    def test_cleanup_evidence_requires_four_reconciled_strata(self):
        client = {"numerator": 3_000, "cleanup_strata": [100, 400, 900, 1_600]}
        server = {"numerator": 3_000}
        evidence = _cleanup_evidence(server, client, 1_000_000_000)
        self.assertEqual(
            [
                evidence["strata"][label]["completed"]
                for label in ("fin", "reset_stream", "stop_sending", "connection_close")
            ],
            client["cleanup_strata"],
        )
        self.assertEqual(
            evidence["strata"]["reset_stream"]["operations_per_second_decimal"],
            "400",
        )
        self.assertAlmostEqual(
            float(
                evidence[
                    "aggregate_geometric_mean_operations_per_second_decimal"
                ]
            ),
            489.8979485566356,
        )

        client["cleanup_strata"][0] = 99
        client["numerator"] = server["numerator"] = 2_999
        with self.assertRaisesRegex(
            EndpointRunError, "close_reset_cleanup_stratum_below_100"
        ):
            _cleanup_evidence(server, client, 1_000_000_000)

        client["cleanup_strata"][0] = 100
        client["numerator"] = 3_000
        server["numerator"] = 2_999
        with self.assertRaisesRegex(
            EndpointRunError, "close_reset_cleanup_strata_do_not_reconcile"
        ):
            _cleanup_evidence(server, client, 1_000_000_000)

    def test_cleanup_artifact_reports_each_stratum_and_aggregate(self):
        evidence = _cleanup_evidence(
            {"numerator": 400},
            {"numerator": 400, "cleanup_strata": [100, 100, 100, 100]},
            1_000_000_000,
        )
        artifact, reasons = _cleanup_artifact(
            [
                {
                    "config": {
                        "scenario": "close_reset_cleanup",
                        "server": "quiczigperf",
                        "server_backend": "syscall",
                        "reference_client": "quiczigperf",
                    },
                    "session_number": 1,
                    "planned_microblock_id": "m",
                    "planned_trial_id": "planned",
                    "committed_trial_id": "committed",
                    "sample": {
                        "completion_status": "valid",
                        "cleanup": evidence,
                        "metric": {
                            "name": "cleanup_geometric_mean_operations_per_second",
                            "numerator": 400,
                            "derived_decimal": "100",
                        },
                    },
                }
            ]
        )
        self.assertEqual(reasons, [])
        rendered = artifact.decode("utf-8")
        self.assertIn("fin_completed\tfin_rate", rendered)
        self.assertIn("\t100\t100\t100\t100\t100\t100\t100\t100\t100\tvalid\n", rendered)

    def test_memory_polling_uses_fresh_process_cgroup_and_smaps_evidence(self):
        raw = iter(range(0, 100_000_000_000, 100_000_000))
        with mock.patch(
            "quicperf_harness.runner.time.clock_gettime_ns",
            side_effect=lambda _clock: next(raw),
        ), mock.patch(
            "quicperf_harness.runner.read_cgroup_snapshot",
            return_value=CgroupSnapshot(0, 0, 123_456_789, 1),
        ), mock.patch(
            "quicperf_harness.runner._smaps_rollup",
            return_value=(100_000_000, 50_000_000),
        ):
            result = _collect_memory_observation(
                Path("server-cgroup"), 123, 64, threading.Event()
            )
        self.assertEqual(result["connections"], 64)
        self.assertEqual(result["settled_at_ns"], 5_000_000_000)
        self.assertEqual(result["final_median_bytes"], 123_456_789)
        self.assertEqual(len(result["polls"]), 71)

    def test_coordinator_affinity_is_exact_housekeeping_and_endpoint_disjoint(self):
        lanes = {
            0: LaneTopology(0, 3, (4, 5), (1, 2)),
            1: LaneTopology(1, 6, (7, 8), (1, 2)),
        }
        with mock.patch(
            "quicperf_harness.runner.os.sched_getaffinity", return_value={1, 2}
        ):
            self.assertEqual(_attest_coordinator_affinity(lanes), (1, 2))
        with mock.patch(
            "quicperf_harness.runner.os.sched_getaffinity", return_value={2}
        ):
            self.assertEqual(
                _attest_coordinator_affinity(lanes, reserved_cpus=(1,)),
                (2,),
            )
        with mock.patch(
            "quicperf_harness.runner.os.sched_getaffinity", return_value={1}
        ), self.assertRaisesRegex(RunnerError, "exact frozen housekeeping"):
            _attest_coordinator_affinity(lanes)
        with self.assertRaisesRegex(RunnerError, "no coordinator CPU"):
            _attest_coordinator_affinity(lanes, reserved_cpus=(1, 2))
        overlapping = {0: LaneTopology(0, 2, (4, 5), (1, 2))}
        with self.assertRaisesRegex(RunnerError, "overlap endpoint"):
            _attest_coordinator_affinity(overlapping)

    def create(self, root: Path) -> Path:
        run_dir = root / "run"
        create_campaign(
            root=ROOT,
            profile=PROFILE,
            run_dir=run_dir,
            seed="31" * 32,
            bin_dir=BIN,
        )
        return run_dir

    def create_repeated_cell_session(self, root: Path) -> Path:
        profile = json.loads(PROFILE.read_bytes())
        profile["name"] = "repeated-cell-resume"
        profile["roles"]["servers"] = [
            "ngtcp2perf",
            "lsperf",
            "tquicperf",
            "quicheperf",
            "picoperf",
            "xquicperf",
        ]
        profile["roles"]["reference_clients"] = ["ngtcp2perf", "picoperf"]
        profile["workloads"] = profile["workloads"][:1]
        profile["schedule"]["sessions"] = 2
        profile["schedule"]["williams_rows"] = 6
        profile["expected_cardinality"] = {
            "planned_trials": 36,
            "maximum_trial_ids": 36,
            "committed_samples": 36,
            "sessions": 2,
            "williams_rows": 6,
        }
        profile_path = root / "repeated-cell.json"
        profile_path.write_text(
            json.dumps(profile, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        run_dir = root / "run"
        synthetic_cores = tuple(
            PhysicalCore(0, core, (core,), 0) for core in range(8)
        )
        with mock.patch(
            "quicperf_harness.topology.discover_physical_cores",
            return_value=synthetic_cores,
        ):
            create_campaign(
                root=ROOT,
                profile=profile_path,
                run_dir=run_dir,
                seed="39" * 32,
                bin_dir=BIN,
            )
        return run_dir

    def test_deterministic_suppression_is_identical_after_journal_resume(self) -> None:
        sample = {
            "runtime": {
                "journal_writes_during_measurement": 0,
                "measurement_ns": 100_000_000,
                "nonmeasurement_overhead_ns": 1,
                "scenario": "download",
            }
        }

        def validated_sample(journal: Journal, *_args, **kwargs):
            trial_id = str(kwargs["trial_row"]["trial_id"])
            attempt_id = journal.ensure_attempt(trial_id)
            for state in (
                "starting",
                "ready",
                "armed",
                "measuring",
                "draining",
                "validating",
                "validated_provisional",
            ):
                journal.transition_attempt(attempt_id, state)
            return sample

        def terminal_rows(run_dir: Path) -> tuple[list[tuple[object, ...]], bytes, bytes]:
            with Journal(run_dir) as journal:
                campaign = campaign_identity(journal)
                rows = [
                    tuple(row)
                    for row in journal.connection.execute(
                        """
                        SELECT m.ordinal, m.status, t.ordinal, t.state,
                               a.termination_reason, a.details_json
                        FROM microblock m JOIN trial t USING(microblock_id)
                        LEFT JOIN attempt a USING(trial_id)
                        WHERE m.session_number=1
                        ORDER BY m.ordinal, t.ordinal
                        """
                    )
                ]
                campaign_id = str(campaign["campaign_id"])
                return (
                    rows,
                    journal._schedule_tsv(campaign_id),
                    journal._samples_tsv(campaign_id),
                )

        with (
            tempfile.TemporaryDirectory() as first_temp,
            tempfile.TemporaryDirectory() as second_temp,
        ):
            uninterrupted = self.create_repeated_cell_session(Path(first_temp))
            resumed = self.create_repeated_cell_session(Path(second_temp))

            calls = 0

            def fail_first(journal: Journal, *_args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise EndpointRunError(
                        "unexpected_flow_control_blocking",
                        detail='{"data_blocked":3}',
                    )
                return validated_sample(journal, **kwargs)

            with mock.patch(
                "quicperf_harness.runner._run_trial", side_effect=fail_first
            ):
                uninterrupted_result = run_campaign_session(
                    root=ROOT,
                    run_dir=uninterrupted,
                    session=1,
                    endpoint_override=FAKE,
                )

            with Journal(resumed) as journal:
                first_block = journal.connection.execute(
                    """
                    SELECT microblock_id FROM microblock
                    WHERE session_number=1 AND slot='primary'
                    ORDER BY ordinal LIMIT 1
                    """
                ).fetchone()[0]
                root_trial = journal.connection.execute(
                    """
                    SELECT trial_id FROM trial
                    WHERE microblock_id=? ORDER BY ordinal LIMIT 1
                    """,
                    (first_block,),
                ).fetchone()[0]
                journal.fail_microblock(
                    str(first_block),
                    "unexpected_flow_control_blocking",
                    root_trial_id=str(root_trial),
                    root_detail='{"data_blocked":3}',
                )

            with mock.patch(
                "quicperf_harness.runner._run_trial",
                side_effect=validated_sample,
            ):
                resumed_result = run_campaign_session(
                    root=ROOT,
                    run_dir=resumed,
                    session=1,
                    endpoint_override=FAKE,
                )

            self.assertEqual(uninterrupted_result["status"], "nonpublishable")
            self.assertEqual(resumed_result["status"], "nonpublishable")
            self.assertEqual(calls, 7)
            self.assertEqual(terminal_rows(uninterrupted), terminal_rows(resumed))

    def test_publication_create_fails_before_execution_on_profile_design_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = load_artifact(
                ROOT / "profiles" / "v2" / "statistical-simulation" / "calibration-v2.json"
            )
            planning = next(
                item
                for item in artifact["planning"]
                if item["name"] == "rate_planning_envelope_rho_0_25"
            )
            planning["equivalence"] = {
                "count": 0,
                "probability": "0",
                "one_sided_95_exact_binomial_lower": "0",
            }
            planning["passed"] = False
            artifact["profile_design_power_gate_passed"] = False
            artifact["publication_analysis_permitted"] = False
            artifact["passed"] = False
            artifact_path = (
                root / "profiles" / "v2" / "statistical-simulation" / "calibration-v2.json"
            )
            artifact_path.parent.mkdir(parents=True)
            artifact_path.write_text(
                json.dumps(artifact, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            profile = json.loads(
                (ROOT / "profiles" / "v2" / "publication.json").read_bytes()
            )
            profile["analysis"]["statistical_calibration"] = frozen_analysis_calibration(
                artifact,
                hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
                "rate_planning_envelope",
            )
            profile_path = root / "publication.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaisesRegex(
                RunnerError, "frozen profile design misses its power gate"
            ):
                create_campaign(
                    root=root,
                    profile=profile_path,
                    run_dir=root / "run",
                    seed="30" * 32,
                    bin_dir=BIN,
                )

    def create_two_lane(
        self, root: Path, *, name: str, qualification_store: Path | None = None
    ) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        profile = json.loads(PROFILE.read_bytes())
        profile["name"] = name
        profile["campaign_kind"] = "qualification"
        profile["schedule"]["lane_assignment"] = "hmac_then_minimum_balancing"
        profile["qualification"]["lane_interference_required"] = True
        profile_path = root / "two-lane.json"
        profile_path.write_text(
            json.dumps(profile, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        run_dir = root / "run"
        create_campaign(
            root=ROOT,
            profile=profile_path,
            run_dir=run_dir,
            seed="32" * 32,
            bin_dir=BIN,
            qualification_store=qualification_store,
        )
        return run_dir

    def test_fake_endpoint_complete_commit_analysis_and_nonpublication_finalize(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.create(Path(temporary))
            result = run_campaign_session(
                root=ROOT, run_dir=run_dir, session=1, endpoint_override=FAKE
            )
            self.assertEqual(result["status"], "complete")
            self.assertEqual(campaign_status(run_dir)["committed_samples"], 2)
            with Journal(run_dir, writable=False) as journal:
                samples = [
                    json.loads(row["sample_json"])
                    for row in journal.connection.execute(
                        "SELECT sample_json FROM sample ORDER BY trial_id"
                    )
                ]
                runtime_before = bytes(
                    journal.connection.execute(
                        "SELECT content FROM artifact WHERE path='runtime/session-1.json'"
                    ).fetchone()["content"]
                )
            self.assertEqual(len(samples), 2)
            for sample in samples:
                diagnostics = sample["endpoint_diagnostics"]
                for role in ("server", "reference_client"):
                    self.assertEqual(
                        diagnostics[f"{role}_validated_units_by_connection"],
                        [[0, sample["units"]["completed"]]],
                    )
                    self.assertEqual(
                        diagnostics[f"{role}_transport_blocking"],
                        {
                            "data_blocked_frames": 0,
                            "stream_data_blocked_frames": 0,
                            "write_blocked_events": 0,
                        },
                    )
            repeated = run_campaign_session(
                root=ROOT, run_dir=run_dir, session=1, endpoint_override=FAKE
            )
            self.assertTrue(repeated["already_terminal"])
            self.assertEqual(repeated["runtime"], result["runtime"])
            with Journal(run_dir, writable=False) as journal:
                runtime_after = bytes(
                    journal.connection.execute(
                        "SELECT content FROM artifact WHERE path='runtime/session-1.json'"
                    ).fetchone()["content"]
                )
            self.assertEqual(runtime_after, runtime_before)
            analysis = analyze_campaign(run_dir)
            self.assertTrue(analysis["analysis_complete"])
            self.assertFalse(analysis["publication_valid"])
            runtime = result["runtime"]
            self.assertEqual(runtime["journal_writes_during_measurement"], 0)
            self.assertEqual(runtime["successful_trial_count"], 2)
            self.assertGreater(runtime["useful_measurement_ns"], 0)
            self.assertGreater(runtime["nonmeasurement_overhead_median_ns"], 0)
            session_runtime = json.loads(
                (run_dir / "artifacts" / "runtime" / "session-1.json").read_bytes()
            )
            self.assertEqual(
                session_runtime["runtime"]["journal_writes_during_measurement"], 0
            )
            render_runtime = json.loads(
                (run_dir / "artifacts" / "runtime" / "render.json").read_bytes()
            )
            self.assertTrue(render_runtime["runtime"]["sixty_second_budget_passed"])
            campaign = campaign_status(run_dir)
            with Journal(run_dir) as journal:
                persisted_spec, _manifest, _schedule = _persisted_run_identity(
                    journal, run_dir
                )
                runtime_reasons = _runtime_gate_reasons(
                    journal, campaign["campaign_id"], 1, persisted_spec
                )
                v21_runtime_reasons = _runtime_gate_reasons(
                    journal,
                    campaign["campaign_id"],
                    1,
                    replace(
                        persisted_spec,
                        schema_version="quicperf.experiment.v2.1",
                    ),
                )
                v21_render = render_analysis(
                    journal,
                    campaign["campaign_id"],
                    persisted_spec.campaign_kind,
                    methodology={
                        "runtime": {
                            "operational_session_timeout_ns": (
                                21_960_000_000_000
                            )
                        }
                    },
                )
                v22_render = render_analysis(
                    journal,
                    campaign["campaign_id"],
                    persisted_spec.campaign_kind,
                    methodology={
                        "version": "2.2",
                        "runtime": {
                            "operational_session_timeout_ns": (
                                8_400_000_000_000
                            )
                        },
                    },
                )
                v22_exceeded = render_analysis(
                    journal,
                    campaign["campaign_id"],
                    persisted_spec.campaign_kind,
                    methodology={
                        "version": "2.2",
                        "runtime": {"operational_session_timeout_ns": 1},
                    },
                )
                v23_render = render_analysis(
                    journal,
                    campaign["campaign_id"],
                    persisted_spec.campaign_kind,
                    methodology={
                        "version": "2.3",
                        "runtime": {
                            "operational_session_timeout_ns": (
                                10_800_000_000_000
                            )
                        },
                    },
                )
            self.assertNotIn(
                "runtime_session_1_one_lane_identity_mismatch", runtime_reasons
            )
            self.assertNotIn(
                "runtime_session_1_useful_time_below_75_percent",
                v21_runtime_reasons,
            )
            rendered_document = json.loads(
                v21_render.artifacts["analysis.json"]
            )
            self.assertEqual(
                rendered_document["schema_version"],
                "quicperf.analysis.v2.1",
            )
            self.assertEqual(
                rendered_document["runtime_efficiency"][0][
                    "publication_qualification_gate"
                ],
                False,
            )
            self.assertIn(
                b"reported, not a publication gate",
                v21_render.artifacts["report.md"],
            )
            v22_document = json.loads(v22_render.artifacts["analysis.json"])
            self.assertEqual(
                v22_document["schema_version"],
                "quicperf.analysis.v2.2",
            )
            self.assertEqual(
                v22_document["runtime_efficiency"][0][
                    "publication_qualification_gate"
                ],
                True,
            )
            self.assertIn(
                b"publication session ceiling",
                v22_render.artifacts["report.md"],
            )
            v23_document = json.loads(v23_render.artifacts["analysis.json"])
            self.assertEqual(
                v23_document["schema_version"],
                "quicperf.analysis.v2.3",
            )
            self.assertTrue(
                v23_document["runtime_efficiency"][0][
                    "publication_qualification_gate"
                ]
            )
            exceeded_document = json.loads(
                v22_exceeded.artifacts["analysis.json"]
            )
            self.assertFalse(exceeded_document["publication_valid"])
            self.assertIn(
                "runtime_session_1_operational_timeout_exceeded",
                exceeded_document["reasons"],
            )
            finalized = finalize_campaign(run_dir)
            self.assertEqual(finalized["finalization_status"], "nonpublishable")
            self.assertFalse(finalized["publication_valid"])
            required = {
                "schedule.tsv", "samples.tsv", "events.jsonl", "row-results.tsv",
                "comparisons.tsv", "quality-audit.tsv", "scenario-coverage.tsv",
                "capacity-search.tsv", "report.md", "checksums.sha256",
            }
            self.assertTrue(required.issubset({path.name for path in (run_dir / "artifacts").iterdir()}))

    def test_unqualified_host_diagnostic_is_frozen_fresh_watermarked_and_terminal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = json.loads(PROFILE.read_bytes())
            profile["name"] = "diagnostic-unqualified-host-ci"
            profile["campaign_kind"] = "diagnostic"
            profile["estimand"] = "symmetric_stack_pair"
            profile["qualification"]["host_stability_required"] = True
            profile["qualification"]["client_headroom_required"] = True
            profile["qualification"]["worker_reuse_required"] = True
            profile_path = root / "profile.json"
            profile_path.write_text(
                json.dumps(profile, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            spec = load_experiment_spec(profile_path)
            manifest = collect_manifest(ROOT, spec, bin_dir=BIN)
            store_path = root / "qualification-store"
            store = QualificationArtifactStore(store_path)
            store.store(
                "host-stability",
                build_qualification_identity("host-stability", spec, manifest),
                QualificationDecision(
                    "host-stability",
                    "qualified",
                    (),
                    {"provider": "amd_delivered_performance_v1"},
                ),
            )
            store.store(
                "client-headroom",
                build_qualification_identity("client-headroom", spec, manifest),
                QualificationDecision(
                    "client-headroom",
                    "not_qualified",
                    ("external_cpu_or_irq_noise",),
                    {},
                ),
            )
            store.store(
                "worker-reuse",
                build_qualification_identity("worker-reuse", spec, manifest),
                QualificationDecision("worker-reuse", "qualified", (), {}),
            )
            authorization = diagnostic_host_failure_authorization(
                root=ROOT,
                profile=profile_path,
                bin_dir=BIN,
                qualification_store=store_path,
            )
            self.assertEqual(authorization["artifact_kind"], "client-headroom")
            run_dir = root / "run"
            create_campaign(
                root=ROOT,
                profile=profile_path,
                run_dir=run_dir,
                seed="39" * 32,
                bin_dir=BIN,
                qualification_store=store_path,
                diagnostic_unqualified_host=True,
                diagnostic_authorization=authorization,
            )
            with Journal(run_dir, writable=False) as journal:
                persisted_spec, persisted_manifest, schedule = (
                    _persisted_run_identity(journal, run_dir)
                )
                self.assertEqual(
                    {block["lane"] for block in schedule["blocks"]}, {0}
                )
                self.assertEqual(
                    {
                        trial["cell_config"]["measurement_duration_ns"]
                        for block in schedule["blocks"]
                        for trial in block["trials"]
                    },
                    {10_000_000_000},
                )
                diagnostic = schedule["diagnostic_unqualified_host"]
                self.assertFalse(diagnostic["publication_qualified"])
                self.assertEqual(
                    {item["kind"] for item in diagnostic["qualifications"]},
                    {
                        "client-headroom",
                        "host-stability",
                        "lane-interference",
                        "tail-window",
                        "window-qualification",
                        "worker-reuse",
                    },
                )
                self.assertIsNotNone(
                    journal.connection.execute(
                        "SELECT 1 FROM artifact WHERE path="
                        "'qualification/diagnostic-physical-failure-authorization.json'"
                    ).fetchone()
                )
            with mock.patch(
                "quicperf_harness.runner._WorkerPool"
            ) as worker_pool, mock.patch(
                "quicperf_harness.runner._run_trial", wraps=_run_trial
            ) as run_trial:
                result = run_campaign_session(
                    root=ROOT,
                    run_dir=run_dir,
                    session=1,
                    endpoint_override=FAKE,
                )
            self.assertEqual(result["status"], "complete")
            worker_pool.assert_not_called()
            self.assertTrue(run_trial.call_args_list)
            self.assertTrue(
                all(
                    call.kwargs["external_thermal_provider"]
                    for call in run_trial.call_args_list
                )
            )
            self.assertTrue(
                all(
                    call.kwargs["allow_client_headroom_failure"]
                    for call in run_trial.call_args_list
                )
            )
            analysis = analyze_campaign(run_dir)
            self.assertTrue(analysis["analysis_complete"])
            self.assertFalse(analysis["publication_valid"])
            self.assertEqual(
                analysis["watermark"], DIAGNOSTIC_UNQUALIFIED_HOST_WATERMARK
            )
            self.assertTrue(
                (run_dir / "artifacts" / "report.md")
                .read_text(encoding="utf-8")
                .startswith("# DIAGNOSTIC — NOT PUBLICATION DATA")
            )
            clean_source = dict(persisted_manifest.source)
            clean_source["clean"] = True
            clean_manifest = replace(
                persisted_manifest,
                source=clean_source,
            )
            with mock.patch(
                "quicperf_harness.runner._persisted_run_identity",
                return_value=(persisted_spec, clean_manifest, schedule),
            ), mock.patch(
                "quicperf_harness.runner._attest_diagnostic_defaults",
                return_value=True,
            ):
                finalized = finalize_campaign(run_dir)
            self.assertEqual(
                finalized["finalization_status"],
                "diagnostic_complete_nonpublication",
            )
            self.assertFalse(finalized["publication_valid"])
            self.assertEqual(finalized["diagnostic_completion_reasons"], [])
            self.assertIn(
                "diagnostic_unqualified_host",
                finalized["finalization_reasons"],
            )

    def test_measurement_start_wait_includes_long_warmup(self) -> None:
        self.assertEqual(
            _measurement_started_timeout_ns(
                measurement_start_raw_ns=15_000_000_000,
                now_raw_ns=10_000_000_000,
            ),
            7_000_000_000,
        )
        self.assertEqual(
            _measurement_started_timeout_ns(
                measurement_start_raw_ns=9_000_000_000,
                now_raw_ns=10_000_000_000,
            ),
            2_000_000_000,
        )

    def test_finalize_preserves_hardware_unqualified_terminal_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.create(Path(temporary))
            with Journal(run_dir) as journal:
                campaign = campaign_identity(journal)
                journal.invalidate_session_hardware(
                    str(campaign["campaign_id"]),
                    1,
                    "tctl_thermal_headroom_breach",
                    {"provider": "amd_delivered_performance_v1"},
                )
            analyze_campaign(run_dir)
            finalized = finalize_campaign(run_dir)
            self.assertEqual(
                finalized["finalization_status"], "hardware_unqualified"
            )
            with Journal(run_dir, writable=False) as journal:
                self.assertEqual(
                    campaign_identity(journal)["status"], "hardware_unqualified"
                )

    def test_journal_mutation_during_measurement_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.create(Path(temporary))
            from quicperf_harness import runner

            original = runner._receive_result_stream
            mutated = False

            def mutate_during_measurement(*args, **kwargs):
                nonlocal mutated
                if not mutated:
                    mutated = True
                    connection = sqlite3.connect(run_dir / "journal.sqlite3")
                    try:
                        connection.execute(
                            """
                            INSERT INTO artifact(campaign_id,path,media_type,content,sha256)
                            SELECT campaign_id,'diagnostic/measurement-mutation',
                                   'application/octet-stream',X'00',?
                            FROM campaign
                            """,
                            ("0" * 64,),
                        )
                        connection.commit()
                    finally:
                        connection.close()
                return original(*args, **kwargs)

            with mock.patch(
                "quicperf_harness.runner._receive_result_stream",
                side_effect=mutate_during_measurement,
            ):
                result = run_campaign_session(
                    root=ROOT,
                    run_dir=run_dir,
                    session=1,
                    endpoint_override=FAKE,
                )
            self.assertEqual(result["status"], "nonpublishable")
            with Journal(run_dir) as journal:
                reasons = {
                    str(row["termination_reason"])
                    for row in journal.connection.execute(
                        "SELECT termination_reason FROM attempt WHERE state='invalid'"
                    )
                }
            self.assertIn("journal_mutation_during_measurement", reasons)

    def test_qualified_workers_reuse_pids_reset_and_keep_trial_dimensions_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = root / "trace.jsonl"
            run_dir = self.create_worker_reuse(
                root, name="acquired-worker-reuse", acquire=True
            )
            result = run_campaign_session(
                root=ROOT,
                run_dir=run_dir,
                session=1,
                endpoint_override=FAKE,
                endpoint_environment={"QUICPERF_FAKE_TRACE": str(trace)},
            )
            self.assertEqual(
                result["status"],
                "complete",
                (result, self.failure_reasons(run_dir), self.trace(trace)),
            )
            events = self.trace(trace)
            for role in ("server", "client"):
                role_events = [event for event in events if event["role"] == role]
                configs = [event for event in role_events if event["event"] == "config"]
                self.assertEqual(len(configs), 2)
                self.assertEqual({event["pid"] for event in configs}, {configs[0]["pid"]})
                self.assertEqual(
                    [event["scenario"] for event in configs], ["download", "reqresp"]
                )
                self.assertEqual({event["backend"] for event in configs}, {"syscall"})
                self.assertEqual({event["lane"] for event in configs}, {0})
                self.assertEqual(
                    [event["event"] for event in role_events],
                    [
                        "worker_start",
                        "config",
                        "result",
                        "reset",
                        "reset_ack",
                        "config",
                        "result",
                        "reset",
                        "reset_ack",
                        "shutdown",
                    ],
                )

            binary = ROOT / "build" / "bin" / "ngtcp2perf"
            baseline = _WorkerPool.key(
                binary=binary,
                role="server",
                backend="syscall",
                lane=0,
                cpuset=(2,),
                cgroup=Path("/sys/fs/cgroup/lane-0/server"),
            )
            self.assertNotEqual(
                baseline,
                _WorkerPool.key(
                    binary=binary,
                    role="server",
                    backend="iouring",
                    lane=0,
                    cpuset=(2,),
                    cgroup=Path("/sys/fs/cgroup/lane-0/server"),
                ),
            )
            self.assertNotEqual(
                baseline,
                _WorkerPool.key(
                    binary=binary,
                    role="server",
                    backend="syscall",
                    lane=1,
                    cpuset=(6,),
                    cgroup=Path("/sys/fs/cgroup/lane-1/server"),
                ),
            )

    def test_frozen_process_policy_controls_reuse_without_an_artifact(self):
        for name, persistent in (
            ("fresh-worker-policy", False),
            ("persistent-worker-policy", True),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                trace = root / "trace.jsonl"
                run_dir = self.create_worker_reuse(
                    root,
                    name=name,
                    acquire=False,
                    persistent=persistent,
                )
                result = run_campaign_session(
                    root=ROOT,
                    run_dir=run_dir,
                    session=1,
                    endpoint_override=FAKE,
                    endpoint_environment={"QUICPERF_FAKE_TRACE": str(trace)},
                )
                self.assertEqual(
                    result["status"],
                    "complete",
                    (result, self.failure_reasons(run_dir), self.trace(trace)),
                )
                events = self.trace(trace)
                resets = [event for event in events if event["event"] == "reset_ack"]
                starts = [event for event in events if event["event"] == "worker_start"]
                self.assertEqual(len(resets), 4 if persistent else 0)
                self.assertEqual(len(starts), 2 if persistent else 4)

    def test_lifecycle_scenarios_remain_fresh_even_when_reuse_is_qualified(self):
        self.assertFalse(_worker_reuse_eligible("publication", "connect"))
        self.assertFalse(_worker_reuse_eligible("publication", "resumed_connect"))
        self.assertFalse(_worker_reuse_eligible("publication", "zero_rtt_reqresp"))
        self.assertFalse(_worker_reuse_eligible("memory", "download"))
        self.assertTrue(_worker_reuse_eligible("publication", "download"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = root / "trace.jsonl"
            run_dir = self.create_worker_reuse(
                root,
                name="qualified-fresh-lifecycle",
                acquire=True,
                lifecycle_scenarios=True,
            )
            result = run_campaign_session(
                root=ROOT,
                run_dir=run_dir,
                session=1,
                endpoint_override=FAKE,
                endpoint_environment={"QUICPERF_FAKE_TRACE": str(trace)},
            )
            self.assertEqual(result["status"], "complete")
            events = self.trace(trace)
            self.assertFalse(any(event["event"] == "reset" for event in events))
            self.assertEqual(
                len([event for event in events if event["event"] == "worker_start"]),
                4,
            )

    def test_reset_failure_discards_reuse_workers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = root / "trace.jsonl"
            run_dir = self.create_worker_reuse(
                root, name="worker-reuse-validation", acquire=False
            )
            result = run_campaign_session(
                root=ROOT,
                run_dir=run_dir,
                session=1,
                endpoint_override=FAKE,
                endpoint_environment={
                    "QUICPERF_FAKE_BEHAVIOR": "reset_failure",
                    "QUICPERF_FAKE_TRACE": str(trace),
                },
            )
            self.assertEqual(result["status"], "nonpublishable")
            events = self.trace(trace)
            failed_pids = {
                event["pid"] for event in events if event["event"] == "reset_failure"
            }
            self.assertTrue(failed_pids)
            for pid in failed_pids:
                self.assertFalse(Path(f"/proc/{pid}").exists())
                self.assertEqual(
                    len(
                        [
                            event
                            for event in events
                            if event["pid"] == pid and event["event"] == "config"
                        ]
                    ),
                    1,
                )

    def test_late_arm_recreates_workers_and_retries_only_unstarted_block(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = root / "trace.jsonl"
            marker = root / "late-arm-once"
            run_dir = self.create_worker_reuse(
                root,
                name="arm-control-retry",
                acquire=False,
                arm_retry=True,
            )
            with mock.patch(
                "quicperf_harness.runner._arm_control_policy",
                return_value=_ArmControlPolicy(
                    V21_ARM_LEAD_NS,
                    V21_ARM_PRE_SEND_GUARD_NS,
                    2,
                    1,
                ),
            ):
                result = run_campaign_session(
                    root=ROOT,
                    run_dir=run_dir,
                    session=1,
                    endpoint_override=FAKE,
                    endpoint_environment={
                        "QUICPERF_FAKE_BEHAVIOR": "late_arm_once",
                        "QUICPERF_FAKE_LATE_ARM_MARKER": str(marker),
                        "QUICPERF_FAKE_LATE_ARM_DELAY_NS": "900000000",
                        "QUICPERF_FAKE_TRACE": str(trace),
                    },
                )
            self.assertEqual(
                result["status"],
                "complete",
                (result, self.failure_reasons(run_dir), self.trace(trace)),
            )
            self.assertEqual(
                result["recovery"]["arm_control_window_rejections"], 1
            )
            events = self.trace(trace)
            rejected_pids = {
                event["pid"]
                for event in events
                if event["event"] == "arm_rejected"
            }
            result_pids = {
                event["pid"]
                for event in events
                if event["event"] == "result"
            }
            self.assertEqual(len(rejected_pids), 1)
            self.assertTrue(result_pids)
            self.assertTrue(rejected_pids.isdisjoint(result_pids))
            rejected_trial_ids = {
                event["trial_id"]
                for event in events
                if event["event"] == "arm_rejected"
            }
            rejected_generation_pids = {
                event["pid"]
                for event in events
                if event["event"] == "config"
                and event["trial_id"] in rejected_trial_ids
            }
            self.assertEqual(len(rejected_generation_pids), 2)
            self.assertTrue(rejected_generation_pids.isdisjoint(result_pids))
            with Journal(run_dir, writable=False) as journal:
                states = {
                    (str(row["slot"]), str(row["status"])): int(row["count"])
                    for row in journal.connection.execute(
                        """
                        SELECT slot,status,COUNT(*) AS count
                        FROM microblock GROUP BY slot,status
                        """
                    )
                }
                self.assertEqual(
                    states,
                    {
                        ("primary", "committed"): 1,
                        ("primary", "superseded"): 1,
                        ("retry", "committed"): 1,
                        ("retry", "dormant"): 1,
                    },
                )
                self.assertEqual(
                    journal.connection.execute(
                        "SELECT COUNT(*) FROM committed_sample"
                    ).fetchone()[0],
                    2,
                )

    def test_late_arm_retry_failure_is_terminal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = root / "trace.jsonl"
            run_dir = self.create_worker_reuse(
                root,
                name="arm-control-retry-exhaustion",
                acquire=False,
                arm_retry=True,
            )
            with mock.patch(
                "quicperf_harness.runner._arm_control_policy",
                return_value=_ArmControlPolicy(
                    V21_ARM_LEAD_NS,
                    V21_ARM_PRE_SEND_GUARD_NS,
                    2,
                    1,
                ),
            ):
                result = run_campaign_session(
                    root=ROOT,
                    run_dir=run_dir,
                    session=1,
                    endpoint_override=FAKE,
                    endpoint_environment={
                        "QUICPERF_FAKE_BEHAVIOR": "late_arm_always",
                        "QUICPERF_FAKE_LATE_ARM_DELAY_NS": "900000000",
                        "QUICPERF_FAKE_TRACE": str(trace),
                    },
                )
            self.assertEqual(result["status"], "nonpublishable")
            self.assertEqual(
                result["recovery"]["arm_control_window_rejections"], 2
            )
            self.assertEqual(
                result["recovery"]["arm_control_retry_exhausted"], 1
            )
            with Journal(run_dir, writable=False) as journal:
                states = {
                    (str(row["slot"]), str(row["status"])): int(row["count"])
                    for row in journal.connection.execute(
                        """
                        SELECT slot,status,COUNT(*) AS count
                        FROM microblock GROUP BY slot,status
                        """
                    )
                }
            self.assertEqual(
                states,
                {
                    ("primary", "failed"): 1,
                    ("primary", "superseded"): 1,
                    ("retry", "dormant"): 1,
                    ("retry", "failed"): 1,
                },
            )

    def test_two_lane_execution_is_gated_and_qualification_profile_runs_concurrently(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gated = self.create_two_lane(root / "gated", name="two-lane-production-test")
            with self.assertRaisesRegex(
                RunnerError, "exact-identity lane-interference"
            ):
                run_campaign_session(
                    root=ROOT, run_dir=gated, session=1, endpoint_override=FAKE
                )
            with Journal(gated) as journal:
                spec, manifest, schedule = _persisted_run_identity(journal, gated)
                campaign = campaign_identity(journal)
                self.assertEqual(
                    {int(block["lane"]) for block in schedule["blocks"]},
                    {0, 1},
                )
                self.assertEqual(
                    journal.connection.execute(
                        "SELECT COUNT(*) FROM sample"
                    ).fetchone()[0],
                    0,
                )
                with self.assertRaisesRegex(
                    RunnerError, "exact-identity lane-interference"
                ):
                    _attest_frozen_lane_count(
                        journal,
                        str(campaign["campaign_id"]),
                        spec,
                        manifest,
                        2,
                    )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = self.create_two_lane(
                root, name="lane-interference-validation"
            )
            worker_counts: list[int] = []

            def executor(*args, **kwargs):
                worker_counts.append(int(kwargs["max_workers"]))
                return RealThreadPoolExecutor(*args, **kwargs)

            with mock.patch("quicperf_harness.runner.ThreadPoolExecutor", executor):
                result = run_campaign_session(
                    root=ROOT, run_dir=run_dir, session=1, endpoint_override=FAKE
                )
            failures = self.failure_reasons(run_dir)
            self.assertEqual(result["status"], "complete", failures)
            self.assertEqual(result["runtime"]["qualified_lane_count"], 2)
            self.assertEqual(worker_counts, [2])
            with Journal(run_dir) as journal:
                starts = {
                    json.loads(row["sample_json"])["timestamps"][
                        "global_start_raw_ns"
                    ]
                    for row in journal.connection.execute(
                        "SELECT sample_json FROM sample"
                    )
                }
            self.assertEqual(len(starts), 1, "parallel lanes did not share one ARM epoch")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_root = root / "qualified"
            profile_root.mkdir(parents=True)
            profile = json.loads(PROFILE.read_bytes())
            profile["name"] = "qualified-two-lane-production-test"
            profile["campaign_kind"] = "qualification"
            profile["schedule"]["lane_assignment"] = "hmac_then_minimum_balancing"
            profile["qualification"]["lane_interference_required"] = True
            profile_path = profile_root / "profile.json"
            profile_path.write_text(
                json.dumps(profile, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            spec = load_experiment_spec(profile_path)
            manifest = collect_manifest(ROOT, spec, bin_dir=BIN)
            store = root / "store"
            QualificationArtifactStore(store).store(
                "lane-interference",
                build_qualification_identity("lane-interference", spec, manifest),
                QualificationDecision(
                    "lane-interference", "qualified", (), {"max_lanes": 2}
                ),
            )
            run_dir = profile_root / "run"
            create_campaign(
                root=ROOT,
                profile=profile_path,
                run_dir=run_dir,
                seed="33" * 32,
                bin_dir=BIN,
                qualification_store=store,
            )
            with Journal(run_dir) as journal:
                frozen_spec, frozen_manifest, schedule = _persisted_run_identity(
                    journal, run_dir
                )
                lanes = {int(block["lane"]) for block in schedule["blocks"]}
                self.assertEqual(lanes, {0, 1})
                campaign = campaign_identity(journal)
                _attest_frozen_lane_count(
                    journal,
                    str(campaign["campaign_id"]),
                    frozen_spec,
                    frozen_manifest,
                    2,
                )

    def test_crash_before_ready_is_terminal_and_partial_data_never_commits(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.create(Path(temporary))
            result = run_campaign_session(
                root=ROOT,
                run_dir=run_dir,
                session=1,
                endpoint_override=FAKE,
                endpoint_environment={"QUICPERF_FAKE_BEHAVIOR": "crash_before_ready"},
            )
            self.assertEqual(result["status"], "nonpublishable")
            status = campaign_status(run_dir)
            self.assertEqual(status["status"], "nonpublishable")
            self.assertEqual(status["committed_samples"], 0)
            self.assertEqual(status["trial_states"], {"failed": 2})

    def test_wrong_identity_and_duplicate_result_cannot_commit(self):
        for behavior in ("wrong_identity", "duplicate_result"):
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory() as temporary:
                run_dir = self.create(Path(temporary))
                result = run_campaign_session(
                    root=ROOT,
                    run_dir=run_dir,
                    session=1,
                    endpoint_override=FAKE,
                    endpoint_environment={"QUICPERF_FAKE_BEHAVIOR": behavior},
                )
                self.assertEqual(result["status"], "nonpublishable")
                self.assertEqual(campaign_status(run_dir)["committed_samples"], 0)

    def test_unsupported_capability_remains_visible_as_unsupported(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.create(Path(temporary))
            result = run_campaign_session(
                root=ROOT,
                run_dir=run_dir,
                session=1,
                endpoint_override=FAKE,
                endpoint_environment={"QUICPERF_FAKE_BEHAVIOR": "unsupported"},
            )
            self.assertEqual(result["status"], "nonpublishable")
            self.assertEqual(campaign_status(run_dir)["trial_states"], {"unsupported": 2})
            analysis = analyze_campaign(run_dir)
            self.assertIn("unsupported", analysis["analysis_reasons"])

    def test_mutated_frozen_spec_is_rejected_on_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.create(Path(temporary))
            (run_dir / "spec.json").write_bytes((run_dir / "spec.json").read_bytes() + b"\n")
            with self.assertRaises(IdentityMismatchError):
                run_campaign_session(
                    root=ROOT, run_dir=run_dir, session=1, endpoint_override=FAKE
                )


class CommandAndRendererTests(unittest.TestCase):
    def test_loss_trace_gate_recomputes_exact_phase_direction_prefixes(self):
        seed = bytes.fromhex("0a" * 32)

        def result(direction: int) -> dict[str, int]:
            warmup = 1_000
            measurement = 2_000
            warmup_drops = _expected_loss_drops(
                seed, measurement=False, direction=direction, packet_count=warmup
            )
            measurement_drops = _expected_loss_drops(
                seed,
                measurement=True,
                direction=direction,
                packet_count=measurement,
            )
            return {
                "loss_direction": direction,
                "loss_packets_considered": warmup + measurement,
                "loss_packets_dropped": warmup_drops + measurement_drops,
                "loss_warmup_packets_considered": warmup,
                "loss_warmup_packets_dropped": warmup_drops,
                "loss_measurement_packets_considered": measurement,
                "loss_measurement_packets_dropped": measurement_drops,
                "transport_packets_lost": 1,
                "transport_timer_expirations": 1,
            }

        server = result(0)
        client = result(1)
        config = {
            "scenario": "loss_recovery",
            "path_profile": "loss_recovery_v1",
            "trace_seed": seed.hex(),
        }
        path_evidence = {
            "profile": "loss_recovery_v1",
            "trace_epoch_raw_ns": 1,
            "trace_seed": seed.hex(),
            "directions": {
                str(direction): {
                    "bytes": 1,
                    "packets": 1,
                    "drops": 0,
                    "overlimits": 0,
                    "requeues": 0,
                }
                for direction in (0, 1)
            },
        }
        self.assertTrue(_loss_trace_gate(config, server, client, path_evidence))
        server["loss_measurement_packets_dropped"] += 1
        server["loss_packets_dropped"] += 1
        self.assertFalse(_loss_trace_gate(config, server, client, path_evidence))
        server["loss_measurement_packets_dropped"] -= 1
        server["loss_packets_dropped"] -= 1
        path_evidence["directions"]["0"]["drops"] = 1
        self.assertFalse(_loss_trace_gate(config, server, client, path_evidence))
        for index in range(10):
            _expected_loss_drops(
                bytes((index,)) * 32,
                measurement=True,
                direction=0,
                packet_count=0,
            )
        from quicperf_harness import runner
        self.assertLessEqual(len(runner._LOSS_PREFIX_CACHE), 8)

    def test_every_profile_scenario_translates_to_strict_native_workload_fields(self):
        expected = {
            "download": (1, 262_144, 8, 0, 0, 0, 0, 0, 0),
            "upload": (1, 262_144, 8, 0, 0, 0, 0, 0, 0),
            "multistream_download": (8, 262_144, 8, 0, 0, 0, 0, 0, 0),
            "multistream_upload": (8, 262_144, 8, 0, 0, 0, 0, 0, 0),
            "bidi": (1, 262_144, 0, 0, 0, 0, 0, 0, 0),
            "loss_recovery": (1, 262_144, 8, 0, 0, 0, 0, 0, 0),
            "flow_control": (1, 262_144, 8, 0, 0, 0, 0, 0, 0),
            "small_payload_pps": (1, 0, 0, 0, 64, 0, 0, 0, 0),
            "datagram": (0, 0, 0, 0, 0, 64, 128, 2_048, 0),
            "reqresp": (1, 0, 64, 1_024, 0, 0, 0, 16, 0),
            "stream_churn": (1, 0, 0, 0, 1, 0, 0, 16, 0),
            "close_reset_cleanup": (1, 0, 0, 0, 1, 0, 0, 16, 0),
            "connect": (0, 0, 0, 0, 0, 0, 0, 16, 0),
            "resumed_connect": (0, 0, 0, 0, 0, 0, 0, 16, 16),
            "zero_rtt_reqresp": (1, 0, 64, 1_024, 0, 0, 0, 16, 16),
            "memory_curve": (1, 262_144, 1, 1, 1, 64, 0, 1, 0),
        }
        self.assertEqual(_NATIVE_WORKLOAD_FIELDS, expected)
        observed = {}
        for profile in ("publication.json", "memory.json"):
            spec = load_experiment_spec(ROOT / "profiles" / "v2" / profile)
            for workload in spec.raw["workloads"]:
                scenario = str(workload["scenario"])
                config = _endpoint_config(
                    root=ROOT,
                    spec=spec,
                    workload=workload,
                    cell={"scenario": scenario, "concurrency": int(workload["connections"])},
                    role="server",
                    backend="syscall",
                    peer_port=0,
                )
                observed[scenario] = tuple(
                    int(config[field])
                    for field in (
                        "active_streams_per_connection",
                        "bulk_chunk_bytes",
                        "request_body_bytes",
                        "response_body_bytes",
                        "operation_body_bytes",
                        "datagram_body_bytes",
                        "datagram_max_unreturned_per_connection",
                        "global_operation_slots",
                        "ticket_slots",
                    )
                )
        self.assertEqual(observed, expected)

    def test_native_config_is_complete_role_specific_and_flat(self):
        spec = load_experiment_spec(PROFILE)
        workload = spec.raw["workloads"][0]
        cell = {"scenario": workload["scenario"], "concurrency": 16}
        server = _endpoint_config(
            root=ROOT, spec=spec, workload=workload, cell=cell,
            role="server", backend="syscall", peer_port=0,
        )
        client = _endpoint_config(
            root=ROOT, spec=spec, workload=workload, cell=cell,
            role="client", backend="iouring", peer_port=4433,
        )
        self.assertEqual(len(server), 63)
        self.assertTrue(all(not isinstance(value, (dict, list)) for value in server.values()))
        self.assertEqual((server["event_loop_workers"], client["event_loop_workers"]), (1, 2))
        publication = load_experiment_spec(ROOT / "profiles/v2/publication.json")
        publication_workload = publication.raw["workloads"][0]
        publication_client = _endpoint_config(
            root=ROOT,
            spec=publication,
            workload=publication_workload,
            cell={
                "scenario": publication_workload["scenario"],
                "concurrency": 16,
            },
            role="client",
            backend="iouring",
            peer_port=4433,
        )
        self.assertEqual(publication_client["event_loop_workers"], 4)
        four_core = _endpoint_config(
            root=ROOT, spec=spec, workload=workload,
            cell={**cell, "client_event_loop_workers": 4},
            role="client", backend="iouring", peer_port=4433,
        )
        self.assertEqual(four_core["event_loop_workers"], 4)
        qualified_window = _endpoint_config(
            root=ROOT,
            spec=spec,
            workload=workload,
            cell={**cell, "measurement_duration_ns": 5_000_000_000},
            role="client",
            backend="iouring",
            peer_port=4433,
        )
        self.assertEqual(
            qualified_window["measurement_duration_ns"], 5_000_000_000
        )
        with self.assertRaisesRegex(RunnerError, "two or four workers"):
            _endpoint_config(
                root=ROOT, spec=spec, workload=workload,
                cell={**cell, "client_event_loop_workers": 3},
                role="client", backend="iouring", peer_port=4433,
            )
        self.assertEqual((server["peer_address"], server["peer_port"]), ("0.0.0.0", 0))
        self.assertEqual((client["peer_address"], client["peer_port"]), ("127.0.0.1", 4433))
        self.assertFalse(server["tls_verify_peer"])
        self.assertTrue(client["tls_verify_peer"])
        self.assertEqual(server["tls_hostname"], "server.quicperf.test")
        self.assertEqual(client["tls_hostname"], "server.quicperf.test")
        self.assertEqual(server["quic_version"], "0x00000001")
        self.assertEqual(server["alpn"], "qperf/2")
        self.assertEqual(server["initial_congestion_window_bytes"], 13_500)
        self.assertEqual(server["max_ack_delay_ns"], 25_000_000)
        self.assertEqual(server["datagram_max_frame_size"], 1_200)
        self.assertEqual(server["tls_cipher_suite"], "TLS_AES_128_GCM_SHA256")
        self.assertEqual(server["tls_key_exchange"], "X25519")
        self.assertEqual(server["tls_leaf_signature"], "Ed25519")
        self.assertTrue(server["tls_one_use_tickets"])
        self.assertTrue(client["require_multishot_receive"])

    def test_tail_schedule_freezes_every_qualified_scenario_duration(self):
        spec = load_experiment_spec(ROOT / "profiles" / "v2" / "tail.json")
        selected = {
            scenario: (2, 5, 10, 20)[index % 4]
            for index, scenario in enumerate(spec.scenarios)
        }
        decision = QualificationDecision(
            "tail-window",
            "qualified",
            (),
            {"scenario_durations_seconds": selected},
        )
        self.assertEqual(_tail_qualification_durations(decision, spec), selected)
        schedule = _generic_schedule(
            spec,
            b"tail-schedule-test",
            b"t" * 32,
            tail_durations_seconds=selected,
        )
        for block in schedule["blocks"]:
            for trial in block["trials"]:
                cell = trial["cell_config"]
                self.assertEqual(
                    cell["measurement_duration_ns"],
                    selected[cell["scenario"]] * 1_000_000_000,
                )
        missing = dict(selected)
        missing.pop(next(iter(missing)))
        with self.assertRaisesRegex(RunnerError, "every frozen tail scenario"):
            _tail_qualification_durations(
                QualificationDecision(
                    "tail-window",
                    "qualified",
                    (),
                    {"scenario_durations_seconds": missing},
                ),
                spec,
            )
    def test_command_surface_and_exit_code_constants_are_visible(self):
        completed = subprocess.run(
            [str(ROOT / "tools" / "quicperfctl"), "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        for command in (
            "doctor", "campaign", "capacity", "memory", "tail", "suite",
            "export", "legacy",
        ):
            self.assertIn(command, completed.stdout)
        diagnostic_help = subprocess.run(
            [
                str(ROOT / "tools" / "quicperfctl"),
                "suite",
                "run",
                "--help",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(diagnostic_help.returncode, 0)
        self.assertIn("--diagnostic-unqualified-host", diagnostic_help.stdout)
        self.assertNotIn("--campaign", diagnostic_help.stdout)
        self.assertNotIn("--all-confirmatory", diagnostic_help.stdout)

    def test_publication_session_budget_is_hard_and_diagnostic_exempt(self):
        publication = load_experiment_spec(ROOT / "profiles/v2/publication.json")
        publication_v22 = load_experiment_spec(
            ROOT / "profiles/v2.2/publication.json"
        )
        publication_v23 = load_experiment_spec(
            ROOT / "profiles/v2.3/publication.json"
        )
        diagnostic = load_experiment_spec(
            ROOT / "profiles/v2/symmetric-diagnostic.json"
        )
        budget = PUBLICATION_SESSION_WALL_BUDGET_NS
        self.assertEqual(budget, 12_672_000_000_000)
        self.assertFalse(
            _publication_session_budget_reached(publication, False, budget - 1)
        )
        self.assertTrue(
            _publication_session_budget_reached(publication, False, budget)
        )
        self.assertFalse(
            _publication_session_budget_reached(publication, True, budget)
        )
        self.assertFalse(
            _publication_session_budget_reached(diagnostic, False, budget)
        )
        self.assertTrue(
            _publication_session_budget_allows_block(
                publication,
                False,
                budget - PUBLICATION_SESSION_FINALIZATION_RESERVE_NS - 1,
                1,
            )
        )
        self.assertFalse(
            _publication_session_budget_allows_block(
                publication,
                False,
                budget - PUBLICATION_SESSION_FINALIZATION_RESERVE_NS,
                1,
            )
        )
        v22_budget = 8_400_000_000_000
        self.assertFalse(
            _publication_session_budget_reached(
                publication_v22, False, v22_budget - 1
            )
        )
        self.assertTrue(
            _publication_session_budget_reached(
                publication_v22, False, v22_budget
            )
        )
        self.assertTrue(
            _publication_session_budget_allows_block(
                publication_v22,
                False,
                v22_budget
                - PUBLICATION_SESSION_FINALIZATION_RESERVE_NS
                - 1,
                1,
            )
        )
        self.assertFalse(
            _publication_session_budget_allows_block(
                publication_v22,
                False,
                v22_budget
                - PUBLICATION_SESSION_FINALIZATION_RESERVE_NS,
                1,
            )
        )
        v23_budget = 10_800_000_000_000
        self.assertFalse(
            _publication_session_budget_reached(
                publication_v23, False, v23_budget - 1
            )
        )
        self.assertTrue(
            _publication_session_budget_reached(
                publication_v23, False, v23_budget
            )
        )
        self.assertTrue(
            _publication_session_budget_allows_block(
                publication_v23,
                False,
                v23_budget
                - PUBLICATION_SESSION_FINALIZATION_RESERVE_NS
                - 1,
                1,
            )
        )
        self.assertFalse(
            _publication_session_budget_allows_block(
                publication_v23,
                False,
                v23_budget
                - PUBLICATION_SESSION_FINALIZATION_RESERVE_NS,
                1,
            )
        )

    def test_publication_epoch_failure_prefers_root_over_barrier_collateral(self):
        barrier = _PublicationEpochFailure(
            block_id="01" * 32,
            root_trial_id="02" * 32,
            cell_ids=("03" * 32,),
            error=EndpointRunError(
                "parallel_measurement_barrier_failed:after_result",
                terminal_state="invalid",
            ),
            collateral=True,
        )
        root = _PublicationEpochFailure(
            block_id="04" * 32,
            root_trial_id="05" * 32,
            cell_ids=("06" * 32,),
            error=EndpointRunError("adapter_failed"),
            collateral=False,
        )
        decision, selected = _publication_epoch_failure_decision(
            (barrier, root)
        )
        self.assertEqual(decision, "deterministic")
        self.assertIs(selected, root)

        transient = _PublicationEpochFailure(
            block_id="07" * 32,
            root_trial_id="08" * 32,
            cell_ids=("09" * 32,),
            error=EndpointRunError(
                "host_stability_monitor_transient",
                infrastructure_transient=True,
                terminal_state="invalid",
            ),
            collateral=False,
        )
        decision, selected = _publication_epoch_failure_decision(
            (barrier, root, transient)
        )
        self.assertEqual(decision, "replay")
        self.assertIs(selected, transient)

        hardware = HardwareUnqualifiedError("thermal_throttle")
        decision, selected = _publication_epoch_failure_decision(
            (barrier, transient, hardware)
        )
        self.assertEqual(decision, "hardware")
        self.assertIs(selected, hardware)

    def test_parallel_padding_preserves_unexpected_overhead(self):
        regular_arm_ns = 2_250_000_000
        loss_arm_ns = 5_500_000_000
        padding_ns = _parallel_scheduled_padding_ns(
            mock.Mock(parallel_arm_ns=loss_arm_ns),
            regular_arm_ns,
        )
        self.assertEqual(padding_ns, 3_250_000_000)
        self.assertEqual(
            _parallel_scheduled_padding_ns(
                mock.Mock(parallel_arm_ns=loss_arm_ns),
                loss_arm_ns,
            ),
            0,
        )
        self.assertEqual(
            _parallel_scheduled_padding_ns(None, regular_arm_ns),
            0,
        )
        unexpected_ns = 1_000_000_000
        arm_lead_ns = 750_000_000
        self.assertEqual(
            _intrinsic_nonmeasurement_overhead_ns(
                trial_wall_ns=(
                    arm_lead_ns + regular_arm_ns + padding_ns + unexpected_ns
                ),
                warmup_ns=250_000_000,
                measurement_ns=2_000_000_000,
                arm_lead_ns=arm_lead_ns,
                parallel_scheduled_padding_ns=padding_ns,
            ),
            unexpected_ns,
        )
        self.assertGreater(unexpected_ns, 750_000_000)

    def test_intrinsic_overhead_excludes_one_accepted_arm_lead(self):
        arm_lead_ns = 750_000_000
        warmup_ns = 250_000_000
        measurement_ns = 2_000_000_000
        unexpected_ns = 200_000_000
        self.assertEqual(
            _intrinsic_nonmeasurement_overhead_ns(
                trial_wall_ns=(
                    arm_lead_ns
                    + warmup_ns
                    + measurement_ns
                    + unexpected_ns
                ),
                warmup_ns=warmup_ns,
                measurement_ns=measurement_ns,
                arm_lead_ns=arm_lead_ns,
                parallel_scheduled_padding_ns=0,
            ),
            unexpected_ns,
        )

    def test_renderer_rejects_incomparable_global_leaderboard(self):
        with self.assertRaisesRegex(RenderError, "campaign_kind"):
            reject_mixed_leaderboard(
                [
                    {"campaign_kind": "publication", "estimand": "fixed"},
                    {"campaign_kind": "capacity", "estimand": "capacity"},
                ]
            )

    def test_fixed_renderer_pairs_two_sessions_into_twelve_superblocks(self):
        rows = []
        for session in (1, 2):
            for williams_row in range(12):
                block = (session - 1) * 12 + williams_row
                reference_client = (
                    "ngtcp2perf"
                    if (williams_row + session - 1) % 2 == 0
                    else "picoperf"
                )
                for server, rate in (("ngtcp2perf", 100.0), ("picoperf", 110.0)):
                    rows.append(
                        {
                            "config": {
                                "estimand": "fixed_treatment_server",
                                "scenario": "download",
                                "path_profile": "loopback",
                                "server_backend": "syscall",
                                "server": server,
                                "reference_client": reference_client,
                            },
                            "sample": {
                                "completion_status": "valid",
                                "metric": {
                                    "name": "throughput_gbps",
                                    "orientation": "higher_is_better",
                                    "derived_decimal": str(rate),
                                },
                            },
                            "planned_microblock_id": f"{block + 1:064x}",
                            "superblock_id": f"{williams_row + 1:064x}",
                            "williams_row": williams_row,
                            "session_number": session,
                        }
                    )
        comparisons, reasons = _comparisons(rows)
        self.assertEqual(reasons, [])
        self.assertIn(b"picoperf/ngtcp2perf", comparisons)
        self.assertIn(b"superior", comparisons)

    def test_capacity_search_is_separate_from_held_out_confirmation(self):
        rows = []
        rates = {1: 100.0, 2: 190.0, 4: 300.0, 8: 289.0, 16: 200.0}
        for search_round, (concurrency, client) in enumerate(
            (load, client)
            for load in rates
            for client in ("ngtcp2perf", "picoperf")
        ):
            rows.append(self.capacity_row(
                phase="exploratory", concurrency=concurrency, rate=rates[concurrency],
                reference_client=client, round_index=search_round,
            ))
        for round_index in range(24):
            for concurrency, rate in ((2, 270.0), (4, 300.0), (8, 300.0)):
                rows.append(self.capacity_row(
                    phase="confirmatory", concurrency=concurrency, rate=rate,
                    reference_client=(
                        "ngtcp2perf"
                        if (round_index % 12 + round_index // 12) % 2 == 0
                        else "picoperf"
                    ),
                    round_index=round_index, candidate=4,
                ))

        table, comparisons, reasons = _capacity_artifacts(rows)
        self.assertIn(b"\t4\t", table)
        self.assertIn(b"confirmation_interval", table)
        self.assertIn(b"confirmed", table)
        self.assertEqual(comparisons.splitlines()[0].count(b"\t"), 11)
        self.assertEqual(reasons, ["capacity_server_comparison_incomplete"])

    def test_memory_renderer_fits_each_block_before_paired_inference(self):
        rows = []
        for server, intercept, slope in (
            ("ngtcp2perf", 1_000_000.0, 2_000.0),
            ("picoperf", 900_000.0, 1_800.0),
        ):
            for block in range(24):
                for connections in (0, 64, 256, 1024):
                    rows.append({
                        "config": {
                            "server": server,
                            "server_backend": "syscall",
                            "block_position": block,
                            "connections": connections,
                        },
                        "session_number": 1 if block < 12 else 2,
                        "williams_row": block % 12,
                        "superblock_id": f"{block % 12 + 1:064x}",
                        "sample": {
                            "completion_status": "valid",
                            "metric": {
                                "name": "memory_current_bytes",
                                "derived_decimal": str(intercept + slope * connections),
                            },
                        },
                    })
        curves, comparisons, reasons = _memory_artifacts(rows)
        self.assertEqual(reasons, [])
        self.assertEqual(len(curves.splitlines()), 193)
        self.assertIn(b"bytes_per_connection", comparisons)
        self.assertIn(b"intercept_bytes", comparisons)

    def test_tail_renderer_uses_first_1024_per_block_and_wilson_gate(self):
        rows = []
        start = 1_000_000
        end = start + 2_000_000_000
        for server, scale in (("ngtcp2perf", 1), ("picoperf", 2)):
            for block in range(24):
                operations = [
                    {
                        "operation_sequence": sequence,
                        "start_raw_ns": start + sequence * 2_000,
                        "terminal_raw_ns": start + sequence * 2_000 + scale * (1_000 + sequence),
                        "latency_ns": scale * (1_000 + sequence),
                    }
                    for sequence in range(1024)
                ]
                rows.append({
                    "config": {
                        "server": server,
                        "server_backend": "syscall",
                        "scenario": "reqresp",
                        "path_profile": "loopback",
                        "measurement_duration_ns": 2_000_000_000,
                        "reference_client": (
                            "ngtcp2perf"
                            if (block % 12 + block // 12) % 2 == 0
                            else "picoperf"
                        ),
                    },
                    "sample": {
                        "completion_status": "valid",
                        "timestamps": {"global_start_raw_ns": start, "global_end_raw_ns": end},
                        "tail": {
                            "started_operations": 1024,
                            "failed_operations": 0,
                            "censored_operations": 0,
                            "histogram_resolution_ns": 1,
                            "operations": operations,
                        },
                    },
                    "planned_microblock_id": f"{block:064x}",
                    "session_number": 1 if block < 12 else 2,
                    "williams_row": block % 12,
                    "superblock_id": f"{block % 12 + 1:064x}",
                })
        blocks, comparisons, reasons = _tail_artifacts(rows)
        self.assertEqual(reasons, [])
        self.assertEqual(len(blocks.splitlines()), 49)
        self.assertIn(b"tail_latency|syscall|reqresp|loopback", comparisons)
        for row in rows:
            if row["planned_microblock_id"] == f"{0:064x}":
                row["config"]["reference_client"] = "picoperf"
        _blocks, _comparisons, reasons = _tail_artifacts(rows)
        self.assertIn(
            "tail_inference_requires_twelve_blocks_per_reference_client",
            reasons,
        )
        for row in rows:
            if row["planned_microblock_id"] == f"{0:064x}":
                row["config"]["reference_client"] = "ngtcp2perf"
        rows[0]["config"]["measurement_duration_ns"] = 5_000_000_000
        _blocks, _comparisons, reasons = _tail_artifacts(rows)
        self.assertIn("malformed_tail_observations", reasons)

    @staticmethod
    def capacity_row(
        *, phase: str, concurrency: int, rate: float, reference_client: str,
        round_index: int, candidate: int | None = None,
    ) -> dict[str, object]:
        config = {
            "estimand": "capacity_frontier",
            "phase": phase,
            "server": "ngtcp2perf",
            "server_backend": "syscall",
            "scenario": "download",
            "path_profile": "loopback",
            "reference_client": reference_client,
            "reference_client_backend": "syscall",
            "concurrency": concurrency,
        }
        if phase == "exploratory":
            config["search_round"] = round_index
        else:
            config["confirmation_round"] = round_index
            config["branch_candidate"] = candidate
            config["williams_row"] = round_index % 12
        return {
            "config": config,
            "sample": {
                "completion_status": "valid",
                "metric": {"derived_decimal": str(rate)},
                "telemetry": {"client_cpu_p95_decimal": "0.1"},
            },
            "planned_microblock_status": "committed",
            "planned_microblock_id": f"{round_index:064x}",
            "session_number": 1 if round_index < 12 else 2,
            "williams_row": round_index % 12,
            "superblock_id": f"{round_index % 12 + 1:064x}",
        }


if __name__ == "__main__":
    unittest.main()
