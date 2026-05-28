import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load_adaptive_module():
    root = Path(__file__).resolve().parents[1]
    tools = root / "tools"
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    path = tools / "run-adaptive-publication-suite.py"
    spec = importlib.util.spec_from_file_location("run_adaptive_publication_suite", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RunAdaptivePublicationSuiteTests(unittest.TestCase):
    def make_sample(self, module, target, index, *, phase="confirm", status="ok", value=1.0):
        return module.Sample(
            publication_id="test",
            round=index // 5 + 1,
            block_id=f"b{index // 5}",
            sample_id=f"s{index}",
            binary=target.binary,
            library=target.binary,
            scenario=target.scenario,
            network=target.network,
            path_profile=target.path_profile,
            client_threads=target.threads,
            server_connections=module.server_connections_for_target(target),
            metric=module.scenario_metric_name(target.scenario),
            value=value,
            phase=phase,
            status=status,
            reason="" if status == "ok" else status,
            started_utc="",
            ended_utc="",
            duration_sec=1.0,
            run_order=index,
            random_seed="1",
            out_dir="",
            client_log="",
            server_log="",
            git_commit="",
            env_hash="",
            machine_hash="",
        )

    def test_capability_rows_use_two_server_connections_per_client(self):
        module = load_adaptive_module()

        for scenario in ("resumed_connect", "zero_rtt_reqresp"):
            target = module.Target("tquicperf", scenario, "iouring", "loopback", 3)
            self.assertEqual(module.server_connections_for_target(target), 6)

    def test_regular_rows_match_server_connections_to_client_threads(self):
        module = load_adaptive_module()

        target = module.Target("tquicperf", "download", "iouring", "loopback", 3)
        self.assertEqual(module.server_connections_for_target(target), 3)

    def test_publication_support_threads_are_selected_best_and_boundary_only(self):
        module = load_adaptive_module()

        decision = module.SaturationDecision(
            selected_threads=11,
            best_threads=12,
            boundary_threads=13,
            selection_probability_within_tolerance=1.0,
            best_p50=1.0,
            selected_p50=1.0,
            selected_vs_best_ratio=1.0,
            selected_vs_best_ci95_low=1.0,
            selected_vs_best_ci95_high=1.0,
            plateau_sentinel_count=1,
            edge_status="converged",
            decision_status="converged",
            reason="",
        )

        self.assertEqual(module.publication_support_threads(decision), {11, 12, 13})

    def test_confirm_status_accepts_discovery_when_confirmation_disabled(self):
        module = load_adaptive_module()

        cfg = module.load_config()
        stats = module.RowStats(
            n=20,
            blocks=4,
            median=1.0,
            p90=0.9,
            p99=0.8,
            p99_status="exact",
            ci95_low=0.95,
            ci95_high=1.05,
            ci95_rel_width=0.1,
            p20=0.9,
            p80=1.1,
            p20_p80_ratio=1.1,
            mad_rel=0.01,
            block_median_min=0.95,
            block_median_max=1.05,
            block_median_ratio=1.1,
            drift_rel=0.01,
            lag1_autocorr=0.0,
            outlier_count=0,
            status="converged",
            reason="",
        )

        self.assertEqual(
            module.confirm_status(stats, None, stats, "download", cfg),
            ("converged", "confirm_disabled"),
        )

    def test_pending_confirm_targets_skip_finished_rows(self):
        module = load_adaptive_module()

        with mock.patch.dict(
            os.environ,
            {"QUICPERF_ADAPTIVE_BLOCK_SIZE": "5", "QUICPERF_ADAPTIVE_CONFIRM_BLOCKS": "2"},
            clear=True,
        ):
            cfg = module.load_config()

        target = module.Target("xquicperf", "upload", "iouring", "loopback", 3)
        complete = [self.make_sample(module, target, index, phase="confirm") for index in range(10)]
        partial = complete[:-1]
        failed = [self.make_sample(module, target, 0, phase="confirm", status="client_failed", value=None)]

        self.assertEqual(module.pending_confirm_targets({target}, complete, cfg), [])
        self.assertEqual(module.pending_confirm_targets({target}, partial, cfg), [target])
        self.assertEqual(module.pending_confirm_targets({target}, failed, cfg), [])

    def test_resume_normalizes_client_failed_samples_to_failed_rows(self):
        module = load_adaptive_module()

        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = module.load_config()

        target = module.Target("lsperf", "download", "iouring", "loopback", 1)
        row_state, row_reason, group_state, active = module.initialize_resume_state(
            binaries=[target.binary],
            scenarios=[target.scenario],
            networks=[target.network],
            path_profiles=[target.path_profile],
            samples=[self.make_sample(module, target, 0, phase="discovery", status="client_failed", value=None)],
            block_failures={},
            cfg=cfg,
        )

        self.assertEqual(row_state[target], "failed")
        self.assertEqual(row_reason[target], "client_failed")
        self.assertEqual(group_state[target.group], "failed")
        self.assertEqual(active, set())

    def test_inactive_finalization_treats_failed_status_aliases_as_failed(self):
        module = load_adaptive_module()

        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = module.load_config()

        target = module.Target("tquicperf", "download", "syscall", "loopback", 2)
        row_state = {target: "client_failed"}
        row_reason = {target: "exit_124"}
        group_state = {target.group: "active"}
        decisions = {}

        module.finalize_inactive_discovery_groups([], row_state, row_reason, group_state, decisions, cfg)

        self.assertEqual(group_state[target.group], "failed")
        self.assertNotIn(target.group, decisions)

    def test_terminal_group_state_overrides_stale_not_ready_decision(self):
        module = load_adaptive_module()

        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = module.load_config()

        target = module.Target("xquicperf", "download", "iouring", "loopback", 4)
        row_state = {target: "failed"}
        row_reason = {target: "exit_124"}
        group_state = {target.group: "failed"}
        decisions = {
            target.group: module.SaturationDecision(
                selected_threads=3,
                best_threads=3,
                boundary_threads=0,
                selection_probability_within_tolerance=1.0,
                best_p50=1.0,
                selected_p50=1.0,
                selected_vs_best_ratio=1.0,
                selected_vs_best_ci95_low=1.0,
                selected_vs_best_ci95_high=1.0,
                plateau_sentinel_count=0,
                edge_status="edge",
                decision_status="not_ready",
                reason="no_incremental_plateau",
            )
        }

        module.finalize_group_decisions([], row_state, row_reason, group_state, decisions, cfg)

        self.assertEqual(decisions[target.group].decision_status, "failed")
        self.assertEqual(decisions[target.group].edge_status, "failed")
        self.assertEqual(decisions[target.group].selected_threads, 0)
        self.assertEqual(decisions[target.group].reason, "exit_124")

    def test_failed_block_status_is_terminal_failed_with_specific_reason(self):
        module = load_adaptive_module()

        status, reason = module.block_terminal_status(
            "quicperf_run_result binary=lsperf scenario=download network=iouring "
            "path_profile=loopback run=x status=client_failed reason=exit_124\n"
        )

        self.assertEqual(status, "failed")
        self.assertEqual(reason, "exit_124")

    def test_inactive_resume_groups_are_finalized_before_confirm(self):
        module = load_adaptive_module()

        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = module.load_config()

        t1 = module.Target("xquicperf", "upload", "iouring", "loopback", 1)
        t2 = module.Target("xquicperf", "upload", "iouring", "loopback", 2)
        samples = [
            self.make_sample(module, target, index, phase="discovery", value=100.0)
            for target in (t1, t2)
            for index in range(20)
        ]
        row_state = {t1: "converged", t2: "converged"}
        row_reason = {}
        group_state = {t1.group: "active"}
        decisions = {}

        module.finalize_inactive_discovery_groups(samples, row_state, row_reason, group_state, decisions, cfg)

        self.assertEqual(group_state[t1.group], "converged")
        self.assertEqual(decisions[t1.group].decision_status, "converged")

    def test_scenario_tiers_and_promotion(self):
        module = load_adaptive_module()

        self.assertEqual(module.scenario_tier("zero_rtt_reqresp"), "capability")
        self.assertEqual(module.scenario_tier("idle_footprint"), "lifecycle")
        self.assertEqual(module.scenario_tier("download"), "publication")
        self.assertEqual(module.scenario_tier("idle_footprint", ("idle_footprint",)), "publication")

    def test_calibrated_workload_scales_slow_byte_rows_down(self):
        module = load_adaptive_module()

        with mock.patch.dict(os.environ, {"QUICPERF_ADAPTIVE_CALIBRATION_TARGET_SEC": "5"}, clear=True):
            cfg = module.load_config()

        target = module.Target("lsperf", "download", "iouring", "loopback", 1)
        samples = [
            self.make_sample(module, target, index, phase="calibration", value=1.0)
            for index in range(2)
        ]
        for sample in samples:
            sample.duration_sec = 20.0

        plan = module.build_workload_plan(target, cfg, samples)

        self.assertTrue(plan.calibrated)
        self.assertEqual(plan.workload_kind, "bytes")
        self.assertLess(plan.selected_work_units, module.DEFAULT_SMALL_TEST_BYTES)
        self.assertIn("QUICPERF_TEST_BYTES", plan.env_overrides)
        self.assertGreaterEqual(plan.timeout_sec, cfg.calibrated_timeout_min_sec)

    def test_lifecycle_rows_are_smoke_not_calibrated(self):
        module = load_adaptive_module()

        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = module.load_config()

        target = module.Target("mvfstperf", "reqresp", "iouring", "loopback", 1)
        samples = [self.make_sample(module, target, 0, phase="calibration")]
        samples[0].duration_sec = 45.0
        plan = module.build_workload_plan(target, cfg, samples)

        self.assertFalse(plan.publication_eligible)
        self.assertFalse(plan.calibrated)
        self.assertEqual(plan.reason, "tier_smoke_no_calibration")
        self.assertEqual(plan.env_overrides, {})
        self.assertEqual(plan.selected_work_units, module.DEFAULT_OPERATION_SCENARIO_OPERATIONS)

    def test_operation_calibration_does_not_jump_past_scale_cap(self):
        module = load_adaptive_module()

        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = module.load_config()

        target = module.Target("mvfstperf", "small_payload_pps", "iouring", "loopback", 1)
        samples = [self.make_sample(module, target, 0, phase="calibration")]
        samples[0].duration_sec = 0.25

        plan = module.build_workload_plan(target, cfg, samples)

        self.assertTrue(plan.publication_eligible)
        self.assertTrue(plan.calibrated)
        self.assertEqual(plan.selected_work_units, 4096)
        self.assertIn("max_scale", plan.reason)

    def test_workload_validation_falls_back_to_validated_units(self):
        module = load_adaptive_module()

        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = module.load_config()

        target = module.Target("lsperf", "download", "iouring", "loopback", 1)
        base = module.WorkloadPlan(
            binary=target.binary,
            scenario=target.scenario,
            network=target.network,
            path_profile=target.path_profile,
            tier="publication",
            publication_eligible=True,
            calibrated=True,
            workload_kind="bytes",
            selected_work_units=64 * 1024 * 1024,
            probe_work_units=16 * 1024 * 1024,
            target_duration_sec=5.0,
            calibration_duration_sec=1.0,
            timeout_sec=15,
            env_overrides={"QUICPERF_TEST_BYTES": str(64 * 1024 * 1024)},
            reason="too_fast_scaled_up;max_scale",
        )
        calls = []

        def fake_run_block(*_args, **kwargs):
            calls.append(int(kwargs["env_overrides"]["QUICPERF_TEST_BYTES"]))
            self.assertEqual(kwargs["phase"], module.CALIBRATION_VALIDATION_PHASE)
            self.assertEqual(kwargs["warmup"], cfg.warmup)
            self.assertEqual(kwargs["repeat"], min(cfg.block_size, 2))
            status = "failed" if calls[-1] == 64 * 1024 * 1024 else "ok"
            return module.BlockResult(target, "calibration", "b", status, "exit_124" if status == "failed" else "", Path("/tmp"), 0)

        def fake_load_samples(_path):
            return [
                self.make_sample(module, target, index, phase="calibration", value=1.0)
                for index, units in enumerate(calls)
                if units != 64 * 1024 * 1024
            ]

        with mock.patch.object(module, "run_block", side_effect=fake_run_block), \
             mock.patch.object(module, "load_samples", side_effect=fake_load_samples):
            plan, ordinal = module.validate_scaled_workload(
                root=Path("/tmp"),
                out_root=Path("/tmp/out"),
                samples_path=Path("/tmp/samples.tsv"),
                target=target,
                plan=base,
                cfg=cfg,
                publication_id="test",
                commit="",
                env_sig="",
                machine_sig="",
                round_index=0,
                block_ordinal=10,
            )

        self.assertEqual(calls, [64 * 1024 * 1024, 32 * 1024 * 1024, 16 * 1024 * 1024])
        self.assertEqual(ordinal, 13)
        self.assertEqual(plan.selected_work_units, 16 * 1024 * 1024)
        self.assertIn("guard_step_down_after_validation_failure", plan.reason)
        self.assertIn("fallback_after_validation_failure", plan.reason)

    def test_resume_failure_scan_ignores_calibration_validation_blocks(self):
        module = load_adaptive_module()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            validation = root / "blocks" / "r000b00001t1-lsperf-download-iouring-loopback"
            validation.mkdir(parents=True)
            (validation / "adaptive-block.stdout").write_text(
                "quicperf_run_result binary=lsperf scenario=download network=iouring "
                "path_profile=loopback run=r000b00001t1-1 status=client_failed exit=124\n",
                encoding="utf-8",
            )
            (validation / "adaptive-block-request.tsv").write_text(
                "block_id\tphase\tbinary\tscenario\tnetwork\tpath_profile\tclient_threads\n"
                "r000b00001t1\tcalibration_validation\tlsperf\tdownload\tiouring\tloopback\t1\n",
                encoding="utf-8",
            )
            (validation / "run-meta.tsv").write_text(
                "run_label\tphase\tbinary\tscenario\tnetwork\tpath_profile\tclient_threads\t"
                "server_connections\tstatus\treason\n"
                "warmup\twarmup\tlsperf\tdownload\tiouring\tloopback\t1\t1\tclient_failed\texit_124\n",
                encoding="utf-8",
            )

            failure = root / "blocks" / "r000b00002t1-lsperf-upload-iouring-loopback"
            failure.mkdir(parents=True)
            (failure / "adaptive-block.stdout").write_text(
                "quicperf_run_result binary=lsperf scenario=upload network=iouring "
                "path_profile=loopback run=r000b00002t1-1 status=client_failed exit=124\n",
                encoding="utf-8",
            )
            (failure / "run-meta.tsv").write_text(
                "run_label\tphase\tbinary\tscenario\tnetwork\tpath_profile\tclient_threads\t"
                "server_connections\tstatus\treason\n"
                "sample\tdiscovery\tlsperf\tupload\tiouring\tloopback\t1\t1\t"
                "client_failed\texit_124\n",
                encoding="utf-8",
            )

            failures = module.load_block_failures(root, ["iouring"], ["loopback"])

        self.assertNotIn(module.Target("lsperf", "download", "iouring", "loopback", 1), failures)
        self.assertIn(module.Target("lsperf", "upload", "iouring", "loopback", 1), failures)

    def test_pairwise_excludes_non_publication_tiers(self):
        module = load_adaptive_module()

        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = module.load_config()

        rows = [
            {
                "binary": "a",
                "scenario": "reqresp",
                "network": "syscall",
                "path_profile": "loopback",
                "metric": "ops_per_sec",
                "publication_status": "converged",
                "publication_eligible": "0",
                "selected_threads": "1",
            },
            {
                "binary": "b",
                "scenario": "reqresp",
                "network": "syscall",
                "path_profile": "loopback",
                "metric": "ops_per_sec",
                "publication_status": "converged",
                "publication_eligible": "0",
                "selected_threads": "1",
            },
        ]

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "pairwise.tsv"
            module.write_pairwise(output, [], rows, cfg)
            lines = output.read_text(encoding="utf-8").splitlines()

        self.assertEqual(len(lines), 1)

    def test_row_stats_exclude_calibration_samples(self):
        module = load_adaptive_module()

        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = module.load_config()

        target = module.Target("quicheperf", "download", "syscall", "loopback", 1)
        samples = [self.make_sample(module, target, index, phase="calibration") for index in range(4)]

        with tempfile.TemporaryDirectory() as tmp:
            rows = module.write_row_stats(Path(tmp) / "row-stats.tsv", samples, cfg)

        self.assertEqual(rows, {})


if __name__ == "__main__":
    unittest.main()
