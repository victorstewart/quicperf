import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from quicperf_fixed_design import (  # noqa: E402
    DEFAULT_MAX_CLIENT_THREADS,
    DEFAULT_SCOUT_GRID,
    PlanRow,
    ScoutPoint,
    benchmark_fingerprint,
    fixed_schedule,
    fixed_status,
    load_plan,
    materialize_scout_cache,
    row_stats_config,
    scout_cache_scope,
    scout_point_from_samples,
    select_scout_threads,
    target_env,
    target_connections_for_duration,
    validate_scout_cache,
    write_plan,
    write_scout_cache,
)
from quicperf_stats import Sample, row_stats  # noqa: E402


def make_sample(index: int, *, value: float = 1.0, status: str = "ok") -> Sample:
    return Sample(
        publication_id="fixed-test",
        round=index // 4 + 1,
        block_id=f"b{index // 4}",
        sample_id=f"s{index}",
        binary="ngtcp2perf",
        library="ngtcp2",
        scenario="download",
        network="syscall",
        path_profile="loopback",
        client_threads=2,
        server_connections=2,
        metric="throughput_gbps",
        value=value if status == "ok" else None,
        phase="publication",
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


class FixedDesignTests(unittest.TestCase):
    def test_scout_selects_first_point_when_next_step_plateaus(self):
        points = [
            ScoutPoint("ngtcp2perf", "download", "syscall", "loopback", 1, "ok", "", "throughput_gbps", 100.0, 3),
            ScoutPoint("ngtcp2perf", "download", "syscall", "loopback", 2, "ok", "", "throughput_gbps", 101.0, 3),
        ]

        selected = select_scout_threads(points)

        self.assertEqual(selected.status, "ok")
        self.assertEqual(selected.selected_threads, 1)
        self.assertEqual(selected.best_threads, 2)

    def test_scout_selects_lowest_near_best_before_plateau(self):
        points = [
            ScoutPoint("ngtcp2perf", "download", "syscall", "loopback", 1, "ok", "", "throughput_gbps", 100.0, 3),
            ScoutPoint("ngtcp2perf", "download", "syscall", "loopback", 2, "ok", "", "throughput_gbps", 130.0, 3),
            ScoutPoint("ngtcp2perf", "download", "syscall", "loopback", 4, "ok", "", "throughput_gbps", 131.0, 3),
        ]

        selected = select_scout_threads(points)

        self.assertEqual(selected.selected_threads, 2)
        self.assertEqual(selected.best_threads, 4)

    def test_connect_target_connections_are_derived_from_scout_rate(self):
        point = ScoutPoint("ngtcp2perf", "connect", "syscall", "loopback", 2, "ok", "", "connections_per_second", 50.0, 3)

        self.assertEqual(target_connections_for_duration(point, 2000), 50)

    def test_connect_target_connections_are_capped_by_total_sample_work(self):
        point = ScoutPoint("lsperf", "connect", "iouring", "loopback", 16, "ok", "", "connections_per_second", 7427.0, 3)

        self.assertEqual(target_connections_for_duration(point, 2000), 8)

    def test_fixed_design_caps_default_scout_grid_at_sixteen_threads(self):
        self.assertEqual(DEFAULT_MAX_CLIENT_THREADS, 16)
        self.assertEqual(DEFAULT_SCOUT_GRID, (1, 2, 4, 8, 16))

    def test_plan_validation_rejects_more_than_sixteen_threads(self):
        row = PlanRow(
            "ngtcp2perf",
            "download",
            "syscall",
            "loopback",
            client_threads=17,
            mode="duration",
            duration_ms=2000,
            work_units=0,
            samples=20,
            warmup=1,
            block_count=5,
        )

        with self.assertRaisesRegex(ValueError, "exceeds max 16"):
            row.validate()

    def test_scout_reports_failed_or_unsupported_without_ok_points(self):
        failed = [ScoutPoint("xquicperf", "download", "iouring", "loopback", 1, "failed", "exit_124", "throughput_gbps", 0.0, 0)]
        unsupported = [ScoutPoint("s2nperf", "datagram", "syscall", "loopback", 1, "unsupported", "no_api", "datagrams_per_second", 0.0, 0)]

        self.assertEqual(select_scout_threads(failed).status, "failed")
        self.assertEqual(select_scout_threads(unsupported).status, "unsupported")

    def test_zero_value_ok_scout_samples_remain_successful(self):
        samples = [make_sample(0, value=0.0)]

        point = scout_point_from_samples("ngtcp2perf", "download", "syscall", "loopback", 2, samples)

        self.assertEqual(point.status, "ok")
        self.assertEqual(point.median, 0.0)
        self.assertEqual(point.samples, 1)

    def test_scout_selects_lowest_thread_when_all_successes_are_zero(self):
        points = [
            ScoutPoint("xquicperf", "zero_rtt_reqresp", "iouring", "loopback", 1, "ok", "", "requests_per_second", 0.0, 3),
            ScoutPoint("xquicperf", "zero_rtt_reqresp", "iouring", "loopback", 2, "ok", "", "requests_per_second", 0.0, 3),
        ]

        selected = select_scout_threads(points)

        self.assertEqual(selected.status, "ok")
        self.assertEqual(selected.selected_threads, 1)
        self.assertEqual(selected.best_threads, 1)

    def test_scout_point_fails_when_any_sample_failed(self):
        samples = [
            make_sample(0, value=10.0),
            make_sample(1, value=11.0),
            make_sample(2, status="client_failed"),
        ]

        point = scout_point_from_samples("ngtcp2perf", "download", "syscall", "loopback", 2, samples)

        self.assertEqual(point.status, "failed")
        self.assertEqual(point.reason, "client_failed")
        self.assertEqual(point.samples, 0)

    def test_fixed_schedule_does_not_change_sample_count_or_threads(self):
        row = PlanRow(
            "ngtcp2perf",
            "download",
            "syscall",
            "loopback",
            client_threads=4,
            mode="duration",
            duration_ms=2000,
            work_units=0,
            samples=20,
            warmup=1,
            block_count=5,
        )

        schedule = fixed_schedule([row], seed=7)

        self.assertEqual(len(schedule), 5)
        self.assertEqual([item.repeat for item in schedule], [4, 4, 4, 4, 4])
        self.assertEqual([item.warmup for item in schedule], [1, 0, 0, 0, 0])
        self.assertEqual({item.row.client_threads for item in schedule}, {4})

    def test_plan_roundtrip_preserves_fixed_design_fields(self):
        row = PlanRow(
            "ngtcp2perf",
            "download",
            "iouring",
            "loopback",
            client_threads=8,
            mode="duration",
            duration_ms=2000,
            work_units=0,
            samples=20,
            warmup=1,
            block_count=5,
            selected_threads=8,
            best_threads=16,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.tsv"
            write_plan(path, [row])
            loaded = load_plan(path)

        self.assertEqual(loaded, [row])

    def test_work_mode_plan_roundtrip_does_not_add_duration(self):
        row = PlanRow(
            "ngtcp2perf",
            "resumed_connect",
            "syscall",
            "loopback",
            client_threads=1,
            mode="work",
            duration_ms=0,
            work_units=2,
            samples=1,
            warmup=0,
            block_count=1,
            target_connections=2,
            selected_threads=1,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.tsv"
            write_plan(path, [row])
            loaded = load_plan(path)

        self.assertEqual(loaded, [row])

    def test_target_env_does_not_turn_duration_rows_into_zero_work(self):
        row = PlanRow(
            "ngtcp2perf",
            "download",
            "syscall",
            "loopback",
            client_threads=1,
            mode="duration",
            duration_ms=2000,
            work_units=0,
            samples=20,
            warmup=1,
            block_count=5,
            selected_threads=1,
        )

        env = target_env(row)

        self.assertEqual(env["QUICPERF_MEASURE_MODE"], "duration")
        self.assertNotIn("QUICPERF_TEST_BYTES", env)
        self.assertNotIn("QUICPERF_TARGET_CONNECTIONS", env)

    def test_target_env_omits_zero_target_connections_for_zero_rtt_duration(self):
        row = PlanRow(
            "xquicperf",
            "zero_rtt_reqresp",
            "iouring",
            "loopback",
            client_threads=1,
            mode="duration",
            duration_ms=2000,
            work_units=0,
            samples=20,
            warmup=1,
            block_count=5,
            selected_threads=1,
        )

        env = target_env(row)

        self.assertNotIn("QUICPERF_TARGET_CONNECTIONS", env)
        self.assertNotIn("QUICPERF_SERVER_CONNECTIONS", env)

    def test_target_env_sizes_connect_server_connections_from_target_count(self):
        row = PlanRow(
            "ngtcp2perf",
            "connect",
            "syscall",
            "loopback",
            client_threads=3,
            mode="work",
            duration_ms=0,
            work_units=0,
            samples=20,
            warmup=1,
            block_count=5,
            target_connections=7,
        )

        env = target_env(row)

        self.assertEqual(env["QUICPERF_TARGET_CONNECTIONS"], "7")
        self.assertEqual(env["QUICPERF_SERVER_CONNECTIONS"], "21")

    def test_target_env_sizes_resumed_connect_server_connections_for_warmup_and_measurement(self):
        row = PlanRow(
            "ngtcp2perf",
            "resumed_connect",
            "syscall",
            "loopback",
            client_threads=2,
            mode="work",
            duration_ms=0,
            work_units=0,
            samples=20,
            warmup=1,
            block_count=5,
            target_connections=5,
        )

        env = target_env(row)

        self.assertEqual(env["QUICPERF_TARGET_CONNECTIONS"], "5")
        self.assertEqual(env["QUICPERF_SERVER_CONNECTIONS"], "20")

    def test_scout_cache_fingerprint_changes_with_benchmark_file_content(self):
        scope = scout_cache_scope(
            binaries=["ngtcp2perf"],
            scenarios=["download"],
            networks=["syscall"],
            path_profiles=["loopback"],
            grid=[1, 2],
            samples=3,
            loopback_duration_ms=1000,
            impaired_duration_ms=2000,
            congestion_profile="cubic",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "perf.cpp").write_text("one\n", encoding="utf-8")
            first, first_files = benchmark_fingerprint(root, scope)
            (root / "perf.cpp").write_text("two\n", encoding="utf-8")
            second, second_files = benchmark_fingerprint(root, scope)

        self.assertNotEqual(first, second)
        self.assertEqual(first_files[0]["path"], "perf.cpp")
        self.assertEqual(second_files[0]["path"], "perf.cpp")

    def test_scout_cache_roundtrip_materializes_plan_and_metadata(self):
        scope = scout_cache_scope(
            binaries=["ngtcp2perf"],
            scenarios=["download"],
            networks=["syscall"],
            path_profiles=["loopback"],
            grid=[1],
            samples=3,
            loopback_duration_ms=1000,
            impaired_duration_ms=2000,
            congestion_profile="cubic",
        )
        row = PlanRow(
            "ngtcp2perf",
            "download",
            "syscall",
            "loopback",
            client_threads=1,
            mode="duration",
            duration_ms=2000,
            work_units=0,
            samples=20,
            warmup=1,
            block_count=5,
            selected_threads=1,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "perf.cpp").write_text("benchmark\n", encoding="utf-8")
            fingerprint, files = benchmark_fingerprint(root, scope)
            scout_dir = root / "scout"
            scout_dir.mkdir()
            write_plan(scout_dir / "benchmark-plan.tsv", [row])
            (scout_dir / "saturation-scout.tsv").write_text("run_order\tbinary\n", encoding="utf-8")
            (scout_dir / "scout-samples.tsv").write_text("publication_id\n", encoding="utf-8")
            cache_dir = root / "cache"
            out_dir = root / "out"

            write_scout_cache(
                cache_dir,
                scout_dir,
                fingerprint=fingerprint,
                scope=scope,
                source_run="scout",
                file_records=files,
            )
            valid, reason = validate_scout_cache(cache_dir, fingerprint, scope)
            materialize_scout_cache(cache_dir, out_dir)

            self.assertTrue(valid, reason)
            self.assertEqual(load_plan(out_dir / "benchmark-plan.tsv"), [row])
            self.assertTrue((out_dir / "scout-cache-metadata.json").is_file())

    def test_fixed_status_separates_completion_from_noisy_audit(self):
        row = PlanRow(
            "ngtcp2perf",
            "download",
            "syscall",
            "loopback",
            client_threads=2,
            mode="duration",
            duration_ms=2000,
            work_units=0,
            samples=20,
            warmup=1,
            block_count=5,
        )
        clean_samples = [make_sample(index, value=1.0) for index in range(20)]
        clean_stats = row_stats(clean_samples, row_stats_config(row, bootstrap_iters=200, seed=1))

        self.assertEqual(fixed_status(clean_samples, clean_stats, row.samples)[:3], ("complete", "tail_insufficient", "publishable"))

        noisy_samples = [make_sample(index, value=1.0 if index < 10 else 2.0) for index in range(20)]
        noisy_stats = row_stats(noisy_samples, row_stats_config(row, bootstrap_iters=200, seed=1))

        self.assertEqual(fixed_status(noisy_samples, noisy_stats, row.samples)[:3], ("complete", "noisy", "inconclusive"))

    def test_fixed_status_keeps_infrastructure_failures_terminal(self):
        row = PlanRow(
            "ngtcp2perf",
            "download",
            "syscall",
            "loopback",
            client_threads=2,
            mode="duration",
            duration_ms=2000,
            work_units=0,
            samples=20,
            warmup=1,
            block_count=5,
        )
        samples = [make_sample(index, value=1.0) for index in range(19)]
        samples.append(make_sample(19, status="client_failed"))
        stats = row_stats(samples, row_stats_config(row, bootstrap_iters=200, seed=1))

        self.assertEqual(fixed_status(samples, stats, row.samples)[0], "failed")


if __name__ == "__main__":
    unittest.main()
