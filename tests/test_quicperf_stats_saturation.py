#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from quicperf_stats import Sample, StatsConfig, row_stats, saturation_decision  # noqa: E402


def make_samples(threads: int, value: float) -> list[Sample]:
    samples = []
    for index in range(20):
        block = index // 5
        samples.append(
            Sample(
                publication_id="test",
                round=block + 1,
                block_id=f"r{block + 1:03d}b{block + 1:05d}t{threads}",
                sample_id=f"t{threads}-{index}",
                binary="picoperf",
                library="picoquic",
                scenario="download",
                network="syscall",
                path_profile="loopback",
                client_threads=threads,
                server_connections=threads,
                metric="throughput_gbps",
                value=value,
                phase="discovery",
                status="ok",
                reason="",
                started_utc="2026-05-18T00:00:00Z",
                ended_utc="2026-05-18T00:00:01Z",
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
        )
    return samples


def decision_for(values_by_thread: dict[int, float]):
    cfg = StatsConfig(
        min_blocks=4,
        min_samples=20,
        bootstrap_iters=200,
        saturation_min_incremental_improvement=0.01,
        saturation_probability=0.95,
        saturation_sentinels=1,
    )
    sample_map = {threads: make_samples(threads, value) for threads, value in values_by_thread.items()}
    stats_map = {threads: row_stats(samples, cfg) for threads, samples in sample_map.items()}
    return saturation_decision(stats_map, sample_map, cfg)


class QuicperfStatsSaturationTests(unittest.TestCase):
    def test_one_to_two_non_improvement_stops_at_two_clients(self):
        decision = decision_for({1: 100.0, 2: 99.0})

        self.assertEqual(decision.decision_status, "ready")
        self.assertEqual(decision.selected_threads, 1)
        self.assertEqual(decision.best_threads, 1)
        self.assertEqual(decision.boundary_threads, 2)
        self.assertIn("incremental_improvement_-1.00pct_le_1.00pct", decision.reason)

    def test_later_adjacent_non_improvement_stops_at_boundary(self):
        decision = decision_for({1: 100.0, 2: 130.0, 3: 130.5})

        self.assertEqual(decision.decision_status, "ready")
        self.assertEqual(decision.selected_threads, 2)
        self.assertEqual(decision.boundary_threads, 3)
        self.assertIn("incremental_improvement_0.38pct_le_1.00pct", decision.reason)

    def test_improving_edge_requests_next_client_count(self):
        decision = decision_for({1: 100.0, 2: 130.0})

        self.assertEqual(decision.decision_status, "not_ready")
        self.assertEqual(decision.edge_status, "edge")
        self.assertEqual(decision.boundary_threads, 0)
        self.assertEqual(decision.reason, "no_incremental_plateau")


if __name__ == "__main__":
    unittest.main()
