#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "quicperf_network_path.py"


def load_module():
    spec = importlib.util.spec_from_file_location("quicperf_network_path", MODULE_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class NetworkProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_required_profiles_exist_and_validate(self):
        profiles = self.mod.load_profiles()
        for name in (
            "loopback",
            "dc-fabric-1ms",
            "lte-good",
            "5g-sub6-good",
            "5g-ucc-driving-replay",
            "5g-ucc-static-good",
            "5g-ucc-driving-good",
            "5g-ucc-driving-handover-heavy",
            "5g-ucc-driving-bursty-high",
            "5g-ucc-video-app-shaped",
            "5g-5gophers-walking-loop",
            "lte-ucc-static-good",
            "lte-ucc-pedestrian-replay",
            "lte-ucc-car-replay",
            "lte-ucc-tram-handover",
            "lte-ucc-train-adverse",
            "lte-ucc-congested",
        ):
            self.assertIn(name, profiles)
            profile = self.mod.profile_by_name(name)
            self.assertEqual(profile["name"], name)

    def test_loopback_plan_has_no_namespace_commands(self):
        profile = self.mod.profile_by_name("loopback")
        plan = self.mod.plan_commands(profile, "unit")
        self.assertEqual(plan["kind"], "loopback")
        self.assertEqual(plan["commands"], [])
        self.assertEqual(self.mod.bdp_window_bytes(profile), 0)

    def test_namespace_plan_is_deterministic_and_shapes_both_directions(self):
        profile = self.mod.profile_by_name("lte-good")
        first = self.mod.plan_commands(profile, "unit")
        second = self.mod.plan_commands(profile, "unit")
        self.assertEqual(first["names"], second["names"])

        self.assertEqual(first["kind"], "namespace")
        downlink = first["tc"]["downlink"]
        uplink = first["tc"]["uplink"]
        self.assertIn("qprc0", downlink)
        self.assertIn("qprs0", uplink)
        self.assertIn("50000000bit", downlink)
        self.assertIn("12000000bit", uplink)
        self.assertTrue(first["static_neighbors"])
        self.assertGreaterEqual(self.mod.bdp_window_bytes(profile), 1024 * 1024)

    def test_mobile_profiles_have_capacity_traces(self):
        for name in ("lte-good", "lte-congested", "5g-sub6-good", "5g-mmwave-bursty"):
            profile = self.mod.profile_by_name(name)
            self.assertGreater(len(profile.get("trace", [])), 1)
            self.assertGreater(self.mod.max_rate_bps(profile), int(profile["downlink_bps"]))

    def test_mobile_trace_steps_can_override_impairments(self):
        profile = self.mod.profile_by_name("lte-congested")
        step = profile["trace"][2]
        dynamic = self.mod.trace_step_profile(profile, step)
        self.assertEqual(dynamic["one_way_delay_us"], step["one_way_delay_us"])
        self.assertEqual(dynamic["loss_percent"], step["loss_percent"])
        command = self.mod.tc_replace_command("unit-ns", "qprc0", dynamic, int(step["downlink_bps"]))
        self.assertIn("85ms", command)
        self.assertIn("2.5000%", command)
        self.assertIn("2000000bit", command)

    def test_public_cellular_profiles_are_loaded_from_secondary_profile_file(self):
        profile = self.mod.profile_by_name("5g-ucc-driving-replay")
        self.assertIn("source", profile)
        self.assertEqual(profile["source"]["name"], "UCC 5G production dataset")
        self.assertGreaterEqual(len(profile["trace"]), 30)
        self.assertTrue(any(step.get("event") == "handover-outage" for step in profile["trace"]))

        lte = self.mod.profile_by_name("lte-ucc-train-adverse")
        self.assertEqual(lte["source"]["name"], "UCC 4G LTE dataset")
        self.assertGreaterEqual(len(lte["trace"]), 30)
        self.assertTrue(any(step.get("event") == "handover-outage" for step in lte["trace"]))

        video = self.mod.profile_by_name("5g-ucc-video-app-shaped")
        self.assertIn("Netflix", video["source"]["input"])
        self.assertLessEqual(min(step["downlink_bps"] for step in video["trace"] if "downlink_bps" in step), 16000)

        walking = self.mod.profile_by_name("5g-5gophers-walking-loop")
        self.assertEqual(walking["source"]["name"], "5Gophers v1.0 dataset")
        self.assertIn("walking-trace.csv", walking["source"]["input"])
        self.assertTrue(any(step.get("event") == "handover-outage" for step in walking["trace"]))


if __name__ == "__main__":
    unittest.main()
