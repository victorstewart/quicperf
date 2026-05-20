import importlib.util
import sys
import unittest
from pathlib import Path


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
    def test_capability_rows_use_two_server_connections_per_client(self):
        module = load_adaptive_module()

        for scenario in ("resumed_connect", "zero_rtt_reqresp"):
            target = module.Target("tquicperf", scenario, "iouring", "loopback", 3)
            self.assertEqual(module.server_connections_for_target(target), 6)

    def test_regular_rows_match_server_connections_to_client_threads(self):
        module = load_adaptive_module()

        target = module.Target("tquicperf", "download", "iouring", "loopback", 3)
        self.assertEqual(module.server_connections_for_target(target), 3)


if __name__ == "__main__":
    unittest.main()
