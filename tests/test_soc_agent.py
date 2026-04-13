from pathlib import Path
import importlib.util
import sys
import unittest


AGENTS_DIR = Path(__file__).resolve().parents[1] / "agents"
if str(AGENTS_DIR) not in sys.path:
    sys.path.insert(0, str(AGENTS_DIR))

SOC_AGENT_PATH = AGENTS_DIR / "soc_agent.py"
SOC_AGENT_SPEC = importlib.util.spec_from_file_location("soc_agent", SOC_AGENT_PATH)
if SOC_AGENT_SPEC is None or SOC_AGENT_SPEC.loader is None:
    raise RuntimeError("Unable to load agents/soc_agent.py for tests")
soc_agent = importlib.util.module_from_spec(SOC_AGENT_SPEC)
SOC_AGENT_SPEC.loader.exec_module(soc_agent)


class SocAgentBatchingTests(unittest.TestCase):
    def test_batching_covers_all_events(self):
        events = [{"id": idx} for idx in range(5)]
        captured_batch_sizes = []

        def capture_send(_api_url, _headers, batch):
            captured_batch_sizes.append(len(batch))
            return True

        sent, failed = soc_agent.flush_event_batches(
            api_url="http://localhost:8000",
            headers={"X-API-Key": "k", "X-Tenant-Id": "t"},
            events=events,
            batch_size=2,
            send_func=capture_send,
            max_retries=0,
            retry_base_delay=1.0,
            retry_max_delay=8.0,
            sleep_func=lambda _seconds: None,
        )

        self.assertEqual(sent, 3)
        self.assertEqual(failed, 0)
        self.assertEqual(captured_batch_sizes, [2, 2, 1])

    def test_flush_event_batches_retries_until_success(self):
        attempts = {"count": 0}
        sleep_calls = []

        def fake_send(_api_url, _headers, _batch):
            attempts["count"] += 1
            return attempts["count"] >= 3

        sent, failed = soc_agent.flush_event_batches(
            api_url="http://localhost:8000",
            headers={"X-API-Key": "k", "X-Tenant-Id": "t"},
            events=[{"id": 1}],
            batch_size=10,
            send_func=fake_send,
            max_retries=3,
            retry_base_delay=1.0,
            retry_max_delay=8.0,
            sleep_func=sleep_calls.append,
        )

        self.assertEqual(sent, 1)
        self.assertEqual(failed, 0)
        self.assertEqual(sleep_calls, [1.0, 2.0])

    def test_flush_event_batches_marks_failed_after_retries(self):
        sleep_calls = []

        def always_fail(_api_url, _headers, _batch):
            return False

        sent, failed = soc_agent.flush_event_batches(
            api_url="http://localhost:8000",
            headers={"X-API-Key": "k", "X-Tenant-Id": "t"},
            events=[{"id": 1}, {"id": 2}],
            batch_size=2,
            send_func=always_fail,
            max_retries=2,
            retry_base_delay=1.0,
            retry_max_delay=8.0,
            sleep_func=sleep_calls.append,
        )

        self.assertEqual(sent, 0)
        self.assertEqual(failed, 1)
        self.assertEqual(sleep_calls, [1.0, 2.0])


if __name__ == "__main__":
    unittest.main()