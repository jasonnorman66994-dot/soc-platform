from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient


BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as backend_app


class FakeCursor:
    def __init__(self, fetchone_result=None, fetchall_result=None):
        self.fetchone_result = fetchone_result
        self.fetchall_result = fetchall_result or []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, query, params=None):
        self.last_query = query
        self.last_params = params

    def fetchone(self):
        return self.fetchone_result

    def fetchall(self):
        return self.fetchall_result


class FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return self._cursor


class ApiVoiceIntentTests(unittest.TestCase):
    def setUp(self):
        backend_app.app.dependency_overrides[backend_app.get_tenant] = lambda: "demo-corp"
        backend_app.app.dependency_overrides[backend_app.get_current_user] = lambda: {
            "id": "owner.user",
            "role": "owner",
            "tenant_id": "demo-corp",
        }
        self.client = TestClient(backend_app.app)

    def tearDown(self):
        backend_app.app.dependency_overrides.clear()

    def test_voice_command_accepts_intent_payload_for_isolation_reasoning(self):
        latest_isolation_cursor = FakeCursor(fetchone_result={"resource": "users/demo.user"})
        reasoning_cursor = FakeCursor(
            fetchall_result=[
                {
                    "action": "jit.session_revoked",
                    "resource": "users/demo.user",
                    "meta": {"reason": "risk_spike"},
                    "timestamp": None,
                }
            ]
        )

        with (
            patch.object(
                backend_app,
                "get_conn",
                side_effect=[FakeConn(latest_isolation_cursor), FakeConn(reasoning_cursor)],
            ),
            patch.object(backend_app, "log_action", return_value=None),
        ):
            response = self.client.post(
                "/voice/command",
                json={"intent": "why_was_this_user_isolated"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "why_was_this_user_isolated")
        self.assertEqual(payload["target_user"], "demo.user")
        self.assertEqual(payload["status"], "explained")
        self.assertEqual(payload["reasoning"], ["JIT isolation triggered (risk_spike)"])


if __name__ == "__main__":
    unittest.main()