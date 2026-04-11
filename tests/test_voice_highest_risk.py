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


class VoiceHighestRiskTests(unittest.TestCase):
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

    def test_voice_identify_highest_risk_user_with_data(self):
        from datetime import datetime, timezone

        hourly_rows = [
            {"user_id": "analyst.user", "type": "login_success", "hour_bucket": datetime(2026, 4, 10, 8, tzinfo=timezone.utc), "cnt": 3},
            {"user_id": "analyst.user", "type": "login_success", "hour_bucket": datetime(2026, 4, 10, 9, tzinfo=timezone.utc), "cnt": 2},
            {"user_id": "analyst.user", "type": "login_success", "hour_bucket": datetime(2026, 4, 10, 10, tzinfo=timezone.utc), "cnt": 15},
            {"user_id": "demo.user", "type": "network_connection", "hour_bucket": datetime(2026, 4, 10, 8, tzinfo=timezone.utc), "cnt": 5},
            {"user_id": "demo.user", "type": "network_connection", "hour_bucket": datetime(2026, 4, 10, 9, tzinfo=timezone.utc), "cnt": 4},
        ]
        risk_cursor = FakeCursor(fetchall_result=hourly_rows)
        log_cursor = FakeCursor()

        with (
            patch.object(
                backend_app,
                "get_conn",
                side_effect=[FakeConn(risk_cursor), FakeConn(log_cursor)],
            ),
            patch.object(backend_app, "log_action", return_value=None),
        ):
            response = self.client.post(
                "/voice/command",
                json={"intent": "identify_highest_risk_user"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["command"], "identify_highest_risk_user")
        self.assertEqual(payload["status"], "explained")
        self.assertEqual(payload["target_user"], "analyst.user")
        self.assertGreater(payload["max_z_score"], 0)
        self.assertIn("event_type", payload)
        self.assertIsInstance(payload["reasoning"], list)
        self.assertGreater(len(payload["reasoning"]), 0)
        self.assertIn("z_score_meta", payload)

    def test_voice_highest_risk_user_no_data(self):
        empty_cursor = FakeCursor(fetchall_result=[])
        log_cursor = FakeCursor()

        with (
            patch.object(
                backend_app,
                "get_conn",
                side_effect=[FakeConn(empty_cursor), FakeConn(log_cursor)],
            ),
            patch.object(backend_app, "log_action", return_value=None),
        ):
            response = self.client.post(
                "/voice/command",
                json={"intent": "who_is_highest_risk"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["command"], "identify_highest_risk_user")
        self.assertEqual(payload["status"], "no_data")
        self.assertIsNone(payload["target_user"])

    def test_voice_highest_risk_alias_accepted(self):
        rows = [
            {"user_id": "cyber.lead", "type": "login_success", "hour_bucket": "2026-04-10T08:00:00+00:00", "cnt": 5},
        ]
        risk_cursor = FakeCursor(fetchall_result=rows)
        log_cursor = FakeCursor()

        with (
            patch.object(
                backend_app,
                "get_conn",
                side_effect=[FakeConn(risk_cursor), FakeConn(log_cursor)],
            ),
            patch.object(backend_app, "log_action", return_value=None),
        ):
            response = self.client.post(
                "/voice/command",
                json={"intent": "identify_the_highest_risk_user_and_explain_why"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["command"], "identify_highest_risk_user")
        self.assertEqual(payload["intent"], "identify_the_highest_risk_user_and_explain_why")


if __name__ == "__main__":
    unittest.main()
