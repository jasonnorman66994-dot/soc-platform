"""Tests for the email_drive_status voice command intent."""
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


class EmailDriveVoiceTests(unittest.TestCase):
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

    def test_email_drive_status_threat_detected(self):
        """Voice command returns flagged TLDs when a spamming drive is detected."""
        drive_result = {
            "flagged_tlds": [
                {
                    "tld": "evil-spam.xyz",
                    "z_score": 5.12,
                    "current_avg_link_density": 12.5,
                    "baseline_mean": 1.8,
                    "baseline_stddev": 0.6,
                    "current_hour_msgs": 240,
                    "threat_type": "spamming_drive",
                }
            ],
            "total_tlds_analyzed": 3,
            "status": "threat_detected",
            "current_hour_msgs": 320,
        }

        with (
            patch.object(backend_app, "_email_drive_status", return_value=drive_result),
            patch.object(backend_app, "log_action", return_value=None),
        ):
            response = self.client.post(
                "/voice/command",
                json={"intent": "email_drive_status"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["command"], "email_drive_status")
        self.assertEqual(payload["status"], "threat_detected")
        self.assertEqual(len(payload["flagged_tlds"]), 1)
        self.assertEqual(payload["flagged_tlds"][0]["tld"], "evil-spam.xyz")
        self.assertEqual(payload["current_hour_msgs"], 320)
        self.assertIn("evil-spam.xyz", payload["reasoning"][0])
        self.assertIn("5.12", payload["reasoning"][0])

    def test_email_drive_status_clear(self):
        """Voice command returns clear status when no drives are active."""
        drive_result = {
            "flagged_tlds": [],
            "total_tlds_analyzed": 2,
            "status": "clear",
            "current_hour_msgs": 15,
        }

        with (
            patch.object(backend_app, "_email_drive_status", return_value=drive_result),
            patch.object(backend_app, "log_action", return_value=None),
        ):
            response = self.client.post(
                "/voice/command",
                json={"intent": "spam_drive_status"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["command"], "email_drive_status")
        self.assertEqual(payload["intent"], "spam_drive_status")
        self.assertEqual(payload["status"], "clear")
        self.assertEqual(payload["flagged_tlds"], [])
        self.assertEqual(payload["current_hour_msgs"], 15)
        self.assertIn("No active spamming drives", payload["reasoning"][0])


if __name__ == "__main__":
    unittest.main()
