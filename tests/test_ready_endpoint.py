from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient


BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as backend_app


class ReadyEndpointTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(backend_app.app)

    def test_ready_returns_200_when_dependencies_healthy(self):
        with (
            patch.object(backend_app, "_check_database_readiness", return_value=None),
            patch.object(backend_app, "_check_redis_readiness", return_value=None),
        ):
            response = self.client.get("/ready")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["service"], "api-gateway")
        self.assertEqual(payload["checks"]["database"], "ok")
        self.assertEqual(payload["checks"]["redis"], "ok")

    def test_ready_returns_503_with_sanitized_check_status(self):
        with (
            patch.object(backend_app, "_check_database_readiness", side_effect=RuntimeError("db secret details")),
            patch.object(backend_app, "_check_redis_readiness", return_value=None),
        ):
            response = self.client.get("/ready")

        self.assertEqual(response.status_code, 503)
        payload = response.json()
        self.assertEqual(payload["status"], "not_ready")
        self.assertEqual(payload["service"], "api-gateway")
        self.assertEqual(payload["checks"]["database"], "unavailable")
        self.assertEqual(payload["checks"]["redis"], "ok")
        self.assertNotIn("detail", payload)
        self.assertNotIn("db secret details", str(payload))

    def test_health_ready_alias_works(self):
        with (
            patch.object(backend_app, "_check_database_readiness", return_value=None),
            patch.object(backend_app, "_check_redis_readiness", return_value=None),
        ):
            response = self.client.get("/health/ready")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ready")


if __name__ == "__main__":
    unittest.main()