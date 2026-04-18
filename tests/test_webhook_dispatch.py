"""Tests for send_webhook real HTTP dispatch."""
from __future__ import annotations

import json
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Allow importing backend modules without a full FastAPI startup
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from integrations.messaging import send_webhook


class TestSendWebhookMissingUrl(unittest.TestCase):
    def test_empty_url_returns_error(self):
        result = send_webhook("", {})
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["action"], "send_webhook")

    def test_none_url_returns_error(self):
        result = send_webhook(None, {})
        self.assertEqual(result["status"], "error")


class TestSendWebhookSuccess(unittest.TestCase):
    def _mock_response(self, status: int = 200):
        resp = MagicMock()
        resp.status = status
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_success_returns_ok(self):
        resp = self._mock_response(200)
        with patch("urllib.request.urlopen", return_value=resp):
            result = send_webhook("https://example.com/hook", {"event": "test"})

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["http_status"], 200)
        self.assertIn("example.com", result["url"])

    def test_custom_headers_forwarded(self):
        resp = self._mock_response(204)
        captured: list = []

        def fake_urlopen(request, timeout=None):
            captured.append(request.get_header("Authorization"))
            return resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = send_webhook(
                "https://example.com/hook",
                {"event": "test"},
                headers={"Authorization": "Bearer token123"},
            )

        self.assertEqual(result["status"], "success")
        self.assertEqual(captured[0], "Bearer token123")

    def test_payload_is_json_encoded(self):
        resp = self._mock_response(200)
        captured: list = []

        def fake_urlopen(request, timeout=None):
            captured.append(request.data)
            return resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            send_webhook("https://example.com/hook", {"key": "value"})

        decoded = json.loads(captured[0])
        self.assertEqual(decoded["key"], "value")


class TestSendWebhookErrors(unittest.TestCase):
    def test_http_error_returns_error_status(self):
        import urllib.error

        http_err = urllib.error.HTTPError(
            url="https://example.com/hook",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=None,
        )
        with patch("urllib.request.urlopen", side_effect=http_err):
            result = send_webhook("https://example.com/hook", {})

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["http_status"], 403)

    def test_url_error_returns_error_status(self):
        import urllib.error

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Name or service not known"),
        ):
            result = send_webhook("https://bad-host.invalid/hook", {})

        self.assertEqual(result["status"], "error")
        self.assertIn("failed", result["message"])


if __name__ == "__main__":
    unittest.main()
