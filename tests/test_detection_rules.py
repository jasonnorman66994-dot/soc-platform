"""Tests for detection/rules.py geo allowlist configuration."""
from __future__ import annotations

import os
import sys
import unittest

_BACKEND_PATH = os.path.join(os.path.dirname(__file__), "..", "backend")
if _BACKEND_PATH not in sys.path:
    sys.path.insert(0, _BACKEND_PATH)

import importlib


class TestDetectGeoDefault(unittest.TestCase):
    def setUp(self):
        os.environ.pop("ALLOWED_LOCATIONS", None)
        import detection.rules as mod
        importlib.reload(mod)
        self.rules = mod

    def test_us_no_impossible_travel(self):
        event = {"event_type": "login_success", "location": "US", "ip": "1.2.3.4"}
        alerts = self.rules.detect(event)
        types = [a["type"] for a in alerts]
        self.assertNotIn("impossible_travel", types)

    def test_ng_no_impossible_travel(self):
        event = {"event_type": "login_success", "location": "NG", "ip": "1.2.3.4"}
        alerts = self.rules.detect(event)
        types = [a["type"] for a in alerts]
        self.assertNotIn("impossible_travel", types)

    def test_ru_triggers_impossible_travel(self):
        event = {"event_type": "login_success", "location": "RU", "ip": "1.2.3.4"}
        alerts = self.rules.detect(event)
        types = [a["type"] for a in alerts]
        self.assertIn("impossible_travel", types)

    def test_location_is_normalized_before_check(self):
        event = {"event_type": "login_success", "location": " us ", "ip": "1.2.3.4"}
        alerts = self.rules.detect(event)
        types = [a["type"] for a in alerts]
        self.assertNotIn("impossible_travel", types)

    def test_gb_no_impossible_travel_default(self):
        """GB is in the default allowlist."""
        event = {"event_type": "login_success", "location": "GB", "ip": "1.2.3.4"}
        alerts = self.rules.detect(event)
        types = [a["type"] for a in alerts]
        self.assertNotIn("impossible_travel", types)


class TestDetectGeoCustomAllowlist(unittest.TestCase):
    def test_custom_allowlist_respected(self):
        os.environ["ALLOWED_LOCATIONS"] = "JP,KR"
        import detection.rules as mod
        importlib.reload(mod)

        try:
            event_jp = {"event_type": "login_success", "location": "JP", "ip": "1.2.3.4"}
            self.assertNotIn(
                "impossible_travel",
                [a["type"] for a in mod.detect(event_jp)],
            )

            event_us = {"event_type": "login_success", "location": "US", "ip": "1.2.3.4"}
            self.assertIn(
                "impossible_travel",
                [a["type"] for a in mod.detect(event_us)],
            )
        finally:
            os.environ.pop("ALLOWED_LOCATIONS", None)
            importlib.reload(mod)

    def test_whitespace_in_env_var_handled(self):
        os.environ["ALLOWED_LOCATIONS"] = " US , CA , GB "
        import detection.rules as mod
        importlib.reload(mod)

        try:
            event = {"event_type": "login_success", "location": "CA", "ip": "1.2.3.4"}
            self.assertNotIn(
                "impossible_travel",
                [a["type"] for a in mod.detect(event)],
            )
        finally:
            os.environ.pop("ALLOWED_LOCATIONS", None)
            importlib.reload(mod)


class TestDetectFailedLogin(unittest.TestCase):
    def setUp(self):
        os.environ.pop("ALLOWED_LOCATIONS", None)
        import detection.rules as mod
        importlib.reload(mod)
        self.rules = mod

    def test_failed_login_triggers_brute_force(self):
        event = {"event_type": "failed_login", "location": "US", "ip": "10.0.0.1"}
        alerts = self.rules.detect(event)
        types = [a["type"] for a in alerts]
        self.assertIn("brute_force", types)

    def test_suspicious_ip_prefix(self):
        event = {"event_type": "login_success", "location": "US", "ip": "185.220.101.5"}
        alerts = self.rules.detect(event)
        types = [a["type"] for a in alerts]
        self.assertIn("suspicious_ip", types)


if __name__ == "__main__":
    unittest.main()
