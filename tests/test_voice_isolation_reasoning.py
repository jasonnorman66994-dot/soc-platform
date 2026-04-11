from pathlib import Path
import sys
import unittest
from unittest.mock import patch


BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as backend_app


class FakeCursor:
    def __init__(self, fetchone_result=None, fetchall_result=None):
        self.fetchone_result = fetchone_result
        self.fetchall_result = fetchall_result or []
        self.execute_calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, query, params=None):
        self.execute_calls.append((query, params))

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


class VoiceIsolationReasoningTests(unittest.TestCase):
    def test_latest_isolated_user_includes_automated_revocation_action(self):
        cursor = FakeCursor(fetchone_result={"resource": "users/demo.user"})

        with patch.object(backend_app, "get_conn", return_value=FakeConn(cursor)):
            user_id = backend_app._latest_isolated_user("demo-corp")

        self.assertEqual(user_id, "demo.user")
        _, params = cursor.execute_calls[0]
        self.assertEqual(params, ("demo-corp", ["jit.revoke", "jit.session_revoked"]))

    def test_build_isolation_reasoning_accepts_session_revoked_action(self):
        cursor = FakeCursor(
            fetchall_result=[
                {
                    "action": "jit.session_revoked",
                    "resource": "users/demo.user",
                    "meta": {"reason": "risk_spike"},
                    "timestamp": None,
                }
            ]
        )

        with patch.object(backend_app, "get_conn", return_value=FakeConn(cursor)):
            reasons = backend_app._build_isolation_reasoning("demo-corp", "demo.user")

        self.assertEqual(reasons, ["JIT isolation triggered (risk_spike)"])


if __name__ == "__main__":
    unittest.main()