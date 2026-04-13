from pathlib import Path
import sys
import unittest

from fastapi import HTTPException


BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as backend_app


class TenantHeaderValidationTests(unittest.TestCase):
    def test_get_tenant_rejects_whitespace_only_header(self):
        with self.assertRaises(HTTPException) as ctx:
            backend_app.get_tenant("   ")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "Missing X-Tenant-ID header")

    def test_get_tenant_strips_whitespace(self):
        tenant_id = backend_app.get_tenant("  demo-corp  ")
        self.assertEqual(tenant_id, "demo-corp")


if __name__ == "__main__":
    unittest.main()