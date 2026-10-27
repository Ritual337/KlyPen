import json
import os
import unittest
from unittest.mock import patch

from backend.providers import osv, otx


class FakeContent:
    def __init__(self, data):
        self.data = data
    async def read(self, limit=-1):
        return self.data[:limit]


class FakeResponse:
    status = 200
    def __init__(self, payload):
        self.content = FakeContent(json.dumps(payload).encode())
    async def __aenter__(self): return self
    async def __aexit__(self, *args): return None


class FakeSession:
    def __init__(self, *args, **kwargs): self.posts = 0
    async def __aenter__(self): return self
    async def __aexit__(self, *args): return None
    def post(self, *args, **kwargs):
        self.posts += 1
        return FakeResponse({"vulns": [{"id": "GHSA-test", "summary": "Example advisory", "references": [{"url": "https://example.org/advisory"}]}]})


class ProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_osv_uses_documented_package_version_shape_and_caches(self):
        key = ("klypen-test-package", "1.2.3", "PyPI")
        osv._cache.pop(key, None)
        with patch("backend.providers.osv.aiohttp.ClientSession", FakeSession):
            first = await osv.query_package(*key)
            second = await osv.query_package(*key)
        self.assertEqual(first["count"], 1)
        self.assertEqual(first["vulnerabilities"][0]["id"], "GHSA-test")
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertIn("not proof", first["note"])

    async def test_osv_rejects_unsupported_ecosystem(self):
        with self.assertRaises(ValueError):
            await osv.query_package("some-package", "1.0", "NotAnEcosystem")

    async def test_otx_is_disabled_without_explicit_opt_in(self):
        with patch.dict(os.environ, {"KLYPEN_OTX_ENABLED": "false", "OTX_API_KEY": ""}):
            with self.assertRaises(RuntimeError):
                await otx.lookup_domain("example.com")


if __name__ == "__main__":
    unittest.main()
