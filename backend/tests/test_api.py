import os
import tempfile
import unittest
from pathlib import Path

# Keep test data isolated from a user's real KlyPen database.
_TEST_TMP = tempfile.TemporaryDirectory(prefix="klypen-tests-")
os.environ["KLYPEN_DB_PATH"] = str(Path(_TEST_TMP.name) / "klypen-tests.db")
os.environ["KLYPEN_LAB_ENABLED"] = "false"

from fastapi.testclient import TestClient
from backend.app import app, db


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client_context = TestClient(app)
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)

    def test_health_and_provider_status(self):
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["app"], "KlyPen")
        providers = self.client.get("/api/v1/providers").json()["providers"]
        self.assertTrue(any(p["name"] == "OSV.dev" for p in providers))
        self.assertTrue(any(p["name"] == "Local scanner" for p in providers))

    def test_scan_requires_authorization_confirmation(self):
        response = self.client.post("/api/v1/scans", json={"url": "https://example.com", "authorized": False})
        self.assertEqual(response.status_code, 400)
        self.assertIn("permission", response.json()["detail"].lower())

    def test_scan_blocks_loopback_targets_by_default(self):
        response = self.client.post("/api/v1/scans", json={"url": "http://127.0.0.1/", "authorized": True})
        self.assertEqual(response.status_code, 400)
        self.assertTrue("loopback" in response.json()["detail"].lower() or "private" in response.json()["detail"].lower())

    def test_dashboard_serves_static_app(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("KlyPen", response.text)
        self.assertIn("/static/app.js", response.text)

    def test_finding_list_endpoint(self):
        response = self.client.get("/api/v1/findings")
        self.assertEqual(response.status_code, 200)
        self.assertIn("findings", response.json())

    def test_rejects_unexpected_host_header(self):
        response = self.client.get("/api/v1/health", headers={"Host": "example.invalid"})
        self.assertEqual(response.status_code, 400)

    def test_blocks_cross_origin_state_changing_request(self):
        response = self.client.post("/api/v1/scans", headers={"Origin": "https://example.invalid"}, json={"url": "https://example.com", "authorized": True})
        self.assertEqual(response.status_code, 403)

    def test_html_report_escapes_untrusted_finding_content(self):
        from backend.scanner.findings import make_finding
        import uuid
        scan_id = str(uuid.uuid4())
        db.create_scan(scan_id, "https://example.com/", "https://example.com")
        db.update_scan(scan_id, status="completed", stage="completed", progress=100, summary_json={"score": 100, "explanation": "test"})
        db.add_findings(scan_id, [make_finding(title="<script>alert(1)</script>", category="test", severity="info", confidence="low",
            url="https://example.com/", description="<img src=x onerror=alert(1)>", evidence={"note": "<script>"}, remediation="<b>fix</b>")])
        response = self.client.get(f"/api/v1/reports/{scan_id}/html")
        self.assertEqual(response.status_code, 200)
        self.assertIn("&lt;script&gt;", response.text)
        self.assertNotIn("<script>alert(1)</script>", response.text)
        self.assertNotIn("<img src=x onerror=alert(1)>", response.text)


if __name__ == "__main__":
    unittest.main()
