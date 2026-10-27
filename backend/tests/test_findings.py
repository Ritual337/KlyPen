import unittest
from backend.scanner.findings import make_finding, redact, score, deduplicate


class FindingTests(unittest.TestCase):
    def test_redacts_sensitive_text(self):
        self.assertIn("[REDACTED]", redact("api_key=very-secret"))
        self.assertEqual(redact({"Set-Cookie": "secret=value", "status": 200}), {"Set-Cookie": "[REDACTED]", "status": 200})

    def test_finding_schema_and_severity_validation(self):
        finding = make_finding(title="Test", category="test", severity="nonsense", confidence="odd", url="https://example.com", description="desc", evidence={"token": "abc"}, remediation="fix")
        self.assertEqual(finding["severity"], "info")
        self.assertEqual(finding["confidence"], "low")
        self.assertEqual(finding["evidence"]["token"], "[REDACTED]")

    def test_deduplication(self):
        f = make_finding(title="A", category="headers", severity="low", confidence="high", url="https://example.com", description="d", evidence={}, remediation="r")
        self.assertEqual(len(deduplicate([f, f])), 1)

    def test_score_is_bounded_and_transparent(self):
        fs = [make_finding(title="A", category="x", severity="high", confidence="high", url="https://example.com", description="d", evidence={}, remediation="r")]
        value = score(fs)
        self.assertEqual(value["score"], 85)
        self.assertIn("not a certification", value["explanation"])
        self.assertEqual(score([])["score"], 100)


if __name__ == "__main__":
    unittest.main()
