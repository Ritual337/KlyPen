import unittest
from backend.checks.headers import check_headers
from backend.checks.cookies import check_cookies
from backend.checks.html_checks import inspect_html
from backend.checks.cors import check_cors


class CheckTests(unittest.TestCase):
    def test_header_checks(self):
        findings = check_headers("https://example.com", {"server": "demo"}, is_https=True)
        titles = {f["title"] for f in findings}
        self.assertIn("HTTP Strict Transport Security is missing", titles)
        self.assertIn("Technology-identifying response headers are present", titles)

    def test_cookie_values_are_not_stored(self):
        findings = check_cookies("https://example.com", {"set-cookie": "session_id=secret-value; Path=/"}, is_https=True)
        self.assertTrue(findings)
        evidence = str(findings[0]["evidence"])
        self.assertNotIn("secret-value", evidence)
        self.assertIn("session_id", evidence)

    def test_password_form_over_http(self):
        html = '<form method="post" action="http://example.com/login"><input type="password" name="p"></form>'
        findings, links = inspect_html("https://example.com/", html, is_https=True)
        self.assertTrue(any(f["severity"] == "high" and "Password form" in f["title"] for f in findings))

    def test_mixed_content(self):
        findings, _ = inspect_html("https://example.com/", '<img src="http://cdn.example.org/image.png">', is_https=True)
        self.assertTrue(any(f["category"] == "mixed-content" for f in findings))

    def test_wildcard_cors_is_informational(self):
        findings = check_cors("https://example.com", {"Access-Control-Allow-Origin": "*"})
        self.assertEqual(findings[0]["severity"], "info")

    def test_source_map_reference_is_reported_as_informational(self):
        findings, _ = inspect_html("https://example.com/", '<script>/*# sourceMappingURL=app.js.map */</script>', is_https=True)
        self.assertTrue(any("source-map" in f["title"].lower() for f in findings))


if __name__ == "__main__":
    unittest.main()
