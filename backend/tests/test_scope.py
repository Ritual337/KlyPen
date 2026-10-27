import os
import unittest
from unittest.mock import patch

from backend.scanner.scope import ScopeError, normalize_and_validate, redact_url


class ScopeTests(unittest.TestCase):
    def test_normalizes_public_url_without_network_resolution(self):
        target = normalize_and_validate("HTTPS://Example.COM/path?q=1#fragment", resolve_dns=False)
        self.assertEqual(target.url, "https://example.com/path?q=1")
        self.assertEqual(target.origin, "https://example.com")

    def test_rejects_credentials_in_url(self):
        with self.assertRaises(ScopeError):
            normalize_and_validate("https://user:pass@example.com", resolve_dns=False)

    def test_rejects_non_http_schemes(self):
        with self.assertRaises(ScopeError):
            normalize_and_validate("file:///etc/passwd", resolve_dns=False)

    def test_rejects_private_ip(self):
        for url in ("http://127.0.0.1/", "http://10.10.0.2/", "http://169.254.169.254/", "http://192.168.1.1/"):
            with self.subTest(url=url), self.assertRaises(ScopeError):
                normalize_and_validate(url, resolve_dns=False)

    def test_rejects_ipv4_mapped_and_6to4_ipv6(self):
        for url in ("http://[::ffff:127.0.0.1]/", "http://[2002:0808:0808::]/"):
            with self.subTest(url=url), self.assertRaises(ScopeError):
                normalize_and_validate(url, resolve_dns=False)

    def test_rejects_ambiguous_numeric_host(self):
        with self.assertRaises(ScopeError):
            normalize_and_validate("http://2130706433/", resolve_dns=False)

    def test_rejects_unsupported_port(self):
        with self.assertRaises(ScopeError):
            normalize_and_validate("https://example.com:4444/", resolve_dns=False)

    def test_port_9001_requires_enabled_lab_and_loopback(self):
        with patch.dict(os.environ, {"KLYPEN_LAB_ENABLED": "false"}):
            with self.assertRaises(ScopeError):
                normalize_and_validate("http://127.0.0.1:9001/", resolve_dns=False)
        with patch.dict(os.environ, {"KLYPEN_LAB_ENABLED": "true"}):
            target = normalize_and_validate("http://127.0.0.1:9001/", resolve_dns=False)
            self.assertTrue(target.is_lab)
            with self.assertRaises(ScopeError):
                normalize_and_validate("http://example.com:9001/", resolve_dns=False)

    def test_redacts_secret_query_params(self):
        result = redact_url("https://example.com/?page=2&access_token=abc123&password=hunter2")
        self.assertIn("page=2", result)
        self.assertNotIn("abc123", result)
        self.assertNotIn("hunter2", result)
        self.assertIn("REDACTED", result)

    def test_rejects_malformed_bracketed_host(self):
        with self.assertRaises(ScopeError):
            normalize_and_validate("https://[:::]/", resolve_dns=False)


if __name__ == "__main__":
    unittest.main()
