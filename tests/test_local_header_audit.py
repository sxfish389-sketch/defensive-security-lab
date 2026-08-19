import unittest

from defensive_security_lab.local_header_audit import audit_headers, require_loopback_url


class LocalHeaderAuditTests(unittest.TestCase):
    def test_accepts_loopback_targets(self):
        self.assertEqual(require_loopback_url("http://127.0.0.1:8000"), "http://127.0.0.1:8000")
        self.assertEqual(require_loopback_url("https://localhost"), "https://localhost")

    def test_rejects_external_targets(self):
        for value in ("https://example.com", "http://203.0.113.42", "ftp://127.0.0.1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                require_loopback_url(value)

    def test_reports_missing_headers(self):
        result = audit_headers({"X-Content-Type-Options": "nosniff"})
        self.assertIn("x-content-type-options", result["present"])
        self.assertIn("content-security-policy", result["missing"])


if __name__ == "__main__":
    unittest.main()

