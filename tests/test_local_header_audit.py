import unittest

from defensive_security_lab.local_header_audit import (
    TargetRefused,
    audit_headers,
    require_loopback_url,
    resolve_addresses,
)


class LoopbackBoundaryTests(unittest.TestCase):
    def test_accepts_loopback_literals(self):
        for value in ("http://127.0.0.1:8000", "http://127.0.0.1:3000/path", "https://[::1]:443"):
            with self.subTest(value=value):
                self.assertEqual(require_loopback_url(value), value)

    def test_accepts_localhost_when_it_resolves_to_loopback(self):
        self.assertEqual(require_loopback_url("http://localhost:3000"), "http://localhost:3000")

    def test_rejects_external_hosts_and_schemes(self):
        for value in (
            "https://example.com",
            "http://203.0.113.42",
            "http://198.51.100.9:3000",
            "ftp://127.0.0.1",
            "file:///etc/passwd",
            "http://",
            "not-a-url",
        ):
            with self.subTest(value=value), self.assertRaises(TargetRefused):
                require_loopback_url(value)

    def test_rejects_hostnames_other_than_localhost(self):
        for value in ("http://juice-shop.local", "http://demo.owasp-juice.shop"):
            with self.subTest(value=value), self.assertRaises(TargetRefused):
                require_loopback_url(value, verify_dns=False)

    def test_offline_mode_still_rejects_non_loopback(self):
        with self.assertRaises(TargetRefused):
            require_loopback_url("http://192.168.1.10", verify_dns=False)

    def test_localhost_resolves_only_to_loopback_on_this_host(self):
        for address in resolve_addresses("localhost", 80):
            with self.subTest(address=address):
                self.assertTrue(address.startswith("127.") or address in {"::1", "0:0:0:0:0:0:0:1"})

    def test_a_hijacked_localhost_is_refused(self):
        """The reason DNS is verified rather than trusted.

        Some resolvers answer names that should not exist — this project's
        verification host returns addresses in 198.18.0.0/15 for
        ``invalid.invalid``. If a resolver can be made to answer ``localhost``
        with a routable address, a name-only check would send traffic off the
        machine. Verification must catch that.
        """

        import socket as socket_module

        from defensive_security_lab import local_header_audit

        original = local_header_audit.socket.getaddrinfo

        def hostile(host, port, *args, **kwargs):
            if host == "localhost":
                return [(socket_module.AF_INET, None, None, "", ("198.18.0.149", port))]
            return original(host, port, *args, **kwargs)

        local_header_audit.socket.getaddrinfo = hostile
        try:
            with self.assertRaises(TargetRefused):
                require_loopback_url("http://localhost:3000")
        finally:
            local_header_audit.socket.getaddrinfo = original

    def test_name_only_check_would_have_passed_the_hijack(self):
        """Contrast: with verification disabled the same URL is accepted."""

        self.assertEqual(
            require_loopback_url("http://localhost:3000", verify_dns=False),
            "http://localhost:3000",
        )


class HeaderPresenceTests(unittest.TestCase):
    def test_reports_present_and_missing(self):
        result = audit_headers({"X-Content-Type-Options": "nosniff"})
        self.assertIn("x-content-type-options", result["present"])
        self.assertIn("content-security-policy", result["missing"])

    def test_header_names_are_case_insensitive(self):
        result = audit_headers({"REFERRER-POLICY": "no-referrer"})
        self.assertIn("referrer-policy", result["present"])


if __name__ == "__main__":
    unittest.main()
