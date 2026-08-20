import json
import unittest
from pathlib import Path

from defensive_security_lab.local_header_audit import TargetRefused
from defensive_security_lab.web_assessment import (
    analyze_cookie,
    analyze_cors,
    analyze_csp,
    analyze_headers,
    analyze_hsts,
    assess_response,
    assess_target,
    parse_csp,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def ids(findings):
    return {finding.identifier for finding in findings}


class CSPParsingTests(unittest.TestCase):
    def test_parses_directives_and_sources(self):
        parsed = parse_csp(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'"
        )
        self.assertEqual(parsed["default-src"], ["'self'"])
        self.assertEqual(parsed["script-src"], ["'self'", "'unsafe-inline'"])
        self.assertEqual(parsed["object-src"], ["'none'"])

    def test_tolerates_extra_semicolons_and_spacing(self):
        parsed = parse_csp("  default-src 'self' ;; script-src 'none' ; ")
        self.assertEqual(set(parsed), {"default-src", "script-src"})


class CSPWeaknessTests(unittest.TestCase):
    def test_unsafe_inline_in_script_src_is_high(self):
        findings = analyze_csp("script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        self.assertIn("csp-unsafe-inline-script-src", ids(findings))
        finding = next(f for f in findings if f.identifier == "csp-unsafe-inline-script-src")
        self.assertEqual(finding.severity, "high")

    def test_unsafe_inline_in_style_src_is_medium(self):
        findings = analyze_csp("style-src 'unsafe-inline'; frame-ancestors 'none'")
        finding = next(f for f in findings if f.identifier == "csp-unsafe-inline-style-src")
        self.assertEqual(finding.severity, "medium")

    def test_unsafe_eval_is_reported(self):
        findings = analyze_csp("script-src 'unsafe-eval'; frame-ancestors 'none'")
        self.assertIn("csp-unsafe-eval-script-src", ids(findings))

    def test_wildcard_source_is_reported(self):
        findings = analyze_csp("script-src *; frame-ancestors 'none'")
        self.assertIn("csp-wildcard-script-src", ids(findings))

    def test_data_uri_in_script_src_is_reported(self):
        findings = analyze_csp("script-src 'self' data:; frame-ancestors 'none'")
        self.assertIn("csp-data-uri-script-src", ids(findings))

    def test_directives_inherit_from_default_src(self):
        findings = analyze_csp("default-src 'unsafe-inline'; frame-ancestors 'none'")
        self.assertIn("csp-unsafe-inline-script-src", ids(findings))

    def test_frame_ancestors_does_not_inherit_from_default_src(self):
        """A real CSP subtlety: frame-ancestors has no default-src fallback."""

        findings = analyze_csp("default-src 'self'")
        self.assertIn("csp-no-frame-ancestors", ids(findings))

    def test_a_strict_policy_produces_no_findings(self):
        findings = analyze_csp("default-src 'none'; script-src 'self'; frame-ancestors 'none'")
        self.assertEqual(findings, [])


class HSTSTests(unittest.TestCase):
    def test_missing_max_age(self):
        self.assertIn("hsts-no-max-age", ids(analyze_hsts("includeSubDomains")))

    def test_zero_max_age(self):
        self.assertIn("hsts-max-age-zero", ids(analyze_hsts("max-age=0; includeSubDomains")))

    def test_short_max_age(self):
        self.assertIn("hsts-max-age-short", ids(analyze_hsts("max-age=3600; includeSubDomains")))

    def test_missing_subdomains(self):
        self.assertIn("hsts-no-subdomains", ids(analyze_hsts("max-age=31536000")))

    def test_good_policy_is_clean(self):
        self.assertEqual(analyze_hsts("max-age=31536000; includeSubDomains; preload"), [])


class CookieTests(unittest.TestCase):
    def test_flags_all_three_missing_attributes(self):
        found = ids(analyze_cookie("session=abc123; Path=/"))
        self.assertEqual(
            found,
            {
                "cookie-no-httponly-session",
                "cookie-no-secure-session",
                "cookie-no-samesite-session",
            },
        )

    def test_fully_protected_cookie_is_clean(self):
        self.assertEqual(
            analyze_cookie("session=abc; Path=/; HttpOnly; Secure; SameSite=Strict"), []
        )

    def test_attribute_matching_is_case_insensitive(self):
        self.assertEqual(analyze_cookie("s=1; httponly; secure; samesite=lax"), [])


class CORSTests(unittest.TestCase):
    """Added after a real capture returned ACAO: * on every endpoint reviewed."""

    def test_wildcard_origin_is_reported(self):
        self.assertIn(
            "cors-wildcard-origin", ids(analyze_cors({"Access-Control-Allow-Origin": "*"}))
        )

    def test_wildcard_with_credentials_is_high(self):
        findings = analyze_cors(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        self.assertEqual([f.identifier for f in findings], ["cors-wildcard-with-credentials"])
        self.assertEqual(findings[0].severity, "high")

    def test_specific_origin_is_not_reported(self):
        self.assertEqual(analyze_cors({"Access-Control-Allow-Origin": "https://example.com"}), [])

    def test_absent_header_is_not_reported(self):
        self.assertEqual(analyze_cors({}), [])


class HeaderReviewTests(unittest.TestCase):
    def test_absent_headers_are_reported(self):
        found = ids(analyze_headers({}))
        for expected in (
            "missing-csp",
            "missing-nosniff",
            "missing-x-frame-options",
            "missing-referrer-policy",
        ):
            self.assertIn(expected, found)

    def test_disclosure_headers_are_reported_as_info(self):
        findings = analyze_headers({"Server": "nginx/1.2.3", "X-Powered-By": "Express"})
        self.assertIn("disclosure-server", ids(findings))
        self.assertIn("disclosure-x-powered-by", ids(findings))
        for finding in findings:
            if finding.identifier.startswith("disclosure-"):
                self.assertEqual(finding.severity, "info")

    def test_a_well_configured_response_is_quiet(self):
        headers = {
            "Content-Security-Policy": (
                "default-src 'none'; script-src 'self'; frame-ancestors 'none'"
            ),
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }
        self.assertEqual(analyze_headers(headers), [])

    def test_set_cookie_is_analyzed(self):
        findings = analyze_headers({"Set-Cookie": "token=xyz; Path=/"})
        self.assertIn("cookie-no-httponly-token", ids(findings))


class AssessmentTests(unittest.TestCase):
    def test_findings_sort_by_severity(self):
        assessment = assess_response(
            "http://127.0.0.1:3000/",
            200,
            {"Server": "test", "Content-Security-Policy": "script-src 'unsafe-inline'"},
        )
        severities = [f.severity for f in assessment.sorted_findings()]
        self.assertEqual(
            severities, sorted(severities, key=lambda s: ["high", "medium", "low", "info"].index(s))
        )

    def test_serializes_to_plain_data(self):
        payload = assess_response("http://127.0.0.1:3000/", 200, {}).as_dict()
        self.assertEqual(payload["url"], "http://127.0.0.1:3000/")
        self.assertEqual(payload["status"], 200)
        self.assertIsInstance(payload["findings"], list)
        json.dumps(payload)  # must be JSON-serialisable

    def test_assess_target_refuses_a_non_loopback_url_before_any_request(self):
        with self.assertRaises(TargetRefused):
            assess_target("http://demo.owasp-juice.shop")


class CapturedResponseTests(unittest.TestCase):
    """Replay a response captured from the authorized local lab target.

    The capture is a fixture, so this test needs no running service and CI never
    starts a vulnerable application.
    """

    FIXTURE = FIXTURES / "juice_shop_baseline.json"

    @unittest.skipUnless(FIXTURE.exists(), "capture fixture not present")
    def test_capture_replays_to_recorded_findings(self):
        capture = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        assessment = assess_response(capture["url"], capture["status"], capture["headers"])
        self.assertEqual(
            sorted(f.identifier for f in assessment.findings),
            sorted(capture["expected_finding_ids"]),
        )

    @unittest.skipUnless(FIXTURE.exists(), "capture fixture not present")
    def test_capture_target_is_loopback(self):
        capture = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        self.assertTrue(capture["url"].startswith("http://127.0.0.1:"))


if __name__ == "__main__":
    unittest.main()
