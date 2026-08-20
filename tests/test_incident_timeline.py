import unittest
from datetime import timedelta
from pathlib import Path

from defensive_security_lab.incident_timeline import analyze_events, analyze_file, load_events

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def event(timestamp, user, source_ip, result):
    return {"timestamp": timestamp, "user": user, "source_ip": source_ip, "result": result}


def types(findings):
    return sorted(finding["type"] for finding in findings)


class BurstWindowTests(unittest.TestCase):
    """Regressions for defect A2: burst counted totals, not a rate."""

    def test_failures_inside_the_window_are_a_burst(self):
        events = [
            event("2026-08-20T00:00:01Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:02Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:03Z", "u", "203.0.113.9", "failure"),
        ]
        self.assertIn("failed_login_burst", types(analyze_events(events)))

    def test_failures_spread_beyond_the_window_are_not_a_burst(self):
        events = [
            event("2025-01-01T00:00:00Z", "u", "203.0.113.9", "failure"),
            event("2025-06-01T00:00:00Z", "u", "203.0.113.9", "failure"),
            event("2026-01-01T00:00:00Z", "u", "203.0.113.9", "failure"),
        ]
        self.assertEqual(analyze_events(events), [])

    def test_window_boundary_is_inclusive(self):
        events = [
            event("2026-08-20T00:00:00Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:02:30Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:05:00Z", "u", "203.0.113.9", "failure"),
        ]
        self.assertIn("failed_login_burst", types(analyze_events(events)))

    def test_one_second_past_the_window_does_not_burst(self):
        events = [
            event("2026-08-20T00:00:00Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:02:30Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:05:01Z", "u", "203.0.113.9", "failure"),
        ]
        self.assertEqual(analyze_events(events), [])

    def test_window_is_configurable(self):
        events = [
            event("2026-08-20T00:00:00Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:30:00Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:59:00Z", "u", "203.0.113.9", "failure"),
        ]
        self.assertEqual(analyze_events(events), [])
        widened = analyze_events(events, window=timedelta(hours=2))
        self.assertIn("failed_login_burst", types(widened))


class SuccessResetTests(unittest.TestCase):
    """Regressions for defect A3: the counter survived a successful login."""

    def test_success_after_enough_failures_is_reported(self):
        events = [
            event("2026-08-20T00:00:01Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:02Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:03Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:04Z", "u", "203.0.113.9", "success"),
        ]
        self.assertIn("success_after_failed_logins", types(analyze_events(events)))

    def test_a_later_success_does_not_reuse_closed_history(self):
        events = [
            event("2026-08-20T00:00:01Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:02Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:03Z", "u", "203.0.113.9", "success"),
            event("2026-08-20T00:00:04Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:05Z", "u", "203.0.113.9", "success"),
        ]
        findings = analyze_events(events)
        self.assertEqual(
            [f for f in findings if f["type"] == "success_after_failed_logins"],
            [],
            "two failures either side of a success must not be summed",
        )

    def test_a_new_episode_after_a_success_is_still_detected(self):
        events = [
            event("2026-08-20T00:00:01Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:02Z", "u", "203.0.113.9", "success"),
            event("2026-08-20T00:00:03Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:04Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:05Z", "u", "203.0.113.9", "failure"),
            event("2026-08-20T00:00:06Z", "u", "203.0.113.9", "success"),
        ]
        self.assertIn("success_after_failed_logins", types(analyze_events(events)))


class PasswordSprayTests(unittest.TestCase):
    def test_one_source_touching_many_accounts_is_spraying(self):
        events = [
            event("2026-08-20T02:00:00Z", "alice", "198.51.100.9", "failure"),
            event("2026-08-20T02:00:20Z", "bob", "198.51.100.9", "failure"),
            event("2026-08-20T02:00:40Z", "carol", "198.51.100.9", "failure"),
        ]
        findings = [f for f in analyze_events(events) if f["type"] == "password_spray"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["users"], ["alice", "bob", "carol"])

    def test_deep_attempts_on_one_account_are_not_spraying(self):
        events = [
            event("2026-08-20T02:00:00Z", "alice", "198.51.100.9", "failure"),
            event("2026-08-20T02:00:10Z", "alice", "198.51.100.9", "failure"),
            event("2026-08-20T02:00:20Z", "alice", "198.51.100.9", "failure"),
        ]
        findings = analyze_events(events)
        self.assertNotIn("password_spray", types(findings))
        self.assertIn("failed_login_burst", types(findings))

    def test_accounts_touched_outside_the_window_are_not_spraying(self):
        events = [
            event("2026-08-20T02:00:00Z", "alice", "198.51.100.9", "failure"),
            event("2026-08-20T02:30:00Z", "bob", "198.51.100.9", "failure"),
            event("2026-08-20T03:00:00Z", "carol", "198.51.100.9", "failure"),
        ]
        self.assertNotIn("password_spray", types(analyze_events(events)))


class EventLoadingTests(unittest.TestCase):
    def test_rejects_missing_fields(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
            handle.write('{"timestamp":"2026-08-20T00:00:00Z","user":"u"}\n')
            path = handle.name
        with self.assertRaises(ValueError):
            load_events(path)

    def test_rejects_unknown_result_value(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
            handle.write(
                '{"timestamp":"2026-08-20T00:00:00Z","user":"u",'
                '"source_ip":"203.0.113.9","result":"maybe"}\n'
            )
            path = handle.name
        with self.assertRaises(ValueError):
            load_events(path)


class BundledFixtureTests(unittest.TestCase):
    def test_burst_fixture_reports_expected_findings(self):
        findings = analyze_file(FIXTURES / "auth_events.jsonl")
        self.assertEqual(types(findings), ["failed_login_burst", "success_after_failed_logins"])
        self.assertTrue(all(f["user"] == "lab-user" for f in findings))

    def test_slow_user_in_the_same_fixture_is_a_negative_control(self):
        findings = analyze_file(FIXTURES / "auth_events.jsonl")
        self.assertEqual([f for f in findings if f.get("user") == "slow-user"], [])

    def test_spray_fixture_reports_spraying(self):
        findings = analyze_file(FIXTURES / "auth_events_spray.jsonl")
        spray = [f for f in findings if f["type"] == "password_spray"]
        self.assertEqual(len(spray), 1)
        self.assertEqual(spray[0]["source_ip"], "198.51.100.9")
        self.assertEqual(spray[0]["user_count"], 4)


if __name__ == "__main__":
    unittest.main()
