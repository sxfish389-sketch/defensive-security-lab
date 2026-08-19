import unittest

from defensive_security_lab.incident_timeline import analyze_events


class IncidentTimelineTests(unittest.TestCase):
    def test_flags_burst_and_success_after_failures(self):
        events = [
            {"timestamp": "2026-08-20T00:00:01Z", "user": "lab", "source_ip": "203.0.113.42", "result": "failure"},
            {"timestamp": "2026-08-20T00:00:02Z", "user": "lab", "source_ip": "203.0.113.42", "result": "failure"},
            {"timestamp": "2026-08-20T00:00:03Z", "user": "lab", "source_ip": "203.0.113.42", "result": "failure"},
            {"timestamp": "2026-08-20T00:00:04Z", "user": "lab", "source_ip": "203.0.113.42", "result": "success"},
        ]
        findings = analyze_events(events)
        self.assertEqual({finding["type"] for finding in findings}, {"failed_login_burst", "success_after_failed_logins"})


if __name__ == "__main__":
    unittest.main()

