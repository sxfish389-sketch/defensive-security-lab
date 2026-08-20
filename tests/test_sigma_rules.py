import unittest
from pathlib import Path

from defensive_security_lab.incident_timeline import load_events
from defensive_security_lab.sigma import (
    SigmaError,
    evaluate,
    load_rule_text,
    load_rules,
    parse_condition,
    parse_timeframe,
)

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "sigma"
FIXTURES = ROOT / "fixtures"


class RuleHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules(RULES)

    def test_all_bundled_rules_parse(self):
        self.assertGreaterEqual(len(self.rules), 3)

    def test_rules_carry_required_metadata(self):
        for rule in self.rules:
            with self.subTest(rule=rule["title"]):
                for field in ("title", "id", "description", "logsource", "detection", "level"):
                    self.assertIn(field, rule)
                self.assertIn(rule["level"], {"low", "medium", "high", "critical"})

    def test_rule_ids_are_unique(self):
        ids = [rule["id"] for rule in self.rules]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_rule_documents_false_positives(self):
        for rule in self.rules:
            with self.subTest(rule=rule["title"]):
                self.assertTrue(rule.get("falsepositives"))

    def test_every_condition_is_supported(self):
        for rule in self.rules:
            with self.subTest(rule=rule["title"]):
                parse_condition(rule["detection"]["condition"])


class ParserTests(unittest.TestCase):
    def test_parses_nested_maps_lists_and_block_scalars(self):
        rule = load_rule_text(
            "title: Example\n"
            "id: abc\n"
            "description: >\n"
            "    first line\n"
            "    second line\n"
            "logsource:\n"
            "    product: lab\n"
            "detection:\n"
            "    selection:\n"
            "        result: failure\n"
            "    condition: selection\n"
            "tags:\n"
            "    - one\n"
            "    - two\n"
            "level: low\n"
        )
        self.assertEqual(rule["description"], "first line second line")
        self.assertEqual(rule["logsource"], {"product": "lab"})
        self.assertEqual(rule["tags"], ["one", "two"])
        self.assertEqual(rule["detection"]["selection"], {"result": "failure"})

    def test_ignores_comments(self):
        rule = load_rule_text("# leading\ntitle: X  # trailing\nlevel: low\n")
        self.assertEqual(rule["title"], "X")

    def test_rejects_unsupported_condition(self):
        with self.assertRaises(SigmaError):
            parse_condition("selection | avg(x) by y > 1")

    def test_timeframe_units(self):
        self.assertEqual(parse_timeframe("30s").total_seconds(), 30)
        self.assertEqual(parse_timeframe("5m").total_seconds(), 300)
        self.assertEqual(parse_timeframe("2h").total_seconds(), 7200)
        self.assertIsNone(parse_timeframe(None))
        with self.assertRaises(SigmaError):
            parse_timeframe("5 minutes")


class BurstRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rule = next(
            rule
            for rule in load_rules(RULES)
            if rule["id"] == "6f1c2a94-3b57-4d18-9e02-5a7c81de44b1"
        )
        cls.events = load_events(FIXTURES / "auth_events.jsonl")

    def test_fires_on_the_burst_account(self):
        matches = evaluate(self.rule, self.events)
        self.assertEqual([match["group"] for match in matches], ["lab-user"])
        self.assertGreaterEqual(matches[0]["observed"], 3)

    def test_does_not_fire_on_the_slow_account(self):
        groups = {match["group"] for match in evaluate(self.rule, self.events)}
        self.assertNotIn("slow-user", groups)

    def test_agrees_with_the_module_detection(self):
        from defensive_security_lab.incident_timeline import analyze_events

        module_users = {
            finding["user"]
            for finding in analyze_events(self.events)
            if finding["type"] == "failed_login_burst"
        }
        rule_users = {match["group"] for match in evaluate(self.rule, self.events)}
        self.assertEqual(module_users, rule_users)


class SprayRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rule = next(
            rule
            for rule in load_rules(RULES)
            if rule["id"] == "b28d4f70-91ac-4e63-8f15-2c0d7e6b3a58"
        )

    def test_fires_on_the_spray_fixture(self):
        events = load_events(FIXTURES / "auth_events_spray.jsonl")
        matches = evaluate(self.rule, events)
        self.assertEqual([match["group"] for match in matches], ["198.51.100.9"])
        self.assertEqual(matches[0]["observed"], 4)

    def test_does_not_fire_on_the_single_account_fixture(self):
        events = load_events(FIXTURES / "auth_events.jsonl")
        self.assertEqual(evaluate(self.rule, events), [])


class ExclusionRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rule = next(
            rule
            for rule in load_rules(RULES)
            if rule["id"] == "3a5e8c11-7d64-42b9-b0f3-9e1a6c25d7f4"
        )

    def test_selects_only_external_failures(self):
        events = load_events(FIXTURES / "auth_events.jsonl")
        matches = evaluate(self.rule, events)
        self.assertTrue(matches)
        for match in matches:
            self.assertEqual(match["event"]["result"], "failure")
            self.assertFalse(match["event"]["source_ip"].startswith("192.0.2."))

    def test_excludes_the_internal_range(self):
        events = [
            {
                "timestamp": "2026-08-20T00:00:00Z",
                "user": "u",
                "source_ip": "192.0.2.5",
                "result": "failure",
            }
        ]
        self.assertEqual(evaluate(self.rule, events), [])


class FieldModifierTests(unittest.TestCase):
    def _rule(self, selection_body, condition="selection"):
        return load_rule_text(
            "title: T\nid: i\ndescription: d\nlogsource:\n    product: lab\n"
            "detection:\n"
            f"{selection_body}"
            f"    condition: {condition}\n"
            "falsepositives:\n    - none\n"
            "level: low\n"
        )

    def test_contains_modifier(self):
        rule = self._rule("    selection:\n        note|contains: spray\n")
        events = [{"note": "synthetic spray attempt"}, {"note": "ordinary"}]
        self.assertEqual(len(evaluate(rule, events)), 1)

    def test_list_values_are_or(self):
        rule = self._rule(
            "    selection:\n        result:\n            - failure\n            - locked\n"
        )
        events = [{"result": "failure"}, {"result": "locked"}, {"result": "success"}]
        self.assertEqual(len(evaluate(rule, events)), 2)

    def test_missing_field_does_not_match(self):
        rule = self._rule("    selection:\n        absent: x\n")
        self.assertEqual(evaluate(rule, [{"present": "x"}]), [])


if __name__ == "__main__":
    unittest.main()
