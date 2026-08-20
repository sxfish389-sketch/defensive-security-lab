import json
import unittest
from pathlib import Path

from defensive_security_lab.ioc_matcher import (
    hash_type,
    load_indicators,
    match_text,
    normalize_defanged,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SHA256 = "0" * 62 + "42"


class IOCCorpusTests(unittest.TestCase):
    """Drive the matcher from the recorded positive/negative corpus."""

    @classmethod
    def setUpClass(cls):
        cls.indicators = load_indicators(FIXTURES / "iocs.json")
        cls.corpus = json.loads((FIXTURES / "ioc_corpus.json").read_text(encoding="utf-8"))

    def test_corpus_covers_both_outcomes(self):
        hits = [c for c in self.corpus if any(c["expect"].values())]
        misses = [c for c in self.corpus if not any(c["expect"].values())]
        self.assertGreaterEqual(len(hits), 5)
        self.assertGreaterEqual(len(misses), 5)

    def test_every_corpus_case_matches(self):
        for case in self.corpus:
            with self.subTest(case=case["name"]):
                self.assertEqual(match_text(case["text"], self.indicators), case["expect"])


class SubstringRegressionTests(unittest.TestCase):
    """Regressions for defect A1: ``indicator in text`` produced false positives."""

    def setUp(self):
        self.indicators = {
            "domains": ["evil.com"],
            "ips": ["1.2.3.4"],
            "hashes": [],
            "allowlist": [],
        }

    def test_ip_is_not_matched_inside_a_longer_address(self):
        self.assertEqual(match_text("connection to 11.2.3.45 observed", self.indicators)["ips"], [])

    def test_ip_is_matched_when_it_stands_alone(self):
        self.assertEqual(
            match_text("connection to 1.2.3.4 observed", self.indicators)["ips"], ["1.2.3.4"]
        )

    def test_domain_is_not_matched_with_a_prefix(self):
        self.assertEqual(match_text("visited notevil.com today", self.indicators)["domains"], [])

    def test_domain_is_not_matched_with_a_suffix(self):
        self.assertEqual(match_text("visited evil.com.br today", self.indicators)["domains"], [])

    def test_domain_is_matched_at_boundaries(self):
        for text in ("visited evil.com today", "http://evil.com/path", "(evil.com)"):
            with self.subTest(text=text):
                self.assertEqual(match_text(text, self.indicators)["domains"], ["evil.com"])


class DefangTests(unittest.TestCase):
    def test_normalizes_common_conventions(self):
        self.assertEqual(normalize_defanged("evil[.]com"), "evil.com")
        self.assertEqual(normalize_defanged("evil(dot)com"), "evil.com")
        self.assertEqual(normalize_defanged("hxxp://a"), "http://a")
        self.assertEqual(normalize_defanged("hxxps://a"), "https://a")
        self.assertEqual(normalize_defanged("user[at]evil.com"), "user@evil.com")

    def test_defanging_can_be_disabled(self):
        indicators = {"domains": ["evil.com"], "ips": [], "hashes": [], "allowlist": []}
        self.assertEqual(match_text("evil[.]com", indicators, defang=False)["domains"], [])


class CIDRTests(unittest.TestCase):
    def setUp(self):
        self.indicators = {
            "domains": [],
            "ips": ["198.51.100.0/24"],
            "hashes": [],
            "allowlist": [],
        }

    def test_address_inside_range_matches(self):
        for address in ("198.51.100.1", "198.51.100.9", "198.51.100.255"):
            with self.subTest(address=address):
                result = match_text(f"seen {address} inbound", self.indicators)
                self.assertEqual(result["ips"], ["198.51.100.0/24"])

    def test_address_outside_range_does_not_match(self):
        for address in ("198.51.101.9", "203.0.113.9"):
            with self.subTest(address=address):
                self.assertEqual(match_text(f"seen {address}", self.indicators)["ips"], [])


class HashTests(unittest.TestCase):
    def test_infers_algorithm_from_length(self):
        self.assertEqual(hash_type("d" * 32), "md5")
        self.assertEqual(hash_type("d" * 40), "sha1")
        self.assertEqual(hash_type("d" * 64), "sha256")

    def test_rejects_unknown_lengths_and_alphabets(self):
        self.assertIsNone(hash_type("d" * 31))
        self.assertIsNone(hash_type("z" * 32))
        self.assertIsNone(hash_type(""))

    def test_hash_must_stand_alone(self):
        indicators = {"domains": [], "ips": [], "hashes": [SHA256], "allowlist": []}
        self.assertEqual(match_text(f"sample {SHA256} seen", indicators)["hashes"], [SHA256])
        self.assertEqual(match_text(f"id ff{SHA256}ff", indicators)["hashes"], [])


class AllowlistTests(unittest.TestCase):
    def test_allowlisted_indicator_is_suppressed(self):
        indicators = {
            "domains": ["evil.com"],
            "ips": ["1.2.3.4"],
            "hashes": [],
            "allowlist": ["evil.com"],
        }
        result = match_text("evil.com contacted 1.2.3.4", indicators)
        self.assertEqual(result["domains"], [])
        self.assertEqual(result["ips"], ["1.2.3.4"])


class IndicatorFileValidationTests(unittest.TestCase):
    def test_bundled_indicator_file_loads(self):
        indicators = load_indicators(FIXTURES / "iocs.json")
        self.assertIn("malware.test", indicators["domains"])
        self.assertIn("198.51.100.0/24", indicators["ips"])

    def test_malformed_hash_is_rejected(self):
        path = FIXTURES / "iocs.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["hashes"] = ["not-a-hash"]
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(data, handle)
            temporary = handle.name
        with self.assertRaises(ValueError):
            load_indicators(temporary)

    def test_missing_category_is_rejected(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump({"domains": [], "ips": []}, handle)
            temporary = handle.name
        with self.assertRaises(ValueError):
            load_indicators(temporary)


if __name__ == "__main__":
    unittest.main()
