import unittest

from defensive_security_lab.ioc_matcher import match_text


class IOCMatcherTests(unittest.TestCase):
    def test_matches_synthetic_indicators_case_insensitively(self):
        indicators = {
            "domains": ["malware.test"],
            "ips": ["203.0.113.42"],
            "hashes": ["00000042"],
        }
        result = match_text("Connection to MALWARE.TEST from 203.0.113.42", indicators)
        self.assertEqual(result["domains"], ["malware.test"])
        self.assertEqual(result["ips"], ["203.0.113.42"])
        self.assertEqual(result["hashes"], [])


if __name__ == "__main__":
    unittest.main()

