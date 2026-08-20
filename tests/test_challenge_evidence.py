import json
import unittest
from pathlib import Path

from defensive_security_lab.challenge_evidence import (
    EvidenceError,
    completed_categories,
    validate_matrix,
    validate_record,
)

MATRIX = Path(__file__).resolve().parents[1] / "fixtures" / "challenge_matrix.json"


def base_record():
    return {
        "name": "Example",
        "official_category": "Injection",
        "difficulty_stars": 2,
        "authorization_basis": "local training instance",
        "timestamp": "2026-08-19T20:52Z",
        "target_url": "http://127.0.0.1:3000/rest/user/login",
        "method": "POST",
        "request_summary": "masked payload",
        "response_status": 200,
        "instance_solved_state": "true",
        "root_cause_location": "routes/login.ts:34",
        "remediation": "Use a parameterised query so input is bound, not concatenated.",
        "genuinely_completed": True,
    }


class BundledMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = json.loads(MATRIX.read_text(encoding="utf-8"))

    def test_bundled_matrix_validates(self):
        validate_matrix(self.records)

    def test_matrix_covers_three_categories(self):
        categories = completed_categories(self.records)
        self.assertTrue({"Injection", "Broken Access Control", "XSS"}.issubset(categories))

    def test_every_completed_record_is_confirmed_by_the_instance(self):
        for record in self.records:
            if record["genuinely_completed"]:
                self.assertIn(str(record["instance_solved_state"]).lower(), {"true", "solved"})

    def test_no_record_contains_a_raw_payload(self):
        # Teaching payloads are masked; the raw iframe/SQL text must not appear.
        blob = json.dumps(self.records).lower()
        self.assertNotIn("javascript:", blob)
        self.assertNotIn("or 1=1", blob)


class LoopbackEnforcementTests(unittest.TestCase):
    def test_rejects_non_loopback_target(self):
        for host in (
            "http://demo.owasp-juice.shop/x",
            "http://192.168.1.5:3000/x",
            "http://10.0.0.1/x",
        ):
            record = base_record()
            record["target_url"] = host
            with self.subTest(host=host), self.assertRaises(EvidenceError):
                validate_record(record)

    def test_rejects_hostname_even_localhost(self):
        record = base_record()
        record["target_url"] = "http://localhost:3000/x"
        with self.assertRaises(EvidenceError):
            validate_record(record)

    def test_accepts_ipv6_loopback(self):
        record = base_record()
        record["target_url"] = "http://[::1]:3000/x"
        validate_record(record)


class SecretRejectionTests(unittest.TestCase):
    def test_rejects_forbidden_key(self):
        for key in ("authorization", "token", "password", "cookie", "jwt"):
            record = base_record()
            record[key] = "anything"
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                validate_record(record)

    def test_rejects_forbidden_key_when_nested(self):
        record = base_record()
        record["extra"] = {"details": {"Authorization": "Bearer abc"}}
        with self.assertRaises(EvidenceError):
            validate_record(record)

    def test_rejects_jwt_shaped_value(self):
        record = base_record()
        record["request_summary"] = "captured eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig12345 here"
        with self.assertRaises(EvidenceError):
            validate_record(record)

    def test_rejects_bearer_token_value(self):
        record = base_record()
        record["request_summary"] = "sent header bearer aab2cd3ef4gh5.ij6kl7mn.op8qr9"
        with self.assertRaises(EvidenceError):
            validate_record(record)

    def test_allows_the_plain_english_word_bearer(self):
        # "bearer" as prose must not be a false positive.
        record = base_record()
        record["request_summary"] = "the session bearer was held in memory only"
        validate_record(record)


class SchemaTests(unittest.TestCase):
    def test_requires_all_fields(self):
        for field in list(base_record().keys()):
            record = base_record()
            del record[field]
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                validate_record(record)

    def test_remediation_must_be_substantive(self):
        record = base_record()
        record["remediation"] = "fix it"
        with self.assertRaises(EvidenceError):
            validate_record(record)

    def test_cannot_claim_completion_without_instance_confirmation(self):
        record = base_record()
        record["genuinely_completed"] = True
        record["instance_solved_state"] = "false"
        with self.assertRaises(EvidenceError):
            validate_record(record)

    def test_observation_without_completion_is_allowed(self):
        record = base_record()
        record["genuinely_completed"] = False
        record["instance_solved_state"] = "false"
        validate_record(record)

    def test_difficulty_bounds(self):
        for bad in (0, 7, "2", 2.5):
            record = base_record()
            record["difficulty_stars"] = bad
            with self.subTest(bad=bad), self.assertRaises(EvidenceError):
                validate_record(record)

    def test_clean_record_passes(self):
        self.assertEqual(validate_record(base_record())["name"], "Example")


if __name__ == "__main__":
    unittest.main()
