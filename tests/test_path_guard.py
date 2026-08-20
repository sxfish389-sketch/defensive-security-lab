import json
import unittest
from pathlib import Path

from defensive_security_lab.path_guard import (
    ALLOWED_EXTENSIONS,
    FilenameRejected,
    classify_filenames,
    explain,
    validate_filename,
)

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "traversal_corpus.json"


class PathGuardCorpusTests(unittest.TestCase):
    """Drive the validator from the recorded traversal corpus."""

    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text(encoding="utf-8"))

    def test_corpus_is_not_trivially_one_sided(self):
        verdicts = {entry["expected_verdict"] for entry in self.corpus}
        self.assertEqual(verdicts, {"allowed", "rejected"})
        self.assertGreaterEqual(len(self.corpus), 30)

    def test_every_corpus_entry_matches_its_recorded_verdict(self):
        for entry in self.corpus:
            with self.subTest(name=entry["name"], group=entry["group"]):
                result = explain(entry["name"])
                self.assertEqual(result["verdict"], entry["expected_verdict"])
                self.assertEqual(result["reason"], entry["expected_reason"])


class PathGuardBoundaryTests(unittest.TestCase):
    def test_allows_each_permitted_extension(self):
        for extension in sorted(ALLOWED_EXTENSIONS):
            with self.subTest(extension=extension):
                self.assertEqual(validate_filename(f"report{extension}"), f"report{extension}")

    def test_rejects_separators_and_absolute_paths(self):
        for value in ("../payload.mp4", "nested/file.log", r"nested\file.log", "/tmp/report.txt"):
            with self.subTest(value=value):
                with self.assertRaises(FilenameRejected) as ctx:
                    validate_filename(value)
                self.assertEqual(ctx.exception.reason, "path_separator")

    def test_rejects_single_and_double_percent_encoding(self):
        for value in ("..%2fpayload.txt", "%252e%252e%252fboot.txt", "%2E%2E/report.txt"):
            with self.subTest(value=value):
                with self.assertRaises(FilenameRejected) as ctx:
                    validate_filename(value)
                self.assertEqual(ctx.exception.reason, "percent_encoded")

    def test_rejects_null_byte_and_control_characters(self):
        with self.assertRaises(FilenameRejected) as nul:
            validate_filename("report.vtt\x00.exe")
        self.assertEqual(nul.exception.reason, "nul_byte")
        with self.assertRaises(FilenameRejected) as ctrl:
            validate_filename("report\x07.txt")
        self.assertEqual(ctrl.exception.reason, "control_character")

    def test_rejects_windows_reserved_device_names(self):
        for value in ("CON.txt", "con", "nul.log", "com1.txt", "LPT9.md"):
            with self.subTest(value=value):
                with self.assertRaises(FilenameRejected) as ctx:
                    validate_filename(value)
                self.assertEqual(ctx.exception.reason, "reserved_device_name")

    def test_reserved_name_check_does_not_match_a_mere_prefix(self):
        """``console.txt`` starts with ``con`` but is a perfectly ordinary name."""

        self.assertEqual(validate_filename("console.txt"), "console.txt")

    def test_rejects_alternate_data_stream_separator(self):
        with self.assertRaises(FilenameRejected) as ctx:
            validate_filename("file.txt:hidden")
        self.assertEqual(ctx.exception.reason, "alternate_data_stream")

    def test_rejects_trailing_dots_and_spaces(self):
        for value in ("report.txt ", "report.txt.", "report.txt.."):
            with self.subTest(value=value):
                with self.assertRaises(FilenameRejected) as ctx:
                    validate_filename(value)
                self.assertEqual(ctx.exception.reason, "trailing_dot_or_space")

    def test_rejects_empty_and_non_string_input(self):
        for value in ("", None, 42):
            with self.subTest(value=value):
                with self.assertRaises(FilenameRejected) as ctx:
                    validate_filename(value)
                self.assertEqual(ctx.exception.reason, "empty")

    def test_classify_splits_allowed_and_rejected(self):
        result = classify_filenames(["report.vtt", "../payload.mp4", "console.txt"])
        self.assertEqual(result["allowed"], ["report.vtt", "console.txt"])
        self.assertEqual(result["rejected"], ["../payload.mp4"])


if __name__ == "__main__":
    unittest.main()
