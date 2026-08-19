import unittest

from defensive_security_lab.path_guard import canonicalize_package_name, classify_filenames, validate_filename


class PathGuardTests(unittest.TestCase):
    def test_allows_expected_filename(self):
        self.assertEqual(validate_filename("report.vtt"), "report.vtt")

    def test_rejects_traversal_and_nested_paths(self):
        for value in ("../payload.mp4", "nested/file.log", r"nested\file.log", "/tmp/report.txt"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_filename(value)

    def test_rejects_hidden_and_unlisted_extensions(self):
        for value in (".hidden.md", "payload.exe", "report"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_filename(value)

    def test_classifies_fixture(self):
        result = classify_filenames(["report.vtt", "../payload.mp4"])
        self.assertEqual(result, {"allowed": ["report.vtt"], "rejected": ["../payload.mp4"]})

    def test_canonicalizes_equivalent_package_names(self):
        values = {canonicalize_package_name(value) for value in ("Example_Pkg", "example.pkg", "example-pkg")}
        self.assertEqual(values, {"example-pkg"})


if __name__ == "__main__":
    unittest.main()

