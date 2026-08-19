# Test results

## Local verification — 2026-08-20

Environment: Python standard library on macOS.

Command:

```bash
python3 -m unittest discover -s tests -v
```

Result:

- 10 tests executed.
- 10 tests passed.
- No test accesses an external network target.

Covered boundaries:

- traversal, nested-path, hidden-name, and extension rejection;
- equivalent package-name canonicalization;
- synthetic IOC matching;
- failed-login burst and success-after-failures detection;
- loopback URL acceptance and external-target rejection; and
- missing HTTP security-header reporting.

GitHub Actions is configured to repeat the unit-test command after publication.

