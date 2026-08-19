# Defensive Security Evidence Lab

A small, reproducible defensive-security portfolio maintained by
[`sxfish389-sketch`](https://github.com/sxfish389-sketch). The project uses only
localhost targets, reserved example addresses, synthetic logs, and deliberately
constructed fixtures.

The repository demonstrates six common defensive-security workflows without
claiming a CVE, professional certification, employer, client engagement, or
third-party discovery credit.

## Safety scope

- No Internet targets are scanned.
- The web-audit command rejects non-loopback hosts.
- All indicators and authentication events are synthetic.
- Path-traversal examples operate on strings and temporary fixtures only.
- Results are intended for learning, regression testing, and defensive review.

See [AUTHORIZATION.md](AUTHORIZATION.md) and [ETHICS.md](ETHICS.md) before using
the project.

## Demonstrated workflows

| Area | Reproducible artifact |
|---|---|
| Authorized testing | Localhost-only HTTP security-header audit |
| Vulnerability research | CWE-22-style filename boundary regression tests |
| Threat analysis | Synthetic IOC matching using reserved indicators |
| Incident response | Timeline and failed-login burst analysis |
| Security tool development | Standard-library Python CLI with unit tests |
| CTF / lab research | Safe filename-triage challenge and documented solution |

## Run locally

Python 3.10 or newer is recommended. The project has no third-party runtime
dependencies.

```bash
python3 -m unittest discover -s tests -v
python3 -m defensive_security_lab all
```

Individual commands:

```bash
python3 -m defensive_security_lab path report.vtt ../payload.mp4
python3 -m defensive_security_lab ioc fixtures/iocs.json fixtures/auth_events.jsonl
python3 -m defensive_security_lab incident fixtures/auth_events.jsonl
python3 -m defensive_security_lab headers --fixture fixtures/http_headers.json
```

## Evidence status

The code, fixtures, tests, and reports in this repository are reproducible
portfolio evidence. Items that depend on an external event—such as an actual
Claude safeguard block, a course certificate, or an independent disclosure—are
explicitly marked `PENDING` in [EVIDENCE.md](EVIDENCE.md).

This repository is not proof of CVP eligibility by itself and does not guarantee
approval. Any application should describe only work actually performed and
understood by the applicant.

The latest local verification record is in [TEST_RESULTS.md](TEST_RESULTS.md).

