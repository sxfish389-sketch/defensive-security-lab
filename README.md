# Defensive Security Evidence Lab

[![tests](https://github.com/sxfish389-sketch/defensive-security-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/sxfish389-sketch/defensive-security-lab/actions/workflows/tests.yml)

A reproducible defensive-security lab maintained by
[`sxfish389-sketch`](https://github.com/sxfish389-sketch). Every target is a
loopback address, a reserved documentation range, or a fixture written for this
repository. There are no third-party runtime dependencies.

## What is implemented

| Module | What it does |
|---|---|
| `path_guard.py` | Validates a filename against a traversal, encoding, platform-quirk and extension policy; returns a machine-readable rejection reason |
| `ioc_matcher.py` | Boundary-anchored indicator matching with defang normalisation, CIDR containment, hash typing, and allowlist suppression |
| `incident_timeline.py` | Sliding-window authentication triage: failure bursts, success-after-failures, password spraying |
| `local_header_audit.py` | Reviews response security headers, rejecting any target that is not loopback |
| `sigma.py` | A strict Sigma-subset loader and evaluator, written against the standard library so rules stay executable without PyYAML |
| `web_assessment.py` | Security-header review with real depth: CSP directive weaknesses, HSTS lifetime, cookie attributes, permissive CORS, and stack disclosure |
| `challenge_evidence.py` | Schema and validator for local training-challenge evidence: refuses non-loopback targets, secrets, or records missing remediation |

Detection rules live in [`rules/sigma/`](rules/sigma) and are evaluated against
fixtures by the test suite, not merely shipped as text.

## Three defects this lab found in itself

Each was reproduced before it was fixed, and each is now pinned by regressions:

1. **Indicator false positives.** `indicator in text` reported `1.2.3.4` as
   present in `11.2.3.45`, and `evil.com` in `notevil.com.br`. Matching is now
   anchored on token and label boundaries.
2. **A burst with no time window.** Three failures spread across a year were
   reported as a burst. A burst is a rate, so failures are now counted inside a
   sliding window whose boundary is tested explicitly.
3. **A counter that survived success.** The failure list was never cleared after
   a successful login, so a later single failure re-fired the alert on stale
   history. A success now closes the episode.

## Safety scope

- No Internet target is ever contacted; `require_loopback_url` enforces this in
  code before any request is issued.
- All indicators, authentication events and filenames are synthetic.
- No malware sample is executed, unpacked or stored.

Read [AUTHORIZED_SCOPE.md](AUTHORIZED_SCOPE.md) and
[THREAT_MODEL.md](THREAT_MODEL.md) before using the project. Nothing here is
authorization to test anything you do not own.

## Run locally

Python 3.10 or newer.

```bash
python3 -m unittest discover -s tests -v
python3 -m defensive_security_lab all
```

Individual commands:

```bash
python3 -m defensive_security_lab explain report.vtt ../payload.mp4 CON.txt
python3 -m defensive_security_lab ioc fixtures/iocs.json fixtures/auth_events.jsonl
python3 -m defensive_security_lab incident fixtures/auth_events_spray.jsonl
python3 -m defensive_security_lab headers --fixture fixtures/http_headers.json
python3 -m defensive_security_lab sigma
python3 -m defensive_security_lab assess --capture fixtures/juice_shop_baseline.json
python3 -m defensive_security_lab challenges
```

### Local training-range assessment

`LAB_JUICE_SHOP_REPORT.md` records a bounded assessment of a local OWASP Juice
Shop instance — a deliberately vulnerable application published for security
training. It documents the authorization basis, a one-line patch that was
required because the upstream project binds `0.0.0.0` with no supported way to
change it, three independent verifications that the service was reachable only
on loopback, and exactly what was and was not achieved.

`LAB_CHALLENGE_MATRIX.md` records four official training challenges completed
against that instance across three vulnerability classes (Injection, Broken
Access Control, XSS), each with the upstream root cause and a written
remediation. Payloads are masked and the records are validated in code to contain
no secrets and no non-loopback target.

Neither the third-party source nor its dependencies are committed here.

Static checks. ruff is a development tool only, and it is deliberately invoked
through `uvx` at a pinned version so the commands work without ruff being
installed or on `PATH`:

```bash
uvx --from ruff==0.15.14 ruff check .
```

```bash
uvx --from ruff==0.15.14 ruff format --check .
```

If you already have that exact version installed and on `PATH`, plain
`ruff check .` is equivalent — but do not assume it resolves.

## Reproducibility

124 unit tests pass locally; see [TEST_RESULTS.md](TEST_RESULTS.md). The same
suite, lint, formatting, and CLI smoke checks run in public GitHub Actions across
Python 3.10, 3.12, and 3.13:

- [workflow history and current status](https://github.com/sxfish389-sketch/defensive-security-lab/actions/workflows/tests.yml)
- [full code/test revision](https://github.com/sxfish389-sketch/defensive-security-lab/actions/runs/32342424625)
