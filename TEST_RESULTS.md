# Test results

## Local verification — 2026-08-20

Environment: Python 3.14.6 on macOS, standard library only.

```bash
python3 -m unittest discover -s tests -v
```

Result: **124 tests executed, 124 passed.** No test reaches an external network
target, and no test starts a vulnerable application: the capture and the
challenge matrix from the local training range are replayed from fixtures.

| Test module | Cases | Covers |
|---|---:|---|
| `test_ioc_matcher.py` | 18 | boundary matching, defang normalisation, CIDR containment, hash typing, allowlist, indicator-file validation |
| `test_sigma_rules.py` | 19 | rule hygiene, YAML-subset parsing, conditions, timeframes, aggregation, field modifiers |
| `test_incident_timeline.py` | 16 | sliding window, window boundary, success reset, password spray, event validation |
| `test_path_guard.py` | 12 | 32-entry traversal corpus plus targeted boundary assertions |
| `test_web_assessment.py` | 26 | CSP parsing and weaknesses, HSTS, cookies, CORS, disclosure, capture replay |
| `test_challenge_evidence.py` | 18 | loopback enforcement, secret rejection, schema, completion-requires-instance-confirmation |
| `test_local_header_audit.py` | 9 | loopback acceptance, external rejection, DNS verification, hijack simulation |

## Regression coverage for the three defects found by testing

Each defect was reproduced first, then fixed, then pinned:

| Defect | Reproduction | Regression test |
|---|---|---|
| **A1** `ioc_matcher` matched substrings: `1.2.3.4` reported present in `11.2.3.45`, `evil.com` in `notevil.com.br` | both strings ran through the old matcher | `SubstringRegressionTests` (5 cases) |
| **A2** `failed_login_burst` counted lifetime totals: three failures spread across a year were reported as a burst | events dated 2025-01-01, 2025-06-01, 2026-01-01 | `BurstWindowTests` (5 cases, including the exact window boundary and one second past it) |
| **A3** the failure counter survived a success, so `fail, fail, success, fail, success` re-fired on stale history | that exact sequence | `SuccessResetTests` (3 cases) |

## Boundary hardening verified by test

`require_loopback_url` previously accepted the literal hostname `localhost`
without resolving it. The verification host turned out to be a good argument for
fixing that: its resolver answers `invalid.invalid` with `198.18.0.149` rather
than failing, so a name that should not exist resolves to a routable address.
`test_a_hijacked_localhost_is_refused` substitutes a resolver that answers
`localhost` the same way and asserts the URL is refused;
`test_name_only_check_would_have_passed_the_hijack` shows the contrast.

## Static checks

ruff is invoked through `uvx` at a pinned version. A bare `ruff` command is not
assumed to resolve: on the verification machine it is installed under
`~/.local/bin`, which is not on `PATH` in every shell, so the pinned form is the
reproducible one.

```bash
uvx --from ruff==0.15.14 ruff check .          # All checks passed!
uvx --from ruff==0.15.14 ruff format --check . # 12 files already formatted
python3 -m compileall -q defensive_security_lab tests   # OK
```

Lint configuration lives in `pyproject.toml`: line length 100, rule sets
`E, F, W, I, UP, B, C4, SIM`.

## CLI verification

```bash
python3 -m defensive_security_lab all
python3 -m defensive_security_lab sigma
python3 -m defensive_security_lab explain report.vtt ../payload.mp4 CON.txt
```

The `explain` output reproduces the documented lab exercise exactly:
`report.vtt` allowed; `../payload.mp4` rejected as `path_separator`; `CON.txt`
rejected as `reserved_device_name`.

`sigma` evaluates the three bundled rules against `fixtures/auth_events.jsonl`:
the burst rule matches `lab-user` only, the spray rule matches nothing (correct
— that fixture has no spraying), and the exclusion rule selects the six failures
originating outside the internal range.

## Continuous integration

`.github/workflows/tests.yml` runs three jobs: unit tests across Python 3.10,
3.12 and 3.13; `ruff check` and `ruff format --check`; and a CLI smoke job that
executes the bundled analyses, the filename triage, and the Sigma evaluation.

### Historical record

The first public workflow run, before this revision:

- Workflow `tests`, commit `e7384b06492e9a62f7aa10279d6f1463d79512fa`
- Result `success`
- https://github.com/sxfish389-sketch/defensive-security-lab/actions/runs/32292234555

The revision described above has **not** yet been pushed, so no CI run covers it
at the time of writing.
