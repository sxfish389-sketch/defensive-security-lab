# Evidence index

Status vocabulary:

- `VERIFIED`: present in this repository and reproducible locally by a third party.
- `PENDING`: requires a real external event or an applicant-supplied record that
  does not yet exist.
- `NOT CLAIMED`: deliberately excluded because no supporting evidence exists.

## Provenance (disclosed deliberately)

A reviewer reads these dates straight from the GitHub API, so they are stated
here rather than left to be discovered.

| Fact | Value |
|---|---|
| GitHub account `sxfish389-sketch` created | 2026-08-19T17:42:10Z |
| Repository created | 2026-08-19T19:14:21Z |
| Public repositories on the account | 1 |
| Followers / stars / forks / external contributors | 0 / 0 / 0 / 0 |
| Prior public activity by this account | None |

This repository was created while preparing a CVP application. It is new work,
not a record of prior security practice, and it is not presented as one.

## What is in the repository

| Evidence | Status | Location |
|---|---|---|
| Loopback boundary enforced in code before any request | VERIFIED | `local_header_audit.py:20`, `AUTHORIZED_SCOPE.md` |
| Filename policy with machine-readable rejection reasons | VERIFIED | `path_guard.py`, `tests/test_path_guard.py` |
| 32-entry traversal corpus: encoding, platform quirks, control bytes | VERIFIED | `fixtures/traversal_corpus.json` |
| Boundary-anchored indicator matching | VERIFIED | `ioc_matcher.py`, `tests/test_ioc_matcher.py` |
| 12-entry indicator corpus with positive and negative cases | VERIFIED | `fixtures/ioc_corpus.json` |
| Sliding-window authentication triage and spray detection | VERIFIED | `incident_timeline.py`, `tests/test_incident_timeline.py` |
| Three Sigma rules, evaluated against fixtures by tests | VERIFIED | `rules/sigma/`, `tests/test_sigma_rules.py` |
| Standard-library Sigma subset loader and evaluator | VERIFIED | `sigma.py` |
| Threat model naming its own limits | VERIFIED | `THREAT_MODEL.md` |
| Security-header analyzer: CSP directives, HSTS, cookies, CORS, disclosure | VERIFIED | `web_assessment.py`, `tests/test_web_assessment.py` |
| Loopback boundary hardened with DNS verification, hijack simulated in test | VERIFIED | `local_header_audit.py`, `test_a_hijacked_localhost_is_refused` |
| Authorized local assessment of OWASP Juice Shop 20.2.0 | VERIFIED | `LAB_JUICE_SHOP_REPORT.md`, `fixtures/juice_shop_baseline.json` |
| Four training challenges completed across 3 classes, confirmed by the instance API | VERIFIED | `LAB_CHALLENGE_MATRIX.md`, `fixtures/challenge_matrix.json` |
| Challenge-evidence validator: refuses non-loopback targets and stored secrets | VERIFIED | `challenge_evidence.py`, `tests/test_challenge_evidence.py` |
| 124 passing unit tests, clean `ruff check` and `ruff format` | VERIFIED | `TEST_RESULTS.md` |
| Historical CI run on commit `e7384b0`, conclusion `success` | VERIFIED | `actions/runs/32292234555` |
| CI run covering the current revision | PENDING | not yet pushed |
| Interface-visible cyber safeguard flag + Opus 5→4.8 downgrade (no log ID) | VERIFIED (self-reported, re-observable) | `BLOCKED_REQUESTS.md` |
| Course or certification | PENDING | applicant must add a real verification URL |
| Independent third-party review of this code | PENDING | no issues, PRs, forks or stars exist |
| YARA rules | NOT CLAIMED | no YARA engine available here, so rules could not be executed against fixtures; shipping unverifiable rules would contradict the point of this repository |
| CVE/GHSA reporter credit | NOT CLAIMED | no such claim is made |
| Security employment or client engagement | NOT CLAIMED | no such claim is made |
| Bug-bounty platform history | NOT CLAIMED | no such account is claimed |

## Defects found and fixed within this repository

These are the clearest genuinely-own artefacts here: the finding, the fix, and
the regression test are all the maintainer's work.

| Defect | Symptom reproduced | Fix | Regression |
|---|---|---|---|
| A1 | `1.2.3.4` matched inside `11.2.3.45`; `evil.com` inside `notevil.com.br` | token and label boundary anchoring | `SubstringRegressionTests` |
| A2 | three failures across a year reported as a burst | sliding window with tested boundary | `BurstWindowTests` |
| A3 | failure counter survived a success and re-fired | success closes the episode | `SuccessResetTests` |

## What this repository does not establish

1. **Not a history of security work.** The account and repository are one day
   old. Reproducibility is not a track record.
2. **Not independently validated.** CI proves the tests pass on a clean runner.
   It does not prove anyone else has reviewed or relied on this code.
3. **One interface-visible safeguard event, not a full block.** On 2026-08-20 a
   request to continue the localhost-only authorized Juice Shop review was
   flagged and the session was downgraded Opus 5 → Opus 4.8; the task continued.
   There is no log ID, so this is self-reported and re-observable rather than
   server-verifiable. It is not a full block and not an approval signal. See
   `BLOCKED_REQUESTS.md`.
4. **Not six independent competencies.** Seven modules exist; the CLI and the lab
   write-up are presentations of them, not additional capabilities.
5. **Not professional penetration testing.** Phase 3 completed four *training*
   challenges across three classes on a local, authorized instance, with root
   causes and remediations. That supports the CVP category only as an explicitly
   authorized local training assessment — not a client engagement or red team.
   See `FORM_EVIDENCE_MAP.md`.
6. **Not a discovery about Juice Shop.** Every observation in
   `LAB_JUICE_SHOP_REPORT.md` is a published training scenario with an official
   description.

## Reproduction

```bash
python3 -m unittest discover -s tests -v
python3 -m defensive_security_lab all
python3 -m defensive_security_lab sigma
uvx --from ruff==0.15.14 ruff check .
uvx --from ruff==0.15.14 ruff format --check .
```
