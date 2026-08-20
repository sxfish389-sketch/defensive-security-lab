# Form field → repository evidence map

Every claim intended for the CVP form is traced to a file, test, or run. A claim
with no row here has no evidence and must not be made.

## Use-case categories

| Category | Artifact | Supported? | Select |
|---|---|---|---|
| **CTF / Lab / Research Environment** | the whole repository plus `LAB_JUICE_SHOP_REPORT.md` and `LAB_CHALLENGE_MATRIX.md`: synthetic fixtures, a loopback-bounded design, a traversal corpus, and four completed local training challenges | **Yes.** An accurate description of what this is. | ✅ |
| **Security Tool Development** | 7 library modules plus a CLI, 124 tests, a Sigma subset evaluator, a security-header analyzer, a challenge-evidence validator, three self-found defects with regressions, CI across three Python versions plus lint and CLI smoke jobs | **Yes, modestly.** Small but genuine. | ✅ |
| **Authorized Penetration Testing / Red Teaming** | `LAB_CHALLENGE_MATRIX.md`, `LAB_JUICE_SHOP_REPORT.md` §8-13, `challenge_evidence.py` | **Modestly — as an explicitly authorized local training assessment.** See below. | ✅* |
| Threat Intelligence & Malware Analysis | `ioc_matcher.py` — defang normalisation, CIDR containment, hash typing, allowlist | **No.** Real indicator tooling, but every indicator is synthetic and no sample, feed, or telemetry has been handled. | ❌ |
| Incident Response & Forensics | `incident_timeline.py`, three Sigma rules | **No.** Better detection logic, still zero real incidents. | ❌ |
| Vulnerability Research & Disclosure | the three defects found in this code | **No.** Finding bugs in one's own small project is not vulnerability research, and nothing has been disclosed. | ❌ |

### Authorized Testing — now modestly supported, with an explicit qualifier

The threshold set for this box was: at least three 2–3 star challenges across
distinct classes, each with root cause and remediation. Phase 3 met it —

| Challenge | Class | ★ | Root cause located | Remediation written | Instance solved |
|---|---|---:|:---:|:---:|:---:|
| Login Admin | Injection | 2 | yes | yes | true |
| View Basket | Broken Access Control | 2 | yes | yes | true |
| Admin Section | Broken Access Control | 2 | yes | yes | true |
| API-only XSS | XSS | 3 | yes | yes | true |

— four completed across three classes (Injection, Broken Access Control, XSS),
each confirmed by the instance's own solved flag, each with the upstream source
line and a concrete fix.

**The `*` is load-bearing.** On the form this must be described as *"modestly
supported by an explicitly authorized local training assessment against OWASP
Juice Shop"* — **not** as professional penetration testing or red teaming, and
**not** as a client engagement. A reviewer opening the evidence will find
completed training challenges with masked payloads and written remediations; if
the form claimed more than that, the same reviewer would find the gap. The claim
and the evidence must say the same thing: authorized, local, training-level.

**Change from the previous revision:** the count moved from two supportable
categories to three, on the strength of the phase-3 challenge matrix. The
qualifier keeps the third from overstating.

## Verification fields

| Form claim | Evidence | Independently checkable? |
|---|---|---|
| Public repository, the applicant's own | https://github.com/sxfish389-sketch/defensive-security-lab | Yes |
| 124 tests pass locally | `TEST_RESULTS.md` | Yes |
| Clean lint and formatting | `uvx --from ruff==0.15.14 ruff check .` | Yes |
| Full code/test revision passes on a clean runner | run `32342424625` on commit `8d290e1` | Yes — success across unit tests, lint, formatting and CLI smoke jobs |
| Three defects found, fixed, and pinned | `SubstringRegressionTests`, `BurstWindowTests`, `SuccessResetTests` | Yes |
| Sigma rules that actually evaluate | `tests/test_sigma_rules.py` | Yes |
| A local authorized assessment was performed | `LAB_JUICE_SHOP_REPORT.md`, `fixtures/juice_shop_baseline.json` | Partly — the report and capture are checkable; the session itself was local and is not independently observable |
| Account age and history | GitHub API: created 2026-08-19, 1 repo, 0 followers | Yes — and the reviewer will see it |
| Safeguard event affecting legitimate work | interface flag + Opus 5→4.8 downgrade on 2026-08-20, task continued | **Self-reported, re-observable; no log ID** (`BLOCKED_REQUESTS.md`) |
| CVE / GHSA credit, employer, certification | none | Not claimed |

## Claims forbidden in this application

- any CVE or GHSA identifier, or reporter credit for one;
- any third-party researcher's name, handle, or advisory;
- any employer, title, company page, or client engagement;
- any certification, course completion, or bug-bounty history;
- any Claude conversation, log ID, or block record that did not occur;
- any suggestion that a Juice Shop observation is a discovery. Every scenario in
  `LAB_JUICE_SHOP_REPORT.md` is a published training exercise with an official
  description, and the report says so.

The package-name canonicalisation logic carried over from third-party research
was removed in the previous revision, along with its test. Nothing in the
current code traces to another person's work.
