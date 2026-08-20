# Technical gaps — what is actually missing, concretely

> **Status after the second phase (2026-08-19).** Sections A1–A3, B1 (partly),
> B3, B4, C (detection rules and threat model), and the Juice Shop item in C
> are **done**. See `TEST_RESULTS.md` and `LAB_JUICE_SHOP_REPORT.md`. What
> remains open is listed in §F at the end of this file.

This file answers one question: *what real technical work would make this
repository substantive?* It deliberately does not say "get a job" or "obtain a
CVE". Everything below can be done by the maintainer alone, on targets that are
legal to test, without impersonating anyone.

Current size: 190 lines of module code, 96 lines of tests.

---

## A. Defects confirmed in the existing code

These were reproduced by running the code, not inferred by reading it. Fixing
them is the cheapest available improvement because the finding, the fix, and the
regression test are all genuinely the maintainer's own work.

### A1. `ioc_matcher.match_text` produces substring false positives

`match_text` uses `value in haystack`, which matches across token boundaries.

```
indicators = {"ips": ["1.2.3.4"], "domains": ["evil.com"]}
match_text("connection to 11.2.3.45 observed", indicators)   → ips: ["1.2.3.4"]      # wrong
match_text("visited notevil.com.br today",     indicators)   → domains: ["evil.com"] # wrong
```

An indicator matcher that fires on unrelated hosts is worse than none. Fix by
tokenizing, or by matching on word/label boundaries, and add both strings above
as regression tests.

### A2. `incident_timeline.analyze_events` has no time window

`failed_login_burst` counts failures for the lifetime of the log. Three failures
spread across a full year are reported as a burst:

```
2025-01-01, 2025-06-01, 2026-01-01  (same user, same IP)  → failed_login_burst
```

A burst is a rate, not a total. Add a sliding window (for example, N failures
within M minutes) and make the window a parameter.

### A3. The failure counter never resets after a success

`failures[key]` is never cleared when a success occurs, so every later success
re-triggers `success_after_failed_logins` on stale history:

```
fail, fail, success, fail, success  → success_after_failed_logins fires on the
                                      second success, on a single new failure
```

Reset or age out the counter after a successful authentication.

---

## B. Making each module non-trivial

Each item is real detection-engineering work with a testable outcome.

### B1. `ioc_matcher.py` (19 lines of logic)

- Normalize defanged indicators: `hxxp://`, `[.]`, `(dot)`, `[at]`.
- Match IPs by CIDR containment, not string equality, so `203.0.113.0/24`
  covers the whole range.
- Infer hash type from length (32 / 40 / 64 hex → MD5 / SHA-1 / SHA-256) and
  reject malformed values instead of silently accepting them.
- Ingest a standard format — MISP JSON or STIX 2.1 — rather than a bespoke
  three-key file.
- Support an allowlist so known-good infrastructure suppresses matches.

### B2. `incident_timeline.py` (49 lines of logic)

- Sliding windows and per-principal baselines instead of global totals.
- Detect additional patterns: password spraying (one password, many users),
  credential stuffing (many users, one source), impossible travel if the fixture
  carries geo data.
- Emit findings in a documented schema (OCSF or ECS) so output is consumable by
  something other than this CLI.

### B3. `local_header_audit.py` (40 lines of logic)

Presence/absence of four header names is the shallowest possible check.

- Parse the CSP and flag weak directives: `unsafe-inline`, `unsafe-eval`,
  wildcard sources, `data:` in `script-src`.
- Validate HSTS properly: `max-age` threshold, `includeSubDomains`, `preload`.
- Audit cookie attributes: `Secure`, `HttpOnly`, `SameSite`.

### B4. `path_guard.py` (32 lines of logic)

The logic is correct but the corpus is five strings. Build a real traversal
corpus and prove the validator against all of it:

- percent-encoded `%2e%2e%2f` and double-encoded `%252e%252e%252f`
- UTF-8 overlong encodings
- backslash and mixed separators
- null-byte truncation `report.vtt\x00.exe`
- Windows reserved device names (`CON`, `NUL`, `LPT1`)
- trailing dots and spaces, alternate data streams (`file.txt:hidden`)

Consider property-based testing (`hypothesis`) so the validator is exercised
against generated input rather than a hand-written list.

---

## C. Artifact types absent entirely

A defensive portfolio that contains only ad-hoc Python is narrow. Missing:

- **Detection rules** — Sigma rules for the authentication patterns in B2, YARA
  rules for file triage. These are the standard currency of defensive work and
  are portable evidence of understanding.
- **A written threat model** — what this lab defends against, what it assumes,
  what it explicitly does not cover.
- **Benchmarking against deliberately vulnerable software.** OWASP Juice Shop,
  DVWA, and WebGoat are published expressly for security training; running them
  in a local container and testing against them is authorized by the software's
  own purpose and licence. This is the single highest-value addition, because:
  1. it moves *Authorized Testing* from unsupported to genuinely supportable;
  2. it is real dual-use work rather than string validation; and
  3. it is the kind of work that may legitimately encounter safeguards — and in
     fact did: on 2026-08-20 a request to continue this authorized local review
     was flagged and downgraded Opus 5 → Opus 4.8 (task continued), producing the
     optional block-field evidence honestly, as a by-product of real work rather
     than anything manufactured for the form. See `BLOCKED_REQUESTS.md`.

---

## D. Repository-level signals

- **Sustained history.** Three commits inside 93 minutes is a single session.
  Weeks of genuine commits carry weight that no single push does.
- **External interaction.** Zero stars, forks, issues, contributors. Publishing
  the Sigma rules or the traversal corpus somewhere useful invites the first
  real outside signal.
- **A second identity anchor.** Everything currently lives on infrastructure the
  maintainer controls. One artifact on a site the maintainer cannot edit — a CTF
  platform profile with a solve history, an accepted VDP report, a merged
  security fix in someone else's repository — changes the verification picture
  more than any amount of additional code here.

---

## E. Honest ordering

If the goal is a credible application rather than a fast one:

1. Fix A1–A3 and add their regression tests. (hours)
2. Build the traversal corpus in B4. (hours)
3. Write Sigma rules for B2's patterns. (a day)
4. Stand up Juice Shop or DVWA locally and work against it, documenting
   findings and remediation. (weeks, and the most valuable item here)
5. Let commit history accumulate as a side effect of 1–4.
6. Pursue one external anchor from D.

Steps 1–3 make the repository defensible on its own terms. Step 4 is what moves
the application from "a learning project" to "work that plausibly needs the
CVP". It also, in phase 3, produced one honest optional-block-field observation
(an interface flag and model downgrade), recorded in `BLOCKED_REQUESTS.md`.

---

## F. Still open after the second phase

1. **Done in phase 3.** Four 2–3 star challenges across Injection, Broken Access
   Control, and XSS were completed with root cause and remediation
   (`LAB_CHALLENGE_MATRIX.md`), which made *Authorized Penetration Testing*
   selectable as a local training assessment. Sending that phase-3 task also
   produced one real interface safeguard flag and an Opus 5 → Opus 4.8 downgrade
   (`BLOCKED_REQUESTS.md`) — not provoked, not a full block. What is still absent
   is the *professional* form of this — a scoped engagement against a system
   owned by someone else who authorized it, which cannot be self-manufactured.
2. **The Score Board challenge remains unfinished.** The hidden route was found
   in `main.js` but the solve never registered (fragment routing, headless
   client). Not counted as completed anywhere.
3. **IOC matcher still IPv4-only**, and still ingests a bespoke JSON shape
   rather than MISP or STIX 2.1.
4. **No YARA rules**, because no YARA engine is available on this host to
   validate them against fixtures.
5. **No external anchor.** Everything still lives on infrastructure the
   maintainer controls. One artifact on a site the maintainer cannot edit — a
   CTF platform profile, an accepted VDP report, a merged security fix in
   someone else's repository — remains the single highest-value addition.
6. **Sustained history.** Two working sessions on one day is not a track record.
