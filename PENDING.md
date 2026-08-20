# PENDING items

Consolidated list of everything that is not yet real. Nothing here may be
answered by writing a better sentence; each requires an actual event.

## Corrected status of the block requirement

An earlier revision of this file listed a safeguard block as mandatory. That
overstated the rule and is corrected here.

Anthropic's published wording is: *"If your use case has a legitimate defensive
purpose and is being affected by these safeguards, we encourage you to apply."*
That is a conditional encouragement, not a stated gate, and the corresponding
form field is explicitly marked **optional**. Several public applicants report
approval on the strength of background alone — own CVEs, OSCP, CTFtime history,
accepted HackerOne reports — without citing a block.

The accurate reading: a prior security background and a real block record each
add evidentiary weight, and both point at the same underlying question — whether
the applicant does work of the kind the safeguards act on. **Anthropic has not
said that either one is required.** An application may be made on a
forward-looking description of genuine current work, and approval is never
guaranteed with or without them.

Everything below is therefore about strengthening evidence, not about clearing a
gate. No item here is a stated prerequisite.

## STRONGLY NEEDED

### 1. Evidence of work in the high-risk dual-use zone

**Status:** partially present now, and one safeguard event has actually occurred.

The synthetic parts of this repository are loopback-only string validation and
would not, on their own, trip a safeguard. But phase 3 completed four authorized
OWASP Juice Shop training challenges across Injection, Broken Access Control, and
XSS with root cause and remediation (`LAB_CHALLENGE_MATRIX.md`) — dual-use-shaped
work, at training level.

**A real safeguard event was observed.** On 2026-08-20, a request to continue
that localhost-only authorized review was flagged by the cyber safeguards in the
Claude Code interface and the session was downgraded Opus 5 → Opus 4.8; the task
then continued. This was **not** deliberately provoked and is **not** a full
block. It is interface-visible and self-reportable, with no log ID
(`BLOCKED_REQUESTS.md`).

What is still missing is not "any safeguard contact" — that has happened — but
the *professional* form of this work: a scoped engagement against a system the
applicant does not own, which cannot be self-manufactured, plus item 2 below.

Do **not** manufacture a block. Constructing a request designed to trip a
safeguard so it can be cited is fabricating evidence, and such a request does not
represent real work anyway. The event above is usable precisely because it arose
from genuine authorized work, not from an attempt to provoke it.

If a further event occurs during ordinary defensive work, record in
`BLOCKED_REQUESTS.md`:

- a masked summary of the request (no secrets, no private paths);
- the exact interface text;
- observation time and timezone, surface, and model transition;
- the log or request ID **only if the interface actually shows one**;
- the repository file or command the request related to;
- why the request was legitimate defensive work.

### 2. Evidence of security work that predates the application

**Status:** does not exist. Account and repository are one day old, 1 public
repo, 0 followers, no other public activity.

A repository created while preparing an application is honest work but not a
track record. Options, roughly in ascending order of effort:

- CTF platform profiles under this identity with a real solve history
  (picoCTF, HackTheBox, TryHackMe, CTFtime team page);
- accepted reports on HackerOne or Bugcrowd, including VDP-only programs;
- merged security-relevant contributions to real open-source projects, where
  the commit history is on someone else's repository and cannot be self-issued;
- a certification with a public verification URL (Credly or equivalent);
- a LinkedIn profile consistent with the same identity.

At least one item should live on a site the applicant does not control. A
self-hosted repository verifies only that the applicant can create a repository.

## SHOULD HAVE

### 3. Independent interaction with the repository

**Status:** 0 stars, 0 forks, 0 issues, 0 external contributors.

Not required, but the difference between "code exists" and "code was used by
someone" is exactly the difference a reviewer is looking for.

### 4. Sustained commit history

**Status:** 3 commits within 93 minutes, then two further working sessions on
the same day. Nothing pushed since the first three.

Continued genuine work over weeks is worth more than any single-session push.
This accrues by working, not by backdating or padding commits.

## COMPLETED

### Removed `canonicalize_package_name()` from `path_guard.py`

**Status:** done.

The function implemented PEP 503 package-name canonicalization inside a module
documented as filename handling, and its subject matter traced to third-party
research reviewed while preparing this application. No authorship was ever
claimed, so it was not misrepresentation — but it was an unexplained artifact
with someone else's origin.

The function and its test are gone. `path_guard.py` was rewritten around a
single coherent policy, and the suite grew from 10 tests to 68. A grep for
`canonicalize`, `PyPI`, `jupyterlab`, and every third-party handle now returns
nothing outside the explicit "not claimed" statements in this file and in
`FORM_EVIDENCE_MAP.md`.

### Fixed the three defects found by testing

`ioc_matcher` substring false positives, the missing burst time window, and the
failure counter that survived a success. Each was reproduced first, then fixed,
then pinned by regressions. See `TEST_RESULTS.md`.

## NEVER

Recorded so the boundary stays explicit:

- inventing a log ID, block record, or Claude conversation;
- claiming a CVE, GHSA, or advisory reported by anyone else;
- claiming an employer, client, co-founder title, or certification not held;
- uploading another person's research to this account and presenting it as this
  applicant's;
- describing synthetic fixtures as a real production incident;
- selecting use-case categories the repository does not support in order to
  improve perceived odds.

## Current recommendation

An application may be filed — nothing bars it, and the optional block field can
now honestly carry one real, interface-visible safeguard event (flag + Opus
5→4.8 downgrade, no log ID). But on current evidence rejection is still more
likely than approval, so filing now spends the 7-day window for little.

The cheapest thing that would change the picture is `TECHNICAL_GAPS.md` §F
item 1 (exploitation rather than reconnaissance, which also makes a third
category selectable) followed by §F item 5 (one artifact on infrastructure the
applicant does not control).
