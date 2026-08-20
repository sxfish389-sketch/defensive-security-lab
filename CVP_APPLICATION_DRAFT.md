# CVP application draft — forward-looking, evidence-bounded

Every answer uses only material that exists in this repository under the account
`sxfish389-sketch`. No third-party CVE, GHSA, identity, certification,
employment, or approval record appears anywhere in this document.

## Eligibility position

Anthropic's published guidance reads:

> "If your use case has a legitimate defensive purpose and is being affected by
> these safeguards, we encourage you to apply for the CVP."

That is a conditional encouragement, not a stated gate, and the block-description
field on the form is explicitly marked *optional*. Anthropic has not said that a
prior security background or a recorded block is required; both add evidentiary
weight, and neither is a prerequisite. Approval is not guaranteed either way.

- **Legitimate defensive purpose — satisfied.**
- **Currently affected by the safeguards — yes, once, observed in the interface.**
  On 2026-08-20 a request to continue the localhost-only authorized OWASP Juice
  Shop review was flagged by the cyber safeguards and the session was downgraded
  from Opus 5 to Opus 4.8; the task then continued. It was a flag and downgrade,
  not a full block, and no log ID was shown. See `BLOCKED_REQUESTS.md`.

## Field: How are you accessing Claude?

`PENDING` — answer truthfully for the account actually in use.

## Field: Organization ID / Account email

`PENDING` — the real Org ID and email. Approval binds to one Organization ID and
does not carry to another. Confirm the organization is not on Zero Data
Retention; ZDR organizations are not currently eligible.

## Field: Use-case categories

Three, all traceable to artifacts (full reasoning in `FORM_EVIDENCE_MAP.md`):

- [x] **CTF / Lab / Research Environment**
- [x] **Security Tool Development**
- [x] **Authorized Penetration Testing / Red Teaming** — *only* as an explicitly
      authorized local training assessment against OWASP Juice Shop (four
      challenges across Injection, Broken Access Control, XSS); not professional
      pentesting, not a client engagement
- [ ] Threat Intelligence & Malware Analysis — indicators are synthetic; no sample handled
- [ ] Incident Response & Forensics — no real incident handled
- [ ] Vulnerability Research & Disclosure — nothing disclosed

## Field: What is a typical cyber-related task you would use Claude for?

> The field is phrased conditionally ("would use"), so a forward-looking answer
> is what it asks for.

I maintain a defensive lab whose targets are loopback addresses, reserved
documentation ranges, and fixtures I write, plus a local OWASP Juice Shop
instance I run for training. I would use Claude to review and harden my detection
logic against what I actually observe. Concrete examples from this week: my
indicator matcher tested `indicator in text`, so it reported `1.2.3.4` as present
in the unrelated string `11.2.3.45`; my authentication triage counted failures
with no time window, so three failures spread across a year registered as a
burst, and it never reset after a successful login; and my security-header
analyzer had no CORS check at all until a baseline capture from the local
training range came back with `Access-Control-Allow-Origin: *` on every endpoint.
Each of those became a fix plus regression tests, and where the pattern was
generalisable, a Sigma rule validated against synthetic fixtures.

## Field: Help us verify your work

- Repository: https://github.com/sxfish389-sketch/defensive-security-lab
- GitHub profile: https://github.com/sxfish389-sketch
- CI run on commit `e7384b0`, conclusion `success`:
  https://github.com/sxfish389-sketch/defensive-security-lab/actions/runs/32292234555

The repository contains eight defensive modules, 124 passing unit tests, a
standard-library Sigma subset evaluator with three rules validated against
fixtures, a security-header analyzer covering CSP directives, HSTS, cookies and
CORS, a 32-entry filename-traversal corpus, a threat model that names its own
limits, and an authorization boundary enforced in code and hardened to verify DNS
rather than trust a hostname. `LAB_JUICE_SHOP_REPORT.md` documents a bounded
assessment of a deliberately vulnerable application run locally, including the
one-line patch needed because the upstream project binds all interfaces by
default, and three independent verifications that it was reachable only on
loopback. `LAB_CHALLENGE_MATRIX.md` records four training challenges completed
against that instance across three vulnerability classes, each with the upstream
root cause and a written remediation, and validated in code to hold no secrets.

This account and repository were created on 2026-08-19 while preparing this
application. It is my own work and it is the only public work I have. I claim no
CVE, GHSA, employer, client engagement, certification, or credit for research
published by anyone else, and no observation in the Juice Shop report is a
discovery — all are published training scenarios.

## Field: Describe the types of requests that triggered a cyber block *(optional)*

On 2026-08-20, a request to continue a localhost-only authorized OWASP Juice Shop
training review (local instance on 127.0.0.1 only, no third-party target) was
flagged by the cyber safeguards in my Claude Code session and the model was
downgraded from Opus 5 to Opus 4.8; the task then continued on the downgraded
model. This is an interface-visible observation with no log ID shown, not a full
block.

## Field: Anything else you would like us to know? *(optional)*

All work is confined to loopback targets, reserved documentation ranges, the
`.test` namespace, fixtures I wrote, and a local training-range instance I start
and stop myself. `AUTHORIZED_SCOPE.md` records the boundary, including the
explicit rule that third-party deployments — such as the project's own public
demo, which its README says is not for hacking — are never touched.
`THREAT_MODEL.md` records what the lab does not cover.

## Security-requirement fields

- MFA on every account that can reach the Console or mint API credentials —
  answer `Yes` only after actually enabling it.
- API keys in a secrets manager or password locker, never committed — answer
  `Yes` only if already true.

## Honest forecast

Rejection is still a realistic outcome, and that is stated plainly. The work is
now genuinely defensible — real detection logic, three self-found defects fixed,
and an authorized local assessment that completed four training challenges across
Injection, Broken Access Control, and XSS with root causes and remediations. But
it is days old, lives entirely on infrastructure I control, and is training-level
rather than the professional practice the safeguards are calibrated around. I am
describing it as exactly that, and no more.

`TECHNICAL_GAPS.md` §F lists what remains, in order of value — chiefly one
evidence anchor on a site I do not control.
