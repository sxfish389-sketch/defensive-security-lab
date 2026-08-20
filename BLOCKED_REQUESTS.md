# Safeguard event record

One real, interface-visible safeguard event has occurred. It was a **flag and a
model downgrade, not a full block** — the task continued on the downgraded model.
It is recorded here exactly as observed, with its limits stated. It is the
applicant's own interface observation: there is no server-issued log ID, no
screenshot, and no email, and none is invented here.

## Event 1 — cyber safeguard flag with model downgrade

| Field | Value |
|---|---|
| Observation time | 2026-08-20 15:45 JST (06:45 UTC) — the time the interface message was seen and recorded, not a claimed server timestamp |
| Surface | Claude Desktop, Code session |
| Model transition | Opus 5 → Opus 4.8 (automatic downgrade) |
| Outcome | Message flagged; task **continued** on Opus 4.8. Not a full refusal. |
| Triggering task | A request to continue an explicitly authorized local security assessment: completing official OWASP Juice Shop training challenges on a local instance bound to `127.0.0.1:3000` only, with third-party instances, demo sites, DoS, RCE, SSRF, network egress, and destructive deletion all forbidden by the instruction. |
| Interface message (verbatim) | "Opus 5's safeguards flagged this message. Our intentionally broad safeguards allow us to deliver more capabilities faster, but can sometimes flag legitimate coding, cybersecurity, and biology tasks. Switched to Opus 4.8. Details: [cyber]" |
| Log / request ID | Not shown by the interface. None is claimed. |
| Defensive purpose | Authorized local training assessment of a deliberately vulnerable application, run by the operator on their own machine, to learn vulnerability classes and their remediations. |
| Authorization boundary | Local instance only, `127.0.0.1`; no third-party target; see `AUTHORIZED_SCOPE.md`. |

### How to characterise this, and how not to

- **Accurate:** a localhost-only, explicitly-authorized OWASP Juice Shop training
  review was flagged by the cyber safeguards and the session was downgraded from
  Opus 5 to Opus 4.8. The work then continued.
- **Not accurate:** a full block or refusal (it was not — the task completed on
  Opus 4.8); an event with a captured request ID (none was shown); any suggestion
  that this guarantees or influences a CVP decision.
- **Verifiability:** this is interface-visible and self-reportable. A reviewer
  cannot pull a log ID from it, but the applicant can re-observe the same
  behaviour in the same interface. It is offered on that basis, not as
  server-side proof.

## Guidance for any future event

Record only the minimum necessary evidence: observation time and timezone,
surface and model, a masked summary of the request, the exact interface text, a
log/request ID **only if the interface actually shows one**, the defensive
purpose, and the authorization boundary.

Do not intentionally provoke a flag or block, invent a log ID or request ID,
fabricate a screenshot or email, or include passwords, tokens, private paths,
customer data, or live indicators.
