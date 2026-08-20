# Authorized testing

**Supports the CVP category "Authorized Penetration Testing / Red Teaming":
modestly, as an explicitly authorized local training assessment.**

Two things live under this heading, and they must not be conflated.

1. **A boundary control.** `local_header_audit.require_loopback_url` rejects every
   target that is not loopback, resolving hostnames rather than trusting them
   (`tests/test_local_header_audit.py`). This is the discipline of authorized
   testing — a scope enforced in code.

2. **Actual training-level testing.** Phase 3 completed four official OWASP Juice
   Shop challenges on a local, authorized instance, across Injection, Broken
   Access Control, and XSS, each with the upstream root cause located and a
   remediation written (`LAB_CHALLENGE_MATRIX.md`, `fixtures/challenge_matrix.json`).
   Records are validated in code (`challenge_evidence.py`) to contain no secrets
   and no non-loopback target.

What this is **not**: a professional penetration test, a red-team engagement, or
a client project. Every target was a deliberately vulnerable application the
maintainer ran locally for training, and every challenge is a published exercise
with an official description. The claim on the form carries that qualifier
explicitly. See `AUTHORIZED_SCOPE.md`.
