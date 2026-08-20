# Authorized scope

This file defines the only targets this project may be pointed at. It is a
commitment, not a disclaimer, and one part of it is enforced in code rather than
left to good intentions.

## Permitted targets

| Target class | Examples | Why it is permitted |
|---|---|---|
| Loopback interfaces | `127.0.0.0/8`, `::1`, `localhost` | Cannot leave the operator's machine |
| Reserved documentation ranges | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737 reserves these; they route nowhere |
| Reserved test namespace | any name ending `.test` | RFC 6761 reserves it; it resolves nowhere |
| Synthetic fixtures | everything under `fixtures/` | Written by the maintainer for this repository |
| Local strings | filenames validated in memory | Never written to disk outside a temporary test area |

## Enforcement, not just policy

The target boundary is checked in code before any request is issued:

```python
# defensive_security_lab/local_header_audit.py
def fetch_and_audit(url: str, timeout: float = 3.0) -> dict[str, list[str]]:
    require_loopback_url(url)   # raises for anything that is not loopback
    ...
```

`require_loopback_url` rejects every scheme other than HTTP(S), every hostname
that is neither `localhost` nor a loopback address, and anything that does not
parse as a complete URL. `tests/test_local_header_audit.py` pins both the
accepting and the rejecting cases.

## Prohibited without separate written authorization

- Any host on the public Internet.
- Any third-party account, API, or service.
- Any employer, client, or customer system.
- Any network the operator does not own or control.
- Any system belonging to another person, including one that appears to invite
  testing.

Nothing in this repository is authorization to test anything. A permissive
licence on the code is not permission to point it at someone else's system.

## Completed expansion: OWASP Juice Shop, 2026-08-19

This phase has been carried out once. Full record in
[LAB_JUICE_SHOP_REPORT.md](LAB_JUICE_SHOP_REPORT.md).

| Item | Value |
|---|---|
| Software | OWASP Juice Shop 20.2.0, MIT, commit `1618a611b173b4bf114028e6e02549950606e29d` |
| Basis | published expressly as an insecure application for trainings, CTFs, and as a guinea pig for security tools |
| Bound to | `127.0.0.1:3000` only, verified by `lsof`, `netstat`, and a failed connection from the host's own LAN address — re-verified at the start of phase 3 |
| Challenges | four official training challenges completed (Injection, Broken Access Control, XSS); see `LAB_CHALLENGE_MATRIX.md` |
| Phase 2 requests | ~19 read-only `GET`s across 8 endpoints, no credentials, no modification |
| Phase 3 requests | logged individually; two synthetic accounts and challenge payloads against the disposable instance, per the phase-3 authorization |
| Stopped | yes — no listener, no process, connection refused afterwards |

**A required deviation:** upstream calls `server.listen(port, …)` with no host,
which makes Node bind `0.0.0.0`, and no configuration option changes it. A
one-line local patch was applied before first start and is recorded at
`.lab_runtime/loopback_bind.patch`. Anyone repeating this must do the same, or
the deliberately vulnerable application is exposed to their whole network.

No container runtime is available on this host, so isolation came from the
loopback binding and from keeping the runtime under `.lab_runtime/`, outside
this repository. That is weaker than a container and is stated rather than
glossed over.

## Limits that apply to this and any future vulnerable-app work

1. The application runs on the operator's own machine, bound to loopback only,
   never exposed to a LAN or the Internet — verified, not assumed.
2. It runs in a container or virtual machine where one is available; where none
   is, that reduction in isolation is recorded explicitly.
3. No traffic leaves the host. Nothing is scanned that was not started by the
   operator on that host.
4. Findings are recorded against the local instance and its version, and are
   never described as a discovery affecting a real deployment.
5. No third party's copy of that software is touched, including public demo
   instances, which are somebody else's servers regardless of the software's
   purpose.
6. If a genuine, previously unknown flaw in the upstream project is found,
   active testing stops and the project's own security policy or a coordinated
   disclosure process is followed — it is not published here first.

## If something real is discovered

Stop testing, preserve the minimum evidence needed to reproduce, do not widen
access, and follow the affected project's disclosure process. Do not post the
detail publicly before the maintainers have had a reasonable chance to respond.

## Reporting a problem in this repository

See `SECURITY.md`. Reproductions must use reserved addresses and synthetic
content; live indicators, real logs, and credentials are not accepted.
