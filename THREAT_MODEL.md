# Threat model

This document states what the lab defends, what it assumes, and — more usefully
— what it does not cover. A threat model that only lists strengths is marketing.

## Scope of the model

The modelled system is the lab itself: four defensive checks, their fixtures,
and the CLI that runs them. It is not a model of any production system, and no
production system is in scope.

## Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Output directory integrity | The filename validator exists to keep caller-supplied names from escaping an intended output directory | `path_guard.py` |
| Target boundary | The header audit must never reach a host outside loopback, whatever it is asked | `local_header_audit.py` |
| Detection fidelity | A matcher that fires on unrelated infrastructure erodes trust in every later alert | `ioc_matcher.py`, `incident_timeline.py` |
| Rule correctness | A detection rule that silently misparses is worse than one that refuses to load | `sigma.py`, `rules/sigma/` |
| Isolation of the training range | A deliberately vulnerable application must never be reachable off this host | `AUTHORIZED_SCOPE.md`, `.lab_runtime/loopback_bind.patch` |

## Trust boundaries

1. **Caller → validator.** Every filename, indicator file, event file, and URL
   entering the library is untrusted. Each is validated before use; malformed
   input raises rather than being coerced.
2. **Library → network.** Exactly one function reaches the network,
   `local_header_audit.fetch_and_audit`, and it calls `require_loopback_url`
   first. The boundary is enforced in code, not by convention or documentation.
3. **Rule file → evaluator.** Rules are data, not code. The loader supports a
   deliberately narrow subset and raises `SigmaError` on anything else, so an
   unsupported construct cannot be silently reinterpreted.

## Threats considered, and how they are addressed

| Threat | Treatment | Evidence |
|---|---|---|
| Directory traversal via `../` | Separators, absolute paths, and non-bare names rejected | `tests/test_path_guard.py` |
| Traversal hidden behind encoding | Percent-encoded and double-encoded input rejected outright | corpus group *percent and double encoding* |
| Platform-specific filename tricks | Reserved device names, alternate data streams, trailing dots and spaces rejected | corpus groups for each |
| Truncation via NUL or control bytes | Rejected before any other interpretation | `test_rejects_null_byte_and_control_characters` |
| Indicator false positives | Boundary-anchored matching; regressions pinned for the exact defects found | `SubstringRegressionTests` |
| Alert fatigue from stale counters | Sliding window; success closes the episode | `BurstWindowTests`, `SuccessResetTests` |
| Accidental scanning of a third party | Loopback enforced in code before any request is issued | `test_rejects_external_targets` |
| Silent rule misparse | Strict subset loader that raises on unsupported syntax | `ParserTests` |
| Resolver answering `localhost` with a routable address | Every resolved address must be loopback; a hostile resolver is simulated in test | `test_a_hijacked_localhost_is_refused` |
| A vulnerable training app exposed to the LAN | Upstream binds `0.0.0.0`; patched to `127.0.0.1` and verified three ways before any request, re-verified in phase 3 | `LAB_JUICE_SHOP_REPORT.md` §2, §8 |
| A secret or off-scope target leaking into evidence | Challenge records are validated in code to reject non-loopback URLs, `Authorization`/`token`/`password`/`cookie` fields, and JWT/bearer-shaped strings | `challenge_evidence.py`, `tests/test_challenge_evidence.py` |
| A security header that exists but does nothing | CSP directives, HSTS lifetime, and cookie attributes are inspected rather than counted | `tests/test_web_assessment.py` |

## Explicitly out of scope

Stated so no reader infers coverage that does not exist:

- **No authentication, authorisation, or multi-user model.** The lab is a
  single-user local tool.
- **No cryptography.** Hashes are matched as identifiers, never verified.
- **No protection of the host.** The lab assumes the machine running it is
  already trusted; it is not a sandbox. When a deliberately vulnerable
  application is run locally, the only isolation is the loopback binding and a
  runtime directory outside this repository — no container was available.
- **No malware handling.** No sample is executed, unpacked, or stored.
- **No production log ingestion.** All events are synthetic fixtures written by
  the maintainer.
- **No adversary who can edit this repository.** An attacker with commit access
  can disable any check here; that is outside the model.
- **No performance or denial-of-service properties.** Inputs are assumed small.

## Assumptions

1. Fixtures are synthetic and contain no real indicator, credential, or host.
2. Reserved ranges (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`) and the
   `.test` namespace are used precisely because they can never route to a real
   third party.
3. The validators are libraries, not a security boundary for hostile callers in
   the same process; a caller that bypasses them is out of scope.

## Known limitations

- `path_guard` enforces one policy, not a general-purpose sanitiser. It rejects
  far more than a real application might need to.
- `ioc_matcher` matches IPv4 only; IPv6 indicators are not handled.
- `incident_timeline` has no notion of user baselines, so a genuinely busy
  service account will look like a burst.
- `sigma.py` implements a small subset of Sigma. It is sufficient for the
  bundled rules and will refuse rules that need more.
- No YARA rules are included. Without a YARA engine available in this
  environment they could not be executed against fixtures, and shipping
  unverifiable rules would contradict the point of this repository.
