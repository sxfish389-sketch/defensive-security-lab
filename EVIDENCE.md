# Evidence index

Status vocabulary:

- `VERIFIED`: present in this repository and reproducible locally.
- `PENDING`: requires a real external event or applicant-supplied record.
- `NOT CLAIMED`: deliberately excluded because no supporting evidence exists.

| Evidence | Status | Location |
|---|---|---|
| Localhost-only authorization boundary | VERIFIED | `AUTHORIZATION.md`, `local_header_audit.py` |
| Path-boundary regression tests | VERIFIED | `tests/test_path_guard.py` |
| Synthetic IOC matching | VERIFIED | `tests/test_ioc_matcher.py`, `fixtures/iocs.json` |
| Incident timeline analysis | VERIFIED | `tests/test_incident_timeline.py` |
| Security-header review | VERIFIED | `tests/test_local_header_audit.py` |
| Unified defensive CLI | VERIFIED | `defensive_security_lab/__main__.py` |
| CTF/lab write-up | VERIFIED | `evidence/06_ctf_lab.md` |
| Independent GitHub Actions test run | VERIFIED | `actions/runs/32292234555` |
| Actual Claude block and log ID | PENDING | `BLOCKED_REQUESTS.md` |
| Course or certification | PENDING | Applicant must add a real verification URL |
| CVE/GHSA reporter credit | NOT CLAIMED | No such claim is made |
| Security employment | NOT CLAIMED | No such claim is made |

## Reproduction commands

```bash
python3 -m unittest discover -s tests -v
python3 -m defensive_security_lab all
```
