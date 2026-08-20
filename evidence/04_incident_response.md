# Authentication triage

**Supports the CVP category "Incident Response & Forensics": no.**

`incident_timeline.py` validates and orders JSONL authentication events and
reports three detections: failure bursts inside a sliding window,
success-after-repeated-failures, and password spraying (one source, many
accounts, few attempts each).

Two defects were reproduced and fixed here: bursts previously counted lifetime
totals, and the failure counter previously survived a successful login. Both are
pinned, including the exact window boundary and one second past it.

All events are fixtures written for this repository. No real incident has been
triaged, so the category is not claimed.
