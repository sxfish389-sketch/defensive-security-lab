# Incident-response evidence

The incident-timeline module validates and orders JSONL authentication events,
detects failed-login bursts, and flags a successful login following repeated
failures from the same synthetic source.

The output is a small triage finding suitable for a defensive report. All
events are constructed fixtures, not a real incident.

