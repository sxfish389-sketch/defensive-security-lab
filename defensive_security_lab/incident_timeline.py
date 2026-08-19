"""Analyze synthetic authentication events for defensive triage."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def load_events(path: str | Path) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        event = json.loads(line)
        required = {"timestamp", "user", "source_ip", "result"}
        if not required.issubset(event):
            raise ValueError(f"line {line_number} is missing required fields")
        datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        events.append(event)
    return sorted(events, key=lambda item: item["timestamp"])


def analyze_events(events: list[dict[str, str]], threshold: int = 3) -> list[dict[str, object]]:
    failures: dict[tuple[str, str], list[str]] = defaultdict(list)
    findings: list[dict[str, object]] = []

    for event in events:
        key = (event["user"], event["source_ip"])
        if event["result"] == "failure":
            failures[key].append(event["timestamp"])
        elif event["result"] == "success" and len(failures[key]) >= threshold:
            findings.append(
                {
                    "type": "success_after_failed_logins",
                    "user": event["user"],
                    "source_ip": event["source_ip"],
                    "failure_count": len(failures[key]),
                    "success_timestamp": event["timestamp"],
                }
            )

    for (user, source_ip), timestamps in sorted(failures.items()):
        if len(timestamps) >= threshold:
            findings.append(
                {
                    "type": "failed_login_burst",
                    "user": user,
                    "source_ip": source_ip,
                    "failure_count": len(timestamps),
                    "first_timestamp": timestamps[0],
                    "last_timestamp": timestamps[-1],
                }
            )
    return findings


def analyze_file(path: str | Path, threshold: int = 3) -> list[dict[str, object]]:
    return analyze_events(load_events(path), threshold=threshold)

