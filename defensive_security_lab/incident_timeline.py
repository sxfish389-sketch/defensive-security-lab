"""Authentication-event triage over synthetic logs.

Two defects in the previous revision motivated this rewrite, both reproduced
before being fixed:

* ``failed_login_burst`` counted failures for the entire lifetime of the log, so
  three failures spread across a year were reported as a burst. A burst is a
  rate, not a total, so failures are now evaluated inside a sliding window.
* The failure counter was never cleared after a successful authentication, so
  every later success re-fired ``success_after_failed_logins`` on stale history.
  A success now closes the episode.

All events are synthetic fixtures. Nothing here reads a production log.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

REQUIRED_FIELDS = frozenset({"timestamp", "user", "source_ip", "result"})
VALID_RESULTS = frozenset({"success", "failure"})

#: Failures inside this window count toward one episode.
DEFAULT_WINDOW = timedelta(minutes=5)

#: Failures needed inside the window before an episode is reported.
DEFAULT_THRESHOLD = 3

#: Distinct users one source must touch before it looks like spraying.
DEFAULT_SPRAY_USERS = 3

#: A sprayer stays shallow; more attempts than this per user looks like a
#: targeted brute force instead.
SPRAY_MAX_ATTEMPTS_PER_USER = 2


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, accepting a trailing ``Z``."""

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_events(path: str | Path) -> list[dict[str, str]]:
    """Load and validate JSONL authentication events, sorted by timestamp."""

    events: list[dict[str, str]] = []
    raw = Path(path).read_text(encoding="utf-8")
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number} is not valid JSON") from exc
        missing = REQUIRED_FIELDS - set(event)
        if missing:
            raise ValueError(f"line {line_number} is missing fields: {sorted(missing)}")
        if event["result"] not in VALID_RESULTS:
            raise ValueError(f"line {line_number} has an unknown result: {event['result']!r}")
        parse_timestamp(event["timestamp"])
        events.append(event)
    return sorted(events, key=lambda item: item["timestamp"])


def _prune(timestamps: list[datetime], now: datetime, window: timedelta) -> list[datetime]:
    """Drop timestamps that have fallen out of the sliding window."""

    return [stamp for stamp in timestamps if now - stamp <= window]


def analyze_events(
    events: list[dict[str, str]],
    threshold: int = DEFAULT_THRESHOLD,
    *,
    window: timedelta = DEFAULT_WINDOW,
    spray_users: int = DEFAULT_SPRAY_USERS,
) -> list[dict[str, object]]:
    """Return findings for one ordered sequence of authentication events."""

    failures: dict[tuple[str, str], list[datetime]] = defaultdict(list)
    reported_burst: set[tuple[str, str]] = set()
    by_source: dict[str, list[dict[str, object]]] = defaultdict(list)
    findings: list[dict[str, object]] = []

    for event in sorted(events, key=lambda item: item["timestamp"]):
        moment = parse_timestamp(event["timestamp"])
        key = (event["user"], event["source_ip"])
        by_source[event["source_ip"]].append({"moment": moment, "event": event})

        recent = _prune(failures[key], moment, window)

        if event["result"] == "failure":
            recent.append(moment)
            failures[key] = recent
            if len(recent) >= threshold and key not in reported_burst:
                reported_burst.add(key)
                findings.append(
                    {
                        "type": "failed_login_burst",
                        "user": event["user"],
                        "source_ip": event["source_ip"],
                        "failure_count": len(recent),
                        "window_seconds": int(window.total_seconds()),
                        "first_timestamp": recent[0].isoformat(),
                        "last_timestamp": recent[-1].isoformat(),
                    }
                )
        else:
            if len(recent) >= threshold:
                findings.append(
                    {
                        "type": "success_after_failed_logins",
                        "user": event["user"],
                        "source_ip": event["source_ip"],
                        "failure_count": len(recent),
                        "window_seconds": int(window.total_seconds()),
                        "success_timestamp": moment.isoformat(),
                    }
                )
            # A success closes the episode; later failures start a new one.
            failures[key] = []
            reported_burst.discard(key)

    findings.extend(_detect_spray(by_source, window, spray_users))
    findings.sort(key=lambda item: (str(item.get("type")), str(item.get("source_ip"))))
    return findings


def _detect_spray(
    by_source: dict[str, list[dict[str, object]]],
    window: timedelta,
    spray_users: int,
) -> list[dict[str, object]]:
    """Flag one source failing shallowly against many distinct users.

    Spraying is broad and shallow: many accounts, few attempts each. A source
    hammering one account is a brute force and is already covered by
    ``failed_login_burst``.
    """

    findings: list[dict[str, object]] = []
    for source_ip, entries in sorted(by_source.items()):
        ordered = sorted(entries, key=lambda item: item["moment"])
        for index, anchor in enumerate(ordered):
            attempts: dict[str, int] = defaultdict(int)
            last = anchor["moment"]
            for candidate in ordered[index:]:
                if candidate["moment"] - anchor["moment"] > window:
                    break
                if candidate["event"]["result"] != "failure":
                    continue
                attempts[candidate["event"]["user"]] += 1
                last = candidate["moment"]
            if (
                len(attempts) >= spray_users
                and attempts
                and max(attempts.values()) <= SPRAY_MAX_ATTEMPTS_PER_USER
            ):
                findings.append(
                    {
                        "type": "password_spray",
                        "source_ip": source_ip,
                        "user_count": len(attempts),
                        "users": sorted(attempts),
                        "window_seconds": int(window.total_seconds()),
                        "first_timestamp": anchor["moment"].isoformat(),
                        "last_timestamp": last.isoformat(),
                    }
                )
                break
    return findings


def analyze_file(
    path: str | Path,
    threshold: int = DEFAULT_THRESHOLD,
    *,
    window: timedelta = DEFAULT_WINDOW,
) -> list[dict[str, object]]:
    """Load a JSONL fixture and return its findings."""

    return analyze_events(load_events(path), threshold=threshold, window=window)
