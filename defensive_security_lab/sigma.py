"""A small, strict Sigma-subset loader and evaluator.

The repository has no third-party runtime dependencies, so this module carries
its own YAML reader rather than pulling in PyYAML. It deliberately supports only
the subset the bundled rules use and raises on anything else: silently
misreading a detection rule is worse than refusing to load it.

Supported per rule:

* mapping and list structure by indentation, ``#`` comments, quoted scalars,
  and ``>``/``|`` block scalars;
* ``detection.<name>`` selections whose fields match by equality, by list
  membership (OR), or through the ``contains``, ``startswith``, ``endswith``
  and ``re`` modifiers;
* ``condition`` of the form ``<selection>``, ``<a> and not <b>``, ``<a> or <b>``;
* the aggregation ``<selection> | count() by <field> > N`` and its distinct
  form ``<selection> | count(<field>) by <field> > N``, evaluated inside the
  sliding window given by ``timeframe``.

Anything outside that subset raises :class:`SigmaError`.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


class SigmaError(ValueError):
    """Raised when a rule cannot be parsed or uses an unsupported construct."""


# --------------------------------------------------------------------------- #
# Minimal YAML subset reader
# --------------------------------------------------------------------------- #

_TIMEFRAME = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def _strip_comment(line: str) -> str:
    """Remove a trailing ``#`` comment that is not inside quotes."""

    out: list[str] = []
    quote: str | None = None
    for index, character in enumerate(line):
        if quote:
            if character == quote:
                quote = None
        elif character in "\"'":
            quote = character
        elif character == "#" and (index == 0 or line[index - 1] in " \t"):
            break
        out.append(character)
    return "".join(out).rstrip()


def _scalar(raw: str) -> object:
    """Convert a YAML scalar to a Python value."""

    text = raw.strip()
    if not text:
        return ""
    if text[0] == text[-1] and text[0] in "\"'" and len(text) >= 2:
        return text[1:-1]
    lowered = text.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "~"}:
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_block(lines: list[tuple[int, str]], start: int, indent: int) -> tuple[object, int]:
    """Parse one block at ``indent`` and return the value plus the next index."""

    if start < len(lines) and lines[start][1].lstrip().startswith("- "):
        items: list[object] = []
        index = start
        while index < len(lines):
            level, text = lines[index]
            stripped = text.lstrip()
            if level < indent or not stripped.startswith("- "):
                break
            items.append(_scalar(stripped[2:]))
            index += 1
        return items, index

    mapping: dict[str, object] = {}
    index = start
    while index < len(lines):
        level, text = lines[index]
        if level < indent:
            break
        stripped = text.strip()
        if ":" not in stripped:
            raise SigmaError(f"expected 'key: value', got {stripped!r}")
        key, _, remainder = stripped.partition(":")
        key = key.strip()
        remainder = remainder.strip()
        index += 1

        if remainder in {">", "|", ">-", "|-"}:
            chunks: list[str] = []
            while index < len(lines) and lines[index][0] > level:
                chunks.append(lines[index][1].strip())
                index += 1
            mapping[key] = " ".join(chunks).strip()
            continue

        if remainder:
            mapping[key] = _scalar(remainder)
            continue

        if index < len(lines) and lines[index][0] > level:
            value, index = _parse_block(lines, index, lines[index][0])
            mapping[key] = value
        else:
            mapping[key] = None
    return mapping, index


def load_rule_text(text: str) -> dict[str, object]:
    """Parse one Sigma rule from YAML text."""

    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        cleaned = _strip_comment(raw)
        if not cleaned.strip() or cleaned.strip() == "---":
            continue
        lines.append((_indent_of(cleaned), cleaned))
    if not lines:
        raise SigmaError("rule is empty")
    parsed, _ = _parse_block(lines, 0, 0)
    if not isinstance(parsed, dict):
        raise SigmaError("a rule must be a mapping at the top level")
    return parsed


def load_rule(path: str | Path) -> dict[str, object]:
    """Parse one Sigma rule from a file and check its required fields."""

    rule = load_rule_text(Path(path).read_text(encoding="utf-8"))
    for field in ("title", "id", "logsource", "detection", "level"):
        if field not in rule:
            raise SigmaError(f"rule {path} is missing required field {field!r}")
    detection = rule["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaError(f"rule {path} has no detection.condition")
    return rule


def load_rules(directory: str | Path) -> list[dict[str, object]]:
    """Load every ``.yml`` rule in ``directory``, sorted by filename."""

    return [load_rule(path) for path in sorted(Path(directory).glob("*.yml"))]


# --------------------------------------------------------------------------- #
# Field matching
# --------------------------------------------------------------------------- #


def _match_value(actual: object, expected: object, modifier: str | None) -> bool:
    text = "" if actual is None else str(actual)
    wanted = "" if expected is None else str(expected)
    if modifier is None:
        return text.lower() == wanted.lower()
    if modifier == "contains":
        return wanted.lower() in text.lower()
    if modifier == "startswith":
        return text.lower().startswith(wanted.lower())
    if modifier == "endswith":
        return text.lower().endswith(wanted.lower())
    if modifier == "re":
        return re.search(wanted, text) is not None
    raise SigmaError(f"unsupported field modifier: {modifier!r}")


def _match_selection(event: dict[str, object], selection: object) -> bool:
    if not isinstance(selection, dict):
        raise SigmaError("a selection must be a mapping of fields to values")
    for raw_field, expected in selection.items():
        field, _, modifier = raw_field.partition("|")
        modifier = modifier or None
        if field not in event:
            return False
        candidates = expected if isinstance(expected, list) else [expected]
        if not any(_match_value(event[field], value, modifier) for value in candidates):
            return False
    return True


# --------------------------------------------------------------------------- #
# Condition and aggregation
# --------------------------------------------------------------------------- #

_AGG = re.compile(
    r"^(?P<sel>[A-Za-z_][\w]*)\s*\|\s*count\(\s*(?P<countfield>[\w]*)\s*\)"
    r"\s+by\s+(?P<by>[\w]+)\s*(?P<op>>=|>)\s*(?P<value>\d+)$"
)
_PLAIN = re.compile(
    r"^(?P<a>[A-Za-z_][\w]*)(?:\s+(?P<op>and not|or|and)\s+(?P<b>[A-Za-z_][\w]*))?$"
)


def parse_condition(condition: str) -> dict[str, object]:
    """Parse the supported condition forms into a small description."""

    text = str(condition).strip()
    aggregation = _AGG.match(text)
    if aggregation:
        return {
            "kind": "aggregation",
            "selection": aggregation["sel"],
            "count_field": aggregation["countfield"] or None,
            "by": aggregation["by"],
            "op": aggregation["op"],
            "value": int(aggregation["value"]),
        }
    plain = _PLAIN.match(text)
    if plain:
        return {
            "kind": "plain",
            "a": plain["a"],
            "op": plain["op"],
            "b": plain["b"],
        }
    raise SigmaError(f"unsupported condition: {condition!r}")


def parse_timeframe(value: object) -> timedelta | None:
    """Convert a Sigma ``timeframe`` such as ``5m`` into a timedelta."""

    if value is None:
        return None
    match = _TIMEFRAME.match(str(value).strip())
    if not match:
        raise SigmaError(f"unsupported timeframe: {value!r}")
    return timedelta(**{_UNITS[match[2]]: int(match[1])})


def _selected(rule: dict[str, object], events: list[dict[str, object]]) -> list[dict[str, object]]:
    detection = rule["detection"]
    parsed = parse_condition(detection["condition"])
    name = parsed["selection"] if parsed["kind"] == "aggregation" else parsed["a"]
    if name not in detection:
        raise SigmaError(f"condition references unknown selection {name!r}")
    hits = [event for event in events if _match_selection(event, detection[name])]

    if parsed["kind"] == "plain" and parsed["op"]:
        other = parsed["b"]
        if other not in detection:
            raise SigmaError(f"condition references unknown selection {other!r}")
        second = detection[other]
        if parsed["op"] == "and not":
            hits = [event for event in hits if not _match_selection(event, second)]
        elif parsed["op"] == "and":
            hits = [event for event in hits if _match_selection(event, second)]
        else:  # or
            extra = [event for event in events if _match_selection(event, second)]
            seen = {id(event) for event in hits}
            hits = hits + [event for event in extra if id(event) not in seen]
    return hits


def evaluate(
    rule: dict[str, object],
    events: list[dict[str, object]],
    *,
    timestamp_field: str = "timestamp",
) -> list[dict[str, object]]:
    """Evaluate one rule and return its matches.

    Plain rules return one entry per matching event. Aggregation rules slide the
    ``timeframe`` window over the selected events and return one entry per group
    that crosses the threshold.
    """

    detection = rule["detection"]
    parsed = parse_condition(detection["condition"])
    hits = _selected(rule, events)
    title = rule.get("title")

    if parsed["kind"] == "plain":
        return [{"rule": title, "event": event} for event in hits]

    window = parse_timeframe(detection.get("timeframe"))
    by_field = parsed["by"]
    count_field = parsed["count_field"]
    threshold = parsed["value"]
    strictly_greater = parsed["op"] == ">"

    grouped: dict[object, list[dict[str, object]]] = defaultdict(list)
    for event in hits:
        if by_field in event:
            grouped[event[by_field]].append(event)

    results: list[dict[str, object]] = []
    for group, members in sorted(grouped.items(), key=lambda item: str(item[0])):
        ordered = sorted(members, key=lambda item: str(item[timestamp_field]))
        for index, anchor in enumerate(ordered):
            bucket = []
            for candidate in ordered[index:]:
                if window is not None:
                    span = _to_datetime(candidate[timestamp_field]) - _to_datetime(
                        anchor[timestamp_field]
                    )
                    if span > window:
                        break
                bucket.append(candidate)
            observed = (
                len({event.get(count_field) for event in bucket}) if count_field else len(bucket)
            )
            crossed = observed > threshold if strictly_greater else observed >= threshold
            if crossed:
                results.append(
                    {
                        "rule": title,
                        "group_field": by_field,
                        "group": group,
                        "observed": observed,
                        "threshold": threshold,
                        "first_timestamp": str(bucket[0][timestamp_field]),
                        "last_timestamp": str(bucket[-1][timestamp_field]),
                    }
                )
                break
    return results


def _to_datetime(value: object) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
