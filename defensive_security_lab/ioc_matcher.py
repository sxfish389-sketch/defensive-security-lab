"""Match synthetic indicators against text records."""

from __future__ import annotations

import json
from pathlib import Path


def load_indicators(path: str | Path) -> dict[str, list[str]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    expected = {"domains", "ips", "hashes"}
    if set(data) != expected or not all(isinstance(data[key], list) for key in expected):
        raise ValueError("indicator file must contain domains, ips, and hashes lists")
    return {key: [str(value).lower() for value in data[key]] for key in expected}


def match_text(text: str, indicators: dict[str, list[str]]) -> dict[str, list[str]]:
    haystack = text.lower()
    return {
        category: sorted({value for value in values if value in haystack})
        for category, values in indicators.items()
    }


def match_file(indicator_path: str | Path, record_path: str | Path) -> dict[str, list[str]]:
    indicators = load_indicators(indicator_path)
    records = Path(record_path).read_text(encoding="utf-8")
    return match_text(records, indicators)

