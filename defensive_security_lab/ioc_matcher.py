"""Boundary-aware indicator matching over text records.

An earlier revision of this module tested ``indicator in text``. That reports a
match whenever the indicator appears as a substring, so ``1.2.3.4`` was found
inside ``11.2.3.45`` and ``evil.com`` inside ``notevil.com.br``. Both are false
positives, and an indicator matcher that cries wolf on unrelated infrastructure
is worse than no matcher at all.

This revision extracts candidate tokens and compares them on their own
boundaries, understands CIDR ranges, recognises defanged notation, and supports
an allowlist for known-good infrastructure.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

#: Hex digest lengths mapped to the algorithm that produces them.
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}

_IPV4 = re.compile(r"(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3})(?![0-9.])")
_HEX_TOKEN = re.compile(r"(?<![0-9A-Za-z])([0-9A-Fa-f]{32,64})(?![0-9A-Za-z])")

_DEFANG_PATTERNS = (
    (re.compile(r"h(?:xx|XX)p(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\((?:dot)\)", re.IGNORECASE), "."),
    (re.compile(r"\[(?:dot)\]", re.IGNORECASE), "."),
    (re.compile(r"\[(?:at)\]", re.IGNORECASE), "@"),
    (re.compile(r"\[:\]"), ":"),
)


def normalize_defanged(text: str) -> str:
    """Return ``text`` with common defanging conventions reversed.

    Analysts routinely share indicators as ``evil[.]com`` or ``hxxp://…`` so the
    values are not clickable. Matching must see through that.
    """

    for pattern, replacement in _DEFANG_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def hash_type(value: str) -> str | None:
    """Return the algorithm implied by a hex digest's length, if recognised."""

    candidate = value.strip().lower()
    if not candidate or any(character not in "0123456789abcdef" for character in candidate):
        return None
    return HASH_LENGTHS.get(len(candidate))


def _domain_pattern(domain: str) -> re.Pattern[str]:
    """Compile a matcher that only fires on whole-label boundaries.

    The lookbehind stops ``evil.com`` matching inside ``notevil.com``; the
    lookahead stops it matching inside ``evil.com.br``.
    """

    return re.compile(
        r"(?<![0-9A-Za-z._-])" + re.escape(domain) + r"(?![0-9A-Za-z.-])",
        re.IGNORECASE,
    )


def load_indicators(path: str | Path) -> dict[str, list[str]]:
    """Load and validate an indicator file.

    Unknown keys, non-list values, and malformed hashes are rejected rather than
    silently carried into matching.
    """

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    expected = {"domains", "ips", "hashes"}
    if not isinstance(data, dict):
        raise ValueError("indicator file must contain a JSON object")
    if set(data) - expected - {"allowlist"}:
        raise ValueError(f"indicator file may only contain {sorted(expected)} and allowlist")
    for key in expected:
        if key not in data:
            raise ValueError(f"indicator file must contain a {key} list")
        if not isinstance(data[key], list):
            raise ValueError(f"{key} must be a list")

    for digest in data["hashes"]:
        if hash_type(str(digest)) is None:
            raise ValueError(f"unrecognised hash length or alphabet: {digest!r}")

    indicators = {key: [str(value).strip().lower() for value in data[key]] for key in expected}
    indicators["allowlist"] = [str(value).strip().lower() for value in data.get("allowlist", [])]
    return indicators


def _match_ips(text: str, patterns: list[str]) -> list[str]:
    """Match literal addresses and CIDR ranges against addresses found in text."""

    networks: list[tuple[str, ipaddress.IPv4Network]] = []
    for pattern in patterns:
        try:
            networks.append((pattern, ipaddress.ip_network(pattern, strict=False)))
        except ValueError:
            continue

    hits: set[str] = set()
    for candidate in _IPV4.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        for original, network in networks:
            if address in network:
                hits.add(original)
    return sorted(hits)


def match_text(
    text: str,
    indicators: dict[str, list[str]],
    *,
    defang: bool = True,
) -> dict[str, list[str]]:
    """Return the indicators genuinely present in ``text``, by category."""

    haystack = normalize_defanged(text) if defang else text
    allowlist = set(indicators.get("allowlist", []))

    domains = sorted(
        {
            domain
            for domain in indicators.get("domains", [])
            if domain not in allowlist and _domain_pattern(domain).search(haystack)
        }
    )

    ips = [
        value for value in _match_ips(haystack, indicators.get("ips", [])) if value not in allowlist
    ]

    found_hashes = {token.lower() for token in _HEX_TOKEN.findall(haystack)}
    hashes = sorted(
        {
            digest
            for digest in indicators.get("hashes", [])
            if digest not in allowlist and digest in found_hashes
        }
    )

    return {"domains": domains, "ips": ips, "hashes": hashes}


def match_file(indicator_path: str | Path, record_path: str | Path) -> dict[str, list[str]]:
    """Match an indicator file against a text record file."""

    indicators = load_indicators(indicator_path)
    records = Path(record_path).read_text(encoding="utf-8")
    return match_text(records, indicators)
