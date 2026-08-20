"""Schema and validator for local training-range challenge evidence.

Every challenge record produced during an authorized local assessment must pass
:func:`validate_record` before it is written to the matrix. The validator is the
enforcement point for three promises made in ``AUTHORIZED_SCOPE.md``:

1. every target URL is a ``127.0.0.1`` loopback URL — never a hostname, never a
   third-party or LAN address;
2. no secret (an ``Authorization`` header, a JWT, a password, a session cookie)
   is ever stored in the evidence; and
3. every record carries a remediation, so the evidence stays defensive.

These are checked in code and pinned by tests, so a later careless edit that
pastes a bearer token or points at a public demo cannot slip into the record.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

REQUIRED_FIELDS = (
    "name",
    "official_category",
    "difficulty_stars",
    "authorization_basis",
    "timestamp",
    "target_url",
    "method",
    "request_summary",
    "response_status",
    "instance_solved_state",
    "root_cause_location",
    "remediation",
    "genuinely_completed",
)

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

#: A JWT is three base64url segments separated by dots, the header segment
#: beginning with ``eyJ`` (``{"`` base64url-encoded).
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")

#: Field names that must never appear in a stored record, at any nesting depth.
_FORBIDDEN_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "token",
    "access_token",
    "jwt",
    "bearer",
    "session",
}

#: Secret-shaped substrings that must not appear in any stored string value.
#: The bearer pattern requires a token-shaped tail (long, and containing a digit
#: or a token separator) so the ordinary English word "bearer" does not trip it.
_SECRET_PATTERNS = (
    re.compile(r"\bbearer\s+(?=[a-z0-9._-]*[0-9._-])[a-z0-9._-]{12,}", re.IGNORECASE),
    re.compile(r"\bauthorization\s*[:=]\s*\S", re.IGNORECASE),
    _JWT,
)


class EvidenceError(ValueError):
    """Raised when a challenge record violates the evidence schema or scope."""


def _require_loopback(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise EvidenceError(f"target_url must be http(s): {url!r}")
    host = parsed.hostname or ""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        # A bare hostname (including 'localhost') is refused: the record must
        # pin the literal loopback address that was actually used.
        raise EvidenceError(f"target_url host must be a loopback IP literal, not {host!r}") from exc
    if not address.is_loopback:
        raise EvidenceError(f"target_url is not loopback: {url!r}")


def _scan_for_secrets(value: object, path: str = "") -> None:
    """Walk a record and refuse forbidden keys or secret-shaped values."""

    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).strip().lower() in _FORBIDDEN_KEYS:
                raise EvidenceError(f"forbidden sensitive field {key!r} at {path or '<root>'}")
            _scan_for_secrets(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _scan_for_secrets(item, f"{path}[{index}]")
    elif isinstance(value, str):
        for pattern in _SECRET_PATTERNS:
            if pattern.search(value):
                raise EvidenceError(f"secret-shaped content at {path or '<root>'}")


def validate_record(record: dict[str, object]) -> dict[str, object]:
    """Validate one challenge record, returning it unchanged if it is clean."""

    missing = [field for field in REQUIRED_FIELDS if field not in record]
    if missing:
        raise EvidenceError(f"record is missing required fields: {missing}")

    _require_loopback(str(record["target_url"]))

    if str(record["method"]).upper() not in ALLOWED_METHODS:
        raise EvidenceError(f"unsupported method: {record['method']!r}")

    stars = record["difficulty_stars"]
    if not isinstance(stars, int) or not 1 <= stars <= 6:
        raise EvidenceError(f"difficulty_stars must be an int in 1..6, got {stars!r}")

    if not isinstance(record["genuinely_completed"], bool):
        raise EvidenceError("genuinely_completed must be a boolean")

    remediation = str(record.get("remediation", "")).strip()
    if len(remediation) < 20:
        raise EvidenceError("remediation must be a substantive string")

    # A record may only claim completion if the instance itself recorded it.
    solved_state = str(record["instance_solved_state"]).strip().lower()
    if record["genuinely_completed"] and solved_state not in {"true", "solved"}:
        raise EvidenceError(
            "genuinely_completed is true but instance_solved_state does not confirm it"
        )

    _scan_for_secrets(record)
    return record


def validate_matrix(records: list[dict[str, object]]) -> list[dict[str, object]]:
    """Validate every record and return them unchanged if all pass."""

    for index, record in enumerate(records):
        try:
            validate_record(record)
        except EvidenceError as exc:
            raise EvidenceError(f"record {index} ({record.get('name', '?')!r}): {exc}") from exc
    return records


def completed_categories(records: list[dict[str, object]]) -> set[str]:
    """Return the official categories with at least one genuinely-completed record."""

    return {
        str(record["official_category"]) for record in records if record.get("genuinely_completed")
    }
