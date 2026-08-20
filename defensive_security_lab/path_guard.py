"""Filename boundary validation for a local, synthetic output directory.

The policy this module enforces is deliberately narrow: a caller may supply a
single bare filename whose extension appears in ``ALLOWED_EXTENSIONS``. Anything
that could escape the intended output directory, resolve differently on another
platform, or change meaning after one more decoding pass is rejected.

All checks operate on strings. Nothing here touches the filesystem.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import unquote

ALLOWED_EXTENSIONS = {".json", ".log", ".md", ".txt", ".vtt"}

#: Maximum number of percent-decoding rounds applied when looking for input that
#: only becomes dangerous after the receiving layer decodes it again.
MAX_DECODE_ROUNDS = 3

#: Reserved device names on Windows. These are rejected with or without an
#: extension because the operating system resolves ``CON.txt`` to the console
#: device rather than to a file.
WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{digit}" for digit in range(1, 10)}
    | {f"lpt{digit}" for digit in range(1, 10)}
)

_PERCENT_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")


class FilenameRejected(ValueError):
    """Raised when a candidate filename violates the output-path policy.

    ``reason`` is a stable machine-readable slug so tests can assert *why* a
    value was rejected rather than only that it was.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _decode_rounds(value: str) -> list[str]:
    """Return ``value`` plus each distinct percent-decoding of it.

    ``%252e`` decodes to ``%2e`` and then to ``.``; a validator that inspects
    only the original string would miss it.
    """

    forms = [value]
    current = value
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = unquote(current)
        if decoded == current:
            break
        forms.append(decoded)
        current = decoded
    return forms


def _check_single_form(name: str) -> None:
    """Apply every structural rule to one already-decoded candidate."""

    if "\x00" in name:
        raise FilenameRejected("nul_byte", "NUL bytes are not allowed")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise FilenameRejected("control_character", "control characters are not allowed")

    normalized = name.replace("\\", "/")
    if "/" in normalized:
        raise FilenameRejected("path_separator", "path separators are not allowed")

    path = PurePosixPath(normalized)
    if path.is_absolute() or len(path.parts) != 1:
        raise FilenameRejected("not_a_bare_name", "a single bare filename is required")
    if normalized in {".", ".."}:
        raise FilenameRejected("traversal", "traversal names are not allowed")
    if normalized.startswith("."):
        raise FilenameRejected("hidden", "hidden names are not allowed")
    if ":" in normalized:
        raise FilenameRejected("alternate_data_stream", "stream separators are not allowed")
    if normalized != normalized.rstrip(" ."):
        raise FilenameRejected(
            "trailing_dot_or_space",
            "trailing dots and spaces are stripped by some filesystems",
        )

    stem = normalized.split(".", 1)[0]
    if stem.lower() in WINDOWS_RESERVED_NAMES:
        raise FilenameRejected("reserved_device_name", "reserved device names are not allowed")

    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise FilenameRejected("extension", "file extension is outside the allowlist")


def validate_filename(name: str) -> str:
    """Validate one output filename and return it unchanged.

    Raises :class:`FilenameRejected` describing the first rule that failed.
    """

    if not isinstance(name, str) or not name:
        raise FilenameRejected("empty", "filename must be a non-empty string")

    forms = _decode_rounds(name)
    if len(forms) > 1 or _PERCENT_ENCODED.search(name):
        # A filename under this policy never needs percent-encoding, and
        # accepting it would mean trusting every downstream decoder to agree
        # with this one.
        raise FilenameRejected("percent_encoded", "percent-encoded input is not allowed")

    for form in forms:
        _check_single_form(form)
    return name


def classify_filenames(names: list[str]) -> dict[str, list[str]]:
    """Split filename strings into allowed and rejected values."""

    result: dict[str, list[str]] = {"allowed": [], "rejected": []}
    for name in names:
        try:
            validate_filename(name)
        except FilenameRejected:
            result["rejected"].append(name)
        else:
            result["allowed"].append(name)
    return result


def explain(name: str) -> dict[str, str]:
    """Return the verdict for one filename, including the rejection reason."""

    try:
        validate_filename(name)
    except FilenameRejected as exc:
        return {"name": name, "verdict": "rejected", "reason": exc.reason}
    return {"name": name, "verdict": "allowed", "reason": "policy_satisfied"}
