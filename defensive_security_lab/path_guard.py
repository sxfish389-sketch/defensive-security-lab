"""Safe filename handling used by the educational regression lab."""

from __future__ import annotations

import re
from pathlib import PurePosixPath


ALLOWED_EXTENSIONS = {".json", ".log", ".md", ".txt", ".vtt"}


def canonicalize_package_name(name: str) -> str:
    """Return the PEP 503-style canonical spelling of a package name."""

    if not isinstance(name, str) or not name.strip():
        raise ValueError("package name must be a non-empty string")
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def validate_filename(name: str) -> str:
    """Validate a single safe output filename and return it unchanged."""

    if not isinstance(name, str) or not name:
        raise ValueError("filename must be a non-empty string")
    if "\x00" in name:
        raise ValueError("NUL bytes are not allowed")

    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or len(path.parts) != 1:
        raise ValueError("path separators and absolute paths are not allowed")
    if normalized in {".", ".."} or normalized.startswith("."):
        raise ValueError("hidden and traversal names are not allowed")
    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("file extension is outside the allowlist")
    return name


def classify_filenames(names: list[str]) -> dict[str, list[str]]:
    """Split a list of filename strings into allowed and rejected values."""

    result: dict[str, list[str]] = {"allowed": [], "rejected": []}
    for name in names:
        try:
            validate_filename(name)
        except ValueError:
            result["rejected"].append(name)
        else:
            result["allowed"].append(name)
    return result

