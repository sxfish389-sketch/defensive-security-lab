"""Audit HTTP response headers while enforcing a loopback-only target boundary."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen


RECOMMENDED_HEADERS = {
    "content-security-policy",
    "referrer-policy",
    "x-content-type-options",
    "x-frame-options",
}


def require_loopback_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("a complete HTTP(S) URL is required")
    if parsed.hostname == "localhost":
        return url
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("only localhost or a loopback IP is allowed") from exc
    if not address.is_loopback:
        raise ValueError("only localhost or a loopback IP is allowed")
    return url


def audit_headers(headers: dict[str, str]) -> dict[str, list[str]]:
    normalized = {name.lower(): str(value) for name, value in headers.items()}
    missing = sorted(RECOMMENDED_HEADERS - normalized.keys())
    present = sorted(RECOMMENDED_HEADERS & normalized.keys())
    return {"present": present, "missing": missing}


def audit_fixture(path: str | Path) -> dict[str, list[str]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("header fixture must be a JSON object")
    return audit_headers(data)


def fetch_and_audit(url: str, timeout: float = 3.0) -> dict[str, list[str]]:
    require_loopback_url(url)
    request = Request(url, method="HEAD", headers={"User-Agent": "defensive-security-lab/0.1"})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - loopback enforced above
        return audit_headers(dict(response.headers.items()))

