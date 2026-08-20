"""Audit HTTP response headers while enforcing a loopback-only target boundary.

The boundary is the security-relevant part of this module. An earlier revision
accepted the literal hostname ``localhost`` without resolving it, which trusts
whatever ``/etc/hosts`` or the resolver happens to say. Resolution is now
verified by default: every address a hostname resolves to must be a loopback
address, or the URL is refused.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

RECOMMENDED_HEADERS = {
    "content-security-policy",
    "referrer-policy",
    "x-content-type-options",
    "x-frame-options",
}


class TargetRefused(ValueError):
    """Raised when a URL falls outside the authorized loopback boundary."""


def resolve_addresses(hostname: str, port: int = 80) -> list[str]:
    """Return every address ``hostname`` resolves to.

    Raises :class:`TargetRefused` when the name does not resolve, because a
    caller must never be left guessing whether a check passed or was skipped.
    """

    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetRefused(f"hostname {hostname!r} does not resolve") from exc
    return sorted({info[4][0] for info in infos})


def require_loopback_url(url: str, *, verify_dns: bool = True) -> str:
    """Return ``url`` unchanged if it targets loopback, else refuse it.

    With ``verify_dns`` (the default) a hostname is resolved and **every**
    resulting address must be a loopback address. Passing ``verify_dns=False``
    checks only the literal host and is intended for offline unit tests.
    """

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetRefused("a complete HTTP(S) URL is required")

    hostname = parsed.hostname
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None

    if literal is not None:
        if not literal.is_loopback:
            raise TargetRefused(f"{hostname} is not a loopback address")
        return url

    if hostname != "localhost":
        raise TargetRefused("only localhost or a loopback IP is allowed")

    if verify_dns:
        addresses = resolve_addresses(hostname, parsed.port or 80)
        for address in addresses:
            if not ipaddress.ip_address(address).is_loopback:
                raise TargetRefused(f"{hostname} resolves to {address}, which is not loopback")
    return url


def audit_headers(headers: dict[str, str]) -> dict[str, list[str]]:
    """Report which recommended security headers are present and missing."""

    normalized = {name.lower(): str(value) for name, value in headers.items()}
    missing = sorted(RECOMMENDED_HEADERS - normalized.keys())
    present = sorted(RECOMMENDED_HEADERS & normalized.keys())
    return {"present": present, "missing": missing}


def audit_fixture(path: str | Path) -> dict[str, list[str]]:
    """Audit a captured header fixture."""

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("header fixture must be a JSON object")
    return audit_headers(data)


def fetch_headers(url: str, timeout: float = 5.0, method: str = "HEAD") -> dict[str, object]:
    """Fetch one loopback URL and return its status and headers.

    The boundary is enforced before the request is constructed, not after.
    """

    require_loopback_url(url)
    request = Request(url, method=method, headers={"User-Agent": "defensive-security-lab/0.2"})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - loopback enforced above
        return {
            "url": url,
            "status": response.status,
            "headers": dict(response.headers.items()),
        }


def fetch_and_audit(url: str, timeout: float = 5.0) -> dict[str, list[str]]:
    """Fetch one loopback URL and audit its security headers."""

    return audit_headers(fetch_headers(url, timeout=timeout)["headers"])
