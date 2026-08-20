"""Baseline security review of an HTTP response from an authorized local target.

This module deepens the presence/absence check in :mod:`local_header_audit`. A
header that exists is not automatically a header that helps: a Content-Security
-Policy containing ``unsafe-inline`` in ``script-src`` provides very little, and
an ``HSTS`` header with a two-second ``max-age`` provides none.

Everything here is pure analysis over data structures. Fetching is delegated to
:func:`local_header_audit.fetch_headers`, which enforces the loopback boundary
before any request is made.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .local_header_audit import fetch_headers, require_loopback_url

#: Minimum HSTS lifetime generally considered useful (six months).
MIN_HSTS_MAX_AGE = 15_552_000

#: Directives whose absence falls back to ``default-src``.
FETCH_DIRECTIVES = ("script-src", "style-src", "object-src", "frame-ancestors")

#: Header names that disclose implementation detail without providing value.
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass(frozen=True)
class Finding:
    """One observation about a response."""

    identifier: str
    severity: str
    summary: str
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.identifier,
            "severity": self.severity,
            "summary": self.summary,
            "detail": self.detail,
        }


@dataclass
class Assessment:
    """The result of reviewing one response."""

    url: str
    status: int
    findings: list[Finding] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.identifier))

    def as_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "status": self.status,
            "finding_count": len(self.findings),
            "findings": [finding.as_dict() for finding in self.sorted_findings()],
        }


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Lowercase header names so lookups are case-insensitive."""

    return {str(name).lower(): str(value) for name, value in headers.items()}


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a Content-Security-Policy into directive → source list."""

    directives: dict[str, list[str]] = {}
    for chunk in value.split(";"):
        parts = chunk.split()
        if not parts:
            continue
        directives[parts[0].lower()] = [source.lower() for source in parts[1:]]
    return directives


def _effective_sources(directives: dict[str, list[str]], directive: str) -> list[str] | None:
    """Return the sources that apply to ``directive``, following default-src."""

    if directive in directives:
        return directives[directive]
    if directive == "frame-ancestors":
        return None  # frame-ancestors does not fall back to default-src
    return directives.get("default-src")


def analyze_csp(value: str) -> list[Finding]:
    """Report weaknesses in a Content-Security-Policy value."""

    directives = parse_csp(value)
    findings: list[Finding] = []

    for directive in FETCH_DIRECTIVES:
        sources = _effective_sources(directives, directive)
        if sources is None:
            if directive == "frame-ancestors":
                findings.append(
                    Finding(
                        "csp-no-frame-ancestors",
                        "medium",
                        "CSP does not set frame-ancestors",
                        "frame-ancestors does not inherit from default-src, so framing is"
                        " unrestricted by CSP.",
                    )
                )
            continue
        if "'unsafe-inline'" in sources:
            findings.append(
                Finding(
                    f"csp-unsafe-inline-{directive}",
                    "high" if directive == "script-src" else "medium",
                    f"CSP allows 'unsafe-inline' in {directive}",
                    "Inline content is permitted, which removes most of the XSS benefit of a CSP.",
                )
            )
        if "'unsafe-eval'" in sources:
            findings.append(
                Finding(
                    f"csp-unsafe-eval-{directive}",
                    "medium",
                    f"CSP allows 'unsafe-eval' in {directive}",
                    "String-to-code evaluation remains available to injected content.",
                )
            )
        if "*" in sources:
            findings.append(
                Finding(
                    f"csp-wildcard-{directive}",
                    "high" if directive == "script-src" else "medium",
                    f"CSP allows any origin in {directive}",
                    "A wildcard source permits loading from arbitrary hosts.",
                )
            )
        if directive == "script-src" and "data:" in sources:
            findings.append(
                Finding(
                    "csp-data-uri-script-src",
                    "high",
                    "CSP allows data: URIs in script-src",
                    "data: script sources are a well-known CSP bypass.",
                )
            )
    return findings


def analyze_hsts(value: str) -> list[Finding]:
    """Report weaknesses in a Strict-Transport-Security value."""

    findings: list[Finding] = []
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match:
        return [
            Finding(
                "hsts-no-max-age",
                "medium",
                "HSTS header has no max-age",
                "Without max-age the header has no effect.",
            )
        ]
    max_age = int(match.group(1))
    if max_age == 0:
        findings.append(
            Finding("hsts-max-age-zero", "medium", "HSTS max-age is 0", "This disables HSTS.")
        )
    elif max_age < MIN_HSTS_MAX_AGE:
        findings.append(
            Finding(
                "hsts-max-age-short",
                "low",
                f"HSTS max-age is {max_age}s, below the usual six-month baseline",
                f"Values under {MIN_HSTS_MAX_AGE}s leave a wide first-visit window.",
            )
        )
    if "includesubdomains" not in value.lower():
        findings.append(
            Finding(
                "hsts-no-subdomains",
                "low",
                "HSTS does not set includeSubDomains",
                "Subdomains are not covered by the policy.",
            )
        )
    return findings


def analyze_cookie(set_cookie: str) -> list[Finding]:
    """Report missing protective attributes on one Set-Cookie value."""

    name = set_cookie.split("=", 1)[0].strip() or "(unnamed)"
    lowered = set_cookie.lower()
    findings: list[Finding] = []
    if "httponly" not in lowered:
        findings.append(
            Finding(
                f"cookie-no-httponly-{name}",
                "medium",
                f"Cookie {name} is not HttpOnly",
                "Script can read the value, so XSS can exfiltrate it.",
            )
        )
    if "secure" not in lowered:
        findings.append(
            Finding(
                f"cookie-no-secure-{name}",
                "low",
                f"Cookie {name} is not marked Secure",
                "The cookie may be sent over plaintext HTTP.",
            )
        )
    if "samesite" not in lowered:
        findings.append(
            Finding(
                f"cookie-no-samesite-{name}",
                "low",
                f"Cookie {name} has no SameSite attribute",
                "Cross-site requests may carry the cookie.",
            )
        )
    return findings


def analyze_cors(headers: dict[str, str]) -> list[Finding]:
    """Report a permissive cross-origin policy.

    Added after a baseline capture against the authorized local lab target
    returned ``Access-Control-Allow-Origin: *`` on every endpoint reviewed,
    which this analyzer had no check for.
    """

    normalized = normalize_headers(headers)
    origin = normalized.get("access-control-allow-origin", "").strip()
    if origin != "*":
        return []

    credentials = normalized.get("access-control-allow-credentials", "").strip().lower()
    if credentials == "true":
        return [
            Finding(
                "cors-wildcard-with-credentials",
                "high",
                "CORS allows any origin together with credentials",
                "Any site could read authenticated responses if a browser honoured"
                " this combination.",
            )
        ]
    return [
        Finding(
            "cors-wildcard-origin",
            "medium",
            "CORS allows any origin",
            "Any site may read responses from this endpoint.",
        )
    ]


def analyze_headers(headers: dict[str, str]) -> list[Finding]:
    """Review one set of response headers end to end."""

    normalized = normalize_headers(headers)
    findings: list[Finding] = []

    if "content-security-policy" in normalized:
        findings.extend(analyze_csp(normalized["content-security-policy"]))
    else:
        findings.append(
            Finding(
                "missing-csp",
                "medium",
                "No Content-Security-Policy header",
                "The response carries no content restrictions.",
            )
        )

    if "strict-transport-security" in normalized:
        findings.extend(analyze_hsts(normalized["strict-transport-security"]))

    if normalized.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(
            Finding(
                "missing-nosniff",
                "low",
                "X-Content-Type-Options is not nosniff",
                "Browsers may MIME-sniff the response body.",
            )
        )

    if "x-frame-options" not in normalized:
        findings.append(
            Finding(
                "missing-x-frame-options",
                "low",
                "No X-Frame-Options header",
                "Legacy browsers without CSP frame-ancestors support are unprotected.",
            )
        )

    if "referrer-policy" not in normalized:
        findings.append(
            Finding(
                "missing-referrer-policy",
                "low",
                "No Referrer-Policy header",
                "Full URLs may leak to third parties in the Referer header.",
            )
        )

    findings.extend(analyze_cors(headers))

    for header in DISCLOSURE_HEADERS:
        if header in normalized:
            findings.append(
                Finding(
                    f"disclosure-{header}",
                    "info",
                    f"Response discloses {header}: {normalized[header]}",
                    "Version and stack detail helps an attacker select known exploits.",
                )
            )

    for cookie in _split_set_cookie(headers):
        findings.extend(analyze_cookie(cookie))

    return findings


def _split_set_cookie(headers: dict[str, str]) -> list[str]:
    """Collect Set-Cookie values, tolerating one joined header string."""

    values: list[str] = []
    for name, value in headers.items():
        if str(name).lower() != "set-cookie":
            continue
        values.extend(part for part in re.split(r",\s*(?=[^;=,]+=)", str(value)) if part.strip())
    return values


def assess_response(url: str, status: int, headers: dict[str, str]) -> Assessment:
    """Build an assessment from an already-captured response."""

    return Assessment(url=url, status=status, findings=analyze_headers(headers))


def assess_target(url: str, timeout: float = 5.0) -> Assessment:
    """Fetch one authorized loopback URL and assess it.

    The boundary is checked here and again inside ``fetch_headers``; the
    duplication is deliberate, so a future refactor cannot remove it silently.
    """

    require_loopback_url(url)
    response = fetch_headers(url, timeout=timeout, method="GET")
    return assess_response(url, int(response["status"]), dict(response["headers"]))
