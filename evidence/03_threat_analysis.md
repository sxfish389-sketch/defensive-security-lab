# Indicator matching

**Supports the CVP category "Threat Intelligence & Malware Analysis": no.**

`ioc_matcher.py` performs boundary-anchored matching with defang normalisation
(`evil[.]com`, `hxxp://`), CIDR containment rather than string equality, hash
type inference by digest length, and allowlist suppression.

It replaced a substring matcher that reported `1.2.3.4` as present in
`11.2.3.45` and `evil.com` in `notevil.com.br`; both are pinned as regressions.

The tooling is real, but every indicator is synthetic and drawn from reserved
namespaces. No malware sample, threat feed, or customer telemetry has been
handled, so the category is not claimed.
