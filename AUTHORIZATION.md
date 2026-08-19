# Authorization and scope

All tests in this repository are limited to assets controlled by the maintainer
or to deliberately synthetic fixtures:

- loopback addresses (`127.0.0.0/8`, `::1`, and `localhost`);
- reserved example domains ending in `.test`;
- documentation-only IP ranges such as `203.0.113.0/24`;
- synthetic authentication events; and
- local filename strings that are never written outside a temporary test area.

The tools are not authorized for scanning public systems, third-party accounts,
production services, or networks outside the operator's control. The
localhost-audit component enforces this boundary in code.

