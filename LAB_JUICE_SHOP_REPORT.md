# Local lab assessment: OWASP Juice Shop

A small, bounded assessment of a deliberately vulnerable application running on
this machine only. Nothing in this report is a discovery about Juice Shop. Every
observation is a known teaching scenario the project publishes on purpose.

## 1. Authorization

| Item | Value |
|---|---|
| Target software | OWASP Juice Shop 20.2.0 |
| Upstream repository | https://github.com/juice-shop/juice-shop |
| Commit assessed | `1618a611b173b4bf114028e6e02549950606e29d` |
| Upstream commit date | 2026-08-10T21:37:49Z |
| Fetched (UTC) | 2026-08-19T20:25:54Z |
| Licence | MIT |
| Basis for authorization | The project publishes the application expressly as an insecure application for security trainings, awareness demos, CTFs and "as a guinea pig for security tools". Running a local copy for that purpose is its stated use. |
| Instance | Local only, `127.0.0.1:3000`, started and stopped by the operator |

**Third-party instances were not touched.** The upstream README states of its
public demo that you are *"not supposed to use this instance for your own
hacking endeavours"*. No request in this assessment went to
`demo.owasp-juice.shop` or to any host other than `127.0.0.1`.

## 2. Runtime and the loopback binding problem

| Item | Value |
|---|---|
| Node baseline | v24.19.0, obtained with `npx --yes node@24` |
| npm | 11.12.1, run under the Node 24 binary |
| System Node | v25.9.0 — deliberately **not** used as the baseline |
| Container runtime | none available (no Docker, Podman, or Colima) |
| Install command | `npm install --no-audit --no-fund` (official README step 4) |
| Start command | `node build/app` (official README step 5), `PORT=3000` |

### The application does not bind to loopback by default

Upstream `server.ts` calls:

```ts
server.listen(port, () => { ... })
```

Node treats a missing host argument as `0.0.0.0`, so an unmodified Juice Shop is
reachable from the whole local network. There is no supported configuration
option for the bind address: `config/default.yml` exposes only `server.port`,
`server.basePath` and `server.baseUrl`, and the only related environment
variables are `PORT` and `BASE_PATH`.

A one-line local patch was therefore applied before the first start, recorded in
full at `.lab_runtime/loopback_bind.patch`:

```diff
-  server.listen(port, () => {
+  // LOCAL LAB PATCH (not upstream): bind to the loopback interface only.
+  // Upstream calls server.listen(port, ...) with no host, which makes Node bind
+  // 0.0.0.0 and expose this deliberately vulnerable application to the LAN.
+  server.listen(Number(port), '127.0.0.1', () => {
```

`Number(port)` is required: with a bare string host argument `tsc` reports
`TS2769: No overload matches this call`. The first build emitted output despite
that error — TypeScript does not set `noEmitOnError` here — so the patch reached
`build/server.js` anyway. That is a fragile way to be right, so the type was
fixed and the server rebuilt cleanly (`npm run build:server`, exit 0).

### Binding verified three ways before any request

```
lsof   -> node 53166 ... TCP 127.0.0.1:3000 (LISTEN)
netstat-> tcp4  127.0.0.1.3000  *.*  LISTEN
```

Negative control: this host's LAN address is `192.168.2.151`, and
`curl http://192.168.2.151:3000/` returned HTTP `000` (connection failed),
confirming the service was not reachable off the loopback interface.

## 3. Scope of requests issued (phase 2)

Every request was a read-only `GET` to `http://127.0.0.1:3000`. No credentials
were submitted, no account was created, no data was modified or deleted, and no
token or personal data was retained.

**Request count, stated honestly.** An earlier version of this report showed
seven table rows and called it "seven requests". That conflated table rows with
requests: row 4 alone was three separate GETs, and several endpoints were fetched
more than once during exploration. Reconstructed from the command record, phase 2
issued approximately **19 HTTP requests across 8 unique endpoints**. The table
below lists the unique endpoints, not a request total.

| Unique endpoint | Result |
|---|---|
| `GET /` | 200 — baseline headers (fetched several times) |
| `GET /rest/products/search?q=` | 200 — second endpoint for comparison |
| `GET /api/Challenges/` | 200 — official challenge metadata |
| `GET /polyfills.js` | 200 — client bundle |
| `GET /scripts.js` | 200 — client bundle |
| `GET /main.js` | 200 — client bundle (fetched several times) |
| `GET /#/score-board` | 200 — fragment; never sent to the server |
| `GET /ftp`, `GET /ftp/acquisitions.md` | 200 — directory listing and document |

Phase 3 (§8) logged every request individually to avoid reconstructing the count
after the fact.

## 4. Baseline security-header review

Performed with this repository's own `web_assessment` module against `GET /`:

| Severity | Finding | Observation |
|---|---|---|
| medium | `cors-wildcard-origin` | `Access-Control-Allow-Origin: *` on every endpoint reviewed |
| medium | `missing-csp` | no `Content-Security-Policy` header |
| low | `missing-referrer-policy` | no `Referrer-Policy` header |

Headers that were present and correct: `X-Content-Type-Options: nosniff`,
`X-Frame-Options: SAMEORIGIN`, and a `Feature-Policy: payment 'self'`.

**This assessment improved the tool, not the target.** The analyzer had no CORS
check at all until the capture showed `ACAO: *`; `analyze_cors()` and four tests
were added in response. That is the honest value of this exercise: pointing a
detector at real traffic exposed a gap in the detector.

The response was captured to `fixtures/juice_shop_baseline.json` with volatile
headers (`Date`, `ETag`, `Last-Modified`, …) stripped, so
`tests/test_web_assessment.py` replays it deterministically and CI never needs to
start a vulnerable application.

## 5. Training challenges attempted

Two official 1-star challenges, both unsolved on this instance beforehand.

### Confidential Document — completed

- Category: Sensitive Data Exposure. Official description: "Access a
  confidential document."
- `GET /ftp` returned a browsable directory listing.
- `GET /ftp/acquisitions.md` returned 200 with readable content.
- The instance's own API confirmed the result: `solved=True`.

### Score Board — discovered, not registered

- Category: Miscellaneous. Official description: "Find the carefully hidden
  'Score Board' page."
- The intended technique is reading the client bundle. `GET /main.js`
  (1,207,732 bytes) contains the hidden route seven times, including
  ``routerLink`,`/score-board`,`aria-label`,`Open score-boa…``
- `GET /#/score-board` returned 200.
- **The challenge still reports `solved=False`**, and that is reported as-is.
  The fragment `#/score-board` is never sent to the server, and the solve is
  registered by the Angular application at runtime; a headless `curl` client
  does not trigger it. The route was found; the flag was not earned.

Final state: 1 of 116 challenges solved on this instance.

## 6. What this exercise does and does not evidence

**Does:**

- A defensive tool was pointed at real traffic and a real gap in it was found
  and fixed.
- An authorization boundary was designed, enforced in code, and verified by
  three independent means, including a negative control.
- A genuine deployment hazard was identified and mitigated before exposure: the
  upstream project binds `0.0.0.0` with no supported way to change it.

**Does not:**

- No vulnerability in Juice Shop was discovered. Both scenarios are published
  training exercises with official descriptions.
- No third-party system was tested.
- Phase 2 was introductory: two 1-star challenges, one of them incomplete. The
  separately recorded phase-3 work below completed four additional challenges.

## 7. Hygiene

- Juice Shop source, `node_modules`, build output, and its SQLite database live
  under `.lab_runtime/`, outside this repository, and are not committed.
- The service was stopped after the assessment. Verified four ways: `lsof` shows
  no listener on 3000, `netstat` agrees, no `build/app` process remains, and
  `curl http://127.0.0.1:3000/` returns `000`.
- Nothing retained from the target contains credentials, tokens, or personal
  data. The only artifact kept is the header capture, with volatile fields
  removed.

---

# Phase 3 — authorized training-challenge assessment (2026-08-19)

Same machine, same local instance, same boundary. This phase completed four
official training challenges across three vulnerability classes. The structured
records are in `LAB_CHALLENGE_MATRIX.md` and `fixtures/challenge_matrix.json`,
validated in code.

## 8. Boundary re-verification

Before starting, the loopback patch was confirmed present in the build output:

```
build/server.js:731  server.listen(Number(port), '127.0.0.1', () => {
```

After starting, the binding was verified three ways again:

```
lsof    -> node 4100 ... TCP 127.0.0.1:3000 (LISTEN)
netstat -> tcp4  127.0.0.1.3000  *.*  LISTEN
```

Negative control: `curl http://192.168.2.151:3000/` (this host's LAN address)
returned HTTP `000` — not reachable off loopback.

## 9. Requests issued (phase 3, logged individually)

Unlike phase 2, every request was logged as it was made. Totals:

- Challenge 1 runner: 2 requests (1 login attempt + 1 solved-state check).
- Challenges 2–4 runner: 8 requests (2 account registrations, 2 logins, 1
  cross-user basket read, 1 product write, 2 solved-state checks).
- Admin Section: 1 server-side probe (`GET /api/Users`) plus a local browser
  navigation to `/#/administration` and one login fetch executed in-page.
- Solved-state re-checks: a small number of additional `GET /api/Challenges`.

Every request targeted `http://127.0.0.1:3000`. Account registrations and the
product write were made against the disposable local instance, as the phase-3
authorization explicitly permits. Two synthetic accounts (`alice…@lab.test`,
`bob…@lab.test`) were created; no real personal data was used.

## 10. Challenges completed

| Challenge | Category | ★ | Method | Instance solved |
|---|---|---:|---|:---:|
| Login Admin | Injection | 2 | POST `/rest/user/login` | true |
| View Basket | Broken Access Control | 2 | GET `/rest/basket/{id}` | true |
| Admin Section | Broken Access Control | 2 | client route + GET `/api/Users` | true |
| API-only XSS | XSS | 3 | PUT `/api/Products/{id}` | true |

Full per-challenge root cause and remediation are in `LAB_CHALLENGE_MATRIX.md`.
All four were confirmed `solved=true` by the instance's own API.

## 11. Sensitive-data handling

- Session tokens were held in memory (Python variables, browser `localStorage`
  during the one browser step) and were **never written** to any file in this
  repository. The browser `localStorage` token was cleared before the tab closed.
- Every teaching payload is **masked** in the matrix (`<SQLI-OR-TRUE-COMMENT>`,
  `<IFRAME-SCRIPT-SRC>`).
- `challenge_evidence.py` enforces this in code: it refuses any record
  containing an `Authorization`/`token`/`password`/`cookie` field or a
  JWT/bearer-shaped value, and refuses any non-loopback target URL. A grep of the
  committed matrix for `javascript:`, `or 1=1`, `eyJ`, and the lab password
  returns nothing.

## 12. Shutdown verification (phase 3)

The service was stopped and verified four ways:

- `lsof` — no listener on port 3000;
- `netstat` — no `3000` LISTEN;
- no `build/app` process remains;
- `curl http://127.0.0.1:3000/` returns `000`.

## 13. What phase 3 does and does not evidence

**Does:** four official training challenges completed across Injection, Broken
Access Control, and XSS, each with the upstream root cause located in source and
a concrete remediation written; all confirmed by the instance's own solved flag;
a validator that keeps the evidence free of secrets and non-loopback targets.

**Does not:** this is an explicitly authorized *local training* assessment. It is
not a professional red-team engagement, not a client project, and not a discovery
— every challenge is a published exercise with an official description and
companion-guide walkthrough. The work demonstrates hands-on understanding of
these vulnerability classes and their fixes at an introductory-to-intermediate
level, nothing beyond that.
