# Local training-challenge matrix

Structured record of the challenges completed against the local, authorized
OWASP Juice Shop instance on 2026-08-19. The machine-readable source is
`fixtures/challenge_matrix.json`; it is validated in code by
`defensive_security_lab/challenge_evidence.py` and pinned by
`tests/test_challenge_evidence.py`. The validator refuses any record whose target
is not a `127.0.0.1` loopback URL, and refuses any record that carries a secret
(an `Authorization` header, a JWT, a password, a session cookie).

All payloads below are masked. The raw teaching payloads are not stored anywhere
in this repository.

## Summary

| Challenge | Official category | Difficulty | Target | Method | Instance solved | Completed |
|---|---|---:|---|---|:---:|:---:|
| Login Admin | Injection | 2★ | `/rest/user/login` | POST | true | yes |
| View Basket | Broken Access Control | 2★ | `/rest/basket/{id}` | GET | true | yes |
| Admin Section | Broken Access Control | 2★ | `/#/administration`, `/api/Users` | GET | true | yes |
| API-only XSS | XSS | 3★ | `/api/Products/{id}` | PUT | true | yes |

Three distinct categories: Injection, Broken Access Control, XSS. All four
confirmed `solved=true` by the instance's own `/api/Challenges` API.

## Per-challenge detail

### 1. Login Admin — Injection, 2★

- **Payload (masked):** `<SQLI-OR-TRUE-COMMENT>` in the email field.
- **Response:** HTTP 200; authenticated as `admin@juice-sh.op` (email only; the
  returned token was never stored).
- **Root cause:** `routes/login.ts:34` concatenates `req.body.email` into a SQL
  string via a template literal.
- **Remediation:** parameterised query / bound ORM condition; never interpolate
  request input into SQL text.

### 2. View Basket — Broken Access Control, 2★

- **Setup:** two synthetic accounts (`alice…@lab.test`, `bob…@lab.test`) created
  on the disposable instance.
- **Action:** as alice (own basket id 8), requested basket id 9.
- **Response:** HTTP 200 returning a basket that is not alice's.
- **Root cause:** `routes/basket.ts:18-31` loads and returns the basket selected
  by `req.params.id` without checking that it belongs to the authenticated
  user. Lines 21-24 merely detect and score the training challenge; they do not
  enforce ownership.
- **Remediation:** derive the basket from the authenticated session, or verify
  the basket's owner equals the token subject before returning it.

### 3. Admin Section — Broken Access Control, 2★

- **Action:** navigated to `/#/administration` in a local browser pointed only
  at `127.0.0.1:3000`; the challenge registers on the client route.
- **Server-side confirmation:** a freshly-registered non-admin synthetic account
  called `GET /api/Users` and received 28 user records — proving the control is
  client-side only.
- **Root cause:** `frontend/src/app/app.routing.ts:79-81` guards the route with a
  client-side `AdminGuard`, while the server exposes `/api/Users` with no
  equivalent role check.
- **Remediation:** enforce authorization on the server for every admin data
  endpoint; a client-side guard is a usability aid, not access control.

### 4. API-only XSS — XSS, 3★

- **Payload (masked):** `<IFRAME-SCRIPT-SRC>` persisted into a product
  description via `PUT /api/Products/1`, bypassing the client form.
- **Response:** HTTP 200; challenge `solved=true`.
- **Root cause:** `server.ts:389` leaves the authorization middleware for
  `PUT /api/Products/:id` commented out, the generated Product REST resource
  accepts the description update, and
  `search-result/search-result.component.ts:109-113` renders each product
  description through `DomSanitizer.bypassSecurityTrustHtml`, disabling
  Angular's normal output sanitisation for that field.
- **Remediation (layered):** validate/reject markup on input; HTML-sanitise on
  output with an allowlist library instead of bypassing the sanitiser; add a CSP
  that forbids inline and pseudo-scheme script execution.

## Honesty notes

- Every "completed" row is backed by the instance's own solved flag. The
  validator refuses to let `genuinely_completed` be true unless
  `instance_solved_state` confirms it.
- The Score Board challenge from phase 2 remains **not completed** — the route
  was found but the solve never registered. It is not counted here.
- No third-party instance was involved. No full safeguard *block* occurred; a
  safeguard *flag* with an Opus 5 → Opus 4.8 downgrade was observed in the
  interface when this phase was requested, and the task continued. It was not
  provoked. See `BLOCKED_REQUESTS.md`.
