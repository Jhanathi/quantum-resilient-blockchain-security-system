# API and route security inventory

The registered Flask route map is the source of truth. The complete
route-by-route inventory is maintained in [`API_ENDPOINTS.csv`](./API_ENDPOINTS.csv)
and includes methods, path, endpoint, purpose, authentication, role,
CSRF policy, rate limit, input format, important response codes, and relevant
tests. [`tests/test_route_inventory.py`](../tests/test_route_inventory.py)
compares every CSV entry with `app.url_map`, including implicit `HEAD` and
`OPTIONS` methods and the static route. An unlisted or removed route fails the
check.

## Reviewed access policy

- Customer pages and APIs require a signed Flask session and enforce account
  ownership. Administrative views require `ADMIN`; security and research
  consoles require `ADMIN` or `SECURITY_ANALYST`, except the security test
  route, which is intentionally analyst-only.
- The Module 12 security lab is limited to `ADMIN` and `SECURITY_ANALYST`.
  Every demonstration uses a fresh in-memory SQLite database populated only
  with synthetic records; results are process-local and are not written to the
  financial ledger or audit logs.
- The Module 13 security audit dashboard, event APIs, and exports are limited
  to `ADMIN` and `SECURITY_ANALYST`. They read the persistent
  `security_audit_events` table; Module 12 simulation events are explicitly
  marked as demo data.
- `/`, `/login`, `/register`, `/health`, `/healthz`, the ephemeral signature
  demo APIs, and legacy in-memory demo blocks are intentionally public. The
  `/api/transaction`
  endpoint is a legacy in-memory signature demonstration and does not debit or
  credit real accounts. It is CSRF-protected and rate-limited. There are no
  machine-to-machine routes; all mutating APIs require a browser session CSRF
  token, including login and registration.
- `GET /static/<path:filename>` serves from the `static` asset directory only.
  Application code, database files, and other project-root files are not
  exposed through this endpoint.
- Read-only GET routes do not require CSRF tokens. Every currently registered
  POST route is checked for a session-bound token from `X-CSRF-Token` or the
  `csrf_token` form field.

## Shared security controls

- Authentication requests are limited to 5 requests per 300 seconds for each
  source-IP-and-identity bucket. Successful login clears that bucket.
- Registration allows 10 requests per hour per source IP. Money transfers allow
  10 requests per minute per authenticated user. Module 12 lab runs and resets
  allow 10 requests per minute per authenticated user. Other sensitive writes
  and Module 13 audit reads/exports allow 30 requests per minute per user or
  source IP. Rejections return HTTP 429 and `Retry-After`.
- Limits are atomic upserts in the configured application database. Workers
  and instances sharing that database share counters; rate-limit storage
  failures return HTTP 503 rather than silently switching to a process-local
  counter. SQLite, PostgreSQL, MySQL, and MariaDB are supported by the upsert
  implementation. The automated tests exercise SQLite; deployment-specific
  integration testing remains necessary for PostgreSQL/MySQL/MariaDB.
- `X-Forwarded-For` is ignored unless `TRUSTED_PROXY_CIDRS` explicitly lists
  the remote proxy network. Configure those CIDRs only for proxies that
  overwrite or append the client address safely.
- Authenticated sessions use a 30-minute idle timeout and a 12-hour absolute
  timeout by default. `SESSION_IDLE_TIMEOUT_SECONDS` and
  `SESSION_ABSOLUTE_TIMEOUT_SECONDS` configure them. Login clears old state,
  rotates the CSRF token, and marks the session permanent; logout clears it.
- Transfer creation requires `Idempotency-Key`. Keys are unique per user and
  transfer operation. A retry with the same payload returns the original
  response; reuse with a different payload returns HTTP 409. Concurrent
  duplicate requests either receive the stored response or a 409 while the
  original request is still processing and can retry with the same key.
- `POST /api/users/me/accounts` creates only an account owned by the current
  session user; account creation is unfunded and limited to the supported
  account types. `POST /api/deposits` is an authenticated, ownership-checked,
  CSRF-protected simulated credit with its own `deposit:create` idempotency
  scope. It records `DEPOSIT` as a separate hash-linked ledger entry and is
  rate-limited like transfer creation. It is not an external bank payment and
  does not use the transfer AQRS/ML-DSA signature path.

## Verification

Run the inventory and database-safety checks from the project directory:

```powershell
.\venv\Scripts\python.exe -m pytest -q tests\test_database_safety.py tests\test_route_inventory.py
```

The isolation and broader security/regression commands are documented in
[`../tests/README.md`](../tests/README.md). Concurrency results on SQLite do not
prove production database behavior; deployment should run concurrent transfer
and duplicate-key integration tests against the exact production database
engine and isolation level.
