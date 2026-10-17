# Test suite

Run the suite from the project directory in Windows PowerShell:

```powershell
.\venv\Scripts\python.exe -m pytest -q
```

The root `conftest.py` configures `TEST_DATABASE_URL` and refuses test startup
when `DATABASE_URL` points to a different database. The test database must be an
isolated SQLite file or in-memory database; the live `pqbank.db` is not a test
target. `tests/test_database_safety.py` verifies this configuration and checks
that the production database path is recognized even when expressed as an
absolute path.

The test client in `tests/conftest.py` automatically fetches a session CSRF
token for state-changing requests and adds an idempotency key to transfer
requests. Tests that verify rejection behavior must opt out explicitly with
`csrf=False` or `idempotency=False`.

## Focused validation

```powershell
.\venv\Scripts\python.exe -m pytest -q tests\test_database_safety.py tests\test_route_inventory.py
.\venv\Scripts\python.exe -m pytest -q tests\test_module11_controls.py tests\test_module11_system.py
```

`docs/API_ENDPOINT_INVENTORY.md` describes the reviewed access policy and
production configuration. `docs/API_ENDPOINTS.csv` is the route-by-route
inventory and is checked against Flask's registered route map.

## Coverage map

- `test_auth.py`, `test_module11_auth.py`: registration, password hashing,
  authentication, logout, password change, session revocation, and RBAC.
- `test_module3.py`, `test_registration_accounts.py`: accounts, cross-user
  transfers by recipient account number, validation, balances, transaction
  history, and transaction audit events.
- `test_module4.py`: AQRS decision policy and exact risk threshold boundaries.
- `test_module5.py`: real ML-DSA signatures, signed-field tampering, and
  verification with a different public key.
- `test_module6.py`: persistent blockchain creation and integrity/tamper
  validation.
- `test_module7.py`, `test_module8.py`: UI/API integration, ownership, role
  separation, analytics, and sensitive response fields.
- `test_module9.py`: research modes, metric validation, persistence, invalid
  configuration, and failed-run status.
- `test_module10_security.py`, `test_module11_system.py`: security headers,
  cookie controls, shared login throttling, API role matrix, malformed
  requests, safe errors, transaction rollback, and isolated-database checks.
- `test_module11_controls.py`: CSRF enforcement, shared rate limits, trusted
  proxy handling, transfer idempotency, duplicate-request concurrency, and
  idle/absolute session expiration.
- `test_module12_security_lab.py`: isolated demo scenarios, existing verifier
  outcomes, reset/repeat behavior, access control, CSRF, error reporting, and
  production-data isolation.
- `test_module13_security_audit.py`: persistent audit service, secret-safe
  metadata, event instrumentation, role-protected dashboard/filter/detail APIs,
  CSV/JSON exports, and report-generation events.
- `test_route_inventory.py`: endpoint inventory completeness, mutating-route
  policy coverage, and static-file serving boundaries.
- `test_database.py`: schema constraints and ORM relationships.

## Security controls and limits

- All mutating browser requests require the session-bound token sent in
  `X-CSRF-Token` (or the supported form field). Login rotates the token.
- Transfer POSTs require `Idempotency-Key`; same-key/same-payload retries replay
  the original response, while reuse with a different payload returns HTTP
  409. The key and transaction are persisted together so failed transfers do
  not consume the key.
- Rate-limit counters are stored in the configured application database and
  shared by workers using that database. Defaults are 5 login attempts per
  300 seconds per source-IP/identity bucket, 10 registrations per hour per
  source IP, 10 transfers per minute per authenticated user, and 30 other
  sensitive writes per minute per user or source IP.
- Forwarded client IP addresses are trusted only when the immediate peer
  matches a CIDR listed in `TRUSTED_PROXY_CIDRS`.
- Authenticated sessions expire after 30 minutes idle or 12 hours absolute by
  default. Set `SESSION_IDLE_TIMEOUT_SECONDS` and
  `SESSION_ABSOLUTE_TIMEOUT_SECONDS` to change those limits.
- SQLite tests cover atomic transfer rollback, conditional debits, and duplicate
  request behavior. They do not certify PostgreSQL/MySQL/MariaDB deployment
  concurrency or isolation behavior; run integration tests against the exact
  production engine and isolation level before deployment.

Tests must use synthetic users and credentials. Never include real secrets,
private keys, or production account data in fixtures or assertions.
