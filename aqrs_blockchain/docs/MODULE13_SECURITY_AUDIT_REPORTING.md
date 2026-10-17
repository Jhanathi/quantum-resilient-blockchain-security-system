# Module 13: Security Audit & Reporting

## Architecture and schema

The module adds `SecurityAuditEvent` in
`backend/models/security_audit_event.py` and the reusable service in
`backend/services/security_audit_service.py`. It uses the application's
existing SQLAlchemy `Base`, `SessionLocal`, database configuration, Flask
session authentication, CSRF checks, and database-backed shared rate limiter.
The existing `AuditLog` model and legacy audit API remain available.

The new `security_audit_events` table is created by the application's existing
`Base.metadata.create_all` startup initialization. Creating this table does
not drop or recreate existing tables or rows. Existing audit-log rows are not
automatically copied into the new schema.

Each event includes a UUID, event type and category, severity (`INFO`, `LOW`,
`MEDIUM`, `HIGH`, `CRITICAL`), title and description, UTC timestamp, actor ID
and optional username/email snapshots, target, outcome (`SUCCESS`, `FAILURE`,
`BLOCKED`), source, request correlation ID, demo marker, and JSON metadata.
Indexes support filtering and time-ordered queries. There are no normal
application update/delete routes for events.

The central service validates event fields, constrains metadata to JSON-safe
values and 8 KiB, strips secret-like metadata keys (passwords, secrets, tokens,
cookies, credentials, private keys, authorization and session fields), and
limits nested structure and field lengths. Display and reports handle invalid
stored metadata by omitting it safely. The Flask integration persists each
event in its own short database transaction, so audit writes do not join or
commit an in-flight banking transaction. Persistence failures are recorded in
the server log by exception type and do not expose details to clients.

## Instrumented events

The application records sign-in success/failure, inactive account sign-in,
sign-out, registration/account creation, role and authentication denials,
session expiry, CSRF failures, rate-limit blocks, transfer success/rejection,
idempotency conflicts, blockchain validation, Module 12 lab executions and
resets, and report exports. Module 12 events are marked `DEMO` and
`is_demo=true`; they describe a controlled simulation and are never represented
as production incidents.

Severity indicates operational significance: ordinary successes are `INFO`,
validation and authentication failures are generally `LOW` or `MEDIUM`,
authorization failures are `MEDIUM`, account-ownership violations are `HIGH`,
and failed blockchain validation is `HIGH`. Demonstrations remain informational
regardless of the simulated verifier result.

Sensitive material is not passed to the security-event metadata. In
particular, login records do not include attempted passwords or raw account
credentials, and lab records do not include cryptographic secrets.

## Authorization and dashboard

Only `ADMIN` and `SECURITY_ANALYST` users may view `/security/audit` or its
API/export routes. Authentication and role checks use the existing Module 11
decorators. Audit reads and exports are limited to 30 requests per minute per
user by the shared rate limiter. Audit records are query-only through this
module.

The dashboard uses database aggregates for event totals, the previous 24-hour
count, high/critical events, failures/blocks, operational/demo counts, severity
and category distributions, and recent events. The paginated event API supports
inclusive start/end date filters, severity, category, event type, outcome,
actor, operational/demo mode, title/description search, and timestamp
ascending/descending order. Page size is capped at 100.

## Reports

Use **Download CSV** or **Download JSON** on the dashboard, or request:

- `/api/security/audit/export.csv`
- `/api/security/audit/export.json`

Both report routes accept the same validated filters as the paginated view.
Exports are capped at 10,000 rows and include generation time, selected
filters, total matching count, exported row count, and safe event details.
CSV values beginning with spreadsheet formula characters are prefixed with an
apostrophe. Export actions are themselves recorded once in the audit stream;
the export query is completed before recording that report event, preventing a
recursive export loop.

## Database initialization, tests, and manual check

There is no separate migration framework in this project. Startup
`create_tables()` creates only missing tables. Do not drop or reset the
application database to install this module. Tests use the repository's
isolated SQLite test database, never `pqbank.db`.

Run focused tests:

```powershell
.\venv\Scripts\python.exe -m pytest -q tests\test_module13_security_audit.py tests\test_route_inventory.py
```

Run the full regression suite:

```powershell
.\venv\Scripts\python.exe -m pytest -q
```

To verify manually, run the Flask app from `aqrs_blockchain` with the
appropriate `SECRET_KEY` and `DATABASE_URL`, sign in as an admin or security
analyst, visit `/security/audit`, filter events, open details, and download both
formats. Confirm that a customer and an anonymous browser cannot access the
page, detail APIs, or exports. Run and reset a Module 12 demonstration and
check that it appears as `DEMO / SIMULATION`, not a production attack.

## Limitations

- Events are persistent application records, but database storage is not
  cryptographically immutable. No claim of append-only physical storage or
  resistance to a privileged database administrator is made.
- Security-event writes use independent commits to protect banking transaction
  boundaries. If storage fails, the application logs the failure and proceeds
  with the banking action; deployments requiring a transactional outbox or
  fail-closed audit policy need a separate operational decision.
- Exports are intentionally bounded to 10,000 rows; larger reports require
  narrower date or event filters.
- Existing legacy `AuditLog` history is not migrated automatically. The
  existing legacy audit API remains separate from Module 13 records.
- This dashboard reports events emitted by the application. It does not
  replace infrastructure monitoring, external log retention, or incident
  response.
