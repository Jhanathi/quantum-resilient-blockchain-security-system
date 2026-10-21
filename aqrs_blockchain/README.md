# PQBank

Adaptive Post-Quantum Secure Banking Using Blockchain and AQRS.

## Problem Statement

This project addresses the research question: how can adaptive post-quantum cryptographic security be applied to blockchain-based financial transactions while balancing security and computational/storage overhead?

The current repository is a working prototype focused on research validation and benchmarking. It compares classical ECDSA with post-quantum Dilithium signatures, adapts the signature strength to transaction risk via AQRS, and evaluates the resulting blockchain performance.

## Research Contribution

The central research contribution is the Adaptive Quantum-Readiness Scoring (AQRS) layer. It maps transaction risk to a suitable Post-Quantum security level:

- LOW -> Dilithium Level 2
- MEDIUM -> Dilithium Level 3
- HIGH -> Dilithium Level 5

The project measures the trade-off between stronger cryptographic protection and increased signing time, verification time, signature size, and blockchain footprint.

## CURRENTLY IMPLEMENTED

- Transaction generation with risk classification
- ECDSA signing and verification
- Dilithium Level 2, Level 3, and Level 5 signing and verification
- AQRS-based security-level selection
- Simple blockchain chaining with block creation and chain-size metrics
- Offline simulation for ECDSA, DIL2, DIL3, DIL5, and AQRS modes
- Plot generation for timing, size, throughput, and AQRS comparison
- Flask-based prototype API for transaction and signature experimentation

## PLANNED

- Banking user and account model
- Authentication and authorization
- Persistent database layer
- REST API design for real banking workflows
- Modular service architecture
- Frontend pages for customer and admin/researcher flows
- Long-term production-grade blockchain integration
- Audit, tamper detection, and analytics services

## Existing Architecture

The current prototype is a single-layer research implementation with responsibilities concentrated in a few modules:

- `main.py` orchestrates the benchmark pipeline
- `transaction_generator.py` creates synthetic transactions and risk labels
- `signature_engine.py` wraps ECDSA and Dilithium operations
- `blockchain.py` maintains the chain and pending transactions
- `simulation.py` runs one benchmark mode and aggregates metrics
- `aqrs_calculator.py` calculates AQRS scores
- `visualizer.py` generates plots and summary output
- `app.py` exposes a Flask API that mixes transaction processing, signing, verification, and blockchain logic in one place

## Target Architecture

The final architecture will separate the system into the following layers:

1. Presentation Layer
2. API Layer
3. Service Layer
4. Domain/Core Layer
5. Persistence Layer
6. Research Layer

The project is intentionally planned to evolve into:

- a banking application for real transactions and user flows
- a research lab for benchmarking and simulation
- a shared core for AQRS, cryptography, and blockchain logic

## Technology Stack

- Python 3
- Flask
- cryptography
- dilithium-py
- matplotlib
- pandas
- JSON-based research artifacts

## Module 2: Authentication & Authorization

This repository now includes the Module 2 foundation for secure banking access control. It keeps the original research engine unchanged while adding a database-backed authentication layer on top of the existing `User`, `Account`, and `AuditLog` models created in Module 1.

### Authentication architecture

```text
Client
↓
Auth API
↓
Authentication Service
↓
User Repository
↓
Database
```

```text
Request
↓
Authentication
↓
User
↓
Role Authorization
↓
Protected Resource
```

### Authentication mechanism

- Session-based authentication is used with Flask server-side sessions.
- Passwords are hashed using Werkzeug's `generate_password_hash` and validated with `check_password_hash`.
- Secrets are loaded from environment variables via `.env.example`.
- The identity used for authorization is always loaded from the database user record, never from client-provided role input.
- JWT is not required for this module because the project already uses Flask sessions and the auth scope is intentionally limited to the prototype stage.

### Roles

- `CUSTOMER`: default role for public registration.
- `ADMIN`: protected administrative access.
- `SECURITY_ANALYST`: protected research/security access.

### Authorization rules

- Public registration can only create `CUSTOMER` users.
- `ADMIN` is required for `/api/admin/test`.
- `SECURITY_ANALYST` is required for `/api/security/test`.
- Customers can only access their own accounts via `/api/accounts/<account_id>`.
- Admins may access protected account views for oversight, but customer ownership checks remain enforced for normal users.

### API endpoints

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/admin/test`
- `GET /api/security/test`
- `GET /api/users/me/accounts`
- `GET /api/accounts/<account_id>`

### Environment variables

Set these variables in the shell that starts the application. The project does not automatically load a `.env` file:

```bash
SECRET_KEY=your-local-secret
JWT_SECRET_KEY=your-local-jwt-secret
DATABASE_URL=sqlite:///./pqbank.db
DATABASE_ECHO=false
```

### Safe database configuration and testing

The application uses a single, explicit SQLite database path derived from the project root. The production database is always `pqbank.db` in the repository root. Tests must never operate against that file; they are redirected to `test_pqbank.db` by the test configuration. This prevents resets or cleanup from destroying the live application state.

For Windows CMD, start the app from the repository root with:

```cmd
cd /d C:\Users\JHANATHI M V\Desktop\Quantum-Ressiliant-Blockchain\aqrs_blockchain
set SECRET_KEY=my-local-secret
set DATABASE_URL=sqlite:///./pqbank.db
python app.py
```

Run tests against the isolated database with:

```cmd
cd /d C:\Users\JHANATHI M V\Desktop\Quantum-Ressiliant-Blockchain\aqrs_blockchain
set TEST_DATABASE_URL=sqlite:///./test_pqbank.db
set DATABASE_URL=sqlite:///./test_pqbank.db
python -m pytest tests/test_auth.py -q
python -m pytest -q
```

If a target file is accidentally set to the production database during tests, the project now aborts with a clear error rather than dropping or recreating the live schema.

Back up the live SQLite database before any schema changes or data migration work:

```cmd
cd /d C:\Users\JHANATHI M V\Desktop\Quantum-Ressiliant-Blockchain\aqrs_blockchain
copy pqbank.db "C:\temp\pqbank_backup_before_migration.db"
```

Check that the backup file is readable and contains the expected tables before continuing. Do not overwrite the backup with a copy made after data loss. Use differences or a fresh backup if the main database has already been reset.

### Customer accounts, transfers, and simulated deposits

- Each customer may own multiple accounts. Existing `User.accounts` / `Account.user_id` relationships are reused; additional accounts are created with `POST /api/users/me/accounts` and are initially unfunded.
- Account creation accepts an optional supported `account_type` (`SAVINGS` or `CURRENT`). The server assigns the authenticated user as owner and generates a unique account number.
- Transfers use the source account's internal `sender_account_id` and the recipient's public `receiver_account_number`. The transfer screen labels these separately, lists only the signed-in user's active source accounts, and refreshes balances and recent activity after completion.
- `POST /api/transactions` continues to support the existing idempotency key, CSRF, ownership checks, risk/AQRS selection, ML-DSA signature verification, audit logging, and blockchain inclusion.
- The dashboard's **Add money** action submits `POST /api/deposits` for an account owned by the signed-in user. This is a **simulated demo credit only**: it does not contact a payment gateway, move real money, or verify an external bank payment. Deposits appear in history as `DEPOSIT`, not as transfers, and are added as their own entry to a hash-linked ledger block. Unlike transfers, demo credits do not use the transaction AQRS/ML-DSA signature path.
- Both account creation and deposits have authenticated, CSRF-protected endpoints. Deposits require `Idempotency-Key`; a repeat request with the same key and payload replays the original receipt without crediting the balance again.

The deposit history uses a new `simulated_deposits` table. It is created additively with the existing `create_all` initialization; existing accounts, transactions, and user associations are not rewritten. No manual migration or database reset is required. Tests must continue to point `TEST_DATABASE_URL` and `DATABASE_URL` at the same isolated SQLite file, never `pqbank.db`.

Run focused account and money tests against a temporary SQLite file from
PowerShell:

```powershell
$testDb = Join-Path $env:TEMP "pqbank-account-money-tests.sqlite"
$env:TEST_DATABASE_URL = "sqlite:///$testDb"
$env:DATABASE_URL = $env:TEST_DATABASE_URL
python -m pytest tests/test_account_money.py tests/test_module11_controls.py -q
Remove-Item -LiteralPath $testDb
```

### Development user creation

The test suite uses an isolated SQLite database; test users are not available to the running application. Register an account through `/register` so it is written to the same database used by the app. Public registration creates customer accounts only. Example payload:

```json
{
  "name": "Test Customer",
  "email": "customer@example.com",
  "username": "customer",
  "password": "StrongPass123!"
}
```

Then log in via:

```json
{
  "email": "customer@example.com",
  "password": "StrongPass123!"
}
```

On Windows PowerShell, start the application from the repository root with:

```powershell
.\venv\Scripts\Activate.ps1
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:DATABASE_URL = "sqlite:///./pqbank.db"
python app.py
```

Open `http://127.0.0.1:5000/register`, create the customer account, then sign in at `/login` using that account's email or exact username and password. There are no built-in administrator credentials. To initialize an administrator securely, run this command and enter the password only at its hidden prompt:

```powershell
python -m backend.database.create_admin --name "System Administrator" --email "admin@example.com" --username "admin"
```

The optional development data seeder also requires explicit `admin_password` and `customer_password` arguments; it does not install default credentials.

### Risk classification and AQRS decision flow

The banking flow now classifies each transfer before the post-quantum policy is selected:

```text
Transaction
↓
Risk Classification
↓
LOW / MEDIUM / HIGH
↓
AQRS Decision
↓
DIL2 / DIL3 / DIL5
↓
Persist Decision
↓
Transaction Complete
```

Risk rules:
- LOW: amount < ₹1,000
- MEDIUM: ₹1,000 ≤ amount < ₹100,000
- HIGH: amount ≥ ₹100,000

AQRS security mapping:
- LOW → DIL2 / ML-DSA-44
- MEDIUM → DIL3 / ML-DSA-65
- HIGH → DIL5 / ML-DSA-87

This module does not perform live cryptographic signing or verification. It decides which post-quantum level the transaction should use next, based on the project’s benchmark-driven AQRS policy. The benchmark AQRS score remains a comparative research score; it is not a per-transaction mathematical guarantee of quantum security.

The AQRS decision is persisted in the database alongside the transaction and audit log so the decision can be reviewed without mixing it with signing or blockchain behavior.

### Running the authentication tests

```bash
python -m pytest tests/test_auth.py -q
python -m pytest -q
```

### Security limitations

This module is intentionally limited to the prototype stage. It does not claim production banking-grade security; it provides a safe and auditable auth foundation with hashed passwords, DB-backed roles, and ownership checks for the next development phases.

## Module 6: Persistent Tamper-Evident Ledger

Completed banking transactions are added to a persistent SQLAlchemy-backed ledger only after account validation, balance updates, AQRS decision persistence, ML-DSA signing, and signature verification succeed. The database remains the system of record; the ledger adds hash linkage and integrity validation through the `Block` model and `Transaction.block_id` relationship.

The persistent ledger provides:

- One deterministic genesis block at index `0` with a zero-hash previous reference.
- SHA-256 block hashes over canonical block metadata and normalized transaction/signature references.
- Previous-block hash linkage and transaction-to-block association.
- Block and full-chain validation, including detection of block, transaction, signature-reference, and linkage changes.
- `BLOCK_CREATED` audit events for ledger inclusion.

Explorer endpoints are restricted to `ADMIN` and `SECURITY_ANALYST` roles:

- `GET /api/blockchain`
- `GET /api/blockchain/validate`
- `GET /api/blockchain/blocks/<block_number>`
- `GET /api/transactions/<transaction_id>/block` for an authorized transaction owner or privileged role

This is an academic persistent tamper-evident ledger for the banking prototype. It is not a decentralized, permissionless, mining-based, cryptocurrency, consensus, or Byzantine-fault-tolerant blockchain. The original in-memory research implementation in `blockchain.py` remains independently executable and unchanged.

## How to Run the Current Research Simulation

From the project root:

```bash
pip install -r requirements.txt
python main.py
```

This generates:

- `results.json`
- `plots/*.png`
- console metrics and AQRS summary

To run the prototype Flask API:

```bash
python app.py
```

Then open the local endpoint at `http://127.0.0.1:5000`.

## Module 11: Self-Service Password Security

The repository did not previously define a Module 11. This proposed module adds authenticated password changes without email-based reset, since no verified email-delivery service is configured.

- `GET /account/security` renders the password-change page for any authenticated role; anonymous page requests redirect to login.
- `POST /api/auth/password` requires an authenticated session and current password, plus matching new-password and confirmation fields. It reuses the registration password policy and Werkzeug hashing.
- Successful password changes increment `users.auth_version`, revoke all existing sessions, and require a fresh login. Failed attempts and successful changes are audited without recording password values or hashes.
- The `auth_version` column is added with the existing additive schema migration. Existing users receive version `0`; no account data is reset.
- Security settings are linked from customer and operations navigation. Public registration remains customer-only, and each user may change only their own password.

Focused tests: `python -m pytest tests/test_module11_auth.py -v`.
Full regression suite: `python -m pytest -v`.

## Module 13: Security Audit & Reporting

Persistent security events are available to `ADMIN` and `SECURITY_ANALYST`
roles at `/security/audit`. The dashboard supports filtering and pagination,
safe event details, and bounded CSV/JSON reports. Module 12 lab records are
identified as demo/simulation events, not production incidents.

See [docs/MODULE13_SECURITY_AUDIT_REPORTING.md](docs/MODULE13_SECURITY_AUDIT_REPORTING.md)
for event schema, instrumentation, access rules, report endpoints, security
limitations, and verification instructions.

## Future Development Roadmap

### Module 0
- Audit the research prototype
- Define target architecture
- Establish repository structure
- Preserve research engine
- Record baseline metrics

### Module 1
- Database design and entity modeling
- Repository and persistence layer design
- Data model for users, accounts, transactions, signatures, AQRS decisions, blocks, and audit logs

### Module 2
- Banking core service layer
- Risk engine and AQRS service
- Crypto service abstraction
- Blockchain service abstraction

### Module 3
- REST API layer and route groups
- Transaction and account workflows
- Research endpoints

### Module 4
- Frontend pages and dashboard flows
- Research lab UI and experiment monitoring

## Important Note

This repository must preserve the research engine as a separate concern from the future banking application. The research layer remains essential to the project’s academic and engineering contribution.

## Deployment & Production Packaging

This project already supports environment-based startup and explicit database segregation. The default application database remains `pqbank.db` in the repository root and should never be used as a test target. Use an isolated SQLite path such as `test_pqbank.db` or a temporary file for automated tests and demo seeding.

### Supported configuration variables

The app honors the following environment variables:

- `APP_ENV` or `FLASK_ENV`: `development`, `testing`, `demo`, or `production`
- `SECRET_KEY`: required for non-testing startup; production must set it explicitly
- `DATABASE_URL`: SQLite database path used by the main application
- `TEST_DATABASE_URL`: isolated database for tests
- `DATABASE_ECHO`: enable SQL echo for debugging
- `APP_HOST` or `HOST`: bind address for `python app.py`
- `APP_PORT` or `PORT`: bind port
- `APP_DEBUG` or `FLASK_DEBUG`: debug mode
- `SESSION_COOKIE_SECURE`: secure cookies when behind HTTPS
- `SESSION_IDLE_TIMEOUT_SECONDS`: idle session lifetime
- `SESSION_ABSOLUTE_TIMEOUT_SECONDS`: absolute session lifetime
- `TRUSTED_PROXY_CIDRS`: comma-delimited CIDR list for trusted reverse-proxy peers

The app will also accept optional `.env` values when `python-dotenv` is installed. A safe template is in [`.env.example`](.env.example). Copy it to `.env` and replace placeholders before local startup; never commit a real `.env` file.

### Windows PowerShell setup

```powershell
cd "C:\Users\JHANATHI M V\Desktop\Quantum-Ressiliant-Blockchain\aqrs_blockchain"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
# edit .env and replace the SECRET_KEY and any database paths you need
$env:APP_ENV = "development"
$env:SECRET_KEY = "replace-with-a-random-secret-key"
$env:DATABASE_URL = "sqlite:///./pqbank.db"
python app.py
```

If you are running tests, keep them on an isolated database:

```powershell
$env:APP_ENV = "testing"
$env:SECRET_KEY = "test-secret"
$env:TEST_DATABASE_URL = "sqlite:///./test_pqbank.db"
$env:DATABASE_URL = "sqlite:///./test_pqbank.db"
python -m pytest -q
```

### Safe database initialization

The application uses SQLAlchemy metadata creation at startup and an additive migration helper for SQLite schema compatibility. For a fresh local install, create the database file and initialize tables by starting the app with the desired database URL. Do not call destructive database resets against the real `pqbank.db`.

Explicit demo data is opt-in via `backend.database.seed.seed_database(...)` and refuses to target the production database unless `allow_production=True` is passed intentionally. This keeps local seed/demo work separate from the live store.

### Production safety notes

- Production startup fails fast if `SECRET_KEY` is missing.
- Debug mode is rejected in production.
- Cookie security is enabled when the app is configured for production HTTPS.
- Health checks do not reveal secrets or internal credentials.
- Docker is optional and not required; the app is intentionally kept lightweight and deployable via a standard Python process manager or a reverse proxy.

### Health checks

```powershell
Invoke-WebRequest http://127.0.0.1:5000/health
```

The response returns only a safe status payload and the configured environment name.

### Known limitations

- This project is a prototype banking and research application, not a proof of quantum security.
- The real PQC implementation uses the project’s simulator and ML-DSA integration patterns rather than a production-grade post-quantum PKI.
- SQLite is the default engine for local and test use; production deployment should validate the exact database engine and concurrency model before going live.

## Manual verification checklist

1. Create a virtual environment and install `requirements.txt`.
2. Copy `.env.example` to `.env` and replace the placeholders.
3. Start the app without touching the real `pqbank.db` unless explicitly intended.
4. Confirm `GET /health` returns `{"status": "ok"}`.
5. Run at least the auth and database-safety tests with the isolated database.
6. Review the diff for accidental changes to tracked databases or secrets.
