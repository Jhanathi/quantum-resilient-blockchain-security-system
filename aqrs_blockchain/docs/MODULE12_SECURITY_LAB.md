# Module 12: Security Attack / Tamper Demonstration Lab

## Purpose and access

The lab is an educational demonstration of integrity checks already implemented
by PQBank. Open **Security operations → Demo lab** at `/security/lab`. Only
authenticated `ADMIN` and `SECURITY_ANALYST` users can view the page or call its
API. Browser POST requests use the application's session-bound CSRF token, and
demo run/reset requests share a limit of 10 requests per minute per user.

Each run starts from new synthetic data in a dedicated in-memory SQLite
database. It does not query or update application accounts, balances,
transactions, persistent blocks, or financial audit records. Keys created for
the signature demonstration are ephemeral and private keys are neither stored
nor displayed. On-page demo history is process-local and limited to 100 runs.
Module 13 separately persists minimal execution/reset metadata as explicitly
marked `DEMO` / `SIMULATION` audit events; these are not production incidents.
Reset clears only the on-page history; the next run always creates another
clean demo database.

## Demonstrations

1. **Transaction amount tampering** changes a synthetic transaction amount
   without changing its containing block hash. The transaction amount is
   included in the canonical block content hashed by the existing
   `calculate_block_hash` function. This project does not currently assign
   transactions an independent transaction hash.
2. **Block data tampering** changes a block's transaction count without
   rebuilding the hash. The existing block verifier compares the recalculated
   canonical block hash, transaction count, and previous-hash link.
3. **Previous-hash link tampering** changes block 2's link to block 1. The
   existing chain validation checks a non-genesis block's `previous_hash`
   against the stored hash of its predecessor, as well as checking the block's
   own hash.
4. **Digital-signature tampering** uses the project's ML-DSA signing and
   verification service on a synthetic transaction, then changes the signed
   amount and verifies the changed canonical payload against the original
   signature. The signature should fail to verify.
5. **Recomputed hash** changes block 1's data and recalculates that block's
   hash, but leaves block 2's previous-hash value untouched. Block 1 may then
   pass its own hash check while the chain fails because block 2 still links to
   the old value.

The reported `baseline_status` is produced before alteration. The subsequent
status is `VALID`, `INVALID`, `UNSUPPORTED`, or `VERIFICATION_ERROR`; the
separate `detected` flag is true only when the initial valid baseline was
followed by a completed verification that rejected the tampering. An operation
that cannot be verified is not reported as successful detection.

## Detection is not prevention

Hashes and signatures provide integrity checks; they do not prevent somebody
with sufficient write access from changing stored data. A hash chain makes an
unreconciled change detectable through a later link, but recalculating all
affected hashes is not itself proof of authorization or consensus. This
demonstration uses the application's local chain-validation rules; it is not a
distributed consensus protocol and does not claim immunity to attacks,
including quantum attacks.

## Running and resetting

Run one of the five scenario cards. The page reports its initial validation,
operation, post-tampering result, detection outcome, and explanation. Use
**Reset demo history** to clear only the process-local demonstration results;
each individual scenario already starts with a fresh baseline.

Run the tests from the project directory:

```powershell
.\venv\Scripts\python.exe -m pytest -q tests\test_module12_security_lab.py
.\venv\Scripts\python.exe -m pytest -q
```

The test configuration requires an isolated SQLite test database. Tests and
demonstrations must never point to `pqbank.db`.

## Limitations

- The lab validates the current local SHA-256 canonical block hashes and
  previous-hash relationships; it does not model distributed consensus,
  authorization for block replacement, or a remote attacker.
- The amount demonstration relies on the amount being represented in canonical
  block data; there is no independent persisted transaction-hash field in the
  current transaction model.
- Signature availability and behavior depend on the configured ML-DSA provider.
  An unsupported provider operation is shown as `UNSUPPORTED`, and provider or
  verifier errors are shown as `VERIFICATION_ERROR`.
- Run history is in memory and is lost when the application process restarts.
  It is intentionally not written to the production audit trail.

## Manual interface check

Sign in as an admin or security analyst, open `/security/lab`, run all five
cards, and confirm that each shows a valid baseline followed by an invalid
post-tampering result with detection. Run a scenario again to confirm the same
baseline behavior, then reset and confirm the cards and process-local history
are cleared. A customer should receive a permission denial, and an unsigned
POST should be rejected by CSRF protection.
