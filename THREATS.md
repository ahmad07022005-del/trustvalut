# TrustVault Threat Model

## Status

Threat inventory with implementation and verification status.
**VERIFIED** = implemented in code and covered by automated tests.
**PARTIAL** = implemented but not all cases are test-covered.
**PLANNED** = not yet implemented.

| Threat | Mitigation | Status | Verification |
|---|---|---|---|
| Unauthorized document ID access | Server-side document-level authorization on every download and permission request | **VERIFIED** | `test/documents.test.js` cross-user 403 tests; `test/permissions.test.js` ownership checks |
| Direct storage access | Files stored in `./uploads/` (not under any `express.static` path); UUID storage names | **VERIFIED** | Code inspection: no `express.static` mounted; `test/documents.test.js` checks UUID names |
| Revoked permission reused | `revoked_at IS NULL` checked on every new download request; no session-cached grants | **VERIFIED** | `test/permissions.test.js` — `grantee loses access immediately after revocation` |
| Viewer privilege escalation | Role derived from DB row at login; stored in session server-side; never read from client input | **VERIFIED** | `test/auth.test.js` — role is always `viewer` after registration; `requireRole` tested in audit tests |
| Search result leakage | Search query filtered by same ownership/active-grant WHERE clause as document list | **VERIFIED** | `test/documents.test.js` — `GET /documents?q= does not return documents owned by another user` |
| Audit record tampering | Append-only INSERT path; no application DELETE/UPDATE route; SHA-256 hash chain per row | **VERIFIED** | `test/audit.test.js` — chain verification, tamper detection, no-delete-route tests |
| Malicious file upload | MIME type allowlist in `fileFilter`; magic-byte validation after multer writes to disk; file deleted on mismatch; 10 MB size limit | **VERIFIED** | `test/documents.test.js` — disallowed type 400, magic-byte mismatch 400, size limit 413 |
| Session theft or fixation | `httpOnly`, `sameSite: lax`, `secure` in production; `session.regenerate()` on login; `session.destroy()` on logout; file-backed session store | **VERIFIED** | `test/auth.test.js` — session regenerated on login, destroyed on logout |
| Cross-site request forgery | Synchronizer-token CSRF on all state-changing routes; token rotated after each use; manual post-multer check for uploads | **VERIFIED** | `test/auth.test.js`, `test/permissions.test.js`, `test/documents.test.js` — missing CSRF returns 403 |
| SQL injection | Parameterized queries throughout (`db.run(sql, params)` / `db.exec(sql, params)`) | **VERIFIED** | Code inspection: no string interpolation in SQL; search term uses `LIKE ?` binding |
| Account deactivation bypass | `requireActiveAccount(db)` middleware re-queries `is_active` on every authenticated request; session destroyed immediately | **VERIFIED** | `test/auth.test.js` — `a deactivated account is blocked on the next request` |
| Concurrent revocation | `revoked_at IS NULL` checked at the database level on each download; no in-memory caching | **PARTIAL** | Logic verified by code inspection and revocation test; no concurrent-request race test |
| Brute-force login and automated account creation | `express-rate-limit` applied to `POST /auth/login` (10 req / 15 min) and `POST /auth/register` (5 req / 1 hr) per IP; returns 429 with `Retry-After` header | **VERIFIED** | `test/ratelimit.test.js` — limit enforced, 429 returned, headers present, counter resets |
| Upload flooding | `express-rate-limit` applied to `POST /documents/upload` (20 req / 1 hr) per IP | **VERIFIED** | `test/ratelimit.test.js` — same limiter behaviour verified |
| Crash during document deletion | Persisted pending state, immediate access revocation, startup filesystem reconciliation | **PARTIAL** | `src/lib/deletion.js`, `test/security-features.test.js`; process-crash integration coverage remains limited |
| Audit field tampering | Version-2 hash covers detail, IP, timestamp, and previous-hash linkage; legacy rows remain versioned for compatibility | **VERIFIED** | `test/security-features.test.js` protected-field tampering test |
| Permission/audit inconsistency | Grant/revoke mutations and mandatory success audit writes share a database transaction | **PARTIAL** | `src/routes/permissions.js`; concurrent database-level integration coverage remains limited |

## Known limitations

- Revocation cannot erase copies downloaded before access was removed.
- The audit hash chain is stored in the same writable SQLite database. A privileged attacker with database write access can recompute hashes. Production deployments should supplement this with an independently retained append-only log or signed external checkpoints.
- Rate limiting uses an in-memory store (per process). Counters reset on server restart and do not synchronise across multiple processes or servers. For a multi-process or multi-server deployment, replace the store with a shared Redis store.
- The `owner` role is defined in the schema but not assigned by any current route; all registrations receive the `viewer` role. Admin promotion requires direct database access.
- No HTTPS is included in the application. Deploy behind a TLS-terminating reverse proxy in production.
- Uploaded files are not virus-scanned.
- Preview isolation is not a separate origin; only PDF and image MIME types are served inline, with `nosniff` and authorization checks. A separate origin is recommended for higher-assurance deployments.
- `text/plain` files have no magic-byte signature; content validation for `.txt` uploads relies solely on the declared MIME type.

## Review process

For each threat, record the implementation, automated test result, and residual risk. Update this document as testing reveals additional attack paths or as mitigations are strengthened.
