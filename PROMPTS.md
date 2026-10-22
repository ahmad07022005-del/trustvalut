# TrustVault — AI Development Diary

## Entry 1 — 2026-10-19

### Activity
Created the initial public repository and documented the project objectives and initial security threats.

### AI assistance
Used ChatGPT to help structure the project, select a manageable technology stack and identify initial authorization and audit risks.

### Output produced
Initial README and threat inventory.

### Review and verification
These documents describe planned controls, not completed security features. The implementation and tests must establish whether the controls work.

### Commit
Record the actual GitHub commit URL after committing this entry.

### Next step
Set up the Express application, SQLite schema, authentication and automated tests.

---

## Future entries

Add a new dated entry after each significant AI-assisted implementation or review. Record the actual prompt, output, specific issue found, correction, verification results and real commit URL.

At least two entries must examine authorization, access control or audit integrity. Do not invent errors, test results or commit links.

---

## Entry 2 — 2026-10-20

### Activity
Implemented the full application foundation across multiple sessions:

- Express application scaffold (`src/app.js`, `src/server.js`)
- SQLite schema with `users`, `documents`, `document_permissions`, `audit_events`
- Authentication: registration, login, logout with bcrypt (cost 12), session regeneration, CSRF protection
- Document upload (MIME allowlist, magic-byte validation, UUID storage names, 10 MB limit)
- Document listing with title search (`GET /documents?q=`)
- Per-document read/edit permission grants and revocation
- Tamper-evident audit trail with SHA-256 hash chain
- Admin audit dashboard with action/outcome/actor/date filters
- Admin user management (deactivate/activate accounts)
- `requireActiveAccount` middleware re-validating `is_active` on every authenticated request
- Auth audit events for login success, login failure, and logout

### AI assistance
Used Kiro (Claude-based) to generate, review, and debug implementations across all milestones. Every generated piece of code was reviewed, tested, and corrected where the AI introduced bugs (e.g., CSRF token unreadable before multer in multipart uploads; schema comment semicolons breaking sql.js statement splitting; foreign-key constraint failures in hash-chain tests due to non-existent actorId fixtures).

### Output produced
- Source: `src/routes/auth.js`, `src/routes/documents.js`, `src/routes/permissions.js`, `src/routes/admin.js`, `src/lib/audit.js`, `src/middleware/auth.js`, `src/middleware/csrf.js`, `src/db/schema.sql`, `src/db/database.js`, `src/app.js`, `src/server.js`
- Views: `src/views/` (login, register, documents/index, documents/upload, documents/permissions, admin/audit, admin/users)
- Tests: `test/health.test.js`, `test/database.test.js`, `test/auth.test.js`, `test/documents.test.js`, `test/permissions.test.js`, `test/audit.test.js`

### Review and verification
68+ automated tests passing as of this entry. Known remaining limitations are documented in THREATS.md and README.md.

### Commit
Record the actual GitHub commit URL after committing.

### Next step
Add rate limiting on login and upload endpoints. Add a seed script for demo accounts. Consider a concurrent-revocation race test.

---

## Future entries

Add a new dated entry after each significant AI-assisted implementation or review. Record the actual prompt, output, specific issues found, corrections, verification results, and real commit URL. Do not invent errors, test results, or commit links.
