# TrustVault 🔐

**Secure document sharing with a real audit trail**

TrustVault is a security-focused document management platform. Confidential documents are accessible only to explicitly authorized users, and every security-relevant action is recorded in a tamper-evident audit log.

## Project status

**Implemented and test-verified** (78+ automated tests passing):

- Role-based authentication (admin, viewer); bcrypt password hashing
- Private document uploads (PDF, TXT, PNG, JPEG, DOCX; max 10 MB; magic-byte validation)
- Secure document listing with title search
- Per-document read/edit permissions with immediate revocation
- Server-side authorization on every request; deactivated accounts blocked immediately
- Tamper-evident audit trail with SHA-256 hash chain
- Admin audit dashboard with action/outcome/actor/date filters
- Admin user management (activate/deactivate accounts)
- CSRF protection on all state-changing requests
- Session security: `httpOnly`, `sameSite`, file-backed session store
- Rate limiting on login, registration, and upload endpoints

## Quick start

### 1. Prerequisites

- Node.js ≥ 20.0.0
- npm

### 2. Install dependencies

```bash
cd trustvault
npm install
```

### 3. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set a strong random value for `SESSION_SECRET`:

```
PORT=3000
NODE_ENV=development
SESSION_SECRET=replace-with-a-long-random-string
DB_PATH=./data/trustvault.db
```

### 4. Start the server

```bash
npm start
```

Or for development with auto-restart:

```bash
npm run dev
```

Visit `http://localhost:3000/auth/register` to create your first account.

### 5. Create a demo admin account

After registering your first account, promote it to admin directly in the database:

```bash
node -e "
const { getDb, closeDb } = require('./src/db/database');
getDb().then(db => {
  db.run(\"UPDATE users SET role = 'admin' WHERE email = ?\", ['your@email.com']);
  const { persist } = require('./src/db/database');
  persist();
  closeDb();
  console.log('Done');
});
"
```

Then visit `http://localhost:3000/admin/audit` to access the audit dashboard.

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | No | `3000` | HTTP port |
| `NODE_ENV` | No | `development` | Set to `production` for secure cookies |
| `SESSION_SECRET` | **Yes** | — | Long random string for session signing |
| `DB_PATH` | No | `./data/trustvault.db` | SQLite database file path |
| `RATE_LOGIN_MAX` | No | `10` | Max login attempts per window per IP |
| `RATE_LOGIN_WINDOW_MS` | No | `900000` | Login rate-limit window (ms); default 15 min |
| `RATE_REGISTER_MAX` | No | `5` | Max registration attempts per window per IP |
| `RATE_REGISTER_WINDOW_MS` | No | `3600000` | Registration rate-limit window (ms); default 1 hr |
| `RATE_UPLOAD_MAX` | No | `20` | Max upload attempts per window per IP |
| `RATE_UPLOAD_WINDOW_MS` | No | `3600000` | Upload rate-limit window (ms); default 1 hr |

Never commit `.env`. Use `.env.example` as a template.

> **Rate limiting note:** limits use an in-memory store and reset on server restart. They do not synchronise across multiple processes. For multi-server deployments, configure a shared Redis store.

## API routes

| Method | Path | Auth required | Description |
|---|---|---|---|
| GET | `/health` | No | Server health check |
| GET | `/auth/register` | No | Registration form |
| POST | `/auth/register` | No | Create account |
| GET | `/auth/login` | No | Login form |
| POST | `/auth/login` | No | Authenticate |
| POST | `/auth/logout` | Yes | Destroy session |
| GET | `/documents` | Yes | List / search documents |
| GET | `/documents/upload` | Yes | Upload form |
| POST | `/documents/upload` | Yes | Upload document |
| GET | `/documents/:id/download` | Yes | Download (owner or grantee) |
| GET | `/documents/:id/permissions` | Yes (owner) | Manage permissions |
| POST | `/documents/:id/permissions/grant` | Yes (owner) | Grant read/edit access |
| POST | `/documents/:id/permissions/:permId/revoke` | Yes (owner) | Revoke access |
| GET | `/admin/audit` | Admin | Audit log dashboard |
| GET | `/admin/users` | Admin | User management |
| POST | `/admin/users/:id/deactivate` | Admin | Deactivate account |
| POST | `/admin/users/:id/activate` | Admin | Re-activate account |

## Running tests

```bash
npm test
```

All tests use an in-memory database and temporary upload directories. No real files or database entries are created.

## Deployment notes

For production:

1. Set `NODE_ENV=production` — this enables `secure: true` on session cookies (requires HTTPS).
2. Use HTTPS. Without it, `secure` cookies will not be sent by browsers.
3. Rotate `SESSION_SECRET` periodically. Rotating invalidates all existing sessions.
4. Store `SESSION_SECRET` and `DB_PATH` in your platform's secret manager, not in `.env` files on disk.
5. Back up `DB_PATH` regularly. The SQLite file contains all user data and audit records.
6. Restrict filesystem access to `./uploads/` and `./data/` to the process user only.

## Security principles

1. The server authorizes every document operation server-side.
2. Files are stored privately and are never served directly from a public directory.
3. Access revocation blocks the next request immediately; no caching of grants.
4. Security-relevant events are recorded in a hash-chained audit log.
5. Deactivated accounts are blocked on every request, not just at login.
6. Security claims are supported by code and reproducible automated tests.

## Known limitations

- Revocation cannot erase copies downloaded before access was removed.
- The audit hash chain is stored in the same SQLite database; a privileged attacker who can rewrite the database file can also recompute hashes. An independently retained append-only log is stronger.
- Rate limiting uses an in-memory store (per process). Counters reset on restart and do not sync across multiple processes. For multi-server deployments, configure a shared Redis store.
- No production-grade virus scanning of uploaded files.
- The `owner` role in the schema is defined but not assigned by any current route.
- No HTTPS termination is included; deploy behind a reverse proxy (nginx, Caddy) in production.

See [THREATS.md](THREATS.md) for the full threat model.


## 🎥 Project Demo

Watch the complete TrustVault demonstration video:

[▶ Watch TrustVault Demo](https://youtu.be/Rx5zWcJqGmA)

The video demonstrates document uploading, file management, sharing permissions, access management, and other application features.


## License

MIT
