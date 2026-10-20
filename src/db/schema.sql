-- TrustVault SQLite schema
-- All foreign keys are enforced; enable them at connection time with:
--   PRAGMA foreign_keys = ON;

-- ── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  email       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
  -- bcrypt hash; never store plaintext passwords
  password_hash TEXT  NOT NULL,
  -- 'admin' | 'owner' | 'viewer'
  role        TEXT    NOT NULL DEFAULT 'viewer'
                      CHECK (role IN ('admin', 'owner', 'viewer')),
  is_active   INTEGER NOT NULL DEFAULT 1
                      CHECK (is_active IN (0, 1)),
  created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- ── Documents ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS documents (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
  title        TEXT    NOT NULL,
  -- Filename stored on disk (never the original upload name)
  storage_name TEXT    NOT NULL UNIQUE,
  mime_type    TEXT    NOT NULL,
  size_bytes   INTEGER NOT NULL CHECK (size_bytes > 0),
  is_deleted   INTEGER NOT NULL DEFAULT 0
                       CHECK (is_deleted IN (0, 1)),
  created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents (owner_id);

-- ── Document permissions ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS document_permissions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id INTEGER NOT NULL REFERENCES documents (id) ON DELETE CASCADE,
  user_id     INTEGER NOT NULL REFERENCES users (id)     ON DELETE CASCADE,
  -- 'read' | 'edit'
  permission  TEXT    NOT NULL CHECK (permission IN ('read', 'edit')),
  granted_by  INTEGER NOT NULL REFERENCES users (id)     ON DELETE RESTRICT,
  granted_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  revoked_at  TEXT    -- NULL means the grant is currently active
);

-- Enforce at most one active grant per (document, user, permission) combination.
CREATE UNIQUE INDEX IF NOT EXISTS idx_doc_perm_active
  ON document_permissions (document_id, user_id, permission)
  WHERE revoked_at IS NULL;

-- ── Audit events ──────────────────────────────────────────────────────────────
-- Rows are append-only; no UPDATE or DELETE should ever be issued on this table.
CREATE TABLE IF NOT EXISTS audit_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  -- NULL for unauthenticated requests
  actor_id    INTEGER REFERENCES users (id) ON DELETE SET NULL,
  action      TEXT    NOT NULL,
  resource    TEXT,   -- e.g. 'document:42'
  outcome     TEXT    NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
  detail      TEXT,   -- JSON blob for extra context
  ip_address  TEXT,
  -- sha256 of (id || actor_id || action || outcome || prev_hash) for tamper detection
  row_hash    TEXT,
  occurred_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_actor    ON audit_events (actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_occurred ON audit_events (occurred_at);
