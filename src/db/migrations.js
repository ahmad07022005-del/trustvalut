'use strict';

function hasColumn(db, table, column) {
  const result = db.exec(`PRAGMA table_info(${table})`);
  return result.length > 0 && result[0].values.some(row => row[1] === column);
}

function applyMigrations(db) {
  db.run(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  )`);

  const applied = new Set();
  const rows = db.exec('SELECT version FROM schema_migrations');
  if (rows.length) for (const [version] of rows[0].values) applied.add(version);

  if (!applied.has(1)) {
    db.run(`CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE COLLATE NOCASE,
      created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    )`);
    if (!hasColumn(db, 'documents', 'description')) db.run("ALTER TABLE documents ADD COLUMN description TEXT NOT NULL DEFAULT ''");
    if (!hasColumn(db, 'documents', 'category_id')) db.run('ALTER TABLE documents ADD COLUMN category_id INTEGER REFERENCES categories (id) ON DELETE SET NULL');
    if (!hasColumn(db, 'documents', 'deleted_at')) db.run('ALTER TABLE documents ADD COLUMN deleted_at TEXT');
    if (!hasColumn(db, 'documents', 'deletion_error')) db.run('ALTER TABLE documents ADD COLUMN deletion_error TEXT');
    db.run('CREATE INDEX IF NOT EXISTS idx_documents_category ON documents (category_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_documents_created ON documents (created_at)');
    db.run('INSERT INTO schema_migrations (version) VALUES (1)');
  }

  if (!applied.has(2)) {
    if (!hasColumn(db, 'documents', 'deletion_state')) db.run("ALTER TABLE documents ADD COLUMN deletion_state TEXT NOT NULL DEFAULT 'active'");
    if (!hasColumn(db, 'documents', 'deletion_attempts')) db.run('ALTER TABLE documents ADD COLUMN deletion_attempts INTEGER NOT NULL DEFAULT 0');
    if (!hasColumn(db, 'audit_events', 'prev_hash')) db.run('ALTER TABLE audit_events ADD COLUMN prev_hash TEXT');
    if (!hasColumn(db, 'audit_events', 'integrity_version')) db.run('ALTER TABLE audit_events ADD COLUMN integrity_version INTEGER NOT NULL DEFAULT 1');
    db.run('INSERT INTO schema_migrations (version) VALUES (2)');
  }
}

module.exports = { applyMigrations };
