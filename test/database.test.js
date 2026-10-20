'use strict';

/**
 * database.test.js
 *
 * Verifies:
 *   1. All four schema tables are created.
 *   2. The foreign_keys PRAGMA is ON.
 *   3. persist() writes a readable SQLite file to disk and data survives a reload.
 *   4. DB_PATH=:memory: never creates a real file.
 *
 * Uses Node's built-in test runner (node --test).
 * Each test gets its own isolated database via beforeEach/afterEach closeDb().
 */

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('node:fs');
const os     = require('node:os');
const path   = require('node:path');

const { getDb, persist, closeDb } = require('../src/db/database');

beforeEach(() => closeDb());
afterEach(()  => closeDb());

// ── 1. Schema: all four tables exist ─────────────────────────────────────────

test('getDb creates all four tables', async () => {
  process.env.DB_PATH = ':memory:';
  const db = await getDb();

  const result = db.exec(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
  );

  // exec returns [] when there are no rows; guard against that.
  assert.ok(result.length > 0, 'sqlite_master returned no rows');

  const tables = result[0].values.map(r => r[0]);
  assert.ok(tables.includes('users'),                'users table missing');
  assert.ok(tables.includes('documents'),            'documents table missing');
  assert.ok(tables.includes('document_permissions'), 'document_permissions table missing');
  assert.ok(tables.includes('audit_events'),         'audit_events table missing');
});

// ── 2. Foreign keys PRAGMA is enabled ────────────────────────────────────────

test('foreign_keys PRAGMA is ON', async () => {
  process.env.DB_PATH = ':memory:';
  const db = await getDb();

  const result = db.exec('PRAGMA foreign_keys');
  const value  = result[0].values[0][0];
  assert.equal(value, 1, 'PRAGMA foreign_keys should be 1 (ON)');
});

// ── 3. Disk persistence ───────────────────────────────────────────────────────

test('persist() writes file to disk and data survives a reload', async () => {
  const tmpFile = path.join(os.tmpdir(), `tv_test_${Date.now()}.db`);

  try {
    // Open a real on-disk database in a temp file.
    process.env.DB_PATH = tmpFile;
    const db = await getDb();

    // Insert a row then persist to disk.
    db.run(
      'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
      ['persist@example.com', 'bcrypt-placeholder', 'viewer']
    );
    persist();

    assert.ok(fs.existsSync(tmpFile), 'database file was not created on disk');
    assert.ok(fs.statSync(tmpFile).size > 0, 'database file is empty');

    // Close and reopen from the same file path.
    closeDb();
    process.env.DB_PATH = tmpFile;
    const db2 = await getDb();

    const rows = db2.exec(
      "SELECT email FROM users WHERE email = 'persist@example.com'"
    );
    assert.ok(rows.length > 0 && rows[0].values.length > 0,
      'inserted row not found after reloading database from disk');

  } finally {
    closeDb();
    if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
  }
});

// ── 4. In-memory isolation: no file written ───────────────────────────────────

test(':memory: database never writes a file to disk', async () => {
  process.env.DB_PATH = ':memory:';
  const db = await getDb();

  db.run(
    'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
    ['mem@example.com', 'bcrypt-placeholder', 'viewer']
  );

  // persist() must be a no-op for in-memory databases.
  persist();

  // Confirm no .db or .sqlite file appeared anywhere near the project root.
  const cwd = process.cwd();
  const leaked = fs.readdirSync(cwd)
    .filter(f => f.endsWith('.db') || f.endsWith('.sqlite'));

  assert.equal(leaked.length, 0,
    `persist() wrote unexpected file(s) to disk: ${leaked.join(', ')}`);
});
