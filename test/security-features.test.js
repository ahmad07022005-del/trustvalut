'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { containedPath } = require('../src/lib/paths');
const { getDb, closeDb } = require('../src/db/database');
const { writeAuditEvent, verifyAuditChain } = require('../src/lib/audit');
const { createApp } = require('../src/app');

process.env.NODE_ENV = 'test';
process.env.DB_PATH = ':memory:';
process.env.SESSION_SECRET = 'test-secret-not-for-production';

let db;
beforeEach(async () => { closeDb(); db = await getDb(); });
afterEach(() => closeDb());

test('containedPath rejects traversal outside the storage root', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-path-'));
  assert.equal(containedPath(root, 'abc'), path.join(root, 'abc'));
  assert.throws(() => containedPath(root, '../outside'), /escapes storage directory/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('audit detail redaction recursively removes sensitive keys', () => {
  const ok = writeAuditEvent(db, () => {}, {
    actorId: null, action: 'test.redaction', resource: null, outcome: 'success',
    detail: { nested: { password: 'hidden', safe: 'visible' }, items: [{ token: 'hidden', value: 1 }] }, ipAddress: null,
  });
  assert.equal(ok, true);
  const detail = db.exec("SELECT detail FROM audit_events WHERE action='test.redaction'")[0].values[0][0];
  assert.equal(detail.includes('hidden'), false);
  assert.equal(detail.includes('visible'), true);
});

test('ordered migration runner creates schema version and feature columns', () => {
  const tables = db.exec("SELECT name FROM sqlite_master WHERE type='table'")[0].values.flat();
  assert.ok(tables.includes('schema_migrations'));
  assert.ok(tables.includes('categories'));
  const columns = db.exec('PRAGMA table_info(documents)')[0].values.map(row => row[1]);
  for (const column of ['description', 'category_id', 'deleted_at', 'deletion_error', 'deletion_state', 'deletion_attempts']) assert.ok(columns.includes(column));
});

test('production app rejects missing or weak session secrets', () => {
  const previousEnv = process.env.NODE_ENV;
  const previousSecret = process.env.SESSION_SECRET;
  process.env.NODE_ENV = 'production';
  process.env.SESSION_SECRET = '';
  assert.throws(() => createApp(db), /SESSION_SECRET/);
  process.env.NODE_ENV = previousEnv;
  process.env.SESSION_SECRET = previousSecret;
});

test('audit integrity detects tampering of protected fields', async () => {
  const fields = [
    ['action', "'tampered'"], ['resource', "'tampered'"], ['outcome', "'denied'"],
    ['detail', "'{\"value\":\"tampered\"}'"], ['ip_address', "'tampered'"],
    ['occurred_at', "'tampered'"], ['prev_hash', "'tampered'"],
  ];
  for (const [field, value] of fields) {
    closeDb();
    db = await getDb();
    writeAuditEvent(db, () => {}, { actorId:null, action:'integrity.test', resource:'document:1', outcome:'success', detail:{value:'a'}, ipAddress:'127.0.0.1' });
    db.run(`UPDATE audit_events SET ${field}=${value} WHERE id=1`);
    assert.equal(verifyAuditChain(db).valid, false, `tampering ${field} must invalidate the chain`);
  }
});

test('migration upgrades an original-schema database without losing existing rows', async () => {
  const initSqlJs = require('sql.js');
  const SQL = await initSqlJs();
  const legacy = new SQL.Database();
  legacy.run("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer', is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)");
  legacy.run("CREATE TABLE documents (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, title TEXT NOT NULL, storage_name TEXT NOT NULL UNIQUE, mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, is_deleted INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)");
  legacy.run("CREATE TABLE document_permissions (id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL, user_id INTEGER NOT NULL, permission TEXT NOT NULL, granted_by INTEGER NOT NULL, granted_at TEXT NOT NULL, revoked_at TEXT)");
  legacy.run("CREATE TABLE audit_events (id INTEGER PRIMARY KEY, actor_id INTEGER, action TEXT NOT NULL, resource TEXT, outcome TEXT NOT NULL, detail TEXT, ip_address TEXT, row_hash TEXT, occurred_at TEXT NOT NULL)");
  legacy.run("INSERT INTO users VALUES (1,'legacy@example.com','hash','viewer',1,'t','t')");
  legacy.run("INSERT INTO documents VALUES (1,1,'Legacy','legacy-file','application/pdf',4,0,'t','t')");
  const { applyMigrations } = require('../src/db/migrations');
  applyMigrations(legacy);
  assert.equal(legacy.exec('SELECT email FROM users WHERE id=1')[0].values[0][0], 'legacy@example.com');
  assert.equal(legacy.exec('SELECT title FROM documents WHERE id=1')[0].values[0][0], 'Legacy');
  assert.ok(legacy.exec("SELECT name FROM sqlite_master WHERE name='categories'").length);
  assert.ok(legacy.exec('SELECT deletion_state, deletion_attempts FROM documents WHERE id=1')[0].values[0][0] === 'active');
  legacy.close();
});

test('pending deletion reconciliation is idempotent for already-missing files', () => {
  const { reconcilePendingDeletions } = require('../src/lib/deletion');
  db.run("INSERT INTO users (email,password_hash) VALUES ('delete@example.com','hash')");
  db.run("INSERT INTO documents (owner_id,title,storage_name,mime_type,size_bytes,is_deleted,deletion_state) VALUES (1,'Pending','missing-file','application/pdf',1,1,'pending')");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-reconcile-'));
  const result = reconcilePendingDeletions(db, root, () => {});
  assert.deepEqual(result, { attempted: 1, completed: 1, failed: 0 });
  assert.equal(db.exec('SELECT deletion_state FROM documents WHERE id=1')[0].values[0][0], 'deleted');
  const second = reconcilePendingDeletions(db, root, () => {});
  assert.deepEqual(second, { attempted: 0, completed: 0, failed: 0 });
  fs.rmSync(root, { recursive: true, force: true });
});

test('pending deletion reconciliation records unsafe-path failure for retry', () => {
  const { reconcilePendingDeletions } = require('../src/lib/deletion');
  db.run("INSERT INTO users (email,password_hash) VALUES ('failure@example.com','hash')");
  db.run("INSERT INTO documents (owner_id,title,storage_name,mime_type,size_bytes,is_deleted,deletion_state) VALUES (1,'Failure','../outside','application/pdf',1,1,'pending')");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-reconcile-fail-'));
  const result = reconcilePendingDeletions(db, root, () => {});
  assert.deepEqual(result, { attempted: 1, completed: 0, failed: 1 });
  const row = db.exec('SELECT deletion_state, deletion_attempts, deletion_error FROM documents WHERE id=1')[0].values[0];
  assert.equal(row[0], 'pending');
  assert.equal(row[1], 1);
  assert.match(row[2], /escapes storage directory/);
  fs.rmSync(root, { recursive: true, force: true });
});
