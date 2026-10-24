'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { containedPath } = require('../src/lib/paths');
const { getDb, closeDb } = require('../src/db/database');
const { writeAuditEvent } = require('../src/lib/audit');
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
  for (const column of ['description', 'category_id', 'deleted_at', 'deletion_error']) assert.ok(columns.includes(column));
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
