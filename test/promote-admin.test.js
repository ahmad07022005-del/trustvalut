'use strict';

const { test, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { getDb, persist, closeDb } = require('../src/db/database');
const { promoteAdmin, parseArgs, resolveDatabasePath } = require('../scripts/promote-admin');

let tempDir;

async function createDatabase(users) {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustvault-bootstrap-'));
  const dbPath = path.join(tempDir, 'trustvault.db');
  const db = await getDb(dbPath);
  for (const user of users) {
    db.run(
      'INSERT INTO users (email, password_hash, role, is_active) VALUES (?, ?, ?, ?)',
      [user.email, 'test-only-placeholder-hash', user.role || 'viewer', user.isActive === undefined ? 1 : user.isActive]
    );
  }
  persist();
  closeDb();
  return dbPath;
}

afterEach(() => {
  closeDb();
  if (tempDir && fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
  tempDir = null;
});

test('promoteAdmin backs up and promotes exactly the selected active user', async () => {
  const dbPath = await createDatabase([
    { email: 'viewer@example.com', role: 'viewer' },
    { email: 'other@example.com', role: 'viewer' },
  ]);
  const backupPath = path.join(tempDir, 'before-promotion.db');

  const result = await promoteAdmin({ dbPath, email: 'VIEWER@example.com', backupPath });

  assert.equal(result.email, 'viewer@example.com');
  assert.equal(result.previousRole, 'viewer');
  assert.equal(result.role, 'admin');
  assert.ok(fs.existsSync(backupPath), 'a pre-change backup must be created');

  const db = await getDb(dbPath);
  const rows = db.exec('SELECT role FROM users WHERE email = ?', ['viewer@example.com']);
  assert.deepEqual(rows[0].values, [['admin']]);
  const other = db.exec('SELECT role FROM users WHERE email = ?', ['other@example.com']);
  assert.deepEqual(other[0].values, [['viewer']]);
});

test('promoteAdmin rejects an unknown email without changing any role', async () => {
  const dbPath = await createDatabase([{ email: 'viewer@example.com', role: 'viewer' }]);
  const backupPath = path.join(tempDir, 'unknown-email-backup.db');

  await assert.rejects(
    promoteAdmin({ dbPath, email: 'missing@example.com', backupPath }),
    /No existing user matches/
  );

  const db = await getDb(dbPath);
  const rows = db.exec('SELECT role FROM users WHERE email = ?', ['viewer@example.com']);
  assert.deepEqual(rows[0].values, [['viewer']]);
  assert.ok(fs.existsSync(backupPath), 'backup must exist even when the requested user is not found');
});

test('promoteAdmin requires an explicit on-disk database path and email', () => {
  assert.throws(() => parseArgs(['--email', 'owner@example.com']), /--db/);
  assert.throws(() => resolveDatabasePath(':memory:'), /on-disk/);
});
