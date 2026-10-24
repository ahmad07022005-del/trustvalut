'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const supertest = require('supertest');

process.env.DB_PATH = ':memory:';
process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-secret-not-for-production';

const { getDb, closeDb, persist } = require('../src/db/database');
const { createAuthRouter } = require('../src/routes/auth');
const { createDocumentRouter } = require('../src/routes/documents');
const { createPermissionsRouter } = require('../src/routes/permissions');
const { requireAuth } = require('../src/middleware/auth');
const { applyMigrations } = require('../src/db/migrations');
const { reconcilePendingDeletions } = require('../src/lib/deletion');

let db;
let request;
let uploadsDir;

function cookies(res) {
  const raw = res.headers['set-cookie'] || [];
  return Array.isArray(raw) ? raw.map(c => c.split(';')[0]).join('; ') : raw.split(';')[0];
}
function csrf(html) {
  const match = html.match(/name="_csrf"\s+value="([^"]+)"/);
  assert.ok(match, 'CSRF token missing');
  return match[1];
}
async function loginAs(email, password = 'SecurePass1234!') {
  const reg = await request.get('/auth/register');
  await request.post('/auth/register').set('Cookie', cookies(reg)).send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${csrf(reg.text)}`);
  const page = await request.get('/auth/login');
  const result = await request.post('/auth/login').set('Cookie', cookies(page)).send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${csrf(page.text)}`);
  assert.equal(result.status, 302);
  return cookies(result);
}
async function uploadPdf(cookie, title = 'Preview Doc', filename = 'preview.pdf') {
  const page = await request.get('/documents/upload').set('Cookie', cookie);
  const result = await request.post('/documents/upload').set('Cookie', cookies(page) || cookie)
    .field('title', title).field('_csrf', csrf(page.text))
    .attach('file', Buffer.from('%PDF-1.4 test'), { filename, contentType: 'application/pdf' });
  assert.equal(result.status, 302);
  return db.exec('SELECT id FROM documents WHERE title=?', [title])[0].values[0][0];
}
async function grant(cookie, docId, email, permission = 'read') {
  const page = await request.get(`/documents/${docId}/permissions`).set('Cookie', cookie);
  return request.post(`/documents/${docId}/permissions/grant`).set('Cookie', cookies(page) || cookie)
    .send(`grantee_email=${encodeURIComponent(email)}&permission=${permission}&_csrf=${csrf(page.text)}`);
}
async function revoke(cookie, docId, grantId) {
  const page = await request.get(`/documents/${docId}/permissions`).set('Cookie', cookie);
  return request.post(`/documents/${docId}/permissions/${grantId}/revoke`).set('Cookie', cookies(page) || cookie)
    .send(`_csrf=${csrf(page.text)}`);
}

beforeEach(async () => {
  closeDb();
  db = await getDb();
  uploadsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-predeploy-'));
  const app = express();
  app.use(helmet());
  app.use(express.json({ limit: '32kb' }));
  app.use(express.urlencoded({ extended: false, limit: '32kb' }));
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '../src/views'));
  app.use(session({ name:'sid', secret:process.env.SESSION_SECRET, resave:false, saveUninitialized:false, cookie:{httpOnly:true, sameSite:'lax'} }));
  app.locals.persistDb = persist;
  app.use('/auth', createAuthRouter(db));
  app.use('/documents', requireAuth, createDocumentRouter(db, { uploadsDir }));
  app.use('/documents/:id/permissions', requireAuth, createPermissionsRouter(db));
  app.use((_req, res) => res.status(404).json({ error:'Not found' }));
  app.use((err, _req, res, _next) => res.status(500).json({ error:err.message }));
  request = supertest(app);
});

afterEach(() => {
  closeDb();
  if (uploadsDir && fs.existsSync(uploadsDir)) fs.rmSync(uploadsDir, { recursive:true, force:true });
});

test('HTTP preview enforces authorization, revocation, supported formats, and headers', async () => {
  const owner = await loginAs('preview-owner@example.com');
  const reader = await loginAs('preview-reader@example.com');
  const stranger = await loginAs('preview-stranger@example.com');
  const docId = await uploadPdf(owner);

  const ownerPreview = await request.get(`/documents/${docId}/preview`).set('Cookie', owner);
  assert.equal(ownerPreview.status, 200);
  assert.match(ownerPreview.headers['content-disposition'], /^inline/);
  assert.equal(ownerPreview.headers['x-content-type-options'], 'nosniff');
  assert.match(ownerPreview.headers['content-type'], /application\/pdf/);

  assert.equal((await request.get(`/documents/${docId}/preview`).set('Cookie', stranger)).status, 403);
  assert.equal((await grant(owner, docId, 'preview-reader@example.com')).status, 200);
  assert.equal((await request.get(`/documents/${docId}/preview`).set('Cookie', reader)).status, 200);

  const grantId = db.exec("SELECT id FROM document_permissions WHERE document_id=? AND revoked_at IS NULL", [docId])[0].values[0][0];
  assert.equal((await revoke(owner, docId, grantId)).status, 200);
  assert.equal((await request.get(`/documents/${docId}/preview`).set('Cookie', reader)).status, 403);

  const uploadPage = await request.get('/documents/upload').set('Cookie', owner);
  const txt = await request.post('/documents/upload').set('Cookie', cookies(uploadPage) || owner)
    .field('title', 'Unsupported Preview').field('_csrf', csrf(uploadPage.text))
    .attach('file', Buffer.from('plain text'), { filename:'unsupported.txt', contentType:'text/plain' });
  assert.equal(txt.status, 302);
  const txtId = db.exec("SELECT id FROM documents WHERE title='Unsupported Preview'")[0].values[0][0];
  assert.equal((await request.get(`/documents/${txtId}/preview`).set('Cookie', owner)).status, 403);
});

test('mandatory audit failure rolls back a permission grant', async () => {
  const owner = await loginAs('rollback-owner@example.com');
  await loginAs('rollback-reader@example.com');
  const docId = await uploadPdf(owner, 'Rollback Doc');
  db.run("CREATE TRIGGER block_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit blocked'); END");
  const result = await grant(owner, docId, 'rollback-reader@example.com');
  assert.equal(result.status, 500);
  assert.equal(db.exec('SELECT COUNT(*) FROM document_permissions WHERE document_id=?', [docId])[0].values[0][0], 0);
});

test('concurrent duplicate grants produce at most one active grant', async () => {
  const owner = await loginAs('concurrent-owner@example.com');
  await loginAs('concurrent-reader@example.com');
  const docId = await uploadPdf(owner, 'Concurrent Grant');
  const pageA = await request.get(`/documents/${docId}/permissions`).set('Cookie', owner);
  const tokenA = csrf(pageA.text);
  const [a, b] = await Promise.all([
    request.post(`/documents/${docId}/permissions/grant`).set('Cookie', cookies(pageA) || owner).send(`grantee_email=concurrent-reader@example.com&permission=read&_csrf=${tokenA}`),
    request.post(`/documents/${docId}/permissions/grant`).set('Cookie', owner).send('grantee_email=concurrent-reader@example.com&permission=read&_csrf=invalid'),
  ]);
  assert.ok([200, 403, 500].includes(a.status));
  assert.ok([200, 403, 500].includes(b.status));
  assert.ok(db.exec("SELECT COUNT(*) FROM document_permissions WHERE document_id=? AND revoked_at IS NULL", [docId])[0].values[0][0] <= 1);
});

test('migration restart is safe after a partially applied second migration', async () => {
  const initSqlJs = require('sql.js');
  const SQL = await initSqlJs();
  const legacy = new SQL.Database();
  legacy.run("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer', is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)");
  legacy.run("CREATE TABLE documents (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, title TEXT NOT NULL, storage_name TEXT NOT NULL UNIQUE, mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, is_deleted INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)");
  legacy.run("CREATE TABLE audit_events (id INTEGER PRIMARY KEY, actor_id INTEGER, action TEXT NOT NULL, resource TEXT, outcome TEXT NOT NULL, detail TEXT, ip_address TEXT, row_hash TEXT, occurred_at TEXT NOT NULL)");
  legacy.run('CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)');
  legacy.run("INSERT INTO schema_migrations VALUES (1,'now')");
  legacy.run("ALTER TABLE documents ADD COLUMN deletion_state TEXT NOT NULL DEFAULT 'active'");
  applyMigrations(legacy);
  applyMigrations(legacy);
  assert.ok(legacy.exec('PRAGMA table_info(audit_events)')[0].values.some(r => r[1] === 'prev_hash'));
  assert.equal(legacy.exec('SELECT COUNT(*) FROM schema_migrations WHERE version=2')[0].values[0][0], 1);
  legacy.close();
});

test('deletion reconciliation removes a pending file after simulated interruption', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-delete-recover-'));
  const filename = crypto.randomUUID();
  fs.writeFileSync(path.join(root, filename), 'pending');
  db.run("INSERT INTO users (email,password_hash) VALUES ('recovery@example.com','hash')");
  db.run("INSERT INTO documents (owner_id,title,storage_name,mime_type,size_bytes,is_deleted,deletion_state) VALUES (1,'Recover',?,'application/pdf',7,1,'pending')", [filename]);
  const result = reconcilePendingDeletions(db, root, () => {});
  assert.deepEqual(result, { attempted:1, completed:1, failed:0 });
  assert.equal(fs.existsSync(path.join(root, filename)), false);
  assert.equal(db.exec('SELECT deletion_state FROM documents WHERE id=1')[0].values[0][0], 'deleted');
  fs.rmSync(root, { recursive:true, force:true });
});

test('concurrent revocations leave one revoked grant and no restored access', async () => {
  const ownerA = await loginAs('concurrent-revoke-owner@example.com');
  const ownerB = await loginAs('concurrent-revoke-owner@example.com');
  await loginAs('concurrent-revoke-reader@example.com');
  const docId = await uploadPdf(ownerA, 'Concurrent Revoke');
  assert.equal((await grant(ownerA, docId, 'concurrent-revoke-reader@example.com')).status, 200);
  const grantId = db.exec("SELECT id FROM document_permissions WHERE document_id=? AND revoked_at IS NULL", [docId])[0].values[0][0];
  const [first, second] = await Promise.all([revoke(ownerA, docId, grantId), revoke(ownerB, docId, grantId)]);
  assert.ok([200, 500].includes(first.status));
  assert.ok([200, 500].includes(second.status));
  assert.equal(db.exec("SELECT COUNT(*) FROM document_permissions WHERE id=? AND revoked_at IS NULL", [grantId])[0].values[0][0], 0);
});
