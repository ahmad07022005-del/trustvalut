'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const supertest = require('supertest');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');

process.env.DB_PATH = ':memory:';
process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-secret-not-for-production';

const { getDb, closeDb, persist } = require('../src/db/database');
const { createAuthRouter } = require('../src/routes/auth');
const { createDocumentRouter } = require('../src/routes/documents');
const { createPermissionsRouter } = require('../src/routes/permissions');
const { requireAuth } = require('../src/middleware/auth');

function csrf(html) {
  const match = html.match(/name="_csrf"\s+value="([^"]+)"/);
  assert.ok(match, 'CSRF token missing');
  return match[1];
}
function cookies(res) {
  const raw = res.headers['set-cookie'];
  return raw ? raw.map(value => value.split(';')[0]).join('; ') : '';
}
async function loginAs(req, email, password = 'SecurePass1234!') {
  const registerPage = await req.get('/auth/register');
  const registered = await req.post('/auth/register')
    .set('Cookie', cookies(registerPage))
    .send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${encodeURIComponent(csrf(registerPage.text))}`);
  assert.equal(registered.status, 302);
  const loginPage = await req.get('/auth/login');
  const loggedIn = await req.post('/auth/login')
    .set('Cookie', cookies(loginPage))
    .send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${encodeURIComponent(csrf(loginPage.text))}`);
  assert.equal(loggedIn.status, 302);
  return cookies(loggedIn);
}
async function upload(req, ownerCookie, fields = {}) {
  const page = await req.get('/documents/upload').set('Cookie', ownerCookie);
  const form = req.post('/documents/upload')
    .set('Cookie', cookies(page) || ownerCookie)
    .field('title', fields.title || 'Shared Report')
    .field('description', fields.description || 'A shared test document')
    .field('category', fields.category || 'Finance')
    .field('_csrf', csrf(page.text))
    .attach('file', Buffer.from('%PDF-1.4 shared test'), { filename: 'report.pdf', contentType: 'application/pdf' });
  if (fields.shareEmail) form.field('share_email', fields.shareEmail);
  if (fields.sharePermission) form.field('share_permission', fields.sharePermission);
  const response = await form;
  if (response.status === 302) {
    const rows = db.exec('SELECT id FROM documents WHERE title = ?', [fields.title || 'Shared Report']);
    assert.ok(rows.length && rows[0].values.length, 'uploaded document missing');
    return rows[0].values[0][0];
  }
  return response;
}
async function revoke(req, ownerCookie, docId, grantId) {
  const page = await req.get(`/documents/${docId}/permissions`).set('Cookie', ownerCookie);
  return req.post(`/documents/${docId}/permissions/${grantId}/revoke`)
    .set('Cookie', cookies(page) || ownerCookie)
    .send(`_csrf=${encodeURIComponent(csrf(page.text))}`);
}

let db;
let request;
let uploadsDir;

beforeEach(async () => {
  closeDb();
  db = await getDb();
  uploadsDir = path.join(os.tmpdir(), `tv_share_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`);
  fs.mkdirSync(uploadsDir, { recursive: true });
  const app = express();
  app.use(helmet());
  app.use(express.json({ limit: '32kb' }));
  app.use(express.urlencoded({ extended: false, limit: '32kb' }));
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '../src/views'));
  app.use(session({ name: 'sid', secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { httpOnly: true, secure: false, sameSite: 'lax' } }));
  app.locals.persistDb = persist;
  app.use('/auth', createAuthRouter(db));
  app.use('/documents', requireAuth, createDocumentRouter(db, { uploadsDir }));
  app.use('/documents/:id/permissions', requireAuth, createPermissionsRouter(db));
  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  app.use((err, _req, res, _next) => { console.error('[sharing test]', err.message); res.status(500).json({ error: 'Internal server error' }); });
  request = supertest(app);
});

afterEach(() => {
  closeDb();
  if (uploadsDir && fs.existsSync(uploadsDir)) fs.rmSync(uploadsDir, { recursive: true, force: true });
});

test('owner can upload privately with category and it stays out of Shared with me', async () => {
  const owner = await loginAs(request, 'private-owner@example.com');
  const recipient = await loginAs(request, 'private-recipient@example.com');
  const docId = await upload(request, owner, { title: 'Private Finance', category: 'Finance' });
  const shared = await request.get('/documents/shared').set('Cookie', recipient);
  assert.equal(shared.status, 200);
  assert.ok(!shared.text.includes('Private Finance'));
  const row = db.exec('SELECT category_id FROM documents WHERE id = ?', [docId]);
  assert.ok(row[0].values[0][0]);
});

test('upload and share creates registered recipient access and Shared with me entry', async () => {
  const owner = await loginAs(request, 'share-owner@example.com');
  const recipient = await loginAs(request, 'share-recipient@example.com');
  const docId = await upload(request, owner, { title: 'Quarterly Plan', shareEmail: ' SHARE-RECIPIENT@EXAMPLE.COM ', sharePermission: 'read' });
  const shared = await request.get('/documents/shared').set('Cookie', recipient);
  assert.equal(shared.status, 200);
  assert.match(shared.text, /Quarterly Plan/);
  assert.match(shared.text, /share-owner@example.com/);
  assert.match(shared.text, /Read/);
  const preview = await request.get(`/documents/${docId}/preview`).set('Cookie', recipient);
  assert.equal(preview.status, 200);
  assert.equal(preview.headers['content-disposition'], 'inline');
  const download = await request.get(`/documents/${docId}/download`).set('Cookie', recipient);
  assert.equal(download.status, 200);
  assert.match(download.headers['content-type'], /application\/pdf/);
});

test('unrelated users cannot access a shared document by changing the URL', async () => {
  const owner = await loginAs(request, 'private-owner-2@example.com');
  const recipient = await loginAs(request, 'intended-recipient@example.com');
  const stranger = await loginAs(request, 'unrelated-stranger@example.com');
  const docId = await upload(request, owner, { title: 'Intended Only', shareEmail: 'intended-recipient@example.com' });
  const denied = await request.get(`/documents/${docId}/download`).set('Cookie', stranger);
  assert.equal(denied.status, 403);
  const shared = await request.get('/documents/shared').set('Cookie', stranger);
  assert.equal(shared.status, 200);
  assert.ok(!shared.text.includes('Intended Only'));
  const allowed = await request.get(`/documents/${docId}/download`).set('Cookie', recipient);
  assert.equal(allowed.status, 200);
});

test('edit permission allows metadata editing while read permission does not', async () => {
  const owner = await loginAs(request, 'permission-owner@example.com');
  const reader = await loginAs(request, 'permission-reader@example.com');
  const editor = await loginAs(request, 'permission-editor@example.com');
  const docId = await upload(request, owner, { title: 'Permission Matrix' });
  const page = await request.get(`/documents/${docId}/permissions`).set('Cookie', owner);
  const token = csrf(page.text);
  const grantRead = await request.post(`/documents/${docId}/permissions/grant`).set('Cookie', cookies(page) || owner).send(`grantee_email=permission-reader@example.com&permission=read&_csrf=${token}`);
  assert.equal(grantRead.status, 200);
  const editorPage = await request.get(`/documents/${docId}/permissions`).set('Cookie', owner);
  const grantEdit = await request.post(`/documents/${docId}/permissions/grant`).set('Cookie', cookies(editorPage) || owner).send(`grantee_email=permission-editor@example.com&permission=edit&_csrf=${csrf(editorPage.text)}`);
  assert.equal(grantEdit.status, 200);
  assert.equal((await request.get(`/documents/${docId}/edit`).set('Cookie', reader)).status, 403);
  assert.equal((await request.get(`/documents/${docId}/edit`).set('Cookie', editor)).status, 200);
});

test('revocation immediately removes Shared with me and access', async () => {
  const owner = await loginAs(request, 'revocation-owner@example.com');
  const recipient = await loginAs(request, 'revocation-recipient@example.com');
  const docId = await upload(request, owner, { title: 'Revoked Plan', shareEmail: 'revocation-recipient@example.com' });
  const rows = db.exec('SELECT id FROM document_permissions WHERE document_id = ? AND revoked_at IS NULL', [docId]);
  const revoked = await revoke(request, owner, docId, rows[0].values[0][0]);
  assert.equal(revoked.status, 200);
  assert.equal((await request.get(`/documents/${docId}/download`).set('Cookie', recipient)).status, 403);
  const shared = await request.get('/documents/shared').set('Cookie', recipient);
  assert.ok(!shared.text.includes('Revoked Plan'));
});

test('unregistered recipients receive a clear error and no document is created', async () => {
  const owner = await loginAs(request, 'unregistered-owner@example.com');
  const response = await upload(request, owner, { title: 'Should Not Exist', shareEmail: 'not-registered@example.com', sharePermission: 'edit' });
  assert.equal(response.status, 400);
  assert.match(response.text, /register first/);
  assert.equal(db.exec("SELECT COUNT(*) FROM documents WHERE title = 'Should Not Exist'")[0].values[0][0], 0);
  assert.equal(fs.readdirSync(uploadsDir).length, 0);
});
