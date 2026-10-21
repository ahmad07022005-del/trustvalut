'use strict';

/**
 * permissions.test.js
 *
 * Adversarial integration tests for document permission grant and revocation.
 *
 * Every test uses:
 *  - An in-memory database (no real files)
 *  - A temp uploads directory (cleaned up in afterEach)
 *  - A fresh app instance per test via beforeEach/afterEach
 *
 * CSRF: every POST fetches the current form page first to get a valid token,
 * then carries both the session cookie and the token through the POST.
 */

const { test, beforeEach, afterEach } = require('node:test');
const assert    = require('node:assert/strict');
const fs        = require('node:fs');
const os        = require('node:os');
const path      = require('node:path');
const crypto    = require('node:crypto');
const supertest = require('supertest');
const express   = require('express');
const session   = require('express-session');
const helmet    = require('helmet');

process.env.DB_PATH        = ':memory:';
process.env.NODE_ENV       = 'test';
process.env.SESSION_SECRET = 'test-secret-not-for-production';

const { getDb, closeDb, persist } = require('../src/db/database');
const { createAuthRouter }        = require('../src/routes/auth');
const { createDocumentRouter }    = require('../src/routes/documents');
const { createPermissionsRouter } = require('../src/routes/permissions');
const { requireAuth }             = require('../src/middleware/auth');

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractCsrf(html) {
  const match = html.match(/name="_csrf"\s+value="([^"]+)"/);
  assert.ok(match, `CSRF hidden field not found in page. HTML:\n${html.slice(0, 500)}`);
  return match[1];
}

function extractCookies(res) {
  const raw = res.headers['set-cookie'];
  if (!raw) return '';
  return Array.isArray(raw)
    ? raw.map(c => c.split(';')[0]).join('; ')
    : raw.split(';')[0];
}

/** Register + login; returns session cookie. */
async function loginAs(req, email, password = 'SecurePass1234!') {
  const regGet  = await req.get('/auth/register');
  const regPost = await req
    .post('/auth/register')
    .set('Cookie', extractCookies(regGet))
    .send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${extractCsrf(regGet.text)}`);
  assert.equal(regPost.status, 302, `registration failed for ${email}: ${regPost.status}`);

  const loginGet  = await req.get('/auth/login');
  const loginPost = await req
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${extractCsrf(loginGet.text)}`);
  assert.equal(loginPost.status, 302, `login failed for ${email}: ${loginPost.status}`);

  return extractCookies(loginPost);
}

/** Upload a minimal PDF; returns the document id. */
async function uploadDoc(req, cookie, title = 'Test Doc') {
  const getRes    = await req.get('/documents/upload').set('Cookie', cookie);
  const token     = extractCsrf(getRes.text);
  const newCookie = extractCookies(getRes) || cookie;

  const upRes = await req
    .post('/documents/upload')
    .set('Cookie', newCookie)
    .field('title', title)
    .field('_csrf', token)
    .attach('file', Buffer.from('%PDF-1.4 test'), {
      filename:    'test.pdf',
      contentType: 'application/pdf',
    });
  assert.equal(upRes.status, 302, `upload failed: ${upRes.status}`);

  // Retrieve the document id from the DB directly.
  const rows = db.exec(`SELECT id FROM documents WHERE title = ?`, [title]);
  assert.ok(rows.length > 0 && rows[0].values.length > 0, 'uploaded doc not found in DB');
  return rows[0].values[0][0];
}

/**
 * POST to grant a permission.
 * Fetches a fresh CSRF token from the permissions page first.
 */
async function grantPermission(req, cookie, docId, granteeEmail, permission) {
  const getRes    = await req.get(`/documents/${docId}/permissions`).set('Cookie', cookie);
  const token     = extractCsrf(getRes.text);
  const newCookie = extractCookies(getRes) || cookie;

  return req
    .post(`/documents/${docId}/permissions/grant`)
    .set('Cookie', newCookie)
    .send(
      `grantee_email=${encodeURIComponent(granteeEmail)}` +
      `&permission=${encodeURIComponent(permission)}` +
      `&_csrf=${token}`
    );
}

/**
 * POST to revoke a permission by its grant ID.
 */
async function revokePermission(req, cookie, docId, grantId) {
  const getRes    = await req.get(`/documents/${docId}/permissions`).set('Cookie', cookie);
  const token     = extractCsrf(getRes.text);
  const newCookie = extractCookies(getRes) || cookie;

  return req
    .post(`/documents/${docId}/permissions/${grantId}/revoke`)
    .set('Cookie', newCookie)
    .send(`_csrf=${token}`);
}

// ── Test lifecycle ────────────────────────────────────────────────────────────

let db;
let request;
let tmpUploadsDir;

beforeEach(async () => {
  closeDb();
  db = await getDb();

  tmpUploadsDir = path.join(
    os.tmpdir(),
    `tv_perm_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`
  );
  fs.mkdirSync(tmpUploadsDir, { recursive: true });

  const testApp = express();
  testApp.use(helmet());
  testApp.use(express.json({ limit: '32kb' }));
  testApp.use(express.urlencoded({ extended: false, limit: '32kb' }));
  testApp.set('view engine', 'ejs');
  testApp.set('views', path.join(__dirname, '../src/views'));

  testApp.use(session({
    name: 'sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, sameSite: 'lax', maxAge: 7200000 },
  }));

  testApp.locals.persistDb = persist;

  testApp.use('/auth',      createAuthRouter(db));
  testApp.use('/documents', requireAuth, createDocumentRouter(db, { uploadsDir: tmpUploadsDir }));
  testApp.use('/documents/:id/permissions', requireAuth, createPermissionsRouter(db));

  testApp.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  // eslint-disable-next-line no-unused-vars
  testApp.use((err, _req, res, _next) => {
    console.error('[test-app error]', err.message);
    res.status(500).json({ error: 'Internal server error' });
  });

  request = supertest(testApp);
});

afterEach(() => {
  closeDb();
  if (tmpUploadsDir && fs.existsSync(tmpUploadsDir)) {
    fs.rmSync(tmpUploadsDir, { recursive: true, force: true });
  }
});

// ── 1. Unauthenticated users cannot access permissions routes ─────────────────

test('unauthenticated GET /documents/:id/permissions redirects to login', async () => {
  const res = await request.get('/documents/1/permissions');
  assert.equal(res.status, 302);
  assert.ok(res.headers.location.includes('/auth/login'));
});

test('unauthenticated POST /documents/:id/permissions/grant redirects to login', async () => {
  const res = await request
    .post('/documents/1/permissions/grant')
    .send('grantee_email=x@x.com&permission=read&_csrf=fake');
  assert.equal(res.status, 302);
  assert.ok(res.headers.location.includes('/auth/login'));
});

// ── 2. Owner can grant and view permissions ───────────────────────────────────

test('owner can grant read access to a registered user', async () => {
  const ownerCookie   = await loginAs(request, 'owner@example.com');
  await loginAs(request, 'reader@example.com');
  const docId = await uploadDoc(request, ownerCookie, 'Shared Doc');

  const res = await grantPermission(request, ownerCookie, docId, 'reader@example.com', 'read');
  assert.equal(res.status, 200, `expected 200, got ${res.status}: ${res.text.slice(0,200)}`);
  assert.ok(res.text.includes('reader@example.com'), 'grantee email should appear in response');
  assert.ok(res.text.includes('read'), 'permission level should appear in response');

  // Verify the DB record.
  const rows = db.exec(
    `SELECT dp.permission FROM document_permissions dp
     JOIN users u ON u.id = dp.user_id
     WHERE dp.document_id = ? AND u.email = ? AND dp.revoked_at IS NULL`,
    [docId, 'reader@example.com']
  );
  assert.ok(rows.length > 0 && rows[0].values.length > 0, 'grant not found in DB');
  assert.equal(rows[0].values[0][0], 'read');
});

test('owner can grant edit access to a registered user', async () => {
  const ownerCookie = await loginAs(request, 'owner2@example.com');
  await loginAs(request, 'editor@example.com');
  const docId = await uploadDoc(request, ownerCookie, 'Edit Doc');

  const res = await grantPermission(request, ownerCookie, docId, 'editor@example.com', 'edit');
  assert.equal(res.status, 200);

  const rows = db.exec(
    `SELECT permission FROM document_permissions dp
     JOIN users u ON u.id = dp.user_id
     WHERE dp.document_id = ? AND u.email = ? AND dp.revoked_at IS NULL`,
    [docId, 'editor@example.com']
  );
  assert.equal(rows[0].values[0][0], 'edit');
});

// ── 3. Grantee can download after read grant ──────────────────────────────────

test('read grantee can download the document', async () => {
  const ownerCookie  = await loginAs(request, 'gowner@example.com');
  const readerCookie = await loginAs(request, 'greader@example.com');
  const docId        = await uploadDoc(request, ownerCookie, 'Readable Doc');

  await grantPermission(request, ownerCookie, docId, 'greader@example.com', 'read');

  const dlRes = await request
    .get(`/documents/${docId}/download`)
    .set('Cookie', readerCookie);

  assert.equal(dlRes.status, 200, `expected 200 for grantee download, got ${dlRes.status}`);
  assert.ok(dlRes.headers['content-type'].includes('application/pdf'));
});

// ── 4. Access is denied before a grant ───────────────────────────────────────

test('user without a grant cannot download the document', async () => {
  const ownerCookie  = await loginAs(request, 'o3@example.com');
  const otherCookie  = await loginAs(request, 'stranger@example.com');
  const docId        = await uploadDoc(request, ownerCookie, 'Private Doc');

  const dlRes = await request
    .get(`/documents/${docId}/download`)
    .set('Cookie', otherCookie);

  assert.equal(dlRes.status, 403);
});

// ── 5. Immediate revocation ───────────────────────────────────────────────────

test('grantee loses access immediately after revocation', async () => {
  const ownerCookie  = await loginAs(request, 'rowner@example.com');
  const readerCookie = await loginAs(request, 'rreader@example.com');
  const docId        = await uploadDoc(request, ownerCookie, 'Revoke Doc');

  await grantPermission(request, ownerCookie, docId, 'rreader@example.com', 'read');

  // Confirm grantee can download before revocation.
  const beforeRes = await request
    .get(`/documents/${docId}/download`)
    .set('Cookie', readerCookie);
  assert.equal(beforeRes.status, 200, 'should be able to download before revocation');

  // Get the grant id from the DB.
  const rows = db.exec(
    `SELECT dp.id FROM document_permissions dp
     JOIN users u ON u.id = dp.user_id
     WHERE dp.document_id = ? AND u.email = ? AND dp.revoked_at IS NULL`,
    [docId, 'rreader@example.com']
  );
  assert.ok(rows.length > 0 && rows[0].values.length > 0, 'grant not found in DB');
  const grantId = rows[0].values[0][0];

  // Revoke.
  const revokeRes = await revokePermission(request, ownerCookie, docId, grantId);
  assert.equal(revokeRes.status, 200, `revoke should return 200, got ${revokeRes.status}`);

  // Grantee must be blocked immediately on the next request.
  const afterRes = await request
    .get(`/documents/${docId}/download`)
    .set('Cookie', readerCookie);
  assert.equal(afterRes.status, 403, 'should be denied after revocation');
});

// ── 6. Non-owner cannot grant or revoke permissions ───────────────────────────

test('non-owner cannot grant permissions on someone else\'s document', async () => {
  const ownerCookie     = await loginAs(request, 'docowner@example.com');
  const nonOwnerCookie  = await loginAs(request, 'nonowner@example.com');
  await loginAs(request, 'target@example.com');
  const docId = await uploadDoc(request, ownerCookie, 'Protected Doc');

  // non-owner tries to grant on owner's doc.
  const getRes    = await request
    .get(`/documents/${docId}/permissions`)
    .set('Cookie', nonOwnerCookie);
  // Non-owner should be forbidden even on the GET.
  assert.equal(getRes.status, 403, `non-owner GET permissions should be 403, got ${getRes.status}`);
});

test('non-owner cannot revoke permissions on someone else\'s document', async () => {
  const ownerCookie    = await loginAs(request, 'revokeowner@example.com');
  const nonOwnerCookie = await loginAs(request, 'nonrevoker@example.com');
  const readerCookie   = await loginAs(request, 'revokereader@example.com'); // eslint-disable-line no-unused-vars
  const docId          = await uploadDoc(request, ownerCookie, 'Revoke Target Doc');

  await grantPermission(request, ownerCookie, docId, 'revokereader@example.com', 'read');

  const rows = db.exec(
    `SELECT dp.id FROM document_permissions dp
     JOIN users u ON u.id = dp.user_id
     WHERE dp.document_id = ? AND u.email = ? AND dp.revoked_at IS NULL`,
    [docId, 'revokereader@example.com']
  );
  const grantId = rows[0].values[0][0];

  // non-owner tries to revoke.
  const getRes    = await request
    .get(`/documents/${docId}/permissions`)
    .set('Cookie', nonOwnerCookie);
  assert.equal(getRes.status, 403, 'non-owner should get 403 on permissions page');

  // Even with a valid CSRF token (obtained from a page the non-owner CAN reach),
  // the server-side ownership check must still return 403.
  // We use the login page to get a CSRF token for the non-owner's session.
  const loginPage = await request.get('/auth/login').set('Cookie', nonOwnerCookie);
  const csrfForNonOwner = extractCsrf(loginPage.text);
  const freshNonOwnerCookie = extractCookies(loginPage) || nonOwnerCookie;

  const revokeAttempt = await request
    .post(`/documents/${docId}/permissions/${grantId}/revoke`)
    .set('Cookie', freshNonOwnerCookie)
    .send(`_csrf=${csrfForNonOwner}`);
  assert.equal(
    revokeAttempt.status, 403,
    `expected 403 for non-owner revoke attempt, got ${revokeAttempt.status}`
  );
});

// ── 7. Self-grant is rejected ─────────────────────────────────────────────────

test('owner cannot grant permissions to themselves', async () => {
  const ownerCookie = await loginAs(request, 'selfgrant@example.com');
  const docId       = await uploadDoc(request, ownerCookie, 'Self Grant Doc');

  const res = await grantPermission(request, ownerCookie, docId, 'selfgrant@example.com', 'read');
  assert.equal(res.status, 200, 'page should render');
  assert.ok(res.text.includes('cannot grant permissions to yourself'),
    'error message should appear');

  // No grant should be in the DB.
  const rows = db.exec(
    `SELECT id FROM document_permissions
     WHERE document_id = ? AND revoked_at IS NULL`,
    [docId]
  );
  assert.ok(rows.length === 0 || rows[0].values.length === 0, 'no grant should be stored');
});

// ── 8. Invalid permission level is rejected ───────────────────────────────────

test('granting an invalid permission level returns an error', async () => {
  const ownerCookie = await loginAs(request, 'badperm@example.com');
  await loginAs(request, 'bptarget@example.com');
  const docId = await uploadDoc(request, ownerCookie, 'Bad Perm Doc');

  const res = await grantPermission(request, ownerCookie, docId, 'bptarget@example.com', 'admin');
  assert.equal(res.status, 200, 'page should render');
  assert.ok(res.text.includes('Permission level must be'), 'error message should appear');

  const rows = db.exec(
    `SELECT id FROM document_permissions WHERE document_id = ? AND revoked_at IS NULL`,
    [docId]
  );
  assert.ok(rows.length === 0 || rows[0].values.length === 0, 'no grant should be stored');
});

// ── 9. Non-existent grantee is rejected ──────────────────────────────────────

test('granting to a non-existent user email returns an error', async () => {
  const ownerCookie = await loginAs(request, 'nouser@example.com');
  const docId       = await uploadDoc(request, ownerCookie, 'No User Doc');

  const res = await grantPermission(request, ownerCookie, docId, 'ghost@nowhere.example', 'read');
  assert.equal(res.status, 200);
  assert.ok(res.text.includes('No active registered user'), 'error message should appear');
});

// ── 10. Guessed/invalid document IDs are rejected ────────────────────────────

test('non-integer document ID on permissions page returns 400', async () => {
  const ownerCookie = await loginAs(request, 'validuser@example.com');
  const res         = await request
    .get('/documents/abc/permissions')
    .set('Cookie', ownerCookie);
  assert.equal(res.status, 400);
});

test('guessing another document\'s ID returns 403 on permissions page', async () => {
  const ownerCookie = await loginAs(request, 'guessowner@example.com');
  const otherCookie = await loginAs(request, 'guesser@example.com');
  const docId       = await uploadDoc(request, ownerCookie, 'Guess Target Doc');

  const res = await request
    .get(`/documents/${docId}/permissions`)
    .set('Cookie', otherCookie);
  assert.equal(res.status, 403);
});

// ── 11. CSRF protection on permissions routes ─────────────────────────────────

test('POST /permissions/grant without CSRF token returns 403', async () => {
  const ownerCookie = await loginAs(request, 'csrfowner@example.com');
  const docId       = await uploadDoc(request, ownerCookie, 'CSRF Doc');

  const res = await request
    .post(`/documents/${docId}/permissions/grant`)
    .set('Cookie', ownerCookie)
    .send('grantee_email=anyone@example.com&permission=read');

  assert.equal(res.status, 403, 'missing CSRF should return 403');
});

test('POST /permissions/revoke without CSRF token returns 403', async () => {
  const ownerCookie = await loginAs(request, 'csrfowner2@example.com');
  const docId       = await uploadDoc(request, ownerCookie, 'CSRF Revoke Doc');

  const res = await request
    .post(`/documents/${docId}/permissions/1/revoke`)
    .set('Cookie', ownerCookie)
    .send('');

  assert.equal(res.status, 403, 'missing CSRF should return 403');
});

// ── 12. Duplicate active grant is rejected ────────────────────────────────────

test('granting the same permission twice returns an error for the second attempt', async () => {
  const ownerCookie  = await loginAs(request, 'dupowner@example.com');
  await loginAs(request, 'dupgrantee@example.com');
  const docId = await uploadDoc(request, ownerCookie, 'Dup Grant Doc');

  // First grant.
  const res1 = await grantPermission(request, ownerCookie, docId, 'dupgrantee@example.com', 'read');
  assert.equal(res1.status, 200);
  assert.ok(!res1.text.includes('already has an active'), 'first grant should succeed');

  // Second identical grant attempt.
  const res2 = await grantPermission(request, ownerCookie, docId, 'dupgrantee@example.com', 'read');
  assert.equal(res2.status, 200);
  assert.ok(res2.text.includes('already has an active'), 'second grant should be rejected as duplicate');
});

// ── 13. Edit grantee can also download ───────────────────────────────────────
// The download query accepts any active grant (read or edit).
// This test confirms edit-only grantees are not blocked from downloading.

test('edit grantee can download the document', async () => {
  const ownerCookie  = await loginAs(request, 'editdlowner@example.com');
  const editorCookie = await loginAs(request, 'editdleditor@example.com');
  const docId        = await uploadDoc(request, ownerCookie, 'Edit DL Doc');

  await grantPermission(request, ownerCookie, docId, 'editdleditor@example.com', 'edit');

  const dlRes = await request
    .get(`/documents/${docId}/download`)
    .set('Cookie', editorCookie);

  assert.equal(dlRes.status, 200,
    `expected 200 for edit-grantee download, got ${dlRes.status}`);
  assert.ok(dlRes.headers['content-type'].includes('application/pdf'));
});

// ── 14. Document list does not leak inaccessible documents ────────────────────
// GET /documents must only return documents the user owns or has an active grant for.

test('GET /documents does not show documents the user cannot access', async () => {
  const ownerCookie = await loginAs(request, 'listowner@example.com');
  const otherCookie = await loginAs(request, 'listother@example.com');

  // Owner uploads a document that other user has no access to.
  await uploadDoc(request, ownerCookie, 'Secret List Doc');

  const listRes = await request.get('/documents').set('Cookie', otherCookie);
  assert.equal(listRes.status, 200);
  assert.ok(
    !listRes.text.includes('Secret List Doc'),
    'document list must not expose documents the user has no access to'
  );
});
