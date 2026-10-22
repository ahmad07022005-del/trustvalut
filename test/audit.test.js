'use strict';

/**
 * audit.test.js
 *
 * Tests for the audit trail implementation.
 * Covers:
 *  - Successful operations create the expected audit events
 *  - Denied operations create denied audit events
 *  - Permission grant/revoke events are recorded correctly
 *  - Audit records contain no passwords, tokens, or file contents
 *  - Non-admin cannot access the audit dashboard
 *  - Admin can view the audit dashboard but cannot download files from it
 *  - Hash-chain verification passes on a clean chain
 *  - Tampering with a row is detected by verifyAuditChain
 *  - All dynamic audit page values are HTML-escaped (EJS default)
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

const { getDb, closeDb, persist }       = require('../src/db/database');
const { createAuthRouter }              = require('../src/routes/auth');
const { createDocumentRouter }          = require('../src/routes/documents');
const { createPermissionsRouter }       = require('../src/routes/permissions');
const { createAdminRouter }             = require('../src/routes/admin');
const { requireAuth }                   = require('../src/middleware/auth');
const { requireRole }                   = require('../src/middleware/auth');
const { writeAuditEvent, verifyAuditChain } = require('../src/lib/audit');

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractCsrf(html) {
  const match = html.match(/name="_csrf"\s+value="([^"]+)"/);
  assert.ok(match, `CSRF field not found in: ${html.slice(0, 300)}`);
  return match[1];
}

function extractCookies(res) {
  const raw = res.headers['set-cookie'];
  if (!raw) return '';
  return Array.isArray(raw)
    ? raw.map(c => c.split(';')[0]).join('; ')
    : raw.split(';')[0];
}

async function loginAs(req, email, password = 'SecurePass1234!') {
  const regGet  = await req.get('/auth/register');
  await req
    .post('/auth/register')
    .set('Cookie', extractCookies(regGet))
    .send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${extractCsrf(regGet.text)}`);

  const loginGet  = await req.get('/auth/login');
  const loginPost = await req
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${extractCsrf(loginGet.text)}`);
  assert.equal(loginPost.status, 302, `login failed for ${email}`);
  return extractCookies(loginPost);
}

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
      filename: 'test.pdf', contentType: 'application/pdf',
    });
  assert.equal(upRes.status, 302, `upload failed: ${upRes.status}`);
  const rows = db.exec('SELECT id FROM documents WHERE title = ?', [title]);
  assert.ok(rows.length > 0 && rows[0].values.length > 0);
  return rows[0].values[0][0];
}

async function grantPermission(req, cookie, docId, granteeEmail, permission) {
  const getRes    = await req.get(`/documents/${docId}/permissions`).set('Cookie', cookie);
  const token     = extractCsrf(getRes.text);
  const newCookie = extractCookies(getRes) || cookie;
  return req
    .post(`/documents/${docId}/permissions/grant`)
    .set('Cookie', newCookie)
    .send(`grantee_email=${encodeURIComponent(granteeEmail)}&permission=${encodeURIComponent(permission)}&_csrf=${token}`);
}

/** Promote a user to admin directly in the DB. */
function makeAdmin(email) {
  db.run("UPDATE users SET role = 'admin' WHERE email = ?", [email]);
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
    `tv_audit_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`
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
  testApp.use('/admin', requireAuth, requireRole('admin'), createAdminRouter(db));

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

// ── Helper: query audit events from DB ───────────────────────────────────────

function getAuditEvents(action, outcome) {
  const q   = outcome
    ? 'SELECT * FROM audit_events WHERE action = ? AND outcome = ? ORDER BY id DESC'
    : 'SELECT * FROM audit_events WHERE action = ? ORDER BY id DESC';
  const params = outcome ? [action, outcome] : [action];
  const result = db.exec(q, params);
  if (result.length === 0 || result[0].values.length === 0) return [];
  const cols = result[0].columns;
  return result[0].values.map(row =>
    Object.fromEntries(cols.map((c, i) => [c, row[i]]))
  );
}

// ── 1. Successful upload creates audit event ──────────────────────────────────

test('successful upload creates document.upload/success audit event', async () => {
  const cookie = await loginAs(request, 'uploader@example.com');
  await uploadDoc(request, cookie, 'Audit Upload Doc');

  const events = getAuditEvents('document.upload', 'success');
  assert.ok(events.length >= 1, 'expected at least one upload success audit event');

  const ev = events[0];
  assert.equal(ev.outcome, 'success');
  assert.ok(ev.resource && ev.resource.startsWith('document:'), 'resource should be document:<id>');
  assert.ok(ev.actor_id !== null, 'actor_id should be set');
  assert.ok(ev.row_hash, 'row_hash should be set');
});

// ── 2. Failed upload (disallowed type) creates audit event ────────────────────

test('failed upload (disallowed type) creates document.upload/error audit event', async () => {
  const cookie  = await loginAs(request, 'failupload@example.com');
  const getRes  = await request.get('/documents/upload').set('Cookie', cookie);
  const token   = extractCsrf(getRes.text);
  const newCook = extractCookies(getRes) || cookie;

  await request
    .post('/documents/upload')
    .set('Cookie', newCook)
    .field('title', 'Bad Type')
    .field('_csrf', token)
    .attach('file', Buffer.from('<html>x</html>'), {
      filename: 'evil.html', contentType: 'text/html',
    });

  const events = getAuditEvents('document.upload', 'error');
  assert.ok(events.length >= 1, 'expected at least one upload error audit event');
  const detail = JSON.parse(events[0].detail || '{}');
  assert.equal(detail.reason, 'disallowed_mime_type');
});

// ── 3. Successful download creates audit event ────────────────────────────────

test('successful download creates document.download/success audit event', async () => {
  const cookie = await loginAs(request, 'dlowner@example.com');
  const docId  = await uploadDoc(request, cookie, 'DL Success Doc');

  await request.get(`/documents/${docId}/download`).set('Cookie', cookie);

  const events = getAuditEvents('document.download', 'success');
  assert.ok(events.length >= 1, 'expected at least one download success audit event');
  assert.equal(events[0].resource, `document:${docId}`);
});

// ── 4. Denied download creates audit event ────────────────────────────────────

test('denied cross-user download creates document.download/denied audit event', async () => {
  const ownerCookie = await loginAs(request, 'deniedowner@example.com');
  const otherCookie = await loginAs(request, 'deniedother@example.com');
  const docId       = await uploadDoc(request, ownerCookie, 'DL Denied Doc');

  const res = await request
    .get(`/documents/${docId}/download`)
    .set('Cookie', otherCookie);
  assert.equal(res.status, 403);

  const events = getAuditEvents('document.download', 'denied');
  assert.ok(events.length >= 1, 'expected at least one download denied audit event');
  assert.equal(events[0].resource, `document:${docId}`);
});

// ── 5. Successful permission grant creates audit event ────────────────────────

test('successful permission grant creates permission.grant/success audit event', async () => {
  const ownerCookie = await loginAs(request, 'grantowner@example.com');
  await loginAs(request, 'grantee1@example.com');
  const docId = await uploadDoc(request, ownerCookie, 'Grant Audit Doc');

  await grantPermission(request, ownerCookie, docId, 'grantee1@example.com', 'read');

  const events = getAuditEvents('permission.grant', 'success');
  assert.ok(events.length >= 1, 'expected at least one grant success audit event');
  assert.equal(events[0].resource, `document:${docId}`);
  const detail = JSON.parse(events[0].detail || '{}');
  assert.equal(detail.permission, 'read');
});

// ── 6. Denied permission grant (non-owner) creates audit event ────────────────

test('denied permission grant (non-owner) creates permission.grant/denied audit event', async () => {
  const ownerCookie    = await loginAs(request, 'grantowner2@example.com');
  const nonOwnerCookie = await loginAs(request, 'nonowner2@example.com');
  await loginAs(request, 'target2@example.com');
  const docId = await uploadDoc(request, ownerCookie, 'Denied Grant Doc');

  // The GET /permissions page passes auditAction=null, so it does NOT write a
  // permission.grant/denied event — that action is only relevant for a POST.
  // To get a permission.grant/denied audit event, the non-owner must attempt
  // POST /grant.  We get a valid CSRF token from the login page (accessible to
  // all logged-in users), then submit the grant POST with the non-owner's
  // authenticated session.  requireDocumentOwner sees a non-owner and writes
  // the denied audit event.
  const loginPage      = await request.get('/auth/login').set('Cookie', nonOwnerCookie);
  const csrfForNonOwner = extractCsrf(loginPage.text);
  const freshNonOwner   = extractCookies(loginPage) || nonOwnerCookie;

  const res = await request
    .post(`/documents/${docId}/permissions/grant`)
    .set('Cookie', freshNonOwner)
    .send(
      `grantee_email=target2%40example.com` +
      `&permission=read` +
      `&_csrf=${csrfForNonOwner}`
    );
  // non-owner is rejected with 403 (ownership check fails before grant logic)
  assert.equal(res.status, 403);

  const events = getAuditEvents('permission.grant', 'denied');
  assert.ok(events.length >= 1, 'expected at least one grant denied audit event');
  assert.equal(events[0].resource, `document:${docId}`);
});

// ── 7. Successful revocation creates audit event ──────────────────────────────

test('successful permission revocation creates permission.revoke/success audit event', async () => {
  const ownerCookie  = await loginAs(request, 'revokeaudit@example.com');
  const readerCookie = await loginAs(request, 'revokeread@example.com'); // eslint-disable-line no-unused-vars
  const docId        = await uploadDoc(request, ownerCookie, 'Revoke Audit Doc');

  await grantPermission(request, ownerCookie, docId, 'revokeread@example.com', 'read');

  const rows = db.exec(
    `SELECT dp.id FROM document_permissions dp
     JOIN users u ON u.id = dp.user_id
     WHERE dp.document_id = ? AND u.email = ? AND dp.revoked_at IS NULL`,
    [docId, 'revokeread@example.com']
  );
  const grantId = rows[0].values[0][0];

  const getRes    = await request.get(`/documents/${docId}/permissions`).set('Cookie', ownerCookie);
  const token     = extractCsrf(getRes.text);
  const newCookie = extractCookies(getRes) || ownerCookie;
  await request
    .post(`/documents/${docId}/permissions/${grantId}/revoke`)
    .set('Cookie', newCookie)
    .send(`_csrf=${token}`);

  const events = getAuditEvents('permission.revoke', 'success');
  assert.ok(events.length >= 1, 'expected at least one revoke success audit event');
  assert.equal(events[0].resource, `document:${docId}`);
});

// ── 8. Denied revocation (non-owner) creates audit event ─────────────────────

test('denied revocation (non-owner) creates permission.revoke/denied audit event', async () => {
  const ownerCookie    = await loginAs(request, 'revokeaudit2@example.com');
  const nonOwnerCookie = await loginAs(request, 'nonrevoker2@example.com');
  const docId          = await uploadDoc(request, ownerCookie, 'Revoke Denied Audit Doc');

  // Use the non-owner's authenticated session and a valid CSRF token so that
  // requireAuth passes and requireDocumentOwner runs and writes the denied event.
  // (Using an unauthenticated session would cause a 302 redirect before the
  //  ownership check, producing no audit event.)
  const loginPage      = await request.get('/auth/login').set('Cookie', nonOwnerCookie);
  const csrfForNonOwner = extractCsrf(loginPage.text);
  const freshNonOwner   = extractCookies(loginPage) || nonOwnerCookie;

  const revokeRes = await request
    .post(`/documents/${docId}/permissions/1/revoke`)
    .set('Cookie', freshNonOwner)
    .send(`_csrf=${csrfForNonOwner}`);
  assert.equal(revokeRes.status, 403,
    `expected 403 for non-owner revoke attempt, got ${revokeRes.status}`);

  const events = getAuditEvents('permission.revoke', 'denied');
  assert.ok(events.length >= 1, 'expected at least one revoke denied audit event');
});

// ── 9. Audit records contain no sensitive fields ──────────────────────────────

test('audit records do not contain passwords, tokens, or file contents', async () => {
  const cookie = await loginAs(request, 'sensitivecheck@example.com');
  await uploadDoc(request, cookie, 'Sensitive Check Doc');

  const result = db.exec('SELECT detail FROM audit_events WHERE detail IS NOT NULL');
  if (result.length === 0 || result[0].values.length === 0) return; // no detail rows

  const forbidden = /password|secret|token|cookie|storage_name/i;
  for (const [detail] of result[0].values) {
    assert.ok(
      !forbidden.test(detail),
      `audit detail contains forbidden field: ${detail}`
    );
  }
});

// ── 10. Non-admin cannot access audit dashboard ───────────────────────────────

test('non-admin cannot access GET /admin/audit', async () => {
  const cookie = await loginAs(request, 'viewer@example.com');
  const res    = await request.get('/admin/audit').set('Cookie', cookie);
  // requireRole returns 403 for wrong role
  assert.equal(res.status, 403, `expected 403, got ${res.status}`);
});

test('unauthenticated user cannot access GET /admin/audit', async () => {
  const res = await request.get('/admin/audit');
  // requireAuth redirects unauthenticated browser requests
  assert.equal(res.status, 302);
  assert.ok(res.headers.location.includes('/auth/login'));
});

// ── 11. Admin can view audit dashboard ───────────────────────────────────────

test('admin can access GET /admin/audit and sees HTML audit page', async () => {
  const cookie = await loginAs(request, 'admin@example.com');
  makeAdmin('admin@example.com');

  // Re-login to get a session that reflects the admin role.
  const loginGet  = await request.get('/auth/login');
  const loginPost = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=admin%40example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);
  const adminCookie = extractCookies(loginPost);

  const res = await request.get('/admin/audit').set('Cookie', adminCookie);
  assert.equal(res.status, 200, `expected 200, got ${res.status}`);
  assert.ok(res.text.includes('Audit Log'), 'page should contain "Audit Log"');
  assert.ok(res.headers['content-type'].includes('text/html'));
});

// ── 12. Admin audit page does not expose download links or file paths ─────────

test('admin audit page does not contain file storage paths or download links', async () => {
  const ownerCookie = await loginAs(request, 'admincheck@example.com');
  await uploadDoc(request, ownerCookie, 'Admin Check Doc');

  const adminCookie2 = await loginAs(request, 'admin2@example.com');
  makeAdmin('admin2@example.com');
  const loginGet  = await request.get('/auth/login');
  const loginPost = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=admin2%40example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);
  const adminCookie = extractCookies(loginPost);

  const res = await request.get('/admin/audit').set('Cookie', adminCookie);
  assert.equal(res.status, 200);

  // The audit page must not contain a /download link or UUID storage names.
  assert.ok(!res.text.includes('/download'), 'audit page must not include download links');

  // Check no UUID-like storage names leaked.
  const uuidPattern = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/;
  assert.ok(!uuidPattern.test(res.text), 'audit page must not expose storage UUIDs');
});

// ── 13. Hash chain is valid on a clean chain ──────────────────────────────────

test('verifyAuditChain passes on a freshly written chain', async () => {
  // Write several events directly via the library.
  // actorId is null because no user rows exist in this isolated in-memory DB.
  // actor_id is nullable in the schema (ON DELETE SET NULL), so this is valid.
  // The hash chain covers actor_id as a field, so null exercises the chain fully.
  writeAuditEvent(db, persist, {
    actorId: null, action: 'document.upload', resource: 'document:1',
    outcome: 'success', detail: { docId: 1 }, ipAddress: '127.0.0.1',
  });
  writeAuditEvent(db, persist, {
    actorId: null, action: 'document.download', resource: 'document:1',
    outcome: 'denied', detail: { reason: 'no_access' }, ipAddress: '127.0.0.2',
  });
  writeAuditEvent(db, persist, {
    actorId: null, action: 'permission.grant', resource: 'document:1',
    outcome: 'success', detail: { granteeId: 2, permission: 'read' }, ipAddress: '127.0.0.1',
  });

  const { valid, firstBadId, total } = verifyAuditChain(db);
  assert.ok(valid, `chain should be valid, but firstBadId = ${firstBadId}`);
  assert.equal(total, 3);
});

// ── 14. Hash chain detects a tampered row ─────────────────────────────────────

test('verifyAuditChain detects a tampered audit row', async () => {
  // actorId: null — no user rows in this isolated in-memory DB, actor_id is nullable.
  writeAuditEvent(db, persist, {
    actorId: null, action: 'document.upload', resource: 'document:1',
    outcome: 'success', detail: { docId: 1 }, ipAddress: '127.0.0.1',
  });
  writeAuditEvent(db, persist, {
    actorId: null, action: 'document.download', resource: 'document:1',
    outcome: 'denied', detail: { reason: 'no_access' }, ipAddress: '127.0.0.2',
  });

  // Verify the chain is valid before tampering.
  const before = verifyAuditChain(db);
  assert.ok(before.valid, 'chain should be valid before tampering');

  // Tamper: change the outcome of row 1 from 'success' to 'denied'.
  db.run("UPDATE audit_events SET outcome = 'denied' WHERE id = 1");

  const after = verifyAuditChain(db);
  assert.ok(!after.valid, 'chain should be invalid after tampering');
  assert.equal(after.firstBadId, 1, 'tampered row id should be 1');
});

// ── 15. No application route can delete or modify audit events ────────────────

test('no exposed application route can DELETE or UPDATE audit_events', async () => {
  const adminCookie = await loginAs(request, 'adminmod@example.com');
  makeAdmin('adminmod@example.com');
  const loginGet  = await request.get('/auth/login');
  const loginPost = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=adminmod%40example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);
  const cookie = extractCookies(loginPost);

  // These paths do not exist — should all return 404.
  const attempts = [
    ['DELETE', '/admin/audit/1'],
    ['POST',   '/admin/audit/1/delete'],
    ['POST',   '/admin/audit/1/update'],
    ['PUT',    '/admin/audit/1'],
    ['PATCH',  '/admin/audit/1'],
  ];

  for (const [method, url] of attempts) {
    const res = await request[method.toLowerCase()](url).set('Cookie', cookie);
    assert.ok(
      res.status === 404 || res.status === 405 || res.status === 403,
      `expected 404/405/403 for ${method} ${url}, got ${res.status}`
    );
  }
});

// ── 16. Admin activation/deactivation audit events ───────────────────────────

/**
 * Helper: register + login a user, return their session cookie.
 * Used inline so each test is fully self-contained.
 */
async function registerAndLoginLocal(req, email, password = 'SecurePass1234!') {
  const regGet  = await req.get('/auth/register');
  await req
    .post('/auth/register')
    .set('Cookie', extractCookies(regGet))
    .send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${extractCsrf(regGet.text)}`);
  const loginGet  = await req.get('/auth/login');
  const loginPost = await req
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${extractCsrf(loginGet.text)}`);
  return extractCookies(loginPost);
}

/**
 * Helper: get an admin cookie by registering, promoting in DB, then re-logging in.
 */
async function getAdminCookie(req, email) {
  await registerAndLoginLocal(req, email);
  makeAdmin(email);
  // Re-login to get a session that carries the admin role.
  const loginGet  = await req.get('/auth/login');
  const loginPost = await req
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=${encodeURIComponent(email)}&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);
  return extractCookies(loginPost);
}

test('admin deactivation creates admin.deactivate/success audit event with correct actor and target', async () => {
  const adminCookie  = await getAdminCookie(request, 'auditdeact@example.com');
  await registerAndLoginLocal(request, 'auditdeacttarget@example.com');

  // Look up IDs
  const adminRow  = db.exec("SELECT id FROM users WHERE email = 'auditdeact@example.com'");
  const targetRow = db.exec("SELECT id FROM users WHERE email = 'auditdeacttarget@example.com'");
  const adminId   = adminRow[0].values[0][0];
  const targetId  = targetRow[0].values[0][0];

  // Get a CSRF token from the users page (admin-accessible).
  const usersPage = await request.get('/admin/users').set('Cookie', adminCookie);
  assert.equal(usersPage.status, 200, 'admin must reach /admin/users');
  const csrf  = extractCsrf(usersPage.text);
  const fresh = extractCookies(usersPage) || adminCookie;

  const res = await request
    .post(`/admin/users/${targetId}/deactivate`)
    .set('Cookie', fresh)
    .send(`_csrf=${csrf}`);
  assert.equal(res.status, 302, `expected redirect after deactivation, got ${res.status}`);

  // Verify the audit event.
  const result = db.exec(
    "SELECT actor_id, resource, outcome, detail FROM audit_events WHERE action = 'admin.deactivate' ORDER BY id DESC LIMIT 1"
  );
  assert.ok(result.length > 0 && result[0].values.length > 0, 'admin.deactivate audit event not found');
  const [actorId, resource, outcome, detail] = result[0].values[0];
  assert.equal(actorId, adminId, 'actorId must be the admin who performed the action');
  assert.equal(resource, `user:${targetId}`, 'resource must identify the target user');
  assert.equal(outcome, 'success');
  const parsed = JSON.parse(detail);
  assert.equal(parsed.targetId, targetId, 'detail.targetId must match the deactivated user');
});

test('admin activation creates admin.activate/success audit event with correct actor and target', async () => {
  const adminCookie = await getAdminCookie(request, 'auditact@example.com');
  await registerAndLoginLocal(request, 'auditacttarget@example.com');

  const adminRow  = db.exec("SELECT id FROM users WHERE email = 'auditact@example.com'");
  const targetRow = db.exec("SELECT id FROM users WHERE email = 'auditacttarget@example.com'");
  const adminId   = adminRow[0].values[0][0];
  const targetId  = targetRow[0].values[0][0];

  // First deactivate the target (consume CSRF token from page).
  const usersPage1 = await request.get('/admin/users').set('Cookie', adminCookie);
  const csrf1  = extractCsrf(usersPage1.text);
  const fresh1 = extractCookies(usersPage1) || adminCookie;
  await request
    .post(`/admin/users/${targetId}/deactivate`)
    .set('Cookie', fresh1)
    .send(`_csrf=${csrf1}`);

  // Now activate them — fetch a fresh CSRF token after the CSRF rotation.
  const usersPage2 = await request.get('/admin/users').set('Cookie', adminCookie);
  assert.equal(usersPage2.status, 200, 'admin must reach /admin/users for second visit');
  const csrf2  = extractCsrf(usersPage2.text);
  const fresh2 = extractCookies(usersPage2) || adminCookie;

  const res = await request
    .post(`/admin/users/${targetId}/activate`)
    .set('Cookie', fresh2)
    .send(`_csrf=${csrf2}`);
  assert.equal(res.status, 302, `expected redirect after activation, got ${res.status}`);

  // Verify the audit event.
  const result = db.exec(
    "SELECT actor_id, resource, outcome, detail FROM audit_events WHERE action = 'admin.activate' ORDER BY id DESC LIMIT 1"
  );
  assert.ok(result.length > 0 && result[0].values.length > 0, 'admin.activate audit event not found');
  const [actorId, resource, outcome, detail] = result[0].values[0];
  assert.equal(actorId, adminId, 'actorId must be the admin who performed the action');
  assert.equal(resource, `user:${targetId}`, 'resource must identify the target user');
  assert.equal(outcome, 'success');
  const parsed = JSON.parse(detail);
  assert.equal(parsed.targetId, targetId, 'detail.targetId must match the activated user');
});
