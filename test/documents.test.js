'use strict';

/**
 * documents.test.js
 *
 * Tests for document upload and download.
 * Uses a temporary uploads directory so no files persist after the suite.
 * Uses an in-memory database so no real data is written.
 *
 * Each test gets a fresh DB and app instance via beforeEach/afterEach.
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
const { requireAuth }             = require('../src/middleware/auth');

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractCsrf(html) {
  const match = html.match(/name="_csrf"\s+value="([^"]+)"/);
  assert.ok(match, 'CSRF hidden field not found in page');
  return match[1];
}

function extractCookies(res) {
  const raw = res.headers['set-cookie'];
  if (!raw) return '';
  return Array.isArray(raw)
    ? raw.map(c => c.split(';')[0]).join('; ')
    : raw.split(';')[0];
}

/**
 * Register a user and log in, returning the authenticated session cookie.
 */
async function loginAs(req, email, password = 'SecurePass1234!') {
  const regGet  = await req.get('/auth/register');
  const regPost = await req
    .post('/auth/register')
    .set('Cookie', extractCookies(regGet))
    .send(
      `email=${encodeURIComponent(email)}` +
      `&password=${encodeURIComponent(password)}` +
      `&_csrf=${extractCsrf(regGet.text)}`
    );
  assert.equal(regPost.status, 302, `registration failed for ${email}`);

  const loginGet  = await req.get('/auth/login');
  const loginPost = await req
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(
      `email=${encodeURIComponent(email)}` +
      `&password=${encodeURIComponent(password)}` +
      `&_csrf=${extractCsrf(loginGet.text)}`
    );
  assert.equal(loginPost.status, 302, `login failed for ${email}`);

  return extractCookies(loginPost);
}

/**
 * Upload a file and return the response.
 */
async function uploadFile(req, cookie, {
  fileContent = Buffer.from('%PDF-1.4 test'),
  mimeType    = 'application/pdf',
  filename    = 'test.pdf',
  title       = 'Test Document',
} = {}) {
  const getRes    = await req.get('/documents/upload').set('Cookie', cookie);
  const token     = extractCsrf(getRes.text);
  const newCookie = extractCookies(getRes) || cookie;

  return req
    .post('/documents/upload')
    .set('Cookie', newCookie)
    .field('title', title)
    .field('_csrf', token)
    .attach('file', fileContent, { filename, contentType: mimeType });
}

// ── Test lifecycle ────────────────────────────────────────────────────────────

let db;
let request;
let tmpUploadsDir;

beforeEach(async () => {
  closeDb();
  db = await getDb();

  // Fresh temp uploads dir for every test — cleaned up in afterEach.
  tmpUploadsDir = path.join(
    os.tmpdir(),
    `tv_uploads_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`
  );
  fs.mkdirSync(tmpUploadsDir, { recursive: true });

  // Build a minimal Express app that mirrors the real app but uses the temp
  // uploads directory.  We do NOT call createApp(db) because that would mount
  // the document router pointing at the real ./uploads/ directory.
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

  testApp.get('/health', (_req, res) => res.json({ status: 'ok' }));
  testApp.use('/auth',      createAuthRouter(db));
  testApp.use('/documents', requireAuth,
    createDocumentRouter(db, { uploadsDir: tmpUploadsDir }));

  // 404
  testApp.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  // 500
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

// ── 1. Unauthenticated access is blocked ─────────────────────────────────────

test('GET /documents without auth redirects to login', async () => {
  const res = await request.get('/documents');
  assert.equal(res.status, 302);
  assert.ok(res.headers.location.includes('/auth/login'));
});

test('GET /documents/upload without auth redirects to login', async () => {
  const res = await request.get('/documents/upload');
  assert.equal(res.status, 302);
  assert.ok(res.headers.location.includes('/auth/login'));
});

test('POST /documents/upload without auth redirects to login', async () => {
  const res = await request
    .post('/documents/upload')
    .send('title=test&_csrf=fake');
  assert.equal(res.status, 302);
  assert.ok(res.headers.location.includes('/auth/login'));
});

test('GET /documents/1/download without auth redirects to login', async () => {
  const res = await request.get('/documents/1/download');
  assert.equal(res.status, 302);
  assert.ok(res.headers.location.includes('/auth/login'));
});

// ── 2. Upload validation ──────────────────────────────────────────────────────

test('authenticated owner can upload a PDF and is redirected', async () => {
  const cookie = await loginAs(request, 'owner@example.com');
  const res    = await uploadFile(request, cookie, {
    fileContent: Buffer.from('%PDF-1.4 minimal test document'),
    mimeType:    'application/pdf',
    filename:    'report.pdf',
    title:       'Annual Report',
  });

  assert.equal(res.status, 302, `expected 302, got ${res.status}`);
  assert.ok(res.headers.location.includes('/documents'));

  // DB row created with correct data.
  const rows = db.exec(
    "SELECT title, mime_type FROM documents WHERE title = 'Annual Report'"
  );
  assert.ok(rows.length > 0 && rows[0].values.length > 0, 'document row not in DB');
  assert.equal(rows[0].values[0][1], 'application/pdf');

  // A single file written using a UUID storage name (not the original filename).
  const files = fs.readdirSync(tmpUploadsDir);
  assert.equal(files.length, 1, 'expected exactly one file in uploads dir');
  assert.ok(!files[0].includes('report'),
    'storage name must not contain the original filename');
});

test('upload without a file returns 400', async () => {
  const cookie    = await loginAs(request, 'nofile@example.com');
  const getRes    = await request.get('/documents/upload').set('Cookie', cookie);
  const token     = extractCsrf(getRes.text);
  const newCookie = extractCookies(getRes) || cookie;

  const res = await request
    .post('/documents/upload')
    .set('Cookie', newCookie)
    .field('title', 'No File')
    .field('_csrf', token);

  assert.equal(res.status, 400);
});

test('upload with disallowed MIME type returns 400', async () => {
  const cookie = await loginAs(request, 'badtype@example.com');
  const res    = await uploadFile(request, cookie, {
    fileContent: Buffer.from('<script>alert(1)</script>'),
    mimeType:    'text/html',
    filename:    'evil.html',
    title:       'Malicious',
  });
  assert.equal(res.status, 400);
});

test('upload with mismatched magic bytes returns 400 and file is deleted', async () => {
  const cookie = await loginAs(request, 'magic@example.com');
  const res    = await uploadFile(request, cookie, {
    fileContent: Buffer.from('<html>not a pdf</html>'),
    mimeType:    'application/pdf',
    filename:    'fake.pdf',
    title:       'Fake PDF',
  });

  assert.equal(res.status, 400);

  // The rejected file must be deleted — no files should remain on disk.
  const files = fs.readdirSync(tmpUploadsDir);
  assert.equal(files.length, 0, 'rejected file must be deleted from disk');
});

test('upload with missing title returns 400', async () => {
  const cookie = await loginAs(request, 'notitle@example.com');
  const res    = await uploadFile(request, cookie, {
    fileContent: Buffer.from('%PDF-1.4 ok'),
    mimeType:    'application/pdf',
    filename:    'ok.pdf',
    title:       '',
  });
  assert.equal(res.status, 400);
});

// ── 3. Download — ownership ───────────────────────────────────────────────────

test('owner can download their own document', async () => {
  const cookie = await loginAs(request, 'downowner@example.com');

  const upRes = await uploadFile(request, cookie, {
    fileContent: Buffer.from('%PDF-1.4 my private doc'),
    mimeType:    'application/pdf',
    filename:    'private.pdf',
    title:       'Private Doc',
  });
  assert.equal(upRes.status, 302);

  const rows = db.exec(
    "SELECT id FROM documents WHERE title = 'Private Doc'"
  );
  assert.ok(rows.length > 0 && rows[0].values.length > 0, 'doc not found in DB');
  const docId = rows[0].values[0][0];

  // Use the same cookie to download (session is already authenticated).
  const dlRes = await request
    .get(`/documents/${docId}/download`)
    .set('Cookie', cookie);

  assert.equal(dlRes.status, 200, `expected 200, got ${dlRes.status}`);
  assert.ok(dlRes.headers['content-type'].includes('application/pdf'));
});

// ── 4. Download — unauthorized access ────────────────────────────────────────

test('another user cannot download a document they do not own', async () => {
  const cookieA = await loginAs(request, 'usera@example.com');
  const upRes   = await uploadFile(request, cookieA, {
    fileContent: Buffer.from('%PDF-1.4 user a doc'),
    mimeType:    'application/pdf',
    filename:    'a.pdf',
    title:       'User A Doc',
  });
  assert.equal(upRes.status, 302);

  const rows  = db.exec(
    "SELECT id FROM documents WHERE title = 'User A Doc'"
  );
  const docId = rows[0].values[0][0];

  const cookieB = await loginAs(request, 'userb@example.com');
  const dlRes   = await request
    .get(`/documents/${docId}/download`)
    .set('Cookie', cookieB);

  assert.equal(dlRes.status, 403,
    'expected 403 when accessing another user\'s document');
});

test('user cannot access a document by guessing sequential IDs', async () => {
  const cookieA = await loginAs(request, 'seqowner@example.com');
  await uploadFile(request, cookieA, {
    fileContent: Buffer.from('%PDF-1.4 secret'),
    mimeType:    'application/pdf',
    filename:    'secret.pdf',
    title:       'Secret Doc',
  });

  const cookieB = await loginAs(request, 'attacker@example.com');

  for (const guessId of [1, 2, 3]) {
    const dlRes = await request
      .get(`/documents/${guessId}/download`)
      .set('Cookie', cookieB);
    assert.equal(dlRes.status, 403,
      `expected 403 for guessed ID ${guessId}, got ${dlRes.status}`);
  }
});

test('non-integer document ID returns 400', async () => {
  const cookie = await loginAs(request, 'badid@example.com');
  const res    = await request
    .get('/documents/abc/download')
    .set('Cookie', cookie);
  assert.equal(res.status, 400);
});
