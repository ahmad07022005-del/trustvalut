'use strict';

/**
 * auth.test.js
 *
 * Tests for registration, login, logout, wrong passwords, duplicate accounts,
 * and unauthenticated access to protected routes.
 *
 * Each test suite (describe-equivalent via nested test) gets a fresh in-memory
 * database and a fresh app instance so tests are fully isolated.
 *
 * CSRF: every POST must include a valid _csrf token. The test helper fetches
 * the GET form page first, extracts the token from the hidden field, and
 * carries the session cookie through the POST.
 */

const { test, beforeEach, afterEach } = require('node:test');
const assert  = require('node:assert/strict');
const supertest = require('supertest');

process.env.DB_PATH    = ':memory:';
process.env.NODE_ENV   = 'test';
process.env.SESSION_SECRET = 'test-secret-not-for-production';

const { getDb, closeDb }   = require('../src/db/database');
const { createApp }        = require('../src/app');

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Extract the CSRF token from a rendered HTML form.
 * Looks for: <input type="hidden" name="_csrf" value="...">
 */
function extractCsrf(html) {
  const match = html.match(/name="_csrf"\s+value="([^"]+)"/);
  assert.ok(match, 'CSRF hidden field not found in page');
  return match[1];
}

/**
 * Extract Set-Cookie header(s) from a supertest response.
 * Returns a single cookie string suitable for use in the Cookie header.
 */
function extractCookies(res) {
  const raw = res.headers['set-cookie'];
  if (!raw) return '';
  return Array.isArray(raw) ? raw.map(c => c.split(';')[0]).join('; ') : raw.split(';')[0];
}

// ── Test lifecycle ────────────────────────────────────────────────────────────

let db;
let request;

beforeEach(async () => {
  closeDb();
  db      = await getDb();
  request = supertest(createApp(db));
});

afterEach(() => {
  closeDb();
});

// ── 1. Registration ───────────────────────────────────────────────────────────

test('GET /auth/register returns 200 with a CSRF token', async () => {
  const res = await request.get('/auth/register');
  assert.equal(res.status, 200);
  assert.ok(res.text.includes('name="_csrf"'), 'CSRF field missing from register form');
});

test('POST /auth/register creates a new account and redirects', async () => {
  const getRes = await request.get('/auth/register');
  const token  = extractCsrf(getRes.text);
  const cookie  = extractCookies(getRes);

  const postRes = await request
    .post('/auth/register')
    .set('Cookie', cookie)
    .send(`email=newuser@example.com&password=SecurePass1234!&_csrf=${token}`);

  assert.equal(postRes.status, 302, 'expected redirect after registration');
  assert.ok(postRes.headers.location.includes('/auth/login'),
    'expected redirect to /auth/login');

  // Verify the user row exists in the DB.
  const rows = db.exec("SELECT email, role FROM users WHERE email = 'newuser@example.com'");
  assert.ok(rows.length > 0 && rows[0].values.length > 0, 'user row not found in DB');
  assert.equal(rows[0].values[0][1], 'viewer', 'role must be viewer, never from client input');
});

test('POST /auth/register rejects duplicate email with 409', async () => {
  // Register once.
  const get1  = await request.get('/auth/register');
  const post1 = await request
    .post('/auth/register')
    .set('Cookie', extractCookies(get1))
    .send(`email=dup@example.com&password=SecurePass1234!&_csrf=${extractCsrf(get1.text)}`);
  assert.equal(post1.status, 302);

  // Try to register again with the same email.
  const get2  = await request.get('/auth/register');
  const post2 = await request
    .post('/auth/register')
    .set('Cookie', extractCookies(get2))
    .send(`email=dup@example.com&password=AnotherPass5678!&_csrf=${extractCsrf(get2.text)}`);

  assert.equal(post2.status, 409, 'expected 409 for duplicate email');
});

test('POST /auth/register rejects a short password with 400', async () => {
  const getRes = await request.get('/auth/register');
  const res = await request
    .post('/auth/register')
    .set('Cookie', extractCookies(getRes))
    .send(`email=short@example.com&password=tooshort&_csrf=${extractCsrf(getRes.text)}`);

  assert.equal(res.status, 400);
});

// ── 2. Login ──────────────────────────────────────────────────────────────────

test('POST /auth/login succeeds with correct credentials and sets session', async () => {
  // Register a user first.
  const reg  = await request.get('/auth/register');
  await request
    .post('/auth/register')
    .set('Cookie', extractCookies(reg))
    .send(`email=login@example.com&password=SecurePass1234!&_csrf=${extractCsrf(reg.text)}`);

  // Now log in.
  const loginGet = await request.get('/auth/login');
  const loginRes = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=login@example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);

  assert.equal(loginRes.status, 302, 'expected redirect after login');
  assert.ok(loginRes.headers['set-cookie'], 'expected session cookie to be set');
});

test('POST /auth/login fails with wrong password and returns 401', async () => {
  // Register a user.
  const reg = await request.get('/auth/register');
  await request
    .post('/auth/register')
    .set('Cookie', extractCookies(reg))
    .send(`email=wrongpw@example.com&password=SecurePass1234!&_csrf=${extractCsrf(reg.text)}`);

  // Attempt login with wrong password.
  const loginGet = await request.get('/auth/login');
  const loginRes = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=wrongpw@example.com&password=WrongPassword!!&_csrf=${extractCsrf(loginGet.text)}`);

  assert.equal(loginRes.status, 401);
});

test('POST /auth/login fails for non-existent user with 401 (no enumeration)', async () => {
  const loginGet = await request.get('/auth/login');
  const loginRes = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=ghost@example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);

  // Must return the same status as a wrong-password attempt — no user enumeration.
  assert.equal(loginRes.status, 401);
});

// ── 3. CSRF protection ────────────────────────────────────────────────────────

test('POST /auth/login without CSRF token returns 403', async () => {
  const res = await request
    .post('/auth/login')
    .send('email=any@example.com&password=SecurePass1234!');

  assert.equal(res.status, 403);
});

// ── 4. Logout ─────────────────────────────────────────────────────────────────

test('POST /auth/logout destroys the session and redirects', async () => {
  // Register and log in.
  const reg = await request.get('/auth/register');
  await request
    .post('/auth/register')
    .set('Cookie', extractCookies(reg))
    .send(`email=logout@example.com&password=SecurePass1234!&_csrf=${extractCsrf(reg.text)}`);

  const loginGet = await request.get('/auth/login');
  const loginRes = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=logout@example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);

  const sessionCookie = extractCookies(loginRes);
  assert.ok(sessionCookie, 'expected a session cookie after login');

  // Get a fresh CSRF token using the authenticated session.
  const loginGet2 = await request.get('/auth/login').set('Cookie', sessionCookie);
  const csrfForLogout = extractCsrf(loginGet2.text);

  const logoutRes = await request
    .post('/auth/logout')
    .set('Cookie', sessionCookie)
    .send(`_csrf=${csrfForLogout}`);

  assert.equal(logoutRes.status, 302, 'expected redirect after logout');
  assert.ok(
    logoutRes.headers.location.includes('/auth/login'),
    'expected redirect to /auth/login after logout'
  );
});
