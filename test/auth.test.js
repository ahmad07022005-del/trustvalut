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
  const preAuthCookie = extractCookies(loginGet);
  const loginRes = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=login@example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);

  assert.equal(loginRes.status, 302, 'expected redirect after login');
  assert.ok(loginRes.headers['set-cookie'], 'expected session cookie to be set');
  assert.notEqual(extractCookies(loginRes), preAuthCookie, 'login must regenerate the session identifier');
});

test('deactivated accounts cannot log in with otherwise valid credentials', async () => {
  const reg = await request.get('/auth/register');
  await request
    .post('/auth/register')
    .set('Cookie', extractCookies(reg))
    .send(`email=inactive-login@example.com&password=SecurePass1234!&_csrf=${extractCsrf(reg.text)}`);
  db.run("UPDATE users SET is_active = 0 WHERE email = 'inactive-login@example.com'");

  const loginGet = await request.get('/auth/login');
  const loginRes = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=inactive-login@example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);

  assert.equal(loginRes.status, 403);
  assert.match(loginRes.text, /deactivated/i);
});

test('explicit SESSION_COOKIE_SECURE override controls cookie transport', async () => {
  const previous = process.env.SESSION_COOKIE_SECURE;
  try {
    process.env.SESSION_COOKIE_SECURE = 'true';
    const secureRes = await supertest(createApp(db)).get('/auth/login');
    assert.equal(secureRes.headers['set-cookie'], undefined, 'secure cookies must not be emitted over plain HTTP');

    process.env.SESSION_COOKIE_SECURE = 'false';
    const localRes = await supertest(createApp(db)).get('/auth/login');
    assert.ok(localRes.headers['set-cookie'], 'local HTTP mode must emit a session cookie');
    assert.doesNotMatch(localRes.headers['set-cookie'].join('; '), /; Secure/i);
  } finally {
    if (previous === undefined) delete process.env.SESSION_COOKIE_SECURE;
    else process.env.SESSION_COOKIE_SECURE = previous;
  }
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

  const protectedAfterLogout = await request.get('/documents').set('Cookie', sessionCookie);
  assert.ok(
    protectedAfterLogout.status === 302 || protectedAfterLogout.status === 401,
    `expected protected access to fail after logout, got ${protectedAfterLogout.status}`
  );
});

// ── 5. Auth audit events ──────────────────────────────────────────────────────

function getAuthAuditEvents(outcome) {
  const result = db.exec(
    "SELECT actor_id, resource, outcome, detail FROM audit_events WHERE action = 'auth.login' AND outcome = ? ORDER BY id DESC",
    [outcome]
  );
  if (result.length === 0 || result[0].values.length === 0) return [];
  return result[0].values.map(([actorId, resource, oc, detail]) =>
    ({ actorId, resource, outcome: oc, detail: detail ? JSON.parse(detail) : null })
  );
}

test('successful login writes auth.login/success audit event', async () => {
  const reg = await request.get('/auth/register');
  await request
    .post('/auth/register')
    .set('Cookie', extractCookies(reg))
    .send(`email=auditlogin@example.com&password=SecurePass1234!&_csrf=${extractCsrf(reg.text)}`);

  const loginGet = await request.get('/auth/login');
  await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=auditlogin@example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);

  const events = getAuthAuditEvents('success');
  assert.ok(events.length >= 1, 'expected at least one auth.login/success event');
  assert.ok(events[0].actorId !== null, 'actorId must be set on successful login');
  assert.ok(events[0].resource.startsWith('user:'), 'resource must be user:<id>');
  // Must not contain password, email, or session identifiers.
  const raw = JSON.stringify(events[0]);
  assert.ok(!/password|session|cookie|secret/i.test(raw),
    'audit event must not contain sensitive fields');
});

test('failed login (wrong password) writes auth.login/denied event with actorId null', async () => {
  const reg = await request.get('/auth/register');
  await request
    .post('/auth/register')
    .set('Cookie', extractCookies(reg))
    .send(`email=auditfail@example.com&password=SecurePass1234!&_csrf=${extractCsrf(reg.text)}`);

  const loginGet = await request.get('/auth/login');
  await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=auditfail@example.com&password=WrongPassword999!&_csrf=${extractCsrf(loginGet.text)}`);

  const events = getAuthAuditEvents('denied');
  assert.ok(events.length >= 1, 'expected at least one auth.login/denied event');
  // actorId must be null — must not reveal whether the email exists.
  assert.equal(events[0].actorId, null,
    'actorId must be null on failed login to prevent user enumeration');
  assert.equal(events[0].detail.reason, 'bad_credentials');
  // Must not contain the submitted email.
  const raw = JSON.stringify(events[0]);
  assert.ok(!/auditfail@example\.com/i.test(raw),
    'failed login audit event must not contain the submitted email');
});

test('failed login (non-existent user) also writes denied event with actorId null', async () => {
  const loginGet = await request.get('/auth/login');
  await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=ghost99@example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);

  const events = getAuthAuditEvents('denied');
  assert.ok(events.length >= 1, 'expected denied audit event for non-existent user');
  assert.equal(events[0].actorId, null, 'actorId must be null for non-existent user');
});

test('logout writes auth.logout/success audit event', async () => {
  const reg = await request.get('/auth/register');
  await request
    .post('/auth/register')
    .set('Cookie', extractCookies(reg))
    .send(`email=auditlogout@example.com&password=SecurePass1234!&_csrf=${extractCsrf(reg.text)}`);

  const loginGet  = await request.get('/auth/login');
  const loginRes  = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=auditlogout@example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);
  const sessionCookie = extractCookies(loginRes);

  const loginGet2     = await request.get('/auth/login').set('Cookie', sessionCookie);
  const csrfForLogout = extractCsrf(loginGet2.text);
  await request
    .post('/auth/logout')
    .set('Cookie', sessionCookie)
    .send(`_csrf=${csrfForLogout}`);

  const result = db.exec(
    "SELECT actor_id, outcome FROM audit_events WHERE action = 'auth.logout' ORDER BY id DESC LIMIT 1"
  );
  assert.ok(result.length > 0 && result[0].values.length > 0, 'expected auth.logout audit event');
  const [actorId, outcome] = result[0].values[0];
  assert.equal(outcome, 'success');
  assert.ok(actorId !== null, 'actorId must be set on logout');
});

// ── 6. Account deactivation bypass ────────────────────────────────────────────

test('a deactivated account is blocked on the next request even with a valid session', async () => {
  // Register and log in.
  const reg = await request.get('/auth/register');
  await request
    .post('/auth/register')
    .set('Cookie', extractCookies(reg))
    .send(`email=deactivate@example.com&password=SecurePass1234!&_csrf=${extractCsrf(reg.text)}`);

  const loginGet = await request.get('/auth/login');
  const loginRes = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=deactivate@example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);
  assert.equal(loginRes.status, 302, 'login should succeed');
  const sessionCookie = extractCookies(loginRes);

  // Confirm the session works before deactivation.
  const before = await request.get('/documents').set('Cookie', sessionCookie);
  assert.ok(before.status !== 401 && before.status !== 302,
    `expected access before deactivation, got ${before.status}`);

  // Deactivate the account directly in the DB.
  db.run("UPDATE users SET is_active = 0 WHERE email = 'deactivate@example.com'");

  // The existing session must now be rejected.
  const after = await request.get('/documents').set('Cookie', sessionCookie);
  assert.ok(
    after.status === 302 || after.status === 401,
    `expected 302 or 401 after deactivation, got ${after.status}`
  );
});

// ── 7. Admin user management ───────────────────────────────────────────────────

async function registerAndLogin(req, email, password = 'SecurePass1234!') {
  const reg = await req.get('/auth/register');
  await req
    .post('/auth/register')
    .set('Cookie', extractCookies(reg))
    .send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${extractCsrf(reg.text)}`);
  const loginGet  = await req.get('/auth/login');
  const loginRes  = await req
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}&_csrf=${extractCsrf(loginGet.text)}`);
  return extractCookies(loginRes);
}

test('non-admin cannot deactivate a user account', async () => {
  // Register two viewers; one tries to deactivate the other.
  const cookieA = await registerAndLogin(request, 'viewerA@example.com');
  await registerAndLogin(request, 'viewerB@example.com');

  const userBRow = db.exec("SELECT id FROM users WHERE email = 'viewerB@example.com'");
  const userBId  = userBRow[0].values[0][0];

  // Get a CSRF token for viewerA via the login page (any CSRF-bearing page works).
  const loginPage = await request.get('/auth/login').set('Cookie', cookieA);
  const csrf      = extractCsrf(loginPage.text);
  const fresh     = extractCookies(loginPage) || cookieA;

  const res = await request
    .post(`/admin/users/${userBId}/deactivate`)
    .set('Cookie', fresh)
    .send(`_csrf=${csrf}`);

  // Non-admin must be rejected before the handler runs.
  assert.equal(res.status, 403, `expected 403 for non-admin, got ${res.status}`);

  // UserB must still be active.
  const check = db.exec("SELECT is_active FROM users WHERE email = 'viewerB@example.com'");
  assert.equal(check[0].values[0][0], 1, 'viewerB must still be active');
});

test('admin cannot self-deactivate', async () => {
  const adminCookie = await registerAndLogin(request, 'selfdeact@example.com');
  db.run("UPDATE users SET role = 'admin' WHERE email = 'selfdeact@example.com'");

  // Register a second user so the /admin/users page renders at least one row
  // with a CSRF-bearing form.  Without another user the page only shows the
  // admin's own "(you)" row, which has no _csrf field by design.
  await registerAndLogin(request, 'otherusr@example.com');

  // Re-login so the session reflects admin role.
  const loginGet  = await request.get('/auth/login');
  const loginRes  = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=selfdeact%40example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);
  const cookie = extractCookies(loginRes);

  const adminRow = db.exec("SELECT id FROM users WHERE email = 'selfdeact@example.com'");
  const adminId  = adminRow[0].values[0][0];

  // Get CSRF from the users page — the other user's row provides the token.
  const usersPage = await request.get('/admin/users').set('Cookie', cookie);
  assert.equal(usersPage.status, 200, 'admin should reach /admin/users');
  const csrf  = extractCsrf(usersPage.text);
  const fresh = extractCookies(usersPage) || cookie;

  const res = await request
    .post(`/admin/users/${adminId}/deactivate`)
    .set('Cookie', fresh)
    .send(`_csrf=${csrf}`);

  assert.equal(res.status, 400, `expected 400 for self-deactivation, got ${res.status}`);

  // Admin must still be active.
  const check = db.exec("SELECT is_active FROM users WHERE email = 'selfdeact@example.com'");
  assert.equal(check[0].values[0][0], 1, 'admin must still be active after self-deactivation attempt');
});

// ── 8. requireActiveAccount database-error handling ───────────────────────────

test('requireActiveAccount fails closed when the database throws an error', async () => {
  // Register and log in so we have a valid authenticated session.
  const reg = await request.get('/auth/register');
  await request
    .post('/auth/register')
    .set('Cookie', extractCookies(reg))
    .send(`email=dberror@example.com&password=SecurePass1234!&_csrf=${extractCsrf(reg.text)}`);

  const loginGet = await request.get('/auth/login');
  const loginRes = await request
    .post('/auth/login')
    .set('Cookie', extractCookies(loginGet))
    .send(`email=dberror@example.com&password=SecurePass1234!&_csrf=${extractCsrf(loginGet.text)}`);
  assert.equal(loginRes.status, 302, 'login should succeed');
  const sessionCookie = extractCookies(loginRes);

  // Verify the session works before the DB is closed.
  const before = await request.get('/documents').set('Cookie', sessionCookie);
  assert.ok(
    before.status !== 401 && before.status !== 302,
    `expected access before DB close, got ${before.status}`
  );

  // Close the database. The next call to db.exec() inside requireActiveAccount
  // will throw "Database closed". The middleware must fail closed (not pass through).
  closeDb();

  // The request must be rejected — redirect or 401, never the actual route response.
  const after = await request.get('/documents').set('Cookie', sessionCookie);
  assert.ok(
    after.status === 302 || after.status === 401,
    `expected 302 or 401 when DB is closed (fail closed), got ${after.status}`
  );

  // Reopen the DB so afterEach and subsequent tests can clean up normally.
  db = await getDb();
});
