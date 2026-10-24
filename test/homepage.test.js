'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const supertest = require('supertest');

process.env.NODE_ENV = 'test';
process.env.DB_PATH = ':memory:';
process.env.SESSION_SECRET = 'test-secret-not-for-production';

const { getDb, closeDb } = require('../src/db/database');
const { createApp } = require('../src/app');

let request;
let db;

function cookieHeader(res) {
  return (res.headers['set-cookie'] || []).map(value => value.split(';')[0]).join('; ');
}
function csrfToken(html) {
  const match = html.match(/name="_csrf"\s+value="([^"]+)"/);
  assert.ok(match, 'expected CSRF token');
  return match[1];
}

beforeEach(async () => {
  closeDb();
  db = await getDb();
  request = supertest(createApp(db));
});

afterEach(() => closeDb());

test('GET / redirects logged-out visitors to /auth/login', async () => {
  const response = await request.get('/');
  assert.equal(response.status, 302);
  assert.equal(response.headers.location, '/auth/login');
  assert.equal((await request.get('/health')).status, 200);
  const loginPage = await request.get('/auth/login');
  assert.equal(loginPage.status, 200);
  assert.match(loginPage.text, /href="\/styles\.css"/);
  assert.match(loginPage.text, /Welcome back/);
});

test('GET / redirects logged-in users to /documents', async () => {
  const registerPage = await request.get('/auth/register');
  const register = await request.post('/auth/register')
    .set('Cookie', cookieHeader(registerPage))
    .send(`email=homepage@example.com&password=SecurePass1234!&_csrf=${encodeURIComponent(csrfToken(registerPage.text))}`);
  assert.equal(register.status, 302);

  const loginPage = await request.get('/auth/login');
  const login = await request.post('/auth/login')
    .set('Cookie', cookieHeader(loginPage))
    .send(`email=homepage@example.com&password=SecurePass1234!&_csrf=${encodeURIComponent(csrfToken(loginPage.text))}`);
  assert.equal(login.status, 302);

  const home = await request.get('/').set('Cookie', cookieHeader(login));
  assert.equal(home.status, 302);
  assert.equal(home.headers.location, '/documents');
  const dashboard = await request.get('/documents').set('Cookie', cookieHeader(login));
  assert.equal(dashboard.status, 200);
  assert.match(dashboard.text, /My documents/);
  assert.match(dashboard.text, /href="\/styles\.css"/);
});

test('invalid credentials render a useful error page instead of a blank response', async () => {
  const page = await request.get('/auth/login');
  const response = await request.post('/auth/login')
    .set('Cookie', cookieHeader(page))
    .send(`email=missing@example.com&password=WrongPassword123!&_csrf=${encodeURIComponent(csrfToken(page.text))}`);
  assert.equal(response.status, 401);
  assert.match(response.text, /Invalid email or password/);
  assert.match(response.text, /href="\/styles\.css"/);
});
