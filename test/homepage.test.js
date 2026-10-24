'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const session = require('express-session');
const supertest = require('supertest');
const path = require('node:path');

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
  assert.equal((await request.get('/auth/login')).status, 200);
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
  assert.equal((await request.get('/documents').set('Cookie', cookieHeader(login))).status, 200);
});
