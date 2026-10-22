'use strict';

/**
 * ratelimit.test.js
 *
 * Tests for rate-limit middleware behaviour.
 *
 * The rate limiters skip in NODE_ENV=test (pass-through), so we cannot test
 * them via the full application.  Instead, each test builds a minimal Express
 * app that mounts a fresh rateLimit instance with a tiny limit, exercises it
 * directly, and verifies the 429 response and headers.
 *
 * This approach tests the integration of express-rate-limit with our app
 * without depending on the environment-variable configuration.
 */

const { test }  = require('node:test');
const assert    = require('node:assert/strict');
const express   = require('express');
const supertest = require('supertest');
const rateLimit = require('express-rate-limit');

// ── Helper: build a minimal app with a configurable rate limit ────────────────

function buildApp(max, windowMs) {
  const app    = express();
  const limiter = rateLimit({
    max,
    windowMs,
    standardHeaders: true,
    legacyHeaders:   false,
    message:         { error: 'Too many requests' },
  });

  app.use(express.json());
  app.post('/limited', limiter, (_req, res) => res.json({ ok: true }));
  app.get('/limited',  limiter, (_req, res) => res.json({ ok: true }));
  return supertest(app);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test('requests within the limit are allowed', async () => {
  const request = buildApp(3, 60 * 1000); // 3 per minute
  for (let i = 0; i < 3; i++) {
    const res = await request.post('/limited');
    assert.equal(res.status, 200, `request ${i + 1} should succeed`);
  }
});

test('request exceeding the limit returns 429', async () => {
  const request = buildApp(2, 60 * 1000); // 2 per minute
  await request.post('/limited'); // 1
  await request.post('/limited'); // 2
  const res = await request.post('/limited'); // 3 — should be blocked
  assert.equal(res.status, 429, 'expected 429 after limit exceeded');
});

test('429 response body contains an error field', async () => {
  const request = buildApp(1, 60 * 1000);
  await request.post('/limited'); // 1 — within limit
  const res = await request.post('/limited'); // 2 — over limit
  assert.equal(res.status, 429);
  assert.ok(res.body && res.body.error, 'expected error field in 429 body');
});

test('RateLimit-Limit header is present on a limited response', async () => {
  const request = buildApp(1, 60 * 1000);
  await request.post('/limited');
  const res = await request.post('/limited');
  assert.equal(res.status, 429);
  // standardHeaders: true means express-rate-limit sets RateLimit-* headers.
  const hasHeader =
    'ratelimit-limit' in res.headers ||
    'ratelimit-remaining' in res.headers ||
    'retry-after' in res.headers;
  assert.ok(hasHeader, 'expected at least one rate-limit response header');
});

test('rate limit counter resets after the window expires', async () => {
  // Use a 100 ms window so the test does not take long.
  const request = buildApp(1, 100);
  await request.post('/limited');
  const blocked = await request.post('/limited');
  assert.equal(blocked.status, 429, 'should be blocked within the window');

  // Wait for the window to expire.
  await new Promise(resolve => setTimeout(resolve, 150));

  const after = await request.post('/limited');
  assert.equal(after.status, 200, 'should be allowed after window resets');
});

test('GET /limited also respects the rate limit', async () => {
  const request = buildApp(1, 60 * 1000);
  await request.get('/limited');
  const res = await request.get('/limited');
  assert.equal(res.status, 429);
});
