'use strict';

/**
 * health.test.js
 *
 * Uses Node's built-in test runner (node --test, available since Node 18).
 * supertest drives HTTP assertions without starting a real server.
 *
 * DB_PATH=:memory: is set as a safety measure: if any future code path
 * accidentally calls getDb() during these tests it will get an isolated
 * in-memory database and will never touch the real data file.
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const supertest = require('supertest');

process.env.DB_PATH  = ':memory:';
process.env.NODE_ENV = 'test';

const { createApp } = require('../src/app');

const request = supertest(createApp());

// ── Tests ──────────────────────────────────────────────────────────────────

test('GET /health returns 200 with status ok', async () => {
  const res = await request.get('/health');

  assert.equal(res.status, 200, 'expected HTTP 200');
  assert.equal(res.body.status, 'ok', 'expected body.status === "ok"');
  assert.ok(res.body.ts, 'expected a timestamp field');
});

test('GET /health Content-Type is application/json', async () => {
  const res = await request.get('/health');

  assert.ok(
    res.headers['content-type'].includes('application/json'),
    'expected Content-Type to include application/json'
  );
});

test('GET /unknown-route returns 404', async () => {
  const res = await request.get('/does-not-exist');

  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'Not found');
});
