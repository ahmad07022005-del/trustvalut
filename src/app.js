'use strict';

const express = require('express');
const helmet  = require('helmet');
const path    = require('path');

function createApp() {
  const app = express();

  // ── Security headers ───────────────────────────────────────────────────────
  app.use(helmet());

  // ── Body parsing (limit size to reduce DoS risk) ──────────────────────────
  app.use(express.json({ limit: '32kb' }));
  app.use(express.urlencoded({ extended: false, limit: '32kb' }));

  // ── View engine (EJS) ─────────────────────────────────────────────────────
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  // ── Routes ────────────────────────────────────────────────────────────────

  // Health check – no auth required; used by tests and uptime monitors.
  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', ts: new Date().toISOString() });
  });

  // ── Error handlers ────────────────────────────────────────────────────────

  // 404
  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  // 500 – never leak internal detail to the client
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    console.error('[error]', err.message);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

module.exports = { createApp };
