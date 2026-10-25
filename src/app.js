'use strict';

const express        = require('express');
const helmet         = require('helmet');
const session        = require('express-session');
const path           = require('path');
const FileStore      = require('session-file-store')(session);

const { createAuthRouter }        = require('./routes/auth');
const { createDocumentRouter }    = require('./routes/documents');
const { createPermissionsRouter } = require('./routes/permissions');
const { createAdminRouter }       = require('./routes/admin');
const { persist }                 = require('./db/database');
const { requireAuth }             = require('./middleware/auth');
const { requireRole }             = require('./middleware/auth');
const { requireActiveAccount }    = require('./middleware/auth');

/**
 * Create and configure the Express application.
 *
 * @param {import('sql.js').Database|null} db - The open sql.js database
 *   instance. Pass null (or omit) when the DB is not needed (e.g. health-only
 *   test environments).
 * @returns {import('express').Application}
 */
function createApp(db = null) {
  const app = express();

  // Trust only an explicitly configured proxy topology.
  const trustProxy = process.env.TRUST_PROXY;
  if (trustProxy === 'loopback') app.set('trust proxy', 'loopback');
  else if (trustProxy === 'true') app.set('trust proxy', 1);

  // ── Security headers ───────────────────────────────────────────────────────
  app.use(helmet());

  // ── Body parsing (limit size to reduce DoS risk) ──────────────────────────
  app.use(express.json({ limit: '32kb' }));
  app.use(express.urlencoded({ extended: false, limit: '32kb' }));
  app.use(express.static(path.join(__dirname, 'public'), { index: false }));

  // ── View engine (EJS) ─────────────────────────────────────────────────────
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  // ── Session middleware ─────────────────────────────────────────────────────
  // Session secret must be set via SESSION_SECRET environment variable.
  // session-file-store persists session files under ./sessions/ by default,
  // which is excluded from Git in .gitignore.
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret && process.env.NODE_ENV !== 'test') {
    console.warn('[warn] SESSION_SECRET is not set. Set it in your .env file.');
  }
  if (process.env.NODE_ENV === 'production' &&
      (!sessionSecret || sessionSecret.length < 32)) {
    throw new Error('SESSION_SECRET must be at least 32 characters in production');
  }

  const isProduction = process.env.NODE_ENV === 'production';
  const explicitSecureCookie = process.env.SESSION_COOKIE_SECURE;
  // Plain HTTP is the supported local-development transport. An accidentally
  // copied production value must not make the local login form lose its session.
  // Production remains secure by default; false is an explicit local override.
  const secureCookie = isProduction
    ? explicitSecureCookie !== 'false'
    : false;
  if (!isProduction && explicitSecureCookie === 'true') {
    console.warn('[warn] SESSION_COOKIE_SECURE=true is ignored in development; use HTTPS with NODE_ENV=production for secure cookies.');
  }
  if (isProduction && secureCookie === false) {
    console.warn('[warn] SESSION_COOKIE_SECURE=false disables HTTPS-only session cookies; use only for local HTTP testing.');
  }

  const sessionConfig = {
    name: 'sid',
    secret: sessionSecret || 'local-development-only-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,                             // not accessible via JS
      secure: secureCookie,                         // HTTPS-only by default in prod
      sameSite: 'lax',                            // CSRF mitigation layer
      maxAge: 2 * 60 * 60 * 1000,                // 2 hours
    },
  };

  // Use file store for persistence unless running tests (memory is fine there).
  if (process.env.NODE_ENV !== 'test') {
    sessionConfig.store = new FileStore({
      path: './sessions',
      ttl: 7200,      // seconds — matches cookie maxAge
      retries: 0,
    });
  }

  app.use(session(sessionConfig));

  // ── Expose persist() so route handlers can call app.locals.persistDb() ────
  // This avoids route files importing database.js directly and makes it
  // easy to swap the persist implementation in tests.
  app.locals.persistDb = db ? persist : () => {};

  // ── Routes ────────────────────────────────────────────────────────────────

  // Homepage: send authenticated users to their documents and visitors to login.
  app.get('/', (req, res) => {
    if (req.session && req.session.user) return res.redirect('/documents');
    return res.redirect('/auth/login');
  });

  // Health check — no auth required.
  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', ts: new Date().toISOString() });
  });

  // Auth routes — only mounted when a database is available.
  if (db) {
    app.use('/auth',                          createAuthRouter(db));
    app.use('/documents',        requireAuth, requireActiveAccount(db), createDocumentRouter(db));
    app.use('/documents/:id/permissions', requireAuth, requireActiveAccount(db), createPermissionsRouter(db));
    app.use('/admin',            requireAuth, requireActiveAccount(db), requireRole('admin', db), createAdminRouter(db));
  }

  // ── Error handlers ────────────────────────────────────────────────────────

  // 404
  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  // 500 — never leak internal detail to the client
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    console.error('[error]', err.message);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

module.exports = { createApp };
