'use strict';

/**
 * auth.js — Registration, login, and logout routes
 *
 * Security notes:
 *  - Passwords are hashed with bcryptjs (cost factor 12) before storage.
 *  - Roles are assigned server-side only; any role field in the request body
 *    is ignored entirely.
 *  - All DB queries use parameterised statements (sql.js .run / .exec).
 *  - Sessions are regenerated after login to prevent fixation attacks.
 *  - Error messages are deliberately vague on login failure to prevent
 *    user-enumeration.
 *  - The CSRF token is validated by verifyCsrf middleware on every POST.
 */

const express  = require('express');
const bcrypt   = require('bcryptjs');
const { csrfToken, verifyCsrf } = require('../middleware/csrf');

const BCRYPT_ROUNDS = 12;

// Minimal input validation helpers — no third-party validator needed.
function isValidEmail(value) {
  // RFC-5322-ish; good enough for server-side gating.
  return typeof value === 'string'
    && value.length <= 254
    && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isValidPassword(value) {
  return typeof value === 'string'
    && value.length >= 12
    && value.length <= 128;
}

/**
 * @param {import('sql.js').Database} db
 * @returns {import('express').Router}
 */
function createAuthRouter(db) {
  const router = express.Router();

  // ── GET /auth/register ─────────────────────────────────────────────────────
  router.get('/register', (req, res) => {
    res.render('register', { error: null, token: csrfToken(req) });
  });

  // ── POST /auth/register ────────────────────────────────────────────────────
  router.post('/register', verifyCsrf, async (req, res) => {
    const { email, password } = req.body;

    if (!isValidEmail(email)) {
      return res.status(400).render('register', {
        error: 'Please enter a valid email address.',
        token: csrfToken(req),
      });
    }

    if (!isValidPassword(password)) {
      return res.status(400).render('register', {
        error: 'Password must be between 12 and 128 characters.',
        token: csrfToken(req),
      });
    }

    // Check for duplicate email (case-insensitive via COLLATE NOCASE in schema).
    const existing = db.exec(
      'SELECT id FROM users WHERE email = ?',
      [email.toLowerCase().trim()]
    );
    if (existing.length > 0 && existing[0].values.length > 0) {
      return res.status(409).render('register', {
        error: 'An account with that email already exists.',
        token: csrfToken(req),
      });
    }

    // Hash the password server-side; role is always 'viewer' at registration.
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    db.run(
      'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
      [email.toLowerCase().trim(), hash, 'viewer']
    );

    // Persist the new user to disk immediately.
    req.app.locals.persistDb();

    return res.redirect('/auth/login');
  });

  // ── GET /auth/login ────────────────────────────────────────────────────────
  router.get('/login', (req, res) => {
    res.render('login', { error: null, token: csrfToken(req) });
  });

  // ── POST /auth/login ───────────────────────────────────────────────────────
  router.post('/login', verifyCsrf, async (req, res) => {
    const { email, password } = req.body;

    if (!isValidEmail(email) || !isValidPassword(password)) {
      return res.status(400).render('login', {
        error: 'Invalid email or password.',
        token: csrfToken(req),
      });
    }

    // Fetch the user record by email.
    const result = db.exec(
      'SELECT id, email, password_hash, role, is_active FROM users WHERE email = ?',
      [email.toLowerCase().trim()]
    );

    const row = result.length > 0 && result[0].values.length > 0
      ? result[0].values[0]
      : null;

    // Use a constant-time comparison via bcrypt even when no row exists,
    // to avoid timing-based user enumeration.
    const hashToCheck = row ? row[2] : '$2a$12$invalidhashfortimingnormalization';
    const match = await bcrypt.compare(password, hashToCheck);

    if (!row || !match) {
      return res.status(401).render('login', {
        error: 'Invalid email or password.',
        token: csrfToken(req),
      });
    }

    const [id, userEmail, , role, is_active] = row;

    if (!is_active) {
      return res.status(403).render('login', {
        error: 'This account has been deactivated.',
        token: csrfToken(req),
      });
    }

    // Regenerate the session to prevent fixation attacks.
    req.session.regenerate((err) => {
      if (err) {
        console.error('[login] session regenerate error:', err.message);
        return res.status(500).render('login', {
          error: 'An error occurred. Please try again.',
          token: csrfToken(req),
        });
      }

      // Store only the minimum identity info server-side.
      // Role comes from the database row, never from client input.
      req.session.user = { id, email: userEmail, role };

      res.redirect('/');
    });
  });

  // ── POST /auth/logout ──────────────────────────────────────────────────────
  router.post('/logout', verifyCsrf, (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.error('[logout] session destroy error:', err.message);
      }
      res.clearCookie('sid');
      res.redirect('/auth/login');
    });
  });

  return router;
}

module.exports = { createAuthRouter };
