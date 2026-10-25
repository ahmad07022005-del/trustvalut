'use strict';

/**
 * csrf.js — Synchronizer-token CSRF protection
 *
 * How it works:
 *  1. csrfToken(req) generates a random token and stores it in the session.
 *  2. EJS views embed the token as a hidden field named _csrf.
 *  3. verifyCsrf middleware checks that the submitted _csrf value matches
 *     the one stored in the session before allowing state-changing requests.
 *
 * This is the standard synchronizer-token pattern (OWASP recommended).
 * No third-party CSRF package is used.
 */

const crypto = require('crypto');

/**
 * Return (and lazily create) the CSRF token for the current session.
 * Call this in GET handlers to embed the token in the rendered form.
 *
 * @param {import('express').Request} req
 * @returns {string}
 */
function csrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

/**
 * Express middleware that validates the CSRF token on state-changing requests.
 * Reads the submitted token from req.body._csrf or the X-CSRF-Token header.
 * Responds with 403 if the token is missing or does not match.
 */
function verifyCsrf(req, res, next) {
  // Only check methods that change state.
  const checked = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (!checked.includes(req.method)) return next();

  const submitted = req.body._csrf || req.headers['x-csrf-token'];
  const stored    = req.session && req.session.csrfToken;

  if (!submitted || !stored || submitted !== stored) {
    const formViews = { '/login': 'login', '/register': 'register' };
    const view = formViews[req.path];
    if (view && req.accepts('html')) {
      return res.status(403).render(view, {
        error: 'Your form session expired or your browser did not send its session cookie. Refresh the page and try again.',
        token: csrfToken(req),
      });
    }
    return res.status(403).json({ error: 'Invalid or missing CSRF token' });
  }

  // Rotate the token after each successful use.
  req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  next();
}

module.exports = { csrfToken, verifyCsrf };
