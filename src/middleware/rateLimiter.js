'use strict';

/**
 * rateLimiter.js — Express rate-limit middleware factories
 *
 * Uses express-rate-limit v7 with the default in-memory store.
 *
 * STORE LIMITATION
 *   The in-memory store is per-process.  If the server is restarted or
 *   deployed across multiple processes/instances, the counters reset.
 *   For a production multi-process deployment, replace the store with a
 *   shared Redis store (e.g. rate-limit-redis).  See THREATS.md.
 *
 * ENVIRONMENT VARIABLES (all optional — defaults shown)
 *   RATE_LOGIN_MAX       Max login attempts per window (default: 10)
 *   RATE_LOGIN_WINDOW_MS Login window in milliseconds (default: 900000 = 15 min)
 *   RATE_REGISTER_MAX    Max registration attempts per window (default: 5)
 *   RATE_REGISTER_WINDOW_MS Registration window in ms (default: 3600000 = 1 hr)
 *   RATE_UPLOAD_MAX      Max upload attempts per window (default: 20)
 *   RATE_UPLOAD_WINDOW_MS Upload window in ms (default: 3600000 = 1 hr)
 *
 * Tests set NODE_ENV=test.  Limiters always skip when NODE_ENV=test so they
 * never interfere with the test suite.
 */

const rateLimit = require('express-rate-limit');

/**
 * Parse an env var as a positive integer; return defaultValue if absent/invalid.
 */
function envInt(name, defaultValue) {
  const raw = process.env[name];
  if (!raw) return defaultValue;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : defaultValue;
}

/**
 * Build a rate-limit middleware.
 * In test mode the middleware always calls next() immediately.
 *
 * @param {object} opts
 * @param {number} opts.max         - Max requests per windowMs
 * @param {number} opts.windowMs    - Window duration in milliseconds
 * @param {string} opts.message     - Human-readable error message on 429
 */
function buildLimiter({ max, windowMs, message }) {
  if (process.env.NODE_ENV === 'test') {
    // Return a pass-through middleware so tests are never affected.
    return (_req, _res, next) => next();
  }

  return rateLimit({
    max,
    windowMs,
    standardHeaders: true,   // Return rate limit info in RateLimit-* headers
    legacyHeaders:   false,   // Do not return X-RateLimit-* headers
    message:         { error: message },
    // keyGenerator defaults to req.ip — correct for a single-server deployment.
  });
}

/**
 * Rate limiter for POST /auth/login.
 * 10 attempts per 15-minute window per IP.
 */
const loginLimiter = buildLimiter({
  max:       envInt('RATE_LOGIN_MAX',       10),
  windowMs:  envInt('RATE_LOGIN_WINDOW_MS', 15 * 60 * 1000),
  message:   'Too many login attempts. Please wait before trying again.',
});

/**
 * Rate limiter for POST /auth/register.
 * 5 registrations per 1-hour window per IP.
 */
const registerLimiter = buildLimiter({
  max:       envInt('RATE_REGISTER_MAX',       5),
  windowMs:  envInt('RATE_REGISTER_WINDOW_MS', 60 * 60 * 1000),
  message:   'Too many registration attempts. Please wait before trying again.',
});

/**
 * Rate limiter for POST /documents/upload.
 * 20 uploads per 1-hour window per IP.
 */
const uploadLimiter = buildLimiter({
  max:       envInt('RATE_UPLOAD_MAX',       20),
  windowMs:  envInt('RATE_UPLOAD_WINDOW_MS', 60 * 60 * 1000),
  message:   'Too many upload attempts. Please wait before trying again.',
});

module.exports = { loginLimiter, registerLimiter, uploadLimiter };
