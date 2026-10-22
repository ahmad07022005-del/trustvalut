'use strict';

/**
 * auth.js — Authentication and authorisation middleware
 *
 * requireAuth          — rejects unauthenticated requests (401/redirect)
 * requireActiveAccount — re-validates is_active on each request (must follow
 *                        requireAuth; requires `db` to be passed at mount time)
 * requireRole          — rejects users whose server-side role is insufficient
 *
 * Roles are NEVER read from client input. They are loaded from the database
 * when the session is established and stored in req.session.user.
 */

/**
 * Reject requests that have no authenticated session.
 * API callers get 401 JSON; browser requests are redirected to /auth/login.
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }

  if (req.accepts('html')) {
    return res.redirect('/auth/login');
  }
  return res.status(401).json({ error: 'Authentication required' });
}

/**
 * Factory that returns middleware which re-checks `is_active = 1` in the
 * database on every authenticated request.
 *
 * If the account has been deactivated the session is destroyed immediately
 * and the user is redirected (or gets 401).  This prevents a deactivated user
 * from continuing to use a session that was valid at login.
 *
 * Must be used AFTER requireAuth (so req.session.user is guaranteed to exist).
 *
 * @param {import('sql.js').Database} db
 */
function requireActiveAccount(db) {
  return (req, res, next) => {
    const userId = req.session.user.id;

    let isActive = false;
    try {
      const result = db.exec(
        'SELECT is_active FROM users WHERE id = ?',
        [userId]
      );
      isActive =
        result.length > 0 &&
        result[0].values.length > 0 &&
        result[0].values[0][0] === 1;
    } catch (dbErr) {
      // Treat any database error as inactive — fail closed.
      // The error is logged but the session is still destroyed.
      console.error('[requireActiveAccount] db error, failing closed:', dbErr.message);
      isActive = false;
    }

    if (isActive) return next();

    // Account deactivated (or DB error) — destroy the session immediately.
    // If destroy itself errors we still clear the cookie and reject the request;
    // we must never let execution fall through to next() on failure.
    req.session.destroy((destroyErr) => {
      if (destroyErr) {
        console.error('[requireActiveAccount] session destroy error:', destroyErr.message);
      }
      res.clearCookie('sid');
      if (req.accepts('html')) {
        return res.redirect('/auth/login');
      }
      return res.status(401).json({ error: 'Account deactivated' });
    });
  };
}

/**
 * Factory that returns middleware allowing only users with one of the
 * specified roles. Must be used after requireAuth.
 *
 * @param {...string} roles - Allowed roles, e.g. requireRole('admin')
 */
function requireRole(...roles) {
  return (req, res, next) => {
    const userRole = req.session && req.session.user && req.session.user.role;
    if (userRole && roles.includes(userRole)) {
      return next();
    }
    return res.status(403).json({ error: 'Forbidden' });
  };
}

module.exports = { requireAuth, requireActiveAccount, requireRole };
