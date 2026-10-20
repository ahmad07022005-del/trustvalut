'use strict';

/**
 * auth.js — Authentication and authorisation middleware
 *
 * requireAuth    — rejects unauthenticated requests (401 JSON or redirect)
 * requireRole    — rejects users whose server-side role is insufficient
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

  // Distinguish API from browser requests by Accept header.
  if (req.accepts('html')) {
    return res.redirect('/auth/login');
  }
  return res.status(401).json({ error: 'Authentication required' });
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

module.exports = { requireAuth, requireRole };
