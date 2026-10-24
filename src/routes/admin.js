'use strict';

/**
 * admin.js — Admin-only routes
 *
 * Routes:
 *   GET  /admin/audit              — paginated, filtered audit log
 *   POST /admin/users/:id/deactivate — deactivate a user account (admin only)
 *   POST /admin/users/:id/activate   — re-activate a user account (admin only)
 *
 * Security:
 *  - requireAuth + requireRole('admin') + requireActiveAccount applied in app.js.
 *  - Audit page renders metadata only — no document file paths, storage names,
 *    or file contents. Admins cannot download files from here.
 *  - All query parameters are validated/sanitized before use in SQL.
 *  - Results are paginated (50/page).
 *  - All dynamic values rendered via EJS <%= %> (HTML-escaped by default).
 *  - Date filter values are validated as ISO-8601 date strings before use.
 */

const express = require('express');
const { verifyCsrf }      = require('../middleware/csrf');
const { writeAuditEvent } = require('../lib/audit');

const PAGE_SIZE = 50;

const ALLOWED_ACTIONS  = new Set([
  'document.upload', 'document.download', 'document.edit', 'document.delete',
  'permission.grant', 'permission.revoke',
  'auth.login', 'auth.logout',
  'admin.deactivate', 'admin.activate', 'admin.category.delete',
]);
const ALLOWED_OUTCOMES = new Set(['success', 'denied', 'error']);

// Validate a date parameter: must be YYYY-MM-DD or empty.
function sanitizeDate(value) {
  if (!value || typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return trimmed;
  return null;
}

function createAdminRouter(db) {
  const router = express.Router();

  // ── GET /admin/audit ───────────────────────────────────────────────────────
  router.get('/audit', (req, res) => {
    const page    = Math.max(1, parseInt(req.query.page, 10) || 1);
    const offset  = (page - 1) * PAGE_SIZE;

    const filterAction  = ALLOWED_ACTIONS.has(req.query.action)   ? req.query.action   : null;
    const filterOutcome = ALLOWED_OUTCOMES.has(req.query.outcome)  ? req.query.outcome  : null;
    const rawActor      = String(req.query.actor || '').trim();
    const filterActor   = /^\d+$/.test(rawActor) ? parseInt(rawActor, 10) : null;
    const filterFrom    = sanitizeDate(req.query.from);
    const filterTo      = sanitizeDate(req.query.to);

    const conditions = [];
    const params     = [];

    if (filterAction)  { conditions.push('ae.action = ?');             params.push(filterAction); }
    if (filterOutcome) { conditions.push('ae.outcome = ?');            params.push(filterOutcome); }
    if (filterActor)   { conditions.push('ae.actor_id = ?');           params.push(filterActor); }
    // Date range: occurred_at is stored as ISO-8601 UTC text; string comparison is correct.
    if (filterFrom)    { conditions.push("ae.occurred_at >= ?");       params.push(filterFrom); }
    if (filterTo)      { conditions.push("ae.occurred_at < date(?, '+1 day')"); params.push(filterTo); }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countResult = db.exec(`SELECT COUNT(*) FROM audit_events ae ${where}`, params);
    const total       = countResult.length > 0 ? countResult[0].values[0][0] : 0;
    const totalPages  = Math.max(1, Math.ceil(total / PAGE_SIZE));

    const eventsResult = db.exec(
      `SELECT ae.id, ae.actor_id, u.email, ae.action, ae.resource,
              ae.outcome, ae.detail, ae.occurred_at
       FROM audit_events ae
       LEFT JOIN users u ON u.id = ae.actor_id
       ${where}
       ORDER BY ae.id DESC
       LIMIT ? OFFSET ?`,
      [...params, PAGE_SIZE, offset]
    );

    const events = eventsResult.length > 0
      ? eventsResult[0].values.map(
          ([id, actorId, email, action, resource, outcome, detail, occurredAt]) => ({
            id, actorId, email, action, resource, outcome, detail, occurredAt,
          })
        )
      : [];

    res.render('admin/audit', {
      events,
      page,
      totalPages,
      total,
      filterAction:  filterAction  || '',
      filterOutcome: filterOutcome || '',
      filterActor:   filterActor   || '',
      filterFrom:    filterFrom    || '',
      filterTo:      filterTo      || '',
      user:          req.session.user,
      allowedActions:  [...ALLOWED_ACTIONS],
      allowedOutcomes: [...ALLOWED_OUTCOMES],
    });
  });

  // ── POST /admin/users/:id/deactivate ───────────────────────────────────────
  router.post('/users/:id/deactivate', verifyCsrf, (req, res) => {
    const targetId = parseInt(req.params.id, 10);
    if (!Number.isInteger(targetId) || targetId <= 0 || String(targetId) !== req.params.id) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    // An admin cannot deactivate themselves.
    if (targetId === req.session.user.id) {
      return res.status(400).json({ error: 'You cannot deactivate your own account' });
    }

    const result = db.exec('SELECT id FROM users WHERE id = ?', [targetId]);
    if (result.length === 0 || result[0].values.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    db.run('UPDATE users SET is_active = 0, updated_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\', \'now\') WHERE id = ?', [targetId]);
    req.app.locals.persistDb();

    writeAuditEvent(db, req.app.locals.persistDb, {
      actorId:   req.session.user.id,
      action:    'admin.deactivate',
      resource:  `user:${targetId}`,
      outcome:   'success',
      detail:    { targetId },
      ipAddress: req.ip,
    });

    return res.redirect('/admin/users');
  });

  // ── POST /admin/users/:id/activate ────────────────────────────────────────
  router.post('/users/:id/activate', verifyCsrf, (req, res) => {
    const targetId = parseInt(req.params.id, 10);
    if (!Number.isInteger(targetId) || targetId <= 0 || String(targetId) !== req.params.id) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    const result = db.exec('SELECT id FROM users WHERE id = ?', [targetId]);
    if (result.length === 0 || result[0].values.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    db.run('UPDATE users SET is_active = 1, updated_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\', \'now\') WHERE id = ?', [targetId]);
    req.app.locals.persistDb();

    writeAuditEvent(db, req.app.locals.persistDb, {
      actorId:   req.session.user.id,
      action:    'admin.activate',
      resource:  `user:${targetId}`,
      outcome:   'success',
      detail:    { targetId },
      ipAddress: req.ip,
    });

    return res.redirect('/admin/users');
  });

  // ── GET /admin/users ───────────────────────────────────────────────────────
  router.get('/users', (req, res) => {
    const result = db.exec(
      'SELECT id, email, role, is_active, created_at FROM users ORDER BY created_at DESC'
    );
    const users = result.length > 0
      ? result[0].values.map(([id, email, role, isActive, createdAt]) => ({
          id, email, role, isActive: isActive === 1, createdAt,
        }))
      : [];

    // Import csrfToken for the CSRF hidden field in the deactivate/activate forms.
    const { csrfToken } = require('../middleware/csrf');
    res.render('admin/users', { users, user: req.session.user, token: csrfToken(req) });
  });

  router.get('/categories', (req, res) => {
    const result = db.exec(`SELECT c.id, c.name, COUNT(d.id)
      FROM categories c LEFT JOIN documents d ON d.category_id = c.id AND d.is_deleted = 0
      GROUP BY c.id ORDER BY c.name`);
    const categories = result.length ? result[0].values.map(([id, name, documentCount]) => ({ id, name, documentCount })) : [];
    const { csrfToken } = require('../middleware/csrf');
    return res.render('admin/categories', { categories, user: req.session.user, token: csrfToken(req) });
  });

  router.post('/categories/:id/delete', verifyCsrf, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0 || String(id) !== req.params.id) return res.status(400).json({ error: 'Invalid category ID' });
    const result = db.exec('SELECT id FROM categories WHERE id = ?', [id]);
    if (!result.length || !result[0].values.length) return res.status(404).json({ error: 'Category not found' });
    db.run('DELETE FROM categories WHERE id = ?', [id]);
    req.app.locals.persistDb();
    writeAuditEvent(db, req.app.locals.persistDb, { actorId: req.session.user.id, action: 'admin.category.delete', resource: `category:${id}`, outcome: 'success', detail: { categoryId: id }, ipAddress: req.ip });
    return res.redirect('/admin/categories');
  });

  return router;
}

module.exports = { createAdminRouter };
