'use strict';

/**
 * admin.js — Audit dashboard for administrators
 *
 * Security:
 *  - requireAuth + requireRole('admin') applied in app.js before this router.
 *  - Renders audit metadata only. No document file paths, storage names,
 *    or file contents are exposed here. Admins cannot download files
 *    merely by accessing this page.
 *  - All query parameters are validated/sanitized before use in SQL.
 *  - Results are paginated to avoid dumping the full log.
 *  - All dynamic values rendered via EJS <%= %> (HTML-escaped by default).
 */

const express = require('express');

const PAGE_SIZE = 50;

// Allowed filter values — anything else is ignored to prevent injection.
const ALLOWED_ACTIONS  = new Set([
  'document.upload', 'document.download',
  'permission.grant', 'permission.revoke',
]);
const ALLOWED_OUTCOMES = new Set(['success', 'denied', 'error']);

function createAdminRouter(db) {
  const router = express.Router();

  // ── GET /admin/audit ───────────────────────────────────────────────────────
  router.get('/audit', (req, res) => {
    // ── Parse and validate query parameters ──────────────────────────────
    const page    = Math.max(1, parseInt(req.query.page, 10) || 1);
    const offset  = (page - 1) * PAGE_SIZE;

    const filterAction  = ALLOWED_ACTIONS.has(req.query.action)   ? req.query.action   : null;
    const filterOutcome = ALLOWED_OUTCOMES.has(req.query.outcome)  ? req.query.outcome  : null;
    // actor filter: must be a positive integer string or empty
    const rawActor      = String(req.query.actor || '').trim();
    const filterActor   = /^\d+$/.test(rawActor) ? parseInt(rawActor, 10) : null;

    // ── Build WHERE clauses with parameterized bindings ───────────────────
    const conditions = [];
    const params     = [];

    if (filterAction)  { conditions.push('action = ?');   params.push(filterAction); }
    if (filterOutcome) { conditions.push('outcome = ?');  params.push(filterOutcome); }
    if (filterActor)   { conditions.push('actor_id = ?'); params.push(filterActor); }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // ── Fetch total count for pagination ──────────────────────────────────
    const countResult = db.exec(`SELECT COUNT(*) FROM audit_events ${where}`, params);
    const total       = countResult.length > 0 ? countResult[0].values[0][0] : 0;
    const totalPages  = Math.max(1, Math.ceil(total / PAGE_SIZE));

    // ── Fetch the page of results ─────────────────────────────────────────
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
      user:          req.session.user,
      allowedActions:  [...ALLOWED_ACTIONS],
      allowedOutcomes: [...ALLOWED_OUTCOMES],
    });
  });

  return router;
}

module.exports = { createAdminRouter };
