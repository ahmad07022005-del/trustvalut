'use strict';

/**
 * permissions.js — Document permission grant and revocation routes
 *
 * Security principles:
 *  - Only the document owner may grant or revoke permissions for their document.
 *    Ownership is verified server-side on every state-changing request.
 *  - Grantee is looked up by email address (server-resolved). Client never
 *    supplies a trusted user ID for the grantee.
 *  - An owner cannot grant permissions to themselves.
 *  - Permission level must be exactly 'read' or 'edit'; anything else is rejected.
 *  - Revoking sets revoked_at timestamp. The download query checks
 *    revoked_at IS NULL on every request, so revocation takes effect immediately.
 *  - All DB queries use parameterised statements.
 *  - CSRF protection is applied on all state-changing routes (POST).
 *  - requireAuth is applied at the router level in app.js.
 *  - Audit events are written for every significant outcome.
 */

const express = require('express');
const { csrfToken, verifyCsrf } = require('../middleware/csrf');
const { writeAuditEvent }       = require('../lib/audit');

const VALID_PERMISSIONS = new Set(['read', 'edit']);

/**
 * Helper: look up a document and verify the current user is its owner.
 * When ownership fails, writes a denied audit event and sends 403.
 *
 * @param {object}   req
 * @param {object}   res
 * @param {object}   db
 * @param {string}   auditAction  - e.g. 'permission.grant'
 * @returns {{ docId: number, title: string } | null}
 */
function requireDocumentOwner(req, res, db, auditAction) {
  const docId = parseInt(req.params.id, 10);
  if (!Number.isInteger(docId) || docId <= 0 || String(docId) !== req.params.id) {
    res.status(400).json({ error: 'Invalid document ID' });
    return null;
  }

  const result = db.exec(
    'SELECT id, title, owner_id FROM documents WHERE id = ? AND is_deleted = 0',
    [docId]
  );

  if (result.length === 0 || result[0].values.length === 0) {
    if (auditAction) {
      writeAuditEvent(db, req.app.locals.persistDb, {
        actorId:   req.session.user.id,
        action:    auditAction,
        resource:  `document:${docId}`,
        outcome:   'denied',
        detail:    { reason: 'document_not_found' },
        ipAddress: req.ip,
      });
    }
    res.status(403).json({ error: 'Forbidden' });
    return null;
  }

  const [id, title, ownerId] = result[0].values[0];

  if (ownerId !== req.session.user.id) {
    if (auditAction) {
      writeAuditEvent(db, req.app.locals.persistDb, {
        actorId:   req.session.user.id,
        action:    auditAction,
        resource:  `document:${docId}`,
        outcome:   'denied',
        detail:    { reason: 'not_owner' },
        ipAddress: req.ip,
      });
    }
    res.status(403).json({ error: 'Forbidden' });
    return null;
  }

  return { docId: id, title };
}

/**
 * @param {import('sql.js').Database} db
 * @returns {import('express').Router}
 */
function createPermissionsRouter(db) {
  const router = express.Router({ mergeParams: true });

  // Shorthand audit writer
  function audit(req, event) {
    return writeAuditEvent(db, req.app.locals.persistDb, {
      actorId:   req.session && req.session.user ? req.session.user.id : null,
      ipAddress: req.ip,
      ...event,
    });
  }

  // ── GET /documents/:id/permissions ────────────────────────────────────────
  router.get('/', (req, res) => {
    // Pass null for auditAction on GET — we don't audit page views.
    const doc = requireDocumentOwner(req, res, db, null);
    if (!doc) return;

    const result = db.exec(
      `SELECT dp.id, u.email, dp.permission, dp.granted_at, dp.revoked_at
       FROM document_permissions dp
       JOIN users u ON u.id = dp.user_id
       WHERE dp.document_id = ?
       ORDER BY dp.granted_at DESC`,
      [doc.docId]
    );

    const grants = result.length > 0
      ? result[0].values.map(([grantId, email, permission, grantedAt, revokedAt]) => ({
          grantId, email, permission, grantedAt,
          active: revokedAt === null,
        }))
      : [];

    res.render('documents/permissions', {
      doc, grants, error: null, success: null,
      token: csrfToken(req), user: req.session.user,
    });
  });

  // ── POST /documents/:id/permissions/grant ──────────────────────────────────
  router.post('/grant', verifyCsrf, (req, res) => {
    const doc = requireDocumentOwner(req, res, db, 'permission.grant');
    if (!doc) return;

    const { grantee_email, permission } = req.body;

    if (!VALID_PERMISSIONS.has(permission)) {
      return renderPermissionsPage(req, res, db, doc,
        'Permission level must be "read" or "edit".', null);
    }

    if (typeof grantee_email !== 'string' || !grantee_email.trim()) {
      return renderPermissionsPage(req, res, db, doc,
        'Grantee email is required.', null);
    }

    const normalizedEmail = grantee_email.toLowerCase().trim();

    const granteeResult = db.exec(
      'SELECT id FROM users WHERE email = ? AND is_active = 1',
      [normalizedEmail]
    );

    if (granteeResult.length === 0 || granteeResult[0].values.length === 0) {
      return renderPermissionsPage(req, res, db, doc,
        'No active registered user found with that email address.', null);
    }

    const granteeId = granteeResult[0].values[0][0];

    if (granteeId === req.session.user.id) {
      return renderPermissionsPage(req, res, db, doc,
        'You cannot grant permissions to yourself.', null);
    }

    const existing = db.exec(
      `SELECT id, permission FROM document_permissions
       WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL`,
      [doc.docId, granteeId]
    );

    if (existing.length > 0 && existing[0].values.some(row => row[1] === permission)) {
      return renderPermissionsPage(req, res, db, doc,
        `That user already has an active "${permission}" grant for this document.`, null);
    }

    db.run('BEGIN');
    try {
      db.run(
        `UPDATE document_permissions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL`,
        [doc.docId, granteeId]
      );
      db.run(
        `INSERT INTO document_permissions (document_id, user_id, permission, granted_by)
         VALUES (?, ?, ?, ?)`,
        [doc.docId, granteeId, permission, req.session.user.id]
      );
      const auditOk = writeAuditEvent(db, () => {}, {
        actorId: req.session.user.id, ipAddress: req.ip,
        action: existing.length && existing[0].values.length ? 'permission.update' : 'permission.grant', resource: `document:${doc.docId}`,
        outcome: 'success', detail: { docId: doc.docId, granteeId, permission },
      });
      if (!auditOk) throw new Error('mandatory audit write failed');
      db.run('COMMIT');
      req.app.locals.persistDb();
    } catch (err) {
      try { db.run('ROLLBACK'); } catch (_) {}
      audit(req, { action:'permission.grant', resource:`document:${doc.docId}`, outcome:'error', detail:{ reason:'transaction_failed' } });
      return res.status(500).json({ error: 'Permission change could not be recorded' });
    }

    return renderPermissionsPage(req, res, db, doc,
      null, `Granted "${permission}" access to ${normalizedEmail}.`);
  });

  // ── POST /documents/:id/permissions/:permId/revoke ─────────────────────────
  router.post('/:permId/revoke', verifyCsrf, (req, res) => {
    const doc = requireDocumentOwner(req, res, db, 'permission.revoke');
    if (!doc) return;

    const permId = parseInt(req.params.permId, 10);
    if (!Number.isInteger(permId) || permId <= 0 || String(permId) !== req.params.permId) {
      return res.status(400).json({ error: 'Invalid permission ID' });
    }

    const permResult = db.exec(
      `SELECT id, user_id FROM document_permissions
       WHERE id = ? AND document_id = ? AND revoked_at IS NULL`,
      [permId, doc.docId]
    );

    if (permResult.length === 0 || permResult[0].values.length === 0) {
      return renderPermissionsPage(req, res, db, doc,
        'Permission not found or already revoked.', null);
    }

    const revokedUserId = permResult[0].values[0][1];

    db.run('BEGIN');
    try {
      db.run(
        `UPDATE document_permissions
         SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?`, [permId]
      );
      const auditOk = writeAuditEvent(db, () => {}, {
        actorId: req.session.user.id, ipAddress: req.ip,
        action:'permission.revoke', resource:`document:${doc.docId}`,
        outcome:'success', detail:{ docId:doc.docId, revokedUserId, permId },
      });
      if (!auditOk) throw new Error('mandatory audit write failed');
      db.run('COMMIT');
      req.app.locals.persistDb();
    } catch (err) {
      try { db.run('ROLLBACK'); } catch (_) {}
      audit(req, { action:'permission.revoke', resource:`document:${doc.docId}`, outcome:'error', detail:{ reason:'transaction_failed' } });
      return res.status(500).json({ error: 'Permission change could not be recorded' });
    }

    return renderPermissionsPage(req, res, db, doc,
      null, 'Permission revoked successfully.');
  });

  return router;
}

function renderPermissionsPage(req, res, db, doc, error, success) {
  const result = db.exec(
    `SELECT dp.id, u.email, dp.permission, dp.granted_at, dp.revoked_at
     FROM document_permissions dp
     JOIN users u ON u.id = dp.user_id
     WHERE dp.document_id = ?
     ORDER BY dp.granted_at DESC`,
    [doc.docId]
  );

  const grants = result.length > 0
    ? result[0].values.map(([grantId, email, permission, grantedAt, revokedAt]) => ({
        grantId, email, permission, grantedAt,
        active: revokedAt === null,
      }))
    : [];

  return res.render('documents/permissions', {
    doc, grants, error, success,
    token: csrfToken(req), user: req.session.user,
  });
}

module.exports = { createPermissionsRouter };
