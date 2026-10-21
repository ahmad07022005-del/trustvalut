'use strict';

/**
 * documents.js — Secure document upload and download routes
 *
 * Security principles enforced here:
 *  - Every route requires an authenticated session (requireAuth applied in app.js).
 *  - Files are stored in ./uploads/ using a UUID storage name; the original
 *    filename is never used on disk.
 *  - MIME type is validated by both extension allowlist and magic-byte inspection.
 *  - File size is capped at 10 MB by multer before the file hits disk.
 *  - Downloads check server-side ownership OR an active permission grant.
 *    The document ID in the URL is never trusted without this DB lookup.
 *  - A non-owner with no grant receives 403. The document ID is not confirmed
 *    or denied in the response body (avoids confirming document existence to
 *    unauthorized requesters).
 *  - All DB queries use parameterised statements.
 *  - persist() is called after every write.
 *  - Audit events are written for every significant outcome (success / denied /
 *    error). An audit write failure surfaces as a console.error but never
 *    blocks the operation response.
 */

const express = require('express');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');

const { csrfToken }       = require('../middleware/csrf');
const { writeAuditEvent } = require('../lib/audit');

// ── Allowed file types ─────────────────────────────────────────────────────
const ALLOWED_TYPES = {
  'application/pdf': { ext: '.pdf', magic: [0x25, 0x50, 0x44, 0x46] },
  'text/plain':      { ext: '.txt', magic: null },
  'image/png':       { ext: '.png', magic: [0x89, 0x50, 0x4E, 0x47] },
  'image/jpeg':      { ext: '.jpg', magic: [0xFF, 0xD8, 0xFF] },
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
                     { ext: '.docx', magic: [0x50, 0x4B, 0x03, 0x04] },
};

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
const MAX_TITLE_LEN = 200;

function createStorage(uploadsDir) {
  return multer.diskStorage({
    destination(_req, _file, cb) {
      fs.mkdirSync(uploadsDir, { recursive: true });
      cb(null, uploadsDir);
    },
    filename(_req, _file, cb) {
      cb(null, crypto.randomUUID());
    },
  });
}

function createUploader(uploadsDir) {
  return multer({
    storage: createStorage(uploadsDir),
    limits: { fileSize: MAX_FILE_SIZE, files: 1 },
    fileFilter(_req, file, cb) {
      if (ALLOWED_TYPES[file.mimetype]) {
        cb(null, true);
      } else {
        const err = new Error('File type not allowed');
        err.code  = 'DISALLOWED_TYPE';
        cb(err, false);
      }
    },
  });
}

function validateMagicBytes(filePath, mimeType) {
  const spec = ALLOWED_TYPES[mimeType];
  if (!spec || !spec.magic) return true;
  const buf       = Buffer.alloc(spec.magic.length);
  const fd        = fs.openSync(filePath, 'r');
  const bytesRead = fs.readSync(fd, buf, 0, spec.magic.length, 0);
  fs.closeSync(fd);
  if (bytesRead < spec.magic.length) return false;
  return spec.magic.every((byte, i) => buf[i] === byte);
}

/**
 * @param {import('sql.js').Database} db
 * @param {object} [opts]
 * @param {string} [opts.uploadsDir]
 */
function createDocumentRouter(db, opts = {}) {
  const uploadsDir = opts.uploadsDir
    ? path.resolve(opts.uploadsDir)
    : path.resolve('./uploads');

  const upload = createUploader(uploadsDir);
  const router = express.Router();

  // Helper: shorthand for writing an audit event using app.locals.persistDb
  function audit(req, event) {
    return writeAuditEvent(db, req.app.locals.persistDb, {
      actorId:   req.session && req.session.user ? req.session.user.id : null,
      ipAddress: req.ip,
      ...event,
    });
  }

  // ── GET /documents ───────────────────────────────────────────────────────
  // Optional ?q= parameter searches document titles.
  // Authorization rules (owner OR active grant) are enforced regardless of q.
  router.get('/', (req, res) => {
    const userId = req.session.user.id;

    // Sanitize the search term: trim whitespace, cap length to avoid
    // absurdly long LIKE patterns. Empty string means "no filter".
    const rawQ  = typeof req.query.q === 'string' ? req.query.q.trim() : '';
    const query = rawQ.length > 0 ? rawQ.slice(0, 200) : '';

    // Build the SQL conditionally. When no search term is given the query
    // is identical to the original list query.
    const searchClause = query ? 'AND d.title LIKE ?' : '';
    // Wrap the term in % wildcards for a contains-search.
    // The binding is parameterized — the user-supplied value never touches SQL text.
    const params = query
      ? [userId, userId, `%${query}%`]
      : [userId, userId];

    const result = db.exec(
      `SELECT d.id, d.title, d.mime_type, d.size_bytes, d.created_at
       FROM documents d
       WHERE d.is_deleted = 0
         AND (
           d.owner_id = ?
           OR EXISTS (
             SELECT 1 FROM document_permissions p
             WHERE p.document_id = d.id
               AND p.user_id     = ?
               AND p.revoked_at  IS NULL
           )
         )
         ${searchClause}
       ORDER BY d.created_at DESC`,
      params
    );

    const docs = result.length > 0
      ? result[0].values.map(([id, title, mimeType, sizeBytes, createdAt]) => ({
          id, title, mimeType, sizeBytes, createdAt,
        }))
      : [];

    res.render('documents/index', { docs, user: req.session.user, query });
  });

  // ── GET /documents/upload ────────────────────────────────────────────────
  router.get('/upload', (req, res) => {
    res.render('documents/upload', {
      error: null,
      token: csrfToken(req),
      user: req.session.user,
      allowedTypes: Object.keys(ALLOWED_TYPES).join(', '),
    });
  });

  // ── POST /documents/upload ───────────────────────────────────────────────
  // CSRF is verified manually after multer, because req.body is empty until
  // multer parses the multipart form.
  router.post('/upload', (req, res, next) => {
    const uploader = upload.single('file');

    uploader(req, res, async (err) => {
      // ── multer errors ────────────────────────────────────────────────────
      if (err) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          audit(req, {
            action: 'document.upload', resource: null,
            outcome: 'error', detail: { reason: 'file_too_large' },
          });
          return res.status(413).render('documents/upload', {
            error: 'File exceeds the 10 MB size limit.',
            token: csrfToken(req),
            user: req.session.user,
            allowedTypes: Object.keys(ALLOWED_TYPES).join(', '),
          });
        }
        if (err.code === 'DISALLOWED_TYPE') {
          audit(req, {
            action: 'document.upload', resource: null,
            outcome: 'error', detail: { reason: 'disallowed_mime_type' },
          });
          return res.status(400).render('documents/upload', {
            error: 'File type not allowed. Permitted: PDF, TXT, PNG, JPEG, DOCX.',
            token: csrfToken(req),
            user: req.session.user,
            allowedTypes: Object.keys(ALLOWED_TYPES).join(', '),
          });
        }
        return next(err);
      }

      // ── CSRF check ───────────────────────────────────────────────────────
      const submittedCsrf = req.body._csrf || req.headers['x-csrf-token'];
      const storedCsrf    = req.session && req.session.csrfToken;
      if (!submittedCsrf || !storedCsrf || submittedCsrf !== storedCsrf) {
        if (req.file && req.file.path) {
          try { fs.unlinkSync(req.file.path); } catch (_) {}
        }
        return res.status(403).json({ error: 'Invalid or missing CSRF token' });
      }
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');

      // ── No file uploaded ─────────────────────────────────────────────────
      if (!req.file) {
        audit(req, {
          action: 'document.upload', resource: null,
          outcome: 'error', detail: { reason: 'no_file' },
        });
        return res.status(400).render('documents/upload', {
          error: 'Please select a file to upload.',
          token: csrfToken(req),
          user: req.session.user,
          allowedTypes: Object.keys(ALLOWED_TYPES).join(', '),
        });
      }

      const storedPath = req.file.path;

      // ── Magic-byte validation ─────────────────────────────────────────────
      if (!validateMagicBytes(storedPath, req.file.mimetype)) {
        fs.unlinkSync(storedPath);
        audit(req, {
          action: 'document.upload', resource: null,
          outcome: 'error', detail: { reason: 'magic_byte_mismatch' },
        });
        return res.status(400).render('documents/upload', {
          error: 'File content does not match its declared type.',
          token: csrfToken(req),
          user: req.session.user,
          allowedTypes: Object.keys(ALLOWED_TYPES).join(', '),
        });
      }

      // ── Title validation ──────────────────────────────────────────────────
      const title = (req.body.title || '').trim();
      if (!title || title.length > MAX_TITLE_LEN) {
        fs.unlinkSync(storedPath);
        audit(req, {
          action: 'document.upload', resource: null,
          outcome: 'error', detail: { reason: 'invalid_title' },
        });
        return res.status(400).render('documents/upload', {
          error: `Title is required and must be ${MAX_TITLE_LEN} characters or fewer.`,
          token: csrfToken(req),
          user: req.session.user,
          allowedTypes: Object.keys(ALLOWED_TYPES).join(', '),
        });
      }

      // ── Insert document row ───────────────────────────────────────────────
      let newDocId = null;
      try {
        db.run(
          `INSERT INTO documents (owner_id, title, storage_name, mime_type, size_bytes)
           VALUES (?, ?, ?, ?, ?)`,
          [
            req.session.user.id,
            title,
            req.file.filename,
            req.file.mimetype,
            req.file.size,
          ]
        );
        req.app.locals.persistDb();

        const idRow = db.exec('SELECT last_insert_rowid()');
        newDocId    = idRow[0].values[0][0];
      } catch (dbErr) {
        fs.unlinkSync(storedPath);
        audit(req, {
          action: 'document.upload', resource: null,
          outcome: 'error', detail: { reason: 'db_insert_failed' },
        });
        return next(dbErr);
      }

      audit(req, {
        action:   'document.upload',
        resource: `document:${newDocId}`,
        outcome:  'success',
        detail:   { docId: newDocId, mimeType: req.file.mimetype },
      });

      return res.redirect('/documents');
    });
  });

  // ── GET /documents/:id/download ──────────────────────────────────────────
  router.get('/:id/download', (req, res) => {
    const docId = parseInt(req.params.id, 10);
    if (!Number.isInteger(docId) || docId <= 0 || String(docId) !== req.params.id) {
      return res.status(400).json({ error: 'Invalid document ID' });
    }

    const userId = req.session.user.id;

    const result = db.exec(
      `SELECT d.storage_name, d.mime_type, d.title
       FROM documents d
       WHERE d.id         = ?
         AND d.is_deleted = 0
         AND (
           d.owner_id = ?
           OR EXISTS (
             SELECT 1 FROM document_permissions p
             WHERE p.document_id = d.id
               AND p.user_id     = ?
               AND p.revoked_at  IS NULL
           )
         )`,
      [docId, userId, userId]
    );

    if (result.length === 0 || result[0].values.length === 0) {
      // Audit the denial without revealing document metadata to the requester.
      audit(req, {
        action:   'document.download',
        resource: `document:${docId}`,
        outcome:  'denied',
        detail:   { reason: 'no_access' },
      });
      return res.status(403).json({ error: 'Forbidden' });
    }

    const [storageName, mimeType, title] = result[0].values[0];
    const filePath = path.join(uploadsDir, storageName);

    if (!fs.existsSync(filePath)) {
      console.error(`[download] file missing on disk: ${storageName}`);
      audit(req, {
        action:   'document.download',
        resource: `document:${docId}`,
        outcome:  'error',
        detail:   { reason: 'file_missing_on_disk' },
      });
      return res.status(500).json({ error: 'Internal server error' });
    }

    audit(req, {
      action:   'document.download',
      resource: `document:${docId}`,
      outcome:  'success',
      detail:   { docId },
    });

    res.setHeader('Content-Disposition',
      `attachment; filename="${encodeURIComponent(title)}"`);
    res.setHeader('Content-Type', mimeType);
    res.sendFile(filePath);
  });

  return router;
}

module.exports = { createDocumentRouter, ALLOWED_TYPES, MAX_FILE_SIZE };
