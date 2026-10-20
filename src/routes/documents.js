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
 */

const express = require('express');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');

const { csrfToken } = require('../middleware/csrf');

// ── Allowed file types ─────────────────────────────────────────────────────
// Checked by MIME type (from multer) AND magic bytes (first 8 bytes of file).
const ALLOWED_TYPES = {
  'application/pdf':                                { ext: '.pdf',  magic: [0x25, 0x50, 0x44, 0x46] },           // %PDF
  'text/plain':                                     { ext: '.txt',  magic: null },                                // no universal magic
  'image/png':                                      { ext: '.png',  magic: [0x89, 0x50, 0x4E, 0x47] },           // \x89PNG
  'image/jpeg':                                     { ext: '.jpg',  magic: [0xFF, 0xD8, 0xFF] },                  // JPEG SOI
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
                                                    { ext: '.docx', magic: [0x50, 0x4B, 0x03, 0x04] },           // PK zip header
};

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
const MAX_TITLE_LEN = 200;

// ── Multer storage ─────────────────────────────────────────────────────────
// destination and uploadsDir are set at router-creation time so tests can
// override the uploads directory without touching the real ./uploads/ folder.

function createStorage(uploadsDir) {
  return multer.diskStorage({
    destination(_req, _file, cb) {
      // Ensure the directory exists before multer tries to write.
      fs.mkdirSync(uploadsDir, { recursive: true });
      cb(null, uploadsDir);
    },
    filename(_req, _file, cb) {
      // UUID — no extension, no original name on disk.
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

// ── Magic-byte validation ─────────────────────────────────────────────────
// Read the first bytes of the stored file and compare to known signatures.
// Returns true if the magic bytes match (or if the type has no magic bytes).
function validateMagicBytes(filePath, mimeType) {
  const spec = ALLOWED_TYPES[mimeType];
  if (!spec || !spec.magic) return true; // text/plain has no universal magic

  const buf    = Buffer.alloc(spec.magic.length);
  const fd     = fs.openSync(filePath, 'r');
  const bytesRead = fs.readSync(fd, buf, 0, spec.magic.length, 0);
  fs.closeSync(fd);

  if (bytesRead < spec.magic.length) return false;
  return spec.magic.every((byte, i) => buf[i] === byte);
}

// ── Router factory ────────────────────────────────────────────────────────

/**
 * @param {import('sql.js').Database} db
 * @param {object} [opts]
 * @param {string} [opts.uploadsDir] Override uploads directory (used in tests)
 * @returns {import('express').Router}
 */
function createDocumentRouter(db, opts = {}) {
  const uploadsDir = opts.uploadsDir
    ? path.resolve(opts.uploadsDir)
    : path.resolve('./uploads');

  const upload = createUploader(uploadsDir);
  const router = express.Router();

  // ── GET /documents ───────────────────────────────────────────────────────
  // List documents the current user owns or has an active permission grant for.
  router.get('/', (req, res) => {
    const userId = req.session.user.id;

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
       ORDER BY d.created_at DESC`,
      [userId, userId]
    );

    const docs = result.length > 0
      ? result[0].values.map(([id, title, mimeType, sizeBytes, createdAt]) => ({
          id, title, mimeType, sizeBytes, createdAt,
        }))
      : [];

    res.render('documents/index', { docs, user: req.session.user });
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
  // NOTE: verifyCsrf is NOT applied as Express middleware here because for
  // multipart/form-data requests, req.body is empty until multer runs its
  // parser. We call verifyCsrf manually inside the multer callback, after
  // multer has populated req.body with the _csrf field.
  router.post('/upload', (req, res, next) => {
    const uploader = upload.single('file');

    uploader(req, res, async (err) => {
      // ── multer errors ────────────────────────────────────────────────────
      if (err) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(413).render('documents/upload', {
            error: `File exceeds the 10 MB size limit.`,
            token: csrfToken(req),
            user: req.session.user,
            allowedTypes: Object.keys(ALLOWED_TYPES).join(', '),
          });
        }
        if (err.code === 'DISALLOWED_TYPE') {
          return res.status(400).render('documents/upload', {
            error: 'File type not allowed. Permitted: PDF, TXT, PNG, JPEG, DOCX.',
            token: csrfToken(req),
            user: req.session.user,
            allowedTypes: Object.keys(ALLOWED_TYPES).join(', '),
          });
        }
        return next(err);
      }

      // ── CSRF check (after multer has parsed the multipart body) ──────────
      // For multipart/form-data, req.body is only populated after multer runs,
      // so CSRF must be verified here rather than as a pre-multer middleware.
      const submittedCsrf = req.body._csrf || req.headers['x-csrf-token'];
      const storedCsrf    = req.session && req.session.csrfToken;
      if (!submittedCsrf || !storedCsrf || submittedCsrf !== storedCsrf) {
        // If a file was already written, delete it before rejecting.
        if (req.file && req.file.path) {
          try { fs.unlinkSync(req.file.path); } catch (_) {}
        }
        return res.status(403).json({ error: 'Invalid or missing CSRF token' });
      }
      // Rotate the token after successful verification.
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');

      // ── No file uploaded ─────────────────────────────────────────────────
      if (!req.file) {
        return res.status(400).render('documents/upload', {
          error: 'Please select a file to upload.',
          token: csrfToken(req),
          user: req.session.user,
          allowedTypes: Object.keys(ALLOWED_TYPES).join(', '),
        });
      }

      const storedPath = req.file.path;

      // ── Magic-byte validation ─────────────────────────────────────────────
      // Verify the file content matches its declared MIME type.
      if (!validateMagicBytes(storedPath, req.file.mimetype)) {
        fs.unlinkSync(storedPath); // delete the suspicious file immediately
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
        return res.status(400).render('documents/upload', {
          error: `Title is required and must be ${MAX_TITLE_LEN} characters or fewer.`,
          token: csrfToken(req),
          user: req.session.user,
          allowedTypes: Object.keys(ALLOWED_TYPES).join(', '),
        });
      }

      // ── Insert document row ───────────────────────────────────────────────
      try {
        db.run(
          `INSERT INTO documents (owner_id, title, storage_name, mime_type, size_bytes)
           VALUES (?, ?, ?, ?, ?)`,
          [
            req.session.user.id,
            title,
            req.file.filename,   // UUID — server-generated, not the original name
            req.file.mimetype,
            req.file.size,
          ]
        );
        req.app.locals.persistDb();
      } catch (dbErr) {
        // Clean up the stored file if the DB insert fails.
        fs.unlinkSync(storedPath);
        return next(dbErr);
      }

      return res.redirect('/documents');
    });
  });

  // ── GET /documents/:id/download ──────────────────────────────────────────
  router.get('/:id/download', (req, res) => {
    // Validate that :id is a positive integer before touching the DB.
    const docId = parseInt(req.params.id, 10);
    if (!Number.isInteger(docId) || docId <= 0 || String(docId) !== req.params.id) {
      return res.status(400).json({ error: 'Invalid document ID' });
    }

    const userId = req.session.user.id;

    // Single query: fetch the document only if the requester is the owner
    // OR has an active (non-revoked) permission grant.
    // Never reveal whether a document exists to an unauthorized user.
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
      // Return 403 whether the document doesn't exist, belongs to someone else,
      // or the user simply has no grant — the caller cannot distinguish these.
      return res.status(403).json({ error: 'Forbidden' });
    }

    const [storageName, mimeType, title] = result[0].values[0];
    const filePath = path.join(uploadsDir, storageName);

    if (!fs.existsSync(filePath)) {
      // File is missing from disk — log but don't expose internals.
      console.error(`[download] file missing on disk: ${storageName}`);
      return res.status(500).json({ error: 'Internal server error' });
    }

    // Serve the file with the original title as the suggested download name.
    res.setHeader('Content-Disposition',
      `attachment; filename="${encodeURIComponent(title)}"`);
    res.setHeader('Content-Type', mimeType);
    res.sendFile(filePath);
  });

  return router;
}

module.exports = { createDocumentRouter, ALLOWED_TYPES, MAX_FILE_SIZE };
