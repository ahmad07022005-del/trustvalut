'use strict';

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { csrfToken } = require('../middleware/csrf');
const { writeAuditEvent } = require('../lib/audit');
const { uploadLimiter } = require('../middleware/rateLimiter');
const { containedPath } = require('../lib/paths');

const ALLOWED_TYPES = {
  'application/pdf': { ext: '.pdf', magic: [0x25, 0x50, 0x44, 0x46] },
  'text/plain': { ext: '.txt', magic: null },
  'image/png': { ext: '.png', magic: [0x89, 0x50, 0x4e, 0x47] },
  'image/jpeg': { ext: '.jpg', magic: [0xff, 0xd8, 0xff] },
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': { ext: '.docx', magic: [0x50, 0x4b, 0x03, 0x04] },
};
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_TITLE_LEN = 200;
const MAX_DESCRIPTION_LEN = 2000;

function isValidEmail(value) {
  return typeof value === 'string'
    && value.length <= 254
    && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function createStorage(uploadsDir) {
  return multer.diskStorage({
    destination(_req, _file, cb) { fs.mkdirSync(uploadsDir, { recursive: true }); cb(null, uploadsDir); },
    filename(_req, _file, cb) { cb(null, crypto.randomUUID()); },
  });
}

function createUploader(uploadsDir) {
  return multer({
    storage: createStorage(uploadsDir),
    limits: { fileSize: MAX_FILE_SIZE, files: 1 },
    fileFilter(_req, file, cb) {
      const spec = ALLOWED_TYPES[file.mimetype];
      const ext = path.extname(file.originalname || '').toLowerCase();
      if (spec && ext === spec.ext) return cb(null, true);
      const err = new Error('File type not allowed'); err.code = 'DISALLOWED_TYPE'; return cb(err, false);
    },
  });
}

function validateMagicBytes(filePath, mimeType) {
  const spec = ALLOWED_TYPES[mimeType];
  if (!spec || !spec.magic) return true;
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.alloc(spec.magic.length);
    const bytesRead = fs.readSync(fd, buf, 0, spec.magic.length, 0);
    return bytesRead === spec.magic.length && spec.magic.every((byte, i) => buf[i] === byte);
  } finally { fs.closeSync(fd); }
}

function parseId(value) {
  const id = parseInt(value, 10);
  return Number.isInteger(id) && id > 0 && String(id) === value ? id : null;
}

function createDocumentRouter(db, opts = {}) {
  const uploadsDir = opts.uploadsDir ? path.resolve(opts.uploadsDir) : path.resolve('./uploads');
  const upload = createUploader(uploadsDir);
  const router = express.Router();
  const audit = (req, event) => writeAuditEvent(db, req.app.locals.persistDb, {
    actorId: req.session && req.session.user ? req.session.user.id : null,
    ipAddress: req.ip, ...event,
  });
  const tokenOk = req => {
    const submitted = req.body._csrf || req.headers['x-csrf-token'];
    const ok = submitted && req.session && submitted === req.session.csrfToken;
    if (ok) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    return Boolean(ok);
  };

  function renderUpload(req, res, status = 200, error = null, values = {}) {
    return res.status(status).render('documents/upload', {
      error,
      token: csrfToken(req),
      user: req.session.user,
      allowedTypes: Object.keys(ALLOWED_TYPES).join(', '),
      title: values.title || '',
      description: values.description || '',
      category: values.category || '',
      shareEmail: values.shareEmail || '',
      sharePermission: values.sharePermission || 'read',
    });
  }

  router.get('/', (req, res) => {
    const userId = req.session.user.id;
    const query = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 200) : '';
    const mime = typeof req.query.mime === 'string' ? req.query.mime.trim().slice(0, 100) : '';
    const category = typeof req.query.category === 'string' ? req.query.category.trim().slice(0, 100) : '';
    const from = /^\d{4}-\d{2}-\d{2}$/.test(req.query.from || '') ? req.query.from : '';
    const to = /^\d{4}-\d{2}-\d{2}$/.test(req.query.to || '') ? req.query.to : '';
    const minSize = Number.isInteger(Number(req.query.minSize)) && Number(req.query.minSize) >= 0 ? Number(req.query.minSize) : null;
    const maxSize = Number.isInteger(Number(req.query.maxSize)) && Number(req.query.maxSize) >= 0 ? Number(req.query.maxSize) : null;
    const page = Math.max(1, Math.min(10000, parseInt(req.query.page, 10) || 1));
    const filters = [];
    const filterParams = [];
    if (query) { filters.push('d.title LIKE ?'); filterParams.push(`%${query}%`); }
    if (mime) { filters.push('d.mime_type = ?'); filterParams.push(mime); }
    if (category) { filters.push('c.name = ?'); filterParams.push(category); }
    if (from) { filters.push('d.created_at >= ?'); filterParams.push(`${from}T00:00:00.000Z`); }
    if (to) { filters.push("d.created_at < date(?, '+1 day')"); filterParams.push(to); }
    if (minSize !== null) { filters.push('d.size_bytes >= ?'); filterParams.push(minSize); }
    if (maxSize !== null) { filters.push('d.size_bytes <= ?'); filterParams.push(maxSize); }
    const clause = filters.length ? `AND ${filters.join(' AND ')}` : '';
    const rows = db.exec(`SELECT d.id,d.title,d.description,c.name,d.mime_type,d.size_bytes,d.created_at
      FROM documents d LEFT JOIN categories c ON c.id=d.category_id
      WHERE d.is_deleted=0 AND (d.owner_id=? OR EXISTS(SELECT 1 FROM document_permissions p WHERE p.document_id=d.id AND p.user_id=? AND p.revoked_at IS NULL))
      ${clause} ORDER BY d.created_at DESC LIMIT ? OFFSET ?`, [userId, userId, ...filterParams, 50, (page - 1) * 50]);
    const docs = rows.length ? rows[0].values.map(([id,title,description,categoryName,mimeType,sizeBytes,createdAt]) => ({ id,title,description,category:categoryName,mimeType,sizeBytes,createdAt })) : [];
    const categories = db.exec('SELECT name FROM categories ORDER BY name').flatMap(r => r.values.map(v => v[0]));
    res.render('documents/index', { docs, user: req.session.user, query, mime, category, from, to, minSize, maxSize, page, categories, token: csrfToken(req) });
  });

  router.get('/upload', (req, res) => renderUpload(req, res));

  router.post('/upload', uploadLimiter, (req, res, next) => {
    upload.single('file')(req, res, async err => {
      if (err) {
        if (err.code === 'LIMIT_FILE_SIZE') { audit(req,{action:'document.upload',resource:null,outcome:'error',detail:{reason:'file_too_large'}}); return renderUpload(req, res, 413, 'File exceeds the 10 MB size limit.'); }
        if (err.code === 'DISALLOWED_TYPE') { audit(req,{action:'document.upload',resource:null,outcome:'error',detail:{reason:'disallowed_mime_type'}}); return renderUpload(req, res, 400, 'File type and extension are not allowed or do not match.'); }
        return next(err);
      }
      if (!tokenOk(req)) { if (req.file) try { fs.unlinkSync(req.file.path); } catch (_) {} return res.status(403).json({ error:'Invalid or missing CSRF token' }); }
      const values = {
        title: typeof req.body.title === 'string' ? req.body.title.trim() : '',
        description: typeof req.body.description === 'string' ? req.body.description.trim() : '',
        category: typeof req.body.category === 'string' ? req.body.category.trim().slice(0, 100) : '',
        shareEmail: typeof req.body.share_email === 'string' ? req.body.share_email.trim().toLowerCase() : '',
        sharePermission: typeof req.body.share_permission === 'string' ? req.body.share_permission : 'read',
      };
      if (!req.file) { audit(req,{action:'document.upload',resource:null,outcome:'error',detail:{reason:'no_file'}}); return renderUpload(req, res, 400, 'Please select a file to upload.', values); }
      const storedPath = containedPath(uploadsDir, req.file.filename);
      if (!validateMagicBytes(storedPath, req.file.mimetype)) { fs.unlinkSync(storedPath); audit(req,{action:'document.upload',resource:null,outcome:'error',detail:{reason:'magic_byte_mismatch'}}); return renderUpload(req, res, 400, 'File content does not match its declared type.', values); }
      if (!values.title || values.title.length > MAX_TITLE_LEN || values.description.length > MAX_DESCRIPTION_LEN) { fs.unlinkSync(storedPath); audit(req,{action:'document.upload',resource:null,outcome:'error',detail:{reason:'invalid_title_or_description'}}); return renderUpload(req, res, 400, 'Title or description is invalid.', values); }

      let recipientId = null;
      if (values.shareEmail) {
        if (!isValidEmail(values.shareEmail) || !['read', 'edit'].includes(values.sharePermission)) {
          fs.unlinkSync(storedPath);
          audit(req, { action:'document.upload', resource:null, outcome:'denied', detail:{reason:'invalid_share_request'} });
          return renderUpload(req, res, 400, 'Enter a valid registered recipient email and choose Read or Edit.', values);
        }
        const recipient = db.exec('SELECT id FROM users WHERE email = ? AND is_active = 1', [values.shareEmail]);
        if (!recipient.length || !recipient[0].values.length) {
          fs.unlinkSync(storedPath);
          audit(req, { action:'document.upload', resource:null, outcome:'denied', detail:{reason:'recipient_not_registered'} });
          return renderUpload(req, res, 400, 'No active registered user was found for that email. Ask the recipient to register first.', values);
        }
        recipientId = recipient[0].values[0][0];
        if (recipientId === req.session.user.id) {
          fs.unlinkSync(storedPath);
          return renderUpload(req, res, 400, 'You cannot share a document with yourself.', values);
        }
      }
      try {
        db.run('BEGIN');
        let categoryId = null;
        if (values.category) {
          db.run('INSERT OR IGNORE INTO categories (name, created_by) VALUES (?, ?)', [values.category, req.session.user.id]);
          categoryId = db.exec('SELECT id FROM categories WHERE name = ?', [values.category])[0].values[0][0];
        }
        db.run('INSERT INTO documents (owner_id,title,description,category_id,storage_name,mime_type,size_bytes) VALUES (?,?,?,?,?,?,?)', [req.session.user.id, values.title, values.description, categoryId, req.file.filename, req.file.mimetype, req.file.size]);
        const id = db.exec('SELECT last_insert_rowid()')[0].values[0][0];
        if (recipientId) {
          db.run('INSERT INTO document_permissions (document_id, user_id, permission, granted_by) VALUES (?, ?, ?, ?)', [id, recipientId, values.sharePermission, req.session.user.id]);
        }
        const uploadAuditOk = writeAuditEvent(db, () => {}, { actorId:req.session.user.id, ipAddress:req.ip, action:'document.upload', resource:`document:${id}`, outcome:'success', detail:{ docId:id, mimeType:req.file.mimetype } });
        if (!uploadAuditOk) throw new Error('mandatory upload audit write failed');
        if (recipientId) {
          const shareAuditOk = writeAuditEvent(db, () => {}, { actorId:req.session.user.id, ipAddress:req.ip, action:'permission.grant', resource:`document:${id}`, outcome:'success', detail:{ docId:id, granteeId:recipientId, permission:values.sharePermission } });
          if (!shareAuditOk) throw new Error('mandatory share audit write failed');
        }
        db.run('COMMIT');
        req.app.locals.persistDb();
        return res.redirect('/documents');
      } catch (dbErr) {
        try { db.run('ROLLBACK'); } catch (_) {}
        try { fs.unlinkSync(storedPath); } catch (_) {}
        return next(dbErr);
      }
    });
  });

  router.get('/shared', (req, res) => {
    const result = db.exec(`SELECT d.id, d.title, d.description, c.name, d.mime_type,
      d.size_bytes, d.created_at, u.email, p.permission, p.granted_at
      FROM document_permissions p
      JOIN documents d ON d.id = p.document_id
      JOIN users u ON u.id = d.owner_id
      LEFT JOIN categories c ON c.id = d.category_id
      WHERE p.user_id = ? AND p.revoked_at IS NULL AND d.is_deleted = 0 AND u.is_active = 1
      ORDER BY p.granted_at DESC`, [req.session.user.id]);
    const docs = result.length ? result[0].values.map(([id,title,description,category,mimeType,sizeBytes,createdAt,ownerEmail,permission,grantedAt]) => ({
      id, title, description, category, mimeType, sizeBytes, createdAt, ownerEmail, permission, grantedAt,
    })) : [];
    return res.render('documents/shared', { docs, user:req.session.user, token:csrfToken(req) });
  });

  function documentAccess(req, docId, write = false) {
    const result = db.exec(`SELECT d.id,d.title,d.description,d.storage_name,d.mime_type,d.owner_id,c.name
      FROM documents d LEFT JOIN categories c ON c.id=d.category_id WHERE d.id=? AND d.is_deleted=0 AND
      (d.owner_id=? OR EXISTS(SELECT 1 FROM document_permissions p WHERE p.document_id=d.id AND p.user_id=? AND p.permission='edit' AND p.revoked_at IS NULL) OR
       (${write ? '0' : 'EXISTS(SELECT 1 FROM document_permissions p2 WHERE p2.document_id=d.id AND p2.user_id=? AND p2.revoked_at IS NULL)'}))`, write ? [docId,req.session.user.id,req.session.user.id] : [docId,req.session.user.id,req.session.user.id,req.session.user.id]);
    return result.length && result[0].values.length ? result[0].values[0] : null;
  }

  router.get('/:id/edit', (req,res) => {
    const id = parseId(req.params.id); if (!id) return res.status(400).json({error:'Invalid document ID'});
    const doc = documentAccess(req,id,true); if (!doc) return res.status(403).json({error:'Forbidden'});
    return res.render('documents/edit', { doc:{ id:doc[0], title:doc[1], description:doc[2], category:doc[6] }, token:csrfToken(req), user:req.session.user, error:null });
  });

  router.post('/:id/edit', (req,res) => {
    const id = parseId(req.params.id); if (!id) return res.status(400).json({error:'Invalid document ID'});
    if (!tokenOk(req)) return res.status(403).json({error:'Invalid or missing CSRF token'});
    const doc = documentAccess(req,id,true); if (!doc) { audit(req,{action:'document.edit',resource:`document:${id}`,outcome:'denied',detail:{reason:'no_edit_access'}}); return res.status(403).json({error:'Forbidden'}); }
    const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
    const description = typeof req.body.description === 'string' ? req.body.description.trim() : '';
    const categoryName = typeof req.body.category === 'string' ? req.body.category.trim().slice(0,100) : '';
    if (!title || title.length > MAX_TITLE_LEN || description.length > MAX_DESCRIPTION_LEN) return res.status(400).json({error:'Invalid metadata'});
    let categoryId = null;
    if (categoryName) { db.run('INSERT OR IGNORE INTO categories (name,created_by) VALUES (?,?)',[categoryName,req.session.user.id]); categoryId=db.exec('SELECT id FROM categories WHERE name=?',[categoryName])[0].values[0][0]; }
    db.run("UPDATE documents SET title=?,description=?,category_id=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",[title,description,categoryId,id]); req.app.locals.persistDb();
    audit(req,{action:'document.edit',resource:`document:${id}`,outcome:'success',detail:{docId:id}}); return res.redirect('/documents');
  });

  router.post('/:id/delete', (req,res) => {
    const id = parseId(req.params.id); if (!id) return res.status(400).json({error:'Invalid document ID'});
    if (!tokenOk(req)) return res.status(403).json({error:'Invalid or missing CSRF token'});
    const row=db.exec("SELECT storage_name,owner_id FROM documents WHERE id=? AND is_deleted=0 AND deletion_state='active'",[id]);
    if (!row.length || !row[0].values.length || row[0].values[0][1] !== req.session.user.id) return res.status(403).json({error:'Forbidden'});
    const filePath=containedPath(uploadsDir,row[0].values[0][0]);
    // Persist the pending state and revoke grants before touching the file.
    // A crash after this point leaves an inaccessible row for startup recovery.
    db.run("UPDATE documents SET deletion_state='pending', is_deleted=1, deleted_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), deletion_error=NULL WHERE id=?",[id]);
    db.run("UPDATE document_permissions SET revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE document_id=? AND revoked_at IS NULL",[id]);
    req.app.locals.persistDb();
    try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); }
    catch (err) { db.run('UPDATE documents SET deletion_attempts=deletion_attempts+1,deletion_error=? WHERE id=?',[String(err.message).slice(0,200),id]); req.app.locals.persistDb(); audit(req,{action:'document.delete',resource:`document:${id}`,outcome:'error',detail:{reason:'file_delete_failed'}}); return res.status(500).json({error:'Deletion is pending filesystem cleanup'}); }
    db.run("UPDATE documents SET deletion_state='deleted',deletion_error=NULL WHERE id=?",[id]); req.app.locals.persistDb();
    audit(req,{action:'document.delete',resource:`document:${id}`,outcome:'success',detail:{docId:id}}); return res.redirect('/documents');
  });

  function streamFile(req,res,preview) {
    const id=parseId(req.params.id); if (!id) return res.status(400).json({error:'Invalid document ID'});
    const result=db.exec(`SELECT d.storage_name,d.mime_type,d.title FROM documents d WHERE d.id=? AND d.is_deleted=0 ${preview ? "AND d.mime_type IN ('application/pdf','image/png','image/jpeg')" : ''} AND (d.owner_id=? OR EXISTS(SELECT 1 FROM document_permissions p WHERE p.document_id=d.id AND p.user_id=? AND p.revoked_at IS NULL))`,[id,req.session.user.id,req.session.user.id]);
    if (!result.length || !result[0].values.length) { audit(req,{action:preview?'document.preview':'document.download',resource:`document:${id}`,outcome:'denied',detail:{reason:'no_access'}}); return res.status(403).json({error:'Forbidden'}); }
    const [storageName,mimeType,title]=result[0].values[0]; const filePath=containedPath(uploadsDir,storageName);
    if (!fs.existsSync(filePath)) { audit(req,{action:preview?'document.preview':'document.download',resource:`document:${id}`,outcome:'error',detail:{reason:'file_missing_on_disk'}}); return res.status(500).json({error:'Internal server error'}); }
    audit(req,{action:preview?'document.preview':'document.download',resource:`document:${id}`,outcome:'success',detail:{docId:id}});
    res.setHeader('Content-Type',mimeType); res.setHeader('X-Content-Type-Options','nosniff'); res.setHeader('Content-Disposition',preview?'inline':`attachment; filename="${encodeURIComponent(title)}"`); return res.sendFile(filePath);
  }
  router.get('/:id/download',(req,res)=>streamFile(req,res,false));
  router.get('/:id/preview',(req,res)=>streamFile(req,res,true));
  return router;
}

module.exports = { createDocumentRouter, ALLOWED_TYPES, MAX_FILE_SIZE };
