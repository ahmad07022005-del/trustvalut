'use strict';

const crypto = require('crypto');
const GENESIS = 'GENESIS';

function cleanDetailValue(value, forbidden) {
  if (Array.isArray(value)) return value.map(v => cleanDetailValue(v, forbidden));
  if (!value || typeof value !== 'object') return value;
  const clean = {};
  for (const [key, child] of Object.entries(value)) {
    if (!forbidden.test(key)) clean[key] = cleanDetailValue(child, forbidden);
  }
  return clean;
}

function safeDetail(obj) {
  if (!obj || typeof obj !== 'object') return null;
  return JSON.stringify(cleanDetailValue(obj, /password|secret|token|cookie/i));
}

// Version 1 is retained solely to verify audit rows created before the
// integrity upgrade. New rows use version 2 and cover every immutable field.
function computeRowHash(id, actorId, action, resource, outcome, prevHash, detail = null, ipAddress = null, occurredAt = null, version = 2) {
  const fields = version === 1
    ? [id, actorId, action, resource, outcome, prevHash]
    : [id, actorId, action, resource, outcome, detail, ipAddress, occurredAt, prevHash];
  const canonical = fields.map(v => (v === null || v === undefined ? 'null' : String(v))).join('|');
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function writeAuditEvent(db, persistFn, event) {
  try {
    const { actorId = null, action, resource = null, outcome, detail = null, ipAddress = null } = event;
    if (!action) throw new Error('audit: action is required');
    if (!['success', 'denied', 'error'].includes(outcome)) throw new Error(`audit: invalid outcome "${outcome}"`);
    const previous = db.exec('SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1');
    const prevHash = previous.length && previous[0].values.length ? previous[0].values[0][0] : GENESIS;
    const detailJson = safeDetail(detail);
    const occurredAt = new Date().toISOString();
    db.run(`INSERT INTO audit_events
      (actor_id, action, resource, outcome, detail, ip_address, prev_hash, integrity_version, occurred_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 2, ?)`, [actorId ?? null, action, resource ?? null, outcome, detailJson, ipAddress ?? null, prevHash, occurredAt]);
    const id = db.exec('SELECT last_insert_rowid()')[0].values[0][0];
    const rowHash = computeRowHash(id, actorId, action, resource, outcome, prevHash, detailJson, ipAddress, occurredAt, 2);
    db.run('UPDATE audit_events SET row_hash = ? WHERE id = ?', [rowHash, id]);
    persistFn();
    return true;
  } catch (err) {
    console.error('[audit] failed to write event:', err.message);
    return false;
  }
}

function verifyAuditChain(db) {
  const result = db.exec(`SELECT id, actor_id, action, resource, outcome, detail, ip_address,
    row_hash, prev_hash, integrity_version, occurred_at FROM audit_events ORDER BY id ASC`);
  if (!result.length || !result[0].values.length) return { valid: true, firstBadId: null, total: 0 };
  let prevHash = GENESIS;
  let total = 0;
  for (const row of result[0].values) {
    total++;
    const [id, actorId, action, resource, outcome, detail, ipAddress, storedHash, storedPrev, version, occurredAt] = row;
    const effectiveVersion = version || 1;
    const expectedPrev = effectiveVersion >= 2 ? storedPrev : prevHash;
    if (effectiveVersion >= 2 && storedPrev !== prevHash) return { valid: false, firstBadId: id, total };
    const expected = computeRowHash(id, actorId, action, resource, outcome, expectedPrev, detail, ipAddress, occurredAt, effectiveVersion);
    if (expected !== storedHash) return { valid: false, firstBadId: id, total };
    prevHash = storedHash;
  }
  return { valid: true, firstBadId: null, total };
}

module.exports = { writeAuditEvent, verifyAuditChain, computeRowHash, safeDetail };
