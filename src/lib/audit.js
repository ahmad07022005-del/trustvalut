'use strict';

/**
 * audit.js — Centralized audit-event writer with hash-chain integrity
 *
 * USAGE
 *   const { writeAuditEvent, verifyAuditChain } = require('../lib/audit');
 *   writeAuditEvent(db, persist, {
 *     actorId:   req.session.user.id,   // null for unauthenticated
 *     action:    'document.download',
 *     resource:  `document:${docId}`,
 *     outcome:   'success',             // 'success' | 'denied' | 'error'
 *     detail:    { docId },             // plain object — NO passwords/tokens
 *     ipAddress: req.ip,
 *   });
 *
 * HASH CHAIN
 *   Each row's row_hash is sha256 of its canonical fields concatenated with
 *   the previous row's hash (or the literal string "GENESIS" for the first
 *   row).  This makes undetected single-row tampering computationally hard.
 *
 * KNOWN LIMITATION
 *   The chain is stored in the same SQLite database file.  A privileged
 *   attacker who can overwrite the database file can also recompute all
 *   hashes and produce a valid-looking forged chain.  The chain detects
 *   accidental corruption and unprivileged tampering; it is NOT a substitute
 *   for an independently retained, append-only log.  See THREATS.md.
 *
 * FAILURE POLICY
 *   writeAuditEvent never throws.  If it cannot record the event it logs to
 *   stderr and returns false.  Callers SHOULD check the return value for
 *   security-sensitive operations and handle the failure explicitly (e.g.
 *   abort the parent transaction or surface a warning).  This design ensures
 *   an audit failure never silently blocks a legitimate operation while still
 *   giving callers visibility.
 */

const crypto = require('crypto');

const GENESIS = 'GENESIS';

/**
 * Compute the sha256 hash for an audit row.
 *
 * The canonical string is pipe-separated: id|actorId|action|resource|outcome|prevHash
 * Fields that are null/undefined are serialised as the literal string "null".
 */
function computeRowHash(id, actorId, action, resource, outcome, prevHash) {
  const canonical = [id, actorId, action, resource, outcome, prevHash]
    .map(v => (v === null || v === undefined ? 'null' : String(v)))
    .join('|');
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Sanitize a value for safe inclusion in audit detail JSON.
 * Strips any key whose name contains 'password', 'secret', 'token', or
 * 'cookie' (case-insensitive) from plain objects.
 *
 * @param {object|null} obj
 * @returns {string} JSON string
 */
function safeDetail(obj) {
  if (!obj || typeof obj !== 'object') return null;

  const forbidden = /password|secret|token|cookie/i;
  const clean = {};
  for (const [k, v] of Object.entries(obj)) {
    if (!forbidden.test(k)) {
      clean[k] = v;
    }
  }
  return JSON.stringify(clean);
}

/**
 * Write a single audit event to the database.
 *
 * @param {import('sql.js').Database} db
 * @param {function} persistFn  - the persist() function from database.js
 * @param {{
 *   actorId:   number|null,
 *   action:    string,
 *   resource:  string|null,
 *   outcome:   'success'|'denied'|'error',
 *   detail:    object|null,
 *   ipAddress: string|null,
 * }} event
 * @returns {boolean} true if the event was written, false if it failed
 */
function writeAuditEvent(db, persistFn, event) {
  try {
    const { actorId = null, action, resource = null,
            outcome, detail = null, ipAddress = null } = event;

    if (!action)  throw new Error('audit: action is required');
    if (!['success', 'denied', 'error'].includes(outcome)) {
      throw new Error(`audit: invalid outcome "${outcome}"`);
    }

    // Fetch the previous row's hash (the most recently inserted row).
    const prevResult = db.exec(
      'SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1'
    );
    const prevHash = (prevResult.length > 0 && prevResult[0].values.length > 0)
      ? prevResult[0].values[0][0]
      : GENESIS;

    // Insert the new row without a hash first so we can get its id.
    db.run(
      `INSERT INTO audit_events
         (actor_id, action, resource, outcome, detail, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        actorId   ?? null,
        action,
        resource  ?? null,
        outcome,
        safeDetail(detail),
        ipAddress ?? null,
      ]
    );

    // Retrieve the id of the row we just inserted.
    const idResult = db.exec('SELECT last_insert_rowid()');
    const newId    = idResult[0].values[0][0];

    // Compute the hash and store it.
    const rowHash = computeRowHash(newId, actorId, action, resource, outcome, prevHash);
    db.run('UPDATE audit_events SET row_hash = ? WHERE id = ?', [rowHash, newId]);

    persistFn();
    return true;
  } catch (err) {
    // Never throw — log to stderr so the caller's operation is unblocked.
    console.error('[audit] failed to write event:', err.message);
    return false;
  }
}

/**
 * Verify the entire audit chain from the first row to the last.
 *
 * @param {import('sql.js').Database} db
 * @returns {{ valid: boolean, firstBadId: number|null, total: number }}
 */
function verifyAuditChain(db) {
  const result = db.exec(
    `SELECT id, actor_id, action, resource, outcome, row_hash
     FROM audit_events
     ORDER BY id ASC`
  );

  if (result.length === 0 || result[0].values.length === 0) {
    return { valid: true, firstBadId: null, total: 0 };
  }

  let prevHash = GENESIS;
  let total    = 0;

  for (const [id, actorId, action, resource, outcome, storedHash] of result[0].values) {
    total++;
    const expected = computeRowHash(id, actorId, action, resource, outcome, prevHash);
    if (expected !== storedHash) {
      return { valid: false, firstBadId: id, total };
    }
    prevHash = storedHash;
  }

  return { valid: true, firstBadId: null, total };
}

module.exports = { writeAuditEvent, verifyAuditChain, computeRowHash };
