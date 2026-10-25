'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { getDb, persist, closeDb } = require('../src/db/database');

function usage() {
  return 'Usage: node scripts/promote-admin.js --db <database-file> --email <registered-email> [--backup <backup-file>]';
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const value = argv[i];
    if (!value.startsWith('--')) throw new Error(`Unexpected argument: ${value}`);
    const key = value.slice(2);
    if (!['db', 'email', 'backup'].includes(key)) throw new Error(`Unknown option: --${key}`);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) throw new Error(`Missing value for --${key}`);
    args[key] = next;
    i += 1;
  }
  if (!args.db) throw new Error('An explicit --db path is required.');
  if (!args.email) throw new Error('An explicit --email value is required.');
  return args;
}

function resolveDatabasePath(value) {
  if (!value || value === ':memory:') {
    throw new Error('An existing on-disk database path is required; refusing :memory: or an omitted path.');
  }
  const databasePath = path.resolve(value);
  if (!fs.existsSync(databasePath)) throw new Error(`Database file does not exist: ${databasePath}`);
  if (!fs.statSync(databasePath).isFile()) throw new Error(`Database path is not a regular file: ${databasePath}`);
  return databasePath;
}

function resolveBackupPath(databasePath, requested) {
  const backupPath = requested
    ? path.resolve(requested)
    : `${databasePath}.backup-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  if (fs.existsSync(backupPath)) throw new Error(`Refusing to overwrite existing backup: ${backupPath}`);
  return backupPath;
}

async function promoteAdmin({ dbPath, email, backupPath }) {
  if (typeof email !== 'string' || !email.trim()) throw new Error('An explicit registered email is required.');
  const normalizedEmail = email.trim().toLowerCase();
  const databasePath = resolveDatabasePath(dbPath);
  const resolvedBackupPath = resolveBackupPath(databasePath, backupPath);

  // Create the backup before opening or changing the SQL.js database.
  fs.copyFileSync(databasePath, resolvedBackupPath, fs.constants.COPYFILE_EXCL);

  let db;
  try {
    db = await getDb(databasePath);
    const result = db.exec(
      'SELECT id, email, role, is_active FROM users WHERE email = ?',
      [normalizedEmail]
    );
    const rows = result.length ? result[0].values : [];
    if (rows.length === 0) throw new Error(`No existing user matches the requested email: ${normalizedEmail}`);
    if (rows.length !== 1) throw new Error(`Expected exactly one matching user, found ${rows.length}; refusing to continue.`);

    const [userId, storedEmail, currentRole, isActive] = rows[0];
    if (isActive !== 1) throw new Error(`The selected account is inactive; refusing to promote user id ${userId}.`);

    db.run('BEGIN');
    try {
      db.run('UPDATE users SET role = ? WHERE id = ?', ['admin', userId]);
      const verify = db.exec('SELECT role FROM users WHERE id = ?', [userId]);
      const verifiedRole = verify.length && verify[0].values.length ? verify[0].values[0][0] : null;
      if (verifiedRole !== 'admin') throw new Error('Role verification failed inside the transaction.');
      db.run('COMMIT');
    } catch (error) {
      try { db.run('ROLLBACK'); } catch (_) { /* preserve the original failure */ }
      throw error;
    }

    persist();
    const persisted = db.exec('SELECT email, role FROM users WHERE id = ?', [userId]);
    const persistedRow = persisted.length && persisted[0].values.length ? persisted[0].values[0] : null;
    if (!persistedRow || persistedRow[1] !== 'admin') throw new Error('Post-persistence role verification failed.');

    return {
      backupPath: resolvedBackupPath,
      userId,
      email: storedEmail,
      previousRole: currentRole,
      role: persistedRow[1],
    };
  } finally {
    closeDb();
  }
}

async function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    const result = await promoteAdmin({ dbPath: args.db, email: args.email, backupPath: args.backup });
    console.log(`Promoted ${result.email} (user ${result.userId}) from ${result.previousRole} to ${result.role}.`);
    console.log(`Backup: ${result.backupPath}`);
    console.log('This changed only the selected local database file; it does not change a Render deployment.');
  } catch (error) {
    console.error(`Bootstrap failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { parseArgs, resolveDatabasePath, resolveBackupPath, promoteAdmin };
