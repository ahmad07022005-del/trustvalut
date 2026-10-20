'use strict';

/**
 * database.js — sql.js wrapper for TrustVault
 *
 * sql.js keeps the entire database in memory as a Uint8Array.
 * To persist, we write that buffer back to disk after every write operation
 * using the exported `persist()` helper.
 *
 * Tests set DB_PATH=:memory: to get an isolated in-memory database that is
 * never written to disk and never affects the real data file.
 */

const path       = require('path');
const fs         = require('fs');
const initSqlJs  = require('sql.js');

let _db       = null;   // sql.js Database instance
let _filePath = null;   // absolute path to the .db file (null in-memory)

/**
 * Return the shared database instance, initialising it on first call.
 * Must be awaited.
 *
 * @param {string} [overridePath] - Absolute or relative path, or ':memory:'.
 * @returns {Promise<import('sql.js').Database>}
 */
async function getDb(overridePath) {
  if (_db) return _db;

  const SQL = await initSqlJs();

  const rawPath = overridePath
    || process.env.DB_PATH
    || './data/trustvault.db';

  const inMemory = rawPath === ':memory:';

  if (inMemory) {
    // Tests: fresh empty database, no file I/O.
    _db = new SQL.Database();
  } else {
    _filePath = path.resolve(rawPath);
    const dir = path.dirname(_filePath);

    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    if (fs.existsSync(_filePath)) {
      // Load existing database from disk into memory.
      const buf = fs.readFileSync(_filePath);
      _db = new SQL.Database(buf);
    } else {
      // New database; will be written to disk after schema is applied.
      _db = new SQL.Database();
    }
  }

  // sql.js has no .pragma() — run PRAGMAs as plain SQL.
  _db.run('PRAGMA foreign_keys = ON;');
  if (!inMemory) _db.run('PRAGMA journal_mode = WAL;');

  // Apply schema. sql.js .run() only executes the FIRST statement in a
  // multi-statement string — subsequent ones are silently ignored.
  // We must split on ';' and run each statement individually.
  //
  // Strip -- comments from each line before splitting. Inline comments
  // like "-- bcrypt hash; never store plaintext passwords" contain ';'
  // which breaks naive splitting and produces invalid SQL fragments.
  const schema = fs.readFileSync(
    path.join(__dirname, 'schema.sql'),
    'utf8'
  );

  const stripped = schema
    .split('\n')
    .map(line => {
      const idx = line.indexOf('--');
      return idx === -1 ? line : line.slice(0, idx);
    })
    .join('\n');

  const statements = stripped
    .split(';')
    .map(s => s.trim())
    .filter(s => s.length > 0);

  for (const stmt of statements) {
    _db.run(stmt + ';');
  }

  // Persist the freshly-initialised database to disk.
  persist();

  return _db;
}

/**
 * Write the current in-memory state back to the database file.
 * Call this after every INSERT, UPDATE, or DELETE.
 * Safe to call when running in-memory (no-op).
 */
function persist() {
  if (_db && _filePath) {
    const data = _db.export();               // Uint8Array
    fs.writeFileSync(_filePath, Buffer.from(data));
  }
}

/**
 * Close the database and reset module state.
 * Used between tests to ensure each test suite starts clean.
 */
function closeDb() {
  if (_db) {
    _db.close();
    _db       = null;
    _filePath = null;
  }
}

module.exports = { getDb, persist, closeDb };
