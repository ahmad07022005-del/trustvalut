'use strict';

require('dotenv').config();

const { createApp } = require('./app');
const { getDb }     = require('./db/database');
const { persist }    = require('./db/database');
const { reconcilePendingDeletions } = require('./lib/deletion');
const path = require('path');

const PORT = parseInt(process.env.PORT || '3000', 10);

async function main() {
  if (process.env.NODE_ENV === 'production' &&
      (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
    throw new Error('SESSION_SECRET must be at least 32 characters in production');
  }
  // Initialise database (async because sql.js loads a WASM module).
  const db = await getDb();
  reconcilePendingDeletions(db, path.resolve('./uploads'), persist);

  // Pass db to createApp so auth routes can use it.
  const app = createApp(db);

  app.listen(PORT, () => {
    console.log(`TrustVault listening on http://localhost:${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

main().catch(err => {
  console.error('[startup error]', err.message);
  process.exit(1);
});
