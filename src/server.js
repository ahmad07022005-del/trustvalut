'use strict';

require('dotenv').config();

const { createApp } = require('./app');
const { getDb }     = require('./db/database');

const PORT = parseInt(process.env.PORT || '3000', 10);

async function main() {
  // Initialise database (async because sql.js loads a WASM module).
  const db = await getDb();

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
