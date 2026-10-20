'use strict';

// Load .env file if present. In production inject secrets via the environment.
require('dotenv').config();

const { createApp } = require('./app');
const { getDb }     = require('./db/database');

const PORT = parseInt(process.env.PORT || '3000', 10);

async function main() {
  // Initialise the database (and apply the schema) before accepting requests.
  // getDb() is async because sql.js loads its WASM module asynchronously.
  await getDb();

  const app = createApp();

  app.listen(PORT, () => {
    console.log(`TrustVault listening on http://localhost:${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

main().catch(err => {
  console.error('[startup error]', err.message);
  process.exit(1);
});
