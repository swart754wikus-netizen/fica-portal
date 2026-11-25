import { config } from './config.js';
import { openDb } from './db.js';
import { createApp } from './app.js';

const db = openDb(config.dbPath);
createApp({ db, config }).listen(config.port, () => {
  console.log(`FICA portal on ${config.baseUrl} (provider: ${config.provider})`);
  if (config.provider === 'mock') console.warn('WARNING: mock screening provider — not for production use.');
});
