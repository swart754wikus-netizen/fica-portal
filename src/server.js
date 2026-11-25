// Local / self-hosted entry point. On Vercel the app is served by api/index.js instead.
import { config } from './config.js';
import { createStore } from './store/index.js';
import { createApp } from './app.js';

const store = await createStore(config);
createApp({ store, config }).listen(config.port, () => {
  console.log(`FICA portal on ${config.baseUrl} (store: ${store.kind}, provider: ${config.provider})`);
  if (config.mail.transport === 'log') console.warn('WARNING: MAIL_TRANSPORT=log — invite emails are printed here, not sent.');
  if (config.provider === 'mock') console.warn('WARNING: mock screening provider — not for production use.');
});
