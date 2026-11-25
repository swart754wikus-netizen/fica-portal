import express from 'express';
import helmet from 'helmet';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadSession } from './security/session.js';
import { clientRouter } from './routes/client.js';
import { staffRouter } from './routes/staff.js';
import { getProvider } from './providers/index.js';
import { getMailer } from './email/index.js';
import * as catalog from './onboarding/catalog.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

export function createApp({ db, config, provider = getProvider(config.provider), mailer = getMailer(config), rmcp } = {}) {
  rmcp ??= JSON.parse(readFileSync(join(root, 'config/rmcp.json'), 'utf8'));
  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', join(root, 'views'));
  app.set('trust proxy', config.isProd ? 1 : false);
  app.disable('x-powered-by');
  Object.assign(app.locals, catalog, { firmName: config.firmName || 'Our firm', mockScreening: (config.provider || 'mock') === 'mock' });

  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: { 'script-src': ["'self'"], 'form-action': ["'self'"], 'frame-ancestors': ["'none'"], 'img-src': ["'self'", 'data:'] },
    },
    referrerPolicy: { policy: 'no-referrer' }, // invite tokens live in URLs — never leak them
    hsts: config.isProd,
  }));
  app.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  app.use('/static', express.static(join(root, 'public'), { maxAge: '1h' }));
  app.use(express.urlencoded({ extended: false, limit: '50kb' }));
  app.use(loadSession(db, { ttlMinutes: config.sessionTtlMinutes }));

  app.get('/', (req, res) => res.render('home'));
  app.get('/privacy', (req, res) => res.render('privacy'));
  app.get('/healthz', (req, res) => res.json({ ok: true }));
  app.use(clientRouter({ db, config, provider, rmcp }));
  app.use('/staff', staffRouter({ db, config, mailer }));

  app.use((req, res) => res.status(404).render('error', { message: 'Page not found' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err); // never echo internals (or PII) to the browser
    res.status(500).render('error', { message: 'Something went wrong. Please try again.' });
  });
  return app;
}
