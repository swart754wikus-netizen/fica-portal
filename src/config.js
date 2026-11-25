import { readFileSync, existsSync } from 'node:fs';

// Minimal .env loader (avoids a dependency). Real env vars take precedence.
if (existsSync('.env')) {
  for (const line of readFileSync('.env', 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^(["'])(.*)\1$/, '$2');
  }
}

// Easiest setup: paste the whole service-account JSON file into FIREBASE_SERVICE_ACCOUNT.
// When present it wins over the individual FIREBASE_* variables (except the bucket).
let serviceAccount = {};
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try { serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT.trim()); } catch {
    throw new Error('FIREBASE_SERVICE_ACCOUNT must be the complete contents of the downloaded .json key file (open it in Notepad, Ctrl+A, Ctrl+C, paste)');
  }
}

const key = Buffer.from((process.env.DATA_KEY || '').trim(), 'base64');
if (key.length !== 32) {
  throw new Error('DATA_KEY must be a 32-byte base64 value (about 44 characters ending in =). Generate one as described in the README and set it in Vercel (or .env locally).');
}

export const config = {
  port: Number(process.env.PORT || 3000),
  baseUrl: (process.env.BASE_URL || 'http://localhost:3000').replace(/\/$/, ''),
  dbPath: process.env.DB_PATH || './data/fica.db',
  isProd: process.env.NODE_ENV === 'production',
  dataKey: key,
  provider: process.env.SCREENING_PROVIDER || 'mock',
  inviteTtlHours: Number(process.env.INVITE_TTL_HOURS || 72),
  sessionTtlMinutes: 30,
  maxUploadBytes: 10 * 1024 * 1024, // per file (phone photos); uploads go straight to Storage in production
  retentionYears: 5,
  firmName: process.env.FIRM_NAME || 'Our firm',
  // "sqlite" = local file (development/tests); "firestore" = Firebase (production on Vercel)
  store: process.env.STORE || (process.env.VERCEL ? 'firestore' : 'sqlite'),
  firebase: {
    projectId: serviceAccount.project_id || process.env.FIREBASE_PROJECT_ID?.trim(),
    clientEmail: serviceAccount.client_email || process.env.FIREBASE_CLIENT_EMAIL?.trim().replace(/^"|",?$/g, ''),
    // Tolerate the value being pasted with its JSON quotes or trailing spaces.
    privateKey: serviceAccount.private_key || process.env.FIREBASE_PRIVATE_KEY?.trim().replace(/^"|",?$/g, ''),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET?.trim().replace(/^gs:\/\//, '') || (serviceAccount.project_id && `${serviceAccount.project_id}.firebasestorage.app`),
  },
  // One-time code for /staff/setup (create the first compliance officer from the browser).
  setupToken: process.env.SETUP_TOKEN || '',
  mail: {
    transport: process.env.MAIL_TRANSPORT || 'log',
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.MAIL_FROM,
  }, // FICA s22/s23: keep CDD records ≥5 years after relationship ends
};
