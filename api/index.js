// Vercel serverless entry: every request is routed here (see vercel.json) and handled by
// the same Express app as local development, backed by Firestore + Firebase Storage.
//
// If start-up fails (usually a missing or mistyped environment variable), every request
// gets a plain explanation instead of Vercel's generic "FUNCTION_INVOCATION_FAILED".
// Only our own configuration messages are shown — never secret values.

let app;
let startupError;
try {
  const { config } = await import('../src/config.js');
  const { createStore } = await import('../src/store/index.js');
  const { createApp } = await import('../src/app.js');
  const missing = ['FIREBASE_PROJECT_ID', 'FIREBASE_CLIENT_EMAIL', 'FIREBASE_PRIVATE_KEY', 'FIREBASE_STORAGE_BUCKET', 'BASE_URL', 'FIRM_NAME']
    .filter((k) => !process.env[k]);
  if (missing.length) throw new Error(`Missing Vercel environment variable(s): ${missing.join(', ')}`);
  if (!/-----BEGIN PRIVATE KEY-----/.test(process.env.FIREBASE_PRIVATE_KEY) || !/END PRIVATE KEY-----/.test(process.env.FIREBASE_PRIVATE_KEY)) {
    throw new Error('FIREBASE_PRIVATE_KEY must be the whole private_key value from the JSON file, from -----BEGIN PRIVATE KEY----- to -----END PRIVATE KEY-----\\n (without the surrounding quotes)');
  }
  app = createApp({ store: await createStore(config), config });
} catch (err) {
  startupError = err;
  console.error('STARTUP FAILED:', err);
}

const SAFE = /^(Missing Vercel environment|FIREBASE_PRIVATE_KEY must|DATA_KEY must|Failed to parse private key|Service account object must|Invalid PEM)/;

export default function handler(req, res) {
  if (app) return app(req, res);
  const msg = SAFE.test(startupError?.message || '') ? startupError.message : 'Unexpected start-up error — see Vercel Runtime Logs.';
  res.statusCode = 500;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(`The portal could not start.\n\nSetup problem: ${msg}\n\nFix it in Vercel → Settings → Environment Variables, then Deployments → ⋯ → Redeploy.`);
}
