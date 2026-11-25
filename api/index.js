// Vercel serverless entry: every request is routed here (see vercel.json) and handled by
// the same Express app as local development, backed by Firestore + Firebase Storage.
//
// Start-up is done lazily inside the handler (no top-level await), so any failure —
// usually a missing or mistyped environment variable — is caught and explained instead
// of crashing the function with Vercel's generic FUNCTION_INVOCATION_FAILED page.
// Only our own configuration messages are shown — never secret values.

process.on('unhandledRejection', (err) => console.error('UNHANDLED REJECTION:', err));

const SAFE = /^(Missing Vercel environment|FIREBASE_PRIVATE_KEY must|FIREBASE_SERVICE_ACCOUNT must|DATA_KEY must|Failed to parse private key|Service account object must|Invalid PEM)/;
let ready;

async function start() {
  // Validates and normalises settings (incl. FIREBASE_SERVICE_ACCOUNT) before anything else.
  const { config } = await import('../src/config.js');
  const fb = config.firebase;
  const missing = [
    ['DATA_KEY', process.env.DATA_KEY], ['BASE_URL', process.env.BASE_URL], ['FIRM_NAME', process.env.FIRM_NAME],
    ['FIREBASE_PROJECT_ID', fb.projectId], ['FIREBASE_CLIENT_EMAIL', fb.clientEmail], ['FIREBASE_PRIVATE_KEY', fb.privateKey], ['FIREBASE_STORAGE_BUCKET', fb.storageBucket],
  ].filter(([, v]) => !v).map(([k]) => k);
  if (missing.length) throw new Error(`Missing Vercel environment variable(s): ${missing.join(', ')} (tip: FIREBASE_SERVICE_ACCOUNT = the whole .json key file covers all the FIREBASE_ ones)`);
  if (!/BEGIN PRIVATE KEY/.test(fb.privateKey) || !/END PRIVATE KEY/.test(fb.privateKey)) {
    throw new Error('FIREBASE_PRIVATE_KEY must be the whole private_key value from the JSON file. Easier: add FIREBASE_SERVICE_ACCOUNT containing the entire .json key file (it overrides the separate key settings)');
  }
  const { createStore } = await import('../src/store/index.js');
  const { createApp } = await import('../src/app.js');
  return createApp({ store: await createStore(config), config });
}

export default async function handler(req, res) {
  try {
    ready ||= start();
    const app = await ready;
    return app(req, res);
  } catch (err) {
    ready = undefined; // retry on the next request (e.g. after fixing a setting)
    console.error('STARTUP FAILED:', err);
    const msg = SAFE.test(err?.message || '') ? err.message : `Unexpected start-up error (${err?.name || 'Error'}) — see Vercel Runtime Logs.`;
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(`The portal could not start.\n\nSetup problem: ${msg}\n\nFix it in Vercel → Settings → Environment Variables, then Deployments → ⋯ → Redeploy.`);
  }
}
