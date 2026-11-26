import { randomToken, sha256, safeEqual } from './crypto.js';

const COOKIE = 'fica_sid';

function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map((c) => c.trim().split('=')).filter((p) => p.length === 2));
}

export async function createSession(store, res, staffId, { isProd, ttlMinutes }, mfaOk = false) {
  const token = randomToken();
  await store.createSession({ token_hash: sha256(token), staff_id: String(staffId), csrf: randomToken(), mfa_ok: mfaOk, expires_at: Date.now() + ttlMinutes * 60_000 });
  res.cookie(COOKIE, token, {
    httpOnly: true, sameSite: 'strict', secure: isProd, path: '/staff', maxAge: ttlMinutes * 60_000,
  });
}

export async function destroySession(store, req, res) {
  const token = parseCookies(req.headers.cookie)[COOKIE];
  if (token) await store.deleteSession(sha256(token));
  res.clearCookie(COOKIE, { path: '/staff' });
}

/** Loads req.session / req.staff. Sliding expiry. Deactivated staff lose their session. */
export function loadSession(store, { ttlMinutes }) {
  return async (req, res, next) => {
    try {
      const token = parseCookies(req.headers.cookie)[COOKIE];
      if (token) {
        const hash = sha256(token);
        const s = await store.getSession(hash);
        const staff = s && s.expires_at > Date.now() ? await store.getStaffById(s.staff_id) : null;
        if (s && staff && staff.active !== false && staff.active !== 0) {
          await store.updateSession(hash, { expires_at: Date.now() + ttlMinutes * 60_000 });
          req.session = { ...s, token_hash: hash };
          req.staff = { id: String(staff.id), email: staff.email, name: staff.name, role: staff.role };
        } else if (s) {
          await store.deleteSession(hash);
        }
      }
      res.locals.staff = req.session?.mfa_ok ? req.staff : null;
      res.locals.csrf = req.session?.csrf ?? '';
      next();
    } catch (err) { next(err); }
  };
}

export const requireStaff = (req, res, next) => {
  if (!req.session) return res.redirect('/staff/login');
  if (!req.session.mfa_ok) return res.redirect('/staff/mfa');
  next();
};

export const requireRole = (role) => (req, res, next) =>
  req.staff?.role === role ? next() : res.status(403).render('error', { message: 'Your role cannot perform this action.' });

/** Synchroniser-token CSRF check for all state-changing staff requests. */
export const csrfCheck = (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  // Pre-auth forms have no session to bind a token to; SameSite=Strict + rate limiting cover them.
  if (req.method === 'POST' && (req.path === '/login' || req.path === '/setup')) return next();
  if (!req.session || !safeEqual(req.body?._csrf ?? '', req.session.csrf)) {
    // Diagnostics only — never the token values.
    console.warn('CSRF rejected', JSON.stringify({
      path: req.originalUrl, hasCookieHeader: Boolean(req.headers.cookie), hasSessionCookie: /fica_sid=/.test(req.headers.cookie || ''),
      sessionFound: Boolean(req.session), bodyType: typeof req.body, bodyHasToken: Boolean(req.body?._csrf), contentType: req.headers['content-type'],
      bodyFieldNames: req.body && typeof req.body === 'object' ? Object.keys(req.body).slice(0, 10) : null, contentLength: req.headers['content-length'], vercelHelpers: process.env.NODEJS_HELPERS !== '0',
    }));
    const message = req.session
      ? 'Security token expired. Please reload the page and try again.'
      : 'Your login session was not found (it may have expired, or your browser blocked the cookie). Please log in again.';
    return res.status(403).render('error', { message });
  }
  next();
};
