import { randomToken, sha256, safeEqual } from './crypto.js';

const COOKIE = 'fica_sid';

function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map((c) => c.trim().split('=')).filter((p) => p.length === 2));
}

export function createSession(db, res, staffId, { isProd, ttlMinutes }, mfaOk = false) {
  const token = randomToken();
  db.prepare('INSERT INTO sessions (token_hash, staff_id, csrf, mfa_ok, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(sha256(token), staffId, randomToken(), mfaOk ? 1 : 0, Date.now() + ttlMinutes * 60_000);
  res.cookie(COOKIE, token, {
    httpOnly: true, sameSite: 'strict', secure: isProd, path: '/staff', maxAge: ttlMinutes * 60_000,
  });
}

export function destroySession(db, req, res) {
  const token = parseCookies(req.headers.cookie)[COOKIE];
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
  res.clearCookie(COOKIE, { path: '/staff' });
}

/** Loads req.session / req.staff. Sliding expiry. */
export function loadSession(db, { ttlMinutes }) {
  return (req, res, next) => {
    const token = parseCookies(req.headers.cookie)[COOKIE];
    if (token) {
      const hash = sha256(token);
      const s = db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(hash);
      if (s && s.expires_at > Date.now()) {
        db.prepare('UPDATE sessions SET expires_at = ? WHERE token_hash = ?').run(Date.now() + ttlMinutes * 60_000, hash);
        req.session = { ...s, token_hash: hash };
        req.staff = db.prepare('SELECT id, email, name, role FROM staff WHERE id = ?').get(s.staff_id);
      } else if (s) {
        db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash);
      }
    }
    res.locals.staff = req.session?.mfa_ok ? req.staff : null;
    res.locals.csrf = req.session?.csrf ?? '';
    next();
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
  // Pre-auth login has no session to bind a token to; SameSite=Strict + rate limiting cover it.
  if (req.method === 'POST' && req.path === '/login') return next();
  if (!req.session || !safeEqual(req.body?._csrf ?? '', req.session.csrf)) {
    return res.status(403).render('error', { message: 'Security token expired. Please reload the page.' });
  }
  next();
};
