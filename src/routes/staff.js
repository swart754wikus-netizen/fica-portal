import { Router } from 'express';
import crypto from 'node:crypto';
import { verifyPassword, decrypt, decryptJson, randomToken, sha256 } from '../security/crypto.js';
import { verifyTotp } from '../security/totp.js';
import { createSession, destroySession, requireStaff, requireRole, csrfCheck } from '../security/session.js';
import { rateLimit } from '../security/rateLimit.js';
import { audit, verifyAuditChain } from '../audit.js';
import { sendInvite } from '../email/index.js';

const MAX_FAILED = 5;
const LOCK_MS = 15 * 60_000;
const DOC_LABELS = { idDocument: 'Identity document', proofOfAddress: 'Proof of address' };

export function staffRouter({ db, config, mailer }) {
  const r = Router();
  const loginLimiter = rateLimit({ windowMs: 15 * 60_000, max: 20 });
  const sessOpts = { isProd: config.isProd, ttlMinutes: config.sessionTtlMinutes };

  r.use(csrfCheck);

  // ---- Authentication (password + TOTP) --------------------------------------------------
  r.get('/login', (req, res) => res.render('staff/login', { error: null }));

  r.post('/login', loginLimiter, (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const s = db.prepare('SELECT * FROM staff WHERE email = ?').get(email);
    const fail = (msg = 'Invalid email or password') => {
      audit(db, { actor: `anon:${email.slice(0, 100)}`, action: 'auth.login_failed', ip: req.ip });
      res.status(401).render('staff/login', { error: msg });
    };
    if (!s) { verifyPassword('x', 'scrypt$16384$8$1$AAAA$AAAA'); return fail(); } // equalise timing
    if (s.locked_until && s.locked_until > Date.now()) return fail('Account temporarily locked. Try again later.');
    if (!verifyPassword(String(req.body?.password || ''), s.password_hash)) {
      const n = s.failed_logins + 1;
      db.prepare('UPDATE staff SET failed_logins = ?, locked_until = ? WHERE id = ?')
        .run(n >= MAX_FAILED ? 0 : n, n >= MAX_FAILED ? Date.now() + LOCK_MS : null, s.id);
      return fail();
    }
    db.prepare('UPDATE staff SET failed_logins = 0, locked_until = NULL WHERE id = ?').run(s.id);
    createSession(db, res, s.id, sessOpts);
    res.redirect('/staff/mfa');
  });

  r.get('/mfa', (req, res) => (req.session ? res.render('staff/mfa', { error: null }) : res.redirect('/staff/login')));

  r.post('/mfa', loginLimiter, (req, res) => {
    if (!req.session) return res.redirect('/staff/login');
    const s = db.prepare('SELECT * FROM staff WHERE id = ?').get(req.session.staff_id);
    const secret = decrypt(s.totp_secret_enc, config.dataKey, `totp:${s.id}`).toString();
    if (!verifyTotp(secret, String(req.body?.code || '').trim())) {
      audit(db, { actor: `staff:${s.email}`, action: 'auth.mfa_failed', ip: req.ip });
      if (req.session.mfa_attempts + 1 >= 5) { // stop TOTP brute force: force a fresh password login
        destroySession(db, req, res);
        return res.status(401).render('staff/login', { error: 'Too many invalid codes. Please sign in again.' });
      }
      db.prepare('UPDATE sessions SET mfa_attempts = mfa_attempts + 1 WHERE token_hash = ?').run(req.session.token_hash);
      return res.status(401).render('staff/mfa', { error: 'Invalid code' });
    }
    // Rotate the session token on privilege change (prevents session fixation).
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.session.token_hash);
    createSession(db, res, s.id, sessOpts, true);
    audit(db, { actor: `staff:${s.email}`, action: 'auth.login', ip: req.ip });
    res.redirect('/staff');
  });

  r.post('/logout', (req, res) => {
    if (req.staff) audit(db, { actor: `staff:${req.staff.email}`, action: 'auth.logout', ip: req.ip });
    destroySession(db, req, res);
    res.redirect('/staff/login');
  });

  // ---- Everything below requires an MFA-verified session ---------------------------------
  r.use(requireStaff);
  const actor = (req) => `staff:${req.staff.email}`;

  const loadCase = (req, res) => {
    const c = db.prepare('SELECT * FROM cases WHERE id = ?').get(req.params.id);
    if (!c) { res.status(404).render('error', { message: 'Case not found' }); return null; }
    return c;
  };

  r.get('/', (req, res) => {
    const status = ['invited', 'submitted', 'approved', 'rejected'].includes(req.query.status) ? req.query.status : null;
    const cases = db.prepare(`SELECT id, reference, client_name, client_email, status, risk_level, risk_score, dd_level, created_at, submitted_at
                              FROM cases ${status ? 'WHERE status = ?' : ''} ORDER BY created_at DESC LIMIT 200`)
      .all(...(status ? [status] : []));
    const counts = Object.fromEntries(db.prepare('SELECT status, COUNT(*) n FROM cases GROUP BY status').all().map((r) => [r.status, r.n]));
    res.render('staff/dashboard', { cases, counts, status, invite: null });
  });

  /** Issues a fresh single-use token (invalidating any previous one) and emails it. */
  async function issueInvite(req, c) {
    const token = randomToken();
    const expiresAt = Date.now() + config.inviteTtlHours * 3_600_000;
    db.prepare('UPDATE cases SET invite_token_hash = ?, invite_expires_at = ? WHERE id = ?').run(sha256(token), expiresAt, c.id);
    const link = `${config.baseUrl}/onboard/${token}`;
    try {
      await sendInvite(mailer, config, { to: c.client_email, clientName: c.client_name, reference: c.reference, link, expiresAt });
      audit(db, { actor: actor(req), action: mailer.delivers ? 'invite.emailed' : 'invite.logged', caseId: c.id, ip: req.ip });
      // Once real email is configured, staff never see the link — it only reaches the client's inbox.
      return { reference: c.reference, email: c.client_email, caseId: c.id, sent: mailer.delivers, link: mailer.delivers ? null : link };
    } catch (e) {
      console.error('Invite email failed:', e.code || e.message);
      audit(db, { actor: actor(req), action: 'invite.email_failed', caseId: c.id, ip: req.ip, detail: { code: e.code || 'ERROR' } });
      return { reference: c.reference, email: c.client_email, caseId: c.id, sent: false, failed: true, link };
    }
  }

  r.post('/cases', async (req, res) => {
    const name = String(req.body?.name || '').trim().slice(0, 150);
    const email = String(req.body?.email || '').trim().toLowerCase().slice(0, 200);
    if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).render('error', { message: 'Enter the client name and a valid email address.' });
    }
    const id = crypto.randomUUID();
    const reference = `KYC-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    db.prepare(`INSERT INTO cases (id, reference, client_email, client_name, status, created_by, created_at)
                VALUES (?, ?, ?, ?, 'invited', ?, ?)`)
      .run(id, reference, email, name, req.staff.id, Date.now());
    audit(db, { actor: actor(req), action: 'case.invited', caseId: id, ip: req.ip });
    res.render('staff/invite', { invite: await issueInvite(req, db.prepare('SELECT * FROM cases WHERE id = ?').get(id)) });
  });

  r.post('/cases/:id/resend', async (req, res) => {
    const c = loadCase(req, res); if (!c) return;
    if (c.status !== 'invited') return res.status(409).render('error', { message: 'This client has already submitted.' });
    audit(db, { actor: actor(req), action: 'invite.resent', caseId: c.id, ip: req.ip });
    res.render('staff/invite', { invite: await issueInvite(req, c) });
  });

  r.get('/cases/:id', (req, res) => {
    const c = loadCase(req, res); if (!c) return;
    const data = c.data_enc ? decryptJson(c.data_enc, config.dataKey, c.id) : null;
    const docs = db.prepare('SELECT id, kind, mime, size, sha256, created_at FROM documents WHERE case_id = ?').all(c.id);
    const history = db.prepare('SELECT ts, actor, action FROM audit_log WHERE case_id = ? ORDER BY id').all(c.id);
    audit(db, { actor: actor(req), action: 'case.viewed', caseId: c.id, ip: req.ip });
    res.render('staff/case', {
      c, data, docs, history, DOC_LABELS,
      screening: c.screening ? JSON.parse(c.screening) : null,
      risk: c.risk_breakdown ? JSON.parse(c.risk_breakdown) : null,
      decidedBy: c.decided_by ? db.prepare('SELECT name FROM staff WHERE id = ?').get(c.decided_by)?.name : null,
    });
  });

  r.get('/cases/:id/documents/:docId', (req, res) => {
    const doc = db.prepare('SELECT * FROM documents WHERE id = ? AND case_id = ?').get(req.params.docId, req.params.id);
    if (!doc) return res.status(404).render('error', { message: 'Document not found' });
    const buf = decrypt(doc.blob_enc, config.dataKey, doc.id);
    audit(db, { actor: actor(req), action: 'document.downloaded', caseId: doc.case_id, ip: req.ip, detail: { kind: doc.kind } });
    const ext = { 'application/pdf': 'pdf', 'image/jpeg': 'jpg', 'image/png': 'png' }[doc.mime];
    res.set({
      'Content-Type': doc.mime,
      'Content-Disposition': `attachment; filename="${doc.kind}.${ext}"`,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    }).send(buf);
  });

  r.post('/cases/:id/decision', (req, res) => {
    const c = loadCase(req, res); if (!c) return;
    if (c.status !== 'submitted') return res.status(409).render('error', { message: 'This case is not awaiting a decision.' });
    const decision = req.body?.decision;
    const reason = String(req.body?.reason || '').trim().slice(0, 2000);
    if (!['approved', 'rejected'].includes(decision) || reason.length < 10) {
      return res.status(400).render('error', { message: 'Choose a decision and give a reason of at least 10 characters.' });
    }
    const risk = JSON.parse(c.risk_breakdown);
    if (decision === 'approved' && risk.requiresCompliance && req.staff.role !== 'compliance') {
      return res.status(403).render('error', { message: `${risk.ddLabel}. Only a compliance officer may approve this client.` });
    }
    if (decision === 'approved' && req.body?.eddConfirmed !== 'on' && risk.ddLevel === 'EDD') {
      return res.status(400).render('error', { message: 'Confirm that enhanced due diligence (source of wealth, senior approval) has been completed.' });
    }
    const now = Date.now();
    const retention = new Date(now); retention.setFullYear(retention.getFullYear() + config.retentionYears);
    db.prepare('UPDATE cases SET status = ?, decision_reason = ?, decided_by = ?, decided_at = ?, retention_until = ? WHERE id = ?')
      .run(decision, reason, req.staff.id, now, retention.getTime(), c.id);
    audit(db, { actor: actor(req), action: `case.${decision}`, caseId: c.id, ip: req.ip, detail: { riskLevel: c.risk_level } });
    // NOTE: a sanctions match must also be reported to the FIC (TPR via goAML) — this app flags, it does not file.
    res.redirect(`/staff/cases/${c.id}`);
  });

  r.get('/cases/:id/report', (req, res) => {
    const c = loadCase(req, res); if (!c) return;
    if (!c.data_enc) return res.status(409).render('error', { message: 'The client has not submitted yet.' });
    audit(db, { actor: actor(req), action: 'report.generated', caseId: c.id, ip: req.ip });
    res.set('Cache-Control', 'no-store').render('staff/report', {
      c, data: decryptJson(c.data_enc, config.dataKey, c.id), DOC_LABELS,
      screening: JSON.parse(c.screening), risk: JSON.parse(c.risk_breakdown),
      docs: db.prepare('SELECT kind, mime, size, sha256 FROM documents WHERE case_id = ?').all(c.id),
      decidedBy: c.decided_by ? db.prepare('SELECT name, role FROM staff WHERE id = ?').get(c.decided_by) : null,
      generatedBy: req.staff, generatedAt: new Date(),
    });
  });

  r.get('/audit', requireRole('compliance'), (req, res) => {
    res.render('staff/audit', {
      chain: verifyAuditChain(db),
      rows: db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 300').all(),
    });
  });

  return r;
}
