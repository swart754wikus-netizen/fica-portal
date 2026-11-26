import { Router } from 'express';
import QRCode from 'qrcode';
import crypto from 'node:crypto';
import { verifyPassword, hashPassword, encrypt, decrypt, decryptJson, randomToken, sha256, safeEqual } from '../security/crypto.js';
import { verifyTotp, generateSecret, otpauthUri } from '../security/totp.js';
import { createSession, destroySession, requireStaff, requireRole, csrfCheck } from '../security/session.js';
import { rateLimit } from '../security/rateLimit.js';
import { audit, verifyAuditChain } from '../audit.js';
import { sendInvite } from '../email/index.js';
import { DOC_LABELS } from '../onboarding/catalog.js';

const MAX_FAILED = 5;
const LOCK_MS = 15 * 60_000;
const MIN_PASSWORD = 12;
const isActive = (s) => s && s.active !== false && s.active !== 0;

export function staffRouter({ store, config, mailer }) {
  const r = Router();
  const loginLimiter = rateLimit(store, { windowMs: 15 * 60_000, max: 20, name: 'login' });
  const sessOpts = { isProd: config.isProd, ttlMinutes: config.sessionTtlMinutes };
  const totpAad = (s) => `totp:${s.id}`;

  r.use(csrfCheck);

  // ---- First-run setup: create the first compliance officer from the browser ------------
  // Needs SETUP_TOKEN (a Vercel env var) and only works while no staff exist.
  r.get('/setup', async (req, res) => {
    if (!config.setupToken || (await store.countStaff()) > 0) return res.status(404).render('error', { message: 'Page not found' });
    res.render('staff/setup', { error: null, values: {} });
  });
  r.post('/setup', loginLimiter, async (req, res) => {
    if (!config.setupToken || (await store.countStaff()) > 0) return res.status(404).render('error', { message: 'Page not found' });
    const v = { name: String(req.body?.name || '').trim().slice(0, 100), email: String(req.body?.email || '').trim().toLowerCase() };
    const fail = (error) => res.status(400).render('staff/setup', { error, values: v });
    if (!safeEqual(String(req.body?.token || ''), config.setupToken)) return fail('Setup code is incorrect.');
    if (!v.name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.email)) return fail('Enter your name and a valid email address.');
    if (String(req.body?.password || '').length < MIN_PASSWORD) return fail(`Password must be at least ${MIN_PASSWORD} characters.`);
    const id = await store.createStaff({ email: v.email, name: v.name, role: 'compliance', password_hash: hashPassword(req.body.password), created_at: Date.now() });
    await audit(store, { actor: `staff:${v.email}`, action: 'setup.first_admin', ip: req.ip, detail: { id } });
    res.redirect('/staff/login?setup=1');
  });

  // ---- Authentication (password, then authenticator code) ---------------------------------
  r.get('/login', (req, res) => res.render('staff/login', { error: null, notice: req.query.setup ? 'Account created. Log in to set up two-step verification.' : null }));

  r.post('/login', loginLimiter, async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const s = await store.getStaffByEmail(email);
    const fail = async (msg = 'Invalid email or password') => {
      await audit(store, { actor: `anon:${email.slice(0, 100)}`, action: 'auth.login_failed', ip: req.ip });
      res.status(401).render('staff/login', { error: msg, notice: null });
    };
    if (!s) { verifyPassword('x', 'scrypt$16384$8$1$AAAA$AAAA'); return fail(); } // equalise timing
    if (!isActive(s)) return fail();
    if (s.locked_until && s.locked_until > Date.now()) return fail('Account temporarily locked. Try again later.');
    if (!verifyPassword(String(req.body?.password || ''), s.password_hash)) {
      const n = (s.failed_logins || 0) + 1;
      await store.updateStaff(s.id, { failed_logins: n >= MAX_FAILED ? 0 : n, locked_until: n >= MAX_FAILED ? Date.now() + LOCK_MS : null });
      return fail();
    }
    await store.updateStaff(s.id, { failed_logins: 0, locked_until: null });
    await createSession(store, res, s.id, sessOpts);
    res.redirect('/staff/mfa');
  });

  // First login (or after an MFA reset): show a new secret to add to an authenticator app.
  async function enrolmentView(s) {
    let secret;
    if (s.pending_totp_enc?.length) secret = decrypt(s.pending_totp_enc, config.dataKey, totpAad(s)).toString();
    else {
      secret = generateSecret();
      await store.updateStaff(s.id, { pending_totp_enc: encrypt(secret, config.dataKey, totpAad(s)) });
    }
    const uri = otpauthUri(secret, s.email, config.firmName);
    // QR rendered server-side as a data: URL — the secret never goes to a third-party QR service.
    const qr = await QRCode.toDataURL(uri, { errorCorrectionLevel: 'M', margin: 1, width: 220 });
    return { enroll: true, secret: secret.replace(/(.{4})/g, '$1 ').trim(), uri, qr };
  }

  r.get('/mfa', async (req, res) => {
    if (!req.session) return res.redirect('/staff/login');
    const s = await store.getStaffById(req.session.staff_id);
    res.render('staff/mfa', { error: null, ...(s.totp_secret_enc ? {} : await enrolmentView(s)) });
  });

  r.post('/mfa', loginLimiter, async (req, res) => {
    if (!req.session) return res.redirect('/staff/login');
    const s = await store.getStaffById(req.session.staff_id);
    const enrolling = !s.totp_secret_enc;
    const enc = enrolling ? s.pending_totp_enc : s.totp_secret_enc;
    const counter = enc?.length ? verifyTotp(decrypt(enc, config.dataKey, totpAad(s)).toString(), String(req.body?.code || '').trim()) : null;
    // A code can only be used once, even inside its 30-second window.
    if (counter === null || counter <= (s.totp_last_counter || 0)) {
      await audit(store, { actor: `staff:${s.email}`, action: 'auth.mfa_failed', ip: req.ip });
      if ((req.session.mfa_attempts || 0) + 1 >= 5) { // stop TOTP brute force: force a fresh password login
        await destroySession(store, req, res);
        return res.status(401).render('staff/login', { error: 'Too many invalid codes. Please sign in again.', notice: null });
      }
      await store.updateSession(req.session.token_hash, { mfa_attempts: (req.session.mfa_attempts || 0) + 1 });
      return res.status(401).render('staff/mfa', { error: 'Invalid code', ...(enrolling ? await enrolmentView(s) : {}) });
    }
    await store.updateStaff(s.id, enrolling
      ? { totp_secret_enc: s.pending_totp_enc, pending_totp_enc: null, totp_last_counter: counter }
      : { totp_last_counter: counter });
    // Rotate the session token on privilege change (prevents session fixation).
    await store.deleteSession(req.session.token_hash);
    await createSession(store, res, s.id, sessOpts, true);
    await audit(store, { actor: `staff:${s.email}`, action: enrolling ? 'auth.mfa_enrolled' : 'auth.login', ip: req.ip });
    res.redirect('/staff');
  });

  r.post('/logout', async (req, res) => {
    if (req.staff) await audit(store, { actor: `staff:${req.staff.email}`, action: 'auth.logout', ip: req.ip });
    await destroySession(store, req, res);
    res.redirect('/staff/login');
  });

  // ---- Everything below requires an MFA-verified session ---------------------------------
  r.use(requireStaff);

  // Accounts created with a temporary password must choose their own before doing anything else.
  r.use((req, res, next) => (req.staff.mustChangePassword && req.path !== '/password' ? res.redirect('/staff/password') : next()));

  r.get('/password', (req, res) => res.render('staff/password', { error: null, forced: req.staff.mustChangePassword }));
  r.post('/password', loginLimiter, async (req, res) => {
    const s = await store.getStaffById(req.staff.id);
    const fail = (error) => res.status(400).render('staff/password', { error, forced: req.staff.mustChangePassword });
    const next = String(req.body?.newPassword || '');
    if (!verifyPassword(String(req.body?.currentPassword || ''), s.password_hash)) return fail('Your current password is incorrect.');
    if (next.length < MIN_PASSWORD) return fail(`Choose a password of at least ${MIN_PASSWORD} characters.`);
    if (next !== String(req.body?.confirmPassword || '')) return fail('The two new passwords do not match.');
    if (verifyPassword(next, s.password_hash)) return fail('Choose a password different from your current one.');
    await store.updateStaff(s.id, { password_hash: hashPassword(next), must_change_password: false });
    await audit(store, { actor: `staff:${s.email}`, action: 'auth.password_changed', ip: req.ip });
    res.redirect('/staff?password=changed');
  });
  const actor = (req) => `staff:${req.staff.email}`;
  const staffName = async (id) => (id ? (await store.getStaffById(id))?.name : null);

  const loadCase = async (req, res) => {
    const c = await store.getCase(req.params.id);
    if (!c) { res.status(404).render('error', { message: 'Case not found' }); return null; }
    return c;
  };

  r.get('/', async (req, res) => {
    const status = ['invited', 'submitted', 'approved', 'rejected'].includes(req.query.status) ? req.query.status : null;
    const [cases, counts] = await Promise.all([store.listCases({ status, limit: 200 }), store.countCasesByStatus()]);
    res.render('staff/dashboard', { cases, counts, status, invite: null });
  });

  /** Issues a fresh single-use token (invalidating any previous one) and emails it. */
  async function issueInvite(req, c) {
    const token = randomToken();
    const expiresAt = Date.now() + config.inviteTtlHours * 3_600_000;
    await store.updateCase(c.id, { invite_token_hash: sha256(token), invite_expires_at: expiresAt });
    const link = `${config.baseUrl}/onboard/${token}`;
    try {
      await sendInvite(mailer, config, { to: c.client_email, clientName: c.client_name, reference: c.reference, link, expiresAt });
      await audit(store, { actor: actor(req), action: mailer.delivers ? 'invite.emailed' : 'invite.logged', caseId: c.id, ip: req.ip });
      // Once real email is configured, staff never see the link — it only reaches the client's inbox.
      return { reference: c.reference, email: c.client_email, caseId: c.id, sent: mailer.delivers, link: mailer.delivers ? null : link };
    } catch (e) {
      console.error('Invite email failed:', e.code || e.message);
      await audit(store, { actor: actor(req), action: 'invite.email_failed', caseId: c.id, ip: req.ip, detail: { code: e.code || 'ERROR' } });
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
    await store.createCase({ id, reference, client_email: email, client_name: name, status: 'invited', created_by: req.staff.id, created_at: Date.now() });
    await audit(store, { actor: actor(req), action: 'case.invited', caseId: id, ip: req.ip });
    res.render('staff/invite', { invite: await issueInvite(req, await store.getCase(id)) });
  });

  r.post('/cases/:id/resend', async (req, res) => {
    const c = await loadCase(req, res); if (!c) return;
    if (c.status !== 'invited') return res.status(409).render('error', { message: 'This client has already submitted.' });
    await audit(store, { actor: actor(req), action: 'invite.resent', caseId: c.id, ip: req.ip });
    res.render('staff/invite', { invite: await issueInvite(req, c) });
  });

  // Administrators send invites and track progress only: no client details, documents,
  // risk ratings or decisions (need-to-know; avoids tipping-off risk).
  const notAdmin = (req, res, next) => (req.staff.role === 'admin'
    ? res.status(403).render('error', { message: 'Your role can send invites and track progress, but not open client records.' })
    : next());

  r.get('/cases/:id', async (req, res) => {
    const c = await loadCase(req, res); if (!c) return;
    if (req.staff.role === 'admin') {
      return res.render('staff/case', { c, data: null, docs: [], history: [], DOC_LABELS, decidedBy: null, screening: null, risk: null, limited: true });
    }
    const data = c.data_enc ? decryptJson(c.data_enc, config.dataKey, c.id) : null;
    const [docs, history, decidedBy] = await Promise.all([store.listDocuments(c.id), store.listAudit({ caseId: c.id }), staffName(c.decided_by)]);
    await audit(store, { actor: actor(req), action: 'case.viewed', caseId: c.id, ip: req.ip });
    res.render('staff/case', {
      c, data, docs, history, DOC_LABELS, decidedBy,
      screening: c.screening ? JSON.parse(c.screening) : null,
      risk: c.risk_breakdown ? JSON.parse(c.risk_breakdown) : null,
    });
  });

  r.get('/cases/:id/documents/:docId', notAdmin, async (req, res) => {
    const doc = await store.getDocument(req.params.id, req.params.docId);
    if (!doc) return res.status(404).render('error', { message: 'Document not found' });
    const buf = decrypt(await store.getDocumentBlob(doc), config.dataKey, doc.id);
    await audit(store, { actor: actor(req), action: 'document.downloaded', caseId: doc.case_id, ip: req.ip, detail: { kind: doc.kind } });
    const ext = { 'application/pdf': 'pdf', 'image/jpeg': 'jpg', 'image/png': 'png' }[doc.mime];
    res.set({
      'Content-Type': doc.mime,
      'Content-Disposition': `attachment; filename="${doc.kind}.${ext}"`,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    }).send(buf);
  });

  r.post('/cases/:id/decision', notAdmin, async (req, res) => {
    const c = await loadCase(req, res); if (!c) return;
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
    await store.updateCase(c.id, { status: decision, decision_reason: reason, decided_by: req.staff.id, decided_at: now, retention_until: retention.getTime() });
    await audit(store, { actor: actor(req), action: `case.${decision}`, caseId: c.id, ip: req.ip, detail: { riskLevel: c.risk_level } });
    // NOTE: a sanctions match must also be reported to the FIC (TPR via goAML) — this app flags, it does not file.
    res.redirect(`/staff/cases/${c.id}`);
  });

  r.get('/cases/:id/report', notAdmin, async (req, res) => {
    const c = await loadCase(req, res); if (!c) return;
    if (!c.data_enc) return res.status(409).render('error', { message: 'The client has not submitted yet.' });
    await audit(store, { actor: actor(req), action: 'report.generated', caseId: c.id, ip: req.ip });
    const decider = c.decided_by ? await store.getStaffById(c.decided_by) : null;
    res.set('Cache-Control', 'no-store').render('staff/report', {
      c, data: decryptJson(c.data_enc, config.dataKey, c.id), DOC_LABELS,
      screening: JSON.parse(c.screening), risk: JSON.parse(c.risk_breakdown),
      docs: await store.listDocuments(c.id),
      decidedBy: decider ? { name: decider.name, role: decider.role } : null,
      generatedBy: req.staff, generatedAt: new Date(),
    });
  });

  r.get('/audit', requireRole('compliance'), async (req, res) => {
    res.render('staff/audit', { chain: await verifyAuditChain(store), rows: await store.listAudit({ limit: 300, newestFirst: true }) });
  });

  // ---- Team (compliance officers manage staff accounts) ----------------------------------
  r.get('/team', requireRole('compliance'), async (req, res) => {
    res.render('staff/team', { staffList: await store.listStaff(), error: null, values: {} });
  });

  r.post('/team', requireRole('compliance'), async (req, res) => {
    const v = { name: String(req.body?.name || '').trim().slice(0, 100), email: String(req.body?.email || '').trim().toLowerCase(), role: ['compliance', 'admin'].includes(req.body?.role) ? req.body.role : 'officer' };
    const fail = async (error) => res.status(400).render('staff/team', { staffList: await store.listStaff(), error, values: v });
    if (!v.name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.email)) return fail('Enter a name and a valid email address.');
    if (String(req.body?.password || '').length < MIN_PASSWORD) return fail(`Temporary password must be at least ${MIN_PASSWORD} characters.`);
    if (await store.getStaffByEmail(v.email)) return fail('An account with this email already exists.');
    try {
      const id = await store.createStaff({ email: v.email, name: v.name, role: v.role, password_hash: hashPassword(req.body.password), must_change_password: true, created_at: Date.now() });
      await audit(store, { actor: actor(req), action: 'team.staff_created', ip: req.ip, detail: { id, role: v.role } });
    } catch (err) {
      if (err.code === 'duplicate') return fail(err.message);
      throw err;
    }
    res.redirect('/staff/team');
  });

  r.post('/team/:id', requireRole('compliance'), async (req, res) => {
    const target = await store.getStaffById(req.params.id);
    if (!target) return res.status(404).render('error', { message: 'Staff member not found' });
    const action = req.body?.action;
    if (action === 'deactivate' || action === 'activate') {
      if (target.id === req.staff.id) return res.status(400).render('error', { message: "You can't deactivate your own account." });
      await store.updateStaff(target.id, { active: action === 'activate' });
    } else if (action === 'tempPassword') {
      const temp = String(req.body?.password || '');
      if (temp.length < MIN_PASSWORD) return res.status(400).render('error', { message: `Temporary password must be at least ${MIN_PASSWORD} characters.` });
      await store.updateStaff(target.id, { password_hash: hashPassword(temp), must_change_password: true, failed_logins: 0, locked_until: null });
    } else if (action === 'resetMfa') {
      await store.updateStaff(target.id, { totp_secret_enc: null, pending_totp_enc: null, totp_last_counter: 0 });
    } else {
      return res.status(400).render('error', { message: 'Unknown action' });
    }
    await audit(store, { actor: actor(req), action: `team.${action}`, ip: req.ip, detail: { id: target.id } });
    res.redirect('/staff/team');
  });

  return r;
}
