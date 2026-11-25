import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { MockProvider } from '../src/providers/mock.js';
import { hashPassword, encrypt } from '../src/security/crypto.js';
import { totp, generateSecret } from '../src/security/totp.js';
import { verifyAuditChain } from '../src/audit.js';
import { makeSaId, testKey } from './helpers.js';

const config = { firmName: 'Test Attorneys', port: 0, baseUrl: 'http://x', isProd: false, dataKey: testKey, inviteTtlHours: 72, sessionTtlMinutes: 30, maxUploadBytes: 5 * 1024 * 1024, retentionYears: 5 };
let server, base, db;
const sent = [];
const mailer = { delivers: true, fail: false, async send(m) { if (this.fail) throw Object.assign(new Error('down'), { code: 'ECONNREFUSED' }); sent.push(m); } };
const staff = {};

function addStaff(email, role) {
  const secret = generateSecret();
  const { lastInsertRowid: id } = db.prepare('INSERT INTO staff (email, name, role, password_hash, totp_secret_enc, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(email, email.split('@')[0], role, hashPassword('a-long-test-password'), Buffer.alloc(0), Date.now());
  db.prepare('UPDATE staff SET totp_secret_enc = ? WHERE id = ?').run(encrypt(secret, testKey, `totp:${id}`), id);
  return { email, secret };
}

before(async () => {
  db = openDb(':memory:');
  const app = createApp({ db, config, provider: new MockProvider(), mailer });
  await new Promise((r) => { server = app.listen(0, r); });
  base = `http://127.0.0.1:${server.address().port}`;
  staff.officer = addStaff('officer@firm.test', 'officer');
  staff.compliance = addStaff('compliance@firm.test', 'compliance');
});
after(() => server.close());

const cookieOf = (res) => res.headers.get('set-cookie')?.split(';')[0];
const csrfOf = (html) => html.match(/name="_csrf" value="([^"]+)"/)?.[1];

async function login({ email, secret }) {
  let res = await fetch(`${base}/staff/login`, { method: 'POST', redirect: 'manual', body: new URLSearchParams({ email, password: 'a-long-test-password' }) });
  assert.equal(res.status, 302);
  let cookie = cookieOf(res);
  const html = await (await fetch(`${base}/staff/mfa`, { headers: { cookie } })).text();
  res = await fetch(`${base}/staff/mfa`, { method: 'POST', redirect: 'manual', headers: { cookie }, body: new URLSearchParams({ _csrf: csrfOf(html), code: totp(secret) }) });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/staff');
  cookie = cookieOf(res);
  const dash = await (await fetch(`${base}/staff`, { headers: { cookie } })).text();
  return { cookie, csrf: csrfOf(dash) };
}

async function invite(sess, name) {
  const res = await fetch(`${base}/staff/cases`, { method: 'POST', headers: { cookie: sess.cookie }, body: new URLSearchParams({ _csrf: sess.csrf, name, email: 'client@example.com' }) });
  await res.text();
  return sent.at(-1).text.match(/http:\/\/x(\/onboard\/\S+)/)[1];
}

function clientForm(overrides = {}) {
  const fd = new FormData();
  const fields = { firstName: 'Thandi', lastName: 'Nkosi', idType: 'sa_id', idNumber: makeSaId('900515012308'), nationality: 'ZA', countryOfResidence: 'ZA',
    phone: '+27 82 123 4567', addressLine1: '1 Main Rd', city: 'Cape Town', province: 'WC', postalCode: '8001', occupation: 'Engineer',
    sourceOfFunds: 'salary', expectedValueZar: '80000', purpose: 'Purchase of residential property', pepDeclared: 'no', consent: 'on', declaration: 'on', ...overrides };
  for (const [k, v] of Object.entries(fields)) if (v !== undefined) fd.append(k, v);
  fd.append('idDocument', new Blob([Buffer.from('%PDF-1.4 fake id')], { type: 'application/pdf' }), 'id.pdf');
  fd.append('proofOfAddress', new Blob([Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3])], { type: 'image/jpeg' }), 'poa.jpg');
  return fd;
}

test('unauthenticated staff pages redirect to login', async () => {
  const res = await fetch(`${base}/staff`, { redirect: 'manual' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/staff/login');
});

test('password alone does not grant access (MFA enforced)', async () => {
  const res = await fetch(`${base}/staff/login`, { method: 'POST', redirect: 'manual', body: new URLSearchParams({ email: staff.officer.email, password: 'a-long-test-password' }) });
  const res2 = await fetch(`${base}/staff`, { redirect: 'manual', headers: { cookie: cookieOf(res) } });
  assert.equal(res2.headers.get('location'), '/staff/mfa');
});

test('CSRF token required for state changes', async () => {
  const sess = await login(staff.officer);
  const res = await fetch(`${base}/staff/cases`, { method: 'POST', headers: { cookie: sess.cookie }, body: new URLSearchParams({ name: 'X', email: 'x@y.z' }) });
  assert.equal(res.status, 403);
});

test('security headers present', async () => {
  const res = await fetch(`${base}/`);
  assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('x-powered-by'), null);
});

test('full low-risk flow: invite → submit → approve → report', async () => {
  const sess = await login(staff.officer);
  const path = await invite(sess, 'Thandi Nkosi');

  assert.equal((await fetch(base + path)).status, 200);
  const bad = await fetch(base + path, { method: 'POST', body: clientForm({ idNumber: '8001015009088', consent: undefined }) });
  assert.equal(bad.status, 400);
  const badHtml = await bad.text();
  assert.match(badHtml, /checksum is invalid|invalid/);
  assert.match(badHtml, /Consent is required/);

  const ok = await fetch(base + path, { method: 'POST', body: clientForm() });
  assert.equal(ok.status, 200);
  assert.match(await ok.text(), /received your information/);
  assert.equal((await fetch(base + path)).status, 404, 'invite link is single-use');

  const c = db.prepare("SELECT * FROM cases WHERE client_name = 'Thandi Nkosi'").get();
  assert.equal(c.status, 'submitted');
  assert.equal(c.risk_level, 'low');
  assert.ok(!c.data_enc.toString('latin1').includes('Thandi'), 'PII encrypted at rest');
  const doc = db.prepare('SELECT * FROM documents WHERE case_id = ?').get(c.id);
  assert.ok(!doc.blob_enc.toString('latin1').includes('%PDF'), 'documents encrypted at rest');

  const page = await (await fetch(`${base}/staff/cases/${c.id}`, { headers: { cookie: sess.cookie } })).text();
  assert.match(page, /Thandi/);

  const dl = await fetch(`${base}/staff/cases/${c.id}/documents/${db.prepare("SELECT id FROM documents WHERE case_id = ? AND kind = 'idDocument'").get(c.id).id}`, { headers: { cookie: sess.cookie } });
  assert.equal(await dl.text(), '%PDF-1.4 fake id');
  assert.match(dl.headers.get('content-disposition'), /attachment/);

  const dec = await fetch(`${base}/staff/cases/${c.id}/decision`, { method: 'POST', redirect: 'manual', headers: { cookie: sess.cookie }, body: new URLSearchParams({ _csrf: sess.csrf, decision: 'approved', reason: 'All documents verified and clear.' }) });
  assert.equal(dec.status, 302);
  assert.equal(db.prepare('SELECT status FROM cases WHERE id = ?').get(c.id).status, 'approved');

  const report = await (await fetch(`${base}/staff/cases/${c.id}/report`, { headers: { cookie: sess.cookie } })).text();
  assert.match(report, /Know Your Customer Report/);
  assert.match(report, /APPROVED/);
});

test('sanctioned client is high risk and an officer cannot approve', async () => {
  const officer = await login(staff.officer);
  const path = await invite(officer, 'Bad Actor');
  await fetch(base + path, { method: 'POST', body: clientForm({ firstName: 'Bad', lastName: 'Sanctioned' }) });
  const c = db.prepare("SELECT * FROM cases WHERE client_name = 'Bad Actor'").get();
  assert.equal(c.risk_level, 'high');
  assert.equal(c.dd_level, 'EDD');

  const res = await fetch(`${base}/staff/cases/${c.id}/decision`, { method: 'POST', headers: { cookie: officer.cookie }, body: new URLSearchParams({ _csrf: officer.csrf, decision: 'approved', reason: 'Trying to approve anyway' }) });
  assert.equal(res.status, 403);

  const comp = await login(staff.compliance);
  const noEdd = await fetch(`${base}/staff/cases/${c.id}/decision`, { method: 'POST', headers: { cookie: comp.cookie }, body: new URLSearchParams({ _csrf: comp.csrf, decision: 'approved', reason: 'Approving without EDD' }) });
  assert.equal(noEdd.status, 400, 'EDD confirmation required');

  const rej = await fetch(`${base}/staff/cases/${c.id}/decision`, { method: 'POST', redirect: 'manual', headers: { cookie: comp.cookie }, body: new URLSearchParams({ _csrf: comp.csrf, decision: 'rejected', reason: 'Sanctions match — reported to FIC.' }) });
  assert.equal(rej.status, 302);
});

test('non-PDF/image upload is rejected', async () => {
  const sess = await login(staff.officer);
  const path = await invite(sess, 'Upload Test');
  const fd = clientForm();
  fd.set('idDocument', new Blob(['<html><script>alert(1)</script>'], { type: 'application/pdf' }), 'evil.pdf');
  const res = await fetch(base + path, { method: 'POST', body: fd });
  assert.equal(res.status, 400);
  assert.match(await res.text(), /Only PDF, JPEG or PNG/);
});

test('audit trail is intact and officers cannot view it', async () => {
  assert.deepEqual(verifyAuditChain(db), { ok: true });
  const officer = await login(staff.officer);
  assert.equal((await fetch(`${base}/staff/audit`, { headers: { cookie: officer.cookie } })).status, 403);
  const comp = await login(staff.compliance);
  const html = await (await fetch(`${base}/staff/audit`, { headers: { cookie: comp.cookie } })).text();
  assert.match(html, /Hash chain intact/);
});

test('invite is emailed, link hidden from staff, resend cancels old link', async () => {
  const sess = await login(staff.officer);
  const before = sent.length;
  const res = await fetch(`${base}/staff/cases`, { method: 'POST', headers: { cookie: sess.cookie }, body: new URLSearchParams({ _csrf: sess.csrf, name: 'Mail <b>Test</b>', email: 'mail@example.com' }) });
  const html = await res.text();
  assert.match(html, /Invitation emailed/);
  assert.doesNotMatch(html, /\/onboard\//, 'staff never see the link once email works');
  const msg = sent[before];
  assert.equal(msg.to, 'mail@example.com');
  assert.match(msg.subject, /Test Attorneys/);
  assert.doesNotMatch(msg.html, /<b>Test/, 'client name is HTML-escaped');
  const first = msg.text.match(/http:\/\/x(\/onboard\/\S+)/)[1];
  assert.equal((await fetch(base + first)).status, 200);

  const c = db.prepare("SELECT id FROM cases WHERE client_email = 'mail@example.com'").get();
  await fetch(`${base}/staff/cases/${c.id}/resend`, { method: 'POST', headers: { cookie: sess.cookie }, body: new URLSearchParams({ _csrf: sess.csrf }) });
  const second = sent.at(-1).text.match(/http:\/\/x(\/onboard\/\S+)/)[1];
  assert.notEqual(first, second);
  assert.equal((await fetch(base + first)).status, 404, 'old link cancelled');
  assert.equal((await fetch(base + second)).status, 200);
});

test('email failure falls back to showing the link and is audited', async () => {
  const sess = await login(staff.officer);
  mailer.fail = true;
  try {
    const html = await (await fetch(`${base}/staff/cases`, { method: 'POST', headers: { cookie: sess.cookie }, body: new URLSearchParams({ _csrf: sess.csrf, name: 'Fail Case', email: 'fail@example.com' }) })).text();
    assert.match(html, /Email could not be sent/);
    assert.match(html, /\/onboard\//);
    assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE action = 'invite.email_failed'").get());
  } finally { mailer.fail = false; }
});
