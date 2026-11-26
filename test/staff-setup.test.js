import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { sqliteStore } from '../src/store/sqlite.js';
import { createApp } from '../src/app.js';
import { MockProvider } from '../src/providers/mock.js';
import { totp } from '../src/security/totp.js';
import { testKey } from './helpers.js';

const config = { firmName: 'Test CA', baseUrl: 'http://x', isProd: false, dataKey: testKey, inviteTtlHours: 72, sessionTtlMinutes: 30, maxUploadBytes: 5e6, retentionYears: 5, setupToken: 'setup-code-123' };
let server, base, store;
const mailer = { delivers: false, async send() {} };
before(async () => {
  store = sqliteStore(':memory:');
  server = createApp({ store, config, provider: new MockProvider(), mailer }).listen(0);
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const cookieOf = (res) => res.headers.get('set-cookie')?.split(';')[0];
const csrfOf = (html) => html.match(/name="_csrf" value="([^"]+)"/)?.[1];
const post = (path, body, cookie) => fetch(base + path, { method: 'POST', redirect: 'manual', headers: cookie ? { cookie } : {}, body: new URLSearchParams(body) });

/** Password step, then enrol (first login) or verify. Returns { cookie, csrf, secret }. */
async function login(email, password, secret, at = Date.now()) {
  const res = await post('/staff/login', { email, password });
  assert.equal(res.status, 302, 'password accepted');
  let cookie = cookieOf(res);
  const page = await (await fetch(base + '/staff/mfa', { headers: { cookie } })).text();
  const shown = page.match(/class="setup-key">([A-Z2-7 ]+)</)?.[1]?.replace(/\s/g, '');
  if (shown) assert.match(page, /<img class="enroll-qr" src="data:image\/png;base64,/, 'QR code shown for enrolment');
  const s = secret || shown;
  const v = await post('/staff/mfa', { _csrf: csrfOf(page), code: totp(s, at) }, cookie);
  if (v.status !== 302) return { failed: v.status, secret: s };
  cookie = cookieOf(v);
  const dash = await (await fetch(base + '/staff', { headers: { cookie } })).text();
  return { cookie, csrf: csrfOf(dash), secret: s };
}

test('first-run setup: needs the setup code, creates a compliance officer, then disappears', async () => {
  assert.equal((await fetch(base + '/staff/setup')).status, 200);
  const bad = await post('/staff/setup', { token: 'wrong', name: 'Naledi', email: 'n@firm.co.za', password: 'a-very-long-password' });
  assert.equal(bad.status, 400);
  const ok = await post('/staff/setup', { token: 'setup-code-123', name: 'Naledi', email: 'n@firm.co.za', password: 'a-very-long-password' });
  assert.equal(ok.status, 302);
  assert.equal((await fetch(base + '/staff/setup')).status, 404, 'gone once an account exists');
  assert.equal((await post('/staff/setup', { token: 'setup-code-123', name: 'X', email: 'x@firm.co.za', password: 'a-very-long-password' })).status, 404);
});

let admin;
test('first login forces authenticator enrolment; codes cannot be replayed', async () => {
  admin = await login('n@firm.co.za', 'a-very-long-password');
  assert.ok(admin.cookie && admin.csrf, 'enrolled and logged in');
  assert.ok(admin.secret.length >= 32);
  const replay = await login('n@firm.co.za', 'a-very-long-password', admin.secret);
  assert.equal(replay.failed, 401, 'same code refused a second time');
  const next = await login('n@firm.co.za', 'a-very-long-password', admin.secret, Date.now() + 30_000);
  assert.ok(next.cookie, 'next code works');
  admin = next;
});

test('team: compliance adds an officer; deactivation ends their session; MFA reset forces re-enrolment', async () => {
  const add = await post('/staff/team', { _csrf: admin.csrf, name: 'Sipho', email: 's@firm.co.za', role: 'officer', password: 'temporary-password-1' }, admin.cookie);
  assert.equal(add.status, 302);
  const dup = await post('/staff/team', { _csrf: admin.csrf, name: 'Sipho', email: 's@firm.co.za', role: 'officer', password: 'temporary-password-1' }, admin.cookie);
  assert.equal(dup.status, 400);
  const officer = await login('s@firm.co.za', 'temporary-password-1');
  assert.ok(officer.cookie);
  // Forced to choose their own password before anything else.
  const blocked = await fetch(base + '/staff', { redirect: 'manual', headers: { cookie: officer.cookie } });
  assert.equal(blocked.headers.get('location'), '/staff/password');
  const pwPage = await (await fetch(base + '/staff/password', { headers: { cookie: officer.cookie } })).text();
  const pwCsrf = csrfOf(pwPage);
  assert.equal((await post('/staff/password', { _csrf: pwCsrf, currentPassword: 'wrong', newPassword: 'my-own-secret-pass', confirmPassword: 'my-own-secret-pass' }, officer.cookie)).status, 400);
  assert.equal((await post('/staff/password', { _csrf: pwCsrf, currentPassword: 'temporary-password-1', newPassword: 'my-own-secret-pass', confirmPassword: 'my-own-secret-pass' }, officer.cookie)).status, 302);
  assert.equal((await fetch(base + '/staff', { redirect: 'manual', headers: { cookie: officer.cookie } })).status, 200, 'now allowed in');
  assert.equal((await fetch(base + '/staff/team', { headers: { cookie: officer.cookie } })).status, 403, 'officers cannot manage the team');

  const id = (await store.getStaffByEmail('s@firm.co.za')).id;
  await post(`/staff/team/${id}`, { _csrf: admin.csrf, action: 'deactivate' }, admin.cookie);
  const after = await fetch(base + '/staff', { redirect: 'manual', headers: { cookie: officer.cookie } });
  assert.equal(after.headers.get('location'), '/staff/login', 'session ended');
  assert.equal((await post('/staff/login', { email: 's@firm.co.za', password: 'my-own-secret-pass' })).status, 401, 'cannot log in');

  await post(`/staff/team/${id}`, { _csrf: admin.csrf, action: 'activate' }, admin.cookie);
  await post(`/staff/team/${id}`, { _csrf: admin.csrf, action: 'resetMfa' }, admin.cookie);
  const again = await login('s@firm.co.za', 'my-own-secret-pass');
  assert.ok(again.cookie);
  assert.notEqual(again.secret, officer.secret, 'new authenticator secret after reset');
});
