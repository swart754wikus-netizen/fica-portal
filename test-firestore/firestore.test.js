// Full staff + client flow on the Firestore/Storage store, against the emulators.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { firestoreStore } from '../src/store/firestore.js';
import { createApp } from '../src/app.js';
import { MockProvider } from '../src/providers/mock.js';
import { totp } from '../src/security/totp.js';
import { verifyAuditChain } from '../src/audit.js';
import { makeSaId } from '../test/helpers.js';

process.env.FIRESTORE_EMULATOR_HOST ||= '127.0.0.1:8086';
process.env.FIREBASE_STORAGE_EMULATOR_HOST ||= '127.0.0.1:9198';
const dataKey = crypto.randomBytes(32);
const config = { firmName: 'Test CA', baseUrl: 'http://x', isProd: false, dataKey, inviteTtlHours: 72, sessionTtlMinutes: 30, maxUploadBytes: 10e6, retentionYears: 5, setupToken: 'code-xyz' };
let server, base, store;
const sent = [];
const mailer = { delivers: true, async send(m) { sent.push(m); } };

before(async () => {
  store = firestoreStore({ projectId: 'demo-fica-portal', storageBucket: 'demo-fica-portal.appspot.com' });
  server = createApp({ store, config, provider: new MockProvider(), mailer }).listen(0);
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const cookieOf = (res) => res.headers.get('set-cookie')?.split(';')[0];
const csrfOf = (html) => html.match(/name="_csrf" value="([^"]+)"/)?.[1];
const post = (path, body, cookie) => fetch(base + path, { method: 'POST', redirect: 'manual', headers: cookie ? { cookie } : {}, body: body instanceof FormData ? body : new URLSearchParams(body) });
let admin;

test('setup → enrol → dashboard on Firestore', async () => {
  assert.equal((await post('/staff/setup', { token: 'code-xyz', name: 'Naledi', email: 'n@firm.co.za', password: 'a-very-long-password' })).status, 302);
  const l = await post('/staff/login', { email: 'n@firm.co.za', password: 'a-very-long-password' });
  let cookie = cookieOf(l);
  const page = await (await fetch(base + '/staff/mfa', { headers: { cookie } })).text();
  const secret = page.match(/class="setup-key">([A-Z2-7 ]+)</)[1].replace(/\s/g, '');
  const v = await post('/staff/mfa', { _csrf: csrfOf(page), code: totp(secret) }, cookie);
  assert.equal(v.status, 302);
  cookie = cookieOf(v);
  const dash = await (await fetch(base + '/staff', { headers: { cookie } })).text();
  assert.match(dash, /Onboarding cases/);
  admin = { cookie, csrf: csrfOf(dash) };
});

test('company onboarding with multipart and direct (pre-uploaded) files, encrypted in Storage', async () => {
  await post('/staff/cases', { _csrf: admin.csrf, name: 'Bokamoso Holdings', email: 'c@client.co.za' }, admin.cookie);
  const path = sent.at(-1).text.match(/http:\/\/x(\/onboard\/\S+)/)[1];
  assert.equal((await fetch(base + path)).status, 200);

  // Simulate the browser's direct upload: the object lands in uploads/{caseId}/{uploadId}.
  const c0 = (await store.listCases({ limit: 5 })).find((c) => c.client_name === 'Bokamoso Holdings');
  const uploadId = crypto.randomUUID();
  const { getStorage } = await import('firebase-admin/storage');
  await getStorage().bucket().file(`uploads/${c0.id}/${uploadId}`).save(Buffer.from('%PDF-1.4 big scanned cipc certificate'));

  const fd = new FormData();
  const fields = { clientType: 'company', services: 'company_secretarial', firstName: 'Sipho', lastName: 'Rep', idType: 'sa_id', idNumber: makeSaId('850101500908'),
    nationality: 'ZA', countryOfResidence: 'ZA', addressLine1: '1 Main Rd', city: 'Cape Town', postalCode: '8001', occupation: 'Director', sourceOfFunds: 'business_income',
    purpose: 'Secretarial services', pepDeclared: 'no', consent: 'on', declaration: 'on', entityName: 'Bokamoso Holdings (Pty) Ltd', entitySubtype: 'pty',
    entityRegNumber: '2019/123456/07', entityAddress: '10 Long St', natureOfBusiness: 'Investments', cashIntensive: 'no', capacity: 'Director' };
  for (const [k, v] of Object.entries(fields)) fd.append(k, v);
  fd.append('related[0][name]', 'Bad Sanctioned'); fd.append('related[0][idNumber]', 'P123'); fd.append('related[0][role]', 'shareholder'); fd.append('related[0][nationality]', 'GB');
  fd.append('uploaded[cipcCertificate][]', uploadId);
  for (const f of ['idDocument', 'proofOfAddress', 'businessAddressProof', 'authorityResolution', 'relatedIds']) fd.append(f, new Blob([`%PDF-1.4 ${f}`], { type: 'application/pdf' }), `${f}.pdf`);
  const res = await post(path, fd);
  assert.equal(res.status, 200, (await res.text()).match(/field-error[^<]*/g)?.join(' '));

  const c = await store.getCase(c0.id);
  assert.equal(c.status, 'submitted');
  assert.equal(c.risk_level, 'high', 'sanctioned shareholder');
  assert.ok(!c.data_enc.toString('latin1').includes('Bokamoso'), 'case data encrypted at rest');
  const docs = await store.listDocuments(c.id);
  assert.equal(docs.length, 6);
  const cipc = docs.find((d) => d.kind === 'cipcCertificate');
  const raw = await store.getDocumentBlob(cipc);
  assert.ok(!raw.toString('latin1').includes('%PDF'), 'document encrypted in Storage');
  assert.equal(await store.readUpload(c.id, uploadId), null, 'plain upload removed after encryption');

  const dl = await fetch(`${base}/staff/cases/${c.id}/documents/${cipc.id}`, { headers: { cookie: admin.cookie } });
  assert.equal(await dl.text(), '%PDF-1.4 big scanned cipc certificate');
  const page = await (await fetch(`${base}/staff/cases/${c.id}`, { headers: { cookie: admin.cookie } })).text();
  assert.match(page, /Bad Sanctioned/);
  assert.equal((await fetch(base + path)).status, 404, 'invite single-use');

  const dec = await post(`/staff/cases/${c.id}/decision`, { _csrf: admin.csrf, decision: 'rejected', reason: 'Sanctions match on shareholder; reported to FIC.' }, admin.cookie);
  assert.equal(dec.status, 302);
  assert.equal((await store.getCase(c.id)).status, 'rejected');
});

test('audit chain intact and rate limiting shared via Firestore', async () => {
  assert.deepEqual(await verifyAuditChain(store), { ok: true });
  const html = await (await fetch(base + '/staff/audit', { headers: { cookie: admin.cookie } })).text();
  assert.match(html, /Hash chain intact/);
  let last;
  for (let i = 0; i < 22; i++) last = await post('/staff/login', { email: 'nobody@x.co', password: 'x' });
  assert.equal(last.status, 429);
});
