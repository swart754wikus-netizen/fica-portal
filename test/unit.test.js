import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseSaId } from '../src/validation/saId.js';
import { encrypt, decrypt, hashPassword, verifyPassword } from '../src/security/crypto.js';
import { totp, verifyTotp, generateSecret } from '../src/security/totp.js';
import { assessRisk } from '../src/risk/engine.js';
import { sqliteStore } from '../src/store/sqlite.js';
import { audit, verifyAuditChain } from '../src/audit.js';
import { sniffMime } from '../src/routes/client.js';
import { makeSaId, testKey } from './helpers.js';

const rmcp = JSON.parse(readFileSync(new URL('../config/rmcp.json', import.meta.url)));
const clean = {
  identity: { verified: true }, address: { verified: true },
  sanctions: { match: false }, pep: { match: false }, adverseMedia: { match: false },
};

test('SA ID: valid number parsed', () => {
  const r = parseSaId(makeSaId('800101500908'));
  assert.equal(r.valid, true);
  assert.equal(r.dateOfBirth, '1980-01-01');
  assert.equal(r.gender, 'M');
  assert.equal(r.citizen, true);
});

test('SA ID: rejects bad checksum, date, length, citizenship', () => {
  const good = makeSaId('800101500908');
  const bad = good.slice(0, 12) + ((Number(good[12]) + 1) % 10);
  assert.equal(parseSaId(bad).valid, false);
  assert.equal(parseSaId(makeSaId('800231500908')).valid, false); // 31 Feb
  assert.equal(parseSaId('123').valid, false);
  assert.equal(parseSaId(makeSaId('800101500928')).valid, false); // citizenship 2
});

test('AES-GCM round trip, AAD binding and tamper detection', () => {
  const ct = encrypt('secret PII', testKey, 'case-1');
  assert.equal(decrypt(ct, testKey, 'case-1').toString(), 'secret PII');
  assert.throws(() => decrypt(ct, testKey, 'case-2'));
  ct[ct.length - 1] ^= 1;
  assert.throws(() => decrypt(ct, testKey, 'case-1'));
});

test('password hashing', () => {
  const h = hashPassword('correct horse battery');
  assert.ok(verifyPassword('correct horse battery', h));
  assert.ok(!verifyPassword('wrong', h));
});

test('TOTP matches RFC 6238 test vector', () => {
  // RFC 6238 SHA-1 secret "12345678901234567890" in base32; T=59s → 94287082 (8 digits) → 287082 (6)
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(totp(secret, 59_000), '287082');
  const s = generateSecret();
  assert.ok(verifyTotp(s, totp(s)));
  assert.ok(!verifyTotp(s, '000000') || totp(s) === '000000');
});

test('risk engine: clean salaried SA client is low risk / SDD', () => {
  const r = assessRisk({ nationality: 'ZA', countryOfResidence: 'ZA', sourceOfFunds: 'salary', occupation: 'teacher', expectedValueZar: 50000 }, clean, rmcp);
  assert.equal(r.level, 'low');
  assert.equal(r.ddLevel, 'SDD');
});

test('risk engine: PEP escalates, sanctions always high', () => {
  const base = { nationality: 'ZA', countryOfResidence: 'ZA', sourceOfFunds: 'business_income', occupation: 'x', expectedValueZar: 2_000_000 };
  assert.equal(assessRisk({ ...base, pepDeclared: true }, clean, rmcp).level, 'high');
  const s = assessRisk(base, { ...clean, sanctions: { match: true } }, { ...rmcp, weights: { ...rmcp.weights, sanctionsMatch: 0 } });
  assert.equal(s.level, 'high');
  assert.ok(s.requiresCompliance);
});

test('audit chain detects tampering', async () => {
  const store = sqliteStore(':memory:');
  const db = store.raw;
  await audit(store, { actor: 'a', action: 'x' });
  await audit(store, { actor: 'b', action: 'y' });
  assert.deepEqual(await verifyAuditChain(store), { ok: true });
  assert.throws(() => db.exec("UPDATE audit_log SET actor = 'evil'"), /append-only/);
  db.exec('DROP TRIGGER audit_no_update');
  db.exec("UPDATE audit_log SET actor = 'evil' WHERE id = 1");
  assert.equal((await verifyAuditChain(store)).ok, false);
});

test('file sniffing ignores extension/claimed MIME', () => {
  assert.equal(sniffMime(Buffer.from('%PDF-1.7 ...')), 'application/pdf');
  assert.equal(sniffMime(Buffer.from([0xff, 0xd8, 0xff, 0xe0])), 'image/jpeg');
  assert.equal(sniffMime(Buffer.from('<script>alert(1)</script>')), null);
  assert.equal(sniffMime(Buffer.from('MZ\x90\x00')), null); // Windows executable
});
