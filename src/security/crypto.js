import crypto from 'node:crypto';

const VERSION = 1; // key version prefix allows future key rotation

/** AES-256-GCM encrypt. Output: [ver(1) | iv(12) | tag(16) | ciphertext] */
export function encrypt(plain, key, aad = '') {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(Buffer.from(aad));
  const data = Buffer.isBuffer(plain) ? plain : Buffer.from(plain, 'utf8');
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([Buffer.from([VERSION]), iv, cipher.getAuthTag(), ct]);
}

export function decrypt(blob, key, aad = '') {
  const buf = Buffer.from(blob);
  if (buf[0] !== VERSION) throw new Error('Unknown ciphertext version');
  const iv = buf.subarray(1, 13);
  const tag = buf.subarray(13, 29);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  if (aad) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(buf.subarray(29)), decipher.final()]);
}

export const encryptJson = (obj, key, aad) => encrypt(JSON.stringify(obj), key, aad);
export const decryptJson = (blob, key, aad) => JSON.parse(decrypt(blob, key, aad).toString('utf8'));

export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

/** Keyed hash for lookups/dedup of identifiers (e.g. ID numbers) without storing them in clear. */
export const blindIndex = (value, key) =>
  crypto.createHmac('sha256', key).update(String(value)).digest('hex');

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), hash.toString('base64')].join('$');
}

export function verifyPassword(password, stored) {
  const [alg, N, r, p, salt, hash] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const expected = Buffer.from(hash, 'base64');
  const actual = crypto.scryptSync(password, Buffer.from(salt, 'base64'), expected.length, {
    N: Number(N), r: Number(r), p: Number(p),
  });
  return crypto.timingSafeEqual(expected, actual);
}

export function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
