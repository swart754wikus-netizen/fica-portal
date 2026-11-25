// Usage: npm run create-staff -- email@firm.co.za "Full Name" officer|compliance
import { createInterface } from 'node:readline/promises';
import { config } from '../src/config.js';
import { openDb } from '../src/db.js';
import { hashPassword, encrypt } from '../src/security/crypto.js';
import { generateSecret, otpauthUri } from '../src/security/totp.js';

const [email, name, role = 'officer'] = process.argv.slice(2);
if (!email || !name || !['officer', 'compliance'].includes(role)) {
  console.error('Usage: npm run create-staff -- <email> "<name>" <officer|compliance>');
  process.exit(1);
}
const rl = createInterface({ input: process.stdin, output: process.stdout });
const password = await rl.question('Password (min 12 chars): ');
rl.close();
if (password.length < 12) { console.error('Password too short'); process.exit(1); }

const db = openDb(config.dbPath);
const secret = generateSecret();
const { lastInsertRowid: id } = db.prepare(
  'INSERT INTO staff (email, name, role, password_hash, totp_secret_enc, created_at) VALUES (?, ?, ?, ?, ?, ?)',
).run(email.toLowerCase(), name, role, hashPassword(password), Buffer.alloc(0), Date.now());
db.prepare('UPDATE staff SET totp_secret_enc = ? WHERE id = ?').run(encrypt(secret, config.dataKey, `totp:${id}`), id);

console.log(`\nCreated ${role} ${email}.\nAdd this to an authenticator app:\n  Secret: ${secret}\n  URI:    ${otpauthUri(secret, email)}\n`);
