// Optional: create a staff account from the command line (the browser alternative is
// /staff/setup for the first account, then Team → Add staff member).
// Usage: npm run create-staff -- email@firm.co.za "Full Name" officer|compliance
// They set up two-step verification on first login.
import { createInterface } from 'node:readline/promises';
import { config } from '../src/config.js';
import { createStore } from '../src/store/index.js';
import { hashPassword } from '../src/security/crypto.js';

const [email, name, role = 'officer'] = process.argv.slice(2);
if (!email || !name || !['officer', 'compliance'].includes(role)) {
  console.error('Usage: npm run create-staff -- <email> "<name>" <officer|compliance>');
  process.exit(1);
}
const rl = createInterface({ input: process.stdin, output: process.stdout });
const password = await rl.question('Password (min 12 chars): ');
rl.close();
if (password.length < 12) { console.error('Password too short'); process.exit(1); }

const store = await createStore(config);
await store.createStaff({ email: email.toLowerCase(), name, role, password_hash: hashPassword(password), created_at: Date.now() });
console.log(`\nCreated ${role} ${email} (${store.kind}). They set up two-step verification at first login.\n`);
process.exit(0);
