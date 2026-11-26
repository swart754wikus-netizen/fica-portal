// Regression: updating a session that was deleted (double-submitted MFA form) must not throw.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { firestoreStore } from '../src/store/firestore.js';

process.env.FIRESTORE_EMULATOR_HOST ||= '127.0.0.1:8086';
process.env.FIREBASE_STORAGE_EMULATOR_HOST ||= '127.0.0.1:9198';

test('updateSession on a deleted session is a no-op, not a crash', async () => {
  const store = firestoreStore({ projectId: 'demo-fica-portal', storageBucket: 'demo-fica-portal.appspot.com' });
  await store.createSession({ token_hash: 'gone', staff_id: '1', csrf: 'x', mfa_ok: false, expires_at: Date.now() + 60_000 });
  await store.deleteSession('gone');
  await assert.doesNotReject(store.updateSession('gone', { expires_at: Date.now() }));
  assert.equal(await store.getSession('gone'), null);
});
