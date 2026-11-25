// Production store: Firestore for records, Firebase Storage for encrypted documents.
// Everything sensitive is already AES-256-GCM encrypted by the app before it reaches
// Google (case data_enc, document blobs, TOTP secrets), on top of Google's own encryption.
// Browsers never talk to Firestore directly — firestore.rules / storage.rules deny all.
import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { getStorage } from 'firebase-admin/storage';
import { chainHash, GENESIS } from './auditChain.js';

const toBuf = (v) => (v == null ? v : Buffer.isBuffer(v) ? v : Buffer.from(v));
const withId = (snap) => (snap.exists ? { id: snap.id, ...snap.data() } : null);
const normaliseStaff = (s) => s && { ...s, totp_secret_enc: s.totp_secret_enc ? toBuf(s.totp_secret_enc) : null, pending_totp_enc: toBuf(s.pending_totp_enc), active: s.active !== false };

export function firestoreStore({ projectId, clientEmail, privateKey, storageBucket }) {
  const app = getApps()[0] || initializeApp({
    // In the emulator (FIRESTORE_EMULATOR_HOST set) no credentials are needed.
    ...(privateKey ? { credential: cert({ projectId, clientEmail, privateKey: privateKey.replace(/\\n/g, '\n') }) } : {}),
    projectId,
    storageBucket,
  });
  const db = getFirestore(app);
  const bucket = getStorage(app).bucket();
  const col = (n) => db.collection(n);
  const AUDIT_HEAD = col('meta').doc('auditHead');
  let corsDone = false;

  return {
    kind: 'firestore',
    supportsDirectUpload: true,

    // ---- staff ----
    async countStaff() { return (await col('staff').count().get()).data().count; },
    async getStaffByEmail(email) {
      const q = await col('staff').where('email', '==', email).limit(1).get();
      return q.empty ? null : normaliseStaff(withId(q.docs[0]));
    },
    async getStaffById(id) { return normaliseStaff(withId(await col('staff').doc(String(id)).get())); },
    async listStaff() { return (await col('staff').orderBy('name').get()).docs.map((d) => normaliseStaff(withId(d))); },
    async createStaff(row) {
      // Email uniqueness: a marker doc keyed by email, created in the same transaction.
      const ref = col('staff').doc();
      await db.runTransaction(async (tx) => {
        const marker = col('staffEmails').doc(row.email);
        if ((await tx.get(marker)).exists) throw Object.assign(new Error('An account with this email already exists'), { code: 'duplicate' });
        tx.create(marker, { staffId: ref.id });
        tx.create(ref, { totp_secret_enc: null, failed_logins: 0, locked_until: null, active: true, totp_last_counter: 0, ...row });
      });
      return ref.id;
    },
    async updateStaff(id, patch) { await col('staff').doc(String(id)).update(patch); },

    // ---- sessions (doc ID = SHA-256 of the cookie token) ----
    async createSession(row) { await col('sessions').doc(row.token_hash).set({ mfa_attempts: 0, ...row, mfa_ok: row.mfa_ok ? 1 : 0 }); },
    async getSession(hash) { return withId(await col('sessions').doc(hash).get()); },
    async updateSession(hash, patch) { await col('sessions').doc(hash).update(patch); },
    async deleteSession(hash) { await col('sessions').doc(hash).delete(); },

    // ---- cases ----
    async createCase(row) { await col('cases').doc(row.id).create(row); },
    async getCase(id) { const c = withId(await col('cases').doc(String(id)).get()); return c && { ...c, data_enc: toBuf(c.data_enc) }; },
    async getCaseByInviteHash(hash) {
      const q = await col('cases').where('invite_token_hash', '==', hash).limit(1).get();
      return q.empty ? null : withId(q.docs[0]);
    },
    async findCaseByBlindIndex(idx, excludeId) {
      const q = await col('cases').where('id_blind_index', '==', idx).limit(5).get();
      const hit = q.docs.find((d) => d.id !== excludeId);
      return hit ? { id: hit.id, reference: hit.data().reference } : null;
    },
    async updateCase(id, patch) { await col('cases').doc(String(id)).update(patch); },
    async listCases({ status, limit = 200 } = {}) {
      // Filter in memory rather than needing a composite (status + created_at) index.
      const q = await col('cases').orderBy('created_at', 'desc').limit(status ? 1000 : limit).get();
      return q.docs.map(withId).filter((c) => !status || c.status === status).slice(0, limit);
    },
    async countCasesByStatus() {
      const out = {};
      await Promise.all(['invited', 'submitted', 'approved', 'rejected'].map(async (s) => {
        out[s] = (await col('cases').where('status', '==', s).count().get()).data().count;
      }));
      return out;
    },
    async submitCase(id, patch, docs) {
      // Blobs first (encrypted), then case + metadata in one batch. A failure leaves at most
      // orphaned ciphertext in Storage, never a submitted case pointing at missing files.
      await Promise.all(docs.map((d) => bucket.file(`documents/${id}/${d.id}`).save(d.blob_enc, { resumable: false, contentType: 'application/octet-stream' })));
      const batch = db.batch();
      batch.update(col('cases').doc(id), patch);
      for (const { blob_enc, ...meta } of docs) batch.create(col('documents').doc(meta.id), { ...meta, case_id: id });
      await batch.commit();
    },

    // ---- documents ----
    async listDocuments(caseId) { return (await col('documents').where('case_id', '==', caseId).get()).docs.map(withId); },
    async getDocument(caseId, docId) { const d = withId(await col('documents').doc(String(docId)).get()); return d && d.case_id === caseId ? d : null; },
    async getDocumentBlob(doc) { const [buf] = await bucket.file(`documents/${doc.case_id}/${doc.id}`).download(); return buf; },

    // ---- direct browser uploads (bypass Vercel's ~4.5 MB request limit) ----
    /** Let browsers on the portal's own origin PUT to signed URLs (bucket CORS). Runs once per instance. */
    async ensureUploadCors(origin) {
      if (corsDone) return;
      const [meta] = await bucket.getMetadata();
      const ok = (meta.cors || []).some((c) => c.origin?.includes(origin) && c.method?.includes('PUT'));
      if (!ok) {
        await bucket.setCorsConfiguration([...(meta.cors || []), {
          origin: [origin], method: ['PUT'], maxAgeSeconds: 3600,
          responseHeader: ['Content-Type', 'x-goog-content-length-range'],
        }]);
      }
      corsDone = true;
    },
    async createUploadUrl(caseId, uploadId, contentType, maxBytes) {
      const [url] = await bucket.file(`uploads/${caseId}/${uploadId}`).getSignedUrl({
        version: 'v4', action: 'write', expires: Date.now() + 15 * 60_000, contentType,
        extensionHeaders: { 'x-goog-content-length-range': `0,${maxBytes}` },
      });
      return { url, headers: { 'Content-Type': contentType, 'x-goog-content-length-range': `0,${maxBytes}` } };
    },
    async readUpload(caseId, uploadId) {
      const file = bucket.file(`uploads/${caseId}/${uploadId}`);
      const [exists] = await file.exists();
      if (!exists) return null;
      const [buf] = await file.download();
      return buf;
    },
    async deleteUpload(caseId, uploadId) { await bucket.file(`uploads/${caseId}/${uploadId}`).delete().catch(() => {}); },

    // ---- audit (append-only, hash-chained; serialised through a head document) ----
    async appendAudit(e) {
      await db.runTransaction(async (tx) => {
        const head = (await tx.get(AUDIT_HEAD)).data() || { seq: 0, hash: GENESIS };
        const seq = head.seq + 1;
        const hash = chainHash(head.hash, e);
        tx.create(col('audit_log').doc(String(seq).padStart(12, '0')), { ...e, id: seq, prev_hash: head.hash, hash });
        tx.set(AUDIT_HEAD, { seq, hash });
      });
    },
    async listAudit({ caseId, limit = 300, newestFirst = false } = {}) {
      if (caseId) {
        const rows = (await col('audit_log').where('case_id', '==', caseId).get()).docs.map((d) => d.data()).sort((a, b) => a.id - b.id);
        return (newestFirst ? rows.reverse() : rows).slice(0, limit);
      }
      return (await col('audit_log').orderBy('id', newestFirst ? 'desc' : 'asc').limit(limit).get()).docs.map((d) => d.data());
    },
    async *iterateAudit() {
      let last = null;
      for (;;) {
        let q = col('audit_log').orderBy('id').limit(500);
        if (last !== null) q = q.startAfter(last);
        const page = await q.get();
        if (page.empty) return;
        for (const d of page.docs) yield d.data();
        last = page.docs.at(-1).data().id;
      }
    },

    // ---- rate limiting (fixed window, works across serverless instances) ----
    async rateHit(key, windowMs) {
      const ref = col('rate_limits').doc(key.replace(/[/]/g, '_').slice(0, 500));
      return db.runTransaction(async (tx) => {
        const now = Date.now();
        const cur = (await tx.get(ref)).data();
        const next = !cur || cur.reset < now ? { count: 1, reset: now + windowMs } : { count: cur.count + 1, reset: cur.reset };
        tx.set(ref, next);
        return next;
      });
    },
  };
}

export { FieldValue };
