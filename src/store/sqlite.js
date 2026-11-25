// Local / test store: one SQLite file (node:sqlite). Not for serverless hosting —
// Vercel has no persistent disk; production uses ./firestore.js.
import { openDb } from '../db.js';
import { chainHash, GENESIS } from './auditChain.js';

const pick = (obj, keys) => Object.fromEntries(keys.filter((k) => k in obj).map((k) => [k, obj[k]]));
const setClause = (patch) => Object.keys(patch).map((k) => `${k} = ?`).join(', ');
const vals = (patch) => Object.values(patch).map((v) => (typeof v === 'boolean' ? Number(v) : v));
const enrolled = (s) => s && (s.totp_secret_enc?.length > 0 ? s : { ...s, totp_secret_enc: null });

export function sqliteStore(path) {
  const db = openDb(path);
  return {
    kind: 'sqlite',
    supportsDirectUpload: false,
    raw: db,

    // ---- staff ----
    async countStaff() { return db.prepare('SELECT COUNT(*) n FROM staff').get().n; },
    async getStaffByEmail(email) { return enrolled(db.prepare('SELECT * FROM staff WHERE email = ?').get(email)); },
    async getStaffById(id) { return enrolled(db.prepare('SELECT * FROM staff WHERE id = ?').get(id)); },
    async listStaff() { return db.prepare('SELECT * FROM staff ORDER BY name').all().map(enrolled); },
    async createStaff(row) {
      const r = { totp_secret_enc: Buffer.alloc(0), ...row, active: row.active === false ? 0 : 1 };
      const keys = Object.keys(r);
      return String(db.prepare(`INSERT INTO staff (${keys.join(',')}) VALUES (${keys.map(() => '?').join(',')})`).run(...vals(r)).lastInsertRowid);
    },
    async updateStaff(id, patch) {
      const p = { ...patch };
      if ('totp_secret_enc' in p && p.totp_secret_enc === null) p.totp_secret_enc = Buffer.alloc(0); // NOT NULL column
      db.prepare(`UPDATE staff SET ${setClause(p)} WHERE id = ?`).run(...vals(p), id);
    },

    // ---- sessions ----
    async createSession(row) {
      db.prepare('INSERT INTO sessions (token_hash, staff_id, csrf, mfa_ok, expires_at) VALUES (?, ?, ?, ?, ?)')
        .run(row.token_hash, row.staff_id, row.csrf, row.mfa_ok ? 1 : 0, row.expires_at);
    },
    async getSession(hash) { return db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(hash) || null; },
    async updateSession(hash, patch) { db.prepare(`UPDATE sessions SET ${setClause(patch)} WHERE token_hash = ?`).run(...vals(patch), hash); },
    async deleteSession(hash) { db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash); },

    // ---- cases ----
    async createCase(row) {
      const keys = Object.keys(row);
      db.prepare(`INSERT INTO cases (${keys.join(',')}) VALUES (${keys.map(() => '?').join(',')})`).run(...vals(row));
    },
    async getCase(id) { return db.prepare('SELECT * FROM cases WHERE id = ?').get(id) || null; },
    async getCaseByInviteHash(hash) { return db.prepare('SELECT * FROM cases WHERE invite_token_hash = ?').get(hash) || null; },
    async findCaseByBlindIndex(idx, excludeId) { return db.prepare('SELECT id, reference FROM cases WHERE id_blind_index = ? AND id != ?').get(idx, excludeId) || null; },
    async updateCase(id, patch) { db.prepare(`UPDATE cases SET ${setClause(patch)} WHERE id = ?`).run(...vals(patch), id); },
    async listCases({ status, limit = 200 } = {}) {
      return db.prepare(`SELECT * FROM cases ${status ? 'WHERE status = ?' : ''} ORDER BY created_at DESC LIMIT ?`).all(...(status ? [status, limit] : [limit]));
    },
    async countCasesByStatus() {
      return Object.fromEntries(db.prepare('SELECT status, COUNT(*) n FROM cases GROUP BY status').all().map((r) => [r.status, r.n]));
    },
    /** Saves encrypted documents and the submitted case atomically. */
    async submitCase(id, patch, docs) {
      db.exec('BEGIN');
      try {
        db.prepare(`UPDATE cases SET ${setClause(patch)} WHERE id = ?`).run(...vals(patch), id);
        for (const d of docs) {
          db.prepare('INSERT INTO documents (id, case_id, kind, mime, size, sha256, blob_enc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
            .run(d.id, id, d.kind, d.mime, d.size, d.sha256, d.blob_enc, d.created_at);
        }
        db.exec('COMMIT');
      } catch (e) { db.exec('ROLLBACK'); throw e; }
    },

    // ---- documents ----
    async listDocuments(caseId) { return db.prepare('SELECT id, case_id, kind, mime, size, sha256, created_at FROM documents WHERE case_id = ?').all(caseId); },
    async getDocument(caseId, docId) { return db.prepare('SELECT id, case_id, kind, mime, size, sha256, created_at FROM documents WHERE id = ? AND case_id = ?').get(docId, caseId) || null; },
    async getDocumentBlob(doc) { return db.prepare('SELECT blob_enc FROM documents WHERE id = ?').get(doc.id).blob_enc; },

    async readUpload() { return null; },
    async deleteUpload() {},

    // ---- audit (append-only, hash-chained) ----
    async appendAudit(e) {
      const last = db.prepare('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1').get();
      const prev = last?.hash ?? GENESIS;
      const hash = chainHash(prev, e);
      db.prepare('INSERT INTO audit_log (ts, actor, action, case_id, ip, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(e.ts, e.actor, e.action, e.case_id, e.ip, e.detail, prev, hash);
    },
    async listAudit({ caseId, limit = 300, newestFirst = false } = {}) {
      const order = newestFirst ? 'DESC' : 'ASC';
      return caseId
        ? db.prepare(`SELECT * FROM audit_log WHERE case_id = ? ORDER BY id ${order} LIMIT ?`).all(caseId, limit)
        : db.prepare(`SELECT * FROM audit_log ORDER BY id ${order} LIMIT ?`).all(limit);
    },
    async *iterateAudit() { for (const row of db.prepare('SELECT * FROM audit_log ORDER BY id').iterate()) yield row; },

    // ---- rate limiting (fixed window) ----
    async rateHit(key, windowMs) {
      const now = Date.now();
      const row = db.prepare('SELECT * FROM rate_limits WHERE key = ?').get(key);
      if (!row || row.reset < now) {
        db.prepare('INSERT OR REPLACE INTO rate_limits (key, count, reset) VALUES (?, 1, ?)').run(key, now + windowMs);
        return { count: 1, reset: now + windowMs };
      }
      db.prepare('UPDATE rate_limits SET count = count + 1 WHERE key = ?').run(key);
      return { count: row.count + 1, reset: row.reset };
    },
  };
}

export { pick };
