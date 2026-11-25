import { sha256 } from './security/crypto.js';

const GENESIS = '0'.repeat(64);

function entryHash(prev, e) {
  return sha256(prev + JSON.stringify([e.ts, e.actor, e.action, e.case_id, e.ip, e.detail]));
}

export function audit(db, { actor, action, caseId = null, ip = null, detail = null }) {
  const last = db.prepare('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1').get();
  const prev = last?.hash ?? GENESIS;
  const e = { ts: Date.now(), actor, action, case_id: caseId, ip, detail: detail ? JSON.stringify(detail) : null };
  const hash = entryHash(prev, e);
  db.prepare(`INSERT INTO audit_log (ts, actor, action, case_id, ip, detail, prev_hash, hash)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(e.ts, e.actor, e.action, e.case_id, e.ip, e.detail, prev, hash);
}

/** Returns { ok: true } or { ok: false, brokenAt: id } */
export function verifyAuditChain(db) {
  let prev = GENESIS;
  for (const row of db.prepare('SELECT * FROM audit_log ORDER BY id').iterate()) {
    if (row.prev_hash !== prev || entryHash(prev, row) !== row.hash) return { ok: false, brokenAt: row.id };
    prev = row.hash;
  }
  return { ok: true };
}
