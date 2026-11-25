import { chainHash, GENESIS } from './store/auditChain.js';

/** Append to the tamper-evident audit trail. Never throws into the request: a failed
 *  audit write is logged loudly instead (the action itself already happened). */
export async function audit(store, { actor, action, caseId = null, ip = null, detail = null }) {
  try {
    await store.appendAudit({ ts: Date.now(), actor, action, case_id: caseId, ip, detail: detail ? JSON.stringify(detail) : null });
  } catch (err) {
    console.error('AUDIT WRITE FAILED', action, err.message);
  }
}

/** Returns { ok: true } or { ok: false, brokenAt: id } */
export async function verifyAuditChain(store) {
  let prev = GENESIS;
  for await (const row of store.iterateAudit()) {
    if (row.prev_hash !== prev || chainHash(prev, row) !== row.hash) return { ok: false, brokenAt: row.id };
    prev = row.hash;
  }
  return { ok: true };
}
