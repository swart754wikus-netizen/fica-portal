import crypto from 'node:crypto';

export const GENESIS = '0'.repeat(64);
export const chainHash = (prev, e) =>
  crypto.createHash('sha256').update(prev + JSON.stringify([e.ts, e.actor, e.action, e.case_id, e.ip, e.detail])).digest('hex');
