import crypto from 'node:crypto';
import { luhnValid } from '../src/validation/saId.js';

export const testKey = crypto.randomBytes(32);

/** Build a valid SA ID number from a 12-digit prefix by appending the Luhn check digit. */
export function makeSaId(prefix12) {
  for (let d = 0; d <= 9; d++) if (luhnValid(prefix12 + d)) return prefix12 + d;
}
