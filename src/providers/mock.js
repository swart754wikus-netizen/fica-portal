import { parseSaId } from '../validation/saId.js';

/**
 * Deterministic test provider — NEVER use in production.
 * Surname triggers:  "Sanctioned" → sanctions hit, "Politician" → PEP hit, "Headline" → adverse media.
 */
export class MockProvider {
  async screen(p) {
    const surname = (p.lastName || '').toLowerCase();
    const id = p.idType === 'sa_id' ? parseSaId(p.idNumber) : { valid: Boolean(p.idNumber) };
    return {
      provider: 'mock',
      checkedAt: new Date().toISOString(),
      reference: `MOCK-${Date.now()}`,
      identity: { verified: id.valid, detail: id.valid ? 'Mock: format valid' : id.error || 'Mock: no ID' },
      address: { verified: Boolean(p.hasProofOfAddress), detail: p.hasProofOfAddress ? 'Mock: document supplied' : 'No proof of address' },
      sanctions: { match: surname === 'sanctioned', detail: surname === 'sanctioned' ? 'Mock: UN consolidated list' : undefined },
      pep: { match: surname === 'politician', detail: surname === 'politician' ? 'Mock: domestic PEP' : undefined },
      adverseMedia: { match: surname === 'headline', detail: surname === 'headline' ? 'Mock: fraud allegation' : undefined },
    };
  }
}
