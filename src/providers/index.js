import { MockProvider } from './mock.js';

/**
 * Screening provider contract. Each bureau (VerifyNow, XDS, LexisNexis, Smile ID, eFICA, ...)
 * gets an adapter implementing:
 *
 *   async screen(person) -> {
 *     identity:     { verified: boolean, detail?: string },   // DHA / NPR check
 *     address:      { verified: boolean, detail?: string },
 *     sanctions:    { match: boolean, detail?: string },       // UN, OFAC, EU, UK + TFS list (FIC)
 *     pep:          { match: boolean, detail?: string },       // domestic & foreign PEPs (DPIP/FPPO)
 *     adverseMedia: { match: boolean, detail?: string },
 *     provider: string, checkedAt: string, reference?: string
 *   }
 */
export function getProvider(name) {
  switch (name) {
    case 'mock': return new MockProvider();
    default: throw new Error(`Unknown SCREENING_PROVIDER "${name}". Add an adapter in src/providers/.`);
  }
}
