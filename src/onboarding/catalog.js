// What a chartered accounting firm asks for, per client type. One source of truth for the
// client form, validation, risk scoring, staff case view and KYC report.

export const CLIENT_TYPES = {
  individual: { label: 'Individual', hint: 'A person in their own name (incl. sole proprietors)' },
  company: { label: 'Company or close corporation', hint: '(Pty) Ltd, CC, public company, NPC or foreign company' },
  trust: { label: 'Trust', hint: 'Inter vivos (family) or testamentary trust' },
  partnership: { label: 'Partnership', hint: 'Two or more partners trading together' },
};

export const ENTITY_SUBTYPES = {
  company: { pty: 'Private company (Pty) Ltd', cc: 'Close corporation (CC)', public: 'Public company (Ltd)', npc: 'Non-profit company (NPC)', foreign: 'Foreign / external company' },
  trust: { inter_vivos: 'Inter vivos (family) trust', testamentary: 'Testamentary trust', foreign: 'Foreign trust' },
  partnership: { general: 'Partnership' },
};

// Trust & company service provider (TCSP) work carries the highest FICA risk for accountants.
export const SERVICES = {
  tax: 'Income tax returns / SARS',
  vat_payroll: 'VAT, PAYE & payroll',
  bookkeeping: 'Bookkeeping & management accounts',
  afs: 'Annual financial statements / compilation',
  audit: 'Audit or independent review',
  company_registration: 'Company or CC registration (CIPC)',
  company_secretarial: 'Company secretarial / CIPC annual returns',
  trust_services: 'Trust registration or administration',
  nominee: 'Acting as director, trustee or nominee shareholder',
  registered_address: 'Providing a registered / business address',
};

// Who must be identified behind each entity type (beneficial ownership).
export const ROLES = {
  company: { director: 'Director / member', shareholder: 'Shareholder (25% or more)', controller: 'Controls the company in another way', signatory: 'Authorised signatory' },
  trust: { trustee: 'Trustee', founder: 'Founder / donor', beneficiary: 'Named beneficiary', controller: 'Other person with control', signatory: 'Authorised signatory' },
  partnership: { partner: 'Partner', controller: 'Controls the partnership in another way', signatory: 'Authorised signatory' },
};

export const RELATED_HELP = {
  company: 'List every director or member, every shareholder with 25% or more, and anyone who ultimately controls the company. If a shareholder is itself a company or trust, tick the box — we will ask about the people behind it.',
  trust: 'List every trustee, the founder (donor), every named beneficiary, and anyone else who controls the trust.',
  partnership: 'List every partner and anyone else who controls the partnership.',
};

/** Upload fields. `multiple` fields accept up to 10 files. */
export const DOCUMENTS = {
  idDocument: { label: 'Your identity document (ID card both sides, ID book or passport)' },
  proofOfAddress: { label: 'Your proof of residential address (not older than 3 months)' },
  cipcCertificate: { label: 'CIPC registration certificate (CoR14.3 / CK1)' },
  shareRegister: { label: 'Share register or shareholding structure' },
  letterOfAuthority: { label: "Master's letter of authority (all current trustees)" },
  trustDeed: { label: 'Trust deed and any amendments' },
  partnershipAgreement: { label: 'Partnership agreement' },
  businessAddressProof: { label: 'Proof of business / registered address (not older than 3 months)' },
  authorityResolution: { label: 'Resolution or letter authorising you to act for the entity' },
  relatedIds: { label: 'ID documents of the people listed above', multiple: true },
};

export const REQUIRED_DOCUMENTS = {
  individual: { required: ['idDocument', 'proofOfAddress'], optional: [] },
  company: { required: ['idDocument', 'proofOfAddress', 'cipcCertificate', 'businessAddressProof', 'authorityResolution', 'relatedIds'], optional: ['shareRegister'] },
  trust: { required: ['idDocument', 'proofOfAddress', 'letterOfAuthority', 'trustDeed', 'authorityResolution', 'relatedIds'], optional: [] },
  partnership: { required: ['idDocument', 'proofOfAddress', 'partnershipAgreement', 'authorityResolution', 'relatedIds'], optional: ['businessAddressProof'] },
};

export const DOC_LABELS = {
  ...Object.fromEntries(Object.entries(DOCUMENTS).map(([k, v]) => [k, v.label])),
  idDocument: 'Identity document (person completing the form)',
  proofOfAddress: 'Proof of residential address (person completing the form)',
};
export const MAX_RELATED = 15;
