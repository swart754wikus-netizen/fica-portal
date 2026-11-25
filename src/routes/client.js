import { Router } from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import { sha256, encrypt, encryptJson, blindIndex } from '../security/crypto.js';
import { parseSaId } from '../validation/saId.js';
import { assessRisk } from '../risk/engine.js';
import { audit } from '../audit.js';

export const SOURCES_OF_FUNDS = ['salary', 'pension', 'business_income', 'investments', 'inheritance', 'sale_of_property', 'cryptocurrency', 'other'];

/** Identify file type from magic bytes — never trust the browser-supplied MIME type or extension. */
export function sniffMime(buf) {
  if (buf.subarray(0, 5).toString('latin1') === '%PDF-') return 'application/pdf';
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  return null;
}

const str = (v, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

export function validateSubmission(body, files) {
  const errors = {};
  const d = {
    firstName: str(body.firstName, 100),
    lastName: str(body.lastName, 100),
    idType: body.idType === 'passport' ? 'passport' : 'sa_id',
    idNumber: str(body.idNumber, 30).replace(/\s/g, ''),
    dateOfBirth: str(body.dateOfBirth, 10),
    nationality: str(body.nationality, 2).toUpperCase(),
    countryOfResidence: str(body.countryOfResidence, 2).toUpperCase(),
    phone: str(body.phone, 20),
    addressLine1: str(body.addressLine1),
    addressLine2: str(body.addressLine2),
    city: str(body.city, 100),
    province: str(body.province, 50),
    postalCode: str(body.postalCode, 10),
    occupation: str(body.occupation, 60),
    employer: str(body.employer, 150),
    sourceOfFunds: SOURCES_OF_FUNDS.includes(body.sourceOfFunds) ? body.sourceOfFunds : '',
    expectedValueZar: Number(String(body.expectedValueZar || '').replace(/[^\d.]/g, '')) || 0,
    purpose: str(body.purpose, 500),
    pepDeclared: body.pepDeclared === 'yes',
    pepDetails: str(body.pepDetails, 500),
  };

  for (const k of ['firstName', 'lastName', 'idNumber', 'addressLine1', 'city', 'postalCode', 'occupation', 'purpose']) {
    if (!d[k]) errors[k] = 'Required';
  }
  if (!d.sourceOfFunds) errors.sourceOfFunds = 'Select a source of funds';
  if (!/^[A-Z]{2}$/.test(d.nationality)) errors.nationality = 'Select a country';
  if (!/^[A-Z]{2}$/.test(d.countryOfResidence)) errors.countryOfResidence = 'Select a country';
  if (d.phone && !/^\+?[\d\s-]{9,20}$/.test(d.phone)) errors.phone = 'Enter a valid phone number';
  if (body.pepDeclared !== 'yes' && body.pepDeclared !== 'no') errors.pepDeclared = 'Please answer this question';
  if (d.pepDeclared && !d.pepDetails) errors.pepDetails = 'Please give details of the public position';

  if (d.idType === 'sa_id' && d.idNumber) {
    const parsed = parseSaId(d.idNumber);
    if (!parsed.valid) errors.idNumber = parsed.error;
    else d.dateOfBirth = parsed.dateOfBirth;
  } else if (d.idType === 'passport' && !/^\d{4}-\d{2}-\d{2}$/.test(d.dateOfBirth)) {
    errors.dateOfBirth = 'Enter your date of birth';
  }

  if (body.consent !== 'on') errors.consent = 'Consent is required to process your application';
  if (body.declaration !== 'on') errors.declaration = 'You must confirm the declaration';

  const docs = {};
  for (const [field, label] of [['idDocument', 'identity document'], ['proofOfAddress', 'proof of address (not older than 3 months)']]) {
    const f = files?.[field]?.[0];
    if (!f) { errors[field] = `Upload your ${label}`; continue; }
    const mime = sniffMime(f.buffer);
    if (!mime) { errors[field] = 'Only PDF, JPEG or PNG files are accepted'; continue; }
    docs[field] = { buffer: f.buffer, mime };
  }
  return { data: d, docs, errors };
}

export function clientRouter({ db, config, provider, rmcp }) {
  const r = Router();
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: config.maxUploadBytes, files: 2, fields: 40, fieldSize: 2000 },
  }).fields([{ name: 'idDocument', maxCount: 1 }, { name: 'proofOfAddress', maxCount: 1 }]);

  const findCase = (token) => {
    const c = db.prepare("SELECT * FROM cases WHERE invite_token_hash = ? AND status = 'invited'").get(sha256(token));
    return c && c.invite_expires_at > Date.now() ? c : null;
  };

  r.get('/onboard/:token', (req, res) => {
    const c = findCase(req.params.token);
    if (!c) return res.status(404).render('client/expired');
    res.render('client/form', { c, values: { nationality: 'ZA', countryOfResidence: 'ZA', idType: 'sa_id' }, errors: {}, sources: SOURCES_OF_FUNDS });
  });

  r.post('/onboard/:token', (req, res, next) => {
    upload(req, res, (err) => {
      if (err) {
        const c = findCase(req.params.token);
        if (!c) return res.status(404).render('client/expired');
        const msg = err.code === 'LIMIT_FILE_SIZE' ? `Each file must be under ${config.maxUploadBytes / 1024 / 1024} MB` : 'Upload failed';
        return res.status(400).render('client/form', { c, values: req.body || {}, errors: { form: msg }, sources: SOURCES_OF_FUNDS });
      }
      handleSubmit(req, res).catch(next);
    });
  });

  async function handleSubmit(req, res) {
    const c = findCase(req.params.token);
    if (!c) return res.status(404).render('client/expired');

    const { data, docs, errors } = validateSubmission(req.body, req.files);
    if (Object.keys(errors).length) {
      return res.status(400).render('client/form', { c, values: req.body, errors, sources: SOURCES_OF_FUNDS });
    }

    const screening = await provider.screen({ ...data, hasProofOfAddress: Boolean(docs.proofOfAddress) });
    const risk = assessRisk(data, screening, rmcp);
    const idx = blindIndex(`${data.idType}:${data.idNumber}`, config.dataKey);
    const duplicate = db.prepare('SELECT reference FROM cases WHERE id_blind_index = ? AND id != ?').get(idx, c.id);
    const now = Date.now();

    db.exec('BEGIN');
    try {
      const consent = { popia: true, declaration: true, at: new Date(now).toISOString(), ip: req.ip, userAgent: str(req.get('user-agent'), 300) };
      db.prepare(`UPDATE cases SET status = 'submitted', invite_token_hash = NULL, data_enc = ?, id_blind_index = ?,
                  screening = ?, risk_score = ?, risk_level = ?, dd_level = ?, risk_breakdown = ?, submitted_at = ?
                  WHERE id = ?`)
        .run(encryptJson({ ...data, consent }, config.dataKey, c.id), idx, JSON.stringify(screening),
          risk.score, risk.level, risk.ddLevel, JSON.stringify(risk), now, c.id);
      for (const [kind, doc] of Object.entries(docs)) {
        const docId = crypto.randomUUID();
        db.prepare('INSERT INTO documents (id, case_id, kind, mime, size, sha256, blob_enc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
          .run(docId, c.id, kind, doc.mime, doc.buffer.length, sha256(doc.buffer), encrypt(doc.buffer, config.dataKey, docId), now);
      }
      audit(db, { actor: `client:${c.reference}`, action: 'case.submitted', caseId: c.id, ip: req.ip,
        detail: { riskLevel: risk.level, score: risk.score, provider: screening.provider, duplicateOf: duplicate?.reference } });
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
    res.render('client/done', { c });
  }

  return r;
}
