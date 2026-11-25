import express, { Router } from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import { sha256, encrypt, encryptJson, blindIndex } from '../security/crypto.js';
import { parseSaId } from '../validation/saId.js';
import { assessRisk } from '../risk/engine.js';
import { audit } from '../audit.js';
import { CLIENT_TYPES, ENTITY_SUBTYPES, SERVICES, ROLES, DOCUMENTS, REQUIRED_DOCUMENTS, MAX_RELATED } from '../onboarding/catalog.js';

export const SOURCES_OF_FUNDS = ['salary', 'pension', 'business_income', 'investments', 'inheritance', 'sale_of_property', 'cryptocurrency', 'other'];

/** Identify file type from magic bytes — never trust the browser-supplied MIME type or extension. */
export function sniffMime(buf) {
  if (buf.subarray(0, 5).toString('latin1') === '%PDF-') return 'application/pdf';
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  return null;
}

const str = (v, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

const yesNo = (v) => (v === 'yes' ? true : v === 'no' ? false : null);

/** multer/append-field turns related[0][name] into an array or an index-keyed object. */
function relatedRows(raw) {
  const rows = Array.isArray(raw) ? raw : raw && typeof raw === 'object' ? Object.values(raw) : [];
  return rows.slice(0, MAX_RELATED);
}

function validateRelated(type, raw, errors) {
  const roles = ROLES[type];
  const people = [];
  relatedRows(raw).forEach((row, i) => {
    const p = {
      name: str(row?.name, 150),
      idNumber: str(row?.idNumber, 30).replace(/\s/g, ''),
      nationality: str(row?.nationality, 2).toUpperCase() || 'ZA',
      role: roles[row?.role] ? row.role : '',
      ownership: Math.min(100, Math.max(0, Number(row?.ownership) || 0)),
      pep: yesNo(row?.pep) === true,
      isEntity: row?.isEntity === 'on',
    };
    if (!p.name && !p.idNumber) return; // blank row
    if (!p.name) errors[`related.${i}.name`] = 'Name required';
    if (!p.isEntity && !p.idNumber) errors[`related.${i}.idNumber`] = 'ID or passport number required';
    if (!p.isEntity && p.nationality === 'ZA' && /^\d{13}$/.test(p.idNumber)) {
      const parsed = parseSaId(p.idNumber);
      if (!parsed.valid) errors[`related.${i}.idNumber`] = parsed.error;
    }
    if (!p.role) errors[`related.${i}.role`] = 'Select a role';
    people.push(p);
  });
  if (!people.length) errors.related = 'Add at least one person (see the list above)';
  return people;
}

export function validateSubmission(body, files) {
  const errors = {};
  const clientType = CLIENT_TYPES[body.clientType] ? body.clientType : '';
  const isEntity = clientType && clientType !== 'individual';
  const d = {
    clientType,
    services: (Array.isArray(body.services) ? body.services : body.services ? [body.services] : []).filter((s) => SERVICES[s]),
    firstName: str(body.firstName, 100),
    lastName: str(body.lastName, 100),
    idType: body.idType === 'passport' ? 'passport' : 'sa_id',
    idNumber: str(body.idNumber, 30).replace(/\s/g, ''),
    dateOfBirth: str(body.dateOfBirth, 10),
    nationality: str(body.nationality, 2).toUpperCase(),
    countryOfResidence: str(body.countryOfResidence, 2).toUpperCase(),
    phone: str(body.phone, 20),
    taxNumber: str(body.taxNumber, 20).replace(/\s/g, ''),
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

  if (!clientType) errors.clientType = 'Choose who this application is for';
  if (!d.services.length) errors.services = 'Select at least one service';

  for (const k of ['firstName', 'lastName', 'idNumber', 'addressLine1', 'city', 'postalCode', 'occupation', 'purpose']) {
    if (!d[k]) errors[k] = 'Required';
  }
  if (!d.sourceOfFunds) errors.sourceOfFunds = 'Select a source of funds';
  if (!/^[A-Z]{2}$/.test(d.nationality)) errors.nationality = 'Select a country';
  if (!/^[A-Z]{2}$/.test(d.countryOfResidence)) errors.countryOfResidence = 'Select a country';
  if (d.phone && !/^\+?[\d\s-]{9,20}$/.test(d.phone)) errors.phone = 'Enter a valid phone number';
  if (d.taxNumber && !/^\d{10}$/.test(d.taxNumber)) errors.taxNumber = 'SARS tax numbers are 10 digits';
  if (body.pepDeclared !== 'yes' && body.pepDeclared !== 'no') errors.pepDeclared = 'Please answer this question';
  if (d.pepDeclared && !d.pepDetails) errors.pepDetails = 'Please give details of the public position';

  if (d.idType === 'sa_id' && d.idNumber) {
    const parsed = parseSaId(d.idNumber);
    if (!parsed.valid) errors.idNumber = parsed.error;
    else d.dateOfBirth = parsed.dateOfBirth;
  } else if (d.idType === 'passport' && !/^\d{4}-\d{2}-\d{2}$/.test(d.dateOfBirth)) {
    errors.dateOfBirth = 'Enter your date of birth';
  }

  if (isEntity) {
    const subtypes = ENTITY_SUBTYPES[clientType];
    d.entity = {
      name: str(body.entityName, 200),
      subtype: subtypes[body.entitySubtype] ? body.entitySubtype : Object.keys(subtypes).length === 1 ? Object.keys(subtypes)[0] : '',
      regNumber: str(body.entityRegNumber, 40),
      taxNumber: str(body.entityTaxNumber, 20).replace(/\s/g, ''),
      address: str(body.entityAddress, 300),
      natureOfBusiness: str(body.natureOfBusiness, 300),
      countriesOfOperation: str(body.countriesOfOperation, 200),
      cashIntensive: yesNo(body.cashIntensive) === true,
      capacity: str(body.capacity, 100),
    };
    for (const [k, msg] of [['name', 'Enter the registered name'], ['subtype', 'Select the type'], ['regNumber', 'Enter the registration number'], ['address', 'Enter the registered address'], ['natureOfBusiness', 'Describe what the entity does'], ['capacity', 'Tell us in what capacity you act']]) {
      if (!d.entity[k]) errors[`entity.${k}`] = msg;
    }
    if (d.entity.taxNumber && !/^\d{10}$/.test(d.entity.taxNumber)) errors['entity.taxNumber'] = 'SARS tax numbers are 10 digits';
    if (yesNo(body.cashIntensive) === null) errors['entity.cashIntensive'] = 'Please answer this question';
    d.related = validateRelated(clientType, body.related, errors);
  }

  if (body.consent !== 'on') errors.consent = 'Consent is required to process your application';
  if (body.declaration !== 'on') errors.declaration = 'You must confirm the declaration';

  const docs = [];
  if (clientType) {
    const { required, optional } = REQUIRED_DOCUMENTS[clientType];
    for (const field of [...required, ...optional]) {
      const list = files?.[field] || [];
      if (!list.length) {
        if (required.includes(field)) errors[field] = `Upload: ${DOCUMENTS[field].label}`;
        continue;
      }
      for (const f of list) {
        const mime = sniffMime(f.buffer);
        if (!mime) { errors[field] = 'Only PDF, JPEG or PNG files are accepted'; break; }
        docs.push({ kind: field, buffer: f.buffer, mime });
      }
    }
  }
  return { data: d, docs, errors };
}

/** Screen the person completing the form and every person behind an entity. */
export async function screenAll(provider, data, hasProofOfAddress) {
  const main = await provider.screen({ ...data, hasProofOfAddress });
  const related = [];
  for (const p of (data.related || []).filter((x) => !x.isEntity)) {
    const parts = p.name.split(/\s+/);
    const r = await provider.screen({ firstName: parts.slice(0, -1).join(' '), lastName: parts.at(-1), idNumber: p.idNumber, idType: p.nationality === 'ZA' ? 'sa_id' : 'passport', hasProofOfAddress: true });
    related.push({ name: p.name, role: p.role, sanctions: r.sanctions, pep: r.pep, adverseMedia: r.adverseMedia });
  }
  return { ...main, related };
}

export function clientRouter({ store, config, provider, rmcp }) {
  const r = Router();
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: config.maxUploadBytes, files: 20, fields: 200, fieldSize: 2000 },
  }).fields(Object.entries(DOCUMENTS).map(([name, d]) => ({ name, maxCount: d.multiple ? 10 : 1 })));

  const findCase = async (token) => {
    const c = await store.getCaseByInviteHash(sha256(String(token)));
    return c && c.status === 'invited' && c.invite_expires_at > Date.now() ? c : null;
  };
  const MIMES = ['application/pdf', 'image/jpeg', 'image/png'];
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const view = (extra) => ({ sources: SOURCES_OF_FUNDS, firmName: config.firmName, directUpload: store.supportsDirectUpload, maxUploadMb: config.maxUploadBytes / 1024 / 1024, ...extra });

  // Direct-to-storage upload: the browser asks for a short-lived signed URL per file and
  // uploads it straight to Firebase Storage (no Vercel request-size limit). The server
  // checks and encrypts the file when the form is submitted.
  r.post('/onboard/:token/upload-url', express.json({ limit: '4kb' }), async (req, res) => {
    if (!store.supportsDirectUpload) return res.status(404).json({ error: 'Not available' });
    const c = await findCase(req.params.token);
    if (!c) return res.status(404).json({ error: 'This link is no longer valid.' });
    const { field, contentType, size } = req.body || {};
    if (!DOCUMENTS[field]) return res.status(400).json({ error: 'Unknown document' });
    if (!MIMES.includes(contentType)) return res.status(400).json({ error: 'Only PDF, JPEG or PNG files are accepted' });
    if (!(size > 0 && size <= config.maxUploadBytes)) return res.status(400).json({ error: `Each file must be under ${config.maxUploadBytes / 1024 / 1024} MB` });
    const { count } = await store.rateHit(`uploads:${c.id}`, 24 * 3_600_000);
    if (count > 60) return res.status(429).json({ error: 'Too many uploads for this application' });
    try { await store.ensureUploadCors(new URL(config.baseUrl).origin); } catch (err) {
      console.error('Could not set Storage CORS — run scripts/setStorageCors.js or grant the service account Storage Admin:', err.message);
    }
    const uploadId = crypto.randomUUID();
    res.json({ uploadId, ...(await store.createUploadUrl(c.id, uploadId, contentType, config.maxUploadBytes)) });
  });

  /** Merge multipart files and already-uploaded (direct) files into one { field: [{buffer, uploadId?}] } map. */
  async function collectFiles(c, req) {
    const files = {};
    for (const [field, list] of Object.entries(req.files || {})) files[field] = list.map((f) => ({ buffer: f.buffer }));
    const uploaded = req.body?.uploaded && typeof req.body.uploaded === 'object' ? req.body.uploaded : {};
    const kept = {};
    for (const [field, ids] of Object.entries(uploaded)) {
      if (!DOCUMENTS[field] || !store.supportsDirectUpload) continue;
      for (const id of [].concat(ids).filter((x) => UUID.test(x)).slice(0, 10)) {
        const buffer = await store.readUpload(c.id, id);
        if (!buffer || buffer.length > config.maxUploadBytes) continue;
        (files[field] ||= []).push({ buffer, uploadId: id });
        (kept[field] ||= []).push(id);
      }
    }
    return { files, kept };
  }

  r.get('/onboard/:token', async (req, res) => {
    const c = await findCase(req.params.token);
    if (!c) return res.status(404).render('client/expired');
    res.render('client/form', view({ c, token: req.params.token, values: { nationality: 'ZA', countryOfResidence: 'ZA', idType: 'sa_id' }, errors: {}, kept: {} }));
  });

  r.post('/onboard/:token', (req, res, next) => {
    upload(req, res, async (err) => {
      try {
        if (err) {
          const c = await findCase(req.params.token);
          if (!c) return res.status(404).render('client/expired');
          const msg = err.code === 'LIMIT_FILE_SIZE' ? `Each file must be under ${config.maxUploadBytes / 1024 / 1024} MB` : 'Upload failed';
          return res.status(400).render('client/form', view({ c, token: req.params.token, values: req.body || {}, errors: { form: msg }, kept: {} }));
        }
        await handleSubmit(req, res);
      } catch (e) { next(e); }
    });
  });

  async function handleSubmit(req, res) {
    const c = await findCase(req.params.token);
    if (!c) return res.status(404).render('client/expired');

    const { files, kept } = await collectFiles(c, req);
    const { data, docs, errors } = validateSubmission(req.body, files);
    if (Object.keys(errors).length) {
      return res.status(400).render('client/form', view({ c, token: req.params.token, values: req.body, errors, kept }));
    }

    const screening = await screenAll(provider, data, docs.some((x) => x.kind === 'proofOfAddress'));
    const risk = assessRisk(data, screening, rmcp);
    const idx = blindIndex(`${data.idType}:${data.idNumber}`, config.dataKey);
    const duplicate = await store.findCaseByBlindIndex(idx, c.id);
    const now = Date.now();
    const consent = { popia: true, declaration: true, at: new Date(now).toISOString(), ip: req.ip, userAgent: str(req.get('user-agent'), 300) };
    const docRows = docs.map(({ kind, buffer, mime }) => {
      const id = crypto.randomUUID();
      return { id, kind, mime, size: buffer.length, sha256: sha256(buffer), blob_enc: encrypt(buffer, config.dataKey, id), created_at: now };
    });
    await store.submitCase(c.id, {
      status: 'submitted', invite_token_hash: null, data_enc: encryptJson({ ...data, consent }, config.dataKey, c.id), id_blind_index: idx,
      screening: JSON.stringify(screening), risk_score: risk.score, risk_level: risk.level, dd_level: risk.ddLevel,
      risk_breakdown: JSON.stringify(risk), submitted_at: now, client_type: data.clientType,
    }, docRows);
    // Plain-text uploads are removed once their encrypted copies are safely stored.
    await Promise.all(Object.values(kept).flat().map((id) => store.deleteUpload(c.id, id)));
    await audit(store, { actor: `client:${c.reference}`, action: 'case.submitted', caseId: c.id, ip: req.ip,
      detail: { riskLevel: risk.level, score: risk.score, provider: screening.provider, duplicateOf: duplicate?.reference } });
    res.render('client/done', { c });
  }

  return r;
}
