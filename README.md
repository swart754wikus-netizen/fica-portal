# FICA Client Onboarding Portal

Secure digital FICA client onboarding for a **chartered accounting firm** (one firm per deployment; set `FIRM_NAME`).
Clients complete KYC via a single-use link; staff review an explainable risk score and record a defensible decision.

**Built for accounting work:** individuals, companies/CCs, trusts and partnerships; the services the client wants
(tax, VAT/payroll, bookkeeping, AFS, audit/review, and trust & company services — CIPC registration, secretarial,
trust administration, acting as director/trustee/nominee, registered address). For entities the client lists every
director, shareholder (25%+), trustee, founder, beneficiary, partner and controller; each person is screened, and the
right documents are required per client type (CIPC certificate, Master's letter of authority, trust deed, partnership
agreement, authority resolution, IDs of the people listed).

> FICA status: since the 2022 amendments, accountants who provide trust and company services are accountable
> institutions with full CDD, beneficial-ownership, record-keeping and reporting duties. The firm's compliance officer
> must confirm which of its services are covered and approve `config/rmcp.json` against the firm's RMCP.

**Flow:** Invite → Client details & documents → Screening (identity, sanctions, PEP, adverse media) → Automated RMCP risk score → Risk-based due diligence (SDD / CDD / EDD) → Decision → KYC report

## Quick start
```bash
npm install
cp .env.example .env          # then: npm run gen-key  → paste into DATA_KEY
npm run create-staff -- you@firm.co.za "Your Name" compliance   # scan the TOTP secret into an authenticator app
npm run dev                   # http://localhost:3000/staff/login
npm test
```
Mock provider test triggers (surname, for the client and for every person listed behind an entity): `Sanctioned` → sanctions hit, `Politician` → PEP, `Headline` → adverse media.

## Hosting on Render (recommended)

`render.yaml` sets everything up: Node 22, a 1 GB permanent disk at `/var/data` for the database and encrypted
documents, HTTPS, and a randomly generated `DATA_KEY`. On Render: **New → Blueprint → this repo**, enter
`FIRM_NAME` and `BASE_URL`, deploy, then create staff from the service's **Shell** tab with
`npm run create-staff -- you@firm.co.za "Your Name" compliance`. Region is Frankfurt (no South African region) —
state the cross-border transfer in the privacy notice (POPIA s72). Never change `DATA_KEY` after the first deploy:
existing data could no longer be decrypted. Enable Render's disk snapshots / backups.

## Security controls
| Control | Implementation |
|---|---|
| Encryption at rest | AES-256-GCM for all client PII and documents, bound to record ID via AAD (`src/security/crypto.js`) |
| ID lookups without plaintext | HMAC blind index for duplicate-client detection |
| Staff auth | scrypt passwords + mandatory TOTP MFA, lockout after 5 failures, session rotation after MFA, MFA attempt cap |
| Sessions | Random 256-bit token, stored hashed, HttpOnly + SameSite=Strict + Secure (prod), 30-min sliding expiry |
| CSRF | Per-session synchroniser token on every staff POST |
| Client links | 256-bit single-use tokens, stored hashed, expire (72h default), `Referrer-Policy: no-referrer`; emailed directly to the client (staff never see them), resend cancels the old link |
| Uploads | Magic-byte sniffing (PDF/JPEG/PNG only), 5 MB cap, never written to disk unencrypted, downloaded as attachment |
| Headers | Strict CSP (no inline script), HSTS (prod), frame-ancestors none, `Cache-Control: no-store` |
| Authorisation | Officers can't approve high-risk/EDD clients — compliance role only, with EDD attestation |
| Audit | Append-only (DB triggers), SHA-256 hash-chained log of every view, download, decision and login |
| Retention | `retention_until` = decision + 5 years (FICA s22–23) |

## Regulatory mapping
- **FICA s21 / s21A–H** — identification & verification, risk-based CDD/EDD, PEP (DPIP/FPPO) handling, source of funds
- **FICA s22–23** — record keeping 5 years; KYC report + document hashes
- **FICA s42 (RMCP)** — scoring weights in `config/rmcp.json`, versioned and shown on every assessment
- **FICA s26A / s28A** — sanctions match blocks approval and prompts TPR via goAML (filing itself is manual)
- **POPIA** — explicit consent captured with timestamp/IP, privacy notice template, minimised access, encryption, audit

## Before production (not done in this MVP)
1. **Contract a screening provider** and implement an adapter in `src/providers/` (contract in `index.js`). Mock must never run in prod.
2. **Email sending:** set `MAIL_TRANSPORT=smtp` and the `SMTP_*` settings, plus SPF/DKIM/DMARC on the sending domain.
3. **Hosting in South Africa** (e.g. AWS af-south-1 / Azure South Africa North) behind TLS; set `NODE_ENV=production`.
4. **Key management:** load `DATA_KEY` from KMS/Key Vault; plan rotation (ciphertext is version-prefixed).
5. **PostgreSQL + object storage** instead of SQLite for multi-instance deployment; Redis for rate limits.
6. **Deeper UBO tracing** (when an owner is itself a company or trust, its owners are flagged but not yet collected in a second form), CIPC/Master's office lookups, liveness/selfie match, ongoing monitoring & periodic re-screening.
7. Information Officer review of the privacy notice; operator agreements (POPIA s21) with the provider and host; penetration test.
