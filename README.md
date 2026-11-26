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

## Architecture

- **Production:** Vercel (Cape Town region) runs the Express app as one serverless function (`api/index.js`).
  Records live in **Firestore** and documents in **Firebase Storage**, both in Johannesburg (`africa-south1`).
  Client data, documents and authenticator secrets are AES-256-GCM encrypted by the app (`DATA_KEY`) before they
  reach Google. Browsers never talk to Firebase directly (`firestore.rules` / `storage.rules` deny everything);
  documents go up via 15-minute signed URLs locked to one path, file type and size, so phone photos aren't limited
  by Vercel's 4.5 MB request cap.
- **Local development & tests:** the same app on a SQLite file (`STORE=sqlite`, the default outside Vercel).

## Local development

```bash
npm install
cp .env.example .env          # then: npm run gen-key  → paste into DATA_KEY; set SETUP_TOKEN to any long value
npm run dev                   # http://localhost:3000/staff/setup  → create the first compliance officer
npm test                      # 26 tests, no network needed
cd test-firestore && npm install && npm test   # end-to-end on the Firestore + Storage emulators (needs Java 11+)
```
Mock provider test triggers (surname, for the client and for every person listed behind an entity): `Sanctioned` → sanctions hit, `Politician` → PEP, `Headline` → adverse media.

## Going live on Firebase + Vercel (one firm per project)

1. **Firebase:** create a **new** project for this firm (never share one with another business).
   - Firestore Database → Create → *Production mode* → location **africa-south1 (Johannesburg)**.
   - Storage → Get started → location **africa-south1**. New projects need the **Blaze** (pay-as-you-go) plan for
     Storage; at a small firm's volume expect a few rand a month — set a budget alert in Google Cloud Billing.
   - Firestore → Rules: paste `firestore.rules`, Publish. Storage → Rules: paste `storage.rules`, Publish.
   - Project settings → Service accounts → **Generate new private key** (JSON file — treat as a password).
2. **Vercel:** Add New → Project → import this repo. Environment Variables:
   | Key | Value |
   |---|---|
   | `DATA_KEY` | 32 random bytes, base64 (see `.env.example`). **Never change it after go-live.** |
   | `SETUP_TOKEN` | any long random value — used once at `/staff/setup` |
   | `FIRM_NAME` | the firm's full name |
   | `BASE_URL` | the site address, e.g. `https://fica.firm.co.za` |
   | `FIREBASE_SERVICE_ACCOUNT` | the **entire** downloaded `.json` key file (open in Notepad → Ctrl+A → Ctrl+C → paste). Alternatively set `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, `FIREBASE_PRIVATE_KEY` separately. |
   | `FIREBASE_STORAGE_BUCKET` | from Storage, e.g. `firm-fica.firebasestorage.app` |
   | `NODEJS_HELPERS` | `0` — turns off Vercel's own request-body parsing so Express reads forms and uploads itself |
   Deploy. (Vercel's free Hobby plan is for non-commercial use; a firm's live system belongs on Pro.)
3. Open `BASE_URL/staff/setup`, enter `SETUP_TOKEN`, create the compliance officer, log in and set up the
   authenticator app. Add other staff under **Team**. Optionally remove `SETUP_TOKEN` afterwards.
4. The first document upload sets the bucket's CORS rule for `BASE_URL` automatically. If the logs say it couldn't,
   give the service account the *Storage Admin* role or set CORS manually.

## Security controls
| Control | Implementation |
|---|---|
| Encryption at rest | AES-256-GCM for all client PII and documents, bound to record ID via AAD (`src/security/crypto.js`) |
| ID lookups without plaintext | HMAC blind index for duplicate-client detection |
| Staff auth | scrypt passwords + mandatory TOTP MFA (enrolled at first login, codes single-use), lockout after 5 failures, session rotation after MFA, MFA attempt cap; deactivating a person ends their session |
| Sessions | Random 256-bit token, stored hashed, HttpOnly + SameSite=Strict + Secure (prod), 30-min sliding expiry |
| CSRF | Per-session synchroniser token on every staff POST |
| Client links | 256-bit single-use tokens, stored hashed, expire (72h default), `Referrer-Policy: no-referrer`; emailed directly to the client (staff never see them), resend cancels the old link |
| Uploads | Signed, size-capped direct uploads; magic-byte sniffing (PDF/JPEG/PNG only), 10 MB per file; encrypted before storage and the plain upload deleted; downloaded as attachment |
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
3. **Key management:** keep `DATA_KEY` in a password manager as well as Vercel; plan rotation (ciphertext is version-prefixed).
4. **Backups:** enable Firestore point-in-time recovery / scheduled exports.
6. **Deeper UBO tracing** (when an owner is itself a company or trust, its owners are flagged but not yet collected in a second form), CIPC/Master's office lookups, liveness/selfie match, ongoing monitoring & periodic re-screening.
7. Information Officer review of the privacy notice; operator agreements (POPIA s21) with the provider and host; penetration test.
