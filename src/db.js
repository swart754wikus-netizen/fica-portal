import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

// SQLite keeps the MVP self-contained. For production swap to PostgreSQL (same schema shape)
// with encrypted volumes and point-in-time backups.
export function openDb(path) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS staff (
      id INTEGER PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('officer','compliance','admin')),
      password_hash TEXT NOT NULL,
      totp_secret_enc BLOB NOT NULL,
      failed_logins INTEGER NOT NULL DEFAULT 0,
      locked_until INTEGER,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      staff_id INTEGER NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
      csrf TEXT NOT NULL,
      mfa_ok INTEGER NOT NULL DEFAULT 0,
      mfa_attempts INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS cases (
      id TEXT PRIMARY KEY,
      reference TEXT UNIQUE NOT NULL,
      client_email TEXT NOT NULL,
      client_name TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('invited','submitted','approved','rejected')),
      invite_token_hash TEXT,
      invite_expires_at INTEGER,
      data_enc BLOB,
      id_blind_index TEXT,
      screening TEXT,
      risk_score INTEGER,
      risk_level TEXT,
      dd_level TEXT,
      risk_breakdown TEXT,
      decision_reason TEXT,
      decided_by INTEGER REFERENCES staff(id),
      decided_at INTEGER,
      created_by INTEGER NOT NULL REFERENCES staff(id),
      created_at INTEGER NOT NULL,
      submitted_at INTEGER,
      retention_until INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_cases_invite ON cases(invite_token_hash);
    CREATE INDEX IF NOT EXISTS idx_cases_idx ON cases(id_blind_index);

    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,
      mime TEXT NOT NULL,
      size INTEGER NOT NULL,
      sha256 TEXT NOT NULL,
      blob_enc BLOB NOT NULL,
      created_at INTEGER NOT NULL
    );

    -- Append-only, hash-chained audit trail (tamper-evident).
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      case_id TEXT,
      ip TEXT,
      detail TEXT,
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
  `);
  // Additive migrations for databases created by earlier versions.
  const caseCols = db.prepare('PRAGMA table_info(cases)').all().map((c) => c.name);
  if (!caseCols.includes('client_type')) db.exec('ALTER TABLE cases ADD COLUMN client_type TEXT');
  const staffCols = db.prepare('PRAGMA table_info(staff)').all().map((c) => c.name);
  if (!staffCols.includes('active')) db.exec('ALTER TABLE staff ADD COLUMN active INTEGER NOT NULL DEFAULT 1');
  if (!staffCols.includes('pending_totp_enc')) db.exec('ALTER TABLE staff ADD COLUMN pending_totp_enc BLOB');
  if (!staffCols.includes('pending_approval')) db.exec('ALTER TABLE staff ADD COLUMN pending_approval INTEGER NOT NULL DEFAULT 0');
  if (!staffCols.includes('must_change_password')) db.exec('ALTER TABLE staff ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0');
  if (!staffCols.includes('totp_last_counter')) db.exec('ALTER TABLE staff ADD COLUMN totp_last_counter INTEGER NOT NULL DEFAULT 0');
  // Older local databases only allowed officer/compliance: rebuild the staff table to allow 'admin'.
  const staffSql = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'staff'").get().sql;
  if (!staffSql.includes("'admin'")) {
    const cols = db.prepare('PRAGMA table_info(staff)').all().map((c) => c.name).join(', ');
    db.exec('PRAGMA foreign_keys = OFF');
    db.exec('BEGIN');
    db.exec('ALTER TABLE staff RENAME TO staff_old');
    db.exec(staffSql.replace("('officer','compliance')", "('officer','compliance','admin')").replace(/CREATE TABLE "?staff_old"?/, 'CREATE TABLE staff'));
    db.exec(`INSERT INTO staff (${cols}) SELECT ${cols} FROM staff_old; DROP TABLE staff_old;`);
    db.exec('COMMIT');
    db.exec('PRAGMA foreign_keys = ON');
  }
  db.exec('CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, reset INTEGER NOT NULL)');
  return db;
}
