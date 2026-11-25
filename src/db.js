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
      role TEXT NOT NULL CHECK (role IN ('officer','compliance')),
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
  return db;
}
