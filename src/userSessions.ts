import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export type UserRole = 'admin' | 'viewer';
export interface SessionIdentity {
  username: string;
  role: UserRole;
}

const SCRYPT_OPTIONS = { N: 32_768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const PASSWORD_BYTES = 64;
export const SESSION_TTL_SECONDS = 12 * 60 * 60;

export function isValidUsername(username: string): boolean {
  return /^[A-Za-z0-9._-]{3,40}$/.test(username);
}

export function isValidPassword(password: string): boolean {
  return password.length >= 12 && password.length <= 256;
}

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, PASSWORD_BYTES, SCRYPT_OPTIONS);
  return `scrypt$32768$8$1$${salt.toString('hex')}$${derived.toString('hex')}`;
}

function verifyPassword(password: string, encoded: string): boolean {
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt' || parts[1] !== '32768' || parts[2] !== '8' || parts[3] !== '1') return false;
  const salt = Buffer.from(parts[4], 'hex');
  const expected = Buffer.from(parts[5], 'hex');
  if (salt.length !== 16 || expected.length !== PASSWORD_BYTES) return false;
  const actual = crypto.scryptSync(password, salt, PASSWORD_BYTES, SCRYPT_OPTIONS);
  return crypto.timingSafeEqual(actual, expected);
}

export class UserSessionStore {
  private readonly db: Database.Database;
  private readonly dummyPasswordHash = hashPassword(crypto.randomBytes(32).toString('hex'));

  constructor(databasePath: string, bootstrapUsername = '', bootstrapPassword = '') {
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });
    this.db = new Database(databasePath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.pragma('busy_timeout = 5000');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS auth_users (
        username TEXT PRIMARY KEY COLLATE NOCASE,
        role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS auth_sessions (
        token_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL COLLATE NOCASE,
        created_at TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY (username) REFERENCES auth_users(username) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(expires_at);
    `);
    this.db.prepare('DELETE FROM auth_sessions WHERE expires_at <= ?').run(Date.now());
    this.bootstrapAdmin(bootstrapUsername, bootstrapPassword);
  }

  private bootstrapAdmin(username: string, password: string): void {
    const configured = Boolean(username || password);
    if (!configured) return;
    if (!username || !password || !isValidUsername(username) || !isValidPassword(password)) {
      throw new Error('Bootstrap admin tidak valid: isi PASOPATI_ADMIN_USERNAME (3–40 karakter [A-Z, a-z, 0–9, titik, garis bawah, atau tanda hubung]) dan PASOPATI_ADMIN_PASSWORD (12–256 karakter).');
    }
    const existing = this.db.prepare('SELECT role FROM auth_users WHERE username = ?').get(username) as { role: string } | undefined;
    if (existing) {
      if (existing.role !== 'admin') throw new Error('Username bootstrap sudah terdaftar dan bukan admin.');
      return;
    }
    this.db.prepare('INSERT INTO auth_users (username, role, password_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(username, 'admin', hashPassword(password), new Date().toISOString());
  }

  get userCount(): number {
    return Number((this.db.prepare('SELECT COUNT(*) AS count FROM auth_users').get() as { count: number }).count);
  }

  authenticate(username: string, password: string): SessionIdentity | null {
    const normalized = username.trim();
    const row = isValidUsername(normalized)
      ? this.db.prepare('SELECT username, role, password_hash FROM auth_users WHERE username = ?').get(normalized) as { username: string; role: UserRole; password_hash: string } | undefined
      : undefined;
    const hash = row?.password_hash || this.dummyPasswordHash;
    const valid = verifyPassword(password, hash);
    if (!row || !valid) return null;
    return { username: row.username, role: row.role };
  }

  createSession(username: string): { token: string; expiresAt: number } {
    const token = crypto.randomBytes(32).toString('base64url');
    const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
    this.db.prepare('DELETE FROM auth_sessions WHERE expires_at <= ?').run(Date.now());
    this.db.prepare('INSERT INTO auth_sessions (token_hash, username, created_at, expires_at) VALUES (?, ?, ?, ?)')
      .run(crypto.createHash('sha256').update(token).digest('hex'), username, new Date().toISOString(), expiresAt);
    return { token, expiresAt };
  }

  getSession(token: string): SessionIdentity | null {
    if (!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return null;
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const row = this.db.prepare(`
      SELECT u.username, u.role FROM auth_sessions s
      JOIN auth_users u ON u.username = s.username
      WHERE s.token_hash = ? AND s.expires_at > ?
    `).get(tokenHash, Date.now()) as { username: string; role: UserRole } | undefined;
    return row || null;
  }

  deleteSession(token: string): void {
    if (!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return;
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    this.db.prepare('DELETE FROM auth_sessions WHERE token_hash = ?').run(tokenHash);
  }

  createViewer(username: string, password: string): void {
    if (!isValidUsername(username)) throw new Error('Username harus 3–40 karakter: huruf, angka, titik, garis bawah, atau tanda hubung.');
    if (!isValidPassword(password)) throw new Error('Password harus 12–256 karakter.');
    this.db.prepare('INSERT INTO auth_users (username, role, password_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(username, 'viewer', hashPassword(password), new Date().toISOString());
  }
}
