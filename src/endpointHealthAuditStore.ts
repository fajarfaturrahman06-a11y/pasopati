import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

export type EndpointHealthAuditEventType = 'ENDPOINT_ACCESSED' | 'REMEDIATION_APPROVED';

export interface EndpointHealthAuditRecord {
  id: string;
  eventType: EndpointHealthAuditEventType;
  occurredAt: string;
  accessedBy: string;
  accessIp?: string;
  approvedBy?: string;
  approvedAt?: string;
  planId?: string;
  target: {
    endpointId: string;
    name: string;
    hostname: string;
    role: string;
    os: string;
    endpointUser: string;
    ip: string;
    mac: string;
    deletedAt?: string;
  };
  computerCondition: {
    capturedAt: string;
    captureStatus: 'CAPTURED' | 'NOT_FOUND';
    latestAuditAt: string | null;
    score: number | null;
    passCount: number;
    warningCount: number;
    failCount: number;
    totalChecks: number;
    quarantined: boolean;
    openPorts: number[];
    failedControls: string[];
    warningControls: string[];
  };
}

const MAX_RECORDS = 20_000;
const DATABASES = new Map<string, InstanceType<typeof Database>>();

function isObject(value: unknown): value is Record<string, any> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function validRecord(value: unknown): value is EndpointHealthAuditRecord {
  if (!isObject(value) || !isObject(value.target) || !isObject(value.computerCondition)) return false;
  const condition = value.computerCondition;
  return typeof value.id === 'string' && value.id.length > 0 &&
    (value.eventType === 'ENDPOINT_ACCESSED' || value.eventType === 'REMEDIATION_APPROVED') &&
    typeof value.occurredAt === 'string' && typeof value.accessedBy === 'string' &&
    typeof value.target.endpointId === 'string' && typeof value.target.endpointUser === 'string' &&
    (condition.captureStatus === 'CAPTURED' || condition.captureStatus === 'NOT_FOUND') &&
    typeof condition.capturedAt === 'string' && Array.isArray(condition.openPorts) &&
    Array.isArray(condition.failedControls) && Array.isArray(condition.warningControls);
}

function restrictDatabaseFilePermissions(filePath: string): void {
  // POSIX permissions are not equivalent to Windows ACLs; do not overwrite Windows ACLs.
  if (process.platform === 'win32') return;
  for (const file of [filePath, `${filePath}-wal`, `${filePath}-shm`]) {
    if (fs.existsSync(file)) fs.chmodSync(file, 0o600);
  }
}

function insertStatement(db: InstanceType<typeof Database>) {
  return db.prepare(`
    INSERT OR IGNORE INTO endpoint_health_audit (
      id, event_type, occurred_at, accessed_by, access_ip, approved_by,
      approved_at, plan_id, endpoint_id, endpoint_user, record_json
    ) VALUES (
      @id, @eventType, @occurredAt, @accessedBy, @accessIp, @approvedBy,
      @approvedAt, @planId, @endpointId, @endpointUser, @recordJson
    )
  `);
}

function migrateLegacyJson(db: InstanceType<typeof Database>, databasePath: string): void {
  const marker = db.prepare('SELECT value FROM schema_meta WHERE key = ?').get('legacy_json_imported') as { value: string } | undefined;
  if (marker?.value === '1') return;
  if (marker) throw new Error('Status migrasi database audit endpoint tidak valid.');

  const legacyPath = path.join(path.dirname(databasePath), 'endpoint_health_audit.json');
  let legacyRecords: EndpointHealthAuditRecord[] = [];
  if (fs.existsSync(legacyPath)) {
    const parsed: unknown = JSON.parse(fs.readFileSync(legacyPath, 'utf-8'));
    if (!Array.isArray(parsed) || parsed.some(item => !validRecord(item))) {
      throw new Error('endpoint_health_audit.json lama tidak sesuai skema; database SQLite tidak diubah.');
    }
    legacyRecords = parsed as EndpointHealthAuditRecord[];
  }

  const insert = insertStatement(db);
  const migration = db.transaction((records: EndpointHealthAuditRecord[]) => {
    for (const record of records) {
      insert.run({
        id: record.id,
        eventType: record.eventType,
        occurredAt: record.occurredAt,
        accessedBy: record.accessedBy,
        accessIp: record.accessIp ?? null,
        approvedBy: record.approvedBy ?? null,
        approvedAt: record.approvedAt ?? null,
        planId: record.planId ?? null,
        endpointId: record.target.endpointId,
        endpointUser: record.target.endpointUser,
        recordJson: JSON.stringify(record)
      });
    }
    db.prepare('INSERT INTO schema_meta (key, value) VALUES (?, ?)').run('legacy_json_imported', '1');
  });
  migration(legacyRecords);
}

function openDatabase(filePath: string): InstanceType<typeof Database> {
  const resolvedPath = path.resolve(filePath);
  const cached = DATABASES.get(resolvedPath);
  if (cached?.open) {
    restrictDatabaseFilePermissions(resolvedPath);
    return cached;
  }

  fs.mkdirSync(path.dirname(resolvedPath), { recursive: true, mode: 0o700 });
  const db = new Database(resolvedPath);
  try {
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous = FULL');
    db.pragma('busy_timeout = 5000');
    db.exec(`
      CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS endpoint_health_audit (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL CHECK (event_type IN ('ENDPOINT_ACCESSED', 'REMEDIATION_APPROVED')),
        occurred_at TEXT NOT NULL,
        accessed_by TEXT NOT NULL,
        access_ip TEXT,
        approved_by TEXT,
        approved_at TEXT,
        plan_id TEXT,
        endpoint_id TEXT NOT NULL,
        endpoint_user TEXT NOT NULL,
        record_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_endpoint_health_audit_time
        ON endpoint_health_audit (occurred_at DESC, id DESC);
      CREATE INDEX IF NOT EXISTS idx_endpoint_health_audit_endpoint
        ON endpoint_health_audit (endpoint_id, occurred_at DESC);
      PRAGMA user_version = 1;
    `);
    migrateLegacyJson(db, resolvedPath);
    restrictDatabaseFilePermissions(resolvedPath);
    DATABASES.set(resolvedPath, db);
    return db;
  } catch (error) {
    if (db.open) db.close();
    throw error;
  }
}

/** Read the separate SQLite audit database; JSON from the prior release is imported once on first open. */
export function readEndpointHealthAuditRecords(filePath: string): EndpointHealthAuditRecord[] {
  const db = openDatabase(filePath);
  const rows = db.prepare('SELECT record_json FROM endpoint_health_audit ORDER BY occurred_at ASC, rowid ASC').all() as Array<{ record_json: string }>;
  const records = rows.map(row => JSON.parse(row.record_json) as unknown);
  if (records.some(record => !validRecord(record))) {
    throw new Error('Database SQLite audit endpoint tidak sesuai skema; data tidak ditimpa.');
  }
  return records as EndpointHealthAuditRecord[];
}

/** Append an immutable record in a durable SQLite transaction. */
export function appendEndpointHealthAuditRecord(
  filePath: string,
  record: EndpointHealthAuditRecord
): number {
  if (!validRecord(record)) throw new Error('Rekaman audit endpoint tidak valid.');
  const db = openDatabase(filePath);
  const insert = insertStatement(db);
  const append = db.transaction(() => {
    const current = db.prepare('SELECT COUNT(*) AS count FROM endpoint_health_audit').get() as { count: number };
    const count = Number(current.count);
    const exists = db.prepare('SELECT 1 AS found FROM endpoint_health_audit WHERE id = ?').get(record.id);
    if (exists) return count;
    if (count >= MAX_RECORDS) {
      throw new Error(`Database SQLite audit endpoint mencapai batas ${MAX_RECORDS} rekaman; arsipkan database sebelum menambah data.`);
    }
    insert.run({
      id: record.id,
      eventType: record.eventType,
      occurredAt: record.occurredAt,
      accessedBy: record.accessedBy,
      accessIp: record.accessIp ?? null,
      approvedBy: record.approvedBy ?? null,
      approvedAt: record.approvedAt ?? null,
      planId: record.planId ?? null,
      endpointId: record.target.endpointId,
      endpointUser: record.target.endpointUser,
      recordJson: JSON.stringify(record)
    });
    return count + 1;
  });
  const total = append.immediate();
  restrictDatabaseFilePermissions(path.resolve(filePath));
  return total;
}
