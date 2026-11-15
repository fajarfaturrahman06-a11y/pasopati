import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

/** Aktivitas baca-saja yang diaudit: unduhan berkas dan pemindaian realtime. */
export type ActivityAuditEventType = 'FILE_DOWNLOADED' | 'REALTIME_SCAN';

export interface ActivityAuditRecord {
  id: string;
  eventType: ActivityAuditEventType;
  occurredAt: string;
  /** Nama akun pelaku, atau `anonim` bila unduhan tanpa sesi/kunci. */
  actor: string;
  actorRole: string;
  sourceIp?: string;
  /** Nama berkas yang diunduh atau unit yang dipindai. */
  subject: string;
  /** Plan terkait bila unduhan berasal dari artefak remediasi. */
  planId?: string;
  /** Keterangan tambahan: status HTTP atau skor hasil scan. */
  detail: string;
  status: 'SUCCESS' | 'FAILED';
}

const MAX_RECORDS = 20_000;
const DATABASES = new Map<string, InstanceType<typeof Database>>();

function isObject(value: unknown): value is Record<string, any> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function validRecord(value: unknown): value is ActivityAuditRecord {
  if (!isObject(value)) return false;
  return typeof value.id === 'string' && value.id.length > 0 &&
    (value.eventType === 'FILE_DOWNLOADED' || value.eventType === 'REALTIME_SCAN') &&
    typeof value.occurredAt === 'string' && typeof value.actor === 'string' &&
    typeof value.actorRole === 'string' && typeof value.subject === 'string' &&
    typeof value.detail === 'string' &&
    (value.status === 'SUCCESS' || value.status === 'FAILED');
}

function restrictDatabaseFilePermissions(filePath: string): void {
  if (process.platform === 'win32') return;
  for (const file of [filePath, `${filePath}-wal`, `${filePath}-shm`]) {
    if (fs.existsSync(file)) fs.chmodSync(file, 0o600);
  }
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
      CREATE TABLE IF NOT EXISTS activity_audit (
        id TEXT PRIMARY KEY,
        occurred_at TEXT NOT NULL,
        event_type TEXT NOT NULL CHECK (event_type IN ('FILE_DOWNLOADED', 'REALTIME_SCAN')),
        actor TEXT NOT NULL,
        actor_role TEXT NOT NULL,
        source_ip TEXT,
        subject TEXT NOT NULL,
        plan_id TEXT,
        detail TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('SUCCESS', 'FAILED'))
      );
      CREATE INDEX IF NOT EXISTS idx_activity_audit_time
        ON activity_audit (occurred_at DESC, id DESC);
      CREATE INDEX IF NOT EXISTS idx_activity_audit_type
        ON activity_audit (event_type, occurred_at DESC);
      PRAGMA user_version = 1;
    `);
    const columns = db.prepare('PRAGMA table_info(activity_audit)').all() as Array<{ name: string }>;
    if (!columns.some(column => column.name === 'plan_id')) {
      db.exec('ALTER TABLE activity_audit ADD COLUMN plan_id TEXT');
    }
    restrictDatabaseFilePermissions(resolvedPath);
    DATABASES.set(resolvedPath, db);
    return db;
  } catch (error) {
    if (db.open) db.close();
    throw error;
  }
}

/** Baca rekaman aktivitas, terbaru lebih dulu. */
export function readActivityAuditRecords(
  filePath: string,
  options: { limit?: number; eventType?: ActivityAuditEventType } = {}
): { records: ActivityAuditRecord[]; total: number } {
  const db = openDatabase(filePath);
  const limit = Number.isInteger(options.limit) && Number(options.limit) > 0 ? Math.min(Number(options.limit), 500) : 200;
  const where = options.eventType ? 'WHERE event_type = ?' : '';
  const params = options.eventType ? [options.eventType] : [];
  const total = Number((db.prepare(`SELECT COUNT(*) AS count FROM activity_audit ${where}`).get(...params) as { count: number }).count);
  const rows = db.prepare(`SELECT * FROM activity_audit ${where} ORDER BY occurred_at DESC, rowid DESC LIMIT ?`).all(...params, limit) as any[];
  const records = rows.map(row => ({
    id: String(row.id),
    eventType: row.event_type,
    occurredAt: String(row.occurred_at),
    actor: String(row.actor),
    actorRole: String(row.actor_role),
    ...(row.source_ip ? { sourceIp: String(row.source_ip) } : {}),
    subject: String(row.subject),
    ...(row.plan_id ? { planId: String(row.plan_id) } : {}),
    detail: String(row.detail),
    status: row.status
  })) as ActivityAuditRecord[];
  if (records.some(record => !validRecord(record))) {
    throw new Error('Database SQLite aktivitas audit tidak sesuai skema; data tidak ditimpa.');
  }
  return { records, total };
}

/** Tambah satu rekaman aktivitas. Gagal tulis tidak boleh menggagalkan respons utama. */
export function appendActivityAuditRecord(filePath: string, record: ActivityAuditRecord): void {
  if (!validRecord(record)) throw new Error('Rekaman aktivitas audit tidak valid.');
  const db = openDatabase(filePath);
  const append = db.transaction(() => {
    const current = db.prepare('SELECT COUNT(*) AS count FROM activity_audit').get() as { count: number };
    if (Number(current.count) >= MAX_RECORDS) {
      throw new Error(`Database aktivitas audit mencapai batas ${MAX_RECORDS} rekaman; arsipkan database sebelum menambah data.`);
    }
    db.prepare(`
      INSERT OR IGNORE INTO activity_audit (
        id, occurred_at, event_type, actor, actor_role, source_ip, subject, plan_id, detail, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      record.id,
      record.occurredAt,
      record.eventType,
      record.actor,
      record.actorRole,
      record.sourceIp ?? null,
      record.subject,
      record.planId ?? null,
      record.detail,
      record.status
    );
  });
  append.immediate();
  restrictDatabaseFilePermissions(path.resolve(filePath));
}
