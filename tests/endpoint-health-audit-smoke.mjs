import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 4100 + Math.floor(Math.random() * 300);
const BASE = `http://127.0.0.1:${PORT}`;
const API_KEY = 'endpoint-health-audit-smoke-admin-key';
const HMAC_SECRET = 'endpoint-health-audit-smoke-hmac-secret-0123456789';
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pasopati-health-audit-'));
const sqlitePath = path.join(dataDir, 'endpoint_health_audit.sqlite');
const legacyJsonPath = path.join(dataDir, 'endpoint_health_audit.json');
const legacySeed = {
  id: 'LEGACY-HEALTH-ACCESS-1', eventType: 'ENDPOINT_ACCESSED', occurredAt: '2026-10-01T00:00:00.000Z', accessedBy: 'legacy-admin',
  target: { endpointId: 'LEGACY-ENDPOINT-1', name: 'Legacy Test Endpoint', hostname: 'legacy.test.local', role: 'Workstation', os: 'Linux', endpointUser: 'legacy-user', ip: '192.0.2.12', mac: 'aa:bb:cc:dd:ee:12' },
  computerCondition: { capturedAt: '2026-10-01T00:00:00.000Z', captureStatus: 'CAPTURED', latestAuditAt: null, score: 91, passCount: 9, warningCount: 0, failCount: 0, totalChecks: 9, quarantined: false, openPorts: [443], failedControls: [], warningControls: [] }
};
fs.writeFileSync(legacyJsonPath, JSON.stringify([legacySeed]), { encoding: 'utf-8', mode: 0o600 });
const legacyJsonBefore = fs.readFileSync(legacyJsonPath);
const results = [];
let server;
let serverLog = '';

function check(name, passed, detail = '') {
  results.push({ name, passed });
  console.log(`${passed ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  if (!passed) throw new Error(`${name}: ${detail}`);
}

function startServer() {
  serverLog = '';
  server = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], {
    cwd: root,
    env: {
      ...process.env,
      NODE_ENV: 'production',
      PORT: String(PORT),
      PASOPATI_API_KEY: API_KEY,
      HMAC_SECRET,
      PASOPATI_DATA_DIR: dataDir,
      AI_DISABLED: '1',
      GEMINI_API_KEY: ''
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  server.stdout.on('data', chunk => { serverLog += chunk.toString(); });
  server.stderr.on('data', chunk => { serverLog += chunk.toString(); });
}

async function waitReady(timeoutMs = 30000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(`${BASE}/api/endpoints`, { headers: { 'X-Pasopati-API-Key': API_KEY } });
      if (response.ok) return true;
    } catch { /* server still starting */ }
    if (server?.exitCode !== null) break;
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  return false;
}

async function stopServer() {
  if (!server || server.exitCode !== null) return;
  server.kill('SIGTERM');
  await Promise.race([
    new Promise(resolve => server.once('exit', resolve)),
    new Promise(resolve => setTimeout(resolve, 5000))
  ]);
  if (server.exitCode === null) server.kill('SIGKILL');
}

async function request(method, endpoint, { body, key = API_KEY, headers = {} } = {}) {
  const response = await fetch(BASE + endpoint, {
    method,
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(key ? { 'X-Pasopati-API-Key': key } : {}),
      ...headers
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {})
  });
  const data = await response.json().catch(() => null);
  return { status: response.status, data };
}

try {
  startServer();
  check('Server siap', await waitReady(), serverLog.slice(-1000));

  const noKey = await request('GET', '/api/admin/endpoint-health-audit', { key: '' });
  check('GET audit baru tanpa kredensial ditolak', noKey.status === 401, `HTTP ${noKey.status}`);

  const viewerCreated = await request('POST', '/api/operators', { body: { name: 'health-audit-viewer', role: 'viewer' } });
  const viewerKey = viewerCreated.data?.key;
  const viewerRead = await request('GET', '/api/admin/endpoint-health-audit', { key: viewerKey });
  const viewerWrite = await request('POST', '/api/admin/endpoint-health-audit/access', { key: viewerKey, body: { endpointId: 'not-yet-created' } });
  check('Fitur audit baru hanya dapat dibaca dan ditulis administrator',
    viewerCreated.status === 200 && viewerRead.status === 403 && viewerWrite.status === 403,
    `create=${viewerCreated.status}, read=${viewerRead.status}, write=${viewerWrite.status}`);

  const created = await request('POST', '/api/endpoints', {
    body: {
      name: 'Audit Test Laptop', hostname: 'audit-test-laptop.local', role: 'Workstation',
      os: 'Windows 11', platformType: 'windows', ip: '192.0.2.55', mac: 'aa:bb:cc:dd:ee:55',
      user: 'endpoint-user-1', openPorts: [443, 3389],
      checks: [
        { id: 'fw', parameter: 'Firewall aktif', category: 'Endpoint Protection', status: 'FAIL', details: 'disabled' },
        { id: 'log', parameter: 'System logging', category: 'System Logging', status: 'WARNING', details: 'partial' }
      ],
      history: [{ timestamp: new Date().toISOString(), score: 73, passCount: 4, warnCount: 1, failCount: 1, event: 'Smoke test' }]
    }
  });
  const endpointId = created.data?.endpoint?.id;
  check('Endpoint uji tersimpan di registry', created.status === 201 && Boolean(endpointId), `HTTP ${created.status}`);

  const oldAuditBefore = await request('GET', '/api/audit-logs');
  const oldCountBefore = oldAuditBefore.data?.logs?.length;
  const access = await request('POST', '/api/admin/endpoint-health-audit/access', {
    body: { endpointId, accessedBy: 'forged-user', computerCondition: { score: 0 } }
  });
  check('Akses admin menyimpan snapshot server-side, bukan identitas/kondisi dari body',
    access.status === 201 && access.data?.record?.accessedBy === 'master' &&
      access.data?.record?.target?.endpointUser === 'endpoint-user-1' &&
      access.data?.record?.computerCondition?.score === 73 &&
      access.data?.record?.computerCondition?.failCount === 1 &&
      access.data?.record?.computerCondition?.failedControls?.[0] === 'Firewall aktif',
    `HTTP ${access.status}`);

  const planCreated = await request('POST', '/api/remediation-plan', {
    body: { deviceId: endpointId, items: [{ alias: 'rdp-nla-enable', risk: 'MEDIUM' }] }
  });
  const approval = await request('POST', '/api/remediation-approve', {
    body: { planId: planCreated.data?.plan?.planId, selfApprove: true, acknowledgeConsole: true }
  });
  check('Persetujuan remediasi sukses dicatat terpisah dengan approver tepercaya',
    planCreated.status === 200 && approval.status === 200 && approval.data?.plan?.approvedBy === 'master',
    `plan=${planCreated.status}, approval=${approval.status}`);

  const linkedAccess = await request('POST', '/api/admin/endpoint-health-audit/access', { body: { endpointId } });
  check('Snapshot akses berikutnya ikut mencatat approval terakhir endpoint',
    linkedAccess.status === 201 && linkedAccess.data?.record?.approvedBy === 'master' &&
      linkedAccess.data?.record?.planId === planCreated.data?.plan?.planId,
    `HTTP ${linkedAccess.status}`);

  const records = await request('GET', '/api/admin/endpoint-health-audit?limit=50');
  const accessRecord = records.data?.records?.find(record => record.eventType === 'ENDPOINT_ACCESSED' && record.planId === planCreated.data?.plan?.planId);
  const approvalRecord = records.data?.records?.find(record => record.eventType === 'REMEDIATION_APPROVED');
  check('Database audit terpisah berisi rekaman akses dan approval beserta user/kondisi',
    records.status === 200 && records.data?.total === 4 && records.data?.database === 'endpoint_health_audit.sqlite' &&
      accessRecord?.accessedBy === 'master' && accessRecord?.approvedBy === 'master' && accessRecord?.target?.endpointUser === 'endpoint-user-1' &&
      approvalRecord?.approvedBy === 'master' && approvalRecord?.planId === planCreated.data?.plan?.planId &&
      approvalRecord?.computerCondition?.score === 73 &&
      records.data?.records?.some(record => record.id === legacySeed.id && record.accessedBy === 'legacy-admin'),
    `HTTP ${records.status}, total=${records.data?.total}`);

  const auditPath = path.join(dataDir, 'audit_logs.json');
  const sqliteDb = new Database(sqlitePath, { readonly: true, fileMustExist: true });
  const sqliteTotal = Number(sqliteDb.prepare('SELECT COUNT(*) AS count FROM endpoint_health_audit').get().count);
  const migrationMarker = sqliteDb.prepare('SELECT value FROM schema_meta WHERE key = ?').get('legacy_json_imported')?.value;
  const journalMode = String(sqliteDb.pragma('journal_mode', { simple: true })).toLowerCase();
  sqliteDb.close();
  const sqliteHeader = fs.readFileSync(sqlitePath).subarray(0, 16).toString('binary');
  const sqlitePermissionsOk = process.platform === 'win32' || (fs.statSync(sqlitePath).mode & 0o077) === 0;
  check('Database fitur baru adalah SQLite WAL, migrasi satu kali, dan tetap terpisah dari Audit Log JSON',
    fs.existsSync(sqlitePath) && sqliteHeader === 'SQLite format 3\u0000' && sqliteTotal === 4 &&
      migrationMarker === '1' && journalMode === 'wal' && sqlitePermissionsOk &&
      fs.existsSync(legacyJsonPath) && fs.readFileSync(legacyJsonPath).equals(legacyJsonBefore) && fs.existsSync(auditPath),
    `SQLite=${sqliteTotal}, journal=${journalMode}, migrated=${migrationMarker}`);

  const oldAuditAfter = await request('GET', '/api/audit-logs');
  const oldVerify = await request('GET', '/api/audit-logs/verify');
  check('Aksi fitur baru tidak menambah/mengubah Audit Log lama dan hash chain tetap valid',
    oldAuditAfter.status === 200 && oldAuditAfter.data?.logs?.length === oldCountBefore && oldVerify.data?.chainOk === true,
    `old=${oldCountBefore}→${oldAuditAfter.data?.logs?.length}, chainOk=${oldVerify.data?.chainOk}`);

  await stopServer();
  startServer();
  check('Server restart memakai direktori data yang sama', await waitReady(), serverLog.slice(-1000));
  const afterRestart = await request('GET', '/api/admin/endpoint-health-audit?limit=50');
  check('Rekaman audit endpoint tetap tersedia setelah restart backend',
    afterRestart.status === 200 && afterRestart.data?.total === 4 &&
      afterRestart.data?.records?.some(record => record.eventType === 'REMEDIATION_APPROVED'),
    `HTTP ${afterRestart.status}, total=${afterRestart.data?.total}`);

  console.log(`\n${results.length}/${results.length} endpoint-health audit checks passed`);
} catch (error) {
  console.error('\nEndpoint-health audit smoke test failed:', error?.stack || error);
  if (serverLog) console.error('\nServer log (tail):\n' + serverLog.split('\n').slice(-35).join('\n'));
  process.exitCode = 1;
} finally {
  await stopServer();
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* cleanup best effort */ }
}
