/**
 * Smoke test registry endpoint pusat terhadap Express server nyata.
 * Meliputi klien A/B, concurrent writes, HMAC telemetry, idempotency lintas restart,
 * auth, validasi, soft-delete, dan persistensi JSON.
 */
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 3600 + Math.floor(Math.random() * 500);
const BASE = `http://127.0.0.1:${PORT}`;
const API_KEY = 'endpoint-registry-smoke-api-key';
const HMAC_SECRET = 'endpoint-registry-smoke-hmac-secret-0123456789';
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pasopati-endpoints-'));
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
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
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

function sign(rawBody, timestamp) {
  return {
    'X-Pasopati-Signature': crypto.createHmac('sha256', HMAC_SECRET).update(rawBody).digest('hex'),
    'X-Pasopati-Timestamp': String(timestamp),
    'X-Pasopati-Unit': 'AGENT-SMOKE-1'
  };
}

try {
  startServer();
  check('Server registry siap', await waitReady(), serverLog.slice(-1200));

  const competingServer = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], {
    cwd: root,
    env: {
      ...process.env, NODE_ENV: 'production', PORT: String(PORT + 1),
      PASOPATI_API_KEY: API_KEY, HMAC_SECRET, PASOPATI_DATA_DIR: dataDir, AI_DISABLED: '1'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let competingLog = '';
  competingServer.stdout.on('data', chunk => { competingLog += chunk.toString(); });
  competingServer.stderr.on('data', chunk => { competingLog += chunk.toString(); });
  const competingExit = await Promise.race([
    new Promise(resolve => competingServer.once('exit', resolve)),
    new Promise(resolve => setTimeout(() => resolve(null), 5000))
  ]);
  if (competingExit === null) competingServer.kill('SIGKILL');
  check('Proses server kedua ditolak dari DATA_DIR yang sama', competingExit === 1 && /Lock DATA_DIR gagal dipasang/.test(competingLog), `exit=${competingExit}`);

  const unauthorized = await request('GET', '/api/endpoints', { key: '' });
  check('GET registry tanpa API key ditolak', unauthorized.status === 401, `HTTP ${unauthorized.status}`);

  const invalid = await request('POST', '/api/endpoints', { body: { name: 'Bad IP', hostname: 'bad-host', ip: 'not-an-ip' } });
  check('Payload endpoint invalid ditolak', invalid.status === 400, `HTTP ${invalid.status}: ${invalid.data?.reason || ''}`);

  const endpointBody = {
    name: 'Laptop A', hostname: 'laptop-a.example', role: 'Workstation', os: 'Windows 11',
    platformType: 'windows', ip: '192.0.2.10', mac: 'aa:bb:cc:dd:ee:01', user: 'operator', openPorts: [443], checks: []
  };
  const created = await request('POST', '/api/endpoints', { body: endpointBody });
  const endpointId = created.data?.endpoint?.id;
  check('Browser A membuat endpoint ber-ID stabil dan timestamp snake_case',
    created.status === 201 && /^[0-9a-f-]{36}$/i.test(endpointId || '') && Boolean(created.data?.endpoint?.created_at) && Boolean(created.data?.endpoint?.updated_at) && created.data?.endpoint?.revision === 1,
    `HTTP ${created.status}`);

  const viewer = await request('POST', '/api/operators', { body: { name: 'endpoint-smoke-viewer', role: 'viewer' } });
  const viewerKey = viewer.data?.key;
  const viewerRead = await request('GET', '/api/endpoints', { key: viewerKey });
  const viewerCreate = await request('POST', '/api/endpoints', { key: viewerKey, body: { name: 'Forbidden', hostname: 'forbidden.example' } });
  const viewerDelete = await request('DELETE', `/api/endpoints/${endpointId}`, { key: viewerKey });
  check('RBAC viewer dapat membaca, tetapi tidak dapat menambah atau mengarsipkan endpoint',
    Boolean(viewerKey) && viewerRead.status === 200 && viewerCreate.status === 403 && viewerDelete.status === 403,
    `read=${viewerRead.status}, create=${viewerCreate.status}, delete=${viewerDelete.status}`);

  const clientBRead = await request('GET', '/api/endpoints');
  const fromB = clientBRead.data?.endpoints?.find(item => item.id === endpointId);
  check('Browser B membaca endpoint baru dari VPS tanpa refresh server', Boolean(fromB) && fromB.hostname === 'laptop-a.example');

  const initialRevision = fromB?.revision;
  const updated = await request('PUT', `/api/endpoints/${endpointId}`, { body: { name: 'Laptop A — updated', role: 'Admin workstation', expected_revision: initialRevision } });
  const clientARead = await request('GET', '/api/endpoints');
  const fromA = clientARead.data?.endpoints?.find(item => item.id === endpointId);
  check('Perubahan Browser B terlihat oleh Browser A', updated.status === 200 && fromA?.name === 'Laptop A — updated' && fromA?.role === 'Admin workstation' && fromA?.revision === Number(initialRevision) + 1);
  const staleUpdate = await request('PUT', `/api/endpoints/${endpointId}`, { body: { name: 'Stale overwrite', expected_revision: initialRevision } });
  const afterStale = await request('GET', `/api/endpoints/${endpointId}`);
  check('PUT dari revision lama ditolak tanpa menimpa edit terbaru', staleUpdate.status === 409 && afterStale.data?.endpoint?.name === 'Laptop A — updated', `HTTP ${staleUpdate.status}`);

  const concurrentBody = { name: 'Shared Node', hostname: 'shared-node.example', platformType: 'linux', os: 'Debian', ip: '192.0.2.40', mac: 'aa:bb:cc:dd:ee:40' };
  const duplicates = await Promise.all([
    request('POST', '/api/endpoints', { body: concurrentBody }),
    request('POST', '/api/endpoints', { body: concurrentBody })
  ]);
  const duplicateIds = duplicates.map(result => result.data?.endpoint?.id);
  let list = await request('GET', '/api/endpoints');
  const shared = list.data?.endpoints?.filter(item => item.hostname === concurrentBody.hostname) || [];
  check('Dua POST bersamaan untuk identitas sama menghasilkan satu endpoint', duplicateIds[0] && duplicateIds[0] === duplicateIds[1] && shared.length === 1);

  const uniqueConcurrent = await Promise.all([
    request('POST', '/api/endpoints', { body: { name: 'Concurrent 1', hostname: 'concurrent-1.example' } }),
    request('POST', '/api/endpoints', { body: { name: 'Concurrent 2', hostname: 'concurrent-2.example' } })
  ]);
  list = await request('GET', '/api/endpoints');
  const concurrentSaved = ['concurrent-1.example', 'concurrent-2.example'].every(hostname => list.data?.endpoints?.some(item => item.hostname === hostname));
  check('Dua browser POST serentak tidak saling menimpa', uniqueConcurrent.every(result => [200, 201].includes(result.status)) && concurrentSaved);

  const telemetry = {
    metadata: { tactical_unit: 'AGENT-SMOKE-1', standard_baseline: 'CIS v8' },
    device_info: {
      hostname: 'laptop-a.example', os: 'Windows 11 Pro', platform_type: 'Windows Workstation',
      primary_ip: '192.0.2.10', mac_address: 'aa:bb:cc:dd:ee:01', active_user: 'operator', ports_list: [443, 3389]
    },
    scoring: { cyber_readiness_score: 77, passed_checks: 4, warning_checks: 1, failed_checks: 1, total_checks: 6 },
    compliance_matrix: [{ parameter: 'Firewall aktif', category: 'Endpoint Protection', cis_id: 'CIS 4.1', status: 'PASS', details: 'enabled' }]
  };
  const rawTelemetry = JSON.stringify(telemetry);
  const timestamp = Math.floor(Date.now() / 1000);
  const telemetryHeaders = sign(rawTelemetry, timestamp);
  const telemetryResponse = await fetch(`${BASE}/api/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...telemetryHeaders },
    body: rawTelemetry
  });
  const telemetryResult = await telemetryResponse.json().catch(() => null);
  const ingestedEndpointId = telemetryResult?.endpoint_id;
  list = await request('GET', '/api/endpoints');
  const ingestedEndpoint = list.data?.endpoints?.find(item => item.id === endpointId);
  check('Agen HMAC meng-upsert endpoint yang sama berdasarkan MAC', telemetryResponse.status === 200 && ingestedEndpointId === endpointId && ingestedEndpoint?.ip === '192.0.2.10');
  check('Compliance matrix dan score tersimpan di registry endpoint', ingestedEndpoint?.checks?.[0]?.parameter === 'Firewall aktif' && ingestedEndpoint?.history?.at(-1)?.score === 77);

  const beforeRestartLogs = await request('GET', '/api/audit-logs');
  const logsBefore = beforeRestartLogs.data?.logs?.length || 0;
  const inventoryPath = path.join(dataDir, 'endpoint_inventory.json');
  check('File registry permanen dibuat di DATA_DIR', fs.existsSync(inventoryPath));
  await stopServer();

  startServer();
  check('Backend restart berhasil memakai DATA_DIR yang sama', await waitReady(), serverLog.slice(-1200));
  const afterRestart = await request('GET', '/api/endpoints');
  const persisted = afterRestart.data?.endpoints?.find(item => item.id === endpointId);
  check('Data endpoint tetap ada sesudah restart backend', Boolean(persisted) && persisted.name === 'Laptop A — updated' && persisted.history?.at(-1)?.score === 77);

  // Replay request identical setelah restart tidak menambah point history/log baru.
  const replayResponse = await fetch(`${BASE}/api/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...telemetryHeaders },
    body: rawTelemetry
  });
  const afterReplayList = await request('GET', '/api/endpoints');
  const afterReplayEndpoint = afterReplayList.data?.endpoints?.find(item => item.id === endpointId);
  const afterReplayLogs = await request('GET', '/api/audit-logs');
  check('Replay lintas restart idempotent untuk endpoint, revision, dan audit', replayResponse.status === 200 && afterReplayEndpoint?.history?.length === 1 && afterReplayEndpoint?.revision === persisted?.revision && (afterReplayLogs.data?.logs?.length || 0) === logsBefore);

  const removed = await request('DELETE', `/api/endpoints/${endpointId}`);
  const detailAfterDelete = await request('GET', `/api/endpoints/${endpointId}`);
  const archived = JSON.parse(fs.readFileSync(inventoryPath, 'utf-8')).find(item => item.id === endpointId);
  check('Delete admin mengarsipkan endpoint dan mempertahankan riwayat', removed.status === 200 && detailAfterDelete.status === 404 && Boolean(archived?.deletedAt) && archived.history.length === 1);

  console.log(`\n${results.length}/${results.length} integration checks passed`);
} catch (error) {
  console.error('\nEndpoint registry smoke test failed:', error?.stack || error);
  if (serverLog) console.error('\nServer log (tail):\n' + serverLog.split('\n').slice(-35).join('\n'));
  process.exitCode = 1;
} finally {
  await stopServer();
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* cleanup best effort */ }
}
