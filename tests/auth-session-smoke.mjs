import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 4300 + Math.floor(Math.random() * 500);
const BASE = `http://127.0.0.1:${PORT}`;
const API_KEY = crypto.randomBytes(32).toString('hex');
const ADMIN_USERNAME = 'smoke-admin';
const ADMIN_PASSWORD = crypto.randomBytes(32).toString('base64url');
const VIEWER_USERNAME = 'smoke-viewer';
const VIEWER_PASSWORD = crypto.randomBytes(32).toString('base64url');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pasopati-auth-session-'));
const authDbPath = path.join(dataDir, 'auth.sqlite');
let server;
let serverLog = '';
const results = [];

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
      NODE_ENV: 'development',
      PORT: String(PORT),
      PASOPATI_API_KEY: API_KEY,
      PASOPATI_ADMIN_USERNAME: ADMIN_USERNAME,
      PASOPATI_ADMIN_PASSWORD: ADMIN_PASSWORD,
      HMAC_SECRET: crypto.randomBytes(32).toString('hex'),
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
    } catch { /* server starting */ }
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

async function request(method, endpoint, { body, cookie = '', headers = {} } = {}) {
  const response = await fetch(BASE + endpoint, {
    method,
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
      ...headers
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {})
  });
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  return { response, data };
}

async function login(username, password) {
  const result = await request('POST', '/api/auth/login', {
    body: { username, password },
    headers: { Origin: BASE }
  });
  const setCookie = result.response.headers.get('set-cookie') || '';
  const token = setCookie.match(/pasopati_session=([^;]+)/)?.[1] || '';
  return { ...result, setCookie, token, cookie: token ? `pasopati_session=${token}` : '' };
}

try {
  startServer();
  check('Server auth smoke siap', await waitReady(), serverLog.slice(-1200));

  const noCreds = await request('GET', '/api/endpoints');
  check('Endpoint dilindungi tanpa cookie/API key', noCreds.response.status === 401, `HTTP ${noCreds.response.status}`);

  const noOrigin = await request('POST', '/api/auth/login', { body: { username: ADMIN_USERNAME, password: ADMIN_PASSWORD } });
  check('Login ditolak bila Origin hilang', noOrigin.response.status === 403, `HTTP ${noOrigin.response.status}`);

  const badLogin = await login(ADMIN_USERNAME, crypto.randomBytes(16).toString('base64url'));
  check('Username/password salah ditolak', badLogin.response.status === 401 && !badLogin.token, `HTTP ${badLogin.response.status}`);

  const admin = await login(ADMIN_USERNAME, ADMIN_PASSWORD);
  check('Admin bootstrap dapat login', admin.response.status === 200 && admin.data?.role === 'admin' && Boolean(admin.token), `HTTP ${admin.response.status}`);
  check('Cookie memiliki atribut HttpOnly dan SameSite=Lax', /HttpOnly/i.test(admin.setCookie) && /SameSite=Lax/i.test(admin.setCookie), admin.setCookie.replace(/pasopati_session=[^;]+/, 'pasopati_session=[redacted]'));
  check('Token sesi tidak dikirim di body JSON', !JSON.stringify(admin.data).includes(admin.token), JSON.stringify(admin.data));

  const whoAdmin = await request('GET', '/api/whoami', { cookie: admin.cookie });
  check('Sesi cookie diterima oleh API backend/RBAC', whoAdmin.response.status === 200 && whoAdmin.data?.role === 'admin' && whoAdmin.data?.kind === 'session', `HTTP ${whoAdmin.response.status}`);

  const createViewer = await request('POST', '/api/auth/users', {
    cookie: admin.cookie,
    body: { username: VIEWER_USERNAME, password: VIEWER_PASSWORD },
    headers: { Origin: BASE }
  });
  check('Admin membuat akun viewer username/password', createViewer.response.status === 201 && createViewer.data?.role === 'viewer', `HTTP ${createViewer.response.status}`);

  const tooShort = await request('POST', '/api/auth/users', {
    cookie: admin.cookie,
    body: { username: 'short-pass', password: crypto.randomBytes(2).toString('hex') },
    headers: { Origin: BASE }
  });
  check('Password di bawah batas minimum ditolak', tooShort.response.status === 400, `HTTP ${tooShort.response.status}`);

  const duplicate = await request('POST', '/api/auth/users', {
    cookie: admin.cookie,
    body: { username: VIEWER_USERNAME, password: VIEWER_PASSWORD },
    headers: { Origin: BASE }
  });
  check('Username duplikat ditolak', duplicate.response.status === 409, `HTTP ${duplicate.response.status}`);

  const csrf = await request('POST', '/api/auth/users', {
    cookie: admin.cookie,
    body: { username: 'csrf-check-viewer', password: VIEWER_PASSWORD }
  });
  check('Perubahan cookie-session tanpa Origin ditolak (CSRF)', csrf.response.status === 403, `HTTP ${csrf.response.status}`);

  const viewer = await login(VIEWER_USERNAME, VIEWER_PASSWORD);
  check('Viewer dapat login memakai akun lokal', viewer.response.status === 200 && viewer.data?.role === 'viewer', `HTTP ${viewer.response.status}`);
  const viewerEndpoints = await request('GET', '/api/endpoints', { cookie: viewer.cookie });
  check('Viewer dapat membaca endpoint pusat', viewerEndpoints.response.status === 200, `HTTP ${viewerEndpoints.response.status}`);
  const viewerAudit = await request('GET', '/api/admin/endpoint-health-audit', { cookie: viewer.cookie });
  check('Audit Akses & Kondisi Endpoint tetap admin-only', viewerAudit.response.status === 403, `HTTP ${viewerAudit.response.status}`);
  const viewerWrite = await request('POST', '/api/endpoints', {
    cookie: viewer.cookie,
    body: { name: 'auth-viewer-write', hostname: 'auth-viewer.local', platformType: 'linux', checks: [] },
    headers: { Origin: BASE }
  });
  check('Viewer dapat menambah endpoint (kebutuhan upload hasil audit)', viewerWrite.response.status === 201, `HTTP ${viewerWrite.response.status}`);
  const viewerEndpointId = viewerWrite.data?.endpoint?.id;
  const viewerUpdate = await request('PUT', `/api/endpoints/${viewerEndpointId}`, {
    cookie: viewer.cookie,
    body: { role: 'viewer-updated', expected_revision: viewerWrite.data?.endpoint?.revision },
    headers: { Origin: BASE }
  });
  const viewerDelete = await request('DELETE', `/api/endpoints/${viewerEndpointId}`, { cookie: viewer.cookie, headers: { Origin: BASE } });
  check('Viewer dapat mengubah tetapi tidak menghapus endpoint', viewerUpdate.response.status === 200 && viewerDelete.response.status === 403,
    `update=${viewerUpdate.response.status}, delete=${viewerDelete.response.status}`);

  const auditAdmin = await request('GET', '/api/admin/endpoint-health-audit', { cookie: admin.cookie });
  check('Audit endpoint terpisah masih dapat dibuka oleh admin', auditAdmin.response.status === 200, `HTTP ${auditAdmin.response.status}`);

  const db = new Database(authDbPath, { readonly: true });
  const users = db.prepare('SELECT username, role, password_hash FROM auth_users ORDER BY username').all();
  const sessions = db.prepare('SELECT token_hash FROM auth_sessions').all();
  const adminRecord = users.find(row => row.username.toLowerCase() === ADMIN_USERNAME);
  const adminTokenHash = crypto.createHash('sha256').update(admin.token).digest('hex');
  check('Password tersimpan sebagai hash scrypt, bukan plaintext', Boolean(adminRecord?.password_hash.startsWith('scrypt$')) && !users.some(row => row.password_hash === ADMIN_PASSWORD || row.password_hash === VIEWER_PASSWORD), `users=${users.length}`);
  check('Database menyimpan hash token sesi, bukan token mentah', sessions.some(row => row.token_hash === adminTokenHash) && !sessions.some(row => row.token_hash === admin.token), `sessions=${sessions.length}`);
  db.close();

  const legacy = await request('GET', '/api/endpoints', { headers: { 'X-Pasopati-API-Key': API_KEY } });
  check('Autentikasi API key lama tetap berfungsi untuk integrasi', legacy.response.status === 200, `HTTP ${legacy.response.status}`);

  await stopServer();
  startServer();
  check('Server hidup kembali memakai direktori data yang sama', await waitReady(), serverLog.slice(-1200));
  const persisted = await request('GET', '/api/auth/session', { cookie: admin.cookie });
  check('Sesi dan akun persisten setelah restart backend', persisted.response.status === 200 && persisted.data?.authenticated === true && persisted.data?.role === 'admin', `HTTP ${persisted.response.status}`);
  const viewerAfterRestart = await login(VIEWER_USERNAME, VIEWER_PASSWORD);
  check('Kredensial viewer tetap berlaku setelah restart', viewerAfterRestart.response.status === 200 && viewerAfterRestart.data?.role === 'viewer', `HTTP ${viewerAfterRestart.response.status}`);

  const loggedOut = await request('POST', '/api/auth/logout', { cookie: admin.cookie, headers: { Origin: BASE } });
  const afterLogout = await request('GET', '/api/endpoints', { cookie: admin.cookie });
  check('Logout mencabut sesi di server', loggedOut.response.status === 204 && afterLogout.response.status === 401, `logout=${loggedOut.response.status}, follow-up=${afterLogout.response.status}`);

  console.log(`\nAuth session smoke tests: ${results.filter(result => result.passed).length}/${results.length} passed.`);
} catch (error) {
  console.error(error);
  console.error(serverLog.slice(-6000));
  process.exitCode = 1;
} finally {
  await stopServer();
  fs.rmSync(dataDir, { recursive: true, force: true });
}
