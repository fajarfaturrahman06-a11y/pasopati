/**
 * Uji khusus masa berlaku token remediasi (tanpa menunggu 10 menit).
 *
 * 1. Token kedaluwarsa → approve ulang diizinkan dan nonce lama tidak berlaku.
 * 2. Batas waktu evidence habis → verify ditolak 401.
 *
 * Jalankan: node tests/remediation-expiry.mjs
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const API_KEY = 'expiry-api-key';
const HMAC_SECRET = 'expiry-hmac';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const results = [];
// Hindari rentang port yang bisa dieksklusikan Windows/Hyper-V.
const BASE_PORT = 6100 + Math.floor(Math.random() * 300);
function check(name, passed, detail = '') {
  results.push({ name, passed });
  console.log(`${passed ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
}

async function boot(port, env) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pasopati-expiry-'));
  const server = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], {
    cwd: root,
    env: {
      ...process.env,
      NODE_ENV: 'production',
      PORT: String(port),
      PASOPATI_API_KEY: API_KEY,
      HMAC_SECRET,
      PASOPATI_DATA_DIR: dataDir,
      GEMINI_API_KEY: '',
      ...env
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  server.stderr.on('data', () => {});
  server.stdout.on('data', () => {});
  for (let i = 0; i < 80; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/audit-logs`, { headers: { 'X-Pasopati-API-Key': API_KEY } });
      if (res.ok) return { server, dataDir };
    } catch {
      /* belum siap */
    }
    await sleep(250);
  }
  throw new Error('server tidak siap');
}

async function req(port, method, urlPath, body) {
  const raw = body === undefined ? undefined : JSON.stringify(body);
  const headers = { 'Content-Type': 'application/json', 'X-Pasopati-API-Key': API_KEY };
  if (raw !== undefined) {
    headers['X-Pasopati-Signature'] = crypto.createHmac('sha256', HMAC_SECRET).update(raw).digest('hex');
    headers['X-Pasopati-Timestamp'] = String(Math.floor(Date.now() / 1000));
  }
  const res = await fetch(`http://127.0.0.1:${port}${urlPath}`, {
    method,
    headers,
    body: raw
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* non-JSON */
  }
  return { status: res.status, json };
}

async function newPlan(port) {
  const created = await req(port, 'POST', '/api/remediation-plan', {
    deviceId: 'EXPIRY-DEVICE',
    items: [{ alias: 'fw-enable-ufw', risk: 'LOW' }]
  });
  const approved = await req(port, 'POST', '/api/remediation-approve', {
    planId: created.json?.plan?.planId,
    acknowledgeConsole: true,
    selfApprove: true
  });
  return { planId: created.json?.plan?.planId, nonce: approved.json?.nonce };
}

const evidence = [{ stepIndex: 0, alias: 'fw-enable-ufw', exitCode: 0, outputHash: 'sha256:x', verified: true }];
const postAudit = {
  scoring: { cyber_readiness_score: 100, failed_checks: 0 },
  compliance_matrix: [
    { parameter: 'Host-Based Local Firewall Active', status: 'PASS' },
    { parameter: 'Network & Dangerous Ports Filtering', status: 'PASS' }
  ]
};

try {
  // ---- A. token pendek: approve ulang setelah kedaluwarsa harus boleh ----
  {
    const port = BASE_PORT;
    const { server, dataDir } = await boot(port, { REMEDIATION_TOKEN_TTL_MS: '200', REMEDIATION_EVIDENCE_GRACE_MS: '5000' });
    const { planId, nonce } = await newPlan(port);
    await sleep(350);
    const re = await req(port, 'POST', '/api/remediation-approve', { planId, acknowledgeConsole: true, selfApprove: true });
    check('Approve ulang setelah token kedaluwarsa diterima', re.status === 200 && typeof re.json?.nonce === 'string', `status=${re.status}`);
    const newNonce = re.json?.nonce;
    check('Nonce baru berbeda dari nonce lama', Boolean(newNonce) && newNonce !== nonce);
    const staleNonce = await req(port, 'POST', '/api/remediation-verify', { planId, nonce, toStatus: 'VERIFIED', evidence, postAudit });
    check('Nonce lama ditolak setelah re-approve', staleNonce.status === 401, `status=${staleNonce.status}`);
    const freshNonce = await req(port, 'POST', '/api/remediation-verify', { planId, nonce: newNonce, toStatus: 'VERIFIED', evidence, postAudit });
    check('Nonce baru diterima', freshNonce.status === 200, `status=${freshNonce.status}`);
    server.kill('SIGKILL');
    fs.rmSync(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }

  // ---- B. batas evidence pendek: verify setelah batas harus 401 ----
  {
    const port = BASE_PORT + 1;
    const { server, dataDir } = await boot(port, { REMEDIATION_TOKEN_TTL_MS: '100', REMEDIATION_EVIDENCE_GRACE_MS: '200' });
    const { planId, nonce } = await newPlan(port);
    await sleep(400);
    const late = await req(port, 'POST', '/api/remediation-verify', { planId, nonce, toStatus: 'VERIFIED', evidence });
    check('Verify setelah batas evidence ditolak 401', late.status === 401, `status=${late.status}`);
    server.kill('SIGKILL');
    fs.rmSync(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
  // ---- C. mode manual: artefak terikat plan, unduhan tercatat, MANUAL_REPORTED → VERIFIED ----
  {
    const port = BASE_PORT + 2;
    const { server, dataDir } = await boot(port, {});
    const created = await req(port, 'POST', '/api/remediation-plan', {
      deviceId: 'MANUAL-DEVICE',
      executionMode: 'manual',
      items: [{ alias: 'fw-enable-ufw', risk: 'LOW' }],
      artifacts: { hardening: '#!/bin/bash\necho hard\n', rollback: '#!/bin/bash\necho roll\n' }
    });
    const planId = created.json?.plan?.planId;
    check('Plan manual dibuat dengan hash artefak', created.status === 200 && Boolean(created.json?.plan?.artifacts?.hardeningHash), `status=${created.status}`);
    const approved = await req(port, 'POST', '/api/remediation-approve', { planId, acknowledgeConsole: true, selfApprove: true });
    const nonce = approved.json?.nonce;
    const artifact = await fetch(`http://127.0.0.1:${port}/api/remediation-plans/${planId}/artifacts/hardening`, { headers: { 'X-Pasopati-API-Key': API_KEY } });
    const artifactText = await artifact.text();
    check('Artefak resmi dapat diunduh dan hash cocok', artifact.status === 200 && artifactText.includes('echo hard') &&
      artifact.headers.get('x-pasopati-artifact-hash') === created.json?.plan?.artifacts?.hardeningHash, `status=${artifact.status}`);
    const activity = await req(port, 'GET', '/api/admin/activity-audit?type=FILE_DOWNLOADED');
    check('Unduhan artefak tercatat dengan planId', (activity.json?.records || []).some(r => r.planId === planId && String(r.subject).includes(planId)));
    const manualEvidence = [{ stepIndex: 0, alias: 'fw-enable-ufw', exitCode: 0, outputHash: 'sha256:manual', source: 'manual' }];
    const reported = await req(port, 'POST', '/api/remediation-verify', { planId, nonce, toStatus: 'MANUAL_REPORTED', source: 'manual', evidence: manualEvidence });
    check('Laporan manual diterima sebagai MANUAL_REPORTED', reported.status === 200 && reported.json?.planStatus === 'MANUAL_REPORTED', `status=${reported.status}`);
    const verified = await req(port, 'POST', '/api/remediation-verify', { planId, nonce, toStatus: 'VERIFIED', source: 'manual', evidence: manualEvidence, postAudit });
    check('MANUAL_REPORTED naik ke VERIFIED setelah audit ulang', verified.status === 200 && verified.json?.planStatus === 'VERIFIED', `status=${verified.status}`);
    const agentPlan = await req(port, 'POST', '/api/remediation-plan', { deviceId: 'AGENT-DEVICE', items: [{ alias: 'fw-enable-ufw', risk: 'LOW' }] });
    check('Plan mode agent tanpa artefak tetap kompatibel', agentPlan.status === 200 && agentPlan.json?.plan?.executionMode === 'agent');
    server.kill('SIGKILL');
    fs.rmSync(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
} catch (err) {
  check('Uji expiry selesai tanpa exception', false, err?.message || String(err));
}

const failed = results.filter(r => !r.passed);
console.log(`\n${results.length - failed.length}/${results.length} pengujian lolos`);
if (failed.length > 0) process.exit(1);
