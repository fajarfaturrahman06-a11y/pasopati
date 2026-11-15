/**
 * Smoke test kontrol plane PASOPATI (tanpa browser, tanpa agent).
 *
 * Yang diuji benar-benar dijalankan terhadap server Express sungguhan:
 *  - HMAC ingest: tolak tanpa signature, tolak signature salah, tolak timestamp kedaluwarsa, terima yang valid
 *  - Remediation: tolak alias di luar allowlist, tolak nonce salah, tolak replay, redaksi token di GET
 *  - Gate API key pada endpoint operasional
 *
 * Jalankan: npm run test:smoke
 */
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 3200 + Math.floor(Math.random() * 300);
const BASE = `http://127.0.0.1:${PORT}`;
const API_KEY = 'smoke-test-api-key';
const HMAC_SECRET = 'smoke-test-hmac-secret-0123456789abcdef';
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pasopati-smoke-'));
const PYTHON = process.platform === 'win32' ? 'python' : 'python3';

/** Jalankan potongan Python yang menulis hasil JSON ke file (hindari masalah encoding stdout Windows). */
function runPython(code, outFile, args = []) {
  const res = spawnSync(PYTHON, ['-c', code, ...args], { cwd: root, encoding: 'utf-8' });
  if (res.error || res.status !== 0) {
    throw new Error(`Python gagal: ${res.error?.message || res.stderr || res.status}`);
  }
  return JSON.parse(fs.readFileSync(outFile, 'utf-8'));
}

const results = [];
function check(name, passed, detail = '') {
  results.push({ name, passed, detail });
  console.log(`${passed ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
}

async function req(method, urlPath, { body, key, headers = {}, signed = false } = {}) {
  const payload = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
  const sig = signed && payload !== undefined ? sign(payload, HMAC_SECRET) : null;
  const res = await fetch(BASE + urlPath, {
    method,
    headers: {
      ...(payload !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(key ? { 'X-Pasopati-API-Key': key } : {}),
      ...(sig ? { 'X-Pasopati-Signature': sig.signature, 'X-Pasopati-Timestamp': sig.timestamp } : {}),
      ...headers
    },
    body: payload
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* non-JSON response */
  }
  return { status: res.status, json };
}

function sign(rawBody, secret, timestamp = Math.floor(Date.now() / 1000)) {
  return {
    signature: crypto.createHmac('sha256', secret).update(rawBody).digest('hex'),
    timestamp: String(timestamp)
  };
}

const server = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], {
  cwd: root,
  env: {
    ...process.env,
    NODE_ENV: 'production',
    PORT: String(PORT),
    PASOPATI_API_KEY: API_KEY,
    HMAC_SECRET: HMAC_SECRET,
    PASOPATI_DATA_DIR: dataDir,
    GEMINI_API_KEY: '',
    AI_DISABLED: '1'
  },
  stdio: ['ignore', 'pipe', 'pipe']
});
let serverLog = '';
server.stdout.on('data', d => (serverLog += d.toString()));
server.stderr.on('data', d => (serverLog += d.toString()));

async function waitForReady(timeoutMs = 30000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(BASE + '/api/audit-logs', { headers: { 'X-Pasopati-API-Key': API_KEY } });
      if (res.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise(r => setTimeout(r, 250));
  }
  return false;
}

try {
  if (!(await waitForReady())) {
    console.error('Server tidak siap. Log:\n' + serverLog);
    process.exit(1);
  }

  // ---------- 1. Endpoint operasional wajib API key ----------
  const noKey = await req('GET', '/api/audit-logs');
  check('GET /api/audit-logs tanpa API key ditolak 401', noKey.status === 401, `status=${noKey.status}`);

  // ---------- 2. HMAC ingest ----------
  const payload = JSON.stringify({
    metadata: { tactical_unit: 'SMOKE-UNIT' },
    scoring: { cyber_readiness_score: 71, passed_checks: 7, warning_checks: 1, failed_checks: 2 }
  });

  const noSig = await req('POST', '/api/ingest', { body: payload });
  check('Ingest tanpa signature ditolak 401', noSig.status === 401, `status=${noSig.status}`);

  const badSig = sign(payload, 'secret-yang-salah');
  const tampered = await req('POST', '/api/ingest', {
    body: payload,
    headers: { 'X-Pasopati-Signature': badSig.signature, 'X-Pasopati-Timestamp': badSig.timestamp }
  });
  check('Ingest dengan signature salah ditolak 401', tampered.status === 401, `status=${tampered.status}`);

  const stale = sign(payload, HMAC_SECRET, Math.floor(Date.now() / 1000) - 3600);
  const replay = await req('POST', '/api/ingest', {
    body: payload,
    headers: { 'X-Pasopati-Signature': stale.signature, 'X-Pasopati-Timestamp': stale.timestamp }
  });
  check('Ingest dengan timestamp kedaluwarsa ditolak 401', replay.status === 401, `status=${replay.status}`);

  const good = sign(payload, HMAC_SECRET);
  const accepted = await req('POST', '/api/ingest', {
    body: payload,
    headers: { 'X-Pasopati-Signature': good.signature, 'X-Pasopati-Timestamp': good.timestamp }
  });
  check(
    'Ingest dengan HMAC valid diterima & signature_verified=true',
    accepted.status === 200 && accepted.json?.signature_verified === true,
    `status=${accepted.status}`
  );

  const replayed = await req('POST', '/api/ingest', {
    body: payload,
    headers: { 'X-Pasopati-Signature': good.signature, 'X-Pasopati-Timestamp': good.timestamp }
  });
  check('Replay body bertanda tangan identik ditolak 401', replayed.status === 401, `status=${replayed.status}`);

  // ---------- 2b. Interop: body yang ditandatangani agent Python harus diterima server ----------
  const pyIn = path.join(dataDir, 'py-ingest.json');
  const pySignCode = `
import json, hmac, hashlib, time, sys
payload = {"metadata": {"tactical_unit": "UNIT-UJI-Ñ"}, "scoring": {"cyber_readiness_score": 88, "passed_checks": 9, "warning_checks": 0, "failed_checks": 1}}
body = json.dumps(payload, sort_keys=True, ensure_ascii=False)
sig = hmac.new(sys.argv[1].encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps({"body": body, "signature": sig, "timestamp": str(int(time.time()))}, ensure_ascii=False))
`;
  const signedByPython = runPython(pySignCode, pyIn, [HMAC_SECRET, pyIn]);
  const pyIngest = await req('POST', '/api/ingest', {
    body: signedByPython.body,
    headers: { 'X-Pasopati-Signature': signedByPython.signature, 'X-Pasopati-Timestamp': signedByPython.timestamp }
  });
  check(
    'Interop HMAC: signature dari agent Python diterima server',
    pyIngest.status === 200 && pyIngest.json?.signature_verified === true,
    `status=${pyIngest.status}`
  );

  // ---------- 2c. Unit null-prototype (__proto__ / constructor) ----------
  for (const unitName of ['__proto__', 'constructor']) {
    const raw = JSON.stringify({ metadata: { tactical_unit: unitName }, scoring: { cyber_readiness_score: 50 } });
    const sg = sign(raw, HMAC_SECRET);
    const r = await req('POST', '/api/ingest', {
      body: raw,
      headers: { 'X-Pasopati-Signature': sg.signature, 'X-Pasopati-Timestamp': sg.timestamp }
    });
    check(`Ingest unit ${unitName} tidak 500`, r.status === 200, `status=${r.status}`);
  }
  const protoDrift = await req('GET', '/api/compliance-drift/__proto__', { key: API_KEY });
  check('Compliance drift __proto__ mengembalikan array', Array.isArray(protoDrift.json?.history), JSON.stringify(protoDrift.json));

  const listed = await req('GET', '/api/audit-logs', { key: API_KEY });
  const endpointsAfterIngest = await req('GET', '/api/endpoints', { key: API_KEY });
  const ingestedEndpoint = (endpointsAfterIngest.json?.endpoints || []).find(item => item.agentId === 'UNIT-UJI-Ñ');
  const ingestedLog = (listed.json?.logs || []).find(l => l.deviceId === ingestedEndpoint?.id);
  check(
    'Telemetri tersimpan sebagai endpoint pusat dan audit log memakai ID endpoint stabil',
    listed.status === 200 && Boolean(ingestedEndpoint) && Boolean(ingestedLog) && ingestedLog?.action === 'TELEMETRY INGESTION',
    `logs=${(listed.json?.logs || []).length}`
  );

  // ---------- 3. Remediation plan: allowlist ----------
  const badAlias = await req('POST', '/api/remediation-plan', {
    key: API_KEY,
    body: { deviceId: 'SMOKE-DEVICE', items: [{ alias: 'rm-rf-everything', risk: 'HIGH' }] }
  });
  check('Plan dengan alias di luar allowlist ditolak 400', badAlias.status === 400, `status=${badAlias.status}`);

  const created = await req('POST', '/api/remediation-plan', {
    key: API_KEY,
    body: { deviceId: 'SMOKE-DEVICE', items: [{ alias: 'fw-enable-ufw', risk: 'LOW' }], createdBy: 'smoke' }
  });
  const planId = created.json?.plan?.planId;
  check('Plan valid dibuat (status PLANNED)', created.status === 200 && created.json?.plan?.status === 'PLANNED', `planId=${planId}`);

  // ---------- 4. Approve: token sekali terbit + gate konfirmasi jalur akses ----------
  const approveNoAck = await req('POST', '/api/remediation-approve', { key: API_KEY, body: { selfApprove: true, planId, approvedBy: 'smoke' } });
  check(
    'Plan berisiko akses ditolak 409 tanpa acknowledgeConsole',
    approveNoAck.status === 409 && approveNoAck.json?.requiresConsoleAck === true && Array.isArray(approveNoAck.json?.accessNotes),
    `status=${approveNoAck.status}`
  );
  const approved = await req('POST', '/api/remediation-approve', {
    key: API_KEY, body: { selfApprove: true, planId, approvedBy: 'smoke', acknowledgeConsole: true }
  });
  const nonce = approved.json?.nonce;
  const signature = approved.json?.signature;
  check(
    'Approve menerbitkan nonce + signature + expiry',
    approved.status === 200 && typeof nonce === 'string' && typeof signature === 'string' && Number.isFinite(approved.json?.expiresAt),
    `status=${approved.status}`
  );

  // ---------- 4b. Interop: token dari server harus lolos validasi agent Python ----------
  const token = approved.json?.token;
  const planPath = path.join(dataDir, 'plan-for-agent.json');
  fs.writeFileSync(planPath, JSON.stringify(approved.json?.plan), 'utf-8');
  const pyValidateCode = `
import json, sys
import pasopati_audit as agent
plan = json.load(open(sys.argv[1], encoding="utf-8"))
result = {}
for label, token in (("valid", sys.argv[2]), ("tampered", sys.argv[2][:-1] + ("0" if sys.argv[2][-1] != "0" else "1"))):
    ok, msg = agent._validate_remediation_token(plan, token, sys.argv[3])
    result[label] = {"ok": ok, "msg": msg}
open(sys.argv[4], "w", encoding="utf-8").write(json.dumps(result))
`;
  const tokenOut = path.join(dataDir, 'py-token.json');
  const pyToken = runPython(pyValidateCode, tokenOut, [planPath, token, HMAC_SECRET, tokenOut]);
  check('Interop token: agent Python menerima token dari server', pyToken.valid?.ok === true, pyToken.valid?.msg || '');
  check('Interop token: agent Python menolak token yang diubah', pyToken.tampered?.ok === false, pyToken.tampered?.msg || '');

  const wrongNonce = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { selfApprove: true, planId, nonce: 'deadbeef', toStatus: 'EXECUTING', evidence: [] }
  });
  check('Verify dengan nonce salah ditolak 401', wrongNonce.status === 401, `status=${wrongNonce.status}`);

  const evidence = [{ stepIndex: 0, alias: 'fw-enable-ufw', exitCode: 0, outputHash: 'sha256:smoke', verified: true }];
  // Matriks audit ulang: parameter plan harus berstatus bukan-FAIL.
  const postAuditClean = (status = 'PASS') => ({
    scoring: { cyber_readiness_score: status === 'PASS' ? 100 : 50, failed_checks: status === 'PASS' ? 0 : 1 },
    compliance_matrix: [
      { parameter: 'Network & Dangerous Ports Filtering', status },
      { parameter: 'Host-Based Local Firewall Active', status },
      { parameter: 'SSH Root Login & Auth', status },
      { parameter: 'Auditd Daemon Security Logging', status },
      { parameter: 'Full Disk Encryption (LUKS)', status },
      { parameter: 'USB Mass Storage Restriction', status },
      { parameter: 'Sudoers Privilege Boundary & NOPASSWD', status },
      { parameter: 'SUID Binary Escalation Vector Scan', status }
    ]
  });
  const executing = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { selfApprove: true, planId, nonce, toStatus: 'EXECUTING', evidence }
  });
  check('Verify EXECUTING diterima', executing.status === 200 && executing.json?.planStatus === 'EXECUTING', `status=${executing.status}`);

  // ---------- 4b2. Server menilai kelengkapan evidence, bukan percaya agent ----------
  const partialVerify = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { selfApprove: true, planId, nonce, toStatus: 'VERIFIED', evidence: [] }
  });
  check('VERIFIED tanpa evidence ditolak 400', partialVerify.status === 400, `status=${partialVerify.status}`);

  const dupStep = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: {
      planId, nonce, toStatus: 'VERIFIED',
      evidence: [
        { stepIndex: 0, alias: 'fw-enable-ufw', exitCode: 0, outputHash: 'sha256:a', verified: true },
        { stepIndex: 0, alias: 'fw-enable-ufw', exitCode: 0, outputHash: 'sha256:a', verified: true }
      ]
    }
  });
  check('Evidence dengan stepIndex duplikat ditolak 400', dupStep.status === 400, `status=${dupStep.status}`);

  const badExit = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { selfApprove: true, planId, nonce, toStatus: 'VERIFIED', evidence: [{ stepIndex: 0, alias: 'fw-enable-ufw', exitCode: 1, outputHash: 'sha256:a', verified: true }] }
  });
  check('VERIFIED dengan exitCode != 0 ditolak 400', badExit.status === 400, `status=${badExit.status}`);

  const unverifiedStep = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { selfApprove: true, planId, nonce, toStatus: 'VERIFIED', evidence: [{ stepIndex: 0, alias: 'fw-enable-ufw', exitCode: 0, outputHash: 'sha256:a', verified: false }] }
  });
  check('VERIFIED dengan langkah belum terverifikasi ditolak 400', unverifiedStep.status === 400, `status=${unverifiedStep.status}`);

  const noPostAudit = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { selfApprove: true, planId, nonce, toStatus: 'VERIFIED', evidence }
  });
  check('VERIFIED tanpa post-audit ditolak 400', noPostAudit.status === 400, `status=${noPostAudit.status}`);

  const regressed = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { selfApprove: true, planId, nonce, toStatus: 'VERIFIED', evidence, postAudit: postAuditClean('FAIL') }
  });
  check('VERIFIED ditolak bila audit ulang masih FAIL', regressed.status === 400, `status=${regressed.status}`);

  const verified = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { selfApprove: true, planId, nonce, toStatus: 'VERIFIED', evidence, postAudit: postAuditClean() }
  });
  check('Verify VERIFIED diterima dengan evidence', verified.status === 200 && verified.json?.planStatus === 'VERIFIED', `status=${verified.status}`);

  const verifyUnsigned = await req('POST', '/api/remediation-verify', {
    key: API_KEY,
    body: { selfApprove: true, planId, nonce, toStatus: 'VERIFIED', evidence }
  });
  check('Verify tanpa signature HMAC ditolak 401', verifyUnsigned.status === 401, `status=${verifyUnsigned.status}`);

  const logsAfterVerify = await req('GET', '/api/audit-logs?limit=50', { key: API_KEY });
  const remediationLogged = (logsAfterVerify.json?.logs || []).some(
    l => l.planId === planId || (l.action === 'HARDENING REMEDIATION' && l.changesSummary?.includes(planId))
  );
  check('Remediasi VERIFIED tercatat di audit log', remediationLogged, `entries=${logsAfterVerify.json?.logs?.length}`);

  const planAfterVerify = await req('GET', '/api/remediation-plans/' + planId, { key: API_KEY });
  check('Evidence tersimpan pada plan', planAfterVerify.json?.plan?.evidence?.length === 1, JSON.stringify(planAfterVerify.json?.plan?.evidence));

  // ---------- 3b. Integritas audit log: hash chain terdeteksi saat disunting ----------
  const chainBefore = await req('GET', '/api/audit-logs/verify', { key: API_KEY });
  check('Rantai audit valid setelah penulisan', chainBefore.status === 200 && chainBefore.json?.chainOk === true, JSON.stringify(chainBefore.json));

  const auditFile = path.join(dataDir, 'audit_logs.json');
  const auditRaw = fs.readFileSync(auditFile, 'utf-8');
  const tamperedLogs = JSON.parse(auditRaw);
  tamperedLogs[0].changesSummary = 'DISUNTING DI LUAR SERVER';
  fs.writeFileSync(auditFile, JSON.stringify(tamperedLogs, null, 2), 'utf-8');
  const chainTampered = await req('GET', '/api/audit-logs/verify', { key: API_KEY });
  check(
    'Rantai audit mendeteksi entri yang disunting di luar server',
    chainTampered.status === 409 && chainTampered.json?.chainOk === false && Number.isFinite(chainTampered.json?.brokenAt),
    JSON.stringify(chainTampered.json)
  );
  fs.writeFileSync(auditFile, auditRaw, 'utf-8');

  const replayVerify = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { selfApprove: true, planId, nonce, toStatus: 'VERIFIED', evidence }
  });
  check('Replay verify setelah terminal ditolak (bukan 200)', replayVerify.status === 401 || replayVerify.status === 409, `status=${replayVerify.status}`);

  // ---------- 4c. Evidence kosong ditolak untuk status terminal ----------
  const planNoEvidence = await req('POST', '/api/remediation-plan', {
    key: API_KEY,
    body: { deviceId: 'SMOKE-DEVICE', items: [{ alias: 'auditd-enable', risk: 'LOW' }] }
  });
  const approve2 = await req('POST', '/api/remediation-approve', {
    key: API_KEY,
    body: { selfApprove: true, planId: planNoEvidence.json?.plan?.planId, approvedBy: 'smoke' }
  });
  const emptyEvidence = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { selfApprove: true, planId: approve2.json?.planId, nonce: approve2.json?.nonce, toStatus: 'VERIFIED', evidence: [] }
  });
  check('Verify VERIFIED tanpa evidence ditolak 400', emptyEvidence.status === 400, `status=${emptyEvidence.status}`);

  // ---------- 4d. Alias duplikat di-dedupe ----------
  // Item tunggal sebagai objek (perilaku ConvertTo-Json PowerShell) harus diterima.
  const singleObjectPlan = await req('POST', '/api/remediation-plan', {
    key: API_KEY,
    body: { deviceId: 'SMOKE-SINGLE', items: { alias: 'uac-enable', risk: 'LOW' } }
  });
  check('Plan dengan items berupa objek tunggal diterima', singleObjectPlan.status === 200 && Array.isArray(singleObjectPlan.json?.plan?.items), `status=${singleObjectPlan.status}`);

  const dupPlan = await req('POST', '/api/remediation-plan', {
    key: API_KEY,
    body: { deviceId: 'SMOKE-DEVICE', items: [{ alias: 'uac-enable', risk: 'LOW' }, { alias: 'uac-enable', risk: 'HIGH' }] }
  });
  check(
    'Alias duplikat di-dedupe menjadi satu item',
    dupPlan.status === 200 && dupPlan.json?.plan?.items?.length === 1,
    `items=${dupPlan.json?.plan?.items?.length}`
  );

  // ---------- 4d2. Plan advisory saja ditolak; enforce + advisory diterima ----------
  const advisoryOnly = await req('POST', '/api/remediation-plan', {
    key: API_KEY,
    body: { deviceId: 'SMOKE-DEVICE', items: [{ alias: 'advisory-fde', risk: 'LOW' }] }
  });
  check('Plan advisory saja ditolak 400', advisoryOnly.status === 400, `status=${advisoryOnly.status}`);

  const mixedOs = await req('POST', '/api/remediation-plan', {
    key: API_KEY,
    body: { deviceId: 'SMOKE-OS', items: [{ alias: 'uac-enable', risk: 'LOW' }, { alias: 'auditd-enable', risk: 'LOW' }] }
  });
  check('Plan campuran Windows+Linux ditolak 400', mixedOs.status === 400, `status=${mixedOs.status}`);

  const mixed = await req('POST', '/api/remediation-plan', {
    key: API_KEY,
    body: {
      deviceId: 'SMOKE-DEVICE',
      items: [
        { alias: 'fw-enable-ufw', risk: 'HIGH' },
        { alias: 'advisory-fde', risk: 'LOW' },
        { alias: 'ports-block-linux', risk: 'HIGH' }
      ]
    }
  });
  check('Plan enforce + advisory diterima', mixed.status === 200, `status=${mixed.status}`);
  const mixedApprove = await req('POST', '/api/remediation-approve', {
    key: API_KEY,
    body: { selfApprove: true, planId: mixed.json?.plan?.planId, approvedBy: 'smoke', acknowledgeConsole: true, overrideQueue: true }
  });
  const mixedEvidence = [
    { stepIndex: 0, alias: 'fw-enable-ufw', exitCode: 0, outputHash: 'sha256:a', verified: true },
    { stepIndex: 1, alias: 'advisory-fde', exitCode: 0, outputHash: 'sha256:b', verified: false, advisory: true },
    { stepIndex: 2, alias: 'ports-block-linux', exitCode: 0, outputHash: 'sha256:c', verified: true }
  ];
  const mixedVerify = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { selfApprove: true, planId: mixedApprove.json?.planId, nonce: mixedApprove.json?.nonce, toStatus: 'VERIFIED', evidence: mixedEvidence, postAudit: postAuditClean() }
  });
  check('Advisory dengan verified=false tetap bisa VERIFIED', mixedVerify.status === 200, `status=${mixedVerify.status}`);
  const mixedPlan = await req('GET', '/api/remediation-plans/' + mixedApprove.json?.planId, { key: API_KEY });
  check('Evidence advisory ditandai di plan', mixedPlan.json?.plan?.evidence?.[1]?.advisory === true, JSON.stringify(mixedPlan.json?.plan?.evidence?.[1]));

  // ---------- 4e. Approve ulang saat token masih berlaku ditolak 409 ----------
  const reApprove = await req('POST', '/api/remediation-approve', { key: API_KEY, body: { selfApprove: true, planId } });
  check('Approve ulang saat token masih berlaku ditolak 409', reApprove.status === 409, `status=${reApprove.status}`);
  const forced = await req('POST', '/api/remediation-approve', {
    key: API_KEY,
    body: { selfApprove: true, planId: planNoEvidence.json?.plan?.planId, force: true }
  });
  check('Approve paksa dengan force=true diterima', forced.status === 200 && Boolean(forced.json?.nonce), `status=${forced.status}`);

  // ---------- 4e2. Antrean per host: satu plan aktif, override eksplisit ----------
  const q1 = await req('POST', '/api/remediation-plan', {
    key: API_KEY, body: { deviceId: 'SMOKE-QUEUE', items: [{ alias: 'auditd-enable', risk: 'LOW' }] }
  });
  const q2 = await req('POST', '/api/remediation-plan', {
    key: API_KEY, body: { deviceId: 'SMOKE-QUEUE', items: [{ alias: 'uac-enable', risk: 'LOW' }] }
  });
  const q1Approve = await req('POST', '/api/remediation-approve', { key: API_KEY, body: { selfApprove: true, planId: q1.json?.plan?.planId } });
  check('Plan pertama host sama diterima', q1Approve.status === 200, `status=${q1Approve.status}`);
  const q2Blocked = await req('POST', '/api/remediation-approve', { key: API_KEY, body: { selfApprove: true, planId: q2.json?.plan?.planId } });
  check(
    'Plan kedua host sama ditolak 409 dengan plan penghalang',
    q2Blocked.status === 409 && typeof q2Blocked.json?.blockingPlanId === 'string',
    JSON.stringify(q2Blocked.json)
  );
  const q2Forced = await req('POST', '/api/remediation-approve', {
    key: API_KEY, body: { selfApprove: true, planId: q2.json?.plan?.planId, overrideQueue: true }
  });
  check('overrideQueue=true melewati antrean', q2Forced.status === 200, `status=${q2Forced.status}`);


  // ---------- 4f. Karantina: unitId wajib + registry bisa dibaca ----------
  const qBad = await req('POST', '/api/quarantine', { key: API_KEY, body: {} });
  check('Quarantine tanpa unitId ditolak 400', qBad.status === 400, `status=${qBad.status}`);
  const qLock = await req('POST', '/api/quarantine', { key: API_KEY, body: { unitId: 'SMOKE-Q', action: 'LOCK' } });
  const qList = await req('GET', '/api/quarantine', { key: API_KEY });
  check(
    'Karantina tersimpan & terbaca lewat GET registry',
    qLock.status === 200 && qList.status === 200 && qList.json?.units?.['SMOKE-Q']?.quarantined === true,
    `lock=${qLock.status} read=${qList.status}`
  );
  const qRelease = await req('POST', '/api/quarantine', { key: API_KEY, body: { unitId: 'SMOKE-Q', action: 'RELEASE' } });
  check('Release karantina diterima', qRelease.status === 200 && qRelease.json?.quarantined === false, `status=${qRelease.status}`);

  // ---------- 4f2. Escrow kunci BitLocker ----------
  const escrowBad = await req('POST', '/api/escrow', { key: API_KEY, body: { deviceId: 'SMOKE-E' } });
  check('Escrow tanpa kind/value ditolak 400', escrowBad.status === 400, `status=${escrowBad.status}`);
  const escrowOk = await req('POST', '/api/escrow', {
    key: API_KEY,
    body: { deviceId: 'SMOKE-E', kind: 'recovery', value: '123456-654321-000000-111111' }
  });
  const escrowRead = await req('GET', '/api/escrow/SMOKE-E', { key: API_KEY });
  check(
    'Escrow tersimpan & terbaca kembali',
    escrowOk.status === 200 && escrowRead.json?.escrow?.recovery?.value === '123456-654321-000000-111111',
    JSON.stringify(escrowRead.json)
  );

  // ---------- 4i. RBAC empat mata ----------
  const selfPlan = await req('POST', '/api/remediation-plan', {
    key: API_KEY, body: { deviceId: 'SMOKE-SELF', items: [{ alias: 'auditd-enable' }] }
  });
  const selfBlocked = await req('POST', '/api/remediation-approve', { key: API_KEY, body: { planId: selfPlan.json?.plan?.planId } });
  check(
    'Plan buatan sendiri ditolak sebelum selfApprove',
    selfBlocked.status === 409 && /Empat mata/i.test(String(selfBlocked.json?.reason)),
    JSON.stringify(selfBlocked.json)
  );
  const selfAllowed = await req('POST', '/api/remediation-approve', {
    key: API_KEY, body: { planId: selfPlan.json?.plan?.planId, selfApprove: true }
  });
  check('selfApprove=true diterima', selfAllowed.status === 200, `status=${selfAllowed.status}`);

  const viewerOp = await req('POST', '/api/operators', { key: API_KEY, body: { name: 'SMOKE-VIEWER', role: 'viewer' } });
  const viewerKey = viewerOp.json?.key;
  const whoViewer = await req('GET', '/api/whoami', { key: viewerKey });
  check('whoami mengembalikan identitas & role', whoViewer.status === 200 && whoViewer.json?.role === 'viewer', JSON.stringify(whoViewer.json));
  const viewerPlan = await req('POST', '/api/remediation-plan', { key: viewerKey, body: { deviceId: 'SMOKE-RBAC', items: [{ alias: 'auditd-enable' }] } });
  check('viewer ditolak membuat plan (403)', viewerPlan.status === 403, `status=${viewerPlan.status}`);
  const badRole = await req('POST', '/api/operators', { key: API_KEY, body: { name: 'SMOKE-BADROLE', role: 'root' } });
  check('role operator tak dikenal ditolak 400', badRole.status === 400, `status=${badRole.status}`);

  // ---------- 4j. Enrolment host & pengikatan plan ----------
  const hostA = await req('POST', '/api/hosts/enroll', { key: API_KEY, body: { name: 'SMOKE-HOST-A' } });
  const hostB = await req('POST', '/api/hosts/enroll', { key: API_KEY, body: { name: 'SMOKE-HOST-B' } });
  const hostKeyA = hostA.json?.hostKey;
  const hostKeyB = hostB.json?.hostKey;
  check('Enrol host mengembalikan hostId + kunci', typeof hostA.json?.hostId === 'string' && typeof hostKeyA === 'string', JSON.stringify(hostA.json));

  const bound = await req('POST', '/api/remediation-plan', {
    key: API_KEY, body: { deviceId: 'SMOKE-RBAC-BOUND', items: [{ alias: 'auditd-enable' }], hostId: hostA.json?.hostId }
  });
  check('Plan bisa diikat ke host', bound.status === 200 && bound.json?.plan?.hostId === hostA.json?.hostId, JSON.stringify(bound.json));
  await req('POST', '/api/remediation-approve', { key: API_KEY, body: { planId: bound.json?.plan?.planId, selfApprove: true } });

  const agentPath = `/api/remediation-plans/${bound.json?.plan?.planId}/agent`;
  const wrongHost = await req('GET', agentPath, { headers: { 'X-Pasopati-Host-Key': hostKeyB } });
  check('Host lain ditolak mengambil plan (403)', wrongHost.status === 403, `status=${wrongHost.status}`);
  const rightHost = await req('GET', agentPath, { headers: { 'X-Pasopati-Host-Key': hostKeyA } });
  check('Host pemilik boleh mengambil plan', rightHost.status === 200 && rightHost.json?.token, `status=${rightHost.status}`);

  const hostVerify = sign(JSON.stringify({ planId: bound.json?.plan?.planId, nonce: rightHost.json?.token?.split('.')[0], toStatus: 'EXECUTING', evidence: [] }), HMAC_SECRET);
  const hostVerifyRes = await req('POST', '/api/remediation-verify', {
    headers: { 'X-Pasopati-Host-Key': hostKeyA, 'X-Pasopati-Signature': hostVerify.signature, 'X-Pasopati-Timestamp': hostVerify.timestamp },
    body: JSON.stringify({ planId: bound.json?.plan?.planId, nonce: rightHost.json?.token?.split('.')[0], toStatus: 'EXECUTING', evidence: [] })
  });
  check('Host terikat boleh mengirim evidence', hostVerifyRes.status === 200, `status=${hostVerifyRes.status}`);

  await req('POST', `/api/hosts/${hostA.json?.hostId}/revoke`, { key: API_KEY });
  const afterRevoke = await req('GET', agentPath, { headers: { 'X-Pasopati-Host-Key': hostKeyA } });
  check('Kunci host yang dicabut ditolak 401', afterRevoke.status === 401, `status=${afterRevoke.status}`);
  const otherHostStillOk = await req('GET', '/api/hosts', { headers: { 'X-Pasopati-Host-Key': hostKeyB } });
  check('Host lain tetap berfungsi setelah pencabutan', otherHostStillOk.status === 200, `status=${otherHostStillOk.status}`);


  // ---------- 4g. Body cacat tidak mematikan server ----------
  const badChecks = await req('POST', '/api/analyze-threats', { key: API_KEY, body: { deviceName: 'X', checks: 'bukan-array' } });
  check('analyze-threats dengan checks bukan array tetap 200', badChecks.status === 200, `status=${badChecks.status}`);
  const nullCheck = await req('POST', '/api/analyze-threats', { key: API_KEY, body: { deviceName: 'X', checks: [null], userApiKey: 123 } });
  check('analyze-threats dengan checks [null] & key numerik tetap 200', nullCheck.status === 200, `status=${nullCheck.status}`);

  // ---------- 4h. Audit log: 250 entri dilaporkan jujur, tidak dipotong diam-diam ----------
  const many = Array.from({ length: 250 }, (_, i) => ({ id: 'SMOKE-L' + i, timestamp: '2026-01-01 00:00:0' + (i % 10), deviceName: 'D', action: 'BASELINE RECON' }));
  const postMany = await req('POST', '/api/audit-logs', { key: API_KEY, body: { logs: many } });
  check(
    'POST 250 audit log: melaporkan received=250 dan rejected=50',
    postMany.status === 200 && postMany.json?.received === 250 && postMany.json?.added === 200 && postMany.json?.rejected === 50,
    JSON.stringify(postMany.json)
  );

  // ---------- 4h2. Soft delete: entri dipertahankan, rantai tetap valid ----------
  const delRes = await req('DELETE', '/api/audit-logs', { key: API_KEY });
  const afterDel = await req('GET', '/api/audit-logs?limit=10', { key: API_KEY });
  const afterDelAll = await req('GET', '/api/audit-logs?includeDeleted=1&limit=10', { key: API_KEY });
  check(
    'DELETE audit log bersifat soft delete (entri tetap tersimpan)',
    delRes.status === 200 && delRes.json?.softDeleted > 0 &&
      afterDel.json?.logs?.length === 0 && (afterDelAll.json?.logs?.length || 0) > 0 &&
      afterDelAll.json?.logs?.every(l => typeof l.deletedAt === 'string'),
    JSON.stringify({ del: delRes.json, visible: afterDel.json?.logs?.length, retained: afterDelAll.json?.logs?.length })
  );
  const chainAfterDelete = await req('GET', '/api/audit-logs/verify', { key: API_KEY });
  check(
    'Rantai audit tetap valid setelah soft delete',
    chainAfterDelete.status === 200 && chainAfterDelete.json?.chainOk === true,
    JSON.stringify(chainAfterDelete.json)
  );

  // ---------- 4k. Waiver temuan ----------
  const waiverBody = { deviceId: 'SMOKE-WAIVER', parameter: 'Password Policy: Minimum Length', reason: 'Kebijakan pusat menengah', days: 14 };
  const waiverNoReason = await req('POST', '/api/waivers', { key: API_KEY, body: { deviceId: 'SMOKE-WAIVER', parameter: 'X' } });
  check('Waiver tanpa reason ditolak 400', waiverNoReason.status === 400, `status=${waiverNoReason.status}`);
  const waiverViewer = await req('POST', '/api/waivers', { key: viewerKey, body: waiverBody });
  check('Viewer ditolak membuat waiver (403)', waiverViewer.status === 403, `status=${waiverViewer.status}`);
  const waiverOk = await req('POST', '/api/waivers', { key: API_KEY, body: waiverBody });
  const waiverList = await req('GET', '/api/waivers/SMOKE-WAIVER', { key: API_KEY });
  check(
    'Waiver tersimpan dengan owner + expiry',
    waiverOk.status === 200 && waiverList.json?.waivers?.[0]?.owner === 'master' && Boolean(waiverList.json?.waivers?.[0]?.expiresAt),
    JSON.stringify(waiverList.json)
  );
  const waiverDup = await req('POST', '/api/waivers', { key: API_KEY, body: waiverBody });
  check('Waiver ganda untuk temuan sama ditolak 409', waiverDup.status === 409, `status=${waiverDup.status}`);
  const waiverDel = await req('DELETE', `/api/waivers/SMOKE-WAIVER/${waiverOk.json?.waiver?.id}`, { key: API_KEY });
  check('Waiver bisa dihapus', waiverDel.status === 200, `status=${waiverDel.status}`);

  // ---------- 4k2. Integritas artefak agen + mode air-gapped ----------
  const manifest = await req('GET', '/api/agent/manifest');
  const manifestHash = manifest.json?.files?.find(f => f.name === 'pasopati_audit.py')?.sha256;
  const localHash = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'pasopati_audit.py'))).digest('hex');
  check('Manifest agen memuat hash berkas yang cocok', manifest.status === 200 && manifestHash === localHash, `status=${manifest.status}`);
  const offlineAi = await req('POST', '/api/analyze-threats', { key: API_KEY, body: { deviceName: 'X', checks: [] } });
  check('AI_DISABLED memaksa mesin rule-based', offlineAi.status === 200 && offlineAi.json?.source === 'rule-based-fallback', JSON.stringify(offlineAi.json));

  // ---------- 4l. Observability ----------
  const health = await req('GET', '/api/health', { key: API_KEY });
  check('Health endpoint melaporkan status & integritas rantai', health.status === 200 && health.json?.auditChainOk === true, JSON.stringify(health.json));
  const metrics = await req('GET', '/api/metrics', { key: API_KEY });
  check('Metrik Prometheus tersedia', metrics.status === 200, `status=${metrics.status}`);

  // ---------- 4m. Antrean tarik untuk agent --watch ----------
  const hostC = await req('POST', '/api/hosts/enroll', { key: API_KEY, body: { name: 'SMOKE-HOST-C' } });
  const hostKeyC = hostC.json?.hostKey;
  const watchPlan = await req('POST', '/api/remediation-plan', {
    key: API_KEY, body: { deviceId: 'SMOKE-WATCH', items: [{ alias: 'auditd-enable' }], hostId: hostC.json?.hostId }
  });
  await req('POST', '/api/remediation-approve', { key: API_KEY, body: { planId: watchPlan.json?.plan?.planId, selfApprove: true } });
  const pending = await req('GET', '/api/hosts/me/plans', { headers: { 'X-Pasopati-Host-Key': hostKeyC } });
  check(
    'Host hanya melihat plan terikat miliknya',
    pending.status === 200 && (pending.json?.plans || []).some(p => p.planId === watchPlan.json?.plan?.planId),
    JSON.stringify(pending.json)
  );
  const pendingWrongHost = await req('GET', '/api/hosts/me/plans', { headers: { 'X-Pasopati-Host-Key': hostKeyB } });
  check(
    'Host lain tidak melihat plan tersebut',
    !(pendingWrongHost.json?.plans || []).some(p => p.planId === watchPlan.json?.plan?.planId),
    JSON.stringify(pendingWrongHost.json)
  );

  // ---------- 5. GET plan tidak boleh membocorkan token ----------
  const fetched = await req('GET', `/api/remediation-plans/${planId}`, { key: API_KEY });
  const publicPlan = fetched.json?.plan || {};
  check(
    'GET plan meredaksi nonce & signature',
    fetched.status === 200 && !('nonce' in publicPlan) && !('signature' in publicPlan) && publicPlan.hasToken === true,
    `status=${fetched.status}`
  );

  // ---------- 5b. Live scan tidak boleh bergantung pada TTY/sudo ----------
  const liveScan = await req('POST', '/api/scan-host', {
    key: API_KEY,
    body: { unitName: 'SMOKE-LIVE-SCAN' }
  });
  check(
    'POST /api/scan-host berjalan tanpa elevasi interaktif',
    liveScan.status === 200 && typeof liveScan.json?.scoring?.cyber_readiness_score === 'number',
    `status=${liveScan.status} ${liveScan.status !== 200 ? JSON.stringify(liveScan.json) : ''}`
  );

  // ---------- 5c. ZIP tidak boleh membawa .git, build, atau rahasia hidup ----------
  const zipRes = await fetch(BASE + '/api/download/project-zip', { headers: { 'X-Pasopati-API-Key': API_KEY } });
  const zipBuf = Buffer.from(await zipRes.arrayBuffer());
  const zipPath = path.join(dataDir, 'project.zip');
  fs.writeFileSync(zipPath, zipBuf);
  const listCode = `
import json, sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
open(sys.argv[2], 'w').write(json.dumps(names))
`;
  const listOut = path.join(dataDir, 'zip-names.json');
  const zipNames = runPython(listCode, listOut, [zipPath, listOut]);
  const has = n => zipNames.includes(n) || zipNames.some(x => x.startsWith(n));
  check('ZIP 200 dan berisi source inti', zipRes.status === 200 && zipNames.includes('server.ts'), `status=${zipRes.status} entries=${zipNames.length}`);
  check('ZIP mengecualikan .git & dist & node_modules', !has('.git/') && !has('dist/') && !has('node_modules/'), `entries=${zipNames.length}`);
  check('ZIP mengecualikan rahasia hidup, tetapi memuat .env.example',
    !zipNames.includes('.env') && !zipNames.includes('opencode.json') && !zipNames.includes('reapprove.ps1')
      && !zipNames.includes('token.txt') && !zipNames.some(n => n.startsWith('bitlocker-recovery-'))
      && zipNames.includes('.env.example'));

  // ---------- 6. Semua request cacat di atas tidak mematikan proses ----------
  const alive = await req('GET', '/api/audit-logs', { key: API_KEY });
  check('Server tetap hidup setelah seluruh request cacat', alive.status === 200, `status=${alive.status}`);
} catch (err) {
  check('Smoke test selesai tanpa exception', false, err?.message || String(err));
} finally {
  server.kill();
  try {
    fs.rmSync(dataDir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
}

const failed = results.filter(r => !r.passed);
console.log(`\n${results.length - failed.length}/${results.length} pengujian lolos`);
if (failed.length > 0) {
  console.error('\nLog server (tail):\n' + serverLog.split('\n').slice(-25).join('\n'));
  process.exit(1);
}
