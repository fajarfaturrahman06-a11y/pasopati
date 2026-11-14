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
    GEMINI_API_KEY: ''
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
  const ingestedLog = (listed.json?.logs || []).find(l => l.deviceId === 'UNIT-UJI-Ñ');
  check(
    'Telemetri yang di-ingest benar-benar tersimpan & terbaca di /api/audit-logs',
    listed.status === 200 && Boolean(ingestedLog) && ingestedLog?.action === 'TELEMETRY INGESTION',
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

  // ---------- 4. Approve: token sekali terbit ----------
  const approved = await req('POST', '/api/remediation-approve', { key: API_KEY, body: { planId, approvedBy: 'smoke' } });
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
    body: { planId, nonce: 'deadbeef', toStatus: 'EXECUTING', evidence: [] }
  });
  check('Verify dengan nonce salah ditolak 401', wrongNonce.status === 401, `status=${wrongNonce.status}`);

  const evidence = [{ stepIndex: 0, alias: 'fw-enable-ufw', exitCode: 0, outputHash: 'sha256:smoke', verified: true }];
  const executing = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { planId, nonce, toStatus: 'EXECUTING', evidence }
  });
  check('Verify EXECUTING diterima', executing.status === 200 && executing.json?.planStatus === 'EXECUTING', `status=${executing.status}`);

  const verified = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { planId, nonce, toStatus: 'VERIFIED', evidence }
  });
  check('Verify VERIFIED diterima dengan evidence', verified.status === 200 && verified.json?.planStatus === 'VERIFIED', `status=${verified.status}`);

  const verifyUnsigned = await req('POST', '/api/remediation-verify', {
    key: API_KEY,
    body: { planId, nonce, toStatus: 'VERIFIED', evidence }
  });
  check('Verify tanpa signature HMAC ditolak 401', verifyUnsigned.status === 401, `status=${verifyUnsigned.status}`);

  const logsAfterVerify = await req('GET', '/api/audit-logs?limit=50', { key: API_KEY });
  const remediationLogged = (logsAfterVerify.json?.logs || []).some(
    l => l.planId === planId || (l.action === 'HARDENING REMEDIATION' && l.changesSummary?.includes(planId))
  );
  check('Remediasi VERIFIED tercatat di audit log', remediationLogged, `entries=${logsAfterVerify.json?.logs?.length}`);

  const planAfterVerify = await req('GET', '/api/remediation-plans/' + planId, { key: API_KEY });
  check('Evidence tersimpan pada plan', planAfterVerify.json?.plan?.evidence?.length === 1, JSON.stringify(planAfterVerify.json?.plan?.evidence));

  const replayVerify = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { planId, nonce, toStatus: 'VERIFIED', evidence }
  });
  check('Replay verify setelah terminal ditolak (bukan 200)', replayVerify.status === 401 || replayVerify.status === 409, `status=${replayVerify.status}`);

  // ---------- 4c. Evidence kosong ditolak untuk status terminal ----------
  const planNoEvidence = await req('POST', '/api/remediation-plan', {
    key: API_KEY,
    body: { deviceId: 'SMOKE-DEVICE', items: [{ alias: 'auditd-enable', risk: 'LOW' }] }
  });
  const approve2 = await req('POST', '/api/remediation-approve', {
    key: API_KEY,
    body: { planId: planNoEvidence.json?.plan?.planId, approvedBy: 'smoke' }
  });
  const emptyEvidence = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { planId: approve2.json?.planId, nonce: approve2.json?.nonce, toStatus: 'VERIFIED', evidence: [] }
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
    body: { planId: mixed.json?.plan?.planId, approvedBy: 'smoke' }
  });
  const mixedEvidence = [
    { stepIndex: 0, alias: 'fw-enable-ufw', exitCode: 0, outputHash: 'sha256:a', verified: true },
    { stepIndex: 1, alias: 'advisory-fde', exitCode: 0, outputHash: 'sha256:b', verified: false, advisory: true }
  ];
  const mixedVerify = await req('POST', '/api/remediation-verify', {
    key: API_KEY, signed: true,
    body: { planId: mixedApprove.json?.planId, nonce: mixedApprove.json?.nonce, toStatus: 'VERIFIED', evidence: mixedEvidence }
  });
  check('Advisory dengan verified=false tetap bisa VERIFIED', mixedVerify.status === 200, `status=${mixedVerify.status}`);
  const mixedPlan = await req('GET', '/api/remediation-plans/' + mixedApprove.json?.planId, { key: API_KEY });
  check('Evidence advisory ditandai di plan', mixedPlan.json?.plan?.evidence?.[1]?.advisory === true, JSON.stringify(mixedPlan.json?.plan?.evidence?.[1]));

  // ---------- 4e. Approve ulang saat token masih berlaku ditolak 409 ----------
  const reApprove = await req('POST', '/api/remediation-approve', { key: API_KEY, body: { planId } });
  check('Approve ulang saat token masih berlaku ditolak 409', reApprove.status === 409, `status=${reApprove.status}`);
  const forced = await req('POST', '/api/remediation-approve', {
    key: API_KEY,
    body: { planId: planNoEvidence.json?.plan?.planId, force: true }
  });
  check('Approve paksa dengan force=true diterima', forced.status === 200 && Boolean(forced.json?.nonce), `status=${forced.status}`);

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
