import express from 'express';
import { createServer as createViteServer } from 'vite';
import type { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { execFile } from 'child_process';
import { ZipArchive, type ArchiverError } from 'archiver';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import crypto from 'crypto';
import { normalizeAuditAction } from './src/auditActions';
import { redactSensitive } from './src/redaction';

dotenv.config();

/** Bungkus handler async agar rejection masuk ke error middleware (Express 4 tidak otomatis). */
const asyncHandler =
  (fn: (req: Request, res: Response) => Promise<unknown>) =>
  (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res)).catch(next);
  };

// Nilai env boleh mengandung komentar inline (# ...) di .env; ambil bagian depannya saja.
function envValue(name: string, fallback = ''): string {
  const raw = process.env[name];
  if (!raw) return fallback;
  const cleaned = raw.split('#')[0].trim();
  return cleaned || fallback;
}

const AI_MODEL_NAME = envValue('AI_MODEL_NAME', 'gemini-2.5-flash');
const AI_BASE_URL = envValue('GEMINI_BASE_URL').replace(/\/+$/, '');
// Base URL OpenAI-compatible (mis. Experensial Labs) butuh jalur /chat/completions,
// bukan endpoint Gemini. Endpoint Google resmi tetap memakai SDK Google.
const AI_USES_OPENAI_COMPAT = Boolean(AI_BASE_URL) && !AI_BASE_URL.includes('generativelanguage.googleapis.com');

const app = express();
app.disable('x-powered-by');
const PORT = Number(process.env.PORT) || 3000;
// Di belakang reverse proxy, aktifkan agar rate limit memakai IP klien (TRUST_PROXY=1 / jumlah hop).
const TRUST_PROXY = envValue('TRUST_PROXY');
if (TRUST_PROXY) app.set('trust proxy', /^\d+$/.test(TRUST_PROXY) ? Number(TRUST_PROXY) : TRUST_PROXY);
// Folder penyimpanan state (quarantine/plan/nonce/audit). Bisa diarahkan ke folder
// sementara saat pengujian agar data operasional tidak tercampur.
const DATA_DIR = process.env.PASOPATI_DATA_DIR ? path.resolve(process.env.PASOPATI_DATA_DIR) : path.resolve(process.cwd(), 'data');

/** Tulis JSON secara atomik (tmp + rename) agar file state tidak pernah setengah jadi. */
function writeJsonAtomic(filePath: string, value: unknown) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = `${filePath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { encoding: 'utf-8', mode: 0o600 });
  fs.renameSync(tmp, filePath);
}

app.use(express.json({
  limit: '10mb',
  verify: (req, _res, buf: Buffer) => {
    (req as { rawBody?: Buffer }).rawBody = buf;
  }
}));

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  // API tidak boleh dicache browser/proxy.
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  // KHUSUS PRODUCTION: CSP ketat + HSTS. Di dev (Vite HMR) CSP disengaja tidak dipasang
  // agar HMR/ws tidak rusak — jangan jadikan acuan deploy publik tanpa CSP.
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  }
  next();
});

function safeEqualStrTop(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// API key gate for operational endpoints (fail-closed, tanpa bypass loopback)
const API_KEY = (process.env.PASOPATI_API_KEY || '').trim();

const requireApiKey = (req: Request, res: Response, next: NextFunction) => {
  if (!API_KEY) {
    return res.status(503).json({ status: 'rejected', reason: 'Server belum siap: set PASOPATI_API_KEY di environment.' });
  }
  const provided = req.headers['x-pasopati-api-key'] as string | undefined;
  if (provided && safeEqualStrTop(provided.trim(), API_KEY)) {
    return next();
  }
  return res.status(401).json({ status: 'rejected', reason: 'X-Pasopati-API-Key tidak valid.' });
};

// Helper to get fallback tactical risk analysis
function getFallbackRiskAnalysis(deviceName: string, deviceRole: string, os: string, failChecks: any[]) {
  if (!failChecks || failChecks.length === 0) {
    return `Perangkat ${deviceName} (${deviceRole}) dalam status optimal. Seluruh parameter CIS Benchmark v8.0 dan DISA STIG berstatus PASS.`;
  }

  let text = `TELAAH INTELIJEN SIBER PERTAHANAN (PASOPATI THREAT INTEL):\n\n`;
  text += `Berdasarkan inspeksi mendalam pada aset inti "${deviceName}" (${deviceRole} - ${os}), ditemukan ${failChecks.length} temuan kritis berstatus FAIL yang berpotensi melumpuhkan kerahasiaan dan kontinuitas operasi militer:\n\n`;

  failChecks.forEach((fc, idx) => {
    const param = fc.parameter || fc.param || '';
    const detail = fc.details || fc.detail || '';
    if (param.includes('4444') || detail.includes('4444')) {
      text += `${idx + 1}. [EMERGENCY - C2 BACKDOOR] Port 4444 Terbuka:\n`;
      text += `   Dampak Taktis: Merupakan port default payload reverse shell C2 (Command & Control). Threat actor berpotensi telah mendirikan persistence di workstation ini untuk memantau telegram sandi dan pergerakan satgas secara real-time.\n\n`;
    } else if (param.includes('SMB') || param.includes('445')) {
      text += `${idx + 1}. [HIGH - LATERAL MOVEMENT] Port SMB 445 Tanpa Segmentasi:\n`;
      text += `   Dampak Taktis: Paparan port 445 membuka celah eksploitasi mirip EternalBlue/EternalRomance. Penyerang di satu titik dapat melompat secara lateral ke seluruh server logistik dan puskodal kompi tanpa kendala otentikasi.\n\n`;
    } else if (param.includes('SSH') || param.includes('Root')) {
      text += `${idx + 1}. [CRITICAL - ACCESS CONTROL] SSH Root Direct Login Aktif:\n`;
      text += `   Dampak Taktis: Membiarkan PermitRootLogin aktif melanggar CIS 5.2.10 dan membuka peluang serangan kamus terdistribusi ke superuser server pangkalan data taktis.\n\n`;
    } else if (param.includes('Telnet') || param.includes('FTP') || param.includes('23')) {
      text += `${idx + 1}. [HIGH - SIGINT INTERCEPTION] Protokol Komunikasi Plaintext (Telnet/FTP):\n`;
      text += `   Dampak Taktis: Pengiriman sandi komando dalam format tidak terenkripsi pada radio gateway OT dapat disadap oleh unit peperangan elektronika (EW/SIGINT) lawan dengan mudah.\n\n`;
    } else if (param.includes('Firewall')) {
      text += `${idx + 1}. [MEDIUM/HIGH - SURFACE EXPOSURE] Firewall Lokal Tidak Aktif:\n`;
      text += `   Dampak Taktis: Tidak adanya isolasi port inbound mempermudah musuh memetakan topologi jaringan dan port aktif secara presisi menggunakan SYN scan.\n\n`;
    } else if (param.includes('Audit') || param.includes('auditd')) {
      text += `${idx + 1}. [HIGH - FORENSIC BLINDSPOT] Audit Daemon / Security Logging Mati:\n`;
      text += `   Dampak Taktis: Tiadanya catatan kernel auditd menghalangi tim CSIRT TNI dalam mengidentifikasi titik awal intrusi (Patient Zero) jika terjadi insiden sabotase sistem.\n\n`;
    } else {
      text += `${idx + 1}. [VULNERABILITY] ${param}:\n   Dampak Taktis: ${detail}\n\n`;
    }
  });

  text += `Rekomendasi Taktis Segera: Lakukan eksekusi "One-Click Hardening" di bawah ini untuk menutup seluruh port listener berbahaya, menerapkan isolasi firewall, dan mengunci hak akses pengguna.`;
  return text;
}

// API: AI Contextual Threat Analysis (wajib X-Pasopati-API-Key; body userApiKey = GEMINI key terpisah)
app.post('/api/analyze-threats', requireApiKey, rateLimit(20), asyncHandler(async (req, res) => {
  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, any>;
  const deviceName = String(body.deviceName ?? 'UNKNOWN-NODE').slice(0, 120);
  const deviceRole = String(body.deviceRole ?? 'UNASSIGNED').slice(0, 160);
  const os = String(body.os ?? 'unknown').slice(0, 120);
  // `checks` bisa bukan array (atau berisi null) — jangan sampai mematikan proses.
  const checks = Array.isArray(body.checks) ? body.checks.filter((c: any) => c && typeof c === 'object') : [];
  const failChecks = checks.filter((c: any) => c.status === 'FAIL');

  // OPSEC Data Sanitization: Mask sensitive military telemetry before sending to Cloud AI
  const isOpsec = body.opsecActive !== false; // Default active
  const sanitizedDeviceName = isOpsec ? `[REDACTED_NODE_${deviceName.substring(0, 3)}]` : deviceName;
  const sanitizedRole = isOpsec ? `[DEFENSE_INFRA_ASSET]` : deviceRole;
  const sanitizedOS = isOpsec ? `${os.split(' ')[0]} (Protected)` : os;
  const sanitizedChecks = failChecks.map((c: any) => ({
    parameter: String(c.parameter ?? c.param ?? '').slice(0, 200),
    category: String(c.category ?? c.cat ?? '').slice(0, 80),
    cis_id: String(c.cis_id ?? c.cis ?? '').slice(0, 120),
    details: isOpsec
      ? redactSensitive(c.details ?? c.detail ?? '').slice(0, 1000)
      : String(c.details ?? c.detail ?? '').slice(0, 1000)
  }));

  const rawKey = String(body.userApiKey ?? '') || process.env.GEMINI_API_KEY || '';
  const apiKey = rawKey.trim();

  // If no valid key provided or placeholder, use fast military rule-based engine directly
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY' || apiKey.length < 15 || apiKey.startsWith('MY_')) {
    return res.json({
      source: 'rule-based-fallback',
      analysis: getFallbackRiskAnalysis(deviceName, deviceRole, os, failChecks),
      opsec_sanitized: isOpsec
    });
  }

  try {
    const prompt = `Bertindaklah sebagai Senior Military Cyber Defense Analyst dari PASOPATI (Pusat Operasi Siber Pertahanan).
Lakukan Analisis Risiko Kontekstual Taktis dalam Bahasa Indonesia yang lugas, tegas, dan berwibawa militer mengenai temuan celah keamanan berikut:

Identitas Perangkat:
- Nama Aset: ${sanitizedDeviceName}
- Peran Operasi: ${sanitizedRole}
- Sistem Operasi: ${sanitizedOS}

Temuan Celah Keamanan (FAIL):
${JSON.stringify(sanitizedChecks, null, 2)}

Jelaskan secara padat dan taktis:
1. Telaah Vektor Serangan: Potensi lateral movement, C2 backdoor, atau eksfiltrasi data intelijen.
2. Dampak Operasional terhadap kerahasiaan dan ketersediaan misi tempur.
3. Prioritas Tindakan Kontinjensi sesuai CIS Benchmark dan DISA STIG.`;

    // Timeout guard of 15 seconds to accommodate network variations
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Koneksi Cloud AI mencapai batas waktu')), 15000)
    );

    const generatePromise = (async (): Promise<string> => {
      if (AI_USES_OPENAI_COMPAT) {
        // Provider OpenAI-compatible (mis. Experensial Labs / DeepSeek).
        const response = await fetch(`${AI_BASE_URL}/chat/completions`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({
            model: AI_MODEL_NAME,
            messages: [{ role: 'user', content: prompt }],
            max_tokens: 600,
            temperature: 0.2
          })
        });
        if (!response.ok) {
          throw new Error(`Cloud AI HTTP ${response.status}`);
        }
        const json: any = await response.json();
        return String(json?.choices?.[0]?.message?.content ?? '');
      }
      const ai = new GoogleGenAI({
        apiKey,
        httpOptions: { headers: { 'User-Agent': 'aistudio-build' } }
      });
      const response: any = await ai.models.generateContent({
        model: AI_MODEL_NAME,
        contents: prompt,
        config: { maxOutputTokens: 600, temperature: 0.2 }
      });
      return String(response?.text ?? '');
    })();

    const analysisText = await Promise.race([generatePromise, timeoutPromise]);

    return res.json({
      source: AI_MODEL_NAME,
      engine: 'cloud',
      analysis: analysisText || getFallbackRiskAnalysis(deviceName, deviceRole, os, failChecks),
      opsec_sanitized: isOpsec
    });
  } catch (error: any) {
    console.log('[PASOPATI] Threat Intel switching to resilient air-gapped engine:', error?.message || 'Offline mode');
    return res.json({
      source: 'rule-based-fallback',
      analysis: getFallbackRiskAnalysis(deviceName, deviceRole, os, failChecks),
      note: 'Engine taktis air-gapped aktif untuk memastikan evaluasi tetap 100% lancar.',
      opsec_sanitized: isOpsec
    });
  }
}));

// (legacy stable-stringify helper removed — authentication now signs the raw
// request body, eliminating canonicalization drift entirely)

// Ingestion endpoint with HMAC-SHA256 signature verification & drift storage
// import crypto from 'crypto';
const HMAC_SECRET = process.env.HMAC_SECRET;
const MAX_TIMESTAMP_DRIFT_MS = 5 * 60 * 1000; // anti-replay window

// In-memory compliance drift store (null-prototype agar aman untuk unit seperti __proto__).

function safeEqualHex(signature: string, expected: string): boolean {
  const a = Buffer.from(signature, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

type SignatureCheck = { ok: true; signature: string } | { ok: false; status: number; reason: string };

/** Verifikasi tanda tangan HMAC atas raw body + jendela waktu (dipakai ingest & evidence). */
function verifySignedRequest(req: Request, secret: string | undefined, missingReason: string): SignatureCheck {
  if (!secret) return { ok: false, status: 503, reason: missingReason };
  const rawBody = (req as { rawBody?: Buffer }).rawBody;
  if (!rawBody) return { ok: false, status: 400, reason: 'Raw body tidak tersedia untuk verifikasi.' };
  const signature = (req.headers['x-pasopati-signature'] as string | undefined)?.trim().toLowerCase();
  const timestamp = req.headers['x-pasopati-timestamp'] as string | undefined;
  if (!signature || !timestamp) {
    return { ok: false, status: 401, reason: 'Header X-Pasopati-Signature dan X-Pasopati-Timestamp wajib ada.' };
  }
  const tsNum = Number(timestamp);
  if (!Number.isFinite(tsNum)) {
    return { ok: false, status: 401, reason: 'X-Pasopati-Timestamp bukan angka yang valid.' };
  }
  const tsMs = tsNum < 1e12 ? tsNum * 1000 : tsNum;
  if (Math.abs(Date.now() - tsMs) > MAX_TIMESTAMP_DRIFT_MS) {
    return { ok: false, status: 401, reason: 'X-Pasopati-Timestamp kedaluwarsa atau tidak valid.' };
  }
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  if (!safeEqualHex(signature, expected)) return { ok: false, status: 401, reason: 'Signature HMAC tidak valid.' };
  return { ok: true, signature };
}

// Cache tanda tangan ingest yang sudah dipakai (anti-replay nyata, bukan sekadar jendela waktu).
const usedIngestSignatures = new Map<string, number>();
const MAX_USED_INGEST_SIGNATURES = 10_000;

function recordIngestSignature(signature: string) {
  const now = Date.now();
  if (usedIngestSignatures.size > MAX_USED_INGEST_SIGNATURES) {
    for (const [key, expiresAt] of usedIngestSignatures) {
      if (expiresAt < now) usedIngestSignatures.delete(key);
    }
    while (usedIngestSignatures.size >= MAX_USED_INGEST_SIGNATURES) {
      const oldest = usedIngestSignatures.keys().next().value;
      if (oldest === undefined) break;
      usedIngestSignatures.delete(oldest);
    }
  }
  usedIngestSignatures.set(signature, now + MAX_TIMESTAMP_DRIFT_MS * 2);
}

const complianceDriftStore: Record<string, Array<{ timestamp: string; score: number; passCount: number; warnCount: number; failCount: number; event: string }>> = Object.create(null);

// Quarantine registry (kill-switch state per unit, persisten ke disk)
// Catatan jujur: endpoint ini hanya mencatat status di server; pemutusan koneksi nyata
// memerlukan agen di host endpoint untuk polling/memblokir (tidak dilakukan server saja).
const QUARANTINE_PATH = path.join(DATA_DIR, 'quarantine_registry.json');
type QuarantineEntry = { quarantined: boolean; updatedAt: string };

function loadQuarantine(): Map<string, QuarantineEntry> {
  const map = new Map<string, QuarantineEntry>();
  try {
    if (!fs.existsSync(QUARANTINE_PATH)) return map;
    const parsed = JSON.parse(fs.readFileSync(QUARANTINE_PATH, 'utf-8'));
    if (parsed && typeof parsed === 'object') {
      for (const [k, v] of Object.entries(parsed as Record<string, QuarantineEntry>)) {
        if (v && typeof v.quarantined === 'boolean') map.set(k, v);
      }
    }
  } catch (err) {
    console.error('[PASOPATI] Gagal membaca quarantine registry:', (err as Error).message);
  }
  return map;
}

function saveQuarantine(map: Map<string, QuarantineEntry>) {
  try {
    writeJsonAtomic(QUARANTINE_PATH, Object.fromEntries(map));
  } catch (err) {
    console.error('[PASOPATI] Gagal menulis quarantine registry:', (err as Error).message);
  }
}

const quarantineRegistry = loadQuarantine();

// Rate-limit sederhana in-memory (tanpa dep baru): 60 req/mnt/IP untuk endpoint sensitif.
const rateBuckets = new Map<string, { count: number; resetAt: number }>();
const RATE_BUCKET_SOFT_LIMIT = 5000;
function rateLimit(maxPerMinute: number) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = String((req.socket?.remoteAddress as string) || req.ip || 'unknown');
    const now = Date.now();
    // Bersihkan bucket kedaluwarsa agar Map tidak tumbuh tanpa batas.
    if (rateBuckets.size > RATE_BUCKET_SOFT_LIMIT) {
      for (const [key, value] of rateBuckets) {
        if (now > value.resetAt) rateBuckets.delete(key);
      }
    }
    const bucket = rateBuckets.get(ip);
    if (!bucket || now > bucket.resetAt) {
      rateBuckets.set(ip, { count: 1, resetAt: now + 60_000 });
      return next();
    }
    if (bucket.count >= maxPerMinute) {
      return res.status(429).json({ status: 'rejected', reason: 'Terlalu banyak permintaan, coba lagi nanti.' });
    }
    bucket.count += 1;
    return next();
  };
}

app.post('/api/ingest', rateLimit(60), (req, res) => {
  const auth = verifySignedRequest(
    req,
    HMAC_SECRET,
    'Server belum siap: set HMAC_SECRET di environment.'
  );
  if (!auth.ok) {
    if (auth.status === 503) console.error('[PUSKODAL-INGEST] Kunci HMAC belum dikonfigurasi — telemetri ditolak.');
    return res.status(auth.status).json({ status: 'rejected', reason: auth.reason });
  }
  if (usedIngestSignatures.has(auth.signature)) {
    return res.status(401).json({ status: 'rejected', reason: 'Replay: tanda tangan ingest sudah pernah dipakai.' });
  }
  recordIngestSignature(auth.signature);

  const payload = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, any>;
  const metadata = (payload.metadata && typeof payload.metadata === 'object' ? payload.metadata : {}) as Record<string, any>;
  const scoring = (payload.scoring && typeof payload.scoring === 'object' ? payload.scoring : {}) as Record<string, any>;
  const unit = String(metadata.tactical_unit || 'UNKNOWN-UNIT').slice(0, 64);
  const score = Number(scoring.cyber_readiness_score) || 0;

  // Record into Compliance Drift History (dibatasi agar memori tidak bocor).
  if (!Object.hasOwn(complianceDriftStore, unit)) {
    const units = Object.keys(complianceDriftStore);
    if (units.length >= 200) delete complianceDriftStore[units[0]];
    complianceDriftStore[unit] = [];
  }
  const drift = complianceDriftStore[unit];
  drift.push({
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 16),
    score: score,
    passCount: Number(scoring.passed_checks) || 0,
    warnCount: Number(scoring.warning_checks) || 0,
    failCount: Number(scoring.failed_checks) || 0,
    event: 'Telemetry Ingest Puskodal'
  });
  if (drift.length > 200) drift.splice(0, drift.length - 200);

  // Persist telemetry into the local audit database the dashboard reads.
  // Sebelumnya ingest hanya menulis ke memori (complianceDriftStore) sehingga
  // dashboard tidak pernah menampilkan telemetri agen meski server membalas 200.
  const receivedAt = new Date();
  const ingestEntry = {
    id: `INGEST-${unit}-${receivedAt.getTime()}`,
    timestamp: receivedAt.toISOString().replace('T', ' ').substring(0, 19),
    deviceId: unit,
    deviceName: unit,
    deviceRole: String(metadata.device_role || 'Endpoint (telemetri agen)').slice(0, 160),
    action: 'TELEMETRY INGESTION',
    operator: 'pasopati_audit.py',
    preScore: 0,
    postScore: score,
    changesSummary: `Telemetri audit bertanda tangan HMAC dari ${unit} (PASS ${Number(scoring.passed_checks) || 0} / WARN ${Number(scoring.warning_checks) || 0} / FAIL ${Number(scoring.failed_checks) || 0})`,
    changesDetails: [
      '[NYATA] Data berasal dari pasopati_audit.py di host, bukan simulasi dashboard.',
      `Total parameter: ${Number(scoring.total_checks) || 0} | Skor: ${score}/100`
    ],
    status: 'SUCCESS',
    storedInDb: true
  };
  const totalLogs = appendAuditLogs([ingestEntry]);

  console.log(`[PUSKODAL-INGEST] Telemetri dari: ${unit} | Score: ${score}/100 | Cryptographic Signature: VALID`);
  return res.json({
    status: 'success',
    message: `Telemetri dari ${unit} berhasil dicatat di Puskodal PASOPATI`,
    tactical_unit: unit,
    signature_verified: true,
    stored: true,
    total_logs: totalLogs,
    timestamp: new Date().toISOString()
  });
});


// Emergency Network Quarantine Vector (Kill-Switch) — mencatat status; agen host yang
// wajib mengeksekusi pemblokiran nyata (server tidak memutus koneksi endpoint sendiri).
app.post('/api/quarantine', requireApiKey, rateLimit(60), (req, res) => {
  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, any>;
  const unitId = String(body.unitId || '').trim().slice(0, 64);
  if (!unitId) {
    return res.status(400).json({ status: 'rejected', reason: 'unitId wajib diisi.' });
  }
  const isLock = String(body.action || '').toUpperCase() !== 'RELEASE';
  quarantineRegistry.set(unitId, { quarantined: isLock, updatedAt: new Date().toISOString() });
  saveQuarantine(quarantineRegistry);
  console.log(`[PUSKODAL-KILLSWITCH] ${isLock ? 'LOCKDOWN EMERGENCY' : 'RELEASE'} dipicu untuk unit: ${unitId}`);
  return res.json({
    status: 'success',
    unitId,
    quarantined: isLock,
    message: isLock
      ? `STATUS KARANTINA DICATAT: ${unitId} ditandai terisolasi di registry Puskodal. Pemblokiran firewall nyata harus dieksekusi oleh agen host (pasopati_remediate.py); server ini tidak memutus koneksi.`
      : `STATUS KARANTINA DICABUT: ${unitId} dikembalikan ke status perimeter normal di registry.`,
    timestamp: new Date().toISOString()
  });
});

// Baca registry karantina agar dashboard dapat memulihkan status setelah reload.
app.get('/api/quarantine', requireApiKey, (_req, res) => {
  return res.json({ units: Object.fromEntries(quarantineRegistry) });
});

// Riwayat compliance drift per unit (diisi oleh /api/ingest).
app.get('/api/compliance-drift/:unitId', requireApiKey, (req, res) => {
  const unitId = String(req.params.unitId || '').slice(0, 64);
  const history = Object.hasOwn(complianceDriftStore, unitId) ? complianceDriftStore[unitId] : [];
  return res.json({ unitId, history });
});

// ===== Real Agent Remediation — kontrol plane (Fase B) =====
// State machine: PLANNED → APPROVED → EXECUTING → VERIFIED | ROLLED_BACK | FAILED.
// Server hanya menyimpan rencana + token; eksekusi nyata dilakukan agent (Fase C).
// Tanpa persetujuan, agent TIDAK boleh mengubah konfigurasi apa pun (read-only).

type PlanStatus = 'PLANNED' | 'APPROVED' | 'EXECUTING' | 'VERIFIED' | 'ROLLED_BACK' | 'FAILED';
interface PlanItem {
  findingId: string;
  alias: string; // ID tindakan dari allowlist agent (mis. 'fw-enable-ufw')
  risk: string;  // LOW | MEDIUM | HIGH
  reversible: boolean;
  preState?: string;
  postStateExpected?: string;
}
interface Plan {
  planId: string;
  deviceId: string;
  createdBy: string;
  createdAt: string;
  items: PlanItem[];
  status: PlanStatus;
  approvedBy?: string;
  approvedAt?: string;
  nonce?: string;
  expiresAt?: number;
  evidenceDeadline?: number;
  signature?: string;
  evidence?: any[];
  updatedAt?: string;
}

const REMEDIATION_PLANS_PATH = path.join(DATA_DIR, 'remediation_plans.json');
const ALIAS_REGEX = /^[a-z0-9][a-z0-9-]{2,47}$/;
// Sinkron dengan ALLOWLIST_ANALISA di pasopati_audit.py (20 alias: 16 enforce + 4 advisory).
// Server menolak alias fiktif.
const ALLOWED_ALIASES = new Set([
  'fw-enable-defender',
  'guest-account-disable',
  'usb-storage-block',
  'fw-enable-ufw',
  'ssh-disable-root',
  'auditd-enable',
  'usb-block-linux',
  'rdp-nla-enable',
  'uac-enable',
  'bitlocker-enable',
  'grub-config-perms',
  'sudoers-remove-nopasswd',
  'suid-strip-critical',
  'win-auditpol-process',
  'ports-block-linux',
  'ports-block-windows',
  'advisory-fde',
  'advisory-rootkit',
  'advisory-secureboot',
  'advisory-admins'
]);
// Langkah advisory tidak mengubah host; plan wajib punya minimal satu langkah enforce.
const ADVISORY_ALIASES = new Set([
  'advisory-fde',
  'advisory-rootkit',
  'advisory-secureboot',
  'advisory-admins'
]);
const ALLOWED_TRANSITIONS: Record<PlanStatus, PlanStatus[]> = {
  PLANNED: ['APPROVED'],
  APPROVED: ['EXECUTING', 'VERIFIED', 'ROLLED_BACK', 'FAILED'],
  EXECUTING: ['VERIFIED', 'ROLLED_BACK', 'FAILED'],
  VERIFIED: [],
  ROLLED_BACK: [],
  FAILED: []
};

function loadPlans(): Map<string, Plan> {
  const map = new Map<string, Plan>();
  try {
    if (!fs.existsSync(REMEDIATION_PLANS_PATH)) return map;
    const parsed = JSON.parse(fs.readFileSync(REMEDIATION_PLANS_PATH, 'utf-8'));
    if (Array.isArray(parsed)) {
      for (const p of parsed) {
        if (p && typeof p.planId === 'string') map.set(p.planId, p as Plan);
      }
    }
  } catch (err) {
    console.error('[PASOPATI] Gagal membaca remediation plans:', (err as Error).message);
  }
  return map;
}

const MAX_PLANS = 500;
const PLAN_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const TERMINAL_STATUSES: PlanStatus[] = ['VERIFIED', 'ROLLED_BACK', 'FAILED'];

/** Buang plan terminal yang kedaluwarsa, lalu batasi jumlah plan agar file state tidak tumbuh tanpa batas. */
function prunePlans(plans: Map<string, Plan>) {
  const now = Date.now();
  for (const [id, plan] of plans) {
    const updated = Date.parse(String(plan.updatedAt || plan.createdAt || ''));
    if (TERMINAL_STATUSES.includes(plan.status) && Number.isFinite(updated) && now - updated > PLAN_RETENTION_MS) {
      plans.delete(id);
    }
  }
  if (plans.size > MAX_PLANS) {
    const ordered = Array.from(plans.values())
      .sort((a, b) => String(a.updatedAt || a.createdAt || '').localeCompare(String(b.updatedAt || b.createdAt || '')));
    for (const plan of ordered.slice(0, plans.size - MAX_PLANS)) {
      if (TERMINAL_STATUSES.includes(plan.status)) plans.delete(plan.planId);
    }
  }
}

function savePlans(plans: Map<string, Plan>) {
  try {
    prunePlans(plans);
    writeJsonAtomic(REMEDIATION_PLANS_PATH, Array.from(plans.values()));
  } catch (err) {
    console.error('[PASOPATI] Gagal menulis remediation plans:', (err as Error).message);
  }
}

const plansStore = loadPlans();
const USED_NONCES_PATH = path.join(DATA_DIR, 'remediation_used_nonces.json');

function loadUsedNonces(): Set<string> {
  try {
    if (!fs.existsSync(USED_NONCES_PATH)) return new Set<string>();
    const parsed = JSON.parse(fs.readFileSync(USED_NONCES_PATH, 'utf-8'));
    if (Array.isArray(parsed)) {
      const values = parsed.filter((x: unknown): x is string => typeof x === 'string');
      return new Set(values.slice(-MAX_USED_NONCES));
    }
  } catch (err) {
    console.error('[PASOPATI] Gagal membaca used nonces:', (err as Error).message);
  }
  return new Set<string>();
}

function saveUsedNonces(set: Set<string>) {
  try {
    writeJsonAtomic(USED_NONCES_PATH, Array.from(set));
  } catch (err) {
    console.error('[PASOPATI] Gagal menulis used nonces:', (err as Error).message);
  }
}

const MAX_USED_NONCES = 5000;
const usedNonces = loadUsedNonces();

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value) as string;
  }
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter(k => obj[k] !== undefined)
    .sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}

function canonicalPlan(p: Plan): string {
  return stableStringify({
    planId: p.planId,
    deviceId: p.deviceId,
    items: p.items,
    approvedBy: p.approvedBy,
    nonce: p.nonce,
    expiresAt: p.expiresAt
  });
}

function signPlan(p: Plan): string {
  return crypto.createHmac('sha256', String(HMAC_SECRET)).update(canonicalPlan(p)).digest('hex');
}

function validateItems(raw: any): PlanItem[] | null {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > 50) return null;
  const items: PlanItem[] = [];
  const seen = new Set<string>();
  for (const it of raw) {
    if (!it || typeof it !== 'object') return null;
    const alias = String(it.alias || '');
    if (!ALIAS_REGEX.test(alias) || !ALLOWED_ALIASES.has(alias)) return null;
    if (seen.has(alias)) continue; // dedupe: alias sama tidak dieksekusi dua kali
    seen.add(alias);
    const risk = String(it.risk || 'MEDIUM').toUpperCase();
    if (!['LOW', 'MEDIUM', 'HIGH'].includes(risk)) return null;
    items.push({
      findingId: String(it.findingId || alias).slice(0, 80),
      alias,
      risk,
      reversible: it.reversible !== false,
      preState: typeof it.preState === 'string' ? it.preState.slice(0, 500) : undefined,
      postStateExpected: typeof it.postStateExpected === 'string' ? it.postStateExpected.slice(0, 500) : undefined
    });
  }
  return items;
}

// 1. Operator/dashboard membuat rencana per temuan (belum ada eksekusi)
app.post('/api/remediation-plan', requireApiKey, (req, res) => {
  const { deviceId, items: rawItems, createdBy } = req.body || {};
  if (!deviceId || typeof deviceId !== 'string') {
    return res.status(400).json({ status: 'rejected', reason: 'deviceId wajib diisi.' });
  }
  // PowerShell `ConvertTo-Json` mengirim item tunggal sebagai objek, bukan array.
  const items = validateItems(Array.isArray(rawItems) ? rawItems : rawItems ? [rawItems] : rawItems);
  if (!items) {
    return res.status(400).json({ status: 'rejected', reason: 'items tidak valid: 1–50 item, alias harus salah satu allowlist (16 enforce + 4 advisory), risk LOW|MEDIUM|HIGH.' });
  }
  if (!items.some(i => !ADVISORY_ALIASES.has(i.alias))) {
    return res.status(400).json({ status: 'rejected', reason: 'Plan harus punya minimal satu langkah enforce (advisory saja tidak cukup).' });
  }
  const plan: Plan = {
    planId: `PLAN-${Date.now()}-${Math.floor(Math.random() * 1e6)}`,
    deviceId: String(deviceId).slice(0, 64),
    createdBy: String(createdBy || 'operator').slice(0, 80),
    createdAt: new Date().toISOString(),
    items,
    status: 'PLANNED',
    updatedAt: new Date().toISOString()
  };
  plansStore.set(plan.planId, plan);
  savePlans(plansStore);
  return res.json({ status: 'success', plan });
});

// 2. Operator menyetujui rencana → server menerbitkan nonce + HMAC signature + expiry (token untuk agent)
// Token boleh diterbitkan ulang HANYA jika token sebelumnya sudah kedaluwarsa, agar plan tidak macet.
const TOKEN_TTL_MS = Math.max(Number(process.env.REMEDIATION_TOKEN_TTL_MS) || 10 * 60 * 1000, 100);
const EVIDENCE_GRACE_MS = Math.max(Number(process.env.REMEDIATION_EVIDENCE_GRACE_MS) || 60 * 60 * 1000, TOKEN_TTL_MS); // batas kirim evidence setelah approval
app.post('/api/remediation-approve', requireApiKey, (req, res) => {
  if (!HMAC_SECRET) {
    return res.status(503).json({ status: 'rejected', reason: 'Server belum siap: set HMAC_SECRET di environment.' });
  }
  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, any>;
  const plan = plansStore.get(String(body.planId || ''));
  if (!plan) return res.status(404).json({ status: 'rejected', reason: 'Plan tidak ditemukan.' });
  if (plan.status !== 'PLANNED' && plan.status !== 'APPROVED') {
    return res.status(409).json({ status: 'rejected', reason: `Transisi tidak diizinkan: ${plan.status} → APPROVED.` });
  }
  const force = body.force === true;
  if (!force && plan.status === 'APPROVED' && plan.expiresAt && Date.now() < plan.expiresAt) {
    return res.status(409).json({
      status: 'rejected',
      reason: 'Token lama masih berlaku. Tunggu hingga kedaluwarsa sebelum menerbitkan token baru (agar token agent tidak bentrok).'
    });
  }
  plan.approvedBy = String(body.approvedBy || plan.approvedBy || 'operator').slice(0, 80);
  plan.approvedAt = new Date().toISOString();
  plan.nonce = crypto.randomBytes(32).toString('hex');
  plan.expiresAt = Date.now() + TOKEN_TTL_MS;
  plan.evidenceDeadline = Date.now() + EVIDENCE_GRACE_MS;
  plan.signature = signPlan(plan);
  plan.status = 'APPROVED';
  plan.updatedAt = new Date().toISOString();
  plansStore.set(plan.planId, plan);
  savePlans(plansStore);
  // Kembalikan plan LENGKAP sekali ini (berisi nonce/signature) untuk dipakai
  // operator menyusun plan.json agent. GET di bawah tetap diredaksi (toPublicPlan).
  return res.json({ status: 'success', planId: plan.planId, nonce: plan.nonce, expiresAt: plan.expiresAt, evidenceDeadline: plan.evidenceDeadline, signature: plan.signature, token: `${plan.nonce}.${plan.signature}`, plan: { ...plan } });
});

// 3. Agent mengirim evidence eksekusi/verifikasi (setelah validasi nonce + signature + expiry + anti-replay)
// Catatan jujur: status EXECUTING bersifat idempoten (nonce belum dikonsumsi) agar agent dapat
// memanggil ulang; nonce baru dikonsumsi persisten pada VERIFIED/ROLLED_BACK/FAILED.
app.post('/api/remediation-verify', requireApiKey, rateLimit(60), (req, res) => {
  const auth = verifySignedRequest(
    req,
    HMAC_SECRET,
    'Server belum siap: set HMAC_SECRET di environment.'
  );
  if (!auth.ok) {
    return res.status(auth.status).json({ status: 'rejected', reason: auth.reason });
  }
  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, any>;
  const { planId, nonce, toStatus, evidence } = body;
  const plan = plansStore.get(String(planId || ''));
  if (!plan) return res.status(404).json({ status: 'rejected', reason: 'Plan tidak ditemukan.' });
  const target = String(toStatus || '').toUpperCase() as PlanStatus;
  if (!['EXECUTING', 'VERIFIED', 'ROLLED_BACK', 'FAILED'].includes(target)) {
    return res.status(400).json({ status: 'rejected', reason: 'toStatus tidak valid (EXECUTING|VERIFIED|ROLLED_BACK|FAILED).' });
  }
  if (!ALLOWED_TRANSITIONS[plan.status].includes(target)) {
    return res.status(409).json({ status: 'rejected', reason: `Transisi tidak diizinkan: ${plan.status} → ${target}.` });
  }
  if (!plan.nonce || !safeEqualHex(String(nonce || '').toLowerCase(), plan.nonce.toLowerCase())) {
    return res.status(401).json({ status: 'rejected', reason: 'Nonce tidak valid.' });
  }
  const evidenceDeadline = plan.evidenceDeadline || plan.expiresAt;
  if (evidenceDeadline && Date.now() > evidenceDeadline) {
    return res.status(401).json({ status: 'rejected', reason: 'Batas waktu pengiriman evidence sudah habis. Terbitkan ulang token.' });
  }
  if (!plan.signature || !safeEqualHex(String(plan.signature).toLowerCase(), signPlan(plan))) {
    return res.status(401).json({ status: 'rejected', reason: 'Signature plan tidak valid.' });
  }
  if (usedNonces.has(plan.nonce)) {
    return res.status(401).json({ status: 'rejected', reason: 'Nonce sudah digunakan (replay).' });
  }

  const ev = Array.isArray(evidence) ? evidence.slice(0, 100) : [];
  // Status terminal wajib membawa bukti; EXECUTING boleh kosong (dipakai sebagai heartbeat).
  if (target !== 'EXECUTING' && ev.length === 0) {
    return res.status(400).json({ status: 'rejected', reason: `Evidence wajib dikirim untuk status ${target}.` });
  }
  for (const e of ev) {
    if (!e || typeof e !== 'object') return res.status(400).json({ status: 'rejected', reason: 'Evidence tidak valid.' });
    const stepIndex = Number(e.stepIndex);
    if (!Number.isInteger(stepIndex) || stepIndex < 0 || stepIndex > 49) return res.status(400).json({ status: 'rejected', reason: 'Evidence stepIndex tidak valid.' });
    if (typeof e.alias !== 'string' || !ALIAS_REGEX.test(e.alias) || !ALLOWED_ALIASES.has(e.alias)) return res.status(400).json({ status: 'rejected', reason: 'Evidence alias tidak valid.' });
    if (!Number.isFinite(Number(e.exitCode))) return res.status(400).json({ status: 'rejected', reason: 'Evidence exitCode tidak valid.' });
    if (typeof e.outputHash !== 'string' || !e.outputHash) return res.status(400).json({ status: 'rejected', reason: 'Evidence outputHash wajib ada.' });
    if (!plan.items.some(i => i.alias === e.alias)) {
      return res.status(400).json({ status: 'rejected', reason: 'Evidence alias tidak ada dalam plan.' });
    }
  }

  plan.status = target;
  const normalizedEvidence = ev.map(e => ({
    stepIndex: Number(e.stepIndex),
    alias: String(e.alias),
    exitCode: Number(e.exitCode),
    outputHash: String(e.outputHash).slice(0, 128),
    ...(typeof e.output === 'string' ? { output: e.output.slice(0, 400) } : {}),
    verified: e.verified === true,
    advisory: e.advisory === true || ADVISORY_ALIASES.has(String(e.alias)),
    ...(e.rollback && typeof e.rollback === 'object'
      ? {
          rollback: {
            exitCode: Number((e.rollback as any).exitCode) || 0,
            verified: (e.rollback as any).verified === true,
            outputHash: String((e.rollback as any).outputHash || '').slice(0, 128)
          }
        }
      : {}),
    at: new Date().toISOString()
  }));
  // Jangan hapus evidence lama saat heartbeat EXECUTING tanpa muatan.
  plan.evidence = normalizedEvidence.length > 0 ? normalizedEvidence : plan.evidence;
  plan.updatedAt = new Date().toISOString();
  plansStore.set(plan.planId, plan);
  if (['VERIFIED', 'ROLLED_BACK', 'FAILED'].includes(target) && plan.nonce) {
    usedNonces.add(plan.nonce);
    saveUsedNonces(usedNonces);
  }
  savePlans(plansStore);
  const evidenceCount = plan.evidence?.length ?? 0;
  if (['VERIFIED', 'ROLLED_BACK', 'FAILED'].includes(target)) {
    const verifiedCount = normalizedEvidence.filter(e => e.verified).length;
    appendAuditLogs([{
      id: `LOG-EVID-${plan.planId}-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      deviceId: plan.deviceId,
      deviceName: plan.deviceId,
      deviceRole: 'Endpoint (evidence agen)',
      action: target === 'ROLLED_BACK' ? 'ROLLBACK RESTORATION' : 'HARDENING REMEDIATION',
      operator: 'pasopati_remediate.py',
      preScore: 0,
      postScore: Math.round((verifiedCount / Math.max(normalizedEvidence.length, 1)) * 100),
      changesSummary: `Plan ${plan.planId} → ${target}: ${verifiedCount}/${normalizedEvidence.length} langkah terverifikasi (evidence HMAC valid).`,
      changesDetails: normalizedEvidence.slice(0, 10).map(e => `[${e.verified ? 'VERIFIED' : 'FAIL'}] ${e.alias} (exit ${e.exitCode})`),
      status: target === 'VERIFIED' ? 'SUCCESS' : target === 'FAILED' ? 'FAILED' : 'WARNING',
      storedInDb: true,
      planId: plan.planId
    }]);
  }
  console.log(`[PUSKODAL-REMEDIATION] Plan ${plan.planId} → ${target} | device: ${plan.deviceId} | evidence: ${evidenceCount} | HMAC: valid`);
  return res.json({ status: 'success', planId: plan.planId, planStatus: target, evidenceCount });
});

// Jangan pernah mengembalikan nonce/signature via GET. Token hanya dikirim sekali saat approve.
function toPublicPlan(p: Plan): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...p };
  delete copy.nonce;
  delete copy.signature;
  copy.hasToken = Boolean(p.nonce);
  return copy;
}

app.get('/api/remediation-plans', requireApiKey, (_req, res) => {
  const plans = Array.from(plansStore.values()).sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || ''))).map(toPublicPlan);
  return res.json({ plans });
});

// Endpoint khusus AGENT: mengembalikan plan LENGKAP (nonce+signature).
// Dipakai `pasopati_remediate.py --plan-id` agar host target cukup punya script itu saja.
app.get('/api/remediation-plans/:planId/agent', requireApiKey, rateLimit(30), (req, res) => {
  const plan = plansStore.get(req.params.planId);
  if (!plan) return res.status(404).json({ status: 'rejected', reason: 'Plan tidak ditemukan.' });
  if (!plan.nonce || !plan.signature) {
    return res.status(409).json({ status: 'rejected', reason: 'Plan belum disetujui; approve dulu di dashboard.' });
  }
  if (['VERIFIED', 'ROLLED_BACK', 'FAILED'].includes(plan.status)) {
    return res.status(409).json({ status: 'rejected', reason: `Plan sudah terminal (${plan.status}). Buat plan baru.` });
  }
  return res.json({ plan, token: `${plan.nonce}.${plan.signature}` });
});

app.get('/api/remediation-plans/:planId', requireApiKey, (req, res) => {
  const plan = plansStore.get(req.params.planId);
  if (!plan) return res.status(404).json({ status: 'rejected', reason: 'Plan tidak ditemukan.' });
  return res.json({ plan: toPublicPlan(plan) });
});

// Local audit log persistence (JSON-file based local database)
const AUDIT_DB_PATH = path.join(DATA_DIR, 'audit_logs.json');

function ensureAuditDbDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function readAuditLogs(): any[] {
  try {
    ensureAuditDbDir();
    if (!fs.existsSync(AUDIT_DB_PATH)) return [];
    const raw = fs.readFileSync(AUDIT_DB_PATH, 'utf-8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error('[PASOPATI] Gagal membaca local audit database:', (err as Error).message);
    return [];
  }
}

function writeAuditLogs(logs: any[]) {
  try {
    ensureAuditDbDir();
    writeJsonAtomic(AUDIT_DB_PATH, logs);
  } catch (err) {
    console.error('[PASOPATI] Gagal menulis local audit database:', (err as Error).message);
  }
}

function appendAuditLogs(entries: any[]) {
  if (!Array.isArray(entries) || entries.length === 0) return 0;
  const existing = readAuditLogs();
  const byId = new Map<string, any>();
  for (const l of existing) byId.set(String(l.id), l);
  for (const l of entries) byId.set(String(l.id), l);
  const merged = Array.from(byId.values())
    .sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')))
    .slice(0, 2000);
  writeAuditLogs(merged);
  return merged.length;
}

app.get('/api/audit-logs', requireApiKey, (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 2000, 1), 2000);
  const offset = Math.max(Number(req.query.offset) || 0, 0);
  const all = readAuditLogs().sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')));
  const logs = all.slice(offset, offset + limit);
  return res.json({ logs, total: all.length, offset, limit });
});

app.post('/api/audit-logs', requireApiKey, (req, res) => {
  const body = req.body;
  const incoming = Array.isArray(body) ? body : Array.isArray(body?.logs) ? body.logs : [];
  if (!Array.isArray(incoming) || incoming.length === 0) {
    return res.status(400).json({ status: 'rejected', reason: 'No audit log entries provided.' });
  }

  const MAX_PER_REQUEST = 200;
  const cleaned = incoming.slice(0, MAX_PER_REQUEST).map((e: any) => ({
    id: typeof e?.id === 'string' ? e.id.slice(0, 80) : `LOG-${Date.now()}`,
    timestamp: typeof e?.timestamp === 'string' ? e.timestamp.slice(0, 40) : new Date().toISOString().replace('T', ' ').substring(0, 19),
    deviceId: typeof e?.deviceId === 'string' ? e.deviceId.slice(0, 64) : 'UNKNOWN',
    deviceName: typeof e?.deviceName === 'string' ? e.deviceName.slice(0, 120) : 'UNKNOWN',
    deviceRole: typeof e?.deviceRole === 'string' ? e.deviceRole.slice(0, 160) : 'UNKNOWN',
    action: normalizeAuditAction(e?.action),
    operator: typeof e?.operator === 'string' ? e.operator.slice(0, 80) : 'operator',
    preScore: Number(e?.preScore) || 0,
    postScore: Number(e?.postScore) || 0,
    changesSummary: typeof e?.changesSummary === 'string' ? e.changesSummary.slice(0, 300) : '',
    changesDetails: Array.isArray(e?.changesDetails)
      ? e.changesDetails.filter((x: any) => typeof x === 'string').slice(0, 10).map((x: any) => String(x).slice(0, 200))
      : [],
    status: ['SUCCESS', 'WARNING', 'FAILED'].includes(String(e?.status)) ? String(e.status) : 'SUCCESS',
    storedInDb: true,
    ...(typeof e?.planId === 'string' ? { planId: e.planId.slice(0, 80) } : {}),
    ...(Array.isArray(e?.evidence)
      ? {
          evidence: e.evidence.slice(0, 100).map((ev: any) => ({
            stepIndex: Number(ev?.stepIndex) || 0,
            alias: typeof ev?.alias === 'string' ? ev.alias.slice(0, 64) : '',
            exitCode: Number(ev?.exitCode) || 0,
            outputHash: typeof ev?.outputHash === 'string' ? ev.outputHash.slice(0, 128) : '',
            verified: ev?.verified === true,
            ...(typeof ev?.at === 'string' ? { at: ev.at.slice(0, 40) } : {})
          }))
        }
      : {})
  }));

  const existing = readAuditLogs();
  const byId = new Map<string, any>();
  for (const l of existing) byId.set(String(l.id), l);
  for (const l of cleaned) byId.set(String(l.id), l);
  const merged = Array.from(byId.values())
    .sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')))
    .slice(0, 2000);
  writeAuditLogs(merged);
  return res.json({
    status: 'success',
    received: incoming.length,
    added: cleaned.length,
    rejected: Math.max(incoming.length - cleaned.length, 0),
    total: merged.length
  });
});

app.delete('/api/audit-logs', requireApiKey, (_req, res) => {
  writeAuditLogs([]);
  return res.json({ status: 'success' });
});

// Direct Downloads for Jury Evaluation & Field Deployment
// Download script PASOPATI. Alias /api/download/pasopati_agent.py tetap dilayani
// agar tautan lama tidak 404.
function serveScript(res: Response, file: string) {
  const filePath = path.resolve(process.cwd(), file);
  if (fs.existsSync(filePath)) {
    res.download(filePath, file);
  } else {
    res.status(404).send(`File ${file} tidak ditemukan`);
  }
}
app.get('/api/download/pasopati_audit.py', (_req, res) => serveScript(res, 'pasopati_audit.py'));
app.get('/api/download/pasopati_remediate.py', (_req, res) => serveScript(res, 'pasopati_remediate.py'));
app.get('/api/download/pasopati_agent.py', (_req, res) => serveScript(res, 'pasopati_audit.py'));

// Download app.py (Streamlit dashboard)
app.get('/api/download/app.py', (_req, res) => {
  const filePath = path.resolve(process.cwd(), 'app.py');
  if (fs.existsSync(filePath)) {
    res.download(filePath, 'app.py');
  } else {
    res.status(404).send('File app.py tidak ditemukan');
  }
});

// Download requirements.txt
app.get('/api/download/requirements.txt', (_req, res) => {
  const filePath = path.resolve(process.cwd(), 'requirements.txt');
  if (fs.existsSync(filePath)) {
    res.download(filePath, 'requirements.txt');
  } else {
    res.status(404).send('File requirements.txt tidak ditemukan');
  }
});

// Download README.md
app.get('/api/download/README.md', (_req, res) => {
  const filePath = path.resolve(process.cwd(), 'README.md');
  if (fs.existsSync(filePath)) {
    res.download(filePath, 'README.md');
  } else {
    res.status(404).send('File README.md tidak ditemukan');
  }
});

// Download Complete Project as ZIP (1-Click Package for user's laptop)
// Pure Node (archiver) — no Python dependency. Secrets (.env), data runtime,
// dan direktori dependency/build dikecualikan; template .env.example tetap ikut.
app.get('/api/download/project-zip', requireApiKey, (_req, res) => {
  const projectRoot = process.cwd();
  // Path unik per request agar dua unduhan bersamaan tidak saling menimpa.
  const zipPath = path.resolve(os.tmpdir(), `pasopati-project-${Date.now()}-${crypto.randomBytes(4).toString('hex')}.zip`);
  let cleanedUp = false;
  const cleanup = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    fs.unlink(zipPath, () => {});
  };

  const output = fs.createWriteStream(zipPath);
  const archive = new ZipArchive({ zlib: { level: 9 } });

  output.on('error', (err: NodeJS.ErrnoException) => {
    console.error('ZIP write error:', err.message);
    cleanup();
    if (!res.headersSent) {
      res.status(500).send('Gagal membuat file ZIP project');
    }
  });

  archive.on('warning', (err: ArchiverError) => {
    console.warn('ZIP warning:', err.message);
  });

  archive.on('error', (err: ArchiverError) => {
    console.error('ZIP generation error:', err.message);
    cleanup();
    if (!res.headersSent) {
      res.status(500).send('Gagal membuat file ZIP project');
    }
  });

  output.on('close', () => {
    res.download(zipPath, 'pasopati-project.zip', (err) => {
      if (err && !res.headersSent) {
        console.error('Error sending zip:', err.message);
        res.status(500).send('Gagal mengunduh file ZIP');
      }
      cleanup();
    });
  });

  archive.pipe(output);
  archive.glob('**/*', {
    cwd: projectRoot,
    dot: true,
    // Catatan: `skip` archiver tidak menyaring isi direktori bertanda `**/`, jadi
    // seluruh pengecualian direktori ditaruh di `ignore` (terbukti lewat uji ZIP).
    ignore: [
      '**/node_modules/**',
      'node_modules/**',
      '**/dist/**',
      'dist/**',
      '**/__pycache__/**',
      '__pycache__/**',
      '**/.vite/**',
      '**/.aistudio/**',
      '**/.git/**',
      '.git/**',
      '**/.freebuff/**',
      '.freebuff/**',
      '**/*.pyc',
      '**/*.zip',
      '**/*.log',
      'bun.lock',
      '.DS_Store',
      'audit_result.json',
      'audit.json',
      '.env',
      '.env.local',
      '.env.*.local',
      '.env.production',
      '.env.development',
      '.env.test',
      // Rahasia hidup: template .env.example tetap disertakan.
      'opencode.json',
      'reapprove.ps1',
      'token.txt',
      'bitlocker-recovery-*.txt',
      'CATATAN-PENGEMBANGAN.md',
      'data/**',
      '**/data/**'
    ]
  });
  archive.finalize();
});

// Resolve Python binary per platform — Windows typically ships `python`,
// Linux/macOS use `python3`.
function resolvePythonBinary(): string {
  return process.platform === 'win32' ? 'python' : 'python3';
}

function runHostAuditAgent(unit: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const agentScript = path.resolve(process.cwd(), 'pasopati_audit.py');
    const outputPath = path.resolve(os.tmpdir(), `audit_${Date.now()}_${process.pid}_${crypto.randomBytes(3).toString('hex')}.json`);

    execFile(
      resolvePythonBinary(),
      [agentScript, '-u', unit, '-o', outputPath, '-q', '--no-elevate'],
      { timeout: 120_000, maxBuffer: 4 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          try {
            if (fs.existsSync(outputPath)) fs.unlinkSync(outputPath);
          } catch { /* abaikan */ }
          const killed = (error as any)?.killed ? ' (timeout 120s)' : '';
          const diagnostics = String(stderr || stdout || '').trim().slice(-600);
          return reject(new Error((error?.message || 'Deep agent execution failed') + killed + (diagnostics ? ` — ${diagnostics}` : '')));
        }
        try {
          const data = JSON.parse(fs.readFileSync(outputPath, 'utf-8'));
          try {
            if (fs.existsSync(outputPath)) fs.unlinkSync(outputPath);
          } catch { /* abaikan */ }
          return resolve(data);
        } catch (parseErr: any) {
          try {
            if (fs.existsSync(outputPath)) fs.unlinkSync(outputPath);
          } catch { /* abaikan */ }
          return reject(new Error('Deep agent produced invalid JSON: ' + (parseErr?.message || 'unknown')));
        }
      }
    );
  });
}

// Live Container/Host Scan Execution — delegates to the standalone deep agent.
// No fabricated fallback: if the agent is unavailable we fail honestly (503).
app.post('/api/scan-host', requireApiKey, asyncHandler(async (req, res) => {
  const rawUnitName = (req.body && typeof req.body === 'object' ? (req.body as any).unitName : '');
  const targetUnit = String(rawUnitName || 'PASOPATI-HOST-RUNTIME').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64);
  try {
    const data = await runHostAuditAgent(targetUnit);
    if (!data?.scoring) {
      throw new Error('Deep agent response is missing scoring block');
    }
    return res.json(data);
  } catch (err: any) {
    console.error('[PUSKODAL-SCAN] Live host scan gagal:', err?.message || err);
    return res.status(503).json({
      error: 'Live host scan tidak tersedia pada server ini.',
      reason: 'Deep agent subprocess gagal.',
      detail: err?.message || 'unknown'
    });
  }
}));

// Error middleware global: request cacat tidak boleh mematikan proses.
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  const isBodyParse = err?.type === 'entity.parse.failed' || err instanceof SyntaxError;
  const status = isBodyParse ? 400 : Number(err?.status) || 500;
  console.error('[PASOPATI] Request error:', err?.message || err);
  if (res.headersSent) return;
  res.status(status).json({
    status: 'rejected',
    reason: isBodyParse ? 'Body JSON tidak valid.' : 'Terjadi kesalahan internal pada server.',
    ...(process.env.NODE_ENV !== 'production' ? { detail: String(err?.message || err) } : {})
  });
});

async function startServer() {
  const isDev = process.env.NODE_ENV !== 'production';

  if (isDev) {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
        watch: null
      },
      appType: 'spa'
    });

    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    // Aset ber-hash boleh di-cache lama; index.html tetap no-store dari middleware global.
    app.use('/assets', express.static(path.join(distPath, 'assets'), { maxAge: '1y', immutable: true }));
    app.use(express.static(distPath, { maxAge: 0 }));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[PASOPATI] Command Center server running at http://0.0.0.0:${PORT}`);
  });

  server.on('error', (err: any) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`[PASOPATI] Port ${PORT} already in use.`);
    } else {
      console.error('[PASOPATI] Server error:', err);
    }
  });
}

startServer().catch(err => {
  console.error('[PASOPATI] Server failed to start:', err);
});
