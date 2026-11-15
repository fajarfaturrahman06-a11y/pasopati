import express from 'express';
import { createServer as createViteServer } from 'vite';
import type { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import os from 'os';
import https from 'https';
import { execFile } from 'child_process';
import { ZipArchive, type ArchiverError } from 'archiver';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import crypto from 'crypto';
import { normalizeAuditAction } from './src/auditActions';
import { redactSensitive } from './src/redaction';
import { findEndpointByIdentity, normalizeEndpointInput, readEndpointRecords, writeEndpointRecords } from './src/endpointStore';
import type { EndpointRecord } from './src/endpointStore';
import { appendEndpointHealthAuditRecord, readEndpointHealthAuditRecords } from './src/endpointHealthAuditStore';
import type { EndpointHealthAuditEventType, EndpointHealthAuditRecord } from './src/endpointHealthAuditStore';
import { appendActivityAuditRecord, readActivityAuditRecords } from './src/activityAuditStore';
import type { ActivityAuditEventType } from './src/activityAuditStore';
import { isValidPassword, isValidUsername, SESSION_TTL_SECONDS, UserSessionStore } from './src/userSessions';
import { writeJsonAtomicSync } from './src/atomicWrite';

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
const SESSION_COOKIE = 'pasopati_session';
const userSessionStore = new UserSessionStore(
  path.join(DATA_DIR, 'auth.sqlite'),
  process.env.PASOPATI_ADMIN_USERNAME || '',
  process.env.PASOPATI_ADMIN_PASSWORD || ''
);

/** Tulis JSON secara atomik (temp + fsync + rename retry) agar file state tidak setengah jadi. */
function writeJsonAtomic(filePath: string, value: unknown) {
  writeJsonAtomicSync(filePath, value);
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

// ===== Identitas & RBAC =====
// Master PASOPATI_API_KEY = admin (bootstrap/kompatibilitas). Selain itu ada
// operator ber-role dan host ter-enrol dengan kunci sendiri. Yang disimpan hanya
// hash SHA-256 kuncinya; kunci mentah ditampilkan sekali saat dibuat.
type Role = 'viewer' | 'planner' | 'approver' | 'executor' | 'admin' | 'agent';
interface Principal { name: string; role: Role; kind: 'master' | 'operator' | 'host' | 'session'; hostId?: string }
interface OperatorRecord { name: string; role: Role; keyHash: string; createdAt: string; revokedAt?: string; lastSeenAt?: string }
interface HostRecord { hostId: string; name: string; keyHash: string; createdAt: string; revokedAt?: string; lastSeenAt?: string }

const OPERATORS_PATH = path.join(DATA_DIR, 'operators.json');
const HOSTS_PATH = path.join(DATA_DIR, 'hosts.json');
const OPERATOR_ROLES: Role[] = ['viewer', 'planner', 'approver', 'executor'];

function sha256(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function readJsonArray<T>(filePath: string): T[] {
  try {
    if (!fs.existsSync(filePath)) return [];
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

const operatorsStore: OperatorRecord[] = readJsonArray<OperatorRecord>(OPERATORS_PATH);
const hostsStore: HostRecord[] = readJsonArray<HostRecord>(HOSTS_PATH);

function saveOperators() {
  try { writeJsonAtomic(OPERATORS_PATH, operatorsStore); } catch (err) {
    console.error('[PASOPATI] Gagal menulis operators:', (err as Error).message);
  }
}
function saveHosts() {
  try { writeJsonAtomic(HOSTS_PATH, hostsStore); } catch (err) {
    console.error('[PASOPATI] Gagal menulis hosts:', (err as Error).message);
  }
}

const HOST_KEY_HEADER = 'x-pasopati-host-key';

function resolvePrincipal(req: Request): Principal | null {
  const hostKey = String(req.headers[HOST_KEY_HEADER] || '').trim();
  if (hostKey) {
    const hash = sha256(hostKey);
    const host = hostsStore.find(h => h.keyHash === hash && !h.revokedAt);
    if (!host) return null;
    host.lastSeenAt = new Date().toISOString();
    return { name: host.name, role: 'agent', kind: 'host', hostId: host.hostId };
  }
  const provided = String(req.headers['x-pasopati-api-key'] || '').trim();
  if (provided) {
    if (API_KEY && safeEqualStrTop(provided, API_KEY)) {
      return { name: 'master', role: 'admin', kind: 'master' };
    }
    const hash = sha256(provided);
    const operator = operatorsStore.find(o => o.keyHash === hash && !o.revokedAt);
    if (operator) {
      operator.lastSeenAt = new Date().toISOString();
      return { name: operator.name, role: operator.role, kind: 'operator' };
    }
    return null;
  }
  const cookies = String(req.headers.cookie || '').split(';');
  const sessionCookie = cookies.map(part => part.trim()).find(part => part.startsWith(`${SESSION_COOKIE}=`));
  const token = sessionCookie ? sessionCookie.slice(SESSION_COOKIE.length + 1) : '';
  const session = token ? userSessionStore.getSession(token) : null;
  return session ? { name: session.username, role: session.role, kind: 'session' } : null;
}

function hasSameOrigin(req: Request): boolean {
  const origin = req.get('origin');
  if (!origin) return false;
  try {
    return new URL(origin).origin === `${req.protocol}://${req.get('host')}`;
  } catch {
    return false;
  }
}

function requireRole(...roles: Role[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!API_KEY && operatorsStore.length === 0 && hostsStore.length === 0 && userSessionStore.userCount === 0) {
      return res.status(503).json({ status: 'rejected', reason: 'Server belum siap: set PASOPATI_API_KEY di environment.' });
    }
    const principal = resolvePrincipal(req);
    if (!principal) {
      return res.status(401).json({ status: 'rejected', reason: 'Kredensial tidak valid atau sudah dicabut.' });
    }
    if (principal.role !== 'admin' && !roles.includes(principal.role)) {
      return res.status(403).json({ status: 'rejected', reason: `Role ${principal.role} tidak berhak untuk endpoint ini.` });
    }
    if (principal.kind === 'session' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !hasSameOrigin(req)) {
      return res.status(403).json({ status: 'rejected', reason: 'Origin request tidak valid.' });
    }
    (req as Request & { principal?: Principal }).principal = principal;
    return next();
  };
}

/** Hanya "sudah terautentikasi" (semua role). */
const requireApiKey = requireRole('viewer', 'planner', 'approver', 'executor', 'agent');

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
app.post('/api/analyze-threats', requireApiKey, rateLimit(20, 'analyze'), asyncHandler(async (req, res) => {
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
  const aiDisabled = (process.env.AI_DISABLED || '').trim() === '1';
  if (aiDisabled || !apiKey || apiKey === 'MY_GEMINI_API_KEY' || apiKey.length < 15 || apiKey.startsWith('MY_')) {
    return res.json({
      source: 'rule-based-fallback',
      analysis: getFallbackRiskAnalysis(deviceName, deviceRole, os, failChecks),
      opsec_sanitized: isOpsec,
      ...(aiDisabled ? { note: 'Mode air-gapped: AI cloud dimatikan (AI_DISABLED=1).' } : {})
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
// Bucket dipisah per nama endpoint — sebelumnya satu Map global membuat limit ingest
// dan evidence saling memakan kuota klien yang sama.
const rateBuckets = new Map<string, { count: number; resetAt: number }>();
const RATE_BUCKET_SOFT_LIMIT = 5000;
function rateLimit(maxPerMinute: number, name = 'default') {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = String((req.socket?.remoteAddress as string) || req.ip || 'unknown');
    const key = `${name}:${ip}`;
    const now = Date.now();
    // Bersihkan bucket kedaluwarsa agar Map tidak tumbuh tanpa batas.
    if (rateBuckets.size > RATE_BUCKET_SOFT_LIMIT) {
      for (const [bucketKey, value] of rateBuckets) {
        if (now > value.resetAt) rateBuckets.delete(bucketKey);
      }
    }
    const bucket = rateBuckets.get(key);
    if (!bucket || now > bucket.resetAt) {
      rateBuckets.set(key, { count: 1, resetAt: now + 60_000 });
      return next();
    }
    if (bucket.count >= maxPerMinute) {
      return res.status(429).json({ status: 'rejected', reason: 'Terlalu banyak permintaan, coba lagi nanti.' });
    }
    bucket.count += 1;
    return next();
  };
}

// Registry endpoint JSON persisten. Operasi baca-ubah-tulis pada route di bawah
// sengaja sinkron: Node hanya menjalankan satu handler JavaScript pada satu waktu.
function setSessionCookie(req: Request, res: Response, token: string, maxAgeSeconds: number) {
  const secure = req.secure || process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure ? '; Secure' : ''}`);
}

function clearSessionCookie(req: Request, res: Response) {
  const secure = req.secure || process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? '; Secure' : ''}`);
}

app.post('/api/auth/login', rateLimit(10, 'auth-login'), (req, res) => {
  if (!hasSameOrigin(req)) return res.status(403).json({ status: 'rejected', reason: 'Origin request tidak valid.' });
  if (!userSessionStore.userCount) {
    return res.status(503).json({ status: 'rejected', reason: 'Belum ada akun. Konfigurasikan PASOPATI_ADMIN_USERNAME dan PASOPATI_ADMIN_PASSWORD di environment lokal lalu jalankan ulang server.' });
  }
  const username = typeof req.body?.username === 'string' ? req.body.username : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const identity = userSessionStore.authenticate(username, password);
  if (!identity) return res.status(401).json({ status: 'rejected', reason: 'Username atau password tidak valid.' });
  const session = userSessionStore.createSession(identity.username);
  setSessionCookie(req, res, session.token, SESSION_TTL_SECONDS);
  return res.json({ authenticated: true, name: identity.username, role: identity.role, kind: 'session', expiresAt: session.expiresAt });
});

app.get('/api/auth/session', (req, res) => {
  const cookies = String(req.headers.cookie || '').split(';');
  const part = cookies.map(value => value.trim()).find(value => value.startsWith(`${SESSION_COOKIE}=`));
  const token = part ? part.slice(SESSION_COOKIE.length + 1) : '';
  const identity = token ? userSessionStore.getSession(token) : null;
  if (!identity) {
    if (token) clearSessionCookie(req, res);
    return res.json({ authenticated: false });
  }
  return res.json({ authenticated: true, name: identity.username, role: identity.role, kind: 'session' });
});

app.post('/api/auth/logout', (req, res) => {
  if (!hasSameOrigin(req)) return res.status(403).json({ status: 'rejected', reason: 'Origin request tidak valid.' });
  const cookies = String(req.headers.cookie || '').split(';');
  const part = cookies.map(value => value.trim()).find(value => value.startsWith(`${SESSION_COOKIE}=`));
  const token = part ? part.slice(SESSION_COOKIE.length + 1) : '';
  if (token) userSessionStore.deleteSession(token);
  clearSessionCookie(req, res);
  return res.status(204).end();
});

app.post('/api/auth/users', requireRole('admin'), rateLimit(20, 'auth-user-create'), (req, res) => {
  const principal = (req as Request & { principal?: Principal }).principal;
  if (principal?.kind !== 'session' || principal.role !== 'admin') {
    return res.status(403).json({ status: 'rejected', reason: 'Buat akun username/password hanya dapat dilakukan dari sesi admin.' });
  }
  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!isValidUsername(username)) return res.status(400).json({ status: 'rejected', reason: 'Username harus 3–40 karakter: huruf, angka, titik, garis bawah, atau tanda hubung.' });
  if (!isValidPassword(password)) return res.status(400).json({ status: 'rejected', reason: 'Password harus 12–256 karakter.' });
  try {
    userSessionStore.createViewer(username, password);
    return res.status(201).json({ username, role: 'viewer' });
  } catch (err) {
    const message = (err as Error).message;
    if (/UNIQUE constraint failed/i.test(message)) return res.status(409).json({ status: 'rejected', reason: 'Username sudah digunakan.' });
    return res.status(400).json({ status: 'rejected', reason: message });
  }
});

const ENDPOINTS_PATH = path.join(DATA_DIR, 'endpoint_inventory.json');
const ENDPOINT_HEALTH_AUDIT_DB_PATH = path.join(DATA_DIR, 'endpoint_health_audit.sqlite');
const ACTIVITY_AUDIT_DB_PATH = path.join(DATA_DIR, 'activity_audit.sqlite');
const MAX_ENDPOINT_BODY_BYTES = 1024 * 1024;

function endpointRecords(): EndpointRecord[] {
  return readEndpointRecords(ENDPOINTS_PATH);
}

/**
 * Tempelkan waiver aktif ke salinan record saat dibaca. Waiver tetap satu sumber
 * (waivers.json); status tidak pernah ikut ditulis ke endpoint_inventory.json,
 * sehingga polling 5 detik tidak menghapus WAIVED.
 */
function withActiveWaivers(record: EndpointRecord): EndpointRecord {
  const active = activeWaivers(record.id);
  if (active.length === 0) return record;
  return {
    ...record,
    checks: (record.checks || []).map(check => {
      const waiver = active.find(item => item.parameter === check.parameter);
      return waiver ? { ...check, status: 'WAIVED' as const, waiver } : check;
    })
  };
}

function endpointBodyTooLarge(req: Request, res: Response): boolean {
  const raw = (req as Request & { rawBody?: Buffer }).rawBody;
  if (raw && raw.length > MAX_ENDPOINT_BODY_BYTES) {
    res.status(413).json({ status: 'rejected', reason: 'Payload endpoint melebihi batas 1 MB.' });
    return true;
  }
  return false;
}

function endpointActor(req: Request): string {
  return (req as Request & { principal?: Principal }).principal?.name || 'operator';
}

/**
 * Catat aktivitas baca-saja (unduhan berkas, scan realtime) untuk panel
 * "Aktivitas & Akses" yang hanya bisa dibaca admin. Kegagalan tulis tidak
 * boleh menggagalkan respons utama, jadi galat hanya dilog.
 */
function recordActivity(
  req: Request,
  eventType: ActivityAuditEventType,
  subject: string,
  detail: string,
  status: 'SUCCESS' | 'FAILED',
  planId?: string
) {
  try {
    const principal = resolvePrincipal(req);
    const ip = String(req.ip || req.socket?.remoteAddress || '').slice(0, 128);
    appendActivityAuditRecord(ACTIVITY_AUDIT_DB_PATH, {
      id: crypto.randomUUID(),
      eventType,
      occurredAt: new Date().toISOString(),
      actor: (principal?.name || 'anonim').slice(0, 80),
      actorRole: (principal?.role || 'anonim').slice(0, 20),
      ...(ip ? { sourceIp: ip } : {}),
      ...(planId ? { planId: planId.slice(0, 60) } : {}),
      subject: subject.slice(0, 160),
      detail: detail.slice(0, 200),
      status
    });
  } catch (err) {
    console.error('[PASOPATI] Gagal menulis aktivitas audit:', (err as Error).message);
  }
}

function buildEndpointHealthAuditRecord(input: {
  eventType: EndpointHealthAuditEventType;
  endpointId: string;
  accessedBy: string;
  accessIp?: string;
  approvedBy?: string;
  approvedAt?: string;
  planId?: string;
}): EndpointHealthAuditRecord {
  const endpoint = endpointRecords().find(item =>
    item.id === input.endpointId || item.agentId === input.endpointId || item.hostname === input.endpointId
  );
  const capturedAt = new Date().toISOString();
  const checks = endpoint?.checks || [];
  const latest = endpoint?.history?.at(-1);
  const countStatus = (status: string) => checks.filter(check => check.status === status).length;
  const count = (historical: unknown, status: string) => Number.isFinite(Number(historical))
    ? Number(historical)
    : countStatus(status);
  return {
    id: crypto.randomUUID(),
    eventType: input.eventType,
    occurredAt: capturedAt,
    accessedBy: input.accessedBy,
    ...(input.accessIp ? { accessIp: input.accessIp.slice(0, 128) } : {}),
    ...(input.approvedBy ? { approvedBy: input.approvedBy } : {}),
    ...(input.approvedAt ? { approvedAt: input.approvedAt } : {}),
    ...(input.planId ? { planId: input.planId.slice(0, 100) } : {}),
    target: {
      endpointId: endpoint?.id || input.endpointId.slice(0, 120),
      name: endpoint?.name || 'Unknown endpoint',
      hostname: endpoint?.hostname || '',
      role: endpoint?.role || '',
      os: endpoint?.os || '',
      endpointUser: endpoint?.user || '',
      ip: endpoint?.ip || '',
      mac: endpoint?.mac || '',
      ...(endpoint?.deletedAt ? { deletedAt: endpoint.deletedAt } : {})
    },
    computerCondition: {
      capturedAt,
      captureStatus: endpoint ? 'CAPTURED' : 'NOT_FOUND',
      latestAuditAt: latest?.timestamp || null,
      score: latest && Number.isFinite(Number(latest.score)) ? Number(latest.score) : null,
      passCount: count(latest?.passCount, 'PASS'),
      warningCount: count(latest?.warnCount, 'WARNING'),
      failCount: count(latest?.failCount, 'FAIL'),
      totalChecks: checks.length || count(latest?.passCount, 'PASS') + count(latest?.warnCount, 'WARNING') + count(latest?.failCount, 'FAIL'),
      quarantined: endpoint?.isQuarantined === true,
      openPorts: (endpoint?.openPorts || []).slice(0, 512),
      failedControls: checks.filter(check => check.status === 'FAIL').slice(0, 30).map(check => String(check.parameter).slice(0, 200)),
      warningControls: checks.filter(check => check.status === 'WARNING').slice(0, 30).map(check => String(check.parameter).slice(0, 200))
    }
  };
}

function addEndpointChange(record: EndpointRecord, action: EndpointRecord['changeHistory'][number]['action'], actor: string, source: 'operator' | 'agent', summary: string) {
  record.changeHistory = [...(record.changeHistory || []), { at: new Date().toISOString(), action, actor, source, summary }].slice(-100);
}

function saveEndpointAudit(record: EndpointRecord, action: string, actor: string, summary: string) {
  // Strict: file audit korup harus menggagalkan operasi, bukan diam-diam di-seal ulang.
  appendAuditLogs([{
    id: `ENDPOINT-${record.id}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    deviceId: record.id,
    deviceName: record.name,
    deviceRole: record.role,
    action: 'BASELINE RECON',
    operator: actor,
    preScore: 0,
    postScore: Number(record.history?.at(-1)?.score) || 0,
    changesSummary: `${action}: ${summary}`.slice(0, 300),
    changesDetails: [`Endpoint ID: ${record.id}`, `Hostname: ${record.hostname}`],
    status: 'SUCCESS',
    storedInDb: true
  }], true);
}

/** Kembalikan registry ke kondisi sebelum perubahan ketika audit gagal ditulis. */
function restoreEndpointRecords(previous: EndpointRecord[]): boolean {
  try {
    writeEndpointRecords(ENDPOINTS_PATH, previous);
    return true;
  } catch (err) {
    console.error('[PASOPATI] Gagal memulihkan registry setelah audit gagal:', (err as Error).message);
    return false;
  }
}

function endpointAuditFailure(res: Response, previous: EndpointRecord[], auditError: unknown) {
  const restored = restoreEndpointRecords(previous);
  const detail = auditError instanceof Error ? auditError.message : 'tidak diketahui';
  console.error('[PASOPATI] Audit endpoint gagal:', detail);
  return res.status(500).json({
    status: 'rejected',
    reason: restored
      ? 'Audit log tidak dapat ditulis; perubahan endpoint dibatalkan agar riwayat tetap utuh.'
      : 'Audit log tidak dapat ditulis dan pemulihan registry juga gagal; periksa data secara manual.',
    auditError: detail
  });
}

function containsControlCharacter(value: string): boolean {
  return Array.from(value).some(char => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127);
}

function normalizeAgentTelemetry(payload: unknown, headerUnit: string | undefined) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Body telemetri harus berupa object JSON.');
  const body = payload as Record<string, any>;
  const metadata = body.metadata;
  const scoring = body.scoring;
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw new Error('metadata wajib berupa object.');
  if (!scoring || typeof scoring !== 'object' || Array.isArray(scoring)) throw new Error('scoring wajib berupa object.');
  const rawUnit = metadata.tactical_unit ?? headerUnit;
  if (typeof rawUnit !== 'string' || !rawUnit.trim() || rawUnit.length > 64 || containsControlCharacter(rawUnit)) {
    throw new Error('metadata.tactical_unit wajib berupa teks 1–64 karakter yang valid.');
  }
  if (headerUnit && metadata.tactical_unit && headerUnit.trim() !== String(metadata.tactical_unit).trim()) {
    throw new Error('X-Pasopati-Unit tidak cocok dengan metadata.tactical_unit.');
  }
  const unit = rawUnit.trim();
  const device = body.device_info === undefined ? {} : body.device_info;
  if (!device || typeof device !== 'object' || Array.isArray(device)) throw new Error('device_info harus berupa object.');
  const score = Number(scoring.cyber_readiness_score ?? 0);
  if (!Number.isFinite(score) || score < 0 || score > 100) throw new Error('scoring.cyber_readiness_score harus 0–100.');
  const count = (field: string) => {
    const value = Number(scoring[field] ?? 0);
    if (!Number.isInteger(value) || value < 0 || value > 100000) throw new Error(`scoring.${field} harus integer non-negatif.`);
    return value;
  };
  const passed = count('passed_checks');
  const warned = count('warning_checks');
  const failed = count('failed_checks');
  const total = count('total_checks');
  if (total && passed + warned + failed > total) throw new Error('Jumlah PASS/WARNING/FAIL melebihi total_checks.');
  if (body.compliance_matrix !== undefined && !Array.isArray(body.compliance_matrix)) throw new Error('compliance_matrix harus berupa array.');
  const matrix = Array.isArray(body.compliance_matrix) ? body.compliance_matrix : [];
  if (matrix.length > 500) throw new Error('compliance_matrix maksimal berisi 500 kontrol.');
  const checks = matrix.map((item: any, index: number) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error(`compliance_matrix[${index}] harus berupa object.`);
    const rawStatus = String(item.status || '').toUpperCase();
    const status = rawStatus === 'SKIPPED' ? 'N/A' : rawStatus;
    if (!['PASS', 'WARNING', 'FAIL', 'N/A', 'WAIVED'].includes(status)) throw new Error(`compliance_matrix[${index}].status tidak valid.`);
    return {
      id: `agent-${index + 1}`,
      parameter: String(item.parameter || item.param || '').trim().slice(0, 200),
      category: String(item.category || item.cat || 'Network & Port').slice(0, 80),
      cis_id: String(item.cis_id || item.cis || '').slice(0, 120),
      status,
      details: String(item.details || item.detail || '').slice(0, 2000),
      mitigation: String(item.mitigation || '').slice(0, 2000)
    };
  });
  const rawPorts = device.ports_list ?? [];
  if (!Array.isArray(rawPorts) || rawPorts.length > 512) throw new Error('device_info.ports_list harus array dengan maksimal 512 port.');
  // Identitas mesin stabil (UUID dari agen). tactical_unit hanya nama; agen lama
  // tanpa machine_id tetap memakai unit agar kompatibel.
  const rawMachineId = metadata.machine_id ?? body.machine_id;
  let agentIdentity = unit;
  if (rawMachineId !== undefined && rawMachineId !== null && String(rawMachineId).trim() !== '') {
    const machineId = String(rawMachineId).trim();
    if (!/^[A-Za-z0-9._:-]{8,128}$/.test(machineId)) {
      throw new Error('metadata.machine_id harus 8–128 karakter (huruf, angka, titik, garis bawah, titik dua, tanda hubung).');
    }
    agentIdentity = machineId;
  }
  const platformText = `${String(device.platform_type || '')} ${String(device.os || '')}`.toLowerCase();
  const platformType = platformText.includes('windows') ? 'windows' : (platformText.includes('embedded') || platformText.includes('openwrt') ? 'embedded' : 'linux');
  const receivedAt = new Date();
  const endpoint = normalizeEndpointInput({
    agentId: agentIdentity,
    name: unit,
    hostname: typeof device.hostname === 'string' && device.hostname.trim() ? device.hostname.trim() : unit,
    role: typeof metadata.device_role === 'string' ? metadata.device_role : `Endpoint (${String(device.platform_type || 'telemetri agen')})`,
    os: typeof device.os === 'string' && device.os.trim() ? device.os : 'Unknown',
    platformType,
    ip: typeof device.primary_ip === 'string' && device.primary_ip !== 'unknown' ? device.primary_ip : '',
    mac: typeof device.mac_address === 'string' ? device.mac_address : '',
    user: typeof device.active_user === 'string' ? device.active_user : '',
    openPorts: rawPorts.map(Number),
    checks,
    history: [{
      timestamp: receivedAt.toISOString(), score, passCount: passed, warnCount: warned,
      failCount: failed, event: 'Telemetry Ingest Puskodal'
    }]
  });
  return { unit, score, passed, warned, failed, total, endpoint, receivedAt };
}

function upsertAgentEndpoint(payload: unknown, headerUnit: string | undefined, eventId: string) {
  const incoming = normalizeAgentTelemetry(payload, headerUnit);
  const explicitRole = Boolean((payload as any)?.metadata?.device_role);
  const records = endpointRecords();
  const previousRecords = records.map(record => record);
  const existing = findEndpointByIdentity(records, incoming.endpoint);
  const duplicate = Boolean(existing?.telemetryEventIds?.includes(eventId));
  if (duplicate && existing) return { ...incoming, record: existing, created: false, duplicate: true, previousRecords };
  const previousHistory = existing?.history || [];
  const record: EndpointRecord = {
    ...(existing || {} as EndpointRecord),
    ...incoming.endpoint,
    id: existing?.id || crypto.randomUUID(),
    name: existing?.name || incoming.endpoint.name || incoming.endpoint.hostname || 'Endpoint',
    role: (existing && !explicitRole ? existing.role : incoming.endpoint.role) || 'Endpoint',
    source: existing?.source || 'agent',
    createdAt: existing?.createdAt || incoming.receivedAt.toISOString(),
    updatedAt: incoming.receivedAt.toISOString(),
    created_at: existing?.created_at || existing?.createdAt || incoming.receivedAt.toISOString(),
    updated_at: incoming.receivedAt.toISOString(),
    revision: (existing?.revision || 0) + 1,
    lastSeenAt: incoming.receivedAt.toISOString(),
    isQuarantined: existing?.isQuarantined || false,
    history: [...previousHistory, ...(incoming.endpoint.history || [])].slice(-200),
    changeHistory: existing?.changeHistory || [],
    telemetryEventIds: [...(existing?.telemetryEventIds || []), eventId].slice(-200)
  };
  addEndpointChange(record, 'TELEMETRY', 'pasopati_audit.py', 'agent', `Skor ${incoming.score}/100; PASS ${incoming.passed}, WARN ${incoming.warned}, FAIL ${incoming.failed}.`);
  if (existing) records[records.findIndex(item => item.id === existing.id)] = record;
  else records.push(record);
  writeEndpointRecords(ENDPOINTS_PATH, records);
  return { ...incoming, record, created: !existing, duplicate: false, previousRecords };
}

app.get('/api/endpoints', requireApiKey, rateLimit(120, 'endpoints-read'), (_req, res) => {
  try {
    const endpoints = endpointRecords().filter(endpoint => !endpoint.deletedAt)
      .map(endpoint => {
        const quarantine = [endpoint.id, endpoint.agentId, endpoint.name].filter(Boolean)
          .map(key => quarantineRegistry.get(String(key))).find(Boolean);
        return withActiveWaivers({ ...endpoint, isQuarantined: quarantine ? quarantine.quarantined : endpoint.isQuarantined });
      })
      .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
    return res.json({ endpoints, total: endpoints.length, updatedAt: new Date().toISOString() });
  } catch (err) {
    console.error('[PASOPATI] Penyimpanan endpoint gagal dibaca:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Penyimpanan endpoint tidak dapat dibaca.' });
  }
});

app.get('/api/endpoints/:id', requireApiKey, rateLimit(120, 'endpoint-read'), (req, res) => {
  try {
    const endpoint = endpointRecords().find(item => item.id === req.params.id && !item.deletedAt);
    if (!endpoint) return res.status(404).json({ status: 'rejected', reason: 'Endpoint tidak ditemukan.' });
    return res.json({ endpoint: withActiveWaivers(endpoint) });
  } catch (err) {
    console.error('[PASOPATI] Penyimpanan endpoint gagal dibaca:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Penyimpanan endpoint tidak dapat dibaca.' });
  }
});

app.post('/api/endpoints', requireRole('planner', 'viewer'), rateLimit(30, 'endpoint-write'), (req, res) => {
  if (endpointBodyTooLarge(req, res)) return;
  try {
    const input = normalizeEndpointInput(req.body);
    const records = endpointRecords();
    const previous = records.map(record => record);
    const existing = findEndpointByIdentity(records, input);
    const ifMatch = String(req.get('If-Match') || '').replace(/^"|"$/g, '');
    const rawExpected = req.body?.expected_revision ?? (ifMatch ? Number(ifMatch) : undefined);
    let currentRevision = 1;
    if (existing) {
      currentRevision = Number.isSafeInteger(existing.revision) && existing.revision > 0 ? existing.revision : 1;
      if (!Number.isSafeInteger(rawExpected) || Number(rawExpected) < 1) {
        return res.status(428).json({ status: 'rejected', reason: 'Endpoint sudah ada; expected_revision wajib diisi agar tidak menimpa perubahan lain.', current_revision: currentRevision, endpoint: withActiveWaivers(existing) });
      }
      if (Number(rawExpected) !== currentRevision) {
        return res.status(409).json({ status: 'conflict', reason: 'Endpoint berubah sejak browser terakhir memuatnya. Data terbaru dikirim untuk mencegah lost update.', current_revision: currentRevision, endpoint: withActiveWaivers(existing) });
      }
    }
    const now = new Date().toISOString();
    const actor = endpointActor(req);
    const record: EndpointRecord = existing ? {
      ...existing, ...input, id: existing.id, source: existing.source,
      createdAt: existing.createdAt, updatedAt: now, created_at: existing.created_at || existing.createdAt,
      updated_at: now, revision: currentRevision + 1, changeHistory: existing.changeHistory || [],
      history: input.history?.length ? input.history : existing.history,
      isQuarantined: existing.isQuarantined
    } : {
      id: crypto.randomUUID(), name: input.name || input.hostname || 'Endpoint',
      hostname: input.hostname || input.name || 'Endpoint', role: input.role || 'Endpoint',
      os: input.os || 'Unknown', platformType: input.platformType || 'linux', ip: input.ip || '',
      mac: input.mac || '', user: input.user || '', openPorts: input.openPorts || [], checks: input.checks || [],
      isQuarantined: input.isQuarantined || false, history: input.history || [], agentId: input.agentId,
      source: 'operator', createdAt: now, updatedAt: now, created_at: now, updated_at: now, revision: 1, changeHistory: []
    };
    addEndpointChange(record, existing ? 'UPDATE' : 'CREATE', actor, 'operator', existing ? 'Upsert melalui API operator.' : 'Endpoint didaftarkan operator.');
    if (existing) records[records.findIndex(item => item.id === existing.id)] = record;
    else records.push(record);
    writeEndpointRecords(ENDPOINTS_PATH, records);
    try {
      saveEndpointAudit(record, existing ? 'ENDPOINT UPDATE' : 'ENDPOINT CREATE', actor, record.name);
    } catch (auditError) {
      return endpointAuditFailure(res, previous, auditError);
    }
    return res.status(existing ? 200 : 201).json({ status: 'success', created: !existing, endpoint: record });
  } catch (err) {
    const message = (err as Error).message;
    const clientError = /wajib|harus|melebihi|maksimal|tidak valid|mengandung|format|berupa|karakter/i.test(message);
    if (!clientError) console.error('[PASOPATI] Gagal menyimpan endpoint:', message);
    return res.status(clientError ? 400 : 500).json({ status: 'rejected', reason: clientError ? message : 'Penyimpanan endpoint gagal; perubahan tidak dikonfirmasi.' });
  }
});

app.put('/api/endpoints/:id', requireRole('planner', 'viewer'), rateLimit(30, 'endpoint-write'), (req, res) => {
  if (endpointBodyTooLarge(req, res)) return;
  try {
    const records = endpointRecords();
    const previous = records.map(record => record);
    const index = records.findIndex(item => item.id === req.params.id && !item.deletedAt);
    if (index < 0) return res.status(404).json({ status: 'rejected', reason: 'Endpoint tidak ditemukan.' });
    const patch = normalizeEndpointInput(req.body, true);
    const current = records[index];
    const currentRevision = Number.isSafeInteger(current.revision) && current.revision > 0 ? current.revision : 1;
    const ifMatch = String(req.get('If-Match') || '').replace(/^"|"$/g, '');
    const expectedRevision = req.body?.expected_revision ?? (ifMatch ? Number(ifMatch) : undefined);
    if (!Number.isSafeInteger(expectedRevision) || Number(expectedRevision) < 1) {
      return res.status(428).json({ status: 'rejected', reason: 'expected_revision wajib diisi; muat versi endpoint terbaru sebelum menyimpan.' });
    }
    if (Number(expectedRevision) !== currentRevision) {
      return res.status(409).json({ status: 'conflict', reason: 'Endpoint berubah sejak browser terakhir memuatnya. Data terbaru dikirim untuk mencegah lost update.', current_revision: currentRevision, endpoint: withActiveWaivers(current) });
    }
    const now = new Date().toISOString();
    const merged: EndpointRecord = { ...current, ...patch, id: current.id, source: current.source, createdAt: current.createdAt, updatedAt: now, created_at: current.created_at || current.createdAt, updated_at: now, revision: currentRevision + 1 };
    if ((patch.agentId !== undefined || patch.mac !== undefined || patch.hostname !== undefined) &&
        records.some(item => item.id !== current.id && !item.deletedAt && findEndpointByIdentity([item], merged))) {
      return res.status(409).json({ status: 'rejected', reason: 'Identitas endpoint sudah terdaftar pada endpoint lain.' });
    }
    addEndpointChange(merged, 'UPDATE', endpointActor(req), 'operator', 'Endpoint diperbarui melalui API.');
    records[index] = merged;
    writeEndpointRecords(ENDPOINTS_PATH, records);
    try {
      saveEndpointAudit(merged, 'ENDPOINT UPDATE', endpointActor(req), merged.name);
    } catch (auditError) {
      return endpointAuditFailure(res, previous, auditError);
    }
    return res.json({ status: 'success', endpoint: merged });
  } catch (err) {
    const message = (err as Error).message;
    const clientError = /wajib|harus|melebihi|maksimal|tidak valid|mengandung|format|berupa|karakter/i.test(message);
    if (!clientError) console.error('[PASOPATI] Gagal memperbarui endpoint:', message);
    return res.status(clientError ? 400 : 500).json({ status: 'rejected', reason: clientError ? message : 'Penyimpanan endpoint gagal; perubahan tidak dikonfirmasi.' });
  }
});

app.delete('/api/endpoints/:id', requireRole('admin'), rateLimit(20, 'endpoint-delete'), (req, res) => {
  try {
    const records = endpointRecords();
    const previous = records.map(record => record);
    const endpoint = records.find(item => item.id === req.params.id && !item.deletedAt);
    if (!endpoint) return res.status(404).json({ status: 'rejected', reason: 'Endpoint tidak ditemukan.' });
    const actor = endpointActor(req);
    const now = new Date().toISOString();
    endpoint.deletedAt = now;
    endpoint.updatedAt = now;
    endpoint.updated_at = now;
    endpoint.revision = (endpoint.revision || 1) + 1;
    addEndpointChange(endpoint, 'DELETE', actor, 'operator', 'Endpoint diarsipkan (soft delete).');
    writeEndpointRecords(ENDPOINTS_PATH, records);
    try {
      saveEndpointAudit(endpoint, 'ENDPOINT DELETE', actor, endpoint.name);
    } catch (auditError) {
      return endpointAuditFailure(res, previous, auditError);
    }
    return res.json({ status: 'success', deleted: true, id: endpoint.id, deletedAt: now });
  } catch (err) {
    console.error('[PASOPATI] Gagal menghapus endpoint:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Penghapusan endpoint gagal; perubahan tidak dikonfirmasi.' });
  }
});

app.post('/api/ingest', rateLimit(60, 'ingest'), (req, res) => {
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
  const rawBody = (req as Request & { rawBody?: Buffer }).rawBody;
  if (rawBody && rawBody.length > MAX_ENDPOINT_BODY_BYTES) {
    return res.status(413).json({ status: 'rejected', reason: 'Payload telemetri melebihi batas 1 MB.' });
  }
  try {
    const unitHeader = typeof req.headers['x-pasopati-unit'] === 'string' ? req.headers['x-pasopati-unit'] : undefined;
    const eventId = crypto.createHash('sha256').update(auth.signature).digest('hex').slice(0, 32);
    const stored = upsertAgentEndpoint(req.body, unitHeader, eventId);
    const { unit, score, passed, warned, failed, total, receivedAt, record } = stored;

    // Drift history is derived from the durable endpoint score history and also
    // kept in memory for compatibility with existing dashboards.
    if (!Object.hasOwn(complianceDriftStore, unit)) {
      const units = Object.keys(complianceDriftStore);
      if (units.length >= 200) delete complianceDriftStore[units[0]];
      complianceDriftStore[unit] = [];
    }
    const drift = complianceDriftStore[unit];
    if (!stored.duplicate) drift.push({
      timestamp: receivedAt.toISOString().replace('T', ' ').substring(0, 16),
      score, passCount: passed, warnCount: warned, failCount: failed,
      event: 'Telemetry Ingest Puskodal'
    });
    if (drift.length > 200) drift.splice(0, drift.length - 200);

    const ingestEntry = {
      id: `INGEST-${record.id}-${eventId}`,
      timestamp: receivedAt.toISOString().replace('T', ' ').substring(0, 19),
      deviceId: record.id,
      deviceName: record.name,
      deviceRole: record.role,
      action: 'TELEMETRY INGESTION',
      operator: 'pasopati_audit.py',
      preScore: 0,
      postScore: score,
      changesSummary: `Telemetri audit bertanda tangan HMAC dari ${unit} (PASS ${passed} / WARN ${warned} / FAIL ${failed})`,
      changesDetails: [
        '[NYATA] Telemetri dari agen PASOPATI; endpoint dan hasil compliance tersimpan di registry pusat.',
        `Total parameter: ${total} | Skor: ${score}/100 | Host: ${record.hostname} | IP: ${record.ip || '—'} | MAC: ${record.mac || '—'}`
      ],
      status: 'SUCCESS',
      storedInDb: true
    };
    let totalLogs: number;
    try {
      totalLogs = appendAuditLogs([ingestEntry], true);
    } catch (auditError) {
      // Endpoint sudah tertulis; kembalikan registry agar audit dan registry
      // tidak berbeda. Signature belum dicatat sehingga retry tetap boleh.
      const restored = restoreEndpointRecords(stored.previousRecords);
      const detail = auditError instanceof Error ? auditError.message : 'tidak diketahui';
      console.error('[PUSKODAL-INGEST] Audit gagal:', detail);
      return res.status(500).json({
        status: 'rejected',
        reason: restored
          ? 'Audit log tidak dapat ditulis; telemetri dibatalkan agar registry dan audit tetap konsisten. Kirim ulang.'
          : 'Audit log gagal ditulis dan pemulihan registry gagal; periksa data manual.',
        auditError: detail
      });
    }
    recordIngestSignature(auth.signature);
    console.log(`[PUSKODAL-INGEST] Telemetri dari: ${unit} | Endpoint: ${record.id} | Score: ${score}/100 | HMAC: valid`);
    return res.json({
      status: 'success',
      message: `Telemetri dari ${unit} berhasil dicatat di Puskodal PASOPATI`,
      tactical_unit: unit,
      endpoint_id: record.id,
      endpoint_created: stored.created,
      signature_verified: true,
      stored: true,
      total_logs: totalLogs,
      timestamp: receivedAt.toISOString()
    });
  } catch (err) {
    const message = (err as Error).message;
    const clientError = /wajib|harus|melebihi|maksimal|tidak valid|tidak cocok|berupa|karakter|melebihi/i.test(message);
    if (!clientError) console.error('[PUSKODAL-INGEST] Gagal menyimpan telemetri:', message);
    return res.status(clientError ? 400 : 500).json({
      status: 'rejected',
      reason: clientError ? message : 'Penyimpanan endpoint atau audit log gagal; telemetri tidak dikonfirmasi.'
    });
  }
});


// Emergency Network Quarantine Vector (Kill-Switch) — mencatat status; agen host yang
// wajib mengeksekusi pemblokiran nyata (server tidak memutus koneksi endpoint sendiri).
app.post('/api/quarantine', requireRole('executor'), rateLimit(60, 'quarantine'), (req, res) => {
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
  try {
    const endpoint = endpointRecords().find(item => !item.deletedAt &&
      (item.agentId === unitId || item.id === unitId || item.hostname === unitId));
    const history = endpoint?.history || (Object.hasOwn(complianceDriftStore, unitId) ? complianceDriftStore[unitId] : []);
    return res.json({ unitId, history });
  } catch (err) {
    console.error('[PASOPATI] Gagal memulihkan compliance drift:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Riwayat compliance tidak dapat dibaca.' });
  }
});

// ===== Escrow kunci BitLocker =====
// Redundansi selain file lokal di host: bila host terkunci / backup hilang,
// operator masih bisa membuka volume. Disimpan 0600 di data/.
const ESCROW_PATH = path.join(DATA_DIR, 'bitlocker_escrow.json');
type EscrowEntry = { value: string; at: string };
type EscrowDevice = { recovery?: EscrowEntry; bootpw?: EscrowEntry };
const ESCROW_KINDS = new Set(['recovery', 'bootpw']);

function loadEscrow(): Record<string, EscrowDevice> {
  try {
    if (!fs.existsSync(ESCROW_PATH)) return {};
    const parsed = JSON.parse(fs.readFileSync(ESCROW_PATH, 'utf-8'));
    return parsed && typeof parsed === 'object' ? parsed as Record<string, EscrowDevice> : {};
  } catch (err) {
    console.error('[PASOPATI] Gagal membaca escrow BitLocker:', (err as Error).message);
    return {};
  }
}

function saveEscrow(store: Record<string, EscrowDevice>) {
  try {
    writeJsonAtomic(ESCROW_PATH, store);
  } catch (err) {
    console.error('[PASOPATI] Gagal menulis escrow BitLocker:', (err as Error).message);
  }
}

const escrowStore = loadEscrow();

app.post('/api/escrow', requireRole('executor', 'agent'), rateLimit(30, 'escrow'), (req, res) => {
  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, any>;
  const deviceId = String(body.deviceId || '').trim().slice(0, 64);
  const kind = String(body.kind || '').toLowerCase();
  const value = String(body.value || '').trim();
  if (!deviceId) return res.status(400).json({ status: 'rejected', reason: 'deviceId wajib diisi.' });
  if (!ESCROW_KINDS.has(kind)) return res.status(400).json({ status: 'rejected', reason: 'kind harus recovery|bootpw.' });
  if (!value || value.length > 400) return res.status(400).json({ status: 'rejected', reason: 'value wajib (maks 400 karakter).' });
  const device = escrowStore[deviceId] || {};
  device[kind as 'recovery' | 'bootpw'] = { value, at: new Date().toISOString() };
  escrowStore[deviceId] = device;
  saveEscrow(escrowStore);
  console.log(`[PUSKODAL-ESCROW] ${kind} untuk ${deviceId} disimpan (${value.length} char).`);
  return res.json({ status: 'success', deviceId, kind, stored: true });
});

app.get('/api/escrow/:deviceId', requireApiKey, (req, res) => {
  const deviceId = String(req.params.deviceId || '').slice(0, 64);
  return res.json({ deviceId, escrow: escrowStore[deviceId] || null });
});

// ===== Observability =====
const STARTED_AT = Date.now();
let APP_VERSION = '0.0.0';
try {
  APP_VERSION = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), 'package.json'), 'utf-8')).version || '0.0.0';
} catch { /* abaikan */ }

function healthSnapshot() {
  const now = Date.now();
  const active = Array.from(plansStore.values()).filter(p => p.status === 'APPROVED' || p.status === 'EXECUTING');
  const stale = active.filter(p => p.status === 'EXECUTING' && p.heartbeatAt && now - Date.parse(String(p.heartbeatAt)) > STALE_EXECUTING_MS);
  const silentHosts = hostsStore.filter(h => !h.revokedAt && h.lastSeenAt && now - Date.parse(String(h.lastSeenAt)) > 24 * 3600 * 1000);
  const chain = verifyAuditChain(readAuditLogs());
  return {
    status: chain.ok && stale.length === 0 ? 'ok' : 'degraded',
    version: APP_VERSION,
    uptimeSec: Math.floor((now - STARTED_AT) / 1000),
    activePlans: active.length,
    staleExecuting: stale.map(p => p.planId),
    auditChainOk: chain.ok,
    auditBrokenAt: chain.brokenAt,
    hosts: hostsStore.filter(h => !h.revokedAt).length,
    silentHosts: silentHosts.map(h => h.hostId)
  };
}

app.get('/api/health', requireRole('viewer', 'agent'), (_req, res) => {
  const snapshot = healthSnapshot();
  return res.status(snapshot.status === 'ok' ? 200 : 503).json(snapshot);
});

app.get('/api/metrics', requireRole('viewer'), (_req, res) => {
  const h = healthSnapshot();
  const lines = [
    '# HELP pasopati_up Server hidup.',
    '# TYPE pasopati_up gauge',
    'pasopati_up 1',
    '# HELP pasopati_version Versi aplikasi.',
    '# TYPE pasopati_version gauge',
    `pasopati_version{version="${h.version}"} 1`,
    '# HELP pasopati_active_plans Plan aktif (APPROVED/EXECUTING).',
    '# TYPE pasopati_active_plans gauge',
    `pasopati_active_plans ${h.activePlans}`,
    '# HELP pasopati_stale_executing Plan EXECUTING tanpa heartbeat.',
    '# TYPE pasopati_stale_executing gauge',
    `pasopati_stale_executing ${h.staleExecuting.length}`,
    '# HELP pasopati_hosts Host aktif ter-enrol.',
    '# TYPE pasopati_hosts gauge',
    `pasopati_hosts ${h.hosts}`,
    '# HELP pasopati_audit_chain_ok Integritas rantai audit (1 = valid).',
    '# TYPE pasopati_audit_chain_ok gauge',
    `pasopati_audit_chain_ok ${h.auditChainOk ? 1 : 0}`
  ];
  res.type('text/plain; version=0.0.4').send(lines.join('\n') + '\n');
});

// Manifest agen: hash SHA-256 + (opsional) tanda tangan HMAC dengan AGENT_SIGNING_KEY.
// Dipakai untuk mendeteksi versi/berkas agen yang diubah sebelum remediasi.
app.get('/api/agent/manifest', (_req, res) => {
  const files = ['pasopati_audit.py', 'pasopati_remediate.py'];
  const entries = files.map(name => {
    try {
      const full = path.resolve(process.cwd(), name);
      return { name, sha256: crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex') };
    } catch {
      return { name, sha256: null };
    }
  });
  const body: Record<string, unknown> = { version: APP_VERSION, generatedAt: new Date().toISOString(), files: entries };
  const key = (process.env.AGENT_SIGNING_KEY || '').trim();
  if (key) {
    body.signature = crypto.createHmac('sha256', key).update(stableStringify(entries)).digest('hex');
  }
  return res.json(body);
});

// ===== Enrolment host & operator (RBAC) =====
app.get('/api/whoami', requireApiKey, (req, res) => {
  const principal = (req as Request & { principal?: Principal }).principal as Principal;
  return res.json({ name: principal.name, role: principal.role, kind: principal.kind, hostId: principal.hostId });
});

app.get('/api/hosts', requireRole('viewer', 'agent'), (_req, res) => {
  return res.json({
    hosts: hostsStore.map(h => ({ hostId: h.hostId, name: h.name, createdAt: h.createdAt, lastSeenAt: h.lastSeenAt, revokedAt: h.revokedAt }))
  });
});

app.post('/api/hosts/enroll', requireRole('admin'), (req, res) => {
  const name = String(req.body?.name || '').trim().slice(0, 80) || 'host';
  const hostKey = crypto.randomBytes(32).toString('hex');
  const hostId = 'HOST-' + crypto.randomBytes(6).toString('hex');
  hostsStore.push({ hostId, name, keyHash: sha256(hostKey), createdAt: new Date().toISOString() });
  saveHosts();
  console.log(`[PUSKODAL-HOST] Enrol ${hostId} (${name}).`);
  return res.json({ status: 'success', hostId, name, hostKey });
});

app.post('/api/hosts/:hostId/revoke', requireRole('admin'), (req, res) => {
  const host = hostsStore.find(h => h.hostId === String(req.params.hostId || ''));
  if (!host) return res.status(404).json({ status: 'rejected', reason: 'Host tidak ditemukan.' });
  if (host.revokedAt) return res.json({ status: 'success', hostId: host.hostId, revoked: true, alreadyRevoked: true });
  host.revokedAt = new Date().toISOString();
  saveHosts();
  console.log(`[PUSKODAL-HOST] Cabut ${host.hostId}.`);
  return res.json({ status: 'success', hostId: host.hostId, revoked: true });
});

// Antrean tarik untuk agent --watch: hanya plan terikat milik host ini.
app.get('/api/hosts/me/plans', requireRole('agent'), (req, res) => {
  const principal = (req as Request & { principal?: Principal }).principal as Principal;
  const now = Date.now();
  const plans = Array.from(plansStore.values())
    .filter(p => p.status === 'APPROVED' && p.hostId === principal.hostId && (!p.expiresAt || p.expiresAt > now))
    .map(p => ({ planId: p.planId, deviceId: p.deviceId, expiresAt: p.expiresAt, items: p.items.length }));
  return res.json({ hostId: principal.hostId, plans });
});

app.get('/api/operators', requireRole('viewer'), (_req, res) => {
  return res.json({
    operators: operatorsStore.map(o => ({ name: o.name, role: o.role, createdAt: o.createdAt, lastSeenAt: o.lastSeenAt, revokedAt: o.revokedAt }))
  });
});

app.post('/api/operators', requireRole('admin'), (req, res) => {
  const name = String(req.body?.name || '').trim().slice(0, 80);
  const role = String(req.body?.role || 'viewer') as Role;
  if (!name) return res.status(400).json({ status: 'rejected', reason: 'name wajib diisi.' });
  if (!OPERATOR_ROLES.includes(role)) {
    return res.status(400).json({ status: 'rejected', reason: `role harus ${OPERATOR_ROLES.join('|')}.` });
  }
  if (operatorsStore.some(o => o.name === name && !o.revokedAt)) {
    return res.status(409).json({ status: 'rejected', reason: 'Nama operator sudah dipakai.' });
  }
  const key = crypto.randomBytes(32).toString('hex');
  operatorsStore.push({ name, role, keyHash: sha256(key), createdAt: new Date().toISOString() });
  saveOperators();
  console.log(`[PUSKODAL-OP] Operator ${name} (${role}) dibuat.`);
  return res.json({ status: 'success', name, role, key });
});

app.post('/api/operators/:name/revoke', requireRole('admin'), (req, res) => {
  const operator = operatorsStore.find(o => o.name === String(req.params.name || ''));
  if (!operator) return res.status(404).json({ status: 'rejected', reason: 'Operator tidak ditemukan.' });
  operator.revokedAt = operator.revokedAt || new Date().toISOString();
  saveOperators();
  return res.json({ status: 'success', name: operator.name, revoked: true });
});

// ===== Waiver / pengecualian temuan =====
// Temuan yang disetujui tidak perlu diperbaiki sampai tanggal tertentu. WAIVED
// dikeluarkan dari penyebut skor (bukan dihitung PASS palsu).
const WAIVERS_PATH = path.join(DATA_DIR, 'waivers.json');
interface WaiverRecord {
  id: string; deviceId: string; parameter: string; reason: string; owner: string;
  createdAt: string; expiresAt: string;
}
const waiversStore: WaiverRecord[] = readJsonArray<WaiverRecord>(WAIVERS_PATH);

function saveWaivers() {
  try { writeJsonAtomic(WAIVERS_PATH, waiversStore); } catch (err) {
    console.error('[PASOPATI] Gagal menulis waivers:', (err as Error).message);
    throw err;
  }
}

function saveWaiverAudit(action: string, waiver: WaiverRecord, actor: string) {
  appendAuditLogs([{
    id: `WAIVER-${waiver.id}-${crypto.randomBytes(3).toString('hex')}`,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    deviceId: waiver.deviceId,
    deviceName: waiver.deviceId,
    deviceRole: 'Endpoint',
    action: 'BASELINE RECON',
    operator: actor,
    preScore: 0,
    postScore: 0,
    changesSummary: `${action}: ${waiver.parameter} (${waiver.id}) — ${waiver.reason}`.slice(0, 300),
    changesDetails: [`Waiver ${waiver.id}`, `Parameter: ${waiver.parameter}`, `Berlaku s/d ${waiver.expiresAt}`],
    status: 'SUCCESS',
    storedInDb: true
  }], true);
}

function activeWaivers(deviceId: string) {
  const now = Date.now();
  return waiversStore.filter(w => w.deviceId === deviceId && Date.parse(w.expiresAt) > now);
}

app.get('/api/waivers/:deviceId', requireRole('viewer', 'agent'), (req, res) => {
  const deviceId = String(req.params.deviceId || '').slice(0, 64);
  const includeExpired = String(req.query.includeExpired || '') === '1';
  const list = includeExpired
    ? waiversStore.filter(w => w.deviceId === deviceId)
    : activeWaivers(deviceId);
  return res.json({ deviceId, waivers: list });
});

app.post('/api/waivers', requireRole('planner'), (req, res) => {
  const principal = (req as Request & { principal?: Principal }).principal as Principal;
  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, any>;
  const deviceId = String(body.deviceId || '').trim().slice(0, 64);
  const parameter = String(body.parameter || '').trim().slice(0, 200);
  const reason = String(body.reason || '').trim().slice(0, 400);
  const days = Math.min(Math.max(Number(body.days) || 30, 1), 365);
  if (!deviceId || !parameter || !reason) {
    return res.status(400).json({ status: 'rejected', reason: 'deviceId, parameter, dan reason wajib diisi.' });
  }
  const existing = activeWaivers(deviceId).find(w => w.parameter === parameter);
  if (existing) {
    return res.status(409).json({ status: 'rejected', reason: 'Temuan ini sudah punya waiver aktif.', waiver: existing });
  }
  const waiver: WaiverRecord = {
    id: 'WV-' + crypto.randomBytes(6).toString('hex'),
    deviceId, parameter, reason, owner: principal.name,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString()
  };
  waiversStore.push(waiver);
  try {
    saveWaivers();
    saveWaiverAudit('WAIVER CREATE', waiver, principal.name);
  } catch (err) {
    const index = waiversStore.findIndex(item => item.id === waiver.id);
    if (index >= 0) waiversStore.splice(index, 1);
    try { saveWaivers(); } catch { /* pertahankan error asli */ }
    console.error('[PASOPATI] Gagal menyimpan waiver:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Waiver tidak dapat disimpan permanen atau audit gagal ditulis.' });
  }
  return res.json({ status: 'success', waiver });
});

app.delete('/api/waivers/:deviceId/:id', requireRole('approver'), (req, res) => {
  const index = waiversStore.findIndex(w => w.deviceId === String(req.params.deviceId || '') && w.id === String(req.params.id || ''));
  if (index === -1) return res.status(404).json({ status: 'rejected', reason: 'Waiver tidak ditemukan.' });
  const principal = (req as Request & { principal?: Principal }).principal as Principal;
  const [removed] = waiversStore.splice(index, 1);
  try {
    saveWaivers();
    saveWaiverAudit('WAIVER REMOVE', removed, principal.name);
  } catch (err) {
    waiversStore.splice(index, 0, removed);
    try { saveWaivers(); } catch { /* pertahankan error asli */ }
    console.error('[PASOPATI] Gagal menghapus waiver:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Waiver tidak dapat dihapus permanen atau audit gagal ditulis.' });
  }
  return res.json({ status: 'success', waiver: removed });
});

// ===== Real Agent Remediation — kontrol plane (Fase B) =====
// State machine: PLANNED → APPROVED → EXECUTING → VERIFIED | ROLLED_BACK | FAILED.
// Server hanya menyimpan rencana + token; eksekusi nyata dilakukan agent (Fase C).
// Tanpa persetujuan, agent TIDAK boleh mengubah konfigurasi apa pun (read-only).

type PlanStatus = 'PLANNED' | 'APPROVED' | 'EXECUTING' | 'MANUAL_REPORTED' | 'VERIFIED' | 'ROLLED_BACK' | 'FAILED';
type PlanExecutionMode = 'agent' | 'manual';
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
  /** Host ter-enrol pemilik plan (opsional; plan lama tidak punya). */
  hostId?: string;
  createdBy: string;
  createdAt: string;
  items: PlanItem[];
  status: PlanStatus;
  /** agent = token + pasopati_remediate.py; manual = unduh artefak + laporkan evidence. */
  executionMode?: PlanExecutionMode;
  artifacts?: { generatedAt: string; hardeningHash: string; rollbackHash: string };
  manualEvidenceAt?: string;
  /** Admin sudah menyimpan kredensial agent dan “mengirim” script ke tab endpoint. */
  agentCredentialsReady?: boolean;
  approvedBy?: string;
  approvedAt?: string;
  nonce?: string;
  expiresAt?: number;
  evidenceDeadline?: number;
  signature?: string;
  evidence?: any[];
  updatedAt?: string;
  /** Plan menyentuh jalur akses; approve wajib acknowledgeConsole=true. */
  requiresConsoleAck?: boolean;
  accessNotes?: string[];
  /** Jejak heartbeat agent saat EXECUTING (deteksi agent mati). */
  heartbeatAt?: string;
  /** Hasil audit ulang pasca-remediasi (bukti perubahan nyata). */
  postAudit?: { at: string; scoring?: Record<string, unknown>; matrix: Array<{ parameter: string; status: string; cis_id: string }> };
  postAuditAt?: string;
}

const REMEDIATION_PLANS_PATH = path.join(DATA_DIR, 'remediation_plans.json');
const REMEDIATION_ARTIFACTS_DIR = path.join(DATA_DIR, 'remediation_artifacts');

type ArtifactKind = 'hardening' | 'rollback';
interface StoredArtifacts { hardening: string; rollback: string; hardeningHash: string; rollbackHash: string; generatedAt: string; credentials?: { apiKey?: string; hmacKey?: string } }

function artifactPath(planId: string) { return path.join(REMEDIATION_ARTIFACTS_DIR, `${planId}.json`); }
function sha256Text(text: string) { return 'sha256:' + crypto.createHash('sha256').update(text, 'utf8').digest('hex'); }

/** Simpan artefak runbook terikat plan; hash dipakai sebagai bukti unduhan. */
function savePlanArtifacts(planId: string, hardening: string, rollback: string): StoredArtifacts {
  fs.mkdirSync(REMEDIATION_ARTIFACTS_DIR, { recursive: true });
  const stored: StoredArtifacts = {
    hardening,
    rollback,
    hardeningHash: sha256Text(hardening),
    rollbackHash: sha256Text(rollback),
    generatedAt: new Date().toISOString()
  };
  writeJsonAtomic(artifactPath(planId), stored);
  return stored;
}

function readPlanArtifacts(planId: string): StoredArtifacts | null {
  try {
    const file = artifactPath(planId);
    if (!fs.existsSync(file)) return null;
    const parsed = JSON.parse(fs.readFileSync(file, 'utf-8'));
    if (!parsed || typeof parsed.hardening !== 'string' || typeof parsed.rollback !== 'string') return null;
    return parsed as StoredArtifacts;
  } catch (err) {
    console.error('[PASOPATI] Gagal membaca artefak plan:', (err as Error).message);
    return null;
  }
}

/** Simpan kredensial agent yang diisi admin saat approve (plaintext, sejajar .env). */
function savePlanCredentials(planId: string, apiKey?: string, hmacKey?: string): void {
  const stored = readPlanArtifacts(planId);
  if (!stored) return;
  const credentials = {
    ...(apiKey ? { apiKey } : {}),
    ...(hmacKey ? { hmacKey } : {})
  };
  if (Object.keys(credentials).length === 0) return;
  writeJsonAtomic(artifactPath(planId), { ...stored, credentials: { ...stored.credentials, ...credentials } });
}
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
// Satu plan hanya untuk satu host, jadi alias Windows dan Linux tidak boleh
// dicampur: agent menolak alias OS lain dan seluruh plan akan batal.
const WINDOWS_ALIASES = new Set([
  'fw-enable-defender',
  'guest-account-disable',
  'usb-storage-block',
  'rdp-nla-enable',
  'uac-enable',
  'bitlocker-enable',
  'win-auditpol-process',
  'ports-block-windows'
]);
const LINUX_ALIASES = new Set([
  'fw-enable-ufw',
  'ssh-disable-root',
  'auditd-enable',
  'usb-block-linux',
  'grub-config-perms',
  'sudoers-remove-nopasswd',
  'suid-strip-critical',
  'ports-block-linux'
]);
// Alias yang dapat memutus jalur akses operator. Plan yang memuat salah satunya
// wajib di-approve dengan acknowledgeConsole=true (operator menyatakan sudah
// punya konsol/KVM atau siap rollback), supaya tidak terkunci di luar host.
const ACCESS_RISK_ALIASES: Record<string, string> = {
  'ports-block-windows': 'Memblokir RDP 3389 inbound: sesi remote BARU tidak bisa masuk sampai rule dihapus.',
  'ports-block-linux': 'Memblokir port 21/23/445/4444 via iptables (port 22 tidak diblokir).',
  'ssh-disable-root': 'Login SSH langsung sebagai root tidak berlaku lagi untuk sesi baru.',
  'fw-enable-ufw': 'UFW default deny incoming; pastikan jalur konsol tersedia sebelum menutup sesi.',
  'fw-enable-defender': 'Windows Firewall dinyalakan di semua profil; sesi remote bisa terputus.'
};
const ALLOWED_TRANSITIONS: Record<PlanStatus, PlanStatus[]> = {
  PLANNED: ['APPROVED'],
  APPROVED: ['EXECUTING', 'MANUAL_REPORTED', 'VERIFIED', 'ROLLED_BACK', 'FAILED'],
  EXECUTING: ['MANUAL_REPORTED', 'VERIFIED', 'ROLLED_BACK', 'FAILED'],
  MANUAL_REPORTED: ['VERIFIED', 'ROLLED_BACK', 'FAILED'],
  VERIFIED: [],
  ROLLED_BACK: [],
  FAILED: []
};

// Parameter post-audit yang harus berstatus PASS/WARNING sebelum VERIFIED diterima.
// Menutup celah "evidence bilang verified, host ternyata belum berubah".
const ALIAS_POST_CHECK: Record<string, string[]> = {
  'ports-block-linux': ['dangerous port', 'network & dangerous'],
  'ports-block-windows': ['dangerous port', 'network & dangerous'],
  'fw-enable-ufw': ['firewall'],
  'fw-enable-defender': ['firewall', 'defender'],
  'ssh-disable-root': ['ssh root', 'permitrootlogin'],
  'auditd-enable': ['auditd', 'audit daemon'],
  'usb-block-linux': ['usb'],
  'usb-storage-block': ['usb'],
  'grub-config-perms': ['grub'],
  'sudoers-remove-nopasswd': ['sudoers', 'nopasswd'],
  'suid-strip-critical': ['suid'],
  'guest-account-disable': ['guest'],
  'rdp-nla-enable': ['rdp', 'nla', '3389'],
  'uac-enable': ['uac', 'user account control'],
  'bitlocker-enable': ['bitlocker'],
  'win-auditpol-process': ['event log', 'auditing', 'process creation']
};

// Antrean per host: satu plan aktif per perangkat, dan batas blast radius armada.
const MAX_ACTIVE_PLANS = Math.max(Number(process.env.REMEDIATION_MAX_ACTIVE) || 10, 1);
const STALE_EXECUTING_MS = Math.max(Number(process.env.REMEDIATION_STALE_MS) || 15 * 60 * 1000, 1000);
const ACCEPTED_POST_STATUSES = new Set(['PASS', 'WARNING', 'N/A']);

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
app.post('/api/remediation-plan', requireRole('planner'), (req, res) => {
  const principal = (req as Request & { principal?: Principal }).principal as Principal;
  const { deviceId, items: rawItems, hostId, executionMode: rawMode, artifacts: rawArtifacts } = req.body || {};
  if (!deviceId || typeof deviceId !== 'string') {
    return res.status(400).json({ status: 'rejected', reason: 'deviceId wajib diisi.' });
  }
  let boundHostId: string | undefined;
  if (hostId !== undefined && hostId !== null && String(hostId).trim() !== '') {
    const host = hostsStore.find(h => h.hostId === String(hostId).trim());
    if (!host) return res.status(400).json({ status: 'rejected', reason: 'hostId tidak dikenal. Enrol host dulu.' });
    if (host.revokedAt) return res.status(400).json({ status: 'rejected', reason: 'hostId sudah dicabut.' });
    boundHostId = host.hostId;
  }
  // PowerShell `ConvertTo-Json` mengirim item tunggal sebagai objek, bukan array.
  const items = validateItems(Array.isArray(rawItems) ? rawItems : rawItems ? [rawItems] : rawItems);
  if (!items) {
    return res.status(400).json({ status: 'rejected', reason: 'items tidak valid: 1–50 item, alias harus salah satu allowlist (16 enforce + 4 advisory), risk LOW|MEDIUM|HIGH.' });
  }
  if (!items.some(i => !ADVISORY_ALIASES.has(i.alias))) {
    return res.status(400).json({ status: 'rejected', reason: 'Plan harus punya minimal satu langkah enforce (advisory saja tidak cukup).' });
  }
  const windowsItems = items.filter(i => WINDOWS_ALIASES.has(i.alias)).map(i => i.alias);
  const linuxItems = items.filter(i => LINUX_ALIASES.has(i.alias)).map(i => i.alias);
  if (windowsItems.length > 0 && linuxItems.length > 0) {
    return res.status(400).json({
      status: 'rejected',
      reason: `Plan mencampur alias Windows (${windowsItems.join(', ')}) dan Linux (${linuxItems.join(', ')}). Pisahkan per OS.`
    });
  }
  const accessNotes = items
    .filter(i => ACCESS_RISK_ALIASES[i.alias])
    .map(i => `${i.alias}: ${ACCESS_RISK_ALIASES[i.alias]}`);
  const executionMode: PlanExecutionMode = rawMode === 'manual' ? 'manual' : 'agent';
  const hardeningText = typeof rawArtifacts?.hardening === 'string' ? rawArtifacts.hardening : '';
  const rollbackText = typeof rawArtifacts?.rollback === 'string' ? rawArtifacts.rollback : '';
  if (hardeningText.length > 400_000 || rollbackText.length > 400_000) {
    return res.status(413).json({ status: 'rejected', reason: 'Artefak runbook melebihi 400 KB.' });
  }
  if (executionMode === 'manual' && (!hardeningText || !rollbackText)) {
    return res.status(400).json({ status: 'rejected', reason: 'Mode manual wajib menyertakan artefak hardening dan rollback.' });
  }
  const plan: Plan = {
    planId: `PLAN-${Date.now()}-${Math.floor(Math.random() * 1e6)}`,
    deviceId: String(deviceId).slice(0, 64),
    ...(boundHostId ? { hostId: boundHostId } : {}),
    createdBy: principal.name,
    createdAt: new Date().toISOString(),
    items,
    status: 'PLANNED',
    executionMode,
    requiresConsoleAck: accessNotes.length > 0,
    accessNotes,
    updatedAt: new Date().toISOString()
  };
  try {
    if (hardeningText && rollbackText) {
      const stored = savePlanArtifacts(plan.planId, hardeningText, rollbackText);
      plan.artifacts = { generatedAt: stored.generatedAt, hardeningHash: stored.hardeningHash, rollbackHash: stored.rollbackHash };
    }
  } catch (err) {
    console.error('[PASOPATI] Gagal menyimpan artefak plan:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Artefak runbook gagal disimpan; plan tidak dibuat.' });
  }
  plansStore.set(plan.planId, plan);
  savePlans(plansStore);
  return res.json({ status: 'success', plan });
});

// 2. Operator menyetujui rencana → server menerbitkan nonce + HMAC signature + expiry (token untuk agent)
// Token boleh diterbitkan ulang HANYA jika token sebelumnya sudah kedaluwarsa, agar plan tidak macet.
const TOKEN_TTL_MS = Math.max(Number(process.env.REMEDIATION_TOKEN_TTL_MS) || 10 * 60 * 1000, 100);
const EVIDENCE_GRACE_MS = Math.max(Number(process.env.REMEDIATION_EVIDENCE_GRACE_MS) || 60 * 60 * 1000, TOKEN_TTL_MS); // batas kirim evidence setelah approval
app.post('/api/remediation-approve', requireRole('approver'), (req, res) => {
  if (!HMAC_SECRET) {
    return res.status(503).json({ status: 'rejected', reason: 'Server belum siap: set HMAC_SECRET di environment.' });
  }
  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, any>;
  const plan = plansStore.get(String(body.planId || ''));
  if (!plan) return res.status(404).json({ status: 'rejected', reason: 'Plan tidak ditemukan.' });
  const principal = (req as Request & { principal?: Principal }).principal as Principal;
  if (plan.createdBy === principal.name && body.selfApprove !== true) {
    return res.status(409).json({
      status: 'rejected',
      reason: `Plan dibuat oleh ${plan.createdBy}. Empat mata: setujui oleh operator lain, atau kirim selfApprove=true.`
    });
  }
  const force = body.force === true;
  const override = force || body.overrideQueue === true;
  // EXECUTING yang heartbeat-nya basi boleh diambil alih (agent mati / terputus).
  const staleExecuting = plan.status === 'EXECUTING' && Boolean(plan.heartbeatAt) &&
    Date.now() - Date.parse(String(plan.heartbeatAt)) > STALE_EXECUTING_MS;
  if (plan.status !== 'PLANNED' && plan.status !== 'APPROVED' && !staleExecuting) {
    return res.status(409).json({ status: 'rejected', reason: `Transisi tidak diizinkan: ${plan.status} → APPROVED.` });
  }
  if (!override) {
    const active = Array.from(plansStore.values())
      .filter(p => {
        if (p.planId === plan.planId) return false;
        if (p.status === 'EXECUTING') {
          return !p.heartbeatAt || Date.now() - Date.parse(String(p.heartbeatAt)) <= STALE_EXECUTING_MS;
        }
        if (p.status === 'APPROVED') {
          // Plan kedaluwarsa (token + grace evidence habis) tidak boleh memblokir selamanya.
          const deadline = p.evidenceDeadline || p.expiresAt || 0;
          return !deadline || Date.now() < deadline;
        }
        return false;
      });
    const sameHost = active.find(p => p.deviceId === plan.deviceId);
    if (sameHost) {
      return res.status(409).json({
        status: 'rejected',
        reason: `Sudah ada plan aktif untuk ${plan.deviceId} (${sameHost.planId}, ${sameHost.status}). Selesaikan atau override dengan force=true.`,
        blockingPlanId: sameHost.planId
      });
    }
    if (active.length >= MAX_ACTIVE_PLANS) {
      return res.status(409).json({
        status: 'rejected',
        reason: `Blast radius: ${active.length} plan aktif (maks ${MAX_ACTIVE_PLANS}). Override dengan overrideQueue=true bila memang disengaja.`,
        activeCount: active.length
      });
    }
  }
  if (!force && plan.status === 'APPROVED' && plan.expiresAt && Date.now() < plan.expiresAt) {
    return res.status(409).json({
      status: 'rejected',
      reason: 'Token lama masih berlaku. Tunggu hingga kedaluwarsa sebelum menerbitkan token baru (agar token agent tidak bentrok).'
    });
  }
  if (plan.requiresConsoleAck && body.acknowledgeConsole !== true) {
    return res.status(409).json({
      status: 'rejected',
      reason: 'Plan menyentuh jalur akses host. Kirim acknowledgeConsole=true setelah memastikan ada konsol/KVM atau jalur rollback.',
      requiresConsoleAck: true,
      accessNotes: plan.accessNotes || []
    });
  }
  const approvedAt = new Date().toISOString();
  try {
    appendEndpointHealthAuditRecord(ENDPOINT_HEALTH_AUDIT_DB_PATH, buildEndpointHealthAuditRecord({
      eventType: 'REMEDIATION_APPROVED',
      endpointId: plan.deviceId,
      accessedBy: principal.name,
      approvedBy: principal.name,
      approvedAt,
      planId: plan.planId
    }));
  } catch (err) {
    console.error('[PASOPATI] Gagal menulis audit kondisi endpoint saat approval:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Persetujuan tidak diproses karena rekaman audit endpoint gagal disimpan.' });
  }
  plan.approvedBy = principal.name;
  plan.approvedAt = approvedAt;
  plan.heartbeatAt = staleExecuting ? undefined : plan.heartbeatAt;
  plan.nonce = crypto.randomBytes(32).toString('hex');
  plan.expiresAt = Date.now() + TOKEN_TTL_MS;
  plan.evidenceDeadline = Date.now() + EVIDENCE_GRACE_MS;
  plan.signature = signPlan(plan);
  try {
    const apiKeyIn = typeof body.agentApiKey === 'string' ? body.agentApiKey.trim().slice(0, 200) : '';
    const hmacIn = typeof body.agentHmacKey === 'string' ? body.agentHmacKey.trim().slice(0, 200) : '';
    if (plan.artifacts && (apiKeyIn || hmacIn)) savePlanCredentials(plan.planId, apiKeyIn, hmacIn);
  } catch (err) {
    console.error('[PASOPATI] Gagal menyimpan kredensial plan:', (err as Error).message);
  }
  plan.status = 'APPROVED';
  plan.updatedAt = new Date().toISOString();
  plansStore.set(plan.planId, plan);
  savePlans(plansStore);
  // Kembalikan plan LENGKAP sekali ini (berisi nonce/signature) untuk dipakai
  // operator menyusun plan.json agent. GET di bawah tetap diredaksi (toPublicPlan).
  return res.json({ status: 'success', planId: plan.planId, nonce: plan.nonce, expiresAt: plan.expiresAt, evidenceDeadline: plan.evidenceDeadline, signature: plan.signature, token: `${plan.nonce}.${plan.signature}`, plan: { ...plan } });
});

// Unduh artefak runbook terikat plan. Pratinjau (status PLANNED) tidak diaudit;
// unduhan setelah plan dibuat/approve dicatat ke activity audit beserta planId.
app.get('/api/remediation-plans/:planId/artifacts/:kind', requireRole('viewer', 'executor', 'agent'), rateLimit(60, 'plan-artifact'), (req, res) => {
  const plan = plansStore.get(String(req.params.planId || ''));
  if (!plan) return res.status(404).json({ status: 'rejected', reason: 'Plan tidak ditemukan.' });
  const kind = String(req.params.kind || '') as ArtifactKind;
  if (kind !== 'hardening' && kind !== 'rollback') {
    return res.status(400).json({ status: 'rejected', reason: 'kind harus hardening atau rollback.' });
  }
  const stored = readPlanArtifacts(plan.planId);
  if (!stored) return res.status(404).json({ status: 'rejected', reason: 'Artefak plan tidak tersedia; buat ulang plan.' });
  const text = kind === 'hardening' ? stored.hardening : stored.rollback;
  const hash = kind === 'hardening' ? stored.hardeningHash : stored.rollbackHash;
  if (plan.status !== 'PLANNED') {
    recordActivity(req, 'FILE_DOWNLOADED', `${plan.planId}.${kind}`, `plan=${plan.planId} hash=${hash}`, 'SUCCESS', plan.planId);
  }
  const ext = plan.items.some(item => WINDOWS_ALIASES.has(item.alias)) ? 'ps1' : 'sh';
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('X-Pasopati-Artifact-Hash', hash);
  res.setHeader('X-Pasopati-Plan-Status', plan.status);
  res.setHeader('Content-Disposition', `attachment; filename="pasopati-${plan.planId}-${kind}.${ext}"`);
  return res.send(text);
});

// Endpoint/health access audit is separate from /api/audit-logs and is admin-only.
app.get('/api/admin/endpoint-health-audit', requireRole('admin'), rateLimit(120, 'endpoint-health-audit-read'), (req, res) => {
  try {
    const all = readEndpointHealthAuditRecords(ENDPOINT_HEALTH_AUDIT_DB_PATH);
    const endpointId = typeof req.query.endpointId === 'string' ? req.query.endpointId : '';
    const filtered = endpointId ? all.filter(record => record.target.endpointId === endpointId) : all;
    const total = filtered.length;
    const rawLimit = Number(req.query.limit);
    const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 500) : 200;
    const records = filtered.slice().sort((a, b) => b.occurredAt.localeCompare(a.occurredAt)).slice(0, limit);
    return res.json({ records, total, limit, database: 'endpoint_health_audit.sqlite' });
  } catch (err) {
    console.error('[PASOPATI] Gagal membaca audit kondisi endpoint:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Database audit kondisi endpoint tidak dapat dibaca.' });
  }
});

// Aktivitas unduhan & scan realtime: hanya admin yang boleh melihat.
app.get('/api/admin/activity-audit', requireRole('admin'), rateLimit(120, 'activity-audit-read'), (req, res) => {
  const typeParam = typeof req.query.type === 'string' ? req.query.type : '';
  if (typeParam && typeParam !== 'FILE_DOWNLOADED' && typeParam !== 'REALTIME_SCAN') {
    return res.status(400).json({ status: 'rejected', reason: 'type harus FILE_DOWNLOADED atau REALTIME_SCAN.' });
  }
  try {
    const rawLimit = Number(req.query.limit);
    const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? rawLimit : 200;
    const result = readActivityAuditRecords(ACTIVITY_AUDIT_DB_PATH, {
      limit,
      ...(typeParam ? { eventType: typeParam as ActivityAuditEventType } : {})
    });
    return res.json({ ...result, limit: Math.min(limit, 500), database: 'activity_audit.sqlite' });
  } catch (err) {
    console.error('[PASOPATI] Gagal membaca aktivitas audit:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Database aktivitas audit tidak dapat dibaca.' });
  }
});

app.post('/api/admin/endpoint-health-audit/access', requireRole('admin'), rateLimit(60, 'endpoint-health-audit-access'), (req, res) => {
  const endpointId = typeof req.body?.endpointId === 'string' ? req.body.endpointId.trim() : '';
  if (!endpointId || endpointId.length > 120) {
    return res.status(400).json({ status: 'rejected', reason: 'endpointId wajib berupa teks maksimal 120 karakter.' });
  }
  const endpoint = endpointRecords().find(item => item.id === endpointId && !item.deletedAt);
  if (!endpoint) return res.status(404).json({ status: 'rejected', reason: 'Endpoint aktif tidak ditemukan.' });
  try {
    const principal = (req as Request & { principal?: Principal }).principal as Principal;
    const relatedApproval = Array.from(plansStore.values())
      .filter(plan => plan.approvedBy && [endpoint.id, endpoint.agentId, endpoint.hostname].includes(plan.deviceId))
      .sort((a, b) => String(b.approvedAt || '').localeCompare(String(a.approvedAt || '')))[0];
    const record = buildEndpointHealthAuditRecord({
      eventType: 'ENDPOINT_ACCESSED',
      endpointId: endpoint.id,
      accessedBy: principal.name,
      accessIp: String(req.ip || req.socket?.remoteAddress || 'unknown'),
      ...(relatedApproval ? {
        approvedBy: relatedApproval.approvedBy,
        approvedAt: relatedApproval.approvedAt,
        planId: relatedApproval.planId
      } : {})
    });
    appendEndpointHealthAuditRecord(ENDPOINT_HEALTH_AUDIT_DB_PATH, record);
    return res.status(201).json({ status: 'success', record });
  } catch (err) {
    console.error('[PASOPATI] Gagal menyimpan akses audit kondisi endpoint:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Rekaman akses kondisi endpoint tidak dapat disimpan.' });
  }
});

// 3. Agent mengirim evidence eksekusi/verifikasi (setelah validasi nonce + signature + expiry + anti-replay)
// Catatan jujur: status EXECUTING bersifat idempoten (nonce belum dikonsumsi) agar agent dapat
// memanggil ulang; nonce baru dikonsumsi persisten pada VERIFIED/ROLLED_BACK/FAILED.
app.post('/api/remediation-verify', requireRole('executor', 'agent'), rateLimit(60, 'evidence'), (req, res) => {
  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, any>;
  const { planId, nonce, toStatus, evidence } = body;
  const plan = plansStore.get(String(planId || ''));
  if (!plan) return res.status(404).json({ status: 'rejected', reason: 'Plan tidak ditemukan.' });
  const manual = plan.executionMode === 'manual' || body.source === 'manual';
  if (!manual) {
    const auth = verifySignedRequest(
      req,
      HMAC_SECRET,
      'Server belum siap: set HMAC_SECRET di environment.'
    );
    if (!auth.ok) {
      return res.status(auth.status).json({ status: 'rejected', reason: auth.reason });
    }
  }
  const principal = (req as Request & { principal?: Principal }).principal as Principal;
  if (plan.hostId && principal.kind === 'host' && principal.hostId !== plan.hostId) {
    return res.status(403).json({ status: 'rejected', reason: 'Plan ini terikat ke host lain.' });
  }
  const target = String(toStatus || '').toUpperCase() as PlanStatus;
  if (!['EXECUTING', 'MANUAL_REPORTED', 'VERIFIED', 'ROLLED_BACK', 'FAILED'].includes(target)) {
    return res.status(400).json({ status: 'rejected', reason: 'toStatus tidak valid (EXECUTING|MANUAL_REPORTED|VERIFIED|ROLLED_BACK|FAILED).' });
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
    if (e.preStateHash !== undefined && typeof e.preStateHash !== 'string') return res.status(400).json({ status: 'rejected', reason: 'Evidence preStateHash harus string.' });
    if (!plan.items.some(i => i.alias === e.alias)) {
      return res.status(400).json({ status: 'rejected', reason: 'Evidence alias tidak ada dalam plan.' });
    }
  }
  // stepIndex harus unik agar tidak ada langkah yang "dilaporkan dua kali".
  const stepIndexes = ev.map(e => Number(e.stepIndex));
  if (new Set(stepIndexes).size !== stepIndexes.length) {
    return res.status(400).json({ status: 'rejected', reason: 'Evidence stepIndex duplikat.' });
  }
  // VERIFIED hanya boleh diklaim bila SELURUH langkah plan punya evidence,
  // semua exitCode 0, dan setiap langkah enforce benar-benar terverifikasi.
  // Status tidak lagi murni assertion agent.
  if (target === 'VERIFIED' || target === 'MANUAL_REPORTED') {
    const evidenceAliases = new Set(ev.map(e => String(e.alias)));
    const missing = plan.items.map(i => i.alias).filter(a => !evidenceAliases.has(a));
    if (missing.length > 0) {
      return res.status(400).json({ status: 'rejected', reason: `Evidence belum lengkap; langkah tanpa bukti: ${missing.join(', ')}.` });
    }
    const failedExit = ev.filter(e => Number(e.exitCode) !== 0).map(e => String(e.alias));
    if (failedExit.length > 0) {
      return res.status(400).json({ status: 'rejected', reason: `exitCode bukan 0 pada: ${failedExit.join(', ')}; gunakan FAILED/ROLLED_BACK.` });
    }
    // Laporan manual bersifat self-reported, jadi flag verified tidak diwajibkan.
    const unverified = manual ? [] : ev
      .filter(e => !(e.advisory === true || ADVISORY_ALIASES.has(String(e.alias))) && e.verified !== true)
      .map(e => String(e.alias));
    if (unverified.length > 0) {
      return res.status(400).json({ status: 'rejected', reason: `Langkah belum terverifikasi: ${unverified.join(', ')}.` });
    }
  }
  if (target === 'VERIFIED') {
    // Audit ulang pasca-remediasi: bukti bahwa host benar-benar berubah.
    const matrix = Array.isArray(body.postAudit?.compliance_matrix) ? body.postAudit.compliance_matrix : null;
    if (!matrix) {
      return res.status(400).json({ status: 'rejected', reason: 'VERIFIED wajib menyertakan postAudit.compliance_matrix hasil audit ulang.' });
    }
    const regressions: string[] = [];
    for (const item of plan.items) {
      if (ADVISORY_ALIASES.has(item.alias)) continue;
      const keys = ALIAS_POST_CHECK[item.alias];
      if (!keys) continue;
      const hit = matrix.find((c: any) => c && typeof c === 'object' &&
        keys.some(k => String(c.parameter ?? '').toLowerCase().includes(k)));
      if (!hit) {
        regressions.push(`${item.alias}: parameter terkait tidak ditemukan di hasil audit ulang`);
        continue;
      }
      const status = String(hit.status ?? '').toUpperCase();
      if (!ACCEPTED_POST_STATUSES.has(status)) {
        regressions.push(`${item.alias}: parameter masih ${status || 'tanpa status'}`);
      }
    }
    if (regressions.length > 0) {
      return res.status(400).json({ status: 'rejected', reason: `Audit ulang belum bersih: ${regressions.join('; ')}.` });
    }
    plan.postAudit = {
      at: new Date().toISOString(),
      scoring: body.postAudit?.scoring && typeof body.postAudit.scoring === 'object' ? body.postAudit.scoring : undefined,
      matrix: matrix.slice(0, 60).map((c: any) => ({
        parameter: String(c?.parameter ?? '').slice(0, 200),
        status: String(c?.status ?? '').slice(0, 20),
        cis_id: String(c?.cis_id ?? '').slice(0, 120)
      }))
    };
    plan.postAuditAt = new Date().toISOString();
    // Sinkronkan registry dengan hasil audit ulang agar dashboard tidak tertinggal
    // menampilkan kondisi pra-remediasi.
    try {
      const records = endpointRecords();
      const index = records.findIndex(item => !item.deletedAt &&
        (item.id === plan.deviceId || item.agentId === plan.deviceId || item.hostname === plan.deviceId));
      if (index >= 0) {
        const endpoint = records[index];
        const mappedChecks: Array<{ id: string; parameter: string; category: string; cis_id: string; status: string; details: string; mitigation: string }> = matrix.slice(0, 500).map((c: any, i: number) => {
          const rawStatus = String(c?.status ?? '').toUpperCase();
          const status = (['PASS', 'WARNING', 'FAIL', 'N/A', 'WAIVED'].includes(rawStatus) ? rawStatus : 'WARNING');
          return {
            id: `post-${i + 1}`,
            parameter: String(c?.parameter ?? '').slice(0, 200),
            category: String(c?.category ?? 'Network & Port'),
            cis_id: String(c?.cis_id ?? c?.cis ?? '').slice(0, 120),
            status,
            details: String(c?.details ?? '').slice(0, 2000),
            mitigation: String(c?.mitigation ?? '').slice(0, 2000)
          };
        });
        const count = (status: string) => mappedChecks.filter(c => c.status === status).length;
        const applicable = mappedChecks.filter(c => c.status !== 'N/A' && c.status !== 'WAIVED').length || 1;
        const computed = Math.round(((count('PASS') * 100) + (count('WARNING') * 50)) / applicable);
        const score = Number(body.postAudit?.scoring?.cyber_readiness_score);
        endpoint.checks = mappedChecks as typeof endpoint.checks;
        endpoint.updatedAt = new Date().toISOString();
        endpoint.updated_at = endpoint.updatedAt;
        endpoint.revision = (endpoint.revision || 1) + 1;
        endpoint.history = [...(endpoint.history || []), {
          timestamp: endpoint.updatedAt.replace('T', ' ').substring(0, 19),
          score: Number.isFinite(score) ? score : computed,
          passCount: count('PASS'),
          warnCount: count('WARNING'),
          failCount: count('FAIL'),
          event: 'Audit ulang pasca-remediasi'
        }].slice(-200);
        records[index] = endpoint;
        writeEndpointRecords(ENDPOINTS_PATH, records);
      }
    } catch (syncErr) {
      console.error('[PASOPATI] Gagal menyinkronkan registry setelah audit ulang:', (syncErr as Error).message);
    }
  }

  plan.status = target;
  if (target === 'EXECUTING') plan.heartbeatAt = new Date().toISOString();
  const normalizedEvidence = ev.map(e => ({
    stepIndex: Number(e.stepIndex),
    alias: String(e.alias),
    exitCode: Number(e.exitCode),
    outputHash: String(e.outputHash).slice(0, 128),
    ...(typeof e.preStateHash === 'string' ? { preStateHash: e.preStateHash.slice(0, 128) } : {}),
    ...(typeof e.output === 'string' ? { output: e.output.slice(0, 400) } : {}),
    verified: manual ? e.verified !== false : e.verified === true,
    source: manual ? 'manual' as const : 'agent' as const,
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
  if (target === 'MANUAL_REPORTED') plan.manualEvidenceAt = new Date().toISOString();
  plan.updatedAt = new Date().toISOString();
  plansStore.set(plan.planId, plan);
  if (['VERIFIED', 'ROLLED_BACK', 'FAILED'].includes(target) && plan.nonce) {
    usedNonces.add(plan.nonce);
    saveUsedNonces(usedNonces);
  }
  savePlans(plansStore);
  const evidenceCount = plan.evidence?.length ?? 0;
  if (['MANUAL_REPORTED', 'VERIFIED', 'ROLLED_BACK', 'FAILED'].includes(target)) {
    const verifiedCount = normalizedEvidence.filter(e => e.verified).length;
    appendAuditLogs([{
      id: `LOG-EVID-${plan.planId}-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      deviceId: plan.deviceId,
      deviceName: plan.deviceId,
      deviceRole: 'Endpoint (evidence agen)',
      action: target === 'ROLLED_BACK' ? 'ROLLBACK RESTORATION' : 'HARDENING REMEDIATION',
      operator: manual ? `manual:${principal.name}` : 'pasopati_remediate.py',
      preScore: 0,
      postScore: Math.round((verifiedCount / Math.max(normalizedEvidence.length, 1)) * 100),
      changesSummary: manual
        ? `Plan ${plan.planId} → ${target}: laporan manual oleh ${principal.name} (${verifiedCount}/${normalizedEvidence.length} langkah).`
        : `Plan ${plan.planId} → ${target}: ${verifiedCount}/${normalizedEvidence.length} langkah terverifikasi (evidence HMAC valid).`,
      changesDetails: normalizedEvidence.slice(0, 10).map(e => `[${e.verified ? 'VERIFIED' : 'FAIL'}] ${e.alias} (exit ${e.exitCode})`),
      status: target === 'VERIFIED' ? 'SUCCESS' : target === 'FAILED' ? 'FAILED' : 'WARNING',
      storedInDb: true,
      planId: plan.planId
    }]);
  }
  console.log(`[PUSKODAL-REMEDIATION] Plan ${plan.planId} → ${target} | device: ${plan.deviceId} | evidence: ${evidenceCount} | HMAC: valid`);
  return res.json({ status: 'success', planId: plan.planId, planStatus: target, evidenceCount });
});

// Script siap pakai untuk host target. API key master + HMAC diambil dari env server,
// sehingga operator host tidak perlu menyalin secret. Tetap hanya untuk plan yang
// sudah di-approve; unduhan tercatat di activity audit.
function publicBaseUrl(req: Request): string {
  return envValue('PASOPATI_PUBLIC_URL').replace(/\/+$/, '') || `${req.protocol}://${req.get('host')}`;
}

app.get('/api/remediation-plans/:planId/run-script', requireRole('viewer', 'executor', 'agent'), rateLimit(60, 'plan-run-script'), (req, res) => {
  const plan = plansStore.get(String(req.params.planId || ''));
  if (!plan) return res.status(404).json({ status: 'rejected', reason: 'Plan tidak ditemukan.' });
  if (plan.status === 'PLANNED') return res.status(409).json({ status: 'rejected', reason: 'Plan belum di-approve; approve dulu.' });
  const stored = readPlanArtifacts(plan.planId);
  const apiKeyOut = stored?.credentials?.apiKey || API_KEY;
  const hmacOut = stored?.credentials?.hmacKey || HMAC_SECRET;
  if (!apiKeyOut || !hmacOut) return res.status(503).json({ status: 'rejected', reason: 'API key/HMAC belum tersedia; isi kolom kredensial lalu approve ulang.' });
  const shell = String(req.query.shell || '') === 'sh' ? 'sh' : 'ps1';
  const base = publicBaseUrl(req);
  const python = shell === 'sh' ? 'python3' : 'python';
  const force = plan.requiresConsoleAck ? ' --force-access-risk' : '';
  const command = `${python} pasopati_remediate.py --server "${base}" --plan-id "${plan.planId}" --remediate-api-key "${apiKeyOut}" --hmac-key "${hmacOut}" --no-exec${force}`;
  const header = shell === 'sh'
    ? `#!/usr/bin/env bash\n# PASOPATI ${plan.planId} — uji aman (--no-exec).\n# Eksekusi nyata: hapus --no-exec.\nset -euo pipefail\n`
    : `# PASOPATI ${plan.planId} — jalankan di PowerShell Administrator.\n# Ini mode uji aman (--no-exec). Eksekusi nyata: hapus --no-exec.\n`;
  const bodyText = header + command + (shell === 'sh' ? '\n' : '\r\n');
  recordActivity(req, 'FILE_DOWNLOADED', `${plan.planId}.run.${shell}`, `plan=${plan.planId}`, 'SUCCESS', plan.planId);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('X-Pasopati-Plan-Status', plan.status);
  res.setHeader('Content-Disposition', `attachment; filename="pasopati-${plan.planId}.${shell}"`);
  return res.send(bodyText);
});

app.post('/api/remediation-plans/:planId/agent-credentials', requireRole('planner', 'approver'), rateLimit(30, 'plan-credentials'), (req, res) => {
  const plan = plansStore.get(String(req.params.planId || ''));
  if (!plan) return res.status(404).json({ status: 'rejected', reason: 'Plan tidak ditemukan.' });
  if (!plan.artifacts) return res.status(409).json({ status: 'rejected', reason: 'Plan ini belum punya artefak runbook; buat plan baru.' });
  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, any>;
  const apiKey = typeof body.agentApiKey === 'string' ? body.agentApiKey.trim().slice(0, 200) : '';
  const hmacKey = typeof body.agentHmacKey === 'string' ? body.agentHmacKey.trim().slice(0, 200) : '';
  if (!apiKey && !hmacKey) return res.status(400).json({ status: 'rejected', reason: 'Isi minimal salah satu kredensial.' });
  try {
    savePlanCredentials(plan.planId, apiKey, hmacKey);
  } catch (err) {
    console.error('[PASOPATI] Gagal menyimpan kredensial plan:', (err as Error).message);
    return res.status(500).json({ status: 'rejected', reason: 'Kredensial gagal disimpan.' });
  }
  plan.agentCredentialsReady = true;
  plan.updatedAt = new Date().toISOString();
  plansStore.set(plan.planId, plan);
  savePlans(plansStore);
  try {
    appendAuditLogs([{
      id: `LOG-CRED-${plan.planId}-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      deviceId: plan.deviceId,
      deviceName: plan.deviceId,
      deviceRole: 'Endpoint',
      action: 'BASELINE RECON',
      operator: endpointActor(req),
      preScore: 0,
      postScore: 0,
      changesSummary: `Script hardening ${plan.planId} dikirim ke tab Endpoint (kredensial tersimpan).`,
      changesDetails: [`Plan: ${plan.planId}`, `Status: ${plan.status}`],
      status: 'SUCCESS',
      storedInDb: true
    }], true);
  } catch (err) {
    console.error('[PASOPATI] Audit pengiriman script gagal:', (err as Error).message);
  }
  return res.json({ status: 'success', planId: plan.planId, agentCredentialsReady: true });
});

// plan.json lengkap (berisi token) untuk eksekusi offline.
app.get('/api/remediation-plans/:planId/plan-json', requireRole('viewer', 'executor', 'agent'), rateLimit(60, 'plan-json'), (req, res) => {
  const plan = plansStore.get(String(req.params.planId || ''));
  if (!plan) return res.status(404).json({ status: 'rejected', reason: 'Plan tidak ditemukan.' });
  if (!plan.nonce || !plan.signature) return res.status(409).json({ status: 'rejected', reason: 'Plan belum di-approve/token sudah tidak ada.' });
  recordActivity(req, 'FILE_DOWNLOADED', `${plan.planId}.plan.json`, `plan=${plan.planId}`, 'SUCCESS', plan.planId);
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${plan.planId}.plan.json"`);
  return res.send(JSON.stringify(plan, null, 2));
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
app.get('/api/remediation-plans/:planId/agent', requireRole('viewer', 'agent'), rateLimit(30, 'agent-plan'), (req, res) => {
  const plan = plansStore.get(req.params.planId);
  if (!plan) return res.status(404).json({ status: 'rejected', reason: 'Plan tidak ditemukan.' });
  const principal = (req as Request & { principal?: Principal }).principal as Principal;
  if (plan.hostId && principal.kind === 'host' && principal.hostId !== plan.hostId) {
    return res.status(403).json({ status: 'rejected', reason: 'Plan ini terikat ke host lain.' });
  }
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

// Local audit log persistence (JSON-file based local database).
// Integritas: setiap entri membawa `seq` + `prevHash` + `hash` (hash chain
// SHA-256). `hash` hanya mencakup isi entri, sehingga soft-delete tidak
// memutus rantai. GET menyertakan status rantai agar manipulasi file terlihat.
const AUDIT_DB_PATH = path.join(DATA_DIR, 'audit_logs.json');
const MAX_AUDIT_LOGS = 2000;
const GENESIS_HASH = 'sha256:genesis';

function ensureAuditDbDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function auditEntryHash(prevHash: string, entry: Record<string, any>): string {
  const content: Record<string, any> = { ...entry };
  delete content.hash;
  delete content.prevHash;
  delete content.seq;
  delete content.deletedAt;
  return 'sha256:' + crypto.createHash('sha256').update(`${prevHash}|${stableStringify(content)}`).digest('hex');
}

/** Bangun ulang seq/prevHash/hash secara deterministik untuk seluruh entri. */
function sealAuditChain(logs: any[]): any[] {
  let prev = GENESIS_HASH;
  return logs.map((entry, index) => {
    const sealed = { ...entry, seq: index + 1, prevHash: prev };
    sealed.hash = auditEntryHash(prev, sealed);
    prev = sealed.hash;
    return sealed;
  });
}

/** Verifikasi rantai apa adanya (tanpa memperbaiki) — mendeteksi suntingan luar. */
function verifyAuditChain(logs: any[]): { ok: boolean; brokenAt: number | null } {
  let prev = GENESIS_HASH;
  for (let i = 0; i < logs.length; i++) {
    const expected = auditEntryHash(prev, logs[i]);
    if (Number(logs[i]?.seq) !== i + 1 || String(logs[i]?.prevHash) !== prev || String(logs[i]?.hash) !== expected) {
      return { ok: false, brokenAt: i + 1 };
    }
    prev = expected;
  }
  return { ok: true, brokenAt: null };
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

function readAuditLogsStrict(): any[] {
  ensureAuditDbDir();
  if (!fs.existsSync(AUDIT_DB_PATH)) return [];
  const parsed = JSON.parse(fs.readFileSync(AUDIT_DB_PATH, 'utf-8'));
  if (!Array.isArray(parsed)) throw new Error('audit_logs.json tidak berisi array; data tidak ditimpa.');
  return parsed;
}

function writeAuditLogs(logs: any[]) {
  try {
    ensureAuditDbDir();
    // Reseal selalu: file lama (pra-hash chain) otomatis dimigrasikan.
    writeJsonAtomic(AUDIT_DB_PATH, sealAuditChain(logs.slice(-MAX_AUDIT_LOGS)));
    return true;
  } catch (err) {
    console.error('[PASOPATI] Gagal menulis local audit database:', (err as Error).message);
    return false;
  }
}

/** Tambah entri (id duplikat diabaikan) — dipakai ingest & evidence remediasi. */
function appendAuditLogs(entries: any[], strict = false) {
  if (!Array.isArray(entries) || entries.length === 0) return 0;
  const existing = strict ? readAuditLogsStrict() : readAuditLogs();
  const known = new Set(existing.map(l => String(l.id)));
  const fresh = entries.filter(l => l && !known.has(String(l.id)));
  if (fresh.length === 0) return existing.length;
  const merged = [...existing, ...fresh].slice(-MAX_AUDIT_LOGS);
  const persisted = writeAuditLogs(merged);
  if (strict && !persisted) throw new Error('Audit log tidak dapat ditulis ke penyimpanan permanen.');
  return merged.length;
}

app.get('/api/audit-logs', requireApiKey, (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 2000, 1), MAX_AUDIT_LOGS);
  const offset = Math.max(Number(req.query.offset) || 0, 0);
  const all = readAuditLogs();
  const includeDeleted = String(req.query.includeDeleted || '') === '1';
  const visible = (includeDeleted ? all : all.filter(l => !l.deletedAt)).slice().reverse(); // terbaru dulu
  const chain = verifyAuditChain(all);
  const logs = visible.slice(offset, offset + limit);
  return res.json({
    logs,
    total: visible.length,
    offset,
    limit,
    chainOk: chain.ok,
    chainBrokenAt: chain.brokenAt,
    deletedCount: all.filter(l => l.deletedAt).length
  });
});

// Verifikasi rantai audit (untuk laporan / pemeriksa eksternal).
app.get('/api/audit-logs/verify', requireApiKey, (_req, res) => {
  const all = readAuditLogs();
  const chain = verifyAuditChain(all);
  return res.status(chain.ok ? 200 : 409).json({
    status: chain.ok ? 'success' : 'rejected',
    chainOk: chain.ok,
    brokenAt: chain.brokenAt,
    entries: all.length,
    deleted: all.filter(l => l.deletedAt).length
  });
});

app.post('/api/audit-logs', requireRole('executor', 'agent'), (req, res) => {
  const body = req.body;
  const incoming = Array.isArray(body) ? body : Array.isArray(body?.logs) ? body.logs : [];
  if (!Array.isArray(incoming) || incoming.length === 0) {
    return res.status(400).json({ status: 'rejected', reason: 'No audit log entries provided.' });
  }

  const MAX_PER_REQUEST = 200;
  const cleaned = incoming.slice(0, MAX_PER_REQUEST).map((e: any) => ({
    id: typeof e?.id === 'string' ? e.id.slice(0, 80) : `LOG-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
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

  const before = readAuditLogs().length;
  const total = appendAuditLogs(cleaned);
  return res.json({
    status: 'success',
    received: incoming.length,
    added: Math.max(total - before, 0),
    rejected: Math.max(incoming.length - cleaned.length, 0),
    total
  });
});

// Soft delete: isi dipertahankan (rantai utuh) dan ditandai deletedAt.
app.delete('/api/audit-logs', requireRole('admin'), (_req, res) => {
  const all = readAuditLogs();
  const now = new Date().toISOString();
  let marked = 0;
  for (const entry of all) {
    if (!entry.deletedAt) {
      entry.deletedAt = now;
      marked += 1;
    }
  }
  if (marked > 0) writeAuditLogs(all);
  return res.json({ status: 'success', softDeleted: marked, retained: all.length });
});

// Catat setiap unduhan berkas (admin dapat melihatnya di tab Endpoint Audit →
// Aktivitas & Akses). Dicatat saat respons selesai agar hanya unduhan sukses tercatat.
app.use('/api/download', (req, res, next) => {
  res.on('finish', () => {
    if (res.statusCode >= 400) return;
    const subject = req.path === '/project-zip' ? 'pasopati-project.zip' : path.basename(req.path);
    recordActivity(req, 'FILE_DOWNLOADED', subject || 'unknown', `HTTP ${res.statusCode}`, 'SUCCESS');
  });
  next();
});

// Direct Downloads for Jury Evaluation & Field Deployment
// Nama kanonis: pasopati_audit.py / pasopati_remediate.py.
// /api/download/pasopati_agent.py tetap dilayani sebagai alias agar tautan lama tidak 404.
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
// Skrip orkestrasi uji lapangan untuk laptop target (LAN).
app.get('/api/download/run-windows-test.ps1', (_req, res) => {
  const filePath = path.resolve(process.cwd(), 'docs', 'run-windows-test.ps1');
  if (!fs.existsSync(filePath)) return res.status(404).send('File run-windows-test.ps1 tidak ditemukan');
  res.download(filePath, 'run-windows-test.ps1');
});

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
app.post('/api/scan-host', requireRole('executor', 'viewer'), asyncHandler(async (req, res) => {
  const rawUnitName = (req.body && typeof req.body === 'object' ? (req.body as any).unitName : '');
  const targetUnit = String(rawUnitName || 'PASOPATI-HOST-RUNTIME').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64);
  try {
    const data = await runHostAuditAgent(targetUnit);
    if (!data?.scoring) {
      throw new Error('Deep agent response is missing scoring block');
    }
    recordActivity(req, 'REALTIME_SCAN', targetUnit, `Skor ${data.scoring.cyber_readiness_score ?? '—'}/100`, 'SUCCESS');
    return res.json(data);
  } catch (err: any) {
    console.error('[PUSKODAL-SCAN] Live host scan gagal:', err?.message || err);
    recordActivity(req, 'REALTIME_SCAN', targetUnit, String(err?.message || 'Scan gagal').slice(0, 200), 'FAILED');
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

// Kunci DATA_DIR: cegah dua server berbagi file state yang sama (tulis JSON
// read-modify-write tidak aman lintas proses). Lock basi (pid mati) ditimpa.
const LOCK_PATH = path.join(DATA_DIR, '.server.lock');

function acquireDataLock() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    let ownsLock = false;
    for (let attempt = 0; attempt < 2 && !ownsLock; attempt++) {
      let descriptor: number | undefined;
      let createdByThisAttempt = false;
      try {
        descriptor = fs.openSync(LOCK_PATH, 'wx', 0o600);
        createdByThisAttempt = true;
        fs.writeFileSync(descriptor, String(process.pid), 'utf-8');
        fs.fsyncSync(descriptor);
        fs.closeSync(descriptor);
        descriptor = undefined;
        ownsLock = true;
      } catch (err: any) {
        if (descriptor !== undefined) {
          try { fs.closeSync(descriptor); } catch { /* preserve original error */ }
        }
        if (createdByThisAttempt) {
          try { fs.unlinkSync(LOCK_PATH); } catch { /* startup will fail closed below */ }
          throw err;
        }
        if (err?.code !== 'EEXIST') throw err;
        const pid = Number(fs.readFileSync(LOCK_PATH, 'utf-8').trim());
        if (!Number.isInteger(pid) || pid <= 0) throw new Error('Lock DATA_DIR ada tetapi PID tidak valid; periksa .server.lock secara manual.', { cause: err });
        let alive = false;
        try {
          process.kill(pid, 0);
          alive = true;
        } catch (probeError: any) {
          if (probeError?.code === 'EPERM') alive = true;
          else if (probeError?.code !== 'ESRCH') throw probeError;
        }
        if (alive) throw new Error(`DATA_DIR sedang dipakai proses lain (pid ${pid}); hentikan proses lama atau gunakan PASOPATI_DATA_DIR berbeda.`, { cause: err });
        fs.unlinkSync(LOCK_PATH);
      }
    }
    if (!ownsLock) throw new Error('Tidak dapat memperoleh lock eksklusif untuk DATA_DIR.');
    const release = () => {
      try {
        if (fs.readFileSync(LOCK_PATH, 'utf-8').trim() === String(process.pid)) fs.unlinkSync(LOCK_PATH);
      } catch { /* abaikan */ }
    };
    process.on('exit', release);
    process.on('SIGINT', () => { release(); process.exit(0); });
    process.on('SIGTERM', () => { release(); process.exit(0); });
  } catch (err) {
    console.error('[PASOPATI] Lock DATA_DIR gagal dipasang; server tidak akan start:', (err as Error).message);
    process.exit(1);
  }
}

async function startServer() {
  const isDev = process.env.NODE_ENV !== 'production';
  console.log(`[PASOPATI] DATA_DIR: ${DATA_DIR}${process.env.PASOPATI_DATA_DIR ? ' (PASOPATI_DATA_DIR)' : ' (default: cwd/data)'}`);
  if (!process.env.PASOPATI_DATA_DIR && /[\\/]system32$/i.test(process.cwd())) {
    console.warn('[PASOPATI] cwd berada di System32; set PASOPATI_DATA_DIR eksplisit agar registry tidak tersebar.');
  }
  acquireDataLock();

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

  const tlsCertPath = process.env.TLS_CERT;
  const tlsKeyPath = process.env.TLS_KEY;
  const useTls = Boolean(tlsCertPath && tlsKeyPath);
  const onListen = () => {
    console.log(`[PASOPATI] Command Center server running at ${useTls ? 'https' : 'http'}://0.0.0.0:${PORT}`);
  };
  const server = useTls
    ? https.createServer({ cert: fs.readFileSync(String(tlsCertPath)), key: fs.readFileSync(String(tlsKeyPath)) }, app).listen(PORT, '0.0.0.0', onListen)
    : app.listen(PORT, '0.0.0.0', onListen);

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
