import fs from 'node:fs';
import path from 'node:path';
import { isIP } from 'node:net';
import type { DeviceInfo, SecurityCheck } from './types';

export interface EndpointChange {
  at: string;
  action: 'CREATE' | 'UPDATE' | 'DELETE' | 'TELEMETRY';
  actor: string;
  source: 'operator' | 'agent';
  summary: string;
}

export interface EndpointRecord extends DeviceInfo {
  agentId?: string;
  source: 'operator' | 'agent';
  createdAt: string;
  updatedAt: string;
  created_at: string;
  updated_at: string;
  revision: number;
  lastSeenAt?: string;
  changeHistory: EndpointChange[];
  telemetryEventIds?: string[];
  deletedAt?: string;
}

export type EndpointInput = Partial<Pick<EndpointRecord,
  'name' | 'hostname' | 'role' | 'os' | 'platformType' | 'ip' | 'mac' | 'user' |
  'openPorts' | 'checks' | 'isQuarantined' | 'history' | 'agentId'>>;

const CHECK_STATUSES = new Set(['PASS', 'WARNING', 'FAIL', 'N/A', 'WAIVED']);
const CHECK_CATEGORIES = new Set([
  'Network & Port', 'Access Control', 'Endpoint Protection', 'System Logging',
  'Kernel & Boot', 'Cryptographic Posture', 'Privilege Boundary'
]);
const textFields = ['name', 'hostname', 'role', 'os', 'ip', 'mac', 'user', 'agentId'] as const;

function plainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function hasUnsafeControlCharacters(value: string): boolean {
  return Array.from(value).some(char => {
    const code = char.charCodeAt(0);
    return (code < 32 && code !== 9 && code !== 10 && code !== 13) || code === 127;
  });
}

function cleanText(value: unknown, field: string, maxLength: number): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new Error(`${field} harus berupa teks.`);
  const text = value.trim();
  if (text.length > maxLength) throw new Error(`${field} melebihi ${maxLength} karakter.`);
  if (hasUnsafeControlCharacters(text)) throw new Error(`${field} mengandung karakter kontrol.`);
  return text;
}

function cleanChecks(value: unknown): SecurityCheck[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 500) throw new Error('checks harus array dengan maksimal 500 item.');
  return value.map((raw, index) => {
    if (!plainObject(raw)) throw new Error(`checks[${index}] harus berupa object.`);
    const parameter = cleanText(raw.parameter ?? raw.param, `checks[${index}].parameter`, 200);
    const status = String(raw.status ?? '').toUpperCase();
    if (!parameter) throw new Error(`checks[${index}].parameter wajib diisi.`);
    if (!CHECK_STATUSES.has(status)) throw new Error(`checks[${index}].status tidak valid.`);
    const category = String(raw.category ?? raw.cat ?? 'Network & Port');
    const safeCategory = CHECK_CATEGORIES.has(category) ? category : 'Network & Port';
    return {
      id: cleanText(raw.id, `checks[${index}].id`, 80) || `c${index + 1}`,
      parameter,
      category: safeCategory as SecurityCheck['category'],
      cis_id: cleanText(raw.cis_id ?? raw.cis, `checks[${index}].cis_id`, 120) || '',
      status: status as SecurityCheck['status'],
      details: cleanText(raw.details ?? raw.detail, `checks[${index}].details`, 2000) || '',
      mitigation: cleanText(raw.mitigation, `checks[${index}].mitigation`, 2000) || ''
    };
  });
}

export function normalizeEndpointInput(raw: unknown, partial = false): EndpointInput {
  if (!plainObject(raw)) throw new Error('Body endpoint harus berupa JSON object.');
  const output: EndpointInput = {};
  const limits: Record<(typeof textFields)[number], number> = {
    name: 120, hostname: 255, role: 160, os: 160, ip: 64, mac: 32, user: 120, agentId: 64
  };
  for (const field of textFields) {
    if (Object.hasOwn(raw, field)) {
      const value = cleanText(raw[field], field, limits[field]);
      if (value !== undefined) Object.assign(output, { [field]: value });
    }
  }

  if (Object.hasOwn(raw, 'platformType')) {
    const platform = String(raw.platformType ?? '').toLowerCase();
    if (!['linux', 'windows', 'embedded'].includes(platform)) throw new Error('platformType harus linux, windows, atau embedded.');
    output.platformType = platform as EndpointRecord['platformType'];
  }
  if (Object.hasOwn(raw, 'ip') && output.ip && isIP(output.ip) === 0) throw new Error('ip harus berupa alamat IPv4 atau IPv6 yang valid.');
  if (Object.hasOwn(raw, 'mac') && output.mac && !/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(output.mac)) {
    throw new Error('mac harus menggunakan format 00:11:22:33:44:55.');
  }
  if (Object.hasOwn(raw, 'openPorts')) {
    if (!Array.isArray(raw.openPorts) || raw.openPorts.length > 512) throw new Error('openPorts harus array dengan maksimal 512 port.');
    const ports = raw.openPorts.map(Number);
    if (ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) throw new Error('Setiap port harus berupa integer 1–65535.');
    output.openPorts = [...new Set(ports)];
  }
  if (Object.hasOwn(raw, 'checks')) output.checks = cleanChecks(raw.checks);
  if (Object.hasOwn(raw, 'isQuarantined')) {
    if (typeof raw.isQuarantined !== 'boolean') throw new Error('isQuarantined harus boolean.');
    output.isQuarantined = raw.isQuarantined;
  }
  if (Object.hasOwn(raw, 'history')) {
    if (!Array.isArray(raw.history) || raw.history.length > 200) throw new Error('history harus array dengan maksimal 200 titik.');
    output.history = raw.history.slice(-200).map((point, i) => {
      if (!plainObject(point)) throw new Error(`history[${i}] harus berupa object.`);
      const score = Number(point.score);
      if (!Number.isFinite(score) || score < 0 || score > 100) throw new Error(`history[${i}].score harus 0–100.`);
      return {
        timestamp: cleanText(point.timestamp ?? point.time, `history[${i}].timestamp`, 40) || new Date().toISOString(),
        score,
        passCount: Math.max(0, Number(point.passCount ?? point.passed_checks) || 0),
        warnCount: Math.max(0, Number(point.warnCount ?? point.warning_checks) || 0),
        failCount: Math.max(0, Number(point.failCount ?? point.failed_checks) || 0),
        event: cleanText(point.event, `history[${i}].event`, 160) || 'Audit'
      };
    });
  }

  if (!partial) {
    if (!(output.name || output.hostname)) throw new Error('name atau hostname wajib diisi.');
    output.name = output.name || output.hostname || 'Endpoint';
    output.hostname = output.hostname || output.name;
    output.role = output.role || 'Endpoint';
    output.os = output.os || 'Unknown';
    output.platformType = output.platformType || 'linux';
    output.ip = output.ip || '';
    output.mac = output.mac || '';
    output.user = output.user || '';
    output.openPorts = output.openPorts || [];
    output.checks = output.checks || [];
  }
  return output;
}

export function endpointIdentityKey(input: Pick<EndpointInput, 'agentId' | 'mac' | 'hostname'>): string {
  const mac = String(input.mac || '').toLowerCase();
  const meaningfulMac = mac && mac !== '00:00:00:00:00:00' ? mac : '';
  const hardware = meaningfulMac ? `mac:${meaningfulMac}` : `host:${String(input.hostname || '').trim().toLowerCase()}`;
  const agent = String(input.agentId || '').trim().toLowerCase();
  return `${agent ? `agent:${agent}|` : ''}${hardware}`;
}

export function findEndpointByIdentity(records: EndpointRecord[], input: EndpointInput): EndpointRecord | undefined {
  const key = endpointIdentityKey(input);
  const mac = String(input.mac || '').toLowerCase();
  const hostname = String(input.hostname || '').trim().toLowerCase();
  return records.find(record => !record.deletedAt && (
    endpointIdentityKey(record) === key ||
    (mac && mac !== '00:00:00:00:00:00' && String(record.mac || '').toLowerCase() === mac) ||
    (!mac && hostname && String(record.hostname || '').trim().toLowerCase() === hostname)
  ));
}

export function readEndpointRecords(filePath: string): EndpointRecord[] {
  if (!fs.existsSync(filePath)) return [];
  const parsed: unknown = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  if (!Array.isArray(parsed) || parsed.some(item => !plainObject(item) || typeof item.id !== 'string' || typeof item.createdAt !== 'string')) {
    throw new Error('endpoint_inventory.json tidak sesuai skema; data tidak ditimpa.');
  }
  return parsed.map((item: any) => {
    const createdAt = String(item.created_at || item.createdAt);
    const updatedAt = String(item.updated_at || item.updatedAt || createdAt);
    return {
      ...item,
      createdAt,
      updatedAt,
      created_at: createdAt,
      updated_at: updatedAt,
      revision: Number.isSafeInteger(item.revision) && item.revision > 0 ? item.revision : 1
    } as EndpointRecord;
  });
}

export function writeEndpointRecords(filePath: string, records: EndpointRecord[]): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  try {
    fs.writeFileSync(tempPath, JSON.stringify(records, null, 2), { encoding: 'utf-8', mode: 0o600, flag: 'wx' });
    fs.renameSync(tempPath, filePath);
  } catch (error) {
    try { fs.rmSync(tempPath, { force: true }); } catch { /* preserve the original write error */ }
    throw error;
  }
}
