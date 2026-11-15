import { RemediationPlan, RemediationPlanItem } from './types';

const jsonHeaders = { 'Content-Type': 'application/json' };

export async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: jsonHeaders,
    body: JSON.stringify(body)
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error((data && data.reason) ? String(data.reason) : `HTTP ${res.status}`);
  }
  return data as T;
}

export async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path, { credentials: 'same-origin' });
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error((data && data.reason) ? String(data.reason) : `HTTP ${res.status}`);
  }
  return data as T;
}

export async function createPlan(
  deviceId: string,
  items: RemediationPlanItem[],
  hostId?: string,
  options?: { executionMode?: 'agent' | 'manual'; artifacts?: { hardening: string; rollback: string } }
): Promise<RemediationPlan> {
  const data = await postJson<{ plan: RemediationPlan }>('/api/remediation-plan', {
    deviceId,
    items,
    ...(hostId ? { hostId } : {}),
    ...(options?.executionMode ? { executionMode: options.executionMode } : {}),
    ...(options?.artifacts ? { artifacts: options.artifacts } : {})
  });
  return data.plan;
}

/** Laporan manual: tanpa HMAC, tetap memakai nonce plan yang sudah disetujui. */
export async function reportManualEvidence(
  planId: string,
  nonce: string,
  evidence: Array<{ stepIndex: number; alias: string; exitCode: number; outputHash: string; source: 'manual' }>
): Promise<{ planStatus: string; evidenceCount: number }> {
  return postJson('/api/remediation-verify', { planId, nonce, toStatus: 'MANUAL_REPORTED', source: 'manual', evidence });
}

export async function approvePlan(
  planId: string,
  acknowledgeConsole = false,
  selfApprove = false,
  force = false,
  credentials?: { agentApiKey?: string; agentHmacKey?: string }
): Promise<{ planId: string; nonce: string; expiresAt: number; signature: string; token: string; plan: RemediationPlan }> {
  return postJson('/api/remediation-approve', { planId, acknowledgeConsole, selfApprove, force, ...credentials });
}

export interface WhoAmI {
  name: string;
  role: string;
  kind: string;
  hostId?: string;
}

export async function getWhoAmI(): Promise<WhoAmI> {
  return getJson<WhoAmI>('/api/whoami');
}

export async function getPlan(planId: string): Promise<RemediationPlan> {
  const data = await getJson<{ plan: RemediationPlan }>('/api/remediation-plans/' + encodeURIComponent(planId));
  return data.plan;
}

export async function listPlans(): Promise<RemediationPlan[]> {
  const data = await getJson<{ plans: RemediationPlan[] }>('/api/remediation-plans');
  return Array.isArray(data.plans) ? data.plans : [];
}

/** Command for an agent host; login credentials stay out of the dashboard UI. */
export function wslCommandText(serverUrl: string, planPath: string, token: string, apiKey: string, forceAccessRisk = false): string {
  const server = (serverUrl || 'http://localhost:3000').trim().replace(/\/$/, '');
  const plan = (planPath || 'plan.json').trim() || 'plan.json';
  const tkn = (token || '').trim() || '<nonce>.<signature>';
  const key = (apiKey || '').trim() || '<PASOPATI_API_KEY>';
  return [
    'python3 pasopati_remediate.py --remediate-plan ' + plan,
    '  --remediate-token "' + tkn + '"',
    '  --push-url "' + server + '"',
    '  --remediate-api-key "' + key + '"',
    '  --hmac-key "$HMAC_SECRET"',
    '  --no-exec' + (forceAccessRisk ? ' --force-access-risk' : '')
  ].join(' \\\n');
}

/** Perintah untuk host target: ambil plan langsung dari server (target hanya butuh agent). */
export function agentCommandText(serverUrl: string, planId: string, apiKey: string, hmacKey: string, forceAccessRisk = false): string {
  const server = (serverUrl || 'http://localhost:3000').trim().replace(/\/$/, '');
  const id = (planId || '<PLAN_ID>').trim();
  const key = (apiKey || '').trim() || '<PASOPATI_API_KEY>';
  const hmac = (hmacKey || '').trim() || '<HMAC_SECRET>';
  return `python pasopati_remediate.py --server "${server}" --plan-id "${id}" --remediate-api-key "${key}" --hmac-key "${hmac}"` + (forceAccessRisk ? ' --force-access-risk' : '');
}
