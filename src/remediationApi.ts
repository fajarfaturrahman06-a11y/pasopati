import { RemediationPlan, RemediationPlanItem } from './types';

function apiHeaders(apiKey: string): Record<string, string> {
  const key = (apiKey || '').trim();
  return key
    ? { 'Content-Type': 'application/json', 'X-Pasopati-API-Key': key }
    : { 'Content-Type': 'application/json' };
}

export async function postJson<T>(path: string, apiKey: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: apiHeaders(apiKey),
    body: JSON.stringify(body)
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error((data && data.reason) ? String(data.reason) : `HTTP ${res.status}`);
  }
  return data as T;
}

export async function getJson<T>(path: string, apiKey: string): Promise<T> {
  const res = await fetch(path, { headers: apiHeaders(apiKey) });
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error((data && data.reason) ? String(data.reason) : `HTTP ${res.status}`);
  }
  return data as T;
}

export async function createPlan(
  apiKey: string,
  deviceId: string,
  items: RemediationPlanItem[],
  createdBy: string
): Promise<RemediationPlan> {
  const data = await postJson<{ plan: RemediationPlan }>('/api/remediation-plan', apiKey, {
    deviceId,
    items,
    createdBy
  });
  return data.plan;
}

export async function approvePlan(
  apiKey: string,
  planId: string,
  approvedBy: string
): Promise<{ planId: string; nonce: string; expiresAt: number; signature: string; token: string; plan: RemediationPlan }> {
  return postJson('/api/remediation-approve', apiKey, { planId, approvedBy });
}

export async function getPlan(apiKey: string, planId: string): Promise<RemediationPlan> {
  const data = await getJson<{ plan: RemediationPlan }>('/api/remediation-plans/' + encodeURIComponent(planId), apiKey);
  return data.plan;
}

export async function listPlans(apiKey: string): Promise<RemediationPlan[]> {
  const data = await getJson<{ plans: RemediationPlan[] }>('/api/remediation-plans', apiKey);
  return Array.isArray(data.plans) ? data.plans : [];
}

export function wslCommandText(serverUrl: string, planPath: string, token: string, apiKey: string): string {
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
    '  --no-exec'
  ].join(' \\\n');
}

/** Perintah untuk host target: ambil plan langsung dari server (target hanya butuh agent). */
export function agentCommandText(serverUrl: string, planId: string, apiKey: string, hmacKey: string): string {
  const server = (serverUrl || 'http://localhost:3000').trim().replace(/\/$/, '');
  const id = (planId || '<PLAN_ID>').trim();
  const key = (apiKey || '').trim() || '<PASOPATI_API_KEY>';
  const hmac = (hmacKey || '').trim() || '<HMAC_SECRET>';
  return `python pasopati_remediate.py --server "${server}" --plan-id "${id}" --remediate-api-key "${key}" --hmac-key "${hmac}"`;
}
