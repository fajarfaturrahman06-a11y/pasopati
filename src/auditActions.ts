/**
 * Satu sumber kebenaran untuk nilai `action` pada audit log.
 * Dipakai server (penulis) dan UI (pembaca) agar tidak pernah drift.
 */
export const AUDIT_ACTIONS = [
  'HARDENING REMEDIATION',
  'ROLLBACK RESTORATION',
  'BASELINE RECON',
  'TELEMETRY INGESTION',
  'QUARANTINE KILL-SWITCH'
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];

/** Normalisasi nilai dari DB/klien; nilai asing menjadi BASELINE RECON. */
export function normalizeAuditAction(value: unknown): AuditAction {
  const raw = String(value ?? '').trim().toUpperCase();
  // Nilai lama server sebelum harmonisasi.
  if (raw === 'TELEMETRY INGEST') return 'TELEMETRY INGESTION';
  return (AUDIT_ACTIONS as readonly string[]).includes(raw) ? (raw as AuditAction) : 'BASELINE RECON';
}
