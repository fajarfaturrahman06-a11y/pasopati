import type { DeviceInfo, RemediationPlanItem, SecurityCheck } from './types';

/**
 * Pemetaan parameter temuan hardening → alias aksi allowlist agent.
 * Dipakai bersama oleh generator runbook dan panel remediasi agar item
 * remediasi selalu berasal dari temuan hardening yang sama.
 */
const ADVISORY_ALIASES = new Set(['advisory-fde', 'advisory-rootkit', 'advisory-secureboot', 'advisory-admins']);

export function aliasForCheck(device: DeviceInfo, parameter: string, details: string): string | null {
  const text = (parameter + ' ' + details).toLowerCase();
  const isWindows = device.platformType === 'windows';
  if (text.includes('dangerous port') || text.includes('network & dangerous ports')) {
    return isWindows ? 'ports-block-windows' : 'ports-block-linux';
  }
  if (text.includes('luks') || text.includes('full disk encryption')) return 'advisory-fde';
  if (text.includes('secure boot')) return 'advisory-secureboot';
  if (text.includes('rootkit') || text.includes('kernel module')) return 'advisory-rootkit';
  if (text.includes('local administrators') || text.includes('administrators group')) return 'advisory-admins';
  if (text.includes('grub')) return isWindows ? null : 'grub-config-perms';
  if (text.includes('suid')) return isWindows ? null : 'suid-strip-critical';
  if (text.includes('sudoers') || text.includes('nopasswd')) return isWindows ? null : 'sudoers-remove-nopasswd';
  if (text.includes('usb')) return isWindows ? 'usb-storage-block' : 'usb-block-linux';
  if (text.includes('guest')) return isWindows ? 'guest-account-disable' : null;
  if (text.includes('bitlocker')) return isWindows ? 'bitlocker-enable' : null;
  if (text.includes('rdp') || text.includes('nla') || text.includes('3389')) return isWindows ? 'rdp-nla-enable' : null;
  if (text.includes('uac')) return isWindows ? 'uac-enable' : null;
  if (text.includes('ssh') && text.includes('root')) return isWindows ? null : 'ssh-disable-root';
  if (text.includes('auditd') || text.includes('audit daemon') || text.includes('syslog')) return isWindows ? null : 'auditd-enable';
  if (text.includes('event log') || text.includes('auditing')) return isWindows ? 'win-auditpol-process' : null;
  if (text.includes('firewall') || text.includes('ufw') || text.includes('defender')) {
    return isWindows ? 'fw-enable-defender' : 'fw-enable-ufw';
  }
  return null;
}

/** Temuan yang masih layak diremediasi (termasuk yang baru disimulasikan di dashboard). */
export function isRemediableCheck(check: SecurityCheck): boolean {
  return check.status === 'FAIL' || check.status === 'WARNING' || check.details.includes('[SIMULASI');
}

/**
 * Turunkan item remediasi (parameter) dari temuan hardening FAIL/WARNING.
 * Parameter temuan, CIS ID, dan mitigasi ikut dibawa agar operator melihat
 * dasar tindakan yang akan dieksekusi agent.
 */
export function buildRemediationItems(device: DeviceInfo | null | undefined): RemediationPlanItem[] {
  if (!device) return [];
  const seen = new Map<string, RemediationPlanItem>();
  for (const check of device.checks) {
    if (!isRemediableCheck(check)) continue;
    const alias = aliasForCheck(device, check.parameter, check.details);
    if (!alias || seen.has(alias)) continue;
    const advisory = ADVISORY_ALIASES.has(alias);
    seen.set(alias, {
      findingId: check.id,
      alias,
      kind: advisory ? 'advisory' : 'enforce',
      title: check.parameter,
      risk: advisory ? 'LOW' : check.status === 'FAIL' ? 'HIGH' : 'MEDIUM',
      reversible: !advisory,
      preState: `[${check.cis_id}] ${check.parameter} — ${check.details}`.slice(0, 500),
      postStateExpected: check.mitigation.slice(0, 500)
    });
  }
  return Array.from(seen.values());
}
