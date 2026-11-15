/**
 * Uji cakupan generator runbook: SETIAP parameter audit yang bisa dihasilkan
 * pasopati_audit.py harus punya aksi di skrip hardening + rollback, dan tidak
 * boleh ada temuan yang hilang tanpa catatan.
 *
 * Jalankan: npx tsx tests/scripts-coverage.ts
 */
import { execFileSync } from 'node:child_process';
import { buildRemediationScripts } from '../src/remediationScripts';
import { buildRemediationItems, aliasForCheck } from '../src/remediationMapping';
import type { DeviceInfo, SecurityCheck } from '../src/types';

let pass = 0;
const failures: string[] = [];
function check(name: string, ok: boolean, detail = '') {
  if (ok) {
    pass++;
    console.log(`PASS  ${name}`);
  } else {
    failures.push(name);
    console.log(`FAIL  ${name}${detail ? ' — ' + detail : ''}`);
  }
}

function mkCheck(i: number, parameter: string, details: string): SecurityCheck {
  return {
    id: `c${i}`,
    parameter,
    category: 'Network & Port',
    cis_id: 'CIS-X',
    status: 'FAIL',
    details,
    mitigation: `Mitigasi untuk ${parameter}`
  };
}

function mkDevice(platformType: 'linux' | 'windows', checks: SecurityCheck[], openPorts: number[] = []): DeviceInfo {
  return {
    id: 'DEV',
    name: 'DEV / UJI',
    hostname: 'dev.test',
    role: 'Server Uji',
    os: platformType === 'windows' ? 'Windows 11 Pro' : 'Ubuntu 22.04',
    platformType,
    ip: '10.0.0.1',
    mac: '00:11:22:33:44:55',
    user: 'tester',
    openPorts,
    checks
  };
}

const linuxParams: Array<[string, string]> = [
  ['Network & Dangerous Ports Filtering', 'Port 445 / 23 / 21 / 4444 terbuka'],
  ['Host-Based Local Firewall Active', 'UFW inactive'],
  ['SSH Root Login & Auth', 'PermitRootLogin yes'],
  ['USB Mass Storage Restriction', 'usb-storage tidak diblacklist'],
  ['Auditd Daemon Security Logging', 'auditd tidak aktif'],
  ['Kernel Module Integrity & Rootkit Scan', 'modul diamorphine terdeteksi'],
  ['Bootloader GRUB Configuration Hardening', 'grub.cfg mode 644'],
  ['Full Disk Encryption (LUKS)', 'belum dienkripsi LUKS'],
  ['Sudoers Privilege Boundary & NOPASSWD', 'ada NOPASSWD'],
  ['SUID Binary Escalation Vector Scan', 'SUID pada /bin/bash']
];

const winParams: Array<[string, string]> = [
  ['Network & Dangerous Ports Filtering', 'Port 445 / 3389 / 4444 terbuka'],
  ['Host-Based Local Firewall Active', 'satu profil firewall OFF'],
  ['Guest Account Lockdown', 'akun Guest aktif'],
  ['USB Storage Device Control', 'Verifikasi kebijakan USB Mass Storage memerlukan hak administrator.'],
  ['Windows Event Log & Auditing', 'audit process creation mati'],
  ['UEFI Secure Boot & Driver Enforcement', 'UEFI Secure Boot DINONAKTIFKAN! Rawan manipulasi rootkit boot (BootHole/BlackLotus).'],
  ['BitLocker Drive Encryption (FDE)', 'BitLocker tidak aktif'],
  ['Local Administrators Group Membership', 'terlalu banyak admin'],
  ['UAC (EnableLUA)', 'UAC tidak aktif'],
  ['Remote Desktop NLA', 'NLA tidak aktif pada RDP 3389']
];

const linux = mkDevice('linux', linuxParams.map(([p, d], i) => mkCheck(i, p, d)), [21, 23, 445, 4444]);
const win = mkDevice('windows', winParams.map(([p, d], i) => mkCheck(i, p, d)), [3389, 445, 4444]);

// ---------- Linux ----------
{
  const { hard, roll } = buildRemediationScripts(linux, true);
  const mustHard = [
    'iptables -A INPUT -p tcp --dport 4444',
    'iptables -A INPUT -p tcp --dport 445',
    'iptables -A INPUT -p tcp --dport 23',
    'iptables -A INPUT -p tcp --dport 21',
    'ufw --force enable',
    'PermitRootLogin no',
    'pasopati-usb-lock.conf',
    'systemctl enable --now auditd',
    '/boot/grub/grub.cfg',
    'NOPASSWD:',
    'chmod u-s',
    'crypto_LUKS',
    'rootkit'
  ];
  for (const token of mustHard) check(`Linux: hardening memuat "${token}"`, hard.includes(token));

  const mustRoll = [
    'iptables -D INPUT -p tcp --dport 4444',
    'ufw --force disable',
    'sshd_config.pre',
    'systemctl disable --now auditd',
    'grub.list',
    'sudoers',
    'suid.list'
  ];
  for (const token of mustRoll) check(`Linux: rollback memuat "${token}"`, roll.includes(token));

  check('Linux: tidak ada temuan yang tertinggal tanpa catatan', !hard.includes("[FAIL] ") && hard.includes('(tidak ada'));
  check('Linux: rollback punya bagian restore', roll.includes('RESTORED'));
  check('Linux: skrip mencantumkan parameter remediasi turunan', hard.includes('PARAMETER REMEDIASI') && hard.includes('# - fw-enable-ufw <-'));
  check('Linux: skrip meminta root otomatis (sudo -E/marker/pkexec)', hard.includes('exec sudo -E bash') && hard.includes('PASOPATI_ELEVATED') && hard.includes('pkexec'));
  check('Linux: rollback juga meminta root', roll.includes('exec sudo -E bash') && roll.includes('PASOPATI_ELEVATED'));

  // Kirim skrip lewat stdin agar path Windows tidak perlu diterjemahkan WSL.
  try {
    execFileSync('bash', ['-n'], { input: hard, stdio: 'pipe' });
    check('Linux: skrip lolos bash -n', true);
  } catch (e: any) {
    check('Linux: skrip lolos bash -n', false, String(e?.stderr || e?.message));
  }
}

// ---------- Windows ----------
{
  const { hard, roll } = buildRemediationScripts(win, false);
  const mustHard = [
    "PASOPATI-Block-4444",
    'Set-NetFirewallProfile',
    'Disable-LocalUser',
    'USBSTOR',
    'auditpol /set',
    'Confirm-SecureBootUEFI',
    'manage-bde -on',
    'EnableLUA',
    'Get-LocalGroupMember'
  ];
  for (const token of mustHard) check(`Windows: hardening memuat "${token}"`, hard.includes(token));
  check('Windows: rollback menghapus rule firewall', roll.includes('Remove-NetFirewallRule'));
  check('Windows: rollback memulihkan USBSTOR', roll.includes('usbstor.txt'));
  check('Windows: tidak ada temuan yang tertinggal tanpa catatan', !hard.includes('[FAIL] ') && hard.includes('(tidak ada'));
  check('Windows: skrip mencantumkan parameter remediasi turunan', hard.includes('PARAMETER REMEDIASI') && hard.includes('# - fw-enable-defender <-'));
  check('Windows: skrip meminta Administrator via UAC', hard.includes('-Verb RunAs') && hard.includes("-Elevated"));
  check('Windows: rollback juga meminta Administrator', roll.includes('-Verb RunAs') && roll.includes('-Elevated'));
}

// ---------- Parameter remediasi diturunkan dari temuan hardening ----------
{
  const items = buildRemediationItems(linux);
  const aliases = items.map(i => i.alias);
  for (const expected of ['fw-enable-ufw', 'ssh-disable-root', 'usb-block-linux', 'auditd-enable', 'grub-config-perms', 'sudoers-remove-nopasswd', 'suid-strip-critical']) {
    check(`Mapping Linux menghasilkan alias "${expected}"`, aliases.includes(expected));
  }
  check('Item remediasi membawa CIS ID + mitigasi', items.every(i => (i.preState || '').includes('CIS-') && i.postStateExpected === 'Mitigasi untuk ' + items.find(x => x.findingId === i.findingId)?.preState?.split('] ')[1]?.split(' —')[0]));
  check('Langkah enforce berisiko HIGH', items.filter(i => i.kind === 'enforce').every(i => i.risk === 'HIGH'));
  check('USB tidak salah petakan ke advisory-admins', items.some(i => i.alias === 'usb-block-linux'));
  check('Temuan non-otomatis menjadi langkah advisory', ['advisory-fde', 'advisory-rootkit'].every(a => items.some(i => i.alias === a && i.kind === 'advisory')));

  const winItemsAll = buildRemediationItems(win);
  const winItemsBefore = winItemsAll.map(i => i.alias);
  check('Secure Boot tidak salah petakan ke advisory-rootkit', winItemsBefore.includes('advisory-secureboot') && !buildRemediationItems(win).find(i => i.title?.includes('Secure Boot'))?.alias?.includes('rootkit'));
  check('Ada langkah advisory untuk Secure Boot & Administrators', buildRemediationItems(win).some(i => i.alias === 'advisory-secureboot') && buildRemediationItems(win).some(i => i.alias === 'advisory-admins'));

  // Seleksi: hanya alias terpilih yang masuk skrip.
  const onlyFw = buildRemediationScripts(linux, true, new Set(['fw-enable-ufw']));
  check('Seleksi menjaga hanya langkah terpilih', onlyFw.hard.includes('ufw --force enable') && !onlyFw.hard.includes('PermitRootLogin no'));
  check('Header hanya mencantumkan yang terpilih', onlyFw.hard.includes('# - fw-enable-ufw <-') && !onlyFw.hard.includes('# - ssh-disable-root <--'));

  const winItems = winItemsBefore;
  for (const expected of ['fw-enable-defender', 'guest-account-disable', 'usb-storage-block', 'uac-enable', 'bitlocker-enable', 'rdp-nla-enable', 'win-auditpol-process']) {
    check(`Mapping Windows menghasilkan alias "${expected}"`, winItems.includes(expected));
  }
  check('aliasForCheck aman untuk device null', buildRemediationItems(null).length === 0);
  check('aliasForCheck Linux tidak memetakan bitlocker', aliasForCheck(linux, 'BitLocker', '') === null);
}

// ---------- Temuan yang baru disimulasikan tetap bisa diremediasi ----------
{
  const simulated = mkCheck(0, 'Host-Based Local Firewall Active', 'UFW inactive [SIMULASI DASHBOARD: status diubah, bukan eksekusi host]');
  simulated.status = 'PASS';
  const dev = mkDevice('linux', [simulated]);
  const items = buildRemediationItems(dev);
  const { hard } = buildRemediationScripts(dev, true);
  check('Temuan ber-marker SIMULASI tetap menghasilkan item remediasi', items.length === 1 && items[0].alias === 'fw-enable-ufw');
  check('Skrip tidak dianggap clean saat masih ada marker SIMULASI', hard.includes('PARAMETER REMEDIASI') && !hard.includes('Tidak diperlukan eksekusi perintah tambahan'));
}

// ---------- Temuan asing tetap dicatat ----------
{
  const unknown = mkDevice('linux', [mkCheck(0, 'Parameter Baru Tanpa Alias', 'detail khusus')]);
  const { hard } = buildRemediationScripts(unknown, true);
  check('Temuan tak dikenal tercatat di bagian advisory', hard.includes('Parameter Baru Tanpa Alias') && hard.includes('detail khusus'));
}

console.log(`\n${pass}/${pass + failures.length} pengujian lolos`);
if (failures.length) process.exit(1);
