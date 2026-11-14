import { DeviceInfo } from '../types';

export const INITIAL_MOCK_DEVICES: DeviceInfo[] = [
  {
    id: 'SRV-DATA-YONIF',
    name: 'SRV-DATA-YONIF',
    hostname: 'srv-data-yonif.tni-ad.mil.id',
    role: 'Server Database Operasi & Logistik Yonif',
    os: 'Ubuntu Server 22.04 LTS (x86_64)',
    platformType: 'linux',
    ip: '10.14.2.10',
    mac: '00:1A:4B:99:21:04',
    user: 'sysadmin_ops',
    openPorts: [22, 80, 443, 445, 3306],
    checks: [
      {
        id: 'c1',
        parameter: 'Network: SMB Port 445 Exposure',
        category: 'Network & Port',
        cis_id: 'CIS 3.4.1 / DISA STIG NET-001',
        status: 'FAIL',
        details: 'Port SMB 445 terbuka di antarmuka publik tanpa segmentasi VLAN taktis.',
        mitigation: 'Matikan daemon smbd jika tidak diperlukan atau isolasi ke subnet taktis.'
      },
      {
        id: 'c2',
        parameter: 'Host-Based Local Firewall (UFW)',
        category: 'Endpoint Protection',
        cis_id: 'CIS 3.5.1 / DISA STIG V-214870',
        status: 'FAIL',
        details: 'UFW Firewall berstatus inactive. Seluruh port inbound terpapar langsung.',
        mitigation: 'Aktifkan UFW dengan kebijakan default drop incoming.'
      },
      {
        id: 'c3',
        parameter: 'SSH Root Direct Login',
        category: 'Access Control',
        cis_id: 'CIS 5.2.10 / DISA STIG V-214878',
        status: 'FAIL',
        details: 'PermitRootLogin diaktifkan di /etc/ssh/sshd_config.',
        mitigation: 'Ubah PermitRootLogin menjadi "no" dan gunakan sudo privilege.'
      },
      {
        id: 'c4',
        parameter: 'USB Mass Storage Lock',
        category: 'Endpoint Protection',
        cis_id: 'CIS 1.1.23 / DISA STIG V-214840',
        status: 'WARNING',
        details: 'Modul usb-storage tidak diblacklist; rentan exfiltration data taktis via flashdisk.',
        mitigation: 'Tambahkan blacklist usb-storage pada /etc/modprobe.d/storage.conf.'
      },
      {
        id: 'c5',
        parameter: 'Kernel Auditd Service',
        category: 'System Logging',
        cis_id: 'CIS 4.1.1 / DISA STIG V-214875',
        status: 'FAIL',
        details: 'Auditd service dimatikan, tidak ada rekaman eskalasi privilege dan akses file rahasia.',
        mitigation: 'Jalankan systemctl enable auditd dan konfigurasikan audit rules.'
      },
      {
        id: 'c6',
        parameter: 'Kernel Module Integrity & Rootkit Scan',
        category: 'Kernel & Boot',
        cis_id: 'CIS 1.1.1 / DISA STIG V-214800',
        status: 'PASS',
        details: 'Modul kernel tervalidasi terhadap whitelist resmi; tidak ada unauthorized hook terdeteksi.',
        mitigation: 'Lakukan pemantauan berkala modul kernel via lsmod & debsums.'
      },
      {
        id: 'c7',
        parameter: 'Full Disk Encryption (LUKS)',
        category: 'Cryptographic Posture',
        cis_id: 'CIS 1.1.2 / DISA STIG V-214820',
        status: 'FAIL',
        details: 'Partisi /data database taktis belum terenkripsi LUKS; risiko cold-boot & physical storage extraction.',
        mitigation: 'Terapkan cryptsetup luksFormat pada partisi data dan gunakan keyfile militer.'
      },
      {
        id: 'c8',
        parameter: 'Sudoers NOPASSWD Privilege Boundary',
        category: 'Privilege Boundary',
        cis_id: 'CIS 5.3.4 / DISA STIG V-214885',
        status: 'FAIL',
        details: 'Ditemukan entri NOPASSWD pada /etc/sudoers.d/ops-script; memungkinkan bypass otentikasi root.',
        mitigation: 'Hapus directive NOPASSWD dan enforce otentikasi password interaktif.'
      }
    ],
    isQuarantined: false,
    history: [
      { timestamp: '2026-10-27 08:00', score: 65, passCount: 5, warnCount: 1, failCount: 2, event: 'Deploy Awal Satuan' },
      { timestamp: '2026-10-28 14:30', score: 50, passCount: 3, warnCount: 2, failCount: 3, event: 'Inspeksi Rutin Mingguan' },
      { timestamp: '2026-10-29 09:15', score: 38, passCount: 2, warnCount: 1, failCount: 5, event: 'Drift Terdeteksi (Celah Sudo & LUKS)' }
    ]
  },
  {
    id: 'PC-STAF-INTEL-01',
    name: 'PC-STAF-INTEL-01',
    hostname: 'pc-intel-analyst-01.tni.mil.id',
    role: 'Workstation Analis Intelijen Taktis',
    os: 'Windows 11 Enterprise (Build 22631)',
    platformType: 'windows',
    ip: '10.14.2.45',
    mac: '2C:F0:5D:81:44:A2',
    user: 'analis_intel',
    openPorts: [135, 139, 445, 3389, 4444],
    checks: [
      {
        id: 'ci1',
        parameter: 'Backdoor Port 4444 Listener',
        category: 'Network & Port',
        cis_id: 'DISA STIG NET-002',
        status: 'FAIL',
        details: 'CRITICAL! Terdeteksi port 4444 (Metasploit default listener) aktif melayani koneksi C2 luar!',
        mitigation: 'Hentikan proses yang mendengarkan port 4444 dan putuskan sambungan C2.'
      },
      {
        id: 'ci2',
        parameter: 'RDP 3389 Tanpa NLA',
        category: 'Network & Port',
        cis_id: 'DISA STIG WN11-00-000045',
        status: 'FAIL',
        details: 'Remote Desktop terbuka tanpa batasan IP whitelist & tanpa NLA enforcement.',
        mitigation: 'Wajibkan Network Level Authentication (NLA) pada Remote Desktop.'
      },
      {
        id: 'ci3',
        parameter: 'Windows Guest Account',
        category: 'Access Control',
        cis_id: 'DISA STIG WN11-00-000010',
        status: 'FAIL',
        details: 'Akun bawaan Guest dalam status aktif, memungkinkan bypass otentikasi AD.',
        mitigation: 'Jalankan Disable-LocalUser -Name Guest di PowerShell.'
      },
      {
        id: 'ci4',
        parameter: 'USB Storage Device Lock',
        category: 'Endpoint Protection',
        cis_id: 'DISA STIG WN11-CC-000180',
        status: 'WARNING',
        details: 'GPO Removable Storage Access belum diterapkan ke OU workstation intelijen.',
        mitigation: 'Set nilai registry USBSTOR Start ke 4 (Disabled).'
      },
      {
        id: 'ci5',
        parameter: 'Windows Event Security Auditing',
        category: 'System Logging',
        cis_id: 'DISA STIG WN11-AU-000050',
        status: 'PASS',
        details: 'Audit Logon Events & Object Access aktif terhubung ke SIEM militer.',
        mitigation: 'Konfigurasi telah optimal sesuai baseline STIG.'
      },
      {
        id: 'ci6',
        parameter: 'BitLocker Drive Encryption (C:)',
        category: 'Cryptographic Posture',
        cis_id: 'DISA STIG WN11-00-000025',
        status: 'FAIL',
        details: 'Volume C: intelijen belum terenkripsi BitLocker; data foto satelit dan analisis rentan diekstraksi.',
        mitigation: 'Jalankan Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256.'
      },
      {
        id: 'ci7',
        parameter: 'UEFI Secure Boot & Driver Enforcement',
        category: 'Kernel & Boot',
        cis_id: 'DISA STIG WN11-00-000005',
        status: 'FAIL',
        details: 'Driver Signing Enforcement dalam mode testsigning=yes; rawan inject kernel driver jahat.',
        mitigation: 'Jalankan bcdedit /set testsigning off dan bcdedit /set nointegritychecks off.'
      },
      {
        id: 'ci8',
        parameter: 'Local Administrators Group Policy',
        category: 'Privilege Boundary',
        cis_id: 'DISA STIG WN11-00-000015',
        status: 'WARNING',
        details: 'Ditemukan 3 akun non-standar terdaftar di grup Administrators lokal.',
        mitigation: 'Audit keanggotaan grup dan hapus akun user biasa dari Administrators.'
      }
    ],
    isQuarantined: false,
    history: [
      { timestamp: '2026-10-27 10:00', score: 70, passCount: 5, warnCount: 2, failCount: 1, event: 'Inspeksi Awal Sat Intel' },
      { timestamp: '2026-10-28 16:20', score: 55, passCount: 4, warnCount: 2, failCount: 2, event: 'Instalasi Software Analisis' },
      { timestamp: '2026-10-29 11:45', score: 38, passCount: 2, warnCount: 2, failCount: 4, event: 'Drift & Backdoor 4444 Terdeteksi' }
    ]
  },
  {
    id: 'PC-STAF-OPS-02',
    name: 'PC-STAF-OPS-02',
    hostname: 'pc-ops-puskodal-02.tni.mil.id',
    role: 'Workstation Puskodal / Komando Pengendalian',
    os: 'Windows 10 Enterprise LTSC',
    platformType: 'windows',
    ip: '10.14.2.66',
    mac: 'B4:2E:99:31:7E:10',
    user: 'ops_officer',
    openPorts: [135, 443],
    checks: [
      {
        id: 'co1',
        parameter: 'Dangerous Ports Exposure',
        category: 'Network & Port',
        cis_id: 'DISA STIG NET-001',
        status: 'PASS',
        details: 'Port berisiko (SMB, RDP, Telnet, Backdoor) terisolasi sempurna.',
        mitigation: 'Konfigurasi jaringan memenuhi standar pertahanan.'
      },
      {
        id: 'co2',
        parameter: 'Windows Defender Firewall',
        category: 'Endpoint Protection',
        cis_id: 'DISA STIG WN10-00-000015',
        status: 'PASS',
        details: 'Firewall Domain, Private, dan Public aktif memblokir unsolicited traffic.',
        mitigation: 'Firewall beroperasi normal.'
      },
      {
        id: 'co3',
        parameter: 'Local Administrator & Guest Policy',
        category: 'Access Control',
        cis_id: 'DISA STIG WN10-00-000020',
        status: 'PASS',
        details: 'Guest dinonaktifkan, LAPS aktif mengelola password lokal administrator.',
        mitigation: 'Akses kredensial terlindungi dengan baik.'
      },
      {
        id: 'co4',
        parameter: 'Removable USB Storage Restriction',
        category: 'Endpoint Protection',
        cis_id: 'DISA STIG WN10-CC-000180',
        status: 'PASS',
        details: 'Hardware ID USB storage dibatasi via registry GPO.',
        mitigation: 'Perlindungan terhadap exfiltrasi data aktif.'
      },
      {
        id: 'co5',
        parameter: 'Security Auditing Policy',
        category: 'System Logging',
        cis_id: 'DISA STIG WN10-AU-000050',
        status: 'WARNING',
        details: 'Audit Process Creation belum mencakup logging Command Line parameters.',
        mitigation: 'Aktifkan Include command line in process creation events via GPO.'
      }
    ]
  },
  {
    id: 'GW-RADIO-TAKTIS-OT',
    name: 'GW-RADIO-TAKTIS-OT',
    hostname: 'gw-hf-vhf-taktis.ot-net.local',
    role: 'Gateway Komunikasi Radio Taktis & BMS (OT)',
    os: 'Embedded OpenWrt / Linux 5.15 (arm64)',
    platformType: 'embedded',
    ip: '192.168.88.1',
    mac: 'E4:5F:01:D3:88:99',
    user: 'root_operator',
    openPorts: [21, 23, 80, 502],
    checks: [
      {
        id: 'cg1',
        parameter: 'Telnet Protocol Unencrypted (Port 23)',
        category: 'Network & Port',
        cis_id: 'ISA/IEC 62443-3-3 SR 3.1',
        status: 'FAIL',
        details: 'Layanan Telnet aktif mengirim kredensial komando dalam format plaintext tanpa enkripsi TLS/SSH.',
        mitigation: 'Matikan telnetd dan gantikan dengan SSHv2 kriptografi Ed25519.'
      },
      {
        id: 'cg2',
        parameter: 'FTP Service Plaintext (Port 21)',
        category: 'Network & Port',
        cis_id: 'ISA/IEC 62443-4-2 CR 3.1',
        status: 'FAIL',
        details: 'Daemon vsftpd aktif dengan izin anonymous download firmware konfigurasi radio taktis.',
        mitigation: 'Hentikan layanan FTP plaintext; gunakan SCP/SFTP terenkripsi.'
      },
      {
        id: 'cg3',
        parameter: 'Default Gateway Passwords',
        category: 'Access Control',
        cis_id: 'ISA/IEC 62443-4-2 CR 1.1',
        status: 'FAIL',
        details: 'Kata sandi root menggunakan kombinasi default pabrikan radio militer.',
        mitigation: 'Perbarui password root dengan entropi tinggi (minimal 16 karakter acak).'
      },
      {
        id: 'cg4',
        parameter: 'Host-Based IP Filtering',
        category: 'Endpoint Protection',
        cis_id: 'ISA/IEC 62443-3-3 SR 5.1',
        status: 'WARNING',
        details: 'Iptables aktif namun belum ada aturan drop pada broadcast domain radio.',
        mitigation: 'Terapkan strict ingress filter hanya dari segmen Puskodal.'
      },
      {
        id: 'cg5',
        parameter: 'Centralized Syslog OT',
        category: 'System Logging',
        cis_id: 'ISA/IEC 62443-4-2 CR 6.1',
        status: 'FAIL',
        details: 'Log disimpan lokal di RAM volatile, hilang seketika jika radio gateway direstart.',
        mitigation: 'Forward remote syslog ke SIEM server via TLS port 6514.'
      }
    ]
  },
  {
    id: 'SRV-LOGISTIK-KODIM',
    name: 'SRV-LOGISTIK-KODIM',
    hostname: 'srv-log-kodim.tni-ad.mil.id',
    role: 'Server Manajemen Materiel & Logistik Kodim',
    os: 'Debian GNU/Linux 12 (bookworm)',
    platformType: 'linux',
    ip: '10.14.5.20',
    mac: '52:54:00:8C:FA:33',
    user: 'kodim_admin',
    openPorts: [22, 443, 5432],
    checks: [
      {
        id: 'cl1',
        parameter: 'Network Port Hardening',
        category: 'Network & Port',
        cis_id: 'CIS 3.4.2',
        status: 'PASS',
        details: 'Port terbuka terbatas pada SSH (port diubah) dan HTTPS bersertifikat internal TNI.',
        mitigation: 'Port telah diisolasi sesuai pedoman CIS.'
      },
      {
        id: 'cl2',
        parameter: 'NFTables Local Firewall',
        category: 'Endpoint Protection',
        cis_id: 'CIS 3.5.3',
        status: 'PASS',
        details: 'NFTables firewall aktif memfilter koneksi berdasarkan whitelist IP Kodam.',
        mitigation: 'Aturan firewall aktif dan terkonfigurasi baik.'
      },
      {
        id: 'cl3',
        parameter: 'SSH Hardening & Key Authentication',
        category: 'Access Control',
        cis_id: 'CIS 5.2.1',
        status: 'PASS',
        details: 'PermitRootLogin NO, PasswordAuthentication NO (wajib Ed25519 Hardware Token).',
        mitigation: 'Akses SSH memenuhi standar pertahanan siber tertinggi.'
      },
      {
        id: 'cl4',
        parameter: 'USB Mass Storage Module',
        category: 'Endpoint Protection',
        cis_id: 'CIS 1.1.23',
        status: 'PASS',
        details: 'Modul usb-storage telah diblacklist di /etc/modprobe.d/storage.conf.',
        mitigation: 'Perlindungan exfiltrasi offline terpasang.'
      },
      {
        id: 'cl5',
        parameter: 'Auditd Daemon Security Rules',
        category: 'System Logging',
        cis_id: 'CIS 4.1.2',
        status: 'PASS',
        details: 'Auditd merekam setiap perubahan file izin /etc/passwd dan sudoers.',
        mitigation: 'Audit logging aktif dan terhubung ke log aggregator.'
      }
    ]
  }
];

export function calculateDeviceScore(checks: DeviceInfo['checks']): number {
  if (!checks || checks.length === 0) return 100;
  // Kontrol N/A tidak dihitung dalam penyebut (sama seperti scoring agent).
  const applicable = checks.filter(c => c.status !== 'N/A');
  if (applicable.length === 0) return 100;
  const pass = applicable.filter(c => c.status === 'PASS').length;
  const warn = applicable.filter(c => c.status === 'WARNING').length;
  return Math.round(((pass * 100) + (warn * 50)) / applicable.length);
}

export function calculateFleetScore(devices: DeviceInfo[]): number {
  if (!devices || devices.length === 0) return 100;
  const scores = devices.map(d => calculateDeviceScore(d.checks));
  return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
}
