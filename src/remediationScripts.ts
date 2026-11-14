import { DeviceInfo } from './types';
import { buildRemediationItems, isRemediableCheck } from './remediationMapping';

export function buildRemediationScripts(currentDevice: DeviceInfo, isLinux: boolean, selectedAliases?: Set<string>): { hard: string; roll: string } {
  const allFindings = currentDevice.checks.filter(isRemediableCheck);
  const selected = selectedAliases ?? new Set(buildRemediationItems(currentDevice).map(i => i.alias));
  const include = (alias: string) => selected.has(alias);
  const isClean = allFindings.length === 0;
  const nowStr = new Date().toISOString();
    const ports = currentDevice.openPorts || [];
    const safeName = (currentDevice.name || '').replace(/[^A-Za-z0-9._-]/g, '_');
    const safeRole = (currentDevice.role || '').replace(/[^A-Za-z0-9._-]/g, '_');
    const safeOs = (currentDevice.os || '').replace(/[^A-Za-z0-9._-]/g, '_');
    const hay = (c: { parameter: string; details: string }) => (c.parameter + ' ' + c.details).toLowerCase();
    const handled = new Set<string>();
    // Tandai SEMUA temuan yang cocok agar tidak muncul lagi sebagai "belum dipetakan".
    const markAll = (re: RegExp) => {
      let found = false;
      for (const c of allFindings) {
        if (re.test(hay(c))) {
          handled.add(c.id);
          found = true;
        }
      }
      return found;
    };
    const oneLine = (v: string) => String(v || '').replace(/\s+/g, ' ').trim();
    // Daftar parameter remediasi yang diturunkan dari temuan hardening yang sama.
    const derivedItems = buildRemediationItems(currentDevice).filter(i => selected.has(i.alias));
    const derivedHeader = derivedItems.length
      ? derivedItems.map(i => `# - ${i.alias} <- ${oneLine(i.preState || '').slice(0, 150)}`)
      : ['# (tidak ada temuan yang bisa diremediasi otomatis oleh agent)'];

    if (isClean) {
      if (isLinux) {
        return {
          hard: `#!/bin/bash
# ==============================================================================
# PASOPATI HARDENING REPORT: ${safeName}
# Standard: CIS Benchmark / DISA STIG / ISA/IEC 62443
# Timestamp: ${nowStr}
# ==============================================================================
# [STATUS: AMAN 100%] Seluruh parameter CIS/STIG/ISA-62443 pada perangkat ini telah patuh.
# Tidak diperlukan eksekusi perintah tambahan.
echo "[+] Perangkat ${safeName} berada dalam status kepatuhan optimal (PASS 100%)."`,
          roll: `#!/bin/bash
# ==============================================================================
# PASOPATI ROLLBACK: ${safeName}
# ==============================================================================
# Tidak ada modifikasi yang perlu dipulihkan.
echo "[*] Baseline perangkat ${safeName} telah patuh standar pertahanan."`
        };
      } else {
        return {
          hard: `# ==============================================================================
# PASOPATI HARDENING REPORT: ${safeName}
# Standard: DISA STIG Windows Baseline
# Timestamp: ${nowStr}
# ==============================================================================
# [STATUS: AMAN 100%] Seluruh parameter CIS/STIG/ISA-62443 pada perangkat ini telah patuh.
# Tidak diperlukan eksekusi perintah tambahan.
Write-Host "[+] Perangkat ${safeName} berada dalam status kepatuhan optimal (PASS 100%)." -ForegroundColor Green`,
          roll: `# ==============================================================================
# PASOPATI ROLLBACK: ${safeName}
# ==============================================================================
# Tidak ada modifikasi yang perlu dipulihkan.
Write-Host "[*] Baseline perangkat ${safeName} telah patuh standar pertahanan." -ForegroundColor Cyan`
        };
      }
    }

    if (isLinux) {
      const hLines = [
        "#!/bin/bash",
        "# ==============================================================================",
        `# PASOPATI DETERMINISTIC & IDEMPOTENT HARDENING ENGINE v2.6`,
        `# Target Unit: ${safeName} | Role: ${safeRole}`,
        `# OS: ${safeOs} | Baseline: CIS Benchmark v8.0, DISA STIG, ISA/IEC 62443`,
        `# Standar: idempoten, auto-backup pre-state, auto rollback, dry-run`,
        `# Generated: ${nowStr}`,
        "# ==============================================================================",
        "set -u",
        "",
        "# [PRASYARAT] Wajib root. Elevasi otomatis (sudo/pkexec) agar semua kontrol berjalan.",
        "if [ \"${PASOPATI_ELEVATED:-0}\" != \"1\" ] && [ \"$(id -u)\" -ne 0 ]; then",
        "  export PASOPATI_ELEVATED=1",
        "  echo '[!] Butuh hak root. Menaikkan hak akses otomatis...' >&2",
        "  if command -v zenity >/dev/null 2>&1; then zenity --error --text='PASOPATI: butuh hak root. Lanjutkan dengan sudo.' 2>/dev/null || true; fi",
        "  if command -v notify-send >/dev/null 2>&1; then notify-send 'PASOPATI' 'Butuh hak root - memanggil sudo.' 2>/dev/null || true; fi",
        "  if command -v sudo >/dev/null 2>&1; then exec sudo -E bash \"$0\" \"$@\"; fi",
        "  if command -v pkexec >/dev/null 2>&1; then exec pkexec env PASOPATI_ELEVATED=1 bash \"$0\" \"$@\"; fi",
        "  echo '[!] sudo/pkexec tidak tersedia. Jalankan: sudo bash \"$0\"' >&2",
        "  exit 1",
        "fi",
        "",
        "DRY_RUN=false",
        "for arg in \"$@\"; do",
        "  if [ \"$arg\" = \"--dry-run\" ] || [ \"$arg\" = \"-n\" ]; then DRY_RUN=true; fi",
        "done",
        "if [ \"$DRY_RUN\" = true ]; then echo '[!] MODE DRY-RUN: evaluasi tanpa mengubah sistem.'; fi",
        "",
        "STATE_DIR=\"/var/lib/pasopati-guard/state\"",
        "if [ \"$DRY_RUN\" = false ]; then mkdir -p \"$STATE_DIR\"; fi",
        "say() { echo \"[*] $*\"; }",
        "run() { if [ \"$DRY_RUN\" = false ]; then \"$@\"; else echo \"    [DRY-RUN] $*\"; fi; }",
        "",
        `say "Memulai hardening terarah pada ${safeName}..."`,
        "",
        "# ------------------------------------------------------------------------------",
        "# PARAMETER REMEDIASI YANG DITURUNKAN DARI TEMUAN INI (dipakai tab Remediation)",
        ...derivedHeader,
        "# ------------------------------------------------------------------------------",
        ""
      ];

      const rLines = [
        "#!/bin/bash",
        "# ==============================================================================",
        `# PASOPATI DETERMINISTIC ROLLBACK ENGINE v2.6: ${safeName}`,
        `# Memulihkan pre-state yang disimpan di /var/lib/pasopati-guard/state`,
        `# Generated: ${nowStr}`,
        "# ==============================================================================",
        "set -u",
        "if [ \"${PASOPATI_ELEVATED:-0}\" != \"1\" ] && [ \"$(id -u)\" -ne 0 ]; then",
        "  export PASOPATI_ELEVATED=1",
        "  if command -v sudo >/dev/null 2>&1; then exec sudo -E bash \"$0\" \"$@\"; fi",
        "  if command -v pkexec >/dev/null 2>&1; then exec pkexec env PASOPATI_ELEVATED=1 bash \"$0\" \"$@\"; fi",
        "  echo '[!] Butuh root. Jalankan: sudo bash \"$0\"' >&2; exit 1",
        "fi",
        "STATE_DIR=\"/var/lib/pasopati-guard/state\"",
        `say() { echo "[*] $*"; }`,
        `say "Menjalankan rollback pada ${safeName}..."`,
        ""
      ];
      let step = 1;

      // ---- Port berbahaya: 4444 / 445 / 23 / 21 ----
      if (include('ports-block-linux')) {
        markAll(/dangerous port|network & dangerous/);
      }
      const dangerous: Array<{ port: number; label: string; cis: string }> = [
        { port: 4444, label: 'Backdoor C2 Port 4444', cis: 'CIS 3.4 / DISA STIG NET-002' },
        { port: 445, label: 'SMB Port 445', cis: 'CIS 3.4.1 / DISA STIG NET-001' },
        { port: 23, label: 'Telnet Plaintext Port 23', cis: 'ISA/IEC 62443-3-3 SR 3.1' },
        { port: 21, label: 'FTP Plaintext Port 21', cis: 'ISA/IEC 62443-4-2 CR 3.1' }
      ];
      for (const d of dangerous) {
        if (!include('ports-block-linux')) break;
        const foundInText = markAll(new RegExp(String(d.port)));
        if (!ports.includes(d.port) && !foundInText) continue;
        hLines.push(`# ${step}. Blokir ${d.label} (${d.cis})`);
        hLines.push(`say "Menutup ${d.label}..."`);
        hLines.push(`run iptables -C INPUT -p tcp --dport ${d.port} -j DROP 2>/dev/null || true`);
        hLines.push(`run iptables -A INPUT -p tcp --dport ${d.port} -j DROP 2>/dev/null || true`);
        if (d.port === 4444) {
          hLines.push("if [ \"$DRY_RUN\" = false ]; then fuser -k 4444/tcp 2>/dev/null || true; fi");
        }
        hLines.push("echo ''");
        rLines.push(`# ${step}. Buka blokir ${d.label}`);
        rLines.push(`iptables -D INPUT -p tcp --dport ${d.port} -j DROP 2>/dev/null || true`);
        rLines.push("echo ''");
        step++;
      }

      // ---- Firewall host ----
      if (include('fw-enable-ufw') && markAll(/firewall|ufw/)) {
        hLines.push(`# ${step}. Tegakkan firewall host (CIS 3.5.1)`);
        hLines.push("if command -v ufw >/dev/null 2>&1; then");
        hLines.push("  if [ \"$DRY_RUN\" = false ]; then ufw status 2>/dev/null | head -1 > \"$STATE_DIR/ufw.state\"; fi");
        hLines.push("  run ufw default deny incoming");
        hLines.push("  run ufw default allow outgoing");
        hLines.push("  # Wajib sebelum enable agar sesi SSH baru tidak terkunci.");
        hLines.push("  run ufw allow 22/tcp comment 'PASOPATI SSH baseline'");
        hLines.push("  run ufw allow from 10.14.0.0/16 to any port 22 proto tcp comment 'Whitelisted Tactical SSH'");
        hLines.push("  run ufw --force enable");
        hLines.push("else");
        hLines.push("  run iptables -A INPUT -i lo -j ACCEPT");
        hLines.push("  run iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
        hLines.push("  run iptables -A INPUT -p tcp --dport 22 -j ACCEPT");
        hLines.push("  run iptables -P INPUT DROP");
        hLines.push("fi");
        hLines.push("echo ''");
        rLines.push(`# ${step}. Pulihkan firewall host ke pre-state`);
        rLines.push("if [ -f \"$STATE_DIR/ufw.state\" ] && grep -qi inactive \"$STATE_DIR/ufw.state\"; then ufw --force disable 2>/dev/null || true; fi");
        rLines.push("iptables -P INPUT ACCEPT 2>/dev/null || true");
        rLines.push("echo ''");
        step++;
      }

      // ---- SSH root ----
      if (include('ssh-disable-root') && markAll(/permitrootlogin|ssh root|root login/)) {
        hLines.push(`# ${step}. Nonaktifkan root login SSH (CIS 5.2.10)`);
        hLines.push("DROPIN=/etc/ssh/sshd_config.d/99-pasopati-root-login.conf");
        hLines.push("MAIN=/etc/ssh/sshd_config");
        hLines.push("[ -f \"$MAIN\" ] || { say 'sshd_config tidak ditemukan'; }");
        hLines.push("if [ -d /etc/ssh/sshd_config.d ] && grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/' \"$MAIN\" && ! grep -qE '^[[:space:]]*PermitRootLogin' \"$MAIN\"; then");
        hLines.push("  # Include aktif dan main belum menetapkan nilai: pakai drop-in (first-match-wins dipertahankan).");
        hLines.push("  if [ \"$DRY_RUN\" = false ]; then");
        hLines.push("    [ -f \"$DROPIN\" ] && cp -a \"$DROPIN\" \"$STATE_DIR/sshd_dropin.pre\" || touch \"$STATE_DIR/sshd_dropin.absent\"");
        hLines.push("    echo 'PermitRootLogin no' > \"$DROPIN\"");
        hLines.push("  fi");
        hLines.push("else");
        hLines.push("  if [ \"$DRY_RUN\" = false ]; then cp -a \"$MAIN\" \"$STATE_DIR/sshd_config.pre\"; fi");
        hLines.push("  if [ \"$DRY_RUN\" = false ]; then");
        hLines.push("    sed -i -E 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin no/' \"$MAIN\"");
        hLines.push("    grep -qE '^PermitRootLogin no' \"$MAIN\" || echo 'PermitRootLogin no' >> \"$MAIN\"");
        hLines.push("  fi");
        hLines.push("fi");
        hLines.push("if [ \"$DRY_RUN\" = false ] && command -v sshd >/dev/null 2>&1 && ! sshd -t 2>/dev/null; then");
        hLines.push("  say 'sshd -t menolak konfigurasi — memulihkan snapshot.'");
        hLines.push("  [ -f \"$STATE_DIR/sshd_config.pre\" ] && cp -a \"$STATE_DIR/sshd_config.pre\" \"$MAIN\"");
        hLines.push("  [ -f \"$STATE_DIR/sshd_dropin.pre\" ] && cp -a \"$STATE_DIR/sshd_dropin.pre\" \"$DROPIN\"");
        hLines.push("  [ -f \"$STATE_DIR/sshd_dropin.absent\" ] && rm -f \"$DROPIN\"");
        hLines.push("  false");
        hLines.push("fi");
        hLines.push("if [ \"$DRY_RUN\" = false ]; then systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true; fi");
        hLines.push("echo ''");
        rLines.push(`# ${step}. Pulihkan sshd_config/drop-in dari snapshot`);
        rLines.push("[ -f \"$STATE_DIR/sshd_config.pre\" ] && cp -a \"$STATE_DIR/sshd_config.pre\" /etc/ssh/sshd_config");
        rLines.push("[ -f \"$STATE_DIR/sshd_dropin.pre\" ] && cp -a \"$STATE_DIR/sshd_dropin.pre\" /etc/ssh/sshd_config.d/99-pasopati-root-login.conf");
        rLines.push("[ -f \"$STATE_DIR/sshd_dropin.absent\" ] && rm -f /etc/ssh/sshd_config.d/99-pasopati-root-login.conf");
        rLines.push("systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true");
        rLines.push("echo ''");
        step++;
      }

      // ---- Sudoers NOPASSWD ----
      if (include('sudoers-remove-nopasswd') && markAll(/sudoers|nopasswd/)) {
        hLines.push(`# ${step}. Hapus NOPASSWD pada sudoers (CIS 5.3.4)`);
        hLines.push("FILES=\"/etc/sudoers\"; [ -d /etc/sudoers.d ] && FILES=\"$FILES $(find /etc/sudoers.d -maxdepth 1 -type f ! -name '*~' ! -name '*.bak' 2>/dev/null | tr '\\n' ' ')\"");
        hLines.push("for f in $FILES; do");
        hLines.push("  [ -f \"$f\" ] || continue");
        hLines.push("  if grep -q 'NOPASSWD:' \"$f\"; then");
        hLines.push("    if [ \"$DRY_RUN\" = false ]; then cp -a \"$f\" \"$STATE_DIR/sudoers$(echo \"$f\" | tr '/' '_').pre\"; sed -i 's/NOPASSWD://g' \"$f\"; fi");
        hLines.push("    say \"NOPASSWD dihapus dari $f\"");
        hLines.push("  fi");
        hLines.push("done");
        hLines.push("echo ''");
        rLines.push(`# ${step}. Pulihkan seluruh berkas sudoers dari snapshot`);
        rLines.push("for s in \"$STATE_DIR\"/sudoers*.pre; do");
        rLines.push("  [ -f \"$s\" ] || continue");
        rLines.push("  target=$(basename \"$s\" .pre | sed 's/^sudoers//; s/_/\\//g')");
        rLines.push("  [ -n \"$target\" ] && cp -a \"$s\" \"$target\"");
        rLines.push("done");
        rLines.push("echo ''");
        step++;
      }

      // ---- SUID ----
      if (include('suid-strip-critical') && markAll(/suid/)) {
        hLines.push(`# ${step}. Cabut bit SUID pada binari kritis (CIS 1.1.21)`);
        hLines.push("for b in /bin/bash /bin/sh /usr/bin/python3 /usr/bin/perl /bin/netcat /usr/bin/find; do");
        hLines.push("  [ -f \"$b\" ] || continue");
        hLines.push("  if [ -u \"$b\" ]; then");
        hLines.push("    if [ \"$DRY_RUN\" = false ]; then stat -c '%a %n' \"$b\" >> \"$STATE_DIR/suid.list\"; chmod u-s \"$b\"; fi");
        hLines.push("    say \"SUID dicabut: $b\"");
        hLines.push("  fi");
        hLines.push("done");
        hLines.push("echo ''");
        rLines.push(`# ${step}. Pulihkan bit SUID dari snapshot`);
        rLines.push("if [ -f \"$STATE_DIR/suid.list\" ]; then while read -r mode path; do chmod \"$mode\" \"$path\" 2>/dev/null || true; done < \"$STATE_DIR/suid.list\"; fi");
        rLines.push("echo ''");
        step++;
      }

      // ---- GRUB ----
      if (include('grub-config-perms') && markAll(/grub/)) {
        hLines.push(`# ${step}. Kunci izin grub.cfg (CIS 1.4.1)`);
        hLines.push("for g in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do");
        hLines.push("  if [ -f \"$g\" ]; then");
        hLines.push("    if [ \"$DRY_RUN\" = false ]; then stat -c '%a %n' \"$g\" >> \"$STATE_DIR/grub.list\"; chmod 600 \"$g\"; fi");
        hLines.push("    say \"izin grub dikunci: $g\"");
        hLines.push("  fi");
        hLines.push("done");
        hLines.push("echo ''");
        rLines.push(`# ${step}. Pulihkan izin grub dari snapshot`);
        rLines.push("if [ -f \"$STATE_DIR/grub.list\" ]; then while read -r mode path; do chmod \"$mode\" \"$path\" 2>/dev/null || true; done < \"$STATE_DIR/grub.list\"; fi");
        rLines.push("echo ''");
        step++;
      }

      // ---- USB storage ----
      if (include('usb-block-linux') && markAll(/usb/)) {
        hLines.push(`# ${step}. Blokir usb-storage (CIS 1.1.23)`);
        hLines.push("if [ -f /etc/modprobe.d/pasopati-usb-lock.conf ]; then");
        hLines.push("  say 'USB storage sudah diblokir (idempoten).'");
        hLines.push("else");
        hLines.push("  if [ \"$DRY_RUN\" = false ]; then");
        hLines.push("    printf 'install usb-storage /bin/true\\nblacklist usb-storage\\n' > /etc/modprobe.d/pasopati-usb-lock.conf");
        hLines.push("  fi");
        hLines.push("  say 'usb-storage diblokir via modprobe blacklist'");
        hLines.push("fi");
        hLines.push("echo ''");
        rLines.push(`# ${step}. Buka blokir USB storage`);
        rLines.push("rm -f /etc/modprobe.d/pasopati-usb-lock.conf");
        rLines.push("echo ''");
        step++;
      }

      // ---- auditd ----
      if (include('auditd-enable') && markAll(/auditd|audit daemon|syslog/)) {
        hLines.push(`# ${step}. Aktifkan auditd (CIS 4.1.1.1)`);
        hLines.push("if [ \"$DRY_RUN\" = false ]; then systemctl is-active auditd > \"$STATE_DIR/auditd.state\" 2>/dev/null || true; fi");
        hLines.push("run systemctl enable --now auditd");
        hLines.push("echo ''");
        rLines.push(`# ${step}. Pulihkan auditd jika sebelumnya mati`);
        rLines.push("if [ -f \"$STATE_DIR/auditd.state\" ] && ! grep -q '^active' \"$STATE_DIR/auditd.state\"; then systemctl disable --now auditd 2>/dev/null || true; fi");
        rLines.push("echo ''");
        step++;
      }

      // ---- LUKS (FDE) ----
      if (include('advisory-fde') && markAll(/luks|full disk encryption/)) {
        hLines.push(`# ${step}. Full Disk Encryption (LUKS) — kontrol yang butuh perencanaan`);
        hLines.push("if lsblk -f 2>/dev/null | grep -q crypto_LUKS; then");
        hLines.push("  say 'LUKS terdeteksi aktif.'");
        hLines.push("else");
        hLines.push("  say 'PERHATIAN: LUKS belum aktif. Enkripsi in-place tidak dilakukan otomatis oleh skrip ini.'");
        hLines.push("  echo '    Rekomendasi: backup data, lalu cryptsetup luksFormat + luksOpen pada partisi data (butuh reboot).'");
        hLines.push("fi");
        hLines.push("echo ''");
        rLines.push(`# ${step}. LUKS tidak mengubah apa pun saat rollback`);
        rLines.push("echo ''");
        step++;
      }

      // ---- Rootkit / kernel modules ----
      if (include('advisory-rootkit') && markAll(/rootkit|kernel module/)) {
        hLines.push(`# ${step}. Kernel module integrity / rootkit (advisory)`);
        hLines.push("echo '    Kernel module mencurigakan perlu ditinjau manual (lihat detail temuan).'");
        hLines.push("echo ''");
        rLines.push(`# ${step}. Kernel module tidak diubah`);
        rLines.push("echo ''");
      }

      hLines.push("# ==============================================================================");
      hLines.push("# TEMUAN YANG BELUM DIPETAKAN KE AKSI OTOMATIS (jangan diabaikan)");
      const remainingLinux = allFindings.filter(c => !handled.has(c.id));
      if (remainingLinux.length === 0) {
        hLines.push("# (tidak ada — semua temuan FAIL/WARNING sudah ditangani di atas)");
      } else {
        for (const c of remainingLinux) {
          hLines.push(`# [${c.status}] ${oneLine(c.parameter).slice(0, 160)}`);
          hLines.push(`#   detail : ${oneLine(c.details).slice(0, 240)}`);
          hLines.push(`#   saran  : ${oneLine(c.mitigation).slice(0, 240)}`);
        }
      }
      hLines.push("");
      hLines.push("echo '[SELESAI] Jalankan audit ulang (pasopati_audit.py) untuk memverifikasi hasil.'");
      rLines.push("echo '[RESTORED] Rollback selesai.'");
      return { hard: hLines.join('\n'), roll: rLines.join('\n') };
    }

    // ======================= WINDOWS (POWERSHELL) =======================
    const hLines = [
      "# ==============================================================================",
      `# PASOPATI DETERMINISTIC & IDEMPOTENT HARDENING (POWERSHELL v2.6): ${safeName}`,
      `# Target Role: ${oneLine(currentDevice.role).slice(0, 120)} | OS: ${oneLine(currentDevice.os).slice(0, 120)}`,
      `# Baseline: DISA STIG Windows Baseline | Standar: -DryRun, auto-backup, auto rollback`,
      `# Generated: ${nowStr}`,
      "# ==============================================================================",
      "# [PRASYARAT] Wajib Administrator; skrip akan meminta elevasi UAC.",
      "[CmdletBinding(SupportsShouldProcess=$true)]",
      "param ([switch]$DryRun, [switch]$Elevated)",
      "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {",
      "  $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File',\"`\"$PSCommandPath`\"\")",
      "  if ($DryRun) { $a += '-DryRun' }",
      "  $a += '-Elevated'",
      "  Start-Process powershell -Verb RunAs -ArgumentList ($a -join ' ')",
      "  exit 0",
      "}",
      "if ($DryRun) { Write-Host '[!] MODE DRY-RUN: tanpa perubahan.' -ForegroundColor Yellow }",
      "$StateDir = Join-Path $env:ProgramData 'PASOPATI\\state'",
      "if (-not $DryRun) { New-Item -ItemType Directory -Force -Path $StateDir | Out-Null }",
      "function Say($m) { Write-Host \"[*] $m\" -ForegroundColor Cyan }",
      `Say 'Memulai hardening pada ${safeName}...'`,
      "",
      "# ------------------------------------------------------------------------------",
      "# PARAMETER REMEDIASI YANG DITURUNKAN DARI TEMUAN INI (dipakai tab Remediation)",
      ...derivedHeader,
      "# ------------------------------------------------------------------------------",
      ""
    ];
    const rLines = [
      "# ==============================================================================",
      `# PASOPATI ROLLBACK (POWERSHELL): ${safeName}`,
      "# Memulihkan pre-state dari $env:ProgramData\\PASOPATI\\state",
      `# Generated: ${nowStr}`,
      "# ==============================================================================",
      "param ([switch]$Elevated)",
      "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {",
      "  Start-Process powershell -Verb RunAs -ArgumentList \"-NoProfile -ExecutionPolicy Bypass -File `\"$PSCommandPath`\" -Elevated\"",
      "  exit 0",
      "}",
      "$StateDir = Join-Path $env:ProgramData 'PASOPATI\\state'",
      "function Say($m) { Write-Host \"[*] $m\" -ForegroundColor Yellow }",
      `Say 'Memulihkan konfigurasi ${safeName}...'`,
      ""
    ];
    let step = 1;

    const portsWin: Array<{ port: number; label: string }> = [
      { port: 4444, label: 'Backdoor C2 Port 4444' },
      { port: 445, label: 'SMB Port 445' },
      { port: 23, label: 'Telnet Port 23' },
      { port: 21, label: 'FTP Port 21' }
    ];
    if (include('ports-block-windows')) markAll(/dangerous port|network & dangerous/);
    for (const d of portsWin) {
      if (!include('ports-block-windows')) break;
      const foundInText = markAll(new RegExp(String(d.port)));
      if (!ports.includes(d.port) && !foundInText) continue;
      hLines.push(`# ${step}. Blokir ${d.label} (firewall rule)`);
      hLines.push(`Say 'Menutup ${d.label}...'`);
      hLines.push(`if (-not (Get-NetFirewallRule -DisplayName 'PASOPATI-Block-${d.port}' -ErrorAction SilentlyContinue)) {`);
      hLines.push(`  if (-not $DryRun) { New-NetFirewallRule -DisplayName 'PASOPATI-Block-${d.port}' -Direction Inbound -LocalPort ${d.port} -Protocol TCP -Action Block | Out-Null }`);
      hLines.push("}");
      hLines.push("");
      rLines.push(`# ${step}. Hapus rule blokir ${d.label}`);
      rLines.push(`Remove-NetFirewallRule -DisplayName 'PASOPATI-Block-${d.port}' -ErrorAction SilentlyContinue`);
      rLines.push("");
      step++;
    }

    if (include('rdp-nla-enable') && markAll(/rdp|nla|3389/)) {
      const key = "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";
      hLines.push(`# ${step}. Terapkan NLA pada RDP (DISA STIG WN11-00-000045)`);
      hLines.push(`$v = (Get-ItemProperty -Path '${key}' -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication`);
      hLines.push("if ($v -ne 1) {");
      hLines.push(`  if (-not $DryRun) { $v | Out-File -Encoding ascii (Join-Path $StateDir 'rdp-nla.txt'); Set-ItemProperty -Path '${key}' -Name 'UserAuthentication' -Value 1 }`);
      hLines.push("  Say 'NLA diterapkan.'");
      hLines.push("} else { Say 'NLA sudah aktif (idempoten).' }");
      hLines.push("");
      rLines.push(`# ${step}. Pulihkan NLA`);
      rLines.push(`if (Test-Path (Join-Path $StateDir 'rdp-nla.txt')) { $old = Get-Content (Join-Path $StateDir 'rdp-nla.txt'); Set-ItemProperty -Path '${key}' -Name 'UserAuthentication' -Value ([int]$old) }`);
      rLines.push("");
      step++;
    }

    if (include('guest-account-disable') && markAll(/guest/)) {
      hLines.push(`# ${step}. Nonaktifkan akun Guest (DISA STIG WN11-00-000010)`);
      hLines.push("$g = (Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled");
      hLines.push("if ($g) { if (-not $DryRun) { $g | Out-File -Encoding ascii (Join-Path $StateDir 'guest.txt'); Disable-LocalUser -Name 'Guest' } Say 'Guest dinonaktifkan.' } else { Say 'Guest sudah nonaktif (idempoten).' }");
      hLines.push("");
      rLines.push(`# ${step}. Pulihkan status Guest`);
      rLines.push("if (Test-Path (Join-Path $StateDir 'guest.txt')) { Enable-LocalUser -Name 'Guest' }");
      rLines.push("");
      step++;
    }

    if (include('fw-enable-defender') && markAll(/firewall|defender/)) {
      hLines.push(`# ${step}. Aktifkan seluruh profil Windows Firewall (DISA STIG WN10-00-000015)`);
      hLines.push("$profiles = Get-NetFirewallProfile -Profile Domain,Public,Private");
      hLines.push("if (-not $DryRun) { ($profiles | ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }) | Out-File -Encoding ascii (Join-Path $StateDir 'fw.txt') }");
      hLines.push("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True");
      hLines.push("Say 'Firewall diaktifkan pada semua profil.'");
      hLines.push("");
      rLines.push(`# ${step}. Pulihkan status firewall dari snapshot`);
      rLines.push("if (Test-Path (Join-Path $StateDir 'fw.txt')) { Get-Content (Join-Path $StateDir 'fw.txt') | ForEach-Object { $p,$e = $_ -split '='; if ($e -eq 'False') { Set-NetFirewallProfile -Profile $p -Enabled False } } }");
      rLines.push("");
      step++;
    }

    if (include('usb-storage-block') && markAll(/usb/)) {
      const usbKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR";
      hLines.push(`# ${step}. Blokir USB Mass Storage (DISA STIG WN11-CC-000180)`);
      hLines.push(`$u = (Get-ItemProperty -Path '${usbKey}' -Name 'Start' -ErrorAction SilentlyContinue).Start`);
      hLines.push(`if (-not $DryRun) { $u | Out-File -Encoding ascii (Join-Path $StateDir 'usbstor.txt'); Set-ItemProperty -Path '${usbKey}' -Name 'Start' -Value 4 }`);
      hLines.push("Say 'USB storage diblokir (Start=4).'");
      hLines.push("");
      rLines.push(`# ${step}. Pulihkan nilai USBSTOR`);
      rLines.push(`if (Test-Path (Join-Path $StateDir 'usbstor.txt')) { $old = Get-Content (Join-Path $StateDir 'usbstor.txt'); Set-ItemProperty -Path '${usbKey}' -Name 'Start' -Value ([int]$old) } else { Set-ItemProperty -Path '${usbKey}' -Name 'Start' -Value 3 }`);
      rLines.push("");
      step++;
    }

    if (include('win-auditpol-process') && markAll(/event log|auditing/)) {
      hLines.push(`# ${step}. Aktifkan audit Process Creation (DISA STIG WN10-AU-000050)`);
      hLines.push("if (-not $DryRun) { auditpol /get /subcategory:\"Process Creation\" | Out-File -Encoding utf8 (Join-Path $StateDir 'auditpol.txt') }");
      hLines.push("auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:enable");
      hLines.push("Say 'Audit Process Creation diaktifkan.'");
      hLines.push("");
      rLines.push(`# ${step}. Pulihkan audit policy (Success/Failure) dari snapshot`);
      rLines.push("if (Test-Path (Join-Path $StateDir 'auditpol.txt')) { $s='disable'; $f='disable'; if (Select-String -Quiet -Pattern 'Success and Failure|Keberhasilan dan Kegagalan' (Join-Path $StateDir 'auditpol.txt')) { $s='enable'; $f='enable' } elseif (Select-String -Quiet -Pattern 'Success|Keberhasilan' (Join-Path $StateDir 'auditpol.txt')) { $s='enable' } elseif (Select-String -Quiet -Pattern 'Failure|Kegagalan' (Join-Path $StateDir 'auditpol.txt')) { $f='enable' }; auditpol /set /subcategory:\"Process Creation\" \"/success:$s\" \"/failure:$f\" }");
      rLines.push("");
      step++;
    }

    if (include('uac-enable') && markAll(/uac/)) {
      const uacKey = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
      hLines.push(`# ${step}. Aktifkan UAC (EnableLUA=1)`);
      hLines.push(`$lua = (Get-ItemProperty -Path '${uacKey}' -Name 'EnableLUA' -ErrorAction SilentlyContinue).EnableLUA`);
      hLines.push(`if ($lua -ne 1) { if (-not $DryRun) { $lua | Out-File -Encoding ascii (Join-Path $StateDir 'uac.txt'); Set-ItemProperty -Path '${uacKey}' -Name 'EnableLUA' -Value 1 } Say 'UAC diaktifkan (butuh reboot).' } else { Say 'UAC sudah aktif (idempoten).' }`);
      hLines.push("");
      rLines.push(`# ${step}. Pulihkan nilai UAC`);
      rLines.push(`if (Test-Path (Join-Path $StateDir 'uac.txt')) { $old = Get-Content (Join-Path $StateDir 'uac.txt'); Set-ItemProperty -Path '${uacKey}' -Name 'EnableLUA' -Value ([int]$old) }`);
      rLines.push("");
      step++;
    }

    if (include('bitlocker-enable') && markAll(/bitlocker/)) {
      hLines.push(`# ${step}. Aktifkan BitLocker C: (DISA STIG WN11-00-000025)`);
      hLines.push("$on = (manage-bde -status C: 2>$null) -match 'Protection On|Perlindungan Aktif'");
      hLines.push("if (-not $on) {");
      hLines.push("  if (-not $DryRun) { New-Item -ItemType File -Force (Join-Path $StateDir 'bitlocker.off') | Out-Null; manage-bde -protectors -add C: -RecoveryPassword | Out-Null; manage-bde -on C: -SkipHardwareTest }");
      hLines.push("  Say 'BitLocker diaktifkan (enkripsi berjalan di background).'");
      hLines.push("} else { Say 'BitLocker sudah aktif (idempoten).' }");
      hLines.push("");
      rLines.push(`# ${step}. Matikan BitLocker hanya bila sebelumnya mati`);
      rLines.push("if (Test-Path (Join-Path $StateDir 'bitlocker.off')) { manage-bde -off C: }");
      rLines.push("");
      step++;
    }

    if (include('advisory-secureboot') && markAll(/secure boot|driver/)) {
      hLines.push(`# ${step}. Secure Boot & driver signing (advisory)`);
      hLines.push("try { $sb = Confirm-SecureBootUEFI } catch { $sb = 'unknown' }");
      hLines.push("if ($sb -eq $false) { Say 'Secure Boot mati: aktifkan manual di UEFI/BIOS (butuh reboot).' } else { Say \"Secure Boot: $sb\" }");
      hLines.push("");
      rLines.push(`# ${step}. Secure Boot tidak diubah`);
      rLines.push("");
      step++;
    }

    if (include('advisory-admins') && markAll(/administrators group|administrator/)) {
      hLines.push(`# ${step}. Tinjau keanggotaan Administrators (advisory)`);
      hLines.push("Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { Say \"Admin: $($_.Name)\" }");
      hLines.push("");
      rLines.push(`# ${step}. Keanggotaan admin tidak diubah`);
      rLines.push("");
    }

    hLines.push("# ==============================================================================");
    hLines.push("# TEMUAN YANG BELUM DIPETAKAN KE AKSI OTOMATIS (jangan diabaikan)");
    const remainingWin = allFindings.filter(c => !handled.has(c.id));
    if (remainingWin.length === 0) {
      hLines.push("# (tidak ada — semua temuan FAIL/WARNING sudah ditangani di atas)");
    } else {
      for (const c of remainingWin) {
        hLines.push(`# [${c.status}] ${oneLine(c.parameter).slice(0, 160)}`);
        hLines.push(`#   detail : ${oneLine(c.details).slice(0, 240)}`);
        hLines.push(`#   saran  : ${oneLine(c.mitigation).slice(0, 240)}`);
      }
    }
    hLines.push("");
    hLines.push("Write-Host '[SELESAI] Jalankan audit ulang (pasopati_audit.py) untuk memverifikasi hasil.' -ForegroundColor Green");
    rLines.push("Write-Host '[RESTORED] Rollback selesai.' -ForegroundColor Cyan");
    return { hard: hLines.join('\n'), roll: rLines.join('\n') };
}
