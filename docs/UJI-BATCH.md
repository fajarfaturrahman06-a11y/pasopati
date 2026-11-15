# Uji lengkap per batch — Linux dan Windows dipisah

Satu plan **hanya boleh berisi alias satu OS** (+ alias `any` yang berupa advisory).
Agent menolak alias OS lain, dan server kini menolak plan campuran sebelum host
di-enrol.

Daftar alias resmi (sumber tunggal: `ALLOWLIST_ANALISA` di agent):

```powershell
# Windows
python .\pasopati_audit.py --list-aliases
# atau dari skrip server
.\docs\run-lan-server.ps1 -ListAliases
```

| OS | Enforce | Advisory (`any`) |
|---|---|---|
| Windows | 8 alias | 4 alias |
| Linux | 8 alias | 4 alias |

---

## A. Windows (batch A–E)

| Batch | Alias | Risiko | Perkiraan hasil |
|---|---|---|---|
| **A** | `guest-account-disable`, `usb-storage-block`, `win-auditpol-process`, `advisory-fde`, `advisory-rootkit`, `advisory-secureboot`, `advisory-admins` | rendah | VERIFIED (USB aktif setelah reboot) |
| **B** | `rdp-nla-enable`, `uac-enable` | sedang | VERIFIED; UAC butuh reboot untuk efek penuh |
| **C** | `fw-enable-defender` | sedang | VERIFIED; sesi remote bisa terputus |
| **D** | `bitlocker-enable` | **tinggi** | sering FAILED di Windows Home; Pro tanpa TPM → boot password |
| **E** | `ports-block-windows` | **tinggi** | VERIFIED; blokir 445/3389/21/23/4444 yang listen |

### Server (batch A butuh Administrator; B–E PowerShell biasa)

```powershell
# A — enrol host sekali
.\docs\run-lan-server.ps1 -EnrollName LAPTOP-UJI-2 -Batch A
# B, C, D, E — pakai ulang host yang sama
.\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch B
.\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch C
.\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch D
.\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch E
```

### Target Windows (tiap batch)

```powershell
powershell -ExecutionPolicy Bypass -File .\run-windows-test.ps1 `
  -Server http://<IP-LAN>:3000 -Set 4 -PlanId "PLAN-..." `
  -HostId HOST-xxxx -HostKey <hostKey> -Hmac <HMAC> -NoApprove
```

Alur: manifest → plan → **dry-run** → `y` → UAC → eksekusi + dead-man.

---

## B. Linux (batch L1–L3)

| Batch | Alias | Risiko | Catatan |
|---|---|---|---|
| **L1** | `auditd-enable`, `grub-config-perms`, `sudoers-remove-nopasswd`, `advisory-fde`, `advisory-rootkit`, `advisory-secureboot`, `advisory-admins` | rendah | aman, tanpa jalur akses |
| **L2** | `usb-block-linux`, `suid-strip-critical` | sedang | `suid-strip-critical` bisa memengaruhi binary setuid |
| **L3** | `fw-enable-ufw`, `ssh-disable-root`, `ports-block-linux` | **tinggi** | **terakhir**; UFW deny incoming, port 22 tidak diblokir |

### Server

```powershell
.\docs\run-lan-server.ps1 -EnrollName SRV-LINUX -Batch L1
.\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch L2
.\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch L3
```

### Target Linux (tiap batch)

```bash
curl -fsS http://<IP-LAN>:3000/api/download/pasopati_audit.py -o pasopati_audit.py
curl -fsS http://<IP-LAN>:3000/api/download/pasopati_remediate.py -o pasopati_remediate.py

# dry-run (tanpa perubahan)
python3 pasopati_remediate.py --server http://<IP-LAN>:3000 --plan-id "PLAN-..." \
  --host-key <hostKey> --hmac-key <HMAC> --no-exec --no-elevate --force-access-risk

# eksekusi nyata
python3 pasopati_remediate.py --server http://<IP-LAN>:3000 --plan-id "PLAN-..." \
  --host-key <hostKey> --hmac-key <HMAC> --deadman-seconds 600 --force-access-risk
```

> Di Linux tidak ada `run-windows-test.ps1`; orkestrasi cukup dua perintah di atas.
> Server mencetak keduanya otomatis saat `-Batch L*` dipakai.

---

## Catatan bersama

- Token plan ~30 menit (tergantung `REMEDIATION_TOKEN_TTL_MS`). Kedaluwarsa →
  jalankan ulang skrip server dengan `-HostId/-HostKey` yang sama (plan baru).
- Jangan approve ulang plan lama saat tokennya masih hidup (server menolak).
- Tiap langkah: backup pre-state → apply → verifikasi. Satu langkah gagal →
  stop-on-failure → rollback langkah sebelumnya.
- `VERIFIED` hanya diterima bila semua langkah punya evidence, `exitCode 0`,
  `verified=true`, dan audit ulang bersih.
- BitLocker: recovery key + boot password disimpan di
  `%USERPROFILE%\.pasopati\backups\` dan di-escrow ke server. Salin keduanya.

## Mencatat hasil

| OS | Batch | Status akhir | Catatan |
|---|---|---|---|
| Windows | A | | |
| Windows | B | | |
| Windows | C | | |
| Windows | D | | recovery key / boot password? |
| Windows | E | | konsol masih hidup? |
| Linux | L1 | | |
| Linux | L2 | | |
| Linux | L3 | | sesi SSH masih hidup? |
