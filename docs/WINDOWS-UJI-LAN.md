# Uji dari laptop lain (LAN)

Topologi: **laptop server** (mesin ini) + **laptop target** di Wi-Fi/LAN yang sama.
Target hanya memegang **host key** dan HMAC — bukan master API key.

> Jaringan di sini berprofil **Public** (Wi-Fi). Jangan jalankan Set 2 dari RDP tanpa
> konsol/KVM: `ports-block-windows` memblokir 3389.

## 1. Sisi server (Administrator)

```powershell
powershell -ExecutionPolicy Bypass -File .\docs\run-lan-server.ps1 -EnrollName LAPTOP-UJI-2 -Set 1
```

Skrip ini:
- menambah aturan firewall TCP 3000 **khusus LocalSubnet**,
- menampilkan alamat `http://<IP-LAN>:3000`,
- meng-enrol host → `hostId` + `hostKey`,
- membuat + menyetujui plan, lalu mencetak perintah siap-tempel untuk target.

Pastikan `npm run dev` sudah jalan di terminal lain. Catat `hostId`, `hostKey`, `planId`, HMAC.

## 2. Sisi target (PowerShell biasa)

```powershell
mkdir C:\PasopatiUji; cd C:\PasopatiUji
Invoke-WebRequest http://<IP-LAN>:3000/api/download/pasopati_audit.py -OutFile .\pasopati_audit.py
Invoke-WebRequest http://<IP-LAN>:3000/api/download/pasopati_remediate.py -OutFile .\pasopati_remediate.py
Invoke-WebRequest http://<IP-LAN>:3000/api/download/run-windows-test.ps1 -OutFile .\run-windows-test.ps1

# audit dulu (read-only)
python .\pasopati_audit.py -u "$env:COMPUTERNAME" -o .\audit.json --no-elevate
```

Unggah `audit.json` ke dashboard server (tab **Agent & Upload**) agar perangkat nyata
muncul. Lalu jalankan perintah yang dicetak skrip server:

```powershell
powershell -ExecutionPolicy Bypass -File .\run-windows-test.ps1 `
  -Server http://<IP-LAN>:3000 -Set 4 -PlanId "PLAN-..." `
  -HostId "HOST-..." -HostKey "<hostKey>" -Hmac "<HMAC>" -NoApprove
```

Tanpa master key, target tetap bisa: ambil plan (terikat host), dry-run, eksekusi,
mengirim evidence bertanda tangan, dan escrow kunci BitLocker.

## 3. Uji lengkap per batch

Linux dan Windows **dipisah**: satu plan hanya berisi alias satu OS (+ advisory
`any`). Panduan lengkap kedua OS ada di [`UJI-BATCH.md`](UJI-BATCH.md).

Daftar alias per OS:

```powershell
.\docs\run-lan-server.ps1 -ListAliases
```

### Windows (batch A–E, berurutan)

| Batch | Alias | Risiko |
|---|---|---|
| **A** | `guest-account-disable`, `usb-storage-block`, `win-auditpol-process`, `advisory-fde`, `advisory-rootkit`, `advisory-secureboot`, `advisory-admins` | aman |
| **B** | `rdp-nla-enable`, `uac-enable` | sedang |
| **C** | `fw-enable-defender` | sedang |
| **D** | `bitlocker-enable` | tinggi |
| **E** | `ports-block-windows` | **terakhir** |

```powershell
# A — enrol host sekali (Administrator)
.\docs\run-lan-server.ps1 -EnrollName LAPTOP-UJI-2 -Batch A
# B–E — pakai ulang host (PowerShell biasa)
.\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch B
.\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch C
.\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch D
.\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch E
```

Tiap perintah mencetak `planId` baru + perintah `run-windows-test.ps1 -Set 4 ...`.
Jalankan di target, lalu catat status akhirnya.

> `ports-block-windows` hanya memblokir port kritis yang **sedang listen**. Di Windows
> 10/11 rumahan biasanya hanya 445 (SMB). Tetap jalankan terakhir dari konsol fisik.

> `-Aliases` tetap tersedia untuk kombinasi bebas, dan menolak campuran Windows+Linux.

## 4. Setelah uji

Di server:
```powershell
# cabut kunci host target
Invoke-RestMethod -Method Post "http://127.0.0.1:3000/api/hosts/<HOST-ID>/revoke" -Headers @{'X-Pasopati-API-Key'='<KEY>'}
# hapus aturan firewall bila selesai
powershell -ExecutionPolicy Bypass -File .\docs\run-lan-server.ps1 -Remove
```

Di target: hapus folder `C:\PasopatiUji` dan `%USERPROFILE%\.pasopati`.

## 5. Keamanan jalur ini

- Kunci & HMAC **plaintext** di HTTP. Aman untuk lab/hotspot terkontrol, bukan untuk Wi-Fi publik bersama.
- Opsional TLS internal:
  ```powershell
  # di server, dengan openssl dari Git for Windows
  openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 30 -subj "/CN=pasopati.lan"
  ```
  set `TLS_CERT`/`TLS_KEY` di `.env`, restart, salin `server.crt` ke target, lalu jalankan
  agent dengan `--ca-cert server.crt`. `--insecure` hanya untuk lab.
- Jangan bagikan `PASOPATI_API_KEY` ke target; host key bisa dicabut per host.

## 6. Bila macet

| Gejala | Tindakan |
|---|---|
| Target tidak bisa membuka `/api/health` | Cek IP, subnet, aturan firewall, dan `npm run dev`. Uji `Test-NetConnection <IP> -Port 3000` dari target. |
| 401 | Host key salah/dicabut, atau HMAC beda |
| 403 "terikat ke host lain" | Plan milik host lain; buat plan dengan `hostId` yang benar |
| 409 jalur akses | Pakai `-NoApprove` + plan yang sudah di-approve dengan `acknowledgeConsole` |
| Token kedaluwarsa | Buat plan baru dengan `run-lan-server.ps1 -HostId ... -HostKey ...`; jangan approve ulang plan lama saat token masih hidup |
| `Alias ... hanya untuk OS linux` | Alias Linux dikirim ke host Windows; keluarkan dari batch |
| `python` tidak ada | Pakai `py -3`; skrip memilih otomatis |
