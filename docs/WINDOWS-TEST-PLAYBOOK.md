# Playbook Uji di Laptop Windows (LAN)

Tujuan: menguji **audit nyata** dan **remediasi terverifikasi** pada laptop uji Windows
dari Command Center yang berjalan di mesin server (WSL) — tanpa menyentuh mesin server.

> Urutan aman: **audit read-only → upload → plan `--no-exec` → eksekusi plan**. Jangan
> langsung mencentang BitLocker/RDP/port pada percobaan pertama.

---

## 0. Peran mesin

| Peran | Mesin | Yang dijalankan |
|---|---|---|
| Server | Mesin ber-WSL (repo di `D:\pasopati`) | `npm run dev`, `setup-lan.ps1` (PowerShell **Administrator**) |
| Target | Laptop uji Windows (satu LAN) | `pasopati_audit.py`, lalu `pasopati_remediate.py` |

Server mengikat `0.0.0.0:3000`. `setup-lan.ps1` membuat portproxy Windows→WSL +
rule firewall, sehingga laptop target mengakses **IP LAN Windows**, bukan IP WSL.

---

## 1. Prasyarat target (laptop uji)

1. Python 3.10+ dari python.org, centang **Add python.exe to PATH**.
   Verifikasi: `py -3 --version`.
2. PowerShell (biasa), koneksi ke LAN yang sama, jam tersinkron
   (`w32tm /resync` bila perlu — HMAC menolak selisih > 5 menit).
3. Tidak perlu `pip install`; agent hanya memakai stdlib.

## 2. Siapkan server (sekali)

Di mesin server:

```bash
cd /mnt/d/pasopati
grep -E '^(PASOPATI_API_KEY|HMAC_SECRET)=' .env   # pastikan terisi (64 karakter)
npm run dev
```

Lalu di **PowerShell Administrator** mesin server (bukan target):

```powershell
cd D:\pasopati
powershell -ExecutionPolicy Bypass -File .\setup-lan.ps1
ipconfig    # catat IPv4 LAN, mis. 192.168.1.20
```

Cek dari laptop target:

```powershell
Test-NetConnection 192.168.1.20 -Port 3000
curl.exe -s -o NUL -w "%{http_code}`n" http://192.168.1.20:3000/api/audit-logs
# 401 = server terjangkau dan auth aktif (benar)
```

Buka `http://192.168.1.20:3000` di browser laptop.

## 3. Ambil agent ke laptop

```powershell
mkdir $env:USERPROFILE\pasopati-uji
cd $env:USERPROFILE\pasopati-uji
curl.exe -O http://192.168.1.20:3000/api/download/pasopati_audit.py
curl.exe -O http://192.168.1.20:3000/api/download/pasopati_remediate.py
```

Kedua file **wajib** satu folder. Ganti `192.168.1.20` sesuai IP Anda.

## 4. Audit (read-only, tanpa UAC)

```powershell
cd $env:USERPROFILE\pasopati-uji
py -3 .\pasopati_audit.py -u "LAPTOP-UJI-WIN" --no-elevate -o audit.json -q
```

- Hasil: `audit.json` (mode 0600 di Linux; di Windows mengikuti ACL profil).
- Beberapa kontrol akan `WARNING` karena tanpa admin — itu wajar.
- Untuk hasil penuh, jalankan tanpa `--no-elevate` dan setujui UAC:

```powershell
py -3 .\pasopati_audit.py -u "LAPTOP-UJI-WIN" -o audit.json
```

## 5. Unggah hasil ke dashboard

1. Buka tab **Agent & Upload**.
2. Unggah `audit.json` dari laptop (salin lewat USB/Share, atau buka UI dari laptop
   dan unggah langsung).
3. Perangkat `LAPTOP-UJI-WIN` muncul; buka **Deep Audit** untuk memeriksa temuan.

Admin key tidak diperlukan untuk audit read-only.

## 6. Uji remediasi (mode aman dulu)

1. Buka **Hardening & Remediation** pada perangkat `LAPTOP-UJI-WIN`.
2. Isi kolom **PASOPATI_API_KEY** (dari `.env` server) dan **HMAC key** (`HMAC_SECRET`).
3. Pilih item yang aman untuk percobaan pertama:
   - `fw-enable-defender`
   - `guest-account-disable`
   - `win-auditpol-process`
   - (hindari dulu: `bitlocker-enable`, `rdp-nla-enable`, `ports-block-windows`)
4. (Opsional, disarankan) Enrol laptop sebagai host di server:
   ```powershell
   curl -X POST http://<server>:3000/api/hosts/enroll -H "X-Pasopati-API-Key: <API_KEY>" `
     -H "Content-Type: application/json" -d '{\"name\":\"LAPTOP-UJI-WIN\"}'
   ```
   Simpan `hostKey`; pakai `--host-key "<hostKey>"` di agent dan pilih host itu saat membuat plan.
5. **Buat Plan** → **Approve** (centang konfirmasi akses & self-approve bila perlu) → salin perintah yang muncul (berisi `--plan-id`).
6. Di laptop, jalankan **persis perintah itu** dengan tambahan `--no-exec` (sertakan `--host-key` bila host diikat):

```powershell
py -3 .\pasopati_remediate.py --server "http://192.168.1.20:3000" --plan-id "PLAN-..." `
  --remediate-api-key "<API_KEY>" --hmac-key "<HMAC_SECRET>" --host-key "<HOST_KEY>" --no-exec
```

`--no-exec` memvalidasi token, signature, dan menampilkan pre-state tanpa mengubah host.

7. Setelah yakin, jalankan ulang **tanpa** `--no-exec`. Script otomatis meminta UAC.
   Bila sesi ini RDP dan plan memblokir RDP, tambahkan `--force-access-risk` (setelah menyiapkan konsol).
   Dead-man otomatis aktif 600 detik; host rollback sendiri bila hasil tidak final.
8. Status plan berubah: `VERIFIED` / `ROLLED_BACK` / `FAILED`; evidence bertanda tangan
   HMAC terlihat di panel dan audit log. `VERIFIED` baru diterima bila audit ulang bersih.

> Bukti ber-status `TERVERIFIKASI NYATA` hanya muncul dari evidence agent, bukan simulasi.

> Dead-man: boleh diuji dengan `--deadman-seconds 60`. Batalkan manual dengan membuat file
> `%USERPROFILE%\.pasopati\backups\<PLAN_ID>.confirmed` bila perlu.

> Bila proses mati di tengah jalan, plan tetap `EXECUTING` dan heartbeat-nya basi. Lanjutkan
> dengan `--resume` (langkah yang sudah terverifikasi dilewati), atau minta operator approve ulang
> dengan `overrideQueue=true`.

## 7. Yang perlu diperiksa setelah eksekusi

```powershell
# Rule buatan tool (bila ports-block-windows dipakai)
Get-NetFirewallRule -DisplayName 'PASOPATI-Block-*' | Select DisplayName, Enabled

# Audit policy (bila win-auditpol-process)
auditpol /get /subcategory "Process Creation"

# Backup pre-state + recovery key BitLocker
dir $env:USERPROFILE\.pasopati\backups
```

- Bila ada `*bitlocker-recovery.txt`, **salin isinya** sebelum reboot.
- Rollback otomatis terjadi bila verifikasi gagal (stop-on-failure).
- Rollback manual: unduh skrip rollback dari panel runbook atau jalankan
  `pasopati_remediate.py --quarantine-release` untuk kill-switch jaringan.

## 8. Uji kill-switch (opsional, paling akhir)

```powershell
py -3 .\pasopati_remediate.py --quarantine            # blok inbound+outbound
py -3 .\pasopati_remediate.py --quarantine-release    # kembali normal
```

Catat: `blockoutbound` memutus koneksi baru ke server; gunakan console lokal.

## 9. Troubleshooting

| Gejala | Penyebab / solusi |
|---|---|
| 401 di UI/agent | API key salah. Samakan dengan `PASOPATI_API_KEY` di `.env`, tanpa spasi. |
| 503 | `PASOPATI_API_KEY`/`HMAC_SECRET` belum diset di server. |
| `Test-NetConnection` gagal | Portproxy/firewall belum dibuat, IP salah, atau beda subnet. Ulangi `setup-lan.ps1` sebagai Administrator. |
| `python` tidak dikenali | Pakai `py -3`, atau instal ulang Python dengan PATH. |
| 401 "Signature HMAC" / "kedaluwarsa" | `HMAC_SECRET` beda atau jam tidak sinkron; `w32tm /resync`. |
| UAC tidak muncul / script berhenti | Jalankan PowerShell sebagai Administrator, atau pakai `--no-elevate` untuk audit. |
| `ExecutionPolicy` memblokir `.ps1` | `powershell -ExecutionPolicy Bypass -File .\setup-lan.ps1`. |
| BitLocker lama | Enkripsi berjalan background; cek `manage-bde -status C:` dan simpan recovery key. |
| Koneksi RDP putus setelah `ports-block-windows` | Rule `PASOPATI-Block-3389` **memblokir RDP masuk** (bukan hanya sesi baru). Akses hanya pulih via konsol/KVM atau dengan menghapus rule dari sesi lokal. |

## 10. Bersih-bersih

```powershell
Remove-NetFirewallRule -DisplayName 'PASOPATI-Block-*' -ErrorAction SilentlyContinue
py -3 .\pasopati_remediate.py --quarantine-release
```

Di server: `Ctrl+C` pada `npm run dev`. Rule portproxy boleh dibiarkan untuk demo berikutnya.
