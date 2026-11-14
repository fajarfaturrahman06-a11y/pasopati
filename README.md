<p align="center">
  <img src="public/pasopati-mark.png" alt="Logo PASOPATI" width="180" />
</p>

# PASOPATI v2.6.1
### Protokol Audit Sistem & Operasi Pengamanan Agen TI
### *Remediasi Taktis · Akurat · Aman*
**Kategori:** Keamanan Siber Pertahanan / Audit Sistem & Operasi Pengamanan Agen TI  
**Klasifikasi:** *Defense-Grade Compliance & Tactical Readiness Simulation (Prototipe Kompetisi)*  
**Sertifikasi & Acuan Standar:** CIS Benchmark v8.0, DISA STIG (U.S. DoD), & ISA/IEC 62443 (Keamanan Siber Industri & OT)

---

> ⚠️ **DISCLAIMER RESMI KOMPETISI:**  
> **PASOPATI** adalah purwarupa penelitian dan inovasi independen berbasis standar kepatuhan pertahanan siber internasional (CIS Benchmark v8.0, DISA STIG, dan ISA/IEC 62443). Purwarupa ini dirancang secara khusus untuk **dapat diadaptasi dan diintegrasikan oleh satuan pertahanan siber nasional / TNI AD**, dan **bukan merupakan sistem kedinasan resmi TNI AD**. Seluruh nama satuan dan data simulasi dalam platform ini digunakan untuk keperluan demonstrasi pengujian kepatuhan taktis.

---

## 🏛️ 1. Hierarki Produk: Produk Utama vs Field Console

Untuk mempermudah pengujian oleh Dewan Juri, repositori ini membagi sistem ke dalam lapisan yang saling melengkapi:

```
+--------------------------------------------------------------------------------------------------+
|            PASOPATI COMMAND CENTER (React UI + Express Kontrol Plane)                        |
|             React 19 · TypeScript · Tailwind CSS · Vite · Express                                 |
|   - Fleet & Endpoint Compliance Dashboard (data mock + upload JSON)                               |
|   - Assisted Remediation (Dry-Run, Auto-Backup, Dynamic Rollback Scripts)                        |
|   - Live Host Scan delegation (/api/scan-host → pasopati_audit.py) — memanggil agent sungguhan     |
|   - HMAC-SHA256 Telemetry Ingestion (/api/ingest)                                                |
|   - OPSEC Data Sanitizer (penyensoran IP/MAC/Host sebelum ke Gemini 2.5 Flash)                   |
|   - Persistent Audit Trail & Export Laporan (.md / .txt / .json)                                 |
+--------------------------------------------------------------------------------------------------+
                                       ▲
                                       │ (telemetri & evidence)
                                       │
+----------------------------------------------------+---------------------------------------------+
|  SCRIPT PEMERIKSAAN: pasopati_audit.py               |       FIELD CONSOLE ALTERNATIF: app.py      |
|  SCRIPT PERBAIKAN  : pasopati_remediate.py           |       Console Taktis Lapangan (Streamlit)   |
| - Audit Kernel, FDE (LUKS/BitLocker), SUID, Auditd | - Deploy cepat 1-file (opsional)            |
| - Deteksi WSL Cerdas (hindari false negative)      | - Tidak wajib untuk demo utama             |
| - HMAC-SHA256 Telemetry Ingestion ke Command Center|                                             |
+----------------------------------------------------+---------------------------------------------+
```

1. **Produk Utama (Primary Command Center): Web Platform (React + Express)**  
   Lapisan utama yang ditunjukkan kepada Dewan Juri. Termasuk dashboard kepatuhan, generator skrip perbaikan, alur remediasi berstate machine, dan kontrol plane untuk telemetri serta evidence.
2. **Field Console Alternatif: `app.py` (Streamlit)**  
   Opsi konsol lapangan berbasis Streamlit. Trek utama kompetisi tidak wajib menjalankannya; tersedia sebagai alternatif interaksi mandiri.
3. **Script Pemeriksaan & Perbaikan: `pasopati_audit.py` + `pasopati_remediate.py`**  
   `pasopati_audit.py` adalah mesin pemeriksaan (audit.json, telemetri). `pasopati_remediate.py` adalah script perbaikan yang memakai mesin yang sama dan mengeksekusi plan yang disetujui. Keduanya dipisah agar operator tidak salah menjalankan perbaikan saat berniat memeriksa. Untuk remediasi, salin **kedua** file ke host target.

### ⚠️ Klarifikasi performa demo vs fitur live
- Dashboard React dapat menunjukkan **audit simulasi, perubahan status, dan generator skrip** tanpa menjalankan apa pun di host sungguhan.
- Untuk **live host scan** atau **remediasi terverifikasi nyata**, sistem memerlukan server yang dijalankan dengan environment yang sesuai, kunci API/HMAC yang aktif, serta `pasopati_audit.py` (audit) dan `pasopati_remediate.py` (perbaikan) di host target.
- Label pada UI tetap jujur: hasil aproval/evidence berstatus **TERVERIFIKASI NYATA** hanya bila berasal dari agent; langkah advisory ditandai **PERLU MANUAL** dan tidak memblokir plan.

---

## 🌟 2. Fitur Inovasi & Nilai Tambah

1. **Assisted Remediation Engine (Bukan Blind Auto-Fix):**
   - Menghasilkan skrip perbaikan Bash (`.sh`) dan PowerShell (`.ps1`) yang **hanya** menargetkan celah berstatus `FAIL` atau `WARNING`.
   - Wajib menyertakan opsi *Dry-Run* (`--dry-run` / `-WhatIf`), *automatic backup* (`.bak`) sebelum manipulasi konfigurasi, dan skrip *Rollback* deterministik.
2. **OPSEC Data Sanitization:**
   - Parameter sensitif (IP militer, MAC address, hostname) otomatis disensor menjadi `[REDACTED_MIL_IP]` dan `[REDACTED_HOST]` sebelum dikirim ke Google Gemini 2.5 Flash.
3. **Deteksi Lingkungan Cerdas (WSL & Virtualization Aware):**
   - Pada `pasopati_audit.py`, sistem memeriksa `/proc/version` untuk mendeteksi apakah agent dijalankan di dalam WSL (Windows Subsystem for Linux).
   - Pada WSL, ketiadaan enkripsi partisi LUKS (karena virtual disk VHDX dikelola host Windows) dan daemon systemd auditd dilaporkan sebagai `WARNING` informatif, **bukan** `FAIL` palsu (*false negative*).
4. **Verifikasi Kriptografis HMAC-SHA256:**
   - Pengiriman telemetri dari agent ke backend `/api/ingest` diverifikasi menggunakan HMAC-SHA256 dengan *recursive key sorting* (`stableStringify`) yang 100% cocok dengan `json.dumps(sort_keys=True)` pada Python.
5. **Emergency Network Quarantine (Kill-Switch):**
   - Operator puskodal dapat **menandai** endpoint terinfeksi sebagai terisolasi di registry persisten. Server tidak memutus koneksi sendiri; pemblokiran firewall nyata dieksekusi oleh `pasopati_remediate.py` di host target.
6. **Audit Trail & Local Database Persistence:**
   - Setiap remediator dan perubahan status tercatat dalam log audit pada database lokal JSON server (`data/audit_logs.json`) dan didukung ekspor laporan offline.
7. **Satu Jalur: Change Set → Runbook → Eksekusi Terverifikasi (tab Hardening & Remediation):**
   - Server (`/api/remediation-plan` → `approve` → `verify`) + agent (`--remediate-plan`) dengan allowance token 10 menit.
   - **Tidak ada dua jalur terpisah lagi.** Setiap temuan FAIL/WARNING otomatis masuk ke satu *change set*:
     langkah **AUTO/enforce** (16 alias allowlist dari 20 total, dieksekusi & diverifikasi agent, punya rollback) dan
     langkah **ADVISORY** (`advisory-fde`, `advisory-rootkit`, `advisory-secureboot`, `advisory-admins`)
     untuk kontrol yang butuh keputusan/reboot (LUKS/Secure Boot) atau hanya perlu ditinjau.
   - Enforce: `ports-block-linux`, `ports-block-windows`, `fw-enable-defender`, `guest-account-disable`,
     `usb-storage-block`, `fw-enable-ufw`, `ssh-disable-root`, `auditd-enable`, `usb-block-linux`,
     `rdp-nla-enable`, `uac-enable`, `bitlocker-enable`, `grub-config-perms`,
     `sudoers-remove-nopasswd`, `suid-strip-critical`, `win-auditpol-process`.
   - Alur UI: **2a** pilih perubahan → **2b** runbook dihasilkan dari pilihan (hardening + rollback, dry-run) →
     **2c** approve (token 10 menit) → agent → evidence. Langkah advisory tidak memblokir plan dan dicatat di evidence.
   - Plan wajib punya minimal satu langkah enforce; advisory saja ditolak 400.
   - Parameter remediasi **diturunkan otomatis dari temuan hardening** pada perangkat yang sama; daftar item menampilkan CIS ID, detail temuan, dan target perbaikan.
   - Pilot WSL (6 Nov 2026): `--no-exec` 2 alias valid; eksekusi `auditd-enable` gagal verify → rollback → evidence `ROLLED_BACK`. Lihat `CATATAN-PENGEMBANGAN.md` §8.

---

## 🔑 3. Kebijakan Keamanan Kredensial & Kunci API

- **Backend Secrets (`.env`):**  
  `GEMINI_API_KEY`, `HMAC_SECRET`, dan `PASOPATI_API_KEY` tersimpan secara aman di sisi server (Node.js/Express) dan tidak pernah diekspos ke klien. Secret lama `TACTICAL_SECRET_2026` telah dipurge dari riwayat git (06 Nov 2026) dan dianggap bocor — jangan dipakai lagi.
- **Kunci di berkas lain:** `opencode.json` memuat API key provider (kini di-`.gitignore`), sedangkan `reapprove.ps1` masih memuat `PASOPATI_API_KEY` sebagai kemudahan demo. Rotasi dulu kunci tersebut bila repo dibagikan luas.
- **Catatan migrasi (arsip):** integrasi Google Sheets + Firebase Auth telah dihapus 06 Nov 2026. Audit log kini persisten lokal via API `http://localhost:3000/api/audit-logs` (`data/audit_logs.json`, dibuat otomatis saat POST pertama).

---

## 📊 4. Catatan Audit Log Lokal & Pengujian Offline

- Database audit lokal JSON server (`data/audit_logs.json`) menjadi penyimpanan persisten utama.
- **Pengujian Lokal:** Database lokal persisten tersedia via API `http://localhost:3000/api/audit-logs`.
- **Mode Offline / Air-Gapped:** Semua fungsi audit, visualisasi, dan ekspor laporan (`.txt`, `.md`, `.json`) tetap berfungsi untuk demonstrasi dan laporan offline.
- **Bukti agent:** evidence remediasi ditandatangani HMAC-SHA256 (`X-Pasopati-Signature` + timestamp) dan setiap status terminal dicatat otomatis ke audit log server.

---

## 📥 5. Akses Unduhan Berkas & Catatan Pengujian (IDM)

Untuk mempermudah Dewan Juri melakukan review kode secara menyeluruh, seluruh berkas proyek dapat diunduh langsung:
- **Download Project (.ZIP):** Tombol 1-klik di Header / Tab Agent & Upload untuk mengunduh seluruh *source code* proyek. Yang dikecualikan: `.env*` (selain `.env.example`), `data/`, `.git/`, `dist/`, `node_modules/`, `opencode.json`, `reapprove.ps1`, `token.txt`, dan `bitlocker-recovery-*.txt`. Endpoint ini memerlukan header `X-Pasopati-API-Key` yang valid; isi API key operasional pada UI terlebih dahulu.
- **Unduh Individual:** `pasopati_audit.py`, `pasopati_remediate.py`, `app.py`, `requirements.txt`, dan `README.md`.

> 💡 **Tips Pengujian untuk Pengguna Internet Download Manager (IDM):**  
> Sistem PASOPATI kini menggunakan *in-memory Blob stream* yang tidak diintersepsi oleh downloader pihak ketiga. Jika Anda menggunakan IDM dan masa trial IDM Anda telah berakhir, pastikan ekstensi IDM di browser dinonaktifkan sementara atau tekan dan tahan tombol **`ALT`** pada keyboard saat mengklik tombol unduh untuk mengizinkan browser mengunduh secara native.

---

## 🚀 6. Panduan Menjalankan Sistem

### A. Menjalankan Command Center Utama (React + Express)

```bash
# 1. Pasang dependensi
npm install

# 2. Siapkan environment (WAJIB: PASOPATI_API_KEY & HMAC_SECRET min. 32 karakter)
cp .env.example .env
#    lalu isi GEMINI_API_KEY/GEMINI_BASE_URL/AI_MODEL_NAME sesuai provider

# 3. Jalankan server dev terpadu (Port 3000)
npm run dev

# Mode produksi (setelah build; CSP ketat + aset ter-cache):
npm run build && npm start
```

Buka browser di `http://localhost:3000`.

> **Catatan demo:** Bila menjalankan Pengadilan tanpa server yang terkonfigurasi atau tanpa script PASOPATI di host target, tombol audit dan remediasi pada Command Center dapat berjalan dalam mode demonstrasi (simulasi status). Untuk hasil host sungguhan, ikuti alur di bagian panduan remediasi.

### B. Menjalankan Script Pemeriksaan di Laptop Juri / VM

Agent **meminta hak root/Administrator secara otomatis** (sudo/pkexec di Linux, UAC di Windows) karena audit maksimal butuh membaca `/etc/sudoers`, iptables, auditd, LUKS, registry, dan BitLocker. Gunakan `--no-elevate` untuk melewatinya.

```bash
# Mode Audit Standar Lokal → menghasilkan audit.json
python3 pasopati_audit.py -u "LAPTOP-EVALUATOR-JURI"

# Mode Telemetri Terpusat (Kirim Otomatis ke Command Center)
python3 pasopati_audit.py -u "LAPTOP-EVALUATOR-JURI" --push-url "http://localhost:3000/api/ingest"
```

- Output default: **`audit.json`** (bisa diubah dengan `-o`). File ditulis atomik.
- `audit.json` memuat matriks kerentanan **dan** blok `execution` berisi status elevasi, metode, serta **riwayat 100 run terakhir** (`/var/lib/pasopati/history.json` saat root, fallback `~/.pasopati/history.json`).
- Pada run berikutnya di komputer yang sama, agent mengelevasi diri lagi secara otomatis (tanpa perlu mengingat perintah `sudo`); bila cache sudo masih berlaku, tidak ada prompt.
- Script hardening/rollback hasil generator juga meminta root/Administrator sendiri, lalu menjalankan ulang dirinya dengan penanda anti-loop.
- Tanpa TTY (cron/CI/server), agent mencoba `sudo -n`; bila tidak ada cache sudo ia melanjutkan secara read-only dengan peringatan, bukan mati diam-diam.

### C. Menjalankan Field Console Alternatif (Streamlit)

```bash
pip install -r requirements.txt
export PASOPATI_DOWNLOAD_PASSWORD='<password-unduh-opsional>'
streamlit run app.py
```

### D. Demo Alur Remediasi Nyata (jika juri ingin melihat live evidence)

1. Jalankan server dengan `PASOPATI_API_KEY` dan `HMAC_SECRET` yang aktif di `.env`.
2. Login atau masuk ke Command Center.
3. Pilih perangkat di **Endpoint Audit** atau **Hardening & Remediation**.
4. Buat rencana per temuan (`/api/remediation-plan`).
5. Setujui rencana (`/api/remediation-approve`) — server akan menerbitkan token sekali pakai berisi nonce + signature.
6. Jalankan `pasopati_remediate.py` di host target (paling mudah: `--server` + `--plan-id`, target tidak perlu `plan.json`).
7. Script mengirim evidence ke `/api/remediation-verify`.
8. Status di dashboard berubah sesuai evidence: `VERIFIED`, `ROLLED_BACK`, atau `FAILED`.

Contoh perintah di host target (cukup `pasopati_remediate.py` + `pasopati_audit.py`):

```powershell
# Uji aman tanpa mengubah host
python pasopati_remediate.py --server "http://<IP-SERVER>:3000" --plan-id "PLAN-..." `
  --remediate-api-key "<API_KEY>" --hmac-key "<HMAC_SECRET>" --no-exec

# Eksekusi nyata (UAC/root diminta otomatis)
python pasopati_remediate.py --server "http://<IP-SERVER>:3000" --plan-id "PLAN-..." `
  --remediate-api-key "<API_KEY>" --hmac-key "<HMAC_SECRET>"
```

Untuk pemeriksaan saja, gunakan `pasopati_audit.py` — script itu tidak pernah mengeksekusi perbaikan.

### E. Verifikasi cepat (typecheck + smoke test kontrol plane)

```bash
npm test              # seluruh uji (lint + smoke + expiry + agent + skrip + app.py + redaksi)
npm run lint          # TypeScript typecheck + ESLint
npm run test:smoke    # server sementara: HMAC, anti-replay, allowlist, nonce, ZIP, scan-host
npm run test:expiry   # token kedaluwarsa, re-approve, batas evidence
npm run test:agent    # unit handler agent + rollback nyata + SSH/UFW + kesesuaian allowlist
npm run test:redaction # redaksi OPSEC (IPv4/IPv6/MAC/FQDN/hostname)
npm run test:scripts  # semua temuan agent tercakup di skrip + bash -n
npm run test:app      # generator runbook app.py + bash -n
npm run test:elevation # bukti nyata: audit & script mengelevasi diri, audit.json + riwayat
```

`test:smoke` benar-benar menjalankan `server.ts` pada port acak dengan folder data sementara, lalu memeriksa:
- `/api/ingest` menolak tanpa signature, signature salah, dan timestamp kedaluwarsa; menerima HMAC valid — termasuk body yang ditandatangani `pasopati_audit.py`.
- Token remediasi yang diterbitkan server diterima oleh `_validate_remediation_token` di agent Python, dan token yang diubah ditolak.
- `/api/remediation-plan` menolak alias di luar allowlist.
- `/api/remediation-verify` menolak nonce salah dan replay setelah status terminal.
- `GET /api/remediation-plans/:id` tidak mengembalikan `nonce`/`signature`, tetapi refresh UI mempertahankan nonce agar `plan.json` tetap valid.
- `/api/analyze-threats` tetap hidup untuk body cacat (`checks` bukan array / berisi null / key numerik).
- Evidence kosong ditolak untuk status terminal; alias duplikat di-dedupe; karantina tanpa `unitId` ditolak 400.
- Setiap alias enforce wajib punya `read`/`apply`/`verify`/`rollback`; alias advisory wajib `read`/`verify` (diuji otomatis).
- Plan campuran enforce + advisory bisa `VERIFIED` walau advisory `verified=false`.
- Agent & script mengelevasi diri tepat sekali (tanpa loop) dan `audit.json` mencatat `elevated`, metode, serta riwayat yang bertambah.

---

## 📚 7. Catatan Penelitian & Perubahan

- `docs/WINDOWS-TEST-PLAYBOOK.md` — langkah uji aman di laptop Windows (LAN, audit → plan `--no-exec` → eksekusi).
- `docs/AUDIT-2026-11-13.md` — hasil audit menyeluruh dan perbaikannya.
- `docs/HASIL-UJI-WINDOWS-2026-11-13.md` — bukti uji lapangan di laptop Windows.
- `docs/RESEARCH-LOG-2026-11-12.md` — analisis bug, keputusan desain, bukti uji, dan **pekerjaan berikutnya** (wajib dibaca sebelum melanjutkan).
- `CHANGELOG.md` — ringkasan perubahan per versi.
- `CHECKPOINT.md` — status pekerjaan & larangan keamanan.

## 🧰 8. Troubleshooting: “Buat Plan / Approve tidak bisa”

1. **Isi kolom yang benar.** Di tab Hardening & Remediation ada dua kolom: (1) AI key opsional, (2) **PASOPATI_API_KEY wajib**. Plan/approve memakai kolom nomor 2.
2. Panel menampilkan status key. Bila “Key ditolak server (401/503)”, samakan dengan `PASOPATI_API_KEY` di `.env` server (tanpa spasi/newline).
3. **Restart server** setelah mengubah `.env` (`npm run dev`), lalu tekan “tes ulang”.
4. 503 = `PASOPATI_API_KEY` belum diset di environment. 401 = key salah.
5. Bila tombol tetap nonaktif: pastikan ada minimal satu langkah **AUTO** tercentang (advisory saja tidak cukup) dan server terjangkau.

## 🛡️ 9. Acuan Standar Keamanan


- **CIS Benchmark v8.0**: CIS Ubuntu Linux, CIS Debian, CIS Microsoft Windows 11.
- **DISA STIG**: U.S. Department of Defense Security Technical Implementation Guides.
- **ISA/IEC 62443**: International Security Standard for Operational Technology (OT) & Industrial Automation.
