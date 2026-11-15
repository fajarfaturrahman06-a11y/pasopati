<p align="center">
  <img src="public/pasopati-mark.png" alt="Logo PASOPATI" width="180" />
</p>

# PASOPATI v2.9.6
### Protokol Audit Sistem & Operasi Pengamanan Agen TI
### *Remediasi Taktis · Akurat · Aman*
**Kategori:** Keamanan Siber Pertahanan / Audit Sistem & Operasi Pengamanan Agen TI  
**Klasifikasi:** *Defense-Grade Compliance & Tactical Readiness Simulation (Prototipe Kompetisi)*  
**Sertifikasi & Acuan Standar:** CIS Benchmark v8.0, DISA STIG (U.S. DoD), & ISA/IEC 62443 (Keamanan Siber Industri & OT)

**Repositori:** <https://github.com/fajarfaturrahman06-a11y/pasopati> · **Versi ini:** `v2.9.6` (14 Nov 2026) · Riwayat perubahan: [`CHANGELOG.md`](CHANGELOG.md)

> Ringkasan rilis terbaru: login dashboard berbasis sesi + RBAC, registri endpoint
> terpusat, audit akses & kondisi endpoint (SQLite), serta perbaikan BitLocker
> tanpa TPM dan password boot numerik. Lihat [`CHANGELOG.md`](CHANGELOG.md) untuk rincian.

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
2. **Field Console Alternatif: `app.py` (Streamlit) — DEPRECATED**
   Mode demo luring berbasis data contoh/unggahan (tidak memanggil agent). Dipertahankan untuk
   presentasi tanpa server; logika remediasinya terpisah dan bisa menyimpang dari agent.
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
   - Plan yang menyentuh jalur akses (`ports-block-*`, `fw-enable-*`, `ssh-disable-root`) wajib di-approve
     dengan konfirmasi jalur konsol; agent juga menahan eksekusi bila sesi remote akan terputus
     (lanjutkan dengan `--force-access-risk` setelah menyiapkan konsol/KVM).
   - Parameter remediasi **diturunkan otomatis dari temuan hardening** pada perangkat yang sama; daftar item menampilkan CIS ID, detail temuan, dan target perbaikan.
   - Pilot WSL (6 Nov 2026): `--no-exec` 2 alias valid; eksekusi `auditd-enable` gagal verify → rollback → evidence `ROLLED_BACK`. Lihat `CATATAN-PENGEMBANGAN.md` §8.
8. **Dead-man Timer & Escrow Kunci BitLocker (anti-lockout):**
   - Setelah langkah enforce pertama, agent memasang watchdog di OS (proses session baru di Linux,
     Scheduled Task `SYSTEM` di Windows). Bila hasil tidak final dalam 10 menit, watchdog me-rollback
     seluruh snapshot plan tanpa perlu server/token.
   - Watchdog dibatalkan otomatis saat `VERIFIED`/`ROLLED_BACK`; atur dengan `--deadman-seconds` (`0` = mati).
   - Recovery key/password boot BitLocker di-escrow ke server (`/api/escrow`) **selain** file lokal 0600.
   - Rule iptables dipersistenkan (`netfilter-persistent` / `/etc/iptables/rules.v4`) agar bertahan setelah reboot.
9. **Antrean per host, heartbeat, dan resume:**
   - Hanya satu plan aktif per perangkat; approve kedua ditolak 409 (override `overrideQueue=true`).
   - Batas blast radius `REMEDIATION_MAX_ACTIVE` (default 10 plan aktif).
   - Heartbeat `EXECUTING` diperbarui tiap evidence; plan basi > `REMEDIATION_STALE_MS` boleh diambil alih.
   - `--resume` melanjutkan plan terputus tanpa mengulang langkah yang sudah terverifikasi (evidence lama dibawa agar cakupan tetap lengkap).
   - `DATA_DIR` dikunci `.server.lock` agar dua server tidak menulis file state yang sama.
11. **Profil kontrol, waiver, observability & integritas artefak:**
    - Baseline tambahan berada di `profiles/*.yaml` (64 kontrol Windows, 73 Linux) dengan ID CIS/STIG,
      tipe check aman, `na_if`, dan severity. Total parameter per host kini ±64–75.
    - `--profile standard|none` memilih paket; `GET /api/agent/manifest` menyediakan hash artefak
      (opsional ditandatangani `AGENT_SIGNING_KEY`), agent memverifikasi via `--verify-manifest`/`--strict-manifest`.
    - Air-gapped: `AI_DISABLED=1` mematikan AI cloud; seluruh audit/remediasi tetap lokal.
    - Waiver per temuan (`POST /api/waivers`) dengan alasan, pemilik, dan masa berlaku; temuan
      `WAIVED` dikeluarkan dari penyebut skor dan tidak muncul sebagai item remediasi.
    - `/api/health` (status, plan basi, host senyap, integritas rantai audit) dan `/api/metrics`
      (Prometheus) untuk monitoring.
    - Agent `--watch` menarik plan terikat milik host dari `/api/hosts/me/plans`; unit systemd
      dan contoh Task Scheduler ada di `deploy/`.
10. **Registri Endpoint Terpusat (bukan state browser):**
    - Inventaris endpoint tersimpan di server (`data/endpoints.json`) melalui API CRUD
      `/api/endpoints` dengan guard `revision` agar tab lama tidak menimpa perubahan yang lebih baru.
    - Endpoint hasil agent membawa `agentId` stabil; UI menandai sumber data (demo, lokal, atau server)
      supaya operator tahu apakah perubahan bertahan setelah browser ditutup.
    - Tulis/hapus dibatasi role `planner`/`admin`, baca untuk `viewer`, dan setiap penulisan ber-rate-limit.
11. **Audit Akses & Kondisi Endpoint (SQLite, terpisah dari Audit Log):**
    - Rekaman siapa yang mengakses endpoint dan snapshot kondisi komputer tersimpan di
      `data/endpoint_health_audit.sqlite` lewat API admin-only dan menu UI tersendiri.
    - Approval remediasi yang berhasil otomatis merekam approver, pengguna endpoint, dan kondisi saat persetujuan.
    - Data JSON versi lama diimpor satu kali dan file asalnya tetap disimpan sebagai cadangan;
      Audit Log lama (API, file, RBAC, hash chain, UI) tidak berubah.

---

## 🔑 3. Identitas, Peran (RBAC) & Transport

Tidak ada lagi satu kunci bersama untuk semua pihak. Modelnya:

- **Login dashboard:** akun username/password admin di-bootstrap dari `PASOPATI_ADMIN_USERNAME` dan `PASOPATI_ADMIN_PASSWORD` pada `.env` lokal. Password di-hash scrypt di `data/auth.sqlite`; browser hanya menerima cookie sesi `HttpOnly`, `SameSite=Lax` selama 12 jam.
- **Akun viewer dashboard:** admin membuat username/password melalui tombol **BUAT USER UJI**. Akun memiliki role `viewer`; semua izin tetap diperiksa di backend.
- **API key dan operator lama:** `PASOPATI_API_KEY` serta akun `POST /api/operators {name, role}` tetap tersedia untuk integrasi API/agen, bukan untuk login UI. Kunci operator ditampilkan **sekali** dan hanya hash SHA-256 yang disimpan. Role API: `viewer` (baca) · `planner` (buat plan) · `approver` (approve) · `executor` (eksekusi/evidence/quarantine).
- **Host** di-enrol: `POST /api/hosts/enroll {name}` → `hostId` + `hostKey`. Agent memakai header
  `X-Pasopati-Host-Key` (atau `--host-key` / `PASOPATI_HOST_KEY`). Plan bisa diikat ke `hostId`,
  dan host lain akan ditolak (403).
- **Pencabutan** per host/operator (`POST /api/hosts/:id/revoke`, `/api/operators/:name/revoke`) tanpa
  mengganggu yang lain.
- **Empat mata:** plan harus di-approve operator lain; bila approver = pembuat, kirim `selfApprove=true`.
  Identitas diambil server dari kunci (`/api/whoami`), bukan dari body.
- **Transport:** set `TLS_CERT` + `TLS_KEY` untuk HTTPS. Agent mendukung `--ca-cert <pem>` (pinning)
  dan `--insecure` untuk lab. Host key di atas `http://` masih terlihat di jaringan.
- **Rahasia server:** `PASOPATI_ADMIN_PASSWORD`, `GEMINI_API_KEY`, `HMAC_SECRET`, dan `PASOPATI_API_KEY` hanya berada di `.env` server; password akun serta token sesi hanya tersimpan dalam bentuk hash di SQLite. Kunci operator/host hanya disimpan sebagai hash SHA-256.

---

## 📊 4. Catatan Audit Log Lokal & Pengujian Offline

- Database audit lokal JSON server (`data/audit_logs.json`) menjadi penyimpanan persisten utama.
- **Integritas:** setiap entri menyimpan `seq` + `prevHash` + `hash` (hash chain SHA-256). `GET /api/audit-logs/verify` memeriksa rantai; suntingan di luar server terdeteksi (409).
- **Hapus = arsip:** `DELETE /api/audit-logs` bersifat soft delete (`deletedAt`), entri dan rantainya tetap utuh. Gunakan `?includeDeleted=1` untuk menampilkannya.
- **Status VERIFIED bukan klaim agent:** server menolak `VERIFIED` bila evidence tidak mencakup semua langkah, `stepIndex` duplikat, ada `exitCode != 0`, langkah enforce belum `verified`, atau **audit ulang pasca-remediasi** melaporkan parameter terkait masih `FAIL`.
- Agent mengirim `postAudit` (matriks + skor hasil audit ulang) hanya saat akan `VERIFIED`; hasilnya disimpan di plan (`postAuditAt`).
- Evidence kini membawa `preStateHash`; `at` diisi jam server, bukan klien.
- **Waiver:** temuan `WAIVED` tidak dihitung dalam skor (bukan PASS palsu), punya alasan/pemilik/expiry, dan otomatis kedaluwarsa.
- **Pengujian Lokal:** Database lokal persisten tersedia via API `http://localhost:3000/api/audit-logs`.
- **Mode Offline / Air-Gapped:** Semua fungsi audit, visualisasi, dan ekspor laporan (`.txt`, `.md`, `.json`) tetap berfungsi untuk demonstrasi dan laporan offline.
- **Bukti agent:** evidence remediasi ditandatangani HMAC-SHA256 (`X-Pasopati-Signature` + timestamp) dan setiap status terminal dicatat otomatis ke audit log server.

---

## 📥 5. Akses Unduhan Berkas & Catatan Pengujian (IDM)

Untuk mempermudah Dewan Juri melakukan review kode secara menyeluruh, seluruh berkas proyek dapat diunduh langsung:
- **Download Project (.ZIP):** Tombol 1-klik di Header / Tab Agent & Upload untuk mengunduh seluruh *source code* proyek. Yang dikecualikan: `.env*` (selain `.env.example`), `data/`, `.git/`, `dist/`, `node_modules/`, `opencode.json`, `reapprove.ps1`, `token.txt`, dan `bitlocker-recovery-*.txt`. Endpoint memerlukan sesi dashboard yang masih aktif.
- **Unduh Individual:** `pasopati_audit.py`, `pasopati_remediate.py`, `app.py`, `requirements.txt`, dan `README.md`.

> 💡 **Tips Pengujian untuk Pengguna Internet Download Manager (IDM):**  
> Sistem PASOPATI kini menggunakan *in-memory Blob stream* yang tidak diintersepsi oleh downloader pihak ketiga. Jika Anda menggunakan IDM dan masa trial IDM Anda telah berakhir, pastikan ekstensi IDM di browser dinonaktifkan sementara atau tekan dan tahan tombol **`ALT`** pada keyboard saat mengklik tombol unduh untuk mengizinkan browser mengunduh secara native.

---

## 🚀 6. Panduan Menjalankan Sistem

### A. Menjalankan Command Center Utama (React + Express)

```bash
# 1. Ambil source dan pasang dependensi
git clone https://github.com/fajarfaturrahman06-a11y/pasopati.git
cd pasopati
npm install

# 2. Siapkan environment lokal
cp .env.example .env
#    isi PASOPATI_ADMIN_USERNAME/PASOPATI_ADMIN_PASSWORD untuk login dashboard
#    (password minimal 12 karakter; akun dibuat sekali saat pemakaian pertama)
#    isi HMAC_SECRET & PASOPATI_API_KEY (min. 32 karakter acak) untuk integrasi agen
#    isi GEMINI_API_KEY/GEMINI_BASE_URL/AI_MODEL_NAME sesuai provider bila diperlukan

# 3. Jalankan server dev terpadu (Port 3000)
npm run dev

# Mode produksi (setelah build; CSP ketat + aset ter-cache):
npm run build && npm start
```

Buka browser di `http://localhost:3000`.

Pemeriksaan cepat sebelum demo: `npm run build` harus sukses dan `npm test` harus hijau.
Hanya satu server yang boleh memakai satu `DATA_DIR` (dikunci `.server.lock`); hentikan
proses lama dulu atau set `PASOPATI_DATA_DIR` berbeda bila perlu menjalankan dua instance.

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
5. Setujui rencana (`/api/remediation-approve`) - sertakan `acknowledgeConsole: true` bila plan menyentuh jalur akses dan `selfApprove: true` bila approver = pembuat; server menerbitkan token sekali pakai berisi nonce + signature.
6. Jalankan `pasopati_remediate.py` di host target (paling mudah: `--server` + `--plan-id`, target tidak perlu `plan.json`).
7. Script mengirim evidence ke `/api/remediation-verify`.
8. Status di dashboard berubah sesuai evidence: `VERIFIED`, `ROLLED_BACK`, atau `FAILED`.
9. Bila proses terputus sebelum status final, dead-man me-rollback host secara otomatis setelah 10 menit.

Contoh perintah di host target (cukup `pasopati_remediate.py` + `pasopati_audit.py`):

```powershell
# Uji aman tanpa mengubah host
python pasopati_remediate.py --server "http://<IP-SERVER>:3000" --plan-id "PLAN-..." `
  --remediate-api-key "<API_KEY>" --hmac-key "<HMAC_SECRET>" --no-exec

# Eksekusi nyata (UAC/root diminta otomatis; dead-man 600 dtk aktif)
python pasopati_remediate.py --server "http://<IP-SERVER>:3000" --plan-id "PLAN-..." `
  --remediate-api-key "<API_KEY>" --hmac-key "<HMAC_SECRET>" --force-access-risk

# Plan terputus (EXECUTING basi) dilanjutkan tanpa mengulang langkah terverifikasi
python pasopati_remediate.py --server "http://<IP-SERVER>:3000" --plan-id "PLAN-..." `
  --remediate-api-key "<API_KEY>" --hmac-key "<HMAC_SECRET>" --resume --force-access-risk
```

Untuk pemeriksaan saja, gunakan `pasopati_audit.py` — script itu tidak pernah mengeksekusi perbaikan.

### E. Verifikasi cepat (typecheck + smoke test kontrol plane)

```bash
npm test                      # seluruh uji (lint + smoke + auth + endpoint + expiry + agent + skrip + app.py + redaksi)
npm run lint                  # TypeScript typecheck + ESLint
npm run test:smoke            # server sementara: HMAC, anti-replay, allowlist, nonce, ZIP, scan-host
npm run test:auth             # login sesi, cookie HttpOnly, RBAC admin/viewer, logout
npm run test:endpoints        # registri endpoint: CRUD, guard revision, RBAC, rate limit
npm run test:endpoint-health-audit # audit akses/kondisi endpoint: RBAC, snapshot, isolasi Audit Log
npm run test:expiry           # token kedaluwarsa, re-approve, batas evidence
npm run test:agent            # unit handler agent + rollback nyata + SSH/UFW + kesesuaian allowlist
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
- Plan berisiko akses ditolak 409 di approve tanpa `acknowledgeConsole`; `VERIFIED` ditolak bila evidence tidak lengkap, `stepIndex` duplikat, `exitCode != 0`, atau langkah belum `verified`.
- Rantai audit valid terdeteksi; entri yang disunting di luar server membuat `/api/audit-logs/verify` menjawab 409; soft delete mempertahankan entri dan rantai.
- `VERIFIED` tanpa `postAudit` ditolak, dan ditolak lagi bila audit ulang masih `FAIL`.
- Antrean per host menolak plan kedua (409 + `blockingPlanId`) dan `overrideQueue` melewatinya.
- Escrow BitLocker tersimpan/terbaca; rantai audit tetap valid setelah soft delete.
- RBAC: `viewer` ditolak membuat plan (403); plan buatan sendiri ditolak sebelum `selfApprove`.
- Enrol host → plan terikat → host lain 403, host pemilik 200; setelah dicabut host 401 tanpa mengganggu host lain.
- Setiap alias enforce wajib punya `read`/`apply`/`verify`/`rollback`; alias advisory wajib `read`/`verify` (diuji otomatis).
- Plan campuran enforce + advisory bisa `VERIFIED` walau advisory `verified=false`.
- Agent & script mengelevasi diri tepat sekali (tanpa loop) dan `audit.json` mencatat `elevated`, metode, serta riwayat yang bertambah.
- Endpoint registry menolak tulisan dengan `revision` basi, dan `viewer` hanya bisa membaca.
- Audit akses/kondisi endpoint tetap terpisah: RBAC admin-only, snapshot tersimpan, dan Audit Log lama tidak berubah.

---

## 📚 7. Catatan Penelitian & Perubahan

- `CHANGELOG.md` — ringkasan perubahan per versi (v2.9.6 terbaru: password boot BitLocker numerik, audit akses endpoint).
- `CARA-MENJALANKAN.md` — prasyarat, setup `.env`, login admin vs viewer, dan batasan.
- `docs/ENDPOINT-HEALTH-AUDIT.md` — desain audit akses & kondisi endpoint (SQLite, RBAC, isolasi Audit Log).
- `docs/WINDOWS-TEST-PLAYBOOK.md` — langkah uji aman di laptop Windows (LAN, audit → plan `--no-exec` → eksekusi).
- `docs/AUDIT-2026-11-13.md` — hasil audit menyeluruh dan perbaikannya.
- `docs/AUDIT-2026-11-14.md` — pengerasan tahap 1: gate jalur akses, verifikasi server, rantai audit.
- `deploy/README.md` — menjalankan agent sebagai layanan (systemd / Task Scheduler) dengan `--watch`.
- `profiles/README.md` — skema paket profil kontrol deklaratif.
- `docs/WINDOWS-UJI-CEPAT.md` — uji end-to-end aman di laptop Windows (loopback/LAN).
- `docs/WINDOWS-UJI-LAN.md` - uji dari laptop lain dengan host key + isolasi host.
- `docs/UJI-BATCH.md` - uji lengkap per batch: **Windows (A–E)** dan **Linux (L1–L3)** dipisah.
- `docs/HASIL-UJI-WINDOWS-2026-11-13.md` — bukti uji lapangan di laptop Windows.
- `docs/RESEARCH-LOG-2026-11-12.md` — analisis bug, keputusan desain, bukti uji, dan **pekerjaan berikutnya** (wajib dibaca sebelum melanjutkan).
- `CHECKPOINT.md` — status pekerjaan & larangan keamanan.

## 🗂️ 8. Struktur Repositori

```
server.ts                  Kontrol plane Express (auth sesi, registry, remediasi, HMAC)
src/                       UI React 19 + Tailwind (komponen tab, store, util OPSEC)
src/data/mockDevices.ts    Fixture demo + fungsi skor (jangan di-ignore .gitignore)
pasopati_audit.py          Mesin audit + eksekusi remediasi (agent)
pasopati_remediate.py      Entry script perbaikan (memakai mesin yang sama)
app.py                     Field Console Streamlit (deprecated, demo luring)
profiles/                  Paket profil kontrol deklaratif (Windows/Linux)
deploy/                    Unit systemd & contoh Task Scheduler untuk --watch
tests/                     Smoke test kontrol plane, agent, auth, registry, audit endpoint
docs/                      Proposal, desain, playbook uji, laporan audit
data/                      State runtime (di-ignore; dibuat ulang saat start)
```

## 🧰 9. Troubleshooting: “Buat Plan / Approve tidak bisa”

1. **Isi kolom yang benar.** Di tab Hardening & Remediation ada dua kolom: (1) AI key opsional, (2) **PASOPATI_API_KEY wajib**. Plan/approve memakai kolom nomor 2.
2. Panel menampilkan status key. Bila “Key ditolak server (401/503)”, samakan dengan `PASOPATI_API_KEY` di `.env` server (tanpa spasi/newline).
3. **Restart server** setelah mengubah `.env` (`npm run dev`), lalu tekan “tes ulang”.
4. 503 = `PASOPATI_API_KEY` belum diset di environment. 401 = key salah.
5. Bila tombol tetap nonaktif: pastikan ada minimal satu langkah **AUTO** tercentang (advisory saja tidak cukup) dan server terjangkau.

## 🛡️ 10. Acuan Standar Keamanan


- **CIS Benchmark v8.0**: CIS Ubuntu Linux, CIS Debian, CIS Microsoft Windows 11.
- **DISA STIG**: U.S. Department of Defense Security Technical Implementation Guides.
- **ISA/IEC 62443**: International Security Standard for Operational Technology (OT) & Industrial Automation.
