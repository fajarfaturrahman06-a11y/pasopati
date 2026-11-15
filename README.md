<p align="center">
  <img src="public/pasopati-mark.png" alt="Logo PASOPATI" width="180" />
</p>

# PASOPATI v2.9.6

**Protokol Audit Sistem & Operasi Pengamanan Agen TI**
_Remediasi Taktis · Akurat · Aman_

**Kategori:** Keamanan Siber Pertahanan / Audit Sistem & Operasi Pengamanan Agen TI
**Klasifikasi:** _Defense-Grade Compliance & Tactical Readiness Simulation (Prototipe Kompetisi)_
**Acuan:** CIS Benchmark v8.0, DISA STIG, ISA/IEC 62443

**Repositori:** <https://github.com/fajarfaturrahman06-a11y/pasopati> · **Riwayat:** [`CHANGELOG.md`](CHANGELOG.md)

> ⚠️ **DISCLAIMER:** PASOPATI adalah purwarupa penelitian independen, bukan sistem kedinasan resmi. Nama satuan dan data simulasi dipakai untuk demonstrasi.

---

## Daftar Isi

1. [Apa yang Dilakukan PASOPATI](#1-apa-yang-dilakukan-pasopati)
2. [Arsitektur Singkat](#2-arsitektur-singkat)
3. [Prasyarat](#3-prasyarat)
4. [Instalasi dan Konfigurasi](#4-instalasi-dan-konfigurasi)
5. [Menjalankan Server](#5-menjalankan-server)
6. [Login, Role, dan Akun Uji](#6-login-role-dan-akun-uji)
7. [Alur Lengkap: Audit → Hardening Terverifikasi](#7-alur-lengkap-audit--hardening-terverifikasi)
8. [Jalur Manual (tanpa agent)](#8-jalur-manual-tanpa-agent)
9. [Registri Endpoint Pusat](#9-registri-endpoint-pusat)
10. [Waiver, Karantina, Audit Trail](#10-waiver-karantina-audit-trail)
11. [Telemetri Agent (HMAC)](#11-telemetri-agent-hmac)
12. [Mode Demo vs Mode Server](#12-mode-demo-vs-mode-server)
13. [Ruang Lingkup Keamanan](#13-ruang-lingkup-keamanan)
14. [Troubleshooting](#14-troubleshooting)
15. [Deployment VPS Windows](#15-deployment-vps-windows)
16. [Backup, Restore, Rollback](#16-backup-restore-rollback)
17. [Pengujian](#17-pengujian)
18. [Struktur Repositori](#18-struktur-repositori)
19. [Dokumen Lanjutan](#19-dokumen-lanjutan)

---

## 1. Apa yang Dilakukan PASOPATI

PASOPATI adalah konsol audit kepatuhan dan remediasi terpandu:

- Mengaudit host terhadap baseline CIS/STIG/IEC 62443 (lewat agent CLI).
- Menyimpan inventaris endpoint di **satu registry server** sehingga semua browser melihat data yang sama.
- Menghasilkan runbook hardening + rollback yang terikat plan dan ber-hash.
- Menjalankan remediasi lewat **agent** (terverifikasi, dengan dead-man rollback) atau **manual** (fallback self-reported).
- Mencatat audit trail, waiver, karantina, dan activity log unduhan/scan untuk admin.

Yang **tidak** dilakukan server: PASOPATI tidak mengubah host dari jauh tanpa agent. Server hanya mengelola plan, token, dan bukti.

---

## 2. Arsitektur Singkat

```
Browser (React 19) ── cookie sesi ──> Express control plane (server.ts)
                                          │
                                          ├─ data/endpoint_inventory.json  (registry)
                                          ├─ data/audit_logs.json          (audit chain)
                                          ├─ data/remediation_plans.json   (plan)
                                          ├─ data/remediation_artifacts/   (runbook ber-hash)
                                          └─ SQLite (auth, waiver log, audit aktivitas)

Host target ── pasopati_audit.py / pasopati_remediate.py ── HMAC ──> /api/ingest & /api/remediation-verify
```

- `pasopati_audit.py` — mesin audit + telemetri (tidak mengubah host).
- `pasopati_remediate.py` — eksekutor plan yang disetujui (hanya mengubah host saat dijalankan).
- `app.py` — Field Console Streamlit (deprecated, demo luring).

---

## 3. Prasyarat

- Node.js 22+ dan npm 10+
- Python 3.10+ (agent di host target)
- Windows: PowerShell Administrator untuk langkah yang butuh elevasi
- Git (untuk klon) dan, untuk produksi, sertifikat TLS

**Hanya satu server per direktori data.** `.server.lock` menolak instance kedua.

---

## 4. Instalasi dan Konfigurasi

```bash
git clone https://github.com/fajarfaturrahman06-a11y/pasopati.git
cd pasopati
npm install
cp .env.example .env
```

Isi `.env` lokal (jangan commit, jangan bagikan):

| Variabel | Wajib | Keterangan |
|---|---|---|
| `PASOPATI_ADMIN_USERNAME` | ya | Akun bootstrap admin saat pertama dijalankan |
| `PASOPATI_ADMIN_PASSWORD` | ya | Minimal 12 karakter |
| `HMAC_SECRET` | ya untuk agent | Acak ≥32 karakter; menandatangani telemetri/evidence |
| `PASOPATI_API_KEY` | ya untuk agent | Acak ≥32 karakter; kredensial integrasi, bukan login UI |
| `PASOPATI_DATA_DIR` | produksi | **Wajib absolut**, mis. `C:\Apps\PASOPATI\data` |
| `PORT` | tidak | Default 3000 |
| `GEMINI_API_KEY` / `GEMINI_BASE_URL` / `AI_MODEL_NAME` | tidak | Tanpa ini AI memakai aturan lokal |
| `TLS_CERT` / `TLS_KEY` | produksi | Mengaktifkan HTTPS |

Buat nilai acak dengan `openssl rand -hex 32`. Akun admin hanya dibuat sekali; mengubah env setelahnya tidak mengganti akun tersimpan.

> Jangan menjalankan server dari `C:\Windows\System32`: `DATA_DIR` akan jatuh ke sana. Selalu set `Set-Location` ke folder proyek dan `PASOPATI_DATA_DIR` absolut.

---

## 5. Menjalankan Server

```bash
npm run dev      # pengembangan, http://localhost:3000
# atau
npm run build && npm start
```

Periksa log awal: harus muncul `[PASOPATI] DATA_DIR: ...` dan `server running at ...`. Buka `http://localhost:3000`.

Jika port dipakai proses lain: hentikan dulu, atau pakai `PORT` lain dan `PASOPATI_DATA_DIR` berbeda.

---

## 6. Login, Role, dan Akun Uji

Login memakai username/password; browser menerima cookie sesi `HttpOnly`, `SameSite=Lax`, 12 jam. Password disimpan sebagai hash scrypt; token sesi sebagai hash.

| Role | Boleh |
|---|---|
| `viewer` | Dashboard, Endpoint Audit, Agent & Upload; baca + tambah/ubah endpoint (hasil upload) |
| `planner` | Semua viewer + buat plan + waiver |
| `approver` | Approve plan, hapus waiver |
| `executor` | Kirim evidence, karantina, scan host |
| `admin` | Semua, termasuk hapus endpoint, kelola user, Audit Log & aktivitas |

**Membuat user uji:** login admin → sidebar **BUAT USER UJI** → tentukan username + password (≥12) → catat kredensial → keluar. Login sebagai user itu untuk mencoba pembatasan role.

---

## 7. Alur Lengkap: Audit → Hardening Terverifikasi

Bagian ini adalah alur yang dinilai. Ikuti berurutan.

### 7.1 Audit host target

1. Tab **Agent & Upload** → unduh **pasopati_audit.py** dan **pasopati_remediate.py** (dua file, satu folder).
2. Di host target, terminal Administrator/root:

```bash
python pasopati_audit.py -u "NAMA-UNIT" --push-url "http://<SERVER>:3000/api/ingest" --hmac-key "<HMAC_SECRET>"
```

Tanpa `--push-url`, hasil hanya tersimpan lokal di `audit.json` dan bisa diunggah lewat UI.

3. Hasil otomatis masuk registry pusat; audit ulang di dashboard.

### 7.2 Pilih temuan

1. **Endpoint Audit** → pilih perangkat → **Remediasi AI**.
2. **Langkah 1**: centang temuan. Wajib minimal satu langkah enforce; advisory boleh ikut.
3. **Langkah 2**: tinjau pratinjau hardening **dan terutama rollback**.

### 7.3 Buat dan setujui plan

1. **Langkah 3**: pilih mode **agent**.
2. Opsional ikat ke host ter-enrol.
3. Jika plan menyentuh SSH/firewall/RDP: siapkan konsol/KVM lalu centang konfirmasi.
4. **BUAT PLAN** → **APPROVE PLAN** (operator lain; jika Anda pembuatnya centang “setujui sendiri”).
5. Token tampil **sekali** dan berlaku 10 menit. Salin `plan.json`/perintah sekarang.
6. Jika host masih punya plan aktif, panel menampilkan plan penghalang: selesaikan/rollback, atau **APPROVE PAKSA**.

### 7.4 Jalankan di host

Isi **API key** dan **HMAC key** di panel agar perintah lengkap, salin, lalu di host target (PowerShell Administrator):

```powershell
python pasopati_remediate.py `
  --server "http://<SERVER>:3000" `
  --plan-id "PLAN-..." `
  --remediate-api-key "<PASOPATI_API_KEY>" `
  --hmac-key "<HMAC_SECRET>" `
  --no-exec
```

Periksa pre-state. Jika wajar, jalankan ulang **tanpa** `--no-exec`; tambahkan `--force-access-risk` bila plan menyentuh akses.

Dead-man aktif: bila hasil tidak terkonfirmasi dalam 10 menit, host di-rollback otomatis.

### 7.5 Verifikasi dan tampilan hardening

1. Agent mengirim evidence dan menjalankan audit ulang.
2. Kembali ke panel → **REFRESH**. Status berubah `VERIFIED`, badge **TERVERIFIKASI NYATA**, evidence menampilkan `verified: PASS`.
3. **Endpoint Audit** menampilkan temuan terkait berubah (mis. UAC/firewall PASS) dan skor naik.
4. Audit Log mencatat aksi `HARDENING REMEDIATION` beserta operator.

Status akhir yang mungkin: `VERIFIED`, `ROLLED_BACK`, `FAILED`, `MANUAL_REPORTED`.

---

## 8. Jalur Manual (tanpa agent)

Gunakan bila agent tidak bisa dipasang.

1. Langkah 1–2 sama; **Langkah 3** pilih mode **manual**.
2. **BUAT PLAN** → approve. Runbook resmi ber-hash tersedia di Langkah 2.
3. Unduh hardening + rollback resmi, jalankan di host (uji `--dry-run`/`-DryRun` dulu).
4. Centang semua langkah, klik **KIRIM LAPORAN MANUAL** → status `MANUAL_REPORTED`.
5. `VERIFIED` hanya setelah audit ulang dan pengiriman `postAudit` (lihat `docs/UJI-BATCH.md`).

Mode manual bersifat self-reported; badge kuning menandakan belum terverifikasi.

---

## 9. Registri Endpoint Pusat

- Sumber data: `PASOPATI_DATA_DIR/endpoint_inventory.json`.
- Semua browser memakai `GET /api/endpoints` dan polling 5 detik; tidak ada state browser sebagai sumber utama.
- Tambah/ubah: `POST`/`PUT`. Bila identitas sudah ada, `expected_revision` wajib (`428` jika kosong, `409` jika basi). Setiap perubahan menaikkan `revision`.
- Hapus = arsip lunak (admin).
- Identitas agent memakai UUID mesin (`metadata.machine_id`), bukan nama unit.
- Unduhan artefak dan scan realtime dicatat untuk admin di **Endpoint Audit → Aktivitas & Akses**.

Uji sinkronisasi dua browser: buka A dan B, tambah di A → B menampilkan ≤5 detik; ubah di B → 409 di A bila form lama; hapus di A → hilang di B.

---

## 10. Waiver, Karantina, Audit Trail

- **Waiver** (planner): temuan dikecualikan dari skor sampai kedaluwarsa. Waiver dikelola server dan tetap tampil setelah refresh.
- **Karantina** (executor): hanya menandai registry; pemutusan jaringan nyata tetap oleh agent/operator.
- **Audit Log** (admin): hash chain SHA-256, soft delete, verifikasi rantai; kegagalan tulis audit membatalkan operasi terkait.
- **Aktivitas & Akses** (admin): akses/kondisi endpoint, unduhan berkas, scan realtime.

---

## 11. Telemetri Agent (HMAC)

`POST /api/ingest` memverifikasi HMAC terhadap body mentah + timestamp (jendela 5 menit) dan anti-replay. Payload membawa `metadata.machine_id` (UUID persisten di `~/.pasopati/machine-id` atau `/var/lib/pasopati/machine-id`). Upsert menjaga satu endpoint per mesin; retry tidak menduplikasi history.

Jika audit gagal ditulis, endpoint dipulihkan dan ingest menjawab `500` agar registry dan audit tetap konsisten. Kirim ulang setelah masalah storage beres.

---

## 12. Mode Demo vs Mode Server

- Sebelum login: data mock, berlabel mode demo.
- Setelah login: registry server; mock tidak menimpa.
- Sesi kedaluwarsa: kembali ke layar login.
- Server tak terjangkau: data terakhir dipertahankan dan status **offline** ditampilkan.

---

## 13. Ruang Lingkup Keamanan

- Password scrypt; token sesi hash; cookie `HttpOnly`; write butuh Origin (CSRF).
- API key/HMAC hanya di `.env` server; UI tidak menyimpannya (kolom perintah hanya memori browser).
- Revisi mencegah lost update; plan butuh approve + token + nonce anti-replay.
- Semua tulis file state atomik (temp + fsync + rename retry).
- TLS wajib sebelum akses publik; tanpa TLS cookie/API key terbaca di jaringan.

---

## 14. Troubleshooting

| Gejala | Penyebab | Tindakan |
|---|---|---|
| `DATA_DIR sedang dipakai proses lain` | instance kedua | Hentikan proses lama; hapus `.server.lock` hanya setelah PID dipastikan mati |
| Halaman kosong | build/modul gagal | `npm run build`, cek console browser & log server |
| `401` di agent | API key salah/placeholder | Isi API key asli; jangan pakai `<...>` |
| `401 Nonce` | token kedaluwarsa/terpakai | Terbitkan ulang token di panel |
| `409` approve | plan aktif lain di host | Selesaikan/rollback, atau APPROVE PAKSA |
| Tombol APPROVE nonaktif | belum self-approve / konfirmasi konsol | Centang yang diminta |
| Artefak 404 | plan lama tanpa artefak | Buat plan baru |
| `413` | payload > 1 MB | Kecilkan matrix |
| Log UAC hilang | UAC dibatalkan/akun berbeda | Jalankan PowerShell sebagai Administrator |
| `EACCES` port | port dieksklusikan Windows | Pakai port lain |

---

## 15. Deployment VPS Windows

Ikuti `DEPLOYMENT-VPS-WINDOWS-SERVER-2022.md` secara penuh. Ringkas:

1. `deploy/check-vps-readonly.ps1` — periksa proses/port/task/DATA_DIR tanpa mengubah apa pun.
2. Supervisor yang ada (`C:\Apps\PASOPATI\start-pasopati.ps1`) wajib `Set-Location 'C:\Apps\PASOPATI'` dan `$env:PASOPATI_DATA_DIR='C:\Apps\PASOPATI\data'`; jangan buat supervisor/task kedua.
3. Backup `data` + `.env`, staging `npm ci && npm run lint && npm run build`.
4. Hentikan task, pastikan `node.exe` mati, salin rilis (kecualikan `data`, `.env`, `.server.lock`), start task yang sama.
5. Verifikasi 401 tanpa sesi, dua browser, lalu pasang HTTPS.

Struktur rilis ZIP ada di `server.ts` dan mengecualikan rahasia.

---

## 16. Backup, Restore, Rollback

```powershell
robocopy 'C:\Apps\PASOPATI\data' "C:\Backups\PASOPATI\$stamp\data" /E /COPY:DAT
icacls "C:\Backups\PASOPATI\$stamp" /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F'
```

Restore: hentikan task → salin balik `data` → start task. Jangan menyalin `data` dari staging.

Rollback rilis: pulihkan source dari backup, lalu data hanya bila perlu.

---

## 17. Pengujian

```bash
npm test
```

Mencakup lint/ESLint, smoke kontrol plane, auth, RBAC, registry, audit endpoint, expiry, runner Python, atomic write, agent, cakupan skrip, app.py, redaksi, elevasi.

---

## 18. Struktur Repositori

```
server.ts                  Kontrol plane Express
src/                       UI React + util (atomic write, OPSEC, store)
src/data/mockDevices.ts    Fixture demo + fungsi skor
pasopati_audit.py          Mesin audit + telemetri
pasopati_remediate.py      Eksekutor plan
app.py                     Field Console Streamlit (deprecated)
profiles/                  Profil kontrol deklaratif
deploy/                    Unit layanan, contoh supervisor, cek VPS
tests/                     Seluruh pengujian
docs/                      Proposal, desain, playbook
data/                      State runtime (di-ignore)
```

---

## 19. Dokumen Lanjutan

- `CARA-MENJALANKAN.md` — setup lokal & batasan.
- `docs/UJI-BATCH.md` — skenario uji Windows/Linux per batch.
- `docs/ENDPOINT-HEALTH-AUDIT.md` — desain audit akses/kondisi.
- `docs/AUDIT-2026-11-13.md`, `docs/AUDIT-2026-11-14.md` — hasil audit.
- `docs/WINDOWS-TEST-PLAYBOOK.md`, `docs/WINDOWS-UJI-LAN.md` — uji laptop/ LAN.
- `IMPLEMENTATION-REPORT.md`, `CHANGELOG.md`, `CHECKPOINT.md` — keputusan & riwayat.
