# PROPOSAL PROYEK TUGAS AKHIR / PROYEK KOMPETISI PASOPATI

**PASOPATI: Sistem Audit Kepatuhan dan Remediasi Agent Terverifikasi Berbasis CIS Benchmark, DISA STIG, dan ISA/IEC 62443**

*Framework Kesiapan Siber Endpoint untuk Infrastruktur Inti dan Perangkat Operasional Taktis*

---

## Identitas Proyek

1. **Judul Proyek/Alat:** PASOPATI — System Audit, Threat Remediation & Intelligence Architecture Guard
2. **Bidang/Kategori:** Keamanan Siber Pertahanan / Cybersecurity Defense / Endpoint Compliance & Tactical Readiness Systems
3. **Klasifikasi:** Defense-Grade Compliance & Tactical Readiness Simulation (Prototipe Kompetisi)
4. **Acuan Standar:** CIS Benchmark v8.0, DISA STIG (U.S. Department of Defense), ISA/IEC 62443 (Keamanan OT/ICS)
5. **Sifat:** Purwarupa penelitian dan inovasi independen. Purwarupa ini dirancang untuk dapat diadaptasi dan diintegrasikan oleh satuan pertahanan siber nasional, dan bukan merupakan sistem kedinasan resmi TNI AD. Seluruh nama satuan dan data simulasi digunakan untuk keperluan demonstrasi pengujian kepatuhan taktis.
6. **Kompetisi Terkait:** Kartika Cyber Hackathon 2026 (PUSSIBERAD × CODEPOLITAN), kategori Penangkalan/Dukungan (endpoint compliance & defense).

---

## BAB I: PENDAHULUAN

### 1.1 Latar Belakang

#### 1.1.1 Urgensi keamanan endpoint di era digitalisasi pertahanan

Digitalisasi satuan pertahanan dan infrastruktur kritis telah melahirkan ekosistem endpoint yang sangat heterogen: server basis data, workstation operator puskodal, gateway radio taktis, terminal OT (Operational Technology) dan BMS (Building Management System), serta perangkat edge Linux dan Windows di berbagai satuan. Heterogenitas ini membuat konfigurasi keamanan menjadi tugas yang rumit. Satu kesalahan kecil — misalnya port SMB 445 terbuka tanpa segmentasi, akun Guest aktif, root login SSH diizinkan, driver USB tanpa batas, enkripsi disk belum aktif, atau daemon audit mati — dapat menjadi pintu masuk lateral movement, penyusupan C2, atau eksfiltrasi data taktis. Praktik-praktik ini berlawanan dengan prinsip *least privilege*, *defense in depth*, dan *zero blank trust* yang diwajibkan oleh CIS Benchmark, DISA STIG, dan ISA/IEC 62443.

Audit keamanan konvensional yang mengandalkan checklist manual tidak dapat memenuhi kebutuhan skala: puluhan aset, ratusan parameter, dan kebutuhan pembuktian yang dapat diaudit ulang. Alat komersial yang ada seringkali bersifat berat, mahal, dan tidak transparan (kotak hitam) — evaluator tidak dapat membedakan hasil nyata dari simulasi. Di sisi lain, alat *auto-fix* yang langsung menjalankan perintah tanpa persetujuan eksplisit melanggar prinsip *fail-safe* dan dapat merusak layanan kritis bila salah konfigurasi.

#### 1.1.2 Permasalahan teater keamanan

Fenomena yang disebut "teater keamanan" adalah kondisi di mana dasbor menampilkan status "aman" atau skor tinggi, padahal host tidak berubah. Hal ini sangat berbahaya karena menciptakan rasa aman palsu (false sense of security). Penilaian kompetisi saat ini menunjukkan bahwa kelemahan terbesar bukan pada kegagalan teknis, melainkan pada risiko ketahuan berlebihan oleh juri saat tombol ditekan: skor naik, tetapi host tidak berubah.

PASOPATI dibangun untuk menutup celah ini. Prinsip utamanya adalah: **setiap klaim keberhasilan harus dapat dibuktikan dengan evidence yang dibaca ulang dari host nyata**, bukan dengan perubahan teks deskripsi. Label UI yang dibedakan secara eksplisit — hijau "TERVERIFIKASI NYATA" versus abu "SIMULASI" — adalah bagian dari desain anti-teater tersebut.

#### 1.1.3 Mengapa pendekatan agent + kontrol plane + approval dibutuhkan

Tiga prinsip keamanan tidak dapat ditawar (non-negotiable) dalam desain PASOPATI, mengadopsi rancangan arsitektur pada `docs/REAL-AGENT-REMEDIATION-DESIGN.md`:

1. **Default read-only** — agent tanpa approval hanya boleh membaca/mengaudit.
2. **Persetujuan eksplisit per-plan** — setiap perubahan harus disetujui operator dengan konteksnya (per-item).
3. **Allowlist, bukan raw command** — dasbor hanya memilih alias tindakan dari daftar terdaftar di agent; agent menerjemahkan alias menjadi perintah nyata. Dashboard tidak boleh mengirim string shell mentah ke host.
4. Empat prinsip pendukung: backup sebelum ubah, verifikasi sesudah ubah, rollback sebagai restore dari backup, dan *fail-safe* (kegagalan menghentikan alur).

Ketiga prinsip ini memastikan bahwa kedisiplinan keamanan ditegakkan oleh arsitektur, bukan sekadar himbauan.

### 1.2 Rumusan Masalah

Berdasarkan latar belakang di atas, penelitian/proyek ini menjawab lima pertanyaan penelitian berikut:

1. Bagaimana merancang agent audit (`pasopati_audit.py`) yang dapat memeriksa parameter CIS/STIG pada host Linux dan Windows secara read-only, deterministik, dan terukur — mencakup kernel & boot, enkripsi disk, batas privilege, firewall, kontrol akses, proteksi endpoint, dan logging — tanpa mengubah host?
2. Bagaimana menghindari pemalsuan telemetri melalui pengiriman telemetri bertanda tangan kriptografis HMAC-SHA256 dengan anti-replay (timestamp + nonce) dan canonical JSON yang konsisten antara Node.js dan Python?
3. Bagaimana remediasi nyata dapat dijalankan hanya oleh alias tindakan allowlist, dengan backup snapshot pra-perubahan, verifikasi baca-ulang, dan rollback dari snapshot — tanpa pernah mengizinkan raw shell dari luar?
4. Bagaimana antarmuka (UI) dapat membedakan secara eksplisit antara label "SIMULASI" dan "TERVERIFIKASI NYATA" agar pengguna tidak salah mengartikan status ekspedisi remediasi?
5. Bagaimana cara membuktikan secara empiris bahwa remediasi berhasil atau gagal di host nyata (evidence `exitCode` + `outputHash` + `verified`) — bukan sekadar simulasi skor?

### 1.3 Batasan Masalah

Agar pembahasan tidak meluas, proyek ini dibatasi pada:

1. **Scope fungsi:** audit kepatuhan + remediasi endpoint. Tidak mencakup respons insiden forensik penuh, IDS/IPS, manajemen jaringan SDN, atau manajemen kerentanan jaringan yang luas.
2. **Scope alias:** hanya alias yang terdaftar di `ALLOWLIST_ANALISA` (10 alias: `fw-enable-defender`, `guest-account-disable`, `usb-storage-block`, `fw-enable-ufw`, `ssh-disable-root`, `auditd-enable`, `usb-block-linux`, `rdp-nla-enable`, `uac-enable`, `bitlocker-enable`). LUKS/sudoers belum ditambah karena butuh repartition + reboot/manual.
3. **Scope platform:** Linux (Ubuntu/WSL, systemd, UFW, OpenSSH, audit kernel) dan Windows (Defender Firewall, Guest, USBSTOR registry, RDP NLA, UAC, BitLocker). Baremetal dengan BitLocker/LUKS paling baik diuji di VM non-kritis dengan snapshot.
4. **Scope AI:** kemampuan AI (Gemini 2.5 Flash) dibatasi pada analisis risiko kontekstual (threat intel) dengan sanitasi OPSEC; keputusan remediasi tetap pada operator dan kontrol plane.
5. **Scope pengujian:** pilot WSL Ubuntu (systemd aktif) sebagai host non-kritis; pengujian di server produksi tidak dilakukan.

### 1.4 Tujuan Penelitian/Pembuatan

1. Menghasilkan agent audit `pasopati_audit.py` yang memeriksa parameter-parameter CIS/STIG yang disebutkan pada Rumusan Masalah 1, dengan skor tertimbang (PASS=100, WARNING=50, FAIL=0) dan deteksi lingkungan WSL yang menghindari false negative.
2. Menghasilkan kontrol plane server (`server.ts`) dengan state machine remediasi `PLANNED → APPROVED → EXECUTING → VERIFIED/ROLLED_BACK/FAILED`, persistensi JSON lokal, dan audit log yang diperluas dengan field `planId` + `evidence[]`.
3. Menghasilkan antarmuka pengguna (UI) runbook persetujuan per-item (`TabRemediation.tsx`) dengan badge `VerificationBadge` (hijau `TERVERIFIKASI NYATA`, biru `MENUNGGU EVIDENCE AGENT`, merah `ROLLED_BACK/FAILED`, abu `SIMULASI`).
4. Menguji bukti end-to-end (token HMAC, backup, verify, evidence) di WSL Ubuntu, termasuk skenario gagal yang benar (`ROLLED_BACK`).
5. Menghasilkan dokumentasi lengkap (README, CATATAN-PENGEMBANGAN.md, CHECKPOINT.md, desain arsitektur) untuk penilaian kelayakan implementasi dan kualitas dokumentasi.

### 1.5 Manfaat Penelitian

#### 1.5.1 Manfaat praktis

- Administrator/satuan siber mendapat alat audit cepat dan reproducible untuk mengetahui celah nyata di setiap aset.
- Operator puskodal mendapat jalur remediasi yang aman (dry-run → plan → approve → eksekusi → verifikasi) tanpa memercayai klaim "auto-fix" buta.
- Evidence yang terekam memungkinkan audit pasca-insiden dan akuntabilitas (siapa menyetujui, kapan, apa buktinya).

#### 1.5.2 Manfaat teoritis dan akademis

- Studi kasus penerapan prinsip least privilege dan fail-safe pada remediasi endpoint berbasis allowlist.
- Demonstrasi konsistensi canonical JSON antara dua bahasa (Node.js `stableStringify` dan Python `json.dumps(sort_keys=True)`) untuk tanda tangan HMAC lintas platform.
- Contoh nyata pemisahan label simulasi dan verifikasi dalam UI keamanan (anti security theater).

#### 1.5.3 Manfaat kompetisi

- Prototipe yang dapat diuji langsung oleh juri di laptop/VM mereka sendiri (agent mandiri, stdlib-only, tanpa dependensi berat).
- Bukti empiris pilot (2 alias VERIFIED + 1 gagal dengan benar) memberikan kredibilitas lebih daripada demo animasi.
- Kelengkapan submission (link publik, thumbnail, screenshot, video, slide) meningkatkan skor kelayakan implementasi dan dokumentasi.

---

## BAB II: TINJAUAN PUSTAKA DAN LANDASAN TEORI

### 2.1 Penelitian Terkait (State of the Art / Perbandingan)

#### 2.1.1 Scanner kepatuhan read-only

Alat seperti OpenSCAP dan Lynis unggul dalam audit konfigurasi (checklist CIS) tetapi berhenti pada rekomendasi — mereka tidak mengubah host. Kelebihan: aman. Kelemahan: operator tetap harus menulis skrip sendiri; tidak ada bukti "sudah diperbaiki". PASOPATI mengambil alur audit sejenis, tetapi menambahkan remediasi terkendali persetujuan di atasnya dengan evidence baca-ulang.

#### 2.1.2 Alat auto-hardening tanpa kontrol plane

Beberapa skrip hardening community (mis. Koleksi CIS hardening Bash) menjalankan `systemctl`, `iptables`, atau editing `sshd_config` secara langsung tanpa nonce, tanpa backup terstruktur, dan tanpa evidence HMAC. Risikonya: perintah salah dapat merusak layanan, dan tidak ada bukti siapa menyetujui apa. PASOPATI menutup celah ini dengan: (a) token nonce+HMAC berumur 10 menit, (b) allowlist tanpa shell mentah, (c) backup snapshot + verify, (d) evidence yang dikirim balik ke server.

#### 2.1.3 Platform SIEM modern

Platform seperti Wazuh unggul dalam deteksi dan korelasi SIEM, tetapi scope-nya luas dan instalasi berat. PASOPATI lebih sempit dan ringan: hardening endpoint deterministik CIS/STIG + remediasi terverifikasi, tanpa beban SIEM penuh.

#### 2.1.4 Generator skrip assisted (dasbor)

Generator skrip Bash/PowerShell yang berbasis deteksi celah (FAIL/WARNING) merupakan artefak yang paling langsung terlihat oleh juri. PASOPATI memperkaya generator ini dengan dry-run (`--dry-run` / `-WhatIf`), backup `.bak`, skrip rollback, dan re-audit loop — menjadikannya bukan sekadar generator teks, melainkan mesin hardening yang dapat diuji.

#### 2.1.5 Posisi PASOPATI

Kebaruan PASOPATI bukan pada satu fitur tunggal, melainkan pada kombinasi: audit deterministik WSL-aware + telemetri HMAC anti-replay + kontrol plane berstate machine + allowlist tanpa shell + backup/verify/rollback + evidence + label UI anti-teater. Kombinasi ini belum ditemukan pada alat open-source sekelasnya yang dapat dijalankan mahasiswa/juri tanpa infrastruktur berat.

### 2.2 Landasan Teori

#### 2.2.1 CIS Benchmark v8.0

CIS Benchmark menyediakan konfigurasi baseline Linux dan Windows yang diterima industri. Setiap parameter memiliki CIS ID (contoh: CIS 3.5.1 firewall, CIS 5.2 SSH, CIS 4.1.1 auditd). Audit PASOPATI memetakan setiap parameter ke CIS ID untuk ketertelusuran.

#### 2.2.2 DISA STIG

Security Technical Implementation Guides dari Departemen Pertahanan AS menyediakan baseline untuk Windows (mis. WN11-00-000010 Guest, WN11-CC-000180 USB, WN11-00-000025 BitLocker, WN11-00-000045 RDP NLA). PASOPATI memakai STIG ID sebagai rujukan kedua di samping CIS.

#### 2.2.3 ISA/IEC 62443

Standar keamanan OT/ICS menekankan segmentasi conduit/zona dan larangan protokol plaintext (Telnet/FTP) pada jalur radio taktis. PASOPATI mengacu pada klausul ini saat menilai port berbahaya dan layanan plaintext.

#### 2.2.4 HMAC-SHA256, nonce, dan anti-replay

HMAC-SHA256 dengan kunci bersama (HMAC_SECRET) menjamin keaslian payload telemetri dan tanda tangan plan remediasi. Nonce acak 32 byte menjamin keunikan setiap token; server menyimpan nonce terpakai untuk menolak replay. Expiry 10 menit membatasi jendela serangan. Verifikasi menggunakan perbandingan constant-time (`timingSafeEqual`) untuk menghindari serangan timing. Pada telemetri ingest, tanda tangan diverifikasi atas raw body persis yang terkirim (bukan hasil parse ulang), menghilangkan drift kanonikalisasi. Pada remediasi, canonical JSON disatukan via urut rekursif (`stableStringify`) di sisi Node agar cocok dengan `json.dumps(sort_keys=True, ensure_ascii=False)` di Python.

#### 2.2.5 Prinsip least privilege dan fail-safe

Agent berjalan dengan hak istimewa minimum. Tanpa token valid, agent menolak perubahan apa pun (read-only). Sudoers sangat sempit hanya untuk alias allowlist, atau tanpa root dengan kapabilitas spesifik bila memungkinkan. Kegagalan di langkah mana pun menghentikan alur (stop-on-failure). Tidak ada penambahan teks deskripsi untuk memalsukan rollback; pemulihan harus berasal dari snapshot backup.

#### 2.2.6 Idempotency dan dry-run

Generator skrip PASOPATI bersifat idempotent: menjalankan dua kali tidak merusak, karena setiap langkah memeriksa status saat ini terlebih dahulu (contoh: cek `ss -tuln | grep :4444` sebelum menghentikan proses). Dry-run memungkinkan evaluator menjalankan skrip tanpa mengubah disk.

#### 2.2.7 Deteksi WSL dan virtualization awareness

Pemeriksaan `/proc/version` untuk mendeteksi string "microsoft" / "wsl" mencegah false FAIL pada lingkungan WSL: disk virtual VHDX dan ketiadaan auditd default di WSL dilaporkan sebagai WARNING informatif, bukan FAIL palsu. Ini penting karena evaluator seringkali menguji di WSL.

### 2.3 Kerangka Berpikir (Alur Logis)

1. **Audit read-only:** agent membaca parameter host nyata dan menghasilkan matriks `SecurityCheck[]` dengan skor.
2. **Runbook:** dasbor (AI + rule-based) menyusun rencana per-temuan: alias tindakan, risiko, reversibility.
3. **Approval per-item:** operator memilih item yang disetujui; server membuat token (nonce + HMAC + expiry).
4. **Transit aman:** server meneruskan plan + token ke operator untuk dijalankan di host target (TLS/mTLS pada deployment ideal; mTLS penuh belum diimplementasikan di prototipe).
5. **Agent verify:** signature/nonce/expiry/allowlist/prasyarat OS diverifikasi.
6. **Backup:** snapshot konfigurasi target ke direktori backup per-host.
7. **Eksekusi + verifikasi per langkah:** bukti (output hash, exit code) di-HMAC dan dikirim real-time.
8. **Hasil akhir:** semua verify PASS → `VERIFIED`; ada gagal → stop → rollback otomatis dari backup → `ROLLED_BACK` (atau `FAILED` bila rollback gagal, dengan alert operator).
9. **UI menampilkan nilai terverifikasi** yang dibaca dari host; audit terdokumentasi permanen.

---

## BAB III: METODOLOGI PERANCANGAN / PENELITIAN

### 3.1 Tahapan Penelitian

> **Status:** Fase A–E **selesai 06 Nov 2026** (pilot WSL: 2 VERIFIED + 1 ROLLED_BACK benar). Operasional + hardening repo (rotasi secret, purge `TACTICAL_SECRET_2026` dari riwayat) selesai. Lihat `CHECKPOINT.md`.

Penelitian ini mengikuti roadmap lima fase:

- **Fase A — Arsitektur + skema + allowlist (desain):** dokumen `docs/REAL-AGENT-REMEDIATION-DESIGN.md`, skema `remediation_plan` dan `evidence`, allowlist awal.
- **Fase B — Server (control plane):** endpoint plan/approve/verify + state machine + skema evidence + persistensi JSON.
- **Fase C — Agent remediate:** mode remediate (allowlist, backup/verify/rollback, evidence HMAC), CLI baru `--remediate-plan --remediate-token --remediate-api-key --hmac-key --no-exec`.
- **Fase D — UI:** runbook persetujuan per-item, display verifikasi nyata, badge `SIMULASI` vs `TERVERIFIKASI NYATA`.
- **Fase E — Pilot di host non-kritis → perluasan OS & alias:** pilot WSL (`--no-exec` lalu eksekusi nyata), tambah alias Linux (`ssh-disable-root`, `auditd-enable`, `usb-block-linux`) dan Windows (`rdp-nla-enable`, `uac-enable`, `bitlocker-enable`), re-test evidence end-to-end, dokumentasi.

### 3.2 Perancangan Perangkat Keras (Hardware Design)

Tidak ada perangkat keras khusus yang dibangun. Sistem berjalan pada perangkat umum:

- Laptop/VM evaluator (Windows 11 / Ubuntu WSL2),
- Mengandalkan kapabilitas bawaan OS host: `systemd`, `ufw`, OpenSSH, kernel audit, `manage-bde` (Windows), `netsh`/`reg`/`net` (Windows).

Blok diagram sistem:

```
┌──────────────────┐     (1) Audit        ┌──────────────────┐
│   Dashboard      │ ───────────────────▶ │      Agent       │
│   (React UI)     │                      │ (pasopati_audit.py)│
│   - runbook      │ ◀─────────────────── │ - allowlist      │
│   - approval     │    (2) Evidence      │ - backup         │
└────────┬─────────┘                      └────────▲─────────┘
         │ (3) plan/approve/verify                │ (4) alias terdaftar
┌────────▼────────────────────────┐               │
│     Server (control plane)      │──── TLS/mTLS ─┘
│  - state machine                │
│  - audit store                  │
└─────────────────────────────────┘
```

### 3.3 Perancangan Perangkat Lunak (Software Design)

#### 3.3.1 Server (`server.ts`)

- **Teknologi:** Node.js + Express + tsx + Vite middleware, port 3000.
- **Endpoint remediasi:**
  - `POST /api/remediation-plan` — buat rencana (status PLANNED, validasi alias regex `^[a-z0-9][a-z0-9-]{2,47}$`, maks 50 item).
  - `POST /api/remediation-approve` — terbitkan nonce + HMAC + expiresAt 10 menit (PLANNED → APPROVED; menuntut `HMAC_SECRET`).
  - `POST /api/remediation-verify` — agent kirim evidence; validasi nonce + signature + expiry + anti-replay + transisi sah.
  - `GET /api/remediation-plans` dan `GET /api/remediation-plans/:id` — daftar/detail plan.
- **State machine:** `PLANNED → APPROVED → EXECUTING → VERIFIED / ROLLED_BACK / FAILED` (transisi diizinkan didefinisikan eksplisit).
- **Persistensi:** `data/remediation_plans.json`; audit log lokal `data/audit_logs.json` diperluas dengan field `planId` dan `evidence[]`.
- **Keamanan kanal:** gate `PASOPATI_API_KEY` via header `X-Pasopati-API-Key` (loopback bypass untuk demo lokal, 401 untuk non-loopback tanpa kunci valid), security headers (`X-Content-Type-Options`, `X-Frame-Options`, dll).
- **Canonical JSON:** `stableStringify` (urut kunci rekursif, abaikan `undefined`) untuk memastikan tanda tangan kompatibel dengan Python.

#### 3.3.2 Agent (`pasopati_audit.py`)

- **Teknologi:** Python stdlib saja (tanpa dependensi berat, kecuali opsional `psutil` bila tersedia; ada fallback stdlib untuk scan port).
- **Mode audit:** `run_full_audit()` mengorkestrasi modul: kernel & boot, kripto/FDE, privilege boundary, firewall, kontrol akses, endpoint protection, logging. Menghasilkan `audit_result.json` dengan metadata, info perangkat, scoring, dan compliance matrix.
- **Mode remediate:** `ALLOWLIST_ANALISA` (10 alias) dengan fungsi `read`/`apply`/`verify` (+ `rollback` opsional). Semua `subprocess.run(list)` tanpa shell.
  - `_validate_remediation_token()`: cek nonce cocok, expiry epoch-ms, signature HMAC-SHA256 kanonis (`sort_keys=True`, `ensure_ascii=False`).
  - `run_remediation()`: allowlist check → token check → read pre-state → backup ke `~/.pasopati/backups/` → apply → verify → evidence `{stepIndex, alias, exitCode, outputHash, verified}` → `POST /api/remediation-verify`.
  - Gagal → stop-on-failure → rollback dari snapshot → status `ROLLED_BACK`.
  - CLI: `--remediate-plan`, `--remediate-token` (format `nonce.signature`), `--remediate-api-key`, `--hmac-key`, `--no-exec` (validasi + tampilkan pre-state tanpa mengubah host).
- **Fitur darurat:** `--quarantine` / `--dry-run` untuk kill-switch isolasi firewall (DEFCON 1) dengan dry-run sebagai default evaluasi.
- **Telemetri:** `push_telemetry()` menghitung HMAC atas raw bytes JSON (`ensure_ascii=False`), header `X-Pasopati-Signature`, `X-Pasopati-Timestamp`, `X-Pasopati-Unit`.

#### 3.3.3 Antarmuka pengguna (UI, `src/`)

- **Teknologi:** React 19, TypeScript, Tailwind CSS v4, Vite, `lucide-react`, `motion`.
- **Baris API:** `src/remediationApi.ts` dengan helper `postJson`/`getJson` (header `X-Pasopati-API-Key` bila ada), `createPlan`, `approvePlan`, `getPlan`, `listPlans`, `wslCommandText`.
- **Tipe:** `src/types.ts` — `PlanStatus`, `RemediationPlanItem`, `RemediationEvidence`, `RemediationPlan`.
- **Komponen:**
  - `TabCommandCenter` — ringkasan armada + skor.
  - `TabDeepAudit` — detail per perangkat + karantina.
  - `TabAIHardening` — analisis risiko AI + generator skrip Bash/PowerShell + simulasi dry-run + rollback baseline + badge VERIFIED (via `listPlans`).
  - `TabLiveAgent` — instruksi unduh `pasopati_audit.py`, unggah `audit_result.json`, sample juri, live host scan (`/api/scan-host`).
  - `TabAuditLog` — daftar audit log persisten + ekspor laporan (.txt/.md).
  - `TabRemediation` — runbook draft dari FAIL/WARNING, checkbox per-item, tombol BUAT PLAN / APPROVE PLAN / REFRESH, status plan, evidence, panel perintah WSL + Server URL + copy.
  - `VerificationBadges` — komponen `VerificationBadge({planStatus})`.
  - `Header` — navigasi tab termasuk `Remediation` (id 5).

#### 3.3.4 Konsol alternatif (`app.py`, Streamlit)

- Label Gemini 2.5 Flash, push-url port 3000, `html.escape` anti-XSS, recon ditandai `[SIMULASI]` agar tidak mengklaim real di luar konteks.
- Berperan sebagai field console air-gapped tanpa Node.js.

#### 3.3.5 Skema data

```text
remediation_plan = {
  planId, deviceId, createdBy, createdAt,
  items: [ { findingId, alias, risk, reversible,
             preState, postStateExpected } ],
  approvedBy, approvedAt, nonce, expiresAt, signature,
  status, evidence: [...]
}
evidence = {
  planId, stepIndex, alias, exitCode,
  outputHash, verified, timestamp
}
```

### 3.4 Metode Pengujian Alat

Parameter yang diukur dan cara mengukurnya:

1. **Uji lint/typecheck:** `npm run lint` (`tsc --noEmit`) harus hijau (exit 0).
2. **Uji build:** `npm run build` (Vite) harus selesai (1672 modul, ~400-800 ms).
3. **Uji agent Python:** `python -m py_compile pasopati_audit.py` harus OK.
4. **Uji API server:** plan (200), approve (200), verify (200), replay (409/401), bad nonce (401), unknown plan (404), bad alias (400).
5. **Uji pilot WSL:**
   - `--no-exec` (read-only): harus mencetak "Token valid" dan pre-state nyata, tanpa membuat backup/lebih tanpa perubahan.
   - Eksekusi nyata sebagai root (`wsl -u root`): backup dibuat, file/sistem berubah, verify baca-ulang PASS/FAIL, evidence dikirim (HTTP 200).
   - Uji rollback: bila verify gagal, handler `rollback()` harus dipanggil dari snapshot dan status menjadi `ROLLED_BACK`.
6. **Uji integrasi dashboard:** unggah `audit_result.json`, generate skrip, salin plan + perintah WSL, refresh status plan.

---

## BAB IV: RANCANGAN IMPLEMENTASI DAN PEMBAHASAN FITUR

### 4.1 Implementasi Perangkat Keras dan Perangkat Lunak

Tidak ada implementasi perangkat keras kustom. Implementasi perangkat lunak mengacu pada desain Bab 3. Bukti implementasi meliputi:

- `server.ts` — endpoint Fase B ditambahkan setelah handler `/api/quarantine`, sebelum `AUDIT_DB_PATH`.
- `pasopati_audit.py` — allowlist, validasi token, `run_remediation`, backup/verify/rollback.
- `src/` — tipe, API layer, komponen, integrasi tab.
- Dokumentasi: `docs/REAL-AGENT-REMEDIATION-DESIGN.md`, `README.md`, `CATATAN-PENGEMBANGAN.md`, `CHECKPOINT.md`.

### 4.2 Penjelasan Detail Fitur-Fitur Alat

#### 4.2.1 Fitur Audit (Alur A)

Agent (`run_full_audit`) menghasilkan:

- Tes port berbahaya (4444 C2, SMB 445, Telnet 23, FTP 21) dengan status FAIL/WARNING/PASS.
- Firewall: Linux (`ufw status` / `iptables -L`), Windows (`netsh advfirewall show allprofiles state`).
- Kontrol akses: SSH `PermitRootLogin` (Linux), Guest account (Windows).
- USB: Linux (cek `install usb-storage /bin/true` / `blacklist usb-storage`), Windows (kebijakan GPO monitoring).
- Logging: `systemctl is-active auditd` (Linux, dengan deteksi WSL), `Get-WinEvent` (Windows).
- Kernel/boot: rootkit signature scan, izin GRUB, Secure Boot (Windows).
- Kripto/FDE: LUKS via `lsblk -f` (Linux), BitLocker via `manage-bde -status C:` (Windows).
- Privilege: NOPASSWD per-line (Linux), SUID scan, membership Administrators (Windows).

Skor dihitung sebagai rata-rata tertimbang PASS=100, WARNING=50, FAIL=0, dibulatkan ke integer. Deteksi WSL (`/proc/version` mengandung microsoft/wsl) mengubah LUKS/auditd dari FAIL menjadi WARNING informatif.

#### 4.2.2 Fitur Assisted Hardening Script (TabAIHardening)

- Generator memetakan `openPorts` dan `failChecks` ke langkah deterministik idempotent:
  - Port 4444: hentikan proses (`fuser -k` / `Stop-Process`) + blokir firewall (`iptables -A` / `New-NetFirewallRule`).
  - Port 445: hentikan `smbd`, blokir 445.
  - Port 23/21: hentikan `telnetd`/`vsftpd`, blokir 23/21.
  - Firewall: `ufw default deny incoming` + whitelist SSH taktis, atau `iptables -P INPUT DROP` fallback.
  - SSH root: edit `sshd_config` (`PermitRootLogin no`), backup `.bak`, restart sshd.
  - Sudoers: hapus `NOPASSWD:` per-file.
  - USB Linux: tulis `install usb-storage /bin/true` + `blacklist usb-storage`.
  - Auditd: `systemctl enable auditd`.
  - Windows: NLA RDP (UserAuthentication), Guest disable (`net user Guest /active:no`), USBSTOR `Start=4`, BitLocker.
- Setiap skrip memiliki opsi `--dry-run` / `-DryRun` (`-WhatIf`) yang mengevaluasi tanpa mengubah disk.
- Re-audit loop: verifikasi port 4444/445 tidak lagi listening.
- Rollback script: mengembalikan blokir firewall, re-enable layanan, restore file `.bak`.
- Tombol dashboard `SIMULATE` (dry-run) dan `APPLY` (mengubah status lokal + audit log) adalah **simulasi dashboard**; skrip yang diunduh adalah artefact nyata yang harus dijalankan manual sebagai root/admin. Label "Peringatan: draft Assisted Remediation, wajib ditinjau Administrator" ditampilkan eksplisit.

#### 4.2.3 Fitur Real Agent Remediation (Alur B)

- **Ubah host secara nyata** hanya melalui alias allowlist (tanpa shell mentah).
- **Contoh alias teruji:**
  - `usb-block-linux`: tulis `/etc/modprobe.d/pasopati-usb-lock.conf`, verify baca file mengandungkan blokir.
  - `fw-enable-ufw`: `ufw --force enable`, verify `ufw status` aktif.
  - `auditd-enable`: `systemctl enable --now auditd`, verify `systemctl is-active`.
  - Windows: `fw-enable-defender` (`netsh advfirewall set ...`), `guest-account-disable` (`net user Guest /active:no`), `usb-storage-block` (registry `Start=4`), `rdp-nla-enable`, `uac-enable` (registry), `bitlocker-enable` (`manage-bde -protectors -add` + `-on -SkipHardwareTest`).
- **Evidence:** `outputHash = sha256(JSON pre-state sort_keys)`, `exitCode` dari apply, `verified` dari baca ulang.
- **Rollback:** handler per alias (mis. hapus file blokir USB, `systemctl disable --now auditd`, set registry kembali, `manage-bde -off`) dipanggil dari snapshot pre-state.

#### 4.2.4 Fitur Analisis Risiko AI

- Endpoint `/api/analyze-threats` memproses `deviceName`, `deviceRole`, `os`, `checks` dengan OPSEC sanitizer (IP/MAC/hostname disensor menjadi `[REDACTED]`).
- Bila `GEMINI_API_KEY` valid, model Gemini 2.5 Flash menghasilkan telaah risiko militer Bahasa Indonesia; bila kosong/invalid, fallback ke rule-based engine (100% tanpa error). Sumber analisis ditampilkan di UI agar tidak mengklaim AI palsu.

#### 4.2.5 Fitur Command Center dan Laporan

- Skor armada, daftar perangkat, status karantina, drift kepatuhan.
- Ekspor laporan komandan (`.txt` plain text dan `.md` Markdown) dengan format justifikasi, inventarisasi aset, rekomendasi taktis, dan blok tanda tangan digital.
- Unduhan project ZIP (archiver) dan berkas individual (`pasopati_audit.py`, `app.py`, `requirements.txt`, `README.md`) — desain Blob untuk menghindari intersepsi IDM.

### 4.3 Hasil Pengujian dan Analisis

#### 4.3.1 Hasil uji otomatis (lint/build/compile)

- `npm run lint` (`tsc --noEmit`): hijau (exit 0). Frase sebelumnya 4 error TS telah diperbaiki.
- `npm run build` (Vite 8.3): sukses (≈1672 modul, 366 kB JS, 53 kB CSS, <1 detik).
- `python -m py_compile pasopati_audit.py`: OK (Python 3.14).
- `npm run lint` setelah penambahan Fase D (D1–D7): hijau; `npm run build`: sukses 1672 modul, 422–775 ms.

#### 4.3.2 Hasil uji API server (Fase B)

- `POST /api/remediation-plan` → 200 (status PLANNED, validasi alias regex, maks 50 item).
- `POST /api/remediation-approve` → 200 (nonce+signature+expiresAt 10 menit, transisi PLANNED→APPROVED).
- `POST /api/remediation-verify` → 200 (validasi nonce+signature+expiry+anti-replay+transisi; bukti audit log `planId`+`evidence[]`).
- Replay nonce → 409/401; bad nonce → 401; unknown plan → 404; bad alias → 400.

#### 4.3.3 Hasil uji agent --no-exec (Fase C & E)

- Token valid + `--no-exec` → "Token valid", pre-state dibaca nyata (mis. `{"exists": false, "blocked": false}`), **tidak ada direktori backup dibuat** (aman), host tidak berubah.
- Token salah → "Nonce tidak cocok" → DIBATALKAN, agent tetap read-only.
- Pada WSL root, `--no-exec` alias `usb-block-linux` dan `auditd-enable`: Token valid, pre-state real (auditd `inactive/not-found`), tanpa perubahan.

#### 4.3.4 Hasil uji pilot nyata di WSL (E1 & operasional)

- **Skenario uji A (rollback benar):** plan `auditd-enable` (`PLAN-1793979505779-499187`, `PLAN-1793981830923-770127`) → apply gagal (auditd tidak terinstal / kernel WSL menolak `Unable to set initial audit startup state`) → verify gagal → rollback handler dipanggil (`rollback auditd-enable dari snapshot ... exitCode 1/0`) → evidence terkirim HTTP 200 → server status `ROLLED_BACK` dengan evidence `{stepIndex:0, alias:auditd-enable, exitCode:1, outputHash:sha256:..., verified:false}`. Backup snapshot terbuat di `~/.pasopati/backups/` dan `/root/.pasopati/backups/`.
- **Skenario uji B (sukses):** plan `usb-block-linux` (`PLAN-1793980530306-587887`) → backup → tulis `/etc/modprobe.d/pasopati-usb-lock.conf` (`install usb-storage /bin/true` + `blacklist usb-storage`) → verify PASS (`blocked:true`) → evidence `exitCode:0, verified:true` → server status `VERIFIED`. File kemudian dihapus manual untuk mengembalikan host ke bersih (rollback manual).
- **Skenario uji C (sukses pasca-install):** setelah `apt install auditd ufw` (meskipun auditd tetap gagal di kernel WSL), plan `fw-enable-ufw` (`PLAN-1793981978857-617214`) → `ufw --force enable` → verify PASS (`Status: active`) → server `VERIFIED` dengan `exitCode:0`. Setelah uji, `ufw disable` mengembalikan host ke `Status: inactive`.

#### 4.3.5 Analisis terhadap rumusan masalah

1. **Audit read-only terukur:** terbukti via `audit_result.json` dan skor; deteksi WSL menghindari false FAIL.
2. **Anti-pemalsuan:** terbukti via HMAC ingest (timing-safe, anti-replay, raw body) dan canonical `stableStringify` yang memperbaiki bug mismatch Node↔Python (signature sebelum fix tidak valid; sesudah fix Token valid).
3. **Remediasi allowlist + backup/verify/rollback:** terbukti via 3 skenario di atas; rollback stub lama (hanya mencetak nama snapshot) telah diperbaiki menjadi pemanggilan handler nyata.
4. **Label UI:** terbukti via badge; TabAIHardening kini menampilkan badge VERIFIED yang diambil dari `listPlans`.
5. **Bukti nyata:** terbukti via evidence yang dibaca ulang (file, `ufw status`, `systemctl`), bukan asumsi.

#### 4.3.6 Tingkat keberhasilan perbaikan

Pilot empiris (WSL, 3 alias): **2 VERIFIED (`usb-block-linux`, `fw-enable-ufw`) dan 1 ROLLED_BACK (`auditd-enable`) yang benar** karena keterbatasan kernel WSL, bukan bug. Ini berarti tingkat keberhasilan pada host yang memenuhi prasyarat (paket terinstal, kernel mendukung) berpotensi tinggi untuk alias yang sederhana (file/reks). Untuk alias yang memerlukan layanan kernel (auditd) atau langkah destruktif (BitLocker/LUKS), keberhasilan tergantung prasyarat baremetal dan tidak boleh diklaim sebagai pasti.

---

## BAB V: KESIMPULAN DAN SARAN

### 5.1 Kesimpulan

PASOPATI berhasil menyediakan (1) audit kepatuhan read-only yang deterministik, (2) kontrol plane berstate machine dengan token HMAC anti-replay, (3) agent remediasi allowlist dengan backup/verify/rollback, dan (4) UI runbook persetujuan per-item dengan badge SIMULASI vs TERVERIFIKASI NYATA. Di pilot WSL, `usb-block-linux` dan `fw-enable-ufw` mencapai VERIFIED dengan evidence terverifikasi, sedangkan `auditd-enable` gagal dengan fail-safe yang benar (ROLLED_BACK + rollback). Bug kritis canonical signature telah diperbaiki dan re-test evidence flow end-to-end lolos. Prototipe siap untuk pilot baremetal dan submission kompetisi.

### 5.2 Saran

1. **Pilot baremetal:** Windows + BitLocker (TPM aktif, admin PowerShell, simpan recovery key offline, reboot), Linux + auditd (kernel audit aktif), LUKS manual (snapshot VM → `cryptsetup luksFormat` → `crypttab` → reboot → verifikasi `crypto_LUKS`). Jangan coba di host produksi tanpa snapshot.
2. **Keamanan operasional:** rotasi `HMAC_SECRET`/`PASOPATI_API_KEY` berkala (hanya di `.env`, tidak dilacak git). Secret lama `TACTICAL_SECRET_2026` **sudah dipurge dari riwayat via `git filter-repo` 06 Nov 2026** (terverifikasi `git log -S` kosong); anggap bocor, jangan dipakai.
3. **Perluasan alias:** `LUKS` dan `sudoers` (memerlukan reboot/manual yang jelas) serta BitLocker di baremetal dengan pengelolaan recovery key yang eksplisit.
4. **Fase lanjutan (Fase F yang diusulkan):** four-eyes approval untuk item HIGH risk, scheduling terjadwal, dan ekspor evidence terverifikasi independen via HMAC untuk audit eksternal.
5. **Submission:** lengkapi link publik, thumbnail 1200×630, screenshot, video YouTube ≤10 menit, dan slide penjelasan sebelum deadline 15 November 2026.

---

## Daftar Acuan (Selected References)

- CIS Benchmark v8.0 (Ubuntu, Debian, Windows 11).
- DISA STIG (V-214800, V-214885, WN11-00-000010, WN11-CC-000180, dll).
- ISA/IEC 62443-3-3 SR 3.1, 62443-4-2 CR 3.1.
- Desain arsitektur: `docs/REAL-AGENT-REMEDIATION-DESIGN.md`.
- Checkpoint pengerjaan: `CHECKPOINT.md`.
- Catatan pengembangan: `CATATAN-PENGEMBANGAN.md`.

*Catatan: Seluruh angka hasil uji pada Bab IV berasal dari pilot nyata yang dijalankan pada WSL Ubuntu (6 November 2026) dan dapat direplikasi dengan mengikuti langkah pada Rencana Uji WSL di CHECKPOINT.md.*
