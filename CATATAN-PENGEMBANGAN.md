# CATATAN PENILAIAN & DASAR PENGEMBANGAN — PASOPATI

> Catatan historis. Beberapa penyebutan di bawah memakai nama lama; proyek kini
> konsisten memakai nama **PASOPATI** (`pasopati_audit.py` / `pasopati_remediate.py`).

> Dibuat: 3 November 2026
> Dasar: Audit menyeluruh kode + pembacaan Rulebook Kartika Cyber Hackathon 2026 + pengujian langsung
> Status: **Dokumen kerja untuk pengembangan lanjutan**

---

## 1. KONTEKS KOMPETISI (Rulebook)

- **Kompetisi:** Kartika Cyber Hackathon 2026 (PUSSIBERAD × CODEPOLITAN)
- **Kategori yang dipilih:** Penangkalan / Dukungan (endpoint compliance & defense)
- **Batas submission:** 15 November 2026, 23:59 WIB
- **Penjurian online:** 16 Nov 2026 · Finalis: 20 Nov · Final: 24 Nov 2026

### Bobot Penilaian Juri
| No | Aspek | Bobot |
|----|-------|-------|
| 1 | Relevansi & Manfaat (untuk TNI AD) | 25% |
| 2 | Inovasi Teknis | 25% |
| 3 | Fungsionalitas Purwarupa | 25% |
| 4 | Kelayakan Implementasi | 15% |
| 5 | Kualitas Dokumentasi | 10% |

### Kelengkapan Submission (WAJIB, saat ini 0% ada)
- [ ] Link karya/publik yang bisa diakses juri
- [ ] Thumbnail 1200×630 px (JPG/PNG/WebP, maks 500KB)
- [ ] Screenshot karya (maks 5 gambar)
- [ ] Video karya di YouTube (maks 10 menit)
- [ ] Slide penjelasan (fitur, arsitektur, teknologi)

---

## 2. SKOR PENILAIAN SAAT INI (jujur)

| Aspek | Skor | Catatan |
|-------|------|---------|
| Relevansi & Manfaat | ~16/25 | Konsep tepat, tapi data mock didressing sebagai infrastruktur militer nyata |
| Inovasi Teknis | ~14/25 | Generator skrip + deteksi WSL bagus; HMAC & "AI" lemah/dekoratif |
| Fungsionalitas Purwarupa | ~11/25 | **Kelemahan terbesar** — fitur headline (live scan, kill-switch, remediation) sebagian besar teater |
| Kelayakan Implementasi | ~8/15 | Potensi ada, security posture tool keamanan sendiri buruk |
| Kualitas Dokumentasi | ~6/10 | README rapi; belum ada proposal, arsitektur, test |
| **TOTAL** | **~55/100** | Range realistis 50–65 tergantung kedalaman pengujian juri |

**Risiko terbesar:** BUKAN gagal teknis, tapi **ketahuan berlebihan oleh juri** saat menekan tombol.

---

## 3. HASIL PENGUJIAN LANGSUNG (3 Nov 2026)

| Perintah | Hasil |
|----------|-------|
| `npm run lint` (tsc --noEmit) | ❌ GAGAL — 4 error TS |
| `npm run dev` (Express :3000) | ✅ Berjalan |
| `POST /api/scan-host` | ⚠️ 200 tapi data fabricated (skor 65, port [22,4444], MAC Docker) |
| `POST /api/quarantine` | ⚠️ 200 sukses — tidak melakukan apa pun |
| `POST /api/ingest` tanpa signature | ⚠️ 200 diterima, `signature_verified: false` |
| `POST /api/analyze-threats` | ⚠️ Fallback rule-based (GEMINI_API_KEY placeholder) |
| `GET /api/download/project-zip` | ❌ ERROR `spawn python3 ENOENT` — rusak di Windows |
| `python pasopati_agent.py` | ✅ Berjalan (skor 75/100, banyak check cacat) |
| `streamlit run app.py` (:8501) | ✅ Berjalan |

---

## 4. DAFTAR MASALAH (PRIORITAS PERBAIKAN)

### P0 — KRITIS (wajib sebelum submission)

- [ ] **Hapus/jujurkan semua fitur teater.** Jangan pernah kembalikan data karangan sebagai "Live Node Execution".
  - `server.ts:306–358` — fallback `/api/scan-host` mengembalikan temuan fabricated (skor 65, "Backdoor 4444 FAIL", MAC `02:42:AC:11:00:02`) saat `python3` absen (selalu di Windows)
  - `TabCommandCenter.tsx:46–77` — "RUN LIVE TACTICAL AUDIT" = string hardcoded di timer, nol network I/O
  - `server.ts:202–215` — `/api/quarantine` hanya `console.log` + JSON sukses
  - `App.tsx:142–225` — "Remediation" = flip string FAIL→PASS di React state, skor dipatok 100
  - `TabAIHardening.tsx:431–460, 789–790` — tombol "DRY-RUN" justru mengubah state permanen
  - `TabAIHardening.tsx:436` — baris terminal "sesi SSH/WinRM AES-256" karangan
  - `App.tsx:21–60` — audit log di-seed 2 entri dengan timestamp 2026-10-29
  - `TabCommandCenter.tsx:175` — "100% Satuan Terkoneksi" string statis
  - `Header.tsx:76–79` — badge DEFCON tidak pernah berubah

- [ ] **Perbaiki HMAC telemetry** (`server.ts:145–199`, `pasopati_agent.py:629–665`)
  - [ ] Tolak request dengan signature invalid/hilang (saat ini selalu diterima)
  - [ ] Constant-time compare (`crypto.timingSafeEqual`)
  - [ ] Secret jangan hardcoded: hilangkan fallback `TACTICAL_SECRET_2026` di `server.ts:159` dan `pasopati_agent.py:40`
  - [ ] Validasi `X-Pasopati-Timestamp` (anti-replay)
  - [ ] Sign raw body, bukan hasil re-serialize JSON
  - [ ] Samakan kanonisasi Python `ensure_ascii` vs `JSON.stringify` (bug non-ASCII)

- [ ] **Bersihkan kebocoran secret**
  - [ ] `.env` jangan masuk ZIP publik (`server.ts:265–277`, `app.py:794–810`) — exclude file dotfile, bukan hanya direktori
  - [ ] Gate semua endpoint mutating (saat ini semua terbuka di `0.0.0.0:3000`)
  - [ ] `.env.example` jangan berisi nilai Firebase/HMAC asli — hanya placeholder

- [ ] **Perbaiki `npm run lint`** — 4 error:
  - [ ] `firebase/auth` types (3× TS7016) — tambah deklarasi atau perbaiki instalasi firebase
  - [ ] `googleAuthService.ts:59` — `string | null` tidak assign ke `string`

- [ ] **Perbaiki Download Project ZIP** — `spawn python3 ENOENT` di Windows; jangan depend `python3` (pakai archiver murni Node atau sediakan zip statis)

### P1 — PENTING (kualitas & keamanan)

- [ ] **Shell injection di generator skrip** (`TabAIHardening.tsx:71,88,103–125,305`; `app.py:434,440,583`) — nama device dari JSON upload diinterpolasi mentah ke string shell; escape/quote dengan benar
- [ ] **Sheets formula injection** (`googleSheetsService.ts:83,173`) — pakai `RAW` atau prefix `'`, bukan `USER_ENTERED`
- [ ] **Bug `--dry-run` abort** (`TabAIHardening.tsx:108,168`) — `set -e` + `[ "$DRY_RUN" = false ] && (...)` menggagalkan script di mode aman
- [ ] **Bug agent Python:**
  - [ ] `pasopati_agent.py:298` — NOPASSWD check `startswith('#')` hampir selalu True → false PASS; parse per-baris
  - [ ] `pasopati_agent.py:432–434` — double `f.read()` → cabang blacklist USB tak pernah match
  - [ ] `pasopati_agent.py:364` — iptables `>6` baris → ruleset kosong tetap PASS
  - [ ] `pasopati_agent.py:390` — grep SSH mentah; `#PermitRootLogin no` dianggap terkonfigurasi
  - [ ] **Error→PASS** di banyak check (GRUB absen→PASS, sshd absen→PASS, sudoers error→PASS) → skor selalu terlalu tinggi; error harus UNKNOWN/WARNING
  - [ ] `pasopati_agent.py:516–523` — Windows Event Log check hardcoded PASS
  - [ ] Port 22 dihitung "critical" → false positive di semua server normal
  - [ ] ID CIS banyak salah petakan (contoh: PermitRootLogin bukan 5.2.10) — verifikasi atau label sebagai "mapped heuristic"
- [ ] **Upload validation lemah** (`TabLiveAgent.tsx:83–107`) — cek tipe field, ukuran file, batasi `unit_id` (bisa overwrite device lain)
- [ ] **Token Google expire ~1 jam, tidak ada refresh** (`googleAuthService.ts:34–46,83–85`) — tambah `getIdToken()`/refresh; bug: reload halaman selalu logout
- [ ] **Re-sync Google Sheets menduplikasi baris** (`TabAuditLog.tsx:112–113`) — fallback "sync semua" saat tidak ada yang unsynced
- [ ] **HTML injection di Streamlit** (`app.py:979–1003,1111–1123,1245–1250`) — `unsafe_allow_html=True` pada data upload & output Gemini
- [ ] **`app.py:755,786`** — klaim "Gemini 3.8 Flash" tidak ada; ganti jadi nama model asli `gemini-2.5-flash`
- [ ] **`app.py:330–338`** — semantik DEFCON terbalik (skor tinggi → "DEFCON 1")
- [ ] **`app.py:1358`** — contoh `--push-url` menunjuk port Streamlit yang tidak punya `/api/ingest`; arahkan ke Express :3000
- [ ] **Arg injection ke agent** (`server.ts:299–306`) — `unitName` dari request jadi argv tanpa validasi (bisa jadi flag lain)
- [ ] **Endpoint tanpa auth** di `0.0.0.0:3000` — minimal gate untuk `/api/quarantine`, `/api/scan-host`, `/api/ingest`, `/api/analyze-threats`

### P2 — PERAPIHAN

- [ ] Aktifkan `strict` di `tsconfig.json`
- [ ] Hapus dead code:
  - `Header.tsx:10,20` — `onExportReport` tidak pernah dipanggil (JSON export tak terjangkau dari UI)
  - `TabLiveAgent.tsx:10,17,50–51` — `onRequestSecureDownload` tidak pernah di-pass
  - `server.ts:162,179–189` — `complianceDriftStore` ditulis tak pernah dibaca
  - Unused imports: `App.tsx:16`, `TabCommandCenter.tsx:2`, `TabDeepAudit.tsx:4`, `TabAuditLog.tsx:20`
- [ ] Rapikan: 3–4 report generator paralel di `App.tsx`; 4 download handler identik di `server.ts`; twin script engine ~200 baris di `TabAIHardening.tsx` (di-render 2× per render)
- [ ] `types.ts:78` — tambah action type untuk quarantine (saat ini menyalah label `HARDENING REMEDIATION`)
- [ ] Tambah error boundary di `main.tsx`
- [ ] Persistensi state devices/logs (refresh = hilang semua kecuali Sheets)
- [ ] `package.json` — `"name": "react-example"` → nama project sebenarnya
- [ ] `requirements.txt` — `pandas` tidak dipakai; hapus atau pakai
- [ ] Label "SIMULASI" konsisten — jangan ada `CONFIDENTIAL // TACTICAL INFRASTRUCTURE` di export data mock (`App.tsx:500`)
- [ ] Data mock wajib diberi penanda eksplisit di dalam kode (bukan hanya footer)
- [ ] Tambah test minimal (script generator, HMAC round-trip, scoring)

---

## 5. YANG SUDAH BAGUS (pertahankan)

1. **Generator skrip Bash/PowerShell** (`TabAIHardening.tsx:55–385`) — dry-run flag, backup `.bak`, rollback, re-audit loop. Artefak paling nyata & impresif di repo.
2. **`pasopati_agent.py`** — query OS sungguhan (`/proc`, `manage-bde`, `netsh`, psutil), deteksi WSL cerdas (hindari false FAIL), HMAC client, stdlib-only.
3. **Integrasi Google Sheets + Firebase Auth — API call asli, error surfacing cukup baik.** *(arsip: dihapus 06 Nov 2026; audit log kini lokal `data/audit_logs.json` — lihat §9. Jangan jadikan acuan aktif.)*
4. **OPSEC sanitizer ide** (`server.ts:61–70`) — perluas cakupan (IP di semua field, bukan hanya `details`).
5. **README** — struktur rapi, disclaimer kompetisi jelas.
6. **UI/UX** — Tailwind v4, animasi, navigasi 5 tab, audio Web Audio API tanpa asset file (`src/utils/audio.ts` bersih).
7. **Export laporan** (.txt/.md/.json) berfungsi.
8. **Upload JSON agent → dashboard** berfungsi.

---

## 6. RENCANA KERJA (usulan urutan)

### Besok — Hari 1 (jujuran & fondasi)
1. Putuskan strategi: **buat fitur benar-benar jalan ATAU label jujur sebagai simulasi** (jangan campur)
2. Perbaiki lint (4 error) + tombol ZIP
3. Perkuat HMAC (tolak invalid, constant-time, no hardcoded fallback)
4. Bersihkan `.env` dari jalur download

### Hari 2 (keamanan & kebenaran data)
5. Perbaiki bug agent Python (NOPASSWD, double-read, error→PASS, iptables)
6. Escape shell injection di generator skrip
7. Hapus/pastikan ulang semua klaim palsu di UI (DEFCON, "Gemini 3.8", "LIVE", audit log seed)
8. Gate endpoint + validasi upload

### Hari 3 (dokumentasi & submission)
9. Tulis proposal/dokumen teknis + arsitektur
10. Rekam video ≤10 menit, buat slide, screenshot, thumbnail 1200×630
11. Deploy link publik untuk juri
12. Uji ulang end-to-end: agent → ingest → dashboard → export → sheets

### Checklist pra-submission
- [ ] `npm run lint` hijau
- [ ] Tidak ada endpoint/fitur yang mengembalikan data palsu sebagai "live/real"
- [ ] Tidak ada secret di jalur download/ZIP
- [ ] Semua tombol utama diuji manual di Windows (mesin demo kemungkinan Windows)
- [ ] Kelengkapan submission 5 item lengkap
- [ ] Disclaimer "purwarupa, bukan sistem kedinasan resmi" tetap ada

---

## 7. PELAJARAN UTAMA

> **Aturan emas untuk pengembangan selanjutnya:**
> Setiap tombol yang ditekan juri harus menghasilkan sesuatu yang **benar-benar terjadi** —
> atau labelnya harus jujur berupa **SIMULASI**. Menjual teater sebagai "live/real-time/autonomous"
> adalah risiko penilaian terbesar project ini, jauh di atas bug teknis apa pun.

---

## 8. FASE E — PILOT & EKSPANSI (6 Nov 2026)

### E2/E3 — Alias baru (allowlist sekarang 10)
- Daftar final 10 (sinkron `pasopati_agent.py` `ALLOWLIST_ANALISA`): `fw-enable-defender`, `guest-account-disable`, `usb-storage-block`, `fw-enable-ufw`, `ssh-disable-root`, `auditd-enable`, `usb-block-linux`, `rdp-nla-enable`, `uac-enable`, `bitlocker-enable`.
- Linux: `ssh-disable-root`, `auditd-enable`, `usb-block-linux` (file edit tanpa shell, rollback dari snapshot)
- Windows: `rdp-nla-enable`, `uac-enable`, `bitlocker-enable` (registry/manage-bde via list, tanpa shell)
- UI `aliasForCheck` diperluas (ssh/root → ssh-disable-root, auditd/syslog → auditd-enable, bitlocker/rdp/uac).
- Rollback kini benar-benar memanggil handler (sebelumnya hanya mencetak nama snapshot).

### E1 — Pilot WSL (Ubuntu 2, non-root)
- `--no-exec` 2 alias (`usb-block-linux`, `auditd-enable`): Token valid, pre-state real, tidak ada perubahan.
- Eksekusi aktual 1 alias (`auditd-enable`, auditd tidak terinstal): verify GAGAL → stop-on-failure →
  rollback handler dipanggil → evidence dikirim → server status `ROLLED_BACK` + backup `~/.pasopati-guard/backups/`.
- Batasan: systemctl/ufw butuh root; LUKS/BitLocker tidak diuapkan di WSL (tetap manual).

### E4 — Re-test evidence flow
1. Fix bug kritis: canonical signature server/agent tidak cocok (key order JS vs Python `sort_keys`).
   Server kini memakai `stableStringify` (urut rekursif) agar cocok dengan `json.dumps(sort_keys=True)`.
2. Re-run: plan → approve → agent WSL (`--no-exec` lalu aktual) → `POST /api/remediation-verify`
   → status `ROLLED_BACK`, evidence `exitCode` + `outputHash` + `verified:false` tersimpan di server.
3. Catatan env: `dotenv` `.env` menang atas shell env saat server start — `PASOPATI_API_KEY`/`HMAC_SECRET`
   untuk pilot harus ditulis di `.env` (atau reload), bukan hanya `cmd set` sebelum `npx tsx`.

### E5 — Dokumentasi
- README diperbarui (allowlist 10 alias, fix canonical, cara pilot WSL).
- CHECKPOINT.md ditandai Fase E selesai; Fase E penuh (LUKS, BitLocker di baremetal) tetap manual.

---

## 9. OPERASIONAL — Siap Host Nyata (6 Nov 2026)

### Rotasi secret
- `HMAC_SECRET` & `PASOPATI_API_KEY` diputar (64 hex acak, di `.env` saja, tidak dilacak git).
- `.gitignore` sudah mengecualikan `.env*` (hanya `.env.example` ter-commit, berisi placeholder).
- ✅ Selesai 06 Nov 2026: nilai lama `TACTICAL_SECRET_2026` **sudah dipurge dari seluruh riwayat git via `git filter-repo`** (riwayat pasca-filter: `1841afb..24c5057`, terverifikasi `git log -S` kosong). Anggap bocor, jangan dipakai lagi.

### Plugin WSL pilot (`auditd` + `ufw`)
- `apt install auditd ufw` selesai; `ufw` **VERIFIED** nyata (`PLAN-1793981978857-617214`, `Status: active`, evidence `exitCode:0`).
- `auditd` **tidak bisa VERIFIED di WSL**: kernel WSL menolak `enable` audit (`Unable to set initial audit startup state`). Plan `PLAN-1793981830923-770127` benar-benar `ROLLED_BACK` + rollback handler dipanggil. Butuh host Linux baremetal (kernel audit aktif) untuk `VERIFIED`.
- `usb-block-linux` sudah `VERIFIED` sebelumnya (root, backup `~/.pasopati-guard/backups/`).

### Baremetal BitLocker / LUKS (manual)
- **BitLocker (Windows):** VM non-kritis, TPM aktif, admin PowerShell: `manage-bde -protectors -add C: -RecoveryPassword`; `manage-bde -on C: -SkipHardwareTest`; simpan recovery key offline; reboot; cek `manage-bde -status C:` → Protection On. Alias `bitlocker-enable` mengotomatiskan 2 perintah pertamanya.
- **LUKS (Linux):** **tidak ada alias otomatis** (perlu repartition + reboot). Cara aman: VM snapshot → partisi ulang dengan `cryptsetup luksFormat` → `cryptsetup open` → format/mount → fstab `crypttab` → reboot → `lsblk -f` tampil `crypto_LUKS`. Jangan coba di host produksi tanpa snapshot.
