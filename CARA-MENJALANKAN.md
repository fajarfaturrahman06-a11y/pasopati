# CARA MENJALANKAN PASOPATI

Arsip ini berisi seluruh source, test, dokumentasi, data runtime, build, dan dependensi
agar mudah direview. Beberapa hal wajib dibaca sebelum menjalankan.

## 1. Prasyarat

- Node.js 22+ dan npm 10+
- Python 3.10+ (agent + Field Console)
- Git bash/PowerShell 7 (opsional)
- Windows: PowerShell **Administrator** untuk `setup-lan.ps1`
- Linux/WSL: akses `sudo` untuk audit/remediasi penuh

> `node_modules/` di arsip dibuat di **Linux/WSL**. Jika membuka di Windows,
> jalankan `npm install` dulu agar binary platform-specific (esbuild, tailwind, rollup)
> diganti otomatis.

## 2. Menyiapkan environment
Arsip ini **tidak menyertakan `.env` aktif**. Buat file lokal dari template; jangan commit atau bagikan file `.env` karena berisi kredensial.
```bash
cp .env.example .env
```
Isi `.env` lokal:
- `PASOPATI_ADMIN_USERNAME` dan `PASOPATI_ADMIN_PASSWORD` — akun admin untuk login dashboard; password minimal 12 karakter. Akun dibuat sebagai bootstrap pada pemakaian pertama.
- `HMAC_SECRET` — min. 32 karakter acak untuk tanda tangan telemetri/evidence agen.
- `PASOPATI_API_KEY` — min. 32 karakter acak untuk kompatibilitas integrasi API/agen; **bukan** kredensial login dashboard.
- `GEMINI_API_KEY` / `GEMINI_BASE_URL` / `AI_MODEL_NAME` — opsional; tanpa ini AI memakai rule-based.

Buat nilai acak, misalnya dengan `openssl rand -hex 32`, lalu simpan hanya di `.env` lokal. Jangan mengisi username/password sungguhan ke `.env.example` atau arsip source. Akun bootstrap admin tidak dibuat bila dua variabel `PASOPATI_ADMIN_*` kosong; endpoint login akan menjelaskan bahwa konfigurasi perlu dilengkapi.

## 3. Menjalankan Command Center
```bash
npm install
npm run dev
```
Buka `http://localhost:3000`.
### Login dan tes admin vs user biasa
1. Masuk dengan `PASOPATI_ADMIN_USERNAME` dan `PASOPATI_ADMIN_PASSWORD` yang dikonfigurasi di `.env` sebelum server pertama kali dijalankan.
2. Di sidebar admin pilih **BUAT USER UJI**. Tentukan username serta password minimal 12 karakter untuk akun `viewer`.
3. Catat kredensial viewer yang ditampilkan, lalu tutup panel dan pilih **KELUAR**.
4. Masuk dengan akun viewer. Viewer dapat membaca Dashboard/Endpoint Audit/Agent & Upload dan **menambah atau mengubah endpoint** (hasil upload/scan), tetapi tidak dapat menghapus endpoint, membuka Audit Log, atau mengelola hardening.
5. Untuk kembali, keluar lalu masuk menggunakan akun admin.

Endpoint pusat disimpan di `PASOPATI_DATA_DIR/endpoint_inventory.json`. Set `PASOPATI_DATA_DIR` eksplisit (mis. `C:\Apps\PASOPATI\data`) agar lokasi data tidak bergantung direktori kerja. Backup folder `data` sebelum rilis; jangan menyalin `data` dari staging.

Password disimpan sebagai hash scrypt di `data/auth.sqlite`. Browser menerima cookie sesi `HttpOnly`, `SameSite=Lax` yang kedaluwarsa setelah 12 jam; password dan token sesi tidak disimpan di `localStorage`. API key/HMAC tetap digunakan oleh integrasi agen/backend lama, bukan sebagai login UI. Pengaturan env bootstrap hanya membuat akun saat pertama kali; mengubah env setelahnya tidak otomatis mengganti akun yang sudah tersimpan.

Untuk production, cookie sesi ditandai `Secure`; akses dashboard wajib melalui HTTPS. Pengujian laptop dengan `npm run dev` dapat memakai HTTP localhost.

Build dan test:
```bash
npm run build
npm test
```

## 4. Menjalankan Field Console (opsional)

```bash
python3 -m pip install -r requirements.txt
PASOPATI_DOWNLOAD_PASSWORD='<password>' python3 -m streamlit run app.py
```

## 5. Uji otomatis

```bash
npm test
```

Berjalan di Linux, WSL, dan Windows (Python dipilih otomatis; `bash -n` lewat stdin;
2 uji berbasis chmod di-skip di Windows; `test:elevation` SKIP tanpa `unshare`).

Mencakup lint/ESLint, smoke kontrol plane, expiry token, unit agent + SSH/UFW,
cakupan skrip, generator app.py, redaksi OPSEC, elevasi nyata, serta auth smoke
untuk login username/password, cookie sesi, RBAC admin/viewer, dan logout.

## 6. Uji di laptop Windows

Ikuti `docs/WINDOWS-TEST-PLAYBOOK.md`. Ringkas:

1. Di mesin server (PowerShell Admin): `setup-lan.ps1`, catat IPv4 Wi-Fi.
2. Di laptop target: unduh kedua skrip agent, jalankan audit `--no-elevate`, unggah JSON.
3. Buat plan, approve, jalankan `--no-exec`, lalu eksekusi.

## 7. Struktur penting

- `server.ts` — kontrol plane Express + HMAC + remediasi
- `src/` — UI React
- `pasopati_audit.py` — mesin audit + eksekusi remediasi
- `pasopati_remediate.py` — entry script perbaikan
- `app.py` — Field Console Streamlit
- `tests/` — seluruh test
- `docs/` — proposal, desain, playbook, laporan audit & uji
- `data/` — state runtime (plan, audit log, kuarantina)

## 8. Batasan yang masih terbuka

TLS/mTLS, database transaksional, antrean per host, dan penandatanganan artefak
agent belum diimplementasikan. RBAC operator berbasis API key tersedia; gunakan
HTTPS saat mengakses dari jaringan selain loopback. Lihat `docs/AUDIT-2026-11-13.md`
dan `docs/RESEARCH-LOG-2026-11-12.md` §8.

## 9. Keamanan arsip

- `.env` dibuat lokal dari `.env.example` dan tidak dimasukkan ke arsip source ini.
- Rotasi `PASOPATI_API_KEY`, `HMAC_SECRET`, atau `GEMINI_API_KEY` jika pernah dibagikan di luar lingkungan uji.
- Jangan unggah file `.env` atau kredensial ke repositori publik.
