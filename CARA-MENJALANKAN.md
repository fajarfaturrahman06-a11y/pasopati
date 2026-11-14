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

Arsip ini **menyertakan `.env` berisi kunci hidup**. Ganti/rotasi bila arsip dibagikan lebih luas.

```bash
cp .env.example .env   # bila ingin mulai dari template
```

Isi minimum:

- `PASOPATI_API_KEY` — min. 32 karakter acak (header `X-Pasopati-API-Key`)
- `HMAC_SECRET` — min. 32 karakter acak (tanda tangan telemetri & evidence)
- `GEMINI_API_KEY` / `GEMINI_BASE_URL` / `AI_MODEL_NAME` — opsional; tanpa ini AI memakai rule-based

Nilai acak bisa dibuat dengan:

```bash
openssl rand -hex 32
```

## 3. Menjalankan Command Center

```bash
npm install
npm run dev
```

Buka `http://localhost:3000`.

Produksi:

```bash
npm run build
npm start
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

Mencakup lint/ESLint, smoke kontrol plane, expiry token, unit agent + SSH/UFW,
cakupan skrip, generator app.py, redaksi OPSEC, dan elevasi nyata.

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

TLS/mTLS, RBAC multi-operator, database transaksional, antrean per host, dan
penandatanganan artefak agent belum diimplementasikan. Lihat `docs/AUDIT-2026-11-13.md`
dan `docs/RESEARCH-LOG-2026-11-12.md` §8.

## 9. Keamanan arsip

- `.env`, `opencode.json`, `reapprove.ps1`, `token.txt`, dan `bitlocker-recovery-NIKO.txt` **disertakan**.
- Rotasi `PASOPATI_API_KEY`, `HMAC_SECRET`, dan `GEMINI_API_KEY` setelah review selesai.
- Jangan unggah arsip ini ke repositori publik tanpa mengganti kunci.
