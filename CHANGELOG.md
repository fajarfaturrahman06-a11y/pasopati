# Changelog

## v2.6.1 — 13 Nov 2026

Perbaikan hasil audit menyeluruh (rendah → tinggi), dengan uji per tahap.

### Diperbaiki
- Live scan berjalan tanpa TTY (tidak lagi bergantung `sudo` interaktif).
- Model AI cloud dikoreksi; AI tidak lagi selalu 403.
- ZIP mengecualikan `.git`, `dist`, `node_modules`, dan rahasia hidup.
- Redaksi OPSEC mencakup IPv6, MAC bertitik, dan hostname satu label.
- SSH menghormati `sshd_config.d`, divalidasi `sshd -t`, verify `sshd -T`.
- UFW mengizinkan SSH dan menegakkan default deny sebelum enable.
- Ingest anti-replay, unit `__proto__`, evidence HMAC, audit log remediasi.
- Tulis JSON atomik, retensi plan/nonce, permission backup, `TRUST_PROXY`.
- `strict` TypeScript, ESLint + react-hooks, CI, LICENSE, audit npm 0.

## v2.6.0 — 12 Nov 2026

### Ditambahkan
- Rebranding penuh **SATRIA-GUARD → PASOPATI** (Protokol Audit Sistem & Operasi
  Pengamanan Agen TI) beserta logo resmi di `public/pasopati.jpeg` dan
  `public/pasopati-mark.png`.
- Dashboard baru bergaya command center: sidebar navigasi, topbar dengan pencarian
  endpoint, empat kartu KPI, grafik temuan per endpoint, tren kesiapan armada,
  tabel aktivitas terbaru, dan daftar status armada.
- `README` menampilkan logo dan identitas baru.

### Diubah
- Script CLI diganti nama: `pasopati_audit.py` (pemeriksaan) dan
  `pasopati_remediate.py` (perbaikan). Endpoint lama tetap dilayani
  sebagai alias.
- ZIP proyek menjadi `pasopati-project.zip`; paket npm menjadi `pasopati@2.6.0`.
- Palet UI React dan Streamlit diselaraskan ke tema gelap + crimson/gold.

### Diperbaiki
- CSS `app.py` dipindahkan ke `assets/pasopati.css` sehingga `app.py` turun
  sekitar 180 baris dan lebih mudah dirawat.

## v2.5.1 — 12 Nov 2026

### Diubah
- **Script dipisah berdasarkan fungsi** (tidak lagi satu nama `pasopati_audit.py`):
  - `pasopati_audit.py` — mesin pemeriksaan/audit, menulis `audit.json`, mengirim telemetri.
  - `pasopati_remediate.py` — script perbaikan; memakai `pasopati_audit.py` sebagai pustaka dan
    mengeksekusi plan yang disetujui (termasuk `--server`/`--plan-id`, `--demo`, `--quarantine`).
- Endpoint unduhan: `/api/download/pasopati_audit.py` dan `/api/download/pasopati_remediate.py`.
  Nama lama `/api/download/pasopati_audit.py` tetap dilayani (alias ke `pasopati_audit.py`).
- UI, README, dan komentar server memakai nama script yang benar sesuai konteks
  (audit vs perbaikan).
- Target remediasi kini butuh **dua** file: `pasopati_remediate.py` + `pasopati_audit.py`.

### Diperbaiki
- Audit port menilai port terekspos hanya bila tidak diblokir firewall
  (Windows: rule `PASOPATI-Block-<port>`; Linux: rule iptables DROP).
- BitLocker mendukung mesin tanpa TPM (`PasswordProtector`) dan memakai cmdlet
  PowerShell murni (bukan `manage-bde` yang bisa salah kode di build lama).

## v2.5.0 — 12 Nov 2026
Perbaikan menyeluruh + satu jalur hardening/remediasi.

### Ditambahkan
- Change set tunggal: langkah **enforce** (otomatis, verifikasi, rollback) + **advisory** (read-only) dalam satu plan.
- Alias enforce: `ports-block-linux`, `ports-block-windows`; advisory: `advisory-fde`, `advisory-rootkit`, `advisory-secureboot`, `advisory-admins`.
- Elevasi otomatis `sudo -E`/`pkexec`/UAC untuk agent dan semua script; `--no-elevate` tersedia.
- Output default `audit.json` (atomik) + blok `execution` dan riwayat 100 run.
- `GET /api/quarantine`, `GET /api/compliance-drift/:unitId`, paginasi audit log.
- Uji: smoke, expiry, agent, scripts, app, elevation (`npm test`).

### Diperbaiki
- Server mati oleh body JSON cacat; validasi input AI.
- `plan.json` rusak setelah refresh; plan macet saat token kedaluwarsa; evidence hilang tanpa `--push-url`.
- Rollback palsu/destruktif; hash evidence salah; backup bertabrakan.
- Karantina write-only, aksi telemetri salah label, `N/A` merusak skor, OPSEC berlebih.
- Audit log terpotong diam-diam, ZIP balapan/kehilangan `.env.example`, CSP font.
- Bug audit agent (BitLocker/sudoers/USB Windows), scan port false-negative.
- Timer/interval bocor, `res.ok` tidak dicek, field upload tanpa batas.

### Diubah
- Tab “AI Hardening” + “Remediation” → satu tab **Hardening & Remediation** dengan alur 2a change set → 2b runbook → 2c approve/eksekusi.
- Tombol simulasi terpisah dihapus; skrip dirender dari item terpilih.
- Versi paket 2.4.0 → 2.5.0.

Lihat `docs/RESEARCH-LOG-2026-11-12.md` untuk analisis, bukti, dan sisa pekerjaan.
