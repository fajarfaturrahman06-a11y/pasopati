PASOPATI v2.9.6
Protokol Audit Sistem & Operasi Pengamanan Agen TI
Remediasi Taktis - Akurat - Aman

Repositori : https://github.com/fajarfaturrahman06-a11y/pasopati
Riwayat    : CHANGELOG.md
Acuan      : CIS Benchmark v8.0, DISA STIG, ISA/IEC 62443

DISCLAIMER
PASOPATI adalah purwarupa penelitian independen, bukan sistem kedinasan resmi.
Nama satuan dan data simulasi dipakai untuk demonstrasi.

===============================================================================
1. RINGKASAN
===============================================================================
PASOPATI adalah konsol audit kepatuhan dan remediasi terpandu:
- Audit host terhadap baseline CIS/STIG/IEC 62443 lewat agent CLI.
- Satu registry endpoint di server; semua browser melihat data yang sama.
- Runbook hardening + rollback terikat plan dan ber-hash.
- Remediasi lewat agent (terverifikasi, dead-man rollback) atau manual.

Server TIDAK mengubah host tanpa agent. Server hanya mengelola plan, token, bukti.

===============================================================================
2. PRASYARAT
===============================================================================
- Node.js 22+ dan npm 10+
- Python 3.10+ di host target
- PowerShell Administrator (Windows) atau root (Linux)
- Sertifikat TLS untuk produksi

Hanya satu server per direktori data. File .server.lock menolak instance kedua.

===============================================================================
3. INSTALASI
===============================================================================
git clone https://github.com/fajarfaturrahman06-a11y/pasopati.git
cd pasopati
npm install
cp .env.example .env

Isi .env lokal (jangan commit):
- PASOPATI_ADMIN_USERNAME / PASOPATI_ADMIN_PASSWORD (min 12 karakter)
- HMAC_SECRET (acak min 32 karakter, untuk agent)
- PASOPATI_API_KEY (acak min 32 karakter, untuk integrasi agent)
- PASOPATI_DATA_DIR (produksi: WAJIB absolut, mis. C:\Apps\PASOPATI\data)
- GEMINI_API_KEY / GEMINI_BASE_URL / AI_MODEL_NAME (opsional)
- TLS_CERT / TLS_KEY (produksi)

Jangan menjalankan server dari C:\Windows\System32. Selalu Set-Location ke folder
proyek dan set PASOPATI_DATA_DIR absolut.

===============================================================================
4. MENJALANKAN
===============================================================================
npm run dev
# atau
npm run build
npm start

Buka http://localhost:3000
Log awal harus memuat "[PASOPATI] DATA_DIR: ..." dan "server running at ...".

===============================================================================
5. LOGIN DAN ROLE
===============================================================================
Login memakai username/password. Cookie sesi HttpOnly, SameSite=Lax, 12 jam.
Password disimpan sebagai hash scrypt.

Role:
- viewer   : Dashboard, Endpoint Audit, Agent & Upload; baca + tambah/ubah endpoint
- planner  : viewer + buat plan + waiver
- approver : approve plan, hapus waiver
- executor : kirim evidence, karantina, scan host
- admin    : semua, termasuk hapus endpoint, kelola user, Audit Log & aktivitas

Membuat user uji: login admin -> sidebar BUAT USER UJI -> isi username/password
(min 12) -> catat -> keluar -> login sebagai user itu.

===============================================================================
6. ALUR LENGKAP: AUDIT -> HARDENING TERVERIFIKASI
===============================================================================
6.1 AUDIT HOST
1. Tab Agent & Upload -> unduh pasopati_audit.py dan pasopati_remediate.py
   (dua file, simpan dalam satu folder).
2. Di host target, terminal Administrator/root:
   python pasopati_audit.py -u "NAMA-UNIT" --push-url "http://<SERVER>:3000/api/ingest" --hmac-key "<HMAC_SECRET>"
   Tanpa --push-url, hasil hanya lokal di audit.json dan bisa diunggah lewat UI.
3. Hasil masuk registry pusat; audit ulang di dashboard.

6.2 PILIH TEMUAN
1. Endpoint Audit -> pilih perangkat -> Remediasi AI.
2. Langkah 1: centang temuan. Wajib minimal satu enforce; advisory boleh ikut.
3. Langkah 2: tinjau pratinjau hardening dan rollback.

6.3 BUAT PLAN DAN KIRIM SCRIPT
1. Langkah 3: pilih mode agent.
2. Opsional ikat ke host ter-enrol.
3. Jika plan menyentuh SSH/firewall/RDP: siapkan konsol/KVM lalu centang konfirmasi.
4. BUAT PLAN.
5. Isi API key dan HMAC key -> klik SIMPAN & KIRIM SCRIPT KE ENDPOINT.
   Script muncul di tab Endpoint Audit untuk host tersebut (menunggu approve).
6. APPROVE PLAN (operator lain; jika Anda pembuatnya centang "setujui sendiri").
   Token tampil sekali, berlaku 10 menit.
7. Jika ada plan aktif lain di host: selesaikan/rollback, atau APPROVE PAKSA.

6.4 JALANKAN DI HOST
Host (viewer/executor) membuka Endpoint Audit pada endpoint tersebut.
Kotak hijau plan ter-approve menyediakan unduhan .ps1 / .sh / plan.json.
Kunci sudah terisi; jalankan sebagai Administrator/root.
Script memakai --no-exec (uji aman). Untuk eksekusi nyata, hapus --no-exec.

Contoh perintah manual:
  python pasopati_remediate.py --server "http://<SERVER>:3000" --plan-id "PLAN-..." --remediate-api-key "<PASOPATI_API_KEY>" --hmac-key "<HMAC_SECRET>" --no-exec

Tambahkan --force-access-risk bila plan menyentuh jalur akses.
Dead-man aktif: tanpa konfirmasi dalam 10 menit, host di-rollback otomatis.

6.5 VERIFIKASI
1. Agent mengirim evidence dan audit ulang.
2. Kembali ke panel -> REFRESH. Status VERIFIED, badge TERVERIFIKASI NYATA.
3. Endpoint Audit menampilkan temuan berubah (mis. UAC/firewall PASS).
4. Audit Log mencatat HARDENING REMEDIATION.

Status akhir: VERIFIED, ROLLED_BACK, FAILED, MANUAL_REPORTED.

===============================================================================
7. JALUR MANUAL (TANPA AGENT)
===============================================================================
1. Langkah 1-2 sama; Langkah 3 pilih mode manual.
2. BUAT PLAN -> approve. Runbook resmi ber-hash tersedia di Langkah 2.
3. Unduh hardening + rollback resmi; uji dengan --dry-run / -DryRun.
4. Jalankan, centang semua langkah, klik KIRIM LAPORAN MANUAL.
   Status: MANUAL_REPORTED (self-reported).
5. VERIFIED hanya setelah audit ulang dan pengiriman postAudit.

===============================================================================
8. REGISTRY ENDPOINT
===============================================================================
- Sumber data: PASOPATI_DATA_DIR/endpoint_inventory.json
- Semua browser memakai GET /api/endpoints + polling 5 detik.
- Tambah/ubah: POST/PUT; jika identitas sudah ada, expected_revision wajib
  (428 bila kosong, 409 bila basi). Setiap perubahan menaikkan revision.
- Hapus = arsip lunak (admin).
- Identitas agent: UUID mesin (metadata.machine_id), bukan nama unit.
- Unduhan artefak dan scan realtime dicatat untuk admin di
  Endpoint Audit -> Aktivitas & Akses.

Uji dua browser: tambah di A -> B melihat <=5 detik; ubah di B -> A kena 409
bila form lama; hapus di A -> hilang di B.

===============================================================================
9. WAIVER, KARANTINA, AUDIT TRAIL
===============================================================================
- Waiver (planner): temuan dikecualikan dari skor sampai kedaluwarsa.
- Karantina (executor): hanya menandai registry; pemutusan nyata oleh agent.
- Audit Log (admin): hash chain SHA-256, soft delete, verifikasi rantai.
- Aktivitas & Akses (admin): akses/kondisi endpoint, unduhan, scan realtime.

===============================================================================
10. TELEMETRI AGENT (HMAC)
===============================================================================
POST /api/ingest memverifikasi HMAC atas body mentah + timestamp (5 menit) dan
anti-replay. Payload membawa metadata.machine_id (UUID persisten). Upsert menjaga
satu endpoint per mesin; retry tidak menduplikasi history. Jika audit gagal
ditulis, endpoint dipulihkan dan ingest menjawab 500; kirim ulang.

===============================================================================
11. MODE DEMO VS SERVER
===============================================================================
- Sebelum login: data mock (mode demo).
- Setelah login: registry server; mock tidak menimpa.
- Sesi kedaluwarsa: kembali ke layar login.
- Server tak terjangkau: data terakhir dipertahankan, status offline.

===============================================================================
12. KEAMANAN
===============================================================================
- Password scrypt; token sesi hash; cookie HttpOnly; write butuh Origin (CSRF).
- API key/HMAC hanya di .env server; UI tidak menyimpannya permanen.
- Revisi mencegah lost update; plan butuh approve + token + nonce anti-replay.
- Tulis file state atomik (temp + fsync + rename retry).
- Kredensial yang dikirim ke plan tersimpan di data/remediation_artifacts
  (plaintext, sejajar .env); rotasi bila bocor.
- TLS wajib sebelum akses publik.

===============================================================================
13. TROUBLESHOOTING
===============================================================================
DATA_DIR dipakai proses lain    : hentikan proses lama; hapus .server.lock
                                  hanya setelah PID dipastikan mati
Halaman kosong                  : npm run build; cek console & log server
401 di agent                    : API key salah/placeholder; isi nilai asli
401 Nonce                       : token kedaluwarsa/terpakai; terbitkan ulang
409 approve                     : plan aktif lain; selesaikan/rollback/APPROVE PAKSA
Tombol APPROVE nonaktif         : belum self-approve / konfirmasi konsol
Artefak 404                     : plan lama tanpa artefak; buat plan baru
413                             : payload > 1 MB; kecilkan matrix
Log UAC hilang                  : UAC dibatalkan; jalankan PowerShell Admin
EACCES port                     : port dieksklusikan Windows; pakai port lain

===============================================================================
14. DEPLOYMENT VPS WINDOWS
===============================================================================
Ikuti DEPLOYMENT-VPS-WINDOWS-SERVER-2022.md. Ringkas:
1. deploy/check-vps-readonly.ps1 (read-only) - periksa proses/port/task/DATA_DIR.
2. Supervisor yang ada wajib Set-Location 'C:\Apps\PASOPATI' dan
   $env:PASOPATI_DATA_DIR='C:\Apps\PASOPATI\data'. Jangan buat supervisor kedua.
3. Backup data + .env; staging npm ci && npm run lint && npm run build.
4. Hentikan task, pastikan node.exe mati, salin rilis (kecualikan data, .env,
   .server.lock), start task yang sama.
5. Verifikasi 401 tanpa sesi, dua browser, lalu pasang HTTPS.

===============================================================================
15. BACKUP, RESTORE, ROLLBACK
===============================================================================
robocopy 'C:\Apps\PASOPATI\data' "C:\Backups\PASOPATI\<stamp>\data" /E /COPY:DAT
icacls "C:\Backups\PASOPATI\<stamp>" /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F"

Restore: hentikan task -> salin balik data -> start task.
Rollback rilis: pulihkan source dari backup; data hanya bila perlu.

===============================================================================
16. PENGUJIAN
===============================================================================
npm test

Mencakup lint, smoke kontrol plane, auth, RBAC, registry, audit endpoint,
expiry, runner, atomic write, agent, cakupan skrip, app.py, redaksi, elevasi.

===============================================================================
17. STRUKTUR
===============================================================================
server.ts                  Kontrol plane Express
src/                       UI React + util
src/data/mockDevices.ts    Fixture demo + skor
pasopati_audit.py          Mesin audit + telemetri
pasopati_remediate.py      Eksekutor plan
app.py                     Field Console Streamlit (deprecated)
profiles/                  Profil kontrol deklaratif
deploy/                    Unit layanan, contoh supervisor, cek VPS
tests/                     Pengujian
docs/                      Proposal, desain, playbook
data/                      State runtime (di-ignore)

===============================================================================
18. DOKUMEN
===============================================================================
CARA-MENJALANKAN.md
docs/UJI-BATCH.md
docs/ENDPOINT-HEALTH-AUDIT.md
docs/AUDIT-2026-11-13.md
docs/AUDIT-2026-11-14.md
docs/WINDOWS-TEST-PLAYBOOK.md
docs/WINDOWS-UJI-LAN.md
IMPLEMENTATION-REPORT.md
CHANGELOG.md
CHECKPOINT.md
