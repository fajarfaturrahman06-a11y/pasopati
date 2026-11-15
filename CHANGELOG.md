# Changelog

## Perbaikan Windows EPERM pada atomic write — 15 Nov 2026

### Diperbaiki
- `writeJsonAtomic` (`server.ts`) dan `writeEndpointRecords` (`src/endpointStore.ts`) memakai helper bersama `src/atomicWrite.ts` yang me-retry rename **hanya** untuk `EPERM`/`EACCES`/`EBUSY` dengan backoff terbatas (maks 6 percobaan / ~2 detik).
- Error permanen (`ENOENT`, `ENOSPC`, dll.) langsung dilempar tanpa retry. File tujuan tidak dihapus sebelum rename; tidak ada fallback copy+delete.
- Temp unik + `fsync` file + close + rename + `fsync` direktori tetap dipertahankan; temp dibersihkan bila semua percobaan gagal dan file tujuan lama tetap utuh.
- Helper Python `_atomic_replace` diterapkan pada 5 `os.replace` di `pasopati_audit.py` untuk masalah yang sama di Windows.

### Diuji
- Regression `tests/atomic-write.mjs` (6 kasus): retry sementara, error permanen, retry habis + tujuan utuh + temp bersih, writer registry memakai jalur yang sama.
- Unit Python: retry sementara, error permanen, gagal total tidak menghapus tujuan.
- `test:endpoints` dijalankan dua kali berturut-turut di Windows: 27/27 dan 27/27.

### Catatan race
- Tidak ada perubahan pada `.server.lock`. Semua read-modify-write audit/registry tetap sinkron dalam satu event loop; tidak ada `await` di antaranya. Retry hanya membungkus syscall rename, bukan transaksi.

## Perbaikan registry pusat pasca-audit — 15 Nov 2026

Pengerasan konsistensi data, integritas audit, dan kesiapan VPS. Tanpa perubahan
framework dan tanpa deploy otomatis.

### Diperbaiki
- `POST /api/endpoints` pada identitas yang sudah ada kini **wajib** `expected_revision`
  (`428` bila kosong, `409` bila basi) dan selalu menaikkan `revision`; tidak ada lagi
  timpa-menimpa diam-diam.
- Upload/scan dari UI memakai `PUT` + `expected_revision` bila endpoint sudah ada
  (retry sekali setelah sinkron pada konflik). Endpoint baru memakai `POST`.
- Waiver status kini dikelola backend dan ditempelkan pada `GET /api/endpoints` serta
  `GET /api/endpoints/:id`, sehingga polling 5 detik tidak menghapus `WAIVED`.
  Perubahan waiver ditulis ke audit trail secara strict.
- Identitas agen memakai `metadata.machine_id` (UUID persisten di sisi agen), bukan
  `tactical_unit`. Dua mesin dengan unit sama tetap menjadi dua endpoint. Agen lama
  tanpa `machine_id` tetap kompatibel; migrasi terjadi saat identitas MAC/hostname cocok.
- Audit log dibaca **strict** untuk operasi tulis endpoint/waiver. File audit korup
  menggagalkan operasi dengan `500`, registry dikembalikan ke kondisi sebelumnya, dan
  chain lama tidak di-seal ulang.
- Ingest telemetri: registry ditulis → audit strict → signature dicatat. Jika audit gagal,
  endpoint dipulihkan dan respons `500`; retry tidak menduplikasi record.
- Penulisan registry memakai `fsync` file + best-effort `fsync` direktori sebelum/sesudah
  rename atomik; kegagalan tulis tidak dianggap sukses.
- UI upload menunggu konfirmasi server sebelum menampilkan hasil; ada indikator proses
  dan error yang jelas. Jendela mock pada login dihapus; data mock tidak lagi menimpa
  tampilan setelah sesi aktif.
- `DATA_DIR` dicetak saat start; ada peringatan bila server berjalan dari `System32`
  tanpa `PASOPATI_DATA_DIR`.

### Ditambah
- `deploy/check-vps-readonly.ps1` — pemeriksaan proses, port, task, DATA_DIR, dan registry
  tanpa mengubah apa pun dan tanpa mencetak secret.
- `deploy/start-pasopati.example.ps1` — contoh supervisor dengan `Set-Location` dan
  `PASOPATI_DATA_DIR` eksplisit (task yang ada tetap dipakai).
- Regression test: wajib revisi pada POST upsert, waiver persist + audit, dua mesin dengan
  unit sama, audit korup + pemulihan, operasi sah/tidak sah per role.

### Diubah
- Izin tulis endpoint: `viewer` boleh `POST`/`PUT` (kebutuhan upload hasil audit),
  `DELETE` tetap `admin`, waiver `planner`, karantina `executor`. Rasional dan risiko
  dicatat di `IMPLEMENTATION-REPORT.md`.

### Kompatibilitas
- File JSON lama dimigrasikan otomatis saat dibaca (tanpa menghapus data). Endpoint lama
  tanpa `machine_id` tetap ada dan dicocokkan lewat MAC/hostname; tidak digabung hanya
  karena `tactical_unit` sama.

## v2.9.6 — 14 Nov 2026

Perbaikan dari uji lapangan Batch D kelima: volume terenkripsi tapi tidak bisa
dibuka saat boot.

### Diperbaiki
- Password boot BitLocker kini **angka saja** (20 digit, `_win_bitlocker_boot_password()`).
  Sebelumnya memakai `secrets.token_urlsafe(18)` yang bisa berisi `_` dan `-`;
  layar pre-boot memakai layout keyboard dasar sehingga karakter itu sering
  tidak bisa diketik. Kasus lapangan: password `2BvdD5V145hBI8Dwj05h_ZfV`
  ditolak di layar "Enter the password to unlock this drive".
- Password numerik dipakai konsisten untuk `PasswordProtector` baru maupun
  protector tambahan saat resume.

### Ditambah
- 2 regression test: password boot hanya angka dan generator selalu 20 digit.

### Fitur terpisah: Audit Akses & Kondisi Endpoint
- Ditambahkan database SQLite khusus `data/endpoint_health_audit.sqlite`, API admin-only, dan menu UI terpisah dari `Audit Log`.
- Data `endpoint_health_audit.json` dari versi sebelumnya diimpor satu kali sebagai rekaman SQLite; file JSON asal tetap disimpan sebagai cadangan.
- Admin dapat merekam siapa yang mengakses endpoint dan snapshot kondisi komputer; approval remediasi yang berhasil otomatis merekam approver, pengguna endpoint, dan kondisi pada saat persetujuan.
- Audit Log lama (API, file, RBAC, hash chain, dan UI) tidak diubah.
- Ditambahkan smoke test integrasi untuk RBAC, snapshot, approval, restart backend, dan isolasi Audit Log lama.

## v2.9.5 — 14 Nov 2026

Perbaikan dari percobaan Batch D keempat (agent v2.9.4).

### Diperbaiki
- `ProtectionStatus` memang bisa `Off` **selama konversi BitLocker berjalan**
  (Windows baru menyalakannya setelah enkripsi selesai/reboot). v2.9.4
  menganggap `pct=1, proteksi=False` sebagai kegagalan lalu me-rollback
  enkripsi yang sebenarnya sudah berjalan.
- Keberhasilan kini dinilai lewat `_win_bitlocker_ok()`: proteksi `On`,
  volume `FullyEncrypted`, **atau** enkripsi berjalan (`pct>0`) dengan
  protector aman (`Password`/`RecoveryPassword`/`Tpm`). `DecryptionInProgress`
  tidak pernah dianggap sukses.
- `verify` dan audit pasca-remediasi memakai aturan yang sama; enkripsi
  berjalan dilaporkan `WARNING` (bukan `FAIL`) agar `VERIFIED` tetap sah.
- `Enable-BitLocker` yang gagal setelah `PasswordProtector` terpasang kini
  tetap mengembalikan `bootPassword` — password acak tidak pernah hilang.
- Run lanjutan saat enkripsi sudah berjalan tidak menerbitkan password baru;
  cukup `Resume-BitLocker` dan laporkan state sebenarnya.
- Rollback menghapus `Password` protector acak yang dibuat remediasi
  (setelah `manage-bde -off`) bila sebelumnya tidak ada; `RecoveryPassword`
  yang sudah di-escrow dibiarkan.
- State BitLocker menyertakan `volumeStatus` untuk membedakan enkripsi dan
  dekripsi yang berjalan.

### Ditambah
- 5 regression test: enkripsi berjalan = sukses, dekripsi = bukan sukses,
  enkripsi tanpa protector = bukan sukses, `bootPassword` tetap dilaporkan
  saat gagal, dan rollback menghapus password acak.

## v2.9.4 — 14 Nov 2026

Perbaikan dari percobaan Batch D ketiga (agent v2.9.3).

### Diperbaiki
- `Enable-BitLocker` kembali **sebelum** status volume ter-update, sehingga
  pembacaan langsung menghasilkan `protectionOn=false, encrypted=false` dan
  plan dianggap gagal padahal enkripsi sudah mulai. Agent kini menunggu
  (maks 120 dtk, cek tiap 5 dtk) sampai `ProtectionStatus=On` atau
  `EncryptionPercentage > 0`.
- State BitLocker menyertakan `encryptionPercentage`; pesan gagal memuat
  persentase + cuplikan mentah untuk diagnosis.
- Recovery key yang sudah terlanjur dibuat tetap disimpan/di-escrow walau
  langkah dinyatakan gagal, agar tidak ada kunci yang hilang.

## v2.9.3 — 14 Nov 2026

Perbaikan lanjutan dari uji lapangan Batch D (Windows 11 Pro tanpa TPM).

### Diperbaiki
- `bitlocker-enable` pada volume OS tanpa TPM:
  - v2.9.2 gagal `0x8028400F` (TPM tidak ditemukan) → policy FVE dipasang.
  - v2.9.2 dengan keempat opsi TPM `Do not allow` gagal `0x8031005B`
    ("startup options in conflict"). Sekarang keempat opsi diset **Allow (2)**,
    sesuai panduan NSA/Microsoft: semua Allow, atau satu Require + tiga Do not allow.
  - Retry `gpupdate /force` + satu percobaan ulang untuk `0x8028400F` dan `0x8031005B`.
- Pre-state BitLocker menyertakan snapshot policy FVE; rollback mengembalikan
  nilai policy ke kondisi semula (nilai yang sebelumnya tidak ada akan dihapus).
- Folder `~/.pasopati/backups` diberi ACL eksplisit (`icacls`) agar recovery key
  dan boot password bisa dibaca operator setelah proses elevated.
- `audit_endpoint_protection()` membaca USBSTOR lewat `_win_usbstor_state()`
  (fungsi yang sama dengan remediasi). Sebelumnya `subprocess.run()` di-unpack
  sebagai tuple sehingga selalu `TypeError` → status USB selalu `WARNING`
  meskipun `Start=4`.

### Ditambah
- Regression test: policy FVE hanya dipasang saat tanpa TPM, keempat opsi TPM
  bernilai Allow, policy tidak disentuh saat TPM ada, rollback memulihkan
  policy, dan audit USB mengikuti nilai registry sebenarnya.

## v2.9.2 — 14 Nov 2026

Percobaan pertama perbaikan BitLocker tanpa TPM. **Digantikan v2.9.3**: policy
`UseTPM*=0` ternyata memicu `0x8031005B`, jadi nilai diubah menjadi Allow.

### Diperbaiki
- `bitlocker-enable` gagal `0x8028400F` pada volume OS tanpa TPM: agent memasang
  policy `HKLM\SOFTWARE\Policies\Microsoft\FVE` sebelum `Enable-BitLocker`.
- Pre-state BitLocker menyertakan snapshot policy FVE; rollback memulihkannya.
- `audit_endpoint_protection()` membaca USBSTOR lewat `_win_usbstor_state()`.
  Sebelumnya `subprocess.run()` di-unpack sebagai tuple sehingga selalu
  `TypeError` → status USB selalu `WARNING` meskipun `Start=4`.

## v2.9.1 — 14 Nov 2026

Dukungan **uji lengkap per batch**, dengan **Linux dan Windows dipisah**.

### Ditambah
- `docs/UJI-BATCH.md`: panduan batch Windows (A–E) dan Linux (L1–L3) terpisah,
  termasuk perintah target untuk masing-masing OS.
- `docs/run-lan-server.ps1` menerima `-Batch A..E` (Windows) dan `-Batch L1..L3`
  (Linux), plus `-Aliases` untuk kombinasi bebas.
- `-ListAliases` mencetak alias per OS dari peta risiko yang sama dengan agent.
- Agent menerima `--list-aliases` (tanpa elevasi) yang membaca `ALLOWLIST_ANALISA`
  sebagai sumber tunggal: 8 alias Windows, 8 alias Linux, 4 advisory `any`.
- `-HostId` + `-HostKey` untuk **memakai ulang host** yang sudah ter-enrol: batch
  berikutnya tidak membuat host baru, dan kunci diverifikasi lewat `/api/whoami`.

### Diubah
- Satu plan **wajib satu OS** (+ advisory `any`). Campuran Windows+Linux ditolak
  sebelum host di-enrol, dengan pesan yang memisahkan daftar per OS.
- Token approval dicetak dari `expiresAt` server (bukan asumsi 10 menit).
- Batch A (atau batch pertama) butuh Administrator; batch berikutnya cukup
  PowerShell biasa bila aturan firewall sudah ada.
- Output skrip server berbeda per OS: Windows memakai `run-windows-test.ps1`,
  Linux memakai `pasopati_remediate.py` langsung (dry-run + eksekusi).

### Diperbaiki
- Skrip tidak lagi menyarankan approve ulang plan lama saat token masih hidup
  (server memang menolaknya); diganti dengan membuat plan baru memakai host yang sama.
- Validasi alias/OS dijalankan **sebelum** enrol host agar tidak meninggalkan host yatim.

## v2.9.0 — 14 Nov 2026

Penyeragaman identitas PASOPATI dan penyegaran tampilan.

### Diubah
- **Semua penyebutan nama lama dihapus** dari kode, tes, skrip, dokumen, dan contoh
  konfigurasi. Rename ikut identifier (bukan hanya teks):
  - `PASOPATI_API_KEY`, header `X-Pasopati-API-Key` / `X-Pasopati-Signature` /
    `X-Pasopati-Timestamp` / `X-Pasopati-Unit`.
  - `PASOPATI_ELEVATED`, `PASOPATI_DATA_DIR`, `PASOPATI_DOWNLOAD_PASSWORD`,
    rule firewall `PASOPATI-Block-*`, state `/var/lib/pasopati/state`,
    `/etc/modprobe.d/pasopati-usb-lock.conf`, backup `*.pasopati.bak`.
  - Nama laporan `pasopati_hardening_*` / `pasopati_rollback_*`.
- `.env` dan `.env.example` memakai `PASOPATI_API_KEY` (tanpa fallback nama lama).
- Aksen utama UI menjadi **rose** (mengikuti desain terbaru): judul, ikon, tombol
  primer, dan panel aksi memakai `rose-600`; teks tombol `text-white`.
  Hijau (`emerald`) dipertahankan khusus status PASS/VERIFIED/sukses.

### Diperbaiki
- Rute unduh duplikat dibersihkan; `/api/download/pasopati_agent.py` tetap alias
  menuju `pasopati_audit.py`.
- `reapprove.ps1` tidak lagi menyimpan API key di file: membaca `PASOPATI_API_KEY`
  dari `.env`, dan menerima `-PlanId`.

### Catatan kompatibilitas
- Deployment lama **wajib** mengganti env/header/rule ke nama `PASOPATI_*`.
  Rule firewall atau marker elevasi bernama lama tidak lagi dikenali otomatis.
- `npm test` hijau: 83/83 smoke, 5/5 expiry, agent 57 (2 skip Windows), 68/68
  scripts, 5/5 app, 11/11 redaction.

## v2.8.3 — 14 Nov 2026

### Diperbaiki
- `run-lan-server.ps1` memilih adapter Wi-Fi (bukan Ethernet4/VMnet) dan memperingatkan
  bila ada beberapa adapter aktif — IP yang dicetak tidak lagi salah.



## v2.8.2 — 14 Nov 2026

Dukungan uji dari laptop lain (LAN) dengan kredensial host saja.

### Ditambahkan
- `docs/run-lan-server.ps1`: aturan firewall khusus LocalSubnet, enrol host, buat+approve
  plan terikat, cetak perintah target; `-Remove` untuk bersih-bersih.
- `docs/WINDOWS-UJI-LAN.md` (alur, isolasi host, TLS opsional, pemecahan masalah).
- `-NoApprove` pada skrip target + dukungan kredensial host saja (tanpa master key).
- Escrow BitLocker menerima host key tanpa API key.

### Diperbaiki
- Skrip target tidak lagi meminta Plan ID bila `-PlanId` sudah diberikan.

### Uji
- E2E lokal jalur host-key: whoami agent, manifest, plan terikat, dry-run OK.
- `npm test` tetap hijau (83/83 smoke, agent 57 dengan 2 skip, 68/68 scripts, 5 app, 11/11 redaction).



## v2.8.1 — 14 Nov 2026

Perbaikan agar uji lapangan Windows bisa dijalankan.

### Ditambahkan
- `docs/WINDOWS-UJI-CEPAT.md` — alur loopback/LAN yang aman.
- `docs/run-windows-test.ps1` ditulis ulang: baca `.env`, whoami, verifikasi manifest,
  ikat host, `selfApprove`+`acknowledgeConsole`+`overrideQueue`, dry-run wajib, dead-man.

### Diperbaiki
- `npm test` kini jalan di Windows: resolver Python (`scripts/run-python.mjs`), ESLint
  dipanggil lewat Node (tanpa shim `.cmd`), `bash -n` lewat stdin (path WSL), dan 2 uji
  berbasis chmod di-skip di Windows.

### Uji
- `npm test` penuh di Windows: 83/83 smoke, 5/5 expiry, agent 57 (2 skip), 68/68 scripts,
  5 app, 11/11 redaction; elevation SKIP.
- E2E lokal: whoami, manifest cocok, plan+approve, dry-run, status.



## v2.8.0 — 14 Nov 2026

Fase 5: paket profil, integritas artefak, air-gapped.

### Ditambahkan
- Mesin profil deklaratif (`profiles/*.yaml`, valid JSON/YAML) dengan 8 tipe check aman,
  `na_if`, severity, dan ID CIS/STIG. Total 64 kontrol Windows / 73 Linux.
- `--profile standard|none`, metadata profil pada audit.
- `GET /api/agent/manifest` (SHA-256 + tanda tangan HMAC opsional `AGENT_SIGNING_KEY`);
  agent `--verify-manifest` / `--strict-manifest` / `--manifest-key`.
- `AI_DISABLED=1` untuk mode air-gapped (AI cloud mati, semua lokal).

### Diperbaiki
- Port ganda (IPv4/IPv6) di-dedupe pada hasil audit.
- Deteksi kebijakan sandi Windows lebih tahan lokalisasi; `Never` tidak lagi dianggap tak terbaca.
- Kontrol berbasis `dpkg`/`sshd` diberi `na_if` agar tidak FAIL palsu di distro lain.

### Uji
- smoke 83/83, expiry 5/5, agent 57 kasus, redaction 11/11; build & audit npm bersih.

## v2.7.0 — 14 Nov 2026

Fase 4: cakupan audit, waiver, observability, operasi tanpa awak.

### Ditambahkan
- Cakupan audit Windows 8 → 22 parameter (UAC, RDP/NLA, SMBv1, SMB signing, Defender,
  LLMNR, autoplay, PowerShell policy, WinRM, Administrator bawaan, kebijakan sandi/lockout,
  audit process creation, wuauserv) dan ±18 parameter Linux (SSH password/empty/MaxAuthTries,
  UMASK, core dump, ASLR, forwarding, ICMP redirect, izin passwd/shadow/group/crontab,
  world-writable, sinkronisasi waktu, AIDE, aturan auditd, PAM pwquality, sudo timestamp, journald).
- Metadata profil mencatat jumlah periksa/NA pada setiap audit.
- Waiver per temuan dengan alasan/pemilik/expiry; `WAIVED` dikeluarkan dari skor dan remediasi.
- `/api/health`, `/api/metrics`, deteksi host senyap & plan EXECUTING basi.
- Agent `--watch` + `/api/hosts/me/plans` (antrean tarik per host) dan berkas `deploy/`.
- `app.py` ditandai DEPRECATED untuk operasi nyata (demo luring).

### Diperbaiki
- Event Log non-admin jadi WARNING (bukan FAIL); detail BitLocker membedakan tak terbaca vs tidak terenkripsi.
- Pemetaan remediasi mengenali `process creation` dan `defender`.

### Uji
- smoke 81/81, expiry 5/5, agent 57 kasus, redaction 11/11; build & audit npm bersih.

## v2.6.4 — 14 Nov 2026

Fase 3: identitas per host, RBAC empat mata, transport.

### Ditambahkan
- Enrolment host (`POST /api/hosts/enroll`) dengan kunci per host (`X-Pasopati-Host-Key`),
  pencabutan per host, dan pengikatan plan ke `hostId` (host lain 403).
- Operator ber-role (`viewer`/`planner`/`approver`/`executor`) dengan kunci sendiri; hanya
  hash SHA-256 yang disimpan. Master `PASOPATI_API_KEY` = admin.
- Empat mata: plan buatan sendiri wajib `selfApprove=true`; identitas diambil server (`/api/whoami`).
- TLS opsional (`TLS_CERT`/`TLS_KEY`); agent `--ca-cert` (pinning) dan `--insecure`.
- UI: badge identitas/role, pemilih host, dan centang self-approve.

### Uji
- smoke 72/72 (termasuk RBAC 403, empat mata, isolasi host, pencabutan), expiry 5/5,
  agent 57 kasus, redaction 11/11; build & audit npm bersih.

## v2.6.3 — 14 Nov 2026

Fase 2: bukti dihitung server, antrean per host, resume.

### Ditambahkan
- Gate audit ulang: `VERIFIED` wajib menyertakan `postAudit.compliance_matrix`; server
  menolak bila parameter terkait plan masih `FAIL` dan menyimpan `postAuditAt`.
- Antrean per host (satu plan aktif), batas blast radius `REMEDIATION_MAX_ACTIVE`,
  heartbeat `EXECUTING` + ambang basi `REMEDIATION_STALE_MS`, override `overrideQueue`.
- `--resume` melanjutkan plan terputus, melewati langkah yang sudah terverifikasi.
- Evidence membawa `preStateHash`; `at` memakai jam server.
- Lock `DATA_DIR` (`.server.lock`) mencegah dua server menulis state yang sama; id
  ingest/log memakai suffix acak agar tidak bentrok dalam milidetik yang sama.

### Uji
- smoke 60/60, agent 57 kasus, expiry 5/5, redaction 11/11; build & audit npm bersih.

## v2.6.2 — 14 Nov 2026

Pengerasan kesiapan produksi tahap 1 (aman untuk demo, belum untuk aset kritikal).

### Ditambahkan
- Repo git nyata (sebelumnya `.git` kosong) + `.gitattributes` LF.
- Gate konfirmasi jalur akses: plan `ports-block-*`/`fw-enable-*`/`ssh-disable-root`
  wajib `acknowledgeConsole`, dan agent menahan eksekusi bila sesi remote akan terputus
  (`--force-access-risk` untuk melanjutkan).
- RDP 3389 masuk runbook Windows + banner peringatan + badge PUTUS RDP.
- Audit log ber-hash-chain + `GET /api/audit-logs/verify`; hapus menjadi soft delete.
- Dead-man watchdog: rollback otomatis 10 menit bila hasil tak dikonfirmasi
  (`--deadman-seconds`, 0 = mati), batal otomatis saat status final.
- Escrow recovery key/password boot BitLocker ke `/api/escrow` (selain file lokal 0600).
- Rule iptables dipersistenkan (`netfilter-persistent`/`iptables-save`).

### Diperbaiki
- Sudoers: tulis atomik + `visudo -c`, batal total bila invalid, cloud-init tanpa
  password dikecualikan (sebelumnya bisa mematikan `sudo`).
- `VERIFIED` dinilai server: evidence wajib lengkap, `stepIndex` unik, `exitCode` 0,
  langkah enforce `verified` (sebelumnya murni klaim agent).
- Rate limit dipisah per endpoint (sebelumnya satu bucket global → 429 silang).
- BitLocker: timeout rollback 120 dtk + pembanding hanya status proteksi.
- `reapprove.ps1` mengirim `acknowledgeConsole`.

### Uji
- smoke 55/55 (termasuk escrow, 4 penolakan evidence, 2 uji rantai audit), agent 56 kasus,
  expiry 5/5, redaction 11/11. Sisa gagal hanya lingkungan Windows (chmod/`bash -n`).

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
- Rebranding penuh ke **PASOPATI** (Protokol Audit Sistem & Operasi
  Pengamanan Agen TI) beserta logo resmi di `public/pasopati.jpeg` dan
  `public/pasopati-mark.png`.
- Dashboard baru bergaya command center: sidebar navigasi, topbar dengan pencarian
  endpoint, empat kartu KPI, grafik temuan per endpoint, tren kesiapan armada,
  tabel aktivitas terbaru, dan daftar status armada.
- `README` menampilkan logo dan identitas baru.

### Diubah
- Script CLI diganti nama: `pasopati_audit.py` (pemeriksaan) dan
  `pasopati_remediate.py` (perbaikan). Endpoint lama `pasopati_*` tetap dilayani
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
