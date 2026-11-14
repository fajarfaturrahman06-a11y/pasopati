# RESEARCH LOG — Audit & Remediation Hardening
**Tanggal:** 11–12 November 2026  
**Rilis:** v2.5.0  
**Lingkup:** audit bug menyeluruh, penggabungan jalur hardening+remediasi, elevasi otomatis, output `audit.json` + riwayat.  
**Status:** seluruh temuan diperbaiki dan diuji; sisa pekerjaan untuk produksi dicatat di §8.

Dokumen ini adalah catatan penelitian agar pekerjaan berikutnya tidak mengulang analisis. Jangan hapus; tambahkan entri baru di atas.

---

## 1. Tujuan

1. Menemukan bug nyata pada kontrol plane, agent, UI, dan generator runbook.
2. Membuat remediasi benar-benar memperbaiki temuan audit (bukan sekadar status UI).
3. Menyatukan hardening dan remediasi menjadi **satu jalur** dengan kontrol yang sama.
4. Meminta hak root/Administrator secara otomatis dan menyimpan bukti eksekusi.

---

## 2. Metode

- Pembacaan kode penuh: `server.ts`, `pasopati_audit.py`, `app.py`, `src/**`.
- Uji runtime terhadap server Express sungguhan (port acak, `PASOPATI_DATA_DIR` sementara).
- Probe khusus yang membuktikan bug: body cacat, refresh plan, token kedaluwarsa, ZIP, audit log >200, dsb.
- Uji elevasi nyata memakai shim `sudo` + `unshare -r` (karena sudo sandbox interaktif).
- Validasi skrip dengan `bash -n`; validasi tipe dengan `tsc`; build Vite.

---

## 3. Temuan kritis dan perbaikannya

| # | Temuan | Akar masalah | Perbaikan | Uji |
|---|---|---|---|---|
| 1 | Satu request JSON cacat mematikan server | handler `async` tanpa penangkap; Express 4 tidak menangkap rejection | `asyncHandler`, validasi `checks`/`userApiKey`, error middleware global | smoke 3 kasus + “server tetap hidup” |
| 2 | `plan.json` tidak valid setelah REFRESH | GET meredaksi nonce, UI menimpa seluruh plan | pertahankan nonce/signature/expiry saat refresh | test nonce + UI |
| 3 | Plan macet saat token kedaluwarsa | approve hanya dari `PLANNED` | re-approve setelah expired + `evidenceDeadline` 60 menit | `test:expiry` 5/5 |
| 4 | Evidence hilang bila `--push-url` lupa | push opsional saat eksekusi | wajibkan `--push-url` untuk eksekusi non-demo | agent test |
| 5 | Klaim “reversibel” palsu | 3 alias tanpa handler rollback | rollback nyata untuk semua alias enforce | agent 21/21 |
| 6 | Rollback destruktif | auditd/BitLocker selalu dimatikan | keputusan berbasis pre-state | agent test |
| 7 | Registry karantina write-only | tidak ada GET; UI tidak hidrasi | `GET /api/quarantine` + hidrasi | smoke |
| 8 | Telemetri tampil “BASELINE RECON” | beda konstanta server/UI | satu modul `src/auditActions.ts` | smoke |
| 9 | `N/A` merusak skor | tipe/penyebut tidak mendukung N/A | N/A dihormati, dikecualikan dari skor, badge khusus | scripts test |
| 10 | Konfigurasi AI `.env` diabaikan | model/endpoint hardcoded | provider OpenAI-compatible + komentar inline dipangkas | probe mock AI 200 |
| 11 | Mode Local AI mati | URL disimpan tapi tidak dipakai | implementasi provider lokal | manual |
| 12 | Log ingest upload tidak persist | lupa `persistAuditLogs` | persist + riwayat drift | code review |
| 13 | Klaim OPSEC berlebih | hanya IP yang diredaksi | redaksi IP/MAC/hostname di nama & detail | code review |
| 14 | Audit log dipotong diam-diam | `slice(0,200)` tanpa laporan | `received/added/rejected`, UI menandai hanya yang tersimpan | smoke 250 entri |
| 15 | CSP memblokir Google Fonts | `style-src`/`font-src` sempit | izinkan domain font | build/manual |
| 16 | `/api/scan-host` tanpa waktu tunggu | `execFile` tanpa timeout | timeout 120 s, `maxBuffer`, path unik | code review |
| 17 | Memori bocor | map rate-limit & drift tanpa batas | pembersihan & cap | code review |
| 18 | VERIFIED tanpa bukti | evidence kosong diterima | wajib evidence untuk status terminal | smoke |
| 19 | `outputHash` salah arti | hash pre-state | hash `{pre, output, post}` | agent test |
| 20 | Backup bisa tertimpa | nama per detik | suffix UUID | agent test |
| 21 | Exit code SSH palsu | hardcoded 0; hanya `ssh` | exit code nyata + fallback `sshd`/`ssh` | agent test |
| 22 | Port fallback false-negative | hanya `127.0.0.1`, 40 ms | IP primer + 150 ms | manual |
| 23 | Kill-switch tanpa release & duplikasi rule | tidak idempoten | `-C`/`-A`, izin ESTABLISHED, `--quarantine-release` | dry-run |
| 24 | Alias duplikat diterima | tanpa dedupe | dedupe saat validasi | smoke |
| 25 | Karantina tanpa `unitId` | default `UNKNOWN` | 400 | smoke |
| 26 | ZIP rawan balapan & kehilangan template | path temp tetap; `.env.*` | path unik + cleanup; `.env.example` disertakan | probe ZIP |
| 27 | Field upload tanpa batas | hanya escape | cap panjang semua field | code review |
| 28 | Interval/timer bocor | tanpa cleanup | ref + cleanup; timer toast | build |
| 29 | `res.ok` tidak dicek | load DB | cek status + pesan | code review |
| 30 | Bug audit agent | BitLocker/sudoers inverted, USB Windows selalu WARNING | perbaiki status & baca registry | agent test |
| 31 | Dua jalur terpisah | hardening vs remediasi beda mekanisme | **change set tunggal**: enforce + advisory | scripts 66/66 |
| 32 | Elevasi tidak otomatis | hanya remediasi & sebagian skrip | `ensure_elevated` untuk semua mode + skrip | `test:elevation` 20/20 |
| 33 | Pemetaan Windows salah pada data nyata | kata “administrator” di detail USB menangkap `advisory-admins`; “rootkit” di detail Secure Boot menangkap `advisory-rootkit` | urutan pemetaan diperbaiki + regex administrators dipersempit | scripts 68/68 (regresi data asli) |
| 34 | Recovery key BitLocker hilang | output `manage-bde -protectors` dibuang | ekstrak kunci, cetak, simpan 0600 di folder backup | agent 23/23 |

---

## 4. Keputusan desain

### 4.1 Satu jalur: enforce + advisory
- Setiap temuan FAIL/WARNING dipetakan ke alias.
- **Enforce** (18 alias): mengubah host, wajib `read/apply/verify/rollback`.
- **Advisory** (4 alias): read-only; LUKS/Secure Boot/admin review. Tidak memblokir `VERIFIED`.
- Plan wajib ≥1 enforce; advisory saja ditolak 400.
- Skrip runbook dirender dari **item yang dipilih** (sumber sama), lengkap dengan rollback.

Alasan: produksi butuh satu otorisasi dan satu jejak bukti, tetapi tidak semua kontrol bisa otomatis.

### 4.2 Elevasi otomatis
- Linux `sudo -E` → `pkexec`; Windows UAC via ShellExecuteW.
- Penanda `PASOPATI_ELEVATED=1` mencegah loop; `--no-elevate` untuk audit tanpa hak.
- Skrip hardening/rollback juga mengelevasi diri (bukan hanya agent).

### 4.3 `audit.json` + riwayat
- Output default `audit.json`, ditulis atomik.
- `execution.elevated`, `elevation_method`, `history_file`, `history` (100 entri).
- Riwayat di `/var/lib/pasopati/history.json` (fallback `~/.pasopati`).

---

## 5. Bukti uji

```
npm run lint ............ OK
npm run build ........... OK (1674 modul)
test:smoke .............. 31/31
test:expiry ............. 5/5
test:agent .............. 21/21
test:scripts ............ 66/66 (bash -n)
test:app ................ 4/4 (bash -n)
test:elevation .......... 20/20 (nyata)
py_compile .............. OK
```

Bukti runtime kunci:
- `POST /api/analyze-threats` dengan `checks:"oops"`/`[null]`/`userApiKey:123` → 200, proses hidup.
- 200 alias duplikat → 1 item; plan advisory saja → 400.
- Evidence advisory `verified=false` tetap `VERIFIED` dan ditandai `advisory:true`.
- Elevasi: satu panggilan sudo, argumen utuh, `audit.json` `elevated:true`, riwayat bertambah.
- Plan campuran `advisory-fde` + `ports-block-linux` → `VERIFIED`, advisory “PERLU MANUAL”.

---

## 6. Peta file

- Baru: `src/auditActions.ts`, `src/remediationMapping.ts`, `src/remediationScripts.ts`.
- Baru (uji): `tests/control-plane-smoke.mjs`, `tests/remediation-expiry.mjs`, `tests/test_agent_remediation.py`, `tests/scripts-coverage.ts`, `tests/gen-sample-script.ts`, `tests/test_app_scripts.py`, `tests/elevation-real.mjs`.
- Diubah: `server.ts`, `pasopati_audit.py`, `app.py`, `src/**`, `README.md`, `CHECKPOINT.md`, `.env.example`, `.gitignore`, `package.json`.

---

## 6b. Uji lapangan Windows (12 Nov 2026)

Audit nyata dari laptop Windows (unit “Laptop Uji 2”, 8 parameter, 3 FAIL/2 WARNING) dijadikan
change set: `ports-block-windows`, `fw-enable-defender`, `usb-storage-block`, `bitlocker-enable`
(enforce) + `advisory-secureboot`. Plan dibuat & disetujui server: `PLAN-1794488213903-129724`.
Ditemukan dan diperbaiki dua bug pemetaan (lihat #33/#34) sebelum eksekusi.
Helper `reapprove.ps1` disertakan untuk menerbitkan ulang token setelah kedaluwarsa.

## 6c. Target hanya punya agent + akses LAN (12 Nov 2026)

Target uji adalah laptop lain. Saat itu hanya berisi `pasopati_audit.py` (kini dipecah menjadi
`pasopati_audit.py` + `pasopati_remediate.py`; lihat §6f).
- Endpoint `GET /api/remediation-plans/:id/agent` (API key, rate-limit) mengembalikan plan
  lengkap + token; agent memakai `--server` + `--plan-id` lalu menyimpan plan sementara.
- `--push-url` otomatis mengikuti `--server`; token/plan.json tidak perlu disalin ke target.
- Akses lintas host: `setup-lan.ps1` (portproxy 3000 Windows→WSL + firewall) dan verifikasi
  `Invoke-WebRequest` 200 dari host Windows.
- UI: perintah utama memakai `--server` + `--plan-id`; plan.json/token hanya fallback.
- `force=true` pada approve untuk menerbitkan ulang token tanpa menunggu kedaluwarsa.

## 6d. Kasus BitLocker lapangan (12 Nov 2026)

Laptop uji: volume C: **sudah terenkripsi 100% tetapi Protection Off dan tanpa key protector**
(state “terenkripsi tapi tidak terlindungi”). TPM ada & siap, jadi penyebabnya bukan TPM mati.
`manage-bde -on` gagal `0x8028400F`; `-protectors -enable` gagal `0x8031001D` karena protector
TPM belum ada.

Urutan yang benar dan berhasil diuji manual:
1. `manage-bde -protectors -add C: -RecoveryPassword` (simpan kunci),
2. `Add-BitLockerKeyProtector -MountPoint C: -TpmProtector`,
3. `Resume-BitLocker -MountPoint C:`.
Hasil: `ProtectionStatus: On`, protector {RecoveryPassword, Tpm}. Kunci disimpan di
`bitlocker-recovery-NIKO.txt`.

Perbaikan agent:
- state dibaca via JSON PowerShell (stabil, tidak lokalisasi),
- jika sudah terenkripsi → tambah RecoveryPassword/TPM lalu Resume (tidak enkripsi ulang),
- fallback password boot bila TPM/resume gagal,
- rollback memakai `Suspend-BitLocker` (tidak mendekripsi) bila pre-state terenkripsi,
- output apply/gagal disimpan di evidence.

## 6e. Plan tanpa BitLocker + audit sadar-firewall (12 Nov 2026)

Target tanpa TPM dan tidak ingin risiko password boot → BitLocker dijadikan **advisory**.
Plan uji: `PLAN-1794494459201-976223` (ports/firewall/USB enforce; secureboot + fde advisory).

Ditemukan juga: audit port hanya melihat socket listening, sehingga port yang sudah diblokir
firewall tetap WARNING. Audit kini memeriksa rule blokir (`PASOPATI-Block-<port>` di Windows,
rule iptables DROP di Linux) dan hanya menandai port yang benar-benar terekspos.

## 6f. Pemisahan script pemeriksaan dan perbaikan (12 Nov 2026)

Masalah: satu nama `pasopati_audit.py` dipakai untuk dua tindakan berbeda (memeriksa dan
mengubah host). Operator bisa salah menjalankan perbaikan saat niatnya hanya memeriksa.

Keputusan:
- `pasopati_audit.py` = mesin pemeriksaan. Menulis `audit.json`, mengirim telemetri, tidak
  pernah mengeksekusi perubahan (kecuali `--quarantine` yang eksplisit).
- `pasopati_remediate.py` = script perbaikan. `import pasopati_audit as core`; menolak jalan
  tanpa mode (`--plan-id/--server`, `--remediate-plan`, `--demo`, `--quarantine`).
- `ensure_elevated(argv, entry_script)` memastikan elevasi menjalankan ulang script yang
  benar, sehingga elevated audit tetap audit dan elevated remediasi tetap remediasi.
- Endpoint unduhan terpisah; nama lama `/api/download/pasopati_audit.py` dipertahankan
  sebagai alias audit agar tautan lama tidak 404.
- Target remediasi perlu **dua** file (`pasopati_remediate.py` + `pasopati_audit.py`).

Bukti uji:
- `python3 pasopati_remediate.py` tanpa mode → exit 2 + panduan mode (tidak menyentuh host).
- `python3 pasopati_remediate.py --demo --no-exec` → plan demo tanpa perubahan.
- `python3 pasopati_audit.py -q -o ...` → audit.json sah.
- py_compile OK; 37/37 uji agent; 4/4 uji app; seluruh rangkaian `npm test` hijau.

## 6g. Rebranding PASOPATI + dashboard command center (12 Nov 2026)

- Identitas produk menjadi **PASOPATI** (Protokol Audit Sistem & Operasi Pengamanan
  Agen TI); logo resmi dipasang di UI dan README.
- Dashboard React disusun ulang mengikuti referensi command center: sidebar,
  topbar + pencarian endpoint, 4 KPI, grafik temuan per endpoint, tren kesiapan,
  tabel aktivitas, dan status armada.
- Script CLI berganti nama menjadi `pasopati_audit.py` dan `pasopati_remediate.py`;
  endpoint lama dipertahankan sebagai alias.
- CSS Streamlit dipindahkan ke `assets/pasopati.css` agar `app.py` ringkas.
- Identifier teknis kini memakai `X-Pasopati-API-Key`, `PASOPATI_API_KEY`, dan nama
  rule firewall `PASOPATI-Block-<port>` agar konsisten dengan branding yang terlihat.

## 7. Cara menjalankan ulang

```bash
npm install
npm test            # seluruh uji
npm run dev         # server + UI
python3 pasopati_audit.py -u NAMA-UNIT       # output audit.json (meminta root)
python3 pasopati_remediate.py --plan-id ... --server ...  # perbaikan plan tervalidasi
```

---

## 8. Keterbatasan & pekerjaan penelitian berikutnya

**Sebelum produksi:**
1. TLS/HTTPS + reverse proxy; API key bukan satu-satunya kontrol.
2. Pindahkan plan/nonce/audit log dari file JSON ke database transaksional.
3. RBAC multi-operator (pembuat vs penyetuju), audit identitas.
4. Antrean eksekusi per host agar dua plan tidak bertabrakan.
5. Heartbeat/registrasi agent; saat ini agent menarik perintah manual.
6. Retensi & rotasi plan, nonce, history, backup.
7. Tanda tangan artefak agent + verifikasi unduhan (checksum/Ed25519).
8. Integrasi baseline dengan Ansible/GPO/Intune.
9. Otomasi LUKS (backup + cryptsetup) dan Secure Boot (UEFI, reboot terjadwal).
10. Uji beban: ingest paralel, audit log besar, ZIP bersamaan.
11. Uji baremetal lintas distro/Windows versi; WSL hanya lingkungan pilot.
12. Perluas allowlist dengan prasyarat versi & dependency.

**Risiko yang masih diterima:**
- Rollback firewall dapat membuka port kembali bila urutan eksekusi keliru.
- BitLocker aktif di background; belum ada verifikasi persentase enkripsi.
- Advisory hanya memberi bukti, bukan perubahan.
- API key disimpan di state UI (hilang saat reload).
