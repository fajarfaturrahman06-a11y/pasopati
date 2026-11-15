# Deployment PASOPATI — Windows Server 2022

Panduan ini untuk proyek di `C:\Apps\PASOPATI`, Node.js di `C:\Program Files\nodejs`, dan Scheduled Task yang sudah ada bernama **PASOPATI Auto Start**. Ini prosedur manual; tidak ada perubahan yang dilakukan pada VPS produksi. Pertahankan task dan `start-pasopati.ps1` yang sudah berjalan—jangan membuat supervisor kedua.

## Peringatan keamanan sebelum rilis

Alamat publik yang saat ini diketahui memakai `http://43.157.225.182:3000`. Jangan masukkan API key operator melalui HTTP: header autentikasi dan informasi endpoint dapat dibaca selama transit. Sebelum membuka API ini ke internet, pasang HTTPS dengan sertifikat valid, idealnya reverse proxy IIS yang meneruskan ke `127.0.0.1:3000`, atau TLS Node yang sudah dikelola secara aman. Jangan menaruh API key/HMAC secret di command line, source, log, atau panduan. Audit HMAC agen tetap memakai secret bersama yang sudah ada; signature membuktikan kepemilikan secret, tetapi belum mengikat satu secret ke satu identitas host.

## 1. Periksa task dan siapkan backup

Jalankan PowerShell sebagai Administrator. Pastikan task yang benar tersedia dan statusnya dicatat:

```powershell
$taskName = 'PASOPATI Auto Start'
Get-ScheduledTask -TaskName $taskName | Select-Object TaskName, State, TaskPath
Get-ScheduledTaskInfo -TaskName $taskName | Select-Object LastRunTime, LastTaskResult, NextRunTime
```

Buat backup bertanggal source dan seluruh direktori data. Backup `.env` secara terpisah dengan ACL terbatas; jangan membuka atau mencetak isinya:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupRoot = "C:\Backups\PASOPATI\$stamp"
New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
robocopy 'C:\Apps\PASOPATI' "$backupRoot\source" /E /COPY:DAT /R:2 /W:2 /XD node_modules dist data .git /XF .env
if ($LASTEXITCODE -ge 8) { throw "Backup source gagal: robocopy $LASTEXITCODE" }
if (Test-Path 'C:\Apps\PASOPATI\data') {
  robocopy 'C:\Apps\PASOPATI\data' "$backupRoot\data" /E /COPY:DAT /R:2 /W:2
  if ($LASTEXITCODE -ge 8) { throw "Backup data gagal: robocopy $LASTEXITCODE" }
}
if (Test-Path 'C:\Apps\PASOPATI\.env') {
  Copy-Item -LiteralPath 'C:\Apps\PASOPATI\.env' -Destination "$backupRoot\.env"
  icacls $backupRoot /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F'
}
```

Simpan nilai `$backupRoot` untuk rollback. Jangan hapus atau mengosongkan `data`. Rilis pertama membuat `data\endpoint_inventory.json` jika belum ada; file audit, quarantine, plans, dan data lama tetap dipertahankan. Tidak ada migrasi database karena arsitektur proyek ini menggunakan JSON.

## 2. Uji kandidat pada staging, bukan pada aplikasi live

Siapkan staging terpisah dari task produksi. Unggah paket source rilis ke VPS, lalu ekstrak ke staging; isi paket tidak mencakup `.env` atau direktori data:

```powershell
$releaseZip = 'C:\Staging\PASOPATI-v2.9.6-implemented.zip'
$unpack = "C:\Staging\PASOPATI-release-$stamp"
$stage = "C:\Apps\PASOPATI-staging-$stamp"
Expand-Archive -LiteralPath $releaseZip -DestinationPath $unpack
$releaseSource = Join-Path $unpack 'PASOPATI-v2.9.6'
New-Item -ItemType Directory -Force -Path $stage | Out-Null
robocopy $releaseSource $stage /E /COPY:DAT /R:2 /W:2 /XD node_modules dist data .git /XF .env
if ($LASTEXITCODE -ge 8) { throw "Pembuatan staging gagal: robocopy $LASTEXITCODE" }
```

Jangan menyalin data produksi atau `.env` ke staging. Kemudian:

```powershell
Set-Location $stage
& 'C:\Program Files\nodejs\npm.cmd' ci --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw 'npm ci gagal' }
& 'C:\Program Files\nodejs\npm.cmd' run lint
if ($LASTEXITCODE -ne 0) { throw 'lint gagal' }
& 'C:\Program Files\nodejs\npm.cmd' run build
if ($LASTEXITCODE -ne 0) { throw 'build gagal' }
```

Gunakan Node.js yang memenuhi `engines` di `package.json` (minimal Node 20.11). Jangan jalankan server staging pada port produksi atau dengan direktori data produksi.

## 3. Pasang source dan restart task yang sama

Sebelum menyalin file, pastikan backup selesai dan build staging lolos. Hentikan task yang sudah ada, tunggu proses lama berhenti, lalu salin rilis. Jangan menjalankan `npm start` atau PowerShell supervisor kedua:

```powershell
Stop-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3
Get-ScheduledTaskInfo -TaskName $taskName | Select-Object LastTaskResult
```

Salin source/build yang sudah diuji dari staging ke `C:\Apps\PASOPATI` dengan `robocopy /E` (bukan `/MIR`), dan kecualikan `data`, `.env`, `.server.lock`, `.git`, serta log. Contoh:

```powershell
robocopy $stage 'C:\Apps\PASOPATI' /E /COPY:DAT /R:2 /W:2 /XD data .git logs /XF .env .server.lock start-pasopati.ps1
if ($LASTEXITCODE -ge 8) { throw "Pemasangan source gagal: robocopy $LASTEXITCODE" }
```

Pertahankan file `start-pasopati.ps1` milik VPS yang sudah ada. Jangan menyalin `data` dari staging dan jangan mengganti task action/trigger/setting-nya.

Setelah semua file terpasang:

```powershell
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 5
Get-ScheduledTask -TaskName $taskName | Select-Object TaskName, State
Get-ScheduledTaskInfo -TaskName $taskName | Select-Object LastRunTime, LastTaskResult
Get-NetTCPConnection -LocalPort 3000 -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
```

Jika konfigurasi task tidak bisa menghentikan child `node.exe` dengan bersih, jangan jalankan task lagi sampai proses lama benar-benar berhenti. Server menggunakan `.server.lock` untuk mencegah dua proses berbagi `DATA_DIR`.

## 4. Verifikasi API dan dua browser

Lakukan verifikasi hanya melalui HTTPS yang sertifikatnya valid. Buka PASOPATI dari dua browser dengan akun yang sudah berwenang. Masukkan API key lewat UI yang tersedia; jangan menaruhnya di URL atau terminal. Pastikan panel Registri Endpoint menunjukkan **TERHUBUNG · DATA VPS** dan waktu sync berubah. Dari Browser A tambahkan endpoint; Browser B seharusnya menampilkan data maksimal sekitar 5 detik. Ubah endpoint dari Browser B dan pastikan Browser A melihat nilai baru. Uji juga endpoint yang sama dikirim dua kali; jumlah endpoint tidak boleh bertambah.

Endpoint API yang diharapkan:

- `GET /api/endpoints` dan `GET /api/endpoints/:id`: role autentikasi yang diizinkan.
- `POST /api/endpoints` dan `PUT /api/endpoints/:id`: role planner/admin. PUT wajib mengirim `expected_revision` dari record yang terakhir dibaca; jika sudah ada perubahan yang lebih baru, server menolak dengan `409` dan UI menyegarkan data agar perubahan tidak hilang.
- `DELETE /api/endpoints/:id`: role admin; penghapusan berupa arsip lunak agar history tidak hilang.
- `POST /api/ingest`: signature HMAC agen yang valid, lalu upsert endpoint dan telemetry.

Tanpa autentikasi, daftar endpoint harus ditolak `401`. Payload invalid harus ditolak dengan status `400`; kegagalan persistensi tidak boleh dibalas sebagai telemetry tersimpan. Periksa kesehatan layanan dan log server sesuai prosedur operasi VPS yang berlaku, tanpa mengeluarkan nilai secret.

## 5. Rollback

Jika verifikasi gagal, hentikan Scheduled Task yang sama, pastikan proses lama telah berhenti, pulihkan source dari `$backupRoot\source`, lalu pulihkan data dari `$backupRoot\data` hanya jika data yang aktif rusak atau ada alasan operasional yang jelas. Pertahankan `.env` yang aktif kecuali rollback memang mensyaratkan pemulihan konfigurasi; jangan menimpa file data baru dengan backup lama tanpa persetujuan operator karena itu dapat menghapus telemetri terbaru. Jalankan kembali **task yang sama**, lalu verifikasi listener port 3000 dan akses HTTPS. Jangan membuat Scheduled Task atau supervisor baru.

## File rilis yang berubah

Lihat daftar file pada laporan implementasi. Perubahan utama backend adalah `server.ts` dan `src/endpointStore.ts`; frontend mengambil endpoint dari API pusat dan memakai polling 5 detik. `package-lock.json` juga diperbaiki pada satu entri versi jiti yang tidak tersedia agar instalasi deterministik dapat berjalan.
