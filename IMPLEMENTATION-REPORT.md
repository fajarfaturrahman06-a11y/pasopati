# PASOPATI — Penyimpanan Endpoint Terpusat

## Ringkasan

Inventaris operasional sebelumnya bersumber dari fixture `mockDevices` di React State, sehingga perubahan hanya hidup di browser tersebut. Belum ada API CRUD endpoint. `/api/ingest` memverifikasi HMAC tetapi hanya mencatat ringkasan skor sebagai audit log, bukan menyimpan rekam endpoint dan data kepatuhan secara lengkap. File JSON memang sudah dipakai di backend untuk fitur lain, namun pola error-write dan lock proses yang lama menyisakan risiko respons sukses palsu atau dua server menulis `DATA_DIR` yang sama.

Sekarang VPS menjadi sumber data endpoint: backend menyimpan registry permanen sebagai JSON atomik, frontend membaca satu registry yang sama dan polling tiap lima detik, dan telemetry agen meng-upsert endpoint sebelum membalas sukses. Fixture tetap tersedia hanya sebagai demo yang diberi label.

## Perubahan utama

### Penyimpanan dan konflik

Registry disimpan di `DATA_DIR/endpoint_inventory.json` (pada instalasi yang menggunakan nilai default, `C:\Apps\PASOPATI\data\endpoint_inventory.json`). Tidak ada database pada arsitektur ini, jadi JSON dipertahankan. Setiap rekam punya UUID stabil, `created_at`, `updated_at`, `revision`, history compliance dan history perubahan; file lama dinormalisasi saat dibaca. Identitas dideduplikasi berdasarkan ID agen serta MAC/hostname yang layak.

Penulisan mengganti file melalui atomic rename. Lock startup sekarang memakai pembuatan file eksklusif; proses kedua yang memakai direktori data sama ditolak dan kegagalan lock menghentikan startup, bukan dibiarkan berjalan tanpa perlindungan. PUT mengirim `expected_revision`; jika perangkat berubah sejak browser membaca datanya, API mengembalikan `409` alih-alih menimpa perubahan terbaru. UI menyegarkan data dan meminta operator membuka ulang formulir edit.

### API dan keamanan

Ditambahkan `GET /api/endpoints`, `GET /api/endpoints/:id`, `POST /api/endpoints`, `PUT /api/endpoints/:id`, dan `DELETE /api/endpoints/:id`. Semuanya memakai auth yang sudah ada; POST/PUT memerlukan planner/admin, DELETE admin. DELETE berupa arsip lunak, sehingga item tidak lagi tampil di registry aktif namun rekam dan history tetap tersimpan. Input, alamat IP/MAC, port, status checks, panjang teks, jumlah item dan ukuran payload divalidasi. Kegagalan baca/tulis dilaporkan sebagai error; tidak ada API publik tanpa autentikasi.

### Agen dan sinkronisasi

`/api/ingest` tetap memakai autentikasi HMAC yang lama agar kompatibel dengan agen. Payload penuh (hostname, OS, IP, MAC, pengguna, port, matrix compliance dan scoring) di-upsert ke endpoint yang sama, lalu masuk audit log. ID event stabil dari signature disimpan untuk mencegah replay menghasilkan history ganda, termasuk setelah backend restart. Jika penyimpanan endpoint gagal, ingest tidak menyatakan sukses.

Setelah autentikasi, seluruh halaman memakai registry VPS; polling dibatasi satu request aktif tiap lima detik, menampilkan status koneksi dan waktu sinkronisasi, serta mencoba pulih otomatis setelah offline. Tanpa autentikasi aplikasi menampilkan mode demo, bukan mengklaim fixture sebagai inventaris operasional. Upload/scan agen disimpan ke registry; tombol sampel tetap lokal/demo.

## File yang berubah

- `server.ts` — REST CRUD, validasi/otorisasi, upsert ingest, error penyimpanan, lock proses eksklusif.
- `src/endpointStore.ts` — modul registry JSON, normalisasi skema, dedupe dan atomic write.
- `src/App.tsx`, `src/types.ts` — polling, state registry, normalisasi data dan token revision.
- `src/components/EndpointRegistryPanel.tsx` — status koneksi/sync dan UI tambah, ubah, arsip.
- `src/components/TabCommandCenter.tsx` — daftar armada terhubung ke registry pusat.
- `src/components/TabLiveAgent.tsx` — pemisahan data sampel dan hasil agen operasional.
- `src/components/TabDeepAudit.tsx`, `src/components/TabAIHardening.tsx` — empty-state aman saat registry belum berisi endpoint.
- `package.json` — menambahkan integration test ke `npm test`.
- `package-lock.json` — menyelaraskan versi app ke 2.9.6 dan mengganti `jiti@2.8.3` yang tidak tersedia dengan `2.7.0` yang memenuhi rentang `^2.7.0`.
- `tests/endpoint-registry-smoke.mjs` — integration test API registry, concurrent writes, konflik stale, restart, HMAC dan RBAC.
- `tests/control-plane-smoke.mjs` — assertion ingest diperbarui sesuai ID endpoint stabil.
- `DEPLOYMENT-VPS-WINDOWS-SERVER-2022.md` — prosedur backup, staging, restart task yang ada, verifikasi dan rollback.
- `IMPLEMENTATION-REPORT.md` — laporan ini.

## Hasil pengujian

- `npm ci --no-audit --no-fund`: berhasil setelah koreksi entri lockfile `jiti` yang awalnya menunjuk versi yang tidak diterbitkan.
- `npm run lint`: lulus (`tsc --noEmit` dan ESLint).
- `npm run build`: lulus; Vite membangun 1.677 modul.
- `npm test`: seluruh rangkaian lulus. Di dalamnya: control-plane 84/84; registry 18/18; expiry 5/5; agent 69 tes (1 skip khusus Windows); script coverage 68/68; app 5 tes; redaction 11/11; elevation 23/23.
- Integration registry menguji dua klien API yang saling melihat perubahan, dua POST bersamaan, dedupe identitas, viewer read-only, penolakan stale update `409`, HMAC ingest, penyimpanan file, restart backend dengan `DATA_DIR` yang sama, dedupe replay, dan arsip lunak.

## Batas verifikasi dan risiko tersisa

Pengujian dua klien dilakukan melalui integration test terhadap server lokal, bukan dua laptop/browser sungguhan pada URL publik. Restart yang dibuktikan adalah restart proses backend di sandbox dengan direktori data yang sama; VPS produksi belum direstart dan belum di-deploy. Karena itu tidak ada klaim bahwa VPS atau Scheduled Task produksi sudah berubah. Prosedur pengujian manual dua browser dan port 3000 ada di panduan deployment.

URL produksi yang diberikan adalah `http://43.157.225.182:3000`. Jangan memasukkan API key melalui HTTP. Pasang HTTPS valid (misalnya reverse proxy IIS ke `127.0.0.1:3000`) sebelum penggunaan publik; panduan deployment menempatkan ini sebagai prasyarat rilis. Secret server tidak ditambahkan ke frontend atau laporan. HMAC agen tetap memakai secret bersama yang sudah ada dan belum mengikat secret unik ke identitas host. Registry JSON cocok untuk satu proses server pada satu VPS; lock mencegah proses ganda, tetapi untuk scale-out beberapa server diperlukan database atau koordinasi lock terdistribusi.

## Deployment

Tidak ada perubahan `.env`, data produksi, Scheduled Task, supervisor, atau VPS dalam pekerjaan ini. Gunakan [panduan deployment Windows Server 2022](DEPLOYMENT-VPS-WINDOWS-SERVER-2022.md): backup source dan data, uji paket di staging, build, hentikan dan jalankan kembali Scheduled Task **PASOPATI Auto Start** yang sama, cek listener port 3000, verifikasi API melalui HTTPS dan dua browser, dan rollback source tanpa menimpa data terbaru.
