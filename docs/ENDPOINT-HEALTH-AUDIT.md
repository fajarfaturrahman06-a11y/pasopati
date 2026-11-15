# Audit Akses & Kondisi Endpoint

Fitur ini adalah rekaman terpisah untuk aktivitas akses endpoint dan persetujuan remediasi. Ia tidak memakai `audit_logs.json`, route `/api/audit-logs`, `AuditLogEntry`, atau komponen `TabAuditLog`.

## Penyimpanan dan akses

Rekaman aktif disimpan di database SQLite khusus `PASOPATI_DATA_DIR/endpoint_health_audit.sqlite` (default: `data/endpoint_health_audit.sqlite`). SQLite memakai WAL, `synchronous=FULL`, transaksi untuk setiap append, batas tunggu lock, dan indeks untuk waktu serta endpoint. Pada POSIX file database/WAL dibatasi ke mode `0600`; Windows tetap memakai ACL filesystem yang berlaku. Database ini memakai tabel dan metadata sendiri, terpisah dari `audit_logs.json`.

Jika `endpoint_health_audit.json` dari versi sebelumnya ada, seluruh rekaman yang valid diimpor satu kali dalam transaksi SQLite saat database pertama kali dibuka. File JSON asli tidak diubah atau dihapus dan tetap sebagai cadangan. Jika file lama tidak valid, migrasi gagal dengan error dan tidak menandainya selesai agar data tidak diam-diam hilang. Setelah migrasi, semua penambahan baru hanya ditulis ke SQLite.

API maupun tab UI fitur ini mensyaratkan role `admin`; kredensial tidak diambil dari body permintaan.

- `GET /api/admin/endpoint-health-audit?limit=200` — baca rekaman terbaru; `limit` dibatasi 500 dan dapat difilter memakai `endpointId`.
- `POST /api/admin/endpoint-health-audit/access` — catat akses dan snapshot satu endpoint aktif. Body hanya menerima `endpointId`; aktor, alamat permintaan, identitas endpoint, dan kondisi dibaca/dibentuk oleh server.
- `POST /api/remediation-approve` — setelah validasi approval berhasil, sistem menambahkan jenis rekaman `REMEDIATION_APPROVED`. Nama approver diambil dari principal terautentikasi, bukan dari payload klien. Jika database audit baru gagal ditulis, approval ditolak agar tidak meloloskan approval tanpa rekaman.

Tidak ada API untuk mengedit atau menghapus rekaman. Fitur membatasi penambahan pada 20.000 rekaman; jika batas tercapai, penambahan baru gagal dan rekaman lama tidak dihapus otomatis. Admin perlu membuat backup/arsip sebelum mendekati batas. Database baru belum menggunakan hash chain tersendiri; hash chain Audit Log lama tetap apa adanya.

## Isi snapshot

Setiap rekaman mencatat waktu, jenis aktivitas, `accessedBy`, target endpoint, pengguna endpoint (`EndpointRecord.user`), dan snapshot komputer yang berasal dari registry server: waktu audit terakhir, skor, jumlah PASS/WARNING/FAIL, status karantina, port terbuka, serta nama hingga 30 kontrol FAIL/WARNING. Jika target approval tidak ditemukan pada registry, identitas target tetap dicatat dan `captureStatus` bernilai `NOT_FOUND`—kondisi tidak direka.

Akses daftar endpoint yang dipoll berkala oleh dashboard tidak dicatat sebagai akses individual, agar polling lima detik tidak membanjiri rekaman. Admin memilih endpoint dan menekan **Rekam akses & kondisi** untuk membuat catatan akses eksplisit. Approval remediasi yang berhasil dicatat otomatis.

## Verifikasi lokal

```bash
npm ci
npm run lint
npm run build
npm run test:endpoint-health-audit
```

Smoke test memeriksa penolakan akses non-admin, atribusi aktor server, snapshot kondisi, catatan approver, impor satu kali rekaman JSON lama, persistensi SQLite setelah restart backend, dan bahwa penambahan rekaman fitur ini tidak menambah/mengubah Audit Log lama atau mematahkan verifikasi hash chain yang lama.
