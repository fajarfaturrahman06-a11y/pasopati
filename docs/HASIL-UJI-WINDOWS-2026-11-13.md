# Hasil Uji Lapangan — Laptop Windows

**Tanggal:** 13 November 2026
**Lingkungan:** laptop uji Windows 11, PowerShell, hotspot iPhone (`172.20.10.0/24`), server WSL di mesin terpisah.
**Branch:** `audit/fixes-2026-11-13`

## Ringkasan

Seluruh skenario yang direncanakan berhasil, termasuk empat bug yang ditemukan saat uji dan langsung diperbaiki:

| Skenario | Hasil |
|---|---|
| Audit read-only + upload JSON | PASS |
| Plan aman (`fw-enable-defender`, `usb-storage-block`, advisory) | VERIFIED |
| Plan port (`ports-block-windows`, `fw-enable-defender`) | VERIFIED |
| Alias `guest-account-disable` (idempoten) | VERIFIED |
| Alias `win-auditpol-process` (setelah fix GUID) | VERIFIED |
| Alias `uac-enable` (idempoten) | VERIFIED |
| Alias `rdp-nla-enable` (idempoten) | VERIFIED |
| Karantina (`blockinbound,blockoutbound`) | PASS |
| Release karantina | PASS |
| Rollback rule port | PASS |
| Upload `audit-akhir` / `audit-pasca-restore` | PASS |
| ZIP tanpa `.env`, `opencode.json`, `reapprove.ps1`, `.git`, `dist` | PASS |
| Evidence signature palsu ditolak | `401` |
| Evidence signature HMAC valid diterima | `200` |

## Bug yang ditemukan & diperbaiki

1. **`--quarantine-release` diabaikan** bila dijalankan tanpa `--quarantine` — dispatcher hanya memeriksa flag karantina. Diperbaiki + 3 test (`2fbd142`).
2. **`win-auditpol-process` gagal di Windows berbahasa Indonesia** — nama subkategori Inggris ditolak `auditpol`. Diganti GUID + parsing CSV numerik (`20b74b9`).
3. **Plan dengan satu item ditolak** — `ConvertTo-Json` PowerShell mengirim objek, bukan array. Server kini menerima keduanya (`9bc8afb`).
4. **UI crash saat upload JSON tanpa `scoring`** — kartu konfirmasi membaca `scoring` tanpa guard. Ditambah fallback (`fe0e7ab`).

## Keadaan akhir laptop

- Port 445 terbuka kembali (rule `PASOPATI-Block-*` dihapus).
- Firewall Domain/Private/Public aktif.
- `USBSTOR Start=3` (USB normal).
- Audit policy Process Creation nonaktif.
- Guest nonaktif; UAC dan NLA sesuai baseline.
- BitLocker belum diuji (sengaja ditunda).

## Catatan

- Starter plan pertama sempat menyertakan BitLocker; diganti plan kecil agar aman.
- Selama karantina, konektivitas putus total sesuai desain; pemulihan manual `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound` berhasil saat rilis otomatis masih bermasalah.
- Server tidak diubah selain perbaikan kode di atas; data uji berada di `data/` runtime.
