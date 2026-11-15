# Uji cepat di laptop Windows

Tujuan: membuktikan pipeline nyata (audit → plan → approve → dry-run → eksekusi → evidence)
tanpa menyentuh aset lain. Semua langkah aman diulang.

> Uji ini mengubah host ini. Set 1 hanya menyalakan firewall + memblokir USB storage
> (bisa dibalik). Set 2 memblokir RDP 3389. Set 3 mengaktifkan BitLocker.

## A. Server di laptop yang sama (loopback, paling mudah)

1. Siapkan `.env` (sudah ada). Pastikan `PASOPATI_API_KEY` dan `HMAC_SECRET` terisi.
2. Jalankan server di PowerShell **pertama**:

   ```powershell
   npm run dev
   ```

3. Buka PowerShell **kedua**, dari folder proyek:

   ```powershell
   # 1) audit + unggah JSON (supaya perangkat nyata muncul di dashboard)
   python .\pasopati_audit.py -u "$env:COMPUTERNAME" -o .\audit.json --no-elevate
   ```

   Buka dashboard → tab **Agent & Upload** → unggah `audit.json`.

4. Jalankan skrip uji (akan memverifikasi manifest, membuat plan, approve, lalu dry-run):

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\docs\run-windows-test.ps1 -Set 1 -DeviceId "$env:COMPUTERNAME"
   ```

5. Baca hasil dry-run. Bila wajar, jawab `y` → UAC muncul → eksekusi.

6. Cek dashboard: status plan harus `VERIFIED` (butuh audit ulang bersih) atau `ROLLED_BACK`.

## B. Dari mesin lain (LAN)

Di server: `.\setup-lan.ps1` (Administrator), lalu di laptop target:

```powershell
powershell -ExecutionPolicy Bypass -File .\docs\run-windows-test.ps1 `
  -Server http://<IP-SERVER>:3000 -ApiKey <KEY> -Hmac <HMAC> -Set 1 -DeviceId "$env:COMPUTERNAME"
```

Bila sesi Anda RDP dan memilih Set 2, siapkan konsol/KVM dulu: rule 3389 memblokir
koneksi remote baru.

## Hasil yang diharapkan

| Tahap | Yang normal terlihat |
|---|---|
| whoami | `[OK] Terhubung ... (admin)` |
| manifest | `[+] Manifest agen cocok` |
| approve | token terbit + batas waktu |
| dry-run | hanya pre-state, tidak ada perubahan |
| eksekusi | tiap langkah + evidence, status final |

Bila verify gagal, agent menghentikan eksekusi dan **rollback** (`ROLLED_BACK`).
Dead-man 10 menit juga me-rollback bila proses terputus.

## Bersih-bersih

```powershell
Remove-NetFirewallRule -DisplayName 'PASOPATI-Block-*' -ErrorAction SilentlyContinue
python .\pasopati_remediate.py --quarantine-release --no-elevate
Remove-Item "$env:USERPROFILE\.pasopati\backups" -Recurse -Force -ErrorAction SilentlyContinue
```

BitLocker tidak otomatis dimatikan: `manage-bde -off C:` (Administrator) bila ingin kembali.

## Bila macet

| Gejala | Sebab / tindakan |
|---|---|
| 401 | API key salah atau host key dicabut |
| 409 "Empat mata" | approver = pembuat → skrip sudah mengirim `selfApprove`; pastikan memakai skrip ini |
| 409 "jalur akses" | butuh `acknowledgeConsole` (skrip sudah mengirim) |
| 503 | `PASOPATI_API_KEY`/`HMAC_SECRET` belum diset di server |
| dry-run exit ≠ 0 | baca alasan; token mungkin kedaluwarsa → approve ulang |
| `python` tidak dikenali | pakai `py -3`, skrip memilih sendiri bila `python` tidak ada |
