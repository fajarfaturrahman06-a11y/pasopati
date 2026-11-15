# Paket profil kontrol

Berkas di folder ini adalah **YAML** (isinya JSON — JSON adalah subset YAML, jadi
tidak memerlukan parser tambahan; `yaml.safe_load` juga menerimanya).

Setiap kontrol:

```json
{
  "parameter": "Nama kontrol",
  "category": "Access Control",
  "cis_id": "CIS 1.2.3",
  "stig": "DISA STIG V-xxxxx",
  "severity": "high|medium|low",
  "na_if": "wsl | missing:<path> | program_missing:<cmd>",
  "mitigation": "Cara memperbaiki",
  "check": { "type": "...", "...": "..." }
}
```

Tipe `check` yang didukung:

| type | Field | Arti |
|---|---|---|
| `registry` | `path`, `name`, `dword?`, `expect` | nilai registry harus termasuk `expect` (int/string/list) |
| `command` | `argv`, `expect_exit?`, `output?`, `mode?`, `min?`, `max?` | jalankan perintah; cocokkan exit/keluaran/nilai numerik |
| `sysctl` | `path` (`a.b.c`), `expect` | nilai `/proc/sys` harus termasuk `expect` |
| `file_mode` | `path`, `max` | mode oktal harus <= `max` |
| `file_content` | `path`, `require[]`, `forbid[]` | regex wajib ada / wajib tidak ada |
| `service` | `name`, `expect` (`running`/`stopped`/`enabled`/`disabled`) | status layanan |
| `exists` | `path`, `want` | keberadaan berkas |
| `sshd` | `directive`, `expect` | nilai efektif `sshd -T` |

Aturan:

- `severity` high/medium → `FAIL` saat tidak sesuai; `low` → `WARNING`.
- Nilai tak terbaca → `WARNING` (bukan `FAIL` palsu).
- `na_if` membuat kontrol dilaporkan `N/A` dan dikecualikan dari skor.
- Kontrol dengan `alias` di server harus punya kata kunci parameter yang cocok di
  `ALIAS_POST_CHECK` agar gate audit-ulang bekerja.
- Tambahkan `na_if: program_missing:<cmd>` untuk alat yang tidak selalu ada
  (mis. `dpkg`, `sshd`) agar distribusi lain tidak menghasilkan FAIL palsu.
