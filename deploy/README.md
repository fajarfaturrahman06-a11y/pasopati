# Menjalankan agent sebagai layanan

Agent mendukung dua mode operasi:

| Mode | Perintah | Kapan |
|---|---|---|
| Manual | `--server --plan-id` | demo/uji, satu plan |
| Watch | `--watch --server --interval` | aset nyata, plan ditarik otomatis |

`--watch` hanya mengambil plan yang **terikat ke host** pemilik kunci, dan hanya plan `APPROVED`
yang belum kedaluwarsa. Semua langkah tetap melewati gate server (token, evidence, audit ulang,
dead-man).

## Linux (systemd)

```bash
# 1. Siapkan berkas & env
sudo install -d -m 700 /etc/pasopati /opt/pasopati
sudo install -m 600 pasopati_audit.py pasopati_remediate.py /opt/pasopati/
sudo tee /etc/pasopati/agent.env >/dev/null <<'EOF'
PASOPATI_SERVER=https://pasopati.contoh.local:3000
PASOPATI_HOST_KEY=<hostKey dari /api/hosts/enroll>
PASOPATI_API_KEY=<PASOPATI_API_KEY server>
HMAC_SECRET=<HMAC_SECRET server>
EOF
sudo chmod 600 /etc/pasopati/agent.env

# 2. Pasang unit
sudo cp deploy/pasopati-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pasopati-agent
journalctl -u pasopati-agent -f
```

Catatan: `HMAC_SECRET`/`PASOPATI_API_KEY` di host target hanya dipakai untuk tanda tangan evidence
dan escrow. Idealnya kelak diganti kunci per host.

## Windows (Task Scheduler)

```powershell
# Jalankan PowerShell sebagai Administrator
$dir = 'C:\ProgramData\PASOPATI'
New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item .\pasopati_audit.py, .\pasopati_remediate.py $dir

$env:PASOPATI_SERVER   = 'https://pasopati.contoh.local:3000'
$env:PASOPATI_HOST_KEY = '<hostKey>'
$env:PASOPATI_API_KEY    = '<PASOPATI_API_KEY>'
$env:HMAC_SECRET       = '<HMAC_SECRET>'

schtasks /create /tn "PASOPATI Agent" /sc onstart /ru SYSTEM /rl HIGHEST /f `
  /tr "cmd /c set PASOPATI_SERVER=$env:PASOPATI_SERVER&& set PASOPATI_HOST_KEY=$env:PASOPATI_HOST_KEY&& set PASOPATI_API_KEY=$env:PASOPATI_API_KEY&& set HMAC_SECRET=$env:HMAC_SECRET&& py -3 C:\ProgramData\PASOPATI\pasopati_remediate.py --watch --server $env:PASOPATI_SERVER --interval 60"
```

`cmd /c set ...&&` dipakai agar variabel tidak hilang saat task berjalan sebagai SYSTEM.
Untuk produksi, gunakan sertifikat internal + `--ca-cert` alih-alih `--insecure`.

## Verifikasi artefak sebelum jalan

Sebelum eksekusi pertama, bandingkan berkas dengan manifest server:

```bash
python3 pasopati_remediate.py --verify-manifest --strict-manifest \
  --server https://pasopati.contoh.local:3000 \
  --manifest-key "$AGENT_SIGNING_KEY"
```

`--strict-manifest` menghentikan proses bila hash berbeda. Simpan `AGENT_SIGNING_KEY`
hanya di server dan host tepercaya.

## Pemeriksaan

- `GET /api/health` harus `ok`; `GET /api/metrics` untuk scraping.
- Host yang tidak terlihat >24 jam muncul di `silentHosts` pada `/api/health`.
- Plan `EXECUTING` tanpa heartbeat 15 menit muncul di `staleExecuting`.
