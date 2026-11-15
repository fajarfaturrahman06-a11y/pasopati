<#
  PASOPATI - persiapan SISI SERVER untuk uji dari laptop lain (LAN).
  Jalankan sebagai Administrator pada batch pertama (membuat aturan firewall).

  Linux dan Windows DIPISAH: satu plan hanya berisi alias satu OS (+ alias 'any').

  Lihat daftar alias per OS:
    .\docs\run-lan-server.ps1 -ListAliases

  Uji lengkap Windows (batch A..E):
    # A: enrol host sekali
    .\docs\run-lan-server.ps1 -EnrollName LAPTOP-UJI-2 -Batch A
    # B..E: pakai ulang host yang sama
    .\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch B

  Uji lengkap Linux (batch L1..L3):
    .\docs\run-lan-server.ps1 -EnrollName SRV-LINUX -Batch L1
    .\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> -Batch L2

  Alias bebas (tetap satu OS per plan):
    .\docs\run-lan-server.ps1 -HostId HOST-xxxx -HostKey <hostKey> `
      -Aliases guest-account-disable,usb-storage-block

  Hasil: aturan firewall (khusus LocalSubnet), host ter-enrol/dipakai ulang,
  plan dibuat + disetujui, dan perintah siap-tempel untuk laptop target.

  Bersih-bersih: -Remove
#>
param(
    [string]$EnrollName,
    [ValidateSet('1', '2', '3')][string]$Set = '1',
    [string[]]$Aliases,
    [ValidateSet('A', 'B', 'C', 'D', 'E', 'L1', 'L2', 'L3')][string]$Batch,
    [ValidateSet('auto', 'windows', 'linux')][string]$Os = 'auto',
    [switch]$ListAliases,
    [string]$DeviceId,
    [string]$HostId,
    [string]$HostKey,
    [int]$Port = 3000,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$RuleName = "PASOPATI $Port"

# Risiko per alias = sama dengan ALLOWLIST_ANALISA di agent. Dipakai untuk
# menyusun item plan saat -Aliases dipakai, dan untuk menolak nama alias salah.
$AliasRisk = @{
    'fw-enable-defender'       = @{ risk = 'MEDIUM'; os = 'windows' }
    'guest-account-disable'    = @{ risk = 'MEDIUM'; os = 'windows' }
    'usb-storage-block'        = @{ risk = 'MEDIUM'; os = 'windows' }
    'rdp-nla-enable'           = @{ risk = 'MEDIUM'; os = 'windows' }
    'uac-enable'               = @{ risk = 'MEDIUM'; os = 'windows' }
    'bitlocker-enable'         = @{ risk = 'HIGH';   os = 'windows' }
    'win-auditpol-process'     = @{ risk = 'LOW';    os = 'windows' }
    'ports-block-windows'      = @{ risk = 'HIGH';   os = 'windows' }
    'fw-enable-ufw'            = @{ risk = 'MEDIUM'; os = 'linux' }
    'ssh-disable-root'         = @{ risk = 'HIGH';   os = 'linux' }
    'auditd-enable'            = @{ risk = 'LOW';    os = 'linux' }
    'usb-block-linux'          = @{ risk = 'MEDIUM'; os = 'linux' }
    'grub-config-perms'        = @{ risk = 'LOW';    os = 'linux' }
    'sudoers-remove-nopasswd'  = @{ risk = 'MEDIUM'; os = 'linux' }
    'suid-strip-critical'      = @{ risk = 'MEDIUM'; os = 'linux' }
    'ports-block-linux'        = @{ risk = 'HIGH';   os = 'linux' }
    'advisory-fde'             = @{ risk = 'LOW';    os = 'any' }
    'advisory-rootkit'         = @{ risk = 'LOW';    os = 'any' }
    'advisory-secureboot'      = @{ risk = 'LOW';    os = 'any' }
    'advisory-admins'          = @{ risk = 'LOW';    os = 'any' }
}
$AdvisoryAliases = @('advisory-fde', 'advisory-rootkit', 'advisory-secureboot', 'advisory-admins')

# Batch uji: satu OS per batch. 'any' = advisory yang berlaku di semua OS.
$BatchPresets = @{
    'A'  = @{ os = 'windows'; label = 'aman'; aliases = @('guest-account-disable', 'usb-storage-block', 'win-auditpol-process', 'advisory-fde', 'advisory-rootkit', 'advisory-secureboot', 'advisory-admins') }
    'B'  = @{ os = 'windows'; label = 'sedang'; aliases = @('rdp-nla-enable', 'uac-enable') }
    'C'  = @{ os = 'windows'; label = 'firewall'; aliases = @('fw-enable-defender') }
    'D'  = @{ os = 'windows'; label = 'BitLocker'; aliases = @('bitlocker-enable') }
    'E'  = @{ os = 'windows'; label = 'port (terakhir)'; aliases = @('ports-block-windows') }
    'L1' = @{ os = 'linux'; label = 'aman'; aliases = @('auditd-enable', 'grub-config-perms', 'sudoers-remove-nopasswd', 'advisory-fde', 'advisory-rootkit', 'advisory-secureboot', 'advisory-admins') }
    'L2' = @{ os = 'linux'; label = 'sedang'; aliases = @('usb-block-linux', 'suid-strip-critical') }
    'L3' = @{ os = 'linux'; label = 'jaringan (terakhir)'; aliases = @('fw-enable-ufw', 'ssh-disable-root', 'ports-block-linux') }
}
# Set lama (Windows saja) dipertahankan agar perintah lama tetap jalan.
$SetPresets = @{
    '1' = @('usb-storage-block', 'fw-enable-defender', 'advisory-secureboot')
    '2' = @('ports-block-windows', 'fw-enable-defender')
    '3' = @('bitlocker-enable', 'win-auditpol-process')
}

function Show-AliasesByOs {
    foreach ($osName in @('windows', 'linux', 'any')) {
        $names = @($AliasRisk.Keys | Where-Object { $AliasRisk[$_].os -eq $osName } | Sort-Object)
        Write-Host "[$osName] $($names.Count) alias" -ForegroundColor Cyan
        foreach ($n in $names) { Write-Host ("  - {0} ({1})" -f $n, $AliasRisk[$n].risk) }
        Write-Host ''
    }
    Write-Host '[i] Satu plan = satu OS (+ alias any).' -ForegroundColor Yellow
}

if ($ListAliases) {
    Show-AliasesByOs
    return
}

function Test-Admin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    if (-not (Test-Admin)) {
        throw 'Jalankan PowerShell sebagai Administrator.'
    }
}

function Format-Ttl([long]$expiresAtMs) {
    $left = [math]::Round(($expiresAtMs - [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) / 60000, 1)
    if ($left -lt 0) { $left = 0 }
    return $left
}

if ($Remove) {
    Assert-Admin
    Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    Write-Host "[OK] Aturan firewall '$RuleName' dihapus." -ForegroundColor Green
    return
}

# --- Firewall: hanya subnet lokal ---
# Batch berikutnya tidak perlu Administrator bila aturan sudah ada.
if (-not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
    if (-not (Test-Admin)) {
        throw "Aturan firewall '$RuleName' belum ada. Jalankan sekali sebagai Administrator, atau buka port TCP $Port manual."
    }
    New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Protocol TCP -LocalPort $Port `
        -RemoteAddress LocalSubnet -Action Allow -Profile Any | Out-Null
    Write-Host "[OK] Firewall: TCP $Port diizinkan dari LocalSubnet." -ForegroundColor Green
} else {
    Write-Host "[i] Aturan firewall sudah ada." -ForegroundColor Cyan
}

# --- Alamat IP yang harus dipakai laptop target ---
# Utamakan adapter Wi-Fi (bukan VMware/WSL/loopback). Ethernet4/VMnet sering muncul lebih dulu.
$candidates = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254*' -and $_.InterfaceAlias -notlike '*WSL*' -and $_.InterfaceAlias -notlike '*VMnet*' }
$wifi = $candidates | Where-Object { $_.InterfaceAlias -eq 'Wi-Fi' } | Select-Object -First 1
if ($wifi) {
    $chosen = $wifi
} else {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
    $chosen = if ($route) { $candidates | Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex } | Select-Object -First 1 } else { $candidates | Select-Object -First 1 }
}
if (-not $chosen) { throw 'Tidak ada IP LAN. Sambungkan Wi-Fi/LAN dulu.' }
if (@($candidates).Count -gt 1) {
    Write-Host ("[i] Beberapa adapter aktif: {0}" -f (($candidates | ForEach-Object { "$($_.InterfaceAlias)=$($_.IPAddress)" }) -join ', ')) -ForegroundColor Yellow
}
$ip = $chosen.IPAddress
$server = "http://${ip}:$Port"
Write-Host "[OK] Server harus diakses dari: $server" -ForegroundColor Green
Write-Host '    Pastikan server sudah jalan (npm run dev) di terminal lain.' -ForegroundColor Yellow

# --- Kredensial server ---
if (-not (Test-Path '.\.env')) { throw '.env tidak ada; tidak bisa enrol/plan.' }
$envMap = @{}
Get-Content '.\.env' | ForEach-Object {
    if ($_ -match '^\s*([A-Z0-9_]+)\s*=\s*(.*)$') { $envMap[$Matches[1]] = $Matches[2].Trim() }
}
$ApiKey = $envMap['PASOPATI_API_KEY']
$Hmac = $envMap['HMAC_SECRET']
if (-not $ApiKey -or -not $Hmac) { throw 'PASOPATI_API_KEY / HMAC_SECRET kosong di .env.' }
$headers = @{ 'X-Pasopati-API-Key' = $ApiKey }

try {
    $health = Invoke-RestMethod "$server/api/health" -Headers $headers
    Write-Host "[OK] Server aktif (versi $($health.version))." -ForegroundColor Green
}
catch {
    $code = $_.Exception.Response.StatusCode.value__
    $detail = $_.ErrorDetails.Message
    if ($code -eq 503 -and $detail) {
        try { $degraded = $detail | ConvertFrom-Json } catch { $degraded = $null }
        if ($degraded -and $degraded.version) {
            Write-Host ("[!] Server hidup (versi {0}) tetapi status {1}: auditChainOk={2}, activePlans={3}." -f `
                $degraded.version, $degraded.status, $degraded.auditChainOk, $degraded.activePlans) -ForegroundColor Yellow
            Write-Host '    Uji tetap bisa jalan; periksa dashboard bila status degraded tidak diharapkan.' -ForegroundColor Yellow
        } else {
            throw ("Server menjawab 503: $detail. Hentikan proses lama, lalu jalankan ulang 'npm run dev' dari folder proyek agar .env baru terbaca.")
        }
    } else {
        throw "Server belum bisa diakses di $server. Jalankan 'npm run dev' dulu di terminal lain."
    }
}

# --- Susun item plan: -Aliases > -Batch > -Set, selalu satu OS per plan ---
# Divalidasi SEBELUM enrol host agar kesalahan tidak meninggalkan host yatim.
$targetOs = $Os
$source = 'Set'
if ($Aliases) {
    $aliasList = @($Aliases | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if ($aliasList.Count -eq 0) { throw '-Aliases kosong.' }
    $source = '-Aliases'
} elseif ($Batch) {
    $preset = $BatchPresets[$Batch]
    $aliasList = @($preset.aliases)
    $source = "Batch $Batch ($($preset.label))"
    if ($targetOs -eq 'auto') { $targetOs = $preset.os }
    elseif ($targetOs -ne $preset.os) { throw "Batch $Batch untuk $($preset.os), bukan $targetOs." }
} else {
    $aliasList = @($SetPresets[$Set])
    $source = "Set $Set"
    if ($targetOs -eq 'auto') { $targetOs = 'windows' }
    elseif ($targetOs -ne 'windows') { throw "Set $Set berisi alias Windows. Untuk Linux pakai -Batch L1..L3." }
}

$unknown = @($aliasList | Where-Object { -not $AliasRisk.ContainsKey($_) })
if ($unknown.Count -gt 0) {
    throw ("Alias tidak dikenal: {0}. Lihat -ListAliases." -f ($unknown -join ', '))
}

# Satu plan tidak boleh mencampur Windows dan Linux: agent menolak alias OS lain.
$osSet = @($aliasList | ForEach-Object { $AliasRisk[$_].os } | Where-Object { $_ -ne 'any' } | Sort-Object -Unique)
if ($osSet.Count -gt 1) {
    $win = @($aliasList | Where-Object { $AliasRisk[$_].os -eq 'windows' }) -join ', '
    $lin = @($aliasList | Where-Object { $AliasRisk[$_].os -eq 'linux' }) -join ', '
    throw ("Alias Windows dan Linux tercampur dalam satu plan. Pisahkan:`n  Windows: {0}`n  Linux: {1}" -f $win, $lin)
}
if ($osSet.Count -eq 1) {
    if ($targetOs -ne 'auto' -and $targetOs -ne $osSet[0]) {
        throw ("Plan berisi alias {0}, tetapi -Os {1}." -f $osSet[0], $targetOs)
    }
    $targetOs = $osSet[0]
} else {
    throw 'Plan hanya berisi advisory. Tambahkan minimal satu alias enforce (lihat -ListAliases).'
}

$items = @($aliasList | ForEach-Object { @{ alias = $_; risk = $AliasRisk[$_].risk } })
$enforceCount = @($aliasList | Where-Object { $AdvisoryAliases -notcontains $_ }).Count
if ($enforceCount -eq 0) {
    throw 'Plan harus punya minimal satu langkah enforce (advisory saja tidak cukup).'
}
Write-Host ("[i] OS target: {0} | sumber: {1} | {2} langkah ({3} enforce, {4} advisory)." -f `
    $targetOs, $source, $items.Count, $enforceCount, ($items.Count - $enforceCount)) -ForegroundColor Cyan

# --- Host: enrol baru, atau pakai ulang hostId/hostKey yang sudah ada ---
$reusedHost = $false
if ($HostId) {
    if (-not $HostKey) { $HostKey = (Read-Host "HostKey untuk $HostId").Trim() }
    if (-not $HostKey) { throw 'HostKey kosong; tidak bisa memakai ulang host.' }
    try {
        $who = Invoke-RestMethod "$server/api/whoami" -Headers @{ 'X-Pasopati-Host-Key' = $HostKey }
    } catch {
        throw "HostKey ditolak server untuk $HostId. Periksa kembali atau enrol host baru (tanpa -HostId)."
    }
    if ($who.kind -ne 'host') {
        throw "Kredensial ini bukan host key (server mengenali peran '$($who.role)')."
    }
    if ($who.hostId -ne $HostId) {
        Write-Host ("[!] HostKey ini milik {0}, bukan {1}. Memakai {0}." -f $who.hostId, $HostId) -ForegroundColor Yellow
        $HostId = $who.hostId
    }
    $enrol = @{ hostId = $HostId; hostKey = $HostKey; name = $who.name }
    $reusedHost = $true
    Write-Host "[OK] Memakai ulang host: $($enrol.hostId) ($($enrol.name))" -ForegroundColor Green
} else {
    if (-not $EnrollName) { $EnrollName = (Read-Host 'Nama host target (mis. LAPTOP-UJI-2)').Trim() }
    $enrol = Invoke-RestMethod -Method Post "$server/api/hosts/enroll" -Headers $headers `
        -ContentType 'application/json' -Body (@{ name = $EnrollName } | ConvertTo-Json)
    Write-Host "[OK] Host ter-enrol: $($enrol.hostId)" -ForegroundColor Green
}

if (-not $DeviceId) { $DeviceId = $enrol.name }

# --- Plan terikat host, langsung disetujui (approver = master) ---
$created = Invoke-RestMethod -Method Post "$server/api/remediation-plan" -Headers $headers `
    -ContentType 'application/json' `
    -Body (@{ deviceId = $DeviceId; hostId = $enrol.hostId; items = @($items) } | ConvertTo-Json -Depth 6)
$planId = $created.plan.planId
if ($created.plan.requiresConsoleAck) {
    Write-Host '[!] Plan menyentuh jalur akses. Approve memakai acknowledgeConsole=true (pastikan ada konsol/KVM).' -ForegroundColor Yellow
}

$approve = Invoke-RestMethod -Method Post "$server/api/remediation-approve" -Headers $headers `
    -ContentType 'application/json' `
    -Body (@{ planId = $planId; selfApprove = $true; acknowledgeConsole = $true; overrideQueue = $true } | ConvertTo-Json)
$ttlMin = Format-Ttl $approve.expiresAt
Write-Host "[OK] Plan $planId dibuat & disetujui. Token berlaku ~$ttlMin menit." -ForegroundColor Green

Write-Host ''
if ($targetOs -eq 'windows') {
    Write-Host '=== DI LAPTOP WINDOWS TARGET ===' -ForegroundColor Cyan
    if (-not $reusedHost) {
        Write-Host '0) Sekali saja: unduh alat uji dari server:'
        Write-Host "   Invoke-WebRequest $server/api/download/pasopati_audit.py -OutFile .\pasopati_audit.py"
        Write-Host "   Invoke-WebRequest $server/api/download/pasopati_remediate.py -OutFile .\pasopati_remediate.py"
        Write-Host "   Invoke-WebRequest $server/api/download/run-windows-test.ps1 -OutFile .\run-windows-test.ps1"
        Write-Host '   (audit read-only: python .\pasopati_audit.py -u "$env:COMPUTERNAME" -o .\audit.json --no-elevate)'
        Write-Host ''
    }
    Write-Host 'Jalankan plan yang sudah disetujui (host key saja, tanpa master key):'
    Write-Host ''
    Write-Host "powershell -ExecutionPolicy Bypass -File .\run-windows-test.ps1 ``" -ForegroundColor White
    Write-Host "  -Server $server -Set 4 -PlanId $planId ``" -ForegroundColor White
    Write-Host "  -HostId $($enrol.hostId) -HostKey $($enrol.hostKey) -Hmac $Hmac -NoApprove" -ForegroundColor White
} else {
    Write-Host '=== DI HOST LINUX TARGET ===' -ForegroundColor Cyan
    if (-not $reusedHost) {
        Write-Host '0) Sekali saja: unduh agent dari server:'
        Write-Host "   curl -fsS $server/api/download/pasopati_audit.py -o pasopati_audit.py"
        Write-Host "   curl -fsS $server/api/download/pasopati_remediate.py -o pasopati_remediate.py"
        Write-Host '   (audit read-only: python3 pasopati_audit.py -u "$(hostname)" -o audit.json --no-elevate)'
        Write-Host ''
    }
    Write-Host 'Dry-run dulu (tanpa perubahan), lalu eksekusi:'
    Write-Host ''
    Write-Host ("python3 pasopati_remediate.py --server {0} --plan-id {1} ``" -f $server, $planId) -ForegroundColor White
    Write-Host ("  --host-key {0} --hmac-key {1} --no-exec --no-elevate --force-access-risk" -f $enrol.hostKey, $Hmac) -ForegroundColor White
    Write-Host ''
    Write-Host ("python3 pasopati_remediate.py --server {0} --plan-id {1} ``" -f $server, $planId) -ForegroundColor White
    Write-Host ("  --host-key {0} --hmac-key {1} --deadman-seconds 600 --force-access-risk" -f $enrol.hostKey, $Hmac) -ForegroundColor White
}
Write-Host ''
Write-Host "[i] Token ~$ttlMin menit. Bila kedaluwarsa, jalankan ulang skrip ini dengan -HostId/-HostKey yang sama" -ForegroundColor Yellow
Write-Host '    (plan baru langsung disetujui). Jangan approve ulang plan lama: server menolak bila token masih hidup.' -ForegroundColor Yellow
Write-Host ''
Write-Host 'Batch berikutnya (tanpa enrol host baru):' -ForegroundColor Cyan
Write-Host ("   .\docs\run-lan-server.ps1 -HostId {0} -HostKey <hostKey> -Batch <A..E | L1..L3>" -f $enrol.hostId)
Write-Host ''
Write-Host 'Simpan hostKey + HMAC; jangan sebarkan master key ke target bila tak perlu.' -ForegroundColor Cyan
