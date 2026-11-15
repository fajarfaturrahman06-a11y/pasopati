<#
  PASOPATI - uji aman di laptop Windows (loopback maupun LAN).
  Urutan: verifikasi manifest -> buat plan -> approve -> DRY-RUN -> konfirmasi -> eksekusi.

  Contoh loopback (server di laptop yang sama):
    powershell -ExecutionPolicy Bypass -File .\docs\run-windows-test.ps1 -Set 1

  Contoh LAN (server di mesin lain):
    powershell -ExecutionPolicy Bypass -File .\docs\run-windows-test.ps1 `
      -Server http://192.168.1.20:3000 -ApiKey <KEY> -Hmac <HMAC> -HostKey <HOSTKEY> -HostId HOST-xxxx

  Jalankan di PowerShell BIASA (UAC akan muncul saat eksekusi nyata).
#>
param(
    [string]$Server = 'http://localhost:3000',
    [string]$ApiKey,
    [string]$Hmac,
    [string]$DeviceId = $env:COMPUTERNAME,
    [string]$HostId,
    [string]$HostKey,
    [ValidateSet('1', '2', '3', '4')][string]$Set = '1',
    [string]$PlanId,
    [int]$DeadmanSeconds = 600,
    [switch]$NoApprove,
    [switch]$Auto
)

$ErrorActionPreference = 'Stop'
# Jalankan dari folder tempat skrip ini berada; pindah ke root repo hanya bila
# skrip ada di subfolder docs dan agent berada satu level di atasnya.
$repoRoot = Split-Path -Parent $PSScriptRoot
if ($repoRoot -and (Test-Path (Join-Path $repoRoot 'pasopati_remediate.py'))) {
    Set-Location $repoRoot
} else {
    Set-Location $PSScriptRoot
}

function Show-ServerError($err) {
    if ($err.ErrorDetails.Message) { Write-Host $err.ErrorDetails.Message -ForegroundColor Yellow }
    else { Write-Host $err.Exception.Message -ForegroundColor Yellow }
}

# --- Kredensial: parameter, atau .env lokal (hanya bila server di mesin ini) ---
if (-not $ApiKey -and (Test-Path '.\.env')) {
    $envMap = @{}
    Get-Content '.\.env' | ForEach-Object {
        if ($_ -match '^\s*([A-Z0-9_]+)\s*=\s*(.*)$') { $envMap[$Matches[1]] = $Matches[2].Trim() }
    }
    if (-not $ApiKey) { $ApiKey = $envMap['PASOPATI_API_KEY'] }
    if (-not $Hmac) { $Hmac = $envMap['HMAC_SECRET'] }
}
if (-not $ApiKey -and -not $HostKey) { $ApiKey = (Read-Host 'PASOPATI_API_KEY / kunci operator').Trim() }
if (-not $Hmac) { $Hmac = (Read-Host 'HMAC_SECRET').Trim() }
if ((-not $ApiKey -and -not $HostKey) -or -not $Hmac) { throw 'Kredensial (API/host key) atau HMAC kosong.' }

if (-not (Test-Path '.\pasopati_remediate.py') -or -not (Test-Path '.\pasopati_audit.py')) {
    throw 'File agent tidak ditemukan di folder proyek.'
}

# --- Deteksi sesi remote (SESSIONNAME bisa kosong di shell non-interaktif) ---
$session = $env:SESSIONNAME
if ($session -like 'RDP*') {
    Write-Host '[!] Sesi ini RDP. Jangan pakai Set 2 tanpa konsol/KVM: port 3389 akan diblokir.' -ForegroundColor Yellow
} elseif (-not $session) {
    Write-Host '[i] SESSIONNAME kosong (shell non-interaktif). Pastikan Anda punya akses fisik/konsol bila memilih Set 2.' -ForegroundColor Yellow
}

# --- Server + kredensial ---
$headers = @{}
if ($ApiKey) { $headers['X-Pasopati-API-Key'] = $ApiKey }
if ($HostKey) { $headers['X-Pasopati-Host-Key'] = $HostKey }
try {
    $who = Invoke-RestMethod -Method Get -Uri "$Server/api/whoami" -Headers $headers
    Write-Host ("[OK] Terhubung ke server sebagai {0} ({1})." -f $who.name, $who.role) -ForegroundColor Green
} catch {
    Write-Host '[X] Server tidak terjangkau atau kredensial ditolak.' -ForegroundColor Red
    Show-ServerError $_
    return
}
if ($HostId) { Write-Host "[i] Plan akan diikat ke host $HostId." -ForegroundColor Cyan }

# --- Manifest agen ---
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
$pyArgs = @()
if (-not $python) { $python = (Get-Command py -ErrorAction SilentlyContinue).Source; $pyArgs = @('-3') }
if (-not $python) { throw 'Python tidak ditemukan.' }

Write-Host '[*] Memeriksa manifest agen...' -ForegroundColor Cyan
& $python @pyArgs '.\pasopati_remediate.py' '--verify-manifest' '--server' $Server '--no-elevate'
$manifestOk = ($LASTEXITCODE -eq 0)

# --- Plan ---
if ($Set -eq '4') {
    if (-not $PlanId) {
        $PlanId = (Read-Host 'Tempel PLAN ID').Trim()
        if (-not $PlanId) { throw 'Plan ID kosong.' }
    }
} else {
    $items = switch ($Set) {
        '1' { @(
                @{ alias = 'usb-storage-block'; risk = 'MEDIUM' },
                @{ alias = 'fw-enable-defender'; risk = 'HIGH' },
                @{ alias = 'advisory-secureboot'; risk = 'LOW' }
            ) }
        '2' { @(
                @{ alias = 'ports-block-windows'; risk = 'HIGH' },
                @{ alias = 'fw-enable-defender'; risk = 'HIGH' }
            ) }
        '3' { @(
                @{ alias = 'bitlocker-enable'; risk = 'HIGH' },
                @{ alias = 'win-auditpol-process'; risk = 'LOW' }
            ) }
    }
    $body = @{ deviceId = $DeviceId; items = @($items) }
    if ($HostId) { $body.hostId = $HostId }
    try {
        $created = Invoke-RestMethod -Method Post -Uri "$Server/api/remediation-plan" -Headers $headers `
            -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 6)
        $PlanId = $created.plan.planId
        Write-Host "[OK] Plan dibuat: $PlanId" -ForegroundColor Green
    } catch {
        Write-Host '[X] Gagal membuat plan.' -ForegroundColor Red
        Show-ServerError $_
        return
    }
}

# --- Approve (empat mata + konfirmasi akses) ---
if (-not $NoApprove) {
    try {
        $approve = Invoke-RestMethod -Method Post -Uri "$Server/api/remediation-approve" -Headers $headers `
            -ContentType 'application/json' `
            -Body (@{ planId = $PlanId; selfApprove = $true; acknowledgeConsole = $true; overrideQueue = $true } | ConvertTo-Json)
        Write-Host "[OK] Plan disetujui. Token berlaku sampai $( [DateTimeOffset]::FromUnixTimeMilliseconds($approve.expiresAt).LocalDateTime )." -ForegroundColor Green
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 409) {
            Write-Host '[i] Plan sudah disetujui (409). Lanjut memakai token yang sudah ada.' -ForegroundColor Yellow
        } else {
            Write-Host '[X] Approve gagal.' -ForegroundColor Red
            Show-ServerError $_
            return
        }
    }
} else {
    Write-Host '[i] -NoApprove: memakai plan yang sudah disetujui server.' -ForegroundColor Cyan
}

$plan = (Invoke-RestMethod -Method Get -Uri "$Server/api/remediation-plans/$PlanId" -Headers $headers).plan
Write-Host ''
Write-Host 'Langkah plan:' -ForegroundColor Cyan
@($plan.items) | ForEach-Object { Write-Host ("  - {0} ({1})" -f $_.alias, $_.risk) }
if (@($plan.items).alias -contains 'bitlocker-enable') {
    Write-Host '[!] BitLocker berjalan di background. Recovery key di-escrow ke server + file lokal 0600 — salin!' -ForegroundColor Yellow
}
if (@($plan.items).alias -contains 'ports-block-windows') {
    Write-Host '[!] ports-block-windows memblokir RDP 3389. Sesi remote baru tidak bisa masuk.' -ForegroundColor Yellow
}
Write-Host "[i] Dead-man: rollback otomatis ${DeadmanSeconds} dtk bila hasil tak final." -ForegroundColor Cyan

# --- Dry-run ---
$common = @('--server', $Server, '--plan-id', $PlanId, '--hmac-key', $Hmac)
if ($ApiKey) { $common += @('--remediate-api-key', $ApiKey) }
if ($HostKey) { $common += @('--host-key', $HostKey) }

Write-Host ''
Write-Host '=== DRY-RUN (--no-exec, tanpa perubahan) ===' -ForegroundColor Cyan
& $python @pyArgs '.\pasopati_remediate.py' @common '--no-exec' '--no-elevate' '--force-access-risk'
if ($LASTEXITCODE -ne 0) {
    Write-Host "[X] Dry-run gagal (exit $LASTEXITCODE). Belum ada perubahan." -ForegroundColor Red
    return
}
if (-not $manifestOk) {
    Write-Host '[!] Manifest agen TIDAK cocok. Lanjut hanya bila Anda yakin.' -ForegroundColor Yellow
}

$go = if ($Auto) { 'y' } else { (Read-Host 'Lanjut EKSEKUSI NYATA? (y/N)').Trim() }
if ($go -notmatch '^[yY]') {
    Write-Host 'Selesai tanpa perubahan. Plan tetap APPROVED sampai token kedaluwarsa.' -ForegroundColor Yellow
    return
}

Write-Host ''
Write-Host '=== EKSEKUSI NYATA (UAC akan muncul) ===' -ForegroundColor Cyan
& $python @pyArgs '.\pasopati_remediate.py' @common '--deadman-seconds' $DeadmanSeconds '--force-access-risk'
$exit = $LASTEXITCODE

Write-Host ''
try {
    $final = (Invoke-RestMethod -Method Get -Uri "$Server/api/remediation-plans/$PlanId" -Headers $headers).plan
    Write-Host ("Status akhir: {0} | evidence: {1}" -f $final.status, @($final.evidence).Count) -ForegroundColor Cyan
} catch {
    Write-Host "Exit $exit. Cek status di dashboard." -ForegroundColor Yellow
}
if ($exit -ne 0) {
    Write-Host "[!] Exit $exit. Bila ROLLED_BACK, host sudah dipulihkan otomatis." -ForegroundColor Yellow
}
Get-ChildItem "$env:USERPROFILE\.pasopati\backups" -Filter '*bitlocker-recovery.txt' -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host "Recovery key: $($_.FullName)"; Get-Content $_.FullName }
