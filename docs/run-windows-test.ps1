# ============================================================================
# PASOPATI - uji aman di laptop Windows: pilih set -> plan -> approve ->
# dry-run (--no-exec) -> konfirmasi -> eksekusi nyata.
# Jalankan di PowerShell BIASA pada laptop target. Jangan di mesin server.
# ============================================================================
$ErrorActionPreference = 'Stop'
Set-Location 'C:\Users\niko\Downloads\PASOPATI'
$Server = 'http://172.20.10.6:3000'

function Show-ServerError($err) {
    if ($err.ErrorDetails.Message) { Write-Host $err.ErrorDetails.Message -ForegroundColor Yellow }
    else { Write-Host $err.Exception.Message -ForegroundColor Yellow }
}

if (-not (Test-Path '.\pasopati_remediate.py') -or -not (Test-Path '.\pasopati_audit.py')) {
    throw 'File agent tidak ditemukan. Unduh pasopati_audit.py + pasopati_remediate.py ke folder ini dulu.'
}

Write-Host ''
Write-Host 'Tempel PASOPATI_API_KEY lalu Enter:' -ForegroundColor Cyan
$ApiKey = (Read-Host).Trim()
Write-Host 'Tempel HMAC_SECRET lalu Enter:' -ForegroundColor Cyan
$Hmac = (Read-Host).Trim()
if (-not $ApiKey -or -not $Hmac) { throw 'API key / HMAC kosong.' }

$headers = @{ 'X-Pasopati-API-Key' = $ApiKey }
try {
    Invoke-RestMethod -Method Get -Uri "$Server/api/audit-logs?limit=1" -Headers $headers | Out-Null
    Write-Host '[OK] Server terjangkau dan API key valid.' -ForegroundColor Green
} catch {
    Write-Host '[X] Gagal terhubung atau API key ditolak.' -ForegroundColor Red
    Show-ServerError $_
    return
}

Write-Host ''
Write-Host 'Pilih set uji:' -ForegroundColor Cyan
Write-Host '  1 = Aman (firewall + USB + advisory)  <- disarankan untuk pertama'
Write-Host '  2 = Port berbahaya + firewall'
Write-Host '  3 = BitLocker (enkripsi background, simpan recovery key)'
Write-Host '  4 = Pakai PLAN ID yang sudah ada'
$choice = (Read-Host 'Ketik 1/2/3/4').Trim()

$planId = ''
if ($choice -eq '4') {
    $planId = (Read-Host 'Tempel PLAN ID').Trim()
    if (-not $planId) { throw 'Plan ID kosong.' }
} else {
    $items = switch ($choice) {
        '1' { @(
                @{ alias = 'fw-enable-defender'; risk = 'HIGH' },
                @{ alias = 'usb-storage-block'; risk = 'MEDIUM' },
                @{ alias = 'advisory-secureboot'; risk = 'LOW' }
            ) }
        '2' { @(
                @{ alias = 'ports-block-windows'; risk = 'MEDIUM' },
                @{ alias = 'fw-enable-defender'; risk = 'HIGH' }
            ) }
        '3' { @(@{ alias = 'bitlocker-enable'; risk = 'HIGH' }) }
        default { throw 'Pilihan tidak valid.' }
    }
    $items = @($items)
    $deviceId = (Read-Host 'Device ID [LAPTOP-UJI-NIKO]').Trim()
    if (-not $deviceId) { $deviceId = 'LAPTOP-UJI-NIKO' }

    try {
        $createBody = @{ deviceId = $deviceId; createdBy = 'operator-laptop'; items = $items } | ConvertTo-Json -Depth 5
        $created = Invoke-RestMethod -Method Post -Uri "$Server/api/remediation-plan" -Headers $headers -ContentType 'application/json' -Body $createBody
        $planId = $created.plan.planId
        Write-Host "[OK] Plan dibuat: $planId" -ForegroundColor Green
    } catch {
        Write-Host '[X] Gagal membuat plan.' -ForegroundColor Red
        Show-ServerError $_
        return
    }
}

# Siapkan / setujui plan
try {
    $plan = (Invoke-RestMethod -Method Get -Uri "$Server/api/remediation-plans/$planId" -Headers $headers).plan
} catch {
    Write-Host '[X] Plan tidak ditemukan.' -ForegroundColor Red
    Show-ServerError $_
    return
}

if ($plan.status -in @('VERIFIED', 'ROLLED_BACK', 'FAILED')) {
    Write-Host "[!] Plan sudah terminal ($($plan.status)). Buat plan baru (pilihan 1-3)." -ForegroundColor Yellow
    return
}

if ($plan.status -eq 'PLANNED' -or -not $plan.hasToken) {
    try {
        $approveBody = @{ planId = $planId; approvedBy = 'operator-laptop' } | ConvertTo-Json
        Invoke-RestMethod -Method Post -Uri "$Server/api/remediation-approve" -Headers $headers -ContentType 'application/json' -Body $approveBody | Out-Null
        Write-Host '[OK] Plan disetujui (token 10 menit).' -ForegroundColor Green
    } catch {
        Write-Host '[X] Approve gagal.' -ForegroundColor Red
        Show-ServerError $_
        return
    }
}

Write-Host ''
Write-Host 'Langkah plan:' -ForegroundColor Cyan
$planItems = @($plan.items)
$planItems | ForEach-Object { Write-Host ("  - {0} ({1})" -f $_.alias, $_.risk) }
if ($planItems.alias -contains 'bitlocker-enable') {
    Write-Host '[!] BitLocker berjalan di background. Recovery key disimpan di %USERPROFILE%\.pasopati\backups — salin setelah eksekusi.' -ForegroundColor Yellow
}
if ($planItems.alias -contains 'ports-block-windows') {
    Write-Host '[!] ports-block-windows memblokir koneksi RDP BARU ke 3389. Aman bila Anda bekerja langsung di laptop.' -ForegroundColor Yellow
}

$python = 'python'
$pyPrefix = @()
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    $python = 'py'
    $pyPrefix = @('-3')
}

Write-Host ''
Write-Host '=== DRY-RUN (--no-exec, tanpa perubahan host) ===' -ForegroundColor Cyan
& $python @pyPrefix '.\pasopati_remediate.py' '--server' $Server '--plan-id' $planId `
    '--remediate-api-key' $ApiKey '--hmac-key' $Hmac '--no-exec' '--no-elevate'
if ($LASTEXITCODE -ne 0) {
    Write-Host "[X] Dry-run gagal (exit $LASTEXITCODE). Perbaiki dulu, belum ada perubahan." -ForegroundColor Red
    return
}

$go = (Read-Host 'Lanjut EKSEKUSI NYATA? (y/N)').Trim()
if ($go -notmatch '^[yY]') {
    Write-Host 'Selesai tanpa perubahan host. Plan tetap APPROVED sampai token kedaluwarsa.' -ForegroundColor Yellow
    return
}

Write-Host ''
Write-Host '=== EKSEKUSI NYATA (UAC akan muncul) ===' -ForegroundColor Cyan
& $python @pyPrefix '.\pasopati_remediate.py' '--server' $Server '--plan-id' $planId `
    '--remediate-api-key' $ApiKey '--hmac-key' $Hmac
$exit = $LASTEXITCODE

Write-Host ''
try {
    $final = (Invoke-RestMethod -Method Get -Uri "$Server/api/remediation-plans/$planId" -Headers $headers).plan
    Write-Host ("Status akhir plan: {0} | evidence: {1}" -f $final.status, @($final.evidence).Count) -ForegroundColor Cyan
} catch {
    Write-Host "Selesai dengan exit $exit. Cek status di dashboard." -ForegroundColor Yellow
}
if ($exit -ne 0) {
    Write-Host "[!] Exit $exit. Bila ROLLED_BACK, host sudah dipulihkan otomatis; periksa detail di dashboard." -ForegroundColor Yellow
}
Write-Host 'Recovery key BitLocker (bila ada):' -ForegroundColor Cyan
Get-ChildItem "$env:USERPROFILE\.pasopati\backups" -Filter '*bitlocker-recovery.txt' -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host "  $($_.FullName)"; Get-Content $_.FullName }
