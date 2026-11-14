# ============================================================================
# PASOPATI - uji lanjutan (tanpa BitLocker): guest, audit policy, UAC, RDP NLA.
# Jalankan di PowerShell BIASA pada laptop target, satu alias per pemanggilan.
# ============================================================================
$ErrorActionPreference = 'Stop'
Set-Location 'C:\Users\niko\Downloads\PASOPATI'
$Server = 'http://172.20.10.6:3000'
$DeviceId = 'LAPTOP-UJI-NIKO'

function Show-ServerError($err) {
    if ($err.ErrorDetails.Message) { Write-Host $err.ErrorDetails.Message -ForegroundColor Yellow }
    else { Write-Host $err.Exception.Message -ForegroundColor Yellow }
}

Write-Host 'Tempel PASOPATI_API_KEY lalu Enter:' -ForegroundColor Cyan
$ApiKey = (Read-Host).Trim()
Write-Host 'Tempel HMAC_SECRET lalu Enter:' -ForegroundColor Cyan
$Hmac = (Read-Host).Trim()
$headers = @{ 'X-Pasopati-API-Key' = $ApiKey }
try {
    Invoke-RestMethod -Method Get -Uri "$Server/api/audit-logs?limit=1" -Headers $headers | Out-Null
} catch {
    Write-Host '[X] Gagal terhubung / auth.' -ForegroundColor Red; Show-ServerError $_; return
}

$python = 'python'
$pyPrefix = @()
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { $python = 'py'; $pyPrefix = @('-3') }

function Uji([string]$Alias, [string]$Risk = 'MEDIUM') {
    Write-Host ''
    Write-Host "=== UJI: $Alias ===" -ForegroundColor Cyan
    try {
        $body = @{ deviceId = $DeviceId; createdBy = 'operator-laptop'; items = @(@{ alias = $Alias; risk = $Risk }) } | ConvertTo-Json -Depth 5
        $plan = (Invoke-RestMethod -Method Post -Uri "$Server/api/remediation-plan" -Headers $headers -ContentType 'application/json' -Body $body).plan
        Invoke-RestMethod -Method Post -Uri "$Server/api/remediation-approve" -Headers $headers -ContentType 'application/json' -Body (@{ planId = $plan.planId } | ConvertTo-Json) | Out-Null
        Write-Host "[OK] Plan $($plan.planId) disetujui." -ForegroundColor Green
    } catch {
        Write-Host '[X] Gagal membuat/menyetujui plan.' -ForegroundColor Red; Show-ServerError $_; return
    }

    & $python @pyPrefix '.\pasopati_remediate.py' '--server' $Server '--plan-id' $plan.planId `
        '--remediate-api-key' $ApiKey '--hmac-key' $Hmac '--no-exec' '--no-elevate'
    if ($LASTEXITCODE -ne 0) { Write-Host '[X] Dry-run gagal.' -ForegroundColor Red; return }

    if ((Read-Host 'Eksekusi nyata? (y/N)').Trim() -notmatch '^[yY]') { Write-Host 'Dilewati.'; return }
    & $python @pyPrefix '.\pasopati_remediate.py' '--server' $Server '--plan-id' $plan.planId `
        '--remediate-api-key' $ApiKey '--hmac-key' $Hmac
    $code = $LASTEXITCODE
    $final = (Invoke-RestMethod -Method Get -Uri "$Server/api/remediation-plans/$($plan.planId)" -Headers $headers).plan
    Write-Host ("Status: {0} | exit: {1}" -f $final.status, $code) -ForegroundColor Cyan
}

# Contoh pemanggilan (satu per satu):
# Uji 'guest-account-disable' 'LOW'
# Uji 'win-auditpol-process' 'LOW'
# Uji 'uac-enable' 'HIGH'
# Uji 'rdp-nla-enable' 'MEDIUM'
