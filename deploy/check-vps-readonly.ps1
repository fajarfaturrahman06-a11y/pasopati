<#
  PASOPATI — pemeriksaan VPS READ-ONLY.
  Tidak mengubah proses/file/task dan tidak mencetak isi .env atau secret.
  Jalankan sebagai Administrator di VPS.
#>
[CmdletBinding()]
param(
  [string]$TaskName = 'PASOPATI Auto Start',
  [string]$ProjectRoot = 'C:\Apps\PASOPATI'
)

$ErrorActionPreference = 'Continue'
function Section($title) { Write-Host "`n=== $title ===" -ForegroundColor Cyan }

Section 'Proses Node.js'
$nodeProcesses = Get-CimInstance Win32_Process -Filter "Name='node.exe'" |
  Select-Object ProcessId, ParentProcessId, ExecutablePath, CommandLine
if ($nodeProcesses) { $nodeProcesses | Format-Table -Wrap -AutoSize } else { Write-Host 'Tidak ada proses node.exe.' }

Section 'Port 3000 dan 3001'
foreach ($port in 3000, 3001) {
  $listeners = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
  if ($listeners) {
    foreach ($listener in $listeners) {
      $owner = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
      $ownerName = if ($owner) { $owner.ProcessName } else { 'tidak diketahui' }
      Write-Host ("Port {0} DIDENGARKAN oleh PID {1} ({2})" -f $port, $listener.OwningProcess, $ownerName)
    }
  } else {
    Write-Host "Port $port tidak didengarkan."
  }
}

Section 'Scheduled Task'
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
  $task | Select-Object TaskName, State, TaskPath | Format-Table -AutoSize
  Get-ScheduledTaskInfo -TaskName $TaskName | Select-Object LastRunTime, LastTaskResult, NextRunTime | Format-List
  ($task.Actions | Select-Object Execute, Arguments, WorkingDirectory) | Format-List
} else {
  Write-Host "Task '$TaskName' tidak ditemukan."
}

Section 'Direktori data'
$dataDir = Join-Path $ProjectRoot 'data'
Write-Host "Registry yang diharapkan: $(Join-Path $dataDir 'endpoint_inventory.json')"
Write-Host "PASOPATI_DATA_DIR proses saat ini (dari environment mesin):"
$machineDataDir = [Environment]::GetEnvironmentVariable('PASOPATI_DATA_DIR', 'Machine')
if ($machineDataDir) { Write-Host "  $machineDataDir" } else { Write-Host '  (tidak diset di level Machine)' }
foreach ($candidate in @($dataDir, (Join-Path $env:WINDIR 'System32\data'))) {
  if (Test-Path -LiteralPath $candidate) {
    Write-Host "Direktori ada: $candidate"
  } else {
    Write-Host "Direktori TIDAK ada: $candidate"
  }
}

Section 'Lock proses'
$lockPath = Join-Path $dataDir '.server.lock'
if (Test-Path -LiteralPath $lockPath) {
  $lockPid = (Get-Content -LiteralPath $lockPath -ErrorAction SilentlyContinue | Select-Object -First 1)
  $alive = $false
  if ($lockPid -and ($lockPid -as [int])) { $alive = [bool](Get-Process -Id ([int]$lockPid) -ErrorAction SilentlyContinue) }
  Write-Host "Lock ada; PID=$lockPid; hidup=$alive"
} else {
  Write-Host 'Tidak ada .server.lock.'
}

Section 'File registry & audit'
foreach ($name in 'endpoint_inventory.json', 'audit_logs.json', 'waivers.json') {
  $file = Join-Path $dataDir $name
  if (Test-Path -LiteralPath $file) {
    $item = Get-Item -LiteralPath $file
    Write-Host ("{0} — {1:N0} byte — diubah {2}" -f $name, $item.Length, $item.LastWriteTime)
  } else {
    Write-Host "$name — tidak ada"
  }
}

Section 'Permission folder data'
if (Test-Path -LiteralPath $dataDir) { icacls $dataDir } else { Write-Host 'Folder data tidak ada; tidak ada ACL yang diperiksa.' }

Section 'Ringkasan'
Write-Host 'Periksa: hanya satu listener port 3000, PID lock sama dengan proses aktif, Task berjalan, dan DATA_DIR menunjuk folder proyek (bukan System32).'
