<#
  CONTOH supervisor PASOPATI untuk Windows Server 2022.
  Ini contoh; task "PASOPATI Auto Start" yang sudah ada tetap dipakai.
  Salin/adaptasi ke C:\Apps\PASOPATI\start-pasopati.ps1 tanpa membuat task kedua.

  Wajib: direktori kerja dan PASOPATI_DATA_DIR eksplisit agar registry tidak
  jatuh ke C:\Windows\System32\data dan tidak terpecah antar instance.
#>
$ErrorActionPreference = 'Stop'

Set-Location -LiteralPath 'C:\Apps\PASOPATI'
$env:NODE_ENV = 'production'
$env:PORT = '3000'
$env:PASOPATI_DATA_DIR = 'C:\Apps\PASOPATI\data'

$node = 'C:\Program Files\nodejs\node.exe'
if (-not (Test-Path -LiteralPath $node)) { throw "Node.js tidak ditemukan di $node" }
if (-not (Test-Path -LiteralPath $env:PASOPATI_DATA_DIR)) {
  New-Item -ItemType Directory -Path $env:PASOPATI_DATA_DIR | Out-Null
}

# Jalankan satu instance saja; lock DATA_DIR akan menolak instance kedua.
& $node --import tsx server.ts *>> 'C:\Apps\PASOPATI\pasopati-service.log'
