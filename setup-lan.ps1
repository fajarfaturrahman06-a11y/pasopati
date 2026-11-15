# Teruskan port 3000 Windows -> WSL agar laptop target bisa mengakses server.
# Jalankan sebagai Administrator (UAC).
$ErrorActionPreference = 'Continue'
$wslIp = ((wsl.exe hostname -I) -replace "`r", "").Trim().Split(' ')[0]
if (-not $wslIp) { Write-Host "WSL IP tidak terbaca." -ForegroundColor Red; exit 1 }

Write-Host "WSL IP: $wslIp"
netsh interface portproxy delete v4tov4 listenport=3000 listenaddress=0.0.0.0 | Out-Null
netsh interface portproxy add v4tov4 listenport=3000 listenaddress=0.0.0.0 connectport=3000 connectaddress=$wslIp
netsh advfirewall firewall delete rule name="PASOPATI 3000" | Out-Null
netsh advfirewall firewall add rule name="PASOPATI 3000" dir=in action=allow protocol=TCP localport=3000 | Out-Null

Write-Host "Portproxy + firewall 3000 disiapkan." -ForegroundColor Green
netsh interface portproxy show v4tov4
