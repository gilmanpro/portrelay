# Instala portrelay (Windows) con venv propio y lanzador en ~/.portrelay/bin
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = (Get-Location).Path }
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $py) { Write-Error "Python no encontrado. Instala Python 3.9+."; exit 1 }
$venv = Join-Path $env:USERPROFILE ".portrelay\venv"
& $py -m venv $venv
& "$venv\Scripts\pip.exe" -q install --upgrade pip
& "$venv\Scripts\pip.exe" -q install $here
$bin = Join-Path $env:USERPROFILE ".portrelay\bin"
New-Item -ItemType Directory -Force -Path $bin | Out-Null
Copy-Item "$venv\Scripts\portrelay.exe" $bin -Force
Copy-Item "$venv\Scripts\portrelay.exe.manifest" $bin -Force -ErrorAction SilentlyContinue
$cur = [Environment]::GetEnvironmentVariable("Path", "User")
if ($cur -notlike "*$bin*") {
  [Environment]::SetEnvironmentVariable("Path", "$cur;$bin", "User")
}
Write-Host ""
Write-Host "portrelay instalado: $bin\portrelay.exe (reabre la terminal)"
& "$venv\Scripts\portrelay.exe" --version
