<#
.SYNOPSIS
  Builds the Jo Workspace Windows installer for the version in desktop-app\package.json
  and records the actual test results next to it in desktop-app\dist.

.DESCRIPTION
  Steps: backend tests -> frontend tests -> npm run build:win (PyInstaller backend, typecheck,
  electron-vite build, electron-builder, NSIS) -> smoke test of the frozen backend (includes the
  Chat-First loopback TCP flow; needs Ollama running) -> 7-Zip archive test (if 7-Zip exists).
  On success, older installers are moved to dist\old-versions and SHA256SUMS.txt plus
  RELEASE-TESTS.txt are written. Logs: output\release-<version>\<step>.log

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -SkipTests
#>
param(
  [switch]$SkipTests,
  [switch]$SkipChatSmoke
)
$ErrorActionPreference = "Continue"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$desktop = Join-Path $root "desktop-app"
$dist = Join-Path $desktop "dist"
$python = Join-Path $root "backend\venv\Scripts\python.exe"
$version = (Get-Content -LiteralPath (Join-Path $desktop "package.json") -Raw | ConvertFrom-Json).version
$out = Join-Path $root "output\release-$version"
New-Item -ItemType Directory -Force -Path $out | Out-Null
Get-ChildItem -LiteralPath $out -Filter *.log -ErrorAction SilentlyContinue | Remove-Item -Force
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
$results = New-Object System.Collections.Generic.List[object]

function Invoke-Step([string]$Name, [string]$Label, [scriptblock]$Block) {
  $log = Join-Path $out "$Name.log"
  Write-Host "`n=== $Label ===" -ForegroundColor Cyan
  $timer = [Diagnostics.Stopwatch]::StartNew()
  $global:LASTEXITCODE = 0
  $failed = $false
  try {
    & $Block 2>&1 | ForEach-Object {
      $line = "$_"
      Add-Content -LiteralPath $log -Value $line -Encoding UTF8
      Write-Host $line
    }
    if ($LASTEXITCODE -ne 0) { $failed = $true }
  } catch {
    Add-Content -LiteralPath $log -Value ("EXCEPTION: " + $_) -Encoding UTF8
    $failed = $true
  }
  $minutes = [math]::Round($timer.Elapsed.TotalMinutes, 1)
  $results.Add([pscustomobject]@{ Name = $Name; Label = $Label; Ok = -not $failed; Minutes = $minutes })
  Write-Host ("{0}: {1} ({2} menit)" -f $Label, $(if ($failed) { "GAGAL" } else { "LULUS" }), $minutes) `
    -ForegroundColor $(if ($failed) { "Red" } else { "Green" })
  return -not $failed
}

Write-Host "Membangun Jo Workspace $version" -ForegroundColor Cyan
if (-not (Test-Path $python)) { throw "backend\venv tidak ditemukan. Lihat WINDOWS_INSTALLER.md." }

if (-not $SkipTests) {
  Invoke-Step "01-backend-tests" "Tes backend (Windows)" {
    Push-Location (Join-Path $root "backend")
    try { $env:PYTHONPATH = ".;tests"; & $python -m unittest discover -s tests -q }
    finally { Pop-Location; Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue }
  } | Out-Null
  Invoke-Step "02-frontend-tests" "Tes frontend" {
    Push-Location $desktop
    try { & npm.cmd test } finally { Pop-Location }
  } | Out-Null
}

$built = Invoke-Step "03-build-win" "Build backend PyInstaller, frontend, electron-builder dan NSIS" {
  Push-Location $desktop
  try { & npm.cmd run build:win } finally { Pop-Location }
}
$installer = Join-Path $dist "Jo-Workspace-$version-Windows-x64-Setup.exe"
if (-not $built -or -not (Test-Path -LiteralPath $installer)) {
  Write-Host "`nBuild gagal; installer lama tidak dipindahkan. Lihat $out\03-build-win.log" -ForegroundColor Red
  exit 1
}

Invoke-Step "04-smoke-frozen" "Smoke test backend terbungkus" {
  if ($SkipChatSmoke) { $env:JO_SMOKE_SKIP_CHAT = "1" }
  try {
    & $python (Join-Path $root "scripts\smoke-windows-backend.py") `
      (Join-Path $desktop "build\backend\agent-backend\agent-backend.exe") (Join-Path $desktop "out\renderer")
  } finally { Remove-Item Env:JO_SMOKE_SKIP_CHAT -ErrorAction SilentlyContinue }
} | Out-Null

$sevenZip = @("C:\Program Files\7-Zip\7z.exe", "C:\Program Files (x86)\7-Zip\7z.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($sevenZip) {
  Invoke-Step "05-archive-test" "Uji integritas arsip installer (7-Zip)" {
    & $sevenZip t $installer | Select-Object -Last 6
  } | Out-Null
}

# Keep only the new installer at the top of dist.
$archive = Join-Path $dist "old-versions"
New-Item -ItemType Directory -Force -Path $archive | Out-Null
Get-ChildItem -LiteralPath $dist -Filter "Jo-Workspace-*-Windows-x64-Setup.exe" |
  Where-Object { $_.Name -ne (Split-Path -Leaf $installer) } |
  ForEach-Object { Move-Item -LiteralPath $_.FullName -Destination (Join-Path $archive $_.Name) -Force; "Dipindahkan ke old-versions: " + $_.Name }

$item = Get-Item -LiteralPath $installer
$hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash
"$hash  $($item.Name)" | Set-Content -LiteralPath (Join-Path $dist "SHA256SUMS.txt") -Encoding ASCII

$lines = @("Jo Workspace $version - " + (Get-Date -Format "dd MMMM yyyy HH:mm"), "")
foreach ($result in $results) {
  $lines += ("{0}: {1} ({2} menit)" -f $(if ($result.Ok) { "PASS" } else { "FAIL" }), $result.Label, $result.Minutes)
}
if ($SkipTests) { $lines += "BATAS: tes backend dan frontend dilewati (-SkipTests)." }
if ($SkipChatSmoke) { $lines += "BATAS: smoke Chat-First TCP dilewati (-SkipChatSmoke)." }
$lines += @(
  "",
  "Installer: $($item.Name)",
  "Bytes: $($item.Length)",
  "SHA256: $hash",
  "Log: output\release-$version\",
  "",
  "BATAS: pemasangan/upgrade tidak dijalankan otomatis oleh skrip ini; pasang manual dari dist.",
  "BATAS: installer belum ditandatangani CA; Windows SmartScreen/Smart App Control dapat memblokirnya.",
  "BATAS: hasil Deep Analysis model tetap memerlukan review manusia."
)
$lines | Set-Content -LiteralPath (Join-Path $dist "RELEASE-TESTS.txt") -Encoding UTF8

$failedSteps = @($results | Where-Object { -not $_.Ok })
Write-Host "`n$($lines -join "`n")"
if ($failedSteps.Count) {
  Write-Host "`nInstaller dibuat, tetapi ada langkah yang gagal. Periksa log sebelum memasang." -ForegroundColor Yellow
  exit 1
}
Write-Host "`nInstaller siap: $installer" -ForegroundColor Green
