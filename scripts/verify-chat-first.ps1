<#
.SYNOPSIS
  Full Chat-First verification on Windows: WhiteRabbitNeo setup, backend tests, frontend
  build, browser UI test, and the live check against the local Ollama.

.DESCRIPTION
  Logs per step are written to output\verify\<step>.log and a summary to output\verify\summary.txt.
  Runtime data in data\runtime is not modified (tests use temporary folders).
  The only network target of the live check is 127.0.0.1 (lab).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-chat-first.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-chat-first.ps1 -SkipModelInstall
#>
param(
  [switch]$SkipModelInstall,
  [string]$SecurityModel = "whiterabbitneo-v3-7b"
)
$ErrorActionPreference = "Continue"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$out = Join-Path $root "output\verify"
New-Item -ItemType Directory -Force -Path $out | Out-Null
Get-ChildItem -LiteralPath $out -Filter *.log -ErrorAction SilentlyContinue | Remove-Item -Force
$python = Join-Path $root "backend\venv\Scripts\python.exe"
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
$results = New-Object System.Collections.Generic.List[string]

function Invoke-Step([string]$Name, [scriptblock]$Block) {
  $log = Join-Path $out "$Name.log"
  Write-Host "`n=== $Name ===" -ForegroundColor Cyan
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
  $status = if ($failed) { "FAIL (exit $LASTEXITCODE)" } else { "PASS" }
  $line = "{0,-22} {1,-16} {2,6:N0} s" -f $Name, $status, $timer.Elapsed.TotalSeconds
  $results.Add($line)
  Write-Host $line -ForegroundColor $(if ($failed) { "Red" } else { "Green" })
}

Invoke-Step "00-environment" {
  "Waktu: " + (Get-Date -Format s)
  "PowerShell: " + $PSVersionTable.PSVersion
  if (Test-Path $python) { & $python --version } else { "python venv tidak ditemukan: $python"; $global:LASTEXITCODE = 1; return }
  "node: " + (& node --version)
  "npm: " + (& npm.cmd --version)
  "ollama: " + (& ollama --version)
  & ollama list
  if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) {
    & nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv
  }
  "Chrome: " + (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe")
  foreach ($tool in "nmap", "nuclei", "docker") {
    "${tool}: " + [bool](Get-Command $tool -ErrorAction SilentlyContinue)
  }
  $global:LASTEXITCODE = 0
}

if (-not $SkipModelInstall) {
  Invoke-Step "01-whiterabbitneo" {
    $listed = (& ollama list) -join "`n"
    if ($listed -match [regex]::Escape($SecurityModel)) {
      "Model $SecurityModel sudah terdaftar; instalasi dilewati."
      & ollama show $SecurityModel
    } else {
      & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "scripts\install-whiterabbitneo.ps1") -ModelName $SecurityModel
    }
    & ollama run $SecurityModel "Jawab satu kata: siap"
    & ollama ps
  }
}

Invoke-Step "02-backend-tests" {
  Push-Location (Join-Path $root "backend")
  try {
    $env:PYTHONPATH = ".;tests"
    & $python -m unittest discover -s tests -q
  } finally { Pop-Location; Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue }
}

Invoke-Step "03-frontend-test" {
  Push-Location (Join-Path $root "desktop-app")
  try { & npm.cmd test } finally { Pop-Location }
}

Invoke-Step "04-frontend-lint" {
  Push-Location (Join-Path $root "desktop-app")
  try {
    & npx.cmd eslint --quiet src/renderer/src/App.tsx src/renderer/src/components/MessageDetails.tsx `
      src/renderer/src/components/SecurityDashboard.tsx src/renderer/src/components/WorkspaceSidebar.tsx `
      src/renderer/src/components/RemoteImage.tsx src/renderer/src/lib/types.ts
  } finally { Pop-Location }
}

Invoke-Step "05-frontend-build" {
  Push-Location (Join-Path $root "desktop-app")
  try { & npm.cmd run build } finally { Pop-Location }
}

Invoke-Step "06-ui-browser" {
  & $python (Join-Path $root "scripts\test_chat_first_ui.py")
}

Invoke-Step "07-live-ollama" {
  & $python (Join-Path $root "scripts\live_chat_first_check.py") --security-model $SecurityModel
}

$summary = @("Verifikasi Chat-First - " + (Get-Date -Format s), "") + $results
$summary | Set-Content -LiteralPath (Join-Path $out "summary.txt") -Encoding UTF8
Write-Host "`n$($summary -join "`n")"
Write-Host "`nLog lengkap: $out"
