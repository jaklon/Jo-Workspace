param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$frontendDir = Join-Path $projectRoot "desktop-app"
$backendDir = Join-Path $projectRoot "backend"
$pythonExe = Join-Path $backendDir "venv\Scripts\python.exe"
$webIndex = Join-Path $frontendDir "out\renderer\index.html"

if (-not (Test-Path -LiteralPath $pythonExe)) {
    throw "Python virtual environment tidak ditemukan di backend\venv."
}

if (-not $SkipBuild) {
    Push-Location $frontendDir
    try {
        npm run build
    }
    finally {
        Pop-Location
    }
}

if (-not (Test-Path -LiteralPath $webIndex)) {
    throw "Frontend web belum dibangun. Jalankan script ini tanpa -SkipBuild."
}

Write-Host "Agent OS Web tersedia lokal di http://127.0.0.1:8010"
Write-Host "Biarkan jendela ini tetap terbuka selama server digunakan."
& $pythonExe -m uvicorn main:app --app-dir $backendDir --host 127.0.0.1 --port 8010
