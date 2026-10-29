$ErrorActionPreference = 'Stop'
$desktop = Join-Path $PSScriptRoot '..\desktop-app'
$source = (Resolve-Path -LiteralPath (Join-Path $desktop 'dist\win-unpacked')).Path
$outputDirectory = (Resolve-Path -LiteralPath (Join-Path $desktop 'dist')).Path
$icon = (Resolve-Path -LiteralPath (Join-Path $desktop 'build\agent-os.ico')).Path
$script = (Resolve-Path -LiteralPath (Join-Path $desktop 'installer-standalone.nsi')).Path
$version = (Get-Content -LiteralPath (Join-Path $desktop 'package.json') -Raw | ConvertFrom-Json).version
$output = Join-Path $outputDirectory "Jo-Workspace-$version-Windows-x64-Setup.exe"

$cache = Join-Path $env:LOCALAPPDATA 'electron-builder\Cache'
$candidates = foreach ($versionDirectory in (Get-ChildItem -Path $cache -Directory -Filter 'nsis-*' -ErrorAction Stop)) {
    foreach ($buildDirectory in (Get-ChildItem -LiteralPath $versionDirectory.FullName -Directory)) {
        $candidate = Join-Path $buildDirectory.FullName 'Bin\makensis.exe'
        if (Test-Path -LiteralPath $candidate) { $candidate }
    }
}
$nsis = $candidates | Select-Object -First 1
if (-not $nsis) { throw 'NSIS compiler tidak tersedia di cache electron-builder.' }

& $nsis "/DSOURCE_DIR=$source" "/DOUTPUT_FILE=$output" "/DAPP_VERSION=$version" "/DICON_FILE=$icon" $script
if ($LASTEXITCODE -ne 0) { throw "NSIS gagal dengan kode $LASTEXITCODE." }
if ((Get-Item -LiteralPath $output).Length -lt 50MB) { throw 'Ukuran installer terlalu kecil; build tidak lengkap.' }
Write-Host "Installer siap: $output"
