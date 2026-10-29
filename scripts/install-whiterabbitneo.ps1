<#
.SYNOPSIS
  Registers WhiteRabbitNeo V3 7B (GGUF Q4_K_M) as a local Ollama model for Jo Workspace.

.DESCRIPTION
  Existing models are not touched. After registration the model appears in
  Settings > Model & inferensi (role "Security" or "Coding") and in the model
  dropdown next to the chat input, because both read the installed list from Ollama.

  Default GGUF location follows the project convention:
    backend\models\security\WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-Q4_K_M.gguf

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install-whiterabbitneo.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install-whiterabbitneo.ps1 -GgufPath "C:\Users\me\Downloads\WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-Q4_K_M.gguf" -ContextTokens 4096
#>
param(
  [string]$GgufPath = (Join-Path $PSScriptRoot "..\backend\models\security\WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-Q4_K_M.gguf"),
  [string]$ModelName = "whiterabbitneo-v3-7b",
  [ValidateRange(2048, 32768)][int]$ContextTokens = 4096,
  [ValidateRange(0.0, 1.0)][double]$Temperature = 0.2
)
$ErrorActionPreference = "Stop"

# Ollama writes progress spinners and --verbose timings to stderr. In Windows PowerShell 5.1,
# redirecting a native program's stderr turns every line into an ErrorRecord, which "Stop" makes
# fatal even when the program succeeds. Run it with "Continue", print plain text without the
# spinner/ANSI noise, and judge success by the exit code only.
function Invoke-Ollama {
  param([Parameter(Mandatory)][string[]]$Arguments, [switch]$Quiet)
  $previous = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $lines = & ollama @Arguments 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previous
  }
  $clean = $lines |
    ForEach-Object { ($_ -replace '\x1b\[[0-9;?]*[A-Za-z]', '' -replace '\p{IsBraillePatterns}', '').TrimEnd() } |
    Where-Object { $_ }
  if (-not $Quiet) { $clean | ForEach-Object { Write-Host $_ } }
  return [pscustomobject]@{ ExitCode = $code; Lines = @($clean) }
}

if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
  throw "Ollama CLI tidak ditemukan. Pasang Ollama dan pastikan 'ollama' ada di PATH."
}
if (-not (Test-Path -LiteralPath $GgufPath)) {
  throw "File GGUF tidak ditemukan: $GgufPath`nSalin file .gguf ke backend\models\security\ atau berikan -GgufPath."
}
if ($ModelName -notmatch '^[a-z0-9][a-z0-9._\-]*(:[a-z0-9._\-]+)?$') {
  throw "Nama model hanya boleh huruf kecil, angka, titik, minus, underscore, dan satu tag opsional."
}

$gguf = (Resolve-Path -LiteralPath $GgufPath).Path
$sizeGb = [math]::Round((Get-Item -LiteralPath $gguf).Length / 1GB, 2)
Write-Host "GGUF: $gguf ($sizeGb GB)"

$modelfileDir = Join-Path $PSScriptRoot "..\deploy\whiterabbitneo"
New-Item -ItemType Directory -Force -Path $modelfileDir | Out-Null
$modelfile = Join-Path $modelfileDir "Modelfile.generated"
# The chat template is read from the GGUF metadata; only runtime parameters are set here.
$modelfileText = @"
FROM "$gguf"
PARAMETER num_ctx $ContextTokens
PARAMETER temperature $Temperature
PARAMETER top_p 0.9
PARAMETER repeat_penalty 1.1
"@
# Without a BOM: Windows PowerShell's -Encoding UTF8 would prepend one.
[IO.File]::WriteAllText($modelfile, $modelfileText, (New-Object Text.UTF8Encoding($false)))

Write-Host "Mendaftarkan model '$ModelName' ke Ollama..."
$create = Invoke-Ollama -Quiet -Arguments @("create", $ModelName, "-f", $modelfile)
$create.Lines | Where-Object { $_ -notmatch '^(gathering|copying|parsing|using|writing|creating|transferring)\b' } |
  ForEach-Object { Write-Host $_ }
if ($create.ExitCode -ne 0) { throw "ollama create gagal (exit $($create.ExitCode))." }

Write-Host "`nTemplate chat yang dipakai Ollama:"
$template = Invoke-Ollama -Arguments @("show", $ModelName, "--template")
if ($template.ExitCode -ne 0) { throw "ollama show gagal (exit $($template.ExitCode))." }

Write-Host "`nUji singkat (memuat model ke GPU)..."
$started = Get-Date
$run = Invoke-Ollama -Quiet -Arguments @("run", $ModelName, "Jawab satu kata: siap", "--verbose")
$run.Lines | Select-Object -Last 12 | ForEach-Object { Write-Host $_ }
Write-Host ("Waktu uji: {0:N1} detik" -f ((Get-Date) - $started).TotalSeconds)
$answer = $run.Lines | Where-Object { $_ -notmatch '^(total duration|load duration|prompt eval|eval (count|duration|rate))' } | Select-Object -First 1
if ($run.ExitCode -ne 0 -or -not $answer) {
  throw "Uji inferensi gagal (exit $($run.ExitCode)). Model sudah terdaftar; periksa 'ollama run $ModelName'."
}
Invoke-Ollama -Arguments @("ps") | Out-Null

Write-Host @"

Selesai. Model lama tidak diubah.
Langkah berikutnya di Jo Workspace:
  - Settings > Model & inferensi > Security  -> pilih '$ModelName' (opsional juga untuk Coding), atau
  - pilih '$ModelName' di dropdown Model dekat kotak chat untuk mengunci model pada satu sesi.
Periksa kolom PROCESSOR pada 'ollama ps': '100% GPU' berarti seluruh layer muat di VRAM.
"@
