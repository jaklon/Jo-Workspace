param([string]$PythonExe)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
if (-not $PythonExe) { $PythonExe = Join-Path $taskRoot 'backend\venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $PythonExe)) { throw 'Siapkan backend/venv dan pasang backend/requirements-build.txt terlebih dahulu.' }
& $PythonExe (Join-Path $taskRoot 'scripts\build-icons.py')
if ($LASTEXITCODE -ne 0) { throw 'Pembuatan ikon aplikasi gagal.' }
& $PythonExe (Join-Path $taskRoot 'scripts\build-fixture-runtime.py')
if ($LASTEXITCODE -ne 0) { throw 'Bundling runtime fixture gagal.' }
& $PythonExe -m PyInstaller --noconfirm --onedir --console --name agent-backend --paths (Join-Path $taskRoot 'backend') --distpath (Join-Path $taskRoot 'desktop-app\build\backend') --workpath (Join-Path $taskRoot 'output\windows-build\pyinstaller') --specpath (Join-Path $taskRoot 'output\windows-build') --add-data "$(Join-Path $taskRoot 'backend\mcp_fixture_server.py');." --add-data "$(Join-Path $taskRoot 'output\windows-build\fixture-python');fixture-python" --add-data "$(Join-Path $taskRoot 'backend\zap_driver.py');." --collect-all uvicorn --collect-all sse_starlette --collect-all playwright --hidden-import python_multipart --hidden-import chat_orchestrator --hidden-import auto_governance --hidden-import analysis_grounding --hidden-import pynvml --hidden-import win32crypt --hidden-import win32security --hidden-import win32job --hidden-import win32pipe --exclude-module tkinter --exclude-module pytest (Join-Path $taskRoot 'backend\desktop_server.py')
if ($LASTEXITCODE -ne 0) { throw 'Bundling backend gagal.' }
Write-Host 'Backend mandiri siap untuk installer Windows.'

