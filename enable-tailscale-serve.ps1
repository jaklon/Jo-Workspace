$ErrorActionPreference = "Stop"

$tailscaleCommand = Get-Command tailscale -ErrorAction SilentlyContinue
$tailscaleExe = if ($tailscaleCommand) { $tailscaleCommand.Source } else { $null }
if (-not $tailscaleExe) {
    $installedCli = "C:\Program Files\Tailscale\tailscale.exe"
    if (Test-Path -LiteralPath $installedCli) {
        $tailscaleExe = $installedCli
    }
}

if (-not $tailscaleExe) {
    throw "Tailscale belum terpasang. Pasang dan login terlebih dahulu."
}

& $tailscaleExe serve --bg --yes http://127.0.0.1:8010
& $tailscaleExe serve status
