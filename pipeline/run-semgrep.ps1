param(
    [string]$OutputPath = "scanner-results/semgrep.json"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command semgrep -ErrorAction SilentlyContinue)) {
    Write-Error "Semgrep was not found on PATH. Install Semgrep or run this scan in CI/Docker."
}

New-Item -ItemType Directory -Force -Path (Split-Path $OutputPath) | Out-Null

semgrep scan `
    --config semgrep-rules `
    --json `
    --output $OutputPath `
    app

Write-Host "Semgrep results written to $OutputPath"

