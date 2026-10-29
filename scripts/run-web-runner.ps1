[CmdletBinding()]
param(
    [string] $BaseUrl = 'http://127.0.0.1:8000',
    [switch] $CheckOnly
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $projectRoot 'web/.env'
if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) {
    throw "Laravel env file not found: $envFile"
}

$tokenLine = Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^\s*PENTESIN_RUNNER_TOKEN\s*=' } | Select-Object -Last 1
if (-not $tokenLine -or $tokenLine -notmatch '^\s*PENTESIN_RUNNER_TOKEN\s*=\s*(.*)$') {
    throw 'PENTESIN_RUNNER_TOKEN is missing from web/.env'
}
$token = $Matches[1].Trim().Trim('"', "'")
if ($token.Length -lt 48) {
    throw 'PENTESIN_RUNNER_TOKEN must contain at least 48 characters; set the same secret in Laravel and the runner.'
}
if ($CheckOnly) {
    Write-Output 'Runner token configured; secret value not displayed.'
    exit 0
}

$hadToken = Test-Path Env:PENTESIN_RUNNER_TOKEN
$previousToken = $env:PENTESIN_RUNNER_TOKEN
try {
    $env:PENTESIN_RUNNER_TOKEN = $token
    & uv run --offline python -m pentesin.interface.web_runner --base-url $BaseUrl
    exit $LASTEXITCODE
} finally {
    if ($hadToken) {
        $env:PENTESIN_RUNNER_TOKEN = $previousToken
    } else {
        Remove-Item Env:PENTESIN_RUNNER_TOKEN -ErrorAction SilentlyContinue
    }
}
