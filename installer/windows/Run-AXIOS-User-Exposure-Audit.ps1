[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $env:USERPROFILE "Downloads")
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Binary = Join-Path $Root "bin\axios-user-exposure-audit.exe"

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "AXIOS user exposure executable was not found: $Binary"
}

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Output = Join-Path $OutputDirectory "AXIOS-User-Exposure-Audit-$Stamp.json"

& $Binary --output $Output
$ExitCode = $LASTEXITCODE

if ($ExitCode -ne 0) {
    throw "AXIOS user exposure audit failed with exit code $ExitCode."
}

$Report = Get-Content -Encoding UTF8 -LiteralPath $Output -Raw | ConvertFrom-Json

if ($Report.success -ne $true) {
    throw "AXIOS user exposure audit did not produce a successful report."
}

"AXIOS_USER_EXPOSURE_SUCCESS=$($Report.success)"
"AXIOS_USER_EXPOSURE_COLLECTION_STATUS=$($Report.collection_status)"
"AXIOS_USER_EXPOSURE_FINDINGS=$($Report.summary.findings)"
"OUTPUT=$Output"
