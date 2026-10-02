[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $env:USERPROFILE "Downloads")
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Binary = Join-Path $Root "bin\axios-user-scope-access-review.exe"

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "AXIOS user-scope executable was not found: $Binary"
}

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Output = Join-Path $OutputDirectory "AXIOS-User-Scope-Review-$Stamp.json"

& $Binary --output $Output
$ExitCode = $LASTEXITCODE

if ($ExitCode -ne 0) {
    throw "AXIOS user-scope review failed with exit code $ExitCode."
}

$Report = Get-Content -Encoding UTF8 -LiteralPath $Output -Raw | ConvertFrom-Json

if ($Report.success -ne $true) {
    throw "AXIOS user-scope review did not produce a successful report."
}

"AXIOS_USER_SCOPE_SUCCESS=$($Report.success)"
"AXIOS_USER_SCOPE_COLLECTION_STATUS=$($Report.collection_status)"
"AXIOS_USER_SCOPE_FINDINGS=$($Report.summary.findings)"
"OUTPUT=$Output"
