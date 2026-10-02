[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $env:USERPROFILE "Downloads")
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$AxiosUtf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $AxiosUtf8
[Console]::OutputEncoding = $AxiosUtf8
$OutputEncoding = $AxiosUtf8

function Get-AxiosOptionalProperty {
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowNull()]
        [object]$DefaultValue = $null
    )

    if ($null -eq $Value) {
        return $DefaultValue
    }

    $Property = $Value.PSObject.Properties[$Name]

    if ($null -eq $Property) {
        return $DefaultValue
    }

    if ($null -eq $Property.Value) {
        return $DefaultValue
    }

    return $Property.Value
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $currentPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "AXIOS Administrator Exposure Audit must run as Administrator."
}

$Root = Split-Path -Parent $PSScriptRoot
$Binary = Join-Path $Root "bin\axios-admin-exposure-audit.exe"

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "AXIOS administrator exposure executable was not found: $Binary"
}

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Output = Join-Path $OutputDirectory "AXIOS-Administrator-Exposure-Audit-$Stamp.json"

& $Binary --output $Output

if ($LASTEXITCODE -ne 0) {
    throw "AXIOS administrator exposure audit failed with exit code $LASTEXITCODE."
}

$Report = Get-Content -Encoding UTF8 -LiteralPath $Output -Raw | ConvertFrom-Json

if ($Report.success -ne $true) {
    throw "AXIOS administrator exposure audit did not produce a successful report."
}

$CollectionStatus = Get-AxiosOptionalProperty `
    -Value $Report `
    -Name "collection_status" `
    -DefaultValue "unknown"

$Summary = Get-AxiosOptionalProperty `
    -Value $Report `
    -Name "summary" `
    -DefaultValue $null

$FindingItems = @(
    Get-AxiosOptionalProperty `
        -Value $Report `
        -Name "findings" `
        -DefaultValue @()
)

$FindingCount = Get-AxiosOptionalProperty `
    -Value $Summary `
    -Name "findings" `
    -DefaultValue $FindingItems.Count

$CollectionErrors = @(
    Get-AxiosOptionalProperty `
        -Value $Report `
        -Name "collection_errors" `
        -DefaultValue @()
)

$DetailedReport = Join-Path `
    $OutputDirectory `
    "AXIOS-Administrator-Exposure-Details-$Stamp.txt"

[System.IO.File]::WriteAllText(
    $DetailedReport,
    ($Report | ConvertTo-Json -Depth 30),
    $AxiosUtf8
)

Write-Host ""
Write-Host "PRIVILEGED SECURITY ASSESSMENT"
Write-Host "==================================="
Write-Host ("Status                 : {0}" -f $CollectionStatus)
Write-Host ("Findings               : {0}" -f $FindingCount)
Write-Host ("Collection errors      : {0}" -f $CollectionErrors.Count)
Write-Host ""
Write-Host "VERIFIED SECURITY FINDINGS"
Write-Host "------------------"
if ($FindingItems.Count -eq 0) {
    Write-Host "None reported by this collector."
}
else {
    foreach ($Finding in @($FindingItems | Select-Object -First 25)) {
        $Severity = Get-AxiosOptionalProperty `
            -Value $Finding `
            -Name "severity" `
            -DefaultValue (
                Get-AxiosOptionalProperty `
                    -Value $Finding `
                    -Name "priority" `
                    -DefaultValue "review"
            )
        $Title = Get-AxiosOptionalProperty -Value $Finding -Name "title" -DefaultValue (
            Get-AxiosOptionalProperty -Value $Finding -Name "id" -DefaultValue "unnamed finding"
        )
        Write-Host ("[{0}] {1}" -f ([string]$Severity).ToUpperInvariant(), $Title)
        foreach ($Field in @("classification", "source", "path", "service_name", "process_id", "registry_path", "observed_value")) {
            $Value = Get-AxiosOptionalProperty -Value $Finding -Name $Field -DefaultValue $null
            if ($null -ne $Value -and -not [string]::IsNullOrWhiteSpace([string]$Value)) {
                Write-Host ("  {0,-20}: {1}" -f ($Field -replace "_", " "), $Value)
            }
        }
        $Evidence = Get-AxiosOptionalProperty -Value $Finding -Name "evidence" -DefaultValue $null
        if ($null -ne $Evidence) {
            foreach ($Property in @($Evidence.PSObject.Properties | Select-Object -First 12)) {
                $Value = [string]$Property.Value
                if (-not [string]::IsNullOrWhiteSpace($Value)) {
                    Write-Host ("  {0,-20}: {1}" -f ($Property.Name -replace "_", " "), $Value)
                }
            }
        }
    }
}
if ($CollectionErrors.Count -gt 0) {
    Write-Host ""
    Write-Host "VISIBILITY LIMITATIONS"
    Write-Host "================="
    foreach ($CollectionError in @($CollectionErrors | Select-Object -First 25)) {
        Write-Host ("- {0}" -f [string]$CollectionError)
    }
}
if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
    Write-Host ""
    Write-Host ("Detailed TXT report    : {0}" -f $DetailedReport)
    Write-Host ("Structured JSON report : {0}" -f $Output)
}
Write-Host ""

[PSCustomObject]@{
    success = $true
    collector = "axios_admin_exposure_audit"
    collection_status = [string]$CollectionStatus
    findings = [int]$FindingCount
    collection_errors = $CollectionErrors.Count
    output = $Output
    detailed_report = $DetailedReport
    size_bytes = (Get-Item -LiteralPath $Output).Length
} | ForEach-Object {
    if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
        $_ | ConvertTo-Json -Depth 5 -Compress
    }
}
