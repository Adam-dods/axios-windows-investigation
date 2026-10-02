param(
    [string]$CorePath = "C:\Program Files\AXIOS\axios-core.exe",
    [string]$DataPath = "C:\ProgramData\AXIOS"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $CorePath -PathType Leaf)) {
    throw "AXIOS core executable was not found: $CorePath"
}

New-Item -ItemType Directory -Path $DataPath -Force | Out-Null

$CoreSnapshot = Join-Path $DataPath "core-snapshot.json"
$Snapshot = Join-Path $DataPath "system-snapshot.json"
$Baseline = Join-Path $DataPath "system-baseline.json"
$Report = Join-Path $DataPath "baseline-change-report.json"

function Get-AxiosJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [string[]]$Arguments = @()
    )

    $raw = & $CorePath $Command @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "AXIOS command failed: $Command"
    }

    return ($raw | ConvertFrom-Json -ErrorAction Stop)
}

& $CorePath collect --output $CoreSnapshot

if ($LASTEXITCODE -ne 0) {
    throw "AXIOS command failed: collect"
}

$core = Get-Content -Encoding UTF8 -LiteralPath $CoreSnapshot -Raw |
    ConvertFrom-Json -ErrorAction Stop

$composite = [PSCustomObject]@{
    schema_version = 2
    collector = "axios_composite_system_snapshot"
    collected_at = [DateTime]::UtcNow.ToString("o")
    core_snapshot = $core
    software_inventory = Get-AxiosJson "software-inventory"
    browser_extensions = Get-AxiosJson "browser-extensions"
    security_posture = Get-AxiosJson "security-posture"
    registry_persistence = Get-AxiosJson "registry-persistence"
    extended_persistence = Get-AxiosJson "extended-persistence"
    access_surface = Get-AxiosJson "access-surface"
    network_posture = Get-AxiosJson "network-posture"
    health_posture = Get-AxiosJson "health-posture"
}

$snapshotJson = $composite | ConvertTo-Json -Depth 32
$snapshotBytes = [System.Text.Encoding]::UTF8.GetBytes($snapshotJson)

[System.IO.File]::WriteAllBytes($Snapshot, $snapshotBytes)

Get-Content -Encoding UTF8 -LiteralPath $Snapshot -Raw |
    ConvertFrom-Json -ErrorAction Stop |
    Out-Null

if (-not (Test-Path -LiteralPath $Baseline -PathType Leaf)) {
    & $CorePath baseline-create $Snapshot --output $Baseline

    if ($LASTEXITCODE -ne 0) {
        throw "AXIOS command failed: baseline-create"
    }

    [PSCustomObject]@{
        schema_version = 2
        collector = "axios_baseline_change_report"
        created_baseline = $true
        changed = $false
        baseline = $Baseline
        snapshot = $Snapshot
        report = $Report
    } |
        ConvertTo-Json -Depth 6 |
        Out-File -LiteralPath $Report -Encoding utf8

    Write-Host "AXIOS composite baseline created: $Baseline"
    exit 0
}

& $CorePath baseline-report $Baseline $Snapshot --output $Report

if ($LASTEXITCODE -ne 0) {
    throw "AXIOS command failed: baseline-report"
}

$result = Get-Content -Encoding UTF8 -LiteralPath $Report -Raw | ConvertFrom-Json

Write-Host "AXIOS baseline report written: $Report"
Write-Host "Stable changes: $($result.total_stable_changes)"
Write-Host "Needs review: $($result.summary.needs_review)"
Write-Host "Confirmed changes: $($result.summary.confirmed_changes)"
