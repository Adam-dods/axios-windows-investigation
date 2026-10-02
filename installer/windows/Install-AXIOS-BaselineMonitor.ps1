[CmdletBinding()]
param(
    [ValidateSet("Install", "Uninstall", "Status", "RunNow")]
    [string]$Action = "Install",

    [ValidatePattern("^\d{2}:\d{2}$")]
    [string]$DailyTime = "03:20"
)

$ErrorActionPreference = "Stop"

$TaskName = "\AXIOS\Baseline Monitor"
$InstallDirectory = Join-Path $env:ProgramFiles "AXIOS"
$CorePath = Join-Path $InstallDirectory "axios-core.exe"
$InstalledScript = Join-Path $InstallDirectory "Compare-AXIOS-Baseline.ps1"
$DataPath = Join-Path $env:ProgramData "AXIOS"
$SourceScript = Join-Path $PSScriptRoot "Compare-AXIOS-Baseline.ps1"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Install-BaselineMonitor {
    if (-not (Test-Path -LiteralPath $CorePath -PathType Leaf)) {
        throw "AXIOS core executable was not found: $CorePath"
    }

    if (-not (Test-Path -LiteralPath $SourceScript -PathType Leaf)) {
        throw "Baseline script was not found beside this installer: $SourceScript"
    }

    New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null

    Copy-Item `
        -LiteralPath $SourceScript `
        -Destination $InstalledScript `
        -Force

    $taskCommand = (
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -File ' +
        ('"{0}"' -f $InstalledScript) +
        ' -CorePath ' +
        ('"{0}"' -f $CorePath) +
        ' -DataPath ' +
        ('"{0}"' -f $DataPath)
    )

    & schtasks.exe `
        /Create `
        /TN $TaskName `
        /SC DAILY `
        /ST $DailyTime `
        /RU SYSTEM `
        /RL HIGHEST `
        /TR $taskCommand `
        /F

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create AXIOS baseline monitor task."
    }

    Write-Host "AXIOS baseline monitor installed."
    Write-Host "Task: $TaskName"
    Write-Host "Daily time: $DailyTime"
    Write-Host "Report: $(Join-Path $DataPath 'baseline-change-report.json')"
}

function Uninstall-BaselineMonitor {
    & schtasks.exe /Delete /TN $TaskName /F

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to remove AXIOS baseline monitor task."
    }

    Write-Host "AXIOS baseline monitor task removed."
}

function Get-BaselineMonitorStatus {
    & schtasks.exe /Query /TN $TaskName /V /FO LIST

    if ($LASTEXITCODE -ne 0) {
        throw "AXIOS baseline monitor task is not installed."
    }
}

function Start-BaselineMonitorNow {
    & schtasks.exe /Run /TN $TaskName

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start AXIOS baseline monitor task."
    }

    Write-Host "AXIOS baseline monitor started."
}

if (-not (Test-Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

switch ($Action) {
    "Install" { Install-BaselineMonitor }
    "Uninstall" { Uninstall-BaselineMonitor }
    "Status" { Get-BaselineMonitorStatus }
    "RunNow" { Start-BaselineMonitorNow }
}
