#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateSet("Install", "Uninstall", "Status", "Start", "Stop")]
    [string]$Action = "Install"
)

$ErrorActionPreference = "Stop"

$ServiceName = "AxiosCore"
$DisplayName = "AXIOS Core Service"
$InstallDirectory = Join-Path $env:ProgramFiles "AXIOS"
$DataDirectory = Join-Path $env:ProgramData "AXIOS"
$TokenPath = Join-Path $DataDirectory "ipc.token"
$ServiceBinary = Join-Path $InstallDirectory "axios-service.exe"
$SourceBinary = Join-Path $PSScriptRoot "axios-service.exe"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Set-AxiosPrivateDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $systemSid = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
    $administratorsSid = New-Object Security.Principal.SecurityIdentifier(
        "S-1-5-32-544"
    )

    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)

    $systemRule = New-Object `
        System.Security.AccessControl.FileSystemAccessRule(
            $systemSid,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )

    $administratorsRule = New-Object `
        System.Security.AccessControl.FileSystemAccessRule(
            $administratorsSid,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )

    $acl.ResetAccessRule($systemRule)
    $acl.AddAccessRule($administratorsRule)

    Set-Acl -LiteralPath $Path -AclObject $acl
}

function New-AxiosToken {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    try {
        $rng.GetBytes($bytes)
        return [Convert]::ToBase64String($bytes)
    }
    finally {
        $rng.Dispose()
    }
}

function Wait-ServiceRemoval {
    param([Parameter(Mandatory = $true)][string]$Name)

    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
            return
        }

        Start-Sleep -Milliseconds 500
    }

    throw "Service removal timed out: $Name"
}

function Install-Axios {
    if (-not (Test-Path -LiteralPath $SourceBinary -PathType Leaf)) {
        throw "Service binary was not found: $SourceBinary"
    }

    New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null

    Set-AxiosPrivateDirectoryAcl -Path $InstallDirectory
    Set-AxiosPrivateDirectoryAcl -Path $DataDirectory

    Copy-Item -LiteralPath $SourceBinary -Destination $ServiceBinary -Force

    if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) {
        Set-Content `
            -LiteralPath $TokenPath `
            -Value (New-AxiosToken) `
            -Encoding ascii `
            -NoNewline
    }

    Set-AxiosPrivateDirectoryAcl -Path $DataDirectory

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($existingService) {
        if ($existingService.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force
        }

        & sc.exe delete $ServiceName | Out-Null
        Wait-ServiceRemoval -Name $ServiceName
    }

    $quotedBinary = '"' + $ServiceBinary + '"'

    New-Service `
        -Name $ServiceName `
        -BinaryPathName $quotedBinary `
        -DisplayName $DisplayName `
        -Description "AXIOS on-demand local system diagnostics service." `
        -StartupType Manual

    Write-Output "AXIOS installed in manual mode."
    Get-Service -Name $ServiceName
}

function Uninstall-Axios {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($service) {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force
        }

        & sc.exe delete $ServiceName | Out-Null
        Wait-ServiceRemoval -Name $ServiceName
    }

    Write-Output "AXIOS service was removed. Diagnostic data was preserved."
}

if (-not (Test-Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

switch ($Action) {
    "Install" {
        Install-Axios
    }

    "Uninstall" {
        Uninstall-Axios
    }

    "Status" {
        Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    }

    "Start" {
        Start-Service -Name $ServiceName
        Get-Service -Name $ServiceName
    }

    "Stop" {
        Stop-Service -Name $ServiceName -Force
        Get-Service -Name $ServiceName
    }
}
