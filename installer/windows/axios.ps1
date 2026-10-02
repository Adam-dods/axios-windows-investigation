[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet(
        "Help",
        "User",
        "Administrator",
        "Network",
        "System",
        "Persistence",
        "Software",
        "Results",
        "DeveloperExposure",
        "DeveloperCredential",
        "DeveloperArchive"
    )]
    [string]$Mode = "Help",

    [ValidateSet("auto", "standard", "administrator")]
    [string]$NetworkProfile = "auto",

    [ValidateSet(
        "overview",
        "wifi",
        "connections",
        "services",
        "dns",
        "routing",
        "firewall",
        "targeted",
        "full"
    )]
    [Alias("View")]
    [string]$NetworkFocus = "full",

    [ValidateSet("overview", "quick", "context")]
    [string]$SystemFocus = "overview",

    [switch]$DeveloperCredentialView,
    [switch]$DecryptCredentialFile,
    [switch]$DeveloperExposureView,

    [string[]]$Target = @(),
    [int[]]$Ports = @(),

    [ValidateRange(50, 10000)]
    [int]$TimeoutMs = 750,

    [ValidateRange(1, 25000)]
    [int]$MaxFiles = 1500,

    [ValidateSet("fast", "smart")]
    [string]$AuditMode = "fast",

    [switch]$Save,

    [string]$OutputDirectory = (
        Join-Path $env:USERPROFILE "Downloads"
    )
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$Launcher = Join-Path $PSScriptRoot "scripts\Run-AXIOS.ps1"

if (-not (Test-Path -LiteralPath $Launcher -PathType Leaf)) {
    throw "AXIOS launcher is missing from this package."
}

& $Launcher @PSBoundParameters
