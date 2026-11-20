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

    [ValidateSet(
        "auto",
        "standard",
        "administrator"
    )]
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

    [ValidateSet(
        "overview",
        "quick",
        "context"
    )]
    [string]$SystemFocus = "overview",

    [ValidateSet("General", "System", "SystemQuick", "SystemContext", "Persistence", "Software")]
    [string]$Focus = "General",

    [switch]$Decrypt,

    [switch]$DeveloperCredentialView,

    [switch]$DecryptCredentialFile,

    [switch]$DeveloperExposureView,

    [string[]]$Target = @(),

    [int[]]$Ports = @(),

    [ValidateRange(50, 10000)]
    [int]$TimeoutMs = 750,

    [ValidateRange(1, 25000)]
    [int]$MaxFiles = 1500,

    [ValidateSet(
        "fast",
        "smart"
    )]
    [string]$AuditMode = "fast",

    [switch]$Save,

    [string]$OutputDirectory = (
        Join-Path $env:USERPROFILE "Downloads"
    )
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$AxiosPowerShellVersion = $PSVersionTable.PSVersion
$AxiosMinimumPowerShellVersion = [version]"5.1"

if ($AxiosPowerShellVersion -lt $AxiosMinimumPowerShellVersion) {
    throw (
        "This AXIOS package requires Windows PowerShell 5.1 or newer. " +
        "Detected version: $AxiosPowerShellVersion. " +
        "Windows 7 and Windows 8 require Windows Management Framework 5.1."
    )
}

$AxiosOperatingSystemVersion = [Environment]::OSVersion.Version
$AxiosOperatingSystemArchitecture = if (
    [Environment]::Is64BitOperatingSystem
) {
    "x64"
}
else {
    "x86"
}

if (
    $PSBoundParameters.ContainsKey("OutputDirectory") -and
    -not $Save
) {
    throw "AXIOS parameter -OutputDirectory requires -Save."
}

$RequestedOutputDirectory = $OutputDirectory
$SessionOutputDirectory = $null

function Initialize-AxiosConsoleSession {
    $ExistingSession = [Environment]::GetEnvironmentVariable(
        "AXIOS_SESSION_DIRECTORY",
        "Process"
    )

    if (
        -not [string]::IsNullOrWhiteSpace($ExistingSession) -and
        (Test-Path -LiteralPath $ExistingSession -PathType Container)
    ) {
        if ($env:AXIOS_CMD_SESSION -eq "1") {
            $Expiry = [DateTime]::UtcNow.AddDays(-1)
            foreach ($OldItem in @(Get-ChildItem -LiteralPath $ExistingSession -Force)) {
                if ($OldItem.LastWriteTimeUtc -lt $Expiry) {
                    Remove-Item -LiteralPath $OldItem.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        return $ExistingSession
    }

    if (
        $env:AXIOS_CMD_SESSION -eq "1" -and
        -not [string]::IsNullOrWhiteSpace($ExistingSession) -and
        $ExistingSession.StartsWith(
            (Join-Path $env:LOCALAPPDATA "AXIOS"),
            [StringComparison]::OrdinalIgnoreCase
        )
    ) {
        $null = New-Item -ItemType Directory -Path $ExistingSession -Force -ErrorAction Stop
        return $ExistingSession
    }

    $TempRoot = [System.IO.Path]::GetTempPath()
    $Expiry = [DateTime]::UtcNow.AddDays(-1)

    foreach ($StaleSession in @(
        Get-ChildItem `
            -LiteralPath $TempRoot `
            -Directory `
            -Filter "AXIOS-Session-*" `
            -ErrorAction SilentlyContinue
    )) {
        if ($StaleSession.LastWriteTimeUtc -lt $Expiry) {
            Remove-Item `
                -LiteralPath $StaleSession.FullName `
                -Recurse `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }

    $SessionDirectory = Join-Path `
        $TempRoot `
        ("AXIOS-Session-{0}" -f [Guid]::NewGuid().ToString("N"))

    $null = New-Item `
        -ItemType Directory `
        -Path $SessionDirectory `
        -Force `
        -ErrorAction Stop

    [Environment]::SetEnvironmentVariable(
        "AXIOS_SESSION_DIRECTORY",
        $SessionDirectory,
        "Process"
    )

    $CleanupEvent = "AXIOS.SessionCleanup.$PID"
    if (
        $env:AXIOS_CMD_SESSION -ne "1" -and
        -not (Get-EventSubscriber -SourceIdentifier $CleanupEvent -ErrorAction SilentlyContinue)
    ) {
        $null = Register-EngineEvent `
            -SourceIdentifier PowerShell.Exiting `
            -SupportEvent `
            -MessageData $SessionDirectory `
            -Action {
                $Directory = [string]$Event.MessageData
                if (
                    -not [string]::IsNullOrWhiteSpace($Directory) -and
                    (Test-Path -LiteralPath $Directory -PathType Container)
                ) {
                    Remove-Item `
                        -LiteralPath $Directory `
                        -Recurse `
                        -Force `
                        -ErrorAction SilentlyContinue
                }
            }
    }

    return $SessionDirectory
}

$IsDeveloperCredentialView = (
    $Mode -eq "Network" -and
    $NetworkFocus -eq "wifi" -and
    $DeveloperCredentialView
)

$IsDeveloperExposureView = (
    $Mode -eq "System" -and
    $DeveloperExposureView
)

$IsHiddenDeveloperCredentialCommand = (
    $Mode -in @(
        "DeveloperCredential",
        "DeveloperArchive"
    )
)

if ($PSBoundParameters.ContainsKey("Focus") -and $Mode -ne "User") {
    throw "AXIOS parameter -Focus is accepted only with -Mode User."
}

if ($Decrypt -and $Mode -ne "DeveloperCredential") {
    throw "AXIOS parameter -Decrypt requires -Mode DeveloperCredential."
}

$IsPrivateDeveloperCredentialCommand = (
    $IsDeveloperCredentialView -or
    $IsHiddenDeveloperCredentialCommand
)

if ($DeveloperExposureView -and -not $IsDeveloperExposureView) {
    throw "AXIOS parameter -DeveloperExposureView requires -Mode System."
}

if ($DeveloperCredentialView -and -not $IsDeveloperCredentialView) {
    throw (
        "AXIOS parameter -DeveloperCredentialView requires " +
        "-Mode Network -View wifi."
    )
}

if ($DecryptCredentialFile -and -not $IsDeveloperCredentialView) {
    throw (
        "AXIOS parameter -DecryptCredentialFile requires " +
        "-Mode Network -View wifi -DeveloperCredentialView."
    )
}

if ($IsPrivateDeveloperCredentialCommand -and $Save) {
    throw (
        "AXIOS developer credential view uses its own encrypted-save prompt; " +
        "do not combine it with -Save."
    )
}

if ($Mode -ne "Help" -and -not $Save -and -not $IsPrivateDeveloperCredentialCommand) {
    $SessionOutputDirectory = Initialize-AxiosConsoleSession
    $OutputDirectory = $SessionOutputDirectory
    $env:AXIOS_CONSOLE_SESSION = "1"
}
else {
    $env:AXIOS_CONSOLE_SESSION = $null
}

if (Test-Path -LiteralPath $OutputDirectory -PathType Leaf) {
    throw "AXIOS OutputDirectory must be a directory, not a file: $OutputDirectory"
}

$NetworkParameters = @(
    "NetworkProfile",
    "NetworkFocus",
    "Target",
    "Ports",
    "TimeoutMs"
    "DeveloperCredentialView"
    "DecryptCredentialFile"
)

if ($Mode -ne "Network") {
    foreach ($Name in $NetworkParameters) {
        if ($PSBoundParameters.ContainsKey($Name)) {
            throw "AXIOS parameter -$Name is only accepted with -Mode Network."
        }
    }
}

if (
    $Mode -ne "System" -and
    $PSBoundParameters.ContainsKey("DeveloperExposureView")
) {
    throw "AXIOS parameter -DeveloperExposureView is only accepted with -Mode System."
}

if (
    $Mode -ne "System" -and
    $PSBoundParameters.ContainsKey("SystemFocus")
) {
    throw "AXIOS parameter -SystemFocus is only accepted with -Mode System."
}

$CompleteParameters = @(
    "MaxFiles",
    "AuditMode"
)

if ($Mode -ne "Administrator") {
    foreach ($Name in $CompleteParameters) {
        if ($PSBoundParameters.ContainsKey($Name)) {
            throw "AXIOS parameter -$Name is accepted only with -Mode Administrator."
        }
    }
}

if (
    $Mode -eq "Network" -and
    $PSBoundParameters.ContainsKey("Ports") -and
    $Target.Count -eq 0
) {
    throw "AXIOS parameter -Ports requires at least one explicit -Target."
}


if ($Mode -ne "Help" -and -not $IsPrivateDeveloperCredentialCommand) {
    $WriteProbe = $null

    try {
        if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
            $null = New-Item `
                -ItemType Directory `
                -Path $OutputDirectory `
                -Force `
                -ErrorAction Stop
        }

        $WriteProbe = Join-Path `
            $OutputDirectory `
            ".axios-write-probe-$PID-$([Guid]::NewGuid().ToString('N')).tmp"

        [System.IO.File]::WriteAllText(
            $WriteProbe,
            "",
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    catch {
        throw (
            "AXIOS OutputDirectory is not writable: " +
            "$OutputDirectory. $($_.Exception.Message)"
        )
    }
    finally {
        if (
            $null -ne $WriteProbe -and
            (Test-Path -LiteralPath $WriteProbe -PathType Leaf)
        ) {
            Remove-Item `
                -LiteralPath $WriteProbe `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
}

$AxiosUtf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $AxiosUtf8
[Console]::OutputEncoding = $AxiosUtf8
$OutputEncoding = $AxiosUtf8
$env:AXIOS_TABLE_OUTPUT = "1"

function Test-AxiosAdministrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [Security.Principal.WindowsPrincipal]::new($Identity)

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-AxiosRunner {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $Path = Join-Path $PSScriptRoot $Name

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "AXIOS runner was not found: $Path"
    }

    return $Path
}

function Invoke-AxiosDeveloperCredentialTool {
    param(
        [switch]$Decrypt
    )

    $PackageRoot = Split-Path -Parent $PSScriptRoot
    $CredentialViewer = Join-Path `
        (Join-Path $PackageRoot "bin") `
        "axios-developer-credential-view.exe"

    if (
        -not (
            Test-Path `
                -LiteralPath $CredentialViewer `
                -PathType Leaf
        )
    ) {
        throw (
            "AXIOS developer credential viewer was not found: " +
            $CredentialViewer
        )
    }

    if ($Decrypt) {
        & $CredentialViewer --decrypt
    }
    else {
        & $CredentialViewer
    }

    if ($LASTEXITCODE -ne 0) {
        throw (
            "AXIOS developer credential viewer failed with exit code " +
            $LASTEXITCODE
        )
    }
}

function Assert-AxiosPackageIntegrity {
    $PackageRoot = Split-Path -Parent $PSScriptRoot
[Environment]::CurrentDirectory = $PackageRoot
    $Manifest = Join-Path $PackageRoot "SHA256SUMS.txt"

    if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
        throw "AXIOS package integrity manifest was not found: $Manifest"
    }

    $RootPrefix = (
        [System.IO.Path]::GetFullPath($PackageRoot)
    ).TrimEnd('\') + '\'

    $EntriesVerified = 0

    foreach ($Line in @(
        Get-Content -Encoding UTF8 `
            -LiteralPath $Manifest
    )) {
        if ([string]::IsNullOrWhiteSpace($Line)) {
            continue
        }

        if (
            $Line -notmatch
            '^(?<hash>[0-9a-fA-F]{64})\s+\*?(?<path>.+)$'
        ) {
            throw "AXIOS package integrity manifest is malformed."
        }

        $ExpectedHash = $Matches.hash.ToLowerInvariant()
        $RelativePath = $Matches.path.Trim().Replace('/', '\')

        if ([System.IO.Path]::IsPathRooted($RelativePath)) {
            throw "AXIOS integrity manifest contains an absolute path."
        }

        $FullPath = [System.IO.Path]::GetFullPath(
            (Join-Path $PackageRoot $RelativePath)
        )

        if (
            -not $FullPath.StartsWith(
                $RootPrefix,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw "AXIOS integrity manifest path escaped the package."
        }

        if (-not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
            throw "AXIOS package integrity failure: missing file: $RelativePath"
        }

        $ActualHash = (
            Get-FileHash `
                -LiteralPath $FullPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()

        if ($ActualHash -ne $ExpectedHash) {
            throw "AXIOS package integrity failure: modified file: $RelativePath"
        }

        $EntriesVerified += 1
    }

    if ($EntriesVerified -eq 0) {
        throw "AXIOS package integrity manifest contains no files."
    }
}

function Show-AxiosHelp {
    @'
AXIOS
Windows Investigation Platform

MAIN COMMANDS

Command                                      Purpose
-------------------------------------------  ------------------------------
.\axios.cmd -Mode User                       Standard-user investigation
.\axios.cmd -Mode Network                    Network investigation
.\axios.cmd -Mode Administrator              Complete 42-stage investigation

USER FOCUS
.\axios.cmd -Mode User -Focus System
.\axios.cmd -Mode User -Focus SystemQuick
.\axios.cmd -Mode User -Focus SystemContext
.\axios.cmd -Mode User -Focus Persistence
.\axios.cmd -Mode User -Focus Software

NETWORK FOCUS
.\axios.cmd -Mode Network -NetworkFocus overview
.\axios.cmd -Mode Network -NetworkFocus wifi
.\axios.cmd -Mode Network -NetworkFocus connections
.\axios.cmd -Mode Network -NetworkFocus services
.\axios.cmd -Mode Network -NetworkFocus dns
.\axios.cmd -Mode Network -NetworkFocus routing
.\axios.cmd -Mode Network -NetworkFocus firewall
.\axios.cmd -Mode Network -NetworkFocus full
.\axios.cmd -Mode Network -NetworkFocus targeted -Target 127.0.0.1 -Ports 80

OTHER
.\axios.cmd -Mode Administrator -AuditMode smart -MaxFiles 5000
.\axios.cmd -Mode Results
.\axios.cmd -Mode Help

The PowerShell launcher .\axios.ps1 accepts the same parameters.
Legacy System, Persistence, and Software modes remain available.

Add -Save to a normal assessment command to retain its artifacts.
Without -Save, evidence remains available only in the current
PowerShell session, or the current user's CMD result session.
Results reads the latest completed command.
'@
}

$Administrator = Test-AxiosAdministrator
$PreviousNativeDirectory = [Environment]::CurrentDirectory

try {
    if ($Mode -ne "Help") {
        Assert-AxiosPackageIntegrity
    }

    switch ($Mode) {
    "Help" {
        Show-AxiosHelp
        return
    }

    "DeveloperExposure" {
        $Runner = Get-AxiosRunner `
            "Run-AXIOS-Developer-Exposure-View.ps1"

        & $Runner `
            -OutputDirectory $OutputDirectory

        return
    }

    "DeveloperCredential" {
        Invoke-AxiosDeveloperCredentialTool -Decrypt:$Decrypt
        return
    }

    "DeveloperArchive" {
        Invoke-AxiosDeveloperCredentialTool -Decrypt
        return
    }

    "User" {
        if ($Focus -eq "General") {
            $Runner = Get-AxiosRunner "Run-AXIOS-Standard-User-Audit.ps1"
            & $Runner -OutputDirectory $OutputDirectory
        }
        else {
            $FocusedLayer = switch ($Focus) {
                "SystemQuick" { "Quick" }
                "SystemContext" { "Context" }
                default { $Focus }
            }
            $Runner = Get-AxiosRunner "Run-AXIOS-Layer.ps1"
            & $Runner -Layer $FocusedLayer -OutputDirectory $OutputDirectory
        }
        return
    }

    "Administrator" {
        if (-not $Administrator) {
            throw (
                "Administrator mode requires elevated PowerShell. " +
                "Restart PowerShell with Run as administrator."
            )
        }

        # Administrator is the primary full privileged investigation.
        $Runner = Get-AxiosRunner `
            "Run-AXIOS-Complete-Investigation.ps1"

        & $Runner `
            -MaxFiles $MaxFiles `
            -AuditMode $AuditMode `
            -OutputDirectory $OutputDirectory

        $ResultsRunner = Get-AxiosRunner "Run-AXIOS-Layer.ps1"
        & $ResultsRunner `
            -Layer Results `
            -OutputDirectory $OutputDirectory `
            -ResultSearchDirectory @($OutputDirectory)

        return
    }

    "Network" {
        if ($IsDeveloperCredentialView) {
            if (
                $Target.Count -gt 0 -or
                $Ports.Count -gt 0
            ) {
                throw (
                    "AXIOS developer credential view cannot be combined " +
                    "with -Target or -Ports."
                )
            }

            $PackageRoot = Split-Path -Parent $PSScriptRoot
            $CredentialViewer = Join-Path `
                (Join-Path $PackageRoot "bin") `
                "axios-developer-credential-view.exe"

            if (-not (Test-Path -LiteralPath $CredentialViewer -PathType Leaf)) {
                throw "AXIOS developer credential viewer was not found: $CredentialViewer"
            }

            if ($DecryptCredentialFile) {
                & $CredentialViewer --decrypt
            }
            else {
                & $CredentialViewer
            }

            if ($LASTEXITCODE -ne 0) {
                throw "AXIOS developer credential viewer failed with exit code $LASTEXITCODE."
            }

            return
        }

        if (
            $NetworkProfile -eq "administrator" -and
            -not $Administrator
        ) {
            throw (
                "AXIOS administrator network profile requires " +
                "elevated PowerShell."
            )
        }

        if (
            $NetworkFocus -eq "targeted" -and
            $Target.Count -eq 0
        ) {
            throw (
                "AXIOS targeted network review requires at least " +
                "one explicit -Target."
            )
        }

        if (
            $NetworkFocus -notin @("connections", "targeted") -and
            $Target.Count -gt 0
        ) {
            throw (
                "-Target is only accepted with " +
                "-NetworkFocus connections (or legacy targeted)."
            )
        }

        $Runner = Get-AxiosRunner `
            "Run-AXIOS-Network-Deep-Review.ps1"

        & $Runner `
            -Profile $NetworkProfile `
            -Focus $NetworkFocus `
            -Target $Target `
            -Ports $Ports `
            -TimeoutMs $TimeoutMs `
            -OutputDirectory $OutputDirectory

        return
    }

    "System" {
        if ($IsDeveloperExposureView) {
            $Runner = Get-AxiosRunner `
                "Run-AXIOS-Developer-Exposure-View.ps1"

            & $Runner `
                -OutputDirectory $OutputDirectory

            return
        }

        $SystemLayer = switch ($SystemFocus) {
            "quick" {
                "Quick"
            }

            "context" {
                "Context"
            }

            default {
                "System"
            }
        }

        $Runner = Get-AxiosRunner "Run-AXIOS-Layer.ps1"

        & $Runner `
            -Layer $SystemLayer `
            -OutputDirectory $OutputDirectory

        return
    }

    "Persistence" {
        $Runner = Get-AxiosRunner "Run-AXIOS-Layer.ps1"

        & $Runner `
            -Layer Persistence `
            -OutputDirectory $OutputDirectory

        return
    }

    "Software" {
        $Runner = Get-AxiosRunner "Run-AXIOS-Layer.ps1"

        & $Runner `
            -Layer Software `
            -OutputDirectory $OutputDirectory

        return
    }

    "Results" {
        $Runner = Get-AxiosRunner "Run-AXIOS-Layer.ps1"

        $ResultDirectories = @($RequestedOutputDirectory)
        if (
            $null -ne $SessionOutputDirectory -and
            (Test-Path -LiteralPath $SessionOutputDirectory -PathType Container)
        ) {
            $ResultDirectories = @(
                $SessionOutputDirectory,
                $RequestedOutputDirectory
            )
        }

        & $Runner `
            -Layer Results `
            -OutputDirectory $OutputDirectory `
            -ResultSearchDirectory $ResultDirectories

        return
    }

        default {
            throw "Unsupported AXIOS mode: $Mode"
        }
    }
}
catch {
    $NativeError = $_.Exception.GetBaseException()
    if (
        $NativeError -is [ComponentModel.Win32Exception] -and
        $NativeError.NativeErrorCode -in @(577, 1260)
    ) {
        throw (
            "Windows application control blocked an AXIOS executable. " +
            "Review CodeIntegrity event 3077 and Windows Security app-control settings. " +
            "AXIOS cannot override a Windows policy."
        )
    }
    throw
}
finally {
    if (
        -not [string]::IsNullOrWhiteSpace($PreviousNativeDirectory) -and
        (Test-Path -LiteralPath $PreviousNativeDirectory -PathType Container)
    ) {
        [Environment]::CurrentDirectory = $PreviousNativeDirectory
    }
}
