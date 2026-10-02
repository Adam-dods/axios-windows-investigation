[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $env:USERPROFILE "Downloads")
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$AxiosUtf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = $AxiosUtf8
[Console]::OutputEncoding = $AxiosUtf8
$OutputEncoding = $AxiosUtf8

$Root = Split-Path -Parent $PSScriptRoot
$Bin = Join-Path $Root "bin"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Work = Join-Path ([System.IO.Path]::GetTempPath()) (
    "AXIOS-Developer-Exposure-{0}" -f [Guid]::NewGuid().ToString("N")
)

$Collectors = @(
    "axios-user-exposure-audit",
    "axios-user-scope-access-review",
    "axios-remote-access-review",
    "axios-security-controls-review",
    "axios-execution-policy-review"
)

function Get-AxiosValue {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Default = $null
    )

    if ($null -eq $Object) {
        return $Default
    }

    $Property = $Object.PSObject.Properties[$Name]

    if ($null -eq $Property) {
        return $Default
    }

    return $Property.Value
}

function Get-AxiosEvidencePath {
    param([object]$Evidence)

    foreach ($Name in @("ExecutablePath", "executable_path", "process_path", "path")) {
        $Value = [string](Get-AxiosValue $Evidence $Name "")
        if (-not [string]::IsNullOrWhiteSpace($Value)) {
            return $Value
        }
    }

    return ""
}

function Get-AxiosTrustedPackageHashes {
    $Hashes = @{}
    $Manifest = Join-Path $Root "SHA256SUMS.txt"

    if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
        return $Hashes
    }

    foreach ($Line in @(Get-Content -Encoding UTF8 -LiteralPath $Manifest)) {
        if ($Line -match '^(?<hash>[0-9a-fA-F]{64})\s+\*?(?<path>.+)$') {
            $RelativePath = $Matches.path.Trim().Replace('/', '\')
            if ($RelativePath.StartsWith("bin\", [StringComparison]::OrdinalIgnoreCase)) {
                $Hashes[$RelativePath.ToLowerInvariant()] = $Matches.hash.ToLowerInvariant()
            }
        }
    }

    return $Hashes
}

$TrustedPackageHashes = Get-AxiosTrustedPackageHashes

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = [Security.Principal.WindowsPrincipal]::new(
    $CurrentIdentity
)
$IsAdministrator = $CurrentPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
$AxiosExecutionContext = if ($IsAdministrator) {
    "Administrator"
}
else {
    "Standard user"
}

function Test-AxiosTrustedPackageBinary {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    try {
        $FullPath = [IO.Path]::GetFullPath($Path)
        $FileName = [IO.Path]::GetFileName($FullPath)

        if ([string]::IsNullOrWhiteSpace($FileName)) {
            return $false
        }

        $ManifestKey = (
            "bin\{0}" -f $FileName
        ).ToLowerInvariant()

        $ExpectedHash = $TrustedPackageHashes[$ManifestKey]

        if ([string]::IsNullOrWhiteSpace([string]$ExpectedHash)) {
            return $false
        }

        $ActualHash = (
            Get-FileHash `
                -LiteralPath $FullPath `
                -Algorithm SHA256 `
                -ErrorAction Stop
        ).Hash.ToLowerInvariant()

        return $ActualHash -eq $ExpectedHash
    }
    catch {
        return $false
    }
}

function ConvertTo-AxiosEvidenceFinding {
    param(
        [string]$Source,
        [object]$Finding
    )

    [PSCustomObject]@{
        source = $Source
        priority = Get-AxiosValue $Finding "priority" (
            Get-AxiosValue $Finding "severity" "review"
        )
        classification = Get-AxiosValue $Finding "classification" "observation"
        id = Get-AxiosValue $Finding "id" $null
        title = Get-AxiosValue $Finding "title" $null
        evidence = Get-AxiosValue $Finding "evidence" $null
        affected_sides = @(
            Get-AxiosValue $Finding "affected_sides" @()
        )
        service = Get-AxiosValue $Finding "service" $null
    }
}

New-Item -ItemType Directory -Path $Work -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$Reports = New-Object System.Collections.ArrayList
$Findings = New-Object System.Collections.ArrayList
$Gaps = New-Object System.Collections.ArrayList
$OperatingSystem = $null
$InstalledHotfixes = @()
$TokenPrivileges = @()

try {
    foreach ($Collector in $Collectors) {
        $Binary = Join-Path $Bin ("{0}.exe" -f $Collector)
        $RawPath = Join-Path $Work ("{0}.json" -f $Collector)

        if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
            [void]$Gaps.Add("missing_binary:$Collector")
            continue
        }

        try {
            & $Binary --output $RawPath | Out-Null

            if ($LASTEXITCODE -ne 0) {
                [void]$Gaps.Add((
                    "collector_exit:{0}:{1}" -f $Collector, $LASTEXITCODE
                ))
                continue
            }

            if (-not (Test-Path -LiteralPath $RawPath -PathType Leaf)) {
                [void]$Gaps.Add("missing_report:$Collector")
                continue
            }

            $Report = Get-Content -Encoding UTF8 -LiteralPath $RawPath -Raw |
                ConvertFrom-Json
            $Success = (Get-AxiosValue $Report "success" $false) -eq $true
            $DefaultStatus = if ($Success) {
                "complete"
            }
            else {
                "failed"
            }
            $Status = [string](
                Get-AxiosValue $Report "collection_status" $DefaultStatus
            )
            $ReportFindings = @(
                Get-AxiosValue $Report "findings" @()
            )
            $ReportErrors = @(
                Get-AxiosValue $Report "collection_errors" @()
            )

            foreach ($Finding in $ReportFindings) {
                [void]$Findings.Add((
                    ConvertTo-AxiosEvidenceFinding $Collector $Finding
                ))
            }

            foreach ($ErrorItem in $ReportErrors) {
                [void]$Gaps.Add(("{0}:{1}" -f $Collector, [string]$ErrorItem))
            }

            if (
                (-not $Success -or $Status -ne "complete") -and
                $ReportErrors.Count -eq 0
            ) {
                [void]$Gaps.Add((
                    "collector_status:{0}:{1}" -f
                    $Collector,
                    $Status
                ))
            }

            [void]$Reports.Add([PSCustomObject]@{
                collector = $Collector
                success = $Success
                collection_status = $Status
                summary = Get-AxiosValue $Report "summary" $null
            })

            if ($Collector -eq "axios-user-exposure-audit") {
                $OperatingSystem = Get-AxiosValue $Report "operating_system" $null
                $InstalledHotfixes = @(
                    Get-AxiosValue $Report "installed_hotfixes" @()
                )
                $TokenPrivileges = @(
                    Get-AxiosValue $Report "token_privileges" @()
                )
            }
        }
        catch {
            [void]$Gaps.Add(("collector_error:{0}:{1}" -f $Collector, $_.Exception.Message))
        }
    }

    $VisibleFindings = New-Object System.Collections.ArrayList
    $SuppressedSelfFindings = 0
    foreach ($Finding in $Findings) {
        $EvidencePath = Get-AxiosEvidencePath $Finding.evidence
        if (Test-AxiosTrustedPackageBinary $EvidencePath) {
            $SuppressedSelfFindings += 1
            continue
        }

        [void]$VisibleFindings.Add($Finding)
    }
    $Findings = $VisibleFindings

    $High = @($Findings | Where-Object {
        [string]$_.priority -eq "high"
    }).Count
    $Medium = @($Findings | Where-Object {
        [string]$_.priority -eq "medium"
    }).Count
    $SuccessfulCollectors = @($Reports | Where-Object {
        $_.success -eq $true
    }).Count
    $CollectionStatus = if ($SuccessfulCollectors -eq $Collectors.Count -and $Gaps.Count -eq 0) {
        "complete"
    }
    elseif ($SuccessfulCollectors -gt 0) {
        "partial"
    }
    else {
        "failed"
    }

    $Result = [PSCustomObject]@{
        success = ($SuccessfulCollectors -gt 0)
        collector = "axios_developer_exposure_view"
        read_only = $true
        exploitation_performed = $false
        connection_attempted = $false
        system_modified = $false
        credentials_collected = $false
        collection_status = $CollectionStatus
        operating_system = $OperatingSystem
        installed_hotfixes = @($InstalledHotfixes)
        token_privileges = @($TokenPrivileges)
        summary = [PSCustomObject]@{
            collectors_total = $Collectors.Count
            collectors_successful = $SuccessfulCollectors
            findings_total = $Findings.Count
            high_priority = $High
            medium_priority = $Medium
            collection_gaps = $Gaps.Count
            verified_self_findings_suppressed = $SuppressedSelfFindings
        }
        collectors = @($Reports)
        findings = @($Findings)
        collection_gaps = @($Gaps)
    }

    $JsonPath = Join-Path $OutputDirectory (
        "AXIOS-Developer-Exposure-{0}.json" -f $Stamp
    )
    $TxtPath = Join-Path $OutputDirectory (
        "AXIOS-Developer-Exposure-{0}.txt" -f $Stamp
    )

    [System.IO.File]::WriteAllText(
        $JsonPath,
        ($Result | ConvertTo-Json -Depth 20),
        $AxiosUtf8
    )

    $ReportLines = [System.Collections.Generic.List[string]]::new()

    function Add-AxiosReportLine {
        param([string]$Text = "")

        $ReportLines.Add($Text)
    }

    function Format-AxiosEvidenceName {
        param([string]$Name)

        if ([string]::IsNullOrWhiteSpace($Name)) {
            return "Value"
        }

        $Text = $Name -replace "_", " "
        $Text = $Text -creplace "([a-z0-9])([A-Z])", '$1 $2'

        return (
            [Globalization.CultureInfo]::InvariantCulture.TextInfo.ToTitleCase(
                $Text.ToLowerInvariant()
            )
        )
    }

    function Format-AxiosEvidenceValue {
        param([AllowNull()][object]$Value)

        if ($null -eq $Value) {
            return "Not available"
        }

        if ($Value -is [bool]) {
            if ($Value) {
                return "Enabled"
            }

            return "Disabled"
        }

        if ($Value -is [string]) {
            if ([string]::IsNullOrWhiteSpace($Value)) {
                return "Not configured"
            }

            return $Value.Trim()
        }

        if ($Value -is [ValueType]) {
            return [string]$Value
        }

        if (
            $Value -is [System.Collections.IEnumerable] -and
            $Value -isnot [string]
        ) {
            $Items = @($Value)

            if ($Items.Count -eq 0) {
                return "None"
            }

            if ($Items.Count -le 8) {
                return ($Items -join ", ")
            }

            return "$($Items.Count) items"
        }

        return [string]$Value
    }

    Add-AxiosReportLine
    Add-AxiosReportLine "ADVANCED EXPOSURE ASSESSMENT"
    Add-AxiosReportLine ("=" * "ADVANCED EXPOSURE ASSESSMENT".Length)
    Add-AxiosReportLine (
        "Assessment status       : {0}" -f $CollectionStatus
    )
    Add-AxiosReportLine (
        "Collectors returned     : {0}/{1}" -f
        $SuccessfulCollectors,
        $Collectors.Count
    )
    Add-AxiosReportLine (
        "Assessment observations : {0}" -f $Findings.Count
    )
    Add-AxiosReportLine (
        "High severity           : {0}" -f $High
    )
    Add-AxiosReportLine (
        "Medium severity         : {0}" -f $Medium
    )
    Add-AxiosReportLine (
        "Visibility limitations  : {0}" -f $Gaps.Count
    )
    Add-AxiosReportLine (
        "Verified self activity  : {0} suppressed" -f
        $SuppressedSelfFindings
    )

    Add-AxiosReportLine
    Add-AxiosReportLine "SYSTEM AND SECURITY PROFILE"
    Add-AxiosReportLine "---------------------------"

    if ($null -ne $OperatingSystem) {
        $WindowsCaption = Get-AxiosValue `
            $OperatingSystem `
            "caption" `
            "Not available"

        $WindowsVersion = Get-AxiosValue `
            $OperatingSystem `
            "version" `
            "Not available"

        $WindowsBuild = Get-AxiosValue `
            $OperatingSystem `
            "build_number" `
            "Not available"

        $DisplayVersion = Get-AxiosValue `
            $OperatingSystem `
            "display_version" `
            "Not available"

        $UpdateBuildRevision = Get-AxiosValue `
            $OperatingSystem `
            "ubr" `
            "Not available"

        Add-AxiosReportLine (
            "Operating system       : {0}" -f $WindowsCaption
        )
        Add-AxiosReportLine (
            "Version                : {0}" -f $WindowsVersion
        )
        Add-AxiosReportLine (
            "Build                  : {0}.{1}" -f
            $WindowsBuild,
            $UpdateBuildRevision
        )
        Add-AxiosReportLine (
            "Feature release        : {0}" -f $DisplayVersion
        )
    }
    else {
        Add-AxiosReportLine "Operating system       : Not available"
    }

    Add-AxiosReportLine (
        "Installed hotfixes      : {0}" -f $InstalledHotfixes.Count
    )
    Add-AxiosReportLine (
        "Token privileges seen   : {0}" -f $TokenPrivileges.Count
    )
    Add-AxiosReportLine (
        "Execution context      : {0}" -f $AxiosExecutionContext
    )

    Add-AxiosReportLine
    Add-AxiosReportLine "CONFIGURATION EXPOSURES"
    Add-AxiosReportLine "-----------------------"

    if ($Findings.Count -eq 0) {
        Add-AxiosReportLine "Observed exposures     : None"
    }
    else {
        $FindingIndex = 0

        foreach ($Finding in @($Findings | Select-Object -First 25)) {
            $FindingIndex += 1

            $Priority = [string](
                Get-AxiosValue $Finding "priority" ""
            )

            $Classification = [string](
                Get-AxiosValue $Finding "classification" ""
            )

            if ([string]::IsNullOrWhiteSpace($Priority)) {
                if ($Classification -in @(
                    "context",
                    "informational",
                    "observation",
                    "visibility_limited",
                    "forensic_visibility_reduced",
                    "credential_exposure_context"
                )) {
                    $Priority = "context"
                }
                else {
                    $Priority = "review"
                }
            }

            $Title = ""

            foreach ($TitleField in @(
                "title",
                "label",
                "finding",
                "id",
                "classification"
            )) {
                $CandidateTitle = [string](
                    Get-AxiosValue $Finding $TitleField ""
                )

                if (-not [string]::IsNullOrWhiteSpace($CandidateTitle)) {
                    $Title = $CandidateTitle
                    break
                }
            }

            if ([string]::IsNullOrWhiteSpace($Title)) {
                $Title = "Unnamed security exposure"
            }

            $Title = $Title -replace "_", " "

            Add-AxiosReportLine
            Add-AxiosReportLine (
                "[{0}] {1}" -f
                $Priority.ToUpperInvariant(),
                $Title
            )

            if (-not [string]::IsNullOrWhiteSpace($Classification)) {
                Add-AxiosReportLine (
                    "  Finding class          : {0}" -f
                    $Classification
                )
            }

            $FindingSource = [string](
                Get-AxiosValue $Finding "source" "Not available"
            )

            Add-AxiosReportLine (
                "  Evidence source        : {0}" -f $FindingSource
            )

            $VerificationState = [string](
                Get-AxiosValue $Finding "verification_state" ""
            )

            if ([string]::IsNullOrWhiteSpace($VerificationState)) {
                $VerificationState = [string](
                    Get-AxiosValue $Finding "status" "Observed"
                )
            }

            Add-AxiosReportLine (
                "  Verification           : {0}" -f
                $VerificationState
            )

            $Evidence = Get-AxiosValue $Finding "evidence" $null

            if ($null -ne $Evidence) {
                $EvidenceRows = 0

                foreach ($Property in @($Evidence.PSObject.Properties)) {
                    if ($EvidenceRows -ge 14) {
                        break
                    }

                    if ($Property.Name -in @(
                        "success",
                        "collector",
                        "recommended_actions",
                        "next_check"
                    )) {
                        continue
                    }

                    $EvidenceName = Format-AxiosEvidenceName `
                        $Property.Name

                    $EvidenceValue = Format-AxiosEvidenceValue `
                        $Property.Value

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            [string]$EvidenceValue
                        )
                    ) {
                        Add-AxiosReportLine (
                            "  {0,-23}: {1}" -f
                            $EvidenceName,
                            $EvidenceValue
                        )

                        $EvidenceRows += 1
                    }
                }
            }
        }
    }

    Add-AxiosReportLine
    Add-AxiosReportLine "VISIBILITY LIMITATIONS"
    Add-AxiosReportLine "----------------------"

    if ($Gaps.Count -eq 0) {
        Add-AxiosReportLine "Limitations observed   : None"
    }
    else {
        foreach ($Gap in @($Gaps | Select-Object -First 25)) {
            $GapText = [string]$Gap
            $GapParts = $GapText -split ":", 3

            Add-AxiosReportLine

            if ($GapParts.Count -ge 1) {
                Add-AxiosReportLine (
                    "Collector              : {0}" -f
                    ($GapParts[0] -replace "_", " ")
                )
            }

            if ($GapParts.Count -ge 2) {
                Add-AxiosReportLine (
                    "Component              : {0}" -f
                    ($GapParts[1] -replace "_", " ")
                )
            }

            if ($GapParts.Count -ge 3) {
                Add-AxiosReportLine (
                    "Collection result      : {0}" -f
                    $GapParts[2]
                )
            }
            else {
                Add-AxiosReportLine (
                    "Collection result      : {0}" -f $GapText
                )
            }

            Add-AxiosReportLine (
                "Assessment effect       : Evidence remains partial"
            )
        }
    }

    [System.IO.File]::WriteAllLines(
        $TxtPath,
        $ReportLines,
        $AxiosUtf8
    )

    foreach ($ReportLine in $ReportLines) {
        Write-Host $ReportLine
    }

    if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
        Write-Host ""
        Write-Host ("JSON={0}" -f $JsonPath)
        Write-Host ("TXT={0}" -f $TxtPath)
    }
}
finally {
    if (Test-Path -LiteralPath $Work -PathType Container) {
        Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
