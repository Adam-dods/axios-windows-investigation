[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $env:USERPROFILE "Downloads")
)

$ErrorActionPreference = "Stop"

$AxiosUtf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $AxiosUtf8
[Console]::OutputEncoding = $AxiosUtf8
$OutputEncoding = $AxiosUtf8

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = [Security.Principal.WindowsPrincipal]::new(
    $CurrentIdentity
)
$IsAdministrator = $CurrentPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

$Root = Split-Path -Parent $PSScriptRoot
$Bin = Join-Path $Root "bin"
$CoreBinary = Join-Path $Bin "axios-core.exe"
$ScopeBinary = Join-Path $Bin "axios-user-scope-access-review.exe"
$ExposureBinary = Join-Path $Bin "axios-user-exposure-audit.exe"
$ResponsePlanBinary = Join-Path $Bin "axios-standard-user-response-plan.exe"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Output = Join-Path $OutputDirectory "AXIOS-Standard-User-Audit-$Stamp"

New-Item -ItemType Directory -Path $Output -Force | Out-Null

foreach ($Binary in @(
    $CoreBinary,
    $ScopeBinary,
    $ExposureBinary,
    $ResponsePlanBinary
)) {
    if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
        throw "AXIOS standard-user executable was not found: $Binary"
    }
}

function Invoke-AxiosStandardUserReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Binary,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    & $Binary --output $Destination
    $ExitCode = $LASTEXITCODE

    if ($ExitCode -ne 0) {
        throw "AXIOS standard-user collector failed with exit code ${ExitCode}: $Binary"
    }

    $Report = Get-Content -Encoding UTF8 -LiteralPath $Destination -Raw | ConvertFrom-Json

    if ($Report.success -ne $true) {
        throw "AXIOS standard-user collector returned success=false: $Binary"
    }

    return $Report
}

$ScopePath = Join-Path $Output "user-scope-access-review.json"
$ExposurePath = Join-Path $Output "user-exposure-audit.json"
$NetworkPath = Join-Path $Output "network-posture.json"

$NetworkRaw = & $CoreBinary "network-posture"
$NetworkExitCode = $LASTEXITCODE

if ($NetworkExitCode -ne 0) {
    throw "AXIOS network posture failed with exit code $NetworkExitCode."
}

if ([string]::IsNullOrWhiteSpace($NetworkRaw)) {
    throw "AXIOS network posture returned an empty report."
}

$NetworkRaw | Set-Content -LiteralPath $NetworkPath -Encoding utf8
$Network = $NetworkRaw | ConvertFrom-Json

if ($Network.success -ne $true) {
    throw "AXIOS network posture returned success=false."
}

$Scope = Invoke-AxiosStandardUserReport `
    -Binary $ScopeBinary `
    -Destination $ScopePath

$Exposure = Invoke-AxiosStandardUserReport `
    -Binary $ExposureBinary `
    -Destination $ExposurePath

$ResponsePlanPath = Join-Path $Output "standard-user-response-plan.json"

& $ResponsePlanBinary `
    --scope $ScopePath `
    --exposure $ExposurePath `
    --network $NetworkPath `
    --output $ResponsePlanPath

$ResponsePlanExitCode = $LASTEXITCODE

if ($ResponsePlanExitCode -ne 0) {
    throw "AXIOS standard-user response plan failed with exit code $ResponsePlanExitCode."
}

$ResponsePlan = Get-Content -Encoding UTF8 -LiteralPath $ResponsePlanPath -Raw | ConvertFrom-Json

if ($ResponsePlan.success -ne $true) {
    throw "AXIOS standard-user response plan returned success=false."
}

$PartialReports = @(
    if ($Network.collection_status -ne "complete") {
        "network-posture"
    }

    if ($Scope.collection_status -ne "complete") {
        "user-scope-access-review"
    }

    if ($Exposure.collection_status -ne "complete") {
        "user-exposure-audit"
    }
)

$Manifest = [PSCustomObject]@{
    success = $true
    collector = "axios_standard_user_audit"
    execution_context = [PSCustomObject]@{
        administrator = $false
        scope = "read_only_standard_user_assessment"
        system_wide_kernel_memory_visibility = "not_available_without_administrator"
    }
    collection_status = if ($PartialReports.Count -eq 0) {
        "complete"
    }
    else {
        "partial"
    }
    partial_reports = @($PartialReports)
    findings = @(
        @($Scope.findings) +
        @($Exposure.findings)
    )
    collection_gaps = @(
        foreach ($PartialReport in $PartialReports) {
            "{0}: partial visibility" -f $PartialReport
        }
    )
    reports = @(
        [PSCustomObject]@{
            name = "network_posture"
            path = $NetworkPath
            findings = 0
            collection_status = $Network.collection_status
        },
        [PSCustomObject]@{
            name = "user_scope_access_review"
            path = $ScopePath
            findings = $Scope.summary.findings
            collection_status = $Scope.collection_status
        },
        [PSCustomObject]@{
            name = "user_exposure_audit"
            path = $ExposurePath
            findings = $Exposure.summary.findings
            collection_status = $Exposure.collection_status
        },
        [PSCustomObject]@{
            name = "standard_user_response_plan"
            path = $ResponsePlanPath
            findings = $ResponsePlan.summary.response_actions
            collection_status = "complete"
        }
    )
    summary = [PSCustomObject]@{
        findings = (
            [int]$Scope.summary.findings +
            [int]$Exposure.summary.findings
        )
        response_actions = [int]$ResponsePlan.summary.response_actions
        reports_completed = 4
    }
}

$ManifestPath = Join-Path $Output "standard-user-manifest.json"
$Manifest |
    ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $ManifestPath -Encoding utf8

$DetailedReport = Join-Path `
    $OutputDirectory `
    "AXIOS-Standard-User-Details-$Stamp.txt"

$Detailed = [PSCustomObject]@{
    manifest = $Manifest
    scope = $Scope
    exposure = $Exposure
    network = $Network
    response_plan = $ResponsePlan
}

[System.IO.File]::WriteAllText(
    $DetailedReport,
    ($Detailed | ConvertTo-Json -Depth 30),
    $AxiosUtf8
)

Write-Host ""
function ConvertTo-AxiosDisplayName {
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

function ConvertTo-AxiosDisplayValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return "Not available"
    }

    if ($Value -is [bool]) {
        if ($Value) {
            return "Yes"
        }

        return "No"
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

    return $null
}

function Write-AxiosEvidenceRows {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [int]$Depth = 0,

        [int]$MaximumDepth = 2,

        [int]$MaximumRows = 24,

        [ref]$RowsWritten
    )

    if ($null -eq $Value -or $RowsWritten.Value -ge $MaximumRows) {
        return
    }

    foreach ($Property in @($Value.PSObject.Properties)) {
        if ($RowsWritten.Value -ge $MaximumRows) {
            break
        }

        if ($Property.Name -in @(
            "success",
            "collector",
            "firewall_profiles",
            "recommended_actions",
            "response_actions",
            "output",
            "path",
            "Length",
            "Count",
            "PSComputerName",
            "RunspaceId",
            "PSShowComputerName"
        )) {
            continue
        }

        $DisplayName = ConvertTo-AxiosDisplayName $Property.Name
        $DisplayValue = ConvertTo-AxiosDisplayValue $Property.Value

        if ($null -ne $DisplayValue) {
            Write-Host (
                "  {0,-27}: {1}" -f
                $DisplayName,
                $DisplayValue
            )

            $RowsWritten.Value += 1
            continue
        }

        $Items = @($Property.Value)

        if (
            $Property.Value -is [System.Collections.IEnumerable] -and
            $Property.Value -isnot [string]
        ) {
            Write-Host (
                "  {0,-27}: {1}" -f
                $DisplayName,
                $Items.Count
            )

            $RowsWritten.Value += 1

            if (
                $Depth -lt $MaximumDepth -and
                $Items.Count -gt 0 -and
                $Items.Count -le 5
            ) {
                foreach ($Item in $Items) {
                    $ItemDisplayValue = ConvertTo-AxiosDisplayValue $Item

                    if ($null -ne $ItemDisplayValue) {
                        Write-Host (
                            "    - {0}" -f $ItemDisplayValue
                        )
                        $RowsWritten.Value += 1
                    }
                    else {
                        Write-AxiosEvidenceRows `
                            -Value $Item `
                            -Depth ($Depth + 1) `
                            -MaximumDepth $MaximumDepth `
                            -MaximumRows $MaximumRows `
                            -RowsWritten $RowsWritten
                    }

                    if ($RowsWritten.Value -ge $MaximumRows) {
                        break
                    }
                }
            }

            continue
        }

        if ($Depth -lt $MaximumDepth) {
            Write-Host ("  {0}" -f $DisplayName)
            $RowsWritten.Value += 1

            Write-AxiosEvidenceRows `
                -Value $Property.Value `
                -Depth ($Depth + 1) `
                -MaximumDepth $MaximumDepth `
                -MaximumRows $MaximumRows `
                -RowsWritten $RowsWritten
        }
    }
}

Write-Host ""
Write-Host "STANDARD USER SECURITY ASSESSMENT"
Write-Host "================================="
Write-Host ("Assessment status      : {0}" -f $Manifest.collection_status)
Write-Host ("Collectors completed   : {0}" -f $Manifest.summary.reports_completed)
Write-Host ("Security findings      : {0}" -f $Manifest.summary.findings)
Write-Host ("Visibility limitations : {0}" -f (@($PartialReports).Count))

Write-Host ""
Write-Host "SYSTEM VISIBILITY"
Write-Host "-----------------"
Write-Host ("Network posture        : {0}" -f $Network.collection_status)
Write-Host ("User access scope      : {0}" -f $Scope.collection_status)
Write-Host ("Exposure assessment    : {0}" -f $Exposure.collection_status)

Write-Host ""
Write-Host "OBSERVED SECURITY DATA"
Write-Host "----------------------"

$CoverageReports = @(
    [PSCustomObject]@{
        Name = "Network Configuration"
        Report = $Network
    },
    [PSCustomObject]@{
        Name = "User Execution Surface"
        Report = $Scope
    },
    [PSCustomObject]@{
        Name = "System Exposure Coverage"
        Report = $Exposure
    }
)

foreach ($CoverageReport in $CoverageReports) {
    Write-Host ""
    Write-Host $CoverageReport.Name.ToUpperInvariant()
    Write-Host ("-" * $CoverageReport.Name.Length)

    $DisplaySource = $CoverageReport.Report

    if (
        $null -ne $CoverageReport.Report -and
        $CoverageReport.Report.PSObject.Properties.Name -contains "summary"
    ) {
        $DisplaySource = $CoverageReport.Report.summary
    }

    $RowsWritten = 0

    Write-AxiosEvidenceRows `
        -Value $DisplaySource `
        -MaximumRows 24 `
        -RowsWritten ([ref]$RowsWritten)

    if (
        $CoverageReport.Name -eq "Network Configuration" -and
        $null -ne $DisplaySource -and
        $DisplaySource.PSObject.Properties.Name -contains
            "firewall_profiles"
    ) {
        $FirewallProfiles = @($DisplaySource.firewall_profiles)

        if ($FirewallProfiles.Count -gt 0) {
            Write-Host "  Firewall profiles"

            foreach ($FirewallProfile in $FirewallProfiles) {
                $ProfileName = if (
                    $FirewallProfile.PSObject.Properties.Name -contains
                        "name"
                ) {
                    [string]$FirewallProfile.name
                }
                else {
                    "Unknown"
                }

                $ProfileEnabled = if (
                    $FirewallProfile.PSObject.Properties.Name -contains
                        "enabled"
                ) {
                    ConvertTo-AxiosDisplayValue `
                        $FirewallProfile.enabled
                }
                else {
                    "Unknown"
                }

                $Inbound = if (
                    $FirewallProfile.PSObject.Properties.Name -contains
                        "default_inbound_action"
                ) {
                    ConvertTo-AxiosDisplayValue `
                        $FirewallProfile.default_inbound_action
                }
                else {
                    "Not configured"
                }

                $Outbound = if (
                    $FirewallProfile.PSObject.Properties.Name -contains
                        "default_outbound_action"
                ) {
                    ConvertTo-AxiosDisplayValue `
                        $FirewallProfile.default_outbound_action
                }
                else {
                    "Not configured"
                }

                Write-Host ("    Profile             : {0}" -f $ProfileName)
                Write-Host ("      Enabled           : {0}" -f $ProfileEnabled)
                Write-Host ("      Default inbound   : {0}" -f $Inbound)
                Write-Host ("      Default outbound  : {0}" -f $Outbound)
            }
        }
    }

    if ($RowsWritten -eq 0) {
        Write-Host "  Verification State         : Evidence collected"
    }
}

Write-Host ""
Write-Host "SECURITY FINDINGS"
Write-Host "-----------------"

$ImportantFindings = @($Scope.findings) + @($Exposure.findings)

if ($ImportantFindings.Count -eq 0) {
    Write-Host "Observed findings      : None"
    Write-Host "Verification state     : No finding established"
}
else {
    foreach ($Finding in @($ImportantFindings | Select-Object -First 15)) {
        $Priority = if (
            $Finding.PSObject.Properties.Name -contains "priority" -and
            -not [string]::IsNullOrWhiteSpace([string]$Finding.priority)
        ) {
            [string]$Finding.priority
        }
        else {
            "review"
        }

        $Title = if (
            $Finding.PSObject.Properties.Name -contains "title" -and
            -not [string]::IsNullOrWhiteSpace([string]$Finding.title)
        ) {
            [string]$Finding.title
        }
        elseif (
            $Finding.PSObject.Properties.Name -contains "classification"
        ) {
            ([string]$Finding.classification) -replace "_", " "
        }
        else {
            "Unnamed security finding"
        }

        Write-Host ""
        Write-Host (
            "[{0}] {1}" -f
            $Priority.ToUpperInvariant(),
            $Title
        )

        $RowsWritten = 0

        Write-AxiosEvidenceRows `
            -Value $Finding `
            -MaximumRows 16 `
            -RowsWritten ([ref]$RowsWritten)
    }
}

Write-Host ""
Write-Host "VISIBILITY LIMITATIONS"
Write-Host "----------------------"

if ($PartialReports.Count -eq 0) {
    Write-Host "Limitations observed   : None"
}
else {
    foreach ($PartialReport in $PartialReports) {
        Write-Host ("Collector              : {0}" -f $PartialReport)
        Write-Host "Collection state       : Partial"
        Write-Host "Assessment effect      : Some evidence remains unavailable"
    }
}

if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
    Write-Host ""
    Write-Host ("Detailed TXT report    : {0}" -f $DetailedReport)
    Write-Host ("Raw evidence directory : {0}" -f $Output)
}
Write-Host ""

if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
    "AXIOS_STANDARD_USER_SUCCESS=$($Manifest.success)"
    "AXIOS_STANDARD_USER_COLLECTION_STATUS=$($Manifest.collection_status)"
    "AXIOS_STANDARD_USER_FINDINGS=$($Manifest.summary.findings)"
    "OUTPUT=$Output"
    "DETAILED_REPORT=$DetailedReport"
}
