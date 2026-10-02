param(
    [ValidateRange(1, 25000)]
    [int]$MaxFiles = 1500,

    [ValidateSet("fast", "smart")]
    [string]$AuditMode = "fast",

    [string]$OutputDirectory = (
        Join-Path $env:USERPROFILE "Downloads"
    )
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"


function Get-AxiosOptionalProperty {
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory)]
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

    return $Property.Value
}



function Get-AxiosOptionalPath {
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory)]
        [string[]]$Names,

        [AllowNull()]
        [object]$DefaultValue = $null
    )

    $Current = $Value

    foreach ($Name in $Names) {
        if ($null -eq $Current) {
            return $DefaultValue
        }

        $Property = $Current.PSObject.Properties[$Name]

        if ($null -eq $Property) {
            return $DefaultValue
        }

        $Current = $Property.Value
    }

    if ($null -eq $Current) {
        return $DefaultValue
    }

    return $Current
}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptRoot
$Bin = Join-Path $Root "bin"
$OutputRoot = $OutputDirectory
$HashManifest = Join-Path $Root "SHA256SUMS.txt"

$Core = Join-Path $Bin "axios-core.exe"
$Audit = Join-Path $Bin "axios-file-audit.exe"
$Applications = Join-Path $Bin "axios-application-investigation.exe"
$Correlate = Join-Path $Bin "axios-audit-correlate.exe"
$TrustReview = Join-Path $Bin "axios-trust-review.exe"
$KernelReview = Join-Path $Bin "axios-kernel-review.exe"
$DriverTrust = Join-Path $Bin "axios-driver-trust.exe"
$ProcessIntegrity = Join-Path $Bin "axios-process-integrity.exe"
$MemoryExecutionReview = Join-Path $Bin "axios-memory-execution-review.exe"
$KernelRuntimeIntegrity = Join-Path $Bin "axios-kernel-runtime-integrity.exe"
$FirmwareIdentityReview = Join-Path $Bin "axios-firmware-identity-review.exe"
$RuntimeResourceReview = Join-Path $Bin "axios-runtime-resource-review.exe"
$NetworkIdentityReview = Join-Path $Bin "axios-network-identity-review.exe"
$NetworkDeepReview = Join-Path $Bin "axios-network-deep-review.exe"
$CollectionIntegrityReview = Join-Path $Bin "axios-collection-integrity-review.exe"
$PrivilegeSurfaceReview = Join-Path $Bin "axios-privilege-surface-review.exe"
$TelemetryIntegrityReview = Join-Path $Bin "axios-telemetry-integrity-review.exe"
$SecurityControlsReview = Join-Path $Bin "axios-security-controls-review.exe"
$RemoteAccessReview = Join-Path $Bin "axios-remote-access-review.exe"
$ExecutionPolicyReview = Join-Path $Bin "axios-execution-policy-review.exe"
$IdentityAccessReview = Join-Path $Bin "axios-identity-access-review.exe"
$PlatformHardeningReview = Join-Path $Bin "axios-platform-hardening-review.exe"
$VirtualizationBoundaryReview = Join-Path $Bin "axios-virtualization-boundary-review.exe"
$ObservationIntegrityReview = Join-Path $Bin "axios-observation-integrity-review.exe"
$AdminExposureAudit = Join-Path $Bin "axios-admin-exposure-audit.exe"
$ReasoningWeb = Join-Path $Bin "axios-reasoning-web.exe"
$NetworkExposure = Join-Path $Bin "axios-network-exposure.exe"
$State = Join-Path $Bin "axios-investigation-state.exe"
$ResponsePlan = Join-Path $Bin "axios-response-plan.exe"
$Baseline = Join-Path $Bin "axios-sensitive-baseline.exe"
$CorrelationScore = Join-Path $Bin "axios-correlation-score.exe"
$HardwareAdvisory = Join-Path $Bin "axios-hardware-advisory.exe"
$ThreatHypotheses = Join-Path $Bin "axios-threat-hypotheses.exe"
$ForensicExport = Join-Path $Bin "axios-forensic-export.exe"
$BehaviorHunt = Join-Path $Bin "axios-behavior-hunt.exe"
$PersistenceExecution = Join-Path $Bin "axios-persistence-execution-review.exe"
$DefenderEvidence = Join-Path $Bin "axios-defender-evidence.exe"
$DefenderTamperReview = Join-Path $Bin "axios-defender-tamper-review.exe"

$RunId = Get-Date -Format "yyyyMMdd-HHmmss-fff"
$Output = Join-Path $OutputRoot "complete-investigation-$RunId"
$Failure = Join-Path $Output "failure.txt"

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Test-IsAdministrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function ConvertTo-AxiosArgument {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value.Contains('"')) {
        throw "AXIOS rejected an argument containing a double quote."
    }

    if ($Value.Length -eq 0) {
        return '""'
    }

    if ($Value -match '\s') {
        return '"' + $Value + '"'
    }

    return $Value
}

function Write-AxiosText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    [System.IO.File]::WriteAllText(
        $Path,
        $Text,
        $Utf8NoBom
    )
}

function Write-AxiosJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$Value,

        [ValidateRange(1, 100)]
        [int]$Depth = 20
    )

    Write-AxiosText `
        -Path $Path `
        -Text ($Value | ConvertTo-Json -Depth $Depth)
}

function Read-AxiosJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "AXIOS JSON report was not created: $Path"
    }

    $Text = [System.IO.File]::ReadAllText(
        $Path,
        $Utf8NoBom
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        throw "AXIOS JSON report is empty: $Path"
    }

    try {
        return $Text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "AXIOS returned invalid JSON in ${Path}: $($_.Exception.Message)"
    }
}

function Get-AxiosPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $Property = $Report.PSObject.Properties[$Name]

    if ($null -eq $Property) {
        return $null
    }

    return $Property.Value
}

function Get-AxiosCompactReport {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report
    )

    $ReportSummary = Get-AxiosPropertyValue `
        -Report $Report `
        -Name "summary"

    if ($null -ne $ReportSummary) {
        return $ReportSummary
    }

    return [PSCustomObject]@{
        collector = Get-AxiosPropertyValue -Report $Report -Name "collector"
        success = Get-AxiosPropertyValue -Report $Report -Name "success"
    }
}

$script:AxiosPerformanceStages = [System.Collections.Generic.List[object]]::new()

function Invoke-AxiosJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $ErrorPath = "${Destination}.stderr.txt"

    Remove-Item `
        -LiteralPath $Destination `
        -Force `
        -ErrorAction SilentlyContinue

    Remove-Item `
        -LiteralPath $ErrorPath `
        -Force `
        -ErrorAction SilentlyContinue

    $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $FilePath
    $StartInfo.Arguments = (
        $Arguments |
            ForEach-Object {
                ConvertTo-AxiosArgument -Value ([string]$_)
            }
    ) -join " "

    $StartInfo.WorkingDirectory = $Root
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $StartInfo.StandardOutputEncoding = $Utf8NoBom
    $StartInfo.StandardErrorEncoding = $Utf8NoBom

    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $StartInfo

    if (-not $Process.Start()) {
        throw "AXIOS process could not be started: $FilePath"
    }

    $StandardOutputTask = $Process.StandardOutput.ReadToEndAsync()
    $StandardErrorTask = $Process.StandardError.ReadToEndAsync()

    $Process.WaitForExit()

    $StandardOutput = $StandardOutputTask.Result
    $StandardError = $StandardErrorTask.Result
    $ExitCode = $Process.ExitCode

    $Process.Dispose()

    if (-not [string]::IsNullOrWhiteSpace($StandardError)) {
        Write-AxiosText `
            -Path $ErrorPath `
            -Text $StandardError
    }

    if ($ExitCode -ne 0) {
        throw (
            "AXIOS command failed with exit code " +
            $ExitCode +
            ": " +
            $FilePath +
            [Environment]::NewLine +
            $StandardError
        )
    }

    $ReportName = [System.IO.Path]::GetFileNameWithoutExtension($Destination)

    if ([string]::IsNullOrWhiteSpace($StandardOutput)) {
        throw "AXIOS command returned an empty report: $ReportName"
    }

    try {
        $Report = $StandardOutput | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "AXIOS command returned invalid JSON: $ReportName ($($_.Exception.Message))"
    }

    $SuccessProperty = $Report.PSObject.Properties["success"]

    if ($null -eq $SuccessProperty) {
        throw "AXIOS command report is missing success: $ReportName"
    }

    if ($SuccessProperty.Value -isnot [bool]) {
        throw "AXIOS command report has a non-boolean success value: $ReportName"
    }

    if ($SuccessProperty.Value -ne $true) {
        $Detail = @(
            Get-AxiosPropertyValue -Report $Report -Name "error"
            Get-AxiosPropertyValue -Report $Report -Name "reason"
            Get-AxiosPropertyValue -Report $Report -Name "collection_error"
        ) | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        }

        throw "AXIOS command report indicates failure: $ReportName ($($Detail -join '; '))"
    }

    Write-AxiosText `
        -Path $Destination `
        -Text $StandardOutput

    $Stopwatch.Stop()

    $script:AxiosPerformanceStages.Add([PSCustomObject]@{
        report = $ReportName
        executable = [System.IO.Path]::GetFileName($FilePath)
        duration_ms = [int64]$Stopwatch.ElapsedMilliseconds
        arguments_count = @($Arguments).Count
        output_utf8_bytes = [System.Text.Encoding]::UTF8.GetByteCount($StandardOutput)
        success = $true
    })

    return $Report
}

function Test-AxiosHashes {
    if (-not (Test-Path -LiteralPath $HashManifest -PathType Leaf)) {
        throw "AXIOS SHA256SUMS.txt was not found."
    }

    foreach ($Line in Get-Content -Encoding UTF8 -LiteralPath $HashManifest) {
        if ([string]::IsNullOrWhiteSpace($Line)) {
            continue
        }

        if ($Line -notmatch '^([0-9a-fA-F]{64})\s+\*?(.+)$') {
            throw "Invalid AXIOS SHA256SUMS entry: $Line"
        }

        $ExpectedHash = $Matches[1].ToLowerInvariant()
        $RelativePath = $Matches[2].Trim().Replace("/", "\")

        if (
            [System.IO.Path]::IsPathRooted($RelativePath) -or
            $RelativePath.Contains(":") -or
            $RelativePath -match '(^|\\)\.\.($|\\)'
        ) {
            throw "AXIOS SHA256SUMS entry escapes the package root: $RelativePath"
        }

        $PackageRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd("\")
        $PackageRootWithSeparator = $PackageRoot + "\"
        $TargetPath = [System.IO.Path]::GetFullPath(
            (Join-Path $PackageRoot $RelativePath)
        )

        if (
            -not $TargetPath.StartsWith(
                $PackageRootWithSeparator,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw "AXIOS SHA256SUMS entry escapes the package root: $RelativePath"
        }

        if (-not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) {
            throw "AXIOS package file is missing: $TargetPath"
        }

        $ActualHash = (
            Get-FileHash `
                -LiteralPath $TargetPath `
                -Algorithm SHA256
        ).Hash.ToLowerInvariant()

        if ($ActualHash -ne $ExpectedHash) {
            throw "AXIOS package hash mismatch: $TargetPath"
        }
    }
}

if (-not (Test-IsAdministrator)) {
    throw "AXIOS Complete Investigation must run as Administrator."
}

foreach ($RequiredFile in @(
    $Core,
    $Audit,
    $Applications,
    $Correlate,
    $State,
    $ResponsePlan,
    $TrustReview,
    $KernelReview,
    $DriverTrust,
    $ProcessIntegrity,
    $MemoryExecutionReview,
    $KernelRuntimeIntegrity,
    $FirmwareIdentityReview,
    $RuntimeResourceReview,
    $TelemetryIntegrityReview,
    $SecurityControlsReview,
    $RemoteAccessReview,
    $ExecutionPolicyReview,
    $IdentityAccessReview,
    $PlatformHardeningReview,
    $VirtualizationBoundaryReview,
    $ObservationIntegrityReview,
    $AdminExposureAudit,
    $ReasoningWeb,
    $PrivilegeSurfaceReview,
    $NetworkIdentityReview,
    $NetworkDeepReview,
    $CollectionIntegrityReview,
    $NetworkExposure,
    (Join-Path $Bin "axios-network-service-review.exe"),
    (Join-Path $Bin "axios-boot-chain-review.exe"),
    (Join-Path $Bin "axios-code-integrity-investigation.exe")
)) {
    if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
        throw "Required AXIOS executable was not found: $RequiredFile"
    }
}

New-Item `
    -ItemType Directory `
    -Path $Output `
    -Force |
    Out-Null

Test-AxiosHashes

try {
    Write-Host "[1/42] AXIOS registry persistence"

    $RegistryPersistencePath = Join-Path `
        $Output `
        "registry-persistence.json"

    $RegistryPersistence = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("registry-persistence") `
        -Destination $RegistryPersistencePath

    Write-Host "[2/42] AXIOS extended persistence"

    $ExtendedPersistencePath = Join-Path `
        $Output `
        "extended-persistence.json"

    $ExtendedPersistence = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("extended-persistence") `
        -Destination $ExtendedPersistencePath

    $PersistenceCoveragePath = Join-Path $Output "persistence-coverage.json"

    $PersistenceCoverage = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("persistence-coverage") `
        -Destination $PersistenceCoveragePath

    $CombinedPersistencePath = Join-Path `
        $Output `
        "persistence-combined.json"

    $CombinedPersistence = [PSCustomObject]@{
        schema_version = 1
        collector = "axios_combined_persistence"
        success = (
            $RegistryPersistence.success -eq $true -and
            $ExtendedPersistence.success -eq $true -and
            $PersistenceCoverage.success -eq $true
        )
        registry = $RegistryPersistence
        extended = $ExtendedPersistence
        coverage = $PersistenceCoverage
    }

    Write-AxiosJson `
        -Path $CombinedPersistencePath `
        -Value $CombinedPersistence `
        -Depth 40

    Write-Host "[3/42] AXIOS live activity"

    $LiveActivityPath = Join-Path `
        $Output `
        "live-activity.json"

    $LiveActivity = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("live-activity") `
        -Destination $LiveActivityPath

    Write-Host "[4/42] AXIOS process integrity"

    $ProcessIntegrityPath = Join-Path `
        $Output `
        "process-integrity.json"

    $ProcessIntegrityReport = Invoke-AxiosJson `
        -FilePath $ProcessIntegrity `
        -Arguments @(
            "--max-processes",
            "512",
            "--max-signature-checks",
            "256"
        ) `
        -Destination $ProcessIntegrityPath

    Write-Host "[5/42] AXIOS runtime CPU and memory review"
    $RuntimeResourceReviewPath = Join-Path $Output "runtime-resource-review.json"
    $RuntimeResourceReviewReport = Invoke-AxiosJson `
        -FilePath $RuntimeResourceReview `
        -Arguments @(
            "--processes", $ProcessIntegrityPath,
            "--max-processes", "30"
        ) `
        -Destination $RuntimeResourceReviewPath

    Write-Host "[6/42] AXIOS telemetry integrity review"
    $TelemetryIntegrityReviewPath = Join-Path $Output "telemetry-integrity-review.json"
    $TelemetryIntegrityReviewReport = Invoke-AxiosJson `
        -FilePath $TelemetryIntegrityReview `
        -Arguments @("--collection-scope", "current") `
        -Destination $TelemetryIntegrityReviewPath

    Write-Host "[7/42] AXIOS privileged execution surface review"
    $PrivilegeSurfaceReviewPath = Join-Path $Output "privilege-surface-review.json"
    $PrivilegeSurfaceReviewReport = Invoke-AxiosJson `
        -FilePath $PrivilegeSurfaceReview `
        -Arguments @("--max-items", "512") `
        -Destination $PrivilegeSurfaceReviewPath

    Write-Host "[8/42] AXIOS hardware trust"

    $HardwareTrustPath = Join-Path `
        $Output `
        "hardware-trust.json"

    $HardwareTrust = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("hardware-trust") `
        -Destination $HardwareTrustPath

    Write-Host "[9/42] AXIOS kernel posture"

    $KernelPosturePath = Join-Path `
        $Output `
        "kernel-posture.json"

    $KernelPosture = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("kernel-posture") `
        -Destination $KernelPosturePath

    $KernelReviewPath = Join-Path `
        $Output `
        "kernel-review.json"

    $KernelReport = Invoke-AxiosJson `
        -FilePath $KernelReview `
        -Arguments @(
            "--kernel-posture",
            $KernelPosturePath,
            "--hardware-trust",
            $HardwareTrustPath
        ) `
        -Destination $KernelReviewPath

    Write-Host "[10/42] AXIOS loaded driver trust"

    $DriverTrustPath = Join-Path `
        $Output `
        "driver-trust.json"

    $DriverTrustReport = Invoke-AxiosJson `
        -FilePath $DriverTrust `
        -Arguments @(
            "--kernel-posture",
            $KernelPosturePath,
            "--max-drivers",
            "256"
        ) `
        -Destination $DriverTrustPath

    $TrustReviewPath = Join-Path `
        $Output `
        "trust-review.json"

    $TrustReport = Invoke-AxiosJson `
        -FilePath $TrustReview `
        -Arguments @(
            "--hardware-trust",
            $HardwareTrustPath
        ) `
        -Destination $TrustReviewPath

    Write-Host "[11/42] AXIOS browser extensions"

    $BrowserExtensionsPath = Join-Path `
        $Output `
        "browser-extensions.json"

    $BrowserExtensions = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("browser-extensions") `
        -Destination $BrowserExtensionsPath

    Write-Host "[12/42] AXIOS access surface"

    $AccessSurfacePath = Join-Path `
        $Output `
        "access-surface.json"

    $AccessSurfaceReport = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("access-surface") `
        -Destination $AccessSurfacePath

    Write-Host "[13/42] AXIOS network posture"

    $NetworkPosturePath = Join-Path `
        $Output `
        "network-posture.json"

    $NetworkPostureReport = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("network-posture") `
        -Destination $NetworkPosturePath

    $ContextPosturePath = Join-Path `
        $Output `
        "context-posture.json"

    $ContextPostureReport = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("context-posture") `
        -Destination $ContextPosturePath

    Write-Host "[14/42] AXIOS network exposure"

    $NetworkExposurePath = Join-Path `
        $Output `
        "network-exposure.json"

    $NetworkExposureReport = Invoke-AxiosJson `
        -FilePath $NetworkExposure `
        -Arguments @(
            "--live-activity",
            $LiveActivityPath,
            "--process-integrity",
            $ProcessIntegrityPath,
            "--max-endpoints",
            "512"
        ) `
        -Destination $NetworkExposurePath

    Write-Host "[15/42] AXIOS security posture"

    $SecurityPosturePath = Join-Path `
        $Output `
        "security-posture.json"

    $SecurityPostureReport = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("security-posture") `
        -Destination $SecurityPosturePath

    Write-Host "[16/42] AXIOS security review"

    $SecurityReviewPath = Join-Path `
        $Output `
        "security-review.json"

    $SecurityReviewReport = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("security-review") `
        -Destination $SecurityReviewPath

    Write-Host "[17/42] AXIOS health posture"

    $HealthPosturePath = Join-Path `
        $Output `
        "health-posture.json"

    $HealthPostureReport = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("health-posture") `
        -Destination $HealthPosturePath

    Write-Host "[18/42] AXIOS software inventory and update exposure"

    $SoftwareInventoryPath = Join-Path `
        $Output `
        "software-inventory.json"

    $SoftwareInventoryReport = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("software-inventory") `
        -Destination $SoftwareInventoryPath

    $UpdateExposurePath = Join-Path `
        $Output `
        "update-exposure.json"

    $UpdateExposureReport = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("updates") `
        -Destination $UpdateExposurePath

    Write-Host "[19/42] AXIOS event correlation"

    $EventCorrelationPath = Join-Path `
        $Output `
        "event-correlation.json"

    $EventCorrelationReport = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @(
            "event-correlation",
            "--hours",
            "24"
        ) `
        -Destination $EventCorrelationPath

    Write-Host "[20/42] AXIOS deep investigation"

    $DeepInvestigationPath = Join-Path `
        $Output `
        "deep-investigation.json"

    $DeepInvestigationReport = Invoke-AxiosJson `
        -FilePath $Core `
        -Arguments @("deep-investigation") `
        -Destination $DeepInvestigationPath

    Write-Host "[21/42] AXIOS universal file audit"

    $AuditPath = Join-Path `
        $Output `
        "universal-file-audit.json"

    $AuditReport = Invoke-AxiosJson `
        -FilePath $Audit `
        -Arguments @(
            "--mode",
            $AuditMode,
            "--max-files",
            $MaxFiles.ToString(),
            "--recent-days",
            "30",
            "--seed-report",
            $CombinedPersistencePath,
            "--seed-report",
            $LiveActivityPath
        ) `
        -Destination $AuditPath

    Write-Host "[22/42] AXIOS application investigation and evidence correlation"

    $ApplicationPath = Join-Path `
        $Output `
        "application-investigation.json"

    $ApplicationReport = Invoke-AxiosJson `
        -FilePath $Applications `
        -Arguments @(
            "--audit",
            $AuditPath
        ) `
        -Destination $ApplicationPath

    $CorrelationPath = Join-Path `
        $Output `
        "audit-correlation.json"

    $CorrelationReport = Invoke-AxiosJson `
        -FilePath $Correlate `
        -Arguments @(
            "--audit",
            $AuditPath,
            "--persistence",
            $CombinedPersistencePath,
            "--live-activity",
            $LiveActivityPath
        ) `
        -Destination $CorrelationPath

Write-Host "[23/42] AXIOS network service review"
    $NetworkServiceReviewPath = Join-Path $Output "network-service-review.json"
    $NetworkServiceReviewReport = Invoke-AxiosJson `
        -FilePath (Join-Path $Bin "axios-network-service-review.exe") `
        -Arguments @("--network-exposure", $NetworkExposurePath, "--max-rules", "1024") `
        -Destination $NetworkServiceReviewPath

    Write-Host "[24/42] AXIOS memory execution review"
    $MemoryExecutionReviewPath = Join-Path $Output "memory-execution-review.json"
    $MemoryExecutionReviewReport = Invoke-AxiosJson `
        -FilePath $MemoryExecutionReview `
        -Arguments @(
            "--processes", $ProcessIntegrityPath,
            "--persistence", (Join-Path $Output "persistence-combined.json"),
            "--network", $NetworkServiceReviewPath,
            "--max-processes", "256",
            "--max-regions", "4096"
        ) `
        -Destination $MemoryExecutionReviewPath

    Write-Host "[25/42] AXIOS network identity and egress review"
    $NetworkIdentityReviewPath = Join-Path $Output "network-identity-review.json"
    $NetworkIdentityReviewReport = Invoke-AxiosJson `
        -FilePath $NetworkIdentityReview `
        -Arguments @(
            "--processes", $ProcessIntegrityPath,
            "--max-connections", "512"
        ) `
        -Destination $NetworkIdentityReviewPath

    Write-Host "[26/42] AXIOS deep network evidence review"
    $NetworkDeepReviewPath = Join-Path $Output "network-deep-review.json"
    $NetworkDeepReviewReport = Invoke-AxiosJson `
        -FilePath $NetworkDeepReview `
        -Arguments @(
            "--profile", "auto",
            "--focus", "overview",
            "--max-tcp", "1024",
            "--max-udp", "512",
            "--max-routes", "512",
            "--max-neighbors", "512",
            "--max-dns", "1024",
            "--max-firewall-rules", "1024",
            "--timeout-ms", "750"
        ) `
        -Destination $NetworkDeepReviewPath

    Write-Host "[27/42] AXIOS boot chain review"
    $BootChainReviewPath = Join-Path $Output "boot-chain-review.json"
    $BootChainReviewReport = Invoke-AxiosJson `
        -FilePath (Join-Path $Bin "axios-boot-chain-review.exe") `
        -Arguments @(
            "--hardware-trust", $HardwareTrustPath,
            "--kernel-posture", $KernelPosturePath
        ) `
        -Destination $BootChainReviewPath

    Write-Host "[28/42] AXIOS Code Integrity investigation"
    $CodeIntegrityInvestigationPath = Join-Path $Output "code-integrity-investigation.json"
    $CodeIntegrityInvestigationReport = Invoke-AxiosJson `
        -FilePath (Join-Path $Bin "axios-code-integrity-investigation.exe") `
        -Arguments @(
            "--kernel-posture", $KernelPosturePath,
            "--driver-trust", $DriverTrustPath,
            "--max-events", "100"
        ) `
        -Destination $CodeIntegrityInvestigationPath

    Write-Host "[29/42] AXIOS kernel runtime integrity review"
    $KernelRuntimeIntegrityPath = Join-Path $Output "kernel-runtime-integrity.json"
    $KernelRuntimeIntegrityReport = Invoke-AxiosJson `
        -FilePath $KernelRuntimeIntegrity `
        -Arguments @(
            "--hardware", $HardwareTrustPath,
            "--kernel", $KernelReviewPath,
            "--drivers", $DriverTrustPath,
            "--boot", $BootChainReviewPath,
            "--code-integrity", $CodeIntegrityInvestigationPath
        ) `
        -Destination $KernelRuntimeIntegrityPath

    Write-Host "[30/42] AXIOS firmware identity and collection confidence review"
    $FirmwareIdentityReviewPath = Join-Path $Output "firmware-identity-review.json"
    $FirmwareIdentityReviewReport = Invoke-AxiosJson `
        -FilePath $FirmwareIdentityReview `
        -Arguments @(
            "--hardware", $HardwareTrustPath,
            "--kernel", $KernelReviewPath
        ) `
        -Destination $FirmwareIdentityReviewPath

    Write-Host "[31/42] AXIOS Defender evidence review"
    $DefenderEvidencePath = Join-Path $Output "defender-evidence.json"

    $DefenderEvidenceReport = Invoke-AxiosJson `
        -FilePath $DefenderEvidence `
        -Arguments @("--days", "30", "--max-events", "500") `
        -Destination $DefenderEvidencePath

    Write-Host "[32/42] AXIOS collection integrity and contradiction review"
    $CollectionIntegrityReviewPath = Join-Path $Output "collection-integrity-review.json"
    $CollectionIntegrityReviewReport = Invoke-AxiosJson `
        -FilePath $CollectionIntegrityReview `
        -Arguments @(
            "--processes", $ProcessIntegrityPath,
            "--memory", $MemoryExecutionReviewPath,
            "--kernel", $KernelRuntimeIntegrityPath,
            "--defender", $DefenderEvidencePath,
            "--network", $NetworkServiceReviewPath,
            "--persistence", (Join-Path $Output "persistence-combined.json")
        ) `
        -Destination $CollectionIntegrityReviewPath

    Write-Host "[33/42] AXIOS security controls review"
    $SecurityControlsReviewPath = Join-Path $Output "security-controls-review.json"
    $SecurityControlsReviewReport = Invoke-AxiosJson `
        -FilePath $SecurityControlsReview `
        -Destination $SecurityControlsReviewPath

    Write-Host "[34/42] AXIOS remote access review"
    $RemoteAccessReviewPath = Join-Path $Output "remote-access-review.json"
    $RemoteAccessReviewReport = Invoke-AxiosJson `
        -FilePath $RemoteAccessReview `
        -Destination $RemoteAccessReviewPath

    Write-Host "[35/42] AXIOS execution policy and audit visibility review"
    $ExecutionPolicyReviewPath = Join-Path $Output "execution-policy-review.json"
    $ExecutionPolicyReviewReport = Invoke-AxiosJson `
        -FilePath $ExecutionPolicyReview `
        -Destination $ExecutionPolicyReviewPath

    Write-Host "[36/42] AXIOS identity and credential access review"
    $IdentityAccessReviewPath = Join-Path $Output "identity-access-review.json"
    $IdentityAccessReviewReport = Invoke-AxiosJson `
        -FilePath $IdentityAccessReview `
        -Destination $IdentityAccessReviewPath

    Write-Host "[37/42] AXIOS platform hardening review"
    $PlatformHardeningReviewPath = Join-Path $Output "platform-hardening-review.json"
    $PlatformHardeningReviewReport = Invoke-AxiosJson `
        -FilePath $PlatformHardeningReview `
        -Destination $PlatformHardeningReviewPath

    Write-Host "[38/42] AXIOS administrator exposure audit"
    $AdminExposureAuditPath = Join-Path $Output "administrator-exposure-audit.json"
    $AdminExposureAuditReport = Invoke-AxiosJson `
        -FilePath $AdminExposureAudit `
        -Destination $AdminExposureAuditPath

    Write-Host "[39/42] AXIOS virtualization boundary review"
    $VirtualizationBoundaryReviewPath = Join-Path $Output "virtualization-boundary-review.json"
    $VirtualizationBoundaryReviewReport = Invoke-AxiosJson `
        -FilePath $VirtualizationBoundaryReview `
        -Arguments @("--max-vms", "64") `
        -Destination $VirtualizationBoundaryReviewPath

    $Summary = [PSCustomObject]@{
        schema_version = 1
        success = $true
        completion_state = "pending_investigation_state_and_response_plan"
        run_id = $RunId
        max_files = $MaxFiles
        audit_mode = $AuditMode
        audit_scope = $AuditReport.scan_scope
        audit_summary = (Get-AxiosOptionalProperty -Value $AuditReport -Name "summary")
        application_summary = (Get-AxiosOptionalProperty -Value $ApplicationReport -Name "summary")
        correlation_summary = (Get-AxiosOptionalProperty -Value $CorrelationReport -Name "summary")
        trust_posture = (Get-AxiosOptionalProperty -Value $TrustReport -Name "summary")
        kernel_posture = (Get-AxiosOptionalProperty -Value $KernelReport -Name "summary")
        driver_trust = (Get-AxiosOptionalProperty -Value $DriverTrustReport -Name "summary")
        process_integrity = Get-AxiosCompactReport -Report $ProcessIntegrityReport
        runtime_resource_review = Get-AxiosCompactReport -Report $RuntimeResourceReviewReport
        telemetry_integrity_review = Get-AxiosCompactReport -Report $TelemetryIntegrityReviewReport
        security_controls_review = Get-AxiosCompactReport -Report $SecurityControlsReviewReport
        remote_access_review = Get-AxiosCompactReport -Report $RemoteAccessReviewReport
        execution_policy_review = Get-AxiosCompactReport -Report $ExecutionPolicyReviewReport
        identity_access_review = Get-AxiosCompactReport -Report $IdentityAccessReviewReport
        platform_hardening_review = Get-AxiosCompactReport -Report $PlatformHardeningReviewReport
        virtualization_boundary_review = Get-AxiosCompactReport -Report $VirtualizationBoundaryReviewReport
        privilege_surface_review = Get-AxiosCompactReport -Report $PrivilegeSurfaceReviewReport
        network_exposure = Get-AxiosCompactReport -Report $NetworkExposureReport
        hardware_trust = [PSCustomObject]@{
            collector = (Get-AxiosOptionalProperty -Value $HardwareTrust -Name "collector")
            success = $HardwareTrust.success
            secure_boot = $HardwareTrust.secure_boot
            tpm = $HardwareTrust.tpm
            device_guard = $HardwareTrust.device_guard
        }
        browser_extensions = [PSCustomObject]@{
            collector = (Get-AxiosOptionalProperty -Value $BrowserExtensions -Name "collector")
            success = $BrowserExtensions.success
            entry_count = $BrowserExtensions.entry_count
            truncated = $BrowserExtensions.truncated
        }
        access_surface = Get-AxiosCompactReport -Report $AccessSurfaceReport
        network_posture = Get-AxiosCompactReport -Report $NetworkPostureReport
        context_posture = Get-AxiosCompactReport -Report $ContextPostureReport
        security_posture = Get-AxiosCompactReport -Report $SecurityPostureReport
        security_review = Get-AxiosCompactReport -Report $SecurityReviewReport
        health_posture = Get-AxiosCompactReport -Report $HealthPostureReport
        software_inventory = Get-AxiosCompactReport -Report $SoftwareInventoryReport
        update_exposure = Get-AxiosCompactReport -Report $UpdateExposureReport
        event_correlation = Get-AxiosCompactReport -Report $EventCorrelationReport
        deep_investigation = Get-AxiosCompactReport -Report $DeepInvestigationReport
        network_service_review = Get-AxiosCompactReport -Report $NetworkServiceReviewReport
        memory_execution = Get-AxiosCompactReport -Report $MemoryExecutionReviewReport
        network_identity_review = Get-AxiosCompactReport -Report $NetworkIdentityReviewReport
        network_deep_review = Get-AxiosCompactReport -Report $NetworkDeepReviewReport
        kernel_runtime_integrity = Get-AxiosCompactReport -Report $KernelRuntimeIntegrityReport
        firmware_identity_review = Get-AxiosCompactReport -Report $FirmwareIdentityReviewReport
        collection_integrity_review = Get-AxiosCompactReport -Report $CollectionIntegrityReviewReport
        boot_chain_review = Get-AxiosCompactReport -Report $BootChainReviewReport
        code_integrity_investigation = Get-AxiosCompactReport -Report $CodeIntegrityInvestigationReport
        output_folder = $Output
        completed_at = (Get-Date).ToString("o")
    }

    $SummaryPath = Join-Path $Output "summary.json"

    Write-AxiosJson `
        -Path $SummaryPath `
        -Value $Summary `
        -Depth 20

    Write-Host "[40/42] AXIOS cross-source observation integrity review"
    $ObservationIntegrityReviewPath = Join-Path $Output "observation-integrity-review.json"
    $ObservationIntegrityReviewReport = Invoke-AxiosJson `
        -FilePath $ObservationIntegrityReview `
        -Arguments @("--processes", $ProcessIntegrityPath) `
        -Destination $ObservationIntegrityReviewPath

    Write-Host "[41/42] AXIOS persistent investigation state"

    $StatePath = Join-Path `
        $Output `
        "investigation-state.json"

    $StateReport = Invoke-AxiosJson `
        -FilePath $State `
        -Arguments @(
            "--summary",
            $SummaryPath,
            "--audit",
            $AuditPath,
            "--applications",
            $ApplicationPath,
            "--correlation",
            $CorrelationPath
        ) `
        -Destination $StatePath

    $Summary | Add-Member `
        -NotePropertyName state `
        -NotePropertyValue $StateReport `
        -Force

    $BaselinePath = Join-Path $Output "sensitive-baseline.json"
    $ScorePath = Join-Path $Output "correlation-score.json"
    $AdvisoryPath = Join-Path $Output "hardware-advisory.json"
    $HypothesesPath = Join-Path $Output "threat-hypotheses.json"
    $ManifestPath = Join-Path $Output "forensic-manifest.json"

    $BaselineReport = Invoke-AxiosJson `
        -FilePath $Baseline `
        -Arguments @(
            "--hardware", $HardwareTrustPath,
            "--kernel", $KernelPosturePath,
            "--drivers", $DriverTrustPath,
            "--persistence", $CombinedPersistencePath,
            "--network", $NetworkServiceReviewPath,
            "--updates", $UpdateExposurePath
        ) `
        -Destination $BaselinePath

    $ScoreReport = Invoke-AxiosJson `
        -FilePath $CorrelationScore `
        -Arguments @(
            "--correlation", $CorrelationPath,
            "--processes", $ProcessIntegrityPath,
            "--network", $NetworkServiceReviewPath,
            "--kernel", $KernelReviewPath,
            "--hardware", $HardwareTrustPath
        ) `
        -Destination $ScorePath

    $AdvisoryReport = Invoke-AxiosJson `
        -FilePath $HardwareAdvisory `
        -Arguments @(
            "--hardware", $HardwareTrustPath,
            "--drivers", $DriverTrustPath,
            "--updates", $UpdateExposurePath
        ) `
        -Destination $AdvisoryPath

    $HypothesesReport = Invoke-AxiosJson `
        -FilePath $ThreatHypotheses `
        -Arguments @(
            "--baseline", $BaselinePath,
            "--score", $ScorePath,
            "--advisory", $AdvisoryPath,
            "--hardware", $HardwareTrustPath,
            "--kernel", $KernelReviewPath
        ) `
        -Destination $HypothesesPath

    $DefenderTamperPath = Join-Path $Output "defender-tamper-review.json"

    $DefenderTamperReport = Invoke-AxiosJson `
        -FilePath $DefenderTamperReview `
        -Arguments @(
            "--defender", $DefenderEvidencePath,
            "--event-cap", "500"
        ) `
        -Destination $DefenderTamperPath

    $BehaviorPath = Join-Path $Output "behavior-hunt.json"

    $BehaviorReport = Invoke-AxiosJson `
        -FilePath $BehaviorHunt `
        -Arguments @(
            "--audit", $AuditPath,
            "--persistence", $CombinedPersistencePath,
            "--live", $LiveActivityPath,
            "--processes", $ProcessIntegrityPath,
            "--network", $NetworkServiceReviewPath,
            "--events", $EventCorrelationPath
        ) `
        -Destination $BehaviorPath

    $PersistenceExecutionPath = Join-Path $Output "persistence-execution-review.json"

    $PersistenceExecutionReport = Invoke-AxiosJson `
        -FilePath $PersistenceExecution `
        -Arguments @(
            "--persistence", $CombinedPersistencePath,
            "--processes", $ProcessIntegrityPath,
            "--live", $LiveActivityPath,
            "--network", $NetworkServiceReviewPath,
            "--drivers", $DriverTrustPath,
            "--code-integrity", $CodeIntegrityInvestigationPath
        ) `
        -Destination $PersistenceExecutionPath

    Write-Host "[42/42] AXIOS Reasoning Web and response plan"
    $ReasoningWebPath = Join-Path $Output "reasoning-web.json"
    $ReasoningWebReport = Invoke-AxiosJson `
        -FilePath $ReasoningWeb `
        -Arguments @(
            "--summary", $SummaryPath,
            "--score", $ScorePath,
            "--behavior", $BehaviorPath,
            "--persistence", $PersistenceExecutionPath,
            "--memory-execution", $MemoryExecutionReviewPath,
            "--collection-integrity", $CollectionIntegrityReviewPath,
            "--observation", $ObservationIntegrityReviewPath,
            "--network", $NetworkIdentityReviewPath,
            "--network-deep", $NetworkDeepReviewPath,
            "--kernel", $KernelRuntimeIntegrityPath,
            "--state", $StatePath,
            "--security-controls", $SecurityControlsReviewPath,
            "--defender-tamper", $DefenderTamperPath,
            "--remote-access", $RemoteAccessReviewPath,
            "--telemetry-integrity", $TelemetryIntegrityReviewPath,
            "--execution-policy", $ExecutionPolicyReviewPath,
            "--identity-access", $IdentityAccessReviewPath,
            "--updates", $UpdateExposurePath,
            "--admin-exposure", $AdminExposureAuditPath,
            "--context", $ContextPosturePath
        ) `
        -Destination $ReasoningWebPath

    $ResponsePlanPath = Join-Path $Output "response-plan.json"
    $ResponsePlanReport = Invoke-AxiosJson `
        -FilePath $ResponsePlan `
        -Arguments @(
            "--summary", $SummaryPath,
            "--state", $StatePath,
            "--audit", $AuditPath,
            "--correlation", $CorrelationPath,
            "--reasoning", $ReasoningWebPath
        ) `
        -Destination $ResponsePlanPath

    $Summary | Add-Member `
        -NotePropertyName response_plan `
        -NotePropertyValue $ResponsePlanReport `
        -Force

    $ForensicReport = Invoke-AxiosJson `
        -FilePath $ForensicExport `
        -Arguments @(
            "--case-id", $RunId,
            "--output", $ManifestPath,
            "--evidence", "baseline=$BaselinePath",
            "--evidence", "correlation_score=$ScorePath",
            "--evidence", "hardware_advisory=$AdvisoryPath",
            "--evidence", "threat_hypotheses=$HypothesesPath",
            "--evidence", "reasoning_web=$ReasoningWebPath",
            "--evidence", "behavior_hunt=$BehaviorPath",
            "--evidence", "persistence_execution=$PersistenceExecutionPath",
            "--evidence", "persistence_coverage=$PersistenceCoveragePath",
            "--evidence", "defender_evidence=$DefenderEvidencePath",
            "--evidence", "defender_tamper_review=$DefenderTamperPath",
            "--evidence", "audit=$AuditPath",
            "--evidence", "processes=$ProcessIntegrityPath",
            "--evidence", "network=$NetworkServiceReviewPath",
            "--evidence", "kernel=$KernelReviewPath",
            "--evidence", "drivers=$DriverTrustPath",
            "--evidence", "updates=$UpdateExposurePath",
            "--evidence", "security_controls=$SecurityControlsReviewPath",
            "--evidence", "remote_access=$RemoteAccessReviewPath",
            "--evidence", "execution_policy=$ExecutionPolicyReviewPath",
            "--evidence", "identity_access=$IdentityAccessReviewPath",
            "--evidence", "platform_hardening=$PlatformHardeningReviewPath",
            "--evidence", "administrator_exposure_audit=$AdminExposureAuditPath",
            "--evidence", "virtualization_boundary=$VirtualizationBoundaryReviewPath",
            "--evidence", "collection_integrity=$CollectionIntegrityReviewPath",
            "--evidence", "observation_integrity=$ObservationIntegrityReviewPath",
            "--evidence", "memory_execution=$MemoryExecutionReviewPath",
            "--evidence", "network_identity=$NetworkIdentityReviewPath",
            "--evidence", "network_deep=$NetworkDeepReviewPath",
            "--evidence", "kernel_runtime_integrity=$KernelRuntimeIntegrityPath",
            "--evidence", "boot_chain_review=$BootChainReviewPath",
            "--evidence", "code_integrity_investigation=$CodeIntegrityInvestigationPath",
            "--evidence", "investigation_state=$StatePath",
            "--evidence", "response_plan=$ResponsePlanPath"
        ) `
        -Destination (Join-Path $Output "forensic-export.json")

    $Summary | Add-Member -NotePropertyName sensitive_baseline -NotePropertyValue $BaselineReport -Force
    $Summary | Add-Member -NotePropertyName correlation_score -NotePropertyValue $ScoreReport -Force
    $Summary | Add-Member -NotePropertyName hardware_advisory -NotePropertyValue $AdvisoryReport -Force
    $Summary | Add-Member -NotePropertyName threat_hypotheses -NotePropertyValue $HypothesesReport -Force
    $Summary | Add-Member -NotePropertyName reasoning_web -NotePropertyValue $ReasoningWebReport -Force
    $Summary | Add-Member -NotePropertyName defender_evidence -NotePropertyValue $DefenderEvidenceReport -Force
    $Summary | Add-Member -NotePropertyName defender_tamper_review -NotePropertyValue $DefenderTamperReport -Force
    $Summary | Add-Member -NotePropertyName behavior_hunt -NotePropertyValue $BehaviorReport -Force
    $Summary | Add-Member -NotePropertyName persistence_execution -NotePropertyValue $PersistenceExecutionReport -Force
    $Summary | Add-Member -NotePropertyName persistence_coverage -NotePropertyValue $PersistenceCoverage -Force
    $Summary | Add-Member -NotePropertyName forensic_export -NotePropertyValue $ForensicReport -Force
    $Summary | Add-Member -NotePropertyName security_controls_review -NotePropertyValue $SecurityControlsReviewReport -Force
    $Summary | Add-Member -NotePropertyName remote_access_review -NotePropertyValue $RemoteAccessReviewReport -Force
    $Summary | Add-Member -NotePropertyName execution_policy_review -NotePropertyValue $ExecutionPolicyReviewReport -Force
    $Summary | Add-Member -NotePropertyName identity_access_review -NotePropertyValue $IdentityAccessReviewReport -Force
    $Summary | Add-Member -NotePropertyName platform_hardening_review -NotePropertyValue $PlatformHardeningReviewReport -Force
    $Summary | Add-Member -NotePropertyName administrator_exposure_audit -NotePropertyValue $AdminExposureAuditReport -Force
    $Summary | Add-Member -NotePropertyName virtualization_boundary_review -NotePropertyValue $VirtualizationBoundaryReviewReport -Force
    $Summary | Add-Member -NotePropertyName observation_integrity_review -NotePropertyValue $ObservationIntegrityReviewReport -Force

    $Summary.success = $true
    $Summary.completion_state = "completed"

    Write-AxiosJson `
        -Path $SummaryPath `
        -Value $Summary `
        -Depth 20

    Write-AxiosText `
        -Path (Join-Path $OutputRoot "latest-run.txt") `
        -Text $Output

    Write-Host ""
    $PerformanceSummaryPath = Join-Path $Output "performance-summary.json"
    $StageMetrics = @(
        $script:AxiosPerformanceStages |
            Sort-Object duration_ms -Descending
    )
    $TotalStageRuntimeMs = if ($StageMetrics.Count -eq 0) {
        [int64]0
    } else {
        [int64](($StageMetrics | Measure-Object -Property duration_ms -Sum).Sum)
    }

    $PerformanceReport = [PSCustomObject]@{
        schema_version = 1
        collector = "axios_performance_summary"
        success = $true
        read_only = $true
        database_used = $false
        run_id = $RunId
        summary = [PSCustomObject]@{
            stages_measured = $StageMetrics.Count
            total_stage_runtime_ms = $TotalStageRuntimeMs
            slowest_stage = if ($StageMetrics.Count -gt 0) { $StageMetrics[0].report } else { $null }
            slowest_stage_duration_ms = if ($StageMetrics.Count -gt 0) { $StageMetrics[0].duration_ms } else { 0 }
        }
        stages = $StageMetrics
        policy = [PSCustomObject]@{
            measurement_scope = "AXIOS child-process execution and report validation time"
            optimization_rule = "profile before parallelizing or reducing repeated collection"
        }
    }

    Write-AxiosText `
        -Path $PerformanceSummaryPath `
        -Text ($PerformanceReport | ConvertTo-Json -Depth 12)

    $PortableResultsSchemaVersion = 1
    $PortableResultsMaximumBytes = 2500000
    $PortableFindingsBudgetBytes = 1700000
    $PortableMaximumErrors = 512
    $PortableMaximumErrorLength = 2048

    $PortableResultsDirectory = $OutputDirectory
    $PortableResultsPath = Join-Path `
        $PortableResultsDirectory `
        ("AXIOS-Investigation-Results-{0}.json" -f $RunId)

    $PortableReports = [System.Collections.Generic.List[object]]::new()
    $PortableFindings = [System.Collections.Generic.List[object]]::new()
    $PortableErrors = [System.Collections.Generic.List[object]]::new()
    $PortableFindingKeys = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $PortableErrorKeys = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $PortableReportFiles = @(
        Get-ChildItem -LiteralPath $Output -File -Filter "*.json" |
            Where-Object {
                $_.Name -ne "summary.json" -and
                $_.Name -ne "forensic-export.json"
            } |
            Sort-Object Name
    )

    foreach ($PortableReportFile in $PortableReportFiles) {
        try {
            $PortableDocument = Get-Content -Encoding UTF8 -LiteralPath $PortableReportFile.FullName `
                -Raw |
                ConvertFrom-Json
        }
        catch {
            $PortableParseError = [string]$_.Exception.Message
            $PortableErrors.Add([PSCustomObject]@{
                source_report = $PortableReportFile.Name
                error = $PortableParseError
                truncated = $false
            })
            continue
        }

        $PortableCollector = if (
            -not [string]::IsNullOrWhiteSpace(
                [string](Get-AxiosOptionalProperty -Value $PortableDocument -Name "collector")
            )
        ) {
            [string](Get-AxiosOptionalProperty -Value $PortableDocument -Name "collector")
        }
        else {
            [IO.Path]::GetFileNameWithoutExtension(
                $PortableReportFile.Name
            )
        }

        $PortableCollectionStatus = if (
            -not [string]::IsNullOrWhiteSpace(
                [string](Get-AxiosOptionalProperty -Value $PortableDocument -Name "collection_status")
            )
        ) {
            [string](Get-AxiosOptionalProperty -Value $PortableDocument -Name "collection_status")
        }
        else {
            "not_declared"
        }

        $PortableReports.Add([PSCustomObject]@{
            name = $PortableReportFile.Name
            collector = $PortableCollector
            success = ($PortableDocument.success -eq $true)
            collection_status = $PortableCollectionStatus
            summary = (Get-AxiosOptionalProperty -Value $PortableDocument -Name "summary")
            truncation = (Get-AxiosOptionalProperty -Value $PortableDocument -Name "truncation")
            declared_limits = (Get-AxiosOptionalProperty -Value $PortableDocument -Name "declared_limits")
            evidence_path = $PortableReportFile.FullName
            size_bytes = $PortableReportFile.Length
        })

        foreach (
            $PortableCollectionError in
            @((Get-AxiosOptionalProperty -Value $PortableDocument -Name "collection_errors" -DefaultValue @()))
        ) {
            if ($null -eq $PortableCollectionError) {
                continue
            }

            $PortableErrorText = [string]$PortableCollectionError
            if ([string]::IsNullOrWhiteSpace($PortableErrorText)) {
                continue
            }

            $PortableErrorKey = (
                "{0}|{1}" -f
                $PortableReportFile.Name,
                $PortableErrorText
            )

            if (-not $PortableErrorKeys.Add($PortableErrorKey)) {
                continue
            }

            $PortableErrorTruncated = (
                $PortableErrorText.Length -gt
                $PortableMaximumErrorLength
            )

            if ($PortableErrorTruncated) {
                $PortableErrorText = $PortableErrorText.Substring(
                    0,
                    $PortableMaximumErrorLength
                )
            }

            $PortableErrors.Add([PSCustomObject]@{
                source_report = $PortableReportFile.Name
                collector = $PortableCollector
                error = $PortableErrorText
                truncated = $PortableErrorTruncated
                full_evidence_path = $PortableReportFile.FullName
            })
        }

        foreach (
            $PortableFinding in
            @((Get-AxiosOptionalProperty -Value $PortableDocument -Name "findings" -DefaultValue @()))
        ) {
            if ($null -eq $PortableFinding) {
                continue
            }

            $PortableFindingId = if (
                -not [string]::IsNullOrWhiteSpace(
                    [string](Get-AxiosOptionalProperty -Value $PortableFinding -Name "id")
                )
            ) {
                [string](Get-AxiosOptionalProperty -Value $PortableFinding -Name "id")
            }
            elseif (
                -not [string]::IsNullOrWhiteSpace(
                    [string](Get-AxiosOptionalProperty -Value $PortableFinding -Name "classification")
                )
            ) {
                [string](Get-AxiosOptionalProperty -Value $PortableFinding -Name "classification")
            }
            else {
                [string](Get-AxiosOptionalProperty -Value $PortableFinding -Name "title")
            }

            $PortableLocator = @(
                (Get-AxiosOptionalPath -Value $PortableFinding -Names @("evidence", "name"))
                (Get-AxiosOptionalPath -Value $PortableFinding -Names @("evidence", "task_name"))
                (Get-AxiosOptionalPath -Value $PortableFinding -Names @("evidence", "driver_name"))
                (Get-AxiosOptionalPath -Value $PortableFinding -Names @("evidence", "path"))
                (Get-AxiosOptionalPath -Value $PortableFinding -Names @("evidence", "executable_path"))
                (Get-AxiosOptionalPath -Value $PortableFinding -Names @("evidence", "image_path"))
                (Get-AxiosOptionalProperty -Value $PortableFinding -Name "path")
                (Get-AxiosOptionalProperty -Value $PortableFinding -Name "process_path")
                (Get-AxiosOptionalProperty -Value $PortableFinding -Name "pid")
            ) |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$_)
                } |
                Select-Object -First 1

            $PortableFindingKey = (
                "{0}|{1}|{2}" -f
                $PortableCollector,
                $PortableFindingId,
                [string]$PortableLocator
            )

            $PortableIdentityText = (
                "{0} {1} {2}" -f
                $PortableFindingId,
                [string](Get-AxiosOptionalProperty -Value $PortableFinding -Name "title"),
                [string](Get-AxiosOptionalProperty -Value $PortableFinding -Name "classification")
            ).ToLowerInvariant()

            if (
                $PortableIdentityText.Contains("secure_boot") -or
                $PortableIdentityText.Contains("secure boot")
            ) {
                $PortableFindingKey = "consolidated|secure_boot_disabled"
            }

            if (-not $PortableFindingKeys.Add($PortableFindingKey)) {
                continue
            }

            $PortableTitle = [string](
                Get-AxiosOptionalProperty `
                    -Value $PortableFinding `
                    -Name "title"
            )

            if ([string]::IsNullOrWhiteSpace($PortableTitle)) {
                $PortableTitle = [string](
                    Get-AxiosOptionalProperty `
                        -Value $PortableFinding `
                        -Name "claim"
                )
            }

            if ([string]::IsNullOrWhiteSpace($PortableTitle)) {
                $PortableTitle = (
                    [string]$PortableFindingId
                ).Replace("_", " ")
            }

            $PortablePriority = Get-AxiosOptionalProperty `
                -Value $PortableFinding `
                -Name "priority" `
                -DefaultValue (
                    Get-AxiosOptionalProperty `
                        -Value $PortableFinding `
                        -Name "severity"
                )

            $PortableFindings.Add([PSCustomObject]@{
                source_report = $PortableReportFile.Name
                collector = $PortableCollector
                id = $PortableFindingId
                priority = $PortablePriority
                confidence = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "confidence")
                classification = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "classification")
                title = $PortableTitle
                reason = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "reason")
                explanation = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "explanation")
                evidence = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "evidence")
                next_check = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "next_check")
                full_evidence_path = $PortableReportFile.FullName
            })
        }
    }

    $PortableSortedFindings = @(
        $PortableFindings |
            Sort-Object `
                @{
                    Expression = {
                        if ($_.priority -eq "high") {
                            0
                        }
                        elseif ($_.priority -eq "medium") {
                            1
                        }
                        else {
                            2
                        }
                    }
                },
                collector,
                id
    )

    $PortableSelectedFindings = [System.Collections.Generic.List[object]]::new()

    $PortableFindingBytesUsed = 0
    $PortableFindingsOmitted = 0

    foreach ($PortableFinding in $PortableSortedFindings) {
        $PortableFindingJson = $PortableFinding |
            ConvertTo-Json -Depth 14 -Compress

        $PortableFindingBytes = [Text.Encoding]::UTF8.GetByteCount($PortableFindingJson)

        if (
            $PortableFindingBytesUsed + $PortableFindingBytes -le
            $PortableFindingsBudgetBytes
        ) {
            $PortableSelectedFindings.Add($PortableFinding)
            $PortableFindingBytesUsed += $PortableFindingBytes
            continue
        }

        $PortableEvidenceReference = [PSCustomObject]@{
            source_report = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "source_report")
            collector = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "collector")
            id = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "id")
            priority = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "priority")
            confidence = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "confidence")
            classification = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "classification")
            title = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "title")
            reason = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "reason")
            explanation = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "explanation")
            evidence_omitted_from_portable_report = $true
            full_evidence_path = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "full_evidence_path")
            next_check = (Get-AxiosOptionalProperty -Value $PortableFinding -Name "next_check")
        }

        $PortableReferenceJson = $PortableEvidenceReference |
            ConvertTo-Json -Depth 8 -Compress

        $PortableReferenceBytes = [Text.Encoding]::UTF8.GetByteCount($PortableReferenceJson)

        if (
            $PortableFindingBytesUsed + $PortableReferenceBytes -le
            $PortableFindingsBudgetBytes
        ) {
            $PortableSelectedFindings.Add(
                $PortableEvidenceReference
            )
            $PortableFindingBytesUsed += $PortableReferenceBytes
        }
        else {
            $PortableFindingsOmitted++
        }
    }

    $PortableSelectedErrors = [System.Collections.Generic.List[object]]::new()

    foreach (
        $PortableError in
        @($PortableErrors | Select-Object -First $PortableMaximumErrors)
    ) {
        $PortableSelectedErrors.Add($PortableError)
    }

    $PortableErrorsOmitted = [Math]::Max(
        0,
        $PortableErrors.Count - $PortableSelectedErrors.Count
    )

    $PortablePartialReports = @(
        $PortableReports |
            Where-Object {
                (Get-AxiosOptionalProperty -Value $_ -Name "collection_status") -eq "partial"
            } |
            Select-Object -ExpandProperty name
    )

    $PortableFailedReports = @(
        $PortableReports |
            Where-Object { $_.success -ne $true } |
            Select-Object -ExpandProperty name
    )

    $PortableHighFindings = @(
        $PortableSortedFindings |
            Where-Object { $_.priority -eq "high" }
    ).Count

    $PortableMediumFindings = @(
        $PortableSortedFindings |
            Where-Object { $_.priority -eq "medium" }
    ).Count

    $PortableContextFindings = (
        $PortableSortedFindings.Count -
        $PortableHighFindings -
        $PortableMediumFindings
    )

    $PortableArtifactIndex = @(
        $PortableForensicArtifacts = @(
            Get-AxiosOptionalProperty `
                -Value $ForensicReport `
                -Name "artifacts" `
                -DefaultValue @()
        )

        foreach ($PortableArtifact in $PortableForensicArtifacts) {
            if ($null -eq $PortableArtifact) {
                continue
            }

            $PortableArtifactName = [string](
                Get-AxiosOptionalProperty `
                    -Value $PortableArtifact `
                    -Name "name"
            )

            $PortableArtifactRole = [string](
                Get-AxiosOptionalProperty `
                    -Value $PortableArtifact `
                    -Name "role"
            )

            $PortableArtifactPath = [string](
                Get-AxiosOptionalProperty `
                    -Value $PortableArtifact `
                    -Name "path"
            )

            if ([string]::IsNullOrWhiteSpace($PortableArtifactName)) {
                if (-not [string]::IsNullOrWhiteSpace($PortableArtifactRole)) {
                    $PortableArtifactName = $PortableArtifactRole
                }
                elseif (-not [string]::IsNullOrWhiteSpace($PortableArtifactPath)) {
                    $PortableArtifactName = [IO.Path]::GetFileName(
                        $PortableArtifactPath
                    )
                }
                else {
                    $PortableArtifactName = "unnamed_artifact"
                }
            }

            [PSCustomObject]@{
                name = $PortableArtifactName
                role = $PortableArtifactRole
                path = $PortableArtifactPath
                size_bytes = (
                    Get-AxiosOptionalProperty `
                        -Value $PortableArtifact `
                        -Name "size_bytes"
                )
                sha256 = (
                    Get-AxiosOptionalProperty `
                        -Value $PortableArtifact `
                        -Name "sha256"
                )
                success = (
                    (
                        Get-AxiosOptionalProperty `
                            -Value $PortableArtifact `
                            -Name "success" `
                            -DefaultValue $false
                    ) -eq $true
                )
            }
        }
    )

    $PortableResult = [PSCustomObject]@{
        schema_version = $PortableResultsSchemaVersion
        collector = "axios_portable_investigation_results"
        success = (
            $Summary.success -eq $true -and
            $PortableFailedReports.Count -eq 0
        )
        completion_state = $Summary.completion_state
        collection_status = if (
            $PortablePartialReports.Count -gt 0
        ) {
            "partial"
        }
        else {
            "complete"
        }
        generated_utc = [DateTime]::UtcNow.ToString("o")
        run_id = $RunId
        mode = [PSCustomObject]@{
            audit_mode = $AuditMode
            maximum_files = $MaxFiles
            administrator = $true
            read_only_investigation = $true
        }
        claim_policy = [PSCustomObject]@{
            malware_confirmed = $false
            intrusion_confirmed = $false
            privilege_escalation_confirmed = $false
            interpretation = (
                "Findings are evidence-backed review items, not proof " +
                "of exploitation, malware, or intrusion."
            )
        }
        summary = [PSCustomObject]@{
            reports_observed = $PortableReports.Count
            failed_reports = $PortableFailedReports.Count
            partial_reports = $PortablePartialReports.Count
            findings_total = $PortableSortedFindings.Count
            findings_included = $PortableSelectedFindings.Count
            findings_omitted_due_to_size = $PortableFindingsOmitted
            high_priority_findings = $PortableHighFindings
            medium_priority_findings = $PortableMediumFindings
            context_findings = $PortableContextFindings
            collection_errors_total = $PortableErrors.Count
            collection_errors_included = $PortableSelectedErrors.Count
            collection_errors_omitted = $PortableErrorsOmitted
            maximum_output_bytes = $PortableResultsMaximumBytes
        }
        system = [PSCustomObject]@{
            hardware = (Get-AxiosOptionalProperty -Value $Summary -Name "hardware")
            health = (Get-AxiosOptionalProperty -Value $Summary -Name "health_posture")
            context = $ContextPostureReport
            kernel = (Get-AxiosOptionalProperty -Value $Summary -Name "kernel_runtime_integrity")
            boot = (Get-AxiosOptionalProperty -Value $Summary -Name "boot_chain_review")
            firmware = (Get-AxiosOptionalProperty -Value $Summary -Name "firmware_identity_review")
        }
        network = [PSCustomObject]@{
            posture = (Get-AxiosOptionalProperty -Value $Summary -Name "network_posture")
            exposure = (Get-AxiosOptionalProperty -Value $Summary -Name "network_exposure")
            identity = (Get-AxiosOptionalProperty -Value $Summary -Name "network_identity_review")
            services = (Get-AxiosOptionalProperty -Value $Summary -Name "network_service_review")
        }
        security = [PSCustomObject]@{
            defender = (Get-AxiosOptionalProperty -Value $Summary -Name "defender_evidence")
            security_controls = (Get-AxiosOptionalProperty -Value $Summary -Name "security_controls_review")
            remote_access = (Get-AxiosOptionalProperty -Value $Summary -Name "remote_access_review")
            platform_hardening = (Get-AxiosOptionalProperty -Value $Summary -Name "platform_hardening_review")
            administrator_exposure = (
                (Get-AxiosOptionalPath `
                    -Value $Summary `
                    -Names @("administrator_exposure_audit", "summary"))
            )
        }
        reasoning = [PSCustomObject]@{
            summary = (Get-AxiosOptionalProperty -Value $ReasoningWebReport -Name "summary")
            intelligence = (Get-AxiosOptionalProperty -Value $ReasoningWebReport -Name "intelligence")
            leading_hypothesis = (Get-AxiosOptionalProperty -Value $ReasoningWebReport -Name "leading_hypothesis")
            alternative_hypotheses = @(
                Get-AxiosOptionalProperty `
                    -Value $ReasoningWebReport `
                    -Name "alternative_hypotheses" `
                    -DefaultValue @() |
                    Select-Object -First 3
            )
            proof_traces = @(
                Get-AxiosOptionalProperty `
                    -Value $ReasoningWebReport `
                    -Name "proof_traces" `
                    -DefaultValue @() |
                    Select-Object -First 8
            )
            next_best_checks = @(
                Get-AxiosOptionalProperty `
                    -Value $ReasoningWebReport `
                    -Name "next_best_checks" `
                    -DefaultValue @() |
                    Select-Object -First 5
            )
            conclusions = (Get-AxiosOptionalProperty -Value $ReasoningWebReport -Name "conclusions" -DefaultValue @())
            claim_policy = (Get-AxiosOptionalProperty -Value $ReasoningWebReport -Name "claim_policy")
        }
        response_plan = [PSCustomObject]@{
            summary = (Get-AxiosOptionalProperty -Value $ResponsePlanReport -Name "summary")
            plan = (Get-AxiosOptionalProperty -Value $ResponsePlanReport -Name "plan")
            items = (Get-AxiosOptionalProperty -Value $ResponsePlanReport -Name "items" -DefaultValue @())
        }
        findings = @($PortableSelectedFindings)
        collection_gaps = [PSCustomObject]@{
            partial_reports = $PortablePartialReports
            errors = @($PortableSelectedErrors)
        }
        reports = @($PortableReports)
        performance = $PerformanceReport
        evidence_manifest = $PortableArtifactIndex
        full_evidence = [PSCustomObject]@{
            output_folder = $Output
            summary_path = $SummaryPath
            forensic_export_path = $ManifestPath
            portable_report_is_not_a_replacement_for_raw_evidence = $true
        }
        limits = [PSCustomObject]@{
            maximum_bytes = $PortableResultsMaximumBytes
            findings_budget_bytes = $PortableFindingsBudgetBytes
            maximum_errors = $PortableMaximumErrors
            truncation_reported = $true
        }
    }

    $PortableResultJson = $PortableResult |
        ConvertTo-Json -Depth 18 -Compress

    $PortableResultBytes = [Text.Encoding]::UTF8.GetByteCount($PortableResultJson)

    while (
        $PortableResultBytes -gt $PortableResultsMaximumBytes -and
        $PortableSelectedFindings.Count -gt 0
    ) {
        $PortableSelectedFindings.RemoveAt(
            $PortableSelectedFindings.Count - 1
        )
        $PortableFindingsOmitted++

        $PortableResult.findings = @($PortableSelectedFindings)
        (Get-AxiosOptionalProperty -Value $PortableResult -Name "summary").findings_included = (
            $PortableSelectedFindings.Count
        )
        (Get-AxiosOptionalProperty -Value $PortableResult -Name "summary").findings_omitted_due_to_size = (
            $PortableFindingsOmitted
        )

        $PortableResultJson = $PortableResult |
            ConvertTo-Json -Depth 18 -Compress

        $PortableResultBytes = [Text.Encoding]::UTF8.GetByteCount($PortableResultJson)
    }

    while (
        $PortableResultBytes -gt $PortableResultsMaximumBytes -and
        $PortableSelectedErrors.Count -gt 0
    ) {
        $PortableSelectedErrors.RemoveAt(
            $PortableSelectedErrors.Count - 1
        )
        $PortableErrorsOmitted++

        $PortableResult.collection_gaps.errors = @(
            $PortableSelectedErrors
        )
        (Get-AxiosOptionalProperty -Value $PortableResult -Name "summary").collection_errors_included = (
            $PortableSelectedErrors.Count
        )
        (Get-AxiosOptionalProperty -Value $PortableResult -Name "summary").collection_errors_omitted = (
            $PortableErrorsOmitted
        )

        $PortableResultJson = $PortableResult |
            ConvertTo-Json -Depth 18 -Compress

        $PortableResultBytes = [Text.Encoding]::UTF8.GetByteCount($PortableResultJson)
    }

    if ($PortableResultBytes -gt $PortableResultsMaximumBytes) {
        throw (
            "AXIOS portable result exceeds the strict size limit: " +
            "${PortableResultBytes} bytes"
        )
    }

    [IO.File]::WriteAllText(
        $PortableResultsPath,
        $PortableResultJson,
        [Text.UTF8Encoding]::new($false)
    )

    $PortableResultsActualBytes = (
        Get-Item -LiteralPath $PortableResultsPath
    ).Length

    if (
        $PortableResultsActualBytes -gt
        $PortableResultsMaximumBytes
    ) {
        throw (
            "AXIOS portable result file exceeded the strict limit: " +
            "${PortableResultsActualBytes} bytes"
        )
    }

    Write-AxiosText `
        -Path (Join-Path $Output "portable-results-path.txt") `
        -Text $PortableResultsPath

    $CompleteDetailedPath = Join-Path `
        $PortableResultsDirectory `
        ("AXIOS-Complete-Details-{0}.txt" -f $RunId)

    [IO.File]::WriteAllText(
        $CompleteDetailedPath,
        ($PortableResult | ConvertTo-Json -Depth 30),
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host ""
    $CompleteHeading = "COMPREHENSIVE SECURITY INVESTIGATION"
    Write-Host $CompleteHeading
    Write-Host ("=" * $CompleteHeading.Length)
    Write-Host ("Completion state       : {0}" -f $Summary.completion_state)
    Write-Host ("Reports observed       : {0}" -f $PortableReports.Count)
    Write-Host ("Reports failed         : {0}" -f $PortableFailedReports.Count)
    Write-Host ("Reports partial        : {0}" -f $PortablePartialReports.Count)
    Write-Host ("High-priority findings : {0}" -f $PortableHighFindings)
    Write-Host ("Medium findings        : {0}" -f $PortableMediumFindings)
    Write-Host ("Raw context records    : {0}" -f $PortableContextFindings)
    Write-Host ("Collection errors      : {0}" -f $PortableErrors.Count)

    $LeadingHypothesis = Get-AxiosOptionalProperty `
        -Value $ReasoningWebReport `
        -Name "leading_hypothesis"

    if ($null -ne $LeadingHypothesis) {
        $LeadingKind = Get-AxiosOptionalProperty `
            -Value $LeadingHypothesis `
            -Name "hypothesis" `
            -DefaultValue "unknown"
        $LeadingScore = Get-AxiosOptionalProperty `
            -Value $LeadingHypothesis `
            -Name "score" `
            -DefaultValue 0
        $IndependentGroups = Get-AxiosOptionalProperty `
            -Value $LeadingHypothesis `
            -Name "independent_support_groups" `
            -DefaultValue 0
        $LeadingContradictions = @(
            Get-AxiosOptionalProperty `
                -Value $LeadingHypothesis `
                -Name "contradictions" `
                -DefaultValue @()
        ).Count
        $LeadingUnknowns = @(
            Get-AxiosOptionalProperty `
                -Value $LeadingHypothesis `
                -Name "unknowns" `
                -DefaultValue @()
        ).Count

        Write-Host ("Leading hypothesis     : {0}" -f $LeadingKind)
        Write-Host ("Hypothesis score       : {0}/10000" -f $LeadingScore)
        Write-Host ("Independent sources    : {0}" -f $IndependentGroups)
        Write-Host ("Contradictions         : {0}" -f $LeadingContradictions)
        Write-Host ("Unresolved facts       : {0}" -f $LeadingUnknowns)
    }

    $NextCheckCount = @(
        Get-AxiosOptionalProperty `
            -Value $ReasoningWebReport `
            -Name "next_best_checks" `
            -DefaultValue @()
    ).Count
    Write-Host ("Next best checks       : {0}" -f $NextCheckCount)

    if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
        Write-Host ("Detailed TXT report    : {0}" -f $CompleteDetailedPath)
        Write-Host ("Portable JSON result   : {0}" -f $PortableResultsPath)
        Write-Host ("Raw evidence directory : {0}" -f $Output)
    }

    Write-Host ""

    if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
        [PSCustomObject]@{
            success = $true
            completion_state = $Summary.completion_state
            run_id = $RunId
            output = $Output
            summary_path = $SummaryPath
            forensic_export_path = $ManifestPath
            performance_summary_path = $PerformanceSummaryPath
            portable_results_path = $PortableResultsPath
            detailed_report_path = $CompleteDetailedPath
            portable_results_size_bytes = $PortableResultsActualBytes
            portable_results_maximum_bytes = $PortableResultsMaximumBytes
            reports_failed = 0
        } | ConvertTo-Json -Depth 4 -Compress
    }
}
catch {
    Write-AxiosText `
        -Path $Failure `
        -Text ($_ | Out-String)

    Write-Host ""
    Write-Host "AXIOS complete investigation failed."
    Write-Host "Failure report: $Failure"

    throw
}
