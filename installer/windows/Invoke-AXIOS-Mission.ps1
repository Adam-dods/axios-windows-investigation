[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet(
        "help",
        "fast-complete",
        "smart-complete",
        "fast-triage",
        "downloads-audit",
        "appdata-audit",
        "persistence",
        "live",
        "processes",
        "network",
        "hardware",
        "kernel",
        "memory",
        "drivers",
        "boot",
        "code-integrity",
        "browser",
        "security",
        "updates",
        "baseline",
        "score",
        "advisories",
        "defender",
        "persistence-execution",
        "applications",
        "correlate",
        "review",
        "show-last"
    )]
    [string]$Mission = "help",

    [ValidateRange(1, 25000)]
    [int]$MaxFiles = 1500,

    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Bin = Join-Path $Root "bin"
$Runner = Join-Path $PSScriptRoot "Run-AXIOS-Complete-Investigation.ps1"
$Core = Join-Path $Bin "axios-core.exe"
$Audit = Join-Path $Bin "axios-file-audit.exe"
$Applications = Join-Path $Bin "axios-application-investigation.exe"
$Correlate = Join-Path $Bin "axios-audit-correlate.exe"
$ProcessIntegrity = Join-Path $Bin "axios-process-integrity.exe"
$MemoryExecutionReview = Join-Path $Bin "axios-memory-execution-review.exe"
$NetworkExposure = Join-Path $Bin "axios-network-exposure.exe"
$NetworkService = Join-Path $Bin "axios-network-service-review.exe"
$DriverTrust = Join-Path $Bin "axios-driver-trust.exe"
$BootReview = Join-Path $Bin "axios-boot-chain-review.exe"
$CodeIntegrity = Join-Path $Bin "axios-code-integrity-investigation.exe"
$EvidenceReview = Join-Path $Bin "axios-evidence-review.exe"
$Baseline = Join-Path $Bin "axios-sensitive-baseline.exe"
$CorrelationScore = Join-Path $Bin "axios-correlation-score.exe"
$HardwareAdvisory = Join-Path $Bin "axios-hardware-advisory.exe"
$PersistenceExecution = Join-Path $Bin "axios-persistence-execution-review.exe"
$DefenderEvidence = Join-Path $Bin "axios-defender-evidence.exe"
$DefenderTamperReview = Join-Path $Bin "axios-defender-tamper-review.exe"

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $Root ("manual-missions\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

function Invoke-AxiosJson {
    param(
        [string]$Executable,
        [string]$Name,
        [string[]]$Arguments
    )

    $Path = Join-Path $OutputDirectory "$Name.json"

    $JsonLines = @(& $Executable @Arguments)
    $ExitCode = $LASTEXITCODE

    if ($ExitCode -ne 0) {
        throw "AXIOS mission command failed: $Name (exit code $ExitCode)"
    }

    $JsonText = $JsonLines -join [Environment]::NewLine

    if ([string]::IsNullOrWhiteSpace($JsonText)) {
        throw "AXIOS mission returned an empty report: $Name"
    }

    try {
        $Report = $JsonText | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "AXIOS mission returned invalid JSON: $Name ($($_.Exception.Message))"
    }

    $SuccessProperty = $Report.PSObject.Properties["success"]

    if ($null -eq $SuccessProperty) {
        throw "AXIOS mission report is missing success: $Name"
    }

    if ($SuccessProperty.Value -isnot [bool]) {
        throw "AXIOS mission report has a non-boolean success value: $Name"
    }

    if ($SuccessProperty.Value -ne $true) {
        $Detail = @($Report.error, $Report.reason) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }

        throw "AXIOS mission report indicates failure: $Name ($($Detail -join '; '))"
    }

    $Utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText(
        $Path,
        $JsonText,
        $Utf8WithoutBom
    )

    return $Path
}

function Show-FastPass {
    param([string]$Path)

    $Report = Get-Content -Encoding UTF8 -LiteralPath $Path -Raw | ConvertFrom-Json
    $Pass = $Report.success -eq $true -and $Report.summary.errors -eq 0

    "AXIOS_MISSION=$Mission"
    "AXIOS_MISSION_EXECUTION_PASS=$Pass"
    "AXIOS_NEEDS_REVIEW=$($Report.summary.needs_review)"
    "OUTPUT=$Path"
    $Report.summary | Format-List
}

function Show-LastComplete {
    $LatestRunFile = Join-Path $Root "output\latest-run.txt"

    if (-not (Test-Path -LiteralPath $LatestRunFile -PathType Leaf)) {
        throw "No complete-investigation run exists in this package."
    }

    $LatestRun = [System.IO.File]::ReadAllText($LatestRunFile).Trim()
    $Summary = Get-Content -Encoding UTF8 -LiteralPath (Join-Path $LatestRun "summary.json") -Raw |
        ConvertFrom-Json

    $Audit = Get-Content -Encoding UTF8 -LiteralPath (Join-Path $LatestRun "universal-file-audit.json") -Raw |
        ConvertFrom-Json

    $Pass = (
        $Summary.success -eq $true -and
        $Summary.completion_state -eq "completed" -and
        $Audit.summary.errors -eq 0
    )

    "AXIOS_MISSION=$Mission"
    "AXIOS_MISSION_EXECUTION_PASS=$Pass"
    "AXIOS_NEEDS_REVIEW=$($Audit.summary.needs_review)"
    "OUTPUT=$LatestRun"

    $Summary |
        Select-Object success, completion_state, run_id, max_files, audit_mode |
        Format-List

    $Audit.summary | Format-List
}

switch ($Mission) {
    "help" {
        @'
AXIOS short missions:

  fast-complete      Full 23-stage bounded investigation
  smart-complete     Broader 23-stage investigation
  fast-triage        Fast file triage
  downloads-audit    Targeted Downloads audit
  appdata-audit      Targeted AppData audit
  persistence        Registry and extended persistence
  live               Live process and connection data
  processes          Process integrity and signatures
  network            Live + process + network + firewall review
  hardware           TPM, Secure Boot, BitLocker, VBS
  kernel             Kernel posture and Code Integrity source data
  drivers            Kernel posture + driver trust
  boot               Hardware + kernel + boot-chain review
  code-integrity     Kernel + drivers + Code Integrity event review
  browser            Browser extension inventory
  security           Windows security posture and review
  updates            Windows Update, reboot, hotfix, and Defender exposure data
  baseline           Trusted temporal baseline from the latest complete run
  score              Cross-layer correlation score from the latest complete run
  advisories          BIOS, firmware, driver, and Windows advisory evidence
  defender            Defender threats, actions, and sensitive configuration changes
  persistence-execution  Persistent startup items verified against process and runtime evidence
  applications       Fast audit + application grouping
  correlate          Fast audit + persistence + live correlation
  review             Exact evidence from the last complete investigation
  show-last          Final flags and summary of last complete mission

Examples:
  .\Invoke-AXIOS-Mission.ps1 fast-complete
  .\Invoke-AXIOS-Mission.ps1 network
  .\Invoke-AXIOS-Mission.ps1 show-last
'@
    }

    "fast-complete" {
        $null = & $Runner -MaxFiles $MaxFiles -AuditMode fast
        Show-LastComplete
    }

    "smart-complete" {
        $null = & $Runner -MaxFiles $MaxFiles -AuditMode smart
        Show-LastComplete
    }

    "fast-triage" {
        $Path = Invoke-AxiosJson $Audit "fast-triage" @(
            "--mode", "fast", "--max-files", "3000", "--recent-days", "365"
        )
        Show-FastPass $Path
    }

    "downloads-audit" {
        $Path = Invoke-AxiosJson $Audit "downloads-audit" @(
            "--mode", "targeted", "--root", (Join-Path $env:USERPROFILE "Downloads"),
            "--max-files", "$MaxFiles", "--recent-days", "365"
        )
        Show-FastPass $Path
    }

    "appdata-audit" {
        $Path = Invoke-AxiosJson $Audit "appdata-audit" @(
            "--mode", "targeted", "--root", $env:APPDATA,
            "--root", $env:LOCALAPPDATA,
            "--max-files", "$MaxFiles", "--recent-days", "90"
        )
        Show-FastPass $Path
    }

    "persistence" {
        Invoke-AxiosJson $Core "registry-persistence" @("registry-persistence") | Out-Null
        Invoke-AxiosJson $Core "extended-persistence" @("extended-persistence") | Out-Null
        "AXIOS_MISSION=persistence"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "live" {
        Invoke-AxiosJson $Core "live-activity" @("live-activity") | Out-Null
        "AXIOS_MISSION=live"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "processes" {
        Invoke-AxiosJson $ProcessIntegrity "process-integrity" @() | Out-Null
        "AXIOS_MISSION=processes"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "network" {
        $Live = Invoke-AxiosJson $Core "live-activity" @("live-activity")
        $Processes = Invoke-AxiosJson $ProcessIntegrity "process-integrity" @()
        $Exposure = Invoke-AxiosJson $NetworkExposure "network-exposure" @(
            "--live-activity", $Live, "--process-integrity", $Processes
        )
        Invoke-AxiosJson $NetworkService "network-service-review" @(
            "--network-exposure", $Exposure
        ) | Out-Null
        "AXIOS_MISSION=network"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "hardware" {
        Invoke-AxiosJson $Core "hardware-trust" @("hardware-trust") | Out-Null
        "AXIOS_MISSION=hardware"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "kernel" {
        Invoke-AxiosJson $Core "kernel-posture" @("kernel-posture") | Out-Null
        "AXIOS_MISSION=kernel"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "memory" {
        $LatestRunFile = Join-Path $Root "output\latest-run.txt"

        if (-not (Test-Path -LiteralPath $LatestRunFile -PathType Leaf)) {
            throw "No complete-investigation run exists in this package."
        }

        $LatestRun = [System.IO.File]::ReadAllText($LatestRunFile).Trim()

        Invoke-AxiosJson $MemoryExecutionReview "memory-execution-review" @(
            "--processes", (Join-Path $LatestRun "process-integrity.json"),
            "--persistence", (Join-Path $LatestRun "persistence-combined.json"),
            "--network", (Join-Path $LatestRun "network-service-review.json"),
            "--max-processes", "256",
            "--max-regions", "4096"
        ) | Out-Null

        "AXIOS_MISSION=memory"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "drivers" {
        $Kernel = Invoke-AxiosJson $Core "kernel-posture" @("kernel-posture")
        Invoke-AxiosJson $DriverTrust "driver-trust" @("--kernel-posture", $Kernel) | Out-Null
        "AXIOS_MISSION=drivers"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "boot" {
        $Hardware = Invoke-AxiosJson $Core "hardware-trust" @("hardware-trust")
        $Kernel = Invoke-AxiosJson $Core "kernel-posture" @("kernel-posture")
        Invoke-AxiosJson $BootReview "boot-chain-review" @(
            "--hardware-trust", $Hardware, "--kernel-posture", $Kernel
        ) | Out-Null
        "AXIOS_MISSION=boot"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "code-integrity" {
        $Kernel = Invoke-AxiosJson $Core "kernel-posture" @("kernel-posture")
        $Drivers = Invoke-AxiosJson $DriverTrust "driver-trust" @("--kernel-posture", $Kernel)
        Invoke-AxiosJson $CodeIntegrity "code-integrity-investigation" @(
            "--kernel-posture", $Kernel, "--driver-trust", $Drivers
        ) | Out-Null
        "AXIOS_MISSION=code-integrity"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "browser" {
        Invoke-AxiosJson $Core "browser-extensions" @("browser-extensions") | Out-Null
        "AXIOS_MISSION=browser"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "security" {
        Invoke-AxiosJson $Core "security-posture" @("security-posture") | Out-Null
        Invoke-AxiosJson $Core "security-review" @("security-review") | Out-Null
        "AXIOS_MISSION=security"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "updates" {
        Invoke-AxiosJson $Core "update-exposure" @("updates") | Out-Null
        "AXIOS_MISSION=updates"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "baseline" {
        $LatestRunFile = Join-Path $Root "output\latest-run.txt"
        if (-not (Test-Path -LiteralPath $LatestRunFile -PathType Leaf)) {
            throw "No complete-investigation run exists in this package."
        }

        $LatestRun = [System.IO.File]::ReadAllText($LatestRunFile).Trim()

        Invoke-AxiosJson $Baseline "sensitive-baseline" @(
            "--hardware", (Join-Path $LatestRun "hardware-trust.json"),
            "--kernel", (Join-Path $LatestRun "kernel-posture.json"),
            "--drivers", (Join-Path $LatestRun "driver-trust.json"),
            "--persistence", (Join-Path $LatestRun "persistence-combined.json"),
            "--network", (Join-Path $LatestRun "network-service-review.json"),
            "--updates", (Join-Path $LatestRun "update-exposure.json")
        ) | Out-Null

        "AXIOS_MISSION=baseline"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "score" {
        $LatestRunFile = Join-Path $Root "output\latest-run.txt"
        if (-not (Test-Path -LiteralPath $LatestRunFile -PathType Leaf)) {
            throw "No complete-investigation run exists in this package."
        }

        $LatestRun = [System.IO.File]::ReadAllText($LatestRunFile).Trim()

        Invoke-AxiosJson $CorrelationScore "correlation-score" @(
            "--correlation", (Join-Path $LatestRun "audit-correlation.json"),
            "--processes", (Join-Path $LatestRun "process-integrity.json"),
            "--network", (Join-Path $LatestRun "network-service-review.json"),
            "--kernel", (Join-Path $LatestRun "kernel-review.json"),
            "--hardware", (Join-Path $LatestRun "hardware-trust.json")
        ) | Out-Null

        "AXIOS_MISSION=score"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "advisories" {
        $LatestRunFile = Join-Path $Root "output\latest-run.txt"
        if (-not (Test-Path -LiteralPath $LatestRunFile -PathType Leaf)) {
            throw "No complete-investigation run exists in this package."
        }

        $LatestRun = [System.IO.File]::ReadAllText($LatestRunFile).Trim()

        Invoke-AxiosJson $HardwareAdvisory "hardware-advisory" @(
            "--hardware", (Join-Path $LatestRun "hardware-trust.json"),
            "--drivers", (Join-Path $LatestRun "driver-trust.json"),
            "--updates", (Join-Path $LatestRun "update-exposure.json")
        ) | Out-Null

        "AXIOS_MISSION=advisories"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "defender" {
        $Evidence = Invoke-AxiosJson $DefenderEvidence "defender-evidence" @(
            "--days", "30",
            "--max-events", "500"
        )

        Invoke-AxiosJson $DefenderTamperReview "defender-tamper-review" @(
            "--defender", $Evidence,
            "--event-cap", "500"
        ) | Out-Null

        "AXIOS_MISSION=defender"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "persistence-execution" {
        $LatestRunFile = Join-Path $Root "output\latest-run.txt"

        if (-not (Test-Path -LiteralPath $LatestRunFile -PathType Leaf)) {
            throw "No complete-investigation run exists in this package."
        }

        $LatestRun = [System.IO.File]::ReadAllText($LatestRunFile).Trim()

        Invoke-AxiosJson $PersistenceExecution "persistence-execution-review" @(
            "--persistence", (Join-Path $LatestRun "persistence-combined.json"),
            "--processes", (Join-Path $LatestRun "process-integrity.json"),
            "--live", (Join-Path $LatestRun "live-activity.json"),
            "--network", (Join-Path $LatestRun "network-service-review.json"),
            "--drivers", (Join-Path $LatestRun "driver-trust.json"),
            "--code-integrity", (Join-Path $LatestRun "code-integrity-investigation.json")
        ) | Out-Null

        "AXIOS_MISSION=persistence-execution"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "applications" {
        $FileAudit = Invoke-AxiosJson $Audit "fast-triage" @(
            "--mode", "fast", "--max-files", "3000", "--recent-days", "365"
        )
        Invoke-AxiosJson $Applications "application-investigation" @("--audit", $FileAudit) | Out-Null
        "AXIOS_MISSION=applications"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "correlate" {
        $Persistence = Invoke-AxiosJson $Core "registry-persistence" @("registry-persistence")
        $Live = Invoke-AxiosJson $Core "live-activity" @("live-activity")
        $FileAudit = Invoke-AxiosJson $Audit "fast-triage" @(
            "--mode", "fast", "--max-files", "3000", "--recent-days", "365",
            "--seed-report", $Persistence,
            "--seed-report", $Live
        )
        Invoke-AxiosJson $Correlate "audit-correlation" @(
            "--audit", $FileAudit,
            "--persistence", $Persistence,
            "--live-activity", $Live
        ) | Out-Null
        "AXIOS_MISSION=correlate"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "review" {
        $LatestRunFile = Join-Path $Root "output\latest-run.txt"
        if (-not (Test-Path -LiteralPath $LatestRunFile -PathType Leaf)) {
            throw "No complete-investigation run exists in this package."
        }

        $LatestRun = [System.IO.File]::ReadAllText($LatestRunFile).Trim()
        Invoke-AxiosJson $EvidenceReview "evidence-review" @(
            "--audit", (Join-Path $LatestRun "universal-file-audit.json"),
            "--processes", (Join-Path $LatestRun "process-integrity.json"),
            "--network", (Join-Path $LatestRun "network-service-review.json"),
            "--response-plan", (Join-Path $LatestRun "response-plan.json"),
            "--correlation", (Join-Path $LatestRun "audit-correlation.json")
        ) | Out-Null

        "AXIOS_MISSION=review"
        "AXIOS_MISSION_EXECUTION_PASS=True"
        "OUTPUT=$OutputDirectory"
    }

    "show-last" {
        Show-LastComplete
    }
}
