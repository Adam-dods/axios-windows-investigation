[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "Quick",
        "System",
        "Persistence",
        "Software",
        "Context",
        "Results"
    )]
    [string]$Layer,

    [string]$OutputDirectory = (
        Join-Path $env:USERPROFILE "Downloads"
    ),

    [string[]]$ResultSearchDirectory = @($OutputDirectory)
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

if (Test-Path -LiteralPath $OutputDirectory -PathType Leaf) {
    throw "AXIOS OutputDirectory must be a directory, not a file: $OutputDirectory"
}


$AxiosUtf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $AxiosUtf8
[Console]::OutputEncoding = $AxiosUtf8
$OutputEncoding = $AxiosUtf8

function Get-AxiosProperty {
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowNull()]
        [object]$Default = $null
    )

    if ($null -eq $Value) {
        return $Default
    }

    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Contains($Name)) {
            return $Value[$Name]
        }

        return $Default
    }

    $Property = $Value.PSObject.Properties[$Name]

    if ($null -eq $Property) {
        return $Default
    }

    return $Property.Value
}

function Get-AxiosCount {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return 0
    }

    return @($Value).Count
}

function Write-AxiosJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    $Json = $Value | ConvertTo-Json -Depth 30

    [System.IO.File]::WriteAllText(
        $Path,
        $Json,
        $AxiosUtf8
    )
}

function Invoke-AxiosCoreReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $Raw = @(& $Core $Command)
    $ExitCode = $LASTEXITCODE

    if ($ExitCode -ne 0) {
        throw "AXIOS core command failed: $Command, exit code $ExitCode"
    }

    $Text = $Raw -join [Environment]::NewLine

    if ([string]::IsNullOrWhiteSpace($Text)) {
        throw "AXIOS core command returned empty output: $Command"
    }

    try {
        $Report = $Text | ConvertFrom-Json
    }
    catch {
        throw "AXIOS core command returned invalid JSON: $Command"
    }

    Write-AxiosJson -Path $Destination -Value $Report

    return $Report
}

function Get-AxiosResultCandidate {
    $Patterns = @(
        "AXIOS-Investigation-Results-*.json",
        "AXIOS-Layer-*.json",
        "AXIOS-Network-Deep-Review-*.json",
        "AXIOS-Administrator-Exposure-Audit-*.json",
        "AXIOS-Developer-Exposure-*.json"
    )

    foreach ($SearchDirectory in $ResultSearchDirectory) {
        if (-not (Test-Path -LiteralPath $SearchDirectory -PathType Container)) {
            continue
        }

        $Candidates = [System.Collections.Generic.List[object]]::new()

        foreach ($File in @(
            Get-ChildItem `
                -LiteralPath $SearchDirectory `
                -File `
                -ErrorAction SilentlyContinue
        )) {
            foreach ($Pattern in $Patterns) {
                if ($File.Name -like $Pattern) {
                    $Candidates.Add($File)
                    break
                }
            }
        }

        foreach ($Directory in @(
            Get-ChildItem `
                -LiteralPath $SearchDirectory `
                -Directory `
                -Filter "AXIOS-Standard-User-Audit-*" `
                -ErrorAction SilentlyContinue
        )) {
            $Manifest = Join-Path `
                $Directory.FullName `
                "standard-user-manifest.json"

            if (Test-Path -LiteralPath $Manifest -PathType Leaf) {
                $Candidates.Add((Get-Item -LiteralPath $Manifest))
            }
        }
        if ($Candidates.Count -gt 0) {
            return $Candidates |
                Sort-Object LastWriteTimeUtc -Descending |
                Select-Object -First 1
        }
    }

    return $null
}

if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    $null = New-Item `
        -ItemType Directory `
        -Path $OutputDirectory `
        -Force
}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptRoot
$Core = Join-Path $Root "bin\axios-core.exe"

if ($Layer -eq "Results") {
    $Candidate = Get-AxiosResultCandidate

    if ($null -eq $Candidate) {
        throw "AXIOS could not find a previous result."
    }

    try {
        $Report = Get-Content -Encoding UTF8 -LiteralPath $Candidate.FullName -Raw |
            ConvertFrom-Json
    }
    catch {
        throw "Latest AXIOS result is not valid JSON: $($Candidate.FullName)"
    }

    $Success = Get-AxiosProperty `
        -Value $Report `
        -Name "success" `
        -Default $false

    $Status = Get-AxiosProperty `
        -Value $Report `
        -Name "completion_state" `
        -Default (
            Get-AxiosProperty `
                -Value $Report `
                -Name "collection_status" `
                -Default "unknown"
        )

    $Findings = @(
        Get-AxiosProperty `
            -Value $Report `
            -Name "findings" `
            -Default @()
    )

    $RawErrors = @(
        Get-AxiosProperty `
            -Value $Report `
            -Name "collection_errors" `
            -Default (
                Get-AxiosProperty `
                    -Value $Report `
                    -Name "collection_gaps" `
                    -Default @()
            )
    )

    $NormalizedErrors =
        [System.Collections.Generic.List[string]]::new()

    $HiddenCoverageFields = @(
        "full_evidence_path",
        "evidence_path",
        "result_path",
        "output_path",
        "artifact_path",
        "machine_receipt",
        "receipt",
        "path"
    )

    function Add-AxiosCoverageMessage {
        param(
            [AllowNull()]
            [object]$Value,

            [string]$Label = ""
        )

        if ($null -eq $Value) {
            return
        }

        if (
            $Value -is [System.Collections.IEnumerable] -and
            $Value -isnot [string] -and
            $Value -isnot [System.Collections.IDictionary] -and
            $null -eq $Value.PSObject.Properties["source_report"]
        ) {
            foreach ($NestedValue in @($Value)) {
                Add-AxiosCoverageMessage `
                    -Value $NestedValue `
                    -Label $Label
            }

            return
        }

        if ($Value -is [string] -or $Value -is [ValueType]) {
            $Text = ([string]$Value).Trim()

            if ([string]::IsNullOrWhiteSpace($Text)) {
                return
            }

            $Text = $Text -replace (
                "(?i)[A-Z]:\\Users\\[^\\]+\\AppData\\Local\\" +
                "Temp\\AXIOS-Session-[^;\s}]+"
            ), "[internal evidence path]"

            $Message = if (
                [string]::IsNullOrWhiteSpace($Label)
            ) {
                $Text
            }
            else {
                "{0}: {1}" -f ($Label -replace "_", " "), $Text
            }

            if (-not $NormalizedErrors.Contains($Message)) {
                $NormalizedErrors.Add($Message)
            }

            return
        }

        $SourceName = [string](
            Get-AxiosProperty `
                -Value $Value `
                -Name "source_report" `
                -Default (
                    Get-AxiosProperty `
                        -Value $Value `
                        -Name "collector" `
                        -Default (
                            Get-AxiosProperty `
                                -Value $Value `
                                -Name "component" `
                                -Default ""
                        )
                )
        )

        if (-not [string]::IsNullOrWhiteSpace($SourceName)) {
            $SourceName = [IO.Path]::GetFileName($SourceName)
            $SourceName = $SourceName -replace "_", " "
        }

        $ErrorText = ""

        foreach ($MessageField in @(
            "error",
            "message",
            "reason",
            "effect",
            "status"
        )) {
            $CandidateMessage = [string](
                Get-AxiosProperty `
                    -Value $Value `
                    -Name $MessageField `
                    -Default ""
            )

            if (
                -not [string]::IsNullOrWhiteSpace(
                    $CandidateMessage
                )
            ) {
                $ErrorText = $CandidateMessage.Trim()
                break
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($ErrorText)) {
            $ErrorText = $ErrorText -replace (
                "(?i)[A-Z]:\\Users\\[^\\]+\\AppData\\Local\\" +
                "Temp\\AXIOS-Session-[^;\s}]+"
            ), "[internal evidence path]"

            $Message = if (
                [string]::IsNullOrWhiteSpace($SourceName)
            ) {
                $ErrorText
            }
            else {
                "{0}: {1}" -f $SourceName, $ErrorText
            }

            if (-not $NormalizedErrors.Contains($Message)) {
                $NormalizedErrors.Add($Message)
            }

            return
        }

        foreach ($Property in @($Value.PSObject.Properties)) {
            if ($Property.Name -in $HiddenCoverageFields) {
                continue
            }

            Add-AxiosCoverageMessage `
                -Value $Property.Value `
                -Label $Property.Name
        }
    }

    foreach ($RawError in $RawErrors) {
        Add-AxiosCoverageMessage -Value $RawError
    }

    $Errors = @($NormalizedErrors)

    if ($Success -ne $true -and $Errors.Count -eq 0) {
        $FailureMessage = Get-AxiosProperty `
            -Value $Report `
            -Name "stderr" `
            -Default (
                Get-AxiosProperty `
                    -Value $Report `
                    -Name "error" `
                    -Default "collector returned success=false"
            )

        $Errors = @([string]$FailureMessage)
    }

    $ConfirmedThreats = @(
        $Findings |
            Where-Object {
                (
                    Get-AxiosProperty `
                        -Value $_ `
                        -Name "confirmed" `
                        -Default $false
                ) -eq $true -or
                (
                    [string](
                        Get-AxiosProperty `
                            -Value $_ `
                            -Name "confidence" `
                            -Default ""
                    )
                ) -eq "confirmed"
            }
    )

    $ImportantFindings = @(
        $Findings |
            Where-Object {
                $Classification = [string](
                    Get-AxiosProperty `
                        -Value $_ `
                        -Name "classification" `
                        -Default ""
                )

                $Severity = [string](
                    Get-AxiosProperty `
                        -Value $_ `
                        -Name "severity" `
                        -Default ""
                )

                $Priority = [string](
                    Get-AxiosProperty `
                        -Value $_ `
                        -Name "priority" `
                        -Default ""
                )

                $IsContext = (
                    $Priority -eq "context" -or
                    $Classification -in @(
                        "",
                        "context",
                        "informational",
                        "information",
                        "observation",
                        "forensic_visibility_reduced",
                        "visibility_limited",
                        "credential_exposure_context"
                    )
                )

                -not $IsContext -or
                $Severity -in @(
                    "critical",
                    "high"
                )
            }
    )

    $ContextFindings = @(
        $Findings |
            Where-Object {
                $Classification = [string](
                    Get-AxiosProperty `
                        -Value $_ `
                        -Name "classification" `
                        -Default ""
                )

                $Severity = [string](
                    Get-AxiosProperty `
                        -Value $_ `
                        -Name "severity" `
                        -Default ""
                )

                $Priority = [string](
                    Get-AxiosProperty `
                        -Value $_ `
                        -Name "priority" `
                        -Default ""
                )

                (
                    $Priority -eq "context" -or
                    $Classification -in @(
                        "",
                        "context",
                        "informational",
                        "information",
                        "observation",
                        "forensic_visibility_reduced",
                        "visibility_limited",
                        "credential_exposure_context"
                    )
                ) -and
                $Severity -notin @(
                    "critical",
                    "high"
                )
            }
    )


    $UniqueImportantFindings = [ordered]@{}

    foreach ($FindingItem in $ImportantFindings) {
        $DedupClassification = [string](
            Get-AxiosProperty `
                -Value $FindingItem `
                -Name "classification" `
                -Default ""
        )

        $DedupTitle = ""

        foreach ($TitleField in @(
            "title",
            "label",
            "finding",
            "id",
            "classification"
        )) {
            $CandidateTitle = [string](
                Get-AxiosProperty `
                    -Value $FindingItem `
                    -Name $TitleField `
                    -Default ""
            )

            if (-not [string]::IsNullOrWhiteSpace($CandidateTitle)) {
                $DedupTitle = $CandidateTitle
                break
            }
        }

        $NormalizedDedupTitle = (
            $DedupTitle `
                -replace "_", " " `
                -replace "\s+", " "
        ).Trim().ToLowerInvariant()

        $DedupKey = (
            "{0}|{1}" -f
            $DedupClassification.ToLowerInvariant(),
            $NormalizedDedupTitle
        )

        $FindingSource = [string](
            Get-AxiosProperty `
                -Value $FindingItem `
                -Name "source" `
                -Default ""
        )

        if (-not $UniqueImportantFindings.Contains($DedupKey)) {
            $Sources = [System.Collections.Generic.List[string]]::new()

            if (-not [string]::IsNullOrWhiteSpace($FindingSource)) {
                $Sources.Add($FindingSource)
            }

            $UniqueImportantFindings[$DedupKey] = [PSCustomObject]@{
                Finding = $FindingItem
                Sources = $Sources
            }

            continue
        }

        $Existing = $UniqueImportantFindings[$DedupKey]

        if (
            -not [string]::IsNullOrWhiteSpace($FindingSource) -and
            $FindingSource -notin $Existing.Sources
        ) {
            $Existing.Sources.Add($FindingSource)
        }

        $ExistingEvidence = Get-AxiosProperty `
            -Value $Existing.Finding `
            -Name "evidence" `
            -Default $null

        $CandidateEvidence = Get-AxiosProperty `
            -Value $FindingItem `
            -Name "evidence" `
            -Default $null

        $ExistingEvidenceCount = if ($null -eq $ExistingEvidence) {
            0
        }
        else {
            @($ExistingEvidence.PSObject.Properties).Count
        }

        $CandidateEvidenceCount = if ($null -eq $CandidateEvidence) {
            0
        }
        else {
            @($CandidateEvidence.PSObject.Properties).Count
        }

        if ($CandidateEvidenceCount -gt $ExistingEvidenceCount) {
            $Existing.Finding = $FindingItem
        }
    }

    $ImportantFindings = @(
        foreach ($UniqueFinding in $UniqueImportantFindings.Values) {
            $MergedSources = @(
                $UniqueFinding.Sources |
                    Sort-Object -Unique
            )

            $UniqueFinding.Finding |
                Add-Member `
                    -NotePropertyName "evidence_sources" `
                    -NotePropertyValue $MergedSources `
                    -Force

            $UniqueFinding.Finding
        }
    )

    $RecommendedActions = @(
        Get-AxiosProperty `
            -Value $Report `
            -Name "recommended_actions" `
            -Default @()
    )

    $SeparateContextObservations = @(
        Get-AxiosProperty `
            -Value $Report `
            -Name "context_observations" `
            -Default @()
    )

    $UniqueForensicObservations = [ordered]@{}
    $GenericContextTitles = @(
        "context",
        "informational",
        "information",
        "observation",
        "visibility limited",
        "forensic visibility reduced"
    )

    foreach ($Observation in @(
        @($ContextFindings) +
        @($SeparateContextObservations)
    )) {
        if ($null -eq $Observation) {
            continue
        }

        if (
            $Observation -is [string] -or
            $Observation -is [ValueType]
        ) {
            $ObservationKey = (
                "scalar:{0}" -f [string]$Observation
            ).ToLowerInvariant()
        }
        else {
            $ObservationClassification = [string](
                Get-AxiosProperty `
                    -Value $Observation `
                    -Name "classification" `
                    -Default ""
            )
            $ObservationCollector = [string](
                Get-AxiosProperty `
                    -Value $Observation `
                    -Name "collector" `
                    -Default ""
            )
            $ObservationSemanticTitle = ""

            foreach ($SemanticField in @(
                "reason",
                "description",
                "message",
                "title",
                "label",
                "finding",
                "name",
                "id"
            )) {
                $SemanticCandidate = [string](
                    Get-AxiosProperty `
                        -Value $Observation `
                        -Name $SemanticField `
                        -Default ""
                )

                $NormalizedSemanticCandidate = (
                    $SemanticCandidate `
                        -replace "_", " " `
                        -replace "\s+", " "
                ).Trim().ToLowerInvariant()

                if (
                    -not [string]::IsNullOrWhiteSpace(
                        $SemanticCandidate
                    ) -and
                    $NormalizedSemanticCandidate -notin
                        $GenericContextTitles
                ) {
                    $ObservationSemanticTitle =
                        $NormalizedSemanticCandidate
                    break
                }
            }

            if (
                [string]::IsNullOrWhiteSpace(
                    $ObservationSemanticTitle
                ) -and
                $ObservationCollector -eq
                    "axios_audit_correlation"
            ) {
                $ObservationSemanticTitle =
                    "audit runtime artifact correlation"
            }

            if (
                [string]::IsNullOrWhiteSpace(
                    $ObservationSemanticTitle
                )
            ) {
                try {
                    $ObservationKey = (
                        $Observation |
                            ConvertTo-Json -Depth 30 -Compress
                    )
                }
                catch {
                    $ObservationKey = [string]$Observation
                }
            }
            else {
                $ObservationKey = (
                    "object:{0}|{1}|{2}" -f
                    $ObservationClassification,
                    $ObservationCollector,
                    $ObservationSemanticTitle
                ).ToLowerInvariant()
            }
        }

        if (
            -not [string]::IsNullOrWhiteSpace($ObservationKey) -and
            -not $UniqueForensicObservations.Contains(
                $ObservationKey
            )
        ) {
            $UniqueForensicObservations[$ObservationKey] =
                $Observation
        }
    }

    $ForensicObservations = @(
        $UniqueForensicObservations.Values
    )

    $Reasoning = Get-AxiosProperty `
        -Value $Report `
        -Name "reasoning" `
        -Default $null
    $LeadingHypothesis = Get-AxiosProperty `
        -Value $Reasoning `
        -Name "leading_hypothesis" `
        -Default $null
    $NextBestChecks = @(
        Get-AxiosProperty `
            -Value $Reasoning `
            -Name "next_best_checks" `
            -Default @()
    )

    $Result = [ordered]@{
        success = [bool]$Success
        collector = "axios_results_summary"
        collection_status = [string]$Status
        overall_status = if ($Success) {
            [string]$Status
        }
        else {
            "failed"
        }
        confirmed_threats = $ConfirmedThreats.Count
        important_findings = $ImportantFindings.Count
        contextual_observations = $ForensicObservations.Count
        collection_gaps = $Errors.Count
        recommended_actions = $RecommendedActions
        leading_hypothesis = $LeadingHypothesis
        next_best_checks = @($NextBestChecks | Select-Object -First 5)
        result_path = $Candidate.FullName
        result_size_bytes = $Candidate.Length
    }

    function Write-AxiosResultEvidenceValue {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Name,

            [AllowNull()]
            [object]$Value,

            [int]$Depth = 0
        )

        $DisplayName = (
            $Name `
                -replace "_", " " `
                -creplace "([a-z0-9])([A-Z])", '$1 $2'
        ).ToLowerInvariant()

        if ($null -eq $Value) {
            return
        }

        if (
            $Value -is [string] -or
            $Value -is [ValueType]
        ) {
            $DisplayValue = if ($Value -is [bool]) {
                if ($Value) { "Yes" } else { "No" }
            }
            else {
                [string]$Value
            }

            if (
                $DisplayValue -match
                '^/Date\((-?[0-9]+)(?:[+-][0-9]{4})?\)/$'
            ) {
                try {
                    $UnixEpoch = [DateTime]::SpecifyKind(
                        [DateTime]::new(1970, 1, 1),
                        [DateTimeKind]::Utc
                    )

                    $DisplayValue = $UnixEpoch.AddMilliseconds(
                        [double]$Matches[1]
                    ).ToLocalTime().ToString(
                        "yyyy-MM-dd HH:mm:ss K"
                    )
                }
                catch {
                    # Preserve the original evidence value.
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($DisplayValue)) {
                Write-Host (
                    "  {0,-28}: {1}" -f
                    $DisplayName,
                    $DisplayValue
                )
            }

            return
        }

        if (
            $Value -is [System.Collections.IEnumerable] -and
            $Value -isnot [string]
        ) {
            $Items = @($Value)
            $ScalarItems = @(
                $Items |
                    Where-Object {
                        $_ -is [string] -or
                        $_ -is [ValueType]
                    } |
                    ForEach-Object { [string]$_ }
            )

            if ($ScalarItems.Count -eq $Items.Count) {
                Write-Host (
                    "  {0,-28}: {1}" -f
                    $DisplayName,
                    ($ScalarItems -join ", ")
                )
            }
            else {
                Write-Host (
                    "  {0,-28}: {1} structured item(s)" -f
                    $DisplayName,
                    $Items.Count
                )

                if ($Depth -lt 2) {
                    $ItemIndex = 0

                    foreach ($Item in @(
                        $Items |
                            Select-Object -First 5
                    )) {
                        $ItemIndex += 1
                        $ItemName = (
                            "{0} {1}" -f
                            $DisplayName,
                            $ItemIndex
                        )

                        if (
                            $Item -is [string] -or
                            $Item -is [ValueType]
                        ) {
                            Write-AxiosResultEvidenceValue `
                                -Name $ItemName `
                                -Value $Item `
                                -Depth ($Depth + 1)
                        }
                        else {
                            foreach ($ItemProperty in @(
                                $Item.PSObject.Properties |
                                    Where-Object {
                                        $_.Name -notin @(
                                            "Length",
                                            "Count",
                                            "PSComputerName",
                                            "RunspaceId",
                                            "PSShowComputerName"
                                        )
                                    } |
                                    Select-Object -First 12
                            )) {
                                Write-AxiosResultEvidenceValue `
                                    -Name (
                                        "{0} {1}" -f
                                        $ItemName,
                                        $ItemProperty.Name
                                    ) `
                                    -Value $ItemProperty.Value `
                                    -Depth ($Depth + 1)
                            }
                        }
                    }
                }
            }

            return
        }

        if ($Depth -ge 2) {
            Write-Host (
                "  {0,-28}: structured evidence" -f
                $DisplayName
            )
            return
        }

        foreach ($NestedProperty in @(
            $Value.PSObject.Properties |
                Where-Object {
                    $_.Name -notin @(
                        "Length",
                        "Count",
                        "PSComputerName",
                        "RunspaceId",
                        "PSShowComputerName"
                    )
                } |
                Select-Object -First 12
        )) {
            Write-AxiosResultEvidenceValue `
                -Name (
                    "{0} {1}" -f
                    $DisplayName,
                    $NestedProperty.Name
                ) `
                -Value $NestedProperty.Value `
                -Depth ($Depth + 1)
        }
    }

    $ResultStamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
    $DetailedResultPath = Join-Path `
        $OutputDirectory `
        "AXIOS-Results-Details-$ResultStamp.txt"

    [System.IO.File]::WriteAllText(
        $DetailedResultPath,
        ($Report | ConvertTo-Json -Depth 30),
        $AxiosUtf8
    )

    Write-Host ""
    $SummaryHeading = "SECURITY ASSESSMENT SUMMARY"
    Write-Host $SummaryHeading
    Write-Host ("=" * $SummaryHeading.Length)
    Write-Host ("Status                 : {0}" -f $Result.overall_status)
    Write-Host "Result scope           : latest completed command"
    Write-Host ("Confirmed threats      : {0}" -f $Result.confirmed_threats)
    Write-Host ("Important findings     : {0}" -f $Result.important_findings)
    Write-Host ("Unique context records : {0}" -f $Result.contextual_observations)
    Write-Host ("Collection gaps        : {0}" -f $Result.collection_gaps)

    if ($null -ne $LeadingHypothesis) {
        $LeadingKind = Get-AxiosProperty `
            -Value $LeadingHypothesis `
            -Name "hypothesis" `
            -Default "unknown"
        $LeadingScore = Get-AxiosProperty `
            -Value $LeadingHypothesis `
            -Name "score" `
            -Default 0
        $IndependentGroups = Get-AxiosProperty `
            -Value $LeadingHypothesis `
            -Name "independent_support_groups" `
            -Default 0

        Write-Host ("Leading hypothesis     : {0}" -f $LeadingKind)
        Write-Host ("Hypothesis score       : {0}/10000" -f $LeadingScore)
        Write-Host ("Independent sources    : {0}" -f $IndependentGroups)
    }

    Write-Host ("Next best checks       : {0}" -f $NextBestChecks.Count)

    $Assessment = if ($Result.confirmed_threats -gt 0) {
        "confirmed threat evidence requires immediate review"
    }
    elseif ($Result.important_findings -gt 0) {
        "important security findings require review"
    }
    elseif ($Result.collection_gaps -gt 0) {
        "no important finding was observed, but visibility is incomplete"
    }
    else {
        "no important finding was observed within available visibility"
    }
    Write-Host ("Assessment             : {0}" -f $Assessment)

    Write-Host ""
    $FindingsHeading = "VERIFIED SECURITY FINDINGS"
    Write-Host $FindingsHeading
    Write-Host ("=" * $FindingsHeading.Length)
    if ($ImportantFindings.Count -eq 0) {
        Write-Host "None observed within available visibility."
    }
    else {
        $FindingIndex = 0
        $CurrentSecurityDomain = ""

        $DisplayFindings = @(
            foreach ($FindingItem in @(
                $ImportantFindings |
                    Select-Object -First 30
            )) {
                $ClassificationText = [string](
                    Get-AxiosProperty `
                        -Value $FindingItem `
                        -Name "classification" `
                        -Default ""
                )

                $FindingTitleText = [string](
                    Get-AxiosProperty `
                        -Value $FindingItem `
                        -Name "title" `
                        -Default (
                            Get-AxiosProperty `
                                -Value $FindingItem `
                                -Name "finding" `
                                -Default ""
                        )
                )

                $FindingText = (
                    $FindingTitleText + " " + $ClassificationText
                ).ToLowerInvariant()

                $SecurityDomain = if (
                    $FindingText -match
                    "boot|bitlocker|firmware|kernel|driver|whql|code.integrity"
                ) {
                    "BOOT AND PLATFORM TRUST"
                }
                elseif (
                    $FindingText -match
                    "defender|firewall|smb|security.control|audit.policy"
                ) {
                    "SECURITY CONTROLS"
                }
                elseif (
                    $FindingText -match
                    "credential|password|identity|account|token"
                ) {
                    "IDENTITY AND ACCESS"
                }
                elseif (
                    $FindingText -match
                    "browser|extension|application|software"
                ) {
                    "APPLICATION SECURITY"
                }
                elseif (
                    $FindingText -match
                    "visibility|collection|truncated|logging"
                ) {
                    "FORENSIC VISIBILITY"
                }
                elseif (
                    $FindingText -match
                    "network|endpoint|connection|dns|remote"
                ) {
                    "NETWORK SECURITY"
                }
                else {
                    "SYSTEM SECURITY"
                }

                $FindingPriority = [string](
                    Get-AxiosProperty `
                        -Value $FindingItem `
                        -Name "priority" `
                        -Default (
                            Get-AxiosProperty `
                                -Value $FindingItem `
                                -Name "severity" `
                                -Default "review"
                        )
                )

                $PriorityRank = switch (
                    $FindingPriority.ToLowerInvariant()
                ) {
                    "critical" { 0 }
                    "high" { 1 }
                    "medium" { 2 }
                    "low" { 3 }
                    "review" { 4 }
                    default { 5 }
                }

                [PSCustomObject]@{
                    Domain = $SecurityDomain
                    PriorityRank = $PriorityRank
                    Finding = $FindingItem
                }
            }
        )

        foreach ($DisplayItem in @(
            $DisplayFindings |
                Sort-Object Domain, PriorityRank
        )) {
            $Finding = $DisplayItem.Finding
            $FindingIndex += 1

            if ($DisplayItem.Domain -ne $CurrentSecurityDomain) {
                $CurrentSecurityDomain = $DisplayItem.Domain

                Write-Host ""
                Write-Host $CurrentSecurityDomain
                Write-Host ("-" * $CurrentSecurityDomain.Length)
            }
            $Priority = [string](
                Get-AxiosProperty `
                    -Value $Finding `
                    -Name "priority" `
                    -Default (
                        Get-AxiosProperty `
                            -Value $Finding `
                            -Name "severity" `
                            -Default ""
                    )
            )

            if ([string]::IsNullOrWhiteSpace($Priority)) {
                $FindingClassification = [string](
                    Get-AxiosProperty `
                        -Value $Finding `
                        -Name "classification" `
                        -Default ""
                )

                if ($FindingClassification -in @(
                    "context",
                    "informational",
                    "information",
                    "observation",
                    "visibility_limited",
                    "credential_exposure_context",
                    "forensic_visibility_reduced"
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
                    Get-AxiosProperty `
                        -Value $Finding `
                        -Name $TitleField `
                        -Default ""
                )

                if (-not [string]::IsNullOrWhiteSpace($CandidateTitle)) {
                    $Title = $CandidateTitle
                    break
                }
            }

            if ([string]::IsNullOrWhiteSpace($Title)) {
                $Title = "unnamed finding"
            }

            $Title = $Title -replace "_", " "

            Write-Host (
                "[{0}] {1}" -f
                ([string]$Priority).ToUpperInvariant(),
                $Title
            )
            $VerificationState = [string](
                Get-AxiosProperty `
                    -Value $Finding `
                    -Name "verification_state" `
                    -Default (
                        Get-AxiosProperty `
                            -Value $Finding `
                            -Name "status" `
                            -Default "Observed"
                    )
            )

            if ([string]::IsNullOrWhiteSpace($VerificationState)) {
                $VerificationState = "Observed"
            }
            else {
                $VerificationState = (
                    [Globalization.CultureInfo]::InvariantCulture.
                        TextInfo.ToTitleCase(
                            $VerificationState.ToLowerInvariant()
                        )
                )
            }

            Write-Host (
                "  {0,-28}: {1}" -f
                "verification",
                $VerificationState
            )

            foreach ($Field in @(
                "classification",
                "evidence_sources",
                "path",
                "sha256",
                "process_id",
                "service_name",
                "endpoint",
                "observed_value"
            )) {
                $Value = Get-AxiosProperty `
                    -Value $Finding `
                    -Name $Field `
                    -Default $null

                if ($null -ne $Value) {
                    Write-AxiosResultEvidenceValue `
                        -Name $Field `
                        -Value $Value
                }
            }

            $Evidence = Get-AxiosProperty `
                -Value $Finding `
                -Name "evidence" `
                -Default $null

            if ($null -ne $Evidence) {
                foreach ($Property in @(
                    $Evidence.PSObject.Properties |
                        Select-Object -First 12
                )) {
                    $PropertyValue = $Property.Value

                    Write-AxiosResultEvidenceValue `
                        -Name $Property.Name `
                        -Value $PropertyValue
                }
            }
        }
    }

    Write-Host ""
    $ForensicHeading = "FORENSIC VISIBILITY"
    Write-Host $ForensicHeading
    Write-Host ("=" * $ForensicHeading.Length)

    if ($ForensicObservations.Count -eq 0) {
        Write-Host "None observed."
    }
    else {
        foreach ($Observation in @(
            $ForensicObservations |
                Select-Object -First 30
        )) {
            if (
                $Observation -is [string] -or
                $Observation -is [ValueType]
            ) {
                Write-Host ("[CONTEXT] {0}" -f [string]$Observation)
                continue
            }

            $ObservationTitle = ""
            $GenericObservationTitles = @(
                "context",
                "informational",
                "information",
                "observation",
                "visibility limited",
                "forensic visibility reduced"
            )

            foreach ($TitleField in @(
                "reason",
                "description",
                "message",
                "title",
                "label",
                "finding",
                "name",
                "id"
            )) {
                $CandidateTitle = [string](
                    Get-AxiosProperty `
                        -Value $Observation `
                        -Name $TitleField `
                        -Default ""
                )

                $NormalizedCandidateTitle = (
                    $CandidateTitle `
                        -replace "_", " " `
                        -replace "\s+", " "
                ).Trim().ToLowerInvariant()

                if (
                    -not [string]::IsNullOrWhiteSpace(
                        $CandidateTitle
                    ) -and
                    $NormalizedCandidateTitle -notin
                        $GenericObservationTitles
                ) {
                    $ObservationTitle = $CandidateTitle
                    break
                }
            }

            if ([string]::IsNullOrWhiteSpace($ObservationTitle)) {
                $ObservationCollector = [string](
                    Get-AxiosProperty `
                        -Value $Observation `
                        -Name "collector" `
                        -Default ""
                )

                if (
                    $ObservationCollector -eq
                        "axios_audit_correlation"
                ) {
                    $ObservationTitle = (
                        "Artifact activity correlated across " +
                        "audit and runtime evidence"
                    )
                }
                else {
                    $PersistenceMatches = @(
                        Get-AxiosProperty `
                            -Value $Observation `
                            -Name "persistence_matches" `
                            -Default @()
                    )
                    $LiveActivityMatches = @(
                        Get-AxiosProperty `
                            -Value $Observation `
                            -Name "live_activity_matches" `
                            -Default @()
                    )

                    if (
                        $PersistenceMatches.Count -gt 0 -or
                        $LiveActivityMatches.Count -gt 0
                    ) {
                        $ObservationTitle =
                            "Artifact correlation context"
                    }
                    else {
                        $ObservationTitle =
                            "Supporting forensic observation"
                    }
                }
            }

            Write-Host (
                "[CONTEXT] {0}" -f
                ($ObservationTitle -replace "_", " ")
            )

            foreach ($ObservationField in @(
                "classification",
                "status",
                "value",
                "source",
                "collector",
                "evidence_sources",
                "evidence"
            )) {
                $ObservationValue = Get-AxiosProperty `
                    -Value $Observation `
                    -Name $ObservationField `
                    -Default $null

                if ($null -ne $ObservationValue) {
                    Write-AxiosResultEvidenceValue `
                        -Name $ObservationField `
                        -Value $ObservationValue
                }
            }
        }

        if ($ForensicObservations.Count -gt 30) {
            Write-Host (
                "Additional observations : {0} retained in detailed evidence" -f
                ($ForensicObservations.Count - 30)
            )
        }
    }

    Write-Host ""
    $CoverageHeading = "COLLECTION COVERAGE"
    Write-Host $CoverageHeading
    Write-Host ("=" * $CoverageHeading.Length)
    if ($Errors.Count -eq 0) {
        Write-Host "None."
    }
    else {
        foreach ($CollectionError in @($Errors | Select-Object -First 20)) {
            Write-Host ("- {0}" -f [string]$CollectionError)
        }
    }

    Write-Host ""
    function Write-AxiosConsoleHeading {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [ValidateSet("-", "=")]
        [string]$Underline = "-"
    )

    Write-Host $Title
    Write-Host ($Underline * $Title.Length)
}

Write-AxiosConsoleHeading `
        -Title "UNRESOLVED VERIFICATION" `
        -Underline "="

    if ($NextBestChecks.Count -eq 0) {
        Write-Host "Open verification items: None"
    }
    else {
        foreach ($Check in @($NextBestChecks | Select-Object -First 5)) {
            $CheckTitle = [string](
                Get-AxiosProperty `
                    -Value $Check `
                    -Name "title" `
                    -Default (
                        Get-AxiosProperty `
                            -Value $Check `
                            -Name "id" `
                            -Default "Additional evidence required"
                    )
            )

            Write-Host (
                "Verification item      : {0}" -f
                ($CheckTitle -replace "_", " ")
            )
        }
    }

    if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
        Write-Host ("Source result          : {0}" -f $Candidate.FullName)
        Write-Host ("Detailed TXT report    : {0}" -f $DetailedResultPath)
    }
    Write-Host ""

    $Result["detailed_report"] = $DetailedResultPath

    if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
        $Result | ConvertTo-Json -Depth 12 -Compress
    }
    return
}

function Format-AxiosDisplayValue {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return "unknown"
    }

    if ($Value -is [bool]) {
        if ($Value) {
            return "enabled"
        }

        return "disabled"
    }

    if (
        $Value -is [string] -or
        $Value -is [char] -or
        $Value -is [ValueType]
    ) {
        return [string]$Value
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $Items = @($Value)

        if ($Items.Count -eq 0) {
            return "none"
        }

        return (
            $Items |
                ForEach-Object {
                    if ($_ -is [string] -or $_ -is [ValueType]) {
                        [string]$_
                    }
                    else {
                        $_ | ConvertTo-Json -Depth 8 -Compress
                    }
                }
        ) -join "; "
    }

    return $Value | ConvertTo-Json -Depth 8 -Compress
}

function Write-AxiosConsoleHeading {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [ValidateSet("-", "=")]
        [string]$Underline = "-"
    )

    Write-Host $Title
    Write-Host ($Underline * $Title.Length)
}

function Write-AxiosLayerHumanReport {
    param(
        [Parameter(Mandatory = $true)]
        [object]$LayerResult,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$ReportData,
        [Parameter(Mandatory = $true)]
        [string]$DetailedReportPath,
        [Parameter(Mandatory = $true)]
        [string]$ResultPath,
        [Parameter(Mandatory = $true)]
        [System.Text.Encoding]$Encoding
    )

    $Summary = Get-AxiosProperty -Value $LayerResult -Name "summary"
    $LayerName = [string](Get-AxiosProperty -Value $LayerResult -Name "layer" -Default "unknown")
    $Title = switch ($LayerName) {
        "System" {
            "SYSTEM SECURITY ASSESSMENT"
        }
        "Software" {
            "SOFTWARE SECURITY ASSESSMENT"
        }
        "Persistence" {
            "PERSISTENCE SECURITY ASSESSMENT"
        }
        default {
            "{0} SECURITY ASSESSMENT" -f
                $LayerName.ToUpperInvariant()
        }
    }

    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title $Title `
        -Underline "="
    Write-Host ("Status                 : {0}" -f (Get-AxiosProperty -Value $LayerResult -Name "collection_status" -Default "unknown"))
    Write-Host ("Reports                : {0}" -f (Get-AxiosProperty -Value $Summary -Name "reports" -Default 0))
    Write-Host ("Reports failed         : {0}" -f (Get-AxiosProperty -Value $Summary -Name "reports_failed" -Default 0))
    Write-Host ("Reports partial        : {0}" -f (Get-AxiosProperty -Value $Summary -Name "reports_partial" -Default 0))
    $FindingLabel = switch ($LayerName) {
        "System" { "Control findings" }
        "Persistence" { "Persistence findings" }
        "Software" { "Software findings" }
        default { "Reported findings" }
    }

    Write-Host (
        "{0,-23}: {1}" -f
        $FindingLabel,
        (
            Get-AxiosProperty `
                -Value $Summary `
                -Name "findings" `
                -Default 0
        )
    )
    Write-Host (
        "Context observations   : {0}" -f (
            Get-AxiosProperty `
                -Value $Summary `
                -Name "context_observations" `
                -Default 0
        )
    )
    Write-Host ("Collection errors      : {0}" -f (Get-AxiosProperty -Value $Summary -Name "collection_errors" -Default 0))
    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "ASSESSMENT COVERAGE" `
        -Underline "-"

    foreach ($Item in @(Get-AxiosProperty -Value $LayerResult -Name "reports" -Default @())) {
        Write-Host ("{0,-28} status={1}; findings={2}; context={3}; errors={4}" -f
            (Get-AxiosProperty -Value $Item -Name "command" -Default "unknown"),
            (Get-AxiosProperty -Value $Item -Name "collection_status" -Default "unknown"),
            (Get-AxiosProperty -Value $Item -Name "findings" -Default 0),
            (Get-AxiosProperty -Value $Item -Name "context_observations" -Default 0),
            (Get-AxiosProperty -Value $Item -Name "collection_errors" -Default 0))
    }

    if ($LayerName -eq "Software") {
        $SoftwareInventory = $ReportData["software-inventory"]
        $Updates = $ReportData["updates"]
        $BrowserExtensions = $ReportData["browser-extensions"]

        $InstalledEntries = Get-AxiosProperty `
            -Value $SoftwareInventory `
            -Name "entry_count" `
            -Default 0

        $InventoryTruncated = Get-AxiosProperty `
            -Value $SoftwareInventory `
            -Name "truncated" `
            -Default $false

        $ExtensionCount = Get-AxiosProperty `
            -Value $BrowserExtensions `
            -Name "entry_count" `
            -Default 0

        $ExtensionsTruncated = Get-AxiosProperty `
            -Value $BrowserExtensions `
            -Name "truncated" `
            -Default $false

        $PendingUpdates = Get-AxiosProperty `
            -Value $Updates `
            -Name "pending_software_update_count" `
            -Default 0

        $Reboot = Get-AxiosProperty `
            -Value $Updates `
            -Name "reboot"

        $RebootRequired = Get-AxiosProperty `
            -Value $Reboot `
            -Name "required" `
            -Default $false

        $RebootReasons = @(
            Get-AxiosProperty `
                -Value $Reboot `
                -Name "reasons" `
                -Default @()
        )

        $UpdateDefender = Get-AxiosProperty `
            -Value $Updates `
            -Name "defender"

        $SignatureAge = Get-AxiosProperty `
            -Value $UpdateDefender `
            -Name "antivirus_signature_age_days" `
            -Default "unknown"

        $TamperProtected = Get-AxiosProperty `
            -Value $UpdateDefender `
            -Name "tamper_protected"

        $InventoryCoverage = if ($InventoryTruncated) {
            "truncated"
        }
        else {
            "complete"
        }

        $ExtensionCoverage = if ($ExtensionsTruncated) {
            "truncated"
        }
        else {
            "complete"
        }

        $RestartState = if ($RebootRequired) {
            "required"
        }
        else {
            "not required"
        }

        Write-Host ""
        Write-AxiosConsoleHeading `
            -Title "INSTALLED SOFTWARE PROFILE" `
            -Underline "-"
        Write-Host (
            "Installed entries      : {0}" -f
            $InstalledEntries
        )
        Write-Host (
            "Inventory coverage     : {0}" -f
            $InventoryCoverage
        )
        Write-Host (
            "Browser extensions     : {0}" -f
            $ExtensionCount
        )
        Write-Host (
            "Extension coverage     : {0}" -f
            $ExtensionCoverage
        )

        Write-Host ""
        Write-AxiosConsoleHeading `
            -Title "UPDATE AND ENDPOINT PROTECTION" `
            -Underline "-"
        Write-Host (
            "Pending updates        : {0}" -f
            $PendingUpdates
        )
        Write-Host (
            "Restart state          : {0}" -f
            $RestartState
        )
        Write-Host (
            "Restart reasons        : {0}" -f (
                Format-AxiosDisplayValue $RebootReasons
            )
        )
        Write-Host (
            "Defender signature age : {0} day(s)" -f
            $SignatureAge
        )
        Write-Host (
            "Tamper protection      : {0}" -f (
                Format-AxiosDisplayValue $TamperProtected
            )
        )

        $PendingUpdateItems = @(
            Get-AxiosProperty `
                -Value $Updates `
                -Name "pending_software_updates" `
                -Default @()
        )

        Write-Host ""
        Write-AxiosConsoleHeading `
            -Title "PENDING SECURITY UPDATES" `
            -Underline "-"

        if ($PendingUpdateItems.Count -eq 0) {
            Write-Host "None."
        }
        else {
            foreach ($Update in @(
                $PendingUpdateItems |
                    Select-Object -First 10
            )) {
                $UpdateTitle = Get-AxiosProperty `
                    -Value $Update `
                    -Name "title" `
                    -Default "unnamed update"

                $UpdateDownloaded = Get-AxiosProperty `
                    -Value $Update `
                    -Name "downloaded" `
                    -Default "unknown"

                $UpdateReboot = Get-AxiosProperty `
                    -Value $Update `
                    -Name "reboot_required" `
                    -Default "unknown"

                Write-Host (
                    "- {0}; downloaded={1}; reboot={2}" -f
                    $UpdateTitle,
                    $UpdateDownloaded,
                    $UpdateReboot
                )
            }
        }
    }

    if ($LayerName -eq "Persistence") {
        $Coverage = $ReportData["persistence-coverage"]

        $CoverageSummary = Get-AxiosProperty `
            -Value $Coverage `
            -Name "summary"

        $CoverageLimits = Get-AxiosProperty `
            -Value $Coverage `
            -Name "limits"

        Write-Host ""
        Write-AxiosConsoleHeading `
            -Title "PERSISTENCE SURFACE" `
            -Underline "-"
        Write-Host (
            "Auto-start services    : {0}" -f (
                Get-AxiosProperty `
                    -Value $CoverageSummary `
                    -Name "auto_start_services" `
                    -Default 0
            )
        )
        Write-Host (
            "Enabled tasks          : {0}" -f (
                Get-AxiosProperty `
                    -Value $CoverageSummary `
                    -Name "enabled_scheduled_tasks" `
                    -Default 0
            )
        )
        Write-Host (
            "Run-key entries        : {0}" -f (
                Get-AxiosProperty `
                    -Value $CoverageSummary `
                    -Name "run_key_entries" `
                    -Default 0
            )
        )
        Write-Host (
            "Startup commands       : {0}" -f (
                Get-AxiosProperty `
                    -Value $CoverageSummary `
                    -Name "startup_commands" `
                    -Default 0
            )
        )
        Write-Host (
            "Startup-folder items   : {0}" -f (
                Get-AxiosProperty `
                    -Value $CoverageSummary `
                    -Name "startup_folder_items" `
                    -Default 0
            )
        )

        Write-Host ""
        Write-AxiosConsoleHeading `
            -Title "WMI PERSISTENCE SUBSCRIPTIONS" `
            -Underline "-"
        Write-Host (
            "Event consumers        : {0}" -f (
                Get-AxiosProperty `
                    -Value $CoverageSummary `
                    -Name "wmi_event_consumers" `
                    -Default 0
            )
        )
        Write-Host (
            "Event filters          : {0}" -f (
                Get-AxiosProperty `
                    -Value $CoverageSummary `
                    -Name "wmi_event_filters" `
                    -Default 0
            )
        )
        Write-Host (
            "Filter bindings        : {0}" -f (
                Get-AxiosProperty `
                    -Value $CoverageSummary `
                    -Name "wmi_filter_bindings" `
                    -Default 0
            )
        )

        $ReviewItemsShown = Get-AxiosProperty `
            -Value $CoverageSummary `
            -Name "review_items" `
            -Default 0

        $ReviewItemsTotal = Get-AxiosProperty `
            -Value $CoverageLimits `
            -Name "review_items_total" `
            -Default $ReviewItemsShown

        $ReviewItemsTruncated = Get-AxiosProperty `
            -Value $CoverageLimits `
            -Name "review_items_truncated" `
            -Default $false

        Write-Host ""
        Write-AxiosConsoleHeading `
            -Title "ASSESSMENT COVERAGE" `
            -Underline "-"
        Write-Host (
            "Review items retained  : {0}" -f $ReviewItemsShown
        )
        Write-Host (
            "Review items observed  : {0}" -f $ReviewItemsTotal
        )
        $ReviewTruncationDisplay = if ($ReviewItemsTruncated) {
            "yes; bounded output limit reached"
        }
        else {
            "no"
        }

        Write-Host (
            "Review list truncated  : {0}" -f
            $ReviewTruncationDisplay
        )
        Write-Host (
            "Interpretation         : inventory candidates; not confirmed persistence threats"
        )
    }

    $Findings = @(Get-AxiosProperty -Value $LayerResult -Name "findings" -Default @())
    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "VERIFIED SECURITY FINDINGS" `
        -Underline "-"
    if ($Findings.Count -eq 0) {
        Write-Host "None reported by this bounded layer."
    }
    else {
        foreach ($Finding in @($Findings | Select-Object -First 25)) {
            $Severity = Get-AxiosProperty -Value $Finding -Name "severity" -Default "review"
            $TitleValue = Get-AxiosProperty -Value $Finding -Name "title" -Default (
                Get-AxiosProperty -Value $Finding -Name "id" -Default "unnamed finding"
            )
            Write-Host ("[{0}] {1}" -f ([string]$Severity).ToUpperInvariant(), $TitleValue)
        }
    }

    $ContextObservations = @(
        Get-AxiosProperty `
            -Value $LayerResult `
            -Name "context_observations" `
            -Default @()
    )

    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "SUPPORTING OBSERVATIONS" `
        -Underline "-"

    if ($ContextObservations.Count -eq 0) {
        Write-Host "None."
    }
    else {
        foreach ($Observation in @(
            $ContextObservations |
                Select-Object -First 25
        )) {
            $ObservationTitle = Get-AxiosProperty `
                -Value $Observation `
                -Name "title" `
                -Default "unnamed observation"

            Write-Host (
                "[CONTEXT] {0}" -f $ObservationTitle
            )
        }
    }

    $Errors = @(Get-AxiosProperty -Value $LayerResult -Name "collection_errors" -Default @())
    $FailedReports = @(
        Get-AxiosProperty `
            -Value $LayerResult `
            -Name "reports" `
            -Default @() |
            Where-Object { $_.success -ne $true }
    )
    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "VISIBILITY LIMITATIONS" `
        -Underline "-"
    if ($Errors.Count -eq 0 -and $FailedReports.Count -eq 0) {
        Write-Host "None."
    }
    else {
        foreach ($Item in $Errors) {
            Write-Host ("- {0}" -f $Item)
        }
        foreach ($FailedReport in $FailedReports) {
            Write-Host (
                "- {0}: collector failed; inspect raw report" -f
                (Get-AxiosProperty `
                    -Value $FailedReport `
                    -Name "command" `
                    -Default "unknown")
            )
        }
    }

    $Builder = [System.Text.StringBuilder]::new()
    $null = $Builder.AppendLine("$Title - COMPLETE TECHNICAL REPORT")
    $null = $Builder.AppendLine("Generated UTC: $([DateTime]::UtcNow.ToString('o'))")
    foreach ($Entry in $ReportData.GetEnumerator()) {
        $null = $Builder.AppendLine("")
        $null = $Builder.AppendLine(("=" * 64))
        $null = $Builder.AppendLine(("REPORT: {0}" -f $Entry.Key))
        $null = $Builder.AppendLine(("=" * 64))
        $null = $Builder.AppendLine(($Entry.Value | ConvertTo-Json -Depth 30))
    }
    [System.IO.File]::WriteAllText($DetailedReportPath, $Builder.ToString(), $Encoding)

    if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
        Write-Host ""
        Write-AxiosConsoleHeading `
            -Title "OUTPUT" `
            -Underline "-"
        Write-Host ("Detailed TXT report    : {0}" -f $DetailedReportPath)
        Write-Host ("Structured JSON result : {0}" -f $ResultPath)
        Write-Host ("Raw evidence directory : {0}" -f (Get-AxiosProperty -Value $LayerResult -Name "output"))
        Write-Host ""
    }
}

function Write-AxiosContextHumanReport {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report,

        [Parameter(Mandatory = $true)]
        [string]$DetailedReportPath,

        [Parameter(Mandatory = $true)]
        [string]$ResultPath,

        [Parameter(Mandatory = $true)]
        [System.Text.Encoding]$Encoding
    )

    $Time = Get-AxiosProperty -Value $Report -Name "time"
    $Locale = Get-AxiosProperty -Value $Report -Name "locale"
    $Network = Get-AxiosProperty -Value $Report -Name "network_context"
    $TimeZone = Get-AxiosProperty -Value $Time -Name "timezone"
    $TimeService = Get-AxiosProperty -Value $Time -Name "windows_time_service"
    $Culture = Get-AxiosProperty -Value $Locale -Name "culture"
    $UiCulture = Get-AxiosProperty -Value $Locale -Name "ui_culture"
    $Region = Get-AxiosProperty -Value $Locale -Name "region"
    $Errors = @(Get-AxiosProperty -Value $Report -Name "collection_errors" -Default @())

    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "SYSTEM CONTEXT ASSESSMENT" `
        -Underline "="
    Write-Host ("Status                 : {0}" -f (Get-AxiosProperty -Value $Report -Name "collection_status" -Default "unknown"))
    Write-Host ("Collection errors      : {0}" -f $Errors.Count)
    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "TIME INTEGRITY" `
        -Underline "-"
    Write-Host ("Local time             : {0}" -f (Get-AxiosProperty -Value $Time -Name "local_time" -Default "unknown"))
    Write-Host ("UTC time               : {0}" -f (Get-AxiosProperty -Value $Time -Name "utc_time" -Default "unknown"))
    Write-Host ("Time zone              : {0}" -f (Get-AxiosProperty -Value $TimeZone -Name "Id" -Default "unknown"))
    Write-Host ("UTC offset             : {0}" -f (Get-AxiosProperty -Value $Time -Name "utc_offset" -Default "unknown"))
    Write-Host ("Windows Time service   : {0}" -f (Get-AxiosProperty -Value $TimeService -Name "status" -Default "unknown"))
    Write-Host ("Synchronization state  : {0}" -f (Get-AxiosProperty -Value $Time -Name "synchronization_state" -Default "unknown"))
    Write-Host ("Synchronization source : {0}" -f (Get-AxiosProperty -Value $Time -Name "synchronization_source" -Default "unavailable"))
    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "REGIONAL CONFIGURATION" `
        -Underline "-"
    Write-Host ("Culture                : {0}" -f (Get-AxiosProperty -Value $Culture -Name "Name" -Default "unknown"))
    Write-Host ("UI language            : {0}" -f (Get-AxiosProperty -Value $UiCulture -Name "Name" -Default "unknown"))
    Write-Host ("Home location          : {0}" -f (Get-AxiosProperty -Value $Region -Name "HomeLocation" -Default "unknown"))
    Write-Host ("Installed languages    : {0}" -f (@(Get-AxiosProperty -Value $Locale -Name "user_languages" -Default @() | ForEach-Object { Get-AxiosProperty -Value $_ -Name "language_tag" }) -join ", "))
    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "NETWORK CONTEXT" `
        -Underline "-"
    Write-Host ("Public profiles        : {0}" -f (Get-AxiosProperty -Value $Network -Name "public_profiles" -Default 0))
    Write-Host ("Private profiles       : {0}" -f (Get-AxiosProperty -Value $Network -Name "private_profiles" -Default 0))
    Write-Host ("Domain profiles        : {0}" -f (Get-AxiosProperty -Value $Network -Name "domain_authenticated_profiles" -Default 0))

    foreach ($Profile in @(Get-AxiosProperty -Value $Network -Name "profiles" -Default @())) {
        Write-Host ("Profile                : {0}; adapter={1}; category={2}; IPv4={3}; IPv6={4}" -f
            (Get-AxiosProperty -Value $Profile -Name "Name" -Default "unknown"),
            (Get-AxiosProperty -Value $Profile -Name "InterfaceAlias" -Default "unknown"),
            (Get-AxiosProperty -Value $Profile -Name "network_category" -Default "unknown"),
            (Get-AxiosProperty -Value $Profile -Name "ipv4_connectivity" -Default "unknown"),
            (Get-AxiosProperty -Value $Profile -Name "ipv6_connectivity" -Default "unknown"))
    }

    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "VISIBILITY LIMITATIONS" `
        -Underline "-"
    if ($Errors.Count -eq 0) {
        Write-Host "None."
    }
    else {
        foreach ($Item in $Errors) {
            Write-Host ("- {0}" -f $Item)
        }
    }

    [System.IO.File]::WriteAllText(
        $DetailedReportPath,
        ($Report | ConvertTo-Json -Depth 30),
        $Encoding
    )

    if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
        Write-Host ""
        Write-AxiosConsoleHeading `
            -Title "OUTPUT" `
            -Underline "-"
        Write-Host ("Detailed TXT report    : {0}" -f $DetailedReportPath)
        Write-Host ("Structured JSON result : {0}" -f $ResultPath)
        Write-Host ""
    }
}

function Write-AxiosQuickHumanReport {
    param(
        [Parameter(Mandatory = $true)]
        [object]$LayerResult,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$ReportData,

        [Parameter(Mandatory = $true)]
        [string]$DetailedReportPath,

        [Parameter(Mandatory = $true)]
        [string]$ResultPath,

        [Parameter(Mandatory = $true)]
        [System.Text.Encoding]$Encoding
    )

    $Security = $ReportData["security-posture"]
    $Health = $ReportData["health-posture"]
    $Activity = $ReportData["live-activity"]
    $Network = $ReportData["network-posture"]
    $Context = $ReportData["context-posture"]

    $Defender = Get-AxiosProperty `
        -Value $Security `
        -Name "defender_status"

    $SecureBoot = Get-AxiosProperty `
        -Value $Security `
        -Name "secure_boot"

    $Uac = Get-AxiosProperty `
        -Value $Security `
        -Name "uac"

    $AntivirusEnabled = Get-AxiosProperty `
        -Value $Defender `
        -Name "antivirus_enabled"

    $RealtimeEnabled = Get-AxiosProperty `
        -Value $Defender `
        -Name "real_time_protection_enabled"

    $BehaviorEnabled = Get-AxiosProperty `
        -Value $Defender `
        -Name "behavior_monitor_enabled"

    $IoavEnabled = Get-AxiosProperty `
        -Value $Defender `
        -Name "ioav_protection_enabled"

    $SignatureUpdated = Get-AxiosProperty `
        -Value $Defender `
        -Name "antivirus_signature_last_updated"

    $TamperProtectionSource = Get-AxiosProperty `
        -Value $Defender `
        -Name "tamper_protection_source"

    $TamperProtected = if (
        $TamperProtectionSource -is [bool]
    ) {
        [bool]$TamperProtectionSource
    }
    elseif (
        [string]$TamperProtectionSource -match
        '^(?i:true|false)$'
    ) {
        [System.Convert]::ToBoolean(
            [string]$TamperProtectionSource
        )
    }
    else {
        $null
    }

    $SecureBootAvailable = Get-AxiosProperty `
        -Value $SecureBoot `
        -Name "available"

    $SecureBootEnabled = Get-AxiosProperty `
        -Value $SecureBoot `
        -Name "enabled"

    $EnableLua = Get-AxiosProperty `
        -Value $Uac `
        -Name "enable_lua"

    $TcpCount = Get-AxiosProperty `
        -Value $Activity `
        -Name "tcp_endpoint_count" `
        -Default 0

    $UdpCount = Get-AxiosProperty `
        -Value $Activity `
        -Name "udp_endpoint_count" `
        -Default 0

    $SecurityErrors = @(
        Get-AxiosProperty `
            -Value $Security `
            -Name "collection_errors" `
            -Default @()
    )

    $NetworkErrors = @(
        Get-AxiosProperty `
            -Value $Network `
            -Name "collection_errors" `
            -Default @()
    )

    $ContextErrors = @(
        Get-AxiosProperty `
            -Value $Context `
            -Name "collection_errors" `
            -Default @()
    )

    $Signals = [System.Collections.Generic.List[string]]::new()

    if ($AntivirusEnabled -eq $false) {
        $Signals.Add(
            "[HIGH] Registered antivirus protection is disabled."
        )
    }

    if ($RealtimeEnabled -eq $false) {
        $Signals.Add(
            "[HIGH] Microsoft Defender real-time protection is disabled."
        )
    }

    if ($BehaviorEnabled -eq $false) {
        $Signals.Add(
            "[HIGH] Defender behavior monitoring is disabled."
        )
    }

    if ($IoavEnabled -eq $false) {
        $Signals.Add(
            "[MEDIUM] Defender downloaded-file inspection is disabled."
        )
    }

    if ($TamperProtected -eq $false) {
        $Signals.Add(
            "[HIGH] Microsoft Defender tamper protection is disabled."
        )
    }

    if ($SecureBootAvailable -eq $true -and $SecureBootEnabled -eq $false) {
        $Signals.Add(
            "[HIGH] Secure Boot is explicitly disabled."
        )
    }

    if ($EnableLua -eq 0) {
        $Signals.Add(
            "[HIGH] User Account Control is disabled."
        )
    }

    $ContextTime = Get-AxiosProperty -Value $Context -Name "time"
    $SynchronizationState = Get-AxiosProperty `
        -Value $ContextTime `
        -Name "synchronization_state" `
        -Default "unknown"

    if ($SynchronizationState -eq "service_not_running") {
        $Signals.Add(
            "[MEDIUM] Windows Time synchronization service is not running."
        )
    }

    $Summary = Get-AxiosProperty `
        -Value $LayerResult `
        -Name "summary"

    $Status = [string](
        Get-AxiosProperty `
            -Value $LayerResult `
            -Name "collection_status" `
            -Default "unknown"
    )

    $HighSignals = @(
        $Signals |
            Where-Object {
                ([string]$_).StartsWith(
                    "[HIGH]",
                    [System.StringComparison]::Ordinal
                )
            }
    )

    $SecurityState = if ($HighSignals.Count -gt 0) {
        "attention required"
    }
    elseif ($Signals.Count -gt 0) {
        "review required"
    }
    elseif (
        $SecurityErrors.Count -gt 0 -or
        $NetworkErrors.Count -gt 0 -or
        $ContextErrors.Count -gt 0
    ) {
        "inconclusive because collection is partial"
    }
    else {
        "no critical control failure observed in Quick scope"
    }

    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "RAPID SECURITY ASSESSMENT" `
        -Underline "="
    Write-Host ("Status                 : {0}" -f $Status)
    Write-Host ("Security state         : {0}" -f $SecurityState)
    Write-Host (
        "Reports completed      : {0}/{1}" -f
        (
            [int](
                Get-AxiosProperty `
                    -Value $Summary `
                    -Name "reports" `
                    -Default 0
            ) -
            [int](
                Get-AxiosProperty `
                    -Value $Summary `
                    -Name "reports_failed" `
                    -Default 0
            )
        ),
        (
            Get-AxiosProperty `
                -Value $Summary `
                -Name "reports" `
                -Default 0
        )
    )
    Write-Host (
        "Reports partial        : {0}" -f (
            Get-AxiosProperty `
                -Value $Summary `
                -Name "reports_partial" `
                -Default 0
        )
    )
    Write-Host ("Control signals        : {0}" -f $Signals.Count)
    Write-Host (
        "Collection errors      : {0}" -f (
            Get-AxiosProperty `
                -Value $Summary `
                -Name "collection_errors" `
                -Default 0
        )
    )

    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "SECURITY CONTROLS" `
        -Underline "-"
    Write-Host (
        "Antivirus              : {0}" -f (
            Format-AxiosDisplayValue $AntivirusEnabled
        )
    )
    Write-Host (
        "Real-time protection   : {0}" -f (
            Format-AxiosDisplayValue $RealtimeEnabled
        )
    )
    Write-Host (
        "Behavior monitoring    : {0}" -f (
            Format-AxiosDisplayValue $BehaviorEnabled
        )
    )
    Write-Host (
        "Downloaded-file scan   : {0}" -f (
            Format-AxiosDisplayValue $IoavEnabled
        )
    )
    Write-Host (
        "Signature last updated : {0}" -f (
            Format-AxiosDisplayValue $SignatureUpdated
        )
    )
    Write-Host (
        "Tamper protection      : {0}" -f (
            Format-AxiosDisplayValue $TamperProtected
        )
    )
    Write-Host (
        "Secure Boot available  : {0}" -f (
            Format-AxiosDisplayValue $SecureBootAvailable
        )
    )
    Write-Host (
        "Secure Boot enabled    : {0}" -f (
            Format-AxiosDisplayValue $SecureBootEnabled
        )
    )
    $UacState = if ($EnableLua -eq 1) {
        "enabled"
    }
    elseif ($EnableLua -eq 0) {
        "disabled"
    }
    else {
        "unknown"
    }

    Write-Host ("UAC                    : {0}" -f $UacState)

    $ControlFindings = @(
        foreach ($Signal in $Signals) {
            $SignalText = [string]$Signal

            if (
                $SignalText -match
                '^\[(?<Severity>HIGH|MEDIUM|LOW|REVIEW)\]\s*(?<Title>.+)$'
            ) {
                [PSCustomObject]@{
                    title = $Matches["Title"]
                    severity = $Matches["Severity"].ToLowerInvariant()
                    priority = $Matches["Severity"].ToLowerInvariant()
                    classification = "security_control_state"
                    verification_state = "observed"
                    source = "quick-control-correlation"
                }
            }
        }
    )

    $ExistingQuickFindings = @(
        Get-AxiosProperty `
            -Value $LayerResult `
            -Name "findings" `
            -Default @()
    )

    $LayerResult["findings"] = @(
        $ExistingQuickFindings +
        $ControlFindings
    )
    $LayerResult["control_signals"] = @($Signals)
    $LayerResult.summary["findings"] = @(
        $LayerResult["findings"]
    ).Count
    $LayerResult.summary["control_signals"] = $Signals.Count
    Write-AxiosJson -Path $ResultPath -Value $LayerResult

    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "SYSTEM AND RUNTIME ACTIVITY" `
        -Underline "-"
    $OperatingSystem = Get-AxiosProperty `
        -Value $Health `
        -Name "operating_system"

    $OsCaption = Get-AxiosProperty `
        -Value $OperatingSystem `
        -Name "Caption" `
        -Default "unknown"

    $OsVersion = Get-AxiosProperty `
        -Value $OperatingSystem `
        -Name "Version" `
        -Default "unknown"

    $OsBuild = Get-AxiosProperty `
        -Value $OperatingSystem `
        -Name "BuildNumber" `
        -Default "unknown"

    $TotalMemoryKb = Get-AxiosProperty `
        -Value $OperatingSystem `
        -Name "TotalVisibleMemorySize" `
        -Default 0

    $FreeMemoryKb = Get-AxiosProperty `
        -Value $OperatingSystem `
        -Name "FreePhysicalMemory" `
        -Default 0

    $TotalMemoryGb = [Math]::Round(
        ([double]$TotalMemoryKb / 1MB),
        2
    )

    $FreeMemoryGb = [Math]::Round(
        ([double]$FreeMemoryKb / 1MB),
        2
    )

    $Battery = Get-AxiosProperty `
        -Value $Health `
        -Name "battery"

    $BatteryName = Get-AxiosProperty `
        -Value $Battery `
        -Name "Name" `
        -Default "unknown"

    $BatteryCharge = Get-AxiosProperty `
        -Value $Battery `
        -Name "EstimatedChargeRemaining" `
        -Default "unknown"

    $BatteryStatus = Get-AxiosProperty `
        -Value $Battery `
        -Name "BatteryStatus" `
        -Default "unknown"

    Write-Host ("Operating system       : {0}" -f $OsCaption)
    Write-Host ("OS version             : {0}" -f $OsVersion)
    Write-Host ("OS build               : {0}" -f $OsBuild)
    Write-Host (
        "Physical memory        : {0} GB total / {1} GB free" -f
        $TotalMemoryGb,
        $FreeMemoryGb
    )
    $BatteryState = switch ([int]$BatteryStatus) {
        1 { "discharging" }
        2 { "AC power / charged" }
        3 { "fully charged" }
        4 { "low" }
        5 { "critical" }
        6 { "charging" }
        7 { "charging / high" }
        8 { "charging / low" }
        9 { "charging / critical" }
        10 { "undefined" }
        11 { "partially charged" }
        default { "unknown" }
    }

    Write-Host (
        "Battery                : {0}; charge {1}%; {2}" -f
        $BatteryName,
        $BatteryCharge,
        $BatteryState
    )
    Write-Host (
        "Physical disks         : {0}" -f (
            Get-AxiosCount (
                Get-AxiosProperty `
                    -Value $Health `
                    -Name "physical_disks" `
                    -Default @()
            )
        )
    )
    Write-Host (
        "Logical disks          : {0}" -f (
            Get-AxiosCount (
                Get-AxiosProperty `
                    -Value $Health `
                    -Name "logical_disks" `
                    -Default @()
            )
        )
    )

    foreach ($Processor in @(
        Get-AxiosProperty -Value $Health -Name "processors" -Default @()
    )) {
        Write-Host (
            "Processor              : {0}; {1} cores/{2} threads; load={3}%" -f
            (Get-AxiosProperty -Value $Processor -Name "Name" -Default "unknown"),
            (Get-AxiosProperty -Value $Processor -Name "NumberOfCores" -Default "unknown"),
            (Get-AxiosProperty -Value $Processor -Name "NumberOfLogicalProcessors" -Default "unknown"),
            (Get-AxiosProperty -Value $Processor -Name "LoadPercentage" -Default "unknown")
        )
    }

    foreach ($Graphics in @(
        Get-AxiosProperty -Value $Health -Name "graphics_adapters" -Default @()
    )) {
        $GraphicsMemory = Get-AxiosProperty `
            -Value $Graphics `
            -Name "AdapterRAM" `
            -Default 0

        $GraphicsMemoryGb = if ([double]$GraphicsMemory -gt 0) {
            [Math]::Round(([double]$GraphicsMemory / 1GB), 2)
        }
        else {
            "unknown"
        }

        Write-Host (
            "Graphics               : {0}; VRAM={1} GB; driver={2}; status={3}" -f
            (Get-AxiosProperty -Value $Graphics -Name "Name" -Default "unknown"),
            $GraphicsMemoryGb,
            (Get-AxiosProperty -Value $Graphics -Name "DriverVersion" -Default "unknown"),
            (Get-AxiosProperty -Value $Graphics -Name "Status" -Default "unknown")
        )
    }

    foreach ($Disk in @(
        Get-AxiosProperty -Value $Health -Name "physical_disks" -Default @()
    )) {
        $DiskBytes = Get-AxiosProperty -Value $Disk -Name "Size" -Default 0
        $DiskGb = [Math]::Round(([double]$DiskBytes / 1GB), 2)

        Write-Host (
            "Physical disk          : {0}; {1} GB; {2}; status={3}" -f
            (Get-AxiosProperty -Value $Disk -Name "Model" -Default "unknown"),
            $DiskGb,
            (Get-AxiosProperty -Value $Disk -Name "InterfaceType" -Default "unknown"),
            (Get-AxiosProperty -Value $Disk -Name "Status" -Default "unknown")
        )
    }

    foreach ($Disk in @(
        Get-AxiosProperty -Value $Health -Name "logical_disks" -Default @()
    )) {
        $DiskSize = [double](Get-AxiosProperty -Value $Disk -Name "Size" -Default 0)
        $DiskFree = [double](Get-AxiosProperty -Value $Disk -Name "FreeSpace" -Default 0)
        $FreePercent = if ($DiskSize -gt 0) {
            [Math]::Round(($DiskFree / $DiskSize) * 100, 1)
        }
        else {
            0
        }

        Write-Host (
            "Logical disk           : {0}; {1} GB free of {2} GB ({3}%)" -f
            (Get-AxiosProperty -Value $Disk -Name "DeviceID" -Default "unknown"),
            ([Math]::Round(($DiskFree / 1GB), 2)),
            ([Math]::Round(($DiskSize / 1GB), 2)),
            $FreePercent
        )
    }

    $ProcessSummary = Get-AxiosProperty `
        -Value $Health `
        -Name "process_summary"
    Write-Host (
        "Processes observed     : {0}" -f (
            Get-AxiosProperty -Value $ProcessSummary -Name "process_count" -Default 0
        )
    )
    Write-Host ("TCP endpoints observed : {0}" -f $TcpCount)
    Write-Host ("UDP endpoints observed : {0}" -f $UdpCount)
    $DnsEntries = @(
        Get-AxiosProperty `
            -Value $Network `
            -Name "dns_servers" `
            -Default @()
    )

    $DnsAddresses = @(
        foreach ($DnsEntry in $DnsEntries) {
            foreach ($Address in @(
                Get-AxiosProperty `
                    -Value $DnsEntry `
                    -Name "ServerAddresses" `
                    -Default @()
            )) {
                [string]$Address
            }
        }
    ) | Sort-Object -Unique

    $FirewallProfiles = @(
        Get-AxiosProperty `
            -Value $Network `
            -Name "firewall_profiles" `
            -Default @()
    )

    $DnsDisplay = if ((Get-AxiosCount $DnsAddresses) -eq 0) {
        "none observed"
    }
    else {
        @($DnsAddresses) -join ", "
    }

    Write-Host ("DNS servers            : {0}" -f $DnsDisplay)

    foreach ($FirewallProfile in $FirewallProfiles) {
        $ProfileName = Get-AxiosProperty `
            -Value $FirewallProfile `
            -Name "Name" `
            -Default "unknown"

        $ProfileEnabled = Get-AxiosProperty `
            -Value $FirewallProfile `
            -Name "Enabled"

        $InboundAction = Get-AxiosProperty `
            -Value $FirewallProfile `
            -Name "DefaultInboundAction" `
            -Default "unknown"

        $OutboundAction = Get-AxiosProperty `
            -Value $FirewallProfile `
            -Name "DefaultOutboundAction" `
            -Default "unknown"

        $FirewallEnabled = if ([int]$ProfileEnabled -eq 1) {
            "enabled"
        }
        else {
            "disabled"
        }

        Write-Host (
            "Firewall {0,-10} : {1}; policy {2}/{3}" -f
            $ProfileName,
            $FirewallEnabled,
            $InboundAction,
            $OutboundAction
        )
    }

    $UserProxy = Get-AxiosProperty `
        -Value $Network `
        -Name "user_proxy"

    $ProxyEnabled = Get-AxiosProperty `
        -Value $UserProxy `
        -Name "ProxyEnable" `
        -Default 0

    $ProxyServer = Get-AxiosProperty `
        -Value $UserProxy `
        -Name "ProxyServer"

    $UserProxyState = if ([int]$ProxyEnabled -eq 1) {
        "configured: $ProxyServer"
    }
    else {
        "disabled"
    }

    $WinHttpProxy = Get-AxiosProperty `
        -Value $Network `
        -Name "winhttp_proxy"

    $WinHttpProxyState = if (
        [string]::IsNullOrWhiteSpace([string]$WinHttpProxy)
    ) {
        "unknown"
    }
    elseif (
        [string]$WinHttpProxy -match
        "direct|directe|sans serveur proxy|no proxy"
    ) {
        "direct connection"
    }
    else {
        "configured; see detailed report"
    }

    Write-Host ("User proxy             : {0}" -f $UserProxyState)
    Write-Host ("WinHTTP proxy          : {0}" -f $WinHttpProxyState)

    if ($null -ne $Context) {
        $Time = Get-AxiosProperty -Value $Context -Name "time"
        $Locale = Get-AxiosProperty -Value $Context -Name "locale"
        $NetworkContext = Get-AxiosProperty `
            -Value $Context `
            -Name "network_context"

        $TimeZone = Get-AxiosProperty -Value $Time -Name "timezone"
        $TimeService = Get-AxiosProperty `
            -Value $Time `
            -Name "windows_time_service"
        $Culture = Get-AxiosProperty -Value $Locale -Name "culture"
        $UiCulture = Get-AxiosProperty -Value $Locale -Name "ui_culture"
        $Region = Get-AxiosProperty -Value $Locale -Name "region"
        $Profiles = @(
            Get-AxiosProperty `
                -Value $NetworkContext `
                -Name "profiles" `
                -Default @()
        )
        $Interfaces = @(
            Get-AxiosProperty `
                -Value $NetworkContext `
                -Name "interfaces" `
                -Default @()
        )

        Write-Host ""
        Write-Host "TIME, LANGUAGE AND NETWORK CONTEXT"
        Write-Host "----------------------------------"
        Write-Host (
            "Local time             : {0}" -f (
                Get-AxiosProperty -Value $Time -Name "local_time"
            )
        )
        Write-Host (
            "UTC time               : {0}" -f (
                Get-AxiosProperty -Value $Time -Name "utc_time"
            )
        )
        Write-Host (
            "Time zone              : {0}" -f (
                Get-AxiosProperty -Value $TimeZone -Name "Id" -Default "unknown"
            )
        )
        Write-Host (
            "UTC offset             : {0}" -f (
                Get-AxiosProperty -Value $Time -Name "utc_offset" -Default "unknown"
            )
        )
        Write-Host (
            "Windows Time service   : {0}" -f (
                Get-AxiosProperty -Value $TimeService -Name "status" -Default "unknown"
            )
        )
        Write-Host (
            "Time synchronization   : {0}" -f (
                Get-AxiosProperty -Value $Time -Name "synchronization_state" -Default "unknown"
            )
        )
        Write-Host (
            "Culture                : {0}" -f (
                Get-AxiosProperty -Value $Culture -Name "Name" -Default "unknown"
            )
        )
        Write-Host (
            "UI language            : {0}" -f (
                Get-AxiosProperty -Value $UiCulture -Name "Name" -Default "unknown"
            )
        )
        Write-Host (
            "Home location          : {0}" -f (
                Get-AxiosProperty -Value $Region -Name "HomeLocation" -Default "unknown"
            )
        )

        foreach ($Profile in $Profiles) {
            Write-Host (
                "Network profile        : {0}; {1}; {2}" -f
                (Get-AxiosProperty -Value $Profile -Name "Name" -Default "unknown"),
                (Get-AxiosProperty -Value $Profile -Name "InterfaceAlias" -Default "unknown"),
                (Get-AxiosProperty -Value $Profile -Name "network_category" -Default "unknown")
            )
        }

        foreach ($Interface in $Interfaces) {
            Write-Host (
                "Interface              : {0}; {1}; IPv4={2}; gateway={3}; DNS={4}" -f
                (Get-AxiosProperty -Value $Interface -Name "InterfaceAlias" -Default "unknown"),
                (Get-AxiosProperty -Value $Interface -Name "adapter_status" -Default "unknown"),
                (@(Get-AxiosProperty -Value $Interface -Name "ipv4_addresses" -Default @()) -join ","),
                (@(Get-AxiosProperty -Value $Interface -Name "ipv4_gateway" -Default @()) -join ","),
                (@(Get-AxiosProperty -Value $Interface -Name "dns_servers" -Default @()) -join ",")
            )
        }
    }

    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "SECURITY CONTROL STATE" `
        -Underline "-"

    if ($Signals.Count -eq 0) {
        Write-Host "None observed in the bounded Quick scope."
    }
    else {
        foreach ($Signal in $Signals) {
            Write-Host $Signal
        }
    }

    Write-Host ""
    Write-AxiosConsoleHeading `
        -Title "VISIBILITY LIMITATIONS" `
        -Underline "-"

    $Gaps = @(
        foreach ($Item in $SecurityErrors) {
            "security-posture: $Item"
        }

        foreach ($Item in $NetworkErrors) {
            "network-posture: $Item"
        }

        foreach ($Item in $ContextErrors) {
            "context-posture: $Item"
        }
    )

    if ($Gaps.Count -eq 0) {
        Write-Host "None."
    }
    else {
        foreach ($Gap in $Gaps) {
            Write-Host ("- {0}" -f $Gap)
        }
    }

    $Builder = [System.Text.StringBuilder]::new()
    $null = $Builder.AppendLine("RAPID SECURITY ASSESSMENT - COMPLETE TECHNICAL REPORT")
    $null = $Builder.AppendLine("Generated UTC: $([DateTime]::UtcNow.ToString('o'))")
    $null = $Builder.AppendLine("Collection status: $Status")
    $null = $Builder.AppendLine("Security state: $SecurityState")
    $null = $Builder.AppendLine("")

    foreach ($Entry in $ReportData.GetEnumerator()) {
        $null = $Builder.AppendLine(
            "================================================================"
        )
        $null = $Builder.AppendLine(
            ("REPORT: {0}" -f $Entry.Key)
        )
        $null = $Builder.AppendLine(
            "================================================================"
        )
        $null = $Builder.AppendLine(
            (
                $Entry.Value |
                    ConvertTo-Json -Depth 30
            )
        )
        $null = $Builder.AppendLine("")
    }

    $null = $Builder.AppendLine(
        "================================================================"
    )
    $null = $Builder.AppendLine("LAYER CORRELATION RESULT")
    $null = $Builder.AppendLine(
        "================================================================"
    )
    $null = $Builder.AppendLine(
        (
            $LayerResult |
                ConvertTo-Json -Depth 30
        )
    )

    [System.IO.File]::WriteAllText(
        $DetailedReportPath,
        $Builder.ToString(),
        $Encoding
    )

    if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
        Write-Host ""
        Write-AxiosConsoleHeading `
            -Title "OUTPUT" `
            -Underline "-"
        Write-Host ("Detailed TXT report    : {0}" -f $DetailedReportPath)
        Write-Host ("Structured JSON result : {0}" -f $ResultPath)
        Write-Host ("Raw evidence directory : {0}" -f $LayerResult.output)
        Write-Host ""
    }
} 

if (-not (Test-Path -LiteralPath $Core -PathType Leaf)) {
    throw "AXIOS core executable was not found: $Core"
}

$Commands = switch ($Layer) {
    "Quick" {
        @(
            "security-posture",
            "health-posture",
            "live-activity",
            "network-posture",
            "context-posture"
        )
    }

    "System" {
        @(
            "hardware-trust",
            "kernel-posture",
            "security-posture",
            "health-posture"
        )
    }

    "Persistence" {
        @(
            "registry-persistence",
            "extended-persistence",
            "persistence-coverage"
        )
    }

    "Software" {
        @(
            "software-inventory",
            "updates",
            "browser-extensions",
            "deep-investigation"
        )
    }

    "Context" {
        @(
            "context-posture"
        )
    }
}

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
$LayerName = $Layer.ToLowerInvariant()
$RunDirectory = Join-Path `
    $OutputDirectory `
    "AXIOS-$Layer-Layer-$Stamp"

$null = New-Item `
    -ItemType Directory `
    -Path $RunDirectory `
    -Force

$Reports = [System.Collections.Generic.List[object]]::new()
$ReportData = [ordered]@{}
$AllFindings = [System.Collections.Generic.List[object]]::new()
$AllContextObservations = [System.Collections.Generic.List[object]]::new()
$AllErrors = [System.Collections.Generic.List[string]]::new()

foreach ($Command in $Commands) {
    $Destination = Join-Path `
        $RunDirectory `
        "$Command.json"

    $Report = Invoke-AxiosCoreReport `
        -Command $Command `
        -Destination $Destination

    $ReportData[$Command] = $Report

    $Success = Get-AxiosProperty `
        -Value $Report `
        -Name "success" `
        -Default $false

    $Status = Get-AxiosProperty `
        -Value $Report `
        -Name "collection_status" `
        -Default "unknown"

    $Findings = @(
        Get-AxiosProperty `
            -Value $Report `
            -Name "findings" `
            -Default @()
    )

    $Errors = @(
        Get-AxiosProperty `
            -Value $Report `
            -Name "collection_errors" `
            -Default @()
    )

    if ($Status -eq "unknown") {
        if ($Success -eq $true -and $Errors.Count -eq 0) {
            $Status = "complete"
        }
        elseif ($Success -eq $true) {
            $Status = "partial"
        }
        else {
            $Status = "failed"
        }
    }

    $ContextFindings = @(
        $Findings |
            Where-Object {
                (
                    Get-AxiosProperty `
                        -Value $_ `
                        -Name "classification" `
                        -Default ""
                ) -eq "context"
            }
    )

    $ImportantFindings = @(
        $Findings |
            Where-Object {
                (
                    Get-AxiosProperty `
                        -Value $_ `
                        -Name "classification" `
                        -Default ""
                ) -ne "context"
            }
    )

    foreach ($Finding in $ImportantFindings) {
        if ($AllFindings.Count -lt 500) {
            $AllFindings.Add($Finding)
        }
    }

    foreach ($Observation in $ContextFindings) {
        if ($AllContextObservations.Count -lt 500) {
            $AllContextObservations.Add($Observation)
        }
    }

    foreach ($ErrorItem in $Errors) {
        if ($AllErrors.Count -lt 500) {
            $AllErrors.Add(
                "$Command`: $([string]$ErrorItem)"
            )
        }
    }

    $Reports.Add([PSCustomObject]@{
        command = $Command
        success = [bool]$Success
        collection_status = [string]$Status
        findings = $ImportantFindings.Count
        context_observations = $ContextFindings.Count
        collection_errors = $Errors.Count
        path = $Destination
    })
}

if ($Layer -eq "System") {
    $SystemSecurity = $ReportData["security-posture"]

    $SystemDefender = Get-AxiosProperty `
        -Value $SystemSecurity `
        -Name "defender_status"

    $SystemSecureBoot = Get-AxiosProperty `
        -Value $SystemSecurity `
        -Name "secure_boot"

    $SystemUac = Get-AxiosProperty `
        -Value $SystemSecurity `
        -Name "uac"

    $SystemAntivirus = Get-AxiosProperty `
        -Value $SystemDefender `
        -Name "antivirus_enabled"

    $SystemRealtime = Get-AxiosProperty `
        -Value $SystemDefender `
        -Name "real_time_protection_enabled"

    $SystemBehavior = Get-AxiosProperty `
        -Value $SystemDefender `
        -Name "behavior_monitor_enabled"

    $SystemIoav = Get-AxiosProperty `
        -Value $SystemDefender `
        -Name "ioav_protection_enabled"

    $SystemTamperSource = Get-AxiosProperty `
        -Value $SystemDefender `
        -Name "tamper_protection_source"

    $SystemTamperProtected = if (
        $SystemTamperSource -is [bool]
    ) {
        [bool]$SystemTamperSource
    }
    elseif (
        [string]$SystemTamperSource -match
        '^(?i:true|false)$'
    ) {
        [System.Convert]::ToBoolean([string]$SystemTamperSource)
    }
    else {
        $null
    }

    $SystemSecureBootAvailable = Get-AxiosProperty `
        -Value $SystemSecureBoot `
        -Name "available"

    $SystemSecureBootEnabled = Get-AxiosProperty `
        -Value $SystemSecureBoot `
        -Name "enabled"

    $SystemEnableLua = Get-AxiosProperty `
        -Value $SystemUac `
        -Name "enable_lua"

    if ($SystemAntivirus -eq $false) {
        $AllFindings.Add([PSCustomObject]@{
            severity = "high"
            classification = "confirmed_control_state"
            title = "Registered antivirus protection is disabled"
            evidence_source = "security-posture"
        })
    }

    if ($SystemRealtime -eq $false) {
        $AllFindings.Add([PSCustomObject]@{
            severity = "high"
            classification = "confirmed_control_state"
            title = "Microsoft Defender real-time protection is disabled"
            evidence_source = "security-posture"
        })
    }

    if ($SystemBehavior -eq $false) {
        $AllFindings.Add([PSCustomObject]@{
            severity = "high"
            classification = "confirmed_control_state"
            title = "Defender behavior monitoring is disabled"
            evidence_source = "security-posture"
        })
    }

    if ($SystemIoav -eq $false) {
        $AllFindings.Add([PSCustomObject]@{
            severity = "medium"
            classification = "confirmed_control_state"
            title = "Defender downloaded-file inspection is disabled"
            evidence_source = "security-posture"
        })
    }

    if ($SystemTamperProtected -eq $false) {
        $AllFindings.Add([PSCustomObject]@{
            severity = "high"
            classification = "confirmed_control_state"
            title = "Microsoft Defender tamper protection is disabled"
            evidence_source = "security-posture"
        })
    }

    if (
        $SystemSecureBootAvailable -eq $true -and
        $SystemSecureBootEnabled -eq $false
    ) {
        $AllFindings.Add([PSCustomObject]@{
            severity = "high"
            classification = "confirmed_control_state"
            title = "Secure Boot is explicitly disabled"
            evidence_source = "security-posture"
        })
    }

    if ($SystemEnableLua -eq 0) {
        $AllFindings.Add([PSCustomObject]@{
            severity = "high"
            classification = "confirmed_control_state"
            title = "User Account Control is disabled"
            evidence_source = "security-posture"
        })
    }
}

if ($Layer -eq "Software") {
    $SoftwareUpdates = $ReportData["updates"]
    $SoftwareDefender = Get-AxiosProperty `
        -Value $SoftwareUpdates `
        -Name "defender"
    $SoftwareTamper = Get-AxiosProperty `
        -Value $SoftwareDefender `
        -Name "tamper_protected"

    if ($SoftwareTamper -eq $false) {
        $AllFindings.Add([PSCustomObject]@{
            severity = "high"
            classification = "confirmed_control_state"
            title = "Microsoft Defender tamper protection is disabled"
            evidence_source = "updates"
        })
    }
}
    
    $Failed = @(
        $Reports |
            Where-Object {
                $_.success -ne $true
            }
    )
    
    $Partial = @(
        $Reports |
            Where-Object {
                $_.collection_status -ne "complete"
            }
    )
    
    $CollectionStatus = if ($Failed.Count -gt 0) {
        "failed"
    }
    elseif ($Partial.Count -gt 0) {
        "partial"
    }
    else {
        "complete"
    }
    
    $LayerResult = [ordered]@{
        success = ($Failed.Count -eq 0)
        collector = "axios_$LayerName`_layer"
        collection_status = $CollectionStatus
        generated_at_utc = (
            Get-Date
        ).ToUniversalTime().ToString("o")
        layer = $LayerName
        reports = $Reports
        findings = $AllFindings
        context_observations = $AllContextObservations
        collection_errors = $AllErrors
        summary = [ordered]@{
            reports = $Reports.Count
            reports_failed = $Failed.Count
            reports_partial = $Partial.Count
            findings = $AllFindings.Count
            context_observations = $AllContextObservations.Count
            collection_errors = $AllErrors.Count
        }
        output = $RunDirectory
    }
    
    $ResultPath = Join-Path `
        $OutputDirectory `
        "AXIOS-Layer-$Layer-$Stamp.json"
    
    Write-AxiosJson -Path $ResultPath -Value $LayerResult
    
    $DetailedReportPath = $null
    
    if ($Layer -eq "Quick") {
        $DetailedReportPath = Join-Path `
            $OutputDirectory `
            "AXIOS-Quick-Details-$Stamp.txt"
    
        Write-AxiosQuickHumanReport `
            -LayerResult $LayerResult `
            -ReportData $ReportData `
            -DetailedReportPath $DetailedReportPath `
            -ResultPath $ResultPath `
            -Encoding $AxiosUtf8
    }
    elseif ($Layer -eq "Context") {
        $DetailedReportPath = Join-Path `
            $OutputDirectory `
            "AXIOS-Context-Details-$Stamp.txt"
    
        Write-AxiosContextHumanReport `
            -Report ($ReportData["context-posture"]) `
            -DetailedReportPath $DetailedReportPath `
            -ResultPath $ResultPath `
            -Encoding $AxiosUtf8
    }
    elseif ($Layer -in @("System", "Persistence", "Software")) {
        $DetailedReportPath = Join-Path `
            $OutputDirectory `
            "AXIOS-$Layer-Details-$Stamp.txt"
    
        Write-AxiosLayerHumanReport `
            -LayerResult $LayerResult `
            -ReportData $ReportData `
            -DetailedReportPath $DetailedReportPath `
            -ResultPath $ResultPath `
            -Encoding $AxiosUtf8
    }
    
    $Size = (Get-Item -LiteralPath $ResultPath).Length
    
    if ($Size -gt 2500000) {
        throw "AXIOS layer result exceeded 2500000 bytes: $Size"
    }
    
    if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
        [ordered]@{
            success = $LayerResult.success
            collector = $LayerResult.collector
            collection_status = $LayerResult.collection_status
            reports = $Reports.Count
            reports_failed = $Failed.Count
            findings = $AllFindings.Count
            context_observations = $AllContextObservations.Count
            control_signals = (
                Get-AxiosProperty `
                    -Value $LayerResult.summary `
                    -Name "control_signals" `
                    -Default 0
            )
            collection_errors = $AllErrors.Count
            output = $RunDirectory
            result = $ResultPath
            detailed_report = $DetailedReportPath
            size_bytes = $Size
        } | ConvertTo-Json -Depth 6 -Compress
    }
