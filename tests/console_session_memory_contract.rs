const LAUNCHER: &str = include_str!("../installer/windows/Run-AXIOS.ps1");
const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");
const USER: &str = include_str!("../installer/windows/Run-AXIOS-Standard-User-Audit.ps1");
const DEVELOPER: &str = include_str!("../installer/windows/Run-AXIOS-Developer-Exposure-View.ps1");
const SECURITY: &str = include_str!("../src/system/security_posture.rs");
const NETWORK: &str = include_str!("../installer/windows/Run-AXIOS-Network-Deep-Review.ps1");

#[test]
fn console_results_survive_until_the_powershell_session_exits() {
    assert!(LAUNCHER.contains("AXIOS_SESSION_DIRECTORY"));
    assert!(LAUNCHER.contains("Register-EngineEvent"));
    assert!(LAUNCHER.contains("PowerShell.Exiting"));
    assert!(LAUNCHER.contains("AXIOS-Session-{0}"));
    assert!(LAUNCHER.contains("AddDays(-1)"));
    assert!(!LAUNCHER.contains("$TemporaryOutputDirectory"));
}

#[test]
fn results_search_session_memory_before_saved_download_results() {
    assert!(LAUNCHER.contains("$SessionOutputDirectory,"));
    assert!(LAUNCHER.contains("$RequestedOutputDirectory"));
    assert!(LAYER.contains("foreach ($SearchDirectory in $ResultSearchDirectory)"));
}

#[test]
fn standard_user_console_displays_decisions_not_machine_flags() {
    assert!(USER.contains("SECURITY FINDINGS"));
    assert!(USER.contains("VISIBILITY LIMITATIONS"));
    assert!(!USER.contains("Write-Host \"RECOMMENDED ACTIONS\""));
    assert!(!USER.contains("Write-Host (\"Response actions"));
    assert!(USER.contains("Write-AxiosEvidenceRows"));
    assert!(USER.contains("-Value $Finding"));
    assert!(USER.contains("$env:AXIOS_CONSOLE_SESSION -ne \"1\""));
}

#[test]
fn results_display_evidence_rows_without_console_file_paths() {
    assert!(LAYER.contains("VERIFIED SECURITY FINDINGS"));
    assert!(LAYER.contains("COLLECTION COVERAGE"));
    assert!(LAYER.contains("$Evidence.PSObject.Properties"));
    assert!(LAYER.contains("$env:AXIOS_CONSOLE_SESSION -ne \"1\""));
}

#[test]
fn session_results_hide_internal_paths_and_machine_receipts() {
    assert!(LAYER.contains("Assessment             :"));
    assert!(LAYER.contains("$env:AXIOS_CONSOLE_SESSION -ne \"1\""));
    assert!(LAYER.contains("Source result"));
    assert!(LAYER.contains("ConvertTo-Json -Depth 12 -Compress"));
}

#[test]
fn developer_output_is_concise_and_verified_self_activity_is_suppressed() {
    assert!(DEVELOPER.contains("Get-AxiosTrustedPackageHashes"));
    assert!(DEVELOPER.contains("Get-FileHash"));
    assert!(DEVELOPER.contains("SHA256SUMS.txt"));
    assert!(DEVELOPER.contains("Verified self activity"));
    assert!(DEVELOPER.contains("ADVANCED EXPOSURE ASSESSMENT"));
    assert!(DEVELOPER.contains("SYSTEM AND SECURITY PROFILE"));
    assert!(DEVELOPER.contains("CONFIGURATION EXPOSURES"));
    assert!(DEVELOPER.contains("VISIBILITY LIMITATIONS"));
    assert!(DEVELOPER.contains("Finding class"));
    assert!(DEVELOPER.contains("Evidence source"));
    assert!(DEVELOPER.contains("Verification"));
    assert!(!DEVELOPER.contains("Write-Host (\"EVIDENCE={0}\""));
}

#[test]
fn unavailable_secure_boot_state_remains_unknown() {
    assert!(SECURITY.contains("$secureBoot = Get-AxiosObservedValue \"secure_boot\""));
    assert!(SECURITY.contains("available = $null\n    enabled = $null"));
}

#[test]
fn results_include_developer_exposure_and_never_print_empty_priority() {
    assert!(LAYER.contains("\"AXIOS-Developer-Exposure-*.json\""));
    assert!(LAYER.contains("-Name \"collection_gaps\""));
    assert!(LAYER.contains("$Priority = \"review\""));
    assert!(LAYER.contains("$Priority = \"context\""));
}

#[test]
fn user_mode_displays_collected_data_even_without_findings() {
    assert!(USER.contains("SYSTEM VISIBILITY"));
    assert!(USER.contains("OBSERVED SECURITY DATA"));
    assert!(USER.contains("$Network.collection_status"));
    assert!(USER.contains("$Scope.collection_status"));
    assert!(USER.contains("$Exposure.collection_status"));
    assert!(!USER.contains("Write-Host \"RECOMMENDED ACTIONS\""));
}

#[test]
fn user_collected_data_supports_reports_without_summary_objects() {
    assert!(USER.contains("$CoverageReport.Report.PSObject.Properties.Name -contains \"summary\""));
    assert!(USER.contains("$DisplaySource = $CoverageReport.Report"));
    assert!(USER.contains("$CoverageReport.Report.PSObject.Properties.Name -contains \"summary\""));
}

#[test]
fn results_flatten_structured_gaps_and_skip_empty_titles() {
    assert!(LAYER.contains("$NormalizedErrors ="));
    assert!(LAYER.contains("[System.Collections.Generic.List[string]]::new()"));
    assert!(LAYER.contains("function Add-AxiosCoverageMessage"));
    assert!(LAYER.contains("Add-AxiosCoverageMessage -Value $RawError"));
    assert!(LAYER.contains("$Value.PSObject.Properties"));
    assert!(LAYER.contains("$HiddenCoverageFields"));
    assert!(LAYER.contains("Add-AxiosCoverageMessage `"));
    assert!(LAYER.contains("\"title\","));
    assert!(LAYER.contains("\"label\","));
    assert!(LAYER.contains("\"finding\","));
    assert!(LAYER.contains("$Title = $Title -replace \"_\", \" \""));
}

#[test]
fn results_use_professional_grouped_security_reporting() {
    for heading in [
        "SECURITY ASSESSMENT SUMMARY",
        "VERIFIED SECURITY FINDINGS",
        "BOOT AND PLATFORM TRUST",
        "SECURITY CONTROLS",
        "IDENTITY AND ACCESS",
        "APPLICATION SECURITY",
        "NETWORK SECURITY",
        "COLLECTION COVERAGE",
        "UNRESOLVED VERIFICATION",
    ] {
        assert!(
            LAYER.contains(heading),
            "missing professional results section: {heading}"
        );
    }

    assert!(LAYER.contains("$VerificationState"));
    assert!(!LAYER.contains("Unresolved localized name"));
    assert!(LAYER.contains("$DisplayFindings"));
    assert!(LAYER.contains("Sort-Object Domain"));
    assert!(!LAYER.contains("Write-Host \"AXIOS LATEST RESULT\""));
}

#[test]
fn results_separate_context_priority_from_important_findings() {
    assert!(LAYER.contains("$Priority -eq \"context\""));
    assert!(LAYER.contains("$ContextFindings.Count"));
    assert!(LAYER.contains("\"FORENSIC VISIBILITY\""));
    assert!(LAYER.contains("\"COLLECTION COVERAGE\""));
}

#[test]
fn human_headings_use_title_length_separators() {
    assert!(LAYER.contains("Write-Host (\"=\" * $SummaryHeading.Length)"));
    assert!(LAYER.contains("Write-Host (\"=\" * $FindingsHeading.Length)"));
}

#[test]
fn standard_user_renderer_preserves_words_and_hides_internal_properties() {
    assert!(USER.contains("$Text = $Text -creplace \"([a-z0-9])([A-Z])\""));
    assert!(USER.contains("\"PSComputerName\""));
    assert!(USER.contains("\"RunspaceId\""));
    assert!(USER.contains("$ItemDisplayValue"));
}

#[test]
fn results_deduplicate_findings_and_preserve_all_sources() {
    assert!(LAYER.contains("$UniqueImportantFindings"));
    assert!(LAYER.contains("\"evidence_sources\""));
    assert!(LAYER.contains("$CandidateEvidenceCount"));
    assert!(LAYER.contains("$ExistingEvidenceCount"));
}

#[test]
fn results_render_structured_evidence_without_raw_powershell_objects() {
    assert!(LAYER.contains("function Write-AxiosResultEvidenceValue"));
    assert!(LAYER.contains("$NestedProperty.Value"));
    assert!(LAYER.contains("structured evidence"));
    assert!(!LAYER.contains("$Value = [string]$Property.Value"));
}

#[test]
fn developer_context_is_derived_from_actual_windows_token() {
    assert!(DEVELOPER.contains("$IsAdministrator"));
    assert!(DEVELOPER.contains("$AxiosExecutionContext"));
    assert!(!DEVELOPER.contains("Execution context      : Standard user"));
}

#[test]
fn developer_self_activity_is_verified_by_packaged_binary_hash() {
    assert!(DEVELOPER.contains("$ManifestKey"));
    assert!(DEVELOPER.contains(r#""bin\{0}" -f $FileName"#));
    assert!(DEVELOPER.contains("$ActualHash -eq $ExpectedHash"));
}

#[test]
fn results_expand_structured_arrays_instead_of_only_counting_them() {
    assert!(LAYER.contains("$ItemProperty.Value"));
    assert!(LAYER.contains("$ItemIndex += 1"));
    assert!(LAYER.contains("structured item(s)"));
}

#[test]
fn developer_property_names_use_case_sensitive_camel_case_splitting() {
    assert!(DEVELOPER.contains("-creplace"));
    assert!(!DEVELOPER.contains("$Text = $Text -replace \"([a-z])([A-Z])\""));
}

#[test]
fn every_console_mode_hides_paths_and_machine_receipts_by_default() {
    assert!(
        LAYER
            .matches("$env:AXIOS_CONSOLE_SESSION -ne \"1\"")
            .count()
            >= 5
    );
    assert!(
        NETWORK
            .matches("$env:AXIOS_CONSOLE_SESSION -ne \"1\"")
            .count()
            >= 2
    );
    assert!(USER.matches("$env:AXIOS_CONSOLE_SESSION -ne \"1\"").count() >= 2);
}
