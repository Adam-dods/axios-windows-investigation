#[cfg(windows)]
use anyhow::bail;
use anyhow::Result;
#[cfg(windows)]
use axios_core::command::{parse_json_output, powershell};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "axios-admin-exposure-audit")]
struct Options {
    #[arg(long, default_value_t = 4096)]
    max_services: usize,
    #[arg(long, default_value_t = 4096)]
    max_tasks: usize,
    #[arg(long, default_value_t = 4096)]
    max_drivers: usize,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();
    validate_limit("max-services", options.max_services)?;
    validate_limit("max-tasks", options.max_tasks)?;
    validate_limit("max-drivers", options.max_drivers)?;

    let snapshot = collect_snapshot(options.max_services, options.max_tasks, options.max_drivers)?;
    let report = build_report(&snapshot);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

fn validate_limit(name: &str, value: usize) -> Result<()> {
    if value == 0 || value > 16_384 {
        anyhow::bail!("{name} must be between 1 and 16384");
    }
    Ok(())
}

#[cfg(windows)]
fn collect_snapshot(max_services: usize, max_tasks: usize, max_drivers: usize) -> Result<Value> {
    let script = ADMIN_EXPOSURE_SCRIPT
        .replace("__MAX_SERVICES__", &max_services.to_string())
        .replace("__MAX_TASKS__", &max_tasks.to_string())
        .replace("__MAX_DRIVERS__", &max_drivers.to_string());

    let output = powershell(&script)?;
    if !output.success {
        bail!("administrator exposure collector failed: {}", output.stderr);
    }

    let report = parse_json_output(output);
    if report.get("success").and_then(Value::as_bool) != Some(true) {
        bail!(
            "administrator exposure collector returned an unsuccessful report: {}",
            report
        );
    }
    Ok(report)
}

#[cfg(not(windows))]
fn collect_snapshot(_max_services: usize, _max_tasks: usize, _max_drivers: usize) -> Result<Value> {
    Ok(json!({
        "success": false,
        "collector": "axios_admin_exposure_audit",
        "collection_status": "windows_only",
        "collection_errors": ["administrator exposure collection requires Windows"],
        "findings": []
    }))
}

fn build_report(snapshot: &Value) -> Value {
    if snapshot.get("success").and_then(Value::as_bool) != Some(true) {
        return json!({
            "success": false,
            "collector": "axios_admin_exposure_audit",
            "collection_status": snapshot
                .get("collection_status")
                .cloned()
                .unwrap_or_else(|| json!("failed")),
            "collection_errors": snapshot
                .get("collection_errors")
                .cloned()
                .unwrap_or_else(|| json!(["collector did not return success=true"])),
            "findings": [],
            "malware_confirmed": false,
            "intrusion_confirmed": false,
            "privilege_escalation_confirmed": false
        });
    }

    let mut findings = snapshot
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    findings.retain(|finding| {
        if finding.get("id").and_then(Value::as_str)
            != Some("unquoted_service_path_writable_candidate")
        {
            return true;
        }

        finding
            .pointer("/evidence/command_line")
            .and_then(Value::as_str)
            .is_some_and(is_unquoted_service_command)
    });

    let mut seen = HashSet::new();
    findings.retain(|finding| seen.insert(finding_key(finding)));
    findings.sort_by_key(|finding| {
        (
            priority_rank(finding.get("priority").and_then(Value::as_str)),
            finding
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            finding_key(finding),
        )
    });

    let high = findings
        .iter()
        .filter(|finding| finding.get("priority").and_then(Value::as_str) == Some("high"))
        .count();
    let medium = findings
        .iter()
        .filter(|finding| finding.get("priority").and_then(Value::as_str) == Some("medium"))
        .count();
    let context = findings
        .iter()
        .filter(|finding| finding.get("priority").and_then(Value::as_str) == Some("context"))
        .count();

    let mut report = snapshot.clone();
    if let Some(object) = report.as_object_mut() {
        object.insert("success".to_string(), json!(true));
        object.insert("collector".to_string(), json!("axios_admin_exposure_audit"));
        object.insert("findings".to_string(), Value::Array(findings));
        object.insert("malware_confirmed".to_string(), json!(false));
        object.insert("intrusion_confirmed".to_string(), json!(false));
        object.insert("privilege_escalation_confirmed".to_string(), json!(false));

        let summary = object.entry("summary").or_insert_with(|| json!({}));
        if !summary.is_object() {
            *summary = json!({});
        }
        if let Some(summary) = summary.as_object_mut() {
            summary.insert("findings".to_string(), json!(high + medium + context));
            summary.insert("high_priority_findings".to_string(), json!(high));
            summary.insert("medium_priority_findings".to_string(), json!(medium));
            summary.insert("context_findings".to_string(), json!(context));
        }
    }

    report
}

fn priority_rank(priority: Option<&str>) -> u8 {
    match priority {
        Some("high") => 0,
        Some("medium") => 1,
        _ => 2,
    }
}

fn finding_key(finding: &Value) -> String {
    let id = finding.get("id").and_then(Value::as_str).unwrap_or("");
    let service = finding
        .pointer("/evidence/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let task = finding
        .pointer("/evidence/task_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let driver = finding
        .pointer("/evidence/driver_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let path = finding
        .pointer("/evidence/executable_path")
        .or_else(|| finding.pointer("/evidence/image_path"))
        .and_then(Value::as_str)
        .unwrap_or("");

    format!(
        "{}|{}|{}|{}|{}",
        id.to_ascii_lowercase(),
        service.to_ascii_lowercase(),
        task.to_ascii_lowercase(),
        driver.to_ascii_lowercase(),
        path.replace('/', "\\").to_ascii_lowercase()
    )
}

fn is_unquoted_service_command(command_line: &str) -> bool {
    let command = command_line.trim();
    if command.is_empty() || command.starts_with('"') {
        return false;
    }

    executable_from_command(command).is_some_and(|path| path.chars().any(char::is_whitespace))
}

fn executable_from_command(command: &str) -> Option<&str> {
    let lower = command.to_ascii_lowercase();
    let mut best_end = None;
    for extension in [".exe", ".com", ".bat", ".cmd", ".ps1", ".sys"] {
        if let Some(index) = lower.find(extension) {
            let end = index + extension.len();
            best_end = Some(best_end.map_or(end, |current: usize| current.min(end)));
        }
    }
    best_end.map(|end| command[..end].trim())
}

#[cfg(windows)]
const ADMIN_EXPOSURE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$collectionErrors = [System.Collections.Generic.List[string]]::new()
$fileAclCache = @{}
$registryAclCache = @{}
$lowPrivilegeSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
$totalTimer = [Diagnostics.Stopwatch]::StartNew()

function Add-AxiosCollectionError {
    param([string]$Source, [object]$Failure)

    $message = if ($null -ne $Failure.Exception) {
        $Failure.Exception.Message
    }
    else {
        [string]$Failure
    }
    $collectionErrors.Add(('{0}: {1}' -f $Source, $message))
}

function Get-AxiosIdentitySid {
    param([object]$IdentityReference)

    try {
        return $IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
    }
    catch {
        return [string]$IdentityReference
    }
}

function Get-AxiosExecutablePath {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $null
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine).Trim()
    if ($expanded.StartsWith('"')) {
        $quoted = [regex]::Match($expanded, '^"([^"]+)"')
        if ($quoted.Success) {
            return $quoted.Groups[1].Value
        }
        return $null
    }

    $match = [regex]::Match(
        $expanded,
        '^(.*?\.(?:exe|com|bat|cmd|ps1|sys))(?=\s|$)',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if ($match.Success) {
        return $match.Groups[1].Value.Trim()
    }

    return $null
}

function Resolve-AxiosExecutablePath {
    param([string]$CommandLine)

    $path = Get-AxiosExecutablePath $CommandLine
    if ([string]::IsNullOrWhiteSpace($path)) {
        return $null
    }

    $path = [Environment]::ExpandEnvironmentVariables($path).Trim('"')
    if ($path -match '^\\SystemRoot\\') {
        $path = Join-Path $env:SystemRoot $path.Substring(12)
    }
    elseif ($path -match '^\\\?\?\\') {
        $path = $path.Substring(4)
    }
    if ([IO.Path]::IsPathRooted($path)) {
        return $path
    }

    try {
        $command = Get-Command -Name $path -CommandType Application -ErrorAction Stop |
            Select-Object -First 1
        return $command.Source
    }
    catch {
        return $path
    }
}

function Get-AxiosExecutionTier {
    param([string]$Principal)

    if ($Principal -match '(?i)^(NT AUTHORITY\\SYSTEM|SYSTEM|LocalSystem)$') {
        return 'system'
    }
    if ($Principal -match '(?i)LocalService|NetworkService') {
        return 'service_account'
    }
    if ([string]::IsNullOrWhiteSpace($Principal)) {
        return 'unknown'
    }
    return 'user_or_custom_account'
}

function Get-AxiosExposurePriority {
    param([string]$ExecutionTier)

    if ($ExecutionTier -eq 'system') {
        return 'high'
    }
    return 'medium'
}

function Get-AxiosFileAclAssessment {
    param([string]$Path, [string]$Source)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [PSCustomObject]@{
            path = $Path
            status = 'unresolved'
            potential_broad_write = $false
            matching_rules = @()
        }
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($Path).Trim('"')
    $key = $expanded.ToLowerInvariant()
    if ($fileAclCache.ContainsKey($key)) {
        return $fileAclCache[$key]
    }

    if (-not (Test-Path -LiteralPath $expanded)) {
        $result = [PSCustomObject]@{
            path = $expanded
            status = 'not_found'
            potential_broad_write = $false
            matching_rules = @()
        }
        $fileAclCache[$key] = $result
        return $result
    }

    try {
        $acl = Get-Acl -LiteralPath $expanded -ErrorAction Stop
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        $writeMask = [int][System.Security.AccessControl.FileSystemRights]::WriteData -bor
            [int][System.Security.AccessControl.FileSystemRights]::AppendData -bor
            [int][System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
            [int][System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
            [int][System.Security.AccessControl.FileSystemRights]::Delete -bor
            [int][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [int][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [int][System.Security.AccessControl.FileSystemRights]::TakeOwnership

        $allow = 0
        $deny = 0
        $matching = @(
            foreach ($rule in $rules) {
                $sid = Get-AxiosIdentitySid $rule.IdentityReference
                if ($lowPrivilegeSids -notcontains $sid) {
                    continue
                }
                $rights = [int]$rule.FileSystemRights -band $writeMask
                if ($rights -eq 0) {
                    continue
                }
                if ($rule.AccessControlType -eq 'Deny') {
                    $deny = $deny -bor $rights
                }
                else {
                    $allow = $allow -bor $rights
                }
                [PSCustomObject]@{
                    sid = $sid
                    rights = [string]$rule.FileSystemRights
                    access = [string]$rule.AccessControlType
                    inherited = $rule.IsInherited
                }
            }
        )

        $effective = $allow -band (-bnot $deny)
        $result = [PSCustomObject]@{
            path = $expanded
            status = 'observed'
            potential_broad_write = ($effective -ne 0)
            matching_rules = $matching
        }
    }
    catch {
        Add-AxiosCollectionError $Source $_
        $result = [PSCustomObject]@{
            path = $expanded
            status = 'access_error'
            potential_broad_write = $false
            matching_rules = @()
        }
    }

    $fileAclCache[$key] = $result
    return $result
}

function Get-AxiosRegistryAclAssessment {
    param([string]$RegistryPath, [string]$Source)

    if ([string]::IsNullOrWhiteSpace($RegistryPath)) {
        return [PSCustomObject]@{
            path = $RegistryPath
            status = 'invalid_path'
            potential_broad_write = $false
            matching_rules = @()
        }
    }

    $key = $RegistryPath.ToLowerInvariant()

    if ($registryAclCache.ContainsKey($key)) {
        return $registryAclCache[$key]
    }

    $subKey = $RegistryPath

    foreach ($prefix in @(
        'Registry::HKEY_LOCAL_MACHINE\',
        'HKEY_LOCAL_MACHINE\',
        'HKLM:\'
    )) {
        if (
            $subKey.StartsWith(
                $prefix,
                [StringComparison]::OrdinalIgnoreCase
            )
        ) {
            $subKey = $subKey.Substring($prefix.Length)
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($subKey)) {
        $result = [PSCustomObject]@{
            path = $RegistryPath
            status = 'invalid_path'
            potential_broad_write = $false
            matching_rules = @()
        }

        $registryAclCache[$key] = $result
        return $result
    }

    $nativeKey = $null

    try {
        $nativeKey = (
            [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $subKey,
                $false
            )
        )

        if ($null -eq $nativeKey) {
            $result = [PSCustomObject]@{
                path = $RegistryPath
                native_subkey = $subKey
                status = 'not_found'
                potential_broad_write = $false
                matching_rules = @()
            }

            $registryAclCache[$key] = $result
            return $result
        }

        $acl = $nativeKey.GetAccessControl()

        $rules = @(
            $acl.GetAccessRules(
                $true,
                $true,
                [System.Security.Principal.SecurityIdentifier]
            )
        )

        $writeMask = (
            [int][System.Security.AccessControl.RegistryRights]::SetValue -bor
            [int][System.Security.AccessControl.RegistryRights]::CreateSubKey -bor
            [int][System.Security.AccessControl.RegistryRights]::Delete -bor
            [int][System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
            [int][System.Security.AccessControl.RegistryRights]::TakeOwnership
        )

        $allow = 0
        $deny = 0

        $matching = @(
            foreach ($rule in $rules) {
                $sid = Get-AxiosIdentitySid $rule.IdentityReference

                if ($lowPrivilegeSids -notcontains $sid) {
                    continue
                }

                $rights = (
                    [int]$rule.RegistryRights -band
                    $writeMask
                )

                if ($rights -eq 0) {
                    continue
                }

                if ($rule.AccessControlType -eq 'Deny') {
                    $deny = $deny -bor $rights
                }
                else {
                    $allow = $allow -bor $rights
                }

                [PSCustomObject]@{
                    sid = $sid
                    rights = [string]$rule.RegistryRights
                    access_type = [string]$rule.AccessControlType
                    inherited = [bool]$rule.IsInherited
                }
            }
        )

        $effective = $allow -band (-bnot $deny)

        $result = [PSCustomObject]@{
            path = $RegistryPath
            native_subkey = $subKey
            status = 'observed'
            potential_broad_write = ($effective -ne 0)
            matching_rules = $matching
        }
    }
    catch {
        Add-AxiosCollectionError $Source $_

        $result = [PSCustomObject]@{
            path = $RegistryPath
            native_subkey = $subKey
            status = 'access_error'
            potential_broad_write = $false
            matching_rules = @()
        }
    }
    finally {
        if ($null -ne $nativeKey) {
            $nativeKey.Dispose()
        }
    }

    $registryAclCache[$key] = $result
    return $result
}

function Get-AxiosServiceRegistryPath {
    param([string]$Name)

    $exact = 'HKLM:\SYSTEM\CurrentControlSet\Services\{0}' -f $Name
    if (Test-Path -LiteralPath $exact) {
        return $exact
    }

    if ($Name -match '^(?<base>.+)_[0-9a-f]{4,}$') {
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\{0}' -f $Matches.base
        if (Test-Path -LiteralPath $base) {
            return $base
        }
    }
    return $exact
}

function Get-AxiosUnquotedCandidates {
    param([string]$ExecutablePath)

    if ([string]::IsNullOrWhiteSpace($ExecutablePath) -or $ExecutablePath -notmatch '\s') {
        return @()
    }

    $items = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $ExecutablePath.Length; $index++) {
        if (-not [char]::IsWhiteSpace($ExecutablePath[$index])) {
            continue
        }
        $candidate = $ExecutablePath.Substring(0, $index) + '.exe'
        $parent = Split-Path -Parent $candidate
        $assessment = Get-AxiosFileAclAssessment $parent ('unquoted_parent:{0}' -f $candidate)
        $items.Add([PSCustomObject]@{
            candidate = $candidate
            parent = $parent
            parent_acl_status = $assessment.status
            parent_potential_broad_write = $assessment.potential_broad_write
            parent_matching_rules = $assessment.matching_rules
        })
    }
    return @($items)
}

$collectionTimer = [Diagnostics.Stopwatch]::StartNew()
$servicesAll = @()
try {
    $servicesAll = @(Get-CimInstance Win32_Service -ErrorAction Stop)
}
catch {
    Add-AxiosCollectionError 'services' $_
}
$services = @($servicesAll | Select-Object -First __MAX_SERVICES__)

$tasksAll = @()
try {
    $tasksAll = @(Get-ScheduledTask -ErrorAction Stop)
}
catch {
    Add-AxiosCollectionError 'scheduled_tasks' $_
}
$tasks = @($tasksAll | Select-Object -First __MAX_TASKS__)

$driversAll = @()
try {
    $driversAll = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop)
}
catch {
    Add-AxiosCollectionError 'system_drivers' $_
}
$drivers = @($driversAll | Select-Object -First __MAX_DRIVERS__)

$localAdministrators = @()
try {
    $localAdministrators = @(
        Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
            Select-Object Name, ObjectClass, PrincipalSource, SID
    )
}
catch {
    Add-AxiosCollectionError 'local_administrators' $_
}

$secureBoot = [PSCustomObject]@{ status = 'unknown'; enabled = $null }
try {
    $secureBoot = [PSCustomObject]@{
        status = 'observed'
        enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
    }
}
catch [System.PlatformNotSupportedException] {
    $secureBoot = [PSCustomObject]@{ status = 'unsupported_or_legacy_boot'; enabled = $null }
}
catch {
    Add-AxiosCollectionError 'secure_boot' $_
}

$deviceGuard = @()
try {
    $deviceGuard = @(
        Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
            -ClassName Win32_DeviceGuard -ErrorAction Stop |
            Select-Object VirtualizationBasedSecurityStatus,
                SecurityServicesConfigured, SecurityServicesRunning,
                AvailableSecurityProperties, RequiredSecurityProperties
    )
}
catch {
    Add-AxiosCollectionError 'device_guard' $_
}
$collectionTimer.Stop()
$analysisTimer = [Diagnostics.Stopwatch]::StartNew()

$findings = [System.Collections.Generic.List[object]]::new()
$serviceEvidence = [System.Collections.Generic.List[object]]::new()
$taskEvidence = [System.Collections.Generic.List[object]]::new()
$driverEvidence = [System.Collections.Generic.List[object]]::new()

foreach ($service in $services) {
    $commandLine = [Environment]::ExpandEnvironmentVariables([string]$service.PathName)
    $executablePath = Resolve-AxiosExecutablePath $commandLine
    $executionTier = Get-AxiosExecutionTier ([string]$service.StartName)
    $privileged = $executionTier -in @('system', 'service_account')
    $exposurePriority = Get-AxiosExposurePriority $executionTier
    $fileAcl = Get-AxiosFileAclAssessment $executablePath ('service_executable:{0}' -f $service.Name)
    $registryPath = Get-AxiosServiceRegistryPath ([string]$service.Name)
    $registryAcl = Get-AxiosRegistryAclAssessment $registryPath ('service_registry:{0}' -f $service.Name)
    $unquoted = -not [string]::IsNullOrWhiteSpace($commandLine) -and
        -not $commandLine.TrimStart().StartsWith('"') -and
        -not [string]::IsNullOrWhiteSpace($executablePath) -and
        $executablePath -match '\s'
    $unquotedCandidates = if ($unquoted) {
        @(Get-AxiosUnquotedCandidates $executablePath)
    }
    else {
        @()
    }
    $writableCandidates = @($unquotedCandidates | Where-Object { $_.parent_potential_broad_write })

    $evidence = [PSCustomObject]@{
        name = $service.Name
        display_name = $service.DisplayName
        start_mode = $service.StartMode
        state = $service.State
        start_name = $service.StartName
        execution_tier = $executionTier
        privileged_execution_context = $privileged
        command_line = $commandLine
        executable_path = $executablePath
        executable_acl = $fileAcl
        service_registry_path = $registryPath
        service_registry_acl = $registryAcl
        unquoted_path_with_spaces = $unquoted
        unquoted_candidates = $unquotedCandidates
    }
    $serviceEvidence.Add($evidence)

    if ($privileged -and $fileAcl.potential_broad_write) {
        $findings.Add([PSCustomObject]@{
            id = 'service_executable_broad_write_acl'
            priority = $exposurePriority
            confidence = 'medium'
            classification = 'privilege_escalation_exposure'
            title = 'Privileged service executable has a potential low-privilege write ACL'
            evidence = $evidence
            next_check = 'Verify effective access for the reported SID and remediate only after owner approval.'
        })
    }
    if ($privileged -and $registryAcl.potential_broad_write) {
        $findings.Add([PSCustomObject]@{
            id = 'service_registry_broad_write_acl'
            priority = $exposurePriority
            confidence = 'medium'
            classification = 'privilege_escalation_exposure'
            title = 'Privileged service configuration has a potential low-privilege write ACL'
            evidence = $evidence
            next_check = 'Verify effective registry access for the reported SID and service configuration.'
        })
    }
    if ($privileged -and $unquoted -and $writableCandidates.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            id = 'unquoted_service_path_writable_candidate'
            priority = $exposurePriority
            confidence = 'medium'
            classification = 'privilege_escalation_exposure'
            title = 'Privileged unquoted service path has a writable interpretation candidate'
            evidence = $evidence
            next_check = 'Confirm effective create/write access on the exact candidate parent before remediation.'
        })
    }
}

foreach ($task in $tasks) {
    $principalUser = [string]$task.Principal.UserId
    $runLevel = [string]$task.Principal.RunLevel
    $executionTier = Get-AxiosExecutionTier $principalUser
    $privileged = $executionTier -in @('system', 'service_account') -or
        $runLevel -eq 'Highest'
    $exposurePriority = if ($executionTier -eq 'system') { 'high' } else { 'medium' }

    foreach ($action in @($task.Actions)) {
        $commandLine = ('{0} {1}' -f $action.Execute, $action.Arguments).Trim()
        $executablePath = Resolve-AxiosExecutablePath ([string]$action.Execute)
        $fileAcl = Get-AxiosFileAclAssessment $executablePath (
            'task_executable:{0}{1}' -f $task.TaskPath, $task.TaskName
        )
        $evidence = [PSCustomObject]@{
            task_name = $task.TaskName
            task_path = $task.TaskPath
            state = [string]$task.State
            principal_user = $principalUser
            run_level = $runLevel
            privileged_execution_context = $privileged
            execution_tier = $executionTier
            command_line = $commandLine
            executable_path = $executablePath
            executable_acl = $fileAcl
        }
        $taskEvidence.Add($evidence)

        if ($privileged -and $fileAcl.potential_broad_write) {
            $findings.Add([PSCustomObject]@{
                id = 'privileged_task_executable_broad_write_acl'
                priority = $exposurePriority
                confidence = 'medium'
                classification = 'privilege_escalation_exposure'
                title = 'Privileged scheduled task executable has a potential low-privilege write ACL'
                evidence = $evidence
                next_check = 'Verify effective access and task principal before remediation.'
            })
        }
    }
}

foreach ($driver in $drivers) {
    $commandLine = [Environment]::ExpandEnvironmentVariables([string]$driver.PathName)
    $imagePath = Resolve-AxiosExecutablePath $commandLine
    $fileAcl = Get-AxiosFileAclAssessment $imagePath ('driver_image:{0}' -f $driver.Name)
    $evidence = [PSCustomObject]@{
        driver_name = $driver.Name
        display_name = $driver.DisplayName
        state = $driver.State
        start_mode = $driver.StartMode
        service_type = $driver.ServiceType
        command_line = $commandLine
        image_path = $imagePath
        image_acl = $fileAcl
    }
    $driverEvidence.Add($evidence)

    if ($fileAcl.potential_broad_write) {
        $findings.Add([PSCustomObject]@{
            id = 'driver_image_broad_write_acl'
            priority = 'high'
            confidence = 'medium'
            classification = 'kernel_integrity_exposure'
            title = 'System driver image has a potential low-privilege write ACL'
            evidence = $evidence
            next_check = 'Verify effective access, signature, catalog trust, and loaded state.'
        })
    }
}

if ($secureBoot.status -eq 'observed' -and $secureBoot.enabled -eq $false) {
    $findings.Add([PSCustomObject]@{
        id = 'secure_boot_disabled'
        priority = 'high'
        confidence = 'high'
        classification = 'boot_integrity_weakening'
        title = 'Secure Boot is disabled'
        evidence = $secureBoot
        next_check = 'Confirm firmware mode and organizational requirements before changing boot policy.'
    })
}
$analysisTimer.Stop()
$totalTimer.Stop()

$truncation = [PSCustomObject]@{
    services = [PSCustomObject]@{
        total = $servicesAll.Count
        returned = $services.Count
        limit = __MAX_SERVICES__
        truncated = ($servicesAll.Count -gt $services.Count)
    }
    scheduled_tasks = [PSCustomObject]@{
        total = $tasksAll.Count
        returned = $tasks.Count
        limit = __MAX_TASKS__
        truncated = ($tasksAll.Count -gt $tasks.Count)
    }
    system_drivers = [PSCustomObject]@{
        total = $driversAll.Count
        returned = $drivers.Count
        limit = __MAX_DRIVERS__
        truncated = ($driversAll.Count -gt $drivers.Count)
    }
}
$isTruncated = $truncation.services.truncated -or
    $truncation.scheduled_tasks.truncated -or
    $truncation.system_drivers.truncated
$collectionStatus = if ($collectionErrors.Count -gt 0 -or $isTruncated) { 'partial' } else { 'complete' }

[PSCustomObject]@{
    success = $true
    collector = 'axios_admin_exposure_audit'
    collection_status = $collectionStatus
    collection_errors = @($collectionErrors)
    declared_limits = [PSCustomObject]@{
        max_services = __MAX_SERVICES__
        max_scheduled_tasks = __MAX_TASKS__
        max_system_drivers = __MAX_DRIVERS__
    }
    truncation = $truncation
    execution_context = [PSCustomObject]@{
        scope = 'read_only_system_wide_exposure_assessment'
        administrator = $true
        exploitation_attempted = $false
        files_modified = $false
        registry_modified = $false
        raw_memory_access = 'not_collected'
    }
    acl_assessment_policy = [PSCustomObject]@{
        principals = $lowPrivilegeSids
        allow_and_deny_evaluated = $true
        effective_access_claimed = $false
        interpretation = 'Potential broad write ACL evidence requires independent effective-access verification.'
    }
    performance = [PSCustomObject]@{
        collection_ms = $collectionTimer.ElapsedMilliseconds
        analysis_ms = $analysisTimer.ElapsedMilliseconds
        total_ms = $totalTimer.ElapsedMilliseconds
        file_acl_cache_entries = $fileAclCache.Count
        registry_acl_cache_entries = $registryAclCache.Count
    }
    local_administrators = $localAdministrators
    secure_boot = $secureBoot
    device_guard = $deviceGuard
    services = @($serviceEvidence)
    scheduled_tasks = @($taskEvidence)
    system_drivers = @($driverEvidence)
    findings = @($findings)
    malware_confirmed = $false
    intrusion_confirmed = $false
    privilege_escalation_confirmed = $false
    summary = [PSCustomObject]@{
        services_examined = $services.Count
        scheduled_task_actions_examined = $taskEvidence.Count
        drivers_examined = $drivers.Count
        file_acl_cache_entries = $fileAclCache.Count
        registry_acl_cache_entries = $registryAclCache.Count
        findings = $findings.Count
        high_priority_findings = @($findings | Where-Object priority -eq 'high').Count
        medium_priority_findings = @($findings | Where-Object priority -eq 'medium').Count
    }
} | ConvertTo-Json -Depth 12 -Compress
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaces_in_arguments_do_not_create_an_unquoted_service_path_finding() {
        assert!(!is_unquoted_service_command(
            r"C:\Windows\System32\svchost.exe -k LocalService -p"
        ));
        assert!(!is_unquoted_service_command(
            r"C:\Windows\System32\cmd.exe /c echo hello world"
        ));
    }

    #[test]
    fn an_actual_unquoted_executable_path_with_spaces_is_detected() {
        assert!(is_unquoted_service_command(
            r"C:\Program Files\Vendor Agent\agent.exe --service"
        ));
        assert!(!is_unquoted_service_command(
            r#""C:\Program Files\Vendor Agent\agent.exe" --service"#
        ));
    }

    #[test]
    fn stale_false_positive_and_duplicate_findings_are_removed() {
        let stale = json!({
            "id": "unquoted_service_path_writable_candidate",
            "priority": "high",
            "evidence": {
                "name": "Example",
                "command_line": "C:\\Windows\\System32\\svchost.exe -k Example"
            }
        });
        let report = build_report(&json!({
            "success": true,
            "collector": "axios_admin_exposure_audit",
            "collection_status": "complete",
            "collection_errors": [],
            "findings": [stale.clone(), stale]
        }));

        assert_eq!(report["summary"]["findings"], 0);
        assert_eq!(report["summary"]["high_priority_findings"], 0);
        assert_eq!(report["privilege_escalation_confirmed"], false);
    }

    #[test]
    fn true_exposure_is_deduplicated_without_losing_evidence() {
        let finding = json!({
            "id": "service_executable_broad_write_acl",
            "priority": "high",
            "classification": "privilege_escalation_exposure",
            "evidence": {
                "name": "VendorAgent",
                "executable_path": "C:\\Program Files\\Vendor\\agent.exe"
            }
        });
        let report = build_report(&json!({
            "success": true,
            "collection_status": "complete",
            "collection_errors": [],
            "findings": [finding.clone(), finding]
        }));

        assert_eq!(report["summary"]["findings"], 1);
        assert_eq!(report["summary"]["high_priority_findings"], 1);
        assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    }
}
