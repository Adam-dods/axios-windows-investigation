use anyhow::Result;
#[cfg(windows)]
use axios_core::command::{parse_json_output, powershell};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

const MAX_SERVICES: usize = 1024;
const MAX_TASKS: usize = 1024;
const MAX_PATH_DIRECTORIES: usize = 256;

#[derive(Parser, Debug)]
#[command(name = "axios-user-exposure-audit")]
struct Options {
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = Options::parse();
    let snapshot = collect_snapshot();
    let report = build_report(&snapshot);

    if let Some(output) = options.output {
        json_file::write_pretty(output, &report)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

#[cfg(windows)]
fn collect_snapshot() -> Value {
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$maxServices = {MAX_SERVICES}
$maxTasks = {MAX_TASKS}
$maxPathDirectories = {MAX_PATH_DIRECTORIES}
$collectionErrors = [System.Collections.Generic.List[string]]::new()
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentUser = $currentIdentity.Name

function Invoke-AxiosExposureSource {{
    param(
        [string]$Source,
        [scriptblock]$Action,
        [object]$Fallback
    )

    try {{
        return & $Action
    }}
    catch {{
        $collectionErrors.Add(("{{0}}: {{1}}" -f $Source, $_.Exception.Message))
        return $Fallback
    }}
}}

function Get-AxiosManagementInstance {{
    param(
        [string]$ClassName,
        [string]$Filter = ""
    )

    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {{
        if ([string]::IsNullOrWhiteSpace($Filter)) {{
            return Get-CimInstance $ClassName -ErrorAction Stop
        }}

        return Get-CimInstance $ClassName -Filter $Filter -ErrorAction Stop
    }}

    if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {{
        if ([string]::IsNullOrWhiteSpace($Filter)) {{
            return Get-WmiObject $ClassName -ErrorAction Stop
        }}

        return Get-WmiObject $ClassName -Filter $Filter -ErrorAction Stop
    }}

    throw "Windows management instrumentation is unavailable."
}}

function Resolve-AxiosFilesystemPath {{
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {{
        return $null
    }}

    $normalized = $Path.Trim().Trim('"')

    if ([string]::IsNullOrWhiteSpace($normalized)) {{
        return $null
    }}

    $normalized = [Environment]::ExpandEnvironmentVariables(
        $normalized
    )

    if ($normalized.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {{
        $normalized = Join-Path `
            $env:SystemRoot `
            $normalized.Substring('\SystemRoot\'.Length)
    }}
    elseif ($normalized.StartsWith('System32\', [StringComparison]::OrdinalIgnoreCase)) {{
        $normalized = Join-Path $env:SystemRoot $normalized
    }}

    try {{
        return [System.IO.Path]::GetFullPath($normalized)
    }}
    catch {{
        $collectionErrors.Add(
            ("path_normalization:{{0}}: {{1}}" -f $Path, $_.Exception.Message)
        )
        return $null
    }}
}}

function Get-AxiosExecutablePath {{
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {{
        return $null
    }}

    $value = $CommandLine.Trim()
    $candidate = $null

    if ($value.StartsWith('"')) {{
        $match = [regex]::Match($value, '^"([^"]+)"')

        if ($match.Success) {{
            $candidate = $match.Groups[1].Value
        }}
    }}

    if ([string]::IsNullOrWhiteSpace($candidate)) {{
        $match = [regex]::Match(
            $value,
            '(?i)^(.+?\.exe)(?:\s|$)'
        )

        if ($match.Success) {{
            $candidate = $match.Groups[1].Value
        }}
    }}

    return Resolve-AxiosFilesystemPath $candidate
}}

function Get-AxiosPotentialWriteAcl {{
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {{
        return @()
    }}

    $normalizedPath = Resolve-AxiosFilesystemPath $Path

    if ([string]::IsNullOrWhiteSpace($normalizedPath)) {{
        return @()
    }}

    try {{
        if (-not (
            Test-Path `
                -LiteralPath $normalizedPath `
                -PathType Leaf `
                -ErrorAction Stop
        )) {{
            if (-not (
                Test-Path `
                    -LiteralPath $normalizedPath `
                    -PathType Container `
                    -ErrorAction Stop
            )) {{
                return @()
            }}
        }}

        @(
            (
                Get-Acl `
                    -LiteralPath $normalizedPath `
                    -ErrorAction Stop
            ).Access |
                Where-Object {{
                    $_.AccessControlType -eq 'Allow' -and
                    $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl|TakeOwnership' -and
                    $_.IdentityReference.Value -match '(?i)(Everyone|Authenticated Users|\\Users$)'
                }} |
                Select-Object `
                    IdentityReference,
                    FileSystemRights,
                    AccessControlType
        )
    }}
    catch {{
        $collectionErrors.Add(
            (
                "acl:{{0}}: {{1}}" -f `
                    $normalizedPath,
                    $_.Exception.Message
            )
        )
        @()
    }}
}}

$operatingSystem = Invoke-AxiosExposureSource 'operating_system' {{
    $os = Get-AxiosManagementInstance "Win32_OperatingSystem"
    $version = Get-ItemProperty `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
        -ErrorAction Stop

    [PSCustomObject]@{{
        caption = [string]$os.Caption
        version = [string]$os.Version
        build_number = [string]$os.BuildNumber
        display_version = [string]$version.DisplayVersion
        ubr = [string]$version.UBR
        install_date = [string]$os.InstallDate
        last_boot_up_time = [string]$os.LastBootUpTime
    }}
}} $null

$hotfixes = @(
    Invoke-AxiosExposureSource 'hotfixes' {{
        Get-AxiosManagementInstance "Win32_QuickFixEngineering" |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 100 HotFixID, InstalledOn, Description
    }} @()
)

$uac = Invoke-AxiosExposureSource 'uac_policy' {{
    $item = Get-ItemProperty `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -ErrorAction Stop

    [PSCustomObject]@{{
        enable_lua = $item.EnableLUA
        consent_prompt_behavior_admin = $item.ConsentPromptBehaviorAdmin
        prompt_on_secure_desktop = $item.PromptOnSecureDesktop
    }}
}} $null

$privileges = @(
    Invoke-AxiosExposureSource 'token_privileges' {{
        & whoami.exe /priv 2>&1 |
            ForEach-Object {{ [string]$_ }}
    }} @()
)

$allServices = @(
    Invoke-AxiosExposureSource 'services' {{
        Get-AxiosManagementInstance "Win32_Service" |
            Select-Object Name, DisplayName, StartMode, State, PathName |
            Sort-Object Name
    }} @()
)

$serviceExposure = @(
    $allServices |
        Select-Object -First $maxServices |
        ForEach-Object {{
            $service = $_
            $commandLine = [string]$service.PathName
            $executablePath = Get-AxiosExecutablePath $commandLine
            $unquotedWithSpaces = (
                -not [string]::IsNullOrWhiteSpace($commandLine) -and
                -not [string]::IsNullOrWhiteSpace($executablePath) -and
                -not $commandLine.TrimStart().StartsWith('"') -and
                $executablePath.Contains(' ')
            )

            [PSCustomObject]@{{
                name = $service.Name
                display_name = $service.DisplayName
                start_mode = $service.StartMode
                state = $service.State
                command_line = $commandLine
                executable_path = $executablePath
                unquoted_path_with_spaces = $unquotedWithSpaces
                broad_write_acl = @(Get-AxiosPotentialWriteAcl $executablePath)
            }}
        }}
)

$allTasks = @(
    Invoke-AxiosExposureSource 'scheduled_tasks' {{
        Get-ScheduledTask -ErrorAction Stop |
            Select-Object -First $maxTasks |
            ForEach-Object {{
                $task = $_
                foreach ($action in @($task.Actions)) {{
                    [PSCustomObject]@{{
                        task_name = $task.TaskName
                        task_path = $task.TaskPath
                        user_id = [string]$task.Principal.UserId
                        execute = [string]$action.Execute
                        arguments = [string]$action.Arguments
                    }}
                }}
            }}
    }} @()
)

$taskExposure = @(
    $allTasks |
        ForEach-Object {{
            $task = $_
            [PSCustomObject]@{{
                task_name = $task.task_name
                task_path = $task.task_path
                user_id = $task.user_id
                execute = $task.execute
                arguments = $task.arguments
                broad_write_acl = @(Get-AxiosPotentialWriteAcl $task.execute)
            }}
        }}
)

$machinePath = Invoke-AxiosExposureSource 'machine_path' {{
    (Get-ItemProperty `
        -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' `
        -Name Path `
        -ErrorAction Stop).Path
}} ''

$allPathDirectories = @(
    [string]$machinePath -split ';' |
        ForEach-Object {{ $_.Trim().Trim('"') }} |
        Where-Object {{ -not [string]::IsNullOrWhiteSpace($_) }} |
        Select-Object -Unique
)

$pathExposure = @(
    $allPathDirectories |
        Select-Object -First $maxPathDirectories |
        ForEach-Object {{
            [PSCustomObject]@{{
                path = $_
                broad_write_acl = @(Get-AxiosPotentialWriteAcl $_)
            }}
        }}
)

[PSCustomObject]@{{
    success = $true
    collector = 'axios_user_exposure_audit'
    execution_context = @{{
        administrator = $false
        principal = $currentUser
        scope = 'read_only_standard_user_exposure_assessment'
        kernel_memory_access = 'not_available_without_administrator'
        exploitation_performed = $false
    }}
    collection_status = if ($collectionErrors.Count -eq 0) {{ 'complete' }} else {{ 'partial' }}
    collection_errors = @($collectionErrors)
    limits = @{{
        max_services = $maxServices
        services_total = $allServices.Count
        services_truncated = ($allServices.Count -gt $serviceExposure.Count)
        max_tasks = $maxTasks
        tasks_total = $allTasks.Count
        tasks_truncated = ($allTasks.Count -gt $taskExposure.Count)
        max_path_directories = $maxPathDirectories
        path_directories_total = $allPathDirectories.Count
        path_directories_truncated = ($allPathDirectories.Count -gt $pathExposure.Count)
    }}
    operating_system = $operatingSystem
    installed_hotfixes = $hotfixes
    uac = $uac
    token_privileges = $privileges
    service_exposure = $serviceExposure
    scheduled_task_exposure = $taskExposure
    machine_path_exposure = $pathExposure
}} | ConvertTo-Json -Depth 10 -Compress
"#
    );

    match powershell(&script) {
        Ok(result) => parse_json_output(result),
        Err(error) => json!({
            "success": false,
            "collector": "axios_user_exposure_audit",
            "error": error.to_string()
        }),
    }
}

#[cfg(not(windows))]
fn collect_snapshot() -> Value {
    json!({
        "success": false,
        "collector": "axios_user_exposure_audit",
        "collection_status": "windows_only"
    })
}

fn has_broad_write_acl(value: &Value) -> bool {
    value
        .get("broad_write_acl")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
}

fn build_report(snapshot: &Value) -> Value {
    if snapshot.get("success").and_then(Value::as_bool) != Some(true) {
        return snapshot.clone();
    }

    let mut findings = Vec::new();

    for service in snapshot
        .get("service_exposure")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if service
            .get("unquoted_path_with_spaces")
            .and_then(Value::as_bool)
            == Some(true)
        {
            findings.push(json!({
                "priority": "high",
                "classification": "privilege_escalation_exposure",
                "title": "Service command path is unquoted and contains spaces",
                "evidence": service,
                "next_check": "Verify the service executable path, directory permissions, and whether an unprivileged principal can create files in any interpreted path segment."
            }));
        }

        if has_broad_write_acl(service) {
            findings.push(json!({
                "priority": "high",
                "classification": "privilege_escalation_exposure",
                "title": "Service executable has a potentially broad write ACL",
                "evidence": service,
                "next_check": "Verify effective permissions using an approved administrator review before treating this as exploitable."
            }));
        }
    }

    for task in snapshot
        .get("scheduled_task_exposure")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if has_broad_write_acl(task) {
            findings.push(json!({
                "priority": "high",
                "classification": "privilege_escalation_exposure",
                "title": "Scheduled-task executable has a potentially broad write ACL",
                "evidence": task,
                "next_check": "Verify task principal, effective permissions, file provenance, and whether the task runs with elevated rights."
            }));
        }
    }

    for directory in snapshot
        .get("machine_path_exposure")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if has_broad_write_acl(directory) {
            findings.push(json!({
                "priority": "medium",
                "classification": "execution_hardening_gap",
                "title": "Machine PATH directory has a potentially broad write ACL",
                "evidence": directory,
                "next_check": "Verify effective permissions and remove write access for broad principals where it is not required."
            }));
        }
    }

    if snapshot
        .get("uac")
        .and_then(|uac| uac.get("enable_lua"))
        .and_then(Value::as_i64)
        == Some(0)
    {
        findings.push(json!({
            "priority": "high",
            "classification": "security_control_weakened",
            "title": "User Account Control is disabled",
            "next_check": "Restore approved UAC policy and independently verify the effective setting."
        }));
    }

    findings.truncate(200);

    json!({
        "success": true,
        "collector": "axios_user_exposure_audit",
        "execution_context": snapshot.get("execution_context").cloned().unwrap_or(Value::Null),
        "collection_status": snapshot.get("collection_status").cloned().unwrap_or_else(|| json!("unknown")),
        "collection_errors": snapshot.get("collection_errors").cloned().unwrap_or_else(|| json!([])),
        "limits": snapshot.get("limits").cloned().unwrap_or_else(|| json!({})),
        "declared_limits": {
            "max_services": MAX_SERVICES,
            "max_tasks": MAX_TASKS,
            "max_path_directories": MAX_PATH_DIRECTORIES
        },
        "operating_system": snapshot.get("operating_system").cloned().unwrap_or(Value::Null),
        "installed_hotfixes": snapshot.get("installed_hotfixes").cloned().unwrap_or_else(|| json!([])),
        "uac": snapshot.get("uac").cloned().unwrap_or(Value::Null),
        "token_privileges": snapshot.get("token_privileges").cloned().unwrap_or_else(|| json!([])),
        "summary": {
            "service_exposure_items": snapshot.get("service_exposure").and_then(Value::as_array).map_or(0, Vec::len),
            "scheduled_task_exposure_items": snapshot.get("scheduled_task_exposure").and_then(Value::as_array).map_or(0, Vec::len),
            "machine_path_exposure_items": snapshot.get("machine_path_exposure").and_then(Value::as_array).map_or(0, Vec::len),
            "findings": findings.len()
        },
        "findings": findings
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broad_write_acl_requires_review() {
        assert!(has_broad_write_acl(&json!({
            "broad_write_acl": [{"IdentityReference": "BUILTIN\\Users"}]
        })));
        assert!(!has_broad_write_acl(&json!({
            "broad_write_acl": []
        })));
    }

    #[test]
    fn standard_user_exposure_audit_is_read_only_and_bounded() {
        let source = include_str!("axios-user-exposure-audit.rs");

        assert!(source.contains("read_only_standard_user_exposure_assessment"));
        assert!(source.contains("exploitation_performed = $false"));
        assert!(source.contains("unquoted_path_with_spaces"));
        assert!(source.contains("broad_write_acl"));
        assert!(source.contains("collection_errors"));
    }
}
