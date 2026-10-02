use anyhow::Result;
#[cfg(windows)]
use axios_core::command::{parse_json_output, powershell};
use axios_core::storage::json_file;
use clap::Parser;
use serde_json::{json, Value};
use std::path::PathBuf;

const MAX_AUTORUNS: usize = 256;
const MAX_STARTUP_FILES: usize = 256;
const MAX_VISIBLE_TASKS: usize = 512;
const MAX_USER_PROCESSES: usize = 512;

#[derive(Parser, Debug)]
#[command(name = "axios-user-scope-access-review")]
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
    let collector_pid = std::process::id();
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$axiosCollectorProcessId = {collector_pid}
$maxAutoruns = {MAX_AUTORUNS}
$maxStartupFiles = {MAX_STARTUP_FILES}
$maxVisibleTasks = {MAX_VISIBLE_TASKS}
$maxUserProcesses = {MAX_USER_PROCESSES}
$collectionErrors = [System.Collections.Generic.List[string]]::new()

function Invoke-AxiosUserSource {{
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

function Get-AxiosUserManagementInstance {{
    param([string]$ClassName)

    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {{
        return Get-CimInstance $ClassName -ErrorAction Stop
    }}

    if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {{
        return Get-WmiObject $ClassName -ErrorAction Stop
    }}

    throw "Windows management instrumentation is unavailable."
}}

$currentUser = [Environment]::UserName
$userProfile = [Environment]::GetFolderPath('UserProfile')
$userWritableRoots = @(
    $userProfile,
    $env:APPDATA,
    $env:LOCALAPPDATA,
    $env:TEMP,
    (Join-Path $userProfile 'Downloads')
) | Where-Object {{ -not [string]::IsNullOrWhiteSpace($_) }}

$runLocations = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

$allAutoruns = @(
    foreach ($location in $runLocations) {{
        try {{
            if (-not (Test-Path -LiteralPath $location -ErrorAction Stop)) {{
                continue
            }}

            $item = Get-ItemProperty -LiteralPath $location -ErrorAction Stop

            foreach ($property in $item.PSObject.Properties) {{
                if ($property.Name -like 'PS*') {{
                    continue
                }}

                [PSCustomObject]@{{
                    source = $location
                    name = [string]$property.Name
                    command = [string]$property.Value
                }}
            }}
        }}
        catch {{
            $collectionErrors.Add(("user_autorun:{{0}}: {{1}}" -f $location, $_.Exception.Message))
        }}
    }}
)
$autoruns = @($allAutoruns | Select-Object -First $maxAutoruns)

$startupPath = [Environment]::GetFolderPath('Startup')
$allStartupFiles = @(
    Invoke-AxiosUserSource 'user_startup_folder' {{
        if (-not (Test-Path -LiteralPath $startupPath -PathType Container -ErrorAction Stop)) {{
            return @()
        }}

        Get-ChildItem -LiteralPath $startupPath -Force -File -ErrorAction Stop |
            Select-Object Name, FullName, Length, LastWriteTimeUtc |
            Sort-Object FullName
    }} @()
)
$startupFiles = @($allStartupFiles | Select-Object -First $maxStartupFiles)

$profileCandidates = @(
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.CurrentUserCurrentHost,
    (Join-Path $userProfile 'Documents\WindowsPowerShell\profile.ps1'),
    (Join-Path $userProfile 'Documents\PowerShell\Profile.ps1')
) |
    Where-Object {{ -not [string]::IsNullOrWhiteSpace($_) }} |
    Select-Object -Unique

$powerShellProfiles = @(
    foreach ($profilePath in $profileCandidates) {{
        try {{
            if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf -ErrorAction Stop)) {{
                continue
            }}

            $item = Get-Item -LiteralPath $profilePath -ErrorAction Stop
            [PSCustomObject]@{{
                path = $item.FullName
                length = [int64]$item.Length
                last_write_time_utc = $item.LastWriteTimeUtc
                sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            }}
        }}
        catch {{
            $collectionErrors.Add(("powershell_profile:{{0}}: {{1}}" -f $profilePath, $_.Exception.Message))
        }}
    }}
)

$sshCandidates = @(
    (Join-Path $userProfile '.ssh\authorized_keys'),
    (Join-Path $userProfile '.ssh\config')
)

$sshPersistenceFiles = @(
    foreach ($sshPath in $sshCandidates) {{
        try {{
            if (-not (Test-Path -LiteralPath $sshPath -PathType Leaf -ErrorAction Stop)) {{
                continue
            }}

            $item = Get-Item -LiteralPath $sshPath -ErrorAction Stop
            [PSCustomObject]@{{
                path = $item.FullName
                length = [int64]$item.Length
                last_write_time_utc = $item.LastWriteTimeUtc
                sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            }}
        }}
        catch {{
            $collectionErrors.Add(("ssh_persistence:{{0}}: {{1}}" -f $sshPath, $_.Exception.Message))
        }}
    }}
)

$allVisibleTasks = @(
    Invoke-AxiosUserSource 'visible_scheduled_tasks' {{
        Get-ScheduledTask -ErrorAction Stop |
            Where-Object {{
                $principal = [string]$_.Principal.UserId
                $principal -match [regex]::Escape($currentUser)
            }} |
            Select-Object TaskName, TaskPath, State,
                @{{
                    Name = 'user_id'
                    Expression = {{ [string]$_.Principal.UserId }}
                }},
                @{{
                    Name = 'actions'
                    Expression = {{
                        @($_.Actions | Select-Object -First 32 | ForEach-Object {{
                            [PSCustomObject]@{{
                                execute = $_.Execute
                                arguments = $_.Arguments
                            }}
                        }})
                    }}
                }} |
            Sort-Object TaskPath, TaskName
    }} @()
)
$visibleTasks = @($allVisibleTasks | Select-Object -First $maxVisibleTasks)

$allUserProcesses = @(
    Invoke-AxiosUserSource 'user_writable_processes' {{
        Get-AxiosUserManagementInstance "Win32_Process" |
            Where-Object {{
                $path = [string]$_.ExecutablePath
                [uint32]$_.ProcessId -ne $axiosCollectorProcessId -and
                $path -and @($userWritableRoots | Where-Object {{
                    $path.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase)
                }}).Count -gt 0
            }} |
            Select-Object ProcessId, Name, ExecutablePath, CommandLine,
                CreationDate, ParentProcessId |
            Sort-Object ExecutablePath, ProcessId
    }} @()
)
$userProcesses = @($allUserProcesses | Select-Object -First $maxUserProcesses)

$proxy = Invoke-AxiosUserSource 'user_proxy' {{
    $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

    if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {{
        return $null
    }}

    Get-ItemProperty -LiteralPath $path -ErrorAction Stop |
        Select-Object ProxyEnable, ProxyServer, AutoConfigURL, AutoDetect
}} $null

[PSCustomObject]@{{
    success = $true
    collector = 'axios_user_scope_access_review'
    execution_context = @{{
        administrator = $false
        scope = 'current_user_visible_evidence'
        kernel_memory_access = 'not_available_without_administrator'
        other_user_profile_access = 'not_available_without_administrator'
    }}
    collection_status = if ($collectionErrors.Count -eq 0) {{ 'complete' }} else {{ 'partial' }}
    collection_errors = @($collectionErrors)
    limits = @{{
        max_autoruns = $maxAutoruns
        autoruns_total = $allAutoruns.Count
        autoruns_truncated = ($allAutoruns.Count -gt $autoruns.Count)
        max_startup_files = $maxStartupFiles
        startup_files_total = $allStartupFiles.Count
        startup_files_truncated = ($allStartupFiles.Count -gt $startupFiles.Count)
        max_visible_tasks = $maxVisibleTasks
        visible_tasks_total = $allVisibleTasks.Count
        visible_tasks_truncated = ($allVisibleTasks.Count -gt $visibleTasks.Count)
        max_user_processes = $maxUserProcesses
        user_processes_total = $allUserProcesses.Count
        user_processes_truncated = ($allUserProcesses.Count -gt $userProcesses.Count)
    }}
    user_autoruns = $autoruns
    user_startup_files = $startupFiles
    powershell_profiles = $powerShellProfiles
    ssh_persistence_files = $sshPersistenceFiles
    visible_user_tasks = $visibleTasks
    user_writable_processes = $userProcesses
    user_proxy = $proxy
}} | ConvertTo-Json -Depth 10 -Compress
"#
    );

    match powershell(&script) {
        Ok(result) => parse_json_output(result),
        Err(error) => json!({
            "success": false,
            "collector": "axios_user_scope_access_review",
            "error": error.to_string()
        }),
    }
}

#[cfg(not(windows))]
fn collect_snapshot() -> Value {
    json!({
        "success": false,
        "collector": "axios_user_scope_access_review",
        "collection_status": "windows_only"
    })
}

fn has_user_writable_execution_path(value: &Value) -> bool {
    let text = serde_json::to_string(value)
        .unwrap_or_default()
        .replace("\\\\", "\\")
        .replace('/', "\\")
        .to_ascii_lowercase();

    text.contains(r"\downloads\")
        || text.contains(r"\appdata\local\temp\")
        || text.contains(r"\windows\temp\")
}

fn build_report(snapshot: &Value) -> Value {
    if snapshot.get("success").and_then(Value::as_bool) != Some(true) {
        return snapshot.clone();
    }

    let mut findings = Vec::new();

    for entry in snapshot
        .get("user_autoruns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if has_user_writable_execution_path(entry) {
            findings.push(json!({
                "priority": "high",
                "classification": "requires_verification",
                "title": "Current-user autorun references a user-writable path",
                "evidence": entry,
                "next_check": "Verify file provenance, signature, hash, and whether the autorun was explicitly approved."
            }));
        }
    }

    for process in snapshot
        .get("user_writable_processes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if has_user_writable_execution_path(process) {
            findings.push(json!({
                "priority": "high",
                "classification": "requires_verification",
                "title": "Running process executes from a user-writable path",
                "evidence": process,
                "next_check": "Verify executable provenance, parent process, signature, hash, and active network activity."
            }));
        }
    }

    for profile in snapshot
        .get("powershell_profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        findings.push(json!({
            "priority": "medium",
            "classification": "configuration_review",
            "title": "Current-user PowerShell profile is present",
            "evidence": profile,
            "next_check": "Review the profile content and compare its hash to an approved baseline."
        }));
    }

    for ssh_file in snapshot
        .get("ssh_persistence_files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        findings.push(json!({
            "priority": "medium",
            "classification": "access_review",
            "title": "Current-user SSH persistence file is present",
            "evidence": ssh_file,
            "next_check": "Confirm every authorized key and SSH configuration entry belongs to the user."
        }));
    }

    findings.truncate(100);

    json!({
        "success": true,
        "collector": "axios_user_scope_access_review",
        "execution_context": snapshot.get("execution_context").cloned().unwrap_or(Value::Null),
        "collection_status": snapshot.get("collection_status").cloned().unwrap_or_else(|| json!("unknown")),
        "collection_errors": snapshot.get("collection_errors").cloned().unwrap_or_else(|| json!([])),
        "limits": snapshot.get("limits").cloned().unwrap_or_else(|| json!({})),
        "declared_limits": {
            "max_autoruns": MAX_AUTORUNS,
            "max_startup_files": MAX_STARTUP_FILES,
            "max_visible_tasks": MAX_VISIBLE_TASKS,
            "max_user_processes": MAX_USER_PROCESSES
        },
        "summary": {
            "user_autoruns": snapshot.get("user_autoruns").and_then(Value::as_array).map_or(0, Vec::len),
            "user_startup_files": snapshot.get("user_startup_files").and_then(Value::as_array).map_or(0, Vec::len),
            "powershell_profiles": snapshot.get("powershell_profiles").and_then(Value::as_array).map_or(0, Vec::len),
            "ssh_persistence_files": snapshot.get("ssh_persistence_files").and_then(Value::as_array).map_or(0, Vec::len),
            "visible_user_tasks": snapshot.get("visible_user_tasks").and_then(Value::as_array).map_or(0, Vec::len),
            "user_writable_processes": snapshot.get("user_writable_processes").and_then(Value::as_array).map_or(0, Vec::len),
            "findings": findings.len()
        },
        "findings": findings
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_writable_paths_require_verification() {
        assert!(has_user_writable_execution_path(&json!({
            "path": r"C:\Users\TestUser\Downloads\run.exe"
        })));
        assert!(has_user_writable_execution_path(&json!({
            "path": r"C:\Users\TestUser\AppData\Local\Temp\run.exe"
        })));
        assert!(!has_user_writable_execution_path(&json!({
            "path": r"C:\Windows\System32\notepad.exe"
        })));
    }

    #[test]
    fn standard_user_scope_is_explicitly_bounded() {
        let source = include_str!("axios-user-scope-access-review.rs");

        assert!(source.contains("current_user_visible_evidence"));
        assert!(source.contains("kernel_memory_access"));
        assert!(source.contains("collection_status"));
        assert!(source.contains("collection_errors"));
        assert!(source.contains("user_writable_processes"));
    }
}
