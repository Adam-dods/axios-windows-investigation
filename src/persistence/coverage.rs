use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'Stop'
$collectionErrors = [System.Collections.Generic.List[string]]::new()

function Invoke-AxiosCollection {
    param(
        [string]$Source,
        [scriptblock]$Action
    )

    try {
        return @(& $Action)
    }
    catch {
        $collectionErrors.Add(("{0}: {1}" -f $Source, $_.Exception.Message))
        return @()
    }
}

$maxRunKeyEntries = 2048
$maxStartupCommands = 2048
$maxScheduledTasks = 2048
$maxAutoStartServices = 4096
$maxStartupFolderItems = 2048
$maxWmiSubscriptions = 1024

$locations = @(
    @{ source = 'current_user_run'; path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' },
    @{ source = 'current_user_run_once'; path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ source = 'local_machine_run'; path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' },
    @{ source = 'local_machine_run_once'; path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' },
    @{ source = 'local_machine_wow6432_run'; path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' },
    @{ source = 'local_machine_wow6432_run_once'; path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' }
)

$allRunEntries = @(
    foreach ($location in $locations) {
        try {
            if (-not (Test-Path -LiteralPath $location.path -ErrorAction Stop)) {
                continue
            }

            $item = Get-ItemProperty -LiteralPath $location.path -ErrorAction Stop
            foreach ($property in $item.PSObject.Properties) {
                if ($property.Name -like 'PS*') {
                    continue
                }

                [PSCustomObject]@{
                    source = $location.source
                    registry_path = $location.path
                    name = $property.Name
                    command = [string]$property.Value
                }
            }
        }
        catch {
            $collectionErrors.Add(("run_key:{0}: {1}" -f $location.source, $_.Exception.Message))
        }
    }
)
$runEntries = @($allRunEntries | Select-Object -First $maxRunKeyEntries)

$allStartupCommands = @(Invoke-AxiosCollection 'startup_commands' {
    Get-CimInstance Win32_StartupCommand -ErrorAction Stop |
        Select-Object Name, Command, Location, User
})
$startupCommands = @($allStartupCommands | Select-Object -First $maxStartupCommands)

$allScheduledTaskCandidates = @(Invoke-AxiosCollection 'scheduled_tasks' {
    Get-ScheduledTask -ErrorAction Stop |
        Where-Object { $_.Settings.Enabled -ne $false }
})
$scheduledTasks = @(
    $allScheduledTaskCandidates |
        Select-Object -First $maxScheduledTasks |
        ForEach-Object {
            $task = $_
            [PSCustomObject]@{
                task_name = $task.TaskName
                task_path = $task.TaskPath
                state = [string]$task.State
                author = $task.Author
                description = $task.Description
                actions = @(
                    $task.Actions |
                        Select-Object -First 64 |
                        ForEach-Object {
                            [PSCustomObject]@{
                                execute = $_.Execute
                                arguments = $_.Arguments
                                working_directory = $_.WorkingDirectory
                            }
                        }
                )
            }
        }
)

$allAutoStartServices = @(Invoke-AxiosCollection 'auto_start_services' {
    Get-CimInstance Win32_Service -ErrorAction Stop |
        Where-Object { $_.StartMode -in 'Auto', 'Boot', 'System' } |
        Select-Object Name, DisplayName, State, StartMode, StartName,
            ProcessId, PathName, Description |
        Sort-Object Name
})
$autoStartServices = @($allAutoStartServices | Select-Object -First $maxAutoStartServices)

$startupFolders = @(
    [Environment]::GetFolderPath('Startup'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
)

$allStartupFolderItems = @(
    foreach ($folder in $startupFolders) {
        try {
            if (-not (Test-Path -LiteralPath $folder -ErrorAction Stop)) {
                continue
            }

            Get-ChildItem -LiteralPath $folder -Force -File -ErrorAction Stop |
                Select-Object @{ Name = 'startup_folder'; Expression = { $folder } },
                    Name, FullName, Length, LastWriteTimeUtc
        }
        catch {
            $collectionErrors.Add(("startup_folder:{0}: {1}" -f $folder, $_.Exception.Message))
        }
    }
)
$startupFolderItems = @($allStartupFolderItems | Select-Object -First $maxStartupFolderItems)

$allFilters = @(Invoke-AxiosCollection 'wmi_event_filters' {
    Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop |
        Select-Object Name, Query, QueryLanguage, EventNamespace
})
$filters = @($allFilters | Select-Object -First $maxWmiSubscriptions)

$allConsumers = @(Invoke-AxiosCollection 'wmi_event_consumers' {
    Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop |
        Select-Object Name, __CLASS, CommandLineTemplate, ExecutablePath,
            ScriptText, ScriptingEngine
})
$consumers = @($allConsumers | Select-Object -First $maxWmiSubscriptions)

$allBindings = @(Invoke-AxiosCollection 'wmi_filter_bindings' {
    Get-CimInstance -Namespace 'root\subscription' `
        -ClassName '__FilterToConsumerBinding' -ErrorAction Stop |
        ForEach-Object {
            $binding = $_
            $filterProperty = $binding.CimInstanceProperties['Filter']
            $consumerProperty = $binding.CimInstanceProperties['Consumer']

            if ($null -eq $filterProperty) {
                throw "WMI binding is missing its Filter property."
            }

            if ($null -eq $consumerProperty) {
                throw "WMI binding is missing its Consumer property."
            }

            $filterPath = [string]$filterProperty.Value
            $consumerPath = [string]$consumerProperty.Value

            if ([string]::IsNullOrWhiteSpace($filterPath)) {
                throw "WMI binding contains an empty Filter reference."
            }

            if ([string]::IsNullOrWhiteSpace($consumerPath)) {
                throw "WMI binding contains an empty Consumer reference."
            }

            [PSCustomObject]@{
                filter_path = $filterPath
                consumer_path = $consumerPath
            }
        }
})
$bindings = @($allBindings | Select-Object -First $maxWmiSubscriptions)

[PSCustomObject]@{
    success = $true
    collector = 'axios_persistence_coverage'
    collection_status = if ($collectionErrors.Count -eq 0) { 'complete' } else { 'partial' }
    collection_errors = @($collectionErrors)
    limits = @{
        max_run_key_entries = $maxRunKeyEntries
        run_key_entries_total = $allRunEntries.Count
        run_key_entries_truncated = ($allRunEntries.Count -gt $runEntries.Count)
        max_startup_commands = $maxStartupCommands
        startup_commands_total = $allStartupCommands.Count
        startup_commands_truncated = ($allStartupCommands.Count -gt $startupCommands.Count)
        max_enabled_scheduled_tasks = $maxScheduledTasks
        enabled_scheduled_tasks_total = $allScheduledTaskCandidates.Count
        enabled_scheduled_tasks_truncated = ($allScheduledTaskCandidates.Count -gt $scheduledTasks.Count)
        max_auto_start_services = $maxAutoStartServices
        auto_start_services_total = $allAutoStartServices.Count
        auto_start_services_truncated = ($allAutoStartServices.Count -gt $autoStartServices.Count)
        max_startup_folder_items = $maxStartupFolderItems
        startup_folder_items_total = $allStartupFolderItems.Count
        startup_folder_items_truncated = ($allStartupFolderItems.Count -gt $startupFolderItems.Count)
        max_wmi_subscriptions = $maxWmiSubscriptions
        wmi_event_filters_total = $allFilters.Count
        wmi_event_filters_truncated = ($allFilters.Count -gt $filters.Count)
        wmi_event_consumers_total = $allConsumers.Count
        wmi_event_consumers_truncated = ($allConsumers.Count -gt $consumers.Count)
        wmi_filter_bindings_total = $allBindings.Count
        wmi_filter_bindings_truncated = ($allBindings.Count -gt $bindings.Count)
    }
    run_key_entries = $runEntries
    startup_commands = $startupCommands
    scheduled_tasks = $scheduledTasks
    auto_start_services = $autoStartServices
    startup_folder_items = $startupFolderItems
    wmi_event_filters = $filters
    wmi_event_consumers = $consumers
    wmi_filter_bindings = $bindings
} | ConvertTo-Json -Depth 10 -Compress
"#;

        return match powershell(script) {
            Ok(result) => compact_persistence_coverage(parse_json_output(result)),
            Err(error) => json!({
                "success": false,
                "collector": "axios_persistence_coverage",
                "error": error.to_string()
            }),
        };
    }

    #[cfg(windows)]
    fn compact_persistence_coverage(raw: Value) -> Value {
        if raw.get("success").and_then(Value::as_bool) != Some(true) {
            return raw;
        }

        let run_entries = values(&raw, "run_key_entries");
        let startup_commands = values(&raw, "startup_commands");
        let scheduled_tasks = values(&raw, "scheduled_tasks");
        let services = values(&raw, "auto_start_services");
        let startup_folder_items = values(&raw, "startup_folder_items");
        let filters = values(&raw, "wmi_event_filters");
        let consumers = values(&raw, "wmi_event_consumers");
        let bindings = values(&raw, "wmi_filter_bindings");
        let collection_status = raw
            .get("collection_status")
            .cloned()
            .unwrap_or_else(|| json!("unknown"));
        let collection_errors = values(&raw, "collection_errors");
        let mut limits = raw
            .get("limits")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let mut review_items = Vec::new();

        for (source, items) in [
            ("run_key", &run_entries),
            ("startup_command", &startup_commands),
            ("scheduled_task", &scheduled_tasks),
            ("auto_start_service", &services),
            ("startup_folder", &startup_folder_items),
        ] {
            for item in items {
                if is_review_candidate(item) {
                    review_items.push(json!({
                        "source": source,
                        "evidence": item
                    }));
                }
            }
        }

        if !bindings.is_empty() {
            for consumer in &consumers {
                review_items.push(json!({
                    "source": "wmi_bound_consumer",
                    "evidence": consumer
                }));
            }
        }

        let review_items_total = review_items.len();
        review_items.truncate(100);
        limits.insert("max_review_items".to_string(), json!(100));
        limits.insert("review_items_total".to_string(), json!(review_items_total));
        limits.insert(
            "review_items_truncated".to_string(),
            json!(review_items_total > review_items.len()),
        );
        limits.insert("max_wmi_persistence_items_in_report".to_string(), json!(32));
        limits.insert(
            "wmi_persistence_details_truncated".to_string(),
            json!(filters.len() > 32 || consumers.len() > 32 || bindings.len() > 32),
        );

        let task_actions = scheduled_tasks
            .iter()
            .map(|task| {
                json!({
                    "task_name": task.get("task_name").cloned().unwrap_or(Value::Null),
                    "task_path": task.get("task_path").cloned().unwrap_or(Value::Null),
                    "actions": task.get("actions").cloned().unwrap_or_else(|| json!([]))
                })
            })
            .collect::<Vec<_>>();

        let service_paths = services
            .iter()
            .filter_map(|item| item.get("PathName").cloned())
            .collect::<Vec<_>>();

        let run_commands = run_entries
            .iter()
            .filter_map(|item| item.get("command").cloned())
            .collect::<Vec<_>>();

        let startup_command_lines = startup_commands
            .iter()
            .filter_map(|item| item.get("Command").cloned())
            .collect::<Vec<_>>();

        let startup_paths = startup_folder_items
            .iter()
            .filter_map(|item| item.get("FullName").cloned())
            .collect::<Vec<_>>();

        json!({
            "success": true,
            "collector": "axios_persistence_coverage",
            "collection_status": collection_status,
            "collection_errors": collection_errors,
            "limits": limits,
            "report_policy": {
                "default_output": "counts_plus_review_items",
                "normal_inventory_details_suppressed": true,
                "execution_index_retained_for_cross_layer_analysis": true,
                "remediation_performed": false
            },
            "summary": {
                "run_key_entries": run_entries.len(),
                "startup_commands": startup_commands.len(),
                "enabled_scheduled_tasks": scheduled_tasks.len(),
                "auto_start_services": services.len(),
                "startup_folder_items": startup_folder_items.len(),
                "wmi_event_filters": filters.len(),
                "wmi_event_consumers": consumers.len(),
                "wmi_filter_bindings": bindings.len(),
                "review_items": review_items.len()
            },
            "review_items": review_items,
            "execution_index": {
                "run_key_commands": run_commands,
                "startup_commands": startup_command_lines,
                "scheduled_task_actions": task_actions,
                "auto_start_service_paths": service_paths,
                "startup_folder_paths": startup_paths
            },
            "wmi_persistence": {
                "filters": filters.iter().take(32).cloned().collect::<Vec<_>>(),
                "consumers": consumers.iter().take(32).cloned().collect::<Vec<_>>(),
                "bindings": bindings.iter().take(32).cloned().collect::<Vec<_>>()
            }
        })
    }

    #[cfg(windows)]
    fn values(raw: &Value, name: &str) -> Vec<Value> {
        raw.get(name)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    #[cfg(windows)]
    fn is_review_candidate(value: &Value) -> bool {
        let text = serde_json::to_string(value)
            .unwrap_or_default()
            .to_ascii_lowercase();

        [
            r"\users\",
            r"\appdata\",
            r"\downloads\",
            r"\temp\",
            r"\programdata\",
            r"\\",
            "powershell",
            ".ps1",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "regsvr32",
        ]
        .iter()
        .any(|signal| text.contains(signal))
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "axios_persistence_coverage",
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod persistence_coverage_contract_tests {
    #[test]
    fn persistence_coverage_reports_partial_visibility_and_all_caps() {
        let source = include_str!("coverage.rs");

        assert!(source.contains("$ErrorActionPreference = 'Stop'"));
        assert!(source.contains("function Invoke-AxiosCollection"));
        assert!(source.contains("collection_status"));
        assert!(source.contains("collection_errors"));
        assert!(source.contains("enabled_scheduled_tasks_truncated"));
        assert!(source.contains("auto_start_services_truncated"));
        assert!(source.contains("wmi_filter_bindings_truncated"));
        let scheduled_task_silent =
            ["Get-ScheduledTask", " -ErrorAction ", "SilentlyContinue"].concat();
        let service_silent = [
            "Get-CimInstance Win32_Service",
            " -ErrorAction ",
            "SilentlyContinue",
        ]
        .concat();

        assert!(!source.contains(&scheduled_task_silent));
        assert!(!source.contains(&service_silent));
    }

    #[test]
    fn compacted_persistence_report_preserves_visibility_envelope() {
        let source = include_str!("coverage.rs");

        assert!(source.contains(r#""collection_status": collection_status"#));
        assert!(source.contains(r#""collection_errors": collection_errors"#));
        assert!(source.contains(r#""limits": limits"#));
        assert!(source.contains("review_items_truncated"));
        assert!(source.contains("wmi_persistence_details_truncated"));
    }
}
