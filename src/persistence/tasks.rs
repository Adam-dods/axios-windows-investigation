use crate::command::{parse_json_output, powershell};
use serde_json::{json, Value};

pub const MAX_SCHEDULED_TASKS: usize = 2048;
pub const MAX_TASK_ACTIONS: usize = 64;
pub const MAX_TASK_TRIGGERS: usize = 64;

pub fn collect() -> Value {
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$maxTasks = {MAX_SCHEDULED_TASKS}
$maxActions = {MAX_TASK_ACTIONS}
$maxTriggers = {MAX_TASK_TRIGGERS}
$collectionErrors = [System.Collections.Generic.List[string]]::new()

$allTasks = @(
    try {{
        Get-ScheduledTask -ErrorAction Stop | Sort-Object TaskPath, TaskName
    }}
    catch {{
        $collectionErrors.Add(("scheduled_tasks: {{0}}" -f $_.Exception.Message))
        @()
    }}
)

$tasks = @(
    $allTasks |
        Select-Object -First $maxTasks |
        ForEach-Object {{
            $task = $_
            $allActions = @($task.Actions)
            $allTriggers = @($task.Triggers)
            $actions = @($allActions | Select-Object -First $maxActions)
            $triggers = @($allTriggers | Select-Object -First $maxTriggers)

            [PSCustomObject]@{{
                task_name = $task.TaskName
                task_path = $task.TaskPath
                state = [string]$task.State
                author = $task.Author
                description = $task.Description
                actions = @($actions | ForEach-Object {{
                    [PSCustomObject]@{{
                        execute = $_.Execute
                        arguments = $_.Arguments
                        working_directory = $_.WorkingDirectory
                    }}
                }})
                actions_truncated = ($allActions.Count -gt $actions.Count)
                triggers = @($triggers | ForEach-Object {{
                    [PSCustomObject]@{{
                        enabled = $_.Enabled
                        start_boundary = $_.StartBoundary
                        end_boundary = $_.EndBoundary
                    }}
                }})
                triggers_truncated = ($allTriggers.Count -gt $triggers.Count)
            }}
        }}
)

[PSCustomObject]@{{
    success = $true
    collector = 'windows_scheduled_tasks'
    collection_status = if ($collectionErrors.Count -eq 0) {{ 'complete' }} else {{ 'partial' }}
    collection_errors = @($collectionErrors)
    limits = @{{
        max_scheduled_tasks = $maxTasks
        scheduled_tasks_total = $allTasks.Count
        scheduled_tasks_truncated = ($allTasks.Count -gt $tasks.Count)
        max_actions_per_task = $maxActions
        max_triggers_per_task = $maxTriggers
    }}
    tasks = $tasks
}} | ConvertTo-Json -Depth 10 -Compress
"#
    );

    match powershell(&script) {
        Ok(result) => parse_json_output(result),
        Err(error) => json!({
            "success": false,
            "collector": "windows_scheduled_tasks",
            "error": error.to_string()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_collection_is_bounded_and_truthful() {
        let source = include_str!("tasks.rs");

        assert_eq!(MAX_SCHEDULED_TASKS, 2048);
        assert!(source.contains("collection_status"));
        assert!(source.contains("collection_errors"));
        assert!(source.contains("scheduled_tasks_truncated"));
        assert!(source.contains("actions_truncated"));
        assert!(source.contains("triggers_truncated"));
    }
}
