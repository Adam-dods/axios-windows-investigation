use chrono::{DateTime, Utc};
use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

#[cfg(windows)]
const MAX_SOURCE_EVENTS_PER_LOG: usize = 400;
#[cfg(windows)]
const MAX_RELEVANT_EVENTS: usize = 160;
#[cfg(windows)]
const MAX_MESSAGE_LENGTH: usize = 1024;

pub fn collect_since(since: DateTime<Utc>) -> Value {
    #[cfg(windows)]
    {
        let timestamp = since.to_rfc3339();

        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$since = [DateTime]::Parse('{timestamp}').ToUniversalTime()
$maxSourceEventsPerLog = {MAX_SOURCE_EVENTS_PER_LOG}
$maxRelevantEvents = {MAX_RELEVANT_EVENTS}
$maxMessageLength = {MAX_MESSAGE_LENGTH}

$logNames = @(
    'System',
    'Application',
    'Security',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-TaskScheduler/Operational'
)

$errors = [System.Collections.Generic.List[string]]::new()
$summaries = [System.Collections.Generic.List[object]]::new()
$relevantEvents = [System.Collections.Generic.List[object]]::new()

$relevantIdsByLog = @{{
    'System' = @(7045)
    'Application' = @()
    'Security' = @(1102, 4697, 4698, 4702)
    'Microsoft-Windows-Windows Defender/Operational' = @(1116, 1117, 5001, 5004)
    'Microsoft-Windows-TaskScheduler/Operational' = @(106, 140, 141)
}}

$eventTime = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

foreach ($logName in $logNames) {{
    try {{
        $relevantIds = @($relevantIdsByLog[$logName])
        $selectionPredicate = 'Level=1 or Level=2 or Level=3'

        if ($relevantIds.Count -gt 0) {{
            $eventIdPredicate = (
                $relevantIds |
                    ForEach-Object {{ "EventID=$_" }}
            ) -join ' or '

            $selectionPredicate = "($selectionPredicate) or ($eventIdPredicate)"
        }}

        $filterXPath = (
            "*[System[TimeCreated[@SystemTime >= '$eventTime'] and " +
            "($selectionPredicate)]]"
        )

        $sourceEvents = @(
            Get-WinEvent `
                -LogName $logName `
                -FilterXPath $filterXPath `
                -MaxEvents $maxSourceEventsPerLog `
                -ErrorAction Stop
        )

        $warningCount = @(
            $sourceEvents | Where-Object {{ $_.LevelDisplayName -eq 'Warning' }}
        ).Count

        $errorCount = @(
            $sourceEvents | Where-Object {{
                $_.LevelDisplayName -in @('Error', 'Critical')
            }}
        ).Count

        $defenderRelevantIds = @(1116, 1117, 5001, 5004)
        $securityRelevantIds = @(1102, 4697, 4698, 4702)
        $systemRelevantIds = @(7045)
        $taskSchedulerRelevantIds = @(106, 140, 141)

        $selectedEvents = @(
            $sourceEvents | Where-Object {{
                $_.LevelDisplayName -in @('Warning', 'Error', 'Critical') -or
                ($logName -eq 'Security' -and $_.Id -in $securityRelevantIds) -or
                ($logName -eq 'System' -and $_.Id -in $systemRelevantIds) -or
                (
                    $logName -eq
                    'Microsoft-Windows-Windows Defender/Operational' -and
                    $_.Id -in $defenderRelevantIds
                ) -or
                (
                    $logName -eq
                    'Microsoft-Windows-TaskScheduler/Operational' -and
                    $_.Id -in $taskSchedulerRelevantIds
                )
            }}
        )

        $summaries.Add([PSCustomObject]@{{
            log_name = $logName
            source_events_read = $sourceEvents.Count
            warnings = $warningCount
            errors_and_critical = $errorCount
            selected_events = $selectedEvents.Count
            source_limit_reached =
                $sourceEvents.Count -ge $maxSourceEventsPerLog
        }})

        foreach ($event in ($selectedEvents | Select-Object -First $maxRelevantEvents)) {{
            $message = [string]$event.Message
            $message = $message -replace '\s+', ' '

            if ($message.Length -gt $maxMessageLength) {{
                $message = $message.Substring(0, $maxMessageLength) + '...'
            }}

            $classification = 'operational_event'

            if ($logName -eq 'Security' -and $event.Id -eq 1102) {{
                $classification = 'security_audit_log_cleared'
            }}
            elseif ($logName -eq 'Security' -and $event.Id -eq 4697) {{
                $classification = 'service_installation'
            }}
            elseif ($logName -eq 'Security' -and $event.Id -eq 4698) {{
                $classification = 'scheduled_task_created'
            }}
            elseif ($logName -eq 'Security' -and $event.Id -eq 4702) {{
                $classification = 'scheduled_task_updated'
            }}
            elseif (
                $logName -eq
                'Microsoft-Windows-Windows Defender/Operational' -and
                $event.Id -eq 1116
            ) {{
                $classification = 'defender_detection'
            }}
            elseif ($logName -eq 'System' -and $event.Id -eq 7045) {{
                $classification = 'service_installation'
            }}
            elseif (
                $logName -eq
                'Microsoft-Windows-TaskScheduler/Operational' -and
                $event.Id -eq 106
            ) {{
                $classification = 'scheduled_task_registered'
            }}
            elseif (
                $logName -eq
                'Microsoft-Windows-TaskScheduler/Operational' -and
                $event.Id -in @(140, 141)
            ) {{
                $classification = 'scheduled_task_updated'
            }}

            $relevantEvents.Add([PSCustomObject]@{{
                log_name = $logName
                timestamp = $event.TimeCreated.ToUniversalTime().ToString('o')
                event_id = [int]$event.Id
                level = [string]$event.LevelDisplayName
                provider = [string]$event.ProviderName
                classification = $classification
                message = $message
            }})
        }}
    }}
    catch {{
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {{
            $summaries.Add([PSCustomObject]@{{
                log_name = $logName
                source_events_read = 0
                warnings = 0
                errors_and_critical = 0
                selected_events = 0
                source_limit_reached = $false
            }})
        }}
        else {{
            $errors.Add("$logName collection failed: $($_.Exception.Message)")
        }}
    }}
}}

$eventsTruncated = $relevantEvents.Count -gt $maxRelevantEvents
$collectionStatus = if ($errors.Count -eq 0) {{
    'complete'
}}
elseif ($summaries.Count -gt 0) {{
    'partial'
}}
else {{
    'failed'
}}

[PSCustomObject]@{{
    success = $collectionStatus -eq 'complete'
    collector = 'windows_event_log'
    collection_status = $collectionStatus
    since = $since.ToString('o')
    limits = @{{
        max_source_events_per_log = $maxSourceEventsPerLog
        max_relevant_events = $maxRelevantEvents
        max_message_length = $maxMessageLength
        relevant_events_truncated = $eventsTruncated
        selection_mode = 'server_side_level_and_event_id_filter'
    }}
    summaries = @($summaries)
    relevant_events = @($relevantEvents | Select-Object -First $maxRelevantEvents)
    errors = @($errors)
}} | ConvertTo-Json -Depth 8 -Compress
"#
        );

        match powershell(&script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_event_log",
                "collection_status": "failed",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_event_log",
            "collection_status": "unsupported",
            "reason": "Windows-only collector",
            "since": since.to_rfc3339()
        })
    }
}

pub fn collection_succeeded(result: &Value) -> bool {
    result
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && result
            .get("collection_status")
            .and_then(Value::as_str)
            .map(|status| status == "complete")
            .unwrap_or(false)
}

pub fn event_risk_score(level: &str, event_id: u32) -> u32 {
    match event_id {
        1102 => 70,
        1116 => 60,
        4697 | 4698 | 4702 | 7045 | 106 | 140 | 141 => 20,
        5001 | 5004 => 30,
        _ if level.trim().eq_ignore_ascii_case("critical") => 10,
        _ if level.trim().eq_ignore_ascii_case("error") => 5,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_clear_is_high_priority() {
        assert_eq!(event_risk_score("Information", 1102), 70);
    }

    #[test]
    fn service_installation_is_a_review_signal_not_a_malware_verdict() {
        assert_eq!(event_risk_score("Information", 7045), 20);
    }

    #[test]
    fn scheduled_task_registration_is_collected_for_review() {
        assert_eq!(event_risk_score("Information", 106), 20);
    }

    #[test]
    fn warning_is_context_not_risk_verdict() {
        assert_eq!(event_risk_score("Warning", 0), 0);
    }

    #[test]
    fn complete_collection_advances_cursor() {
        assert!(collection_succeeded(&json!({
            "success": true,
            "collection_status": "complete"
        })));
    }

    #[test]
    fn partial_collection_does_not_advance_cursor() {
        assert!(!collection_succeeded(&json!({
            "success": true,
            "collection_status": "partial"
        })));
    }

    #[test]
    fn an_empty_event_log_is_not_a_collection_failure() {
        let source = include_str!("windows_events.rs");

        assert!(source.contains("NoMatchingEventsFound*"));
        assert!(source.contains("source_events_read = 0"));
    }

    #[test]
    fn event_collection_uses_server_side_relevant_filter() {
        let source = include_str!("windows_events.rs");

        let legacy_query = concat!("Get-WinEvent -Filter", "Hashtable");

        assert!(source.contains("-FilterXPath $filterXPath"));
        assert!(source.contains("Level=1 or Level=2 or Level=3"));
        assert!(source.contains("server_side_level_and_event_id_filter"));
        assert!(!source.contains(legacy_query));
    }
}
