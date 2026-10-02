use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::env;

#[cfg(windows)]
use axios_core::command::powershell;

fn main() -> Result<()> {
    let Some((days, max_events)) = options()? else {
        return Ok(());
    };
    let source = collect(days, max_events)?;

    let detections = source["threat_detections"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);

    let actions = source["threat_actions"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);

    let operational_events = source["operational_events"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "success": true,
            "collector": "axios_defender_evidence",
            "collection_window_days": days,
            "summary": {
                "threat_detections": detections,
                "threat_actions": actions,
                "operational_events": operational_events
            },
            "source": source,
            "interpretation": {
                "malware_confirmed": false,
                "note": "Defender detections are evidence requiring review. Their absence does not prove that no threat exists."
            }
        }))?
    );

    Ok(())
}

fn options() -> Result<Option<(u32, u32)>> {
    options_from(env::args().skip(1))
}

fn options_from<I, S>(arguments: I) -> Result<Option<(u32, u32)>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut days = 30u32;
    let mut max_events = 500u32;
    let mut days_seen = false;
    let mut max_events_seen = false;
    let mut args = arguments.into_iter().map(Into::into);

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--days" => {
                if days_seen {
                    bail!("--days was supplied more than once");
                }
                days_seen = true;
                days = args
                    .next()
                    .context("--days needs a number")?
                    .parse()
                    .context("--days must be a number")?;
            }
            "--max-events" => {
                if max_events_seen {
                    bail!("--max-events was supplied more than once");
                }
                max_events_seen = true;
                max_events = args
                    .next()
                    .context("--max-events needs a number")?
                    .parse()
                    .context("--max-events must be a number")?;
            }
            "--help" => {
                println!("Usage: axios-defender-evidence.exe [--days 30] [--max-events 500]");
                return Ok(None);
            }
            _ => bail!("unknown argument: {flag}"),
        }
    }

    if !(1..=365).contains(&days) {
        bail!("--days must be between 1 and 365");
    }
    if !(1..=2000).contains(&max_events) {
        bail!("--max-events must be between 1 and 2000");
    }

    Ok(Some((days, max_events)))
}

#[cfg(windows)]
fn collect(days: u32, max_events: u32) -> Result<Value> {
    let script = r#"
$days = __AXIOS_DAYS__
$maxEvents = __AXIOS_MAX_EVENTS__
$start = (Get-Date).AddDays(-$days)

$threatDetections = @(
    Get-MpThreatDetection -ErrorAction Stop |
        Select-Object InitialDetectionTime, ThreatName, Resources,
            ActionSuccess, CurrentThreatExecutionStatus,
            ThreatStatusID, ProcessName
)

$threatActions = @(
    Get-MpThreat -ErrorAction Stop |
        Select-Object ThreatName, Resources, IsActive,
            DidThreatExecute, ActionSuccess, LastThreatStatusChangeTime
)

$operationalEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Windows Defender/Operational"
        StartTime = $start
    } -ErrorAction Stop |
        Where-Object {
            $_.Id -in 1116, 1117, 1118, 1119, 1121, 1122, 5007
        } |
        Select-Object -First $maxEvents |
        ForEach-Object {
            [PSCustomObject]@{
                id = $_.Id
                time_created = $_.TimeCreated
                provider = $_.ProviderName
                level = $_.LevelDisplayName
                message = $_.Message
            }
        }
)

$status = Get-MpComputerStatus -ErrorAction Stop |
    Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled,
        AntispywareEnabled, BehaviorMonitorEnabled,
        AntivirusSignatureLastUpdated, AntivirusSignatureVersion

[PSCustomObject]@{
    threat_detections = $threatDetections
    threat_actions = $threatActions
    operational_events = $operationalEvents
    status = $status
} | ConvertTo-Json -Depth 8 -Compress
"#
    .replace("__AXIOS_DAYS__", &days.to_string())
    .replace("__AXIOS_MAX_EVENTS__", &max_events.to_string());

    let output = powershell(&script).context("failed to start Defender evidence collector")?;

    if !output.success {
        bail!("Defender evidence collector failed: {}", output.stderr);
    }

    serde_json::from_str(&output.stdout)
        .context("Defender evidence collector returned invalid JSON")
}

#[cfg(not(windows))]
fn collect(_days: u32, _max_events: u32) -> Result<Value> {
    Ok(json!({
        "threat_detections": [],
        "threat_actions": [],
        "operational_events": [],
        "status": null,
        "platform_note": "Windows-only collector"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_defaults_are_bounded() {
        let (days, max_events) = options_from(Vec::<String>::new()).unwrap().unwrap();
        assert_eq!(days, 30);
        assert_eq!(max_events, 500);
    }

    #[test]
    fn invalid_limits_and_duplicate_scalar_flags_are_rejected() {
        assert!(options_from(["--days", "0"]).is_err());
        assert!(options_from(["--max-events", "2001"]).is_err());
        assert!(options_from(["--days", "7", "--days", "8"]).is_err());
        assert!(options_from(["--max-events", "50", "--max-events", "51"]).is_err());
    }

    #[test]
    fn help_returns_without_starting_collection() {
        assert!(options_from(["--help"]).unwrap().is_none());
    }

    #[test]
    fn source_uses_utf8_powershell_wrapper() {
        let source = include_str!("axios-defender-evidence.rs");
        assert!(source.contains("powershell(&script)"));
        assert!(!source.contains("Command::new(\"powershell.exe\")"));
    }

    #[test]
    fn defender_collection_does_not_suppress_required_errors() {
        let source = include_str!("axios-defender-evidence.rs");
        let suppressed = concat!("Get-MpThreatDetection -ErrorAction ", "SilentlyContinue");

        assert!(!source.contains(suppressed));
        assert!(source.contains("Get-MpThreatDetection -ErrorAction Stop"));
        assert!(source.contains("Get-MpThreat -ErrorAction Stop"));
        assert!(source.contains("Get-MpComputerStatus -ErrorAction Stop"));
    }
}
