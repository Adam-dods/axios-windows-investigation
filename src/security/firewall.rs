use crate::command::{parse_json_output, powershell};
use serde_json::{json, Value};

pub fn collect() -> Value {
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'

$profiles = Get-NetFirewallProfile |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
        AllowInboundRules, AllowLocalFirewallRules, LogAllowed, LogBlocked,
        LogFileName, LogMaxSizeKilobytes

[PSCustomObject]@{
    profiles = @($profiles)
} | ConvertTo-Json -Depth 6 -Compress
"#;

    match powershell(script) {
        Ok(result) => parse_json_output(result),
        Err(error) => json!({
            "success": false,
            "error": error.to_string()
        }),
    }
}
