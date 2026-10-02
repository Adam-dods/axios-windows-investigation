use anyhow::{Context, Result};
#[cfg(windows)]
use axios_core::command::powershell;
use axios_core::security::native_authenticode::{verify_file, AuthenticodeVerification};
use clap::Parser;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::Path,
};

const DEFAULT_MAX_PROCESSES: usize = 512;
const MAX_PROCESSES: usize = 1024;
const DEFAULT_MAX_SIGNATURE_CHECKS: usize = 256;
const MAX_FILE_BYTES_TO_HASH: u64 = 256 * 1024 * 1024;

#[derive(Parser, Debug)]
#[command(name = "axios-process-integrity")]
struct Options {
    #[arg(long, default_value_t = DEFAULT_MAX_PROCESSES)]
    max_processes: usize,

    #[arg(long, default_value_t = DEFAULT_MAX_SIGNATURE_CHECKS)]
    max_signature_checks: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawProcess {
    process_id: Option<u32>,
    parent_process_id: Option<u32>,
    name: Option<String>,
    executable_path: Option<String>,
    command_line: Option<String>,
    session_id: Option<u32>,
    creation_date: Option<String>,
}

fn main() -> Result<()> {
    let options = Options::parse();

    if options.max_processes == 0 || options.max_processes > MAX_PROCESSES {
        anyhow::bail!("max-processes must be between 1 and {MAX_PROCESSES}");
    }

    if options.max_signature_checks == 0 || options.max_signature_checks > DEFAULT_MAX_PROCESSES {
        anyhow::bail!("max-signature-checks must be between 1 and {DEFAULT_MAX_PROCESSES}");
    }

    let processes = collect_processes()?;
    let report = build_report(
        &processes,
        options.max_processes,
        options.max_signature_checks,
    );

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(windows)]
fn collect_processes() -> Result<Vec<RawProcess>> {
    let script = r#"
$ErrorActionPreference = 'Stop'
Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, SessionId, CreationDate |
    ConvertTo-Json -Depth 4 -Compress
"#;

    let output = powershell(script).context("failed to start Windows process collector")?;

    if !output.success {
        anyhow::bail!("Windows process collector failed: {}", output.stderr);
    }

    parse_processes(&output.stdout)
}

#[cfg(not(windows))]
fn collect_processes() -> Result<Vec<RawProcess>> {
    anyhow::bail!("axios-process-integrity is supported on Windows only")
}

#[cfg(windows)]
fn parse_processes(input: &str) -> Result<Vec<RawProcess>> {
    let input = input
        .trim()
        .strip_prefix('\u{feff}')
        .unwrap_or(input.trim());

    if input.is_empty() {
        anyhow::bail!("Windows process collector returned empty output");
    }

    let value: Value =
        serde_json::from_str(input).context("Windows process collector returned invalid JSON")?;

    match value {
        Value::Array(_) => serde_json::from_value(value)
            .context("Windows process collector returned invalid process records"),
        Value::Object(_) => Ok(vec![serde_json::from_value(value)
            .context("Windows process collector returned invalid process record")?]),
        _ => anyhow::bail!("Windows process collector returned an unexpected JSON shape"),
    }
}

fn build_report(
    raw_processes: &[RawProcess],
    max_processes: usize,
    max_signature_checks: usize,
) -> Value {
    let mut sorted = raw_processes.to_vec();
    sorted.sort_by_key(|process| process.process_id.unwrap_or(u32::MAX));

    let truncated = sorted.len() > max_processes;
    sorted.truncate(max_processes);

    let known_processes: BTreeMap<u32, String> = sorted
        .iter()
        .filter_map(|process| {
            Some((
                process.process_id?,
                process
                    .name
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            ))
        })
        .collect();

    let mut signature_cache: BTreeMap<String, SignatureEvidence> = BTreeMap::new();
    let mut signature_budget = max_signature_checks;
    let mut artifacts = Vec::with_capacity(sorted.len());

    for process in &sorted {
        artifacts.push(inspect_process(
            process,
            &known_processes,
            &mut signature_cache,
            &mut signature_budget,
        ));
    }

    let trusted = artifacts
        .iter()
        .filter(|artifact| artifact["classification"] == "trusted")
        .count();

    let needs_review = artifacts
        .iter()
        .filter(|artifact| artifact["classification"] == "needs_review")
        .count();

    let unknown = artifacts
        .iter()
        .filter(|artifact| artifact["classification"] == "unknown")
        .count();

    let protected_or_pathless = artifacts
        .iter()
        .filter(|artifact| artifact["executable_path"].is_null())
        .count();

    json!({
        "schema_version": 1,
        "collector": "axios_process_integrity",
        "success": true,
        "signature_engine": "winverifytrust",
        "limits": {
            "max_processes": max_processes,
            "processes_observed": raw_processes.len(),
            "processes_reported": artifacts.len(),
            "processes_truncated": truncated,
            "max_signature_checks": max_signature_checks,
            "signature_checks_performed": max_signature_checks - signature_budget,
            "max_file_bytes_to_hash": MAX_FILE_BYTES_TO_HASH
        },
        "summary": {
            "processes_checked": artifacts.len(),
            "trusted": trusted,
            "needs_review": needs_review,
            "unknown": unknown,
            "protected_or_pathless_processes": protected_or_pathless
        },
        "artifacts": artifacts
    })
}

#[derive(Debug, Clone)]
struct SignatureEvidence {
    file_exists: bool,
    sha256: Option<String>,
    hash_skipped_reason: Option<String>,
    signature: AuthenticodeVerification,
}

fn inspect_process(
    process: &RawProcess,
    known_processes: &BTreeMap<u32, String>,
    signature_cache: &mut BTreeMap<String, SignatureEvidence>,
    signature_budget: &mut usize,
) -> Value {
    let executable_path = process
        .executable_path
        .as_deref()
        .map(normalize_path)
        .filter(|path| !path.is_empty());

    let parent_name = process
        .parent_process_id
        .and_then(|pid| known_processes.get(&pid))
        .cloned();

    let command_line = process.command_line.as_deref().map(redact_command_line);
    let command_signals = command_line_signals(process.command_line.as_deref().unwrap_or_default());

    let Some(path) = executable_path.as_deref() else {
        return json!({
            "pid": process.process_id,
            "parent_pid": process.parent_process_id,
            "parent_name": parent_name,
            "name": process.name,
            "session_id": process.session_id,
            "creation_date": process.creation_date,
            "executable_path": Value::Null,
            "command_line": command_line,
            "command_signals": command_signals,
            "classification": "unknown",
            "reason": "executable_path_unavailable",
            "signature": AuthenticodeVerification::not_checked(),
            "sha256": Value::Null,
            "file_exists": Value::Null,
            "user_writable_location": false,
            "parent_mismatch": false
        });
    };

    let cache_key = path.to_ascii_lowercase();
    let evidence = signature_cache
        .entry(cache_key)
        .or_insert_with(|| inspect_executable(Path::new(path), signature_budget));

    let user_writable = is_user_writable_location(path);
    let parent_mismatch = has_parent_mismatch(
        process.name.as_deref().unwrap_or_default(),
        parent_name.as_deref(),
        path,
    );

    let windows_store_app = is_windows_store_app(path);

    let (classification, reason, analysis_context) = if is_current_axios_process(path) {
        ("context", "axios_self_inspection", "self")
    } else {
        let (classification, reason) = classify_process(
            evidence,
            user_writable,
            parent_mismatch,
            &command_signals,
            windows_store_app,
        );

        (classification, reason, "external")
    };

    json!({
        "pid": process.process_id,
        "parent_pid": process.parent_process_id,
        "parent_name": parent_name,
        "name": process.name,
        "session_id": process.session_id,
        "creation_date": process.creation_date,
        "executable_path": path,
        "command_line": command_line,
        "command_signals": command_signals,
        "classification": classification,
        "reason": reason,
        "analysis_context": analysis_context,
        "signature": evidence.signature,
        "sha256": evidence.sha256,
        "hash_skipped_reason": evidence.hash_skipped_reason,
        "file_exists": evidence.file_exists,
        "user_writable_location": user_writable,
        "parent_mismatch": parent_mismatch,
        "windows_store_app": windows_store_app
    })
}

fn inspect_executable(path: &Path, signature_budget: &mut usize) -> SignatureEvidence {
    if !path.is_file() {
        return SignatureEvidence {
            file_exists: false,
            sha256: None,
            hash_skipped_reason: Some("executable_path_missing_or_access_denied".to_string()),
            signature: AuthenticodeVerification::not_checked(),
        };
    }

    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            return SignatureEvidence {
                file_exists: true,
                sha256: None,
                hash_skipped_reason: Some("metadata_unavailable".to_string()),
                signature: AuthenticodeVerification::not_checked(),
            };
        }
    };

    let (sha256, hash_skipped_reason) = if metadata.len() > MAX_FILE_BYTES_TO_HASH {
        (
            None,
            Some(format!(
                "file_exceeds_hash_budget_{}",
                MAX_FILE_BYTES_TO_HASH
            )),
        )
    } else {
        match sha256_file(path) {
            Ok(hash) => (Some(hash), None),
            Err(_) => (None, Some("hash_read_failed".to_string())),
        }
    };

    let signature = if *signature_budget == 0 {
        AuthenticodeVerification::not_checked()
    } else {
        *signature_budget -= 1;
        verify_file(path)
    };

    SignatureEvidence {
        file_exists: true,
        sha256,
        hash_skipped_reason,
        signature,
    }
}

fn classify_process(
    evidence: &SignatureEvidence,
    user_writable: bool,
    parent_mismatch: bool,
    command_signals: &[String],
    windows_store_app: bool,
) -> (&'static str, &'static str) {
    if !evidence.file_exists {
        return (
            "needs_review",
            "running_process_path_missing_or_access_denied",
        );
    }

    if evidence.signature.checked && evidence.signature.trusted {
        if parent_mismatch {
            return ("needs_review", "trusted_process_with_unexpected_parent");
        }

        return ("trusted", "native_signature_valid");
    }

    if !evidence.signature.checked {
        return ("unknown", "signature_not_checked");
    }

    if user_writable && !command_signals.is_empty() {
        return (
            "needs_review",
            "untrusted_user_writable_process_with_execution_signals",
        );
    }

    if user_writable {
        return (
            "needs_review",
            "untrusted_process_in_user_writable_location",
        );
    }

    if parent_mismatch {
        return ("needs_review", "untrusted_process_with_unexpected_parent");
    }

    if windows_store_app && command_signals.is_empty() {
        return ("context", "windows_store_app_signature_context");
    }

    ("needs_review", "running_process_signature_not_trusted")
}

fn is_windows_store_app(path: &str) -> bool {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();

    normalized.starts_with(r"c:\program files\windowsapps\") && normalized.ends_with(".exe")
}

#[cfg(windows)]
fn is_current_axios_process(path: &str) -> bool {
    let Ok(current_executable) = std::env::current_exe() else {
        return false;
    };

    normalize_path(&current_executable.display().to_string()).eq_ignore_ascii_case(path)
}

#[cfg(not(windows))]
fn is_current_axios_process(_path: &str) -> bool {
    false
}

fn normalize_path(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .strip_prefix(r"\??\")
        .or_else(|| path.trim().trim_matches('"').strip_prefix(r"\\?\"))
        .unwrap_or_else(|| path.trim().trim_matches('"'))
        .to_string()
}

fn is_user_writable_location(path: &str) -> bool {
    let path = path.replace('/', "\\").to_ascii_lowercase();

    [
        r"\users\",
        r"\programdata\",
        r"\windows\temp\",
        r"\temp\",
        r"\downloads\",
        r"\desktop\",
        r"\appdata\",
    ]
    .iter()
    .any(|marker| path.contains(marker))
        && !path.contains(r"\windows\system32\")
        && !path.contains(r"\windows\winsxs\")
}

fn has_parent_mismatch(process_name: &str, parent_name: Option<&str>, path: &str) -> bool {
    let process_name = process_name.to_ascii_lowercase();
    let parent_name = parent_name.unwrap_or_default().to_ascii_lowercase();
    let path = path.replace('/', "\\").to_ascii_lowercase();

    let expected_system_path = path.contains(r"\windows\system32\");

    if !expected_system_path {
        return false;
    }

    match process_name.as_str() {
        "lsass.exe" | "services.exe" | "winlogon.exe" | "csrss.exe" => {
            parent_name != "wininit.exe" && parent_name != "smss.exe"
        }
        "smss.exe" => !parent_name.is_empty(),
        _ => false,
    }
}

fn command_line_signals(command_line: &str) -> Vec<String> {
    let lower = command_line.to_ascii_lowercase();
    let mut signals = BTreeSet::new();

    for (needle, signal) in [
        ("-enc", "encoded_powershell"),
        ("-encodedcommand", "encoded_powershell"),
        ("frombase64string", "base64_decode"),
        ("downloadstring", "network_download"),
        ("invoke-expression", "invoke_expression"),
        (" -executionpolicy bypass", "execution_policy_bypass"),
        (" -windowstyle hidden", "hidden_window"),
        ("mshta.exe", "mshta_execution"),
        ("rundll32.exe", "rundll32_execution"),
        ("regsvr32.exe", "regsvr32_execution"),
        ("wscript.exe", "script_host_execution"),
        ("cscript.exe", "script_host_execution"),
    ] {
        if lower.contains(needle) {
            signals.insert(signal.to_string());
        }
    }

    signals.into_iter().collect()
}

fn redact_command_line(command_line: &str) -> String {
    let mut parts = Vec::new();
    let mut redact_next = false;

    for part in command_line.split_whitespace() {
        let lower = part.to_ascii_lowercase();

        if redact_next {
            parts.push("<redacted>".to_string());
            redact_next = false;
            continue;
        }

        if [
            "-password",
            "--password",
            "-token",
            "--token",
            "-apikey",
            "--apikey",
            "-secret",
            "--secret",
        ]
        .contains(&lower.as_str())
        {
            parts.push(part.to_string());
            redact_next = true;
            continue;
        }

        if ["password=", "token=", "apikey=", "secret="]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        {
            let key = part.split('=').next().unwrap_or("secret");
            parts.push(format!("{key}=<redacted>"));
            continue;
        }

        parts.push(part.to_string());
    }

    parts.join(" ")
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;

        if read == 0 {
            break;
        }

        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_signature() -> SignatureEvidence {
        SignatureEvidence {
            file_exists: true,
            sha256: Some("abc".to_string()),
            hash_skipped_reason: None,
            signature: AuthenticodeVerification {
                checked: true,
                trusted: true,
                status: "Valid".to_string(),
                status_code: Some(0),
                source: "test".to_string(),
            },
        }
    }

    #[test]
    fn system_path_is_not_user_writable() {
        assert!(!is_user_writable_location(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ));
    }

    #[test]
    fn appdata_path_is_user_writable() {
        assert!(is_user_writable_location(
            r"C:\Users\TestUser\AppData\Local\Temp\loader.exe"
        ));
    }

    #[test]
    fn encoded_powershell_is_detected() {
        let signals = command_line_signals(
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand AAAA",
        );

        assert!(signals.contains(&"encoded_powershell".to_string()));
        assert!(signals.contains(&"execution_policy_bypass".to_string()));
    }

    #[test]
    fn non_windows_builds_do_not_treat_external_paths_as_self() {
        #[cfg(not(windows))]
        assert!(!is_current_axios_process(
            r"C:\Users\TestUser\Downloads\axios-process-integrity.exe"
        ));
    }

    #[test]
    fn process_collector_uses_utf8_powershell_wrapper() {
        let source = include_str!("axios-process-integrity.rs");

        assert!(source.contains("powershell(script)"));
        assert!(!source.contains("Command::new(\"powershell.exe\")"));
    }

    #[test]
    fn password_value_is_redacted() {
        let redacted = redact_command_line("tool.exe --password hunter2 --mode test");
        assert_eq!(redacted, "tool.exe --password <redacted> --mode test");
    }

    #[test]
    fn unsigned_user_process_with_signals_requires_review() {
        let evidence = SignatureEvidence {
            file_exists: true,
            sha256: Some("abc".to_string()),
            hash_skipped_reason: None,
            signature: AuthenticodeVerification {
                checked: true,
                trusted: false,
                status: "NotSigned".to_string(),
                status_code: None,
                source: "test".to_string(),
            },
        };

        assert_eq!(
            classify_process(
                &evidence,
                true,
                false,
                &["encoded_powershell".to_string()],
                false,
            ),
            (
                "needs_review",
                "untrusted_user_writable_process_with_execution_signals"
            )
        );
    }

    #[test]
    fn ordinary_windows_store_app_is_context_when_signature_is_unavailable() {
        let evidence = SignatureEvidence {
            file_exists: true,
            sha256: None,
            hash_skipped_reason: None,
            signature: AuthenticodeVerification {
                checked: true,
                trusted: false,
                status: "NotSigned".to_string(),
                status_code: None,
                source: "test".to_string(),
            },
        };

        assert_eq!(
            classify_process(&evidence, false, false, &[], true),
            ("context", "windows_store_app_signature_context")
        );

        assert!(is_windows_store_app(
            r"C:\Program Files\WindowsApps\Example.App_1.0_x64__abc\app.exe"
        ));
    }

    #[test]
    fn trusted_process_is_trusted() {
        assert_eq!(
            classify_process(&valid_signature(), false, false, &[], false),
            ("trusted", "native_signature_valid")
        );
    }

    #[test]
    fn system_lsass_with_wrong_parent_is_detected() {
        assert!(has_parent_mismatch(
            "lsass.exe",
            Some("explorer.exe"),
            r"C:\Windows\System32\lsass.exe"
        ));
    }

    #[test]
    fn protected_system_process_without_path_is_unknown() {
        let report = build_report(
            &[RawProcess {
                process_id: Some(4),
                parent_process_id: Some(0),
                name: Some("System".to_string()),
                executable_path: None,
                command_line: None,
                session_id: Some(0),
                creation_date: None,
            }],
            32,
            16,
        );

        assert_eq!(report["summary"]["unknown"], 1);
    }
}
