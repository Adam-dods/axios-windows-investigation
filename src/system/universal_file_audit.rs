#[cfg(windows)]
use anyhow::Context;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;

pub const DEFAULT_MAX_ARTIFACTS: usize = 1_500;
pub const SMART_MAX_ARTIFACTS: usize = 2_000;
pub const FAST_MAX_ARTIFACTS: usize = 3_000;
pub const FAST_DEEP_VERIFICATION_BUDGET: usize = 128;
pub const FAST_TIME_BUDGET_SECONDS: u64 = 90;
pub const HARD_MAX_ARTIFACTS: usize = 25_000;
pub const MAX_SCRIPT_CONTENT_BYTES: u64 = 1_048_576;
pub const MAX_HASH_FILE_BYTES: u64 = 268_435_456;
pub const SMART_HASH_BUDGET: usize = 512;
pub const SIGNATURE_CHECK_BUDGET: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    Smart,
    Fast,
    Targeted,
    Full,
}

impl AuditMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "smart" => Ok(Self::Smart),
            "fast" => Ok(Self::Fast),
            "targeted" => Ok(Self::Targeted),
            "full" => Ok(Self::Full),
            _ => bail!("invalid audit mode: {value}; expected smart, targeted or full"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smart => "smart",
            Self::Fast => "fast",
            Self::Targeted => "targeted",
            Self::Full => "full",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub mode: AuditMode,
    pub max_artifacts: usize,
    pub recent_days: u64,
    pub roots: Vec<PathBuf>,
    pub seed_reports: Vec<PathBuf>,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            mode: AuditMode::Smart,
            max_artifacts: DEFAULT_MAX_ARTIFACTS,
            recent_days: 30,
            roots: Vec::new(),
            seed_reports: Vec::new(),
        }
    }
}

pub fn collect(max_artifacts: usize) -> Result<Value> {
    collect_with_options(&AuditOptions {
        max_artifacts,
        ..AuditOptions::default()
    })
}

pub fn collect_with_options(options: &AuditOptions) -> Result<Value> {
    #[cfg(windows)]
    {
        collect_windows(options)
    }

    #[cfg(not(windows))]
    {
        let effective_limit = effective_limit(options.mode, options.max_artifacts);

        Ok(json!({
            "schema_version": 2,
            "collector": "axios_universal_file_audit",
            "success": false,
            "platform_supported": false,
            "scan_scope": {
                "mode": options.mode.as_str(),
                "requested_max_artifacts": options.max_artifacts,
                "effective_max_artifacts": effective_limit,
                "recent_days": options.recent_days,
                "rust_native_discovery": true
            }
        }))
    }
}

pub fn effective_limit(mode: AuditMode, requested: usize) -> usize {
    let requested = if requested == 0 {
        DEFAULT_MAX_ARTIFACTS
    } else {
        requested
    };

    match mode {
        AuditMode::Smart => requested.min(SMART_MAX_ARTIFACTS),
        AuditMode::Fast => requested.min(FAST_MAX_ARTIFACTS),
        AuditMode::Targeted | AuditMode::Full => requested.min(HARD_MAX_ARTIFACTS),
    }
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct Candidate {
    path: PathBuf,
    sources: std::collections::BTreeSet<String>,
}

#[cfg(windows)]
#[derive(Debug, Clone, Default, Deserialize)]
struct WindowsEnrichment {
    path: String,
    signature_checked: bool,
    signature_status: String,
    signer: Option<String>,
    zone_identifier_present: bool,
    file_description: Option<String>,
    product_name: Option<String>,
    product_version: Option<String>,
}

#[cfg(windows)]
#[derive(Debug, Serialize)]
struct AuditArtifact {
    path: String,
    file_name: String,
    extension: String,
    size_bytes: u64,
    created_utc: Option<String>,
    modified_utc: Option<String>,
    sha256: Option<String>,
    hash_status: String,
    signature_checked: bool,
    signature_status: String,
    signer: Option<String>,
    zone_identifier_present: bool,
    user_writable_location: bool,
    file_description: Option<String>,
    product_name: Option<String>,
    product_version: Option<String>,
    script_indicators: Vec<String>,
    candidate_sources: Vec<String>,
    classification: String,
    classification_evidence: Vec<String>,
}

#[cfg(windows)]
fn collect_windows(options: &AuditOptions) -> Result<Value> {
    use std::{
        collections::HashMap,
        fs,
        time::{Duration, Instant},
    };

    let started = Instant::now();
    let effective_max = effective_limit(options.mode, options.max_artifacts);
    let fast_time_budget =
        (options.mode == AuditMode::Fast).then_some(Duration::from_secs(FAST_TIME_BUDGET_SECONDS));
    let mut time_budget_reached = false;

    let mut candidates = Vec::<Candidate>::new();
    let mut candidate_indexes = HashMap::<String, usize>::new();
    let mut errors = Vec::<String>::new();
    let mut truncated = false;

    for report_path in &options.seed_reports {
        match read_json_value(report_path) {
            Ok(value) => {
                let mut strings = Vec::new();
                collect_strings(&value, 10_000, &mut strings);

                for text in strings {
                    let Some(path) = extract_windows_file_path(&text) else {
                        continue;
                    };

                    add_candidate(
                        path,
                        "seed_report",
                        effective_max,
                        &mut candidates,
                        &mut candidate_indexes,
                    );

                    if candidates.len() >= effective_max {
                        truncated = true;
                        break;
                    }
                }
            }
            Err(error) => push_error(
                &mut errors,
                format!("Seed report failed: {}: {error}", report_path.display()),
            ),
        }

        if candidates.len() >= effective_max {
            break;
        }
    }

    let roots = resolve_roots(options);
    let root_count = roots.len().max(1);

    let per_root_budget = match options.mode {
        AuditMode::Full => effective_max,
        AuditMode::Smart | AuditMode::Fast | AuditMode::Targeted => {
            (effective_max / root_count).max(64)
        }
    };

    for root in &roots {
        if fast_time_budget
            .map(|budget| started.elapsed() >= budget)
            .unwrap_or(false)
        {
            truncated = true;
            time_budget_reached = true;
            break;
        }

        if candidates.len() >= effective_max {
            truncated = true;
            break;
        }

        scan_root(
            root,
            options,
            per_root_budget,
            effective_max,
            &mut candidates,
            &mut candidate_indexes,
            &mut errors,
            &mut truncated,
            started,
            fast_time_budget,
            &mut time_budget_reached,
        );
    }

    let enrichment_paths: Vec<String> = candidates
        .iter()
        .map(|candidate| candidate.path.to_string_lossy().to_string())
        .collect();

    let signature_budget = if options.mode == AuditMode::Fast {
        FAST_DEEP_VERIFICATION_BUDGET
    } else {
        SIGNATURE_CHECK_BUDGET
    };

    let (signature_checks, enrichments) =
        match collect_windows_enrichments(&enrichment_paths, signature_budget) {
            Ok(result) => result,
            Err(error) => {
                push_error(&mut errors, format!("Windows enrichment failed: {error}"));

                (0, Vec::new())
            }
        };

    let enrichment_map: HashMap<String, WindowsEnrichment> = enrichments
        .into_iter()
        .map(|item| (normalize_path_string(&item.path), item))
        .collect();

    let hash_budget = match options.mode {
        AuditMode::Full => effective_max,
        AuditMode::Fast => FAST_DEEP_VERIFICATION_BUDGET,
        AuditMode::Smart | AuditMode::Targeted => SMART_HASH_BUDGET,
    };

    let mut hashes_computed = 0usize;
    let mut hashes_skipped = 0usize;
    let mut artifacts = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        if fast_time_budget
            .map(|budget| started.elapsed() >= budget)
            .unwrap_or(false)
        {
            truncated = true;
            time_budget_reached = true;
            break;
        }

        let path = candidate.path;
        let normalized = normalize_path(&path);

        let metadata = match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => continue,
            Err(error) => {
                push_error(
                    &mut errors,
                    format!("Metadata failed: {}: {error}", path.display()),
                );

                continue;
            }
        };

        let extension = extension_of(&path);
        let user_writable_location = is_user_writable_path(&path);

        let script_indicators = inspect_script_indicators(&path, metadata.len());

        let enrichment =
            enrichment_map
                .get(&normalized)
                .cloned()
                .unwrap_or_else(|| WindowsEnrichment {
                    path: path.to_string_lossy().to_string(),
                    signature_checked: false,
                    signature_status: "NotChecked".to_string(),
                    ..WindowsEnrichment::default()
                });

        let (classification, classification_evidence) = classify_with_evidence(
            &extension,
            user_writable_location,
            enrichment.signature_checked,
            &enrichment.signature_status,
            enrichment.zone_identifier_present,
            &script_indicators,
        );

        let should_hash = options.mode == AuditMode::Full
            || classification == "needs_review"
            || candidate.sources.contains("seed_report");

        let (sha256, hash_status) = if !should_hash {
            hashes_skipped += 1;
            (None, "not_required_for_smart_scan".to_string())
        } else if hashes_computed >= hash_budget {
            hashes_skipped += 1;
            (None, "hash_budget_reached".to_string())
        } else if metadata.len() > MAX_HASH_FILE_BYTES {
            hashes_skipped += 1;
            (None, "file_too_large".to_string())
        } else {
            match hash_file(&path) {
                Ok(hash) => {
                    hashes_computed += 1;
                    (Some(hash), "computed".to_string())
                }
                Err(error) => {
                    hashes_skipped += 1;

                    push_error(
                        &mut errors,
                        format!("Hash failed: {}: {error}", path.display()),
                    );

                    (None, "failed".to_string())
                }
            }
        };

        artifacts.push(AuditArtifact {
            path: path.to_string_lossy().to_string(),
            file_name: path
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_default(),
            extension,
            size_bytes: metadata.len(),
            created_utc: metadata.created().ok().map(system_time_to_rfc3339),
            modified_utc: metadata.modified().ok().map(system_time_to_rfc3339),
            sha256,
            hash_status,
            signature_checked: enrichment.signature_checked,
            signature_status: enrichment.signature_status,
            signer: enrichment.signer,
            zone_identifier_present: enrichment.zone_identifier_present,
            user_writable_location,
            file_description: enrichment.file_description,
            product_name: enrichment.product_name,
            product_version: enrichment.product_version,
            script_indicators,
            candidate_sources: candidate.sources.into_iter().collect(),
            classification,
            classification_evidence,
        });
    }

    artifacts.sort_by(|left, right| {
        classification_rank(&right.classification)
            .cmp(&classification_rank(&left.classification))
            .then_with(|| left.path.cmp(&right.path))
    });

    let signed = artifacts
        .iter()
        .filter(|item| item.classification == "signed")
        .count();

    let unknown = artifacts
        .iter()
        .filter(|item| item.classification == "unknown")
        .count();

    let needs_review = artifacts
        .iter()
        .filter(|item| item.classification == "needs_review")
        .count();

    let scanned_roots: Vec<String> = roots
        .iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect();

    let mut collection_limitations = Vec::<String>::new();

    if truncated {
        if time_budget_reached {
            collection_limitations
                .push("File audit time budget was reached; scan coverage is partial".to_string());
        } else {
            collection_limitations.push(
                "File audit candidate budget limited scan coverage; see scan_scope".to_string(),
            );
        }
    }

    if !errors.is_empty() {
        collection_limitations.push(format!(
            "File audit encountered {} collection errors; see report errors",
            errors.len()
        ));
    }

    let collection_status = if collection_limitations.is_empty() {
        "complete"
    } else {
        "partial"
    };

    Ok(json!({
        "schema_version": 2,
        "collector": "axios_universal_file_audit",
        "success": true,
        "collection_status": collection_status,
        "collection_errors": collection_limitations,
        "duration_ms": started.elapsed().as_millis(),
        "scan_scope": {
            "mode": options.mode.as_str(),
            "requested_max_artifacts": options.max_artifacts,
            "effective_max_artifacts": effective_max,
            "smart_mode_hard_limit": SMART_MAX_ARTIFACTS,
            "recent_days": options.recent_days,
            "scanned_roots": scanned_roots,
            "seed_reports": options
                .seed_reports
                .iter()
                .map(|path| {
                    path.to_string_lossy().to_string()
                })
                .collect::<Vec<_>>(),
            "rust_native_discovery": true,
            "full_drive_enumeration": (
                options.mode == AuditMode::Full
            ),
            "per_root_candidate_budget": per_root_budget,
            "signature_check_budget": signature_budget,
            "fast_time_budget_seconds": fast_time_budget.map(|budget| budget.as_secs()),
            "time_budget_reached": time_budget_reached,
            "signature_engine": "winverifytrust",
            "hash_budget": hash_budget,
            "max_hash_file_bytes": MAX_HASH_FILE_BYTES,
            "truncated": truncated
        },
        "summary": {
            "artifacts": artifacts.len(),
            "signed": signed,
            "unknown": unknown,
            "needs_review": needs_review,
            "signature_checks": signature_checks,
            "hashes_computed": hashes_computed,
            "hashes_skipped": hashes_skipped,
            "errors": errors.len()
        },
        "artifacts": artifacts,
        "errors": errors
    }))
}

#[cfg(windows)]
fn resolve_roots(options: &AuditOptions) -> Vec<PathBuf> {
    use std::{collections::HashSet, env, path::Path};

    let mut roots = options.roots.clone();

    if roots.is_empty()
        || options.mode == AuditMode::Smart
        || options.mode == AuditMode::Fast
        || options.mode == AuditMode::Full
    {
        let user_profile = env::var_os("USERPROFILE").map(PathBuf::from);

        let app_data = env::var_os("APPDATA").map(PathBuf::from);

        let local_app_data = env::var_os("LOCALAPPDATA").map(PathBuf::from);

        let program_data = env::var_os("ProgramData").map(PathBuf::from);

        let system_root = env::var_os("SystemRoot").map(PathBuf::from);

        if let Some(profile) = &user_profile {
            roots.push(profile.join("Downloads"));
            roots.push(profile.join("Desktop"));
        }

        if let Some(path) = &app_data {
            roots.push(path.join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
            roots.push(path.clone());
        }

        if let Some(path) = &local_app_data {
            roots.push(path.join("Temp"));
            roots.push(path.clone());
        }

        if let Some(path) = &program_data {
            roots.push(path.join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
        }

        if let Some(path) = &system_root {
            roots.push(path.join(r"System32\Tasks"));
            roots.push(path.join("Temp"));
        }

        if options.mode == AuditMode::Full {
            if let Some(path) = env::var_os("ProgramFiles").map(PathBuf::from) {
                roots.push(path);
            }

            if let Some(path) = env::var_os("ProgramFiles(x86)").map(PathBuf::from) {
                roots.push(path);
            }

            if let Some(path) = program_data {
                roots.push(path);
            }

            for drive in b'C'..=b'Z' {
                let path = PathBuf::from(format!("{}:\\", drive as char));

                if path.exists() {
                    roots.push(path);
                }
            }
        }
    }

    let mut seen = HashSet::new();

    roots
        .into_iter()
        .filter(|path| Path::new(path).exists())
        .filter(|path| seen.insert(normalize_path(path)))
        .collect()
}

#[cfg(windows)]
fn scan_root(
    root: &std::path::Path,
    options: &AuditOptions,
    root_budget: usize,
    effective_max: usize,
    candidates: &mut Vec<Candidate>,
    indexes: &mut std::collections::HashMap<String, usize>,
    errors: &mut Vec<String>,
    truncated: &mut bool,
    started: std::time::Instant,
    fast_time_budget: Option<std::time::Duration>,
    time_budget_reached: &mut bool,
) {
    use walkdir::WalkDir;

    let max_depth = match options.mode {
        AuditMode::Full => usize::MAX,
        AuditMode::Smart | AuditMode::Fast | AuditMode::Targeted => 10,
    };

    let mut added_from_root = 0usize;

    let walker = WalkDir::new(root)
        .follow_links(false)
        .max_depth(max_depth)
        .into_iter()
        .filter_entry(should_descend);

    for entry in walker {
        if fast_time_budget
            .map(|budget| started.elapsed() >= budget)
            .unwrap_or(false)
        {
            *truncated = true;
            *time_budget_reached = true;
            break;
        }

        if candidates.len() >= effective_max || added_from_root >= root_budget {
            *truncated = true;
            break;
        }

        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                push_error(errors, format!("Walk failed: {}: {error}", root.display()));

                continue;
            }
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();

        if !eligible_path(path) {
            continue;
        }

        if matches!(options.mode, AuditMode::Smart | AuditMode::Fast)
            && !smart_candidate(path, options.recent_days)
        {
            continue;
        }

        let before = candidates.len();

        add_candidate(
            path.to_path_buf(),
            "selective_root",
            effective_max,
            candidates,
            indexes,
        );

        if candidates.len() > before {
            added_from_root += 1;
        }
    }
}

#[cfg(windows)]
fn should_descend(entry: &walkdir::DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }

    if entry.file_type().is_symlink() {
        return false;
    }

    if !entry.file_type().is_dir() {
        return true;
    }

    let name = entry.file_name().to_string_lossy().to_ascii_lowercase();

    !matches!(
        name.as_str(),
        "node_modules"
            | ".git"
            | ".svn"
            | "cache"
            | "caches"
            | "code cache"
            | "gpu cache"
            | "inetcache"
            | "webcache"
            | "crashdumps"
    )
}

#[cfg(windows)]
fn smart_candidate(path: &std::path::Path, recent_days: u64) -> bool {
    let extension = extension_of(path);

    if is_executable_extension(&extension) && is_user_writable_path(path) {
        return true;
    }

    let normalized = normalize_path(path);

    if normalized.contains(r"\start menu\programs\startup\")
        || normalized.contains(r"\windows\system32\tasks\")
    {
        return true;
    }

    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };

    let Ok(modified) = metadata.modified() else {
        return false;
    };

    let Ok(age) = std::time::SystemTime::now().duration_since(modified) else {
        return true;
    };

    age <= std::time::Duration::from_secs(recent_days.saturating_mul(86_400))
}

#[cfg(any(windows, test))]
fn should_ignore_candidate_path(path: &std::path::Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();

    if normalized.contains(r"\appdata\local\go-build\") {
        return true;
    }

    if normalized.contains(r"\target\debug\")
        || normalized.contains(r"\target\release\")
        || normalized.contains(r"\target\x86_64-pc-windows-gnu\")
    {
        return true;
    }

    let axios_bundle_binary_prefixes = [
        r"\axios-complete-investigation\bin\axios-",
        r"\axios-fast-triage-test\bin\axios-",
        r"\axios-fast-complete-test\bin\axios-",
        r"\axios-stable-test\bin\axios-",
        r"\axios-runid-test\bin\axios-",
    ];

    let is_axios_bundle_binary = axios_bundle_binary_prefixes
        .iter()
        .any(|prefix| normalized.contains(prefix))
        && normalized.ends_with(".exe");

    let axios_bundle_archive_prefixes = [
        r"\axios-complete-investigation-",
        r"\axios-fast-triage-test-",
        r"\axios-fast-complete-test-",
        r"\axios-stable-test-",
        r"\axios-runid-test-",
    ];

    let is_axios_bundle_archive = axios_bundle_archive_prefixes
        .iter()
        .any(|prefix| normalized.contains(prefix))
        && normalized.ends_with(".zip");

    let axios_bundle_owned_files = [
        r"\axios-complete-investigation\scripts\run-axios-complete-investigation.ps1",
        r"\axios-complete-investigation\sha256sums.txt",
    ];

    let is_axios_bundle_owned_file = axios_bundle_owned_files
        .iter()
        .any(|file| normalized.ends_with(file));

    is_axios_bundle_binary || is_axios_bundle_archive || is_axios_bundle_owned_file
}

#[cfg(windows)]
fn add_candidate(
    path: PathBuf,
    source: &str,
    limit: usize,
    candidates: &mut Vec<Candidate>,
    indexes: &mut std::collections::HashMap<String, usize>,
) {
    if should_ignore_candidate_path(&path) {
        return;
    }

    if !path.is_file() || !eligible_path(&path) {
        return;
    }

    let normalized = normalize_path(&path);

    if let Some(index) = indexes.get(&normalized).copied() {
        candidates[index].sources.insert(source.to_string());

        return;
    }

    if candidates.len() >= limit {
        return;
    }

    let mut sources = std::collections::BTreeSet::new();
    sources.insert(source.to_string());

    indexes.insert(normalized, candidates.len());
    candidates.push(Candidate { path, sources });
}

#[cfg(windows)]
fn eligible_path(path: &std::path::Path) -> bool {
    is_eligible_extension(&extension_of(path))
}

#[cfg(windows)]
fn is_eligible_extension(extension: &str) -> bool {
    matches!(
        extension,
        ".exe"
            | ".dll"
            | ".sys"
            | ".scr"
            | ".com"
            | ".cpl"
            | ".msi"
            | ".msp"
            | ".ps1"
            | ".psm1"
            | ".psd1"
            | ".bat"
            | ".cmd"
            | ".vbs"
            | ".vbe"
            | ".js"
            | ".jse"
            | ".wsf"
            | ".wsh"
            | ".hta"
            | ".jar"
            | ".lnk"
            | ".reg"
            | ".iso"
            | ".img"
            | ".vhd"
            | ".vhdx"
            | ".zip"
            | ".rar"
            | ".7z"
    )
}

#[cfg(any(windows, test))]
fn is_executable_extension(extension: &str) -> bool {
    matches!(
        extension,
        ".exe" | ".dll" | ".sys" | ".scr" | ".com" | ".cpl" | ".msi" | ".msp"
    )
}

#[cfg(windows)]
fn is_script_extension(extension: &str) -> bool {
    matches!(
        extension,
        ".ps1"
            | ".psm1"
            | ".psd1"
            | ".bat"
            | ".cmd"
            | ".vbs"
            | ".vbe"
            | ".js"
            | ".jse"
            | ".wsf"
            | ".wsh"
            | ".hta"
    )
}

#[cfg(windows)]
fn extension_of(path: &std::path::Path) -> String {
    path.extension()
        .map(|value| format!(".{}", value.to_string_lossy().to_ascii_lowercase()))
        .unwrap_or_default()
}

#[cfg(windows)]
fn normalize_path(path: &std::path::Path) -> String {
    normalize_path_string(&path.to_string_lossy())
}

#[cfg(windows)]
fn normalize_path_string(value: &str) -> String {
    value
        .trim_matches(|character| character == '"' || character == '\'')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

#[cfg(windows)]
fn is_user_writable_path(path: &std::path::Path) -> bool {
    let normalized = normalize_path(path);

    normalized.contains(r"\users\")
        && (normalized.contains(r"\appdata\")
            || normalized.contains(r"\downloads\")
            || normalized.contains(r"\desktop\")
            || normalized.contains(r"\documents\")
            || normalized.contains(r"\pictures\")
            || normalized.contains(r"\videos\")
            || normalized.contains(r"\music\")
            || normalized.contains(r"\temp\"))
}

#[cfg(windows)]
fn inspect_script_indicators(path: &std::path::Path, size: u64) -> Vec<String> {
    if size > MAX_SCRIPT_CONTENT_BYTES {
        return Vec::new();
    }

    let extension = extension_of(path);

    if !is_script_extension(&extension) {
        return Vec::new();
    }

    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    let content = content.to_ascii_lowercase();

    let checks = [
        ("-encodedcommand", "encoded_powershell"),
        ("-enc ", "encoded_powershell_short"),
        ("frombase64string", "base64_decode"),
        ("invoke-expression", "invoke_expression"),
        ("iex(", "invoke_expression_short"),
        ("downloadstring", "download_string"),
        ("downloadfile", "download_file"),
        ("invoke-webrequest", "web_request"),
        ("start-bitstransfer", "bits_transfer"),
        ("schtasks.exe /create", "scheduled_task_create"),
        ("schtasks /create", "scheduled_task_create"),
        ("add-mppreference", "defender_setting_change"),
        ("set-mppreference", "defender_setting_change"),
    ];

    let mut found = std::collections::BTreeSet::new();

    for (needle, label) in checks {
        if content.contains(needle) {
            found.insert(label.to_string());
        }
    }

    found.into_iter().collect()
}

#[cfg(any(windows, test))]
fn has_strong_script_signal(indicators: &[String]) -> bool {
    let contains = |value: &str| indicators.iter().any(|indicator| indicator == value);

    contains("encoded_powershell")
        || contains("encoded_powershell_short")
        || contains("defender_setting_change")
        || contains("scheduled_task_create")
        || (contains("base64_decode")
            && (contains("invoke_expression") || contains("invoke_expression_short")))
        || ((contains("download_string")
            || contains("download_file")
            || contains("web_request")
            || contains("bits_transfer"))
            && (contains("invoke_expression") || contains("invoke_expression_short")))
}

#[cfg(any(windows, test))]
fn high_confidence_signature_failure(status: &str) -> bool {
    [
        "BadDigest",
        "ExplicitDistrust",
        "SecuritySettingsBlocked",
        "CertificateRevoked",
    ]
    .iter()
    .any(|value| status.eq_ignore_ascii_case(value))
}

#[cfg(test)]
fn classify(
    extension: &str,
    user_writable: bool,
    signature_checked: bool,
    signature_status: &str,
    _zone_identifier: bool,
    script_indicators: &[String],
) -> String {
    classify_with_evidence(
        extension,
        user_writable,
        signature_checked,
        signature_status,
        _zone_identifier,
        script_indicators,
    )
    .0
}

#[cfg(any(windows, test))]
fn classify_with_evidence(
    extension: &str,
    user_writable: bool,
    signature_checked: bool,
    signature_status: &str,
    _zone_identifier: bool,
    script_indicators: &[String],
) -> (String, Vec<String>) {
    if has_strong_script_signal(script_indicators) {
        return (
            "needs_review".to_string(),
            vec![format!(
                "strong_script_indicators:{}",
                script_indicators.join(",")
            )],
        );
    }

    if signature_checked && signature_status.eq_ignore_ascii_case("Valid") {
        return (
            "signed".to_string(),
            vec!["valid_authenticode_signature".to_string()],
        );
    }

    if signature_checked && high_confidence_signature_failure(signature_status) {
        return (
            "needs_review".to_string(),
            vec![format!("authenticode_status:{signature_status}")],
        );
    }

    if is_executable_extension(extension)
        && user_writable
        && signature_checked
        && signature_status.eq_ignore_ascii_case("NotSigned")
    {
        return (
            "needs_review".to_string(),
            vec![
                "executable_in_user_writable_location".to_string(),
                "authenticode_status:NotSigned".to_string(),
            ],
        );
    }

    (
        "unknown".to_string(),
        vec!["insufficient_high_confidence_evidence".to_string()],
    )
}

#[cfg(windows)]
fn classification_rank(value: &str) -> u8 {
    match value {
        "needs_review" => 3,
        "unknown" => 2,
        "signed" => 1,
        _ => 0,
    }
}

#[cfg(windows)]
fn hash_file(path: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::{fs::File, io::Read};

    let mut file =
        File::open(path).with_context(|| format!("Could not open file: {}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1_048_576];

    loop {
        let read = file.read(&mut buffer)?;

        if read == 0 {
            break;
        }

        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

#[cfg(windows)]
fn system_time_to_rfc3339(value: std::time::SystemTime) -> String {
    let value: chrono::DateTime<chrono::Utc> = value.into();
    value.to_rfc3339()
}

#[cfg(windows)]
fn read_json_value(path: &std::path::Path) -> Result<Value> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Could not read JSON: {}", path.display()))?;

    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);

    serde_json::from_slice(bytes)
        .with_context(|| format!("Could not parse JSON: {}", path.display()))
}

#[cfg(windows)]
fn collect_strings(value: &Value, maximum: usize, output: &mut Vec<String>) {
    if output.len() >= maximum {
        return;
    }

    match value {
        Value::String(text) => output.push(text.clone()),
        Value::Array(values) => {
            for value in values {
                collect_strings(value, maximum, output);

                if output.len() >= maximum {
                    return;
                }
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_strings(value, maximum, output);

                if output.len() >= maximum {
                    return;
                }
            }
        }
        _ => {}
    }
}

#[cfg(windows)]
fn extract_windows_file_path(text: &str) -> Option<PathBuf> {
    let text = text.trim();

    if text.is_empty() {
        return None;
    }

    let bytes = text.as_bytes();

    let start = (0..bytes.len().saturating_sub(2)).find(|index| {
        bytes[*index].is_ascii_alphabetic()
            && bytes[*index + 1] == b':'
            && matches!(bytes[*index + 2], b'\\' | b'/')
    })?;

    let remainder = &text[start..];
    let lower = remainder.to_ascii_lowercase();

    let extensions = [
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".msi", ".msp", ".ps1", ".psm1", ".psd1",
        ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".lnk",
        ".reg", ".iso", ".img", ".vhd", ".vhdx", ".zip", ".rar", ".7z",
    ];

    let end = extensions
        .iter()
        .filter_map(|extension| {
            lower
                .find(extension)
                .map(|position| position + extension.len())
        })
        .min()?;

    let candidate =
        remainder[..end].trim_matches(|character| character == '"' || character == '\'');

    let path = PathBuf::from(candidate);

    path.is_file().then_some(path)
}

#[cfg(windows)]
fn collect_windows_enrichments(
    paths: &[String],
    signature_budget: usize,
) -> Result<(usize, Vec<WindowsEnrichment>)> {
    use crate::security::native_authenticode::{verify_file, AuthenticodeVerification};

    let mut signature_checks = 0usize;
    let mut items = Vec::with_capacity(paths.len());

    for path_text in paths {
        let path = PathBuf::from(path_text);

        if !path.is_file() {
            continue;
        }

        let extension = extension_of(&path);

        let verification =
            if is_executable_extension(&extension) && signature_checks < signature_budget {
                let result = verify_file(&path);

                if result.checked {
                    signature_checks += 1;
                }

                result
            } else {
                AuthenticodeVerification::not_checked()
            };

        let zone_stream = format!("{}:Zone.Identifier", path.to_string_lossy());

        let zone_identifier_present = std::fs::metadata(zone_stream).is_ok();

        items.push(WindowsEnrichment {
            path: path_text.clone(),
            signature_checked: verification.checked,
            signature_status: verification.status,
            signer: None,
            zone_identifier_present,
            file_description: None,
            product_name: None,
            product_version: None,
        });
    }

    Ok((signature_checks, items))
}

#[cfg(windows)]
fn push_error(errors: &mut Vec<String>, error: String) {
    const MAX_ERRORS: usize = 256;

    if errors.len() < MAX_ERRORS {
        errors.push(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scan_is_smart_and_bounded() {
        let options = AuditOptions::default();

        assert_eq!(options.mode, AuditMode::Smart);
        assert_eq!(options.max_artifacts, DEFAULT_MAX_ARTIFACTS);
    }

    #[test]
    fn smart_scan_cannot_expand_to_twenty_five_thousand() {
        assert_eq!(
            effective_limit(AuditMode::Smart, 25_000),
            SMART_MAX_ARTIFACTS
        );
    }

    #[test]
    fn fast_scan_bounds_candidates_and_deep_verification() {
        assert_eq!(AuditMode::parse("fast").unwrap(), AuditMode::Fast);
        assert_eq!(effective_limit(AuditMode::Fast, 25_000), FAST_MAX_ARTIFACTS);
        const {
            assert!(FAST_DEEP_VERIFICATION_BUDGET < FAST_MAX_ARTIFACTS);
        };
        assert_eq!(FAST_TIME_BUDGET_SECONDS, 90);
    }

    #[test]
    fn full_scan_uses_explicit_hard_limit() {
        assert_eq!(effective_limit(AuditMode::Full, 25_000), HARD_MAX_ARTIFACTS);
    }

    #[test]
    fn zero_does_not_mean_unbounded_scan() {
        assert_eq!(effective_limit(AuditMode::Smart, 0), DEFAULT_MAX_ARTIFACTS);
    }

    #[test]
    fn audit_mode_parser_is_strict() {
        assert_eq!(AuditMode::parse("smart").unwrap(), AuditMode::Smart);

        assert!(AuditMode::parse("everything").is_err());
    }
}

#[cfg(test)]
mod conservative_classification_tests {
    use super::*;

    #[test]
    fn not_checked_executable_is_unknown() {
        assert_eq!(
            classify(".exe", true, false, "NotChecked", false, &[],),
            "unknown"
        );
    }

    #[test]
    fn seed_source_is_not_a_classification_input() {
        let source = include_str!("universal_file_audit.rs");

        assert!(!source.contains("candidate.sources.contains(\"seed_report\"),"));
    }

    #[test]
    fn valid_signature_is_signed() {
        assert_eq!(classify(".exe", true, true, "Valid", false, &[],), "signed");
    }

    #[test]
    fn unsigned_user_executable_requires_review() {
        assert_eq!(
            classify(".exe", true, true, "NotSigned", false, &[],),
            "needs_review"
        );
    }

    #[test]
    fn bad_digest_requires_review() {
        assert_eq!(
            classify(".exe", false, true, "BadDigest", false, &[],),
            "needs_review"
        );
    }

    #[test]
    fn classification_evidence_explains_unsigned_user_executable() {
        let (classification, evidence) =
            classify_with_evidence(".exe", true, true, "NotSigned", false, &[]);

        assert_eq!(classification, "needs_review");
        assert!(evidence.contains(&"executable_in_user_writable_location".to_string()));
        assert!(evidence.contains(&"authenticode_status:NotSigned".to_string()));
    }

    #[test]
    fn download_word_alone_is_not_strong_evidence() {
        assert!(!has_strong_script_signal(&["download_file".to_string(),],));
    }

    #[test]
    fn download_plus_execution_is_strong_evidence() {
        assert!(has_strong_script_signal(&[
            "download_file".to_string(),
            "invoke_expression".to_string(),
        ],));
    }

    #[test]
    fn zone_identifier_alone_is_not_a_verdict() {
        assert_eq!(
            classify(".exe", true, false, "NotChecked", true, &[],),
            "unknown"
        );
    }
}

#[cfg(test)]
mod candidate_scope_exclusion_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn go_build_candidate_is_ignored() {
        assert!(should_ignore_candidate_path(Path::new(
            r"C:\Users\TestUser\AppData\Local\go-build\12\cache\main.exe",
        ),));
    }

    #[test]
    fn rust_target_candidate_is_ignored() {
        assert!(should_ignore_candidate_path(Path::new(
            r"C:\Work\axios\target\x86_64-pc-windows-gnu\release\axios-core.exe",
        ),));
    }

    #[test]
    fn extracted_axios_binary_is_ignored() {
        assert!(should_ignore_candidate_path(Path::new(
            r"C:\Users\TestUser\Downloads\AXIOS-Complete-Investigation-20260804-184934\AXIOS-Complete-Investigation\bin\axios-file-audit.exe",
        ),));
    }

    #[test]
    fn axios_fast_test_bundle_is_ignored() {
        assert!(should_ignore_candidate_path(Path::new(
            r"C:\Users\TestUser\Downloads\AXIOS-Fast-Test-20260902-172250\AXIOS-Fast-Triage-Test\bin\axios-file-audit.exe",
        )));
    }

    #[test]
    fn axios_complete_bundle_zip_is_ignored() {
        assert!(should_ignore_candidate_path(Path::new(
            r"C:\Users\TestUser\Downloads\AXIOS-Complete-Investigation-20260902-163806.zip",
        )));
    }

    #[test]
    fn axios_fast_triage_bundle_binary_is_ignored() {
        assert!(should_ignore_candidate_path(Path::new(
            r"C:\Users\TestUser\Downloads\AXIOS-Self-Exclusion-Test-20260902-183629\AXIOS-Fast-Triage-Test\bin\axios-file-audit.exe",
        )));
    }

    #[test]
    fn axios_fast_complete_bundle_binary_is_ignored() {
        assert!(should_ignore_candidate_path(Path::new(
            r"C:\Users\TestUser\Downloads\AXIOS-Fast-Complete-Test-20260902-180000\AXIOS-Complete-Investigation\bin\axios-core.exe",
        )));
    }

    #[test]
    fn axios_complete_bundle_runner_script_is_ignored() {
        assert!(should_ignore_candidate_path(Path::new(
            r"C:\Users\TestUser\Downloads\AXIOS-Complete-Self-Exclusion-20260902-184758\AXIOS-Complete-Investigation\scripts\Run-AXIOS-Complete-Investigation.ps1",
        )));
    }

    #[test]
    fn ordinary_download_is_not_ignored() {
        assert!(!should_ignore_candidate_path(Path::new(
            r"C:\Users\TestUser\Downloads\unknown-tool.exe",
        ),));
    }

    #[test]
    fn game_file_is_not_ignored() {
        assert!(!should_ignore_candidate_path(Path::new(
            r"C:\Users\TestUser\Desktop\Game\steam_api64.dll",
        ),));
    }

    #[test]
    fn minecraft_runtime_is_not_ignored() {
        assert!(!should_ignore_candidate_path(Path::new(
            r"C:\Users\TestUser\AppData\Roaming\.minecraft\runtime\bin\java.exe",
        ),));
    }
}
