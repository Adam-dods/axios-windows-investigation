use anyhow::{bail, Context, Result};
use axios_core::storage::json_file;
use serde_json::{json, Value};
use std::{collections::BTreeMap, env, path::PathBuf};

fn main() -> Result<()> {
    let paths = options()?;
    let reports = load(&paths)?;

    let baseline = &reports["baseline"];
    let score = &reports["score"];
    let advisory = &reports["advisory"];
    let hardware = &reports["hardware"];
    let kernel = &reports["kernel"];

    let mut hypotheses = Vec::new();

    if hardware["secure_boot"]["enabled"].as_bool() == Some(false) {
        hypotheses.push(json!({
            "id": "boot_chain_protection_reduced",
            "classification": "confirmed_security_weakening",
            "confidence": "high",
            "title": "Secure Boot is disabled",
            "evidence": ["hardware_trust.secure_boot.enabled:false"],
            "explanation": "This reduces boot-chain protection. It does not prove bootkit, rootkit, or firmware compromise."
        }));
    }

    if baseline["baseline"]["baseline_integrity_alert"].as_bool() == Some(true) {
        hypotheses.push(json!({
            "id": "baseline_integrity_failed",
            "classification": "needs_review",
            "confidence": "high",
            "title": "Previous sensitive baseline failed integrity verification",
            "evidence": [baseline["baseline"]["previous_baseline_archive"]],
            "explanation": "AXIOS preserved the old baseline. Corruption or modification needs review; this is not proof of compromise."
        }));
    }

    let high = score["summary"]["high_priority"].as_u64().unwrap_or(0);
    if high > 0 {
        hypotheses.push(json!({
            "id": "cross_layer_execution_chain",
            "classification": "needs_review",
            "confidence": "high",
            "title": "File evidence overlaps persistence, process, and live/network activity",
            "evidence": {
                "high_priority_artifacts": high,
                "rule": score["policy"]["high_requires"]
            },
            "explanation": "Independent evidence layers overlap. Review the files and their parent process chain; this is not a malware verdict."
        }));
    }

    let kernel_findings = kernel["findings"].as_array().map(Vec::len).unwrap_or(0);
    if kernel_findings > 0 {
        hypotheses.push(json!({
            "id": "kernel_or_boot_posture_requires_review",
            "classification": "needs_review",
            "confidence": "medium",
            "title": "Kernel or boot posture contains findings",
            "evidence": { "kernel_finding_count": kernel_findings },
            "explanation": "Kernel posture findings can be configuration or policy related. Correlate with signed driver and boot-chain evidence."
        }));
    }

    let exposures = advisory["potential_exposures"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    if exposures > 0 {
        hypotheses.push(json!({
            "id": "version_matches_trusted_advisory",
            "classification": "possible_exposure",
            "confidence": "medium",
            "title": "Installed component matches a trusted advisory feed entry",
            "evidence": { "potential_exposures": exposures },
            "explanation": "A version match requires vendor/model/configuration verification. It does not prove exploitation."
        }));
    }

    hypotheses.sort_by(|a, b| {
        rank(b["confidence"].as_str().unwrap_or("low"))
            .cmp(&rank(a["confidence"].as_str().unwrap_or("low")))
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "success": true,
            "collector": "axios_threat_hypotheses",
            "claim_policy": {
                "zero_day_confirmed": false,
                "backdoor_confirmed": false,
                "malware_verdicts": false,
                "method": "cross-layer evidence hypotheses"
            },
            "summary": {
                "hypothesis_count": hypotheses.len(),
                "confirmed_security_weakenings": hypotheses.iter()
                    .filter(|x| x["classification"] == "confirmed_security_weakening").count(),
                "needs_review": hypotheses.iter()
                    .filter(|x| x["classification"] == "needs_review").count(),
                "possible_exposures": hypotheses.iter()
                    .filter(|x| x["classification"] == "possible_exposure").count()
            },
            "hypotheses": hypotheses
        }))?
    );
    Ok(())
}

fn rank(value: &str) -> u8 {
    match value {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

fn options() -> Result<BTreeMap<String, PathBuf>> {
    options_from(env::args().skip(1))
}

fn options_from<I, S>(arguments: I) -> Result<BTreeMap<String, PathBuf>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = arguments.into_iter().map(Into::into);
    let mut paths = BTreeMap::new();
    let required = ["baseline", "score", "advisory", "hardware", "kernel"];

    while let Some(flag) = args.next() {
        let key = flag.strip_prefix("--").context("invalid argument")?;
        if !required.contains(&key) {
            bail!("unknown argument: {flag}");
        }
        let value = PathBuf::from(args.next().context(format!("{flag} needs a file"))?);

        if paths.insert(key.to_string(), value).is_some() {
            bail!("{flag} was supplied more than once");
        }
    }

    for key in required {
        if !paths.contains_key(key) {
            bail!("--{key} is required");
        }
    }
    Ok(paths)
}

fn load(paths: &BTreeMap<String, PathBuf>) -> Result<BTreeMap<String, Value>> {
    let mut reports = BTreeMap::new();
    for (name, path) in paths {
        let report = json_file::read_value(path)
            .with_context(|| format!("cannot read {name}: {}", path.display()))?;
        if report["success"].as_bool() != Some(true) {
            bail!("{name} report is not successful");
        }
        reports.insert(name.clone(), report);
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_hypothesis_input_is_rejected() {
        let result = options_from([
            "--baseline",
            "one.json",
            "--baseline",
            "two.json",
            "--score",
            "score.json",
            "--advisory",
            "advisory.json",
            "--hardware",
            "hardware.json",
            "--kernel",
            "kernel.json",
        ]);

        assert!(result.is_err());
    }
}
