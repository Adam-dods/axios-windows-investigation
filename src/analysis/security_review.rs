use crate::system::{browser_extensions, security_posture};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityReviewClassification {
    Context,
    ConfirmedSecurityWeakening,
    NeedsReview,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityReviewFinding {
    pub id: &'static str,
    pub classification: SecurityReviewClassification,
    pub confidence: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
    pub evidence: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityReviewSummary {
    pub context: usize,
    pub confirmed_security_weakening: usize,
    pub needs_review: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityReviewReport {
    pub schema_version: u32,
    pub collector: &'static str,
    pub success: bool,
    pub summary: SecurityReviewSummary,
    pub findings: Vec<SecurityReviewFinding>,
    pub sources: Value,
}

pub fn collect() -> SecurityReviewReport {
    let posture = security_posture::collect();
    let extensions = browser_extensions::collect();

    review(posture, extensions)
}

pub fn review(posture: Value, extensions: Value) -> SecurityReviewReport {
    let mut findings = Vec::new();

    analyze_uac(&posture, &mut findings);
    analyze_defender(&posture, &mut findings);
    analyze_defender_exclusions(&posture, &mut findings);
    analyze_browser_extensions(&extensions, &mut findings);

    let mut summary = SecurityReviewSummary {
        context: 0,
        confirmed_security_weakening: 0,
        needs_review: 0,
    };

    for finding in &findings {
        match finding.classification {
            SecurityReviewClassification::Context => summary.context += 1,
            SecurityReviewClassification::ConfirmedSecurityWeakening => {
                summary.confirmed_security_weakening += 1
            }
            SecurityReviewClassification::NeedsReview => summary.needs_review += 1,
        }
    }

    SecurityReviewReport {
        schema_version: 1,
        collector: "axios_security_review",
        success: posture
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && extensions
                .get("success")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        summary,
        findings,
        sources: json!({
            "security_posture": posture,
            "browser_extensions": extensions
        }),
    }
}

fn analyze_uac(posture: &Value, findings: &mut Vec<SecurityReviewFinding>) {
    let enable_lua = posture
        .get("uac")
        .and_then(|value| value.get("enable_lua"))
        .and_then(Value::as_i64);

    if enable_lua == Some(0) {
        findings.push(finding(
            "uac-disabled",
            SecurityReviewClassification::ConfirmedSecurityWeakening,
            "high",
            "User Account Control is disabled",
            "Windows reports EnableLUA as disabled. This is a confirmed security configuration weakening, not a malware verdict.",
            posture.get("uac").cloned().unwrap_or(Value::Null),
        ));
    }
}

fn analyze_defender(posture: &Value, findings: &mut Vec<SecurityReviewFinding>) {
    let defender = posture.get("defender_status").unwrap_or(&Value::Null);

    let real_time = defender
        .get("real_time_protection_enabled")
        .and_then(Value::as_bool);

    if real_time == Some(false) {
        findings.push(finding(
            "defender-real-time-protection-disabled",
            SecurityReviewClassification::ConfirmedSecurityWeakening,
            "high",
            "Defender real-time protection is disabled",
            "Windows reports that Defender real-time protection is disabled. Review the security product configuration.",
            defender.clone(),
        ));
    }
}

fn analyze_defender_exclusions(posture: &Value, findings: &mut Vec<SecurityReviewFinding>) {
    let exclusions = posture
        .get("defender_exclusions")
        .cloned()
        .unwrap_or(Value::Null);

    let count = ["paths", "processes", "extensions"]
        .iter()
        .map(|key| {
            exclusions
                .get(*key)
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0)
        })
        .sum::<usize>();

    if count > 0 {
        findings.push(finding(
            "defender-exclusions-present",
            SecurityReviewClassification::NeedsReview,
            "medium",
            "Defender exclusions are configured",
            "Defender exclusions can be legitimate. Review each path, process, and extension when it is not expected.",
            exclusions,
        ));
    }
}

fn analyze_browser_extensions(extensions: &Value, findings: &mut Vec<SecurityReviewFinding>) {
    let entries = extensions
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for extension in entries {
        let permissions = extension
            .get("permissions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let broad_access = permissions.iter().any(|permission| {
            permission
                .as_str()
                .map(|value| {
                    value.eq_ignore_ascii_case("<all_urls>")
                        || value.eq_ignore_ascii_case("nativeMessaging")
                })
                .unwrap_or(false)
        });

        if broad_access {
            findings.push(finding(
                "browser-extension-broad-access",
                SecurityReviewClassification::NeedsReview,
                "medium",
                "Browser extension requests broad access",
                "The extension requests broad site access or native messaging. This can be legitimate, but review the extension when it is not recognized.",
                extension,
            ));
        }
    }
}

fn finding(
    id: &'static str,
    classification: SecurityReviewClassification,
    confidence: &'static str,
    title: &'static str,
    summary: &'static str,
    evidence: Value,
) -> SecurityReviewFinding {
    SecurityReviewFinding {
        id,
        classification,
        confidence,
        title,
        summary,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_defender_is_a_confirmed_security_weakening() {
        let report = review(
            json!({
                "success": true,
                "uac": {"enable_lua": 1},
                "defender_status": {
                    "real_time_protection_enabled": false
                },
                "defender_exclusions": {
                    "paths": [],
                    "processes": [],
                    "extensions": []
                }
            }),
            json!({
                "success": true,
                "entries": []
            }),
        );

        assert_eq!(report.summary.confirmed_security_weakening, 1);
    }

    #[test]
    fn broad_extension_access_requires_review_not_a_malware_claim() {
        let report = review(
            json!({
                "success": true,
                "uac": {"enable_lua": 1},
                "defender_status": {
                    "real_time_protection_enabled": true
                },
                "defender_exclusions": {
                    "paths": [],
                    "processes": [],
                    "extensions": []
                }
            }),
            json!({
                "success": true,
                "entries": [{
                    "browser": "Google Chrome",
                    "name": "Example",
                    "permissions": ["<all_urls>"]
                }]
            }),
        );

        assert_eq!(report.summary.needs_review, 1);
        assert_eq!(
            report.findings[0].classification,
            SecurityReviewClassification::NeedsReview
        );
    }
}
