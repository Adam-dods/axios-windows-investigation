use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingClassification {
    Informational,
    NeedsReview,
    ObservedSystemChange,
    SuspiciousActivity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    Context,
    Heuristic,
    DirectObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub score: i32,
    pub strength: EvidenceStrength,
    pub source: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub score: u32,
    pub severity: Severity,
    pub classification: FindingClassification,
    pub confidence: String,
    pub summary: String,
    pub recommendation: String,
    pub limitations: Vec<String>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessFacts {
    pub executable_path: Option<String>,
    pub command_line: String,
    pub signed: Option<bool>,
    pub creates_persistence: bool,
    pub opens_listening_port: bool,
    pub creates_system_service: bool,
    pub adds_defender_exclusion: bool,
    pub launches_encoded_powershell: bool,
    pub drops_driver: bool,
}

pub fn assess_process(facts: &ProcessFacts) -> RiskAssessment {
    let mut evidence = Vec::new();

    if let Some(path) = &facts.executable_path {
        let normalized = path.to_lowercase().replace('/', "\\");

        if normalized.contains("\\temp\\") {
            evidence.push(evidence_item(
                "AX-PROC-001",
                "Executable launched from temporary directory",
                "Temporary directories are common for installers and updaters. Verify provenance before treating this as harmful.",
                5,
                EvidenceStrength::Heuristic,
                "process",
                Some(path.clone()),
            ));
        }

        if normalized.contains("\\appdata\\roaming\\") {
            evidence.push(evidence_item(
                "AX-PROC-002",
                "Executable launched from roaming profile",
                "Roaming profile execution can be legitimate. Inspect the publisher and parent process.",
                5,
                EvidenceStrength::Heuristic,
                "process",
                Some(path.clone()),
            ));
        }
    }

    if facts.signed == Some(false) {
        evidence.push(evidence_item(
            "AX-FILE-001",
            "No valid Authenticode signature detected",
            "Unsigned software is not malware by itself. Verify file origin, hash, publisher, and expected installation path.",
            5,
            EvidenceStrength::Heuristic,
            "signature",
            facts.executable_path.clone(),
        ));
    }

    if facts.creates_persistence {
        evidence.push(evidence_item(
            "AX-PERSIST-001",
            "Persistence mechanism created or modified",
            "A startup mechanism was observed. Verify whether the owning application and authorization are expected.",
            15,
            EvidenceStrength::DirectObservation,
            "persistence",
            None,
        ));
    }

    if facts.opens_listening_port {
        evidence.push(evidence_item(
            "AX-NET-001",
            "Listening network port observed",
            "A listening port is normal for many applications and services. Review exposure and owning process before escalation.",
            0,
            EvidenceStrength::Context,
            "network",
            None,
        ));
    }

    if facts.creates_system_service {
        evidence.push(evidence_item(
            "AX-SERVICE-001",
            "Windows service created",
            "A service installation was observed. This confirms a system change, not malicious intent.",
            15,
            EvidenceStrength::DirectObservation,
            "service",
            None,
        ));
    }

    if facts.adds_defender_exclusion {
        evidence.push(evidence_item(
            "AX-DEFENDER-001",
            "Microsoft Defender exclusion added",
            "A Defender exclusion was observed. Verify the path, owner, installation context, and authorization.",
            25,
            EvidenceStrength::DirectObservation,
            "defender",
            None,
        ));
    }

    if facts.launches_encoded_powershell || contains_encoded_powershell(&facts.command_line) {
        evidence.push(evidence_item(
            "AX-PS-001",
            "Encoded PowerShell command observed",
            "Encoded PowerShell is used by both administration tools and malicious scripts. Decode and inspect the command before deciding.",
            15,
            EvidenceStrength::Heuristic,
            "command_line",
            Some(facts.command_line.clone()),
        ));
    }

    if facts.drops_driver {
        evidence.push(evidence_item(
            "AX-DRIVER-001",
            "Kernel driver created or installed",
            "A driver-related system change was observed. Verify signer, hash, vendor, and installation source.",
            35,
            EvidenceStrength::DirectObservation,
            "driver",
            None,
        ));
    }

    let score = evidence
        .iter()
        .map(|item| item.score)
        .sum::<i32>()
        .clamp(0, 100) as u32;

    let classification = classify(&evidence);
    let confidence = confidence_for(&classification, &evidence);
    let (summary, recommendation) = guidance_for(&classification);

    RiskAssessment {
        score,
        severity: severity_from_score(score),
        classification,
        confidence,
        summary: summary.to_string(),
        recommendation: recommendation.to_string(),
        limitations: vec![
            "AXIOS does not classify software as malware from these indicators alone.".to_string(),
            "A result should be verified with file provenance, signer, hash, parent process, and user authorization.".to_string(),
        ],
        evidence,
    }
}

fn evidence_item(
    rule_id: &str,
    title: &str,
    description: &str,
    score: i32,
    strength: EvidenceStrength,
    source: &str,
    target: Option<String>,
) -> Evidence {
    Evidence {
        rule_id: rule_id.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        score,
        strength,
        source: source.to_string(),
        target,
    }
}

fn classify(evidence: &[Evidence]) -> FindingClassification {
    let heuristic_count = evidence
        .iter()
        .filter(|item| item.strength == EvidenceStrength::Heuristic)
        .count();

    let direct_count = evidence
        .iter()
        .filter(|item| item.strength == EvidenceStrength::DirectObservation)
        .count();

    if direct_count == 0 {
        return match heuristic_count {
            0 => FindingClassification::Informational,
            1..=2 => FindingClassification::NeedsReview,
            _ => FindingClassification::SuspiciousActivity,
        };
    }

    if heuristic_count == 0 {
        FindingClassification::ObservedSystemChange
    } else {
        FindingClassification::SuspiciousActivity
    }
}

fn confidence_for(classification: &FindingClassification, evidence: &[Evidence]) -> String {
    match classification {
        FindingClassification::Informational => "high".to_string(),
        FindingClassification::NeedsReview => "low".to_string(),
        FindingClassification::ObservedSystemChange => "high".to_string(),
        FindingClassification::SuspiciousActivity => {
            let direct_count = evidence
                .iter()
                .filter(|item| item.strength == EvidenceStrength::DirectObservation)
                .count();

            if direct_count > 0 {
                "high".to_string()
            } else {
                "medium".to_string()
            }
        }
    }
}

fn guidance_for(classification: &FindingClassification) -> (&'static str, &'static str) {
    match classification {
        FindingClassification::Informational => (
            "No elevated-risk indicator was observed.",
            "No action is required unless additional evidence appears.",
        ),
        FindingClassification::NeedsReview => (
            "One weak indicator was observed. This is not evidence of malware.",
            "Verify publisher, file hash, parent process, and installation source.",
        ),
        FindingClassification::ObservedSystemChange => (
            "A system change was directly observed, but no malicious conclusion can be made.",
            "Confirm that the change was expected and authorized before taking action.",
        ),
        FindingClassification::SuspiciousActivity => (
            "Multiple independent indicators were observed and require investigation.",
            "Collect the process tree, command line, signer, hash, network context, and user authorization before remediation.",
        ),
    }
}

pub fn severity_from_score(score: u32) -> Severity {
    match score {
        0 => Severity::Informational,
        1..=14 => Severity::Low,
        15..=34 => Severity::Medium,
        35..=59 => Severity::High,
        _ => Severity::Critical,
    }
}

fn contains_encoded_powershell(command: &str) -> bool {
    let normalized = command.to_lowercase();

    let powershell = normalized.contains("powershell") || normalized.contains("pwsh");

    let encoded = normalized.contains("-encodedcommand")
        || normalized.contains("-enc ")
        || normalized.ends_with("-enc");

    powershell && encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_process_is_informational() {
        let facts = ProcessFacts {
            executable_path: Some(r"C:\Windows\System32\notepad.exe".to_string()),
            signed: Some(true),
            ..Default::default()
        };

        let result = assess_process(&facts);

        assert_eq!(result.score, 0);
        assert_eq!(result.classification, FindingClassification::Informational);
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn unsigned_temp_file_requires_review_not_malware_claim() {
        let facts = ProcessFacts {
            executable_path: Some(r"C:\Users\TestUser\AppData\Local\Temp\setup.exe".to_string()),
            signed: Some(false),
            ..Default::default()
        };

        let result = assess_process(&facts);

        assert_eq!(result.classification, FindingClassification::NeedsReview);
        assert_eq!(result.confidence, "low");
        assert!(result.summary.contains("weak indicator"));
    }

    #[test]
    fn listening_port_is_context_not_a_risk_verdict() {
        let facts = ProcessFacts {
            opens_listening_port: true,
            ..Default::default()
        };

        let result = assess_process(&facts);

        assert_eq!(result.score, 0);
        assert_eq!(result.classification, FindingClassification::Informational);
        assert_eq!(result.evidence[0].strength, EvidenceStrength::Context);
    }

    #[test]
    fn service_creation_is_a_confirmed_change_not_malware() {
        let facts = ProcessFacts {
            creates_system_service: true,
            ..Default::default()
        };

        let result = assess_process(&facts);

        assert_eq!(
            result.classification,
            FindingClassification::ObservedSystemChange
        );
        assert_eq!(result.confidence, "high");
    }

    #[test]
    fn encoded_powershell_requires_review() {
        let facts = ProcessFacts {
            command_line: "powershell.exe -NoProfile -EncodedCommand SQBFAFgA".to_string(),
            ..Default::default()
        };

        let result = assess_process(&facts);

        assert_eq!(result.classification, FindingClassification::NeedsReview);
        assert_eq!(result.confidence, "low");
    }

    #[test]
    fn direct_change_plus_heuristic_is_suspicious_activity() {
        let facts = ProcessFacts {
            executable_path: Some(r"C:\Users\TestUser\AppData\Local\Temp\unknown.exe".to_string()),
            signed: Some(false),
            adds_defender_exclusion: true,
            ..Default::default()
        };

        let result = assess_process(&facts);

        assert_eq!(
            result.classification,
            FindingClassification::SuspiciousActivity
        );
        assert_eq!(result.confidence, "high");
    }

    #[test]
    fn risk_score_never_exceeds_one_hundred() {
        let facts = ProcessFacts {
            executable_path: Some(
                r"C:\Users\TestUser\AppData\Roaming\Temp\payload.exe".to_string(),
            ),
            command_line: "powershell.exe -enc SQBFAFgA".to_string(),
            signed: Some(false),
            creates_persistence: true,
            opens_listening_port: true,
            creates_system_service: true,
            adds_defender_exclusion: true,
            launches_encoded_powershell: true,
            drops_driver: true,
        };

        let result = assess_process(&facts);

        assert_eq!(result.score, 100);
        assert_eq!(
            result.classification,
            FindingClassification::SuspiciousActivity
        );
    }
}
