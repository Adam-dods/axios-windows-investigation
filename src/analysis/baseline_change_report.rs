use crate::analysis::diff::{Change, ChangeKind, Comparison};
use serde::Serialize;

const MAX_REPORTED_CHANGES: usize = 250;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaselineChangeClassification {
    Context,
    ConfirmedChange,
    NeedsReview,
}

#[derive(Debug, Clone, Serialize)]
pub struct BaselineChangeFinding {
    pub path: String,
    pub kind: ChangeKind,
    pub classification: BaselineChangeClassification,
    pub confidence: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BaselineChangeSummary {
    pub context: usize,
    pub confirmed_changes: usize,
    pub needs_review: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BaselineChangeReport {
    pub schema_version: u32,
    pub collector: &'static str,
    pub total_stable_changes: usize,
    pub reported_changes: usize,
    pub changes_truncated: bool,
    pub summary: BaselineChangeSummary,
    pub findings: Vec<BaselineChangeFinding>,
}

pub fn build(comparison: Comparison) -> BaselineChangeReport {
    let total_stable_changes = comparison.change_count;
    let changes_truncated = comparison.changes.len() > MAX_REPORTED_CHANGES;

    let findings = comparison
        .changes
        .into_iter()
        .take(MAX_REPORTED_CHANGES)
        .map(finding_from_change)
        .collect::<Vec<_>>();

    let mut summary = BaselineChangeSummary {
        context: 0,
        confirmed_changes: 0,
        needs_review: 0,
    };

    for finding in &findings {
        match finding.classification {
            BaselineChangeClassification::Context => summary.context += 1,
            BaselineChangeClassification::ConfirmedChange => summary.confirmed_changes += 1,
            BaselineChangeClassification::NeedsReview => summary.needs_review += 1,
        }
    }

    BaselineChangeReport {
        schema_version: 1,
        collector: "axios_baseline_change_report",
        total_stable_changes,
        reported_changes: findings.len(),
        changes_truncated,
        summary,
        findings,
    }
}

fn finding_from_change(change: Change) -> BaselineChangeFinding {
    let (classification, confidence, title, summary) = classify_path(&change.path);

    BaselineChangeFinding {
        path: change.path,
        kind: change.kind,
        classification,
        confidence,
        title,
        summary,
        before: change.before,
        after: change.after,
    }
}

fn classify_path(
    path: &str,
) -> (
    BaselineChangeClassification,
    &'static str,
    &'static str,
    &'static str,
) {
    let normalized = path.to_ascii_lowercase();

    if normalized.contains("winlogon")
        || normalized.contains("app_init")
        || normalized.contains("image_file_execution_options")
        || normalized.contains("wmi_event")
        || normalized.contains("registry_persistence")
        || normalized.contains("startup_folder")
        || normalized.contains("scheduled_task")
    {
        return (
            BaselineChangeClassification::NeedsReview,
            "high",
            "Persistence-related baseline change",
            "A persistence-related configuration changed. Review the exact before and after values before taking action.",
        );
    }

    if normalized.contains("firewall")
        || normalized.contains("defender")
        || normalized.contains("services")
        || normalized.contains("network_posture")
        || normalized.contains("access_surface")
        || normalized.contains("hosts")
    {
        return (
            BaselineChangeClassification::ConfirmedChange,
            "high",
            "Security configuration changed",
            "The collected system configuration differs from the saved baseline.",
        );
    }

    (
        BaselineChangeClassification::Context,
        "medium",
        "System baseline changed",
        "A stable system value changed. This is context until the before and after values are reviewed.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn persistence_change_requires_review() {
        let report = build(Comparison {
            change_count: 1,
            added: 1,
            removed: 0,
            modified: 0,
            changes: vec![Change {
                path: "$.extended_persistence.winlogon.Shell".to_string(),
                kind: ChangeKind::Modified,
                before: Some(json!("explorer.exe")),
                after: Some(json!("other.exe")),
            }],
        });

        assert_eq!(report.summary.needs_review, 1);
        assert_eq!(
            report.findings[0].classification,
            BaselineChangeClassification::NeedsReview
        );
    }

    #[test]
    fn report_is_bounded() {
        let changes = (0..300)
            .map(|index| Change {
                path: format!("$.updates.items[{index}]"),
                kind: ChangeKind::Added,
                before: None,
                after: Some(json!(index)),
            })
            .collect::<Vec<_>>();

        let report = build(Comparison {
            change_count: changes.len(),
            added: changes.len(),
            removed: 0,
            modified: 0,
            changes,
        });

        assert_eq!(report.reported_changes, MAX_REPORTED_CHANGES);
        assert!(report.changes_truncated);
    }
}
