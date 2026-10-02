use axios_core::reasoning::{
    evaluate_hypotheses, BranchEvidence, BranchState, HypothesisInput, HypothesisKind, Score,
};

fn evidence(id: &str, strength: u16) -> BranchEvidence {
    BranchEvidence {
        id: id.to_string(),
        strength: Score::new(strength),
        independence_group: None,
    }
}

#[test]
fn equivalent_branches_are_merged() {
    let result = evaluate_hypotheses(
        [
            HypothesisInput {
                hypothesis: HypothesisKind::SecurityMisconfiguration,
                supports: vec![evidence("firewall", 7_000)],
                contradictions: Vec::new(),
                unknowns: Vec::new(),
            },
            HypothesisInput {
                hypothesis: HypothesisKind::SecurityMisconfiguration,
                supports: vec![evidence("smb", 8_000)],
                contradictions: Vec::new(),
                unknowns: Vec::new(),
            },
        ],
        16,
    );

    assert_eq!(result.branches_created, 2);
    assert_eq!(result.branches_merged, 1);
    assert_eq!(result.branches_retained, 1);
    assert_eq!(result.branches[0].supports.len(), 2);
}

#[test]
fn weak_branches_are_pruned_deterministically() {
    let result = evaluate_hypotheses(
        [
            HypothesisInput {
                hypothesis: HypothesisKind::VisibilityLimited,
                supports: vec![evidence("gap", 3_000)],
                contradictions: Vec::new(),
                unknowns: vec!["source".to_string()],
            },
            HypothesisInput {
                hypothesis: HypothesisKind::SuspiciousExecutionChain,
                supports: vec![evidence("chain", 9_000)],
                contradictions: Vec::new(),
                unknowns: Vec::new(),
            },
        ],
        1,
    );

    assert_eq!(result.branches_retained, 1);
    assert_eq!(result.branches[0].state, BranchState::Active);
    assert_eq!(
        result.branches[0].hypothesis,
        HypothesisKind::SuspiciousExecutionChain
    );
    assert_eq!(result.branches[1].state, BranchState::Pruned);
}

#[test]
fn contradiction_reduces_branch_score() {
    let without = evaluate_hypotheses(
        [HypothesisInput {
            hypothesis: HypothesisKind::SuspiciousPersistence,
            supports: vec![evidence("task", 8_000)],
            contradictions: Vec::new(),
            unknowns: Vec::new(),
        }],
        8,
    );
    let with = evaluate_hypotheses(
        [HypothesisInput {
            hypothesis: HypothesisKind::SuspiciousPersistence,
            supports: vec![evidence("task", 8_000)],
            contradictions: vec![evidence("trusted_signer", 2_000)],
            unknowns: Vec::new(),
        }],
        8,
    );

    assert!(with.branches[0].score < without.branches[0].score);
}

#[test]
fn branch_engine_has_no_automatic_malware_confirmation() {
    let module = include_str!("../src/reasoning/hypothesis.rs");
    let reasoning = include_str!("../src/bin/axios-reasoning-web.rs");

    assert!(!module.contains("MalwareConfirmed"));
    assert!(reasoning.contains("\"malware_confirmed\": false"));
    assert!(reasoning.contains("\"leading_hypothesis\""));
    assert!(reasoning.contains("\"alternative_hypotheses\""));
}

#[test]
fn dependent_evidence_is_not_counted_as_independent() {
    let result = evaluate_hypotheses(
        [HypothesisInput {
            hypothesis: HypothesisKind::SuspiciousExecutionChain,
            supports: vec![
                BranchEvidence {
                    id: "memory_process".to_string(),
                    strength: Score::new(8_500),
                    independence_group: Some("windows_process_execution".to_string()),
                },
                BranchEvidence {
                    id: "behavior_process".to_string(),
                    strength: Score::new(7_500),
                    independence_group: Some("windows_process_execution".to_string()),
                },
            ],
            contradictions: Vec::new(),
            unknowns: Vec::new(),
        }],
        8,
    );

    assert_eq!(result.branches[0].supports.len(), 2);
    assert_eq!(result.branches[0].independent_support_groups, 1);
    assert_eq!(result.branches[0].score, Score::new(8_500));
}
