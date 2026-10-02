use axios_core::reasoning::{
    build_proof_traces, rank_checks, BranchEvidence, BranchState, HypothesisKind,
    InvestigationCheck, ReasoningBranch, Score,
};

fn branch() -> ReasoningBranch {
    ReasoningBranch {
        id: "hypothesis.test".to_string(),
        hypothesis: HypothesisKind::SuspiciousExecutionChain,
        supports: vec![BranchEvidence {
            id: "execution.signal".to_string(),
            strength: Score::new(8_000),
            independence_group: Some("process".to_string()),
        }],
        contradictions: Vec::new(),
        unknowns: vec!["network_time".to_string()],
        independent_support_groups: 1,
        score: Score::new(7_000),
        state: BranchState::Active,
    }
}

#[test]
fn proof_trace_preserves_support_and_unknowns() {
    let traces = build_proof_traces(&[branch()], 32);
    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].supports[0].evidence_id, "execution.signal");
    assert_eq!(traces[0].unknowns, ["network_time"]);
    assert!(!traces[0].truncated);
}

#[test]
fn planner_is_bounded_safe_and_deterministic() {
    let checks = (0..10)
        .map(|index| InvestigationCheck {
            id: format!("check-{index:02}"),
            action: "Collect read-only evidence".to_string(),
            resolves: vec!["unknown".to_string()],
            distinguishes: vec!["a".to_string(), "b".to_string()],
            information_gain: Score::new(8_000),
            discrimination: Score::new(8_000),
            safety: Score::MAX,
            cost: Score::new(2_000),
            runtime: Score::new(4_000),
            intrusiveness: Score::new(2_000),
            read_only: index != 0,
        })
        .collect::<Vec<_>>();
    let ranked = rank_checks(checks, 3);
    assert_eq!(ranked.len(), 3);
    assert!(ranked.iter().all(|item| item.check.read_only));
    assert_eq!(ranked[0].check.id, "check-01");
}

#[test]
fn reasoning_output_exposes_proof_and_next_best_checks() {
    let source = include_str!("../src/bin/axios-reasoning-web.rs");
    assert!(source.contains("\"proof_traces\""));
    assert!(source.contains("\"next_best_checks\""));
    assert!(source.contains("build_proof_traces"));
    assert!(source.contains("rank_checks"));
    assert!(source.contains("read_only: true"));
    assert!(source.contains("\"malware_confirmed\": false"));
}
