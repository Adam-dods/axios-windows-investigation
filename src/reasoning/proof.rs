use crate::reasoning::{BranchState, HypothesisKind, ReasoningBranch, Score};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofStep {
    pub evidence_id: String,
    pub role: String,
    pub strength: Score,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub independence_group: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofTrace {
    pub branch_id: String,
    pub hypothesis: HypothesisKind,
    pub score: Score,
    pub supports: Vec<ProofStep>,
    pub contradictions: Vec<ProofStep>,
    pub unknowns: Vec<String>,
    pub truncated: bool,
}

pub fn build_proof_traces(branches: &[ReasoningBranch], max_depth: usize) -> Vec<ProofTrace> {
    let limit = max_depth.max(1);
    branches
        .iter()
        .filter(|branch| branch.state == BranchState::Active)
        .map(|branch| {
            let total_steps = branch.supports.len() + branch.contradictions.len();
            let supports = branch
                .supports
                .iter()
                .take(limit)
                .map(|item| ProofStep {
                    evidence_id: item.id.clone(),
                    role: "support".to_string(),
                    strength: item.strength,
                    independence_group: item.independence_group.clone(),
                })
                .collect::<Vec<_>>();
            let remaining = limit.saturating_sub(supports.len());
            let contradictions = branch
                .contradictions
                .iter()
                .take(remaining)
                .map(|item| ProofStep {
                    evidence_id: item.id.clone(),
                    role: "contradiction".to_string(),
                    strength: item.strength,
                    independence_group: item.independence_group.clone(),
                })
                .collect::<Vec<_>>();
            ProofTrace {
                branch_id: branch.id.clone(),
                hypothesis: branch.hypothesis,
                score: branch.score,
                supports,
                contradictions,
                unknowns: branch.unknowns.clone(),
                truncated: total_steps > limit,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reasoning::BranchEvidence;

    #[test]
    fn proof_depth_is_bounded() {
        let branch = ReasoningBranch {
            id: "branch".to_string(),
            hypothesis: HypothesisKind::SuspiciousExecutionChain,
            supports: (0..4)
                .map(|index| BranchEvidence {
                    id: format!("evidence-{index}"),
                    strength: Score::new(8_000),
                    independence_group: None,
                })
                .collect(),
            contradictions: Vec::new(),
            unknowns: Vec::new(),
            independent_support_groups: 4,
            score: Score::new(8_000),
            state: BranchState::Active,
        };
        let traces = build_proof_traces(&[branch], 2);
        assert_eq!(traces[0].supports.len(), 2);
        assert!(traces[0].truncated);
    }
}
