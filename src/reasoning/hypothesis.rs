use crate::reasoning::Score;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisKind {
    LegitimateActivity,
    AdministrativeActivity,
    SecurityMisconfiguration,
    PotentiallyUnwantedSoftware,
    SuspiciousPersistence,
    SuspiciousExecutionChain,
    VisibilityLimited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchState {
    Active,
    Pruned,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BranchEvidence {
    pub id: String,
    pub strength: Score,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub independence_group: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HypothesisInput {
    pub hypothesis: HypothesisKind,
    pub supports: Vec<BranchEvidence>,
    pub contradictions: Vec<BranchEvidence>,
    pub unknowns: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReasoningBranch {
    pub id: String,
    pub hypothesis: HypothesisKind,
    pub supports: Vec<BranchEvidence>,
    pub contradictions: Vec<BranchEvidence>,
    pub unknowns: Vec<String>,
    pub independent_support_groups: usize,
    pub score: Score,
    pub state: BranchState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BranchEvaluation {
    pub branches_created: usize,
    pub branches_merged: usize,
    pub branches_retained: usize,
    pub branches_pruned: usize,
    pub branches: Vec<ReasoningBranch>,
}

#[derive(Default)]
struct Accumulator {
    supports: BTreeMap<String, BranchEvidence>,
    contradictions: BTreeMap<String, BranchEvidence>,
    unknowns: Vec<String>,
}

pub fn evaluate_hypotheses(
    inputs: impl IntoIterator<Item = HypothesisInput>,
    max_branches: usize,
) -> BranchEvaluation {
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    let branches_created = inputs.len();
    let mut merged = BTreeMap::<HypothesisKind, Accumulator>::new();

    for input in inputs {
        let accumulator = merged.entry(input.hypothesis).or_default();
        merge_evidence(&mut accumulator.supports, input.supports);
        merge_evidence(&mut accumulator.contradictions, input.contradictions);
        accumulator.unknowns.extend(input.unknowns);
    }

    let branches_merged = branches_created.saturating_sub(merged.len());
    let mut branches = merged
        .into_iter()
        .map(|(hypothesis, mut accumulator)| {
            accumulator.unknowns.sort();
            accumulator.unknowns.dedup();
            let supports = evidence_values(accumulator.supports);
            let contradictions = evidence_values(accumulator.contradictions);
            let independent_support_groups = independent_evidence(&supports).len();
            let score = branch_score(&supports, &contradictions, accumulator.unknowns.len());

            ReasoningBranch {
                id: format!("hypothesis.{hypothesis:?}").to_ascii_lowercase(),
                hypothesis,
                supports,
                contradictions,
                unknowns: accumulator.unknowns,
                independent_support_groups,
                score,
                state: if score == Score::ZERO {
                    BranchState::Pruned
                } else {
                    BranchState::Active
                },
            }
        })
        .collect::<Vec<_>>();

    branches.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.hypothesis.cmp(&right.hypothesis))
    });

    let limit = max_branches.max(1);
    for branch in branches.iter_mut().skip(limit) {
        branch.state = BranchState::Pruned;
    }

    let branches_retained = branches
        .iter()
        .filter(|branch| branch.state == BranchState::Active)
        .count();

    BranchEvaluation {
        branches_created,
        branches_merged,
        branches_retained,
        branches_pruned: branches.len().saturating_sub(branches_retained),
        branches,
    }
}

fn merge_evidence(target: &mut BTreeMap<String, BranchEvidence>, evidence: Vec<BranchEvidence>) {
    for item in evidence {
        target
            .entry(item.id.clone())
            .and_modify(|current| {
                if item.strength > current.strength {
                    *current = item.clone();
                }
            })
            .or_insert(item);
    }
}

fn evidence_values(values: BTreeMap<String, BranchEvidence>) -> Vec<BranchEvidence> {
    values.into_values().collect()
}

fn independent_evidence(evidence: &[BranchEvidence]) -> Vec<&BranchEvidence> {
    let mut groups = BTreeMap::<String, &BranchEvidence>::new();

    for item in evidence {
        let group = item
            .independence_group
            .clone()
            .unwrap_or_else(|| format!("evidence:{}", item.id));
        groups
            .entry(group)
            .and_modify(|current| {
                if item.strength > current.strength {
                    *current = item;
                }
            })
            .or_insert(item);
    }

    groups.into_values().collect()
}

fn branch_score(
    supports: &[BranchEvidence],
    contradictions: &[BranchEvidence],
    unknown_count: usize,
) -> Score {
    if supports.is_empty() {
        return Score::ZERO;
    }

    let independent_supports = independent_evidence(supports);
    let independent_contradictions = independent_evidence(contradictions);
    let support = combine_scores(&independent_supports);
    let contradiction = combine_scores(&independent_contradictions);
    let after_contradictions = support.saturating_sub(contradiction);
    let unknown_penalty = u32::try_from(unknown_count)
        .unwrap_or(u32::MAX)
        .saturating_mul(1_000);
    let adjusted = after_contradictions
        .saturating_mul(10_000)
        .checked_div(10_000u32.saturating_add(unknown_penalty))
        .unwrap_or(0)
        .min(10_000);

    Score::new(adjusted as u16)
}

fn combine_scores(evidence: &[&BranchEvidence]) -> u32 {
    evidence.iter().fold(0u32, |combined, item| {
        let strength = u32::from(item.strength.value());
        let remaining = 10_000u32.saturating_sub(combined);
        combined.saturating_add(
            remaining
                .saturating_mul(strength)
                .checked_div(10_000)
                .unwrap_or(0),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(id: &str, strength: u16) -> BranchEvidence {
        BranchEvidence {
            id: id.to_string(),
            strength: Score::new(strength),
            independence_group: None,
        }
    }

    #[test]
    fn contradiction_and_unknown_reduce_branch_score() {
        let clean = branch_score(&[evidence("a", 8_000)], &[], 0);
        let contradicted = branch_score(&[evidence("a", 8_000)], &[evidence("b", 2_000)], 0);
        let unknown = branch_score(&[evidence("a", 8_000)], &[], 2);

        assert!(contradicted < clean);
        assert!(unknown < clean);
    }

    #[test]
    fn equivalent_hypotheses_merge_deterministically() {
        let result = evaluate_hypotheses(
            [
                HypothesisInput {
                    hypothesis: HypothesisKind::SuspiciousPersistence,
                    supports: vec![evidence("b", 7_000)],
                    contradictions: Vec::new(),
                    unknowns: vec!["timestamp".to_string()],
                },
                HypothesisInput {
                    hypothesis: HypothesisKind::SuspiciousPersistence,
                    supports: vec![evidence("a", 8_000), evidence("b", 6_000)],
                    contradictions: Vec::new(),
                    unknowns: vec!["timestamp".to_string()],
                },
            ],
            8,
        );

        assert_eq!(result.branches_created, 2);
        assert_eq!(result.branches_merged, 1);
        assert_eq!(result.branches.len(), 1);
        assert_eq!(result.branches[0].supports[0].id, "a");
        assert_eq!(result.branches[0].supports[1].strength, Score::new(7_000));
        assert_eq!(result.branches[0].unknowns, ["timestamp"]);
        assert_eq!(result.branches[0].independent_support_groups, 2);
    }

    #[test]
    fn dependent_collectors_count_as_one_independent_source() {
        let result = evaluate_hypotheses(
            [HypothesisInput {
                hypothesis: HypothesisKind::SuspiciousExecutionChain,
                supports: vec![
                    BranchEvidence {
                        id: "process_a".to_string(),
                        strength: Score::new(8_000),
                        independence_group: Some("windows_process_snapshot".to_string()),
                    },
                    BranchEvidence {
                        id: "process_b".to_string(),
                        strength: Score::new(7_000),
                        independence_group: Some("windows_process_snapshot".to_string()),
                    },
                ],
                contradictions: Vec::new(),
                unknowns: Vec::new(),
            }],
            8,
        );

        assert_eq!(result.branches[0].supports.len(), 2);
        assert_eq!(result.branches[0].independent_support_groups, 1);
        assert_eq!(result.branches[0].score, Score::new(8_000));
    }

    #[test]
    fn branch_limit_prunes_deterministically() {
        let result = evaluate_hypotheses(
            [
                HypothesisInput {
                    hypothesis: HypothesisKind::VisibilityLimited,
                    supports: vec![evidence("visibility", 4_000)],
                    contradictions: Vec::new(),
                    unknowns: Vec::new(),
                },
                HypothesisInput {
                    hypothesis: HypothesisKind::SuspiciousExecutionChain,
                    supports: vec![evidence("execution", 9_000)],
                    contradictions: Vec::new(),
                    unknowns: Vec::new(),
                },
            ],
            1,
        );

        assert_eq!(result.branches_retained, 1);
        assert_eq!(result.branches_pruned, 1);
        assert_eq!(
            result.branches[0].hypothesis,
            HypothesisKind::SuspiciousExecutionChain
        );
    }
}
