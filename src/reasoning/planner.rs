use crate::reasoning::Score;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvestigationCheck {
    pub id: String,
    pub action: String,
    pub resolves: Vec<String>,
    pub distinguishes: Vec<String>,
    pub information_gain: Score,
    pub discrimination: Score,
    pub safety: Score,
    pub cost: Score,
    pub runtime: Score,
    pub intrusiveness: Score,
    pub read_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RankedCheck {
    #[serde(flatten)]
    pub check: InvestigationCheck,
    pub utility: Score,
}

pub fn rank_checks(
    checks: impl IntoIterator<Item = InvestigationCheck>,
    limit: usize,
) -> Vec<RankedCheck> {
    let mut ranked = checks
        .into_iter()
        .filter(|check| check.read_only)
        .map(|check| RankedCheck {
            utility: utility(&check),
            check,
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .utility
            .cmp(&left.utility)
            .then_with(|| left.check.id.cmp(&right.check.id))
    });
    ranked.truncate(limit);
    ranked
}

fn utility(check: &InvestigationCheck) -> Score {
    let benefit = check
        .information_gain
        .multiply(check.discrimination)
        .multiply(check.safety);
    let burden = check
        .cost
        .multiply(check.runtime)
        .multiply(check.intrusiveness)
        .value()
        .max(1_000);
    let value = u32::from(benefit.value())
        .saturating_mul(1_000)
        .checked_div(u32::from(burden))
        .unwrap_or(0)
        .min(10_000);
    Score::new(value as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: &str, gain: u16, cost: u16, read_only: bool) -> InvestigationCheck {
        InvestigationCheck {
            id: id.to_string(),
            action: id.to_string(),
            resolves: Vec::new(),
            distinguishes: Vec::new(),
            information_gain: Score::new(gain),
            discrimination: Score::new(8_000),
            safety: Score::MAX,
            cost: Score::new(cost),
            runtime: Score::new(5_000),
            intrusiveness: Score::new(2_000),
            read_only,
        }
    }

    #[test]
    fn planner_prefers_safe_high_information_check() {
        let ranked = rank_checks(
            [
                check("expensive", 7_000, 8_000, true),
                check("useful", 9_000, 2_000, true),
                check("mutating", 10_000, 1_000, false),
            ],
            2,
        );
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].check.id, "useful");
        assert!(ranked.iter().all(|item| item.check.read_only));
    }
}
