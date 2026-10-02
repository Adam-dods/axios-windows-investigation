use serde::{Deserialize, Serialize};

pub const SCORE_MAX: u16 = 10_000;

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Score(u16);

impl Score {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(SCORE_MAX);

    pub const fn new(value: u16) -> Self {
        if value > SCORE_MAX {
            Self(SCORE_MAX)
        } else {
            Self(value)
        }
    }

    pub const fn value(self) -> u16 {
        self.0
    }

    pub fn multiply(self, other: Self) -> Self {
        let product = u32::from(self.0) * u32::from(other.0);
        Self::new((product / u32::from(SCORE_MAX)) as u16)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceWeight {
    pub reliability: Score,
    pub collection_quality: Score,
    pub independence: Score,
    pub freshness: Score,
    pub entity_match: Score,
}

impl EvidenceWeight {
    pub fn strength(self) -> Score {
        self.reliability
            .multiply(self.collection_quality)
            .multiply(self.independence)
            .multiply(self.freshness)
            .multiply(self.entity_match)
    }
}

pub fn plan_utility_score(information_gain: u8, collection_cost: u8) -> u8 {
    information_gain
        .saturating_mul(20)
        .checked_div(collection_cost.max(1))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_is_bounded() {
        assert_eq!(Score::new(0), Score::ZERO);
        assert_eq!(Score::new(10_000), Score::MAX);
        assert_eq!(Score::new(u16::MAX), Score::MAX);
    }

    #[test]
    fn fixed_point_multiplication_is_deterministic() {
        assert_eq!(Score::new(8_000).multiply(Score::new(5_000)).value(), 4_000);
        assert_eq!(Score::new(8_000).multiply(Score::new(5_000)).value(), 4_000);
    }

    #[test]
    fn legacy_plan_score_is_preserved_and_zero_cost_is_safe() {
        assert_eq!(plan_utility_score(5, 2), 50);
        assert_eq!(plan_utility_score(5, 0), 100);
        assert_eq!(plan_utility_score(u8::MAX, 1), u8::MAX);
    }

    #[test]
    fn evidence_strength_uses_all_factors_without_overflow() {
        let weight = EvidenceWeight {
            reliability: Score::new(10_000),
            collection_quality: Score::new(8_000),
            independence: Score::new(5_000),
            freshness: Score::new(10_000),
            entity_match: Score::new(5_000),
        };

        assert_eq!(weight.strength().value(), 2_000);
    }
}
