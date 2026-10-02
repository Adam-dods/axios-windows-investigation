use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InferenceLimits {
    pub max_facts: usize,
    pub max_rules: usize,
    pub max_passes: usize,
    pub max_branches: usize,
    pub max_proof_depth: usize,
}

impl Default for InferenceLimits {
    fn default() -> Self {
        Self {
            max_facts: 4_096,
            max_rules: 1_024,
            max_passes: 64,
            max_branches: 128,
            max_proof_depth: 32,
        }
    }
}

impl InferenceLimits {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.max_facts == 0
            || self.max_rules == 0
            || self.max_passes == 0
            || self.max_branches == 0
            || self.max_proof_depth == 0
        {
            return Err("inference limits must be greater than zero");
        }

        if self.max_facts > 100_000
            || self.max_rules > 10_000
            || self.max_passes > 1_000
            || self.max_branches > 10_000
            || self.max_proof_depth > 1_000
        {
            return Err("inference limits exceed the defensive execution boundary");
        }

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_are_valid_and_bounded() {
        assert!(InferenceLimits::default().validate().is_ok());
    }

    #[test]
    fn zero_and_excessive_limits_are_rejected() {
        let zero = InferenceLimits {
            max_passes: 0,
            ..InferenceLimits::default()
        };
        let excessive = InferenceLimits {
            max_facts: 100_001,
            ..InferenceLimits::default()
        };

        assert!(zero.validate().is_err());
        assert!(excessive.validate().is_err());
    }
}
