use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IntelligenceSummary {
    pub engine: String,
    pub branches_created: usize,
    pub branches_retained: usize,
    pub stability_reached: bool,
    pub inference_passes: usize,
}

impl IntelligenceSummary {
    pub fn foundation() -> Self {
        Self {
            engine: "deterministic_symbolic_reasoning".to_string(),
            branches_created: 0,
            branches_retained: 0,
            stability_reached: true,
            inference_passes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foundation_schema_does_not_claim_unimplemented_branches() {
        let summary = IntelligenceSummary::foundation();

        assert_eq!(summary.engine, "deterministic_symbolic_reasoning");
        assert_eq!(summary.branches_created, 0);
        assert_eq!(summary.branches_retained, 0);
    }
}
