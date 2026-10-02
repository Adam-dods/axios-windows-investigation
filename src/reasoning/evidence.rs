use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{confidence::EvidenceWeight, entity::EntityId};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EvidenceId(pub String);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceId(pub String);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Observed,
    ExplicitlyAbsent,
    NotCollected,
    Unsupported,
    CollectionFailed,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Complete,
    Partial,
    Restricted,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub collector: String,
    pub acquisition_method: String,
    pub underlying_source: String,
    pub privilege_level: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub source: SourceId,
    pub entity: Option<EntityId>,
    pub observation: Value,
    pub state: EvidenceState,
    pub weight: EvidenceWeight,
    pub visibility: Visibility,
    pub collected_at: Option<String>,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObservedFact {
    pub kind: EvidenceState,
    pub source: String,
    pub value: Value,
}

impl ObservedFact {
    pub fn new(source: impl Into<String>, value: Value) -> Self {
        Self {
            kind: EvidenceState::Observed,
            source: source.into(),
            value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn observed_fact_preserves_legacy_json_shape() {
        let fact = ObservedFact::new("collector.summary", json!(3));

        assert_eq!(
            serde_json::to_value(fact).expect("fact must serialize"),
            json!({
                "kind": "observed",
                "source": "collector.summary",
                "value": 3
            })
        );
    }

    #[test]
    fn unavailable_evidence_is_distinct_from_explicit_absence() {
        assert_ne!(EvidenceState::NotCollected, EvidenceState::ExplicitlyAbsent);
        assert_ne!(
            EvidenceState::CollectionFailed,
            EvidenceState::ExplicitlyAbsent
        );
        assert_ne!(EvidenceState::Unsupported, EvidenceState::ExplicitlyAbsent);
    }

    #[test]
    fn collection_failure_cannot_serialize_as_explicit_absence() {
        assert_eq!(
            serde_json::to_value(EvidenceState::CollectionFailed).expect("state must serialize"),
            Value::String("collection_failed".to_string())
        );
        assert_eq!(
            serde_json::to_value(EvidenceState::ExplicitlyAbsent).expect("state must serialize"),
            Value::String("explicitly_absent".to_string())
        );
    }
}
