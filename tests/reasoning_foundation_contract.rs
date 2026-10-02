use axios_core::reasoning::{
    plan_utility_score, EvidenceState, EvidenceWeight, InferenceLimits, ObservedFact,
    ProcessIdentity, Score,
};
use serde_json::json;

#[test]
fn typed_observed_fact_preserves_the_legacy_contract() {
    let fact = ObservedFact::new("source.path", json!({"count": 1}));

    assert_eq!(
        serde_json::to_value(fact).expect("fact must serialize"),
        json!({
            "kind": "observed",
            "source": "source.path",
            "value": {"count": 1}
        })
    );
}

#[test]
fn missing_visibility_never_equals_explicit_absence() {
    for state in [
        EvidenceState::NotCollected,
        EvidenceState::Unsupported,
        EvidenceState::CollectionFailed,
        EvidenceState::Inconclusive,
    ] {
        assert_ne!(state, EvidenceState::ExplicitlyAbsent);
    }
}

#[test]
fn fixed_point_scores_are_bounded_and_repeatable() {
    let first = Score::new(8_000).multiply(Score::new(7_500));
    let second = Score::new(8_000).multiply(Score::new(7_500));

    assert_eq!(first.value(), 6_000);
    assert_eq!(first, second);
    assert_eq!(Score::new(u16::MAX), Score::MAX);
}

#[test]
fn existing_plan_utility_formula_is_unchanged() {
    assert_eq!(plan_utility_score(5, 2), 50);
    assert_eq!(plan_utility_score(4, 1), 80);
    assert_eq!(plan_utility_score(1, 1), 20);
}

#[test]
fn evidence_weight_uses_every_deterministic_factor() {
    let weight = EvidenceWeight {
        reliability: Score::new(10_000),
        collection_quality: Score::new(8_000),
        independence: Score::new(5_000),
        freshness: Score::new(10_000),
        entity_match: Score::new(5_000),
    };

    assert_eq!(weight.strength().value(), 2_000);
}

#[test]
fn same_pid_different_start_time_is_not_same_process() {
    let first = ProcessIdentity {
        pid: 4242,
        start_time: Some("100".to_string()),
        normalized_path: Some(r"c:\windows\sample.exe".to_string()),
        sha256: Some("aabb".to_string()),
    };
    let second = ProcessIdentity {
        start_time: Some("200".to_string()),
        ..first.clone()
    };

    assert!(!first.same_instance_as(&second));
}

#[test]
fn inference_limits_reject_unbounded_configuration() {
    assert!(InferenceLimits::default().validate().is_ok());

    let invalid = InferenceLimits {
        max_passes: 0,
        ..InferenceLimits::default()
    };
    assert!(invalid.validate().is_err());
}
