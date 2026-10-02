use axios_core::reasoning::{
    assess_temporal_order, parse_event_time, TemporalAssessment, TemporalPoint,
};

#[test]
fn rfc3339_and_windows_wmi_time_are_equivalent() {
    assert_eq!(
        parse_event_time("2026-09-15T01:00:00Z"),
        parse_event_time("20260915010000.000000+000")
    );
}

#[test]
fn missing_timestamp_remains_unknown() {
    let points = [
        TemporalPoint::from_raw("file_created", Some("2026-09-15T01:00:00Z")),
        TemporalPoint::from_raw("process_started", None),
    ];

    assert_eq!(
        assess_temporal_order(&points, 120, true),
        TemporalAssessment::Unknown
    );
}

#[test]
fn events_outside_window_do_not_form_causal_chain() {
    let points = [
        TemporalPoint::from_raw("file_created", Some("2026-09-15T01:00:00Z")),
        TemporalPoint::from_raw("process_started", Some("2026-09-15T01:10:00Z")),
    ];

    assert_eq!(
        assess_temporal_order(&points, 120, true),
        TemporalAssessment::OutsideWindow
    );
}

#[test]
fn collection_time_is_not_part_of_event_time_api() {
    let source = include_str!("../src/reasoning/temporal.rs");

    assert!(!source.contains("observed_at.and_then(parse_event_time)"));
    assert!(!source.contains("collection_time.and_then(parse_event_time)"));
}

#[test]
fn timestamps_propagate_without_becoming_verdicts() {
    let behavior = include_str!("../src/bin/axios-behavior-hunt.rs");
    let correlation = include_str!("../src/bin/axios-audit-correlate.rs");
    let score = include_str!("../src/bin/axios-correlation-score.rs");

    for source in [behavior, correlation, score] {
        assert!(source.contains("created_utc"));
        assert!(source.contains("modified_utc"));
        assert!(!source.contains("\"malware_confirmed\": true"));
    }
}
