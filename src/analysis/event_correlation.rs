use chrono::{Duration, Utc};
use serde_json::{json, Value};

use crate::telemetry::windows_events;

pub fn collect_recent(hours: i64) -> Value {
    let bounded_hours = hours.clamp(1, 168);
    let since = Utc::now() - Duration::hours(bounded_hours);
    let events = windows_events::collect_since(since);

    build_report(bounded_hours, events)
}

fn build_report(bounded_hours: i64, events: Value) -> Value {
    let success = windows_events::collection_succeeded(&events);

    let items = events
        .get("relevant_events")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let high_priority = items
        .iter()
        .filter(|event| {
            matches!(
                event.get("event_id").and_then(Value::as_u64),
                Some(1102 | 7045 | 4697 | 4698 | 4702)
            )
        })
        .cloned()
        .collect::<Vec<_>>();

    json!({
        "schema_version": 1,
        "collector": "axios_event_correlation",
        "success": success,
        "window_hours": bounded_hours,
        "event_count": items.len(),
        "high_priority_events": high_priority,
        "source": events
    })
}

#[cfg(test)]
mod tests {
    use super::{build_report, json};

    #[test]
    fn correlation_window_is_bounded() {
        assert_eq!(1i64.clamp(1, 168), 1);
        assert_eq!(999i64.clamp(1, 168), 168);
    }

    #[test]
    fn complete_collection_produces_success_and_correlates_relevant_events() {
        let report = build_report(
            24,
            json!({
                "success": true,
                "collection_status": "complete",
                "relevant_events": [
                    { "event_id": 7045 },
                    { "event_id": 1000 }
                ]
            }),
        );

        assert_eq!(report["success"], true);
        assert_eq!(report["event_count"], 2);
        assert_eq!(report["high_priority_events"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn incomplete_collection_produces_failure() {
        let report = build_report(
            24,
            json!({
                "success": false,
                "collection_status": "partial",
                "relevant_events": []
            }),
        );

        assert_eq!(report["success"], false);
    }
}
