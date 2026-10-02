use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TemporalPoint {
    pub label: String,
    pub event_time_millis: Option<i64>,
}

impl TemporalPoint {
    pub fn from_raw(label: impl Into<String>, value: Option<&str>) -> Self {
        Self {
            label: label.into(),
            event_time_millis: value.and_then(parse_event_time),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalAssessment {
    Coherent,
    Unknown,
    OutsideWindow,
    OrderConflict,
}

pub fn assess_temporal_order(
    points: &[TemporalPoint],
    maximum_gap_seconds: u64,
    ordered: bool,
) -> TemporalAssessment {
    if points.len() < 2 || points.iter().any(|point| point.event_time_millis.is_none()) {
        return TemporalAssessment::Unknown;
    }

    let times = points
        .iter()
        .filter_map(|point| point.event_time_millis)
        .collect::<Vec<_>>();

    if ordered && times.windows(2).any(|pair| pair[0] > pair[1]) {
        return TemporalAssessment::OrderConflict;
    }

    let Some(earliest) = times.iter().min() else {
        return TemporalAssessment::Unknown;
    };
    let Some(latest) = times.iter().max() else {
        return TemporalAssessment::Unknown;
    };
    let Some(maximum_gap_millis) = maximum_gap_seconds.checked_mul(1_000) else {
        return TemporalAssessment::OutsideWindow;
    };
    let Ok(observed_gap) = u64::try_from((*latest).saturating_sub(*earliest)) else {
        return TemporalAssessment::OrderConflict;
    };

    if observed_gap > maximum_gap_millis {
        TemporalAssessment::OutsideWindow
    } else {
        TemporalAssessment::Coherent
    }
}

pub fn parse_event_time(value: &str) -> Option<i64> {
    let value = value.trim();

    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Some(parsed.timestamp_millis());
    }

    parse_wmi_datetime(value).map(|value| value.timestamp_millis())
}

fn parse_wmi_datetime(value: &str) -> Option<DateTime<Utc>> {
    if value.len() < 25 || value.as_bytes().get(14) != Some(&b'.') {
        return None;
    }

    let naive = NaiveDateTime::parse_from_str(value.get(..14)?, "%Y%m%d%H%M%S").ok()?;
    let sign = match value.as_bytes().get(21)? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let offset_minutes = value.get(22..25)?.parse::<i32>().ok()?.checked_mul(sign)?;
    let offset = FixedOffset::east_opt(offset_minutes.checked_mul(60)?)?;

    offset
        .from_local_datetime(&naive)
        .single()
        .map(|value| value.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3339_and_wmi_times_deterministically() {
        assert_eq!(
            parse_event_time("2026-09-15T01:00:00Z"),
            parse_event_time("20260915010000.000000+000")
        );
    }

    #[test]
    fn missing_timestamp_remains_unknown() {
        let result = assess_temporal_order(
            &[
                TemporalPoint::from_raw("file", Some("2026-09-15T01:00:00Z")),
                TemporalPoint::from_raw("process", None),
            ],
            120,
            true,
        );

        assert_eq!(result, TemporalAssessment::Unknown);
    }

    #[test]
    fn events_outside_window_do_not_form_a_coherent_chain() {
        let result = assess_temporal_order(
            &[
                TemporalPoint::from_raw("file", Some("2026-09-15T01:00:00Z")),
                TemporalPoint::from_raw("process", Some("2026-09-15T01:10:00Z")),
            ],
            120,
            true,
        );

        assert_eq!(result, TemporalAssessment::OutsideWindow);
    }

    #[test]
    fn reversed_events_are_an_order_conflict() {
        let result = assess_temporal_order(
            &[
                TemporalPoint::from_raw("file", Some("2026-09-15T01:10:00Z")),
                TemporalPoint::from_raw("process", Some("2026-09-15T01:00:00Z")),
            ],
            900,
            true,
        );

        assert_eq!(result, TemporalAssessment::OrderConflict);
    }
}
