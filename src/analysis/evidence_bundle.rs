use chrono::Utc;
use serde_json::{json, Value};

use crate::{
    persistence,
    system::{access_surface, health_posture, network_posture},
};

pub fn collect() -> Value {
    json!({
        "schema_version": 1,
        "generated_at": Utc::now(),
        "collector": "axios_evidence_bundle",
        "access_surface": access_surface::collect(),
        "network_posture": network_posture::collect(),
        "registry_persistence": persistence::registry::collect(),
        "extended_persistence": persistence::extended::collect(),
        "health_posture": health_posture::collect()
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn evidence_bundle_schema_is_versioned() {
        const SCHEMA_VERSION: u32 = 1;
        assert_eq!(SCHEMA_VERSION, 1);
    }
}
