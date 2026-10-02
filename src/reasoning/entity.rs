use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntityId(pub String);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    File,
    Process,
    Service,
    ScheduledTask,
    RegistryEntry,
    Driver,
    NetworkEndpoint,
    User,
    SecurityControl,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileIdentity {
    pub normalized_path: Option<String>,
    pub sha256: Option<String>,
    pub signer_thumbprint: Option<String>,
    pub size_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time: Option<String>,
    pub normalized_path: Option<String>,
    pub sha256: Option<String>,
}

impl ProcessIdentity {
    pub fn same_instance_as(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.start_time.is_some()
            && self.start_time == other.start_time
            && compatible_identity_value(&self.normalized_path, &other.normalized_path)
            && compatible_identity_value(&self.sha256, &other.sha256)
    }
}

fn compatible_identity_value(left: &Option<String>, right: &Option<String>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, start_time: Option<&str>) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_time: start_time.map(str::to_string),
            normalized_path: Some(r"c:\program files\sample\sample.exe".to_string()),
            sha256: Some("aabb".to_string()),
        }
    }

    #[test]
    fn same_pid_with_different_start_time_is_not_the_same_process() {
        assert!(!process(42, Some("100")).same_instance_as(&process(42, Some("200"))));
    }

    #[test]
    fn missing_start_time_cannot_confirm_process_identity() {
        assert!(!process(42, None).same_instance_as(&process(42, None)));
    }
}
