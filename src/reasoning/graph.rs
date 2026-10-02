use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactIdentity {
    pub normalized_path: Option<String>,
    pub sha256: Option<String>,
    pub pid: Option<u32>,
    pub process_start_time: Option<String>,
}

impl ArtifactIdentity {
    pub fn normalized(
        path: Option<&str>,
        sha256: Option<&str>,
        pid: Option<u64>,
        process_start_time: Option<&str>,
    ) -> Self {
        Self {
            normalized_path: path.map(normalize_path).filter(|value| !value.is_empty()),
            sha256: sha256
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_ascii_lowercase),
            pid: pid.and_then(|value| u32::try_from(value).ok()),
            process_start_time: process_start_time
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMatchStrength {
    Strong,
    Partial,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdentityMatch {
    pub strength: IdentityMatchStrength,
    pub shared_path: Option<String>,
    pub shared_sha256: Option<String>,
    pub process_instance_confirmed: bool,
    pub reasons: Vec<String>,
}

pub fn match_artifact_identities(identities: &[ArtifactIdentity]) -> IdentityMatch {
    let paths = known_values(
        identities
            .iter()
            .filter_map(|item| item.normalized_path.as_deref()),
    );
    let hashes = known_values(identities.iter().filter_map(|item| item.sha256.as_deref()));

    if paths.len() > 1 || hashes.len() > 1 {
        let mut reasons = Vec::new();
        if paths.len() > 1 {
            reasons.push("normalized_path_conflict".to_string());
        }
        if hashes.len() > 1 {
            reasons.push("sha256_conflict".to_string());
        }

        return IdentityMatch {
            strength: IdentityMatchStrength::Conflict,
            shared_path: single_value(&paths),
            shared_sha256: single_value(&hashes),
            process_instance_confirmed: false,
            reasons,
        };
    }

    let process_identities = identities
        .iter()
        .filter(|item| item.pid.is_some() || item.process_start_time.is_some())
        .collect::<Vec<_>>();

    let process_instance_confirmed = process_identities.len() >= 2
        && process_identities.iter().all(|item| item.pid.is_some())
        && process_identities
            .iter()
            .all(|item| item.process_start_time.is_some())
        && process_identities.windows(2).all(|pair| {
            pair[0].pid == pair[1].pid && pair[0].process_start_time == pair[1].process_start_time
        });

    let path_confirmed =
        paths.len() == 1 && identities.iter().all(|item| item.normalized_path.is_some());
    let hash_confirmed = hashes.len() == 1
        && identities
            .iter()
            .filter(|item| item.sha256.is_some())
            .count()
            >= 2;

    let strong = path_confirmed && hash_confirmed && process_instance_confirmed;
    let mut reasons = Vec::new();

    if !path_confirmed {
        reasons.push("path_identity_incomplete".to_string());
    }
    if !hash_confirmed {
        reasons.push("hash_identity_incomplete".to_string());
    }
    if !process_instance_confirmed {
        reasons.push("process_instance_identity_incomplete".to_string());
    }

    IdentityMatch {
        strength: if strong {
            IdentityMatchStrength::Strong
        } else {
            IdentityMatchStrength::Partial
        },
        shared_path: single_value(&paths),
        shared_sha256: single_value(&hashes),
        process_instance_confirmed,
        reasons,
    }
}

fn known_values<'a>(values: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
    values.map(str::to_ascii_lowercase).collect()
}

fn single_value(values: &BTreeSet<String>) -> Option<String> {
    (values.len() == 1)
        .then(|| values.iter().next().cloned())
        .flatten()
}

fn normalize_path(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(
        path: &str,
        hash: Option<&str>,
        pid: Option<u64>,
        start: Option<&str>,
    ) -> ArtifactIdentity {
        ArtifactIdentity::normalized(Some(path), hash, pid, start)
    }

    #[test]
    fn matching_hash_and_process_instance_is_strong() {
        let result = match_artifact_identities(&[
            identity(r"C:\Sample.exe", Some("AABB"), None, None),
            identity(r"c:/sample.exe", Some("aabb"), Some(42), Some("100")),
            identity(r"C:\SAMPLE.EXE", Some("AABB"), Some(42), Some("100")),
        ]);

        assert_eq!(result.strength, IdentityMatchStrength::Strong);
        assert!(result.process_instance_confirmed);
    }

    #[test]
    fn same_path_with_different_hash_is_a_conflict() {
        let result = match_artifact_identities(&[
            identity(r"C:\sample.exe", Some("aaaa"), None, None),
            identity(r"C:\sample.exe", Some("bbbb"), Some(42), Some("100")),
        ]);

        assert_eq!(result.strength, IdentityMatchStrength::Conflict);
        assert!(result
            .reasons
            .iter()
            .any(|reason| reason == "sha256_conflict"));
    }

    #[test]
    fn reused_pid_is_not_a_strong_match() {
        let result = match_artifact_identities(&[
            identity(r"C:\sample.exe", Some("aaaa"), Some(42), Some("100")),
            identity(r"C:\sample.exe", Some("aaaa"), Some(42), Some("200")),
        ]);

        assert_eq!(result.strength, IdentityMatchStrength::Partial);
        assert!(!result.process_instance_confirmed);
    }

    #[test]
    fn path_only_match_is_partial() {
        let result = match_artifact_identities(&[
            identity(r"C:\sample.exe", None, None, None),
            identity(r"c:/sample.exe", None, None, None),
        ]);

        assert_eq!(result.strength, IdentityMatchStrength::Partial);
    }
}
