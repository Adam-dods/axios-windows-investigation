use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::{fs, path::Path};

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

pub fn read_value(path: impl AsRef<Path>) -> Result<Value> {
    let path = path.as_ref();

    let bytes =
        fs::read(path).with_context(|| format!("Could not read JSON file: {}", path.display()))?;

    parse_value_bytes(&bytes)
        .with_context(|| format!("Could not parse JSON file: {}", path.display()))
}

pub fn write_pretty<T>(path: impl AsRef<Path>, value: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    let path = path.as_ref();

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Could not create JSON output directory: {}",
                    parent.display()
                )
            })?;
        }
    }

    let rendered = serde_json::to_vec_pretty(value).context("Could not serialize JSON report")?;

    fs::write(path, rendered)
        .with_context(|| format!("Could not write JSON file: {}", path.display()))
}

fn parse_value_bytes(bytes: &[u8]) -> Result<Value> {
    let payload = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);

    serde_json::from_slice(payload).context("Input does not contain valid UTF-8 JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn utf8_bom_is_accepted() {
        let mut bytes = UTF8_BOM.to_vec();
        bytes.extend_from_slice(br#"{"success":true}"#);

        let value = parse_value_bytes(&bytes).unwrap();

        assert_eq!(value["success"], true);
    }

    #[test]
    fn invalid_json_is_rejected() {
        assert!(parse_value_bytes(b"{invalid").is_err());
    }

    #[test]
    fn written_report_can_be_read_again() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "axios-json-file-{}-{unique}.json",
            std::process::id()
        ));

        let expected = json!({
            "schema_version": 1,
            "success": true,
            "items": [1, 2, 3]
        });

        write_pretty(&path, &expected).unwrap();
        let actual = read_value(&path).unwrap();

        let _ = fs::remove_file(path);

        assert_eq!(actual, expected);
    }
}
