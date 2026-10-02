use std::fs;
use std::path::Path;

fn powershell_files() -> Vec<String> {
    let mut files = Vec::new();

    for entry in
        fs::read_dir("installer/windows").expect("Windows installer directory should be readable")
    {
        let entry = entry.expect("directory entry should be readable");
        let path = entry.path();

        if path.extension().and_then(|value| value.to_str()) != Some("ps1") {
            continue;
        }

        files.push(path.to_string_lossy().into_owned());
    }

    files.sort();
    files
}

#[test]
fn axios_powershell_file_reads_are_explicitly_utf8() {
    for file in powershell_files() {
        let source = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("failed to read {file}: {error}"));

        for (index, line) in source.lines().enumerate() {
            if !line.contains("Get-Content") {
                continue;
            }

            assert!(
                line.contains("Get-Content -Encoding UTF8"),
                "{}:{} reads text without explicit UTF-8: {}",
                file,
                index + 1,
                line.trim()
            );
        }
    }
}

#[test]
fn critical_json_runners_use_explicit_utf8_reads() {
    for file in [
        "installer/windows/Run-AXIOS-Layer.ps1",
        "installer/windows/Run-AXIOS-Complete-Investigation.ps1",
        "installer/windows/Run-AXIOS-Standard-User-Audit.ps1",
        "installer/windows/Run-AXIOS-Administrator-Exposure-Audit.ps1",
        "installer/windows/Run-AXIOS-Network-Deep-Review.ps1",
    ] {
        assert!(Path::new(file).is_file());

        let source = fs::read_to_string(file).expect("runner should be readable");

        assert!(
            source.contains("Get-Content -Encoding UTF8"),
            "{file} should use explicit UTF-8 reads"
        );
    }
}
