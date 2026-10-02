use std::fs;
use std::path::Path;

fn matching_type_start(source: &str, static_access: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = static_access;

    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }

    if cursor == 0 || bytes[cursor - 1] != b']' {
        return None;
    }

    cursor -= 1;
    let mut depth = 1usize;

    while cursor > 0 {
        cursor -= 1;

        match bytes[cursor] {
            b']' => depth += 1,
            b'[' => {
                depth -= 1;

                if depth == 0 {
                    return Some(cursor);
                }
            }
            _ => {}
        }
    }

    None
}

#[test]
fn windows_runners_do_not_split_static_type_expressions() {
    let root = Path::new("installer/windows");

    for entry in fs::read_dir(root).expect("windows installer directory") {
        let entry = entry.expect("windows installer entry");
        let path = entry.path();

        if path.extension().and_then(|value| value.to_str()) != Some("ps1") {
            continue;
        }

        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));

        let mut offset = 0usize;

        while let Some(relative) = source[offset..].find("::") {
            let position = offset + relative;

            if let Some(start) = matching_type_start(&source, position) {
                let expression = &source[start..position + 2];

                assert!(
                    !expression.contains('\n') && !expression.contains('\r'),
                    "multiline PowerShell static type expression in {}: {:?}",
                    path.display(),
                    expression
                );
            }

            offset = position + 2;
        }

        assert!(
            !source.contains(".Get.GetBytes("),
            "invalid Get.GetBytes method chain in {}",
            path.display()
        );
    }
}

#[test]
fn optional_property_reader_is_never_used_as_assignment_target() {
    let source = std::fs::read_to_string("installer/windows/Run-AXIOS-Complete-Investigation.ps1")
        .expect("complete runner should be readable");

    for line in source.lines() {
        assert!(
            !(line.contains("Get-AxiosOptionalProperty") && line.contains(") =")),
            "optional property reader cannot be an assignment target: {line}"
        );
    }

    assert!(source.contains("$PortableResult.findings ="));
}

#[test]
fn layer_receipt_guard_never_enters_a_method_argument() {
    let layer = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

    assert!(!layer.contains("$AllFindings.Add(if"));
    assert!(layer.contains("if ($env:AXIOS_CONSOLE_SESSION -ne \"1\") {\n        [ordered]@{"));
}

#[test]
fn developer_view_avoids_reserved_execution_context_variable() {
    let developer = include_str!("../installer/windows/Run-AXIOS-Developer-Exposure-View.ps1");

    assert!(!developer.contains("$ExecutionContext"));
    assert!(developer.contains("$AxiosExecutionContext"));
}

#[test]
fn results_heading_helper_is_defined_before_its_first_call() {
    let layer = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

    let definition = layer
        .find("function Write-AxiosConsoleHeading")
        .expect("heading helper definition is missing");

    let call = layer
        .find("Write-AxiosConsoleHeading `")
        .expect("heading helper call is missing");

    assert!(
        definition < call,
        "Results calls the heading helper before it is defined"
    );
}
