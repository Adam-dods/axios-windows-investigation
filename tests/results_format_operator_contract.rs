const LAYER: &str = include_str!("../installer/windows/Run-AXIOS-Layer.ps1");

#[test]
fn coverage_messages_are_formatted_before_list_insertion() {
    let unsafe_block = r#"$NormalizedErrors.Add(
                        "{0}: {1}" -f"#;

    assert!(
        !LAYER.contains(unsafe_block),
        "format expression must not be split into Add arguments"
    );

    assert!(
        LAYER.contains("$Message = if ("),
        "coverage message must be constructed before insertion"
    );

    assert!(
        LAYER.contains("\"{0}: {1}\" -f $SourceName, $ErrorText"),
        "structured source and error formatting is missing"
    );

    assert!(
        LAYER.contains("$NormalizedErrors.Add($Message)"),
        "formatted coverage message is not added safely"
    );
}

#[test]
fn coverage_messages_are_deduplicated_before_insertion() {
    assert!(
        LAYER.contains("if (-not $NormalizedErrors.Contains($Message))"),
        "coverage messages must be deduplicated"
    );
}
