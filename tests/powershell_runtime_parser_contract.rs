use std::io::ErrorKind;
use std::process::Command;

#[test]
fn every_shipped_powershell_script_parses_when_powershell_is_available() {
    let command = r#"
$Failed = $false

Get-ChildItem -Path "installer/windows","scripts" -Filter "*.ps1" -File -Recurse |
ForEach-Object {
    $Tokens = $null
    $Errors = $null

    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $_.FullName,
        [ref]$Tokens,
        [ref]$Errors
    )

    if ($Errors.Count -gt 0) {
        $Failed = $true
        Write-Output ("PARSE_FAIL={0}" -f $_.FullName)

        foreach ($ErrorItem in $Errors) {
            Write-Output (
                "LINE={0};COLUMN={1};ERROR={2};TEXT={3}" -f
                $ErrorItem.Extent.StartLineNumber,
                $ErrorItem.Extent.StartColumnNumber,
                $ErrorItem.Message,
                $ErrorItem.Extent.Text
            )
        }
    }
}

if ($Failed) {
    exit 1
}
"#;

    let output = match Command::new("pwsh")
        .args(["-NoProfile", "-Command", command])
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == ErrorKind::NotFound => return,
        Err(error) => panic!("failed to execute PowerShell parser: {error}"),
    };

    assert!(
        output.status.success(),
        "PowerShell parser rejected shipped scripts:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
