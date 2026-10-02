#[cfg(windows)]
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub fn inspect(path: &str) -> Value {
    #[cfg(windows)]
    {
        let encoded = STANDARD.encode(
            path.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>(),
        );

        let script = format!(
            r#"
$ErrorActionPreference = 'SilentlyContinue'
$bytes = [Convert]::FromBase64String('{encoded}')
$path = [System.Text.Encoding]::Unicode.GetString($bytes)

if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {{
    [PSCustomObject]@{{
        success = $false
        path = $path
        error = 'file_not_found'
    }} | ConvertTo-Json -Compress

    exit
}}

$signature = Get-AuthenticodeSignature -LiteralPath $path
$certificate = $signature.SignerCertificate

[PSCustomObject]@{{
    success = $true
    path = $path
    status = [string]$signature.Status
    status_message = $signature.StatusMessage
    signature_type = [string]$signature.SignatureType
    signer_subject = if ($certificate) {{ $certificate.Subject }} else {{ $null }}
    signer_issuer = if ($certificate) {{ $certificate.Issuer }} else {{ $null }}
    signer_thumbprint = if ($certificate) {{ $certificate.Thumbprint }} else {{ $null }}
    signer_not_before = if ($certificate) {{ $certificate.NotBefore }} else {{ $null }}
    signer_not_after = if ($certificate) {{ $certificate.NotAfter }} else {{ $null }}
}} | ConvertTo-Json -Depth 5 -Compress
"#
        );

        match powershell(&script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "path": path,
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "path": path,
            "error": "Windows-only Authenticode collector"
        })
    }
}

pub fn risk_score_for_status(status: &str) -> u32 {
    match status.trim().to_lowercase().as_str() {
        "valid" => 0,
        "notsigned" => 20,
        "unknownerror" => 30,
        "nottrusted" => 60,
        "hashmismatch" => 80,
        "notvalid" => 80,
        _ => 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_signature_has_no_risk_score() {
        assert_eq!(risk_score_for_status("Valid"), 0);
    }

    #[test]
    fn unsigned_file_is_low_risk_not_automatically_malware() {
        assert_eq!(risk_score_for_status("NotSigned"), 20);
    }

    #[test]
    fn hash_mismatch_is_high_risk() {
        assert_eq!(risk_score_for_status("HashMismatch"), 80);
    }
}
