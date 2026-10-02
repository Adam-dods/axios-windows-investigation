use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub const MAX_DEFENDER_EXCLUSIONS: usize = 100;
pub const MAX_BITLOCKER_VOLUMES: usize = 32;

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$maxExclusions = {MAX_DEFENDER_EXCLUSIONS}
$maxBitLockerVolumes = {MAX_BITLOCKER_VOLUMES}

$collectionErrors = [System.Collections.Generic.List[string]]::new()

function Get-AxiosObservedValue {{
    param(
        [string]$Source,
        [scriptblock]$Action,
        [object]$Fallback
    )

    try {{
        & $Action
    }}
    catch {{
        $collectionErrors.Add(("{{0}}: {{1}}" -f $Source, $_.Exception.Message))
        $Fallback
    }}
}}

$uac = Get-AxiosObservedValue "uac" {{
    $key = Get-ItemProperty `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -ErrorAction Stop

    [PSCustomObject]@{{
        enable_lua = [int]$key.EnableLUA
        consent_prompt_behavior_admin =
            [int]$key.ConsentPromptBehaviorAdmin
        prompt_on_secure_desktop =
            [int]$key.PromptOnSecureDesktop
    }}
}} ([PSCustomObject]@{{
    available = $false
}})

$secureBoot = Get-AxiosObservedValue "secure_boot" {{
    [PSCustomObject]@{{
        available = $true
        enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
    }}
}} ([PSCustomObject]@{{
    available = $null
    enabled = $null
}})

$defenderStatus = Get-AxiosObservedValue "defender_status" {{
    $status = Get-MpComputerStatus -ErrorAction Stop

    [PSCustomObject]@{{
        available = $true
        antivirus_enabled = [bool]$status.AntivirusEnabled
        antispyware_enabled = [bool]$status.AntispywareEnabled
        real_time_protection_enabled =
            [bool]$status.RealTimeProtectionEnabled
        behavior_monitor_enabled = [bool]$status.BehaviorMonitorEnabled
        ioav_protection_enabled = [bool]$status.IoavProtectionEnabled
        tamper_protection_source = [string]$status.IsTamperProtected
        antivirus_signature_last_updated =
            [string]$status.AntivirusSignatureLastUpdated
    }}
}} ([PSCustomObject]@{{
    available = $false
}})

$defenderExclusions = Get-AxiosObservedValue "defender_exclusions" {{
    $preferences = Get-MpPreference -ErrorAction Stop

    [PSCustomObject]@{{
        available = $true
        paths = @(
            $preferences.ExclusionPath |
                ForEach-Object {{ [string]$_ }} |
                Select-Object -First $maxExclusions
        )
        processes = @(
            $preferences.ExclusionProcess |
                ForEach-Object {{ [string]$_ }} |
                Select-Object -First $maxExclusions
        )
        extensions = @(
            $preferences.ExclusionExtension |
                ForEach-Object {{ [string]$_ }} |
                Select-Object -First $maxExclusions
        )
    }}
}} ([PSCustomObject]@{{
    available = $false
    paths = @()
    processes = @()
    extensions = @()
}})

$securityProducts = Get-AxiosObservedValue "security_center" {{
    @(
        Get-CimInstance `
            -Namespace 'root\SecurityCenter2' `
            -ClassName 'AntiVirusProduct' `
            -ErrorAction Stop |
            Select-Object -First 20 |
            ForEach-Object {{
                [PSCustomObject]@{{
                    display_name = [string]$_.displayName
                    path_to_signed_product_exe =
                        [string]$_.pathToSignedProductExe
                    product_state = [string]$_.productState
                }}
            }}
    )
}} @()

$bitLockerVolumes = Get-AxiosObservedValue "bitlocker" {{
    @(
        Get-BitLockerVolume -ErrorAction Stop |
            Select-Object -First $maxBitLockerVolumes |
            ForEach-Object {{
                [PSCustomObject]@{{
                    mount_point = @($_.MountPoint | Select-Object -First 1)
                    volume_status = [string]$_.VolumeStatus
                    protection_status = [string]$_.ProtectionStatus
                    encryption_percentage = [int]$_.EncryptionPercentage
                    encryption_method = [string]$_.EncryptionMethod
                }}
            }}
    )
}} @()

[PSCustomObject]@{{
    success = $true
    collector = 'windows_security_posture'
    uac = $uac
    secure_boot = $secureBoot
    defender_status = $defenderStatus
    defender_exclusions = $defenderExclusions
    registered_antivirus_products = $securityProducts
    bitlocker_volumes = $bitLockerVolumes
    collection_status = if ($collectionErrors.Count -eq 0) {{ 'complete' }} else {{ 'partial' }}
    collection_errors = @($collectionErrors)
    limits = @{{
        max_defender_exclusions = $maxExclusions
        max_bitlocker_volumes = $maxBitLockerVolumes
    }}
}} | ConvertTo-Json -Depth 10 -Compress
"#
        );

        match powershell(&script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_security_posture",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_security_posture",
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_posture_limits_are_bounded() {
        assert_eq!(MAX_DEFENDER_EXCLUSIONS, 100);
        assert_eq!(MAX_BITLOCKER_VOLUMES, 32);
    }
}
