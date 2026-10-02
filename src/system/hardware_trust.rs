use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub const MAX_PHYSICAL_DISKS: usize = 32;

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'Stop'
$maxDisks = 32

function Invoke-AxiosOptional {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    try {
        & $Action
    }
    catch {
        [PSCustomObject]@{
            available = $false
            error = $_.Exception.Message
        }
    }
}

$secureBoot = Invoke-AxiosOptional {
    [PSCustomObject]@{
        available = $true
        enabled = [bool](Confirm-SecureBootUEFI)
    }
}

$tpm = Invoke-AxiosOptional {
    Get-Tpm |
        Select-Object `
            TpmPresent,
            TpmReady,
            TpmEnabled,
            TpmActivated,
            TpmOwned,
            ManufacturerIdTxt,
            ManufacturerVersion,
            ManagedAuthLevel,
            LockedOut,
            LockoutCount,
            LockoutMax,
            SelfTest
}

$deviceGuard = Invoke-AxiosOptional {
    Get-CimInstance `
        -Namespace 'root\Microsoft\Windows\DeviceGuard' `
        -ClassName 'Win32_DeviceGuard' `
        -ErrorAction Stop |
        Select-Object `
            VirtualizationBasedSecurityStatus,
            SecurityServicesConfigured,
            SecurityServicesRunning,
            CodeIntegrityPolicyEnforcementStatus,
            UsermodeCodeIntegrityPolicyEnforcementStatus,
            AvailableSecurityProperties,
            RequiredSecurityProperties
}

$bitLocker = Invoke-AxiosOptional {
    Get-BitLockerVolume -ErrorAction Stop |
        Select-Object `
            MountPoint,
            VolumeType,
            VolumeStatus,
            ProtectionStatus,
            EncryptionMethod,
            EncryptionPercentage,
            LockStatus
}

$bios = Invoke-AxiosOptional {
    Get-CimInstance Win32_BIOS -ErrorAction Stop |
        Select-Object `
            Manufacturer,
            Name,
            SMBIOSBIOSVersion,
            SerialNumber,
            ReleaseDate
}

$computerSystem = Invoke-AxiosOptional {
    Get-CimInstance Win32_ComputerSystem -ErrorAction Stop |
        Select-Object `
            Manufacturer,
            Model,
            SystemType,
            TotalPhysicalMemory
}

$bootState = Invoke-AxiosOptional {
    Get-ItemProperty `
        -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' `
        -ErrorAction Stop |
        Select-Object UEFISecureBootEnabled
}

$physicalDisks = Invoke-AxiosOptional {
    @(
        Get-CimInstance Win32_DiskDrive -ErrorAction Stop |
            Select-Object `
                Model,
                SerialNumber,
                InterfaceType,
                MediaType,
                Size,
                Status,
                FirmwareRevision |
            Select-Object -First $maxDisks
    )
}

[PSCustomObject]@{
    schema_version = 1
    collector = 'axios_hardware_trust'
    success = $true
    limits = @{
        max_physical_disks = $maxDisks
    }
    secure_boot = $secureBoot
    tpm = $tpm
    device_guard = $deviceGuard
    bitlocker = $bitLocker
    bios = $bios
    computer_system = $computerSystem
    boot_state = $bootState
    physical_disks = $physicalDisks
} | ConvertTo-Json -Depth 12 -Compress
"#;

        match powershell(script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "schema_version": 1,
                "collector": "axios_hardware_trust",
                "success": false,
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "schema_version": 1,
            "collector": "axios_hardware_trust",
            "success": false,
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_disk_limit_is_bounded() {
        assert_eq!(MAX_PHYSICAL_DISKS, 32);
    }
}
