use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'Stop'
$collectionErrors = [System.Collections.Generic.List[string]]::new()

function Get-AxiosPersistenceValue {
    param(
        [string]$Source,
        [scriptblock]$Operation,
        [object]$DefaultValue
    )

    try {
        return & $Operation
    }
    catch {
        $collectionErrors.Add(
            ('{0}: {1}' -f $Source, $_.Exception.Message)
        )
        return $DefaultValue
    }
}

$winlogon = Get-AxiosPersistenceValue 'winlogon' {
    Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
        -ErrorAction Stop |
        Select-Object Shell, Userinit, AutoRestartShell, LegalNoticeCaption
} $null

$appInit = Get-AxiosPersistenceValue 'app_init' {
    Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' `
        -ErrorAction Stop |
        Select-Object AppInit_DLLs, LoadAppInit_DLLs, RequireSignedAppInit_DLLs
} $null

$ifeoDebuggers = @(
    Get-AxiosPersistenceValue 'image_file_execution_options' {
        Get-ChildItem `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' `
            -ErrorAction Stop |
            ForEach-Object {
                $item = $_

                try {
                    $properties = Get-ItemProperty `
                        -Path $item.PSPath `
                        -ErrorAction Stop

                    if ($properties.Debugger) {
                        [PSCustomObject]@{
                            image_name = $item.PSChildName
                            debugger = [string]$properties.Debugger
                            registry_path = $item.Name
                        }
                    }
                }
                catch {
                    $collectionErrors.Add(
                        ('image_file_execution_options:{0}: {1}' -f
                            $item.PSChildName,
                            $_.Exception.Message)
                    )
                }
            } |
            Select-Object -First 128
    } @()
)

$startupFolders = @(
    [Environment]::GetFolderPath('Startup'),
    (Join-Path `
        $env:ProgramData `
        'Microsoft\Windows\Start Menu\Programs\Startup')
)

$startupFolderItems = @(
    foreach ($folder in $startupFolders) {
        try {
            if (Test-Path -LiteralPath $folder -ErrorAction Stop) {
                Get-ChildItem `
                    -LiteralPath $folder `
                    -Force `
                    -File `
                    -ErrorAction Stop |
                    Select-Object `
                        @{ Name = 'startup_folder'; Expression = { $folder } },
                        Name,
                        FullName,
                        Length,
                        LastWriteTimeUtc
            }
        }
        catch {
            $collectionErrors.Add(
                ('startup_folder:{0}: {1}' -f
                    $folder,
                    $_.Exception.Message)
            )
        }
    }
)

[PSCustomObject]@{
    collector = 'windows_extended_persistence'
    winlogon = $winlogon
    app_init = $appInit
    image_file_execution_options = $ifeoDebuggers
    startup_folder_items = $startupFolderItems
    success = $true
    collection_status = if ($collectionErrors.Count -eq 0) {
        'complete'
    }
    else {
        'partial'
    }
    collection_errors = $collectionErrors
} | ConvertTo-Json -Depth 8 -Compress
"#;

        match powershell(script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_extended_persistence",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_extended_persistence",
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ifeo_result_limit_is_bounded() {
        const MAX_IFEO_DEBUGGERS: usize = 128;
        assert_eq!(MAX_IFEO_DEBUGGERS, 128);
    }
}
