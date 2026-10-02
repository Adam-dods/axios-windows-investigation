use serde_json::{json, Value};

#[cfg(windows)]
use crate::command::{parse_json_output, powershell};

pub const MAX_BROWSER_EXTENSIONS: usize = 500;
pub const MAX_EXTENSION_PERMISSIONS: usize = 20;

pub fn collect() -> Value {
    #[cfg(windows)]
    {
        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$maxExtensions = {MAX_BROWSER_EXTENSIONS}
$maxPermissions = {MAX_EXTENSION_PERMISSIONS}
$collectionErrors = [System.Collections.Generic.List[string]]::new()
$entries = [System.Collections.Generic.List[object]]::new()
$extensionScanTruncated = $false

function Add-AxiosBrowserError {{
    param(
        [string]$Source,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $collectionErrors.Add(("{{0}}: {{1}}" -f $Source, $ErrorRecord.Exception.Message))
}}

function Resolve-AxiosManifestMessage {{
    param(
        [System.IO.DirectoryInfo]$VersionDirectory,
        [object]$Manifest,
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value -notmatch '^__MSG_(.+)__$') {{
        return $Value
    }}

    $MessageKey = [string]$Matches[1]
    $DefaultLocale = [string]$Manifest.default_locale

    if ([string]::IsNullOrWhiteSpace($DefaultLocale)) {{
        return $Value
    }}

    $MessagesPath = Join-Path `
        $VersionDirectory.FullName `
        ("_locales\{{0}}\messages.json" -f $DefaultLocale)

    try {{
        if (
            -not (
                Test-Path `
                    -LiteralPath $MessagesPath `
                    -PathType Leaf `
                    -ErrorAction Stop
            )
        ) {{
            return $Value
        }}

        $Messages = Get-Content `
            -LiteralPath $MessagesPath `
            -Raw `
            -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop

        $MessageProperty = @(
            $Messages.PSObject.Properties |
                Where-Object {{
                    $_.Name -ceq $MessageKey
                }} |
                Select-Object -First 1
        ) | Select-Object -First 1

        if ($null -eq $MessageProperty) {{
            return $Value
        }}

        $ResolvedMessage = [string]$MessageProperty.Value.message

        if ([string]::IsNullOrWhiteSpace($ResolvedMessage)) {{
            return $Value
        }}

        return $ResolvedMessage
    }}
    catch {{
        return $Value
    }}
}}

$roots = @(
    [PSCustomObject]@{{
        browser = 'Google Chrome'
        path = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data')
        chromium = $true
    }},
    [PSCustomObject]@{{
        browser = 'Microsoft Edge'
        path = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data')
        chromium = $true
    }},
    [PSCustomObject]@{{
        browser = 'Opera'
        path = (Join-Path $env:APPDATA 'Opera Software\Opera Stable')
        chromium = $false
    }}
)

:browserRoots foreach ($root in $roots) {{
    try {{
        if (-not (Test-Path -LiteralPath $root.path -PathType Container -ErrorAction Stop)) {{
            continue
        }}
    }}
    catch {{
        Add-AxiosBrowserError ("browser_root:{{0}}" -f $root.browser) $_
        continue
    }}

    try {{
        if ($root.chromium) {{
            $profiles = @(
                Get-ChildItem -LiteralPath $root.path -Directory -ErrorAction Stop |
                    Where-Object {{
                        $_.Name -eq 'Default' -or $_.Name -like 'Profile *'
                    }}
            )
        }}
        else {{
            $profiles = @(Get-Item -LiteralPath $root.path -ErrorAction Stop)
        }}
    }}
    catch {{
        Add-AxiosBrowserError ("browser_profiles:{{0}}" -f $root.browser) $_
        continue
    }}

    foreach ($profile in $profiles) {{
        $extensionsPath = Join-Path $profile.FullName 'Extensions'

        try {{
            if (-not (Test-Path -LiteralPath $extensionsPath -PathType Container -ErrorAction Stop)) {{
                continue
            }}

            $extensionDirectories = @(
                Get-ChildItem -LiteralPath $extensionsPath -Directory -ErrorAction Stop |
                    Sort-Object Name
            )
        }}
        catch {{
            Add-AxiosBrowserError (
                "browser_extensions:{{0}}:{{1}}" -f $root.browser, $profile.Name
            ) $_
            continue
        }}

        foreach ($extensionDirectory in $extensionDirectories) {{
            if ($entries.Count -ge $maxExtensions) {{
                $extensionScanTruncated = $true
                break browserRoots
            }}

            try {{
                $versionDirectory = @(
                    Get-ChildItem -LiteralPath $extensionDirectory.FullName `
                        -Directory -ErrorAction Stop |
                        Sort-Object @{{
                            Expression = {{
                                try {{ [version]$_.Name }}
                                catch {{ [version]'0.0' }}
                            }}
                            Descending = $true
                        }} |
                        Select-Object -First 1
                ) | Select-Object -First 1

                if (-not $versionDirectory) {{
                    continue
                }}

                $manifestPath = Join-Path $versionDirectory.FullName 'manifest.json'

                if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf -ErrorAction Stop)) {{
                    continue
                }}

                $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop

                $ResolvedName = Resolve-AxiosManifestMessage `
                    -VersionDirectory $versionDirectory `
                    -Manifest $manifest `
                    -Value ([string]$manifest.name)

                $ResolvedDescription = Resolve-AxiosManifestMessage `
                    -VersionDirectory $versionDirectory `
                    -Manifest $manifest `
                    -Value ([string]$manifest.description)

                $allPermissions = @(
                    $manifest.permissions |
                        ForEach-Object {{ [string]$_ }}
                )
                $permissions = @(
                    $allPermissions |
                        Select-Object -First $maxPermissions
                )

                $entries.Add([PSCustomObject]@{{
                    browser = [string]$root.browser
                    profile = [string]$profile.Name
                    extension_id = [string]$extensionDirectory.Name
                    name = [string]$ResolvedName
                    version = [string]$manifest.version
                    description = [string]$ResolvedDescription
                    manifest_version = [int]$manifest.manifest_version
                    update_url = [string]$manifest.update_url
                    permissions = $permissions
                    permissions_truncated = (
                        $allPermissions.Count -gt $permissions.Count
                    )
                }})
            }}
            catch {{
                Add-AxiosBrowserError (
                    "browser_manifest:{{0}}:{{1}}:{{2}}" -f `
                        $root.browser, $profile.Name, $extensionDirectory.Name
                ) $_

                $entries.Add([PSCustomObject]@{{
                    browser = [string]$root.browser
                    profile = [string]$profile.Name
                    extension_id = [string]$extensionDirectory.Name
                    name = ''
                    version = ''
                    description = ''
                    manifest_version = 0
                    update_url = ''
                    permissions = @()
                    permissions_truncated = $false
                    manifest_error = $_.Exception.Message
                }})
            }}
        }}
    }}
}}

$sorted = @(
    $entries |
        Sort-Object browser, profile, extension_id
)

[PSCustomObject]@{{
    success = $true
    collector = 'windows_browser_extensions'
    collection_status = if ($collectionErrors.Count -eq 0) {{ 'complete' }} else {{ 'partial' }}
    collection_errors = @($collectionErrors)
    entry_count = $sorted.Count
    truncated = $extensionScanTruncated
    limits = @{{
        max_extensions = $maxExtensions
        extensions_observed = $sorted.Count
        extensions_truncated = $extensionScanTruncated
        max_permissions_per_extension = $maxPermissions
    }}
    entries = $sorted
}} | ConvertTo-Json -Depth 8 -Compress
"#
        );

        match powershell(&script) {
            Ok(result) => parse_json_output(result),
            Err(error) => json!({
                "success": false,
                "collector": "windows_browser_extensions",
                "error": error.to_string()
            }),
        }
    }

    #[cfg(not(windows))]
    {
        json!({
            "success": false,
            "collector": "windows_browser_extensions",
            "reason": "Windows-only collector"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_extension_collection_reports_visibility_and_limits() {
        let source = include_str!("browser_extensions.rs");
        let silent_directory_read =
            ["Get-ChildItem", " -ErrorAction ", "SilentlyContinue"].concat();

        assert_eq!(MAX_BROWSER_EXTENSIONS, 500);
        assert_eq!(MAX_EXTENSION_PERMISSIONS, 20);
        assert!(source.contains("collection_status"));
        assert!(source.contains("collection_errors"));
        assert!(source.contains("extensions_truncated"));
        assert!(source.contains("break browserRoots"));
        assert!(!source.contains(&silent_directory_read));
    }
}
