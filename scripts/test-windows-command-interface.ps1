$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

foreach ($script in @(Get-ChildItem -LiteralPath (Join-Path $root 'installer\windows') -Filter '*.ps1')) {
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $script.FullName, [ref]$tokens, [ref]$errors
    )
    if (@($errors).Count -gt 0) {
        throw ('Invalid PowerShell: {0}: {1}' -f $script.Name, ($errors -join '; '))
    }
}

$package = Join-Path $env:TEMP ('AXIOS-Help-Test-' + [guid]::NewGuid().ToString('N'))
try {
    $null = New-Item -ItemType Directory -Path (Join-Path $package 'scripts') -Force
    Copy-Item (Join-Path $root 'installer\windows\axios.cmd') $package
    Copy-Item (Join-Path $root 'installer\windows\axios.ps1') $package
    Copy-Item (Join-Path $root 'installer\windows\Run-AXIOS.ps1') (Join-Path $package 'scripts')

    $cmdHelp = & (Join-Path $package 'axios.cmd') -Mode Help | Out-String
    if ($LASTEXITCODE -ne 0 -or $cmdHelp -notmatch 'MAIN COMMANDS') {
        throw 'CMD Help failed.'
    }
    $psHelp = & (Join-Path $package 'axios.ps1') -Mode Help | Out-String
    if ($psHelp -notmatch 'MAIN COMMANDS') {
        throw 'PowerShell Help failed.'
    }
    if ($cmdHelp -notmatch 'Focus SystemQuick' -or $psHelp -notmatch 'Focus SystemQuick') {
        throw 'Focused User commands are missing from Help.'
    }

    . (Join-Path $root 'installer\windows\Write-AXIOS-Terminal-Results.ps1')
    Write-AxiosTerminalResults `
        -Summary ([ordered]@{ overall_status='partial'; confirmed_threats=0 }) `
        -Findings @([pscustomobject]@{
            priority='medium'; title='Example configuration review';
            evidence_sources=@('example-collector');
            evidence=[pscustomobject]@{ setting='observed'; value='enabled' }
        }) `
        -Context @() -Gaps @('Example source unavailable')
    Write-AxiosTerminalNetwork `
        -Report ([pscustomobject]@{
            collection_status='complete'; findings=@(); observations=@();
            collection_errors=@(); adapters=@(); routes=@(); neighbors=@();
            tcp_connections=@(); udp_endpoints=@(); dns_cache=@();
            firewall_rules=@(); firewall_profiles=@();
            ip_configuration=@([pscustomobject]@{
                interface_alias='Test'; ipv4_addresses=@('127.0.0.1');
                ipv4_gateways=@(); dns_servers=@()
            }); wireless=$null
        }) -Focus overview
    Write-AxiosTerminalUser `
        -Manifest ([pscustomobject]@{
            collection_status='complete'; findings=@(); collection_gaps=@();
            summary=[pscustomobject]@{ reports_completed=4; findings=0 }
        }) `
        -Network ([pscustomobject]@{ collection_status='complete' }) `
        -Scope ([pscustomobject]@{ collection_status='complete'; summary=[pscustomobject]@{ user_autoruns=0 } }) `
        -Exposure ([pscustomobject]@{ collection_status='complete'; summary=[pscustomobject]@{ services=0 } })
    Write-AxiosTerminalLayer `
        -LayerResult ([pscustomobject]@{
            layer='Software'; collection_status='partial';
            reports=@([pscustomobject]@{
                command='updates'; success=$true; collection_status='partial';
                findings=0; context_observations=0; collection_errors=1
            }); findings=@(); context_observations=@(); collection_errors=@('Date unavailable');
            summary=[pscustomobject]@{ reports_partial=1; reports_failed=0 }
        }) `
        -ReportData ([ordered]@{
            updates=[pscustomobject]@{ summary=[pscustomobject]@{ pending_software_update_count=2 } }
        })
    Write-AxiosTerminalLayer `
        -LayerResult ([pscustomobject]@{
            layer='Context'; collection_status='complete'; reports=@(); findings=@();
            context_observations=@(); collection_errors=@();
            summary=[pscustomobject]@{ reports_partial=0; reports_failed=0 }
        }) `
        -ReportData ([ordered]@{
            'context-posture'=[pscustomobject]@{
                time=[pscustomobject]@{ local_time='today'; utc_time='today'; synchronization_state='unknown'; timezone=[pscustomobject]@{ Id='UTC' } };
                locale=[pscustomobject]@{ culture=[pscustomobject]@{ Name='en-US' }; ui_culture=[pscustomobject]@{ Name='en-US' } };
                network_context=[pscustomobject]@{ public_profiles=0; private_profiles=1 }
            }
        })
}
finally {
    Remove-Item -LiteralPath $package -Recurse -Force -ErrorAction SilentlyContinue
}
