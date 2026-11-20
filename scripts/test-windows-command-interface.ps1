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
    Set-StrictMode -Version 2.0
    $priorityOnly = [pscustomobject]@{ priority='high'; title='User exposure' }
    $severityOnly = [pscustomobject]@{ severity='medium'; title='Control review' }
    if ((Get-AxiosConsolePriority $priorityOnly) -ne 'high' -or
        (Get-AxiosConsolePriority $severityOnly) -ne 'medium') {
        throw 'Developer findings require optional priority and severity support.'
    }
    $exposureSource = Get-Content -LiteralPath (Join-Path $root 'installer\windows\Run-AXIOS-Developer-Exposure-View.ps1') -Raw
    if ($exposureSource -match '\$_\.severity') {
        throw 'Developer exposure accesses optional severity directly under StrictMode.'
    }
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
    # Real collectors do not all emit the same optional finding fields.
    $nextChecksOutput = Write-AxiosTerminalResults `
        -Summary ([pscustomobject]@{ overall_status='completed'; confirmed_threats=0 }) `
        -Findings @([pscustomobject]@{ title='Observed configuration'; priority='medium' }) `
        -Context @([pscustomobject]@{ id='context-only' }) `
        -Checks @([pscustomobject]@{
            id='check.security.defender_user_writable_exclusion_requires_review';
            action='Review exact excluded path'
        }) 6>&1 | Out-String
    if ($nextChecksOutput -notmatch 'Review exact excluded path' -or
        $nextChecksOutput -match 'check.security.defender_user_writable') {
        throw 'Next checks did not display the actionable text.'
    }
    Write-AxiosTerminalUser `
        -Manifest ([pscustomobject]@{
            collection_status='partial'; findings=@([pscustomobject]@{ title='Exposure review'; evidence='Observed' });
            collection_gaps=@(); summary=[pscustomobject]@{ reports_completed=3; findings=1 }
        }) `
        -Network ([pscustomobject]@{ collection_status='partial'; collection_errors=@() }) `
        -Scope ([pscustomobject]@{ collection_status='complete'; collection_errors=@(); summary=[pscustomobject]@{} }) `
        -Exposure ([pscustomobject]@{ collection_status='complete'; collection_errors=@(); summary=[pscustomobject]@{} })
    Write-AxiosTerminalLayer `
        -LayerResult ([pscustomobject]@{
            layer='Persistence'; collection_status='complete'; reports=@();
            findings=@([pscustomobject]@{ title='Autostart review' });
            context_observations=@([pscustomobject]@{ id='startup-context' });
            collection_errors=@(); summary=[pscustomobject]@{ reports_partial=0; reports_failed=0 }
        }) -ReportData ([ordered]@{})

    $tokens = $null
    $errors = $null
    $complete = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $root 'installer\windows\Run-AXIOS-Complete-Investigation.ps1'),
        [ref]$tokens, [ref]$errors
    )
    $progressFunction = @($complete.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Write-AxiosProgress'
    }, $true))[0]
    . ([scriptblock]::Create($progressFunction.ToString()))
    $progressText = Write-AxiosProgress -Stage 8 -Name 'AXIOS hardware trust' 6>&1 | Out-String
    if ($progressText -notmatch '8/42' -or $progressText -notmatch '\[[#-]+\]') {
        throw 'Inline Administrator progress did not render a stage and bar.'
    }
}
finally {
    Remove-Item -LiteralPath $package -Recurse -Force -ErrorAction SilentlyContinue
}
