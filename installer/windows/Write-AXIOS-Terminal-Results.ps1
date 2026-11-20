# Console-only presentation. Evidence and machine-readable reports are unchanged.
function Write-AxiosConsoleTable {
    param([Parameter(Mandatory)][object[]]$Rows)
    if ($Rows.Count -eq 0) { return }
    $width = 100
    try { $width = [Math]::Max(78, [Console]::WindowWidth - 1) } catch {}
    $text = $Rows | Format-Table -AutoSize -Wrap | Out-String -Width $width
    Write-Host $text.TrimEnd()
}

function Get-AxiosConsoleValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return $(if ($Value) { 'Yes' } else { 'No' }) }
    if ($Value -is [string] -or $Value -is [ValueType]) { return [string]$Value }
    if ($Value -is [System.Collections.IEnumerable]) {
        return (@($Value | ForEach-Object { Get-AxiosConsoleValue $_ }) -join ', ')
    }
    return (@($Value.PSObject.Properties | ForEach-Object {
        '{0}: {1}' -f ($_.Name -replace '_',' '), (Get-AxiosConsoleValue $_.Value)
    }) -join '; ')
}

function Write-AxiosTerminalResults {
    param(
        [Parameter(Mandatory)][object]$Summary,
        [object[]]$Findings = @(),
        [object[]]$Context = @(),
        [string[]]$Gaps = @(),
        [object[]]$Checks = @(),
        [string]$SavedPath = ''
    )
    Write-Host ''
    Write-Host 'AXIOS RESULTS'
    Write-AxiosConsoleTable @(
        [pscustomobject]@{ Metric = 'Status'; Result = $Summary.overall_status }
        [pscustomobject]@{ Metric = 'Confirmed threats'; Result = $Summary.confirmed_threats }
        [pscustomobject]@{ Metric = 'Important findings'; Result = $Findings.Count }
        [pscustomobject]@{ Metric = 'Context observations'; Result = $Context.Count }
        [pscustomobject]@{ Metric = 'Collection gaps'; Result = $Gaps.Count }
    )
    if ($Findings.Count -eq 0) {
        Write-Host 'No important finding established within available visibility.'
    } else {
        Write-Host 'SECURITY FINDINGS'
        $rows = foreach ($finding in $Findings) {
            $title = @($finding.title, $finding.label, $finding.finding, $finding.id) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                Select-Object -First 1
            $source = Get-AxiosConsoleValue $finding.evidence_sources
            if (-not $source) { $source = Get-AxiosConsoleValue $finding.evidence_source }
            $details = @()
            foreach ($key in @('verification_state','status','path','observed_value','endpoint','service_name','process_id')) {
                $property = $finding.PSObject.Properties[$key]
                if ($null -ne $property -and $null -ne $property.Value) {
                    $details += ('{0}: {1}' -f ($key -replace '_',' '), (Get-AxiosConsoleValue $property.Value))
                }
            }
            if ($null -ne $finding.PSObject.Properties['evidence']) {
                $details += Get-AxiosConsoleValue $finding.evidence
            }
            if ($source) { $details += "Source: $source" }
            $priority = [string]$finding.priority
            if (-not $priority) { $priority = [string]$finding.severity }
            if (-not $priority) { $priority = 'review' }
            [pscustomobject]@{
                Level = $priority.ToUpperInvariant()
                Finding = [string]$title
                Details = ($details | Where-Object { $_ }) -join "`n"
            }
        }
        Write-AxiosConsoleTable @($rows)
    }
    if ($Context.Count -gt 0) {
        Write-Host 'FORENSIC CONTEXT'
        $rows = foreach ($item in $Context) {
            [pscustomobject]@{
                Observation = [string](@($item.title,$item.finding,$item.classification) |
                    Where-Object { $_ } | Select-Object -First 1)
                Evidence = Get-AxiosConsoleValue $item.evidence
            }
        }
        Write-AxiosConsoleTable @($rows)
    }
    if ($Gaps.Count -gt 0) {
        Write-Host 'COLLECTION LIMITATIONS'
        Write-AxiosConsoleTable @($Gaps | ForEach-Object { [pscustomobject]@{ Reason = $_ } })
    }
    if ($Checks.Count -gt 0) {
        Write-Host 'NEXT CHECKS'
        Write-AxiosConsoleTable @($Checks | ForEach-Object {
            [pscustomobject]@{
                Check = [string](@($_.title,$_.id) | Where-Object { $_ } | Select-Object -First 1)
                Detail = Get-AxiosConsoleValue $_.reason
            }
        })
    }
    if ($SavedPath) { Write-Host ("Saved result: {0}" -f $SavedPath) }
}

function Write-AxiosTerminalUser {
    param([object]$Manifest, [object]$Network, [object]$Scope, [object]$Exposure,
          [string]$SavedPath = '')
    Write-Host ''
    Write-Host ("AXIOS USER  {0}" -f ([string]$Manifest.collection_status).ToUpperInvariant())
    Write-AxiosConsoleTable @(
        [pscustomobject]@{ Area = 'Collectors'; Status = 'Completed'; Result = $Manifest.summary.reports_completed }
        [pscustomobject]@{ Area = 'Security findings'; Status = 'Observed'; Result = $Manifest.summary.findings }
        [pscustomobject]@{ Area = 'Network posture'; Status = $Network.collection_status; Result = 'Current-user visibility' }
        [pscustomobject]@{ Area = 'User access scope'; Status = $Scope.collection_status; Result = 'Processes, startup and accessible tasks' }
        [pscustomobject]@{ Area = 'Exposure assessment'; Status = $Exposure.collection_status; Result = 'Accessible service and task exposure' }
    )
    foreach ($section in @(
        [pscustomobject]@{ Name='USER EXECUTION SURFACE'; Report=$Scope },
        [pscustomobject]@{ Name='EXPOSURE COVERAGE'; Report=$Exposure }
    )) {
        $summary = $section.Report.summary
        if ($null -eq $summary) { continue }
        $rows = @($summary.PSObject.Properties | Where-Object {
            $_.Name -notin @('success','collection_errors','response_actions') -and
            $null -ne $_.Value -and ($_.Value -is [string] -or $_.Value -is [ValueType])
        } | ForEach-Object {
            [pscustomobject]@{ Area=($_.Name -replace '_',' '); Observed=$_.Value }
        })
        if ($rows.Count -gt 0) {
            Write-Host $section.Name
            Write-AxiosConsoleTable $rows
        }
    }
    if (@($Manifest.findings).Count -gt 0) {
        Write-Host 'SECURITY FINDINGS'
        Write-AxiosConsoleTable @($Manifest.findings | ForEach-Object {
            [pscustomobject]@{
                Level = [string]$_.severity
                Finding = [string]$_.title
                Details = Get-AxiosConsoleValue $_.evidence
            }
        })
    } else { Write-Host 'No security finding established within available visibility.' }
    $userGaps = @(
        @($Manifest.collection_gaps) +
        @($Scope.collection_errors) +
        @($Exposure.collection_errors) +
        @($Network.collection_errors) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Select-Object -Unique
    )
    if ($userGaps.Count -gt 0) {
        Write-Host 'COLLECTION LIMITATIONS'
        Write-AxiosConsoleTable @($userGaps | ForEach-Object {
            [pscustomobject]@{ Reason = [string]$_ }
        })
    }
    if ($SavedPath) { Write-Host ("Saved result: {0}" -f $SavedPath) }
}

function Write-AxiosTerminalNetwork {
    param([object]$Report, [string]$Focus, [string]$SavedPath = '')
    Write-Host ''
    Write-Host ("AXIOS NETWORK · {0}  {1}" -f $Focus.ToUpperInvariant(),
        ([string]$Report.collection_status).ToUpperInvariant())
    $rows = @(
        [pscustomobject]@{ Area='Findings'; Observed=@($Report.findings).Count }
        [pscustomobject]@{ Area='Observations'; Observed=@($Report.observations).Count }
        [pscustomobject]@{ Area='Collection errors'; Observed=@($Report.collection_errors).Count }
    )
    foreach ($name in @('adapters','ip_configuration','firewall_profiles','tcp_connections',
                        'udp_endpoints','routes','neighbors','dns_cache','firewall_rules')) {
        $property = $Report.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value) {
            $count = @($property.Value | Where-Object { $null -ne $_ }).Count
            if ($count -gt 0) {
                $rows += [pscustomobject]@{ Area=($name -replace '_',' '); Observed=$count }
            }
        }
    }
    Write-AxiosConsoleTable $rows
    if ($Focus -in @('overview','wifi','full')) {
        $interfaces = @($Report.ip_configuration | ForEach-Object {
            [pscustomobject]@{
                Interface = [string]$_.interface_alias
                Address = Get-AxiosConsoleValue $_.ipv4_addresses
                Gateway = Get-AxiosConsoleValue $_.ipv4_gateways
                DNS = Get-AxiosConsoleValue $_.dns_servers
            }
        })
        if ($interfaces.Count -gt 0) {
            Write-Host 'IP CONFIGURATION'
            Write-AxiosConsoleTable $interfaces
        }
        $wirelessRows = @($Report.wireless.raw | ForEach-Object {
            $line = [string]$_
            if ($line -match '^\s*(SSID|Authentication|Authentification|Cipher|Chiffrement|Signal|RSSI|Band|Bande|Channel|Canal)\s*:\s*(.+)$') {
                [pscustomobject]@{ Wireless=$Matches[1]; Value=$Matches[2].Trim() }
            }
        })
        if ($wirelessRows.Count -gt 0) {
            Write-Host 'WIRELESS NETWORK'
            Write-AxiosConsoleTable $wirelessRows
        }
    }
    if ($Focus -in @('overview','firewall','full') -and @($Report.firewall_profiles).Count -gt 0) {
        Write-Host 'FIREWALL PROFILES'
        Write-AxiosConsoleTable @($Report.firewall_profiles | ForEach-Object {
            [pscustomobject]@{
                Profile=$_.Name; Enabled=$_.Enabled;
                Inbound=$_.DefaultInboundAction; Outbound=$_.DefaultOutboundAction
            }
        })
    }
    if ($Focus -in @('connections','services')) {
        $connections = @($Report.tcp_connections)
        if ($Focus -eq 'services') {
            $connections = @($connections | Where-Object { $_.state -match '^(?i:listen|listening)$' })
        }
        if ($connections.Count -gt 0) {
            Write-Host 'TCP ENDPOINTS'
            Write-AxiosConsoleTable @($connections | ForEach-Object {
                [pscustomobject]@{
                    Local=('{0}:{1}' -f $_.local_address,$_.local_port)
                    Remote=('{0}:{1}' -f $_.remote_address,$_.remote_port)
                    State=$_.state; Process=$_.pid
                }
            })
        }
    }
    if ($Focus -eq 'targeted' -and @($Report.active_target_results).Count -gt 0) {
        Write-Host 'EXPLICIT TARGET CHECKS'
        Write-AxiosConsoleTable @($Report.active_target_results | ForEach-Object {
            [pscustomobject]@{ Target=$_.target; Port=$_.port; State=$_.state;
                Resolved=$_.resolved_address }
        })
    }
    if ($Focus -in @('dns','routing')) {
        foreach ($name in $(if ($Focus -eq 'dns') { @('ip_configuration','dns_cache') }
                         else { @('routes','neighbors') })) {
            $items = @($Report.PSObject.Properties[$name].Value)
            if ($items.Count -gt 0) {
                Write-Host (($name -replace '_',' ').ToUpperInvariant())
                Write-AxiosConsoleTable @($items | ForEach-Object {
                    [pscustomobject]@{ Item=Get-AxiosConsoleValue $_ }
                })
            }
        }
    }
    if (@($Report.findings).Count -gt 0) {
        Write-Host 'SECURITY FINDINGS'
        Write-AxiosConsoleTable @($Report.findings | ForEach-Object {
            [pscustomobject]@{ Level=$_.priority; Finding=$_.title;
                Details=((Get-AxiosConsoleValue $_.evidence) + "`nSource: axios-network-deep-review") }
        })
    } else { Write-Host 'No verified network finding within available visibility.' }
    if (@($Report.observations).Count -gt 0) {
        Write-Host 'NETWORK OBSERVATIONS'
        Write-AxiosConsoleTable @($Report.observations | ForEach-Object {
            [pscustomobject]@{ Observation=([string]$_.classification -replace '_',' ');
                Detail=Get-AxiosConsoleValue $_ }
        })
    }
    if (@($Report.collection_errors).Count -gt 0) {
        Write-Host 'COLLECTION LIMITATIONS'
        Write-AxiosConsoleTable @($Report.collection_errors | ForEach-Object {
            [pscustomobject]@{ Reason=[string]$_ }
        })
    }
    if ($SavedPath) { Write-Host ("Saved result: {0}" -f $SavedPath) }
}
