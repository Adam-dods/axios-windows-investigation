# Console-only presentation. Evidence and machine-readable reports are unchanged.
function Write-AxiosConsoleTable {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)
    if ($Rows.Count -eq 0) { return }
    $width = 100
    try { $width = [Math]::Max(78, [Console]::WindowWidth - 1) } catch {}
    $text = $Rows | Format-Table -AutoSize -Wrap | Out-String -Width $width
    Write-Host $text.TrimEnd()
}

function Get-AxiosConsoleProperty {
    param([AllowNull()][object]$Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) {
        if ($Item.Contains($Name)) { return $Item[$Name] }
        return $null
    }
    $property = $Item.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-AxiosConsoleFirst {
    param([AllowNull()][object]$Item, [string[]]$Names, [string]$Default = '')
    foreach ($name in $Names) {
        $value = Get-AxiosConsoleProperty $Item $name
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) { return $value }
    }
    return $Default
}

function Get-AxiosConsoleNested {
    param([AllowNull()][object]$Item, [string[]]$Path)
    foreach ($name in $Path) { $Item = Get-AxiosConsoleProperty $Item $name }
    return $Item
}

function Get-AxiosConsolePriority {
    param([AllowNull()][object]$Item)
    return [string](Get-AxiosConsoleFirst $Item @('priority','severity','level') 'review')
}

function Get-AxiosConsoleObservationTitle {
    param([AllowNull()][object]$Item)
    foreach ($name in @('reason','description','message','title','label','finding','name','id','classification')) {
        $candidate = [string](Get-AxiosConsoleProperty $Item $name)
        $normalized = ($candidate -replace '_',' ' -replace '\s+',' ').Trim().ToLowerInvariant()
        if ($normalized -and $normalized -notin @('context','informational','information','observation')) {
            return $candidate
        }
    }
    $collector = [string](Get-AxiosConsoleProperty $Item 'collector')
    if ($collector -eq 'axios_audit_correlation') {
        return 'Artifact activity correlated across audit and runtime evidence'
    }
    if ($collector) { return ('Context from {0} (no description supplied)' -f $collector) }
    return 'Context record without a description'
}

function Get-AxiosConsoleFindingRows {
    param([object[]]$Findings)
    foreach ($finding in $Findings) {
        $source = Get-AxiosConsoleValue (Get-AxiosConsoleFirst $finding @('evidence_sources','evidence_source','source'))
        $details = @()
        foreach ($key in @('verification_state','status','path','observed_value','endpoint','service_name','process_id')) {
            $value = Get-AxiosConsoleProperty $finding $key
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                $details += ('{0}: {1}' -f ($key -replace '_',' '), (Get-AxiosConsoleValue $value))
            }
        }
        $evidence = Get-AxiosConsoleProperty $finding 'evidence'
        if ($null -ne $evidence) { $details += Get-AxiosConsoleValue $evidence }
        $reason = [string](Get-AxiosConsoleProperty $finding 'reason')
        if ($reason) { $details += $reason }
        if ($source) { $details += "Source: $source" }
        [pscustomobject]@{
            Level=(Get-AxiosConsolePriority $finding).ToUpperInvariant()
            Finding=([string](Get-AxiosConsoleFirst $finding @('title','label','finding','description','reason','id') 'Unlabelled finding') -replace '_',' ')
            Details=($details | Where-Object { $_ }) -join "`n"
        }
    }
}

function Get-AxiosConsoleValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return $(if ($Value) { 'Yes' } else { 'No' }) }
    if ($Value -is [string] -and $Value -match '^/Date\((-?\d+)(?:[+-]\d{4})?\)/$') {
        try {
            return ([datetime]::new(1970,1,1,0,0,0,[DateTimeKind]::Utc)).AddMilliseconds(
                [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
            ).ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
        } catch { return $Value }
    }
    if ($Value -is [string] -or $Value -is [ValueType]) { return [string]$Value }
    if ($Value -is [System.Collections.IDictionary]) {
        return (@($Value.GetEnumerator() | ForEach-Object {
            '{0}: {1}' -f ($_.Key -replace '_',' '), (Get-AxiosConsoleValue $_.Value)
        }) -join '; ')
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return (@($Value | ForEach-Object { Get-AxiosConsoleValue $_ }) -join ', ')
    }
    return (@($Value.PSObject.Properties | ForEach-Object {
        '{0}: {1}' -f ($_.Name -replace '_',' '), (Get-AxiosConsoleValue $_.Value)
    }) -join '; ')
}

function Format-AxiosConsoleEndpoint {
    param([string]$Address, [AllowNull()][object]$Port)
    if ($Address.Contains(':') -and -not $Address.StartsWith('[')) {
        $Address = '[{0}]' -f $Address
    }
    return ('{0}:{1}' -f $Address,$Port)
}

function Get-AxiosConsoleTcpRows {
    param([object]$Report, [object[]]$Connections)
    $processNames = @{}
    foreach ($process in @(Get-AxiosConsoleProperty $Report 'processes')) {
        if ($null -eq $process) { continue }
        $processId = [string](Get-AxiosConsoleProperty $process 'pid')
        $processName = [string](Get-AxiosConsoleProperty $process 'name')
        if ($processId -and $processName) { $processNames[$processId] = $processName }
    }
    foreach ($connection in $Connections) {
        if ($null -eq $connection) { continue }
        $processId = [string](Get-AxiosConsoleProperty $connection 'owning_process')
        $processLabel = if ($processId -and $processNames.ContainsKey($processId)) {
            '{0} ({1})' -f $processNames[$processId],$processId
        } elseif ($processId) {
            'PID {0} (name unavailable)' -f $processId
        } else { 'PID unavailable' }
        [pscustomobject]@{
            Local=Format-AxiosConsoleEndpoint `
                ([string](Get-AxiosConsoleProperty $connection 'local_address')) `
                (Get-AxiosConsoleProperty $connection 'local_port')
            Remote=Format-AxiosConsoleEndpoint `
                ([string](Get-AxiosConsoleProperty $connection 'remote_address')) `
                (Get-AxiosConsoleProperty $connection 'remote_port')
            State=Get-AxiosConsoleProperty $connection 'state'
            Process=$processLabel
        }
    }
}

function Get-AxiosConsoleNetworkObservationRows {
    param([object[]]$Observations)
    $groups = [ordered]@{}
    foreach ($item in $Observations) {
        if ($null -eq $item) { continue }
        $classification = [string](Get-AxiosConsoleProperty $item 'classification')
        if ($classification -eq 'wildcard_listener_observed') {
            $path = [string](Get-AxiosConsoleProperty $item 'process_path')
            $name = [string](Get-AxiosConsoleProperty $item 'process_name')
            $identity = if ($path) { $path } elseif ($name) { $name } else { 'name unavailable' }
            [pscustomobject]@{
                Observation='wildcard listener observed'
                Detail=('pid: {0}; process: {1}; local endpoint: {2}' -f
                    (Get-AxiosConsoleProperty $item 'pid'),$identity,
                    (Format-AxiosConsoleEndpoint `
                        ([string](Get-AxiosConsoleProperty $item 'local_address')) `
                        (Get-AxiosConsoleProperty $item 'local_port')))
            }
            continue
        }
        if ($classification -ne 'user_writable_process_public_connection_observed') {
            [pscustomobject]@{
                Observation=($classification -replace '_',' ')
                Detail=Get-AxiosConsoleValue $item
            }
            continue
        }
        $path = [string](Get-AxiosConsoleProperty $item 'process_path')
        $address = [string](Get-AxiosConsoleProperty $item 'remote_address')
        $port = [string](Get-AxiosConsoleProperty $item 'remote_port')
        $processId = [string](Get-AxiosConsoleProperty $item 'pid')
        $key = @($processId,$path,$address,$port) -join '|'
        if (-not $groups.Contains($key)) {
            $groups[$key] = [pscustomobject]@{
                Pid=$processId; Process=$path; Address=$address; Port=$port; Count=0
            }
        }
        $groups[$key].Count++
    }
    foreach ($group in $groups.Values) {
        [pscustomobject]@{
            Observation='user writable process public connection observed'
            Detail=('pid: {0}; process path: {1}; remote endpoint: {2}:{3}; connection count: {4}' -f
                $group.Pid,$group.Process,$group.Address,$group.Port,$group.Count)
        }
    }
}

function Write-AxiosTerminalLayer {
    param([object]$LayerResult, [System.Collections.IDictionary]$ReportData,
          [string]$SavedPath = '')
    $name = [string](Get-AxiosConsoleProperty $LayerResult 'layer')
    Write-Host ''
    Write-Host ('AXIOS {0}  {1}' -f $name.ToUpperInvariant(),
        ([string](Get-AxiosConsoleProperty $LayerResult 'collection_status')).ToUpperInvariant())
    Write-AxiosConsoleTable @(
        [pscustomobject]@{ Area='Reports'; Result=@(Get-AxiosConsoleProperty $LayerResult 'reports' | Where-Object { $null -ne $_ }).Count }
        [pscustomobject]@{ Area='Partial reports'; Result=(Get-AxiosConsoleNested $LayerResult @('summary','reports_partial')) }
        [pscustomobject]@{ Area='Failed reports'; Result=(Get-AxiosConsoleNested $LayerResult @('summary','reports_failed')) }
        [pscustomobject]@{ Area='Security findings'; Result=@(Get-AxiosConsoleProperty $LayerResult 'findings' | Where-Object { $null -ne $_ }).Count }
        [pscustomobject]@{ Area='Context observations'; Result=@(Get-AxiosConsoleProperty $LayerResult 'context_observations' | Where-Object { $null -ne $_ }).Count }
    )
    Write-Host 'ASSESSMENT COVERAGE'
    Write-AxiosConsoleTable @(Get-AxiosConsoleProperty $LayerResult 'reports' | Where-Object { $null -ne $_ } | ForEach-Object {
        [pscustomobject]@{
            Collector=[string](Get-AxiosConsoleProperty $_ 'command')
            Status=[string](Get-AxiosConsoleProperty $_ 'collection_status')
            Findings=(Get-AxiosConsoleProperty $_ 'findings')
            Context=(Get-AxiosConsoleProperty $_ 'context_observations')
            Errors=(Get-AxiosConsoleProperty $_ 'collection_errors')
        }
    })
    foreach ($entry in $ReportData.GetEnumerator()) {
        $report = $entry.Value
        if ($null -eq $report) { continue }
        $summary = Get-AxiosConsoleProperty $report 'summary'
        if ($null -eq $summary) { continue }
        $rows = @($summary.PSObject.Properties | Where-Object {
            $null -ne $_.Value -and ($_.Value -is [string] -or $_.Value -is [ValueType])
        } | ForEach-Object {
            [pscustomobject]@{ Measure=($_.Name -replace '_',' '); Observed=$_.Value }
        })
        if ($rows.Count -gt 0) {
            Write-Host (([string]$entry.Key -replace '-',' ').ToUpperInvariant())
            Write-AxiosConsoleTable $rows
        }
    }
    if ($name -eq 'Context' -and $null -ne $ReportData['context-posture']) {
        $context = $ReportData['context-posture']
        Write-Host 'TIME, LANGUAGE AND NETWORK CONTEXT'
        Write-AxiosConsoleTable @(
            [pscustomobject]@{ Setting='Local time'; Observed=(Get-AxiosConsoleNested $context @('time','local_time')) }
            [pscustomobject]@{ Setting='UTC time'; Observed=(Get-AxiosConsoleNested $context @('time','utc_time')) }
            [pscustomobject]@{ Setting='Time zone'; Observed=(Get-AxiosConsoleNested $context @('time','timezone','Id')) }
            [pscustomobject]@{ Setting='Synchronization'; Observed=(Get-AxiosConsoleNested $context @('time','synchronization_state')) }
            [pscustomobject]@{ Setting='Culture'; Observed=(Get-AxiosConsoleNested $context @('locale','culture','Name')) }
            [pscustomobject]@{ Setting='UI language'; Observed=(Get-AxiosConsoleNested $context @('locale','ui_culture','Name')) }
            [pscustomobject]@{ Setting='Public profiles'; Observed=(Get-AxiosConsoleNested $context @('network_context','public_profiles')) }
            [pscustomobject]@{ Setting='Private profiles'; Observed=(Get-AxiosConsoleNested $context @('network_context','private_profiles')) }
        )
    }
    $layerFindings = @(Get-AxiosConsoleProperty $LayerResult 'findings' | Where-Object { $null -ne $_ })
    if ($layerFindings.Count -gt 0) {
        Write-Host 'SECURITY FINDINGS'
        Write-AxiosConsoleTable @(Get-AxiosConsoleFindingRows $layerFindings)
    } else { Write-Host 'No security finding established within available visibility.' }
    $layerContext = @(Get-AxiosConsoleProperty $LayerResult 'context_observations' | Where-Object { $null -ne $_ })
    if ($layerContext.Count -gt 0) {
        Write-Host 'FORENSIC CONTEXT'
        Write-AxiosConsoleTable @($layerContext | ForEach-Object {
            [pscustomobject]@{
                Observation=Get-AxiosConsoleObservationTitle $_
                Evidence=(Get-AxiosConsoleValue (Get-AxiosConsoleProperty $_ 'evidence'))
            }
        })
    }
    $gaps = @(@(Get-AxiosConsoleProperty $LayerResult 'collection_errors') + @(
        Get-AxiosConsoleProperty $LayerResult 'reports' | Where-Object {
            (Get-AxiosConsoleProperty $_ 'success') -ne $true -or
            (Get-AxiosConsoleProperty $_ 'collection_status') -ne 'complete'
        } | ForEach-Object {
            '{0}: {1}' -f (Get-AxiosConsoleProperty $_ 'command'),(Get-AxiosConsoleProperty $_ 'collection_status')
        }) | Where-Object { $null -ne $_ -and [string]$_ -ne '' })
    if ($gaps.Count -gt 0) {
        Write-Host 'COLLECTION LIMITATIONS'
        Write-AxiosConsoleTable @($gaps | ForEach-Object { [pscustomobject]@{ Reason=[string]$_ } })
    }
    if ($SavedPath) { Write-Host ('Saved result: {0}' -f $SavedPath) }
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
        Write-AxiosConsoleTable @(Get-AxiosConsoleFindingRows $Findings)
    }
    if ($Context.Count -gt 0) {
        Write-Host 'FORENSIC CONTEXT'
        $rows = foreach ($item in $Context) {
            [pscustomobject]@{
                Observation = Get-AxiosConsoleObservationTitle $item
                Evidence = Get-AxiosConsoleValue (Get-AxiosConsoleProperty $item 'evidence')
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
            $id = [string](Get-AxiosConsoleProperty $_ 'id')
            $label = [string](Get-AxiosConsoleFirst $_ @('title') '')
            if (-not $label) {
                $label = $id -replace '^check\.', '' -replace '^[^.]+\.', '' -replace '_', ' '
            }
            [pscustomobject]@{
                Check = $label
                Detail = [string](Get-AxiosConsoleFirst $_ @('action','reason','description') 'No action supplied')
            }
        })
    }
    if ($SavedPath) { Write-Host ("Saved result: {0}" -f $SavedPath) }
}

function Write-AxiosTerminalUser {
    param([object]$Manifest, [object]$Network, [object]$Scope, [object]$Exposure,
          [string]$SavedPath = '')
    Write-Host ''
    Write-Host ("AXIOS USER  {0}" -f ([string](Get-AxiosConsoleProperty $Manifest 'collection_status')).ToUpperInvariant())
    Write-AxiosConsoleTable @(
        [pscustomobject]@{ Area = 'Collectors'; Status = 'Completed'; Result = (Get-AxiosConsoleNested $Manifest @('summary','reports_completed')) }
        [pscustomobject]@{ Area = 'Security findings'; Status = 'Observed'; Result = (Get-AxiosConsoleNested $Manifest @('summary','findings')) }
        [pscustomobject]@{ Area = 'Network posture'; Status = (Get-AxiosConsoleProperty $Network 'collection_status'); Result = 'Current-user visibility' }
        [pscustomobject]@{ Area = 'User access scope'; Status = (Get-AxiosConsoleProperty $Scope 'collection_status'); Result = 'Processes, startup and accessible tasks' }
        [pscustomobject]@{ Area = 'Exposure assessment'; Status = (Get-AxiosConsoleProperty $Exposure 'collection_status'); Result = 'Accessible service and task exposure' }
    )
    foreach ($section in @(
        [pscustomobject]@{ Name='USER EXECUTION SURFACE'; Report=$Scope },
        [pscustomobject]@{ Name='EXPOSURE COVERAGE'; Report=$Exposure }
    )) {
        $summary = Get-AxiosConsoleProperty $section.Report 'summary'
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
    $userFindings = @(Get-AxiosConsoleProperty $Manifest 'findings' | Where-Object { $null -ne $_ })
    if ($userFindings.Count -gt 0) {
        Write-Host 'SECURITY FINDINGS'
        Write-AxiosConsoleTable @(Get-AxiosConsoleFindingRows $userFindings)
    } else { Write-Host 'No security finding established within available visibility.' }
    $userGaps = @(
        @(Get-AxiosConsoleProperty $Manifest 'collection_gaps') +
        @(Get-AxiosConsoleProperty $Scope 'collection_errors') +
        @(Get-AxiosConsoleProperty $Exposure 'collection_errors') +
        @(Get-AxiosConsoleProperty $Network 'collection_errors') |
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
    $ipConfiguration = @(Get-AxiosConsoleProperty $Report 'ip_configuration')
    $firewallProfiles = @(Get-AxiosConsoleProperty $Report 'firewall_profiles')
    $tcpConnections = @(Get-AxiosConsoleProperty $Report 'tcp_connections')
    $targets = @(Get-AxiosConsoleProperty $Report 'active_target_results')
    $findings = @(Get-AxiosConsoleProperty $Report 'findings')
    $observations = @(Get-AxiosConsoleProperty $Report 'observations')
    $errors = @(Get-AxiosConsoleProperty $Report 'collection_errors')
    Write-Host ''
    Write-Host ("AXIOS NETWORK - {0}  {1}" -f $Focus.ToUpperInvariant(),
        ([string](Get-AxiosConsoleProperty $Report 'collection_status')).ToUpperInvariant())
    $rows = @(
        [pscustomobject]@{ Area='Findings'; Observed=@($findings | Where-Object { $null -ne $_ }).Count }
        [pscustomobject]@{ Area='Observations'; Observed=@($observations | Where-Object { $null -ne $_ }).Count }
        [pscustomobject]@{ Area='Collection errors'; Observed=@($errors | Where-Object { $null -ne $_ }).Count }
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
        $interfaces = @($ipConfiguration | Where-Object { $null -ne $_ } | ForEach-Object {
            [pscustomobject]@{
                Interface = [string](Get-AxiosConsoleProperty $_ 'interface_alias')
                Address = Get-AxiosConsoleValue (Get-AxiosConsoleProperty $_ 'ipv4_addresses')
                Gateway = Get-AxiosConsoleValue (Get-AxiosConsoleProperty $_ 'ipv4_gateways')
                DNS = Get-AxiosConsoleValue (Get-AxiosConsoleProperty $_ 'dns_servers')
            }
        })
        if ($interfaces.Count -gt 0) {
            Write-Host 'IP CONFIGURATION'
            Write-AxiosConsoleTable $interfaces
        }
        $wireless = Get-AxiosConsoleProperty $Report 'wireless'
        $wirelessRows = @(Get-AxiosConsoleProperty $wireless 'raw' | Where-Object { $null -ne $_ } | ForEach-Object {
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
    if ($Focus -in @('overview','firewall','full') -and @($firewallProfiles | Where-Object { $null -ne $_ }).Count -gt 0) {
        Write-Host 'FIREWALL PROFILES'
        Write-AxiosConsoleTable @($firewallProfiles | ForEach-Object {
            [pscustomobject]@{
                Profile=(Get-AxiosConsoleProperty $_ 'Name'); Enabled=(Get-AxiosConsoleProperty $_ 'Enabled');
                Inbound=(Get-AxiosConsoleProperty $_ 'DefaultInboundAction'); Outbound=(Get-AxiosConsoleProperty $_ 'DefaultOutboundAction')
            }
        })
    }
    if ($Focus -in @('connections','services')) {
        $connections = @($tcpConnections | Where-Object { $null -ne $_ })
        if ($Focus -eq 'services') {
            $connections = @($connections | Where-Object { (Get-AxiosConsoleProperty $_ 'state') -match '^(?i:listen|listening)$' })
        }
        if ($connections.Count -gt 0) {
            Write-Host 'TCP ENDPOINTS'
            Write-AxiosConsoleTable @(Get-AxiosConsoleTcpRows $Report $connections)
        }
    }
    if ($Focus -in @('connections','targeted','full') -and @($targets | Where-Object { $null -ne $_ }).Count -gt 0) {
        Write-Host 'EXPLICIT TARGET CHECKS'
        Write-AxiosConsoleTable @($targets | ForEach-Object {
            [pscustomobject]@{ Target=(Get-AxiosConsoleProperty $_ 'target'); Port=(Get-AxiosConsoleProperty $_ 'port');
                State=(Get-AxiosConsoleProperty $_ 'state'); Resolved=(Get-AxiosConsoleProperty $_ 'resolved_address') }
        })
    }
    if ($Focus -in @('dns','routing')) {
        foreach ($name in $(if ($Focus -eq 'dns') { @('ip_configuration','dns_cache') }
                         else { @('routes','neighbors') })) {
            $items = @(Get-AxiosConsoleProperty $Report $name | Where-Object { $null -ne $_ })
            if ($items.Count -gt 0) {
                Write-Host (($name -replace '_',' ').ToUpperInvariant())
                Write-AxiosConsoleTable @($items | ForEach-Object {
                    [pscustomobject]@{ Item=Get-AxiosConsoleValue $_ }
                })
            }
        }
    }
    if (@($findings | Where-Object { $null -ne $_ }).Count -gt 0) {
        Write-Host 'SECURITY FINDINGS'
        Write-AxiosConsoleTable @(Get-AxiosConsoleFindingRows $findings)
    } else { Write-Host 'No verified network finding within available visibility.' }
    if (@($observations | Where-Object { $null -ne $_ }).Count -gt 0) {
        Write-Host 'NETWORK OBSERVATIONS'
        Write-AxiosConsoleTable @(Get-AxiosConsoleNetworkObservationRows $observations)
    }
    if (@($errors | Where-Object { $null -ne $_ }).Count -gt 0) {
        Write-Host 'COLLECTION LIMITATIONS'
        Write-AxiosConsoleTable @($errors | ForEach-Object {
            [pscustomobject]@{ Reason=[string]$_ }
        })
    }
    if ($SavedPath) { Write-Host ("Saved result: {0}" -f $SavedPath) }
}
