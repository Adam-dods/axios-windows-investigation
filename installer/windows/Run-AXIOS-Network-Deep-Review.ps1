param(
    [ValidateSet(
        "auto",
        "standard",
        "administrator"
    )]
    [string]$Profile = "auto",

    [ValidateSet(
        "overview",
        "wifi",
        "connections",
        "services",
        "dns",
        "routing",
        "firewall",
        "targeted",
        "full"
    )]
    [string]$Focus = "full",

    [string[]]$Target = @(),

    [int[]]$Ports = @(),

    [ValidateRange(50, 10000)]
    [int]$TimeoutMs = 750,

    [string]$OutputDirectory = (
        Join-Path $env:USERPROFILE "Downloads"
    )
)

$ErrorActionPreference = "Stop"

$AxiosUtf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $AxiosUtf8
[Console]::OutputEncoding = $AxiosUtf8
$OutputEncoding = $AxiosUtf8

function Get-AxiosOptionalProperty {
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowNull()]
        [object]$DefaultValue = $null
    )

    if ($null -eq $Value) {
        return $DefaultValue
    }

    $Property = $Value.PSObject.Properties[$Name]

    if ($null -eq $Property) {
        return $DefaultValue
    }

    if ($null -eq $Property.Value) {
        return $DefaultValue
    }

    return $Property.Value
}

function Get-AxiosOptionalPath {
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string[]]$Names,

        [AllowNull()]
        [object]$DefaultValue = $null
    )

    $Current = $Value

    foreach ($Name in $Names) {
        $Current = Get-AxiosOptionalProperty `
            -Value $Current `
            -Name $Name `
            -DefaultValue $DefaultValue

        if ($null -eq $Current) {
            return $DefaultValue
        }
    }

    return $Current
}

$Root = Split-Path -Parent $PSScriptRoot
$Binary = Join-Path $Root "bin\axios-network-deep-review.exe"

if (-not (Test-Path -LiteralPath $Binary)) {
    throw "AXIOS network deep review binary was not found: $Binary"
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item `
        -ItemType Directory `
        -Path $OutputDirectory `
        -Force |
        Out-Null
}

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Output = Join-Path `
    $OutputDirectory `
    "AXIOS-Network-Deep-Review-$Stamp.json"

$Arguments = [System.Collections.Generic.List[string]]::new()
$Arguments.Add("--profile")
$Arguments.Add($Profile)
$Arguments.Add("--focus")
$Arguments.Add($Focus)
$Arguments.Add("--timeout-ms")
$Arguments.Add([string]$TimeoutMs)
$Arguments.Add("--output")
$Arguments.Add($Output)

foreach ($Item in $Target) {
    $Arguments.Add("--target")
    $Arguments.Add($Item)
}

if ($Ports.Count -gt 0) {
    $Arguments.Add("--ports")
    $Arguments.Add(($Ports -join ","))
}

& $Binary @Arguments
$ExitCode = $LASTEXITCODE

if ($ExitCode -ne 0) {
    throw "AXIOS network deep review failed with exit code ${ExitCode}."
}

if (-not (Test-Path -LiteralPath $Output)) {
    throw "AXIOS network deep review did not write its report."
}

$Report = Get-Content -Encoding UTF8 -LiteralPath $Output -Raw |
    ConvertFrom-Json

if ($Report.success -ne $true) {
    throw "AXIOS network deep review returned success=false."
}

$Size = (Get-Item -LiteralPath $Output).Length
if ($Size -gt 2500000) {
    throw "AXIOS network deep report exceeded 2500000 bytes: ${Size}"
}

$Collector = Get-AxiosOptionalProperty `
    -Value $Report `
    -Name "collector" `
    -DefaultValue "axios_network_deep_review"

$CollectionStatus = Get-AxiosOptionalProperty `
    -Value $Report `
    -Name "collection_status" `
    -DefaultValue "unknown"

$StatusCapabilities = @(
    Get-AxiosOptionalProperty `
        -Value $Report `
        -Name "capabilities" `
        -DefaultValue @()
)

$RequiredCapabilityUnavailable = @(
    $StatusCapabilities |
        Where-Object {
            $_.status -eq "failed" -or
            (
                $Focus -in @("firewall", "full") -and
                $_.name -eq "firewall_rules" -and
                $_.status -eq "not_attempted"
            )
        }
)

if (
    $CollectionStatus -eq "complete" -and
    $RequiredCapabilityUnavailable.Count -gt 0
) {
    $CollectionStatus = "partial"
}

$FindingItems = @(
    Get-AxiosOptionalProperty `
        -Value $Report `
        -Name "findings" `
        -DefaultValue @()
)

$ObservationItems = @(
    Get-AxiosOptionalProperty `
        -Value $Report `
        -Name "observations" `
        -DefaultValue @()
)

$ActiveChecks = Get-AxiosOptionalPath `
    -Value $Report `
    -Names @("summary", "active_checks_completed") `
    -DefaultValue 0

$ActiveOpenPorts = Get-AxiosOptionalPath `
    -Value $Report `
    -Names @("summary", "active_open_ports") `
    -DefaultValue 0

$CollectionErrors = @(
    Get-AxiosOptionalProperty `
        -Value $Report `
        -Name "collection_errors" `
        -DefaultValue @()
)

foreach ($UnavailableCapability in $RequiredCapabilityUnavailable) {
    $CapabilityName = [string](
        Get-AxiosOptionalProperty `
            -Value $UnavailableCapability `
            -Name "name" `
            -DefaultValue "required_capability"
    )

    $CapabilityState = [string](
        Get-AxiosOptionalProperty `
            -Value $UnavailableCapability `
            -Name "status" `
            -DefaultValue "unavailable"
    )

    $CapabilityReason = [string](
        Get-AxiosOptionalProperty `
            -Value $UnavailableCapability `
            -Name "reason" `
            -DefaultValue "required capability unavailable"
    )

    $CapabilityGap = "{0}: {1}; {2}" -f
        $CapabilityName,
        $CapabilityState,
        $CapabilityReason

    if ($CapabilityGap -notin $CollectionErrors) {
        $CollectionErrors += $CapabilityGap
    }
}

$Report |
    Add-Member `
        -NotePropertyName "collection_status" `
        -NotePropertyValue $CollectionStatus `
        -Force

$Report |
    Add-Member `
        -NotePropertyName "collection_errors" `
        -NotePropertyValue @($CollectionErrors) `
        -Force

[System.IO.File]::WriteAllText(
    $Output,
    ($Report | ConvertTo-Json -Depth 30),
    $AxiosUtf8
)

$Size = (Get-Item -LiteralPath $Output).Length

if ($Size -gt 2500000) {
    throw "AXIOS network deep report exceeded 2500000 bytes after normalization: ${Size}"
}

$DetailedReport = Join-Path `
    $OutputDirectory `
    "AXIOS-Network-Deep-Review-Details-$Stamp.txt"

[System.IO.File]::WriteAllText(
    $DetailedReport,
    ($Report | ConvertTo-Json -Depth 30),
    $AxiosUtf8
)

Write-Host ""
$NetworkHeading = "NETWORK SECURITY ASSESSMENT"
Write-Host $NetworkHeading
Write-Host ("=" * $NetworkHeading.Length)
Write-Host ("Status                 : {0}" -f $CollectionStatus)
Write-Host ("Profile                : {0}" -f $Profile)
Write-Host ("Focus                  : {0}" -f $Focus)
Write-Host ("Findings               : {0}" -f $FindingItems.Count)
Write-Host ("Observations           : {0}" -f $ObservationItems.Count)
Write-Host ("Collection errors      : {0}" -f $CollectionErrors.Count)
Write-Host ("Active checks          : {0}" -f $ActiveChecks)
Write-Host ("Open target ports      : {0}" -f $ActiveOpenPorts)

if ($Focus -in @("overview", "wifi", "full")) {
    $Adapters = @(
        Get-AxiosOptionalProperty `
            -Value $Report `
            -Name "adapters" `
            -DefaultValue @()
    )

    $IpConfigurations = @(
        Get-AxiosOptionalProperty `
            -Value $Report `
            -Name "ip_configuration" `
            -DefaultValue @()
    )

    $FirewallProfiles = @(
        Get-AxiosOptionalProperty `
            -Value $Report `
            -Name "firewall_profiles" `
            -DefaultValue @()
    )

    $Capabilities = @(
        Get-AxiosOptionalProperty `
            -Value $Report `
            -Name "capabilities" `
            -DefaultValue @()
    )

    $CollectedCapabilities = @(
        $Capabilities |
            Where-Object {
                $_.status -eq "collected"
            }
    )

    $NotRequestedCapabilities = @(
        $Capabilities |
            Where-Object {
                $_.status -eq "not_requested"
            }
    )

    Write-Host ""
    $NetworkHeading = "NETWORK ADAPTER INVENTORY"
Write-Host $NetworkHeading
Write-Host ("-" * $NetworkHeading.Length)
    Write-Host (
        "Active adapters        : {0}" -f
        $Adapters.Count
    )

    if ($Adapters.Count -eq 0) {
        Write-Host "No active adapter was returned."
    }
    else {
        foreach ($Adapter in $Adapters) {
            $AdapterName = Get-AxiosOptionalProperty `
                -Value $Adapter `
                -Name "Name" `
                -DefaultValue "unknown"

            $AdapterDescription = Get-AxiosOptionalProperty `
                -Value $Adapter `
                -Name "InterfaceDescription" `
                -DefaultValue "unknown"

            $AdapterStatus = Get-AxiosOptionalProperty `
                -Value $Adapter `
                -Name "Status" `
                -DefaultValue "unknown"

            $AdapterSpeed = Get-AxiosOptionalProperty `
                -Value $Adapter `
                -Name "LinkSpeed" `
                -DefaultValue "unknown"

            Write-Host (
                "Adapter                : {0}; {1}; status={2}; speed={3}" -f
                $AdapterName,
                $AdapterDescription,
                $AdapterStatus,
                $AdapterSpeed
            )
        }
    }

    Write-Host ""
    $NetworkHeading = "ADDRESSING AND DNS CONFIGURATION"
Write-Host $NetworkHeading
Write-Host ("-" * $NetworkHeading.Length)

    if ($IpConfigurations.Count -eq 0) {
        Write-Host "No IP configuration was returned."
    }
    else {
        foreach ($Configuration in $IpConfigurations) {
            $Alias = Get-AxiosOptionalProperty `
                -Value $Configuration `
                -Name "interface_alias" `
                -DefaultValue "unknown"

            $NetworkName = Get-AxiosOptionalProperty `
                -Value $Configuration `
                -Name "network_name" `
                -DefaultValue ""

            $Category = Get-AxiosOptionalProperty `
                -Value $Configuration `
                -Name "network_category" `
                -DefaultValue "unknown"

            $IPv4 = @(
                Get-AxiosOptionalProperty `
                    -Value $Configuration `
                    -Name "ipv4_addresses" `
                    -DefaultValue @()
            ) -join ","

            $Gateway = @(
                Get-AxiosOptionalProperty `
                    -Value $Configuration `
                    -Name "ipv4_gateways" `
                    -DefaultValue @()
            ) -join ","

            $Dns = @(
                Get-AxiosOptionalProperty `
                    -Value $Configuration `
                    -Name "dns_servers" `
                    -DefaultValue @()
            ) -join ","

            Write-Host (
                "Interface              : {0}; network={1}; category={2}" -f
                $Alias,
                $NetworkName,
                $Category
            )
            Write-Host (
                "  IPv4={0}; gateway={1}; DNS={2}" -f
                $IPv4,
                $Gateway,
                $Dns
            )
        }
    }

    Write-Host ""
    $NetworkHeading = "FIREWALL SECURITY PROFILE"
Write-Host $NetworkHeading
Write-Host ("-" * $NetworkHeading.Length)

    if ($FirewallProfiles.Count -eq 0) {
        Write-Host "No firewall profile was returned."
    }
    else {
        foreach ($FirewallProfile in $FirewallProfiles) {
            $FirewallName = Get-AxiosOptionalProperty `
                -Value $FirewallProfile `
                -Name "Name" `
                -DefaultValue "unknown"

            $FirewallEnabled = Get-AxiosOptionalProperty `
                -Value $FirewallProfile `
                -Name "Enabled" `
                -DefaultValue "unknown"

            $Inbound = Get-AxiosOptionalProperty `
                -Value $FirewallProfile `
                -Name "DefaultInboundAction" `
                -DefaultValue "unknown"

            $Outbound = Get-AxiosOptionalProperty `
                -Value $FirewallProfile `
                -Name "DefaultOutboundAction" `
                -DefaultValue "unknown"

            Write-Host (
                "Profile                : {0}; enabled={1}; inbound={2}; outbound={3}" -f
                $FirewallName,
                $FirewallEnabled,
                $Inbound,
                $Outbound
            )
        }
    }

    $Wireless = Get-AxiosOptionalProperty `
        -Value $Report `
        -Name "wireless"

    $WirelessRaw = @(
        Get-AxiosOptionalProperty `
            -Value $Wireless `
            -Name "raw" `
            -DefaultValue @()
    )

    $WirelessSummary = @(
        foreach ($WirelessLine in $WirelessRaw) {
            $Text = ([string]$WirelessLine).Trim()
            if ($Text -notmatch '^([^:]+?)\s*:\s*(.+?)\s*$') {
                continue
            }

            $Label = $Matches[1].Trim()
            $Value = $Matches[2].Trim()
            $Name = $null

            if ($Label -match '^(?:BSSID|Point d.acc.s)') {
                $Name = "Access point"
            }
            elseif ($Label -match '^SSID\b') {
                $Name = "SSID"
            }
            elseif ($Label -match '^(?:Signal)\b') {
                $Name = "Signal"
            }
            elseif ($Label -match '^RSSI\b') {
                $Name = "RSSI"
            }
            elseif ($Label -match '^(?:Authentication|Authentification)\b') {
                $Name = "Authentication"
            }
            elseif ($Label -match 'AKM') {
                $Name = "Connected AKM/cipher"
            }
            elseif ($Label -match '^(?:Cipher|Chiffrement)\b') {
                $Name = "Cipher"
            }
            elseif ($Label -match '^(?:Band|Bande)\b') {
                $Name = "Band"
            }
            elseif ($Label -match '^(?:Channel|Canal)\b') {
                $Name = "Channel"
            }

            if ($null -ne $Name) {
                "{0,-22}: {1}" -f $Name, $Value
            }
        }
    )

    Write-Host ""
    $NetworkHeading = "WIRELESS NETWORK PROFILE"
    Write-Host $NetworkHeading
    Write-Host ("-" * $NetworkHeading.Length)

    if ($WirelessSummary.Count -eq 0) {
        Write-Host "No concise wireless details were returned."
    }
    else {
        foreach ($WirelessLine in $WirelessSummary) {
            Write-Host ("- {0}" -f $WirelessLine)
        }
    }

    Write-Host ""
    $NetworkHeading = "NETWORK VISIBILITY"
Write-Host $NetworkHeading
Write-Host ("-" * $NetworkHeading.Length)
    Write-Host (
        "Capabilities collected : {0}" -f
        $CollectedCapabilities.Count
    )
    Write-Host (
        "Not requested          : {0}" -f
        $NotRequestedCapabilities.Count
    )

    if ($NotRequestedCapabilities.Count -gt 0) {
        Write-Host (
            "Not requested by view  : {0}" -f (
                (
                    $NotRequestedCapabilities |
                        ForEach-Object {
                            [string]$_.name
                        }
                ) -join ", "
            )
        )
    }

    if ($NotRequestedCapabilities.Count -gt 0) {
        Write-Host (
            "Interpretation         : zero counts may reflect capabilities not requested by this view"
        )
    }
    elseif ($CollectionErrors.Count -gt 0) {
        Write-Host (
            "Interpretation         : collection limitations are listed below"
        )
    }
}

if ($Focus -notin @("overview", "wifi")) {
    $TcpItems = @(
        Get-AxiosOptionalProperty -Value $Report -Name "tcp_connections" -DefaultValue @()
    )
    $UdpItems = @(
        Get-AxiosOptionalProperty -Value $Report -Name "udp_endpoints" -DefaultValue @()
    )
    $DnsItems = @(
        Get-AxiosOptionalProperty -Value $Report -Name "dns_cache" -DefaultValue @()
    )
    $RouteItems = @(
        Get-AxiosOptionalProperty -Value $Report -Name "routes" -DefaultValue @()
    )
    $NeighborItems = @(
        Get-AxiosOptionalProperty -Value $Report -Name "neighbors" -DefaultValue @()
    )
    $FirewallRuleItems = @(
        Get-AxiosOptionalProperty -Value $Report -Name "firewall_rules" -DefaultValue @()
    )
    $Capabilities = @(
        Get-AxiosOptionalProperty -Value $Report -Name "capabilities" -DefaultValue @()
    )
    $LimitedCapabilities = @(
        $Capabilities |
            Where-Object {
                $_.status -in @("failed", "not_attempted") -and
                (
                    $_.name -ne "raw_packet_capture" -or
                    $Focus -eq "full"
                )
            }
    )

    Write-Host ""
    $NetworkHeading = "OBSERVED NETWORK DATA"
Write-Host $NetworkHeading
Write-Host ("-" * $NetworkHeading.Length)
    Write-Host ("TCP connections        : {0}" -f $TcpItems.Count)
    Write-Host ("UDP endpoints          : {0}" -f $UdpItems.Count)
    Write-Host ("DNS cache entries      : {0}" -f $DnsItems.Count)
    Write-Host ("Routes                 : {0}" -f $RouteItems.Count)
    Write-Host ("Neighbors              : {0}" -f $NeighborItems.Count)
    $FirewallCapability = @(
        $Capabilities |
            Where-Object { $_.name -eq "firewall_rules" } |
            Select-Object -First 1
    )

    $FirewallRuleDisplay = if ($FirewallCapability.Count -eq 0) {
        "unknown (capability status unavailable)"
    }
    elseif ($FirewallCapability[0].status -eq "collected") {
        [string]$FirewallRuleItems.Count
    }
    elseif ($FirewallCapability[0].status -eq "partial") {
        "{0} (partial)" -f $FirewallRuleItems.Count
    }
    else {
        "not collected ({0})" -f $FirewallCapability[0].status
    }

    Write-Host ("Firewall rules         : {0}" -f $FirewallRuleDisplay)

    if ($ObservationItems.Count -gt 0) {
        Write-Host ""
        $NetworkHeading = "SECURITY-RELEVANT OBSERVATIONS"
Write-Host $NetworkHeading
Write-Host ("-" * $NetworkHeading.Length)
        foreach ($Observation in @($ObservationItems | Select-Object -First 10)) {
            $Classification = Get-AxiosOptionalProperty `
                -Value $Observation `
                -Name "classification" `
                -DefaultValue "observation"
            $Address = Get-AxiosOptionalProperty `
                -Value $Observation `
                -Name "local_address" `
                -DefaultValue ""
            if ([string]::IsNullOrWhiteSpace([string]$Address)) {
                $Address = Get-AxiosOptionalProperty `
                    -Value $Observation `
                    -Name "resolved_address" `
                    -DefaultValue ""
            }
            if ([string]::IsNullOrWhiteSpace([string]$Address)) {
                $Address = Get-AxiosOptionalProperty `
                    -Value $Observation `
                    -Name "target" `
                    -DefaultValue "unknown"
            }

            $Port = Get-AxiosOptionalProperty `
                -Value $Observation `
                -Name "local_port" `
                -DefaultValue ""
            if ([string]::IsNullOrWhiteSpace([string]$Port)) {
                $Port = Get-AxiosOptionalProperty `
                    -Value $Observation `
                    -Name "port" `
                    -DefaultValue "unknown"
            }

            $ObservationProcessId = Get-AxiosOptionalProperty `
                -Value $Observation `
                -Name "pid" `
                -DefaultValue ""

            $ObservationLine = "- {0}; endpoint={1}:{2}" -f `
                $Classification, $Address, $Port

            if (-not [string]::IsNullOrWhiteSpace([string]$ObservationProcessId)) {
                $ObservationLine += "; pid={0}" -f $ObservationProcessId
            }

            Write-Host $ObservationLine
        }
    }

    if ($LimitedCapabilities.Count -gt 0) {
        Write-Host ""
        $NetworkHeading = "VISIBILITY LIMITATIONS"
Write-Host $NetworkHeading
Write-Host ("-" * $NetworkHeading.Length)
        foreach ($Capability in $LimitedCapabilities) {
            Write-Host (
                "- {0}: {1}; {2}" -f
                $Capability.name,
                $Capability.status,
                $Capability.reason
            )
        }
    }
}

Write-Host ""
$NetworkHeading = "VERIFIED NETWORK FINDINGS"
Write-Host $NetworkHeading
Write-Host ("-" * $NetworkHeading.Length)
if ($FindingItems.Count -eq 0) {
    Write-Host "None reported by this bounded review."
}
else {
    foreach ($Finding in @($FindingItems | Select-Object -First 25)) {
        $Severity = Get-AxiosOptionalProperty -Value $Finding -Name "severity" -DefaultValue "review"
        $Title = Get-AxiosOptionalProperty -Value $Finding -Name "title" -DefaultValue (
            Get-AxiosOptionalProperty -Value $Finding -Name "id" -DefaultValue "unnamed finding"
        )
        Write-Host ("[{0}] {1}" -f ([string]$Severity).ToUpperInvariant(), $Title)
    }
}
Write-Host ""
$NetworkHeading = "COLLECTION LIMITATIONS"
Write-Host $NetworkHeading
Write-Host ("-" * $NetworkHeading.Length)
if ($CollectionErrors.Count -eq 0) {
    Write-Host "None."
}
else {
    foreach ($Item in $CollectionErrors) {
        Write-Host ("- {0}" -f $Item)
    }
}
if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
    Write-Host ""
    Write-Host ("Detailed TXT report    : {0}" -f $DetailedReport)
    Write-Host ("Structured JSON report : {0}" -f $Output)
    Write-Host ""
}

if ($env:AXIOS_CONSOLE_SESSION -ne "1") {
    [PSCustomObject]@{
        success = $true
        collector = [string]$Collector
        collection_status = [string]$CollectionStatus
        profile = $Profile
        focus = $Focus
        findings = $FindingItems.Count
        observations = $ObservationItems.Count
        collection_errors = $CollectionErrors.Count
        active_checks = [int]$ActiveChecks
        active_open_ports = [int]$ActiveOpenPorts
        output = $Output
        detailed_report = $DetailedReport
        size_bytes = $Size
    } | ConvertTo-Json -Depth 5 -Compress
}
