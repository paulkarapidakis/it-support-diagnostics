[CmdletBinding()]
param(
    [string]$JsonPath,
    [string]$HtmlPath,
    [switch]$SummaryOnly,
    [switch]$SkipSecurityChecks,
    [double]$DiskWarningFreePercent = 15,
    [double]$DiskCriticalFreePercent = 5,
    [double]$MemoryWarningUsedPercent = 85,
    [double]$MemoryCriticalUsedPercent = 95,
    [double]$UptimeWarningDays = 30,
    [double]$LatencyWarningMs = 100,
    [double]$LatencyCriticalMs = 250
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-CheckResult {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('OK','INFO','WARNING','CRITICAL')][string]$Severity,
        [Parameter(Mandatory)][string]$Summary,
        [string]$Category = 'general',
        [hashtable]$Details = @{},
        [string]$Recommendation = ''
    )

    [pscustomobject]@{
        Name = $Name
        Severity = $Severity
        Summary = $Summary
        Category = $Category
        Details = $Details
        Recommendation = $Recommendation
    }
}

function Get-SeverityRank {
    param([string]$Severity)
    switch ($Severity) {
        'OK' { 0 }
        'INFO' { 1 }
        'WARNING' { 2 }
        'CRITICAL' { 3 }
        default { 0 }
    }
}

function Get-OverallSeverity {
    param([array]$Checks)
    if (-not $Checks -or $Checks.Count -eq 0) { return 'OK' }

    $highest = $Checks | ForEach-Object {
        [pscustomobject]@{ Severity = $_.Severity; Rank = Get-SeverityRank $_.Severity }
    } | Sort-Object Rank -Descending | Select-Object -First 1

    return $highest.Severity
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-SystemChecks {

    try {
        $os = Get-CimInstance Win32_OperatingSystem
        New-CheckResult -Name 'Operating System' -Severity 'OK' -Category 'system' `
            -Summary "$($os.Caption) | $($os.OSArchitecture) | Build $($os.BuildNumber)" `
            -Details @{ Caption=$os.Caption; Version=$os.Version; BuildNumber=$os.BuildNumber; Architecture=$os.OSArchitecture }
    } catch {
        New-CheckResult -Name 'Operating System' -Severity 'INFO' -Category 'system' -Summary "Unable to read OS information: $($_.Exception.Message)"
    }

    try {
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        New-CheckResult -Name 'CPU' -Severity 'OK' -Category 'system' `
            -Summary "$($cpu.Name) | $($cpu.NumberOfLogicalProcessors) logical processors" `
            -Details @{ Name=$cpu.Name; LogicalProcessors=$cpu.NumberOfLogicalProcessors }
    } catch {
        New-CheckResult -Name 'CPU' -Severity 'INFO' -Category 'system' -Summary 'Unable to read CPU information.'
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $totalKb = [double]$os.TotalVisibleMemorySize
        $freeKb = [double]$os.FreePhysicalMemory
        $usedKb = $totalKb - $freeKb
        $usedPct = if ($totalKb -gt 0) { ($usedKb / $totalKb) * 100 } else { 0 }

        if ($usedPct -ge $MemoryCriticalUsedPercent) {
            $sev='CRITICAL'; $rec='Close memory-intensive applications and investigate sustained memory pressure.'
        } elseif ($usedPct -ge $MemoryWarningUsedPercent) {
            $sev='WARNING'; $rec='Review high-memory processes if usage remains elevated.'
        } else { $sev='OK'; $rec='' }

        New-CheckResult -Name 'Memory' -Severity $sev -Category 'system' `
            -Summary ('{0:N1} GB used of {1:N1} GB ({2:N1}%)' -f ($usedKb/1MB), ($totalKb/1MB), $usedPct) `
            -Details @{ UsedPercent=[math]::Round($usedPct,1); TotalKB=[math]::Round($totalKb); FreeKB=[math]::Round($freeKb) } `
            -Recommendation $rec
    } catch {
        New-CheckResult -Name 'Memory' -Severity 'INFO' -Category 'system' -Summary 'Unable to read memory information.'
    }

    try {
        foreach ($drive in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
            if (-not $drive.Size) { continue }
            $freePct = ([double]$drive.FreeSpace / [double]$drive.Size) * 100
            if ($freePct -lt $DiskCriticalFreePercent) {
                $sev='CRITICAL'; $rec='Free disk space immediately; low storage can affect updates and application stability.'
            } elseif ($freePct -lt $DiskWarningFreePercent) {
                $sev='WARNING'; $rec='Review temporary files, downloads, logs, and large user files.'
            } else { $sev='OK'; $rec='' }

            New-CheckResult -Name "Disk $($drive.DeviceID)" -Severity $sev -Category 'system' `
                -Summary ('{0:N1} GB free of {1:N1} GB ({2:N1}% free)' -f ($drive.FreeSpace/1GB), ($drive.Size/1GB), $freePct) `
                -Details @{ DeviceID=$drive.DeviceID; SizeBytes=[int64]$drive.Size; FreeBytes=[int64]$drive.FreeSpace; FreePercent=[math]::Round($freePct,1) } `
                -Recommendation $rec
        }
    } catch {
        New-CheckResult -Name 'Disks' -Severity 'INFO' -Category 'system' -Summary 'Unable to read disk information.'
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $days = ((Get-Date) - $os.LastBootUpTime).TotalDays
        if ($days -ge $UptimeWarningDays) { $sev='WARNING'; $rec='Schedule a restart if updates or stale services may be involved.' }
        else { $sev='OK'; $rec='' }
        New-CheckResult -Name 'System Uptime' -Severity $sev -Category 'system' `
            -Summary ('{0:N1} days' -f $days) -Details @{ UptimeDays=[math]::Round($days,1) } -Recommendation $rec
    } catch {
        New-CheckResult -Name 'System Uptime' -Severity 'INFO' -Category 'system' -Summary 'Unable to calculate uptime.'
    }

    try {
        $restartKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        )
        $pending = @($restartKeys | Where-Object { Test-Path $_ })
        if ($pending.Count -gt 0) {
            New-CheckResult -Name 'Pending Restart' -Severity 'WARNING' -Category 'windows' `
                -Summary 'Windows reports that a restart is pending.' -Details @{ Sources=$pending } `
                -Recommendation 'Restart during an appropriate maintenance window.'
        } else {
            New-CheckResult -Name 'Pending Restart' -Severity 'OK' -Category 'windows' -Summary 'No common pending-restart indicators found.'
        }
    } catch {
        New-CheckResult -Name 'Pending Restart' -Severity 'INFO' -Category 'windows' -Summary 'Unable to read all restart indicators.'
    }

}

function Get-NetworkChecks {
    $configs = @()

    try {
        $configs = @(Get-NetIPConfiguration | Where-Object { $_.NetAdapter -and $_.NetAdapter.Status -eq 'Up' })
        if ($configs.Count -eq 0) {
            New-CheckResult -Name 'Network Adapters' -Severity 'WARNING' -Category 'network' `
                -Summary 'No active network adapters detected.' -Recommendation 'Check Ethernet/Wi-Fi state and adapter status.'
        } else {
            $details = @($configs | ForEach-Object {
                $config = $_

                $ipv4Addresses = @(
                    @($config.IPv4Address) | ForEach-Object {
                        if ($null -ne $_ -and ($_.PSObject.Properties.Name -contains 'IPAddress')) {
                            $_.IPAddress
                        }
                    }
                )

                $gateways = @(
                    @($config.IPv4DefaultGateway) | ForEach-Object {
                        if ($null -eq $_) {
                            return
                        }

                        if ($_.PSObject.Properties.Name -contains 'NextHop') {
                            $_.NextHop
                        }
                        elseif ($_ -is [string]) {
                            $_
                        }
                    }
                )

                @{
                    InterfaceAlias = $config.InterfaceAlias
                    Description    = $config.InterfaceDescription
                    IPv4           = $ipv4Addresses
                    Gateway        = $gateways
                }
            })
            New-CheckResult -Name 'Network Adapters' -Severity 'OK' -Category 'network' `
                -Summary "$($configs.Count) active adapter configuration(s) detected." -Details @{ Adapters=$details }
        }

        $ipv4 = @(
            $configs |
            ForEach-Object { @($_.IPv4Address) } |
            Where-Object { $_ -and ($_.PSObject.Properties.Name -contains 'IPAddress') } |
            ForEach-Object { $_.IPAddress }
        )
        $apipa = @($ipv4 | Where-Object { $_ -like '169.254.*' })
        if ($ipv4.Count -eq 0) {
            New-CheckResult -Name 'Local IPv4' -Severity 'WARNING' -Category 'network' -Summary 'No IPv4 address detected.' `
                -Recommendation 'Check adapter state, DHCP, cable/Wi-Fi connectivity, and IP configuration.'
        } elseif ($apipa.Count -gt 0) {
            New-CheckResult -Name 'Local IPv4' -Severity 'CRITICAL' -Category 'network' `
                -Summary "APIPA address detected: $($apipa -join ', ')" -Details @{ Addresses=$ipv4; APIPA=$apipa } `
                -Recommendation 'The device may have failed to obtain a DHCP lease. Check DHCP reachability and adapter configuration.'
        } else {
            New-CheckResult -Name 'Local IPv4' -Severity 'OK' -Category 'network' -Summary ($ipv4 -join ', ') -Details @{ Addresses=$ipv4 }
        }
    } catch {
        New-CheckResult -Name 'Network Adapters' -Severity 'INFO' -Category 'network' -Summary "Unable to collect adapter information: $($_.Exception.Message)"
    }

    try {
        $rows = @(Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled })
        $dhcpCount = @($rows | Where-Object { $_.DHCPEnabled }).Count
        $staticCount = @($rows | Where-Object { -not $_.DHCPEnabled }).Count
        New-CheckResult -Name 'DHCP / Static IP' -Severity 'OK' -Category 'network' `
            -Summary "$dhcpCount DHCP-enabled adapter(s), $staticCount static-IP adapter(s)" `
            -Details @{ DHCPEnabled=$dhcpCount; StaticIP=$staticCount }
    } catch {
        New-CheckResult -Name 'DHCP / Static IP' -Severity 'INFO' -Category 'network' -Summary 'Unable to read DHCP/static state.'
    }

    try {
        $dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique)
        if ($dnsServers.Count -gt 0) {
            New-CheckResult -Name 'DNS Servers' -Severity 'OK' -Category 'network' -Summary ($dnsServers -join ', ') -Details @{ Servers=$dnsServers }
        } else {
            New-CheckResult -Name 'DNS Servers' -Severity 'WARNING' -Category 'network' -Summary 'No IPv4 DNS servers reported.'
        }
    } catch {
        New-CheckResult -Name 'DNS Servers' -Severity 'INFO' -Category 'network' -Summary 'Unable to read DNS server configuration.'
    }

    $gateway = $null
    try {
        $gateway = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1 -ExpandProperty NextHop
        if ($gateway) {
            New-CheckResult -Name 'Default Gateway' -Severity 'OK' -Category 'network' -Summary $gateway -Details @{ Gateway=$gateway }
        } else {
            New-CheckResult -Name 'Default Gateway' -Severity 'WARNING' -Category 'network' -Summary 'No default IPv4 gateway found.'
        }
    } catch {
        New-CheckResult -Name 'Default Gateway' -Severity 'INFO' -Category 'network' -Summary 'Unable to determine default gateway.'
    }

    if ($gateway) {
        try {
            $ok = Test-Connection -ComputerName $gateway -Count 2 -Quiet -ErrorAction SilentlyContinue
            if ($ok) {
                New-CheckResult -Name 'Gateway Reachability' -Severity 'OK' -Category 'network' -Summary "$gateway reachable"
            } else {
                New-CheckResult -Name 'Gateway Reachability' -Severity 'CRITICAL' -Category 'network' -Summary "$gateway not reachable" `
                    -Recommendation 'Check local link, VLAN, gateway device, Wi-Fi/cable, and IP configuration.'
            }
        } catch {
            New-CheckResult -Name 'Gateway Reachability' -Severity 'INFO' -Category 'network' -Summary 'Gateway ping failed to execute.'
        }
    }

    try {
        $dnsResult = Resolve-DnsName -Name 'example.com' -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
        if ($dnsResult) {
            New-CheckResult -Name 'DNS Resolution' -Severity 'OK' -Category 'network' `
                -Summary "example.com -> $($dnsResult.IPAddress)" -Details @{ Domain='example.com'; IPAddress=$dnsResult.IPAddress }
        }
    } catch {
        New-CheckResult -Name 'DNS Resolution' -Severity 'CRITICAL' -Category 'network' -Summary 'Failed to resolve example.com.' `
            -Recommendation 'Check DNS servers, DNS Client service, VPN/proxy, and upstream DNS reachability.'
    }

    try {
        $internetOk = Test-Connection -ComputerName '1.1.1.1' -Count 2 -Quiet -ErrorAction SilentlyContinue
        if ($internetOk) {
            New-CheckResult -Name 'Internet Reachability' -Severity 'OK' -Category 'network' -Summary '1.1.1.1 reachable'
        } else {
            New-CheckResult -Name 'Internet Reachability' -Severity 'CRITICAL' -Category 'network' -Summary '1.1.1.1 not reachable' `
                -Recommendation 'If the gateway works, investigate upstream routing, firewall, VPN, or ISP connectivity.'
        }
    } catch {
        New-CheckResult -Name 'Internet Reachability' -Severity 'INFO' -Category 'network' -Summary 'Internet reachability test failed to execute.'
    }

    try {
        $samples = @(Test-Connection -ComputerName '1.1.1.1' -Count 4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ResponseTime)
        if ($samples.Count -gt 0) {
            $avg = ($samples | Measure-Object -Average).Average
            if ($avg -ge $LatencyCriticalMs) { $sev='CRITICAL'; $rec='Investigate severe latency: Wi-Fi quality, VPN, WAN congestion, or ISP path.' }
            elseif ($avg -ge $LatencyWarningMs) { $sev='WARNING'; $rec='Latency is elevated; compare wired vs Wi-Fi and inspect VPN/path congestion.' }
            else { $sev='OK'; $rec='' }
            New-CheckResult -Name 'Internet Latency' -Severity $sev -Category 'network' `
                -Summary ('1.1.1.1 average {0:N1} ms' -f $avg) -Details @{ SamplesMs=$samples; AverageMs=[math]::Round($avg,1) } -Recommendation $rec
        } else {
            New-CheckResult -Name 'Internet Latency' -Severity 'INFO' -Category 'network' -Summary 'Latency unavailable because ping samples failed.'
        }
    } catch {
        New-CheckResult -Name 'Internet Latency' -Severity 'INFO' -Category 'network' -Summary 'Unable to calculate latency.'
    }

    try {
        $wlan = netsh wlan show interfaces 2>$null
        $ssidLine = $wlan | Where-Object { $_ -match '^\s*SSID\s*:' } | Select-Object -First 1
        $signalLine = $wlan | Where-Object { $_ -match '^\s*Signal\s*:' } | Select-Object -First 1
        if ($ssidLine) {
            $ssid = ($ssidLine -split ':',2)[1].Trim()
            $signal = if ($signalLine) { ($signalLine -split ':',2)[1].Trim() } else { '' }
            $sev='OK'; $rec=''
            if ($signal -match '(\d+)%') {
                if ([int]$matches[1] -lt 35) { $sev='WARNING'; $rec='Weak Wi-Fi signal; compare wired connectivity or move closer to the access point.' }
            }
            $summary = "SSID: $ssid"
            if ($signal) { $summary += " | Signal: $signal" }
            New-CheckResult -Name 'Wi-Fi' -Severity $sev -Category 'network' -Summary $summary -Details @{ SSID=$ssid; Signal=$signal } -Recommendation $rec
        } else {
            New-CheckResult -Name 'Wi-Fi' -Severity 'INFO' -Category 'network' -Summary 'No active Wi-Fi connection detected.'
        }
    } catch {
        New-CheckResult -Name 'Wi-Fi' -Severity 'INFO' -Category 'network' -Summary 'Wi-Fi information unavailable.'
    }

    try {
        $proxy = (netsh winhttp show proxy 2>$null | Out-String).Trim()
        if ($proxy) {
            $compact = ($proxy -replace '\s+',' ').Trim()
            New-CheckResult -Name 'WinHTTP Proxy' -Severity 'OK' -Category 'network' -Summary $compact -Details @{ Output=$proxy }
        }
    } catch {
        New-CheckResult -Name 'WinHTTP Proxy' -Severity 'INFO' -Category 'network' -Summary 'Proxy information unavailable.'
    }

}

function Get-WindowsChecks {
    param([switch]$SkipSecurity)

    $services = [ordered]@{ Dnscache='DNS Client'; Dhcp='DHCP Client'; wuauserv='Windows Update' }
    foreach ($key in $services.Keys) {
        try {
            $service = Get-Service -Name $key -ErrorAction Stop
            if ($service.Status -eq 'Running') { $sev='OK'; $rec='' }
            elseif ($key -eq 'wuauserv' -and $service.Status -eq 'Stopped') { $sev='INFO'; $rec='Windows Update can be demand-started; investigate only if updates are failing.' }
            else { $sev='WARNING'; $rec='Review this service if related functionality is failing.' }
            New-CheckResult -Name "Service: $($services[$key])" -Severity $sev -Category 'windows' -Summary "$($service.Status)" `
                -Details @{ ServiceName=$key; Status="$($service.Status)" } -Recommendation $rec
        } catch {
            New-CheckResult -Name "Service: $($services[$key])" -Severity 'INFO' -Category 'windows' -Summary 'Service status unavailable.'
        }
    }

    if ($SkipSecurity) {
        New-CheckResult -Name 'Security Checks' -Severity 'INFO' -Category 'windows' -Summary 'Security checks skipped by user.'
        }

    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        $ok = [bool]$defender.AntivirusEnabled -and [bool]$defender.RealTimeProtectionEnabled
        New-CheckResult -Name 'Microsoft Defender' -Severity $(if ($ok) {'OK'} else {'WARNING'}) -Category 'windows' `
            -Summary "Antivirus enabled: $($defender.AntivirusEnabled) | Real-time protection: $($defender.RealTimeProtectionEnabled)" `
            -Details @{ AntivirusEnabled=[bool]$defender.AntivirusEnabled; RealTimeProtectionEnabled=[bool]$defender.RealTimeProtectionEnabled; SignatureLastUpdated="$($defender.AntivirusSignatureLastUpdated)" } `
            -Recommendation $(if ($ok) {''} else {'Review endpoint-security policy and Defender state.'})
    } catch {
        New-CheckResult -Name 'Microsoft Defender' -Severity 'INFO' -Category 'windows' -Summary "Defender status unavailable: $($_.Exception.Message)"
    }

    try {
        $bitlocker = @(Get-BitLockerVolume -ErrorAction Stop)
        if ($bitlocker.Count -eq 0) {
            New-CheckResult -Name 'BitLocker' -Severity 'INFO' -Category 'windows' -Summary 'No BitLocker volumes returned.'
        } else {
            $notProtected = @($bitlocker | Where-Object { "$($_.ProtectionStatus)" -notin @('On','1') })
            $details = @($bitlocker | ForEach-Object { @{ MountPoint="$($_.MountPoint)"; VolumeStatus="$($_.VolumeStatus)"; ProtectionStatus="$($_.ProtectionStatus)"; EncryptionPercentage=$_.EncryptionPercentage } })
            New-CheckResult -Name 'BitLocker' -Severity $(if ($notProtected.Count -gt 0) {'WARNING'} else {'OK'}) -Category 'windows' `
                -Summary "$($bitlocker.Count) volume(s) detected; $($notProtected.Count) may not have active protection." `
                -Details @{ Volumes=$details } -Recommendation $(if ($notProtected.Count -gt 0) {'Confirm encryption requirements with organizational policy.'} else {''})
        }
    } catch {
        $message = $_.Exception.Message
        if ($message -match 'Access.*denied|Unauthorized|privilege') {
            New-CheckResult -Name 'BitLocker' -Severity 'INFO' -Category 'windows' `
                -Summary 'BitLocker status unavailable without elevated permissions.' `
                -Recommendation 'Run PowerShell as Administrator if BitLocker details are required.'
        } else {
            New-CheckResult -Name 'BitLocker' -Severity 'INFO' -Category 'windows' -Summary "BitLocker status unavailable: $message"
        }
    }

}

function Get-TechnicianSummary {
    param([array]$Checks,[string]$OverallSeverity,[string]$Hostname)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Host: $Hostname")
    $lines.Add("Overall: $OverallSeverity")
    $important = @($Checks | Where-Object { $_.Severity -in @('WARNING','CRITICAL') })
    if ($important.Count -eq 0) { $lines.Add('No warning or critical findings.') }
    else {
        $lines.Add('Findings:')
        foreach ($check in $important) {
            $lines.Add("- [$($check.Severity)] $($check.Name): $($check.Summary)")
            if ($check.Recommendation) { $lines.Add("  Recommendation: $($check.Recommendation)") }
        }
    }
    return ($lines -join [Environment]::NewLine)
}

function Write-ConsoleReport {
    param([array]$Checks,[string]$OverallSeverity,[string]$Hostname)
    Write-Host ('=' * 72)
    Write-Host 'IT SUPPORT DIAGNOSTIC REPORT'
    Write-Host ('=' * 72)
    Write-Host "Host: $Hostname"
    Write-Host "Generated: $(Get-Date -Format o)"
    Write-Host "Administrator: $(Test-IsAdministrator)"
    Write-Host "Overall status: $OverallSeverity"
    Write-Host ''
    $currentCategory = ''
    foreach ($check in $Checks) {
        if ($check.Category -ne $currentCategory) { $currentCategory=$check.Category; Write-Host "--- $($currentCategory.ToUpper()) ---" }
        $color = switch ($check.Severity) { 'OK' {'Green'} 'INFO' {'Cyan'} 'WARNING' {'Yellow'} 'CRITICAL' {'Red'} default {'White'} }
        Write-Host "[$($check.Severity)] $($check.Name)" -ForegroundColor $color
        Write-Host "  $($check.Summary)"
        if ($check.Recommendation) { Write-Host "  Recommendation: $($check.Recommendation)" }
        Write-Host ''
    }
}

function Export-JsonReport {
    param([string]$Path,[array]$Checks,[string]$OverallSeverity,[string]$Hostname)
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [ordered]@{
        Hostname=$Hostname; GeneratedAt=(Get-Date -Format o); IsAdministrator=(Test-IsAdministrator); OverallStatus=$OverallSeverity; Checks=$Checks
    } | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
}

function Export-HtmlReport {
    param([string]$Path,[array]$Checks,[string]$OverallSeverity,[string]$Hostname)
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $rows = foreach ($check in $Checks) {
        $n=[System.Net.WebUtility]::HtmlEncode($check.Name); $c=[System.Net.WebUtility]::HtmlEncode($check.Category)
        $s=[System.Net.WebUtility]::HtmlEncode($check.Summary); $r=[System.Net.WebUtility]::HtmlEncode($check.Recommendation)
        $cls=$check.Severity.ToLowerInvariant()
        "<tr><td><span class='badge $cls'>$($check.Severity)</span></td><td>$c</td><td>$n</td><td>$s</td><td>$r</td></tr>"
    }
    $safeHost=[System.Net.WebUtility]::HtmlEncode($Hostname); $safeOverall=[System.Net.WebUtility]::HtmlEncode($OverallSeverity)
    $html=@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IT Diagnostic Report - $safeHost</title><style>
body{font-family:Arial,sans-serif;margin:2rem;color:#222}h1{margin-bottom:.2rem}.meta{color:#555;margin-bottom:1.5rem}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #ddd;padding:.7rem;text-align:left;vertical-align:top}th{background:#f5f5f5}
.badge{padding:.2rem .5rem;border-radius:.35rem;font-weight:bold}.ok{background:#dff4df}.info{background:#e8eef7}.warning{background:#fff1bf}.critical{background:#ffd5d5}
</style></head><body><h1>IT Support Diagnostic Report</h1><div class="meta"><strong>Host:</strong> $safeHost<br><strong>Generated:</strong> $(Get-Date -Format o)<br><strong>Administrator:</strong> $(Test-IsAdministrator)<br><strong>Overall status:</strong> $safeOverall</div>
<table><thead><tr><th>Status</th><th>Category</th><th>Check</th><th>Summary</th><th>Recommendation</th></tr></thead><tbody>$($rows -join [Environment]::NewLine)</tbody></table></body></html>
"@
    Set-Content -Path $Path -Value $html -Encoding UTF8
}


function Write-LiveCheck {
    param(
        [Parameter(Mandatory)]$Check
    )

    if ($script:LastLiveCategory -ne $Check.Category) {
        $script:LastLiveCategory = $Check.Category
        Write-Host ""
        Write-Host "--- $($Check.Category.ToUpper()) ---" -ForegroundColor White
    }

    $color = switch ($Check.Severity) {
        'OK'       { 'Green' }
        'INFO'     { 'Cyan' }
        'WARNING'  { 'Yellow' }
        'CRITICAL' { 'Red' }
        default    { 'White' }
    }

    Write-Host "[$($Check.Severity)] $($Check.Name)" -ForegroundColor $color
    Write-Host "  $($Check.Summary)"

    if ($Check.Recommendation) {
        Write-Host "  Recommendation: $($Check.Recommendation)"
    }

    Write-Host ""
}

function Add-LiveCheck {
    param(
        [Parameter(Mandatory)]$Check,
        [Parameter(Mandatory)]$Collection,
        [switch]$Silent
    )

    [void]$Collection.Add($Check)

    if (-not $Silent) {
        Write-LiveCheck -Check $Check
    }
}

try {
    $hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }

    $checkList = [System.Collections.Generic.List[object]]::new()
    $script:LastLiveCategory = ''

    if (-not $SummaryOnly) {
        Write-Host ('=' * 72)
        Write-Host 'IT SUPPORT DIAGNOSTICS - LIVE RUN'
        Write-Host ('=' * 72)
        Write-Host "Host: $hostname"
        Write-Host "Started: $(Get-Date -Format o)"
        Write-Host "Administrator: $(Test-IsAdministrator)"
        Write-Host ""
        Write-Host "Checks will appear below as soon as each one completes..." -ForegroundColor DarkGray
    }

    Get-SystemChecks | ForEach-Object {
        Add-LiveCheck -Check $_ -Collection $checkList -Silent:$SummaryOnly
    }

    Get-NetworkChecks | ForEach-Object {
        Add-LiveCheck -Check $_ -Collection $checkList -Silent:$SummaryOnly
    }

    Get-WindowsChecks -SkipSecurity:$SkipSecurityChecks | ForEach-Object {
        Add-LiveCheck -Check $_ -Collection $checkList -Silent:$SummaryOnly
    }

    $checks = @($checkList)
    $overall = Get-OverallSeverity -Checks $checks

    if ($SummaryOnly) {
        Write-Host (Get-TechnicianSummary -Checks $checks -OverallSeverity $overall -Hostname $hostname)
    }
    else {
        Write-Host ('=' * 72)
        $overallColor = switch ($overall) {
            'OK'       { 'Green' }
            'INFO'     { 'Cyan' }
            'WARNING'  { 'Yellow' }
            'CRITICAL' { 'Red' }
            default    { 'White' }
        }
        Write-Host "Diagnostics completed. Overall status: $overall" -ForegroundColor $overallColor
        Write-Host ('=' * 72)
    }

    if ($JsonPath) {
        Export-JsonReport -Path $JsonPath -Checks $checks -OverallSeverity $overall -Hostname $hostname
        Write-Host "JSON report written to: $JsonPath"
    }

    if ($HtmlPath) {
        Export-HtmlReport -Path $HtmlPath -Checks $checks -OverallSeverity $overall -Hostname $hostname
        Write-Host "HTML report written to: $HtmlPath"
    }

    if ((Get-SeverityRank $overall) -ge (Get-SeverityRank 'CRITICAL')) {
        exit 1
    }

    exit 0
}
catch {
    Write-Error "Diagnostics failed unexpectedly: $($_.Exception.Message)"
    exit 2
}
