<#
.SYNOPSIS
    Read-only audit of AD Sites & Services: subnets without a site, sites
    without a subnet or site link, and (optionally) client IPs seen in DNS
    that fall outside every registered subnet.

.DESCRIPTION
    A client whose IP isn't covered by any AD Subnet object has no site
    assignment. It does not reliably pick the local DC - it may walk a slow
    or wrong path across segments that otherwise look perfectly "connected"
    at the network layer. This is one of the most common AD-side causes
    behind a "the network is probably misconfigured" complaint, and it is
    entirely visible from AD itself - no access to other network segments
    required.

    Reports:
      - Subnets registered in AD Sites & Services that have no Site assigned.
      - Sites with zero subnets assigned (any DC placed there is never the
        "closest" DC for any client, since nothing maps to that site).
      - Sites with no AD Site Link at all (cannot replicate via the normal
        topology, and KCC connection objects for it may be unpredictable).
      - Site Links left at the untouched defaults (cost 100, replicate every
        15 minutes, "always" schedule) - worth a second look when the sites
        involved are not actually on the same LAN, not necessarily wrong.
      - Optionally (-CheckDns), DNS A records in the given zone(s) whose IP
        falls inside NO registered subnet - the concrete "whose clients is
        AD blind to" list, which is the strongest evidence this script can
        produce without touching the network itself.

.PARAMETER CheckDns
    Also compare DNS A records against the registered subnets. Requires the
    DnsServer module (RSAT) and read access to the DNS server. IPv6 subnets
    and AAAA records are listed in the inventory but not range-checked (the
    CIDR math below is IPv4-only).

.PARAMETER DnsServer
    DNS server to query for -CheckDns. Defaults to the current domain's PDC.

.PARAMETER DnsZone
    Zone(s) to check for -CheckDns. Defaults to all primary forward zones on
    the DNS server.

.PARAMETER MaxUncoveredList
    Cap on how many uncovered DNS records to list in detail. Default 200.
    The summary count is never capped, only the detail list.

.EXAMPLE
    .\Test-AdSiteSubnetCoverage.ps1

.EXAMPLE
    .\Test-AdSiteSubnetCoverage.ps1 -CheckDns -DnsServer dc01

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible. Read-only, makes no changes.
    Requires the ActiveDirectory module; -CheckDns additionally the DnsServer
    module. On a very large DNS zone, -CheckDns can take a while - it is an
    O(records x subnets) comparison with no indexing beyond that.
#>
[CmdletBinding()]
param(
    [switch]   $CheckDns,
    [string]   $DnsServer,
    [string[]] $DnsZone,
    [int]      $MaxUncoveredList = 200
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host 'ActiveDirectory module not found. Install RSAT.' -ForegroundColor Red
    return
}
Import-Module ActiveDirectory -ErrorAction Stop

# ---------------------------------------------------------------------
# IPv4 CIDR helpers (PowerShell 5.1 has no built-in IP network math)
# ---------------------------------------------------------------------
function ConvertTo-UInt32FromIp {
    param([string]$IpAddress)
    try {
        $bytes = ([System.Net.IPAddress]$IpAddress).GetAddressBytes()
        if ($bytes.Length -ne 4) { return $null }
        [Array]::Reverse($bytes)
        return [BitConverter]::ToUInt32($bytes, 0)
    }
    catch { return $null }
}

function Get-CidrRange {
    param([string]$Cidr)
    if ($Cidr -notmatch '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$') { return $null }
    $prefixLen = [int]$Matches[2]
    if ($prefixLen -lt 0 -or $prefixLen -gt 32) { return $null }
    $base = ConvertTo-UInt32FromIp $Matches[1]
    if ($null -eq $base) { return $null }
    $base = [uint64]$base
    $size = [uint64]1 -shl (32 - $prefixLen)
    $network = $base - ($base % $size)
    $broadcast = $network + $size - 1
    return [pscustomobject]@{ Start = $network; End = $broadcast }
}

# ---------------------------------------------------------------------
# Read Sites & Services
# ---------------------------------------------------------------------
Write-Host ''
Write-Host 'Reading AD Sites & Services ...' -ForegroundColor Cyan
Write-Host ''

try {
    $sites   = @(Get-ADReplicationSite -Filter * -Properties Name -ErrorAction Stop)
    $subnets = @(Get-ADReplicationSubnet -Filter * -Properties Name, Site -ErrorAction Stop)
    $links   = @(Get-ADReplicationSiteLink -Filter * -Properties Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded -ErrorAction Stop)
}
catch {
    Write-Host ('Could not read Sites & Services: {0}' -f $_.Exception.Message) -ForegroundColor Red
    return
}

function Get-CnName {
    param([string]$DistinguishedName)
    if (-not $DistinguishedName) { return $null }
    return (($DistinguishedName -split ',')[0] -replace '^CN=', '')
}

$siteNames = @($sites | ForEach-Object { $_.Name })

$orphanSubnets = @($subnets | Where-Object { -not $_.Site })

$coveredSiteNames = @($subnets | Where-Object { $_.Site } | ForEach-Object { Get-CnName $_.Site } | Select-Object -Unique)
$emptySites = @($siteNames | Where-Object { $coveredSiteNames -notcontains $_ })

$linkedSiteNames = New-Object System.Collections.Generic.HashSet[string]
foreach ($l in $links) {
    foreach ($s in $l.SitesIncluded) {
        [void]$linkedSiteNames.Add((Get-CnName $s))
    }
}
$unlinkedSites = @($siteNames | Where-Object { -not $linkedSiteNames.Contains($_) })

$defaultLinks = @($links | Where-Object { $_.Cost -eq 100 -and $_.ReplicationFrequencyInMinutes -eq 15 })

# ---------------------------------------------------------------------
# Report: Sites & Subnets inventory
# ---------------------------------------------------------------------
Write-Host ('Sites:   {0}' -f $siteNames.Count) -ForegroundColor Cyan
Write-Host ('Subnets: {0}' -f $subnets.Count) -ForegroundColor Cyan
Write-Host ('Links:   {0}' -f $links.Count) -ForegroundColor Cyan
Write-Host ''

if ($orphanSubnets.Count -gt 0) {
    Write-Host ('{0} subnet(s) have NO site assigned:' -f $orphanSubnets.Count) -ForegroundColor Red
    foreach ($s in $orphanSubnets) { Write-Host ('  {0}' -f $s.Name) -ForegroundColor Red }
}
else {
    Write-Host 'Every registered subnet has a site assigned.' -ForegroundColor Green
}
Write-Host ''

if ($emptySites.Count -gt 0) {
    Write-Host ('{0} site(s) have NO subnet assigned (any DC there is never the closest DC for any client):' -f $emptySites.Count) -ForegroundColor Red
    foreach ($s in $emptySites) { Write-Host ('  {0}' -f $s) -ForegroundColor Red }
}
else {
    Write-Host 'Every site has at least one subnet assigned.' -ForegroundColor Green
}
Write-Host ''

if ($unlinkedSites.Count -gt 0) {
    Write-Host ('{0} site(s) are in NO site link (cannot replicate via the normal topology):' -f $unlinkedSites.Count) -ForegroundColor Red
    foreach ($s in $unlinkedSites) { Write-Host ('  {0}' -f $s) -ForegroundColor Red }
}
else {
    Write-Host 'Every site is covered by at least one site link.' -ForegroundColor Green
}
Write-Host ''

if ($defaultLinks.Count -gt 0) {
    Write-Host ('{0} site link(s) still use the untouched defaults (cost 100, every 15 min) - worth a second look if the sites are not on the same LAN:' -f $defaultLinks.Count) -ForegroundColor Yellow
    foreach ($l in $defaultLinks) {
        $memberSites = ($l.SitesIncluded | ForEach-Object { Get-CnName $_ }) -join ', '
        Write-Host ('  {0}  [{1}]' -f $l.Name, $memberSites) -ForegroundColor Yellow
    }
}
else {
    Write-Host 'No site links are at the untouched cost/frequency defaults.' -ForegroundColor Green
}
Write-Host ''

# ---------------------------------------------------------------------
# Optional: DNS vs. subnet coverage
# ---------------------------------------------------------------------
if ($CheckDns) {
    if (-not (Get-Module -ListAvailable -Name DnsServer)) {
        Write-Host 'DnsServer module not available - skipping -CheckDns (install RSAT).' -ForegroundColor Yellow
    }
    else {
        Import-Module DnsServer -ErrorAction Stop

        if (-not $DnsServer) {
            try { $DnsServer = (Get-ADDomain).PDCEmulator }
            catch {
                Write-Host 'Could not determine a default DNS server - specify -DnsServer.' -ForegroundColor Red
                $DnsServer = $null
            }
        }

        if ($DnsServer) {
            if (-not $DnsZone) {
                try {
                    $DnsZone = @(Get-DnsServerZone -ComputerName $DnsServer -ErrorAction Stop |
                        Where-Object { -not $_.IsReverseLookupZone -and $_.ZoneType -eq 'Primary' } |
                        Select-Object -ExpandProperty ZoneName)
                }
                catch {
                    Write-Host ('Could not enumerate zones on {0}: {1}' -f $DnsServer, $_.Exception.Message) -ForegroundColor Red
                    $DnsZone = @()
                }
            }

            $ranges = @($subnets | ForEach-Object {
                $r = Get-CidrRange $_.Name
                if ($r) { [pscustomobject]@{ Start = $r.Start; End = $r.End; Subnet = $_.Name } }
            })

            Write-Host ('Checking DNS A records on {0} ({1}) against {2} IPv4 subnet(s) ...' -f $DnsServer, ($DnsZone -join ', '), $ranges.Count) -ForegroundColor Cyan
            Write-Host ''

            $checked = 0
            $uncoveredCount = 0
            $uncoveredSample = New-Object System.Collections.ArrayList

            foreach ($zone in $DnsZone) {
                try {
                    $records = Get-DnsServerResourceRecord -ZoneName $zone -ComputerName $DnsServer -RRType A -ErrorAction Stop
                }
                catch {
                    Write-Host ('  Could not read zone {0}: {1}' -f $zone, $_.Exception.Message) -ForegroundColor Yellow
                    continue
                }

                foreach ($rec in $records) {
                    $ip = $null
                    try { $ip = $rec.RecordData.IPv4Address.IPAddressToString } catch { $ip = $null }
                    if (-not $ip) { continue }

                    $ipNum = ConvertTo-UInt32FromIp $ip
                    if ($null -eq $ipNum) { continue }
                    $checked++

                    $hit = $null
                    foreach ($range in $ranges) {
                        if ($ipNum -ge $range.Start -and $ipNum -le $range.End) { $hit = $range; break }
                    }

                    if (-not $hit) {
                        $uncoveredCount++
                        if ($uncoveredSample.Count -lt $MaxUncoveredList) {
                            [void]$uncoveredSample.Add([pscustomobject]@{ Zone = $zone; Name = $rec.HostName; IP = $ip })
                        }
                    }
                }
            }

            Write-Host ('Checked {0} A record(s).' -f $checked) -ForegroundColor Cyan
            if ($uncoveredCount -gt 0) {
                Write-Host ('{0} record(s) resolve to an IP outside every registered subnet - these clients have no site assignment:' -f $uncoveredCount) -ForegroundColor Red
                foreach ($u in $uncoveredSample) { Write-Host ('  {0}.{1}  {2}' -f $u.Name, $u.Zone, $u.IP) -ForegroundColor Red }
                if ($uncoveredCount -gt $uncoveredSample.Count) {
                    Write-Host ('  ... and {0} more (raise -MaxUncoveredList to see all)' -f ($uncoveredCount - $uncoveredSample.Count)) -ForegroundColor Red
                }
            }
            else {
                Write-Host 'Every checked A record falls inside a registered subnet.' -ForegroundColor Green
            }
            Write-Host ''
        }
    }
}
else {
    Write-Host 'Run with -CheckDns to also compare DNS A records against the registered subnets.' -ForegroundColor DarkGray
    Write-Host ''
}
