<#
.SYNOPSIS
    Lists DNS records by timestamp age, to identify what scavenging would delete.

.DESCRIPTION
    Run this BEFORE enabling scavenging. It answers the only question that
    matters beforehand: which live hosts have a stale timestamp and would be
    deleted even though they still exist?

    The decisive property is not whether a host is a server or a client, but
    whether its record carries a timestamp and who refreshes it:

      No timestamp            static record, never scavenged. Safe.
      Timestamp, refreshed    DCs (Netlogon re-registers hourly), domain-joined
                              Windows clients (every 24 h), DHCP-registered
                              leases (at 50 % of the lease). Safe.
      Timestamp, NOT refreshed  appliances, printers, NAS, ESXi/Linux hosts,
                              VIPs, devices that once registered via DHCP and
                              later received a fixed IP. THIS is the risk group.

    Anything older than (NoRefreshInterval + RefreshInterval) that is still
    reachable belongs to the third group and should be set to static before
    scavenging is switched on.

.PARAMETER Server
    DNS server to query.

.PARAMETER Zone
    One or more zones. Defaults to all primary forward zones on the server.

.PARAMETER AgeDays
    Records older than this are listed as candidates. Set it to
    NoRefreshInterval + RefreshInterval (default 14 days).

.PARAMETER TestReachable
    Additionally ping each candidate. A stale record whose host still answers
    is exactly the dangerous case. Slower - use on the candidate list.

.EXAMPLE
    .\Get-DnsStaleRecords.ps1 -Server DC02

.EXAMPLE
    .\Get-DnsStaleRecords.ps1 -Server DC02 -AgeDays 8 -TestReachable

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible. Read-only, changes nothing.
    Requires the DnsServer module (RSAT).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]   $Server,

    [string[]] $Zone,

    [int]      $AgeDays = 14,

    [switch]   $TestReachable
)

if (-not (Get-Module -ListAvailable -Name DnsServer)) {
    Write-Host 'DnsServer module not available (install RSAT).' -ForegroundColor Red
    return
}

Import-Module DnsServer -ErrorAction Stop

# ---------------------------------------------------------------------
# Zones
# ---------------------------------------------------------------------
if (-not $Zone) {
    try {
        $Zone = Get-DnsServerZone -ComputerName $Server -ErrorAction Stop |
                Where-Object { -not $_.IsReverseLookupZone -and $_.ZoneType -eq 'Primary' } |
                Select-Object -ExpandProperty ZoneName
    }
    catch {
        Write-Host ('Could not enumerate zones: {0}' -f $_.Exception.Message) -ForegroundColor Red
        return
    }
}

Write-Host ''
Write-Host ('Server : {0}' -f $Server) -ForegroundColor Cyan
Write-Host ('Zones  : {0}' -f ($Zone -join ', ')) -ForegroundColor Cyan
Write-Host ('Cutoff : older than {0} days' -f $AgeDays) -ForegroundColor Cyan
Write-Host ''

$now        = Get-Date
$candidates = @()
$allRecords = @()
$staticCnt  = 0
$freshCnt   = 0

foreach ($z in $Zone) {

    try {
        $recs = Get-DnsServerResourceRecord -ComputerName $Server -ZoneName $z `
                    -RRType A -ErrorAction Stop
    }
    catch {
        Write-Host ('{0}: {1}' -f $z, $_.Exception.Message) -ForegroundColor Red
        continue
    }

    foreach ($r in $recs) {

        $ip = $null
        if ($r.RecordData -and $r.RecordData.IPv4Address) {
            $ip = $r.RecordData.IPv4Address.IPAddressToString
        }

        $age = $null
        if ($r.Timestamp) {
            $age = [math]::Round(($now - $r.Timestamp).TotalDays, 1)
        }

        # Every record goes into $allRecords - the duplicate-IP check needs
        # static and fresh entries too, because a collision only shows up
        # when both sides are present.
        $allRecords += [pscustomobject]@{
            Zone     = $z
            HostName = $r.HostName
            IP       = $ip
            AgeDays  = $age
        }

        # No timestamp = static = never scavenged.
        if (-not $r.Timestamp) {
            $staticCnt++
            continue
        }

        if ($age -lt $AgeDays) {
            $freshCnt++
            continue
        }

        $candidates += [pscustomobject]@{
            Zone      = $z
            HostName  = $r.HostName
            IP        = $ip
            Timestamp = $r.Timestamp
            AgeDays   = $age
            Reachable = $null
        }
    }
}

# ---------------------------------------------------------------------
# Optional reachability test - a stale record whose host still answers
# is the case that scavenging would break.
# ---------------------------------------------------------------------
if ($TestReachable -and $candidates.Count -gt 0) {

    Write-Host ('Pinging {0} candidate(s)...' -f $candidates.Count) -ForegroundColor DarkGray

    foreach ($c in $candidates) {
        if ($c.IP) {
            $c.Reachable = Test-Connection -ComputerName $c.IP -Count 1 -Quiet -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------
# Duplicate IPs.
#
# This is the concrete harm scavenging is meant to prevent: a host got an
# IP, registered its record, then vanished without cleaning up. Another
# device later received the same IP and registered too. Now two names
# resolve to one address and one of them is wrong. Name resolution starts
# handing out the wrong answer roughly half the time.
#
# Collected across ALL records, not just the stale ones, because the
# collision is only visible when both entries are compared.
# ---------------------------------------------------------------------
$dupes = $allRecords |
         Where-Object { $_.IP } |
         Group-Object IP |
         Where-Object { $_.Count -gt 1 }

if ($dupes) {

    Write-Host ''
    Write-Host ('Duplicate IPs ({0}) - two or more names on one address:' -f $dupes.Count) -ForegroundColor Yellow
    Write-Host ''

    foreach ($d in $dupes) {

        Write-Host ('  {0}' -f $d.Name) -ForegroundColor Yellow

        foreach ($rec in ($d.Group | Sort-Object AgeDays -Descending)) {

            $ageTxt = 'static'
            if ($null -ne $rec.AgeDays) { $ageTxt = '{0} days old' -f $rec.AgeDays }

            Write-Host ('      {0,-24} {1,-16} {2}' -f $rec.HostName, $ageTxt, $rec.Zone)
        }
    }

    Write-Host ''
    Write-Host '  The older entry of each pair is the likely stale one. This is' -ForegroundColor DarkGray
    Write-Host '  exactly what scavenging removes - and why it is worth enabling.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Caveat: deliberate aliases (several names pointing at one' -ForegroundColor DarkGray
    Write-Host '  server on purpose) look identical here. Judge by the age gap -' -ForegroundColor DarkGray
    Write-Host '  a pair where one side is years old is a collision, not an alias.' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
Write-Host ''
Write-Host ('Static records (no timestamp, never scavenged) : {0}' -f $staticCnt)
Write-Host ('Dynamic records refreshed within {0} days      : {1}' -f $AgeDays, $freshCnt)
Write-Host ('Dynamic records OLDER than {0} days            : {1}' -f $AgeDays, $candidates.Count)
Write-Host ''

if ($candidates.Count -eq 0) {
    Write-Host 'No stale dynamic records found.' -ForegroundColor Green
    Write-Host ''
    return
}

$candidates |
    Sort-Object AgeDays -Descending |
    Format-Table Zone, HostName, IP, Timestamp, AgeDays, Reachable -AutoSize

if ($TestReachable) {
    Write-Host 'How to read this:' -ForegroundColor Cyan
    Write-Host '  Reachable = True  -> the host is alive but is not refreshing its'
    Write-Host '                       record. Scavenging WOULD DELETE IT. Set the'
    Write-Host '                       record to static before enabling scavenging.'
    Write-Host '  Reachable = False -> most likely a genuinely stale record, which'
    Write-Host '                       is what scavenging is meant to remove.'
}
else {
    Write-Host 'The Reachable column is empty - the ping test was not run.' -ForegroundColor Yellow
    Write-Host 'Re-run with -TestReachable to find the dangerous cases: records' -ForegroundColor Yellow
    Write-Host 'that are stale BUT whose host still answers. Those are live hosts' -ForegroundColor Yellow
    Write-Host 'that do not refresh, and scavenging would delete them.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host ('Note: set -AgeDays to NoRefreshInterval + RefreshInterval of the' ) -ForegroundColor DarkGray
Write-Host ('planned configuration (currently {0}). Records younger than that' -f $AgeDays) -ForegroundColor DarkGray
Write-Host ('are never at risk.') -ForegroundColor DarkGray
Write-Host ''
Write-Host 'Take a DNS backup before enabling scavenging.' -ForegroundColor Yellow
Write-Host ''
