<#
.SYNOPSIS
    Measures LDAP (389) and LDAPS (636) bind times against one or more domain
    controllers.

.DESCRIPTION
    A slow LDAPS bind combined with a fast LDAP bind is the classic signature of a
    certificate revocation check timeout: the delay happens during the TLS handshake,
    not in LDAP itself. This script makes that difference visible per DC.

    Interpretation:
      LDAP fast, LDAPS fast   -> healthy
      LDAP fast, LDAPS slow   -> TLS / revocation checking (run Test-LdapsRevocation)
      LDAP slow, LDAPS slow   -> the DC itself is slow (resources, storage, load)

.PARAMETER DC
    One or more domain controllers to test. Defaults to all DCs of the current domain.

.PARAMETER Repeat
    Number of measurements per port. The best (lowest) value is reported, which
    filters out one-off noise. Default 3.

.PARAMETER SlowMs
    Threshold in milliseconds above which a bind is flagged as slow. Default 300.

.PARAMETER ProbeMs
    Timeout of the TCP pre-flight check in milliseconds. Default 2000.

    A DC that is powered off does not refuse the connection, it simply does not
    answer - so without this check the OS SYN timeout (~21 s) applies to every
    single attempt. Raise this on high-latency WAN links if reachable DCs are
    being reported as unreachable.

.PARAMETER TimeoutSec
    Timeout for the LDAP bind operation itself. Default 30. Must stay well above
    the delays being investigated (a revocation-check timeout runs ~10-15 s).

.EXAMPLE
    .\Test-LdapsBind.ps1

.EXAMPLE
    .\Test-LdapsBind.ps1 -DC dc01,dc02 -Repeat 5

.EXAMPLE
    .\Test-LdapsBind.ps1 -Verbose

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible. Read-only, makes no changes.
    Run under an account that may bind to the directory.
#>
[CmdletBinding()]
param(
    [string[]] $DC,
    [int]      $Repeat     = 3,
    [int]      $SlowMs     = 300,
    [int]      $ProbeMs    = 2000,
    [int]      $TimeoutSec = 30
)

Add-Type -AssemblyName System.DirectoryServices.Protocols

# ---------------------------------------------------------------------
# Determine the target DCs
# ---------------------------------------------------------------------
if (-not $DC) {
    try {
        $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
        $DC  = $dom.DomainControllers | ForEach-Object { $_.Name }
    }
    catch {
        Write-Host 'Could not enumerate domain controllers - specify them with -DC.' -ForegroundColor Red
        return
    }
}

Write-Host ''
Write-Host ('Measuring bind times on {0} DC(s), best of {1} attempts...' -f $DC.Count, $Repeat) -ForegroundColor Cyan
Write-Host ('Unreachable DCs are skipped after a {0} ms TCP probe.' -f $ProbeMs) -ForegroundColor DarkGray
Write-Host ''

# ---------------------------------------------------------------------
# Fast TCP reachability test.
#
# This exists because LdapConnection.Timeout governs the LDAP operation,
# NOT the TCP connect. Against a dead host the connect runs into the OS
# SYN timeout (~21 s) before any exception surfaces. A short pre-flight
# check keeps a run against unreachable DCs from taking minutes.
# ---------------------------------------------------------------------
function Test-Port {
    param(
        [string] $Server,
        [int]    $Port,
        [int]    $TimeoutMs = 2000
    )

    $client = New-Object System.Net.Sockets.TcpClient

    try {
        $iar = $client.BeginConnect($Server, $Port, $null, $null)

        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }

        $client.EndConnect($iar)
        return $true
    }
    catch {
        # DNS failure, refused, no route - all mean "not usable"
        return $false
    }
    finally {
        $client.Close()
    }
}

# ---------------------------------------------------------------------
# Measure one bind. Returns milliseconds, or -1 on failure.
# ---------------------------------------------------------------------
function Measure-Bind {
    param(
        [string] $Server,
        [int]    $Port
    )

    $ns   = 'System.DirectoryServices.Protocols'
    $conn = $null

    try {
        $id   = New-Object "$ns.LdapDirectoryIdentifier" -ArgumentList $Server, $Port
        $conn = New-Object "$ns.LdapConnection"          -ArgumentList $id

        $conn.SessionOptions.SecureSocketLayer = ($Port -eq 636)
        $conn.SessionOptions.ProtocolVersion   = 3
        $conn.AuthType                         = 'Negotiate'
        $conn.Timeout                          = [timespan]::FromSeconds($TimeoutSec)

        # Start the clock immediately before the bind - object creation is not
        # part of what we want to measure.
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $conn.Bind()
        $sw.Stop()

        return [int]$sw.ElapsedMilliseconds
    }
    catch {
        return -1
    }
    finally {
        if ($conn) { $conn.Dispose() }
    }
}

# ---------------------------------------------------------------------
# Run the measurements
# ---------------------------------------------------------------------
$results = @()
$i       = 0

foreach ($server in $DC) {

    $i++
    Write-Progress -Activity 'Measuring bind times' `
                   -Status  ('{0} ({1}/{2})' -f $server, $i, $DC.Count) `
                   -PercentComplete (($i / $DC.Count) * 100)

    $row = [ordered]@{ DC = $server }

    foreach ($port in 389, 636) {

        $best = -1

        # Pre-flight: if the port is not even open, do not attempt a bind.
        # This turns a ~21 s OS timeout into a ~2 s check.
        if (Test-Port -Server $server -Port $port -TimeoutMs $ProbeMs) {

            for ($n = 1; $n -le $Repeat; $n++) {

                $ms = Measure-Bind -Server $server -Port $port

                if ($ms -lt 0) {
                    # A failed bind will fail again - do not retry.
                    $best = -1
                    break
                }

                if ($best -lt 0 -or $ms -lt $best) { $best = $ms }
            }
        }

        if ($port -eq 389) { $row['LDAP'] = $best } else { $row['LDAPS'] = $best }
    }

    $results += [pscustomobject]$row

    # Live feedback so a long run is never silent
    $obj = $results[-1]
    $l   = 'FAILED'
    $s   = 'FAILED'
    if ($obj.LDAP  -ge 0) { $l = '{0} ms' -f $obj.LDAP }
    if ($obj.LDAPS -ge 0) { $s = '{0} ms' -f $obj.LDAPS }
    Write-Verbose ('{0}: LDAP {1}, LDAPS {2}' -f $server, $l, $s)
}

Write-Progress -Activity 'Measuring bind times' -Completed

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
$fmt = '  {0,-28} {1,10} {2,10}   {3}'
Write-Host ($fmt -f 'DC', 'LDAP 389', 'LDAPS 636', 'Assessment') -ForegroundColor Cyan
Write-Host ('  ' + ('-' * 76)) -ForegroundColor DarkGray

foreach ($r in $results) {

    $ldap  = $r.LDAP
    $ldaps = $r.LDAPS

    $ldapTxt = 'FAILED'
    if ($ldap -ge 0) { $ldapTxt = '{0} ms' -f $ldap }

    $ldapsTxt = 'FAILED'
    if ($ldaps -ge 0) { $ldapsTxt = '{0} ms' -f $ldaps }

    if ($ldap -lt 0 -and $ldaps -lt 0) {
        $verdict = 'unreachable'
        $colour  = 'Red'
    }
    elseif ($ldaps -ge $SlowMs -and $ldap -ge 0 -and $ldap -lt $SlowMs) {
        $verdict = 'LDAPS slow, LDAP fast -> TLS / revocation check'
        $colour  = 'Red'
    }
    elseif ($ldaps -ge $SlowMs -and $ldap -ge $SlowMs) {
        $verdict = 'both slow -> DC itself (resources / storage)'
        $colour  = 'Yellow'
    }
    elseif ($ldaps -lt 0) {
        $verdict = 'LDAPS bind failed - certificate or port issue'
        $colour  = 'Red'
    }
    else {
        $verdict = 'ok'
        $colour  = 'Green'
    }

    Write-Host ($fmt -f $r.DC, $ldapTxt, $ldapsTxt, $verdict) -ForegroundColor $colour
}

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------
$slowLdaps = @($results | Where-Object { $_.LDAPS -ge $SlowMs -and $_.LDAP -ge 0 -and $_.LDAP -lt $SlowMs })

Write-Host ''

if ($slowLdaps.Count -gt 0) {
    Write-Host ('  {0} of {1} DCs bind LDAPS slowly while LDAP is fast.' -f $slowLdaps.Count, $results.Count) -ForegroundColor Red
    Write-Host '  The delay is in the TLS layer, not in LDAP and not in DC resources.' -ForegroundColor Red
    Write-Host '  Next step: run Test-LdapsRevocation.ps1 on one of these DCs.' -ForegroundColor Red
}
else {
    Write-Host '  No LDAPS-specific delay detected.' -ForegroundColor Green
}

Write-Host ''
