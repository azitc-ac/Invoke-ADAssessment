<#
.SYNOPSIS
    Reachability matrix for the fixed AD ports plus a best-effort check of the
    dynamic RPC port(s) used by replication, against one or more targets.

.DESCRIPTION
    Proves or disproves "segment A can reach segment B on port X" - the raw
    network-layer evidence a network-segmentation claim needs. Pure TCP/UDP
    connect tests: no AD credentials and no domain membership required, so
    this can run from a jump box inside ANY segment, not just a domain-joined
    admin host.

    Tests the fixed well-known AD ports (DNS, Kerberos, RPC endpoint mapper,
    LDAP/LDAPS, SMB, kpasswd, Global Catalog, NTP, AD Web Services) via TCP
    and, where the protocol actually uses it, UDP.

    TCP vs UDP - which transport AD really uses per port, and what that
    means for the probe:
      53   DNS        UDP for every lookup; TCP when a reply is truncated
                      (large SRV sets) and for zone transfers. Both matter.
      88   Kerberos   Windows clients use TCP by default since Vista/2008
                      (MaxPacketSize); UDP only matters for legacy and
                      non-Windows clients.
      464  kpasswd    Same as Kerberos.
      123  NTP        UDP only.
      389  LDAP       TCP for every directory operation. UDP = CLDAP, used
                      solely for the DC-locator "ping" - small but critical
                      (slow logons / wrong DC when it is blocked).
      135, dynamic RPC, 445 SMB, 636/3268/3269, 9389: TCP only.

    A UDP port cannot be "connected" to; the only evidence is a reply, and a
    service only replies to a packet it recognises. So the UDP probes send a
    VALID minimal request for that protocol - a real DNS query (RD=0, root
    NS), a real NTP client request, a real CLDAP RootDSE search - never a
    dummy payload, and repeat it -UdpRepeat times so packet loss shows up as
    a ratio ("2/3 replies") instead of flipping the verdict between runs.
    Kerberos and kpasswd over UDP are NOT probed: there is no cheap valid
    request for them, and for Windows clients the TCP row is the relevant
    one. Those rows stay visible as "Not probed" so nothing is missing
    unexplained.

    Even a valid request can go unanswered for more than one reason: nothing
    bound to the port on the target, a firewall dropping it, or plain loss.
    A Windows target almost never sends ICMP port-unreachable (rate-limited
    and usually filtered), so "Closed" is rarely observable for UDP. "No
    response" is therefore never phrased as a firewall verdict. What settles
    "nothing listening" vs "not reachable from here" is the listener
    inventory Invoke-SegmentProbeFanOut.ps1 collects on the targets
    themselves and feeds into Compare-SegmentProbes.ps1.

    For the RPC dynamic port range used by AD replication (the classic
    "segments are mostly connected but the port range is blocked" failure),
    this script first tries to read each target's actual configured RPC port
    restriction via remote registry (the same OpenRemoteBaseKey technique
    Invoke-ADAssessment.ps1 uses for its hardening checks):
      - HKLM\SOFTWARE\Microsoft\Rpc\Internet (Ports / UseInternetPorts)
      - Netlogon DCTcpipPort
      - NTFRS / DFSR "RPC TCP/IP Port Assignment"
    If a restriction is configured, those exact ports are tested - a precise,
    fast, conclusive result. If nothing is configured (the default dynamic
    range) or the registry can't be read from here, the range is NOT sampled
    with arbitrary ports: an unused dynamic port is dropped by the host firewall
    and reads "Filtered" on a perfectly healthy DC, which cannot be told apart
    from a genuinely blocked range. Instead the script exercises the real path -
    EPM (135) handing out a dynamically-assigned port - with a bounded DCOM/RPC
    call (its timeout follows -ProbeMs) and reports whether that path is
    Reachable, Reachable (access denied - connectivity is fine, only WMI
    rights are missing), Unreachable (RPC server unavailable / timeout = EPM
    or the dynamic port is blocked), or Unknown (the call failed with
    something other than those two recognized errors - e.g. a name
    resolution failure - and is deliberately NOT counted as reachable; check
    it manually rather than trust an unclassified error either way).

    Tag each run with -SegmentName and save it with -OutFile, then run the
    SAME command from a different segment against the SAME targets. Feed
    both files into Compare-SegmentProbes.ps1: a port that is open from one
    segment and closed/filtered from another is the actual proof a
    segmentation claim needs - a single run only shows "reachable from here".

.PARAMETER Target
    One or more hosts to test (DCs, or any AD-relevant server). Defaults to
    all DCs of the current domain (requires the ActiveDirectory module and
    domain membership; if that is not available from this vantage point -
    the normal case for a non-domain-joined jump box in another segment -
    pass -Target explicitly).

.PARAMETER SegmentName
    A label for where this run was executed from, e.g. "Branch-VLAN20" or
    "DMZ". Defaults to "<hostname> (<local IPv4 addresses>)". Stored in the
    output so Compare-SegmentProbes.ps1 can tell runs apart.

.PARAMETER ProbeMs
    Timeout in milliseconds for each individual TCP/UDP probe, and also for
    the DCOM/RPC reachability call used for the unrestricted dynamic-RPC
    check (see RpcSampleCount). Default 2000. A WMI/DCOM connect typically
    needs more headroom than a bare TCP connect, especially over a
    higher-latency WAN link between segments - raise this if that check
    reports Unreachable/Unknown against a target you otherwise know is fine.

.PARAMETER UdpRepeat
    How many times each UDP request (DNS, NTP, CLDAP) is sent. Default 3.
    The result reports replies as a ratio, e.g. "2/3 replies - lossy"; a
    port counts as Responded if at least one reply came back, so loss does
    not masquerade as a segment difference in Compare-SegmentProbes.ps1.

.PARAMETER RpcSampleCount
    Set to 0 to skip the dynamic-RPC check entirely and only test the fixed
    ports. When greater than 0 (default 10) the dynamic-RPC check runs; the
    number is only used to step through a CONFIGURED wide RPC range when one is
    found in the registry (how many points across that range to test). The
    unrestricted case no longer samples arbitrary ports - it uses the DCOM/RPC
    reachability call described above.

.PARAMETER Json
    Emit the result as JSON to the pipeline instead of a formatted table.

.PARAMETER OutFile
    Also save the full JSON result to this path. Use this to feed
    Compare-SegmentProbes.ps1; the console table is still shown unless
    -Json is also given.

.EXAMPLE
    .\Test-AdPortMatrix.ps1 -SegmentName 'HQ' -OutFile hq-probe.json

.EXAMPLE
    .\Test-AdPortMatrix.ps1 -Target dc01.contoso.com -SegmentName 'Branch-VLAN20' -OutFile branch-probe.json

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible. Read-only: TCP connects, three minimal UDP
    requests (DNS/NTP/CLDAP), a DCOM connect and a registry READ. Makes no
    changes anywhere. Needs only .NET Framework (System.DirectoryServices.
    Protocols for CLDAP) - no AD module, no domain membership.
#>
[CmdletBinding()]
param(
    [string[]] $Target,
    [string]   $SegmentName,
    [int]      $ProbeMs         = 2000,
    [int]      $UdpRepeat       = 3,
    [int]      $RpcSampleCount  = 10,
    [switch]   $Json,
    [string]   $OutFile
)

Add-Type -AssemblyName System.DirectoryServices.Protocols

# ---------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------
if (-not $Target) {
    try {
        $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
        $Target = $dom.DomainControllers | ForEach-Object { $_.Name }
    }
    catch {
        Write-Host 'Could not enumerate domain controllers - specify them with -Target.' -ForegroundColor Red
        return
    }
}

if (-not $SegmentName) {
    $localIps = @(
        [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            ForEach-Object { $_.IPAddressToString }
    )
    $SegmentName = '{0} ({1})' -f $env:COMPUTERNAME, ($localIps -join ', ')
}

# ---------------------------------------------------------------------
# Fixed AD ports tested on every target
# ---------------------------------------------------------------------
# Probe = how the port is tested: Tcp (connect), Dns/Ntp/Cldap (a valid
# minimal request for that protocol over UDP), None (listed, not probed).
$FixedPorts = @(
    [pscustomobject]@{ Name = 'DNS';                 Port = 53;   Proto = 'TCP'; Probe = 'Tcp'   }
    [pscustomobject]@{ Name = 'DNS';                 Port = 53;   Proto = 'UDP'; Probe = 'Dns'   }
    [pscustomobject]@{ Name = 'Kerberos';             Port = 88;   Proto = 'TCP'; Probe = 'Tcp'   }
    [pscustomobject]@{ Name = 'Kerberos';             Port = 88;   Proto = 'UDP'; Probe = 'None'  }
    [pscustomobject]@{ Name = 'RPC Endpoint Mapper';  Port = 135;  Proto = 'TCP'; Probe = 'Tcp'   }
    [pscustomobject]@{ Name = 'NTP';                  Port = 123;  Proto = 'UDP'; Probe = 'Ntp'   }
    [pscustomobject]@{ Name = 'LDAP';                 Port = 389;  Proto = 'TCP'; Probe = 'Tcp'   }
    [pscustomobject]@{ Name = 'LDAP (CLDAP)';         Port = 389;  Proto = 'UDP'; Probe = 'Cldap' }
    [pscustomobject]@{ Name = 'SMB';                  Port = 445;  Proto = 'TCP'; Probe = 'Tcp'   }
    [pscustomobject]@{ Name = 'Kerberos kpasswd';     Port = 464;  Proto = 'TCP'; Probe = 'Tcp'   }
    [pscustomobject]@{ Name = 'Kerberos kpasswd';     Port = 464;  Proto = 'UDP'; Probe = 'None'  }
    [pscustomobject]@{ Name = 'LDAPS';                Port = 636;  Proto = 'TCP'; Probe = 'Tcp'   }
    [pscustomobject]@{ Name = 'Global Catalog LDAP';  Port = 3268; Proto = 'TCP'; Probe = 'Tcp'   }
    [pscustomobject]@{ Name = 'Global Catalog LDAPS'; Port = 3269; Proto = 'TCP'; Probe = 'Tcp'   }
    [pscustomobject]@{ Name = 'AD Web Services';      Port = 9389; Proto = 'TCP'; Probe = 'Tcp'   }
)

# ---------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------
function Test-TcpPort {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs)
    $client = New-Object System.Net.Sockets.TcpClient
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return [pscustomobject]@{ State = 'Filtered/Timeout'; Ms = $TimeoutMs }
        }
        $client.EndConnect($iar)
        $sw.Stop()
        return [pscustomobject]@{ State = 'Open'; Ms = [int]$sw.ElapsedMilliseconds }
    }
    catch {
        $sw.Stop()
        return [pscustomobject]@{ State = 'Closed/Refused'; Ms = [int]$sw.ElapsedMilliseconds }
    }
    finally { $client.Close() }
}

# ---------------------------------------------------------------------
# UDP probes. Each sends a VALID minimal request for its protocol (see the
# help text for why a dummy payload tells you nothing) and is repeated
# -UdpRepeat times. Every exchange function returns the same shape:
#   Outcome = Response | Unexpected | Icmp | Timeout | Error
#   Ms      = round-trip ms for a Response, else $null
#   Error   = message for Error, else ''
# "Unexpected" = something replied but it did not parse as that protocol -
# still proof the port is reachable, flagged in the detail text.
# ---------------------------------------------------------------------
function Get-SocketErrorCode {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex -and -not ($ex -is [System.Net.Sockets.SocketException]) -and $ex.InnerException) { $ex = $ex.InnerException }
    if ($ex -is [System.Net.Sockets.SocketException]) { return $ex.SocketErrorCode }
    return $null
}

function Invoke-UdpExchange {
    param([string]$ComputerName, [int]$Port, [byte[]]$Request, [int]$TimeoutMs)
    $client = New-Object System.Net.Sockets.UdpClient
    try {
        $client.Client.ReceiveTimeout = $TimeoutMs
        $client.Connect($ComputerName, $Port)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        [void]$client.Send($Request, $Request.Length)
        try {
            $remoteEp = $null
            $data = $client.Receive([ref]$remoteEp)
            $sw.Stop()
            return [pscustomobject]@{ Outcome = 'Response'; Data = $data; Ms = [int]$sw.ElapsedMilliseconds; Error = '' }
        }
        catch {
            $code = Get-SocketErrorCode $_
            if ($code -eq [System.Net.Sockets.SocketError]::ConnectionReset) {
                return [pscustomobject]@{ Outcome = 'Icmp'; Data = $null; Ms = $null; Error = '' }
            }
            if ($code -eq [System.Net.Sockets.SocketError]::TimedOut) {
                return [pscustomobject]@{ Outcome = 'Timeout'; Data = $null; Ms = $null; Error = '' }
            }
            return [pscustomobject]@{ Outcome = 'Error'; Data = $null; Ms = $null; Error = $_.Exception.Message }
        }
    }
    catch {
        return [pscustomobject]@{ Outcome = 'Error'; Data = $null; Ms = $null; Error = $_.Exception.Message }
    }
    finally { $client.Close() }
}

# DNS: standard query for the root NS record with RD=0, so the server
# answers from its own data immediately instead of recursing to forwarders
# (that would take seconds and measure the upstream, not this DC). Any
# syntactically valid query gets a reply from a working server, whatever
# the RCODE. A reply is accepted when the transaction ID matches and the QR
# bit is set.
function Invoke-DnsExchange {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs)
    $id = Get-Random -Minimum 1 -Maximum 65535
    $b = New-Object System.Collections.Generic.List[byte]
    $b.Add([byte](($id -shr 8) -band 0xFF)); $b.Add([byte]($id -band 0xFF))
    $b.Add(0); $b.Add(0)      # flags: standard query, RD = 0
    $b.Add(0); $b.Add(1)      # QDCOUNT 1
    $b.Add(0); $b.Add(0)      # ANCOUNT
    $b.Add(0); $b.Add(0)      # NSCOUNT
    $b.Add(0); $b.Add(0)      # ARCOUNT
    $b.Add(0)                 # QNAME: root
    $b.Add(0); $b.Add(2)      # QTYPE NS
    $b.Add(0); $b.Add(1)      # QCLASS IN
    $req = $b.ToArray()
    $x = Invoke-UdpExchange -ComputerName $ComputerName -Port $Port -Request $req -TimeoutMs $TimeoutMs
    if ($x.Outcome -eq 'Response') {
        $d = $x.Data
        $valid = ($d.Length -ge 12 -and $d[0] -eq $req[0] -and $d[1] -eq $req[1] -and (($d[2] -band 0x80) -ne 0))
        if (-not $valid) { $x.Outcome = 'Unexpected' }
    }
    return $x
}

# NTP: a plain client request (LI 0, version 4, mode 3) - the fixed 48-byte
# packet every NTP server answers, w32time included. A reply is accepted
# when it is at least 48 bytes with a server-side mode (2, 4 or 5).
function Invoke-NtpExchange {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs)
    $req = New-Object byte[] 48
    $req[0] = 0x23
    $x = Invoke-UdpExchange -ComputerName $ComputerName -Port $Port -Request $req -TimeoutMs $TimeoutMs
    if ($x.Outcome -eq 'Response') {
        $d = $x.Data
        $mode = 0
        if ($d.Length -ge 1) { $mode = $d[0] -band 0x07 }
        $valid = ($d.Length -ge 48 -and ($mode -eq 2 -or $mode -eq 4 -or $mode -eq 5))
        if (-not $valid) { $x.Outcome = 'Unexpected' }
    }
    return $x
}

# CLDAP: a real connectionless LDAP RootDSE search - the same mechanism the
# DC locator ping uses - via System.DirectoryServices.Protocols with the
# identifier's connectionless flag set. A DirectoryOperationException means
# the server answered (with an LDAP error) and still counts as reachable;
# an LdapException 85 (LDAP_TIMEOUT) or 81 (LDAP_SERVER_DOWN) is "no reply".
function Invoke-CldapExchange {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs)
    $conn = $null
    try {
        $id   = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier -ArgumentList $ComputerName, $Port, $false, $true
        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection -ArgumentList $id
        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
        $conn.SessionOptions.ProtocolVersion = 3
        $conn.Timeout = [TimeSpan]::FromMilliseconds($TimeoutMs)
        $req = New-Object System.DirectoryServices.Protocols.SearchRequest
        $req.DistinguishedName = ''
        $req.Filter = '(objectClass=*)'
        $req.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
        [void]$req.Attributes.Add('dnsHostName')
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = $conn.SendRequest($req)
        $sw.Stop()
        return [pscustomobject]@{ Outcome = 'Response'; Data = $null; Ms = [int]$sw.ElapsedMilliseconds; Error = '' }
    }
    catch {
        $ex = $_.Exception
        while ($ex -and -not ($ex -is [System.DirectoryServices.Protocols.LdapException]) -and -not ($ex -is [System.DirectoryServices.Protocols.DirectoryOperationException]) -and $ex.InnerException) { $ex = $ex.InnerException }
        if ($ex -is [System.DirectoryServices.Protocols.DirectoryOperationException]) {
            return [pscustomobject]@{ Outcome = 'Response'; Data = $null; Ms = $null; Error = '' }
        }
        if ($ex -is [System.DirectoryServices.Protocols.LdapException]) {
            if ($ex.ErrorCode -eq 85 -or $ex.ErrorCode -eq 81) {
                return [pscustomobject]@{ Outcome = 'Timeout'; Data = $null; Ms = $null; Error = ('LDAP error {0}' -f $ex.ErrorCode) }
            }
            return [pscustomobject]@{ Outcome = 'Error'; Data = $null; Ms = $null; Error = ('LDAP error {0}: {1}' -f $ex.ErrorCode, $ex.Message) }
        }
        return [pscustomobject]@{ Outcome = 'Error'; Data = $null; Ms = $null; Error = $_.Exception.Message }
    }
    finally { if ($conn) { $conn.Dispose() } }
}

# Runs one of the exchange functions -Repeat times and condenses the
# outcomes into State (what Compare-SegmentProbes.ps1 diffs on), Detail (the
# ratio and anything odd) and Ms (best round trip). Responded needs just one
# reply, so loss shows up in the detail text, not as a segment difference.
function Measure-UdpProbe {
    param([string]$Exchange, [string]$ComputerName, [int]$Port, [int]$TimeoutMs, [int]$Repeat)
    $ok = 0; $odd = 0; $icmp = 0; $timeouts = 0; $errors = 0
    $bestMs = $null; $lastError = ''
    for ($n = 1; $n -le $Repeat; $n++) {
        $x = & $Exchange -ComputerName $ComputerName -Port $Port -TimeoutMs $TimeoutMs
        if ($x.Outcome -eq 'Response' -or $x.Outcome -eq 'Unexpected') {
            if ($x.Outcome -eq 'Unexpected') { $odd++ } else { $ok++ }
            if ($null -ne $x.Ms -and ($null -eq $bestMs -or $x.Ms -lt $bestMs)) { $bestMs = $x.Ms }
        }
        elseif ($x.Outcome -eq 'Icmp')    { $icmp++ }
        elseif ($x.Outcome -eq 'Timeout') { $timeouts++; if ($x.Error) { $lastError = $x.Error } }
        else                              { $errors++; $lastError = $x.Error }
    }
    $replies = $ok + $odd
    $ratio   = '{0}/{1} replies' -f $replies, $Repeat
    if ($replies -gt 0) {
        $state  = 'Responded'
        $detail = $ratio
        if ($replies -lt $Repeat) { $detail += ' - lossy' }
        if ($odd -gt 0) { $detail += (' - {0} did not parse as the expected protocol' -f $odd) }
    }
    elseif ($icmp -gt 0) {
        $state  = 'Closed (ICMP unreachable)'
        $detail = ('{0}, {1} ICMP port-unreachable' -f $ratio, $icmp)
    }
    elseif ($errors -eq $Repeat) {
        $state  = 'Error'
        $detail = $lastError
    }
    else {
        $state  = 'No response'
        $detail = $ratio + ' - no listener, firewall, or loss: NOT a firewall verdict on its own, check the listener inventory'
        if ($lastError) { $detail += (' ({0})' -f $lastError) }
    }
    return [pscustomobject]@{ State = $state; Detail = $detail; Ms = $bestMs }
}

# ---------------------------------------------------------------------
# Best-effort RPC dynamic-port configuration (remote registry READ only)
# ---------------------------------------------------------------------
function Get-RemoteRegValue {
    param($ComputerName, $Hive, $Key, $ValueName)
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive, $ComputerName)
        $sub  = $base.OpenSubKey($Key)
        if ($null -ne $sub) { return $sub.GetValue($ValueName) }
    }
    catch { return $null }
    return $null
}

function Get-RpcPortConfig {
    param([string]$ComputerName)
    $hive = [Microsoft.Win32.RegistryHive]::LocalMachine
    $result = [pscustomobject]@{
        Readable     = $false
        GlobalRange  = $null
        NetlogonPort = $null
        FrsPort      = $null
        DfsrPort     = $null
    }
    try {
        $ports       = Get-RemoteRegValue $ComputerName $hive 'SOFTWARE\Microsoft\Rpc\Internet' 'Ports'
        $useInternet = Get-RemoteRegValue $ComputerName $hive 'SOFTWARE\Microsoft\Rpc\Internet' 'UseInternetPorts'
        $result.Readable = $true
        if ($ports -and "$useInternet" -eq 'Y') { $result.GlobalRange = ($ports -join ',') }
        $result.NetlogonPort = Get-RemoteRegValue $ComputerName $hive 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'DCTcpipPort'
        $result.FrsPort      = Get-RemoteRegValue $ComputerName $hive 'SYSTEM\CurrentControlSet\Services\NtFrs\Parameters' 'RPC TCP/IP Port Assignment'
        $result.DfsrPort     = Get-RemoteRegValue $ComputerName $hive 'SYSTEM\CurrentControlSet\Services\DFSR\Parameters' 'RPC TCP/IP Port Assignment'
    }
    catch { $result.Readable = $false }
    return $result
}

# ---------------------------------------------------------------------
# Real dynamic-RPC reachability: a DCOM/RPC call (EPM 135 -> a dynamic port),
# bounded by -ProbeMs. Connectivity is the signal, not WMI permissions:
#   Reachable                     - the call returned data
#   Reachable (access denied)     - reached the service, just no WMI rights
#   Unreachable (RPC unavailable) - EPM/dynamic port blocked (0x800706BA)
#   Unreachable (timeout)         - no response within the timeout
#   Unknown                       - failed with something else entirely
#                                    (e.g. name resolution) - NOT treated as
#                                    reachable; a false "Reachable" here would
#                                    be the one false-clear this script must
#                                    not produce, so an unrecognized error
#                                    stays unclassified rather than optimistic.
# HRESULT hex in the message is matched (locale-independent).
# ---------------------------------------------------------------------
function Test-RpcDynamic {
    param([string]$ComputerName, [int]$TimeoutMs)
    # Synchronous and in-process (Start-Job fails under Constrained Language mode,
    # the norm on hardened systems). ManagementScope.Connect returns fast when
    # reachable (even access-denied comes back in ms) and returns a definitive
    # "RPC server unavailable" when the dynamic port is filtered (after the OS RPC
    # timeout, ~25 s - it does not hang forever). Any definitive server answer
    # means the transport reached the dynamic port = Reachable; only an explicit
    # RPC-unavailable means blocked. Message is localised + wrapped, so match words.

    # Resolve the target's IPv4 addresses so we can spot the dynamic high port the
    # DCOM/RPC connection actually lands on (a new established TCP conn to the DC).
    $ips = @()
    try { $ips = @([Net.Dns]::GetHostAddresses($ComputerName) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }) } catch { }
    $snapshot = {
        $h = @{}
        try {
            Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                Where-Object { $_.RemotePort -ge 49152 -and ($ips -contains $_.RemoteAddress) } |
                ForEach-Object { $h[[string]$_.LocalPort] = [int]$_.RemotePort }
        } catch { }
        $h
    }
    $before = & $snapshot

    $result = $null
    try {
        $opts = New-Object System.Management.ConnectionOptions
        $opts.Timeout = [TimeSpan]::FromMilliseconds($TimeoutMs)
        $scope = New-Object System.Management.ManagementScope(("\\{0}\root\cimv2" -f $ComputerName), $opts)
        $scope.Connect()
        $result = [pscustomobject]@{ Reach = 'Reachable'; Detail = 'Reachable (DCOM/RPC connect succeeded)' }
    }
    catch {
        $full  = "$($_.Exception.Message)"
        $inner = if ($_.Exception.InnerException) { "$($_.Exception.InnerException.Message)" } else { $full }
        $inner = (($inner -split "`r?`n")[0]).Trim()
        if ($full -match '(?i)0x800706BA|RPC server is unavailable|RPC-Server ist nicht') {
            $result = [pscustomobject]@{ Reach = 'Unreachable'; Detail = 'Unreachable (RPC server unavailable - EPM or dynamic port blocked)' }
        }
        elseif ($full -match '(?i)0x80070005|E_ACCESSDENIED|access is denied|zugriff verweigert') {
            $result = [pscustomobject]@{ Reach = 'Reachable'; Detail = 'Reachable (access denied - connectivity OK, no WMI rights)' }
        }
        else {
            # Neither recognized pattern matched - could be a genuine connectivity
            # problem (e.g. name resolution failure) that just isn't worded like
            # "RPC server unavailable". Reporting this as Reachable would be an
            # unverified guess in exactly the direction this script must not
            # guess in, so it stays Unknown and surfaces the raw message instead.
            $result = [pscustomobject]@{ Reach = 'Unknown'; Detail = ('Unknown (unclassified error - verify manually: ' + $inner + ')') }
        }
    }

    # Name the dynamic high port this connection actually used (ephemeral - it
    # varies per binding, so it illustrates that the range is in use; it is NOT a
    # single port to whitelist, and does not feed the segment diff).
    if ($result.Reach -eq 'Reachable') {
        $after    = & $snapshot
        $newLocal = @($after.Keys | Where-Object { -not $before.ContainsKey($_) })
        if ($newLocal.Count -gt 0) {
            $result.Detail = $result.Detail + ('  [dynamic port used this run: {0}]' -f $after[$newLocal[0]])
        }
    }
    return $result
}

# ---------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------
Write-Host ''
Write-Host ('Segment: {0}' -f $SegmentName) -ForegroundColor Cyan
Write-Host ('Testing {0} target(s), {1} fixed ports each, {2} ms timeout, UDP requests sent {3}x.' -f $Target.Count, $FixedPorts.Count, $ProbeMs, $UdpRepeat) -ForegroundColor Cyan
Write-Host ''

$results = New-Object System.Collections.ArrayList
$i = 0

foreach ($t in $Target) {

    $i++
    Write-Progress -Activity 'Testing AD port matrix' `
                   -Status  ('{0} ({1}/{2})' -f $t, $i, $Target.Count) `
                   -PercentComplete (($i / $Target.Count) * 100)

    $portResults = New-Object System.Collections.ArrayList
    foreach ($p in $FixedPorts) {
        $state = ''; $detail = ''; $ms = $null
        if ($p.Probe -eq 'Tcp') {
            $r = Test-TcpPort -ComputerName $t -Port $p.Port -TimeoutMs $ProbeMs
            $state = $r.State; $ms = $r.Ms
        }
        elseif ($p.Probe -eq 'None') {
            $state  = 'Not probed'
            $detail = 'no cheap valid UDP request exists for this protocol; Windows clients use TCP here - see the TCP row'
        }
        else {
            $exchange = 'Invoke-{0}Exchange' -f $p.Probe
            $r = Measure-UdpProbe -Exchange $exchange -ComputerName $t -Port $p.Port -TimeoutMs $ProbeMs -Repeat $UdpRepeat
            $state = $r.State; $detail = $r.Detail; $ms = $r.Ms
        }
        [void]$portResults.Add([pscustomobject]@{ Name = $p.Name; Port = $p.Port; Proto = $p.Proto; State = $state; Detail = $detail; Ms = $ms })
    }

    $rpcPortsTested = New-Object System.Collections.ArrayList
    $rpcReach  = $null
    $rpcDetail = $null
    $rpcNote = 'Dynamic RPC check skipped (-RpcSampleCount 0).'

    if ($RpcSampleCount -gt 0) {
        $rpcConfig = Get-RpcPortConfig -ComputerName $t
        $explicitPorts = New-Object System.Collections.Generic.List[int]
        if ($rpcConfig.NetlogonPort) { $explicitPorts.Add([int]$rpcConfig.NetlogonPort) }
        if ($rpcConfig.FrsPort)      { $explicitPorts.Add([int]$rpcConfig.FrsPort) }
        if ($rpcConfig.DfsrPort)     { $explicitPorts.Add([int]$rpcConfig.DfsrPort) }
        if ($rpcConfig.GlobalRange) {
            foreach ($part in ($rpcConfig.GlobalRange -split ',')) {
                if ($part -match '^(\d+)-(\d+)$') {
                    $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
                    $step = [Math]::Max(1, [int](($hi - $lo) / [Math]::Max(1, $RpcSampleCount)))
                    for ($port = $lo; $port -le $hi; $port += $step) { $explicitPorts.Add($port) }
                }
                elseif ($part -match '^\d+$') {
                    $explicitPorts.Add([int]$part)
                }
            }
        }

        if ($explicitPorts.Count -gt 0) {
            $rpcNote = 'Configured RPC port(s)/range found via remote registry - testing exactly those.'
            foreach ($port in ($explicitPorts | Select-Object -Unique)) {
                $r = Test-TcpPort -ComputerName $t -Port $port -TimeoutMs $ProbeMs
                [void]$rpcPortsTested.Add([pscustomobject]@{ Port = $port; State = $r.State; Ms = $r.Ms })
            }
        }
        else {
            # No explicit restriction (or the registry is unreadable from here).
            # Arbitrary ports in the dynamic range are assigned on demand and the
            # host firewall drops them while unused, so probing random ports is
            # misleading - they read "Filtered" on a perfectly healthy DC and
            # cannot tell "unused" from "blocked range" apart. Instead exercise
            # the REAL path - EPM (135) handing out a dynamic port - with a
            # DCOM/RPC call, and classify the outcome.
            if ($rpcConfig.Readable) {
                $rpcNote = 'No RPC restriction configured (default dynamic range). Testing actual reachability via a DCOM/RPC call (EPM 135 -> a dynamic port).'
            }
            else {
                $rpcNote = 'RPC port configuration not readable from here. Testing actual reachability via a DCOM/RPC call (EPM 135 -> a dynamic port).'
            }
            $epm = $portResults | Where-Object { $_.Port -eq 135 -and $_.Proto -eq 'TCP' } | Select-Object -First 1
            if ($epm -and $epm.State -eq 'Open') {
                $probe     = Test-RpcDynamic -ComputerName $t -TimeoutMs $ProbeMs
                $rpcReach  = $probe.Reach
                $rpcDetail = $probe.Detail
            }
            else {
                $rpcReach  = 'Unreachable'
                $rpcDetail = 'Unreachable (RPC Endpoint Mapper on TCP 135 is not reachable from here)'
            }
        }
    }

    [void]$results.Add([pscustomobject]@{
        Target    = $t
        Ports     = $portResults
        RpcNote   = $rpcNote
        RpcPorts  = $rpcPortsTested
        RpcReach  = $rpcReach
        RpcDetail = $rpcDetail
    })
}

Write-Progress -Activity 'Testing AD port matrix' -Completed

$report = [pscustomobject]@{
    SegmentName = $SegmentName
    Timestamp   = (Get-Date).ToString('o')
    Targets     = $results
}

if ($OutFile) {
    $report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutFile -Encoding UTF8
    Write-Host ('Saved: {0}' -f $OutFile) -ForegroundColor Green
    Write-Host ''
}

if ($Json) {
    $report | ConvertTo-Json -Depth 6 -Compress
    return
}

# ---------------------------------------------------------------------
# Console table
# ---------------------------------------------------------------------
foreach ($res in $results) {
    Write-Host ('Target: {0}' -f $res.Target) -ForegroundColor Cyan
    $fmt = '  {0,-22} {1,5} {2,-4} {3,-26} {4,6}  {5}'
    Write-Host ($fmt -f 'Service', 'Port', 'Prot', 'State', 'ms', 'Detail') -ForegroundColor DarkGray

    foreach ($p in $res.Ports) {
        $colour = 'Yellow'
        if ($p.State -eq 'Open') { $colour = 'Green' }
        elseif ($p.State -eq 'Responded') { $colour = if ($p.Detail -like '*lossy*') { 'Yellow' } else { 'Green' } }
        elseif ($p.State -eq 'Not probed') { $colour = 'DarkGray' }
        elseif ($p.State -like 'Closed*' -or $p.State -like 'Filtered*' -or $p.State -eq 'Error') { $colour = 'Red' }
        $msTxt = '-'
        if ($null -ne $p.Ms) { $msTxt = $p.Ms }
        $detailTxt = ''
        if ($p.Detail) { $detailTxt = $p.Detail }
        Write-Host ($fmt -f $p.Name, $p.Port, $p.Proto, $p.State, $msTxt, $detailTxt) -ForegroundColor $colour
    }

    Write-Host ('  RPC dynamic: {0}' -f $res.RpcNote) -ForegroundColor DarkGray
    foreach ($rp in $res.RpcPorts) {
        $colour = if ($rp.State -eq 'Open') { 'Green' } else { 'Red' }
        Write-Host ('    port {0,-6} {1}' -f $rp.Port, $rp.State) -ForegroundColor $colour
    }
    if ($res.RpcDetail) {
        $rc = switch ($res.RpcReach) { 'Reachable' { 'Green' } 'Unreachable' { 'Red' } default { 'Yellow' } }
        Write-Host ('    {0}' -f $res.RpcDetail) -ForegroundColor $rc
    }
    Write-Host ''
}

Write-Host 'A single run only shows "reachable from here". Run this from another segment' -ForegroundColor DarkGray
Write-Host 'against the same targets and compare both files with Compare-SegmentProbes.ps1' -ForegroundColor DarkGray
Write-Host 'to find ports that behave differently depending on where the probe ran from.' -ForegroundColor DarkGray
Write-Host ''
