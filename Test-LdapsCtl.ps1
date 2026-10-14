<#
.SYNOPSIS
    Proves (or rules out) the CTL engine as the cause of slow LDAPS binds: the
    Windows auto-update fetch of the Certificate Trust List from
    ctldl.windowsupdate.com, which in an isolated network runs into a ~15 s
    WinHTTP timeout during the TLS handshake and is then cached.

.DESCRIPTION
    This is the gap that Test-LdapsRevocation.ps1 does NOT cover: that script
    checks CDP/AIA/OCSP (revocation). The CTL/AuthRoot auto-update is a SEPARATE
    network path - revocation can be perfectly healthy while the CTL fetch is the
    real culprit.

    It gathers three independent pieces of evidence:

      A. Policy state (instant): is root-certificate auto-update even active?
         DisableRootAutoUpdate=1 -> the fetch never happens -> not the cause.
         A custom RootDirUrl -> an internal CTL source -> the permanent fix.

      B. Active reachability/timing probe to the ctldl.windowsupdate.com CTL
         URLs. Unreachable -> the engine will burn its full soft-fail timeout
         here, which is exactly the LDAPS delay. Fast -> not the cause (this is
         why the customer's DC2/DC3 are quick: they reach it or are configured
         out).

      C. -Capture (needs -DC, admin): the deterministic proof. Enables the CAPI2
         operational log, clears the CTL url cache to force a cold fetch, times
         one real LDAPS bind to -DC, then reads CAPI2 events for a ctldl fetch in
         that exact window and correlates it with the measured bind time.

.PARAMETER DC
    Domain controller for the -Capture LDAPS bind. Use the FQDN.

.PARAMETER Capture
    Run the automated CAPI2 capture (section C). Requires -DC and admin rights.

.PARAMETER TimeoutSec
    Per-URL HTTP timeout for the active probe (section B). Default 8.

.PARAMETER ProbeMs
    TCP pre-flight timeout for the active probe. Default 2000. A fast fail here
    already tells you ctldl is unreachable without waiting the full HTTP timeout.

.PARAMETER KeepCapi2
    Leave the CAPI2 operational log enabled afterwards (default: restore the
    previous state).

.EXAMPLE
    .\Test-LdapsCtl.ps1

.EXAMPLE
    .\Test-LdapsCtl.ps1 -DC dc01.example.com -Capture

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible.

    The DC validates its peer's LDAPS certificate in the SYSTEM context (lsass),
    which has its own CTL cache and proxy. A bind from THIS script runs in the
    current process context - self-consistent for reproducing the mechanism, but
    for the lsass view run elevated as SYSTEM:  psexec -s powershell.exe
#>
[CmdletBinding()]
param(
    [string] $DC,
    [switch] $Capture,
    [int]    $TimeoutSec = 8,
    [int]    $ProbeMs    = 2000,
    [switch] $KeepCapi2
)

$ctlUrls = @(
    'http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab'
    'http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab'
    'http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab'
)
$ctlHost = 'ctldl.windowsupdate.com'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# =====================================================================
# A. Policy state
# =====================================================================
Write-Host ''
Write-Host 'A. Root auto-update / CTL policy state' -ForegroundColor Cyan

function Get-RegVal($Path, $Name) {
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { $null }
}

$polKey  = 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot'
$autoKey = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate'

$disableRoot = Get-RegVal $polKey  'DisableRootAutoUpdate'
$disallowUpd = Get-RegVal $polKey  'EnableDisallowedCertAutoUpdate'
$rootDirUrl  = Get-RegVal $autoKey 'RootDirUrl'

$mechanismActive = ($disableRoot -ne 1)

Write-Host ('  DisableRootAutoUpdate        : {0}' -f $(if ($null -eq $disableRoot) { '(not set -> default: auto-update ON)' } else { $disableRoot }))
Write-Host ('  EnableDisallowedCertAutoUpdate: {0}' -f $(if ($null -eq $disallowUpd) { '(not set -> default: ON)' } else { $disallowUpd }))
Write-Host ('  RootDirUrl (internal source) : {0}' -f $(if ($rootDirUrl) { $rootDirUrl } else { '(not set -> uses ctldl.windowsupdate.com)' }))

if (-not $mechanismActive) {
    Write-Host '  => Root auto-update is DISABLED. The CTL fetch does not happen; LDAPS' -ForegroundColor Green
    Write-Host '     slowness would have another cause. (This is also the mitigation.)' -ForegroundColor Green
}
elseif ($rootDirUrl -and $rootDirUrl -notmatch 'windowsupdate\.com') {
    Write-Host '  => A custom internal CTL source is configured. Verify it is reachable.' -ForegroundColor Yellow
}
else {
    Write-Host '  => Auto-update is active against ctldl.windowsupdate.com (default).' -ForegroundColor Yellow
    Write-Host '     If that host is unreachable here, this is the LDAPS delay (section B).' -ForegroundColor Yellow
}

# =====================================================================
# B. Active reachability / timing probe to ctldl
# =====================================================================
Write-Host ''
Write-Host 'B. Reachability of the CTL distribution point' -ForegroundColor Cyan

function Test-Tcp($Server, $Port, $TimeoutMs) {
    $c = New-Object Net.Sockets.TcpClient
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $iar = $c.BeginConnect($Server, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return [pscustomobject]@{ Ok = $false; Ms = -1 } }
        $c.EndConnect($iar); $sw.Stop()
        [pscustomobject]@{ Ok = $true; Ms = [int]$sw.ElapsedMilliseconds }
    }
    catch { [pscustomobject]@{ Ok = $false; Ms = -1 } }
    finally { $c.Close() }
}

# Raw TLS handshake to a port, accepting any cert, to surface the EXACT reason a
# bind failed: protocol/cipher mismatch vs. a cert that was at least presented.
# SslStream gives a precise SChannel message where LdapConnection only says
# "server unavailable".
function Test-TlsHandshake($HostName, $Port, $TimeoutMs) {
    $r = [pscustomobject]@{ Ok = $false; Protocol = ''; Cipher = ''; CertSubject = ''; Error = '' }
    $client = New-Object Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { $r.Error = 'tcp connect timeout'; return $r }
        $client.EndConnect($iar)

        # Accept any cert (diagnostic) so the handshake completes and we can read
        # the negotiated protocol/cipher. The cert is read reliably afterwards
        # from RemoteCertificate (a $script: write from inside the delegate is not
        # reliable when SChannel invokes it off-thread).
        $cb  = [Net.Security.RemoteCertificateValidationCallback] { param($snd, $cert, $chain, $errors) return $true }
        $ssl = New-Object Net.Security.SslStream($client.GetStream(), $false, $cb)
        $ssl.AuthenticateAsClient($HostName)
        $r.Ok       = $true
        $r.Protocol = $ssl.SslProtocol.ToString()
        $r.Cipher   = $ssl.CipherAlgorithm.ToString()
        if ($ssl.RemoteCertificate) { $r.CertSubject = $ssl.RemoteCertificate.Subject }
        $ssl.Dispose()
    }
    catch {
        $r.Error = $_.Exception.Message
        if ($_.Exception.InnerException) { $r.Error = $_.Exception.InnerException.Message }
    }
    finally { $client.Close() }
    return $r
}

# DNS first - in an isolated net the name often still resolves (public CDN),
# so a resolve success with a connect failure is the classic air-gap signature.
$dnsOk = $false
try { [void][Net.Dns]::GetHostEntry($ctlHost); $dnsOk = $true } catch { $dnsOk = $false }
Write-Host ('  DNS resolve {0,-26}: {1}' -f $ctlHost, $(if ($dnsOk) { 'ok' } else { 'FAILED' })) `
           -ForegroundColor $(if ($dnsOk) { 'Green' } else { 'Yellow' })

$tcp = Test-Tcp $ctlHost 80 $ProbeMs
Write-Host ('  TCP 80      {0,-26}: {1}' -f $ctlHost, $(if ($tcp.Ok) { ('{0} ms' -f $tcp.Ms) } else { ('no connect within {0} ms' -f $ProbeMs) })) `
           -ForegroundColor $(if ($tcp.Ok) { 'Green' } else { 'Red' })

$fetchMs    = -1
$fetchState = 'skipped (no TCP)'
if ($tcp.Ok) {
    $url = $ctlUrls[0]
    try {
        $req = [Net.HttpWebRequest]::Create($url)
        $req.Timeout          = $TimeoutSec * 1000
        $req.Method           = 'GET'
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $resp = $req.GetResponse()
        $sw.Stop()
        $fetchMs    = [int]$sw.ElapsedMilliseconds
        $fetchState = ('HTTP {0}' -f [int]$resp.StatusCode)
        $resp.Close()
    }
    catch { $fetchState = 'fetch failed: ' + $_.Exception.Message }
    Write-Host ('  GET authrootstl.cab            : {0}{1}' -f $fetchState, $(if ($fetchMs -ge 0) { (' ({0} ms)' -f $fetchMs) } else { '' }))
}

$ctlReachable = $tcp.Ok
if (-not $ctlReachable -and $mechanismActive) {
    Write-Host '  => ctldl is unreachable AND auto-update is active. During an LDAPS' -ForegroundColor Red
    Write-Host '     handshake the CTL engine will wait out its full soft-fail timeout' -ForegroundColor Red
    Write-Host '     (~15 s on the first bind, then cached). This is the cause.' -ForegroundColor Red
}
elseif ($ctlReachable) {
    Write-Host '  => ctldl is reachable here, so the CTL fetch is not what slows LDAPS' -ForegroundColor Green
    Write-Host '     on this machine. (Compare with an affected, isolated DC.)' -ForegroundColor Green
}

# =====================================================================
# C. CTL cache state
# =====================================================================
Write-Host ''
Write-Host 'C. CTL url cache (what is already cached -> warm)' -ForegroundColor Cyan
$cache = & certutil -urlcache ctl 2>$null | Where-Object { $_ -match 'authroot|disallowed|pinrules|ctldl' }
if ($cache) { $cache | ForEach-Object { Write-Host ('  ' + $_.Trim()) -ForegroundColor DarkGray } }
else        { Write-Host '  (no CTL entries cached - the next validation will fetch = cold)' -ForegroundColor Yellow }

# =====================================================================
# D. Automated CAPI2 capture around a forced-cold LDAPS bind
# =====================================================================
if ($Capture) {

    Write-Host ''
    Write-Host 'D. CAPI2 capture around a cold LDAPS bind' -ForegroundColor Cyan

    if (-not $DC)     { Write-Host '  -Capture needs -DC. Skipping.' -ForegroundColor Red; return }
    if (-not $isAdmin){ Write-Host '  -Capture needs admin rights. Skipping.' -ForegroundColor Red; return }

    $log = 'Microsoft-Windows-CAPI2/Operational'

    $wasEnabled = $false
    try { $wasEnabled = [bool](Get-WinEvent -ListLog $log -ErrorAction Stop).IsEnabled } catch { }

    if (-not $wasEnabled) {
        Write-Host '  Enabling CAPI2 operational log...' -ForegroundColor DarkGray
        & wevtutil sl $log /e:true 2>$null
    }

    # Force cold: drop cached CTLs so the bind must fetch again.
    Write-Host '  Clearing CTL url cache (forces a cold fetch)...' -ForegroundColor DarkGray
    & certutil -urlcache ctl delete *> $null

    $winStart = Get-Date
    Start-Sleep -Milliseconds 300

    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $ns = 'System.DirectoryServices.Protocols'

    # Is the DC even listening on 636? Separates "LDAPS not configured / blocked"
    # from "TLS reached but cert rejected" when the bind fails.
    $dcFqdn = try { ([Net.Dns]::GetHostEntry($DC)).HostName } catch { $DC }
    $tcp636 = Test-Tcp $dcFqdn 636 $ProbeMs
    Write-Host ('  TCP 636 {0,-28}: {1}' -f $dcFqdn,
        $(if ($tcp636.Ok) { 'open ({0} ms)' -f $tcp636.Ms } else { 'no connect within {0} ms' -f $ProbeMs })) `
        -ForegroundColor $(if ($tcp636.Ok) { 'DarkGray' } else { 'Red' })

    $bindMs = -1
    $conn = $null
    try {
        $id   = New-Object "$ns.LdapDirectoryIdentifier" $dcFqdn, 636
        $conn = New-Object "$ns.LdapConnection" $id
        $conn.SessionOptions.SecureSocketLayer = $true
        $conn.SessionOptions.ProtocolVersion   = 3
        $conn.AuthType                         = 'Negotiate'
        $conn.Timeout                          = [timespan]::FromSeconds(30)
        $conn.SessionOptions.QueryClientCertificate = { param($x, $ca) $null }

        # Accept the server certificate so the handshake completes and the bind
        # time can be MEASURED - this is a diagnostic, not an authentication gate.
        # Without this, .NET rejects any cert doubt and throws ServerDown BEFORE
        # we learn anything. We record the chain's trust status offline
        # (RevocationMode=NoCheck, so no CRL fetch inflates the measured time) to
        # report WHY schannel would otherwise refuse. If this callback never fires
        # yet the bind fails, 636 is not doing TLS (LDAPS not configured / blocked).
        $script:certInfo = $null
        $conn.SessionOptions.VerifyServerCertificate = {
            param($connection, $certificate)
            try {
                $c2    = [Security.Cryptography.X509Certificates.X509Certificate2]$certificate
                $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
                $chain.ChainPolicy.RevocationMode = 'NoCheck'
                $built = $chain.Build($c2)
                $script:certInfo = [pscustomobject]@{
                    Subject = $c2.Subject
                    Built   = $built
                    Status  = (($chain.ChainStatus | ForEach-Object { $_.Status }) -join ',')
                }
            }
            catch {
                $script:certInfo = [pscustomobject]@{ Subject = ''; Built = $false; Status = ('callback error: ' + $_.Exception.Message) }
            }
            return $true
        }

        $sw = [Diagnostics.Stopwatch]::StartNew()
        $conn.Bind()
        $sw.Stop()
        $bindMs = [int]$sw.ElapsedMilliseconds
    }
    catch { Write-Host ('  LDAPS bind failed: {0}' -f $_.Exception.Message) -ForegroundColor Red }
    finally { if ($conn) { $conn.Dispose() } }

    Start-Sleep -Milliseconds 500

    if ($bindMs -ge 0) {
        $col = if ($bindMs -ge 2000) { 'Red' } elseif ($bindMs -ge 300) { 'Yellow' } else { 'Green' }
        Write-Host ('  Cold LDAPS bind to {0}: {1} ms' -f $dcFqdn, $bindMs) -ForegroundColor $col
    }

    if ($script:certInfo) {
        $st = if ($script:certInfo.Status) { $script:certInfo.Status } else { '(clean)' }
        $cc = if ($script:certInfo.Built) { 'DarkGray' } else { 'Yellow' }
        Write-Host ('  Server cert: {0}' -f $script:certInfo.Subject) -ForegroundColor DarkGray
        Write-Host ('  Cert chain : built={0}, status={1}' -f $script:certInfo.Built, $st) -ForegroundColor $cc
        if (-not $script:certInfo.Built) {
            Write-Host '  => schannel would reject this cert by default - that was the earlier' -ForegroundColor Yellow
            Write-Host '     "server unavailable". Fix the chain (trust/validity), then LDAPS works.' -ForegroundColor Yellow
        }
    }
    elseif ($bindMs -lt 0) {
        if (-not $tcp636.Ok) {
            Write-Host '  => 636 is not listening (TCP failed): LDAPS is not configured on this DC' -ForegroundColor Yellow
            Write-Host '     (no Server-Authentication certificate installed) or the port is blocked.' -ForegroundColor Yellow
        }
        else {
            # 636 is open but LdapConnection failed - do a raw TLS handshake to
            # find out exactly why (SChannel gives a precise message).
            $tls = Test-TlsHandshake $dcFqdn 636 ($ProbeMs * 3)
            if ($tls.Ok) {
                Write-Host ('  Raw TLS handshake OK: {0}, cipher {1}' -f $tls.Protocol, $tls.Cipher) -ForegroundColor DarkGray
                if ($tls.CertSubject) { Write-Host ('  Server cert: {0}' -f $tls.CertSubject) -ForegroundColor DarkGray }
                Write-Host '  => TLS itself works; the failure is above TLS (LDAP/auth layer).' -ForegroundColor Yellow
                Write-Host '     Check the DC Directory-Services / Schannel event logs and ldp.exe.' -ForegroundColor Yellow
            }
            else {
                Write-Host ('  Raw TLS handshake FAILED: {0}' -f $tls.Error) -ForegroundColor Red
                if ($tls.CertSubject) { Write-Host ('  (server cert was presented: {0})' -f $tls.CertSubject) -ForegroundColor DarkGray }
                Write-Host '  => The TLS layer itself cannot negotiate - protocol/cipher mismatch' -ForegroundColor Red
                Write-Host '     between this client and the DC. Compare enabled TLS versions and' -ForegroundColor Red
                Write-Host '     cipher suites (e.g. gpedit / registry SChannel) on both sides.' -ForegroundColor Red
            }
        }
    }

    # Read CAPI2 events in the capture window that touch ctldl.
    $events = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $winStart } -ErrorAction Stop
    } catch { }

    # Keep only events that actually touch the CTL distribution point. Matching
    # the ctldl host (not "authroot") excludes the periodic "X509 Objects" dump,
    # which merely lists the AuthRoot certificate and is not a network fetch.
    $ctlEvents = $events | Where-Object { $_.Message -match 'ctldl\.windowsupdate\.com' }

    Write-Host ''
    if ($ctlEvents) {
        Write-Host '  CTL fetches logged during the bind:' -ForegroundColor Cyan
        foreach ($e in $ctlEvents) {
            $url    = ([regex]::Match($e.Message, 'http://ctldl\.windowsupdate\.com\S*')).Value -replace '.*trustedr/', '.../'
            $failed = ($e.LevelDisplayName -eq 'Error' -or $e.Id -eq 53)
            $col    = if ($failed) { 'Red' } else { 'DarkGray' }
            Write-Host ('  [{0}] Id {1,-3} {2,-7} {3}' -f $e.TimeCreated.ToString('HH:mm:ss.fff'), $e.Id, $e.LevelDisplayName, $url) -ForegroundColor $col
        }
        $capiFail = @($ctlEvents | Where-Object { $_.LevelDisplayName -eq 'Error' -or $_.Id -eq 53 })
        Write-Host ''
        if ($capiFail.Count -gt 0) {
            Write-Host '  => A CTL fetch FAILED during the handshake = this is what the bind waited' -ForegroundColor Red
            Write-Host '     on (soft-fail timeout). Proof complete.' -ForegroundColor Red
        }
        else {
            Write-Host '  => CTL fetch(es) occurred but succeeded here (reachable). On an isolated' -ForegroundColor Yellow
            Write-Host '     DC these same fetches time out - that is the delay.' -ForegroundColor Yellow
        }
    }
    else {
        Write-Host '  No CTL fetch to ctldl logged during the bind (cached, or not the cause).' -ForegroundColor Green
    }

    # Restore CAPI2 state.
    if (-not $wasEnabled -and -not $KeepCapi2) {
        Write-Host ''
        Write-Host '  Restoring CAPI2 operational log to disabled...' -ForegroundColor DarkGray
        & wevtutil sl $log /e:false 2>$null
    }
}

Write-Host ''
