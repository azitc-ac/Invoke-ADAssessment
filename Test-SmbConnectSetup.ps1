<#
.SYNOPSIS
    Measures SMB/CIFS connection setup against one or more servers and reports,
    per server, how long it takes cold vs. warm and whether Kerberos or an NTLM
    fallback was used.

.DESCRIPTION
    Active, deterministic probe - no broad trace needed. For each server it:

      1. Removes any existing session to the target (so "cold" is really cold).
      2. Purges the current Kerberos ticket cache (unless -KeepTickets), so a
         fresh TGS must be requested. This is what makes the first access slow.
      3. Measures a bare TCP connect to 445 (DNS + TCP only).
      4. Measures the full connect via WNetAddConnection2 (DNS + TCP + SMB
         negotiate + session setup/auth + tree connect) = COLD.
      5. Reads 'klist': a fresh cifs/<server> (or host/<server>) ticket means
         Kerberos was used. Detection is locale-proof - it matches the SPN
         value, not the (localised) field labels.
      6. Repeats the connect with the ticket now cached = WARM.

    Interpretation:
      Cold ~ Warm, both fast        -> healthy
      Cold >> Warm (large delta)    -> first-contact / TGS acquisition is slow,
                                       i.e. the KDC/DC that issues the ticket is
                                       slow (same DC group as slow LDAP 389?)
      both slow                     -> server/network path, not a cold-cache effect
      success but no Kerberos ticket-> NTLM fallback (silent - explains why users
                                       never raise a CIFS ticket)

    Why this and not netsh trace: the signals here are deterministic and need no
    post-processing. Use a trace only when this points somewhere that needs the
    packet/ETW detail.

.PARAMETER Server
    One or more servers (short name or FQDN) to probe.

.PARAMETER Share
    Share to tree-connect to. Default 'IPC$' - always present and exercises the
    auth path without needing share permissions. Pass a real (or DFS) share name
    to include share ACL / DFS referral in the measurement.

.PARAMETER Repeat
    Warm measurements; the best (lowest) is reported. Default 3. Cold is always
    a single shot (it is only cold once per purge).

.PARAMETER SlowMs
    Connect time (ms) from which a bind counts as slow. Default 300.

.PARAMETER DeltaMs
    Cold-minus-warm difference (ms) from which the first-contact path is flagged
    as the dominant cost. Default 200.

.PARAMETER ProbeMs
    TCP pre-flight timeout in ms. Default 2000.

.PARAMETER KeepTickets
    Do not purge the Kerberos cache. "Cold" then reflects an already-cached
    ticket - use only if purging the current session is undesirable.

.PARAMETER Json
    Emit compact JSON (one object per server) instead of console output.

.EXAMPLE
    .\Test-SmbConnectSetup.ps1 -Server dc08,dc02

.EXAMPLE
    .\Test-SmbConnectSetup.ps1 -Server fileserver01 -Share Data -Verbose

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible. Read-only (maps and immediately releases).

    Run as the USER whose access you want to characterise - the probe measures
    that logon session's tickets and credentials. The NTLM-fallback confirmation
    via the operational log needs that log enabled and admin rights; without it
    the probe still infers NTLM from "connected without a Kerberos ticket".
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]] $Server,
    [string] $Share       = 'IPC$',
    [int]    $Repeat      = 3,
    [int]    $SlowMs      = 300,
    [int]    $DeltaMs     = 200,
    [int]    $ProbeMs     = 2000,
    [switch] $KeepTickets,
    [switch] $Json
)

# Establish the session through the SMB redirector via net.exe - exactly the
# path a real user/app takes. (WNetAddConnection2 was tried first but returns
# ERROR_BAD_NET_NAME under the MPR on non-domain-joined / AAD-joined clients,
# while net use and the redirector work - so the API would mis-measure reality.)
# The ~40 ms process overhead is negligible against the signal we look for
# (hundreds of ms to ~15 s). Win32 error codes are parsed from "System error N".
function Connect-Share([string] $Remote) {
    $sw  = [Diagnostics.Stopwatch]::StartNew()
    $out = & net.exe use $Remote 2>&1
    $sw.Stop()
    $code = 0
    if ($LASTEXITCODE -ne 0) {
        $txt = ($out | Out-String)
        if ($txt -match '(?i)(?:system\s*error|systemfehler)\s+(\d+)') { $code = [int]$Matches[1] }
        else { $code = if ($LASTEXITCODE) { $LASTEXITCODE } else { -1 } }
    }
    [pscustomobject]@{ Ms = [int]$sw.ElapsedMilliseconds; Code = $code; Text = ($out | Out-String).Trim() }
}

function Disconnect-Share([string] $Remote) {
    & net.exe use $Remote /delete /y 2>&1 | Out-Null
}

# Bare TCP connect to 445 (DNS + TCP). Lets us separate network from auth cost.
function Measure-Tcp([string] $Host445) {
    $c = New-Object Net.Sockets.TcpClient
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $iar = $c.BeginConnect($Host445, 445, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($ProbeMs, $false)) { return -1 }
        $c.EndConnect($iar); $sw.Stop()
        [int]$sw.ElapsedMilliseconds
    }
    catch { -1 }
    finally { $c.Close() }
}

# Locale-proof: match the SPN value (cifs/host/ldap), never the field labels.
# Returns the SPNs for the target plus the encryption type, if found.
function Get-TargetTicket([string] $Short, [string] $Fqdn) {
    $lines = & klist 2>$null
    $hit   = $null
    $enc   = $null
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '\b(cifs|host|ldap)/([^\s@]+)') {
            $spn = $Matches[0]
            if ($spn -match [regex]::Escape($Short) -or ($Fqdn -and $spn -match [regex]::Escape($Fqdn))) {
                $hit = $spn
                # Encryption type value is not localised (AES256/AES128/RC4/DES)
                for ($j = $i; $j -lt [math]::Min($i + 5, $lines.Count); $j++) {
                    if ($lines[$j] -match '(AES-?256|AES-?128|RC4|DES-CBC-\w+|DES)') { $enc = $Matches[1]; break }
                }
                break
            }
        }
    }
    [pscustomobject]@{ Spn = $hit; Enc = $enc }
}

function Resolve-Fqdn([string] $Name) {
    try { ([Net.Dns]::GetHostEntry($Name)).HostName } catch { $Name }
}

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$results = @()

foreach ($srv in $Server) {

    $fqdn   = Resolve-Fqdn $srv
    $target = '\\{0}\{1}' -f $srv, $Share

    Write-Verbose ("Probing {0} ..." -f $target)

    # Clean slate: drop target + IPC$ sessions so the cold measurement is cold.
    Disconnect-Share $target
    Disconnect-Share ('\\{0}\IPC$' -f $srv)
    if (-not $KeepTickets) { & klist purge *> $null }

    $probeStart = Get-Date

    $tcpMs = Measure-Tcp $srv

    # --- COLD -------------------------------------------------------------
    $cold = Connect-Share $target
    $tkt  = Get-TargetTicket $srv $fqdn

    # --- WARM (ticket now cached) ----------------------------------------
    $warmMs = -1
    if ($cold.Code -eq 0) {
        for ($n = 1; $n -le $Repeat; $n++) {
            Disconnect-Share $target
            $w = Connect-Share $target
            if ($w.Code -ne 0) { break }
            if ($warmMs -lt 0 -or $w.Ms -lt $warmMs) { $warmMs = $w.Ms }
        }
    }

    # --- NTLM confirmation (best effort; log is often disabled) -----------
    $ntlm = $false
    if ($cold.Code -eq 0 -and -not $tkt.Spn) {
        try {
            $ev = Get-WinEvent -FilterHashtable @{
                      LogName   = 'Microsoft-Windows-NTLM/Operational'
                      StartTime = $probeStart
                  } -ErrorAction Stop
            if ($ev | Where-Object { $_.Message -match [regex]::Escape($srv) -or $_.Message -match [regex]::Escape($fqdn) }) {
                $ntlm = $true
            }
        } catch { }
    }

    Disconnect-Share $target   # leave the environment as found

    # --- Classify ---------------------------------------------------------
    if     ($cold.Code -ne 0)  { $auth = '-' }
    elseif ($tkt.Spn)          { $auth = 'Kerberos' }
    elseif ($ntlm)             { $auth = 'NTLM' }
    else                       { $auth = 'NTLM?' }     # connected, no Kerberos ticket, log unavailable

    $errText = ''
    if ($cold.Code -ne 0) {
        if ($cold.Code -gt 0) { $errText = (New-Object ComponentModel.Win32Exception([int]$cold.Code)).Message }
        if (-not $errText)    { $errText = ($cold.Text -split "`r?`n" | Where-Object { $_ } | Select-Object -Last 1) }
    }

    $delta = -1
    if ($cold.Code -eq 0 -and $warmMs -ge 0) { $delta = $cold.Ms - $warmMs }

    $results += [pscustomobject]@{
        Server   = $srv
        Share    = $Share
        TcpMs    = $tcpMs
        ColdMs   = if ($cold.Code -eq 0) { $cold.Ms } else { -1 }
        WarmMs   = $warmMs
        DeltaMs  = $delta
        Auth     = $auth
        Spn      = $tkt.Spn
        EncType  = $tkt.Enc
        Win32    = $cold.Code
        Error    = $errText
    }
}

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
if ($Json) {
    $results | ConvertTo-Json -Compress
    return
}

Write-Host ''
if (-not $isAdmin) {
    Write-Host '  (not elevated - NTLM confirmation via the operational log is skipped)' -ForegroundColor DarkGray
}
$fmt = '  {0,-20} {1,7} {2,7} {3,7} {4,7}   {5,-9} {6}'
Write-Host ($fmt -f 'Server', 'TCP', 'Cold', 'Warm', 'Delta', 'Auth', 'Assessment') -ForegroundColor Cyan
Write-Host ('  ' + ('-' * 92)) -ForegroundColor DarkGray

foreach ($r in $results) {

    $f = { param($v) if ($v -ge 0) { '{0} ms' -f $v } else { '-' } }

    if ($r.Win32 -ne 0) {
        $verdict = 'connect failed: ' + $r.Error.Trim()
        $colour  = 'Red'
    }
    elseif ($r.Auth -like 'NTLM*') {
        $verdict = 'NTLM fallback - no Kerberos ticket (check SPN / DNS / time skew)'
        $colour  = 'Red'
    }
    elseif ($r.ColdMs -ge $SlowMs -and $r.WarmMs -ge $SlowMs) {
        $verdict = 'both slow -> server/network path, not a cold-cache effect'
        $colour  = 'Yellow'
    }
    elseif ($r.DeltaMs -ge $DeltaMs) {
        $verdict = ('first-contact/TGS slow (~{0} ms) -> KDC/DC latency' -f $r.DeltaMs)
        $colour  = 'Yellow'
    }
    else {
        $verdict = 'ok'
        $colour  = 'Green'
    }

    $encNote = ''
    if ($r.EncType -match 'RC4|DES') { $encNote = ' [' + $r.EncType + ']' }

    Write-Host ($fmt -f $r.Server,
                        (& $f $r.TcpMs), (& $f $r.ColdMs), (& $f $r.WarmMs), (& $f $r.DeltaMs),
                        ($r.Auth + $encNote), $verdict) -ForegroundColor $colour
}

Write-Host ''

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------
$failed   = @($results | Where-Object { $_.Win32 -ne 0 })
$ok       = @($results | Where-Object { $_.Win32 -eq 0 })
$ntlmHits = @($ok | Where-Object { $_.Auth -like 'NTLM*' })
$tgsSlow  = @($ok | Where-Object { $_.DeltaMs -ge $DeltaMs })

if ($failed.Count -gt 0) {
    Write-Host ('  {0} of {1} server(s) could not be connected - see the rows above.' -f $failed.Count, $results.Count) -ForegroundColor Red
    Write-Host '  A failed connect is a reachability/name/permission issue, not a latency one.' -ForegroundColor Red
    Write-Host ''
}

if ($ntlmHits.Count -gt 0) {
    Write-Host ('  {0} server(s) authenticated WITHOUT a Kerberos ticket (NTLM path).' -f $ntlmHits.Count) -ForegroundColor Red
    Write-Host '  This succeeds silently, which is why no CIFS service tickets are raised.' -ForegroundColor Red
    Write-Host '  Check: SPN registration (setspn -L), DNS of the target, and time skew.' -ForegroundColor Red
}
elseif ($tgsSlow.Count -gt 0) {
    Write-Host ('  {0} server(s): the cost is the first contact, not steady state.' -f $tgsSlow.Count) -ForegroundColor Yellow
    Write-Host '  Kerberos works; the delay is acquiring the ticket from the KDC. Compare' -ForegroundColor Yellow
    Write-Host '  against the slow LDAP-389 group - likely the same DCs.' -ForegroundColor Yellow
}
elseif ($ok.Count -gt 0) {
    Write-Host '  SMB connection setup is healthy (Kerberos, no slow first contact).' -ForegroundColor Green
}

Write-Host ''
