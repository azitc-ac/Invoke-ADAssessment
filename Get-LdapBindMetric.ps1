<#
.SYNOPSIS
    Slim LDAP/LDAPS bind-time probe for Zabbix. Returns {DC, LDAP, LDAPS} in ms
    (-1 = failed). No -UserName -> binds as the current identity (gMSA/MACHINE$);
    with -UserName -> Negotiate + NetworkCredential. -Json for a Zabbix master item.
.NOTES
    AZITC - Alexander Zarenko IT Consulting. PowerShell 5.1, read-only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $DC,
    [string] $UserName,
    [string] $Password,
    [switch] $Json,
    [int]    $ProbeMs    = 2000,
    [int]    $TimeoutSec = 15
)

Add-Type -AssemblyName System.DirectoryServices.Protocols
$ns = 'System.DirectoryServices.Protocols'

$cred = $null
if ($UserName) {
    $u, $d = $UserName, $null
    if     ($UserName -match '^(.+)\\(.+)$') { $d, $u = $Matches[1], $Matches[2] }
    elseif ($UserName -match '^(.+)@(.+)$')  { $u, $d = $Matches[1], $Matches[2] }
    $cred = New-Object Net.NetworkCredential($u, $Password, $d)
}

# TCP pre-flight: a dead DC would otherwise hit the ~21 s OS SYN timeout.
function Test-Port($Server, $Port) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($Server, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($ProbeMs, $false)) { return $false }
        $c.EndConnect($iar); $true          # throws on refused/no route -> $false
    }
    catch { $false }
    finally { $c.Close() }
}

# One bind. Returns ms, or -1 on failure.
function Measure-Bind($Server, $Port) {
    $conn = $null
    try {
        $id   = New-Object "$ns.LdapDirectoryIdentifier" $Server, $Port
        $conn = New-Object "$ns.LdapConnection" $id
        $conn.SessionOptions.SecureSocketLayer = ($Port -eq 636)
        $conn.SessionOptions.ProtocolVersion   = 3
        $conn.AuthType                         = 'Negotiate'
        $conn.Timeout                          = [timespan]::FromSeconds($TimeoutSec)
        # Offer no client cert -> no smartcard/PIN dialog on the LDAPS handshake.
        $conn.SessionOptions.QueryClientCertificate = { param($x, $ca) $null }
        if ($cred) { $conn.Credential = $cred }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $conn.Bind()
        [int]$sw.ElapsedMilliseconds
    }
    catch { -1 }
    finally { if ($conn) { $conn.Dispose() } }
}

$out = [pscustomobject]@{
    DC    = $DC
    LDAP  = if (Test-Port $DC 389) { Measure-Bind $DC 389 } else { -1 }
    LDAPS = if (Test-Port $DC 636) { Measure-Bind $DC 636 } else { -1 }
}

if ($Json) { $out | ConvertTo-Json -Compress } else { $out }
