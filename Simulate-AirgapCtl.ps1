<#
.SYNOPSIS
    Reproduces, in a lab and reversibly, the isolated-network CTL-fetch timeout -
    the classic cause of slow first LDAPS binds - by blocking the client's
    outbound HTTP(S), then runs Test-LdapsCtl -Capture and restores.

.DESCRIPTION
    During the TLS handshake the client (via CryptSvc/WinHTTP) fetches the
    Certificate Trust List from ctldl.windowsupdate.com over HTTP. On an isolated
    network those packets are silently dropped, so WinHTTP waits out its ~15 s
    timeout, then caches - the slow first bind.

    To reproduce the *hang* (not a fast failure) the traffic must be silently
    dropped. This adds a Windows Firewall rule that BLOCKS outbound TCP 80 and
    443 (silent drop = the real hang). That is enough and clean because:
      - the CTL fetch and HTTP CDP/OCSP go over 80/443 -> blocked -> they hang;
      - Kerberos (88), LDAP/LDAPS (389/636), SMB (445) and DNS (53) are NOT on
        80/443, so the DC stays reachable and the bind itself still works.

    This replaces an earlier hosts-file approach: redirecting a windowsupdate.com
    name in the hosts file is the malware signature SettingsModifier:
    Win32/HostsFileHijack and Microsoft Defender blocks it. A firewall rule is
    not flagged, needs no IP list (CDN IPs rotate), and is cleanly reversible.

    The firewall rule is removed in a finally block, so an error or Ctrl-C still
    restores connectivity. -Restore removes a rule left by -KeepBlocked.

    IMPORTANT: for the few seconds of the test this client cannot reach any
    HTTP/HTTPS site. Run it on a LAB client, not a production box, and only where
    the DC and DNS are reachable without the internet (same subnet).

.PARAMETER DC
    Domain controller to run the LDAPS diagnostic against (FQDN recommended).

.PARAMETER KeepBlocked
    Leave the block in place after the run (for manual testing). Remove it later
    with -Restore.

.PARAMETER Restore
    Only remove a block left by a previous -KeepBlocked run, then exit.

.EXAMPLE
    .\Simulate-AirgapCtl.ps1 -DC dc01.example.com

.EXAMPLE
    .\Simulate-AirgapCtl.ps1 -DC dc01.example.com -KeepBlocked
    .\Simulate-AirgapCtl.ps1 -Restore

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible. Needs admin. Lab use only.
#>
[CmdletBinding()]
param(
    [string] $DC,
    [switch] $KeepBlocked,
    [switch] $Restore
)

$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false

$ctlHost  = 'ctldl.windowsupdate.com'
$ruleName = 'AZITC-Sim-Airgap-CTL'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host 'This needs admin rights (firewall). Elevate and retry.' -ForegroundColor Red
    return
}

function Remove-Block {
    try { Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue } catch { }
}

function Add-Block {
    Remove-Block
    # Silent drop of outbound web, so the CTL/CDP fetch hangs in its timeout.
    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block `
        -Protocol TCP -RemotePort 80,443 -Profile Any -ErrorAction Stop | Out-Null
    & ipconfig /flushdns *> $null
    & certutil -urlcache ctl delete *> $null
    & certutil -urlcache crl delete *> $null
}

function Test-Tcp($Server, $Port, $TimeoutMs) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($Server, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $c.EndConnect($iar); $true
    } catch { $false } finally { $c.Close() }
}

# ---------------------------------------------------------------------
# -Restore: just tear down a previously kept block
# ---------------------------------------------------------------------
if ($Restore) {
    Write-Host ''
    Write-Host 'Removing any AZITC air-gap simulation firewall rule...' -ForegroundColor Cyan
    Remove-Block
    Write-Host '  Done.' -ForegroundColor Green
    Write-Host ''
    return
}

if (-not $DC) {
    Write-Host 'Specify -DC <domain controller> (or use -Restore to clean up).' -ForegroundColor Red
    return
}

Write-Host ''
Write-Host '=============================================================' -ForegroundColor Magenta
Write-Host ' Air-gap CTL simulation  (LAB ONLY - blocks outbound 80/443)' -ForegroundColor Magenta
Write-Host '=============================================================' -ForegroundColor Magenta

try {
    Add-Block
    Write-Host '  Outbound TCP 80/443 blocked (silent drop).' -ForegroundColor Cyan

    # Confirm the CTL path is now dead.
    $reachable = Test-Tcp $ctlHost 80 3000
    Write-Host ('  {0} reachable now? {1}' -f $ctlHost, $(if ($reachable) { 'YES - block did not take, check the firewall' } else { 'no (blocked as intended)' })) `
        -ForegroundColor $(if ($reachable) { 'Red' } else { 'Green' })
    Write-Host ''

    $ctlScript = Join-Path $PSScriptRoot 'Test-LdapsCtl.ps1'
    if (Test-Path $ctlScript) {
        Write-Host 'Running Test-LdapsCtl -Capture under the simulated air gap...' -ForegroundColor Cyan
        Write-Host '(expect: section B unreachable, section D cold bind in seconds + CAPI2 Event 53)' -ForegroundColor DarkGray
        & $ctlScript -DC $DC -Capture
    }
    else {
        Write-Host ('Test-LdapsCtl.ps1 not found next to this script ({0}).' -f $PSScriptRoot) -ForegroundColor Yellow
        Write-Host 'The block is in place - run your LDAPS measurement now, then re-run with -Restore.' -ForegroundColor Yellow
        $KeepBlocked = $true
    }
}
finally {
    if ($KeepBlocked) {
        Write-Host ''
        Write-Host ('Block LEFT IN PLACE (-KeepBlocked). Undo later with:  .\{0} -Restore' -f (Split-Path $PSCommandPath -Leaf)) -ForegroundColor Yellow
    }
    else {
        Write-Host ''
        Write-Host 'Removing the firewall rule...' -ForegroundColor Cyan
        Remove-Block
        $still = Test-Tcp $ctlHost 80 3000
        Write-Host ('  {0} reachable again? {1}' -f $ctlHost, $(if ($still) { 'yes - restored' } else { 'NO - remove rule "' + $ruleName + '" manually!' })) `
            -ForegroundColor $(if ($still) { 'Green' } else { 'Red' })
    }
    Write-Host ''
}
