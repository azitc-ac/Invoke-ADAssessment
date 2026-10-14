<#
.SYNOPSIS
    Reproduces, in a lab and reversibly, the air-gapped CTL-fetch timeout - the
    classic cause of slow first LDAPS binds in isolated networks: silently
    blackholes the client's path to
    ctldl.windowsupdate.com, clears the caches, runs Test-LdapsCtl -Capture
    against a DC, then restores everything.

.DESCRIPTION
    The slow first LDAPS bind is a soft-fail timeout: during the TLS handshake
    the client (via CryptSvc/WinHTTP) tries to fetch the Certificate Trust List
    from ctldl.windowsupdate.com; in an isolated network those packets are
    silently dropped, so WinHTTP waits out its ~15 s timeout, then caches.

    To reproduce the *hang* (not a fast failure) you must drop the traffic
    silently. This script does that two ways for determinism, independent of CDN
    IP rotation and of how the upstream router behaves:
      1. Pins ctldl.windowsupdate.com to a non-routable blackhole IP (hosts file).
      2. Adds an outbound Windows Firewall BLOCK rule for that IP (silent drop).

    Then it clears the CTL (and CRL) caches and runs the real diagnostic, so you
    see Test-LdapsCtl section B flip to "ctldl unreachable" and section D show the
    cold bind jump to seconds with a CAPI2 Event 53 (retrieval failed) - the red
    path that cannot be seen on an internet-connected machine.

    Everything is undone in a finally block, so an error or Ctrl-C still restores
    the hosts file and removes the firewall rule.

    IMPORTANT: this changes system state (hosts file, firewall) on the machine it
    runs on. Run it on a LAB CLIENT, not a production box, and only where the DC
    and DNS stay reachable without the internet (same subnet).

.PARAMETER DC
    Domain controller to run the LDAPS diagnostic against (FQDN recommended).

.PARAMETER BlackholeIp
    IP that ctldl is pinned to. Default 192.0.2.1 (TEST-NET-1, RFC 5737, never
    routable). The firewall rule drops traffic to it regardless.

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
    [string] $BlackholeIp = '192.0.2.1',
    [switch] $KeepBlocked,
    [switch] $Restore
)

$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false

$ctlHost   = 'ctldl.windowsupdate.com'
$hostsPath = Join-Path $env:windir 'System32\drivers\etc\hosts'
$marker    = '# AZITC-SIM-AIRGAP'
$ruleName  = 'AZITC-Sim-Airgap-CTL'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host 'This needs admin rights (hosts file + firewall). Elevate and retry.' -ForegroundColor Red
    return
}

function Remove-Block {
    # hosts: drop our marked lines
    try {
        $lines = [IO.File]::ReadAllLines($hostsPath)
        $kept  = $lines | Where-Object { $_ -notmatch [regex]::Escape($marker) }
        if ($kept.Count -ne $lines.Count) { [IO.File]::WriteAllLines($hostsPath, $kept) }
    } catch { Write-Host ('  hosts restore failed: {0}' -f $_.Exception.Message) -ForegroundColor Red }

    # firewall: drop our rule(s)
    try { Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue } catch { }

    & ipconfig /flushdns *> $null
}

function Add-Block {
    # hosts: pin ctldl -> blackhole (remove any stale marked line first)
    $lines = @()
    try { $lines = @([IO.File]::ReadAllLines($hostsPath)) } catch { }
    $lines = @($lines | Where-Object { $_ -notmatch [regex]::Escape($marker) })
    $lines += ("{0}`t{1}`t{2}" -f $BlackholeIp, $ctlHost, $marker)
    [IO.File]::WriteAllLines($hostsPath, $lines)

    # firewall: silently drop outbound to the blackhole IP
    try {
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block `
            -RemoteAddress $BlackholeIp -Profile Any -ErrorAction Stop | Out-Null
    } catch {
        Write-Host ('  firewall rule failed ({0}); relying on the blackhole route only.' -f $_.Exception.Message) -ForegroundColor Yellow
    }

    & ipconfig /flushdns *> $null
    & certutil -urlcache ctl delete *> $null
    & certutil -urlcache crl delete *> $null
}

# ---------------------------------------------------------------------
# -Restore: just tear down a previously kept block
# ---------------------------------------------------------------------
if ($Restore) {
    Write-Host ''
    Write-Host 'Removing any AZITC air-gap simulation block...' -ForegroundColor Cyan
    Remove-Block
    Write-Host '  Done. hosts and firewall restored.' -ForegroundColor Green
    Write-Host ''
    return
}

if (-not $DC) {
    Write-Host 'Specify -DC <domain controller> (or use -Restore to clean up).' -ForegroundColor Red
    return
}

function Test-Tcp($Server, $Port, $TimeoutMs) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($Server, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $c.EndConnect($iar); $true
    } catch { $false } finally { $c.Close() }
}

Write-Host ''
Write-Host '=============================================================' -ForegroundColor Magenta
Write-Host ' Air-gap CTL simulation  (LAB ONLY - modifies hosts/firewall)' -ForegroundColor Magenta
Write-Host '=============================================================' -ForegroundColor Magenta
Write-Host ('  Pinning {0} -> {1} and dropping outbound to it.' -f $ctlHost, $BlackholeIp) -ForegroundColor Cyan

try {
    Add-Block

    # Confirm the path is now dead (fast check, short timeout).
    $reachable = Test-Tcp $ctlHost 80 3000
    Write-Host ('  ctldl now reachable? {0}' -f $(if ($reachable) { 'YES (block did not take - check hosts/firewall)' } else { 'no (blackholed as intended)' })) `
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
        Write-Host 'Restoring hosts file and removing the firewall rule...' -ForegroundColor Cyan
        Remove-Block
        $still = Test-Tcp $ctlHost 80 3000
        Write-Host ('  ctldl reachable again? {0}' -f $(if ($still) { 'yes - restored' } else { 'NO - check hosts/firewall manually!' })) `
            -ForegroundColor $(if ($still) { 'Green' } else { 'Red' })
    }
    Write-Host ''
}
