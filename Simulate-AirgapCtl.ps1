<#
.SYNOPSIS
    Reproduces, in a lab and reversibly, the isolated-network CTL-fetch timeout -
    the classic cause of slow first LDAPS binds - by blocking the client's path
    to ctldl.windowsupdate.com, then runs Test-LdapsCtl -Capture and restores.

.DESCRIPTION
    During the TLS handshake the client (via CryptSvc/WinHTTP) fetches the
    Certificate Trust List from ctldl.windowsupdate.com over HTTP. On an isolated
    network those packets are silently dropped, so WinHTTP waits out its timeout,
    then caches - the slow first bind.

    To reproduce the hang the traffic must be silently dropped. This adds two
    Windows Firewall rules (silent drop):
      - outbound TCP 80/443 (the web ports the CTL/CDP fetch uses), and
      - outbound to ctldl's currently resolved IPs and their /24 (covers CDN
        rotation and any non-80/443 case).
    Kerberos (88), LDAP/LDAPS (389/636), SMB (445) and DNS (53) are untouched, so
    the DC stays reachable and the bind itself still works.

    It waits for the rules to propagate and VERIFIES the block actually took
    before running the diagnostic - if some endpoint-protection/proxy layer
    filters outbound traffic ahead of the Windows firewall, the rule has no
    effect and the script says so instead of producing a misleading result. In
    that case reproduce on an isolated VM (internal vSwitch to the DC, no internet
    route) or on-site, where the air gap is real.

    Rules are removed in a finally block; -Restore removes a kept block.

    IMPORTANT: for the duration of the test this client cannot reach the blocked
    hosts/ports. Lab use only; the DC and DNS must be reachable without internet.

.PARAMETER DC
    Domain controller to run the LDAPS diagnostic against (FQDN recommended).

.PARAMETER KeepBlocked
    Leave the block in place after the run. Remove it later with -Restore.

.PARAMETER Restore
    Only remove a block left by a previous -KeepBlocked run, then exit.

.EXAMPLE
    .\Simulate-AirgapCtl.ps1 -DC dc01.example.com

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
    foreach ($n in $ruleName, "$ruleName-ip") {
        try { Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue } catch { }
    }
}

function Test-Tcp($Server, $Port, $TimeoutMs) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($Server, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $c.EndConnect($iar); $true
    } catch { $false } finally { $c.Close() }
}

function Add-Block {
    Remove-Block

    # Resolve ctldl first (DNS = port 53, not blocked), then block its IPs + /24.
    $ips = @()
    try { $ips = @([Net.Dns]::GetHostAddresses($ctlHost) |
                   Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                   ForEach-Object { $_.IPAddressToString }) } catch { }
    $nets = @($ips | ForEach-Object { $_ -replace '\.\d+$', '.0/24' } | Select-Object -Unique)

    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block `
        -Protocol TCP -RemotePort 80,443 -Profile Any -ErrorAction SilentlyContinue | Out-Null
    if ($nets.Count -gt 0) {
        New-NetFirewallRule -DisplayName "$ruleName-ip" -Direction Outbound -Action Block `
            -RemoteAddress $nets -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }

    Start-Sleep -Seconds 2                      # let the rules propagate
    & ipconfig /flushdns *> $null
    & certutil -urlcache ctl delete *> $null
    & certutil -urlcache crl delete *> $null

    return ,$nets
}

# ---------------------------------------------------------------------
# -Restore
# ---------------------------------------------------------------------
if ($Restore) {
    Write-Host ''
    Write-Host 'Removing any AZITC air-gap simulation firewall rules...' -ForegroundColor Cyan
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
Write-Host ' Air-gap CTL simulation  (LAB ONLY - blocks ctldl path)' -ForegroundColor Magenta
Write-Host '=============================================================' -ForegroundColor Magenta

try {
    $nets = Add-Block
    Write-Host ('  Blocked: outbound TCP 80/443 + ctldl nets [{0}]' -f ($nets -join ', ')) -ForegroundColor Cyan

    # Verify the block actually took (try both 80 and 443).
    $r80  = Test-Tcp $ctlHost 80  3000
    $r443 = Test-Tcp $ctlHost 443 3000
    $blocked = (-not $r80) -and (-not $r443)
    Write-Host ('  {0} reachable now? 80={1} 443={2}' -f $ctlHost,
        $(if ($r80) { 'YES' } else { 'no' }), $(if ($r443) { 'YES' } else { 'no' })) `
        -ForegroundColor $(if ($blocked) { 'Green' } else { 'Red' })
    Write-Host ''

    if (-not $blocked) {
        Write-Host '  => The block did NOT take although the Windows firewall is on and the' -ForegroundColor Red
        Write-Host '     rules were created. An endpoint-protection/EDR or proxy layer is' -ForegroundColor Red
        Write-Host '     filtering outbound traffic ahead of the Windows firewall. The red' -ForegroundColor Red
        Write-Host '     path cannot be simulated on this client - use an isolated VM' -ForegroundColor Red
        Write-Host '     (internal vSwitch to the DC, no internet route) or validate on-site.' -ForegroundColor Red
        return
    }

    $ctlScript = Join-Path $PSScriptRoot 'Test-LdapsCtl.ps1'
    if (Test-Path $ctlScript) {
        Write-Host 'ctldl is now unreachable. Running Test-LdapsCtl -Capture...' -ForegroundColor Cyan
        Write-Host '(expect: section B unreachable, section D cold bind slow + CAPI2 Event 53)' -ForegroundColor DarkGray
        & $ctlScript -DC $DC -Capture
    }
    else {
        Write-Host ('Test-LdapsCtl.ps1 not found next to this script ({0}).' -f $PSScriptRoot) -ForegroundColor Yellow
        Write-Host 'The block is in place - run your LDAPS measurement now, then -Restore.' -ForegroundColor Yellow
        $KeepBlocked = $true
    }
}
finally {
    if ($KeepBlocked) {
        Write-Host ''
        Write-Host ('Block LEFT IN PLACE (-KeepBlocked). Undo with:  .\{0} -Restore' -f (Split-Path $PSCommandPath -Leaf)) -ForegroundColor Yellow
    }
    else {
        Write-Host ''
        Write-Host 'Removing the firewall rules...' -ForegroundColor Cyan
        Remove-Block
        Start-Sleep -Seconds 1
        $still = Test-Tcp $ctlHost 80 3000
        Write-Host ('  {0} reachable again? {1}' -f $ctlHost,
            $(if ($still) { 'yes - restored' } else { 'NO - remove rules "' + $ruleName + '*" manually!' })) `
            -ForegroundColor $(if ($still) { 'Green' } else { 'Red' })
    }
    Write-Host ''
}
