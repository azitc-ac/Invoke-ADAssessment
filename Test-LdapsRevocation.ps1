<#
.SYNOPSIS
    Checks the revocation (CDP/AIA/OCSP) health of a DC's LDAPS certificate chain
    and prints a per-URL, per-tier verdict - from the perspective of the machine
    it runs on, which is the perspective that matters for a slow client bind.

.DESCRIPTION
    A slow first LDAPS bind that then goes fast is the signature of a revocation
    fetch that times out (soft-fail) and is then cached. The fetch is done by the
    CLIENT validating the DC's certificate, so where you measure matters: the
    client and the DC can have different network paths to an HTTP CDP.

    -DC grabs the target DC's LDAPS certificate over the wire and verifies it FROM
    THIS MACHINE - use this from an affected client (it also works on a machine
    with no server certificate of its own, and it covers the DC's own view too).
    Without -DC it verifies this machine's local Server-Authentication cert (run
    it on the affected DC).

    It runs 'certutil -urlfetch -verify' and reports, per fetched URL:
      - the chain tier it belongs to (Root / Issuing), best-effort from the URL
      - the protocol (LDAP = in AD, reachable everywhere; HTTP = a specific
        server, reachability depends on location)
      - the fetch duration (ms) and status
      - CRL validity (NextUpdate) per tier - an expired offline-root CRL is a
        classic two-tier failure.

    The raw certutil output is written to a log file.

.PARAMETER DC
    Target DC. Its LDAPS cert is fetched over 636 and verified from this machine.

.PARAMETER SlowMs
    Fetch duration (ms) from which a URL counts as slow. Default 300.

.PARAMETER ShowCache
    Also display the CRL cache and offer to clear it (to force a fresh fetch).

.EXAMPLE
    .\Test-LdapsRevocation.ps1 -DC dc01.example.com

.EXAMPLE
    .\Test-LdapsRevocation.ps1            # verifies this machine's own server cert

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible.

    Run as the context that actually experiences the slow bind. If the consumer
    is a service / lsass (SYSTEM), run elevated as SYSTEM so certutil sees the
    SYSTEM revocation cache and proxy:  psexec -s powershell.exe
    The certutil output is parsed locale-tolerantly (it mixes e.g. 'Time:'/'Zeit:').
#>
[CmdletBinding()]
param(
    [string] $DC,
    [int]    $SlowMs = 300,
    [switch] $ShowCache
)

$cerPath = Join-Path $env:TEMP 'dccert.cer'
$logPath = Join-Path $env:TEMP 'certutil-verify.log'

# ---------------------------------------------------------------------
# 1. Acquire the certificate to verify
# ---------------------------------------------------------------------
Write-Host ''
if ($DC) {
    Write-Host ("Fetching the LDAPS certificate of {0} over 636 (verified from THIS machine)..." -f $DC) -ForegroundColor Cyan
    $tcp = $null; $ssl = $null
    try {
        $tcp = [Net.Sockets.TcpClient]::new($DC, 636)
        $ssl = [Net.Security.SslStream]::new($tcp.GetStream(), $false, { $true })   # accept any cert: we analyse it
        $ssl.AuthenticateAsClient($DC, $null, [Security.Authentication.SslProtocols]::Tls12, $false)
        $cert = [Security.Cryptography.X509Certificates.X509Certificate2]$ssl.RemoteCertificate
        [IO.File]::WriteAllBytes($cerPath, $cert.RawData)
    }
    catch {
        Write-Host ("Could not fetch the certificate from {0}:636 - {1}" -f $DC, $_.Exception.Message) -ForegroundColor Red
        return
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Close() }
    }
    $dns = ($cert.DnsNameList.Unicode -join ', ')
    Write-Host ('  Subject    : {0}' -f $(if ($cert.Subject) { $cert.Subject } else { '(empty - SAN based)' })) -ForegroundColor Green
    Write-Host ('  DNS (SAN)  : {0}' -f $dns)
    Write-Host ('  Issuer     : {0}' -f $cert.Issuer)
}
else {
    Write-Host 'Verifying this machine''s local LDAPS certificate (LocalMachine\My)...' -ForegroundColor Cyan
    $cert = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1' -and $_.HasPrivateKey } |
            Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $cert) {
        Write-Host 'No local Server-Authentication certificate found. Use -DC to check a remote DC.' -ForegroundColor Red
        return
    }
    [IO.File]::WriteAllBytes($cerPath, $cert.RawData)
    Write-Host ('  Subject    : {0}' -f $cert.Subject) -ForegroundColor Green
    Write-Host ('  Issuer     : {0}' -f $cert.Issuer)
}

# ---------------------------------------------------------------------
# 2. Run certutil and keep the raw output
# ---------------------------------------------------------------------
Write-Host ''
Write-Host 'Checking chain and revocation (certutil -urlfetch -verify)...' -ForegroundColor Cyan
# certutil status words may be localised and code-page dependent; the verdict
# keys on fetch DURATION and ASCII failure tokens, never on the exact word, and
# the table shows a normalised OK/FAIL - so console encoding does not matter.
$raw = & certutil -f -urlfetch -verify $cerPath 2>&1 | ForEach-Object { [string]$_ }
$raw | Out-File -FilePath $logPath -Encoding UTF8

# ---------------------------------------------------------------------
# 3. Identify the chain tiers (root = self-signed, issuing = leaf's issuer)
# ---------------------------------------------------------------------
function Get-Cn([string] $Dn) {
    if ($Dn -match 'CN=([^,]+)') { return $Matches[1].Trim() }
    return $Dn
}

$subjects = @(); $issuers = @()
foreach ($l in $raw) {
    if ($l -match '^\s*Subject:\s*(.+)$') { $subjects += $Matches[1].Trim() }
    if ($l -match '^\s*Issuer:\s*(.+)$')  { $issuers  += $Matches[1].Trim() }
}
# root CA: a DN that is its own issuer (self-signed)
$rootDn = $subjects | Where-Object { $_ -and ($issuers -contains $_) } | Select-Object -First 1
# issuing CA: the issuer of the leaf = the first issuer that is not the root
$issuingDn = $issuers | Where-Object { $_ -and $_ -ne $rootDn } | Select-Object -First 1
$rootCn    = if ($rootDn)    { Get-Cn $rootDn }    else { '' }
$issuingCn = if ($issuingDn) { Get-Cn $issuingDn } else { '' }

function Get-Tier([string] $Text) {
    $t = $Text -replace '%20', ' '
    if ($rootCn    -and $t -match [regex]::Escape($rootCn))    { return 'Root' }
    if ($issuingCn -and $t -match [regex]::Escape($issuingCn)) { return 'Issuing' }
    return ''
}
function Get-Proto([string] $Url) {
    if ($Url -match '(?i)ocsp')   { return 'OCSP' }
    if ($Url -match '(?i)^ldap')  { return 'LDAP' }
    if ($Url -match '(?i)^http')  { return 'HTTP' }
    return '?'
}

# ---------------------------------------------------------------------
# 4. Parse per-URL fetches (locale-tolerant: STATUS "object" <label>: <ms>)
# ---------------------------------------------------------------------
# Detect a FAILED status by ASCII tokens only (DE+EN) - robust to code-page
# garbling, which only mangles the non-ASCII "good" words. The real delay signal
# is the fetch DURATION (ms), not the status word.
$badRx = '(?i)fail|fehler|gescheitert|abgelaufen|expired|error|problem|denied|verweigert|timeout'

$hits = @()
$section = ''
for ($i = 0; $i -lt $raw.Count; $i++) {
    $line = $raw[$i]
    if ($line -match '-{4,}\s+(.+?)\s+-{4,}') { $section = $Matches[1].Trim(); continue }

    if ($line -match '^\s+(\S+)\s+"([^"]*)"\s+\S+:\s+(\d+)\b') {
        $status = $Matches[1]; $object = $Matches[2]; $ms = [int]$Matches[3]
        $url = ''
        for ($j = $i + 1; $j -lt [math]::Min($i + 4, $raw.Count); $j++) {
            if ($raw[$j] -match '^\s+\[[\d\.]+\]\s+(.+)$') { $url = $Matches[1].Trim(); break }
        }
        if (-not $url) { continue }
        $hits += [pscustomobject]@{
            Tier   = Get-Tier ($url + ' ' + $object)
            Proto  = Get-Proto $url
            Ms     = $ms
            Status = $status
            Bad    = ($status -match $badRx)
            Url    = $url
        }
    }
}
$hits = $hits | Sort-Object Url, Object -Unique | Sort-Object Ms -Descending

Write-Host ''
Write-Host 'Revocation / AIA fetches (from this machine):' -ForegroundColor Cyan
Write-Host ''
if (-not $hits) { Write-Host '  No URL fetches found in the output.' -ForegroundColor Yellow }

$fmt = '  {0,8} ms  {1,-8} {2,-4} {3,-7}  {4}'
foreach ($h in $hits) {
    $slow   = $h.Ms -ge $SlowMs
    $colour = if ($slow) { 'Red' } elseif ($h.Bad) { 'Yellow' } else { 'Green' }
    $u = $h.Url; if ($u.Length -gt 58) { $u = $u.Substring(0, 55) + '...' }
    $tier = if ($h.Tier) { $h.Tier } else { '-' }
    $st   = if ($h.Bad) { 'FAIL' } else { 'OK' }
    Write-Host ($fmt -f $h.Ms, $st, $h.Proto, $tier, $u) -ForegroundColor $colour
}

# ---------------------------------------------------------------------
# 5. Parse CRL validity per tier
# ---------------------------------------------------------------------
$crls = @()
for ($i = 0; $i -lt $raw.Count; $i++) {
    if ($raw[$i] -match '^\s*(Delta CRL|CRL)\s+([0-9a-fA-F]+):') {
        $kind = $Matches[1]; $issuer = ''; $nu = $null; $tu = $null
        for ($j = $i + 1; $j -lt [math]::Min($i + 8, $raw.Count); $j++) {
            if ($raw[$j] -match '^\s*Issuer:\s*(.+)$')     { $issuer = $Matches[1].Trim() }
            if ($raw[$j] -match '^\s*ThisUpdate:\s*(.+)$') { try { $tu = [datetime]::Parse($Matches[1].Trim()) } catch { } }
            if ($raw[$j] -match '^\s*NextUpdate:\s*(.+)$') { try { $nu = [datetime]::Parse($Matches[1].Trim()) } catch { } ; break }
        }
        if ($nu) {
            $crls += [pscustomobject]@{
                Type = $kind; Tier = (Get-Tier $issuer); Issuer = (Get-Cn $issuer)
                NextUpdate = $nu
            }
        }
    }
}
$crls = $crls | Sort-Object Type, Issuer, NextUpdate -Unique

if ($crls) {
    Write-Host ''
    Write-Host 'CRL validity per tier:' -ForegroundColor Cyan
    Write-Host ''
    foreach ($c in $crls) {
        $h = [math]::Round(($c.NextUpdate - (Get-Date)).TotalHours, 1)
        if     ($h -lt 0)  { $col = 'Red';    $txt = 'EXPIRED' }
        elseif ($h -lt 48) { $col = 'Yellow'; $txt = ('expires in {0} h' -f $h) }
        else               { $col = 'Green';  $txt = ('valid ({0} h left)' -f $h) }
        $tier = if ($c.Tier) { $c.Tier } else { $c.Issuer }
        Write-Host ('  {0,-10} {1,-10} NextUpdate: {2}   {3}' -f $c.Type, $tier, $c.NextUpdate, $txt) -ForegroundColor $col
    }
}

# ---------------------------------------------------------------------
# 6. Verdict
# ---------------------------------------------------------------------
$slow       = @($hits | Where-Object { $_.Ms -ge $SlowMs })
$failedFast = @($hits | Where-Object { $_.Bad -and $_.Ms -lt $SlowMs })
$expired    = @($crls | Where-Object { $_.NextUpdate -lt (Get-Date) })

Write-Host ''
Write-Host 'Verdict:' -ForegroundColor Cyan
if ($slow.Count -gt 0) {
    $worst = $slow | Select-Object -First 1
    $tier  = if ($worst.Tier) { $worst.Tier } else { 'unknown tier' }
    Write-Host ('  [!] Revocation stalls on the {0} stage via {1}: {2} ms' -f $tier, $worst.Proto, $worst.Ms) -ForegroundColor Red
    Write-Host ('      {0}' -f $worst.Url) -ForegroundColor Red
    Write-Host '      That fetch is the LDAPS soft-fail delay from here. Fix reachability or' -ForegroundColor Red
    Write-Host '      validity of this URL (an HTTP CDP to an unreachable server is typical).' -ForegroundColor Red
}
foreach ($e in $expired) {
    $t = if ($e.Tier) { $e.Tier } else { $e.Issuer }
    Write-Host ('  [!] {0} {1} CRL is EXPIRED (NextUpdate {2}) - that CA must republish.' -f $t, $e.Type, $e.NextUpdate) -ForegroundColor Red
}
if ($slow.Count -eq 0 -and $expired.Count -eq 0) {
    if ($failedFast.Count -gt 0) {
        Write-Host ('  [i] {0} fetch(es) failed but returned fast (e.g. LDAP from this host).' -f $failedFast.Count) -ForegroundColor Yellow
        Write-Host '      Not the delay if another URL for the same CRL succeeded (see table).' -ForegroundColor Yellow
    }
    Write-Host '  [ok] No slow fetch, no expired CRL from here - revocation is not the LDAPS' -ForegroundColor Green
    Write-Host '       delay at this vantage. If a client elsewhere is slow, run -DC from there.' -ForegroundColor Green
}

Write-Host ''
Write-Host ('Full certutil output: {0}' -f $logPath) -ForegroundColor DarkGray

# ---------------------------------------------------------------------
# 7. Optional: inspect / clear the CRL cache
# ---------------------------------------------------------------------
if ($ShowCache) {
    Write-Host ''
    Write-Host 'Currently in the CRL cache:' -ForegroundColor Cyan
    certutil -urlcache crl
    $answer = Read-Host 'Delete the cache now to force a fresh fetch? (y/N)'
    if ($answer -eq 'y') { certutil -urlcache crl delete; Write-Host 'Cache cleared.' -ForegroundColor Yellow }
    else { Write-Host 'Cache left untouched.' -ForegroundColor Green }
}
