<#
.SYNOPSIS
    Checks the LDAPS certificate of a domain controller, including chain building and
    revocation checking, and prints a compact verdict instead of raw certutil output.

.DESCRIPTION
    Locates the Server Authentication certificate in the computer store, exports it
    to TEMP, runs 'certutil -urlfetch -verify' and parses the result:
      - Fetch duration per CDP/AIA/OCSP URL (the 'Time:' field, in milliseconds)
      - Status per URL (Verified / OK / Failed / Expired ...)
      - Validity of the retrieved CRLs (NextUpdate)

    This is the core diagnostic for slow LDAPS bind times: a URL with a high fetch
    duration or an error status is the cause of the soft-fail timeout.

    The full certutil output is additionally written to a log file.

.PARAMETER SlowMs
    Fetch duration (ms) from which a URL counts as slow. Default 300.

.PARAMETER ShowCache
    Also display the CRL cache and offer to clear it. Clearing is only useful to
    verify a fix (it forces a fresh fetch); it does not repair anything.

.EXAMPLE
    .\Test-LdapsRevocation.ps1

.EXAMPLE
    .\Test-LdapsRevocation.ps1 -SlowMs 500 -ShowCache

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible. Run locally on an affected DC.

    The DC validates LDAPS certificates in the SYSTEM context (lsass). Run as an
    administrator, certutil shows the USER cache and USER proxy settings, not the
    relevant ones. For the SYSTEM context, start via:
        psexec -s powershell.exe
#>
[CmdletBinding()]
param(
    [int]    $SlowMs = 300,
    [switch] $ShowCache
)

# ---------------------------------------------------------------------
# 1. Locate the certificate
# ---------------------------------------------------------------------
Write-Host ''
Write-Host 'Searching for the LDAPS certificate of this DC (LocalMachine\My)...' -ForegroundColor Cyan

# OID 1.3.6.1.5.5.7.3.1 = Server Authentication (locale-independent,
# unlike the localised FriendlyName).
$cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object {
            $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1' -and
            $_.HasPrivateKey
        } |
        Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $cert) {
    Write-Host 'No suitable certificate found - aborting.' -ForegroundColor Red
    return
}

$daysLeft = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays, 0)

Write-Host ('  Subject    : {0}' -f $cert.Subject) -ForegroundColor Green
Write-Host ('  Expires    : {0}  ({1} days)' -f $cert.NotAfter, $daysLeft)
Write-Host ('  Thumbprint : {0}' -f $cert.Thumbprint)

$cerPath = Join-Path $env:TEMP 'dccert.cer'
$logPath = Join-Path $env:TEMP 'certutil-verify.log'
[System.IO.File]::WriteAllBytes($cerPath, $cert.RawData)   # DER encoded

# ---------------------------------------------------------------------
# 2. Run certutil and keep the raw output
# ---------------------------------------------------------------------
Write-Host ''
Write-Host 'Checking chain and revocation status (certutil -urlfetch -verify)...' -ForegroundColor Cyan

$raw = & certutil -f -urlfetch -verify $cerPath 2>&1 | ForEach-Object { [string]$_ }
$raw | Out-File -FilePath $logPath -Encoding UTF8

# ---------------------------------------------------------------------
# 3. Parse: status and fetch duration per URL
# ---------------------------------------------------------------------
# certutil groups the fetches into sections. They mean different things:
#   Certificate AIA  -> fetching the issuer certificate
#   Certificate CDP  -> fetching the CRL referenced by the leaf certificate
#   Base CRL CDP     -> fetching the delta CRL referenced by the base CRL
#   Certificate OCSP -> OCSP responder (often none)
# The same URL can legitimately appear in more than one section, so the
# section is part of the identity of a hit - not a duplicate.

$section = ''
$hits    = @()

for ($i = 0; $i -lt $raw.Count; $i++) {

    $line = $raw[$i]

    if ($line -match '-{4,}\s+(.+?)\s+-{4,}') {
        $section = $Matches[1].Trim()
        continue
    }

    # e.g.:   Verified "Base CRL (05d8)" Time: 0 40f9e1eb...
    if ($line -match '^\s+(Verified|OK|Failed|Expired|Error|No URLs)\s+"([^"]*)"\s+Time:\s+(\d+)') {

        $status = $Matches[1]
        $object = $Matches[2]
        $ms     = [int]$Matches[3]

        # The URL follows on one of the next lines as [x.y] <url>
        $url = ''
        for ($j = $i + 1; $j -lt [math]::Min($i + 4, $raw.Count); $j++) {
            if ($raw[$j] -match '^\s+\[[\d\.]+\]\s+(.+)$') {
                $url = $Matches[1].Trim()
                break
            }
        }

        # "No URLs / None" -> nothing to fetch, not a finding
        if (-not $url) { continue }

        $hits += [pscustomobject]@{
            Section = $section
            Status  = $status
            Object  = $object
            Ms      = $ms
            Url     = $url
        }
    }
}

# certutil repeats the same fetch once per chain path ([0.0], [1.0.1], [2.0.2] ...).
# Collapse those, but keep genuinely different section/object combinations.
$hits = $hits | Sort-Object Section, Url, Object -Unique | Sort-Object Ms -Descending

Write-Host ''
Write-Host 'Fetch duration per revocation / AIA URL (core finding):' -ForegroundColor Cyan
Write-Host ''

if (-not $hits) {
    Write-Host '  No URL fetches found in the output.' -ForegroundColor Yellow
}

foreach ($hit in $hits) {

    # Shorten the section label for display
    $sec = $hit.Section -replace 'Certificate ', '' -replace ' CDP$', ' CDP'
    if ($sec.Length -gt 12) { $sec = $sec.Substring(0, 12) }

    $urlShort = $hit.Url
    if ($urlShort.Length -gt 60) { $urlShort = $urlShort.Substring(0, 57) + '...' }

    if     (@('Verified', 'OK') -notcontains $hit.Status) { $colour = 'Red' }
    elseif ($hit.Ms -ge 1000)                             { $colour = 'Red' }
    elseif ($hit.Ms -ge $SlowMs)                          { $colour = 'Yellow' }
    else                                                  { $colour = 'Green' }

    Write-Host ('  {0,7} ms  {1,-8}  {2,-12}  {3}' -f $hit.Ms, $hit.Status, $sec, $urlShort) -ForegroundColor $colour
}

# ---------------------------------------------------------------------
# 4. CRL validity (an expired CRL is the most common cause)
# ---------------------------------------------------------------------
$crls = @()

for ($i = 0; $i -lt $raw.Count; $i++) {

    if ($raw[$i] -match '^\s+(Delta CRL|CRL)\s+([0-9a-fA-F]+):') {

        $kind       = $Matches[1]
        $nextUpdate = $null

        $thisUpdate = $null

        for ($j = $i + 1; $j -lt [math]::Min($i + 6, $raw.Count); $j++) {

            if ($raw[$j] -match '^\s+ThisUpdate:\s+(.+)$') {
                try   { $thisUpdate = [datetime]::Parse($Matches[1].Trim()) }
                catch { $thisUpdate = $null }
            }

            if ($raw[$j] -match '^\s+NextUpdate:\s+(.+)$') {
                try   { $nextUpdate = [datetime]::Parse($Matches[1].Trim()) }
                catch { $nextUpdate = $null }
                break
            }
        }

        if ($nextUpdate) {
            $crls += [pscustomobject]@{
                Type       = $kind
                ThisUpdate = $thisUpdate
                NextUpdate = $nextUpdate
            }
        }
    }
}

$crls = $crls | Sort-Object Type, NextUpdate -Unique

if ($crls) {

    Write-Host ''
    Write-Host 'Validity of the retrieved CRLs:' -ForegroundColor Cyan
    Write-Host ''

    foreach ($crl in $crls) {

        $hoursLeft = [math]::Round(($crl.NextUpdate - (Get-Date)).TotalHours, 1)

        if     ($hoursLeft -lt 0)  { $colour = 'Red';    $text = 'EXPIRED' }
        elseif ($hoursLeft -lt 48) { $colour = 'Yellow'; $text = ('expires in {0} h' -f $hoursLeft) }
        else                       { $colour = 'Green';  $text = ('valid, {0} h remaining' -f $hoursLeft) }

        Write-Host ('  {0,-10}  NextUpdate: {1}   {2}' -f $crl.Type, $crl.NextUpdate, $text) -ForegroundColor $colour
    }

    # Is the delta CRL actually doing its job?
    #
    # Do NOT compare NextUpdate here: when the delta period divides the base
    # period evenly (e.g. 1 week into 4 weeks) the final delta of each cycle
    # legitimately expires at the same moment as the base CRL. That is
    # arithmetic, not a misconfiguration.
    #
    # The meaningful signal is ThisUpdate: a working delta CRL is issued more
    # recently than the base CRL it supplements.
    $base  = $crls | Where-Object { $_.Type -eq 'CRL' }       | Select-Object -First 1
    $delta = $crls | Where-Object { $_.Type -eq 'Delta CRL' } | Select-Object -First 1

    if ($base -and $delta -and $base.ThisUpdate -and $delta.ThisUpdate) {

        if ($delta.ThisUpdate -le $base.ThisUpdate) {
            Write-Host ''
            Write-Host '  Note: the delta CRL is not newer than the base CRL, so it adds no' -ForegroundColor Yellow
            Write-Host '        fresher revocation information. Review the publication interval' -ForegroundColor Yellow
            Write-Host '        (certutil -getreg CA\CRLDeltaPeriod).' -ForegroundColor Yellow
        }
        else {
            $ageGain = [math]::Round(($delta.ThisUpdate - $base.ThisUpdate).TotalDays, 1)
            Write-Host ''
            Write-Host ('  [ok] Delta CRL is {0} days newer than the base CRL - working as intended.' -f $ageGain) -ForegroundColor Green
        }
    }
}

# ---------------------------------------------------------------------
# 5. Verdict
# ---------------------------------------------------------------------
$slowest = $hits | Select-Object -First 1
$failed  = @($hits | Where-Object { @('Verified', 'OK') -notcontains $_.Status })
$expired = @($crls | Where-Object { $_.NextUpdate -lt (Get-Date) })
$soon    = @($crls | Where-Object { $_.NextUpdate -ge (Get-Date) -and $_.NextUpdate -lt (Get-Date).AddHours(48) })

$isSlow = ($slowest -and $slowest.Ms -ge $SlowMs)

Write-Host ''
Write-Host 'Verdict:' -ForegroundColor Cyan

if ($failed.Count -gt 0) {
    Write-Host ('  [!] {0} URL(s) returned an error status - this is the cause.' -f $failed.Count) -ForegroundColor Red
    foreach ($fail in $failed) {
        Write-Host ('      {0}  {1}' -f $fail.Status, $fail.Url) -ForegroundColor Red
    }
}

if ($expired.Count -gt 0) {
    Write-Host '  [!] An expired CRL is involved - the CA must republish.' -ForegroundColor Red
}
elseif ($soon.Count -gt 0) {
    Write-Host '  [!] A CRL expires within 48 h. Not a fault in itself, but if the CA' -ForegroundColor Yellow
    Write-Host '      fails to publish in time, every client falls back to soft-fail' -ForegroundColor Yellow
    Write-Host '      timeouts. Verify that the new CRL reaches ALL CDP locations.' -ForegroundColor Yellow
}

if ($isSlow) {
    Write-Host ('  [!] Slowest fetch: {0} ms -> {1}' -f $slowest.Ms, $slowest.Url) -ForegroundColor Red
    Write-Host '      This URL is what produces the LDAPS delay (soft-fail timeout).' -ForegroundColor Red
}
elseif ($slowest) {
    Write-Host ('  [ok] All revocation fetches are fast (max. {0} ms).' -f $slowest.Ms) -ForegroundColor Green
}

if ($raw -match 'revocation check passed') {
    Write-Host '  [ok] Revocation check of the leaf certificate passed.' -ForegroundColor Green
}

Write-Host ''

if ($failed.Count -eq 0 -and $expired.Count -eq 0 -and -not $isSlow) {

    if ($soon.Count -gt 0) {
        Write-Host '  => Revocation checking currently works, but the upcoming CRL rollover' -ForegroundColor Yellow
        Write-Host '     is a single point of failure. Confirm the CA publishes on time.' -ForegroundColor Yellow
    }
    else {
        Write-Host '  => Revocation infrastructure is healthy. Slow LDAPS would have another' -ForegroundColor Green
        Write-Host '     cause here and should be traced further via the CAPI2 log.' -ForegroundColor Green
    }
}
else {
    Write-Host '  => Fix the items above, then re-measure the LDAPS bind time.' -ForegroundColor Red
}

Write-Host ''
Write-Host ('Full certutil output: {0}' -f $logPath) -ForegroundColor DarkGray

# ---------------------------------------------------------------------
# 6. Optional: inspect / clear the CRL cache
# ---------------------------------------------------------------------
if ($ShowCache) {

    Write-Host ''
    Write-Host 'Currently in the CRL cache:' -ForegroundColor Cyan
    certutil -urlcache crl

    # Clearing fixes nothing - it only forces a fresh fetch and is therefore
    # useful solely to verify a correction that has already been made.
    $answer = Read-Host 'Delete the cache now to force a fresh fetch? (y/N)'

    if ($answer -eq 'y') {
        Write-Host 'Deleting cache...' -ForegroundColor Yellow
        certutil -urlcache crl delete
        Write-Host 'Cache afterwards:' -ForegroundColor Cyan
        certutil -urlcache crl
    }
    else {
        Write-Host 'Cache left untouched.' -ForegroundColor Green
    }
}
