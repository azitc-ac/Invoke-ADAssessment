<#
.SYNOPSIS
    Offline connection-setup analyzer. Captures a scoped ETW trace of an SMB/LDAP
    connection (or analyses an existing .etl) and produces a deterministic verdict
    per target: Kerberos vs. NTLM, DNS health, and where the setup time is spent -
    with an optional self-contained HTML report. No internet, no AI, no extra tools.

.DESCRIPTION
    Layer 3 of the diagnostic set (after the active probes Test-SmbConnectSetup.ps1
    and Test-LdapsCtl.ps1). Use it when the probes point somewhere that needs the
    event-level detail, or to produce a shareable report.

    Pipeline:
      1. Capture (needs admin): start an ETW session via logman over the relevant
         providers, reproduce the access (auto-probe, timed, or interactive), stop.
      2. Parse: Get-WinEvent -Path reads and decodes the .etl - no live system
         needed, so the .etl can be captured at the customer and analysed here.
      3. Analyse: deterministic rules per target -> verdict object + console + HTML.

    The rules are deliberately ID-agnostic where possible (provider + target match,
    DNS status, inter-event gaps), so they survive provider-schema differences
    across Windows versions.

    Providers (core): SMBClient, Security-Kerberos, NTLM, DNS-Client.
    -IncludeLdaps adds LDAP-Client + CAPI2 (the LDAPS/CTL angle); -IncludeDfs adds
    DfsSvc.

.PARAMETER Target
    Server(s) to focus the analysis on (short name or FQDN). Also the auto-probe
    targets. If omitted during analysis, all captured targets are summarised.

.PARAMETER EtlPath
    Analyse this existing .etl instead of capturing. No admin needed.

.PARAMETER AutoProbe
    During capture, purge the ticket cache and do a cold 'net use' to each -Target
    (a deterministic repro). Without it, use -DurationSec or the interactive prompt.

.PARAMETER DurationSec
    Capture for this many seconds, then stop automatically. 0 (default) = prompt and
    wait for Enter (reproduce the problem manually in between).

.PARAMETER Share
    Share for the auto-probe. Default 'IPC$'.

.PARAMETER IncludeLdaps
    Also capture LDAP-Client and CAPI2 (for LDAPS / CTL investigation).

.PARAMETER IncludeDfs
    Also capture the DFS provider.

.PARAMETER OutDir
    Where to write the .etl and the HTML report. Default: the current directory.

.PARAMETER Html
    Also write a self-contained HTML report next to the .etl.

.EXAMPLE
    .\Invoke-ConnTrace.ps1 -Target dc08 -AutoProbe -Html

.EXAMPLE
    .\Invoke-ConnTrace.ps1 -Target fileserver01 -DurationSec 20 -IncludeDfs

.EXAMPLE
    .\Invoke-ConnTrace.ps1 -EtlPath .\ConnTrace_20261014_2200.etl -Target dc08 -Html

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible. Capture needs admin; analysis does not.
#>
[CmdletBinding()]
param(
    [string[]] $Target,
    [string]   $EtlPath,
    [switch]   $AutoProbe,
    [int]      $DurationSec = 0,
    [string]   $Share       = 'IPC$',
    [switch]   $IncludeLdaps,
    [switch]   $IncludeDfs,
    [string]   $OutDir,
    [switch]   $Html
)

# This script drives native tools (net.exe, logman, certutil, klist) that
# legitimately return non-zero - e.g. 'net use /delete' when nothing is mapped.
# Do NOT treat that as terminating: under pwsh 7 'Stop' + the native-error
# feature would abort the whole capture on the first harmless /delete.
$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false

$providers = @(
    'Microsoft-Windows-SMBClient'
    'Microsoft-Windows-Security-Kerberos'
    'Microsoft-Windows-NTLM'
    'Microsoft-Windows-DNS-Client'
)
if ($IncludeLdaps) { $providers += 'Microsoft-Windows-LDAP-Client','Microsoft-Windows-CAPI2' }
if ($IncludeDfs)   { $providers += 'Microsoft-Windows-DfsSvc' }

if (-not $OutDir) { $OutDir = (Get-Location).Path }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

function Short([string] $Provider) { $Provider -replace '^Microsoft-Windows-', '' }

# Flatten an event into { Time, Provider, Id, Level, Props(hash), Blob(string) }.
function ConvertTo-Record($Event) {
    $props = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) { $props[$d.Name] = [string]$d.'#text' }
        }
    } catch { }
    $blob = (($props.Values -join ' ') + ' ' + $Event.Message) -replace '\s+', ' '
    [pscustomobject]@{
        Time     = $Event.TimeCreated
        Provider = Short $Event.ProviderName
        Id       = $Event.Id
        Level    = $Event.LevelDisplayName
        Props    = $props
        Blob     = $blob
    }
}

# =====================================================================
# 1. Capture (unless analysing an existing .etl)
# =====================================================================
if (-not $EtlPath) {

    if (-not $isAdmin) {
        Write-Host 'Capture needs admin rights. Elevate, or pass -EtlPath to analyse an existing trace.' -ForegroundColor Red
        return
    }

    $stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $session = "ConnTrace_$stamp"
    $EtlPath = Join-Path $OutDir "$session.etl"
    $provFile = Join-Path $env:TEMP "$session.prov"

    # logman provider file: "Name" Keywords(all) Level(verbose)
    ($providers | ForEach-Object { '"{0}" 0xFFFFFFFFFFFFFFFF 0xFF' -f $_ }) |
        Out-File -FilePath $provFile -Encoding ascii

    # Housekeeping BEFORE the trace starts, so the capture holds ONLY the cold
    # connect - not the pre-clean deletes or the ticket purge, which generate
    # their own SMB/DNS events and sleeps and otherwise pollute the timeline and
    # the gap analysis. The purge makes the in-trace connect genuinely cold: it
    # must re-acquire the TGT and a fresh TGS, which IS real setup cost.
    if ($AutoProbe -and $Target) {
        foreach ($t in $Target) { & net.exe use ('\\{0}\{1}' -f $t, $Share) /delete /y *> $null }
        & klist purge *> $null
    }

    Write-Host ''
    Write-Host ('Starting ETW capture ({0} providers) -> {1}' -f $providers.Count, $EtlPath) -ForegroundColor Cyan
    & logman create trace $session -pf $provFile -o $EtlPath -ets 2>&1 | Out-Null

    try {
        if ($AutoProbe -and $Target) {
            Write-Host '  Auto-probe: cold net use to each target...' -ForegroundColor DarkGray
            foreach ($t in $Target) { & net.exe use ('\\{0}\{1}' -f $t, $Share) *> $null }
            Start-Sleep -Milliseconds 300
        }
        elseif ($DurationSec -gt 0) {
            Write-Host ('  Capturing for {0} s - reproduce the access now...' -f $DurationSec) -ForegroundColor Yellow
            Start-Sleep -Seconds $DurationSec
        }
        else {
            Write-Host '  Reproduce the access now, then press Enter to stop...' -ForegroundColor Yellow
            [void](Read-Host)
        }
    }
    finally {
        & logman stop $session -ets 2>&1 | Out-Null
        Remove-Item $provFile -ErrorAction SilentlyContinue
        if ($AutoProbe -and $Target) {
            foreach ($t in $Target) { & net.exe use ('\\{0}\{1}' -f $t, $Share) /delete /y *> $null }
        }
    }
    Write-Host '  Capture stopped.' -ForegroundColor DarkGray
}

if (-not (Test-Path $EtlPath)) {
    Write-Host ('Trace file not found: {0}' -f $EtlPath) -ForegroundColor Red
    return
}

# =====================================================================
# 2. Parse
# =====================================================================
Write-Host ''
Write-Host ('Parsing {0} ...' -f $EtlPath) -ForegroundColor Cyan
$records = @(Get-WinEvent -Path $EtlPath -Oldest -ErrorAction SilentlyContinue |
             ForEach-Object { ConvertTo-Record $_ })
Write-Host ('  {0} events decoded.' -f $records.Count) -ForegroundColor DarkGray

# Targets: explicit, else derive the short names seen in SMB/Kerberos blobs.
$shorts = @()
if ($Target) {
    $shorts = $Target | ForEach-Object { ($_ -split '\.')[0] }
}
else {
    $shorts = $records |
        Where-Object { $_.Provider -in 'SMBClient','Security-Kerberos' } |
        ForEach-Object { if ($_.Blob -match '\b(?:cifs|host|ldap)/([A-Za-z0-9\-]+)') { $Matches[1] } } |
        Select-Object -Unique
}
$shorts = @($shorts | Where-Object { $_ } | Select-Object -Unique)

# =====================================================================
# 3. Analyse per target
# =====================================================================
function Test-Ref($Record, $Name) { $Record.Blob -match ('\b' + [regex]::Escape($Name)) }

$summary = @()

foreach ($name in $shorts) {

    $refs = @($records | Where-Object { Test-Ref $_ $name } | Sort-Object Time)

    $ntlm = @($refs | Where-Object { $_.Provider -eq 'NTLM' })
    $kerb = @($refs | Where-Object { $_.Provider -eq 'Security-Kerberos' })
    $dns  = @($refs | Where-Object { $_.Provider -eq 'DNS-Client' })
    $smb  = @($refs | Where-Object { $_.Provider -eq 'SMBClient' })
    $errs = @($refs | Where-Object { $_.Level -eq 'Error' })

    # DNS failure: a response FOR THIS TARGET's name carrying a real resolution
    # failure code. Not "QueryStatus != 0" - the DNS-Client provider emits many
    # events whose QueryStatus means other things (e.g. 87 = INVALID_PARAMETER),
    # which is not a lookup failure and falsely flagged a healthy target.
    $dnsFailCodes = '9003','9501','9002','9701','9719','1460','10060','11001','11002','11004'
    $dnsFail = @($dns | Where-Object {
        $_.Props['QueryName'] -and ($_.Props['QueryName'] -match [regex]::Escape($name)) -and
        $_.Props['QueryStatus'] -and ($dnsFailCodes -contains [string]$_.Props['QueryStatus'])
    })

    # Observed setup span and the single largest gap between consecutive events
    # (the gap is where the time most likely went).
    $span = 0; $gapMs = 0; $gapFrom = ''; $gapTo = ''
    if ($refs.Count -ge 2) {
        $span = [int]($refs[-1].Time - $refs[0].Time).TotalMilliseconds
        for ($i = 1; $i -lt $refs.Count; $i++) {
            $d = [int]($refs[$i].Time - $refs[$i-1].Time).TotalMilliseconds
            if ($d -gt $gapMs) { $gapMs = $d; $gapFrom = $refs[$i-1].Provider; $gapTo = $refs[$i].Provider }
        }
    }

    if     ($ntlm.Count -gt 0) { $auth = 'NTLM' }
    elseif ($kerb.Count -gt 0) { $auth = 'Kerberos' }
    else                       { $auth = 'unknown' }

    # Verdict
    if ($refs.Count -eq 0) {
        $verdict = 'no events for this target - widen the repro or verbosity'
    }
    elseif ($ntlm.Count -gt 0) {
        $verdict = 'NTLM fallback - no Kerberos (check SPN / DNS / time skew)'
    }
    elseif ($dnsFail.Count -gt 0) {
        $verdict = ('DNS lookup failed (status {0})' -f ($dnsFail[0].Props['QueryStatus']))
    }
    elseif ($errs.Count -gt 0) {
        $verdict = ('{0} error event(s) in the sequence' -f $errs.Count)
    }
    elseif ($gapMs -ge 500) {
        $verdict = ('setup ~{0} ms; biggest gap {1} ms between {2} and {3}' -f $span, $gapMs, $gapFrom, $gapTo)
    }
    else {
        $verdict = ('{0}, setup ~{1} ms, no stall' -f $auth, $span)
    }

    $summary += [pscustomobject]@{
        Target   = $name
        Auth     = $auth
        Events   = $refs.Count
        Kerb     = $kerb.Count
        Ntlm     = $ntlm.Count
        Dns      = $dns.Count
        DnsFail  = $dnsFail.Count
        Errors   = $errs.Count
        SpanMs   = $span
        MaxGapMs = $gapMs
        Verdict  = $verdict
        Refs     = $refs
    }
}

# =====================================================================
# 4. Console output
# =====================================================================
Write-Host ''
if ($summary.Count -eq 0) {
    Write-Host 'No targets identified. Pass -Target explicitly.' -ForegroundColor Yellow
    return
}

$fmt = '  {0,-18} {1,-9} {2,6} {3,8} {4,8}   {5}'
Write-Host ($fmt -f 'Target','Auth','Events','Span ms','Gap ms','Verdict') -ForegroundColor Cyan
Write-Host ('  ' + ('-' * 100)) -ForegroundColor DarkGray
foreach ($s in $summary) {
    $col = if ($s.Auth -eq 'NTLM' -or $s.DnsFail -gt 0 -or $s.Errors -gt 0) { 'Red' }
           elseif ($s.MaxGapMs -ge 500) { 'Yellow' }
           elseif ($s.Events -eq 0) { 'DarkGray' }
           else { 'Green' }
    Write-Host ($fmt -f $s.Target, $s.Auth, $s.Events, $s.SpanMs, $s.MaxGapMs, $s.Verdict) -ForegroundColor $col
}
Write-Host ''

# =====================================================================
# 5. HTML report (self-contained, offline)
# =====================================================================
if ($Html) {

    try { Add-Type -AssemblyName System.Web } catch { }
    function E($t) { try { [System.Web.HttpUtility]::HtmlEncode([string]$t) } catch { [string]$t } }

    $rows = ($summary | ForEach-Object {
        $cls = if ($_.Auth -eq 'NTLM' -or $_.DnsFail -gt 0 -or $_.Errors -gt 0) { 'bad' }
               elseif ($_.MaxGapMs -ge 500) { 'warn' } else { 'ok' }
        '<tr class="{0}"><td>{1}</td><td>{2}</td><td class="n">{3}</td><td class="n">{4}</td><td class="n">{5}</td><td>{6}</td></tr>' -f `
            $cls, (E $_.Target), (E $_.Auth), $_.Events, $_.SpanMs, $_.MaxGapMs, (E $_.Verdict)
    }) -join "`n"

    $timelineRows = ($summary | ForEach-Object {
        $t = $_.Target
        ($_.Refs | ForEach-Object {
            '<tr><td>{0}</td><td>{1:HH:mm:ss.fff}</td><td>{2}</td><td class="n">{3}</td><td>{4}</td><td class="msg">{5}</td></tr>' -f `
                (E $t), $_.Time, (E $_.Provider), $_.Id, (E $_.Level), (E ($_.Blob.Substring(0, [math]::Min(160, $_.Blob.Length))))
        }) -join "`n"
    }) -join "`n"

    $doc = @"
<!doctype html><html><head><meta charset="utf-8"><title>ConnTrace Report</title>
<style>
body{font-family:Calibri,Segoe UI,sans-serif;margin:24px;color:#222}
h1{font-size:20px}h2{font-size:15px;margin-top:24px}
.meta{color:#666;font-size:12px;margin-bottom:16px}
table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
th,td{border:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top}
th{background:#f3f3f3}
td.n{text-align:right;font-variant-numeric:tabular-nums}
td.msg{color:#555;font-family:Consolas,monospace;font-size:11px}
tr.bad td:first-child{border-left:4px solid #c0392b}
tr.warn td:first-child{border-left:4px solid #d98c00}
tr.ok td:first-child{border-left:4px solid #27936b}
</style></head><body>
<h1>Connection-setup trace analysis</h1>
<div class="meta">Source: $(E $EtlPath) &middot; Events decoded: $($records.Count) &middot; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; AZITC</div>
<h2>Verdict per target</h2>
<table><tr><th>Target</th><th>Auth</th><th>Events</th><th>Span ms</th><th>Max gap ms</th><th>Verdict</th></tr>
$rows
</table>
<h2>Timeline</h2>
<table><tr><th>Target</th><th>Time</th><th>Provider</th><th>Id</th><th>Level</th><th>Detail</th></tr>
$timelineRows
</table>
</body></html>
"@

    $htmlPath = [IO.Path]::ChangeExtension($EtlPath, '.html')
    $doc | Out-File -FilePath $htmlPath -Encoding utf8
    Write-Host ('HTML report: {0}' -f $htmlPath) -ForegroundColor Green
    Write-Host ''
}

$summary | Select-Object Target, Auth, Events, SpanMs, MaxGapMs, Verdict
