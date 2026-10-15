<#
.SYNOPSIS
    Diffs two or more Test-AdPortMatrix.ps1 JSON results to find the actual
    evidence of a network-segmentation problem: a port that behaves
    differently depending on which segment the probe ran from.

.DESCRIPTION
    A single Test-AdPortMatrix.ps1 run only proves "reachable from here". A
    segmentation claim needs comparison: the same target, the same port,
    probed from two different segments, with a different result. That
    asymmetry - not any single run - is the proof the customer is asking
    for. This script takes 2+ JSON files produced by
    Test-AdPortMatrix.ps1 -OutFile and reports every target/port
    combination where the State differs between segments.

    Only reads the given files - makes no network connections itself.

.PARAMETER InputFile
    Two or more JSON files from Test-AdPortMatrix.ps1 -OutFile.

.PARAMETER HtmlReport
    Also write a self-contained HTML report (colour-coded, no external
    dependencies, no internet) to this path - a ready-to-send artifact for
    the customer, with every result (not just the differences) so they can
    see what was actually tested.

.PARAMETER ListenerFile
    The _listeners.json written by Invoke-SegmentProbeFanOut.ps1: which TCP
    ports are in LISTEN state and which UDP ports have a bound endpoint on
    each target. Adds a "Listener" column so a "No response" row can be read
    correctly: NOT listening means there was nothing to reach - a host/role
    question, not a network finding - while a listener that still gets no
    reply from a segment is the real suspect. Rows for targets the inventory
    could not reach show "unknown". Optional; without it the column is
    omitted.

.EXAMPLE
    .\Compare-SegmentProbes.ps1 -InputFile hq-probe.json,branch-probe.json

.EXAMPLE
    .\Compare-SegmentProbes.ps1 -InputFile hq.json,branch.json,dmz.json -HtmlReport segment-diff.html

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible. Read-only: only reads the given JSON files.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $InputFile,

    [string] $HtmlReport,

    [string] $ListenerFile
)

if (@($InputFile).Count -lt 2) {
    Write-Host 'Need at least two input files to compare.' -ForegroundColor Red
    return
}

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $Text = $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
    return $Text
}

$runs = New-Object System.Collections.ArrayList
foreach ($f in $InputFile) {
    if (-not (Test-Path $f)) {
        Write-Host ('File not found: {0}' -f $f) -ForegroundColor Red
        return
    }
    try {
        $data = Get-Content -Path $f -Raw | ConvertFrom-Json
        if (-not $data.SegmentName) {
            Write-Host ('{0} does not look like a Test-AdPortMatrix.ps1 result (no SegmentName).' -f $f) -ForegroundColor Red
            return
        }
        [void]$runs.Add($data)
    }
    catch {
        Write-Host ('Could not parse {0}: {1}' -f $f, $_.Exception.Message) -ForegroundColor Red
        return
    }
}

$segmentNames = @($runs | ForEach-Object { $_.SegmentName })
if (@($segmentNames | Select-Object -Unique).Count -ne $segmentNames.Count) {
    Write-Host 'Two input files have the same SegmentName - re-run Test-AdPortMatrix.ps1 with distinct -SegmentName values so the diff can tell them apart.' -ForegroundColor Red
    return
}

# Optional listener inventory (target -> what is bound there)
$listeners = @{}
$haveListeners = $false
if ($ListenerFile) {
    if (-not (Test-Path $ListenerFile)) {
        Write-Host ('Listener file not found, continuing without it: {0}' -f $ListenerFile) -ForegroundColor Yellow
    }
    else {
        try {
            $lf = Get-Content -Path $ListenerFile -Raw | ConvertFrom-Json
            foreach ($lt in @($lf.Targets)) {
                $listeners[[string]$lt.Target] = [pscustomobject]@{
                    Status = [string]$lt.Status
                    Tcp    = @($lt.Tcp | ForEach-Object { [int]$_ })
                    Udp    = @($lt.Udp | ForEach-Object { [int]$_ })
                }
            }
            $haveListeners = $true
        }
        catch {
            Write-Host ('Could not parse listener file, continuing without it: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}

# listening / NOT listening / unknown, or '-' for rows that have no fixed port
function Get-ListenerState {
    param($Row)
    if (-not $haveListeners) { return '' }
    if ($Row.Proto -ne 'TCP' -and $Row.Proto -ne 'UDP') { return '-' }
    $port = 0
    if (-not [int]::TryParse([string]$Row.Port, [ref]$port)) { return '-' }
    $l = $listeners[[string]$Row.Target]
    if (-not $l -or $l.Status -ne 'OK') { return 'unknown' }
    $bound = if ($Row.Proto -eq 'TCP') { $l.Tcp } else { $l.Udp }
    if ($bound -contains $port) { return 'listening' }
    return 'NOT listening'
}

Write-Host ''
Write-Host ('Comparing {0} segment probes:' -f $runs.Count) -ForegroundColor Cyan
foreach ($r in $runs) { Write-Host ('  - {0} (captured {1})' -f $r.SegmentName, $r.Timestamp) -ForegroundColor Cyan }
Write-Host ''

# ---------------------------------------------------------------------
# Build a lookup: one row per Target/Port/Proto, one column per segment
# ---------------------------------------------------------------------
$matrix = @{}
foreach ($run in $runs) {
    foreach ($t in $run.Targets) {
        foreach ($p in $t.Ports) {
            $key = '{0}|{1}|{2}' -f $t.Target, $p.Port, $p.Proto
            if (-not $matrix.ContainsKey($key)) {
                $matrix[$key] = [pscustomobject]@{
                    Target  = $t.Target
                    Port    = $p.Port
                    Proto   = $p.Proto
                    Name    = $p.Name
                    States  = [ordered]@{}
                    Details = [ordered]@{}
                }
            }
            $matrix[$key].States[$run.SegmentName] = $p.State
            # Detail (reply ratio etc.) exists in newer probe files only
            $d = ''
            if ($p.PSObject.Properties['Detail'] -and $p.Detail) { $d = [string]$p.Detail }
            $matrix[$key].Details[$run.SegmentName] = $d
        }
        # Dynamic RPC ports (TCP). Deterministic per run, so they diff too - the
        # classic "segments connected but the RPC range is blocked" case.
        foreach ($rp in $t.RpcPorts) {
            $key = '{0}|{1}|{2}' -f $t.Target, $rp.Port, 'TCP'
            if (-not $matrix.ContainsKey($key)) {
                $matrix[$key] = [pscustomobject]@{
                    Target  = $t.Target
                    Port    = $rp.Port
                    Proto   = 'TCP'
                    Name    = 'RPC dynamic'
                    States  = [ordered]@{}
                    Details = [ordered]@{}
                }
            }
            $matrix[$key].States[$run.SegmentName] = $rp.State
        }
        # Dynamic-RPC reachability (DCOM/RPC call), normalised to Reachable /
        # Unreachable / Unknown so access-denied (still reachable) does not read
        # as a difference - only a real connectivity asymmetry does.
        if ($t.RpcReach) {
            $key = '{0}|dynamic|RPC' -f $t.Target
            if (-not $matrix.ContainsKey($key)) {
                $matrix[$key] = [pscustomobject]@{
                    Target  = $t.Target
                    Port    = 'dynamic'
                    Proto   = 'RPC'
                    Name    = 'RPC dynamic (DCOM reach)'
                    States  = [ordered]@{}
                    Details = [ordered]@{}
                }
            }
            $matrix[$key].States[$run.SegmentName] = $t.RpcReach
            if ($t.RpcDetail) { $matrix[$key].Details[$run.SegmentName] = [string]$t.RpcDetail }
        }
    }
}

$rows = @($matrix.Values)

$diffRows = @($rows | Where-Object {
    $states = @($_.States.Values | Where-Object { $_ } | Select-Object -Unique)
    $states.Count -gt 1
})

# ---------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------
if ($diffRows.Count -eq 0) {
    Write-Host 'No differences found - every tested port behaved the same from every segment.' -ForegroundColor Green
    Write-Host 'That does not rule out a segmentation problem on a port/target nobody probed yet - it only clears what was tested.' -ForegroundColor DarkGray
}
else {
    Write-Host ('{0} of {1} target/port combination(s) behave differently depending on the segment:' -f $diffRows.Count, $rows.Count) -ForegroundColor Red
    Write-Host ''
    foreach ($row in ($diffRows | Sort-Object Target, Port)) {
        $lstate = Get-ListenerState $row
        $ltxt = ''
        if ($lstate -and $lstate -ne '-') { $ltxt = '   [target: {0}]' -f $lstate }
        Write-Host ('  {0}   port {1}/{2}   ({3}){4}' -f $row.Target, $row.Port, $row.Proto, $row.Name, $ltxt) -ForegroundColor Yellow
        foreach ($seg in $segmentNames) {
            $state = $row.States[$seg]
            if (-not $state) { $state = '(not tested)' }
            $detail = $row.Details[$seg]
            $cell = $state
            if ($detail) { $cell = '{0}  ({1})' -f $state, $detail }
            $colour = 'DarkYellow'
            if ($state -match 'Open|Responded|\bReachable') { $colour = 'Green' }
            elseif ($state -match 'Closed|Filtered|Unreachable|^Error') { $colour = 'Red' }
            elseif ($state -eq 'Not probed') { $colour = 'DarkGray' }
            Write-Host ('      {0,-32} {1}' -f $seg, $cell) -ForegroundColor $colour
        }
    }
}
Write-Host ''

# Rows where the target has nothing bound to the port: whatever the segments
# saw there is not a network finding, so call it out separately.
if ($haveListeners) {
    $noListen = @($rows | Where-Object { (Get-ListenerState $_) -eq 'NOT listening' })
    $unknownListen = @($rows | Where-Object { (Get-ListenerState $_) -eq 'unknown' } | Select-Object -ExpandProperty Target -Unique)
    if ($noListen.Count -gt 0) {
        Write-Host ('{0} port(s) have NO listener on the target - any "No response" there is a host/role question, not a network one:' -f $noListen.Count) -ForegroundColor Yellow
        foreach ($row in ($noListen | Sort-Object Target, Port)) {
            Write-Host ('  {0}   port {1}/{2}   ({3})' -f $row.Target, $row.Port, $row.Proto, $row.Name) -ForegroundColor Yellow
        }
        Write-Host ''
    }
    if ($unknownListen.Count -gt 0) {
        Write-Host ('Listener inventory unavailable for: {0} - their rows show listener = unknown.' -f ($unknownListen -join ', ')) -ForegroundColor DarkGray
        Write-Host ''
    }
}

# ---------------------------------------------------------------------
# Optional HTML report
# ---------------------------------------------------------------------
if ($HtmlReport) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<!doctype html><html><head><meta charset='utf-8'><title>Segment probe comparison</title><style>")
    [void]$sb.Append("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222;background:#fafafa;}")
    [void]$sb.Append("h1{color:#1a3d6d;}")
    [void]$sb.Append("table{border-collapse:collapse;width:100%;margin:12px 0;background:#fff;}")
    [void]$sb.Append("th,td{border:1px solid #ccc;padding:6px 10px;text-align:left;font-size:13px;}")
    [void]$sb.Append("th{background:#1a3d6d;color:#fff;}")
    [void]$sb.Append("tr.diff{font-weight:bold;}")
    [void]$sb.Append("td.open{background:#d4efdf;color:#186a3b;}")
    [void]$sb.Append("td.closed{background:#f5b7b1;color:#922b21;}")
    [void]$sb.Append("td.unclear{background:#fcf3cf;color:#7d6608;}")
    [void]$sb.Append("td.skipped{background:#eee;color:#777;}")
    [void]$sb.Append("td.nolisten{background:#fde9c9;color:#8a4b00;font-weight:bold;}")
    [void]$sb.Append("td.listen{color:#186a3b;}")
    [void]$sb.Append("span.detail{display:block;font-size:11px;font-weight:normal;color:#555;}")
    [void]$sb.Append(".meta{color:#666;font-size:12px;}")
    [void]$sb.Append("</style></head><body>")
    [void]$sb.Append('<h1>Segment probe comparison</h1>')
    [void]$sb.Append("<p class='meta'>Generated: " + (ConvertTo-HtmlEncoded ((Get-Date).ToString('yyyy-MM-dd HH:mm'))) + "</p>")

    [void]$sb.Append('<p>Segments compared:</p><ul>')
    foreach ($r in $runs) {
        [void]$sb.Append('<li><strong>' + (ConvertTo-HtmlEncoded $r.SegmentName) + '</strong> - captured ' + (ConvertTo-HtmlEncoded $r.Timestamp) + '</li>')
    }
    [void]$sb.Append('</ul>')

    [void]$sb.Append('<p>' + $rows.Count + ' target/port combination(s) tested, <strong>' + $diffRows.Count + ' differ</strong> across segments. Rows that differ are bold and listed first.</p>')
    if ($haveListeners) {
        [void]$sb.Append('<p>The <strong>Listener</strong> column is what is actually bound on the target itself (collected there, not from a segment). <strong>NOT listening</strong> means there was nothing to reach - a host/role question, not a network finding. A listener that still gets no reply from a segment is the real suspect.</p>')
    }
    [void]$sb.Append('<p class="meta">UDP rows send a real protocol request (DNS query, NTP request, CLDAP search) several times; the detail under each state is the reply ratio. "No response" on its own is never a firewall verdict. Kerberos/kpasswd over UDP are listed but not probed - Windows clients use TCP there.</p>')

    [void]$sb.Append('<table><tr><th>Target</th><th>Port</th><th>Proto</th><th>Service</th>')
    if ($haveListeners) { [void]$sb.Append('<th>Listener</th>') }
    foreach ($seg in $segmentNames) { [void]$sb.Append('<th>' + (ConvertTo-HtmlEncoded $seg) + '</th>') }
    [void]$sb.Append('</tr>')

    $sortedRows = @($diffRows | Sort-Object Target, Port) + @($rows | Where-Object { $diffRows -notcontains $_ } | Sort-Object Target, Port)

    foreach ($row in $sortedRows) {
        $isDiff = $diffRows -contains $row
        $rowClass = if ($isDiff) { " class='diff'" } else { '' }
        [void]$sb.Append("<tr$rowClass><td>" + (ConvertTo-HtmlEncoded $row.Target) + '</td><td>' + $row.Port + '</td><td>' + (ConvertTo-HtmlEncoded $row.Proto) + '</td><td>' + (ConvertTo-HtmlEncoded $row.Name) + '</td>')
        if ($haveListeners) {
            $lstate = Get-ListenerState $row
            $lcls = ''
            if ($lstate -eq 'NOT listening') { $lcls = " class='nolisten'" }
            elseif ($lstate -eq 'listening') { $lcls = " class='listen'" }
            [void]$sb.Append("<td$lcls>" + (ConvertTo-HtmlEncoded $lstate) + '</td>')
        }
        foreach ($seg in $segmentNames) {
            $state = $row.States[$seg]
            if (-not $state) { $state = '(not tested)' }
            $cls = 'unclear'
            if ($state -match 'Open|Responded|\bReachable') { $cls = 'open' }
            elseif ($state -match 'Closed|Filtered|Unreachable|^Error') { $cls = 'closed' }
            elseif ($state -eq 'Not probed') { $cls = 'skipped' }
            $cell = ConvertTo-HtmlEncoded $state
            $detail = $row.Details[$seg]
            if ($detail) { $cell += "<span class='detail'>" + (ConvertTo-HtmlEncoded $detail) + '</span>' }
            [void]$sb.Append("<td class='$cls'>" + $cell + '</td>')
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</table>')
    [void]$sb.Append("<p class='meta'>Generated by Compare-SegmentProbes.ps1 (AZITC). Read-only - this report reflects only the two or more Test-AdPortMatrix.ps1 runs fed into it.</p>")
    [void]$sb.Append('</body></html>')

    Set-Content -Path $HtmlReport -Value $sb.ToString() -Encoding UTF8
    Write-Host ('HTML report written: {0}' -f $HtmlReport) -ForegroundColor Green
    Write-Host ''
}
