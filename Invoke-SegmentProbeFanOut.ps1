<#
.SYNOPSIS
    Fans Test-AdPortMatrix.ps1 out to one host per network segment via
    PowerShell remoting, collects every result into one folder, and runs
    Compare-SegmentProbes.ps1 once at least two results are present -
    falling back to a manual per-segment run wherever remoting itself
    cannot reach that segment.

.DESCRIPTION
    Running the port matrix from inside every segment is unavoidable - the
    whole point is testing reachability as experienced from each vantage
    point, which cannot be faked from one central host. This script only
    automates the mechanical part: it tries to reach a host inside each
    segment over WinRM and run Test-AdPortMatrix.ps1 there for you.

    That WinRM hop has the same irony the underlying problem does: if the
    network really is segmented badly enough, remoting into a given
    segment's jump host may fail for the exact same reason the AD ports
    would. When that happens for a segment, this script does NOT abort -
    it records the failure, tells you to run Test-AdPortMatrix.ps1 manually
    on a host actually inside that segment, and tells you exactly where to
    drop the resulting -OutFile JSON (ResultsFolder). Re-running this
    script later picks up anything already sitting in ResultsFolder,
    whether produced by remoting or dropped there by hand, and - once two
    or more results are present - automatically runs
    Compare-SegmentProbes.ps1 over all of them.

    The script sent to each remote host is Test-AdPortMatrix.ps1's own TEXT
    content (read locally and transmitted over the remoting session, not a
    separate copy that could drift) with its result forced through -Json so
    it comes back as structured data instead of a console table. It is
    invoked with -SegmentName set from your -Segments entry and the same
    -Target/-ProbeMs/-RpcSampleCount you give this script, splatted BY NAME
    against the remote copy's own param() block - so a future parameter
    added to Test-AdPortMatrix.ps1 does not silently shift positional
    arguments here.

.PARAMETER Segments
    One or more segments to test. Each entry is either:
      - a plain string: the host's name, used as both -SegmentName and
        -ComputerName (the common case - remoting into a handful of named
        hosts with no separate "segment label" or per-host credential).
      - a hashtable: { Name (required), ComputerName (required),
        Credential (optional, falls back to -Credential then the current
        identity) } - use this when the human-readable segment label
        should differ from the host you remote into, or a given host needs
        its own credential.
    The two forms can be mixed in the same array.
    Examples:
      -Segments dc6,dc7
      -Segments @{ Name = 'HQ'; ComputerName = 'jump-hq' }, @{ Name = 'Branch-VLAN20'; ComputerName = 'jump-branch.contoso.com' }

.PARAMETER Target
    Targets passed straight through to Test-AdPortMatrix.ps1 on every
    segment - the same DC(s)/server(s), tested from every vantage point.
    Required: Test-AdPortMatrix.ps1's own auto-discovery (all DCs of the
    current domain) would, run inside a remote scriptblock, resolve against
    whatever domain the JUMP HOST happens to belong to - rarely what you
    want when comparing segments against the same fixed target list - so
    this script does not fall back to it.

.PARAMETER Credential
    Default credential for any -Segments entry that does not specify its
    own.

.PARAMETER ProbeMs
    Passed straight through to Test-AdPortMatrix.ps1 on every segment.

.PARAMETER UdpRepeat
    Passed straight through to Test-AdPortMatrix.ps1 on every segment.

.PARAMETER RpcSampleCount
    Passed straight through to Test-AdPortMatrix.ps1 on every segment.

.PARAMETER NoListenerCheck
    Skip the listener inventory. By default, after the segment probes, this
    script remotes into each -Target itself (same -Credential) and records
    which TCP ports are in LISTEN state and which UDP ports have a bound
    endpoint there. Compare-SegmentProbes.ps1 then shows, per row, whether
    anything is listening on the target at all - which is what separates
    "nothing to reach" (a host/role question, not a network one) from "not
    reachable from this segment". A target that cannot be remoted into is
    simply reported as unknown; the comparison still runs.

.PARAMETER ResultsFolder
    Where each segment's JSON is collected, and where you can manually drop
    a result for any segment remoting could not reach. Defaults to a
    timestamped folder in the current directory. Pass the same folder again
    on a later run (with -SkipExisting) to pick up manual drops without
    re-probing segments that already succeeded.

.PARAMETER SkipExisting
    Do not re-probe a segment whose result file already exists in
    ResultsFolder - use this on a second pass after dropping in a manual
    file for the segment(s) that failed to remote the first time.

.PARAMETER HtmlReport
    Passed straight through to Compare-SegmentProbes.ps1 for the final
    comparison, once two or more results are present.

.EXAMPLE
    # Simple case: remote into dc6 and dc7 by name, no separate segment label.
    .\Invoke-SegmentProbeFanOut.ps1 -Segments dc6,dc7 -Target dc6,dc7 -HtmlReport segment-diff.html

.EXAMPLE
    # Segment label differs from the host remoted into, and/or needs its own credential.
    $segments = @(
        @{ Name = 'HQ';           ComputerName = 'jump-hq' },
        @{ Name = 'Branch-VLAN20'; ComputerName = 'jump-branch.contoso.com' }
    )
    .\Invoke-SegmentProbeFanOut.ps1 -Segments $segments -Target dc01.contoso.com -HtmlReport segment-diff.html

.EXAMPLE
    # Second pass after dropping Branch-VLAN20.json by hand into the same folder:
    .\Invoke-SegmentProbeFanOut.ps1 -Segments $segments -Target dc01.contoso.com `
        -ResultsFolder .\SegmentProbes_20240101_120000 -SkipExisting -HtmlReport segment-diff.html

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible. This script itself only reads
    Test-AdPortMatrix.ps1's text and writes JSON/HTML result files - the
    read-only guarantee for the actual network probing is
    Test-AdPortMatrix.ps1's own, unchanged whether run locally or remoted
    in by this wrapper.
    Requires PowerShell remoting (WinRM) reachable from here to each
    segment's ComputerName, and Compare-SegmentProbes.ps1 /
    Test-AdPortMatrix.ps1 present in the same folder as this script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [object[]] $Segments,

    [Parameter(Mandatory = $true)]
    [string[]] $Target,

    [pscredential] $Credential,

    [int] $ProbeMs = 2000,
    [int] $UdpRepeat = 3,
    [int] $RpcSampleCount = 10,

    [string] $ResultsFolder,

    [switch] $SkipExisting,

    [switch] $NoListenerCheck,

    [string] $HtmlReport
)

$scriptDir      = Split-Path -Parent $MyInvocation.MyCommand.Path
$portMatrixPath = Join-Path $scriptDir 'Test-AdPortMatrix.ps1'
$comparePath    = Join-Path $scriptDir 'Compare-SegmentProbes.ps1'

if (-not (Test-Path $portMatrixPath)) {
    Write-Host ('Test-AdPortMatrix.ps1 not found next to this script ({0}).' -f $scriptDir) -ForegroundColor Red
    return
}
if (-not (Test-Path $comparePath)) {
    Write-Host ('Compare-SegmentProbes.ps1 not found next to this script ({0}).' -f $scriptDir) -ForegroundColor Red
    return
}

if (-not $ResultsFolder) {
    $ResultsFolder = Join-Path (Get-Location) ('SegmentProbes_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
if (-not (Test-Path $ResultsFolder)) {
    New-Item -ItemType Directory -Path $ResultsFolder -Force | Out-Null
}
$ResultsFolder = (Resolve-Path $ResultsFolder).Path

function Get-SafeFileName {
    param([string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern = '[' + [Regex]::Escape($invalid) + ']'
    return ($Name -replace $pattern, '_')
}

$portMatrixCode = Get-Content -Path $portMatrixPath -Raw

Write-Host ''
Write-Host ('Results folder: {0}' -f $ResultsFolder) -ForegroundColor Cyan
Write-Host ('Targets:        {0}' -f ($Target -join ', ')) -ForegroundColor Cyan
Write-Host ''

$outcomes = New-Object System.Collections.ArrayList

foreach ($rawSeg in $Segments) {

    if ($rawSeg -is [string]) {
        $seg = @{ Name = $rawSeg; ComputerName = $rawSeg }
    }
    elseif ($rawSeg -is [hashtable]) {
        $seg = $rawSeg
    }
    else {
        Write-Host ('Skipping unsupported -Segments entry (expected a host name or a hashtable): {0}' -f $rawSeg) -ForegroundColor Red
        continue
    }

    if (-not $seg.Name -or -not $seg.ComputerName) {
        Write-Host ('Skipping a -Segments entry missing Name or ComputerName: {0}' -f ($seg | Out-String)) -ForegroundColor Red
        continue
    }

    $safeName   = Get-SafeFileName $seg.Name
    $resultFile = Join-Path $ResultsFolder ($safeName + '.json')

    if ($SkipExisting -and (Test-Path $resultFile)) {
        Write-Host ('{0}: result already present, skipping (-SkipExisting).' -f $seg.Name) -ForegroundColor DarkGray
        [void]$outcomes.Add([pscustomobject]@{ Segment = $seg.Name; Status = 'Existing'; File = $resultFile; Detail = 'Already in ResultsFolder' })
        continue
    }

    $cred = $seg.Credential
    if (-not $cred) { $cred = $Credential }

    Write-Host ('{0}: remoting into {1} ...' -f $seg.Name, $seg.ComputerName) -ForegroundColor Cyan

    $icParams = @{
        ComputerName = $seg.ComputerName
        ErrorAction  = 'Stop'
    }
    if ($cred) { $icParams.Credential = $cred }

    $remoteParams = @{
        Target         = $Target
        SegmentName    = $seg.Name
        ProbeMs        = $ProbeMs
        UdpRepeat      = $UdpRepeat
        RpcSampleCount = $RpcSampleCount
        Json           = $true
    }

    try {
        $jsonText = Invoke-Command @icParams -ScriptBlock {
            param($Code, $Params)
            $fn = [scriptblock]::Create($Code)
            & $fn @Params
        } -ArgumentList $portMatrixCode, $remoteParams

        if (-not $jsonText) {
            throw 'Remote run returned no output - check the remote PowerShell version/execution policy.'
        }

        # Invoke-Command can hand back a compressed JSON string split across
        # several pipeline objects on some hosts; rejoin before saving/parsing.
        $jsonText = ($jsonText -join '')
        $null = $jsonText | ConvertFrom-Json -ErrorAction Stop   # validate before saving
        Set-Content -Path $resultFile -Value $jsonText -Encoding UTF8

        Write-Host ('{0}: OK - saved {1}' -f $seg.Name, $resultFile) -ForegroundColor Green
        [void]$outcomes.Add([pscustomobject]@{ Segment = $seg.Name; Status = 'Remoted'; File = $resultFile; Detail = 'OK' })
    }
    catch {
        $msg = $_.Exception.Message
        Write-Host ('{0}: could not remote into {1}: {2}' -f $seg.Name, $seg.ComputerName, $msg) -ForegroundColor Red
        Write-Host ('{0}: run manually from a host actually inside that segment:' -f $seg.Name) -ForegroundColor Yellow
        Write-Host ('      .\Test-AdPortMatrix.ps1 -Target {0} -SegmentName "{1}" -OutFile "{2}"' -f ($Target -join ','), $seg.Name, $resultFile) -ForegroundColor Yellow
        Write-Host ('  then re-run this script with the same -ResultsFolder (and -SkipExisting) to pick it up.') -ForegroundColor Yellow
        [void]$outcomes.Add([pscustomobject]@{ Segment = $seg.Name; Status = 'Failed'; File = $resultFile; Detail = $msg })
    }
    Write-Host ''
}

Write-Host '--- Summary ---' -ForegroundColor Cyan
foreach ($o in $outcomes) {
    $colour = 'Red'
    if ($o.Status -eq 'Remoted') { $colour = 'Green' }
    elseif ($o.Status -eq 'Existing') { $colour = 'DarkGray' }
    Write-Host ('  {0,-24} {1,-10} {2}' -f $o.Segment, $o.Status, $o.Detail) -ForegroundColor $colour
}
Write-Host ''

# ---------------------------------------------------------------------
# Listener inventory on the targets themselves. "Is anything bound to this
# port on the DC" is a property of the target, not of the segment probing
# it, so it is collected once from here, not per segment. Failure to reach
# a target is recorded as unknown and never blocks the comparison.
# ---------------------------------------------------------------------
$listenerFile = Join-Path $ResultsFolder '_listeners.json'
if (-not $NoListenerCheck) {
    Write-Host 'Collecting listener inventory on the targets ...' -ForegroundColor Cyan
    $listenerTargets = New-Object System.Collections.ArrayList
    foreach ($t in $Target) {
        $icParams = @{ ComputerName = $t; ErrorAction = 'Stop' }
        if ($Credential) { $icParams.Credential = $Credential }
        try {
            $inv = Invoke-Command @icParams -ScriptBlock {
                $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique)
                $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique)
                [pscustomobject]@{ Computer = $env:COMPUTERNAME; Tcp = $tcp; Udp = $udp }
            }
            [void]$listenerTargets.Add([pscustomobject]@{
                Target   = $t
                Status   = 'OK'
                Computer = $inv.Computer
                Tcp      = @($inv.Tcp | ForEach-Object { [int]$_ })
                Udp      = @($inv.Udp | ForEach-Object { [int]$_ })
            })
            Write-Host ('  {0}: {1} TCP listeners, {2} UDP endpoints' -f $t, @($inv.Tcp).Count, @($inv.Udp).Count) -ForegroundColor Green
        }
        catch {
            [void]$listenerTargets.Add([pscustomobject]@{ Target = $t; Status = ('Failed: ' + $_.Exception.Message); Computer = $null; Tcp = @(); Udp = @() })
            Write-Host ('  {0}: listener inventory unavailable ({1}) - rows for this target will show listener = unknown' -f $t, $_.Exception.Message) -ForegroundColor Yellow
        }
    }
    [pscustomobject]@{ Timestamp = (Get-Date).ToString('o'); Targets = $listenerTargets } |
        ConvertTo-Json -Depth 5 | Set-Content -Path $listenerFile -Encoding UTF8
    Write-Host ''
}

# Segment results only - the listener inventory (and anything else starting
# with an underscore) is not a probe file.
$allResultFiles = @(Get-ChildItem -Path $ResultsFolder -Filter '*.json' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike '_*' } | Select-Object -ExpandProperty FullName)

if ($allResultFiles.Count -lt 2) {
    Write-Host ('Only {0} result file(s) in {1} - need at least 2 to compare.' -f $allResultFiles.Count, $ResultsFolder) -ForegroundColor Yellow
    Write-Host 'Drop more in there (manually, or by re-running this script after fixing remoting) and either re-run this script or call Compare-SegmentProbes.ps1 yourself.' -ForegroundColor Yellow
    return
}

Write-Host ('Running Compare-SegmentProbes.ps1 over {0} result file(s) ...' -f $allResultFiles.Count) -ForegroundColor Cyan
Write-Host ''

$compareParams = @{ InputFile = $allResultFiles }
if ($HtmlReport) { $compareParams.HtmlReport = $HtmlReport }
if (Test-Path $listenerFile) { $compareParams.ListenerFile = $listenerFile }

& $comparePath @compareParams
