<#
.SYNOPSIS
    Measures whether domain controllers are actually under memory pressure.

.DESCRIPTION
    "Free RAM" is a poor indicator on Windows: unused memory is deliberately
    filled with file system cache, so a low free-memory figure is the normal
    state and proves nothing.

    This script collects the counters that do carry meaning:

      Available MBytes  memory immediately available to processes.
                        Below roughly 10 % of installed RAM indicates pressure.
      Committed / Limit how much of the commit charge is used. Above ~90 %
                        the system is close to running out of backing store.
      Pages/sec         hard page faults. Sustained high values mean the server
                        is paging - the symptom that actually costs performance.
      LSASS working set the authentication process. A single reading says
                        nothing; only growth over days indicates a leak.
      LSASS handles     same - a trend, not a snapshot, is what matters.

.PARAMETER DC
    Domain controllers to query. Defaults to all DCs of the current domain.

.PARAMETER Csv
    Optional path. Appends the results with a timestamp, so the script can be
    run repeatedly (e.g. daily) to build the trend that a leak diagnosis needs.

.EXAMPLE
    .\Get-DcMemoryPressure.ps1

.EXAMPLE
    .\Get-DcMemoryPressure.ps1 -Csv C:\Temp\dcmem.csv

.NOTES
    AZITC - Alexander Zarenko IT Consulting
    PowerShell 5.1 compatible. Read-only, makes no changes.
    Requires remote performance counter and CIM access to the DCs.
#>
[CmdletBinding()]
param(
    [string[]] $DC,
    [string]   $Csv
)

# ---------------------------------------------------------------------
# Target DCs
# ---------------------------------------------------------------------
if (-not $DC) {
    try {
        $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain')
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
        $DC  = $dom.DomainControllers | ForEach-Object { $_.Name }
    }
    catch {
        Write-Host 'Could not enumerate DCs - specify them with -DC.' -ForegroundColor Red
        return
    }
}

$counters = @(
    '\Memory\Available MBytes'
    '\Memory\Committed Bytes'
    '\Memory\Commit Limit'
    '\Memory\Pages/sec'
    '\Process(lsass)\Working Set'
    '\Process(lsass)\Handle Count'
)

# Pick each counter out by name. Do NOT apply one unit to all of them -
# Available MBytes is in MB, Working Set is in bytes and Handle Count is a
# plain count. Dividing everything by 1MB is what produced a handle count
# of zero in an earlier version of this check.
function Get-Sample {
    param(
        [object[]] $Samples,
        [string]   $Match
    )

    $hit = $Samples | Where-Object { $_.Path -like ('*' + $Match) } | Select-Object -First 1

    if ($hit) { return $hit.CookedValue }
    return $null
}

$stamp   = Get-Date
$results = @()

foreach ($server in $DC) {

    Write-Verbose ('Querying {0}...' -f $server)

    try {
        $samples = (Get-Counter -Counter $counters -ComputerName $server -ErrorAction Stop).CounterSamples
    }
    catch {
        Write-Host ('{0}: counters unavailable - {1}' -f $server, $_.Exception.Message) -ForegroundColor Red
        continue
    }

    $availMb   = Get-Sample $samples '\memory\available mbytes'
    $committed = Get-Sample $samples '\memory\committed bytes'
    $limit     = Get-Sample $samples '\memory\commit limit'
    $pages     = Get-Sample $samples '\memory\pages/sec'
    $lsassWs   = Get-Sample $samples '\process(lsass)\working set'
    $lsassHnd  = Get-Sample $samples '\process(lsass)\handle count'

    # Installed RAM, to express Available MBytes as a percentage
    $totalMb = $null
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ComputerName $server -ErrorAction Stop
        $totalMb = [math]::Round($cs.TotalPhysicalMemory / 1MB, 0)
    }
    catch {
        Write-Verbose ('{0}: could not read installed RAM' -f $server)
    }

    $availPct = $null
    if ($totalMb -and $totalMb -gt 0) {
        $availPct = [math]::Round(($availMb / $totalMb) * 100, 1)
    }

    $commitPct = $null
    if ($limit -and $limit -gt 0) {
        $commitPct = [math]::Round(($committed / $limit) * 100, 1)
    }

    $results += [pscustomobject]@{
        Time        = $stamp
        DC          = $server
        TotalMB     = $totalMb
        AvailableMB = [math]::Round($availMb, 0)
        AvailablePc = $availPct
        CommitPc    = $commitPct
        PagesSec    = [math]::Round($pages, 0)
        LsassWsMB   = [math]::Round($lsassWs / 1MB, 0)
        LsassHandles= [math]::Round($lsassHnd, 0)
    }
}

if (-not $results) {
    Write-Host 'No data collected.' -ForegroundColor Red
    return
}

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
Write-Host ''
$results |
    Format-Table DC, TotalMB, AvailableMB, AvailablePc, CommitPc,
                 PagesSec, LsassWsMB, LsassHandles -AutoSize

# ---------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------
Write-Host 'Assessment:' -ForegroundColor Cyan

foreach ($r in $results) {

    $flags = @()

    if ($r.AvailablePc -ne $null -and $r.AvailablePc -lt 10) {
        $flags += ('Available memory {0}% of RAM' -f $r.AvailablePc)
    }

    if ($r.CommitPc -ne $null -and $r.CommitPc -gt 90) {
        $flags += ('Commit charge {0}% of limit' -f $r.CommitPc)
    }

    if ($r.PagesSec -gt 1000) {
        $flags += ('Pages/sec {0} - check whether sustained' -f $r.PagesSec)
    }

    if ($flags.Count -gt 0) {
        Write-Host ('  [!] {0}: {1}' -f $r.DC, ($flags -join '; ')) -ForegroundColor Yellow
    }
    else {
        Write-Host ('  [ok] {0}: no memory pressure' -f $r.DC) -ForegroundColor Green
    }
}

Write-Host ''
Write-Host 'Note: a single reading cannot evidence an LSASS leak. Run this' -ForegroundColor DarkGray
Write-Host 'repeatedly with -Csv and look for LsassWsMB / LsassHandles' -ForegroundColor DarkGray
Write-Host 'rising steadily over days. A flat trend rules a leak out.' -ForegroundColor DarkGray
Write-Host ''

if ($Csv) {
    $exists = Test-Path -LiteralPath $Csv
    $results | Export-Csv -LiteralPath $Csv -NoTypeInformation -Append:$exists
    Write-Host ('Appended to {0}' -f $Csv) -ForegroundColor DarkGray
}
