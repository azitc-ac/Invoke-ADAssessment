<#
.SYNOPSIS
    Read-only Active Directory Health & Hygiene Assessment (PowerShell 5.1).

.DESCRIPTION
    Collects health, security and hygiene metrics of an AD domain in a purely
    READ-ONLY fashion and generates an HTML report. Intended as a lightweight
    wrapper around third-party tools (Purple Knight, ADxRay, BloodHound,
    Locksmith, GPOZaurr).

    Makes NO changes. dcdiag/repadmin are only read/queried.

.REQUIREMENTS
    - PowerShell 5.1
    - RSAT: ActiveDirectory module (Import-Module ActiveDirectory)
    - Run as an account with forest-wide read rights (DA/EA assumed in scope)
    - Ideally run on a DC or admin host with RSAT

.PARAMETER OutputPath
    Target folder for the report. Default: .\ADAssessment_<date>

.PARAMETER InactiveDays
    Threshold (days) for inactive accounts. Default 90.

.NOTES
    Author: AZITC (Alexander Zarenko IT Consulting)
    Save file as UTF-8 with BOM.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\ADAssessment_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [int]$InactiveDays = 90
)

$ErrorActionPreference = 'Continue'
$script:Findings = New-Object System.Collections.ArrayList
$script:Sections = New-Object System.Collections.ArrayList

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) { 'WARN' {'Yellow'} 'ERROR' {'Red'} 'OK' {'Green'} default {'Gray'} }
    Write-Host ("[{0}] [{1}] {2}" -f $ts, $Level, $Message) -ForegroundColor $color
}

# Wraps an English/German text pair for the bilingual HTML report. If $De is
# omitted it falls back to $En (keeps language-neutral tokens like numbers working
# without a separate German copy at every call site).
function Bi {
    param([string]$En = '', [string]$De = '')
    if ([string]::IsNullOrEmpty($De)) { $De = $En }
    return [pscustomobject]@{ EN = $En; DE = $De }
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,   # Critical / High / Medium / Low / Info
        $Finding,
        $Detail = (Bi '' ''),
        $Recommendation = (Bi '' ''),
        [string]$Anchor = ''
    )
    [void]$script:Findings.Add([pscustomobject]@{
        Category       = $Category
        Severity       = $Severity
        Finding        = $Finding
        Detail         = $Detail
        Recommendation = $Recommendation
        Anchor         = $Anchor
    })
}

$script:AnchorSeq = 0
function New-Anchor {
    $script:AnchorSeq++
    return ("f{0:D2}" -f $script:AnchorSeq)
}

# Creates a Finding AND its matching detail section with identical (bilingual)
# wording + anchor. $Objects = list of affected accounts/objects (rendered as a table).
function Add-FindingWithObjects {
    param(
        [string]$Category,
        [string]$Severity,
        $Title,           # bilingual wording shared by the Finding headline and the section heading
        [object]$Objects,
        $Detail = (Bi '' ''),
        $Recommendation = (Bi '' ''),
        $Note = (Bi '' '')
    )
    $count  = @($Objects).Count
    $anchor = New-Anchor
    $headline = Bi "$count $($Title.EN)" "$count $($Title.DE)"
    Add-Finding $Category $Severity $headline $Detail $Recommendation $anchor
    Add-Section $headline $Objects $Note $anchor
}

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $Text = $Text.Replace('&','&amp;')
    $Text = $Text.Replace('<','&lt;')
    $Text = $Text.Replace('>','&gt;')
    $Text = $Text.Replace('"','&quot;')
    return $Text
}

# Renders a bilingual (Bi) value as two spans toggled via CSS/JS; a plain string is HTML-encoded as-is.
function Format-Bi {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value.PSObject.Properties.Name -contains 'EN') {
        $en = ConvertTo-HtmlEncoded ([string]$Value.EN)
        $de = ConvertTo-HtmlEncoded ([string]$Value.DE)
        return "<span class='lang-en'>$en</span><span class='lang-de'>$de</span>"
    }
    return ConvertTo-HtmlEncoded ([string]$Value)
}

# Extracts plain (non-HTML) text for one language from a bilingual (Bi) value, or
# returns a plain string unchanged. Used for the CSV exports.
function Get-BiText {
    param($Value, [string]$Lang = 'EN')
    if ($null -eq $Value) { return '' }
    if ($Value.PSObject.Properties.Name -contains $Lang) { return [string]$Value.$Lang }
    return [string]$Value
}

function Add-Section {
    param($Title, [object]$Data, $Note = (Bi '' ''), [string]$Anchor = '')
    [void]$script:Sections.Add([pscustomobject]@{
        Title  = $Title
        Data   = $Data
        Note   = $Note
        Anchor = $Anchor
    })
}

# --- Compliance framework (target/actual with traffic-light rating) --------
# Rating: 'good' (green, better than recommended) | 'meets' (black, meets recommendation)
#         'warn' (yellow, slightly worse) | 'bad' (red, significantly worse) | 'na'
$script:Compliance = New-Object System.Collections.ArrayList

# Source register (rendered as a footnote)
$script:Sources = [ordered]@{
    'CIS'    = Bi 'CIS Microsoft Windows Server 2025 Benchmark v2.0.0 (L1) - www.cisecurity.org' 'CIS Microsoft Windows Server 2025 Benchmark v2.0.0 (L1) - www.cisecurity.org'
    'MSFT'   = Bi 'Microsoft Security Baseline / password policy recommendations - learn.microsoft.com' 'Microsoft Security Baseline / Passwort-Policy-Empfehlungen - learn.microsoft.com'
    'MDI'    = Bi 'Microsoft Defender for Identity - Recommended Action: change KRBTGT password (>180 days) - learn.microsoft.com' 'Microsoft Defender for Identity - Empfohlene Aktion: KRBTGT-Passwort aendern (>180 Tage) - learn.microsoft.com'
    'MSFTL'  = Bi 'Microsoft - Domain/Forest Functional Levels (Windows Server 2016+ recommended) - learn.microsoft.com' 'Microsoft - Domain-/Forest-Funktionsebenen (Windows Server 2016+ empfohlen) - learn.microsoft.com'
    'MSTIER' = Bi 'Microsoft - Securing Privileged Access / Enterprise Access Model (minimize Tier-0) - learn.microsoft.com' 'Microsoft - Securing Privileged Access / Enterprise Access Model (Tier-0 minimieren) - learn.microsoft.com'
    'MSHARD' = Bi 'Microsoft - Disable SMBv1 / LDAP signing & channel binding / network security hardening - learn.microsoft.com' 'Microsoft - SMBv1 deaktivieren / LDAP-Signing & Channel Binding / Netzwerk-Hardening - learn.microsoft.com'
    'MSDR'   = Bi 'Microsoft - AD Forest Recovery & tombstoneLifetime (default 180 days) - learn.microsoft.com' 'Microsoft - AD Forest Recovery & tombstoneLifetime (Standard 180 Tage) - learn.microsoft.com'
    'MSLAPS' = Bi 'Microsoft - Windows LAPS (manage & rotate local admin passwords) - learn.microsoft.com' 'Microsoft - Windows LAPS (lokale Admin-Passwoerter verwalten & rotieren) - learn.microsoft.com'
}

function Add-Compliance {
    param(
        $Check,           # check item
        $IstValue,        # actual
        $SollValue,       # target (recommendation)
        [ValidateSet('good','meets','warn','bad','na')][string]$Rating,
        [string]$SourceKey = '', # key into $script:Sources
        $Comment = (Bi '' '')
    )
    [void]$script:Compliance.Add([pscustomobject]@{
        Check   = $Check
        Ist     = $IstValue
        Soll    = $SollValue
        Rating  = $Rating
        Source  = $SourceKey
        Comment = $Comment
    })
}

# --- Preparation -------------------------------------------------------------
Write-Log "Starting AD assessment." 'INFO'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ActiveDirectory module not found. Install RSAT." 'ERROR'
    return
}
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$OutputPath = (Resolve-Path $OutputPath).Path
Write-Log "Report folder: $OutputPath" 'INFO'

# --- 1. Forest / Domain / FSMO ---------------------------------------------
Write-Log "Collecting forest/domain/FSMO ..." 'INFO'
try {
    $forest = Get-ADForest
    $domain = Get-ADDomain

    $topo = [pscustomobject]@{
        ForestName            = $forest.Name
        ForestFunctionalLevel = $forest.ForestMode
        DomainName            = $domain.DNSRoot
        DomainFunctionalLevel = $domain.DomainMode
        Domains               = ($forest.Domains -join ', ')
        Sites                 = ($forest.Sites -join ', ')
        SchemaMaster          = $forest.SchemaMaster
        DomainNamingMaster    = $forest.DomainNamingMaster
        PDCEmulator           = $domain.PDCEmulator
        RIDMaster             = $domain.RIDMaster
        InfrastructureMaster  = $domain.InfrastructureMaster
    }
    Add-Section (Bi "Forest / Domain / FSMO" "Forest / Domain / FSMO") $topo

    foreach ($pair in @(@('Forest Functional Level','Forest-Funktionsebene', "$($forest.ForestMode)"), @('Domain Functional Level','Domain-Funktionsebene', "$($domain.DomainMode)"))) {
        $lvl = $pair[2]
        $lvlRating = if ($lvl -match '2025') { 'good' } elseif ($lvl -match '2016|2019|2022') { 'meets' } elseif ($lvl -match '2012') { 'warn' } else { 'bad' }
        Add-Compliance (Bi $pair[0] $pair[1]) $lvl (Bi "Windows2016 or higher" "Windows2016 oder hoeher") $lvlRating 'MSFTL' `
            (Bi "From 2016 onward, e.g. Credential Guard / advanced Kerberos features become available." "Ab 2016 u.a. Credential Guard / erweiterte Kerberos-Features nutzbar.")
        if ("$lvl" -match '2008|2003|2000|2012') {
            Add-Finding 'Topology' 'Medium' (Bi "Low functional level: $lvl (target >=2016)" "Niedrige Funktionsebene: $lvl (Soll >=2016)") `
                (Bi "An older functional level is active." "Aeltere Funktionsebene aktiv.") (Bi "Raise to at least Windows Server 2016 (after a compatibility check)." "Auf mind. Windows Server 2016 anheben (nach Kompatibilitaetspruefung).")
        }
    }
} catch { Write-Log "Forest/domain query failed: $_" 'ERROR' }

# --- 2. Domain Controller Inventory ----------------------------------------
Write-Log "Collecting DC inventory ..." 'INFO'
try {
    $dcs = Get-ADDomainController -Filter * |
        Select-Object HostName, Site, IPv4Address, OperatingSystem, IsGlobalCatalog, IsReadOnly, `
            @{n='OperationMasterRoles';e={ ($_.OperationMasterRoles -join ', ') }}
    Add-Section (Bi "Domain Controllers" "Domain Controllers") $dcs

    foreach ($dc in $dcs) {
        if ($dc.OperatingSystem -match '2008|2012') {
            Add-Finding 'DC' 'High' (Bi "DC with legacy OS: $($dc.HostName)" "DC mit Legacy-OS: $($dc.HostName)") `
                (Bi "$($dc.OperatingSystem)" "$($dc.OperatingSystem)") (Bi "OS is EOL/near EOL. Migrate the DC to 2019/2022/2025." "OS ist EOL/nahe EOL. DC auf 2019/2022/2025 migrieren.")
        }
    }
} catch { Write-Log "DC query failed: $_" 'ERROR' }

# --- 3. dcdiag / repadmin (read-only) ---------------------------------------
Write-Log "Running dcdiag/repadmin (read-only) ..." 'INFO'
try {
    $dcdiag = & dcdiag /e /c 2>&1 | Out-String
    Set-Content -Path (Join-Path $OutputPath 'dcdiag.txt') -Value $dcdiag -Encoding UTF8

    # EN + DE patterns (dcdiag output is locale-dependent; internal test names like 'SystemLog' stay untranslated)
    $failedTests = New-Object System.Collections.ArrayList
    foreach ($m in (Select-String -InputObject $dcdiag -Pattern '(\S+)\s+failed test\s+(\S+)' -AllMatches).Matches) {
        [void]$failedTests.Add([pscustomobject]@{ DC = $m.Groups[1].Value; Test = $m.Groups[2].Value })
    }
    foreach ($m in (Select-String -InputObject $dcdiag -Pattern '(\S+)\s+hat den Test\s+(\S+)\s+nicht bestanden' -AllMatches).Matches) {
        [void]$failedTests.Add([pscustomobject]@{ DC = $m.Groups[1].Value; Test = $m.Groups[2].Value })
    }

    # Generic hit-count fallback (in case test name/DC can't be extracted due to unexpected localization)
    $genericFail = Select-String -InputObject $dcdiag -Pattern 'failed test|nicht bestanden' -AllMatches

    if (@($failedTests).Count -gt 0) {
        # Known "noisy" tests: often fail on harmless eventlog warnings alone (usually transient)
        $noisyTests = @('SystemLog','DFSREvent')
        $other = @($failedTests | Where-Object { $_.Test -notin $noisyTests })
        $noisy = @($failedTests | Where-Object { $_.Test -in $noisyTests })

        if (@($other).Count -gt 0) {
            Add-FindingWithObjects 'Health' 'High' (Bi "dcdiag reports failed tests" "dcdiag meldet fehlgeschlagene Tests") $other `
                (Bi "See dcdiag.txt for the full text of each test." "Siehe dcdiag.txt fuer den Volltext je Test.") (Bi "Investigate each failed DC test individually." "Fehlgeschlagene DC-Tests einzeln untersuchen.")
        }
        if (@($noisy).Count -gt 0) {
            Add-FindingWithObjects 'Health' 'Medium' (Bi "dcdiag: SystemLog/DFSREvent warnings" "dcdiag: SystemLog/DFSREvent-Warnungen") $noisy `
                (Bi "SystemLog/DFSREvent often fail on harmless eventlog warnings alone - usually transient." "SystemLog/DFSREvent schlagen haeufig schon bei harmlosen Eventlog-Warnungen an - oft transient.") `
                (Bi "Check the System/DFSR event log on the affected DC; investigate further if it recurs across multiple runs." "System-/DFSR-Eventlog auf dem betroffenen DC pruefen; bei wiederholtem Auftreten ueber mehrere Laeufe genauer untersuchen.")
        }
    } elseif ($genericFail -and $genericFail.Matches.Count -gt 0) {
        Add-Finding 'Health' 'High' (Bi "dcdiag reports failed tests" "dcdiag meldet fehlgeschlagene Tests") `
            (Bi "$($genericFail.Matches.Count) match(es). See dcdiag.txt." "$($genericFail.Matches.Count) Treffer. Siehe dcdiag.txt.") (Bi "Investigate each failed DC test individually." "Fehlgeschlagene DC-Tests einzeln untersuchen.")
    }
} catch { Write-Log "dcdiag failed: $_" 'WARN' }

try {
    $replsum = & repadmin /replsummary 2>&1 | Out-String
    Set-Content -Path (Join-Path $OutputPath 'repadmin_replsummary.txt') -Value $replsum -Encoding UTF8
    if ($replsum -match '\b([1-9]\d*)\s*/\s*\d+') {
        Add-Finding 'Health' 'Medium' (Bi "repadmin reports possible replication errors" "repadmin meldet moegliche Replikationsfehler") `
            (Bi "See repadmin_replsummary.txt (the 'Fails' column)." "Siehe repadmin_replsummary.txt (Spalte 'Fails').") (Bi "Track down replication errors per DC (repadmin /showrepl)." "Replikationsfehler je DC nachverfolgen (repadmin /showrepl).")
    }
} catch { Write-Log "repadmin failed: $_" 'WARN' }

# --- 4. Privileged Groups ----------------------------------------------------
Write-Log "Analyzing privileged groups ..." 'INFO'
$privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators')
$privResult = New-Object System.Collections.ArrayList
$privAnchor = New-Anchor
foreach ($g in $privGroups) {
    try {
        $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop
        [void]$privResult.Add([pscustomobject]@{ Group = $g; Count = @($members).Count; Members = (($members | Select-Object -Expand SamAccountName) -join ', ') })
        if ($g -in @('Domain Admins','Enterprise Admins') -and @($members).Count -gt 5) {
            Add-Finding 'Privileged' 'High' (Bi "$g has $(@($members).Count) members" "$g hat $(@($members).Count) Mitglieder") `
                (Bi "Too many permanently privileged accounts (see the 'Privileged Groups' section)." "Zu viele dauerhaft privilegierte Konten (siehe Sektion 'Privilegierte Gruppen').") `
                (Bi "Reduce to the minimum required accounts; introduce JIT/JEA." "Auf minimal noetige Konten reduzieren; JIT/JEA einfuehren.") $privAnchor
        }
        if ($g -in @('Account Operators','Server Operators') -and @($members).Count -gt 0) {
            Add-Finding 'Privileged' 'Medium' (Bi "$g is populated ($(@($members).Count))" "$g ist besetzt ($(@($members).Count))") `
                (Bi "Legacy operator group with far-reaching rights (see the 'Privileged Groups' section)." "Legacy-Operatorgruppen mit weitreichenden Rechten (siehe Sektion 'Privilegierte Gruppen').") `
                (Bi "Review/remove memberships (frequently unintentionally privileged)." "Mitgliedschaften pruefen/entfernen (haeufig unbeabsichtigt privilegiert).") $privAnchor
        }
        # Compliance target for the critical Tier-0 groups
        if ($g -in @('Domain Admins','Enterprise Admins')) {
            $cnt = @($members).Count
            $daRating = if ($cnt -le 3) { 'good' } elseif ($cnt -le 5) { 'meets' } elseif ($cnt -le 10) { 'warn' } else { 'bad' }
            Add-Compliance (Bi "$g - member count" "$g - Anzahl Mitglieder") "$cnt" (Bi "<= 5 (as few as possible)" "<= 5 (moeglichst wenige)") $daRating 'MSTIER' `
                (Bi "Minimize Tier-0 accounts; ideally just-in-time rather than permanent." "Tier-0-Konten minimieren; idealerweise Just-in-Time statt dauerhaft.")
        }
    } catch { }
}
Add-Section (Bi "Privileged Groups" "Privilegierte Gruppen") $privResult '' $privAnchor

# --- 5. Kerberos / Delegation ------------------------------------------------
Write-Log "Checking Kerberos/delegation ..." 'INFO'
try {
    # Kerberoastable: user accounts with an SPN (excluding krbtgt)
    $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like '*' -and Enabled -eq $true } -Properties ServicePrincipalName, PasswordLastSet |
        Where-Object { $_.SamAccountName -ne 'krbtgt' } |
        Select-Object SamAccountName, PasswordLastSet, @{n='SPNs';e={ ($_.ServicePrincipalName -join '; ') }}, DistinguishedName
    if (@($spnUsers).Count -gt 0) {
        Add-FindingWithObjects 'Kerberos' 'High' (Bi "User accounts with an SPN (Kerberoasting risk)" "User-Konten mit SPN (Kerberoasting-Risiko)") $spnUsers `
            (Bi "Service accounts with an SPN can be attacked offline (Kerberoasting)." "Service-Konten mit SPN sind offline angreifbar (Kerberoasting).") `
            (Bi "Use gMSA or 25+ character passwords, rotate regularly." "gMSA nutzen bzw. 25+ Zeichen Passwoerter, regelmaessige Rotation.")
    }

    # AS-REP roasting: no Kerberos pre-auth (UAC bit 0x400000 = DONT_REQ_PREAUTH)
    $asrep = Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' |
        Select-Object SamAccountName, DistinguishedName
    if (@($asrep).Count -gt 0) {
        Add-FindingWithObjects 'Kerberos' 'High' (Bi "Accounts without Kerberos pre-auth (AS-REP roasting risk)" "Konten ohne Kerberos-Pre-Auth (AS-REP-Roasting-Risiko)") $asrep `
            (Bi "AS-REP roasting is possible." "AS-REP-Roasting moeglich.") `
            (Bi "Remove 'Do not require Kerberos preauthentication'." "'Do not require Kerberos preauthentication' entfernen.")
    }

    # Unconstrained delegation (excluding DCs)
    $unconstrained = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, PrimaryGroupID |
        Where-Object { $_.PrimaryGroupID -ne 516 } | Select-Object Name, DNSHostName, DistinguishedName
    if (@($unconstrained).Count -gt 0) {
        Add-FindingWithObjects 'Delegation' 'Critical' (Bi "Objects with unconstrained delegation" "Objekte mit Unconstrained Delegation") $unconstrained `
            (Bi "Allows impersonation up to Tier 0." "Erlaubt Impersonation bis Tier 0.") `
            (Bi "Switch to constrained delegation/RBCD or remove delegation; put Tier-0 accounts in Protected Users." "Auf Constrained/RBCD umstellen oder Delegation entfernen; Tier-0-Konten in Protected Users.")
    }
} catch { Write-Log "Kerberos analysis partially failed: $_" 'WARN' }

# --- 6. krbtgt Password Age --------------------------------------------------
try {
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
    $age = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
    Add-Section (Bi "krbtgt" "krbtgt") ([pscustomobject]@{ PasswordLastSet = $krbtgt.PasswordLastSet; AgeDays = $age })
    $krbRating = if ($age -le 90) { 'good' } elseif ($age -le 180) { 'meets' } elseif ($age -le 365) { 'warn' } else { 'bad' }
    Add-Compliance (Bi "krbtgt password age" "krbtgt-Passwortalter") (Bi "$age days" "$age Tage") (Bi "<= 180 days" "<= 180 Tage") $krbRating 'MDI' `
        (Bi "Golden ticket protection. High-security environments rotate more often." "Golden-Ticket-Schutz. High-Security-Umgebungen rotieren haeufiger.")
    if ($age -gt 180) {
        Add-Finding 'Kerberos' 'Medium' (Bi "krbtgt password is $age days old (target <=180)" "krbtgt-Passwort ist $age Tage alt (Soll <=180)") `
            (Bi "An old krbtgt key increases golden ticket risk." "Alte krbtgt-Keys erhoehen Golden-Ticket-Risiko.") (Bi "Rotate krbtgt in a controlled way (twice, with a gap in between)." "krbtgt kontrolliert rotieren (2x mit Abstand).")
    }
} catch { }

# --- 7. Account Hygiene ------------------------------------------------------
Write-Log "Checking account hygiene ..." 'INFO'
$cutoff = (Get-Date).AddDays(-$InactiveDays)
try {
    $inactiveUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonTimestamp |
        Where-Object { $_.LastLogonTimestamp -and ([datetime]::FromFileTime($_.LastLogonTimestamp) -lt $cutoff) } |
        Select-Object SamAccountName, @{n='LastLogon';e={ [datetime]::FromFileTime($_.LastLogonTimestamp) }}, DistinguishedName
    if (@($inactiveUsers).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'Medium' (Bi "active users inactive for >$InactiveDays days" "aktive User seit >$InactiveDays Tagen inaktiv") $inactiveUsers `
            (Bi "Stale accounts enlarge the attack surface." "Stale-Konten vergroessern die Angriffsflaeche.") `
            (Bi "Establish a disable/delete (lifecycle) process." "Deaktivierungs-/Loeschprozess (Lifecycle) etablieren.")
    }

    $neverExpire = Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $true } | Select-Object SamAccountName, DistinguishedName
    if (@($neverExpire).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'Medium' (Bi "Accounts with 'Password never expires'" "Konten mit 'Password never expires'") $neverExpire `
            (Bi "Permanent passwords." "Dauerpasswoerter.") `
            (Bi "Justify exceptions; use gMSA/managed accounts." "Ausnahmen begruenden; gMSA/Managed-Accounts nutzen.")
    }

    $pwNotReq = Get-ADUser -Filter { PasswordNotRequired -eq $true -and Enabled -eq $true } | Select-Object SamAccountName, DistinguishedName
    if (@($pwNotReq).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'High' (Bi "Accounts with 'PasswordNotRequired'" "Konten mit 'PasswordNotRequired'") $pwNotReq `
            (Bi "Accounts without a password requirement." "Konten ohne Passwortzwang.") `
            (Bi "Clean up the attribute." "Attribut bereinigen.")
    }

    $reversible = Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true -and Enabled -eq $true } | Select-Object SamAccountName, DistinguishedName
    if (@($reversible).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'High' (Bi "Accounts with reversible encryption" "Konten mit reversibler Verschluesselung") $reversible `
            (Bi "Passwords are effectively stored in cleartext." "Passwoerter praktisch im Klartext.") `
            (Bi "Disable reversible encryption." "Reversible Encryption deaktivieren.")
    }

    $inactiveComputers = Get-ADComputer -Filter { Enabled -eq $true } -Properties LastLogonTimestamp, OperatingSystem |
        Where-Object { $_.LastLogonTimestamp -and ([datetime]::FromFileTime($_.LastLogonTimestamp) -lt $cutoff) } |
        Select-Object Name, OperatingSystem, @{n='LastLogon';e={ [datetime]::FromFileTime($_.LastLogonTimestamp) }}, DistinguishedName
    if (@($inactiveComputers).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'Low' (Bi "inactive computer accounts (>$InactiveDays days)" "inaktive Computerkonten (>$InactiveDays Tage)") $inactiveComputers `
            (Bi "Orphaned computer objects." "Verwaiste Computerobjekte.") `
            (Bi "Clean up/disable." "Bereinigen/deaktivieren.")
    }

    # Legacy OS computers
    $legacyOS = Get-ADComputer -Filter { Enabled -eq $true } -Properties OperatingSystem |
        Where-Object { $_.OperatingSystem -match 'XP|Vista|2003|2008|Windows 7|Windows 8' } |
        Select-Object Name, OperatingSystem, DistinguishedName
    if (@($legacyOS).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'High' (Bi "Machines with an EOL operating system" "Rechner mit EOL-Betriebssystem") $legacyOS `
            (Bi "Unpatched legacy systems." "Ungepatchte Legacy-Systeme.") `
            (Bi "Replace/isolate." "Ersetzen/isolieren.")
    }
} catch { Write-Log "Account hygiene checks partially failed: $_" 'WARN' }

# --- 8. Password Policy -------------------------------------------------------
Write-Log "Checking password policy ..." 'INFO'
try {
    $pw = Get-ADDefaultDomainPasswordPolicy
    Add-Section (Bi "Default Domain Password Policy" "Default Domain Password Policy") ([pscustomobject]@{
        MinPasswordLength      = $pw.MinPasswordLength
        PasswordHistoryCount   = $pw.PasswordHistoryCount
        MaxPasswordAgeDays     = $pw.MaxPasswordAge.Days
        LockoutThreshold       = $pw.LockoutThreshold
        ComplexityEnabled      = $pw.ComplexityEnabled
        ReversibleEncryption   = $pw.ReversibleEncryptionEnabled
    })

    # --- Compliance: minimum password length (CIS: >=14) ---
    $ml = $pw.MinPasswordLength
    $mlRating = if ($ml -ge 15) { 'good' } elseif ($ml -eq 14) { 'meets' } elseif ($ml -ge 10) { 'warn' } else { 'bad' }
    Add-Compliance (Bi "Minimum password length" "Minimale Passwortlaenge") (Bi "$ml characters" "$ml Zeichen") (Bi ">= 14 characters" ">= 14 Zeichen") $mlRating 'CIS' `
        (Bi "NIST/CISA increasingly favor passphrases (16+); the CIS baseline requires 14." "NIST/CISA gehen tendenziell zu Passphrasen (16+); CIS-Baseline fordert 14.")
    if ($ml -lt 14) {
        Add-Finding 'Policy' 'Medium' (Bi "Minimum password length = $ml (target >=14)" "Minimale Passwortlaenge = $ml (Soll >=14)") `
            (Bi "Below the CIS baseline (14 characters)." "Unter CIS-Baseline (14 Zeichen).") (Bi "Raise to >=14; consider a banned-password approach (e.g. Entra Password Protection)." "Auf >=14 anheben; Banned-Password-Ansatz (z.B. Entra Password Protection).")
    }

    # --- Compliance: password history (CIS: >=24) ---
    $hist = $pw.PasswordHistoryCount
    $histRating = if ($hist -ge 24) { 'meets' } elseif ($hist -ge 12) { 'warn' } else { 'bad' }
    Add-Compliance (Bi "Password history" "Passwort-History") "$hist" (Bi ">= 24" ">= 24") $histRating 'CIS'
    if ($hist -lt 24) {
        Add-Finding 'Policy' 'Low' (Bi "Password history = $hist (target >=24)" "Passwort-History = $hist (Soll >=24)") `
            (Bi "Reuse of old passwords is possible." "Wiederverwendung alter Passwoerter moeglich.") (Bi "Set history to 24 (CIS)." "History auf 24 setzen (CIS).")
    }

    # --- Compliance: account lockout threshold (CIS: 1-5, !=0) ---
    $lt = $pw.LockoutThreshold
    $ltRating = if ($lt -eq 0) { 'bad' } elseif ($lt -ge 1 -and $lt -le 5) { 'meets' } elseif ($lt -le 10) { 'warn' } else { 'warn' }
    $ltIst = if ($lt -eq 0) { Bi '0 (disabled)' '0 (deaktiviert)' } else { Bi "$lt attempts" "$lt Versuche" }
    Add-Compliance (Bi "Account lockout threshold" "Account-Lockout-Schwelle") $ltIst (Bi "1-5 attempts (not 0)" "1-5 Versuche (nicht 0)") $ltRating 'CIS' `
        (Bi "0 = no lockout. Very low values can facilitate DoS - keep the balance in mind." "0 = kein Lockout. Sehr niedrige Werte koennen DoS beguenstigen - Balance beachten.")
    if ($lt -eq 0) {
        Add-Finding 'Policy' 'Medium' (Bi "No account lockout configured (target 1-5)" "Kein Account-Lockout konfiguriert (Soll 1-5)") `
            (Bi "Brute-force attacks are unthrottled." "Brute-Force ungebremst.") (Bi "Set a lockout threshold (mind the DoS trade-off)." "Lockout-Schwelle setzen (Balance zu DoS beachten).")
    }

    # --- Compliance: reversible encryption (target: off) ---
    $revRating = if ($pw.ReversibleEncryptionEnabled) { 'bad' } else { 'meets' }
    Add-Compliance (Bi "Reversible encryption (domain policy)" "Reversible Verschluesselung (Domain-Policy)") `
        ($(if ($pw.ReversibleEncryptionEnabled) { Bi 'enabled' 'aktiviert' } else { Bi 'disabled' 'deaktiviert' })) (Bi "disabled" "deaktiviert") $revRating 'CIS'

    # --- Compliance: complexity (CIS: on) ---
    $cxRating = if ($pw.ComplexityEnabled) { 'meets' } else { 'warn' }
    Add-Compliance (Bi "Password complexity" "Passwortkomplexitaet") `
        ($(if ($pw.ComplexityEnabled) { Bi 'enabled' 'aktiviert' } else { Bi 'disabled' 'deaktiviert' })) (Bi "enabled" "aktiviert") $cxRating 'CIS' `
        (Bi "NIST is increasingly critical of forced complexity; the CIS baseline still requires it." "NIST sieht Komplexitaet zunehmend kritisch; CIS-Baseline fordert sie weiterhin.")
} catch { Write-Log "Password policy check failed: $_" 'WARN' }

# --- 9. AdminSDHolder / adminCount Orphans -----------------------------------
try {
    $adminCountOrphans = Get-ADUser -Filter { adminCount -eq 1 -and Enabled -eq $true } -Properties adminCount, memberOf |
        Select-Object SamAccountName, DistinguishedName
    if (@($adminCountOrphans).Count -gt 0) {
        Add-FindingWithObjects 'Privileged' 'Info' (Bi "Accounts with adminCount=1 (SDProp)" "Konten mit adminCount=1 (SDProp)") $adminCountOrphans `
            (Bi "Formerly/currently privileged accounts carrying a restrictive ACL from SDProp." "Ehemals/aktuell privilegierte Konten mit restriktiver ACL durch SDProp.") `
            (Bi "Check for orphans: adminCount set without current group membership should be cleaned up." "Auf Waisen pruefen: adminCount ohne aktuelle Gruppenmitgliedschaft bereinigen.") `
            (Bi "Formerly privileged accounts retain a restrictive ACL (SDProp). Check for orphans." "Ehemals privilegierte Konten behalten restriktive ACL (SDProp). Auf Waisen pruefen.")
    }
} catch { }

# --- 10. Trusts ---------------------------------------------------------------
try {
    $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue |
        Select-Object Name, Direction, TrustType, ForestTransitive, SIDFilteringForestAware, SIDFilteringQuarantined
    if ($trusts) {
        $trustAnchor = New-Anchor
        Add-Section (Bi "Trusts" "Trusts") $trusts '' $trustAnchor
        foreach ($t in $trusts) {
            if ($t.SIDFilteringQuarantined -eq $false) {
                Add-Finding 'Trust' 'Medium' (Bi "Trust '$($t.Name)' without SID filtering quarantine" "Trust '$($t.Name)' ohne SID-Filtering-Quarantine") `
                    (Bi "SID history abuse is possible (see the 'Trusts' section)." "SID-History-Missbrauch moeglich (siehe Sektion 'Trusts').") `
                    (Bi "Review/enable SID filtering." "SID-Filtering pruefen/aktivieren.") $trustAnchor
            }
        }
    }
} catch { }

# --- 11. AD CS Present? --------------------------------------------------------
try {
    $pkiBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services," + (Get-ADRootDSE).configurationNamingContext
    # Only real CA objects (pKIEnrollmentService), not the container itself
    $pkiEnroll = Get-ADObject -SearchBase $pkiBase -LDAPFilter '(objectClass=pKIEnrollmentService)' `
        -Properties dNSHostName, cACertificateDN, displayName, flags, whenCreated -ErrorAction SilentlyContinue
    if ($pkiEnroll) {
        $pkiResult = foreach ($ca in $pkiEnroll) {
            $ip = ''
            if ($ca.dNSHostName) {
                try {
                    $ip = ([System.Net.Dns]::GetHostAddresses($ca.dNSHostName) |
                        Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                        Select-Object -First 1 -Expand IPAddressToString)
                } catch { $ip = '(not resolvable)' }
            }
            [pscustomobject]@{
                CAName      = $ca.Name
                CAHost      = $ca.dNSHostName
                IPAddress   = $ip
                CASubjectDN = $ca.cACertificateDN
                WhenCreated = $ca.whenCreated
            }
        }
        Add-FindingWithObjects 'ADCS' 'Info' (Bi "Enterprise CA(s) in the forest (AD CS active)" "Enterprise-CA(s) im Forest (AD CS aktiv)") $pkiResult `
            (Bi "Enterprise CA detected - AD CS is a frequently overlooked attack path." "Enterprise-CA erkannt - AD CS ist ein haeufig uebersehener Angriffspfad.") `
            (Bi "Check ESC1-ESC16 with Locksmith / PSPKIAudit (separate run)." "ESC1-ESC16 mit Locksmith / PSPKIAudit pruefen (separater Lauf).") `
            (Bi "Review web enrollment/EPA and template permissions separately." "Web-Enrollment/EPA und Template-Berechtigungen gesondert pruefen.")
    }
} catch { }

# --- 12. Legacy Protocols / Hardening (DC-local, best effort) ------------------
Write-Log "Checking legacy protocols / hardening ..." 'INFO'
try {
    $pdc = (Get-ADDomain).PDCEmulator
    # Read registry remotely from the PDC (read-only). Falls back gracefully if unreachable.
    $regResults = New-Object System.Collections.ArrayList
    function Get-RemoteReg {
        param($Computer, $Hive, $Key, $Value)
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive, $Computer)
            $sub  = $base.OpenSubKey($Key)
            if ($null -ne $sub) { return $sub.GetValue($Value) }
        } catch { return $null }
        return $null
    }

    $smb1 = Get-RemoteReg $pdc 'LocalMachine' 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
    $smb1Ist = if ($null -eq $smb1) { Bi 'not set (default)' 'nicht gesetzt (Default)' } elseif ($smb1 -eq 0) { Bi 'disabled (0)' 'deaktiviert (0)' } else { Bi "enabled ($smb1)" "aktiviert ($smb1)" }
    $smb1Rating = if ($smb1 -eq 0) { 'meets' } elseif ($null -eq $smb1) { 'warn' } else { 'bad' }
    Add-Compliance (Bi "SMBv1 (PDC: $pdc)" "SMBv1 (PDC: $pdc)") $smb1Ist (Bi "disabled" "deaktiviert") $smb1Rating 'MSHARD' `
        (Bi "Set SMB1=0 explicitly. 'Not set' means OS-dependent behavior - better to disable/remove the feature explicitly." "SMB1=0 explizit setzen. 'nicht gesetzt' = Verhalten OS-abhaengig, besser explizit deaktivieren/Feature entfernen.")
    if ($smb1 -and $smb1 -ne 0) {
        Add-Finding 'Hardening' 'High' (Bi "SMBv1 enabled on $pdc" "SMBv1 auf $pdc aktiviert") `
            (Bi "Outdated, exploitable protocol (WannaCry vector)." "Veraltetes, angreifbares Protokoll (WannaCry-Vektor).") (Bi "Remove the SMBv1 feature." "SMBv1-Feature entfernen.")
    }

    # LDAP server signing: LDAPServerIntegrity (2 = require)
    $ldapSign = Get-RemoteReg $pdc 'LocalMachine' 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
    $ldapIst = switch ($ldapSign) { 2 { Bi 'require signing (2)' 'require signing (2)' } 1 { Bi 'none/optional (1)' 'none/optional (1)' } default { Bi 'not set' 'nicht gesetzt' } }
    $ldapRating = if ($ldapSign -eq 2) { 'meets' } elseif ($null -eq $ldapSign) { 'warn' } else { 'bad' }
    Add-Compliance (Bi "LDAP Server Signing (PDC)" "LDAP Server Signing (PDC)") $ldapIst (Bi "require (2)" "require (2)") $ldapRating 'MSHARD' `
        (Bi "Protects against LDAP relay. Microsoft is increasingly hardening this by default." "Schutz gegen LDAP-Relay. Microsoft haertet dies zunehmend per Default.")
    if ($ldapSign -ne $null -and $ldapSign -lt 2) {
        Add-Finding 'Hardening' 'Medium' (Bi "LDAP signing not enforced on $pdc" "LDAP-Signing auf $pdc nicht erzwungen") `
            (Bi "LDAP relay/MitM is possible." "LDAP-Relay/MitM moeglich.") (Bi "Enforce LDAPServerIntegrity=2 via GPO (after testing client compatibility)." "LDAPServerIntegrity=2 per GPO erzwingen (nach Client-Kompatibilitaetstest).")
    }

    # LDAP channel binding: LdapEnforceChannelBinding (2 = always)
    $cbt = Get-RemoteReg $pdc 'LocalMachine' 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'
    $cbtIst = switch ($cbt) { 2 { Bi 'always (2)' 'always (2)' } 1 { Bi 'when supported (1)' 'when supported (1)' } 0 { Bi 'off (0)' 'off (0)' } default { Bi 'not set' 'nicht gesetzt' } }
    $cbtRating = if ($cbt -eq 2) { 'meets' } elseif ($cbt -eq 1) { 'warn' } elseif ($null -eq $cbt) { 'warn' } else { 'bad' }
    Add-Compliance (Bi "LDAP Channel Binding (PDC)" "LDAP Channel Binding (PDC)") $cbtIst (Bi "always (2)" "always (2)") $cbtRating 'MSHARD'

    # NTLM: LmCompatibilityLevel (>=5 recommended)
    $lmcl = Get-RemoteReg $pdc 'LocalMachine' 'SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    $lmclIst = if ($null -eq $lmcl) { Bi 'not set (default)' 'nicht gesetzt (Default)' } else { Bi "$lmcl" "$lmcl" }
    $lmclRating = if ($lmcl -ge 5) { 'meets' } elseif ($null -eq $lmcl) { 'warn' } elseif ($lmcl -ge 3) { 'warn' } else { 'bad' }
    Add-Compliance (Bi "LmCompatibilityLevel (PDC)" "LmCompatibilityLevel (PDC)") $lmclIst (Bi ">= 5 (NTLMv2 only)" ">= 5 (nur NTLMv2)") $lmclRating 'MSHARD' `
        (Bi "Level 5 rejects LM/NTLMv1. Check compatibility with older systems first." "Level 5 verweigert LM/NTLMv1. Kompatibilitaet aelterer Systeme vorher pruefen.")
} catch { Write-Log "Hardening checks partially failed (remote registry?): $_" 'WARN' }

# --- 13. Backup / DR / tombstoneLifetime ---------------------------------------
Write-Log "Checking backup/DR metrics ..." 'INFO'
try {
    $cfgNC = (Get-ADRootDSE).configurationNamingContext
    $dsObj = Get-ADObject -Identity ("CN=Directory Service,CN=Windows NT,CN=Services," + $cfgNC) `
        -Properties tombstoneLifetime -ErrorAction SilentlyContinue
    $tsl = if ($dsObj -and $dsObj.tombstoneLifetime) { $dsObj.tombstoneLifetime } else { $null }
    $tslIst = if ($null -eq $tsl) { Bi 'not set (default 60/180)' 'nicht gesetzt (Default 60/180)' } else { Bi "$tsl days" "$tsl Tage" }
    $tslRating = if ($tsl -ge 180) { 'meets' } elseif ($null -eq $tsl) { 'warn' } elseif ($tsl -ge 90) { 'warn' } else { 'bad' }
    Add-Compliance (Bi "tombstoneLifetime" "tombstoneLifetime") $tslIst (Bi ">= 180 days" ">= 180 Tage") $tslRating 'MSDR' `
        (Bi "Determines the max. backup age usable for a restore. Too small = old backups become useless." "Bestimmt max. Backup-Alter fuer Restore. Zu klein = alte Backups unbrauchbar.")

    # Last successful system-state backup can't be reliably read via dsHeuristics/replMetadata -
    # hence an informational finding instead of a hard value:
    Add-Finding 'BackupDR' 'Info' (Bi "Verify backup/DR manually" "Backup/DR manuell verifizieren") `
        (Bi "System-state/DC backup age and a tested forest recovery plan can't be reliably read via LDAP." "Systemstate-/DC-Backup-Alter und getesteter Forest-Recovery-Plan sind per LDAP nicht zuverlaessig auslesbar.") `
        (Bi "Verify the backup solution: regular system-state backup of >=1 DC, a documented and PRACTICED forest recovery plan, DSRM password governance." "Backup-Loesung pruefen: regelmaessiges Systemstate-Backup >=1 DC, dokumentierter & GEUEBTER Forest-Recovery-Plan, DSRM-Passwort-Governance.")
} catch { Write-Log "Backup/DR check failed: $_" 'WARN' }

# --- 14. DCSync Rights (DS-Replication-Get-Changes-All) ------------------------
Write-Log "Checking DCSync rights on the domain NC ..." 'INFO'
try {
    $domainDN = (Get-ADDomain).DistinguishedName
    # Extended rights GUIDs
    $guidGetChangesAll = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' # DS-Replication-Get-Changes-All
    $acl = Get-Acl -Path ("AD:\" + $domainDN) -ErrorAction Stop

    # Known, legitimate principals allowed to perform DCSync
    $legit = @('Domain Admins','Enterprise Admins','Administrators','Domain Controllers',
               'Enterprise Read-only Domain Controllers','SYSTEM','Read-only Domain Controllers')

    $dcsync = foreach ($ace in $acl.Access) {
        if ($ace.ObjectType -eq $guidGetChangesAll -and $ace.AccessControlType -eq 'Allow') {
            $id = $ace.IdentityReference.Value
            $short = ($id -split '\\')[-1]
            if ($legit -notcontains $short) {
                [pscustomobject]@{ Principal = $id; Right = 'DS-Replication-Get-Changes-All'; Type = $ace.AccessControlType }
            }
        }
    }
    if (@($dcsync).Count -gt 0) {
        Add-FindingWithObjects 'Delegation' 'Critical' (Bi "Non-standard principals with DCSync rights" "Nicht-Standard-Prinzipale mit DCSync-Recht") $dcsync `
            (Bi "DS-Replication-Get-Changes-All allows reading all password hashes (DCSync)." "DS-Replication-Get-Changes-All erlaubt das Auslesen aller Passwort-Hashes (DCSync).") `
            (Bi "Restrict the right to DCs/DAs; remove unexpected principals immediately." "Recht auf DCs/DAs beschraenken; unerwartete Prinzipale sofort entfernen.") `
            (Bi "Legitimate standard principals (DAs/EAs/DCs/SYSTEM) are already filtered out." "Legitime Standard-Prinzipale (DAs/EAs/DCs/SYSTEM) sind ausgefiltert.")
    } else {
        Add-Finding 'Delegation' 'Info' (Bi "No non-standard DCSync rights found" "Keine Nicht-Standard-DCSync-Rechte gefunden") `
            (Bi "Only the expected principals hold DS-Replication-Get-Changes-All." "Nur erwartete Prinzipale besitzen DS-Replication-Get-Changes-All.") `
            (Bi "No action needed; re-check after changes." "Keine Aktion noetig; bei Aenderungen erneut pruefen.")
    }
} catch { Write-Log "DCSync check failed (AD PSDrive/permissions?): $_" 'WARN' }

# --- 15. GPP Passwords in SYSVOL (MS14-025) ------------------------------------
Write-Log "Checking for GPP passwords in SYSVOL (MS14-025) ..." 'INFO'
try {
    $domainDns = (Get-ADDomain).DNSRoot
    $sysvol = "\\$domainDns\SYSVOL\$domainDns\Policies"
    if (Test-Path $sysvol) {
        # cpassword appears in Groups.xml/Services.xml/ScheduledTasks.xml/DataSources.xml/Printers.xml/Drives.xml
        $xmlFiles = Get-ChildItem -Path $sysvol -Recurse -Include 'Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Printers.xml','Drives.xml' -ErrorAction SilentlyContinue
        $gppHits = foreach ($f in $xmlFiles) {
            try {
                $content = Get-Content -Path $f.FullName -Raw -ErrorAction Stop
                if ($content -match 'cpassword="([^"]+)"') {
                    [pscustomobject]@{ File = $f.FullName; Preview = ($matches[1].Substring(0,[Math]::Min(12,$matches[1].Length)) + '...') }
                }
            } catch { }
        }
        if (@($gppHits).Count -gt 0) {
            Add-FindingWithObjects 'GPP' 'Critical' (Bi "GPP files with cpassword (MS14-025)" "GPP-Dateien mit cpassword (MS14-025)") $gppHits `
                (Bi "cpassword can be decrypted with a well-known AES key - cleartext passwords in SYSVOL." "cpassword ist mit bekanntem AES-Key entschluesselbar - Klartext-Passwoerter in SYSVOL.") `
                (Bi "Remove the affected GPP entries, rotate the passwords, switch to LAPS." "Betroffene GPP-Eintraege entfernen, Passwoerter rotieren, auf LAPS umstellen.") `
                (Bi "Readable by any authenticated user." "Von jedem authentifizierten User lesbar.")
        } else {
            Add-Finding 'GPP' 'Info' (Bi "No GPP cpassword hits found in SYSVOL" "Keine GPP-cpassword-Funde in SYSVOL") `
                (Bi "No MS14-025 cleartext password found in the usual GPP XML files." "Kein MS14-025-Klartextpasswort in den ueblichen GPP-XMLs gefunden.") `
                (Bi "No action needed." "Keine Aktion noetig.")
        }
    } else {
        Write-Log "SYSVOL path not reachable: $sysvol" 'WARN'
    }
} catch { Write-Log "GPP scan failed: $_" 'WARN' }

# --- 16. LAPS Rollout Coverage --------------------------------------------------
Write-Log "Checking LAPS rollout coverage ..." 'INFO'
try {
    # Consider both Windows LAPS (msLAPS-Password) and legacy LAPS (ms-Mcs-AdmPwd)
    # Only request attributes that actually exist in the schema (otherwise Get-ADComputer throws)
    $schemaNC = (Get-ADRootDSE).schemaNamingContext
    $lapsAttrs = New-Object System.Collections.ArrayList
    foreach ($attr in @('ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime')) {
        $exists = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(lDAPDisplayName=$attr)" -ErrorAction SilentlyContinue
        if ($exists) { [void]$lapsAttrs.Add($attr) }
    }
    if (@($lapsAttrs).Count -eq 0) {
        Add-Compliance (Bi "LAPS rollout coverage" "LAPS-Ausrollgrad") (Bi "no LAPS schema found" "kein LAPS-Schema gefunden") (Bi "roll out LAPS" "LAPS ausrollen") 'bad' 'MSLAPS' `
            (Bi "Neither legacy nor Windows LAPS attributes exist in the schema - LAPS is not set up." "Weder Legacy- noch Windows-LAPS-Attribute im Schema - LAPS ist nicht eingerichtet.")
        Add-Finding 'LAPS' 'Medium' (Bi "LAPS not set up (no schema attribute)" "LAPS nicht eingerichtet (kein Schema-Attribut)") `
            (Bi "No central management of local admin passwords." "Keine zentrale Verwaltung lokaler Admin-Passwoerter.") `
            (Bi "Set up Windows LAPS (extend the schema, roll out via GPO)." "Windows LAPS einrichten (Schema erweitern, GPO ausrollen).")
    } else {
        $queryProps = @('OperatingSystem','PrimaryGroupID') + $lapsAttrs.ToArray()
        $allComp = @(Get-ADComputer -Filter { Enabled -eq $true } -Properties $queryProps -ErrorAction SilentlyContinue)
        $lapsRelevant = $allComp | Where-Object { $_.PrimaryGroupID -ne 516 -and $_.PrimaryGroupID -ne 521 }

        $withLaps = 0; $checked = 0
        $missing = New-Object System.Collections.ArrayList
        foreach ($c in $lapsRelevant) {
            $checked++
            $has = $false
            foreach ($p in $lapsAttrs) {
                $val = $c.$p
                if ($val) { $has = $true; break }
            }
            if ($has) { $withLaps++ } else {
                if (@($missing).Count -lt 200) { [void]$missing.Add([pscustomobject]@{ Name = $c.Name; OS = $c.OperatingSystem; DistinguishedName = $c.DistinguishedName }) }
            }
        }
        if ($checked -gt 0) {
            $pct = [math]::Round(($withLaps / $checked) * 100, 1)
            $lapsRating = if ($pct -ge 95) { 'good' } elseif ($pct -ge 80) { 'meets' } elseif ($pct -ge 50) { 'warn' } else { 'bad' }
            Add-Compliance (Bi "LAPS rollout coverage" "LAPS-Ausrollgrad") "$pct% ($withLaps/$checked)" (Bi ">= 95% of non-DC machines" ">= 95% der Nicht-DC-Rechner") $lapsRating 'MSLAPS' `
                (Bi "Accounts for both Windows LAPS (msLAPS-*) and legacy LAPS (ms-Mcs-AdmPwd*)." "Beruecksichtigt Windows LAPS (msLAPS-*) und Legacy LAPS (ms-Mcs-AdmPwd*).")
            if ($pct -lt 95 -and @($missing).Count -gt 0) {
                Add-FindingWithObjects 'LAPS' 'Medium' (Bi "Machines without LAPS password management" "Rechner ohne LAPS-Passwortverwaltung") $missing `
                    (Bi "Without LAPS: identical/static local admin passwords -> lateral movement." "Ohne LAPS: identische/statische lokale Admin-Passwoerter -> lateral movement.") `
                    (Bi "Roll out LAPS (Windows LAPS preferred) across the board." "LAPS (Windows LAPS bevorzugt) flaechendeckend ausrollen.") `
                    (Bi "Display limited to a maximum of 200 objects." "Anzeige auf max. 200 Objekte begrenzt.")
            }
        }
    }
} catch { Write-Log "LAPS check failed: $_" 'WARN' }

# --- 17. AdminSDHolder ACL - Dangerous ACEs -------------------------------------
Write-Log "Checking AdminSDHolder ACL for dangerous ACEs ..." 'INFO'
try {
    $tier0Principals = @('Domain Admins','Enterprise Admins','Administrators','SYSTEM')
    $sdHolderDN = "CN=AdminSDHolder,CN=System," + (Get-ADDomain).DistinguishedName
    $sdAcl = Get-Acl -Path ("AD:\" + $sdHolderDN) -ErrorAction Stop

    $sdDangerous = foreach ($ace in $sdAcl.Access) {
        if ($ace.AccessControlType -eq 'Allow' -and "$($ace.ActiveDirectoryRights)" -match 'GenericAll|WriteDacl|WriteOwner') {
            $id = $ace.IdentityReference.Value
            $short = ($id -split '\\')[-1]
            if ($tier0Principals -notcontains $short) {
                [pscustomobject]@{ Principal = $id; Rights = "$($ace.ActiveDirectoryRights)"; Inherited = $ace.IsInherited }
            }
        }
    }
    if (@($sdDangerous).Count -gt 0) {
        Add-FindingWithObjects 'Delegation' 'Critical' (Bi "Non-standard principals with dangerous rights on AdminSDHolder" "Nicht-Standard-Prinzipale mit gefaehrlichen Rechten auf AdminSDHolder") $sdDangerous `
            (Bi "GenericAll/WriteDacl/WriteOwner on AdminSDHolder propagates to every SDProp-protected (Tier-0) account - a backdoor into Domain Admins." "GenericAll/WriteDacl/WriteOwner auf AdminSDHolder propagiert per SDProp auf alle geschuetzten (Tier-0) Konten - eine Hintertuer in Richtung Domain Admins.") `
            (Bi "Remove unexpected ACEs immediately; investigate how/when they were added." "Unerwartete ACEs sofort entfernen; pruefen wie/wann sie hinzugefuegt wurden.") `
            (Bi "Only Domain Admins/Enterprise Admins/Administrators/SYSTEM are expected to hold these rights by default." "Standardmaessig sollten nur Domain Admins/Enterprise Admins/Administrators/SYSTEM diese Rechte besitzen.")
    } else {
        Add-Finding 'Delegation' 'Info' (Bi "No non-standard dangerous ACEs found on AdminSDHolder" "Keine Nicht-Standard-ACEs mit gefaehrlichen Rechten auf AdminSDHolder gefunden") `
            (Bi "Only the expected Tier-0 principals hold GenericAll/WriteDacl/WriteOwner." "Nur die erwarteten Tier-0-Prinzipale besitzen GenericAll/WriteDacl/WriteOwner.") `
            (Bi "No action needed; re-check after changes." "Keine Aktion noetig; bei Aenderungen erneut pruefen.")
    }
} catch { Write-Log "AdminSDHolder ACL check failed: $_" 'WARN' }

# --- 18. Domain Root / OU ACL Hardening (Dangerous ACEs) ------------------------
Write-Log "Checking domain root and OU ACLs for dangerous delegated rights ..." 'INFO'
try {
    $tier0Principals = @('Domain Admins','Enterprise Admins','Administrators','SYSTEM')
    $domainDN = (Get-ADDomain).DistinguishedName

    # Returns dangerous (GenericAll/WriteDacl/WriteOwner) Allow ACEs held by non-Tier-0 principals.
    # $OnlyExplicit restricts to non-inherited ACEs (used for OUs, to avoid re-reporting what's already
    # flagged as inherited from the domain root).
    function Get-DangerousAces {
        param([string]$Dn, [bool]$OnlyExplicit)
        $acl = Get-Acl -Path ("AD:\" + $Dn) -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($OnlyExplicit -and $ace.IsInherited) { continue }
            if ("$($ace.ActiveDirectoryRights)" -notmatch 'GenericAll|WriteDacl|WriteOwner') { continue }
            $id = $ace.IdentityReference.Value
            $short = ($id -split '\\')[-1]
            if ($tier0Principals -contains $short) { continue }
            [pscustomobject]@{ Object = $Dn; Principal = $id; Rights = "$($ace.ActiveDirectoryRights)"; Inherited = $ace.IsInherited }
        }
    }

    $rootAces = @(Get-DangerousAces -Dn $domainDN -OnlyExplicit $false)
    if (@($rootAces).Count -gt 0) {
        Add-FindingWithObjects 'Delegation' 'Critical' (Bi "Non-standard principals with dangerous rights on the domain root" "Nicht-Standard-Prinzipale mit gefaehrlichen Rechten auf der Domain-Root") $rootAces `
            (Bi "GenericAll/WriteDacl/WriteOwner on the domain root object grants control over the entire domain." "GenericAll/WriteDacl/WriteOwner auf dem Domain-Root-Objekt erlaubt Kontrolle ueber die gesamte Domaene.") `
            (Bi "Remove unexpected ACEs immediately; investigate how/when they were added." "Unerwartete ACEs sofort entfernen; pruefen wie/wann sie hinzugefuegt wurden.")
    }

    $ouAces = New-Object System.Collections.ArrayList
    $ous = Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue
    foreach ($ou in $ous) {
        try {
            foreach ($ace in (Get-DangerousAces -Dn $ou.DistinguishedName -OnlyExplicit $true)) {
                if (@($ouAces).Count -lt 200) { [void]$ouAces.Add($ace) }
            }
        } catch { }
    }
    if (@($ouAces).Count -gt 0) {
        Add-FindingWithObjects 'Delegation' 'High' (Bi "Non-standard principals with dangerous rights on OUs (explicit delegation)" "Nicht-Standard-Prinzipale mit gefaehrlichen Rechten auf OUs (explizite Delegation)") $ouAces `
            (Bi "GenericAll/WriteDacl/WriteOwner grants far-reaching control over all objects in that OU (e.g. resetting passwords, group membership, further delegation)." "GenericAll/WriteDacl/WriteOwner erlaubt weitreichende Kontrolle ueber alle Objekte in dieser OU (z.B. Passwort-Reset, Gruppenmitgliedschaft, weitere Delegation).") `
            (Bi "Review each ACE: intentional delegation vs. leftover/misconfigured. Remove or scope down anything unexpected." "Jede ACE pruefen: gewollte Delegation vs. Altlast/Fehlkonfiguration. Unerwartetes entfernen oder einschraenken.") `
            (Bi "Only explicitly delegated (non-inherited) ACEs are shown, to avoid duplicate noise from inheritance off the domain root. Display limited to 200 entries." "Nur explizit delegierte (nicht vererbte) ACEs werden angezeigt, um doppeltes Rauschen durch Vererbung von der Domain-Root zu vermeiden. Anzeige auf 200 Eintraege begrenzt.")
    }
    if (@($rootAces).Count -eq 0 -and @($ouAces).Count -eq 0) {
        Add-Finding 'Delegation' 'Info' (Bi "No non-standard dangerous ACEs found on the domain root/OUs" "Keine Nicht-Standard-ACEs mit gefaehrlichen Rechten auf Domain-Root/OUs gefunden") `
            (Bi "No unexpected GenericAll/WriteDacl/WriteOwner delegation detected." "Keine unerwartete GenericAll/WriteDacl/WriteOwner-Delegation gefunden.") `
            (Bi "No action needed; re-check after changes." "Keine Aktion noetig; bei Aenderungen erneut pruefen.")
    }
} catch { Write-Log "Domain root/OU ACL check failed: $_" 'WARN' }

# --- Generate Report ------------------------------------------------------
Write-Log "Generating HTML report ..." 'INFO'

$sevOrder = @{ 'Critical'=0; 'High'=1; 'Medium'=2; 'Low'=3; 'Info'=4 }
$findingsSorted = $script:Findings | Sort-Object { $sevOrder[$_.Severity] }

$css = @"
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222;background:#fafafa;}
h1{color:#1a3d6d;} h2{color:#1a3d6d;border-bottom:2px solid #1a3d6d;padding-bottom:4px;margin-top:32px;}
table{border-collapse:collapse;width:100%;margin:12px 0;background:#fff;}
th,td{border:1px solid #ccc;padding:6px 10px;text-align:left;vertical-align:top;font-size:13px;}
th{background:#1a3d6d;color:#fff;}
tr:nth-child(even){background:#f0f4f8;}
.Critical{background:#c0392b;color:#fff;font-weight:bold;padding:2px 6px;border-radius:3px;}
.High{background:#e67e22;color:#fff;font-weight:bold;padding:2px 6px;border-radius:3px;}
.Medium{background:#f1c40f;color:#222;padding:2px 6px;border-radius:3px;}
.Low{background:#7f8c8d;color:#fff;padding:2px 6px;border-radius:3px;}
.Info{background:#2980b9;color:#fff;padding:2px 6px;border-radius:3px;}
.meta{color:#666;font-size:12px;}
.note{color:#555;font-style:italic;font-size:12px;margin:4px 0;}
html{scroll-behavior:smooth;}
h2{scroll-margin-top:12px;}
a{color:#1a6dbd;text-decoration:none;} a:hover{text-decoration:underline;}
.backlink{font-size:11px;font-weight:normal;margin-left:10px;}
td.good{background:#d4efdf;color:#186a3b;font-weight:bold;}
td.meets{background:#fff;color:#222;}
td.warn{background:#fcf3cf;color:#7d6608;font-weight:bold;}
td.bad{background:#f5b7b1;color:#922b21;font-weight:bold;}
td.na{background:#eee;color:#888;}
.legend span{display:inline-block;padding:2px 8px;margin-right:6px;border-radius:3px;font-size:12px;}
.srcref{font-size:11px;color:#555;}
.sources{font-size:12px;color:#444;margin-top:8px;}
.sources li{margin:2px 0;}
.lang-de{display:none;}
body.show-de .lang-en{display:none;}
body.show-de .lang-de{display:inline;}
.langbar{position:sticky;top:0;background:#fafafa;padding:6px 0;margin-bottom:8px;z-index:10;}
.langbtn{border:1px solid #1a3d6d;background:#fff;color:#1a3d6d;padding:4px 12px;border-radius:3px;cursor:pointer;font-size:12px;margin-right:6px;}
.langbtn.active{background:#1a3d6d;color:#fff;}
</style>
"@

$js = @"
<script>
function setLang(lang){
    document.body.classList.toggle('show-de', lang === 'de');
    document.getElementById('btn-en').classList.toggle('active', lang === 'en');
    document.getElementById('btn-de').classList.toggle('active', lang === 'de');
}
</script>
"@

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append("<html><head><meta charset='utf-8'>$css</head><body>")
[void]$sb.Append("<div class='langbar'><button id='btn-en' class='langbtn active' onclick=""setLang('en')"">English</button><button id='btn-de' class='langbtn' onclick=""setLang('de')"">Deutsch</button></div>")
[void]$sb.Append("<h1>Active Directory Assessment Report</h1>")
[void]$sb.Append("<p class='meta'><span class='lang-en'>Generated:</span><span class='lang-de'>Erstellt:</span> $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; AZITC &middot; <span class='lang-en'>Read-only assessment</span><span class='lang-de'>Reine Lese-Analyse (read-only)</span></p>")

# Findings overview
[void]$sb.Append("<h2 id='findings'><span class='lang-en'>Findings (prioritized)</span><span class='lang-de'>Findings (priorisiert)</span></h2>")
if (@($findingsSorted).Count -eq 0) {
    [void]$sb.Append("<p><span class='lang-en'>No automated findings were generated.</span><span class='lang-de'>Keine automatischen Findings erzeugt.</span></p>")
} else {
    [void]$sb.Append("<table><tr><th><span class='lang-en'>Severity</span><span class='lang-de'>Schweregrad</span></th><th><span class='lang-en'>Category</span><span class='lang-de'>Kategorie</span></th><th>Finding</th><th>Detail</th><th><span class='lang-en'>Recommendation</span><span class='lang-de'>Empfehlung</span></th><th>Details</th></tr>")
    foreach ($f in $findingsSorted) {
        $link = if ($f.Anchor) { "<a href='#$($f.Anchor)'><span class='lang-en'>affected objects &rarr;</span><span class='lang-de'>betroffene Objekte &rarr;</span></a>" } else { '&ndash;' }
        [void]$sb.Append("<tr><td><span class='$($f.Severity)'>$($f.Severity)</span></td><td>$(ConvertTo-HtmlEncoded $f.Category)</td><td>$(Format-Bi $f.Finding)</td><td>$(Format-Bi $f.Detail)</td><td>$(Format-Bi $f.Recommendation)</td><td>$link</td></tr>")
    }
    [void]$sb.Append("</table>")
}

# Compliance overview (target/actual with traffic-light rating)
if (@($script:Compliance).Count -gt 0) {
    [void]$sb.Append("<h2 id='compliance'><span class='lang-en'>Target/Actual Comparison (Best-Practice Baseline)</span><span class='lang-de'>Soll/Ist-Vergleich (Best-Practice-Abgleich)</span></h2>")
    [void]$sb.Append("<p class='legend'><span class='lang-en'>Rating: </span><span class='lang-de'>Bewertung: </span><span style='background:#d4efdf;color:#186a3b;'><span class='lang-en'>green = better than recommended</span><span class='lang-de'>gruen = besser als Empfehlung</span></span><span style='background:#fff;border:1px solid #ccc;'><span class='lang-en'>black = meets recommendation</span><span class='lang-de'>schwarz = deckt sich</span></span><span style='background:#fcf3cf;color:#7d6608;'><span class='lang-en'>yellow = slightly worse</span><span class='lang-de'>gelb = leicht schlechter</span></span><span style='background:#f5b7b1;color:#922b21;'><span class='lang-en'>red = significantly worse</span><span class='lang-de'>rot = deutlich schlechter</span></span></p>")
    [void]$sb.Append("<table><tr><th><span class='lang-en'>Check</span><span class='lang-de'>Pruefpunkt</span></th><th><span class='lang-en'>Actual</span><span class='lang-de'>Ist</span></th><th><span class='lang-en'>Target (recommended)</span><span class='lang-de'>Soll (Empfehlung)</span></th><th><span class='lang-en'>Rating</span><span class='lang-de'>Bewertung</span></th><th><span class='lang-en'>Source</span><span class='lang-de'>Quelle</span></th><th><span class='lang-en'>Comment</span><span class='lang-de'>Anmerkung</span></th></tr>")
    $ratingLabel = @{
        'good'  = (Bi 'better' 'besser')
        'meets' = (Bi 'meets' 'erfuellt')
        'warn'  = (Bi 'slightly worse' 'leicht schlechter')
        'bad'   = (Bi 'significantly worse' 'deutlich schlechter')
        'na'    = (Bi 'n/a' 'n/a')
    }
    foreach ($c in $script:Compliance) {
        $cls = $c.Rating
        [void]$sb.Append("<tr><td>$(Format-Bi $c.Check)</td><td class='$cls'>$(Format-Bi $c.Ist)</td><td>$(Format-Bi $c.Soll)</td><td class='$cls'>$(Format-Bi $ratingLabel[$c.Rating])</td><td class='srcref'>$(ConvertTo-HtmlEncoded $c.Source)</td><td class='srcref'>$(Format-Bi $c.Comment)</td></tr>")
    }
    [void]$sb.Append("</table>")
    # Source footnote
    [void]$sb.Append("<div class='sources'><strong><span class='lang-en'>Sources for the recommendations:</span><span class='lang-de'>Quellen der Empfehlungen:</span></strong><ul>")
    foreach ($k in $script:Sources.Keys) {
        [void]$sb.Append("<li><strong>$k</strong> = $(Format-Bi $script:Sources[$k])</li>")
    }
    [void]$sb.Append("</ul><p class='note'><span class='lang-en'>Note: values follow the CIS baseline (a practical, widely-used standard). NIST SP 800-63B and CISA increasingly favor length/passphrases over enforced complexity/rotation for passwords - treat these recommendations as guidance, not absolute truth.</span><span class='lang-de'>Hinweis: Werte orientieren sich an der CIS-Baseline (praxisnaher Standard). NIST SP 800-63B und CISA setzen bei Passwoertern zunehmend auf Laenge/Passphrasen statt erzwungener Komplexitaet/Rotation - die Empfehlungen sind daher als Richtwert, nicht als absolute Wahrheit zu lesen.</span></p></div>")
}
foreach ($sec in $script:Sections) {
    if ($sec.Anchor) {
        [void]$sb.Append("<h2 id='$($sec.Anchor)'>$(Format-Bi $sec.Title) <a href='#findings' class='backlink'><span class='lang-en'>&uarr; back to findings</span><span class='lang-de'>&uarr; zu den Findings</span></a></h2>")
    } else {
        [void]$sb.Append("<h2>$(Format-Bi $sec.Title)</h2>")
    }
    if ($sec.Note) { [void]$sb.Append("<p class='note'>$(Format-Bi $sec.Note)</p>") }

    if ($null -eq $sec.Data) {
        [void]$sb.Append("<p><em><span class='lang-en'>No data.</span><span class='lang-de'>Keine Daten.</span></em></p>")
        continue
    }

    $items = @($sec.Data)
    if ($items.Count -eq 0) {
        [void]$sb.Append("<p><em><span class='lang-en'>No entries.</span><span class='lang-de'>Keine Eintraege.</span></em></p>")
        continue
    }

    if ($items.Count -eq 1 -and ($items[0] -is [pscustomobject])) {
        # Single object -> vertical key/value table (more readable)
        [void]$sb.Append("<table><tr><th><span class='lang-en'>Property</span><span class='lang-de'>Eigenschaft</span></th><th><span class='lang-en'>Value</span><span class='lang-de'>Wert</span></th></tr>")
        foreach ($p in $items[0].PSObject.Properties) {
            [void]$sb.Append("<tr><td>$(ConvertTo-HtmlEncoded $p.Name)</td><td>$(ConvertTo-HtmlEncoded ([string]$p.Value))</td></tr>")
        }
        [void]$sb.Append("</table>")
    } else {
        $html = ($items | ConvertTo-Html -Fragment) -join "`r`n"
        [void]$sb.Append($html)
    }
}

[void]$sb.Append($js)
[void]$sb.Append("</body></html>")

$reportFile = Join-Path $OutputPath 'ADAssessment_Report.html'
Set-Content -Path $reportFile -Value $sb.ToString() -Encoding UTF8

# Findings also as CSV (both languages as separate columns)
$script:Findings | Select-Object Category, Severity, `
    @{n='Finding';e={ Get-BiText $_.Finding 'EN' }}, @{n='Finding_DE';e={ Get-BiText $_.Finding 'DE' }}, `
    @{n='Detail';e={ Get-BiText $_.Detail 'EN' }}, @{n='Detail_DE';e={ Get-BiText $_.Detail 'DE' }}, `
    @{n='Recommendation';e={ Get-BiText $_.Recommendation 'EN' }}, @{n='Recommendation_DE';e={ Get-BiText $_.Recommendation 'DE' }}, `
    Anchor | Export-Csv -Path (Join-Path $OutputPath 'Findings.csv') -NoTypeInformation -Encoding UTF8

if (@($script:Compliance).Count -gt 0) {
    $script:Compliance | Select-Object `
        @{n='Check';e={ Get-BiText $_.Check 'EN' }}, @{n='Check_DE';e={ Get-BiText $_.Check 'DE' }}, `
        @{n='Ist';e={ Get-BiText $_.Ist 'EN' }}, @{n='Ist_DE';e={ Get-BiText $_.Ist 'DE' }}, `
        @{n='Soll';e={ Get-BiText $_.Soll 'EN' }}, @{n='Soll_DE';e={ Get-BiText $_.Soll 'DE' }}, `
        Rating, Source, `
        @{n='Comment';e={ Get-BiText $_.Comment 'EN' }}, @{n='Comment_DE';e={ Get-BiText $_.Comment 'DE' }} |
        Export-Csv -Path (Join-Path $OutputPath 'Compliance.csv') -NoTypeInformation -Encoding UTF8
}

Write-Log "Done. Report: $reportFile" 'OK'
Write-Log "Total findings: $(@($script:Findings).Count)" 'OK'
Write-Host ""
Write-Host "Next steps (separate, read-only) - official downloads:" -ForegroundColor Cyan
Write-Host "  - Purple Knight  : https://www.semperis.com/purple-knight/            (security score, IOE/IOC, free)" -ForegroundColor Gray
Write-Host "  - Forest Druid   : https://www.purple-knight.com/forest-druid/         (Tier-0 attack paths, free)" -ForegroundColor Gray
Write-Host "  - ADxRay         : https://github.com/ClaudioMerola/ADxRay             (HTML health/inventory)" -ForegroundColor Gray
Write-Host "  - GPOZaurr       : Install-Module GPOZaurr                             (GPO hygiene)" -ForegroundColor Gray
Write-Host "  - Locksmith      : Install-Module Locksmith                            (AD CS, if present; mode 0-3 read-only)" -ForegroundColor Gray
Write-Host "  - BloodHound CE  : https://github.com/SpecterOps/BloodHound            (attack paths; inform SOC beforehand!)" -ForegroundColor Gray
Write-Host "  - PingCastle     : https://www.pingcastle.com/download/                (community edition self-use ONLY; customer audits require a license)" -ForegroundColor Yellow
