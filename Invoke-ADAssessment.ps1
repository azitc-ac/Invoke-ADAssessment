<#
.SYNOPSIS
    Read-only Active Directory Health & Hygiene Assessment (PowerShell 5.1).

.DESCRIPTION
    Sammelt Health-, Security- und Hygiene-Kennzahlen einer AD-Domaene rein LESEND
    und erzeugt einen HTML-Report. Gedacht als Klammer um Fremdtools
    (Purple Knight, ADxRay, BloodHound, Locksmith, GPOZaurr).

    Fuehrt KEINE Aenderungen durch. dcdiag/repadmin werden nur ausgelesen.

.REQUIREMENTS
    - PowerShell 5.1
    - RSAT: ActiveDirectory-Modul (Import-Module ActiveDirectory)
    - Ausfuehrung als Konto mit Leserechten forestweit (DA/EA vorhanden lt. Scope)
    - Idealerweise auf einem DC oder Admin-Host mit RSAT

.PARAMETER OutputPath
    Zielordner fuer den Report. Default: .\ADAssessment_<Datum>

.PARAMETER InactiveDays
    Schwelle (Tage) fuer inaktive Konten. Default 90.

.NOTES
    Autor: AZITC (Alexander Zarenko IT Consulting)
    Datei mit BOM (UTF-8) speichern.
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

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,   # Critical / High / Medium / Low / Info
        [string]$Finding,
        [string]$Detail = '',
        [string]$Recommendation = '',
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

# Legt Finding UND zugehoerige Detail-Sektion mit identischem Titel + Sprungmarke an.
# $Objects = Liste der betroffenen Konten/Objekte (wird als Tabelle gerendert).
function Add-FindingWithObjects {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Title,          # gemeinsames Wording fuer Finding UND Sektionsueberschrift
        [object]$Objects,
        [string]$Detail = '',
        [string]$Recommendation = '',
        [string]$Note = ''
    )
    $count  = @($Objects).Count
    $anchor = New-Anchor
    $headline = "$count $Title"
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

function Add-Section {
    param([string]$Title, [object]$Data, [string]$Note = '', [string]$Anchor = '')
    [void]$script:Sections.Add([pscustomobject]@{
        Title  = $Title
        Data   = $Data
        Note   = $Note
        Anchor = $Anchor
    })
}

# --- Compliance-Framework (Soll/Ist mit Ampel) ------------------------------
# Rating: 'good' (gruen, besser als Empfehlung) | 'meets' (schwarz, deckt sich)
#         'warn' (gelb, leicht schlechter) | 'bad' (rot, deutlich schlechter) | 'na'
$script:Compliance = New-Object System.Collections.ArrayList

# Quellen-Register (wird als Fussnote gerendert)
$script:Sources = [ordered]@{
    'CIS'    = 'CIS Microsoft Windows Server 2025 Benchmark v2.0.0 (L1) - www.cisecurity.org'
    'MSFT'   = 'Microsoft Security Baseline / Password policy recommendations - learn.microsoft.com'
    'MDI'    = 'Microsoft Defender for Identity - Recommended Action: Change KRBTGT password (>180 Tage) - learn.microsoft.com'
    'MSFTL'  = 'Microsoft - Domain/Forest Functional Levels (Windows Server 2016+ empfohlen) - learn.microsoft.com'
    'MSTIER' = 'Microsoft - Securing Privileged Access / Enterprise Access Model (Tier-0 minimieren) - learn.microsoft.com'
    'MSHARD' = 'Microsoft - Disable SMBv1 / LDAP signing & channel binding / Network security hardening - learn.microsoft.com'
    'MSDR'   = 'Microsoft - AD Forest Recovery & tombstoneLifetime (Standard 180 Tage) - learn.microsoft.com'
    'MSLAPS' = 'Microsoft - Windows LAPS (lokale Admin-Passwoerter verwalten & rotieren) - learn.microsoft.com'
}

function Add-Compliance {
    param(
        [string]$Check,          # Pruefpunkt
        [string]$IstValue,       # Ist
        [string]$SollValue,      # Soll (Empfehlung)
        [ValidateSet('good','meets','warn','bad','na')][string]$Rating,
        [string]$SourceKey = '', # Schluessel aus $script:Sources
        [string]$Comment = ''
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

# --- Vorbereitung -----------------------------------------------------------
Write-Log "AD Assessment startet." 'INFO'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ActiveDirectory-Modul nicht gefunden. RSAT installieren." 'ERROR'
    return
}
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$OutputPath = (Resolve-Path $OutputPath).Path
Write-Log "Report-Ordner: $OutputPath" 'INFO'

# --- 1. Forest / Domain / FSMO ---------------------------------------------
Write-Log "Sammle Forest/Domain/FSMO ..." 'INFO'
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
    Add-Section "Forest / Domain / FSMO" $topo

    foreach ($pair in @(@('Forest-Funktionsebene', "$($forest.ForestMode)"), @('Domain-Funktionsebene', "$($domain.DomainMode)"))) {
        $lvl = $pair[1]
        $lvlRating = if ($lvl -match '2025') { 'good' } elseif ($lvl -match '2016|2019|2022') { 'meets' } elseif ($lvl -match '2012') { 'warn' } else { 'bad' }
        Add-Compliance $pair[0] $lvl "Windows2016 oder hoeher" $lvlRating 'MSFTL' `
            "Ab 2016 u.a. Credential Guard / erweiterte Kerberos-Features nutzbar."
        if ("$lvl" -match '2008|2003|2000|2012') {
            Add-Finding 'Topology' 'Medium' "Niedrige Funktionsebene: $lvl (Soll >=2016)" `
                "Aeltere Funktionsebene aktiv." "Auf mind. Windows Server 2016 anheben (nach Kompatibilitaetspruefung)."
        }
    }
} catch { Write-Log "Forest/Domain-Abfrage fehlgeschlagen: $_" 'ERROR' }

# --- 2. Domain Controller Inventar -----------------------------------------
Write-Log "Sammle DC-Inventar ..." 'INFO'
try {
    $dcs = Get-ADDomainController -Filter * |
        Select-Object HostName, Site, IPv4Address, OperatingSystem, IsGlobalCatalog, IsReadOnly, `
            @{n='OperationMasterRoles';e={ ($_.OperationMasterRoles -join ', ') }}
    Add-Section "Domain Controllers" $dcs

    foreach ($dc in $dcs) {
        if ($dc.OperatingSystem -match '2008|2012') {
            Add-Finding 'DC' 'High' "DC mit Legacy-OS: $($dc.HostName)" `
                "$($dc.OperatingSystem)" "OS ist EOL/nahe EOL. DC auf 2019/2022/2025 migrieren."
        }
    }
} catch { Write-Log "DC-Abfrage fehlgeschlagen: $_" 'ERROR' }

# --- 3. dcdiag / repadmin (nur auslesen) -----------------------------------
Write-Log "Fuehre dcdiag/repadmin aus (read-only) ..." 'INFO'
try {
    $dcdiag = & dcdiag /e /c 2>&1 | Out-String
    Set-Content -Path (Join-Path $OutputPath 'dcdiag.txt') -Value $dcdiag -Encoding UTF8

    # DE + EN Muster (dcdiag ist sprachabhaengig)
    $failMatches = Select-String -InputObject $dcdiag -Pattern 'failed test|nicht bestanden' -AllMatches
    if ($failMatches -and $failMatches.Matches.Count -gt 0) {
        Add-Finding 'Health' 'High' "dcdiag meldet fehlgeschlagene Tests" `
            "$($failMatches.Matches.Count) Treffer. Siehe dcdiag.txt." "Fehlgeschlagene DC-Tests einzeln untersuchen."
    }
} catch { Write-Log "dcdiag fehlgeschlagen: $_" 'WARN' }

try {
    $replsum = & repadmin /replsummary 2>&1 | Out-String
    Set-Content -Path (Join-Path $OutputPath 'repadmin_replsummary.txt') -Value $replsum -Encoding UTF8
    if ($replsum -match '\b([1-9]\d*)\s*/\s*\d+') {
        Add-Finding 'Health' 'Medium' "repadmin meldet moegliche Replikationsfehler" `
            "Siehe repadmin_replsummary.txt (Spalte 'Fails')." "Replikationsfehler je DC nachverfolgen (repadmin /showrepl)."
    }
} catch { Write-Log "repadmin fehlgeschlagen: $_" 'WARN' }

# --- 4. Privilegierte Gruppen ----------------------------------------------
Write-Log "Analysiere privilegierte Gruppen ..." 'INFO'
$privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators')
$privResult = New-Object System.Collections.ArrayList
$privAnchor = New-Anchor
foreach ($g in $privGroups) {
    try {
        $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop
        [void]$privResult.Add([pscustomobject]@{ Group = $g; Count = @($members).Count; Members = (($members | Select-Object -Expand SamAccountName) -join ', ') })
        if ($g -in @('Domain Admins','Enterprise Admins') -and @($members).Count -gt 5) {
            Add-Finding 'Privileged' 'High' "$g hat $(@($members).Count) Mitglieder" `
                "Zu viele dauerhaft privilegierte Konten (siehe Sektion 'Privilegierte Gruppen')." `
                "Auf minimal noetige Konten reduzieren; JIT/JEA einfuehren." $privAnchor
        }
        if ($g -in @('Account Operators','Server Operators') -and @($members).Count -gt 0) {
            Add-Finding 'Privileged' 'Medium' "$g ist besetzt ($(@($members).Count))" `
                "Legacy-Operatorgruppen mit weitreichenden Rechten (siehe Sektion 'Privilegierte Gruppen')." `
                "Mitgliedschaften pruefen/entfernen (haeufig unbeabsichtigt privilegiert)." $privAnchor
        }
        # Compliance-Zielwert fuer die kritischen Tier-0-Gruppen
        if ($g -in @('Domain Admins','Enterprise Admins')) {
            $cnt = @($members).Count
            $daRating = if ($cnt -le 3) { 'good' } elseif ($cnt -le 5) { 'meets' } elseif ($cnt -le 10) { 'warn' } else { 'bad' }
            Add-Compliance "$g - Anzahl Mitglieder" "$cnt" "<= 5 (moeglichst wenige)" $daRating 'MSTIER' `
                "Tier-0-Konten minimieren; idealerweise Just-in-Time statt dauerhaft."
        }
    } catch { }
}
Add-Section "Privilegierte Gruppen" $privResult '' $privAnchor

# --- 5. Kerberos / Delegation ----------------------------------------------
Write-Log "Pruefe Kerberos/Delegation ..." 'INFO'
try {
    # Kerberoastable: User mit SPN (ohne krbtgt)
    $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like '*' -and Enabled -eq $true } -Properties ServicePrincipalName, PasswordLastSet |
        Where-Object { $_.SamAccountName -ne 'krbtgt' } |
        Select-Object SamAccountName, PasswordLastSet, @{n='SPNs';e={ ($_.ServicePrincipalName -join '; ') }}
    if (@($spnUsers).Count -gt 0) {
        Add-FindingWithObjects 'Kerberos' 'High' "User-Konten mit SPN (Kerberoasting-Risiko)" $spnUsers `
            "Service-Konten mit SPN sind offline angreifbar (Kerberoasting)." `
            "gMSA nutzen bzw. 25+ Zeichen Passwoerter, regelmaessige Rotation."
    }

    # AS-REP-Roasting: kein Kerberos-Pre-Auth (UAC-Bit 0x400000 = DONT_REQ_PREAUTH)
    $asrep = Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' |
        Select-Object SamAccountName
    if (@($asrep).Count -gt 0) {
        Add-FindingWithObjects 'Kerberos' 'High' "Konten ohne Kerberos-Pre-Auth (AS-REP-Roasting-Risiko)" $asrep `
            "AS-REP-Roasting moeglich." `
            "'Do not require Kerberos preauthentication' entfernen."
    }

    # Unconstrained Delegation (ohne DCs)
    $unconstrained = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, PrimaryGroupID |
        Where-Object { $_.PrimaryGroupID -ne 516 } | Select-Object Name, DNSHostName
    if (@($unconstrained).Count -gt 0) {
        Add-FindingWithObjects 'Delegation' 'Critical' "Objekte mit Unconstrained Delegation" $unconstrained `
            "Erlaubt Impersonation bis Tier 0." `
            "Auf Constrained/RBCD umstellen oder Delegation entfernen; Tier-0-Konten in Protected Users."
    }
} catch { Write-Log "Kerberos-Analyse teilweise fehlgeschlagen: $_" 'WARN' }

# --- 6. krbtgt Passwortalter -----------------------------------------------
try {
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
    $age = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
    Add-Section "krbtgt" ([pscustomobject]@{ PasswordLastSet = $krbtgt.PasswordLastSet; AgeDays = $age })
    $krbRating = if ($age -le 90) { 'good' } elseif ($age -le 180) { 'meets' } elseif ($age -le 365) { 'warn' } else { 'bad' }
    Add-Compliance "krbtgt-Passwortalter" "$age Tage" "<= 180 Tage" $krbRating 'MDI' `
        "Golden-Ticket-Schutz. High-Security-Umgebungen rotieren haeufiger."
    if ($age -gt 180) {
        Add-Finding 'Kerberos' 'Medium' "krbtgt-Passwort ist $age Tage alt (Soll <=180)" `
            "Alte krbtgt-Keys erhoehen Golden-Ticket-Risiko." "krbtgt kontrolliert rotieren (2x mit Abstand)."
    }
} catch { }

# --- 7. Konten-Hygiene ------------------------------------------------------
Write-Log "Pruefe Konten-Hygiene ..." 'INFO'
$cutoff = (Get-Date).AddDays(-$InactiveDays)
try {
    $inactiveUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonTimestamp |
        Where-Object { $_.LastLogonTimestamp -and ([datetime]::FromFileTime($_.LastLogonTimestamp) -lt $cutoff) } |
        Select-Object SamAccountName, @{n='LastLogon';e={ [datetime]::FromFileTime($_.LastLogonTimestamp) }}
    if (@($inactiveUsers).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'Medium' "aktive User seit >$InactiveDays Tagen inaktiv" $inactiveUsers `
            "Stale-Konten vergroessern die Angriffsflaeche." `
            "Deaktivierungs-/Loeschprozess (Lifecycle) etablieren."
    }

    $neverExpire = Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $true } | Select-Object SamAccountName
    if (@($neverExpire).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'Medium' "Konten mit 'Password never expires'" $neverExpire `
            "Dauerpasswoerter." `
            "Ausnahmen begruenden; gMSA/Managed-Accounts nutzen."
    }

    $pwNotReq = Get-ADUser -Filter { PasswordNotRequired -eq $true -and Enabled -eq $true } | Select-Object SamAccountName
    if (@($pwNotReq).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'High' "Konten mit 'PasswordNotRequired'" $pwNotReq `
            "Konten ohne Passwortzwang." `
            "Attribut bereinigen."
    }

    $reversible = Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true -and Enabled -eq $true } | Select-Object SamAccountName
    if (@($reversible).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'High' "Konten mit reversibler Verschluesselung" $reversible `
            "Passwoerter praktisch im Klartext." `
            "Reversible Encryption deaktivieren."
    }

    $inactiveComputers = Get-ADComputer -Filter { Enabled -eq $true } -Properties LastLogonTimestamp, OperatingSystem |
        Where-Object { $_.LastLogonTimestamp -and ([datetime]::FromFileTime($_.LastLogonTimestamp) -lt $cutoff) } |
        Select-Object Name, OperatingSystem, @{n='LastLogon';e={ [datetime]::FromFileTime($_.LastLogonTimestamp) }}
    if (@($inactiveComputers).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'Low' "inaktive Computerkonten (>$InactiveDays Tage)" $inactiveComputers `
            "Verwaiste Computerobjekte." `
            "Bereinigen/deaktivieren."
    }

    # Legacy-OS Computer
    $legacyOS = Get-ADComputer -Filter { Enabled -eq $true } -Properties OperatingSystem |
        Where-Object { $_.OperatingSystem -match 'XP|Vista|2003|2008|Windows 7|Windows 8' } |
        Select-Object Name, OperatingSystem
    if (@($legacyOS).Count -gt 0) {
        Add-FindingWithObjects 'Hygiene' 'High' "Rechner mit EOL-Betriebssystem" $legacyOS `
            "Ungepatchte Legacy-Systeme." `
            "Ersetzen/isolieren."
    }
} catch { Write-Log "Konten-Hygiene teilweise fehlgeschlagen: $_" 'WARN' }

# --- 8. Passwort-Policy -----------------------------------------------------
Write-Log "Pruefe Passwort-Policy ..." 'INFO'
try {
    $pw = Get-ADDefaultDomainPasswordPolicy
    Add-Section "Default Domain Password Policy" ([pscustomobject]@{
        MinPasswordLength      = $pw.MinPasswordLength
        PasswordHistoryCount   = $pw.PasswordHistoryCount
        MaxPasswordAgeDays     = $pw.MaxPasswordAge.Days
        LockoutThreshold       = $pw.LockoutThreshold
        ComplexityEnabled      = $pw.ComplexityEnabled
        ReversibleEncryption   = $pw.ReversibleEncryptionEnabled
    })

    # --- Compliance: Minimale Passwortlaenge (CIS: >=14) ---
    $ml = $pw.MinPasswordLength
    $mlRating = if ($ml -ge 15) { 'good' } elseif ($ml -eq 14) { 'meets' } elseif ($ml -ge 10) { 'warn' } else { 'bad' }
    Add-Compliance "Minimale Passwortlaenge" "$ml Zeichen" ">= 14 Zeichen" $mlRating 'CIS' `
        "NIST/CISA gehen tendenziell zu Passphrasen (16+); CIS-Baseline fordert 14."
    if ($ml -lt 14) {
        Add-Finding 'Policy' 'Medium' "Minimale Passwortlaenge = $ml (Soll >=14)" `
            "Unter CIS-Baseline (14 Zeichen)." "Auf >=14 anheben; Banned-Password-Ansatz (z.B. Entra Password Protection)."
    }

    # --- Compliance: Passwort-History (CIS: >=24) ---
    $hist = $pw.PasswordHistoryCount
    $histRating = if ($hist -ge 24) { 'meets' } elseif ($hist -ge 12) { 'warn' } else { 'bad' }
    Add-Compliance "Passwort-History" "$hist" ">= 24" $histRating 'CIS'
    if ($hist -lt 24) {
        Add-Finding 'Policy' 'Low' "Passwort-History = $hist (Soll >=24)" `
            "Wiederverwendung alter Passwoerter moeglich." "History auf 24 setzen (CIS)."
    }

    # --- Compliance: Account-Lockout-Schwelle (CIS: 1-5, !=0) ---
    $lt = $pw.LockoutThreshold
    $ltRating = if ($lt -eq 0) { 'bad' } elseif ($lt -ge 1 -and $lt -le 5) { 'meets' } elseif ($lt -le 10) { 'warn' } else { 'warn' }
    $ltIst = if ($lt -eq 0) { '0 (deaktiviert)' } else { "$lt Versuche" }
    Add-Compliance "Account-Lockout-Schwelle" $ltIst "1-5 Versuche (nicht 0)" $ltRating 'CIS' `
        "0 = kein Lockout. Sehr niedrige Werte koennen DoS beguenstigen - Balance beachten."
    if ($lt -eq 0) {
        Add-Finding 'Policy' 'Medium' "Kein Account-Lockout konfiguriert (Soll 1-5)" `
            "Brute-Force ungebremst." "Lockout-Schwelle setzen (Balance zu DoS beachten)."
    }

    # --- Compliance: Reversible Verschluesselung (Soll: aus) ---
    $revRating = if ($pw.ReversibleEncryptionEnabled) { 'bad' } else { 'meets' }
    Add-Compliance "Reversible Verschluesselung (Domain-Policy)" `
        ($(if ($pw.ReversibleEncryptionEnabled) { 'aktiviert' } else { 'deaktiviert' })) "deaktiviert" $revRating 'CIS'

    # --- Compliance: Komplexitaet (CIS: an) ---
    $cxRating = if ($pw.ComplexityEnabled) { 'meets' } else { 'warn' }
    Add-Compliance "Passwortkomplexitaet" `
        ($(if ($pw.ComplexityEnabled) { 'aktiviert' } else { 'deaktiviert' })) "aktiviert" $cxRating 'CIS' `
        "NIST sieht Komplexitaet zunehmend kritisch; CIS-Baseline fordert sie weiterhin."
} catch { Write-Log "Passwort-Policy fehlgeschlagen: $_" 'WARN' }

# --- 9. AdminSDHolder / AdminCount-Waisen ----------------------------------
try {
    $adminCountOrphans = Get-ADUser -Filter { adminCount -eq 1 -and Enabled -eq $true } -Properties adminCount, memberOf |
        Select-Object SamAccountName, DistinguishedName
    if (@($adminCountOrphans).Count -gt 0) {
        Add-FindingWithObjects 'Privileged' 'Info' "Konten mit adminCount=1 (SDProp)" $adminCountOrphans `
            "Ehemals/aktuell privilegierte Konten mit restriktiver ACL durch SDProp." `
            "Auf Waisen pruefen: adminCount ohne aktuelle Gruppenmitgliedschaft bereinigen." `
            "Ehemals privilegierte Konten behalten restriktive ACL (SDProp). Auf Waisen pruefen."
    }
} catch { }

# --- 10. Trusts -------------------------------------------------------------
try {
    $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue |
        Select-Object Name, Direction, TrustType, ForestTransitive, SIDFilteringForestAware, SIDFilteringQuarantined
    if ($trusts) {
        $trustAnchor = New-Anchor
        Add-Section "Trusts" $trusts '' $trustAnchor
        foreach ($t in $trusts) {
            if ($t.SIDFilteringQuarantined -eq $false) {
                Add-Finding 'Trust' 'Medium' "Trust '$($t.Name)' ohne SID-Filtering-Quarantine" `
                    "SID-History-Missbrauch moeglich (siehe Sektion 'Trusts')." `
                    "SID-Filtering pruefen/aktivieren." $trustAnchor
            }
        }
    }
} catch { }

# --- 11. AD CS vorhanden? ---------------------------------------------------
try {
    $pkiBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services," + (Get-ADRootDSE).configurationNamingContext
    # Nur echte CA-Objekte (pKIEnrollmentService), nicht der Container selbst
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
                } catch { $ip = '(nicht aufloesbar)' }
            }
            [pscustomobject]@{
                CAName      = $ca.Name
                CAHost      = $ca.dNSHostName
                IPAddress   = $ip
                CASubjectDN = $ca.cACertificateDN
                WhenCreated = $ca.whenCreated
            }
        }
        Add-FindingWithObjects 'ADCS' 'Info' "Enterprise-CA(s) im Forest (AD CS aktiv)" $pkiResult `
            "Enterprise-CA erkannt - AD CS ist ein haeufig uebersehener Angriffspfad." `
            "ESC1-ESC16 mit Locksmith / PSPKIAudit pruefen (separater Lauf)." `
            "Web-Enrollment/EPA und Template-Berechtigungen gesondert pruefen."
    }
} catch { }

# --- 12. Legacy-Protokolle / Hardening (DC-lokal, best effort) --------------
Write-Log "Pruefe Legacy-Protokolle / Hardening ..." 'INFO'
try {
    $pdc = (Get-ADDomain).PDCEmulator
    # Registry remote vom PDC lesen (read-only). Fallback wenn nicht erreichbar.
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
    $smb1Ist = if ($null -eq $smb1) { 'nicht gesetzt (Default)' } elseif ($smb1 -eq 0) { 'deaktiviert (0)' } else { "aktiviert ($smb1)" }
    $smb1Rating = if ($smb1 -eq 0) { 'meets' } elseif ($null -eq $smb1) { 'warn' } else { 'bad' }
    Add-Compliance "SMBv1 (PDC: $pdc)" $smb1Ist "deaktiviert" $smb1Rating 'MSHARD' `
        "SMB1=0 explizit setzen. 'nicht gesetzt' = Verhalten OS-abhaengig, besser explizit deaktivieren/Feature entfernen."
    if ($smb1 -and $smb1 -ne 0) {
        Add-Finding 'Hardening' 'High' "SMBv1 auf $pdc aktiviert" `
            "Veraltetes, angreifbares Protokoll (WannaCry-Vektor)." "SMBv1-Feature entfernen."
    }

    # LDAP Server Signing: LDAPServerIntegrity (2 = require)
    $ldapSign = Get-RemoteReg $pdc 'LocalMachine' 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'
    $ldapIst = switch ($ldapSign) { 2 { 'require signing (2)' } 1 { 'none/optional (1)' } default { 'nicht gesetzt' } }
    $ldapRating = if ($ldapSign -eq 2) { 'meets' } elseif ($null -eq $ldapSign) { 'warn' } else { 'bad' }
    Add-Compliance "LDAP Server Signing (PDC)" $ldapIst "require (2)" $ldapRating 'MSHARD' `
        "Schutz gegen LDAP-Relay. Microsoft haertet dies zunehmend per Default."
    if ($ldapSign -ne $null -and $ldapSign -lt 2) {
        Add-Finding 'Hardening' 'Medium' "LDAP-Signing auf $pdc nicht erzwungen" `
            "LDAP-Relay/MitM moeglich." "LDAPServerIntegrity=2 per GPO erzwingen (nach Client-Kompatibilitaetstest)."
    }

    # LDAP Channel Binding: LdapEnforceChannelBinding (2 = always)
    $cbt = Get-RemoteReg $pdc 'LocalMachine' 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'
    $cbtIst = switch ($cbt) { 2 { 'always (2)' } 1 { 'when supported (1)' } 0 { 'off (0)' } default { 'nicht gesetzt' } }
    $cbtRating = if ($cbt -eq 2) { 'meets' } elseif ($cbt -eq 1) { 'warn' } elseif ($null -eq $cbt) { 'warn' } else { 'bad' }
    Add-Compliance "LDAP Channel Binding (PDC)" $cbtIst "always (2)" $cbtRating 'MSHARD'

    # NTLM: RestrictNTLM/LmCompatibilityLevel (>=5 empfohlen)
    $lmcl = Get-RemoteReg $pdc 'LocalMachine' 'SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    $lmclIst = if ($null -eq $lmcl) { 'nicht gesetzt (Default)' } else { "$lmcl" }
    $lmclRating = if ($lmcl -ge 5) { 'meets' } elseif ($null -eq $lmcl) { 'warn' } elseif ($lmcl -ge 3) { 'warn' } else { 'bad' }
    Add-Compliance "LmCompatibilityLevel (PDC)" $lmclIst ">= 5 (nur NTLMv2)" $lmclRating 'MSHARD' `
        "Level 5 verweigert LM/NTLMv1. Kompatibilitaet aelterer Systeme vorher pruefen."
} catch { Write-Log "Hardening-Pruefung teilweise fehlgeschlagen (Remote-Registry?): $_" 'WARN' }

# --- 13. Backup / DR / tombstoneLifetime -----------------------------------
Write-Log "Pruefe Backup/DR-Kennzahlen ..." 'INFO'
try {
    $cfgNC = (Get-ADRootDSE).configurationNamingContext
    $dsObj = Get-ADObject -Identity ("CN=Directory Service,CN=Windows NT,CN=Services," + $cfgNC) `
        -Properties tombstoneLifetime -ErrorAction SilentlyContinue
    $tsl = if ($dsObj -and $dsObj.tombstoneLifetime) { $dsObj.tombstoneLifetime } else { $null }
    $tslIst = if ($null -eq $tsl) { 'nicht gesetzt (Default 60/180)' } else { "$tsl Tage" }
    $tslRating = if ($tsl -ge 180) { 'meets' } elseif ($null -eq $tsl) { 'warn' } elseif ($tsl -ge 90) { 'warn' } else { 'bad' }
    Add-Compliance "tombstoneLifetime" $tslIst ">= 180 Tage" $tslRating 'MSDR' `
        "Bestimmt max. Backup-Alter fuer Restore. Zu klein = alte Backups unbrauchbar."

    # Letztes erfolgreiches Systemstate-Backup naeherungsweise ueber dsHeuristics/replMetadata ist unzuverlaessig -
    # daher Hinweis-Finding statt harter Wert:
    Add-Finding 'BackupDR' 'Info' "Backup/DR manuell verifizieren" `
        "Systemstate-/DC-Backup-Alter und getesteter Forest-Recovery-Plan sind per LDAP nicht zuverlaessig auslesbar." `
        "Backup-Loesung pruefen: regelmaessiges Systemstate-Backup >=1 DC, dokumentierter & GEUEBTER Forest-Recovery-Plan, DSRM-Passwort-Governance."
} catch { Write-Log "Backup/DR-Pruefung fehlgeschlagen: $_" 'WARN' }

# --- 14. DCSync-Rechte (DS-Replication-Get-Changes-All) --------------------
Write-Log "Pruefe DCSync-Rechte auf Domain-NC ..." 'INFO'
try {
    $domainDN = (Get-ADDomain).DistinguishedName
    # Extended Rights GUIDs
    $guidGetChangesAll = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' # DS-Replication-Get-Changes-All
    $acl = Get-Acl -Path ("AD:\" + $domainDN) -ErrorAction Stop

    # Bekannte, legitime Prinzipale (die DCSync duerfen)
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
        Add-FindingWithObjects 'Delegation' 'Critical' "Nicht-Standard-Prinzipale mit DCSync-Recht" $dcsync `
            "DS-Replication-Get-Changes-All erlaubt das Auslesen aller Passwort-Hashes (DCSync)." `
            "Recht auf DCs/DAs beschraenken; unerwartete Prinzipale sofort entfernen." `
            "Legitime Standard-Prinzipale (DAs/EAs/DCs/SYSTEM) sind ausgefiltert."
    } else {
        Add-Finding 'Delegation' 'Info' "Keine Nicht-Standard-DCSync-Rechte gefunden" `
            "Nur erwartete Prinzipale besitzen DS-Replication-Get-Changes-All." `
            "Keine Aktion noetig; bei Aenderungen erneut pruefen."
    }
} catch { Write-Log "DCSync-Pruefung fehlgeschlagen (AD-PSDrive/Rechte?): $_" 'WARN' }

# --- 15. GPP-Passwoerter in SYSVOL (MS14-025) ------------------------------
Write-Log "Pruefe GPP-Passwoerter in SYSVOL (MS14-025) ..." 'INFO'
try {
    $domainDns = (Get-ADDomain).DNSRoot
    $sysvol = "\\$domainDns\SYSVOL\$domainDns\Policies"
    if (Test-Path $sysvol) {
        # cpassword steht in Groups.xml/Services.xml/Scheduledtasks.xml/Datasources.xml/Printers.xml/Drives.xml
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
            Add-FindingWithObjects 'GPP' 'Critical' "GPP-Dateien mit cpassword (MS14-025)" $gppHits `
                "cpassword ist mit bekanntem AES-Key entschluesselbar - Klartext-Passwoerter in SYSVOL." `
                "Betroffene GPP-Eintraege entfernen, Passwoerter rotieren, auf LAPS umstellen." `
                "Von jedem authentifizierten User lesbar."
        } else {
            Add-Finding 'GPP' 'Info' "Keine GPP-cpassword-Funde in SYSVOL" `
                "Kein MS14-025-Klartextpasswort in den ueblichen GPP-XMLs gefunden." `
                "Keine Aktion noetig."
        }
    } else {
        Write-Log "SYSVOL-Pfad nicht erreichbar: $sysvol" 'WARN'
    }
} catch { Write-Log "GPP-Scan fehlgeschlagen: $_" 'WARN' }

# --- 16. LAPS-Ausrollgrad ---------------------------------------------------
Write-Log "Pruefe LAPS-Ausrollgrad ..." 'INFO'
try {
    # Windows LAPS (msLAPS-Password) und Legacy LAPS (ms-Mcs-AdmPwd) beruecksichtigen
    # Nur Attribute anfragen, die im Schema existieren (sonst wirft Get-ADComputer)
    $schemaNC = (Get-ADRootDSE).schemaNamingContext
    $lapsAttrs = New-Object System.Collections.ArrayList
    foreach ($attr in @('ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime')) {
        $exists = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(lDAPDisplayName=$attr)" -ErrorAction SilentlyContinue
        if ($exists) { [void]$lapsAttrs.Add($attr) }
    }
    if (@($lapsAttrs).Count -eq 0) {
        Add-Compliance "LAPS-Ausrollgrad" "kein LAPS-Schema gefunden" "LAPS ausrollen" 'bad' 'MSLAPS' `
            "Weder Legacy- noch Windows-LAPS-Attribute im Schema - LAPS ist nicht eingerichtet."
        Add-Finding 'LAPS' 'Medium' "LAPS nicht eingerichtet (kein Schema-Attribut)" `
            "Keine zentrale Verwaltung lokaler Admin-Passwoerter." `
            "Windows LAPS einrichten (Schema erweitern, GPO ausrollen)."
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
                if (@($missing).Count -lt 200) { [void]$missing.Add([pscustomobject]@{ Name = $c.Name; OS = $c.OperatingSystem }) }
            }
        }
        if ($checked -gt 0) {
            $pct = [math]::Round(($withLaps / $checked) * 100, 1)
            $lapsRating = if ($pct -ge 95) { 'good' } elseif ($pct -ge 80) { 'meets' } elseif ($pct -ge 50) { 'warn' } else { 'bad' }
            Add-Compliance "LAPS-Ausrollgrad" "$pct% ($withLaps/$checked)" ">= 95% der Nicht-DC-Rechner" $lapsRating 'MSLAPS' `
                "Beruecksichtigt Windows LAPS (msLAPS-*) und Legacy LAPS (ms-Mcs-AdmPwd*)."
            if ($pct -lt 95 -and @($missing).Count -gt 0) {
                Add-FindingWithObjects 'LAPS' 'Medium' "Rechner ohne LAPS-Passwortverwaltung" $missing `
                    "Ohne LAPS: identische/statische lokale Admin-Passwoerter -> lateral movement." `
                    "LAPS (Windows LAPS bevorzugt) flaechendeckend ausrollen." `
                    "Anzeige auf max. 200 Objekte begrenzt."
            }
        }
    }
} catch { Write-Log "LAPS-Pruefung fehlgeschlagen: $_" 'WARN' }

# --- Report generieren ------------------------------------------------------
Write-Log "Erzeuge HTML-Report ..." 'INFO'

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
</style>
"@

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append("<html><head><meta charset='utf-8'>$css</head><body>")
[void]$sb.Append("<h1>Active Directory Assessment Report</h1>")
[void]$sb.Append("<p class='meta'>Erstellt: $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; AZITC &middot; Read-only Assessment</p>")

# Findings-Uebersicht
[void]$sb.Append("<h2 id='findings'>Findings (priorisiert)</h2>")
if (@($findingsSorted).Count -eq 0) {
    [void]$sb.Append("<p>Keine automatischen Findings erzeugt.</p>")
} else {
    [void]$sb.Append("<table><tr><th>Severity</th><th>Kategorie</th><th>Finding</th><th>Detail</th><th>Empfehlung</th><th>Details</th></tr>")
    foreach ($f in $findingsSorted) {
        $link = if ($f.Anchor) { "<a href='#$($f.Anchor)'>betroffene Objekte &rarr;</a>" } else { '&ndash;' }
        [void]$sb.Append("<tr><td><span class='$($f.Severity)'>$($f.Severity)</span></td><td>$(ConvertTo-HtmlEncoded $f.Category)</td><td>$(ConvertTo-HtmlEncoded $f.Finding)</td><td>$(ConvertTo-HtmlEncoded $f.Detail)</td><td>$(ConvertTo-HtmlEncoded $f.Recommendation)</td><td>$link</td></tr>")
    }
    [void]$sb.Append("</table>")
}

# Compliance-Uebersicht (Soll/Ist mit Ampel)
if (@($script:Compliance).Count -gt 0) {
    [void]$sb.Append("<h2 id='compliance'>Soll/Ist-Vergleich (Best-Practice-Abgleich)</h2>")
    [void]$sb.Append("<p class='legend'>Bewertung: <span class='' style='background:#d4efdf;color:#186a3b;'>gruen = besser als Empfehlung</span><span style='background:#fff;border:1px solid #ccc;'>schwarz = deckt sich</span><span style='background:#fcf3cf;color:#7d6608;'>gelb = leicht schlechter</span><span style='background:#f5b7b1;color:#922b21;'>rot = deutlich schlechter</span></p>")
    [void]$sb.Append("<table><tr><th>Pruefpunkt</th><th>Ist</th><th>Soll (Empfehlung)</th><th>Bewertung</th><th>Quelle</th><th>Anmerkung</th></tr>")
    $ratingLabel = @{ 'good'='besser'; 'meets'='erfuellt'; 'warn'='leicht schlechter'; 'bad'='deutlich schlechter'; 'na'='n/a' }
    foreach ($c in $script:Compliance) {
        $cls = $c.Rating
        [void]$sb.Append("<tr><td>$(ConvertTo-HtmlEncoded $c.Check)</td><td class='$cls'>$(ConvertTo-HtmlEncoded $c.Ist)</td><td>$(ConvertTo-HtmlEncoded $c.Soll)</td><td class='$cls'>$(ConvertTo-HtmlEncoded $ratingLabel[$c.Rating])</td><td class='srcref'>$(ConvertTo-HtmlEncoded $c.Source)</td><td class='srcref'>$(ConvertTo-HtmlEncoded $c.Comment)</td></tr>")
    }
    [void]$sb.Append("</table>")
    # Quellen-Fussnote
    [void]$sb.Append("<div class='sources'><strong>Quellen der Empfehlungen:</strong><ul>")
    foreach ($k in $script:Sources.Keys) {
        [void]$sb.Append("<li><strong>$k</strong> = $(ConvertTo-HtmlEncoded $script:Sources[$k])</li>")
    }
    [void]$sb.Append("</ul><p class='note'>Hinweis: Werte orientieren sich an der CIS-Baseline (praxisnaher Standard). NIST SP 800-63B und CISA setzen bei Passwoertern zunehmend auf Laenge/Passphrasen statt erzwungener Komplexitaet/Rotation - die Empfehlungen sind daher als Richtwert, nicht als absolute Wahrheit zu lesen.</p></div>")
}
foreach ($sec in $script:Sections) {
    if ($sec.Anchor) {
        [void]$sb.Append("<h2 id='$($sec.Anchor)'>$(ConvertTo-HtmlEncoded $sec.Title) <a href='#findings' class='backlink'>&uarr; zu den Findings</a></h2>")
    } else {
        [void]$sb.Append("<h2>$(ConvertTo-HtmlEncoded $sec.Title)</h2>")
    }
    if ($sec.Note) { [void]$sb.Append("<p class='note'>$(ConvertTo-HtmlEncoded $sec.Note)</p>") }

    if ($null -eq $sec.Data) {
        [void]$sb.Append("<p><em>Keine Daten.</em></p>")
        continue
    }

    $items = @($sec.Data)
    if ($items.Count -eq 0) {
        [void]$sb.Append("<p><em>Keine Eintraege.</em></p>")
        continue
    }

    if ($items.Count -eq 1 -and ($items[0] -is [pscustomobject])) {
        # Einzelobjekt -> vertikale Key/Value-Tabelle (lesbarer)
        [void]$sb.Append("<table><tr><th>Eigenschaft</th><th>Wert</th></tr>")
        foreach ($p in $items[0].PSObject.Properties) {
            [void]$sb.Append("<tr><td>$(ConvertTo-HtmlEncoded $p.Name)</td><td>$(ConvertTo-HtmlEncoded ([string]$p.Value))</td></tr>")
        }
        [void]$sb.Append("</table>")
    } else {
        $html = ($items | ConvertTo-Html -Fragment) -join "`r`n"
        [void]$sb.Append($html)
    }
}

[void]$sb.Append("</body></html>")

$reportFile = Join-Path $OutputPath 'ADAssessment_Report.html'
Set-Content -Path $reportFile -Value $sb.ToString() -Encoding UTF8

# Findings auch als CSV
$script:Findings | Export-Csv -Path (Join-Path $OutputPath 'Findings.csv') -NoTypeInformation -Encoding UTF8
if (@($script:Compliance).Count -gt 0) {
    $script:Compliance | Export-Csv -Path (Join-Path $OutputPath 'Compliance.csv') -NoTypeInformation -Encoding UTF8
}

Write-Log "Fertig. Report: $reportFile" 'OK'
Write-Log "Findings gesamt: $(@($script:Findings).Count)" 'OK'
Write-Host ""
Write-Host "Naechste Schritte (separat, read-only) - offizielle Downloads:" -ForegroundColor Cyan
Write-Host "  - Purple Knight  : https://www.semperis.com/purple-knight/            (Security-Score, IOE/IOC, kostenlos)" -ForegroundColor Gray
Write-Host "  - Forest Druid   : https://www.purple-knight.com/forest-druid/         (Tier-0-Angriffspfade, kostenlos)" -ForegroundColor Gray
Write-Host "  - ADxRay         : https://github.com/ClaudioMerola/ADxRay             (HTML-Health/Inventory)" -ForegroundColor Gray
Write-Host "  - GPOZaurr       : Install-Module GPOZaurr                             (GPO-Hygiene)" -ForegroundColor Gray
Write-Host "  - Locksmith      : Install-Module Locksmith                            (AD CS, falls vorhanden; Mode 0-3 read-only)" -ForegroundColor Gray
Write-Host "  - BloodHound CE  : https://github.com/SpecterOps/BloodHound            (Angriffspfade; SOC vorab informieren!)" -ForegroundColor Gray
Write-Host "  - PingCastle     : https://www.pingcastle.com/download/                (Community NUR Eigennutzung; Kundenaudit lizenzpflichtig)" -ForegroundColor Yellow
