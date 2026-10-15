# Invoke-ADAssessment

A **read-only** Active Directory Health, Security & Hygiene assessment for PowerShell 5.1. One script, one HTML report — no installation, no changes to your environment.

Built as a lightweight companion to tools like [Purple Knight](https://www.semperis.com/purple-knight/) and [ADxRay](https://github.com/ClaudioMerola/ADxRay): it collects the in-box health data (`dcdiag`, `repadmin`), runs a focused set of security & hygiene checks, and produces a prioritized findings report with a **Best-Practice compliance table** (actual vs. recommended, colour-coded, with sources).

> ⚠️ This is not a Microsoft product. It reads from AD; it never writes. Remediation is your job, done separately.

## Features

- **Health & operations:** FSMO roles, DC inventory, `dcdiag` / `repadmin` (read only), functional levels
- **Security & attack paths:** privileged group membership, Kerberoasting & AS-REP candidates, unconstrained delegation, DCSync rights on the domain NC, krbtgt password age, dangerous ACEs (GenericAll/WriteDacl/WriteOwner) on AdminSDHolder, the domain root and OUs held by non-Tier-0 principals
- **Hygiene:** inactive accounts, "password never expires", `PasswordNotRequired`, reversible encryption, GPP passwords in SYSVOL (MS14-025), LAPS deployment coverage
- **Hardening:** SMBv1, LDAP signing & channel binding, LmCompatibilityLevel (read from the PDC)
- **AD CS detection:** enterprise CA discovery (host, IP, subject DN) as a pointer to run [Locksmith](https://github.com/jakehildreth/Locksmith)
- **Soll/Ist compliance table:** actual vs. recommended for every measurable setting, colour-coded (green = better, black = meets, yellow = borderline, red = action needed), each row citing its source (CIS Benchmark, Microsoft, Defender for Identity)
- **Jump links:** every finding links to the list of affected objects
- **Bilingual report:** English/German toggle in the HTML report (defaults to English); the console/log output and script itself are English
- **Output:** `ADAssessment_Report.html`, plus `Findings.csv` and `Compliance.csv`

## Requirements

- PowerShell 5.1
- RSAT: the `ActiveDirectory` module
- An account with forest-wide read access (run on a DC or an admin host with RSAT)

## Usage

```powershell
# Default: creates a timestamped report folder in the current directory
.\Invoke-ADAssessment.ps1

# Custom output folder and inactivity threshold
.\Invoke-ADAssessment.ps1 -OutputPath "C:\Reports\Contoso" -InactiveDays 60
```

Open `ADAssessment_Report.html` from the output folder when it finishes.

## Before you run it against a customer

- **Get written authorisation** for the scope and time window.
- **Warn the SOC/EDR team.** Reading DCSync ACLs and scanning SYSVOL for GPP passwords looks like attacker enumeration to a SIEM. A heads-up avoids false-positive alerts.
- **Mind data protection.** The report contains account names and admin mappings. Store it encrypted, define retention.

## A note on the password recommendations

The compliance thresholds follow the **CIS Benchmark** as a practical baseline. Note that NIST SP 800-63B and CISA increasingly favour length/passphrases over enforced complexity and rotation — so treat these as guidance, not absolute truth, depending on which model the environment follows. The report says so too.

## How it compares to ADxRay / PingCastle / Purple Knight

This tool doesn't try to match those in breadth — it deliberately covers a focused, fully editable core with a sourced compliance view. For a real assessment, combine it: **Purple Knight** for the security score, **ADxRay** for broad inventory, this script as the editable bracket around them.

## Companion diagnostics

Alongside the main assessment, the repo carries focused scripts for two problems that come up constantly on real DCs — **slow LDAP/LDAPS binds** and **slow SMB/CIFS access**. Each is a single, PowerShell 5.1 script with a compact, colour-coded verdict. All are read-only except `Simulate-AirgapCtl.ps1`, which is clearly marked.

**LDAP / LDAPS bind performance & root cause**

- `Test-LdapsBind.ps1` — LDAP (389) vs LDAPS (636) bind time per DC. A fast LDAP with a slow LDAPS bind is the classic signature of a TLS / certificate-validation delay rather than a slow DC.
- `Get-LdapBindMetric.ps1` — a slim single-DC variant returning `{ DC, LDAP, LDAPS }` (object or `-Json`) for monitoring, e.g. a Zabbix master item with JSONPath dependent items.
- `Test-LdapsRevocation.ps1` — checks the DC's LDAPS certificate chain and parses the per-URL CDP/AIA/OCSP fetch time, so a slow or failing revocation URL becomes visible.
- `Test-LdapsCtl.ps1` — the other validation path: the CTL (AuthRoot auto-update) engine, which fetches from `ctldl.windowsupdate.com` during the handshake and, on an isolated network, times out. Checks policy, reachability, cache, and (`-Capture`, admin) a CAPI2-correlated cold bind; a raw TLS probe reports the exact SChannel error when a bind fails.
- `Simulate-AirgapCtl.ps1` — **not read-only; lab use only.** Reversibly reproduces that isolated-network CTL timeout (hosts pin + firewall drop), clears the caches, runs the diagnostic, and restores everything in a `finally` block (`-Restore` cleans up a kept block).

**SMB / CIFS connection setup**

- `Test-SmbConnectSetup.ps1` — cold vs warm SMB connect per server, and whether Kerberos or a silent NTLM fallback was used. Explains "it works but the first access is slow" and why no CIFS service ticket is raised.
- `Invoke-ConnTrace.ps1` — captures a scoped ETW trace (SMBClient / Kerberos / NTLM / DNS) around a connect, or analyses an existing `.etl`/`.evtx` offline, and produces a per-target verdict (Kerberos vs NTLM, DNS health, the largest inter-event gap) plus a self-contained HTML timeline. No internet, no extra tools.

**Domain controller health**

- `Get-DcMemoryPressure.ps1` — the counters that actually indicate memory pressure (Available MBytes, commit charge, Pages/sec, LSASS trend), because "free RAM" is meaningless when LSASS caches the database.
- `Get-DnsStaleRecords.ps1` — lists DNS records by timestamp age to show what scavenging would delete *before* you enable it, surfacing the risk group: live hosts with a stale timestamp that nothing refreshes.

**Network segmentation evidence**

For "the network is probably misconfigured" claims specifically — proving or disproving that segments aren't properly connected needs comparison across vantage points, not just one more single-host test.

- `Test-AdPortMatrix.ps1` — reachability matrix for the fixed AD ports (DNS, Kerberos, RPC endpoint mapper, LDAP/LDAPS, SMB, kpasswd, Global Catalog, NTP, AD Web Services) against one or more targets. Pure TCP/UDP connect tests — no AD credentials or domain membership needed, so it runs from a jump box in any segment. Also best-effort checks the dynamic RPC port(s) used by replication: reads each DC's actual configured RPC port restriction via remote registry if one exists and tests exactly those ports, or spot-checks a clearly labelled, non-exhaustive sample of the default 49152–65535 range otherwise. Tag a run with `-SegmentName` and save it with `-OutFile` for comparison.
- `Test-AdSiteSubnetCoverage.ps1` — read-only AD Sites & Services audit: subnets with no site, sites with no subnet or no site link, site links left at the untouched defaults, and (`-CheckDns`) DNS A records whose IP falls outside every registered subnet. A client AD can't map to a subnet gets no site assignment and doesn't reliably pick the local DC — one of the most common AD-side causes behind a "the network must be misconfigured" complaint, fully visible from AD itself without touching any other segment.
- `Compare-SegmentProbes.ps1` — the actual proof step: diffs two or more `Test-AdPortMatrix.ps1` JSON results and reports every target/port combination that behaves differently depending on which segment the probe ran from. That asymmetry, not any single run, is the evidence a segmentation claim needs. `-HtmlReport` writes a self-contained, colour-coded report to hand the customer directly.

> These touch certificates, Kerberos and SMB on live DCs. Reading them can look like attacker enumeration to a SIEM — give the SOC/EDR team a heads-up, as with the main assessment.

## License

MIT — see [LICENSE](LICENSE).

## Author

[Alexander Zarenko IT Consulting (AZITC)](https://blog.zarenko.net) · Aachen, Germany
