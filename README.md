# Invoke-ADAssessment

A **read-only** Active Directory Health, Security & Hygiene assessment for PowerShell 5.1. One script, one HTML report — no installation, no changes to your environment.

Built as a lightweight companion to tools like [Purple Knight](https://www.semperis.com/purple-knight/) and [ADxRay](https://github.com/ClaudioMerola/ADxRay): it collects the in-box health data (`dcdiag`, `repadmin`), runs a focused set of security & hygiene checks, and produces a prioritized findings report with a **Best-Practice compliance table** (actual vs. recommended, colour-coded, with sources).

> ⚠️ This is not a Microsoft product. It reads from AD; it never writes. Remediation is your job, done separately.

## Features

- **Health & operations:** FSMO roles, DC inventory, `dcdiag` / `repadmin` (read only), functional levels
- **Security & attack paths:** privileged group membership, Kerberoasting & AS-REP candidates, unconstrained delegation, DCSync rights on the domain NC, krbtgt password age
- **Hygiene:** inactive accounts, "password never expires", `PasswordNotRequired`, reversible encryption, GPP passwords in SYSVOL (MS14-025), LAPS deployment coverage
- **Hardening:** SMBv1, LDAP signing & channel binding, LmCompatibilityLevel (read from the PDC)
- **AD CS detection:** enterprise CA discovery (host, IP, subject DN) as a pointer to run [Locksmith](https://github.com/jakehildreth/Locksmith)
- **Soll/Ist compliance table:** actual vs. recommended for every measurable setting, colour-coded (green = better, black = meets, yellow = borderline, red = action needed), each row citing its source (CIS Benchmark, Microsoft, Defender for Identity)
- **Jump links:** every finding links to the list of affected objects
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

## License

MIT — see [LICENSE](LICENSE).

## Author

[Alexander Zarenko IT Consulting (AZITC)](https://blog.zarenko.net) · Aachen, Germany
