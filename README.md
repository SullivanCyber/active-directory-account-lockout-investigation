# Active Directory Account Lockout Investigation

**Hands-on SOC Analyst Lab | Windows Security Event Analysis | Active Directory | Kerberos**

## Overview

This project documents an **authorized account-lockout simulation** in an isolated Windows Active Directory lab. I configured a domain account lockout policy, deliberately triggered a lockout against a dedicated test account, investigated the resulting Windows Security logs, and verified that the account could sign in after recovery.

The objective was to practice evidence-driven SOC investigation: establish a timeline, correlate identity and host information, validate authentication outcomes, and distinguish confirmed observations from assumptions.

> **Scope:** Training simulation only. The activity does not establish a real attack or account compromise.

## Lab environment

| Component | Configuration |
| --- | --- |
| Virtualization | Oracle VirtualBox; isolated internal network `CyberLab` |
| Domain controller | `DC01` — Windows Server 2022, AD DS, DNS; `10.0.0.10` |
| Workstation | `PC01` — Windows 11 Pro, domain joined; `10.0.0.20` |
| Domain | `cyberlab.local` (`CYBERLAB`) |
| Test account | `CYBERLAB\LockoutTest_` (Employees OU) |
| Investigation tools | Event Viewer, Group Policy Management, PowerShell, Active Directory module |

## Investigation workflow

1. Configured the domain account lockout threshold to **5 invalid logon attempts**, with a **15-minute lockout duration** and **15-minute reset counter window**.
2. Used a dedicated standard-user test identity to simulate failed logons on PC01.
3. Observed Windows **Event ID 4740** on DC01 identifying `LockoutTest_` and caller computer `PC01`.
4. Queried the account using PowerShell and later verified `LockedOut: False`.
5. Successfully signed in to PC01 with the recovered test account.
6. Investigated **Event ID 4768** on DC01 and examined the Kerberos result, encryption, and client address.
7. Compared the event timestamp with the account's `LastLogonDate` while documenting attribution limits.

## Key evidence

| Observation | Evidence | Interpretation |
| --- | --- | --- |
| Account lockout | DC01 Event **4740**, Oct. 23, 2026, **12:58:22 PM** | Domain controller recorded the simulated lockout; caller computer `PC01` |
| Recovery | `Get-ADUser` returned `LockedOut: False` | Account was not locked at the time of the check |
| Workstation access | Interactive sign-in to PC01 succeeded | Account could be used after recovery |
| Kerberos request | DC01 Event **4768**, **3:02:23 PM**, for `LockoutTest_` | TGT request observed; **Result Code `0x0`** indicates success |
| Kerberos source | Event 4768 **Client Address `::1`** | IPv6 loopback on DC01; **does not prove** the request originated on PC01 |
| AD last logon | `LastLogonDate`: **3:02:23 PM** | Consistent timestamp, but not reliable proof of the originating workstation |

**Analyst conclusion:** The domain lockout control operated as expected in this simulation, and the test account recovered and was usable afterward. The available evidence does **not** conclusively link the particular 4768 event with `::1` to the PC01 sign-in. A workstation-side Event 4624, collected with appropriate administrator permissions, would strengthen that correlation.

## PowerShell checks

Run these commands from an authorized administrative session on the domain controller:

```powershell
# Inspect the effective default domain password and lockout policy
Get-ADDefaultDomainPasswordPolicy |
    Select-Object LockoutThreshold,LockoutDuration,LockoutObservationWindow

# Check the test account's lockout status
Get-ADUser 'LockoutTest_' -Properties LockedOut |
    Select-Object Name,LockedOut

# Review the approximate AD last-logon timestamp
Get-ADUser 'LockoutTest_' -Properties LastLogonDate |
    Select-Object Name,LastLogonDate
```

## Screenshots and evidence

Add screenshots captured during the lab to the `screenshots/` directory. Suggested filenames:

- `01-account-lockout-policy.png` — configured Group Policy settings
- `02-account-locked-out.png` — PC01 lockout message
- `03-event-4740.png` — DC01 lockout event and caller computer
- `04-account-recovered.png` — PowerShell showing `LockedOut: False`
- `05-event-4768.png` — Kerberos request, result code, and client address
- `06-last-logon-date.png` — AD last-logon query

Before publishing, review screenshots for passwords, tokens, personal information, and unrelated account details. Do not upload secrets or VM disk images.

## Lessons learned

- Account lockout policies reduce repeated password-guessing opportunities but may also be abused to disrupt user access.
- **4740** records account lockout; **4768** records Kerberos TGT requests; **4624** is a successful logon event on the system that accepted the logon.
- A successful Kerberos request is not automatically proof of a successful interactive workstation sign-in.
- The source address `::1` identifies local loopback, not the IP address of PC01.
- Standard users may be denied access to Windows Security logs; investigation should use authorized elevated access rather than expanding standard-user privileges.
- SOC reporting should clearly separate evidence, interpretation, and outstanding questions.

## Full report

See [SOC Investigation Report](SOC-Investigation-Report.md) for the detailed timeline, evidence analysis, and recommendations.

## Skills demonstrated

**Active Directory administration · Group Policy · Windows Event Viewer · Security event triage · Kerberos authentication analysis · PowerShell · Incident documentation · Least privilege**

---

*This project was performed in a controlled lab for cybersecurity education and portfolio development.*
