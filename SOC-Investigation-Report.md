# SOC Investigation Report: Active Directory Account Lockout and Recovery

**Environment:** CYBERLAB (isolated VirtualBox training environment)  
**Investigation date:** October 23, 2026  
**Classification:** Authorized laboratory simulation  
**Case status:** Lab test completed; attribution of the post-recovery Kerberos event to PC01 not independently established  
**Analyst:** Cybersecurity Lab Analyst

## 1. Executive Summary

An account lockout was deliberately triggered against the dedicated test account `CYBERLAB\LockoutTest_` in an isolated Active Directory lab. The objective was to validate domain account lockout controls, investigate relevant Windows Security events, confirm account recovery, and practice evidence-based SOC triage.

The domain controller `DC01.cyberlab.local` recorded Windows Security **Event ID 4740** at **12:58:22 PM on October 23, 2026**, identifying `LockoutTest_` as the locked-out account and `PC01` as the caller computer. A subsequent Active Directory query showed `LockedOut: False`, and an interactive sign-in on PC01 using the correct credentials succeeded. A domain controller **Event ID 4768** for `LockoutTest_` was observed at **3:02:23 PM**, and the account's `LastLogonDate` displayed the same timestamp. The Kerberos event showed **Result Code `0x0`** (successful ticket request), but its **Client Address was `::1`**, the IPv6 loopback address. Accordingly, that particular event cannot be definitively attributed to PC01.

**Outcome:** The lab demonstrated account lockout enforcement, investigation of an account lockout event, recovery, and successful subsequent workstation access. No evidence in this exercise establishes an actual malicious intrusion.

## 2. Scope and Lab Architecture

| Component | Configuration / role |
| --- | --- |
| Hypervisor | Oracle VirtualBox |
| Virtual network | Internal Network: `CyberLab` |
| Domain controller | `DC01`, Windows Server 2022, Active Directory Domain Services and DNS |
| Domain | `cyberlab.local` (`CYBERLAB`) |
| DC01 IP | `10.0.0.10` |
| Domain-joined workstation | `PC01`, Windows 11 Pro |
| PC01 IP | `10.0.0.20` |
| Test identity | `CYBERLAB\LockoutTest_` (display name: Lockout Test) |
| Test account OU | `OU=Employees,DC=cyberlab,DC=local` |

All authentication tests were performed within the user's authorized laboratory environment.

## 3. Objectives

1. Validate Active Directory's account lockout policy under repeated incorrect-password attempts.
2. Identify the locked-out identity and the caller computer from domain controller logs.
3. Verify account recovery without granting unnecessary privileges.
4. Examine subsequent authentication evidence and distinguish correlation from proof.
5. Record findings suitable for a junior SOC analyst portfolio.

## 4. Security Control Configuration

The domain's default password policy was inspected using `Get-ADDefaultDomainPasswordPolicy` and Group Policy Management Editor. The observed effective values were:

| Policy setting | Observed value |
| --- | --- |
| Account lockout threshold | 5 invalid logon attempts |
| Account lockout duration | 15 minutes |
| Reset account lockout counter after | 15 minutes |

Other password policy values shown in the lab included password complexity enabled, minimum password length 7, and password history count 24. These were observations, not an endorsement of their suitability for production. Production settings should follow current organizational standards and risk assessments.

## 5. Evidence and Timeline

| Date / time (lab local) | Source | Observation | Evidentiary interpretation |
| --- | --- | --- | --- |
| Oct 23, 2026, 12:58:22 PM | DC01 Security log, Event 4740 | `LockoutTest_` locked out; Caller Computer Name `PC01` | Confirms lockout event and reported caller workstation |
| Later on Oct 23 | DC01 PowerShell | `Get-ADUser 'LockoutTest_' -Properties LockedOut` showed `LockedOut: False` | Account was no longer locked at query time; exact unlock time not established |
| Later on Oct 23 | PC01 interactive sign-in | Correct credentials allowed successful desktop access | Confirms successful workstation sign-in after recovery; PC01 Event 4624 not collected |
| Oct 23, 2026, 3:02:23 PM | DC01 Security log, Event 4768 | Account `LockoutTest_`; Kerberos TGT request; Result Code `0x0`; Client Address `::1` | Confirms successful Kerberos ticket request; does not establish PC01 as source |
| Query performed later | DC01 PowerShell | `LastLogonDate` displayed Oct 23, 2026, 3:02:23 PM | Supports a recent account logon; this replicated/derived attribute is not a precise forensic record of source workstation |

**Additional observation:** Another Event 4768 viewed at approximately **2:57:05 PM** showed Client Address `::1`. Its account identity was not established by the provided screenshot, so it is not relied upon to attribute the PC01 login.

## 6. Technical Analysis

### 6.1 Account lockout: Event ID 4740

Event 4740 is generated when an account is locked out. The DC01 event identified:

- **Target account:** `CYBERLAB\LockoutTest_`
- **Caller Computer Name:** `PC01`
- **Recorded on:** `DC01.cyberlab.local`
- **Time:** October 23, 2026, 12:58:22 PM

This is direct evidence that the domain controller recorded an account lockout and associated it with the workstation named PC01. The simulated incorrect-password attempts explain the expected cause in this controlled test; the exact number and sequence of failure events were not separately captured for this specific test account in the supplied evidence.

### 6.2 Account recovery and access

An administrator queried the account with:

```powershell
Get-ADUser 'LockoutTest_' -Properties LockedOut
```

The result showed `Enabled: True` and `LockedOut: False`. The test user subsequently signed into PC01 with correct credentials. Together these observations demonstrate that the account was available for authentication after the lockout period.

While signed in as the standard user, an attempt to inspect PC01's Security event log returned **Access is denied**. This is consistent with Windows access controls protecting sensitive audit logs. The lab appropriately did not elevate the standard user merely to view those records.

### 6.3 Kerberos activity: Event ID 4768

A DC01 Security event for `LockoutTest_` showed:

| Field | Observed value | Interpretation |
| --- | --- | --- |
| Event ID | `4768` | Kerberos authentication ticket (TGT) requested |
| Result Code | `0x0` | Successful Kerberos ticket request |
| Client Address | `::1` | IPv6 loopback (local to the system logging the event) |
| Ticket Encryption Type | `0x12` | AES256-CTS-HMAC-SHA1-96 |
| Session Encryption Type | `0x12` | AES256-CTS-HMAC-SHA1-96 |
| Pre-Authentication Type | `2` | Encrypted timestamp pre-authentication |
| Logged | Oct 23, 2026, 3:02:23 PM | Same displayed time as `LastLogonDate` |

The event's successful result establishes that a Kerberos ticket request succeeded. **It does not by itself prove that the ticket request came from PC01**, because the recorded client address was `::1`, not the workstation's known IPv4 address `10.0.0.20`. A source-specific correlation would require additional evidence, such as PC01's own Event 4624 record or another matching domain authentication event with an attributable client address.

### 6.4 Active Directory last logon information

The following query was used:

```powershell
Get-ADUser 'LockoutTest_' -Properties LastLogonDate |
    Select-Object Name, LastLogonDate
```

The displayed `LastLogonDate` was **10/23/2026 3:02:23 PM**. `LastLogonDate` is based on Active Directory's `lastLogonTimestamp` and may be updated or replicated with delay; it should not be treated as a precise event-by-event audit trail or proof of a particular source computer.

## 7. Findings and Assessment

**Finding 1 — Account lockout control functioned in the test.** A configured five-attempt threshold and 15-minute lockout policy were observed, and the test account generated an Event 4740 lockout record.

**Finding 2 — Caller computer identified.** Event 4740 listed `PC01` as the caller computer, providing a starting point for authentication troubleshooting.

**Finding 3 — Recovery was successful.** The account was later observed as unlocked and a correct-password sign-in to PC01 succeeded.

**Finding 4 — Kerberos authentication activity was recorded.** Event 4768 showed a successful TGT request for `LockoutTest_` with AES256 encryption.

**Finding 5 — Source attribution remained limited.** The reviewed Kerberos event's `::1` client address does not verify that PC01 originated that request. The successful PC01 sign-in was observed directly, but its local Event 4624 was not retrieved due to standard-user log access restrictions.

**Incident classification:** Authorized security-control validation / authentication troubleshooting exercise. No actual compromise established.

## 8. Recommendations

1. **Maintain least privilege.** Do not add standard users to administrator or event-log reader groups solely to simplify an investigation; use an approved administrator or centralized collection method.
2. **Centralize authentication logs.** Forward relevant events from both domain controllers and endpoints to a SIEM or Windows Event Forwarding collector to correlate Event IDs 4625, 4740, 4768, 4771, 4776, and 4624 as appropriate.
3. **Alert on repeated lockouts.** Investigate patterns involving multiple accounts, recurring lockouts, unusual caller systems, or unexpected times; distinguish mistyped passwords and stale credentials from password-spraying indicators.
4. **Retain relevant event details.** Record timestamps, target account, caller computer, source address, result codes, and event record IDs before drawing conclusions.
5. **Use production-appropriate policy.** Evaluate account lockout and password requirements against current organizational guidance, including the risk of account-lockout denial-of-service.
6. **Preserve reproducibility.** Store sanitized screenshots of policy configuration, Event 4740, account status, Event 4768, and the final PowerShell output alongside this report.

## 9. Lessons Learned / Skills Demonstrated

- Windows Security event triage and authentication log interpretation
- Active Directory account administration and PowerShell queries
- Group Policy account lockout configuration and validation
- Kerberos authentication fundamentals and encryption metadata
- Evidence-based reporting, source attribution, and investigative limitations
- Least-privilege handling of protected Security logs

## 10. Suggested Portfolio Evidence

Add appropriately cropped or redacted screenshots to a repository `screenshots/` folder:

- `01-lockout-policy.png` — threshold and duration settings
- `02-event-4740.png` — locked-out account and caller computer
- `03-account-unlocked.png` — `LockedOut: False`
- `04-event-4768-account.png` — test account and timestamp
- `05-event-4768-details.png` — Result Code `0x0`, encryption type, and Client Address `::1`
- `06-last-logon-date.png` — AD PowerShell result

**Sanitization note:** Do not publish real credentials, authentication secrets, or unrelated personal identifiers. Lab-only hostnames and private IPs can be included if desired.

## 11. Conclusion

The CYBERLAB account lockout exercise successfully demonstrated domain lockout enforcement, investigation using Event 4740, verification of account recovery, and analysis of a successful Kerberos ticket request. The test account was able to sign into PC01 after recovery. The investigation deliberately preserves a key evidentiary limitation: the reviewed Event 4768's loopback client address does not independently identify PC01 as its origin. This distinction reflects the evidence discipline expected in a SOC investigation.
