---
type: Playbook
id: SEC-AD-01
title: "Active Directory Domain Services"
frameworks:
- nist_csf_2: [PR.AC-01, PR.AC-03, PR.AC-05, PR.IR-02]
- nis2: [Art. 21.2.a (Access control), Art. 21.2.g]
- gdpr: [Art. 32 (Confidentiality/Integrity)]
- cis_control: [v8 5.1, v8 6.1, v8 13.1]
scope: [Identity, Windows Server, AD DS, Kerberos]
priority: P0 - Mission Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook defines the security architecture for the Windows Identity core. We implement the **Tiered Administration Model** to isolate Domain Controllers from administrative workstations and enforce modern Kerberos security to mitigate "Golden Ticket" and "Pass-the-Hash" attacks.

---

## 2. Implementation Steps

#### 2.1 The Tiered Administrative Model (NIST PR.AC-05)
To comply with NIS2 requirements for lateral movement prevention, restrict administrative logins:
*   **Tier 0 (Domain Controllers):** Only Domain Admins. They must use "Privileged Admin Workstations" (PAWs). They **never** log in to workstations or servers.
*   **Tier 1 (Member Servers):** Server Admins. They can manage ERP/SQL servers but cannot log in to Tier 0 or Tier 2.
*   **Tier 2 (Workstations):** Local Admins. They manage desktops but have no rights over Tiers 0 or 1.

#### 2.2 Kerberos & Authentication Security
*   **Action:** Enforce **AES-256-CTS-HMAC-SHA1-96** for Kerberos encryption. Disable DES and RC4.
*   **Action:** Rotate the **krbtgt** account password twice a year (requires a script to ensure the two-password history doesn't break authentication).
*   **Action:** Enable **Protected Users** security group for highly privileged accounts (prevents caching of credentials on workstations).

#### 2.3 GPO Hardening (The "Security Baseline")
Apply the **Microsoft Security Compliance Toolkit** baselines via GPO:
*   **Action:** Disable "LLMNR" and "NetBIOS" over TCP/IP to prevent spoofing.
*   **Action:** Enforce **SMB Signing** (Required) and **LDAP Signing/Sealing**.
*   **Action:** Configure "Restricted Groups" to ensure only authorized users stay in `Domain Admins`.

#### 2.4 Active Directory Recycle Bin
*   **Action:** Enable the AD Recycle Bin.
    *   *PowerShell:* `Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <domain>`
*   **Benefit:** Critical for **NIS2 Resilience** (Art. 21.2.c) to recover accidentally deleted identity objects without a full forest restore.

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Check for "Privileged Accounts" with no MFA/Smartcard requirement.**
  - `Get-ADUser -Filter 'SmartcardLogonRequired -eq $false' -Properties MemberOf`
- [ ] **Audit 02: Verify Domain Functional Level.**
  - `Get-ADDomain | Select-Object DomainMode` (Should be at least `Windows2016`).
- [ ] **Audit 03: Identify "Non-expiring passwords" on admin accounts.**
  - `Get-ADUser -Filter 'PasswordNeverExpires -eq $true' | Where-Object {$_.MemberOf -like "*Admins*"}`
- [ ] **Audit 04: Check for SMBv1 across the domain.**
  - Use Wazuh or a scanning tool to ensure no legacy SMBv1 is responding.
- [ ] **Audit 05: Verify krbtgt password last set date.**
  - `Get-ADUser -Filter {Name -eq "krbtgt"} -Properties PasswordLastSet` (Should be < 180 days).

---

## 4. Wazuh Monitoring (AD Security Events)

Monitoring the Domain Controller logs is the primary task of your SOC.

**Critical Events to Track:**
*   **4728/4732:** A member was added to a security-enabled global/local group (e.g., Domain Admins).
*   **4740:** Account lockout (Brute force indicator).
*   **4624 (Logon Type 10/3):** Remote logons to Domain Controllers (Check for Tiered Model violations).
*   **4769:** A Kerberos service ticket was requested (Check for "Kerberoasting" patterns).

```xml
<!-- Example Wazuh Rule for Sensitive Group Addition -->
<rule id="106001" level="12">
  <if_sid>60110</if_sid>
  <field name="win.system.eventID">^4728$|^4732$</field>
  <match>Domain Admins|Enterprise Admins|Schema Admins</match>
  <description>AD: A user was added to a SENSITIVE group. Verify immediately!</description>
  <group>pci_dss_10.2.5,gdpr_IV_32.2,</group>
</rule>
```