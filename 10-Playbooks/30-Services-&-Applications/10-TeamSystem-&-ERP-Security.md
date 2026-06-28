---
type: Playbook
id: SEC-ERP-TS
title: "TeamSystem & ERP Security"
frameworks:
- "nist_csf_2: (PR.AC-01, PR.DS-01, PR.DS-10, PR.PS-01)"
- "nis2: (Art. 21.2.a, Art. 21.2.c, Art. 21.2.j (Hygiene/Training))"
- "gdpr: (Art. 32, Art. 33 (Breach Notification), Art. 35 (DPIA))"
- "cis_control: (v8 3.1, v8 4.1, v8 6.1, v8 14.1)"
scope: [Application, ERP, TeamSystem, Financial Data]
priority: P0 - Mission Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

The ERP is the "Crown Jewel" of the organization. A compromise here results in data exfiltration (GDPR violation) and total business standstill (NIS2 impact). This playbook ensures that the TeamSystem application environment is isolated, audited at the row level, and protected by strong identity measures.

---

## 2. Implementation Steps

#### 2.1 Identity & Session Management (NIST PR.AC-01)
*   **Action:** Enforce **Single Sign-On (SSO)** via the Samba/Windows AD DC.
*   **MFA:** Mandatory Multi-Factor Authentication for all users accessing the ERP, especially via VPN or Remote Desktop.
*   **Session Timeout:** Configure a 15-minute inactivity timeout for ERP client sessions.

#### 2.2 Application-Level Isolation
*   **Action:** Ensure the TeamSystem Application Server and SQL Database are in a **Protected VLAN**. 
*   **Firewall:** Only allow traffic from authorized Workstation IPs/Subnets to the ERP ports (typically 80/443 for web-based components or specific RPC ports).
*   **Service Account:** The TeamSystem service must run under a **Managed Service Account (gMSA)** or a dedicated AD user with "Log on as a service" rights and NO interactive login permissions.

#### 2.3 Data Protection (GDPR Art. 32)
*   **Encryption in Transit:** All client-to-server communication must use TLS 1.2+. Disable legacy SSL/TLS.
*   **Document Storage:** If TeamSystem stores attachments (PDFs, Invoices), ensure the storage path is on an encrypted volume (BitLocker/LUKS) and is NOT shared via insecure SMB.
*   **Masking:** Where possible, enable data masking for sensitive fields (IBAN, Tax IDs) for users who do not require them for their specific role.

* **Action:** Ensure your contract with TeamSystem (or the local partner) includes a "Security Addendum" specifying their patching response time for Zero-Day vulnerabilities and how they handle your data during remote support sessions.

#### 2.4 Integrity & Audit (NIS2 Art. 21)
*   **SQL Audit:** Enable SQL Server Audit specifically for TeamSystem tables containing sensitive financial or personal data.
*   **Log Centralization:** Forward TeamSystem application logs (found in `C:\ProgramData\TeamSystem\...` or Event Viewer) to Wazuh.

---

## 3. ERP Audit Checklist

- [ ] **Audit 01: Verify Least Privilege for the ERP Service Account.**
  - Check that the account is NOT a "Domain Admin".
- [ ] **Audit 02: Confirm encrypted communication.**
  - Use `Wireshark` or `Test-Check` to ensure no plaintext passwords travel on the wire.
- [ ] **Audit 03: Check for "Ghost" Users.**
  - Review the TeamSystem user list against active AD accounts; disable ERP access for anyone who has left the company.
- [ ] **Audit 04: Verify Backup Consistency.**
  - Perform a test restore of the TeamSystem DB using the **Veeam Playbook**.
- [ ] **Audit 05: Check for cleartext credentials in config files.**
  - Scan `web.config` or `.ini` files for hardcoded SQL passwords.

---

## 4. Wazuh Monitoring (ERP Intelligence)

Wazuh should be used to detect "Anomalous Behavior" rather than just system errors.

**Critical Use Cases:**
*   **Off-Hours Access:** Alert if a user logs into TeamSystem at 3:00 AM on a Sunday.
*   **Mass Data Export:** Monitor for SQL queries that access an unusually high number of rows in the `Invoices` or `Customers` tables.
*   **Unauthorized Configuration Changes:** Monitor changes to the TeamSystem installation directory.

```xml
<!-- Example Wazuh Rule for ERP File Integrity -->
<rule id="107001" level="10">
  <if_sid>550</if_sid>
  <match>C:\Program Files\TeamSystem</match>
  <description>ERP: Critical application file modified. Potential unauthorized update or tampering!</description>
  <group>pci_dss_11.5,gdpr_IV_35.7.d,nis2_art21</group>
</rule>
```