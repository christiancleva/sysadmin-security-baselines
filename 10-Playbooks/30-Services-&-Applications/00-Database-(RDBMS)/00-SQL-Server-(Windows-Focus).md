---
type: Playbook
id: SEC-SQL-00
title: "Microsoft SQL Server (Windows Focus)"
frameworks:
- nist_csf_2: [PR.DS-01, PR.AC-01, PR.DS-11, PR.PS-01]
- nis2: [Art. 21.2.a, Art. 21.2.c, Art. 21.2.g]
- gdpr: [Art. 32.1.a, Art. 32.1.b]
- cis_control: [v8 3.3, v8 4.1, v8 6.2]
scope: [Database, RDBMS, SQL Server, Windows]
priority: P0 - Mission Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook defines the security baseline for Microsoft SQL Server instances. Given its role in hosting ERP and sensitive business data, the focus is on **Surface Area Reduction**, **Encryption of Data at Rest/Transit**, and **Strict Identity Management**.

---

## 2. Implementation Steps

#### 2.1 Surface Area Reduction (CIS 1.1)
Disable unnecessary features that can be exploited for OS-level access:
*   **Action:** Disable `xp_cmdshell`. This is the most common vector for SQL-to-OS escalation.
    *   *SQL:* `EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;`
*   **Action:** Disable "Ad Hoc Distributed Queries" and "CLR Integration" unless explicitly required by the ERP.

#### 2.2 Authentication & Access Control (NIST PR.AC-01)
*   **Requirement:** Use **Windows Authentication Mode** exclusively where possible. Avoid "Mixed Mode".
*   **Action:** Disable or rename the `sa` account. Ensure it has a 30+ character random password if it cannot be disabled.
*   **Action:** Remove the `BUILTIN\Administrators` group from the SQL Server sysadmin role to ensure only designated DBAs have full control.

#### 2.3 Encryption (GDPR Art. 32)
*   **Transit:** Enforce **Force Encryption** in the SQL Server Configuration Manager.
    *   Requirement: A valid TLS certificate (Internal CA or trusted) must be installed.
*   **At Rest:** Implement **Transparent Data Encryption (TDE)** for databases containing Personal Identifiable Information (PII).
*   **Action:** Disable old protocols (TLS 1.0/1.1) via the Windows Registry (standard Windows Core hardening).

#### 2.4 Networking
*   **Action:** Change the default port from **1433** to a non-standard static port.
*   **Action:** Use the **Windows Firewall** (and Proxmox Firewall) to allow connections only from the Application Server/ERP IP.

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify `sa` account status.**
  - `SELECT name, is_disabled FROM sys.server_principals WHERE name = 'sa';` (Should be `1`).
- [ ] **Audit 02: Check `xp_cmdshell` status.**
  - `SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';` (Should be `0`).
- [ ] **Audit 03: Confirm Encryption in Transit.**
  - Check `sys.dm_exec_connections` to ensure `encrypt_option` is `TRUE` for active sessions.
- [ ] **Audit 04: Audit for 'Public' role permissions.**
  - Ensure the `public` server role has no permissions on user databases.
- [ ] **Audit 05: Check for latest Service Pack / Cumulative Update.**
  - `SELECT @@VERSION;` (Verify against the latest Microsoft security bulletin).

---

## 4. Wazuh Monitoring (SQL Server Integration)

The Wazuh Agent on Windows can read the SQL Server Error Log and Audit Logs.

**Critical Events to Track:**
*   **Failed Logins:** Multiple failures to the same account (Brute Force).
*   **Permission Changes:** Unauthorized granting of `sysadmin` role.
*   **Schema Changes:** `DROP TABLE` or `ALTER DATABASE` commands.

```xml
<!-- Example Wazuh Rule for SQL Failed Login -->
<rule id="104001" level="7">
  <if_sid>18100</if_sid> <!-- Windows login fail base -->
  <match>Login failed for user</match>
  <description>SQL Server: Failed login attempt. Monitor for brute force.</description>
</rule>
```