---
type: Playbook
id: SEC-PG-20
title: PostgreSQL (Linux Focus)
frameworks:
  - "nist_csf_2: (PR.DS-01, PR.AC-01, PR.PT-01)"
  - "nis2: (Art. 21.2.a, Art. 21.2.c)"
  - "gdpr: (Art. 32.1.a, Art. 32.1.b)"
  - "cis_control: (v8 3.3, v8 4.1, v8 6.2)"
scope:
  - Database
  - RDBMS
  - PostgreSQL
  - Linux
priority: P1 - High
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

PostgreSQL is a robust and highly configurable database. This playbook ensures the instance is hardened against unauthorized access by enforcing modern authentication (SCRAM), encrypting transit traffic (SSL/TLS), and restricting the "Attack Surface" via granular Host-Based Authentication.

---

## 2. Implementation Steps

#### 2.1 Network & Connection Security
*   **Action:** Do not listen on all interfaces (`*`) if the database is local or accessed by a single app server.
    *   *postgresql.conf:* `listen_addresses = 'localhost, 192.168.x.x'`
*   **Action:** Change the default port (**5432**) to reduce automated "noise" scans.

#### 2.2 Host-Based Authentication (`pg_hba.conf`)
*   **Requirement:** Enforce the "Least Privilege" for network connections.
*   **Action:** Use `hostssl` instead of `host` to force encrypted connections.
*   **Action:** Replace `md5` or `trust` with `scram-sha-256`.
```conf
# TYPE  DATABASE        USER            ADDRESS                 METHOD
hostssl all             all             192.168.10.0/24         scram-sha-256
```

#### 2.3 Authentication Hardening
- **Action:** Enforce SCRAM-SHA-256 for all new passwords.
    - _postgresql.conf:_ `password_encryption = 'scram-sha-256'`
- **Action:** Rename or restrict the `postgres` superuser. Use dedicated roles for application access.

#### 2.4 Auditing & Logging (NIS2/GDPR Compliance)
- **Requirement:** Capture who accessed what data and when.
- **Action:** Enable `pgaudit` extension for granular session and object auditing.
- **Action:** Configure logging to capture failed connection attempts.
    - _postgresql.conf:_
        - `logging_collector = on`
        - `log_connections = on`
        - `log_disconnections = on`
        - `log_checkpoints = on`

#### 2.5 Encryption
PostgreSQL does not have built-in Transparent Data Encryption (TDE) like SQL Server Enterprise. For **GDPR Art. 32** compliance, you **must** rely on the **10.10 Data-at-Rest Encryption (LUKS)** playbook we created earlier to encrypt the underlying disk or partition where `/var/lib/postgresql` resides.

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify SCRAM-SHA-256 is active.**
    - `SHOW password_encryption;` (Should return `scram-sha-256`).
- [ ] **Audit 02: Check for 'trust' authentication in pg_hba.conf.**
    - `grep "trust" /etc/postgresql/XX/main/pg_hba.conf` (Should return nothing).
- [ ] **Audit 03: Verify SSL status.**
    - `SHOW ssl;` (Should be `on`).
- [ ] **Audit 04: Check file permissions on data directory.**
    - `stat -c "%a" /var/lib/postgresql/data` (Should be `700`).
- [ ] **Audit 05: Identify users with Superuser privileges.**
    - `SELECT usename FROM pg_user WHERE usesuper = 't';` (Minimize this list).

---

## 4. Wazuh Monitoring (PostgreSQL)

Wazuh monitors the PostgreSQL logs (usually in `/var/log/postgresql/`) to detect SQL Injection attempts or Brute Force.
**Critical Events to Track:**
- **FATAL: password authentication failed:** High frequency indicates Brute Force.
- **LOG: statement:** If `pgaudit` is active, Wazuh can track sensitive `DROP` or `ALTER` commands.
- **FATAL: no pg_hba.conf entry:** Indicates a connection attempt from an unauthorized IP.

```XML
<!-- Example Wazuh Rule for Postgres Brute Force -->
<rule id="105001" level="10">
  <if_sid>502</if_sid>
  <match>password authentication failed for user</match>
  <description>PostgreSQL: Multiple failed authentication attempts.</description>
  <group>pci_dss_10.2.4,gdpr_IV_32.2,</group>
</rule>
```