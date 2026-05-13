---
type: Playbook
id: SEC-SQL-DOCKER
title: "SQL Server on Docker"
frameworks:
- nist_csf_2: [PR.DS-01, PR.PS-06]
- nis2: [Art. 21.2.a, Art. 21.2.f]
- gdpr: [Art. 32]
- cis_control: [v8 18.1, v8 3.3]
scope: [Database, Docker, MSSQL, Linux]
priority: P1 - High
status: Draft
last_review: 2026-05-10
---

## 1. Executive Summary

Running MSSQL in Docker provides high portability but requires strict container-level isolation. This playbook ensures the SQL instance is not running as root, uses encrypted persistent storage, and enforces TLS for all traffic, satisfying both database and container security standards.

If you need **SSO/Active Directory**: Keep SQL Server on a **Windows VM** (using Playbook 20.20). 
If you need **Speed/Microservices**: Use **SQL Server in Docker** with strong SQL-native users and TLS.

---

## 2. Implementation Steps

#### 2.1 Non-Root Execution (Critical)
*   **Action:** Ensure you use the official MSSQL 2022 (or later) images, which run as the non-root `mssql` user (UID 10001) by default.
*   **Constraint:** Never use `--privileged` or `--user root`.

#### 2.2 Secure Secret Management
*   **Action:** Do not hardcode the `SA_PASSWORD` in a `docker-compose.yml` file.
*   **Action:** Use **Docker Secrets** or an `.env` file that is excluded from Git/backups and has `600` permissions.
*   **Requirement:** `MSSQL_SA_PASSWORD` must be at least 30 characters.

#### 2.3 Persistent & Encrypted Data (GDPR Art. 32)
*   **Requirement:** Databases must survive container restarts and be encrypted at rest.
*   **Action:** Map the SQL data, logs, and secrets to a host directory located on a **LUKS-encrypted volume** (refer to Playbook 10.10).
    *   *Docker Compose:*
        ```yaml
        volumes:
          - /mnt/encrypted_data/mssql/data:/var/opt/mssql/data
          - /mnt/encrypted_data/mssql/log:/var/opt/mssql/log
        ```

#### 2.4 Network Isolation
- **Action:** Do not publish port `1433` to the host's public IP.
- **Action:** Use a dedicated Docker bridge network and only allow the Application Container to talk to the SQL Container.
- **TLS:** Force encryption by placing your certificates in a volume and updating the `mssql.conf` within the container.

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify Process User.**
    - `docker exec <container_id> id` (Must not be `uid=0(root)`).
- [ ] **Audit 02: Check Environment Variables.**
    - `docker inspect <container_id>` (Verify `SA_PASSWORD` is not visible in cleartext in the metadata).
- [ ] **Audit 03: Confirm Volume Location.**
    - `docker inspect -f '{{ .Mounts }}' <container_id>` (Ensure paths lead to an encrypted partition).
- [ ] **Audit 04: Verify `xp_cmdshell` is disabled.**
    - (Run SQL query via `sqlcmd` inside the container).
- [ ] **Audit 05: Check TLS Enforcement.**
    - `docker exec -it <id> /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -Q "SELECT force_encryption FROM sys.dm_exec_connections"`

---

## 4. Wazuh Monitoring

Wazuh must monitor the host's Docker socket and the mapped log files.
**Key Alerts:**
- **Rule 100010:** SQL Container unexpected restart (Persistence check).
- **Rule 100011:** Execution of `bash` inside the SQL container (`docker exec`).
- **Rule 100012:** Failed SQL login attempts inside the container logs.

```xml
<!-- Ingesting SQL logs from the host-mapped path -->
<localfile>
  <location>/mnt/encrypted_data/mssql/log/errorlog</location>
  <log_format>syslog</log_format>
</localfile>
```