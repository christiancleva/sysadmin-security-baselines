---
type: Playbook
id: SEC-WIN-00
title: "Partitioning & ReFS (SQL/FileServer)"
frameworks:
- nist_csf_2: [PR.DS-01, PR.DS-10, PR.PS-01]
- nis2: [Art. 21.2.c (Business continuity), Art. 21.2.e]
- gdpr: [Art. 32.1.c (Integrity)]
- cis_control: [v8 3.3, v8 11.3]
scope: [Windows Core, Storage, SQL, File Server]
priority: P1 - High
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook defines the Windows storage baseline. We leverage **ReFS** to provide built-in data integrity and performance optimizations for large-scale applications. Proper partitioning ensures that OS instability (e.g., a full C: drive) does not impact database availability or file storage.

---

## 2. Implementation Steps

#### 2.1 Disk Layout (Best Practices)
*   **System Drive (C:):** Minimum 100GB. Strictly for OS and Binaries.
*   **Data Drive (D:):** Dedicated for Applications/File Shares.
*   **Logs/DB Drive (L/E:):** Dedicated for SQL Transaction logs or high-IOPS data.
*   **Action:** Always use **GPT** (GUID Partition Table) instead of MBR for modern UEFI/Proxmox compatibility.

#### 2.2 ReFS Configuration (NIST PR.DS-01)
*   **Why ReFS:** Unlike NTFS, ReFS uses "Integrity Streams" to detect and automatically repair silent data corruption.
*   **Format Command (PowerShell):**
    ```powershell
    # Format for SQL Server / General File Server
    Format-Volume -DriveLetter D -FileSystem ReFS -AllocationUnitSize 64KB -SetIntegrityStreams $true
    ```
*   **Note on Block Size:** Use **64KB** for SQL Server and Veeam Repository drives to maximize performance and reduce fragmentation.

#### 2.3 Volume Isolation & Permissions
*   **Action:** Disable **8.3 Name Creation** on all volumes to improve performance and security.
*   **Action:** Ensure the `System` and `Administrators` groups have Full Control, but restrict `Users` from the root of non-OS drives.

**ReFS Warning:** ReFS is excellent for data, but **never** use it for the Boot (C:) drive. Windows still requires NTFS for the system partition.

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify GPT Partition Style.**
  - `Get-Disk | Select-Object Number, PartitionStyle` (Must be GPT).
- [ ] **Audit 02: Confirm ReFS Usage on Data Volumes.**
  - `Get-Volume | Select-Object DriveLetter, FileSystem, AllocationUnitSize`
- [ ] **Audit 03: Check Integrity Streams Status.**
  - `Get-FileIntegrity D:` (Should be Enabled).
- [ ] **Audit 04: Verify Separation of Roles.**
  - Check that SQL Data and SQL Logs are on physically/logically separate volumes.

---

## 4. Wazuh Monitoring (Windows Agent)

The Wazuh Windows Agent monitors disk space and NTFS/ReFS permissions via the `syscheck` and `logcollector` modules.

**Alerting on Disk Space (DoS Prevention):**
Wazuh will trigger a level 7 alert if any drive exceeds 90% capacity, fulfilling the **NIS2** requirement for availability.
```xml
<!-- Example Wazuh Rule for Disk Space -->
<rule id="102001" level="7">
  <if_sid>501</if_sid>
  <match>ossec: output: 'df -h':</match>
  <condition>capacity > 90%</condition>
  <description>Windows: Disk space is critically low on $(drive). Possible DoS risk.</description>
</rule>
```