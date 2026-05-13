---
type: Playbook
id: SEC-WIN-90
title: "Logging & Wazuh Agent (Windows)"
frameworks:
- nist_csf_2: [DE.CM-01, DE.CM-03, PR.PT-01]
- nis2: [Art. 21.2.e, Art. 21.2.f]
- gdpr: [Art. 32]
- cis_control: [v8 8.1, v8 8.2, v8 8.3, v8 8.5]
scope: [Windows Core, Auditing, SIEM, SOC]
priority: P0 - Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook defines the auditing standard for Windows. We move beyond basic logging by implementing **Sysmon** and specialized **Event Channel** monitoring. This ensures that every administrative action, process start, and network connection is recorded and analyzed by the Wazuh SIEM.

---

## 2. Implementation Steps

#### 2.1 Advanced Audit Policy Configuration
Standard Windows logging is too sparse. Enable "Advanced Audit Policy Configuration" via GPO or `secpol.msc`:
*   **Logon/Logoff:** Audit Success/Failure for "Logon", "Logoff", and "Special Logon".
*   **Object Access:** Audit "File System" (for sensitive folders) and "Registry".
*   **Privilege Use:** Audit "Sensitive Privilege Use".
*   **Process Creation:** Enable "Include command line in process creation events" (Event ID 4688).

#### 2.2 Microsoft Sysmon Installation
*   **Requirement:** Sysmon provides deep visibility into process lineage and network connections.
*   **Action:** Install Sysmon with a modular configuration (e.g., SwiftOnSecurity or Olaf Hartong's config).
    *   `sysmon.exe -i sysmonconfig-export.xml`
*   **Benefit:** Captures **Event ID 1** (Process Creation), **Event ID 3** (Network Connect), and **Event ID 7** (Image Loaded).

#### 2.3 Wazuh Agent Deployment
*   **Action:** Deploy the `.msi` agent and point it to the Wazuh Manager.
*   **Action:** Configure the `ossec.conf` on the agent to ingest the following channels:
    *   `Application`, `System`, `Security`
    *   `Microsoft-Windows-Sysmon/Operational`
    *   `Microsoft-Windows-PowerShell/Operational` (Critical for detecting fileless malware).

#### 2.4 Event Log Size & Retention (CIS 8.2)
*   **Action:** Set the maximum size for the **Security** log to at least **4096 MB**.
*   **Action:** Set "When maximum event log size is reached" to **Overwrite events as needed**. (Wazuh should have already offloaded the logs to the manager).

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify Sysmon service is running.**
  - *PowerShell:* `Get-Service -Name "Sysmon*"`
- [ ] **Audit 02: Check Wazuh Agent connectivity.**
  - *PowerShell:* `& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m <Manager_IP>`
- [ ] **Audit 03: Verify PowerShell Script Block Logging.**
  - Check `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` (Should be `1`).
- [ ] **Audit 04: Verify command-line auditing.**
  - Check Event ID 4688 in the Security log; it must contain the `Process Command Line` field.

---

## 4. Wazuh Integration

The Windows agent provides the data for your **Compliance Dashboards**.

**Key Alerts to Monitor:**
*   **Rule 60106:** Windows Logon Success (Audit trail).
*   **Rule 92601:** Sysmon: Process created (Visibility into attacker tools).
*   **Rule 91802:** PowerShell: Script block logging (Detection of encoded commands).

```xml
<!-- Example Wazuh Agent ossec.conf for Sysmon -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```