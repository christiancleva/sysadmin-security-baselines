---
type: Playbook
id: SEC-LX-90
title: "Logging & Wazuh Agent (Observability)"
frameworks:
- nist_csf_2: [DE.CM-01, DE.CM-03, PR.PT-01]
- nis2: [Art. 21.2.e, Art. 21.2.f]
- gdpr: [Art. 32 (Integrity/Availability)]
- cis_control: [v8 8.1, v8 8.2, v8 8.5, v8 8.11]
scope: [Auditing, Monitoring, SIEM, Linux Core]
priority: P0 - Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

Hardening is useless without monitoring. This playbook ensures that every system event (logins, file changes, process execution) is recorded locally and shipped to a centralized **Wazuh Manager** for analysis. This fulfills the **NIS2** requirement for incident detection and the **GDPR** requirement for data integrity.

---

## 2. Implementation Steps

### 2.1 Syslog & Log Rotation (CIS 8.2)
*   **Action:** Ensure `rsyslog` is installed and active.
*   **Retention:** Modify `/etc/logrotate.conf` to keep logs for at least 90 days (local) to meet compliance baselines.
*   **Integrity:** Logs should be owned by `root:adm` with permissions `640`.

### 2.2 Wazuh Agent Installation
*   **Action:** Install the agent using the official Wazuh repository.
*   **Action:** Point the agent to your Wazuh Manager IP.
    *   `WAZUH_MANAGER="192.168.x.x" apt install wazuh-agent`
*   **Enrollment:** Use a password/key for agent enrollment to prevent rogue agents from joining.

### 2.3 File Integrity Monitoring (FIM)
Configure the agent to watch for changes in critical system files.
*   **Path:** `/var/ossec/etc/ossec.conf`
*   **Action:** Enable `syscheck` for:
    *   `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`
    *   Set `check_all="yes"` and `realtime="yes"`.

### 2.4 Active Response & Rootcheck
*   **Action:** Enable `rootcheck` to scan for known rootkits and malware daily.
*   **Action:** (Optional) Enable `active-response` to automatically drop connections from IPs that fail SSH login 5+ times.

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify Wazuh Agent status.**
  - `systemctl status wazuh-agent` (Should be `active (running)`).
- [ ] **Audit 02: Check Agent Connection to Manager.**
  - `/var/ossec/bin/agent_control -i 000` (On the manager) or check the Wazuh Dashboard.
- [ ] **Audit 03: Verify Log Rotation configuration.**
  - `grep -r "rotate" /etc/logrotate.d/` (Ensure security logs are not deleted too quickly).
- [ ] **Audit 04: Check FIM logs.**
  - Change a file in `/etc/test_file` and check if an alert appears in Wazuh within 60 seconds.

---

## 4. Wazuh Integration

The agent is the primary source of truth for your **Wazuh Dashboard**.

**Critical Monitoring Paths:**
*   `/var/log/auth.log` (Logins/Sudo)
*   `/var/log/syslog` (System events)
*   `/var/log/dpkg.log` (Software changes)

```xml
<!-- Example ossec.conf snippet for FIM -->
<syscheck>
  <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
</syscheck>xml
```
