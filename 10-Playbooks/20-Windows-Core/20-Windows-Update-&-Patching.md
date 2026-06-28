---
type: Playbook
id: SEC-WIN-20
title: "Windows Update & Patching"
frameworks:
- "nist csf 2 (PR.PS-02, PR.PS-05)"
- "nis2 (Art. 21.2.f (Vulnerability handling))"
- "gdpr (Art. 32)"
- "cis control (v8 7.1, v8 7.2, v8 7.4)"
scope: [Windows Core, Vulnerability Management]
priority: P0 - Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook ensures that Windows systems remain resilient against known exploits (CVEs). We define a mandatory patching cycle that automates the download and installation of security updates while maintaining system availability through scheduled reboots.

---

## 2. Implementation Steps

#### 2.1 Automatic Updates Configuration (GPO/Registry)
*   **Requirement:** Critical security updates must be installed within 72 hours of release.
*   **Action:** Configure "Configure Automatic Updates" to **Option 4 (Auto download and schedule the install)**.
    *   *Path:* Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage end user experience.
*   **Scheduled Install Day:** Every day (or specific maintenance window).
*   **Scheduled Install Time:** e.g., 03:00 AM.

**for Proxmox/Veeam Users:** Before a major "Patch Tuesday" (the second Tuesday of every month), use **Veeam** or **Proxmox Snapshots** to create a restore point. Windows updates are generally stable, but having a 1-click rollback is a core part of your **Disaster Recovery (DR)** plan.

#### 2.2 Patch Integrity & Quality
*   **Action:** Enable "Include drivers with Windows Updates" only if hardware is standardized. On Proxmox, it is often safer to manage VirtIO drivers manually to avoid compatibility issues.
*   **Action:** Enable "Receive updates for other Microsoft products" (to ensure SQL Server, Office, and .NET are patched).

#### 2.3 Managing Delivery Optimization (NIS2 Security)
*   **Requirement:** Prevent Windows from sharing patches with unknown peers on the internet (bandwidth and security risk).
*   **Action:** Set "Download Mode" to **Simple (99)** or **Bypass (100)** to ensure updates come directly from Microsoft or your local WSUS/Update Cache.

#### 2.4 Reboot Policy
*   **Requirement:** Patches are not effective until the system reboots.
*   **Action:** Configure "No auto-restart with logged on users for scheduled automatic updates installations" to **Disabled** for servers (to force the reboot) or **Enabled** for critical production VMs with manual reboot windows.

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify last update success time.**
  - *PowerShell:* `(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSuccessTime`
- [ ] **Audit 02: Check for pending reboots.**
  - *PowerShell:* `Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"`
- [ ] **Audit 03: Confirm "Automatic Updates" setting.**
  - `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions` (Should be `4`).
- [ ] **Audit 04: Check for missing critical patches.**
  - *PowerShell:* `Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10`

---

## 4. Wazuh Integration (Vulnerability Detector)

Wazuh is your primary tool for proving NIS2 compliance for Windows patching.

**Configuration:**
Ensure the Wazuh Manager has the Windows provider enabled in `ossec.conf`:
```xml
<vulnerability-detector>
  <provider name="msu">
    <enabled>yes</enabled>
    <update_interval>1h</update_interval>
  </provider>
</vulnerability-detector>
```