---
type: Playbook
id: SEC-LX-20
title: "OS Update & Repositories (Linux)"
frameworks:
- nist_csf_2: [PR.PS-02, PR.PS-05]
- nis2: [Art. 21.2.f (Vulnerability handling)]
- gdpr: [Art. 32]
- cis_control: [v8 7.1, v8 7.2, v8 7.4]
scope: [Vulnerability Management, Patching]
priority: P0 - Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

Unpatched software is the primary entry point for attackers. This playbook ensures that security updates are applied automatically (Unattended Upgrades) and that the supply chain (Repositories) is verified via GPG signatures.

---

## 2. Implementation Steps

#### 2.1 Automated Security Updates (Unattended Upgrades)
*   **Requirement:** Security patches must be applied within 24-48 hours of release.
*   **Action:** Install and configure `unattended-upgrades`.
    *   `apt install unattended-upgrades`
*   **Configuration:** Edit `/etc/apt/apt.conf.d/50unattended-upgrades`:
    *   Enable only `${distro_id}:${distro_codename}-security`.
    *   Enable `Unattended-Upgrade::Automatic-Reboot "false"` for critical servers (reboots must be scheduled).

#### 2.2 Repository Integrity (Supply Chain Security)
*   **Action:** Ensure all repositories use HTTPS.
*   **Action:** Only use official GPG-signed repositories.
*   **Proxmox Note:** Ensure the `pve-enterprise` or `pve-no-subscription` repository is correctly configured in `/etc/apt/sources.list.d/`.

#### 2.3 Vulnerability Scanning (Wazuh Integration)
*   **Requirement:** Maintain an inventory of all installed software and their CVE status.
*   **Action:** Enable the **Vulnerability Detector** module in the Wazuh Manager.
*   **Action:** The Wazuh Agent will inventory all installed packages (`dpkg -l`) and compare them against the OVAL/CVE databases.

#### 2.4 Kernel Management
*   **Action:** Remove old kernels to prevent "Rollback Attacks."
    *   `apt autoremove --purge`
*   **Reboot Policy:** After a kernel update, a reboot is required. Document the maintenance window (e.g., Sunday 03:00 AM).

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify `unattended-upgrades` is active.**
  - `systemctl status unattended-upgrades`
- [ ] **Audit 02: Check for pending security updates.**
  - `apt list --upgradable | grep -i security` (Should return nothing in a hardened state).
- [ ] **Audit 03: Verify GPG keys for all repos.**
  - `apt-key list` or `ls /etc/apt/trusted.gpg.d/`
- [ ] **Audit 04: Check for system reboot requirement.**
  - `cat /var/run/reboot-required` (If this file exists, the server needs a reboot).

---

## 4. Wazuh Integration

Wazuh provides a "Vulnerability" dashboard that acts as your **NIS2 Compliance Report**.

```yaml
# Wazuh Manager Configuration (ossec.conf)
<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>
  <provider name="debian">
    <enabled>yes</enabled>
    <os>bookworm</os>
    <update_interval>1h</update_interval>
  </provider>
</vulnerability-detector>
