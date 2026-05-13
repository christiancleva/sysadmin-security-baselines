---
type: Playbook
id: SEC-PVE-01
title: "Proxmox VE"
frameworks:
- nist_csf_2: [PR.PS-01, PR.AC-03, PR.DS-01]
- nis2: [Art. 21.2.a, Art. 21.2.c, Art. 21.2.g]
- gdpr: [Art. 32]
- cis_control: [v8 3.3, v8 4.1, v8 5.1]
scope: [Hypervisor, Virtualization]
priority: P0 - Mission Critical
status: Draft
last_review: 2026-05-09
auditable: true
Dependencies: [[10 Proxmox Backup Server (PBS)]]
---

## 1. Executive Summary

Proxmox VE (PVE) is the core of the infrastructure. Hardening the hypervisor is critical to prevent "Hyperjacking" and lateral movement between VMs. This playbook focuses on isolating the management interface and securing the Debian-based host.

---

## 2. Implementation Steps

#### 2.1 Management Interface Isolation (Network)
*   **Requirement:** Do not expose Port 8006 to the public internet or general LAN.
*   **Action:** Assign the Management IP to a dedicated **Management VLAN**.
*   **Firewall:** Enable the Proxmox Cluster Firewall.
    *   *Datacenter > Firewall > Options > Enable: Yes*

#### 2.2 Host OS Hardening (SSH & Shell)
*   **SSH:** Disable password-based root login. Use SSH Keys only.
    *   Edit `/etc/ssh/sshd_config`: `PermitRootLogin prohibit-password`
*   **Banner:** Add a legal warning banner to `/etc/issue.net`.

#### 2.3 Proxmox Web GUI Security
*   **MFA:** Enforce TOTP or WebAuthn for all 'root' and 'admin' accounts.
    *   *Datacenter > Permissions > Two Factor Authentication*
*   **TLS:** Replace the self-signed certificate with a valid Let's Encrypt or Internal CA certificate.

#### 2.4 Kernel & Hardware
*   **IOMMU:** Ensure IOMMU is enabled for hardware-level isolation of PCI-passthrough devices.
*   **Microcode:** Ensure `intel-microcode` or `amd64-microcode` is installed and updated to mitigate CPU vulnerabilities (Spectre/Meltdown).

---

## 3. CIS-Based Audit Checklist (Manual/Wazuh)

- [ ] **Audit 01: Verify No-Subscription Nag is not bypassed with insecure scripts.**
  - `grep "Proxmox.Utils.checked_command" /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js`
- [ ] **Audit 02: Check for active MFA on the root account.**
  - Check `/etc/pve/user.cfg` for TFA entries.
- [ ] **Audit 03: Ensure the PVE Firewall is active at the host level.**
  - `pve-firewall status`
- [ ] **Audit 04: Verify SSH configuration.**
  - `sshd -T | grep -E "permitrootlogin|passwordauthentication"`

---

## 4. Advanced Hypervisor Audit

- [ ] **Audit 05: Check Corosync Redundancy**
  - Command: `corosync-cfgtool -s` (Should show multiple active links)
- [ ] **Audit 06: Verify Guest CPU Type**
  - Check: Ensure VMs use `host` CPU type for maximum security features (AES-NI, Spectre mitigations) UNLESS live-migration between different CPUs is required.
- [ ] **Audit 07: Proxmox Metric Server**
  - Ensure Proxmox is sending metrics to an external InfluxDB or Graphite for long-term "Behavioral Analysis" (SOC requirement).
- [ ] **Audit 08: Entropy/Randomness**
  - Install `virtio-rng` on all VMs to ensure they have enough entropy for high-quality cryptographic operations (SSL/SSH).
  - 
---

## 5. Wazuh SCA Integration

```yaml
# Add to /var/ossec/etc/shared/proxmox_policy.yml
checks:
  - id: 20001
    title: "Ensure PVE Firewall is running"
    condition: all
    rules:
      - 'p:pve-firewall status -> r:status: active'