---
type: Playbook
id: SEC-LX-50
title: "Fail2Ban & Firewall (Active Defense)"
frameworks:
- nist_csf_2: [PR.NW-01, PR.NW-02, DE.AE-01]
- nis2: [Art. 21.2.a, Art. 21.2.e]
- gdpr: [Art. 32 (Technical measures)]
- cis_control: [v8 1.1, v8 4.4, v8 12.8]
scope: [Network Security, Linux Core, IDS/IPS]
priority: P1 - High
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook implements a "Default Deny" firewall policy and an automated Intrusion Prevention System (IPS). We use **UFW** (Uncomplicated Firewall) for simplified management of `nftables` and **Fail2Ban** to dynamically block malicious IPs based on log patterns.

In **Proxmox** infrastructure, you have two firewalls: the **Proxmox Datacenter Firewall** (External) and the **Linux UFW** (Internal).
**Defense in Depth:** Use the Proxmox GUI Firewall for macro-segmentation (VLANs/Subnets) and UFW inside the VM for micro-segmentation (limiting specific local ports). This ensures that even if the Hypervisor firewall is misconfigured, the OS remains protected.

---

## 2. Implementation Steps

#### 2.1 Firewall: Default Deny Policy (CIS 12.8)
*   **Action:** Install UFW and set the baseline to block all incoming traffic.
    *   `apt install ufw`
    *   `ufw default deny incoming`
    *   `ufw default allow outgoing`
*   **Action:** Allow only essential services (SSH, Wazuh Agent).
    *   `ufw allow from <Management_Subnet> to any port 22 proto tcp`
    *   `ufw allow out 1514/udp` (Wazuh Agent communication)
*   **Action:** Enable the firewall.
    *   `ufw enable`

#### 2.2 Fail2Ban: Automated Brute-Force Blocking
*   **Action:** Install and configure Fail2Ban.
    *   `apt install fail2ban`
*   **Action:** Create a local configuration (`/etc/fail2ban/jail.local`).
    *   **Bantime:** `1h` (Initial ban)
    *   **Findtime:** `10m`
    *   **Maxretry:** `5`
*   **Action:** Enable the SSH jail.
```ini
[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
```

#### 2.3 Hardening Network Stack (Sysctl)
- **Action:** Disable IP Forwarding (unless the server is a gateway).
    - `sysctl -w net.ipv4.ip_forward=0`
- **Action:** Prevent ICMP Redirects (MITM protection).
    - `sysctl -w net.ipv4.conf.all.accept_redirects=0`

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify Firewall is active.**
    - `ufw status numbered` (Should show `Status: active` and a list of restricted rules).
- [ ] **Audit 02: Check Fail2Ban active jails.**
    - `fail2ban-client status` (Should show `sshd` jail is active).
- [ ] **Audit 03: Verify Default Deny.**
    - Attempt to `nmap` the server from an unauthorized IP; all ports should show `filtered`.
- [ ] **Audit 04: Check for current bans.**
    - `fail2ban-client status sshd` (Check the `Currently banned` list).

---

## 4. Wazuh Integration & SIEM Alerts

Wazuh should ingest Fail2Ban logs to identify persistent attackers across the entire infrastructure.

**Fail2Ban Log Path:** `/var/log/fail2ban.log`

**Wazuh Active Response:** You can configure the Wazuh Manager to trigger a "Global Ban." If an IP is banned on _Server A_ by Fail2Ban, the Wazuh Manager can instruct _Server B, C, and D_ to block that same IP immediately.

```XML
<!-- Example Wazuh Rule for Fail2Ban -->
<rule id="100501" level="10">
  <if_sid>5760</if_sid>
  <match>Ban </match>
  <description>Fail2Ban: An IP has been banned after multiple failed attempts.</description>
  <group>active_response,pci_dss_11.4,gdpr_IV_35.7.d,</group>
</rule>
```
