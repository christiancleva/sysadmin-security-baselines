---
type: Playbook
id: SEC-PVE-NET
title: Proxmox VE Networking & SDN
frameworks:
  - "nist csf 2 (PR.NW-01, PR.NW-02)"
  - "nis2 (Art. 21.2.a (Network Security))"
  - "gdpr (Art. 32 (Data isolation))"
  - "cis control (v8 12.1, v8 12.2)"
scope:
  - Networking
  - SDN
  - VLAN
  - Firewall
priority: P1 - High
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook ensures that the "Virtual Wire" is as secure as a physical one. We aim to prevent ARP spoofing, MAC flooding, and unauthorized inter-VM communication.

---

## 2. Implementation Steps

#### 2.1 Bridge Isolation
*   **Action:** Ensure `bridge-nf-call-iptables` is enabled so the Proxmox Firewall can filter traffic moving *across* the bridge between VMs.
*   **Action:** Disable "MAC Learning" on sensitive bridges if the VM layout is static.

#### 2.2 SDN (Software Defined Network) Setup
*   **Requirement:** Use SDN Zones (Simple or VLAN) to manage multi-tenancy.
*   **Action:** Create a **DMZ Zone** for internet-facing VMs and a **Private Zone** for DBs. Use the PVE SDN module to automate the creation of these isolated segments.

#### 2.3 Guest Network Hardening
*   **Firewall:** Every VM must have the "Firewall" checkbox enabled at the **Network Device** level.
*   **DHCP Guarding:** Prevent a rogue VM from acting as a DHCP server.
    *   *Action:* Use IPSet to allow only the legitimate DHCP server IP.

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify Bridge Netfilter.**
  - `sysctl net.bridge.bridge-nf-call-iptables` (Should be 1).
- [ ] **Audit 02: Check for VLAN Leaks.**
  - Ensure `bridge-vlan-aware` is only enabled on bridges that actually require trunking.
- [ ] **Audit 03: Proxmox Firewall Status.**
  - `pve-firewall status` (Must be running).
- [ ] **Audit 04: Restrict Proxmox GUI to Management IP.**
  - Check `/etc/pve/firewall/cluster.fw` for management IP whitelist.

---

## 4. Wazuh Integration

*   **Monitor:** `pve-firewall` logs located at `/var/log/pve-firewall.log`.
*   **Alert:** Trigger a High-Level alert if a VM attempts to communicate on a port blocked by the Datacenter-level policy.