---
type: Playbook
id: SEC-NET-SW
title: "Network Switches (Layer 2)"
frameworks:
- "nist_csf_2: (PR.NW-01, PR.PT-03)"
- "nis2: (Art. 21.2.a, Art. 21.2.c)"
- "cis_control: (v8 12.1, v8 12.4)"
scope: [Switching, VLANs, Physical Port Security]
priority: P1
status: Draft
last_review: 2026-05-09
---

## 1. Executive Summary

The switch is the "entry point" to the physical network. This playbook prevents unauthorized devices from plugging into your network and stops Layer 2 attacks like MAC flooding and DHCP spoofing.

---

## 2. Implementation Steps

#### 2.1 Management Plane Security
*   **Dedicated Management VLAN:** Never manage switches from the same VLAN as users. Use the **MGMT VLAN (10)**.
*   **Disable Insecure Protocols:** Turn off Telnet, HTTP, and SNMP v1/v2. Use only **SSH** and **SNMP v3** (with encryption).
*   **ACLs:** Restrict switch management access to specific "Jump Host" IPs.

#### 2.2 Port Security & STP (NIS2 Art. 21.2.a)
*   **Action:** Disable all unused ports and move them to a "Blackhole" VLAN.
*   **Sticky MAC:** Limit each port to 1 or 2 specific MAC addresses. Shut down the port if a new device is detected.
*   **BPDU Guard:** Enable on all "Access" ports to prevent an attacker from plugging in their own switch and becoming the "Root Bridge."

#### 2.3 Traffic Integrity
*   **DHCP Snooping:** Enable to prevent "Rogue DHCP" servers from handing out malicious gateway IPs.
*   **Dynamic ARP Inspection (DAI):** Prevents Man-in-the-Middle (MITM) ARP poisoning.

---

## 3. Audit Checklist

- [ ] **Audit 01:** Verify all unused ports show `status: down / admin-down`.
- [ ] **Audit 02:** Attempt to plug a laptop into a server port; the port should automatically disable (Port Security).
- [ ] **Audit 03:** Verify `SSH` only; `telnet` connection should be refused.