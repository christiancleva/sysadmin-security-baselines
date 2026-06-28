---
type: Playbook
id: SEC-NET-FW
title: Firewall Rules & Network Segmentation
frameworks:
  - "nist_csf_2: (PR.NW-01, PR.NW-02)"
  - "nis2: (Art. 21.2.a (Network security), Art. 21.2.c)"
  - "gdpr: (Art. 32 (Technical measures))"
  - "cis_control: (v8 4.1, v8 12.8)"
scope:
  - Gateway
  - VLAN
  - Firewall
  - Routing
priority: P0 - Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook defines the "Zones of Trust" for the infrastructure. By implementing a **Default Deny** posture and strict inter-VLAN routing, we minimize the attack surface and prevent lateral movement. This is the primary defense for the "Crown Jewels" (ERP and AD DC).

---

## 2. Implementation Steps

#### 2.1 Network Segmentation (The "Zones" Model)
Divide the infrastructure into at least four distinct VLANs:
1.  **MGMT (VLAN 10):** Proxmox GUI, PBS, Switches, IPMI. No internet access.
2.  **SRV (VLAN 20):** Active Directory, SQL Server, ERP. Restricted internet.
3.  **DMZ (VLAN 30):** Nginx Proxy, Docker apps, Web servers. Isolated from SRV.
4.  **USER (VLAN 40):** Employee workstations, VPN clients.

#### 2.2 The "Default Deny" Rule (CIS 12.8)
*   **Rule 01:** Every interface must have a "Deny All" rule at the bottom.
*   **Rule 02:** Only explicit, documented traffic is allowed.
*   **Action:** If a rule isn't linked to a specific ticket or playbook ID, it must be disabled.

#### 2.3 Critical Rule Templates
| Source | Destination | Port/Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| **USER** | **DMZ** | TCP 443 | Access Web Apps |
| **DMZ** | **SRV (DB)** | TCP 1433/5432 | Database Queries |
| **MGMT** | **Wazuh** | UDP 1514 | Log Forwarding |
| **Any** | **AD DC** | TCP/UDP 53, 88, 389 | Domain Auth |

#### 2.4 Egress Filtering (NIS2 Requirement)
*   **Requirement:** Servers must not be able to "call home" to random internet IPs.
*   **Action:** Block all outbound traffic from the **SRV** and **MGMT** VLANs. 
*   **Whitelisting:** Only allow outbound traffic to specific Update Mirrors (e.g., Debian/Microsoft) and your Backup Target (e.g., Wasabi/S3).

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify "Any-Any" rules.**
  - Review rulesets for any rule where Source is `*` and Destination is `*`. These must be removed.
- [ ] **Audit 02: Test Inter-VLAN Isolation.**
  - Attempt to `ping` a Proxmox Management IP from a DMZ container. (Should fail).
- [ ] **Audit 03: Check Firewall Log Retention.**
  - Ensure blocked packets are being logged and sent to the Wazuh Manager.
- [ ] **Audit 04: Validate Web GUI access.**
  - Ensure the Firewall's own management GUI is only accessible from the **MGMT** VLAN.
- [ ] **Audit 05: NTP Synchronization.**
  - Verify all network devices are using the same NTP source for accurate audit timestamps.

---

## 4. Wazuh Monitoring (Network Visibility)

The firewall's syslog is the primary source for detecting network-based reconnaissance.

**Critical Alerts:**
*   **Port Scanning:** Multiple "Deny" logs from a single source IP in a short period.
*   **Unauthorized Inter-VLAN traffic:** A DMZ server attempting to SSH into a Domain Controller.
*   **Egress Violation:** A server attempting to communicate with a known malicious IP (using Wazuh's CDB lists).

```xml
<!-- Example Wazuh Rule for Firewall Deny -->
<rule id="110001" level="5">
  <if_sid>4100</if_sid> <!-- Firewall group -->
  <match>DROP|REJECT|DENY</match>
  <description>Firewall: Packet dropped from $(srcip) to $(dstip)</description>
</rule>
```