---
type: Playbook
id: SEC-SOC-00
title: "Wazuh Manager Installation & Configuration"
frameworks:
- "nist_csf_2: (PR.DS-10, DE.CM-01, DE.CM-03)"
- "nis2: (Art. 21.2.e (Supply chain/Monitoring), Art. 21.2.f)"
- "gdpr: (Art. 32 (Integrity/Confidentiality))"
- "cis_control: (v8 8.1, v8 8.2, v8 8.5)"
scope: [SIEM, SOC, Monitoring, Infrastructure]
priority: P0 - Mission Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

The Wazuh Manager is the central nervous system of our security infrastructure. It collects, analyzes, and stores security data from all agents. This playbook ensures the Manager is deployed with high availability, encrypted communication, and storage policies that satisfy GDPR log retention requirements.

---

## 2. Implementation Steps

#### 2.1 Hardware Sizing (NIS2 Resilience)
To ensure the SOC doesn't crash during a heavy attack (DoS), allocate dedicated resources:
*   **CPU:** 4-8 vCPU (depending on agent count).
*   **RAM:** 8GB - 16GB.
*   **Storage:** Use the **20.00 Partitioning & ReFS** (Windows) or **10.00 Partitioning** (Linux) logic. Put `/var/ossec/data` on a separate high-speed SSD volume.

#### 2.2 Secure Installation
*   **Action:** Use the official "Wazuh Central Components" installation script or Docker-Compose for isolation.
*   **Certificates:** Generate unique SSL/TLS certificates for the Indexer, Dashboard, and Manager. Do **not** use the default "wazuh" password.
*   **Action:** Run the `wazuh-passwords-tool.sh` to rotate all internal service passwords immediately after installation.

#### 2.3 Hardening the "Brain"
*   **API Security:** Restrict access to the Wazuh API (Port 55000) to the **MGMT VLAN** only.
*   **Web Console (Dashboard):** Force HTTPS and implement MFA (via SAML/OIDC or local plugin) for all SOC analysts.
*   **Agent Enrollment:** Use **Password Authentication** for agent registration to prevent unauthorized "Rogue Agents" from flooding your SIEM.

#### 2.4 Data Retention (GDPR/NIS2 Compliance)
*   **Requirement:** Logs must be kept for a specific period (e.g., 6 months to 1 year) for forensic investigations.
*   **Action:** Configure **Index Lifecycle Management (ILM)**.
    *   *Hot Phase:* 30 days (High speed search).
    *   *Cold Phase:* 150 days (Compressed, archive).
    *   *Deletion:* After 180+ days (To comply with GDPR "Right to be Forgotten" and data minimization).

---

## 3. Audit Checklist

- [ ] **Audit 01: Verify Component Communication.**
  - Check `filebeat test output` to ensure logs are reaching the Indexer.
- [ ] **Audit 02: Check TLS Certificate Validity.**
  - `openssl x509 -in /etc/filebeat/certs/filebeat.pem -text -noout` (Ensure they are not expired).
- [ ] **Audit 03: Verify Disk Space Alerts.**
  - Ensure Wazuh is monitoring its own `/var/ossec` partition.
- [ ] **Audit 04: Audit User Access.**
  - Review the list of users in the Wazuh Dashboard; ensure no "guest" or "test" accounts exist.
- [ ] **Audit 05: Vulnerability Database Update.**
  - Check the "Vulnerability Detector" dashboard to ensure the CVE databases (NVD/MSU) were updated within the last 24 hours.

---

## 4. Disaster Recovery (Business Continuity)

*   **Action:** Backup the `/var/ossec/etc/` directory and the **Indexer Snapshots** daily using the **Veeam/PBS Playbook**.
*   **Recovery Time Objective (RTO):** 4 Hours.