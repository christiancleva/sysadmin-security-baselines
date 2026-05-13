---
type: Playbook
id: SEC-SOC-10
title: "Incident Response & SIEM Dashboard"
frameworks:
- nist_csf_2: [RS.MA-01, RS.AN-01, RS.CO-02]
- nis2: [Art. 21.2.e (Incident handling), Art. 23 (Reporting)]
- gdpr: [Art. 33 (Notification), Art. 34]
- cis_control: [v8 17.1, v8 17.3, v8 17.5]
scope: [Incident Response, SOC, Governance]
priority: P0 - Mission Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

![[licensed-image 1.jpg]]

## 1. Executive Summary

This playbook defines the workflow to be followed when the Wazuh SIEM triggers a high-severity alert. It ensures that responses are consistent, documented, and compliant with the legal timeframes established by NIS2 and GDPR.

---

## 2. Preparation: The SIEM Dashboard

*   **Requirement:** A single pane of glass for real-time visibility.
*   **Action:** Create a custom **Wazuh Dashboard** filtered by "Level 12+" alerts.
*   **Action:** Enable **Integrations** with Slack, Microsoft Teams, or Email for immediate notification of critical failures (e.g., Ransomware patterns, Domain Admin additions).

---

## 3. Incident Response Workflow (NIST SP 800-61)

#### Phase 1: Detection & Analysis
1.  **Identify:** Is it a False Positive? Cross-reference Wazuh alerts with server logs and user activity.
2.  **Severity Assignment:**
    *   **Low:** Local login failure.
    *   **Medium:** Multiple failed logins (Brute Force).
    *   **High:** Unauthorized Sudo/Admin access, Data export.
    *   **Critical:** Ransomware signature (File encryption detected).

#### Phase 2: Containment (NIS2 Art. 21)
*   **Short-term:** Isolate the affected VM in **Proxmox** (Disconnect Network Interface).
*   **Long-term:** Disable compromised AD accounts; revoke VPN certificates.
*   **Snapshots:** Take a Proxmox/Veeam snapshot of the "infected" state for forensic analysis before cleaning.

#### Phase 3: Eradication & Recovery
*   **Eradication:** Identify the root cause (e.g., unpatched vulnerability) and fix it.
*   **Recovery:** Restore from a "Known Good" backup using the **Veeam/PBS Playbook**.
*   **Verification:** Ensure the Wazuh agent is active and the vulnerability is no longer present.

#### Phase 4: Post-Incident Activity (Legal)
*   **GDPR:** If personal data was breached, you have **72 hours** to notify the DPA.
*   **NIS2:** Submit an initial "Early Warning" to the CSIRT/National Authority within **24 hours** for significant incidents.

---

## 4. Audit Checklist (IR Readiness)

- [ ] **Audit 01: Verify Alerting Path.**
  - Trigger a test alert (e.g., 5 failed SSH logins) and ensure the notification reaches the SOC team.
- [ ] **Audit 02: Check Documentation Integrity.**
  - Ensure every "Critical" alert has a corresponding "Incident Report" (even if it was a false positive).
- [ ] **Audit 03: Review Forensic Storage.**
  - Verify that there is enough free space on the **PBS/Veeam** storage to hold "Snapshot Evidence."
- [ ] **Audit 04: Contact List Accuracy.**
  - Are the phone numbers for the DPO (GDPR) and the IT Manager up to date in the vault?

---

## 5. Wazuh Dashboard Visuals
Ensure your dashboard includes the following visualizations:
*   **Top 5 Targeted Hosts:** (Helps identify where hardening failed).
*   **Alert Level Distribution:** (Visualizes the noise vs. the signal).
*   **SCA Compliance Score:** (A real-time gauge of how many "Hardening Checks" are passing across the fleet).

```xml
<!-- Example Wazuh Active Response for Containment -->
<command>
  <name>host-deny</name>
  <executable>host-deny.sh</executable>
  <expect>srcip</expect>
</command>

<active-response>
  <command>host-deny</command>
  <location>local</location>
  <rules_id>100501</rules_id> <!-- Rule for Fail2Ban/Brute Force -->
</active-response>
```