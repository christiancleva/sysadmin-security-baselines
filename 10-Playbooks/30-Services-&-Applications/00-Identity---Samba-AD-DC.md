---
type: Playbook
id: SEC-APP-00
title: "Identity - Samba AD DC"
frameworks:
- "nist_csf_2: (PR.AC-01, PR.AC-03, PR.AC-06, PR.PS-01)"
- "nis2: (Art. 21.2.a (Access control), Art. 21.2.g)"
- "gdpr: (Art. 32 (Confidentiality/Integrity))"
- "cis_control: (v8 5.1, v8 6.1, v8 6.2)"
scope: [Identity, Authentication, Directory Services]
priority: P0 - Mission Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

The Samba Active Directory Domain Controller (AD DC) is the central authority for your infrastructure. This playbook focuses on securing the directory protocols (LDAP/SMB), enforcing strong authentication, and ensuring the underlying Linux OS is "stealth-hardened" against lateral movement.

---

## 2. Implementation Steps

#### 2.1 Protocol Hardening (The "No Legacy" Rule)
*   **Action:** Disable **NTLMv1**. It is vulnerable to relay attacks and easily cracked.
    *   *smb.conf:* `ntlm auth = ntlmv2-only`
*   **Action:** Enforce **LDAP Signing and Sealing**. This prevents Man-in-the-Middle (MITM) attacks during authentication.
    *   *smb.conf:* 
        *   `ldap server require strong auth = yes`
        *   `server schannel = yes`
*   **Action:** Disable **SMBv1**.
    *   *smb.conf:* `server min protocol = SMB2_10`

**Backup Warning:** Standard file backups are often not enough for an AD DC. You must perform a `samba-tool domain backup online` regularly to ensure the database (`ldb` files) is in a consistent state for recovery.

#### 2.2 Functional Level & Kerberos
*   **Action:** Ensure the Forest and Domain functional levels are at least `2012_R2` (or the highest Samba supports in your version) to enable modern security features.
*   **Action:** Enforce AES-256 for Kerberos encryption.
    *   *Command:* `samba-tool domain passwordsettings set --min-pwd-length=14`

#### 2.3 DNS Security
*   **Requirement:** Samba AD DC usually runs its own DNS (Internal or Bind9).
*   **Action:** Restrict DNS recursions to the local network only.
*   **Action:** Disable zone transfers (`allow-transfer { none; };`) to prevent attackers from mapping your entire internal network.

#### 2.4 Administrative Isolation (PoLP)
*   **Requirement:** Do not use the `Administrator` account for daily tasks.
*   **Action:** Create a "Domain Admins" group and assign unique accounts to individuals.
*   **Action:** Use **GPO (Group Policy Objects)** to restrict where Domain Admins can log in (e.g., Admins should only log in to DCs and Management Jump-Hosts, never to standard workstations).

---

## 3. Audit Checklist (Samba-Specific)

- [ ] **Audit 01: Verify NTLMv1 is disabled.**
  - `testparm -v | grep "ntlm auth"` (Should show `ntlmv2-only`).
- [ ] **Audit 02: Check for anonymous LDAP binds.**
  - `ldapsearch -x -H ldap://localhost -b ""` (Should fail or return no sensitive data).
- [ ] **Audit 03: Verify SMB signing is required.**
  - `testparm -v | grep "server signing"` (Should be `mandatory`).
- [ ] **Audit 04: Check Password Quality settings.**
  - `samba-tool domain passwordsettings show` (Verify length, complexity, and history).
- [ ] **Audit 05: Check for unquoted service paths (Windows-side).**
  - If using Windows RSAT to manage Samba, ensure all service paths are quoted to prevent "Trusted Service Path" exploits.

---

## 4. Wazuh Monitoring (Active Directory Focus)

Monitoring the AD DC is critical for detecting **Golden Ticket** attacks or **Password Spraying**.

**Critical Logs to Ingest:**
*   `/var/lib/samba/private/audit.log` (If full auditing is enabled).
*   Windows Security Logs (from joined clients) for **Event ID 4768** (Kerberos TGT requested).

```xml
<!-- Wazuh Rule: Detect multiple failed logins on AD -->
<rule id="103001" level="10">
  <if_sid>5760</if_sid>
  <match>samba: auth failure</match>
  <description>Samba AD: Multiple authentication failures. Possible brute force/spraying!</description>
  <group>pci_dss_10.2.4,gdpr_IV_32.2,</group>
</rule>
```