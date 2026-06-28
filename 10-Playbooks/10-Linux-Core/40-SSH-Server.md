---
type: Playbook
id: SEC-LX-40
title: "SSH Server"
frameworks:
- "nist csf 2 (PR.AC-01, PR.AC-03, PR.AC-05)"
- "nis2 (Art. 21.2.a (Access control))"
- "gdpr (Art. 32 (Confidentiality))"
- "cis control (v8 4.1, v8 5.2, v8 12.8)"
scope: [Access Control, Identity, Linux Core]
priority: P0 - Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook enforces the **Principle of Least Privilege (PoLP)**. We disable insecure authentication methods (passwords) and restrict administrative access (sudo) to ensure that even if an account is compromised, the damage is contained.

---

## 2. Implementation Steps

#### 2.1 SSH Daemon Hardening (CIS 5.2)
Modify `/etc/ssh/sshd_config` with the following security-first parameters:

*   **Authentication:** Disable passwords. Use SSH Keys (Ed25519) only.
    *   `PasswordAuthentication no`
    *   `PubkeyAuthentication yes`
*   **Root Access:** Prevent direct root login. Admins must login as a standard user and escalate.
    *   `PermitRootLogin prohibit-password` (or `no`)
*   **Crypto Hardening:** Disable legacy ciphers (no SHA1, no 3DES).
    *   `KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256`
    *   `Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com`
*   **Session Management:**
    *   `ClientAliveInterval 300` (5 minutes)
    *   `ClientAliveCountMax 0` (Force logout on idle)
    *   `MaxAuthTries 3`

#### 2.2 User & Group Hardening (NIST PR.AC-01)
*   **No Shared Accounts:** Every admin must have a unique account (e.g., `m.rossi` instead of `admin`).
*   **Sudo Restrictions:** Limit `sudo` to a specific group (usually `sudo` or `wheel`).
    *   Use `sudo visudo` to ensure `%sudo ALL=(ALL:ALL) ALL` is active.
*   **Shell History:** Increase history size and add timestamps for audit trails.
    *   Edit `/etc/bash.bashrc`: `HISTTIMEFORMAT="%F %T "`

#### 2.3 Password Policy (PAM)
If passwords are used for local escalation (`sudo`), enforce complexity via `libpam-pwquality`.
*   **Policy:** Minimum 14 characters, 1 upper, 1 lower, 1 digit, 1 special.

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify Password Authentication is disabled.**
  - `sshd -T | grep passwordauthentication` (Result must be `no`).
- [ ] **Audit 02: Check for empty passwords in /etc/shadow.**
  - `awk -F: '($2 == "") {print $1}' /etc/shadow` (Result must be empty).
- [ ] **Audit 03: Verify SSH Protocol 2 is enforced.**
  - `sshd -T | grep protocol` (Result must be `2`).
- [ ] **Audit 04: Audit sudoers group membership.**
  - `grep '^sudo:.*$' /etc/group` (Verify only authorized users are listed).
- [ ] **Audit 05: Check SSH banner.**
  - `sshd -T | grep banner` (Should point to `/etc/issue.net`).

---

## 4. Wazuh Monitoring & Response
Wazuh is critical here for detecting **Brute Force** and **Unauthorized Sudo**.

**Detecting Sudo Abuse:**
```xml
<rule id="100301" level="10">
  <if_sid>5402</if_sid>
  <description>User not in sudoers attempted to run sudo!</description>
  <group>pci_dss_10.2.2,gdpr_IV_32.2,</group>
</rule>
```

**Monitor `sshd` successful logins and cross-reference**
```YAML
# Wazuh SCA Check
checks:
  - id: 50001
    title: "Ensure SSH PermitRootLogin is set to no"
    condition: all
    rules:
      - 'f:/etc/ssh/sshd_config -> r:^PermitRootLogin\s+no'
```