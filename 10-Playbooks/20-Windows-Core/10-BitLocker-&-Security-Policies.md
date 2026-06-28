---
type: Playbook
id: SEC-WIN-10
title: "BitLocker & Security Policies"
frameworks:
- "nist csf 2 (PR.DS-01, PR.AC-01, PR.AC-03)"
- "nis2 (Art. 21.2.a, Art. 21.2.c)"
- "gdpr (Art. 32.1.a (Encryption))"
- "cis control (v8 3.11, v8 4.1, v8 5.2)"
scope: [Windows Core, Encryption, Access Control]
priority: P0 - Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook enforces volume-level encryption and baseline security configurations for Windows. We leverage **vTPM** in Proxmox to provide transparent encryption, ensuring that data is unreadable if the `.qcow2` or `.raw` disk files are stolen or leaked.

---

## 2. Implementation Steps

#### 2.1 BitLocker with vTPM (Proxmox Integration)
*   **Requirement:** Proxmox VM must have a `TPM State` device (v2.0) and `EFI Disk` configured.
*   **Action:** Enable BitLocker on the OS drive (C:).
    *   *PowerShell (Admin):* `Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -TpmProtector`
*   **Recovery Key:** Back up the 48-digit recovery key to a secure location (Vaultwarden/AD) immediately.
    *   *Command:* `(Get-BitLockerVolume -MountPoint "C:").KeyProtector`

When you run Windows in Proxmox, the **vTPM** stores the secret in a separate small file on your Proxmox storage. Ensure this storage is also backed up (via Veeam or PBS), or you will lose access to the encrypted VM if that specific metadata is lost.

#### 2.2 Account Lockout Policy (NIS2 Art. 21)
To prevent local brute-force attacks, implement the following via `secpol.msc`:
*   **Account lockout threshold:** 5 invalid logon attempts.
*   **Account lockout duration:** 15 minutes.
*   **Reset account lockout counter after:** 15 minutes.

#### 2.3 User Account Control (UAC) & Admin Isolation
*   **Requirement:** No user should work with administrative privileges for daily tasks.
*   **UAC Setting:** "Always notify" (Highest level). This prevents silent elevation by malware.
*   **Rename Local Admin:** Rename the default `Administrator` account to a non-standard name to complicate credential-stuffing attacks.

#### 2.4 Network Protocol Hardening
Disable legacy and insecure protocols that allow lateral movement:
*   **Disable LLMNR/NetBIOS:** Prevents "Responder" attacks (MITM).
    *   *Registry:* `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast` set to `0`.
*   **Disable SMBv1:** (Should be off by default in 2026, but verify).

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify BitLocker Status.**
  - `manage-bde -status C:` (Encryption must be `AES 256` and Protection `On`).
- [ ] **Audit 02: Check UAC Level.**
  - `Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | Select-Object ConsentPromptBehaviorAdmin` (Should be `1` or `2`).
- [ ] **Audit 03: Verify Password Complexity.**
  - `net accounts` (Ensure "Length" and "Complexity" are enforced).
- [ ] **Audit 04: Check for guest account status.**
  - `net user guest` (Must be `Active: No`).

---

## 4. Wazuh Monitoring (Windows)

Wazuh tracks every "Account Lockout" and "Privilege Escalation" event.

**Critical Windows Event IDs to Monitor:**
*   **4625:** Failed Login (Brute force detection).
*   **4740:** A user account was locked out.
*   **4672:** Special privileges assigned to new logon (Admin login).

```xml
<!-- Example Wazuh Rule for BitLocker Status -->
<!-- This requires a custom script/command output on the agent -->
<rule id="102101" level="9">
  <if_sid>501</if_sid>
  <match>BitLocker is not encrypted</match>
  <description>Windows: Encryption is DISABLED on C: drive! GDPR Compliance failure.</description>
</rule>
```
