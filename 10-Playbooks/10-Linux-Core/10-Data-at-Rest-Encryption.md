---
type: Playbook
id: SEC-LX-10
title: "Data-at-Rest Encryption (Linux)"
frameworks:
- "nist csf 2 (PR.DS-01, PR.DS-10)"
- "nis2 (Art. 21.2.c, Art. 21.2.g)"
- "gdpr (Art. 32.1.a)"
- "cis control (v8 3.11)"
scope: [OS, Storage, Privacy]
priority: P0 - Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook defines the standard for protecting data at the block level. If a physical server is decommissioned or a VM disk file is stolen, the data remains cryptographically inaccessible. We focus on **LUKS2** for Linux systems.

---

## 2. Implementation Strategy

#### 2.1 The Encryption Stack
To maintain performance and security, we follow the "Onion" model: 
1. **Physical/Virtual Disk** -> 2. **LUKS Partition** -> 3. **LVM (Optional)** -> 4. **Filesystem**.

#### 2.2 Host-Level Encryption (LUKS2)
*   **Action:** Use `cryptsetup` with the `luks2` format.
*   **Cipher:** `aes-xts-plain64` with a 512-bit key.
*   **Boot:** Encrypt the entire drive except for a small `/boot` partition (or use encrypted `/boot` with GRUB hooks).

#### 2.3 Automated Unlocking (The NIS2 "Resilience" Balance)
Manual passphrases at boot are secure but break "High Availability."
*   **Physical Hosts:** Use **TPM 2.0** with `clevis` and `dracut` to bind the encryption key to the hardware.
    *   *Command:* `clevis luks bind -d /dev/sdX tpm2 '{"pcr_ids":"7"}'`
*   **Virtual Machines:** Use the Hypervisor's **vTPM** or secret management via **Clevis/Tang** servers for network-bound unlocking.

#### 2.4 Key Management & Rotation
*   **Requirement:** Master keys must never be stored on the same disk as the encrypted data.
*   **Action:** Backup LUKS headers to a secure, off-host location (Vaultwarden/KeePass).
    *   *Command:* `cryptsetup luksHeaderBackup /dev/sdX --header-backup-file /path/to/backup`

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify LUKS2 usage.**
  - `cryptsetup luksDump /dev/sdX | grep Version`
- [ ] **Audit 02: Check for weak PBKDF (Argon2id is preferred).**
  - `cryptsetup luksDump /dev/sdX` (Ensure PBKDF is `argon2id` for better brute-force resistance).
- [ ] **Audit 03: Verify TPM binding.**
  - `clevis luks list -d /dev/sdX`
- [ ] **Audit 04: Ensure no plaintext keys are in /etc/crypttab.**
  - `cat /etc/crypttab` (Verify that keys are referenced by UUID and not stored as raw text).

---

## 4. Wazuh Monitoring

Monitor for "Cryptographic Failures" or unauthorized attempts to access encrypted volumes.
```yaml
# Wazuh SCA Check
checks:
  - id: 11001
    title: "Verify LUKS partition is present"
    condition: any
    rules:
      - 'f:/etc/crypttab -> r:^[^#]'
