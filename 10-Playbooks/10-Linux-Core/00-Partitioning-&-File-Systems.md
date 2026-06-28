---
type: Playbook
id: SEC-LX-00
title: Linux Partitioning & File Systems
frameworks:
  - "nist csf 2: (PR.DS-01, PR.PS-01)"
  - "nis2: (Art. 21.2.c),"
  - "gdpr: (Art. 32 (Encryption at rest))"
  - "cis control: (v8 3.3, v8 3.11)"
scope:
  - OS
  - Storage
  - Linux Core
priority: P1 - High
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

A flat file system is a security risk. If `/var/log` fills up, the system crashes (DoS). If a user can execute code in `/tmp`, they can escalate privileges. This playbook enforces partition separation and mount-point hardening according to CIS Benchmarks.

---

## 2. Implementation Steps

#### 2.1 Logical Partitioning (NIST PR.DS-01)
For all new installations (VMs or Bare Metal), ensure the following directories are on separate partitions/LVM volumes:
*   `/var`: Prevents system logs or mail queues from consuming root (`/`) space.
*   `/var/log`: Ensures audit records are preserved even if the main system is compromised.
*   `/home`: Isolates user data from system binaries.
*   `/tmp` & `/var/tmp`: High-risk areas for temporary exploit storage.

#### 2.2 Hardened Mount Options (CIS 1.1.1 - 1.1.21)
Edit `/etc/fstab` to restrict execution and device creation in temporary or user-writable areas.
*   **/tmp**: Add `nodev,nosuid,noexec`
*   **/dev/shm**: Add `nodev,nosuid,noexec`
*   **/home**: Add `nodev,nosuid` (allows execution for user apps but prevents setuid binaries).

| **Partition** | **CIS Requirement** | **Mount Options (Hardening)** | **Rationale**                                           |
| ------------- | ------------------- | ----------------------------- | ------------------------------------------------------- |
| `/tmp`        | 1.1.2 - 1.1.5       | `nodev,nosuid,noexec`         | Prevents executing binaries in a temporary folder.      |
| `/var`        | 1.1.6               | `defaults`                    | Base for variable data; prevents `/` from filling up.   |
| `/var/tmp`    | 1.1.10 - 1.1.11     | `nodev,nosuid,noexec`         | Similar to `/tmp`.                                      |
| `/var/log`    | 1.1.12              | `nodev,nosuid,noexec`         | Ensures logs are preserved even if `/` is full.         |
| `/home`       | 1.1.18 - 1.1.20     | `nodev,nosuid`                | Prevents users from introducing "special device" files. |
| `/dev/shm`    | 1.1.21 - 1.1.23     | `nodev,nosuid,noexec`         | Hardens shared memory against exploitation.             |

#### 2.3 Disk Encryption (GDPR Art. 32)
*   **Action:** Enable **LUKS (Linux Unified Key Setup)** at the partition level.
*   **Proxmox Context:** If the host is physical, use a hardware TPM to unlock LUKS or a manual passphrase at boot.
*   **VM Context:** Use the Hypervisor's encryption (Veeam/PVE) or internal LUKS.

#### 2.4 Sticky Bit on World-Writable Directories
Ensure that only the owner of a file can delete or rename it in shared directories.
*   **Command:** `df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null`

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify separate partition for /var/log.**
  - `mount | grep /var/log`
- [ ] **Audit 02: Check /tmp mount options.**
  - `mount | grep /tmp` (Should show `noexec`, `nosuid`, `nodev`).
- [ ] **Audit 03: Verify LUKS status.**
  - `cryptsetup status <device_name>`
- [ ] **Audit 04: Check for unconfined world-writable directories.**
  - `find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print` (Should return nothing).

---

## 4. Wazuh Integration

Wazuh SCA (Security Configuration Assessment) checks these mount options by default.
**Wazuh Alert:** Monitor `/etc/fstab` for unauthorized changes.
```yaml
# Wazuh Rule
<rule id="100200" level="7">
  <if_sid>550</if_sid>
  <match>/etc/fstab</match>
  <description>Hardening: /etc/fstab has been modified. Verify mount options.</description>
</rule>