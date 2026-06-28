---
type: Playbook
id: SEC-PBS-01
title: "Proxmox Backup Server (PBS)"
frameworks:
- "nist csf 2 (PR.DS-11, RC.RP-01)"
- "nis2 (Art. 21.2.c (Business Continuity) Art. 21.2.e)"
- "gdpr (Art. 32.1.c (Availability/Resilience))"
- "cis control (v8 11.1, v8 11.2)"
scope: [Backup, Storage, Disaster Recovery]
priority: P0 - Mission Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

The Backup Server is the last line of defense against Ransomware. If the PBS is compromised, the entire disaster recovery strategy fails. This playbook enforces encryption and the "Principle of Least Privilege" for backup traffic.

---

## 2. Implementation Steps

#### 2.1 Encryption-at-Rest (GDPR/NIS2 Critical)
*   **Requirement:** All backup data must be encrypted.
*   **Action:** Use **Client-Side Encryption** keys generated in Proxmox VE when linking the storage.
*   **Storage:** If possible, use ZFS with native encryption for the underlying datastores.

#### 2.2 Access Control (API Tokens)
*   **Requirement:** Proxmox VE nodes should not use the PBS 'root' password.
*   **Action:** Create a specific API Token for each PVE Cluster.
    *   Limit the token to the `DatastoreBackup` role only.
    *   Use the "Separate Namespace" feature to isolate backups from different environments.

#### 2.3 Traffic Security
*   **PBS Port:** Port 8007 should be restricted via firewall to only allow PVE Node IPs.
*   **TLS:** Ensure PBS uses a valid certificate to prevent Man-in-the-Middle during backup transfers.

#### 2.4 Maintenance & Integrity
*   **Verify Jobs:** Schedule weekly "Verification Jobs" to ensure backup chunks are not corrupted.
*   **Garbage Collection:** Schedule regular GC to maintain disk health and remove old, unreferenced data.

---

## 3. Deployment Architecture: PBS as a VM

> [!WARNING] Circular Dependency Risk
> To comply with NIS2 Resilience requirements, if PBS is virtualized:
> 1. **Data Passthrough:** Use 'Disk Passthrough' or 'HBA Passthrough' so PBS controls the physical disks directly.
> 2. **Anti-Affinity:** Use PVE "High Availability" groups to ensure the PBS VM never runs on the same node as the Mission Critical VMs it protects.
> 3. **Manual Bootstrap:** Store the `pbs-client` binary and the Encryption Keys/Master Keys on an external, physical "Cold Storage" (USB/Paper backup) to allow manual restoration if the PVE GUI is lost.

---

## 4. CIS-Based Audit Checklist

- [ ] **Audit 01: Check if API Tokens are used instead of passwords.**
  - Inspect `/etc/proxmox-backup/user.cfg`
- [ ] **Audit 02: Verify Datastore Verification Jobs are scheduled.**
  - `proxmox-backup-manager verify-job list`
- [ ] **Audit 03: Ensure Encryption Keys are stored securely off-host.**
  - Manual check: Verify that `.key` files are backed up in a secure password manager (e.g., Vaultwarden/KeepassXC).
- [ ] **Audit 04: Check local firewall for Port 8007 restrictions.**
  - `ufw status` or `nft list ruleset`

---

## 5. Disaster Recovery Note (NIS2)

> [!IMPORTANT]
> Under NIS2, a backup is only valid if it is **immutable** or **off-site**. 
> Ensure a **Sync Job** is configured to push/pull backups to a secondary remote PBS or an off-site S3-compatible storage.
