---
type: Playbook
id: SEC-BAK-VEEAM
title: "Veeam Backup and Replication"
frameworks:
- nist_csf_2: [PR.DS-11, RC.RP-01, PR.AC-01]
- nis2: [Art. 21.2.c, Art. 21.2.e]
- gdpr: [Art. 32.1.c]
- cis_control: [v8 11.1, v8 11.2, v8 11.5]
scope: [Backup Infrastructure, DR, Data Integrity]
priority: P0 - Mission Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

Veeam is the "Last Line of Defense." This playbook ensures the backup server (VBR) and its repositories are isolated from the production domain, encrypted, and immutable to prevent ransomware from deleting recovery points.

---

## 2. Strategic Architecture (The 3-2-1-1-0 Rule)

To meet **NIS2 Resilience** standards, follow this architecture:
*   **3** Copies of data.
*   **2** Different media.
*   **1** Off-site copy.
*   **1** **Offline/Immutable/Air-gapped** copy (Crucial).
*   **0** Errors after recovery verification (SureBackup).

---

## 3. Implementation Steps

#### 3.1 The "Workgroup" Rule (NIST PR.AC-01)
*   **Critical:** Do **NOT** join the Veeam Backup Server to your production Active Directory domain. 
*   **Why:** if AD is compromised via Ransomware, the attacker gains administrative access to the Backup Server.
*   **Action:** Keep VBR in a standalone **Workgroup** with unique, complex local credentials.

#### 3.2 Hardened Linux Repository (Immutability)
*   **Requirement:** Deploy a dedicated physical Linux server (Ubuntu/Debian) using **XFS with Reflink**.
*   **Action:** Enable "Make recent backups immutable" in the Veeam repository settings.
*   **Security:** Use "Single-use credentials" for the repository deployment so Veeam does not store the Linux root password.

#### 3.3 MFA & Console Security
*   **Action:** Enable **Veeam Multi-Factor Authentication (MFA)** for all users accessing the VBR console.
*   **Action:** Restrict RDP access to the Veeam Server to a specific "Management Jump-Host" only.

#### 3.4 Encryption-at-Rest (GDPR Art. 32)
*   **Requirement:** All Backup Jobs must have "Enable backup file encryption" checked.
*   **Action:** Use a high-entropy password and store the **Veeam Configuration Backup** (including the encryption keys) in a physical safe or an offline password manager.

#### 3.5 Proxmox VE Integration
*   **Note:** Ensure the **Veeam Worker** (the small VM Veeam deploys on PVE) is placed on a restricted network segment that can only talk to the VBR server and the PVE API.

Since you are using Proxmox, Veeam uses **"Workers"** (small proxy VMs) to pull data from the hypervisor. These workers are often overlooked. They should:
1. Be automatically deleted after the job.
2. Have no public IP.
3. Use a dedicated Proxmox user with the minimum permissions required for `VM.Backup` (RBAC).

---

## 4. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify Immutability Status.**
  - Check Repository settings: `IsImmutable` should be `True`.
- [ ] **Audit 02: Check Domain Membership.**
  - Command: `systeminfo | findstr /B /C:"Domain"` (Should NOT be the production domain).
- [ ] **Audit 03: Ensure 32-bit/64-bit Encryption is active.**
  - Run the "Veeam Backup Validator" tool on random VIB/VBK files.
- [ ] **Audit 04: Test SureBackup (Recovery Verification).**
  - Verify that at least one automated "SureBackup" job successfully boots a VM in an isolated lab.
- [ ] **Audit 05: Firewall Rules.**
  - Verify that only the VBR server can access the Linux Hardened Repository via Port 6162 (Veeam Transport).

---

## 5. Wazuh Integration

Monitor the Windows Event Logs of the Veeam Server for:
*   **Event ID 29000:** Backup Job Failed.
*   **Event ID 1102:** Audit log cleared (Indicator of Attack).
*   **Unauthorized Login:** Monitor local login attempts on the VBR Workgroup.

```yaml
# Wazuh SCA Rule Snippet
checks:
  - id: 30001
    title: "Veeam Server is not Domain Joined"
    condition: all
    rules:
      - 'c:net config workstation -> !r:Workgroup domain'