---
type: Playbook
id: SEC-LX-30
title: "Backup & Recovery (Restic Client)"
frameworks:
- nist_csf_2: [PR.DS-11, RC.RP-01]
- nis2: [Art. 21.2.c (Business continuity), Art. 21.2.e]
- gdpr: [Art. 32.1.c]
- cis_control: [v8 11.1, v8 11.3, v8 11.4]
scope: [Data Integrity, Disaster Recovery, Linux Core]
priority: P0 - Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook covers granular file-level backups. Restic provides deduplicated, encrypted, and verifiable backups. Unlike image-level backups (Veeam), this allows for rapid recovery of specific application data (e.g., `/var/www` or SQL dumps) even if the entire VM infrastructure is unavailable.

---

## 2. Implementation Steps

#### 2.1 Repository Initialization (Encryption)
*   **Requirement:** Backups must be encrypted before leaving the server.
*   **Action:** Initialize the Restic repository with a high-entropy passphrase.
    *   `restic -r s3:s3.amazonaws.com/your-bucket init`
*   **Secret Management:** Store the `RESTIC_PASSWORD` and S3 keys in `/etc/restic/env.conf` with `chmod 600`.

#### 2.2 Backup & Retention Policy
*   **Action:** Create a backup script that includes automated pruning (retention).
```bash
# Example Backup Command
restic backup /etc /var/www /home/db_dumps

# Retention Policy (NIS2 Compliance)
restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
```

#### 2.3 Data Integrity & Maintenance
- **Requirement:** Backups must be verified regularly to ensure they can be restored.    
- **Action:** Run a `check` command weekly to verify the integrity of the data structures.
       - `restic check --read-data-subset=10%`
   
#### 2.4 The Restore Procedure (The "Real" Backup)
> [!IMPORTANT] A backup is not a backup until you have performed a **Restore Test**.
 1. Create a temporary directory: `mkdir /tmp/restore_test`
 2. Restore the latest snapshot: `restic restore latest --target /tmp/restore_test`
 3. Verify file checksums.

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify Repository Encryption.**
    - Check if `restic stats` requires a password.
- [ ] **Audit 02: Verify Environment File Permissions.**
    - `stat -c "%a" /etc/restic/env.conf` (Must be `600`).
- [ ] **Audit 03: Check Success of Last Backup Job.**
    - `restic snapshots` (Verify the timestamp of the latest entry).
- [ ] **Audit 04: Verify Data Scrubbing.**
    - Review logs for the last successful `restic check`.

---

## 4. Wazuh Monitoring

Monitor the exit codes of the backup script.

```Bash
# In your backup script
if [ $? -eq 0 ]; then
  /var/ossec/bin/agent_control -m "Restic backup successful"
else
  /var/ossec/bin/agent_control -m "Restic backup FAILED"
fi
```