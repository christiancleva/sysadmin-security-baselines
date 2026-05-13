# Security Audit

**Date of Audit:** 2026-05-09

**Auditor:** [Name/Role]

**Frameworks:** NIS2, GDPR, CIS v8, NIST CSF 2.0

---

## 1. Hypervisor & Backup (Proxmox)

- [ ] **Audit 01: Verify No-Subscription Repository.** (Check `/etc/apt/sources.list.d/pve-enterprise.list` is commented out).  
- [ ] **Audit 02: Confirm MFA on Root.** (Attempt login; should prompt for TOTP/WebAuthn).
- [ ] **Audit 03: Check Shell Banner.** (Verify `/etc/issue` or `/etc/motd` contains legal warnng).
- [ ] **Audit 04: PBS Encryption.** (Verify that the Datastore has an encryption fingerprint).
- [ ] **Audit 05: Verify 3-2-1 Rule.** (Confirm existence of local PBS and one off-site/cloud copy).
- [ ] **Audit 06: Backup Integrity.** (Perform a "Verify" job on a random snapshot).

---
## 2. Linux Core Baseline

- [ ] **Audit 01: Verify LUKS Encryption.** (`lsblk -f` must show `crypto_LUKS` on data partitions).
- [ ] **Audit 02: SSH Hardening.** (`sshd -T | grep -E "permitrootlogin|passwordauthentication"` should be `no`).
- [ ] **Audit 03: Last Patch Date.** (`stat /var/lib/apt/periodic/update-success-stamp` should be < 7 days).
- [ ] **Audit 04: Sudo Audit.** (`grep "sudo" /var/log/auth.log` check for unauthorized elevation).

---
## 3. Windows Core Baseline

- [ ] **Audit 01: GPT & ReFS Check.** (`Get-Disk` shows GPT; `Get-Volume` shows ReFS 64KB on data drives).
- [ ] **Audit 02: BitLocker Status.** (`manage-bde -status C:` shows Protection On / AES-256).
- [ ] **Audit 03: Account Lockout.** (`net accounts` shows Lockout Threshold: 5).
- [ ] **Audit 04: Pending Reboots.** (Check `HKLM:\...\WindowsUpdate\Auto Update\RebootRequired`).
- [ ] **Audit 05: UAC Level.** (Verify "ConsentPromptBehaviorAdmin" is set to 1 or 2).

---
## 4. Identity & Directory Services (AD / Samba)

- [ ] **Audit 01: Protocol Status.** (`testparm` or GPO check: SMBv1 Disabled, NTLMv1 Disabled).
- [ ] **Audit 02: LDAP Signing.** (Verify `ldap server require strong auth = yes`).
- [ ] **Audit 03: Tiered Admin Model.** (Verify Domain Admins have not logged into Tier 2 workstations).
- [ ] **Audit 04: KRBTGT Rotation.** (Verify `krbtgt` password last set < 180 days).
- [ ] **Audit 05: Anonymous Binds.** (`ldapsearch -x` should fail to return directory data)

---
## 5. Databases (SQL Server & PostgreSQL)

- [ ] **Audit 01: SA / Postgres Superuser.** (Verify `sa` is disabled; `postgres` role restricted). 
- [ ] **Audit 02: Feature Surface Area.** (`xp_cmdshell` must be 0; Ad-hoc queries disabled).
- [ ] **Audit 03: Force Encryption.** (Verify TLS is required for all incoming connections).
- [ ] **Audit 04: Data Folder Permissions.** (Postgres `/data` must be `700`; SQL files restricted to service account).

---
### 5.1 SQL Server on Docker

- [ ] **Audit 05: Process User.** (`docker exec id` must not be `uid=0`).
- [ ] **Audit 06: Secret Management.** (Verify `SA_PASSWORD` is not in cleartext in `docker inspect`).
- [ ] **Audit 07: Volume Encryption.** (Confirm host-mapped paths are on LUKS-encrypted partitions).
- [ ] **Audit 08: Network Isolation.** (Confirm port 1433 is not mapped to public interfaces).

---
## 6. Applications & Containers

- [ ] **Audit 01: ERP Service Account.** (Confirm TeamSystem runs under a non-admin Service Account).
- [ ] **Audit 02: Docker Rootless.** (Verify Docker daemon is not running as host root).
- [ ] **Audit 03: Privileged Containers.** (No containers running with `--privileged=true`).
- [ ] **Audit 04: Nginx TLS Score.** (Run `testssl.sh`; must be A+ with no TLS 1.0/1.1).
- [ ] **Audit 05: Security Headers.** (Verify HSTS, X-Frame-Options, and CSP are present).

---
## 7. Network & Storage Hardware

- [ ] **Audit 01: Switch Port Security.** (Verify unused ports are `admin-down`; Sticky MAC enabled).
- [ ] **Audit 02: Firewall Default Deny.** (Confirm "Deny All" rule exists at the bottom of every interface).
- [ ] **Audit 03: VPN MFA.** (Confirm 2FA is required for all OpenVPN/Wireguard connections).
- [ ] **Audit 04: NAS Immutability.** (Verify 30-day "Snapshot Locking" is active on the backup volume).
- [ ] **Audit 05: SAN Isolation.** (Confirm iSCSI/FC traffic is on a non-routed, separate VLAN).
- [ ] **Audit 06: Mutual CHAP.** (Verify both Initiator and Target require secret keys).

---
## 8. SOC & Incident Response

- [ ] **Audit 01: Wazuh Agent Connectivity.** (Verify all critical nodes are "Active" in the dashboard).
- [ ] **Audit 02: CVE Database.** (Confirm Vulnerability Detector updated within 24 hours).
- [ ] **Audit 03: Alert Path.** (Trigger test alert; verify email/Slack/Teams notification).
- [ ] **Audit 04: Log Retention.** (Confirm ILM policy preserves logs for 180+ days per GDPR).
- [ ] **Audit 05: Contact Info.** (Verify DPO and CSIRT phone numbers are correct).

---

## Final Review Sign-off

**Overall Status:** [PASSED / FAILED / CONDITIONALLY PASSED]

**Notes:**

**Next Audit Due:** 2026-08-09

**Signature:** 
