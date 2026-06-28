# Infrastructure Security & Hardening Vault

A comprehensive collection of **Security Playbooks** and **Hardening Baselines** designed for modern hybrid infrastructures. This vault is specifically mapped to **NIS2 (Article 21)**, **GDPR (Article 32)**, and **CIS Controls v8**.

## Overview

This repository serves as a "Source of Truth" for system administrators and security officers. It bridges the gap between high-level regulatory requirements and technical execution, providing step-by-step instructions for securing hypervisors, operating systems, and core business applications.

### Key Frameworks & Standards

* **NIS2 Directive:** Incident handling, business continuity, and supply chain security.
* **GDPR:** Data-at-rest encryption (LUKS/BitLocker) and integrity.
* **CIS Controls v8:** Technical benchmarks for OS and network hardening.
* **NIST CSF 2.0:** Identification, Protection, Detection, and Response.

---

## Technical Stack

The playbooks in this vault cover the following infrastructure components:

| Category | Technology |
| --- | --- |
| **Hypervisor** | Proxmox VE, Proxmox Backup Server (PBS) |
| **Operating Systems** | Debian/Ubuntu (Linux), Windows Server 2022 |
| **Identity & Access** | Active Directory (AD DS), Samba AD DC |
| **Databases** | Microsoft SQL Server (Windows/Docker), PostgreSQL |
| **Networking** | pfSense/OPNSense, Wireguard, OpenVPN, L2 Switching |
| **SOC & Monitoring** | Wazuh SIEM, OpenVAS (Greenbone) |

---

## Repository Structure

The vault is organized into logical domains for easy navigation and auditing:

```text
├── 00_Hypervisor/           # Proxmox & PBS Hardening
├── 10_Linux_Core/           # Encryption, SSH, & Patching standards
├── 15_Storage/              # NAS & SAN Security (iSCSI, SMB, NFS)
├── 20_Windows_Core/         # BitLocker, ReFS, & GPO Baselines
├── 30_Services/             # ERP (TeamSystem), SQL, Docker, & Nginx
├── 40_Network/              # VPNs, Firewall Rules, & Switch Security
├── 50_SOC_Monitoring/       # Wazuh Config, OpenVAS, & Incident Response
└── 99_Compliance_Map/       # RACI Matrix & Framework Mapping

```

### Playbook Status & Priority

|File28|ID|Status|Priority|Last Review|Frameworks|
|---|---|---|---|---|---|
|[10-Data-at-Rest-Encryption](10-Playbooks/10-Linux-Core/10-Data-at-Rest-Encryption.md)|SEC-LX-10|Draft|P0|maggio 09, 2026|- nist csf 2 (PR.DS-01, PR.DS-10)<br>- nis2 (Art. 21.2.c, Art. 21.2.g)<br>- gdpr (Art. 32.1.a)<br>- cis control (v8 3.11)|
|[30-Backup-&-Recovery-(Restic-Client)](10-Playbooks/10-Linux-Core/30-Backup-&-Recovery-\(Restic-Client\).md)|SEC-LX-30|Draft|P0|maggio 09, 2026|- nist csf 2 (PR.DS-11, RC.RP-01)<br>- nis2 (Art. 21.2.c (Business continuity), Art. 21.2.e)<br>- gdpr (Art. 32.1.c)<br>- cis control (v8 11.1, v8 11.3, v8 11.4)|
|[40-SSH-Server](10-Playbooks/10-Linux-Core/40-SSH-Server.md)|SEC-LX-40|Draft|P0|maggio 09, 2026|- nist csf 2 (PR.AC-01, PR.AC-03, PR.AC-05)<br>- nis2 (Art. 21.2.a (Access control))<br>- gdpr (Art. 32 (Confidentiality))<br>- cis control (v8 4.1, v8 5.2, v8 12.8)|
|[90-Logging-&-Wazuh-Agent](10-Playbooks/10-Linux-Core/90-Logging-&-Wazuh-Agent.md)|SEC-LX-90|Draft|P0|maggio 09, 2026|- nist csf 2 (DE.CM-01, DE.CM-03, PR.PT-01)<br>- nis2 (Art. 21.2.e, Art. 21.2.f)<br>- gdpr (Art. 32 (Integrity/Availability))<br>- cis control (v8 8.1, v8 8.2, v8 8.5, v8 8.11)|
|[20-OS-Update-&-Repositories](10-Playbooks/10-Linux-Core/20-OS-Update-&-Repositories.md)|SEC-LX-20|Draft|P0|maggio 09, 2026|- nist csf 2 (PR.PS-02, PR.PS-05)<br>- nis2 (Art. 21.2.f (Vulnerability handling))<br>- gdpr (Art. 32)<br>- cis control (v8 7.1, v8 7.2, v8 7.4)|
|[90-Logging-&-Wazuh-Agent](10-Playbooks/20-Windows-Core/90-Logging-&-Wazuh-Agent.md)|SEC-WIN-90|Draft|P0|maggio 09, 2026|- nist csf 2 (DE.CM-01, DE.CM-03, PR.PT-01)<br>- nis2 (Art. 21.2.e, Art. 21.2.f)<br>- gdpr (Art. 32)<br>- cis control (v8 8.1, v8 8.2, v8 8.3, v8 8.5)|
|[20-Windows-Update-&-Patching](10-Playbooks/20-Windows-Core/20-Windows-Update-&-Patching.md)|SEC-WIN-20|Draft|P0|maggio 09, 2026|- nist csf 2 (PR.PS-02, PR.PS-05)<br>- nis2 (Art. 21.2.f (Vulnerability handling))<br>- gdpr (Art. 32)<br>- cis control (v8 7.1, v8 7.2, v8 7.4)|
|[10-BitLocker-&-Security-Policies](10-Playbooks/20-Windows-Core/10-BitLocker-&-Security-Policies.md)|SEC-WIN-10|Draft|P0|maggio 09, 2026|- nist csf 2 (PR.DS-01, PR.AC-01, PR.AC-03)<br>- nis2 (Art. 21.2.a, Art. 21.2.c)<br>- gdpr (Art. 32.1.a (Encryption))<br>- cis control (v8 3.11, v8 4.1, v8 5.2)|
|[00-VPN-Wireguard-&-OpenVPN](10-Playbooks/40-Network-&-Connectivity/00-VPN-Wireguard-&-OpenVPN.md)|SEC-NET-VPN|Draft|P0|maggio 09, 2026|- nist_csf_2: (PR.NW-03, PR.AC-03)<br>- nis2: (Art. 21.2.a (Access control), Art. 21.2.e)<br>- gdpr: (Art. 32 (Confidentiality))<br>- cis_control: (v8 4.1, v8 12.8)|
|[10-Firewall-Rules-(PFSense-OPNSense-Linux)](10-Playbooks/40-Network-&-Connectivity/10-Firewall-Rules-\(PFSense-OPNSense-Linux\).md)|SEC-NET-FW|Draft|P0|maggio 09, 2026|- nist_csf_2: (PR.NW-01, PR.NW-02)<br>- nis2: (Art. 21.2.a (Network security), Art. 21.2.c)<br>- gdpr: (Art. 32 (Technical measures))<br>- cis_control: (v8 4.1, v8 12.8)|
|[00-Proxmox-VE](10-Playbooks/00-Hypervisors/00-Proxmox-VE.md)|SEC-PVE-01|Draft|P0|maggio 09, 2026|- nist csf 2 (PR.PS-01, PR.AC-03, PR.DS-01)<br>- nis2 (Art. 21.2.a, Art. 21.2.c, Art. 21.2.g)<br>- gdpr (Art. 32)<br>- cis control (v8 3.3, v8 4.1, v8 5.1)|
|[10-Proxmox-Backup-Server-(PBS)](10-Playbooks/00-Hypervisors/10-Proxmox-Backup-Server-\(PBS\).md)|SEC-PBS-01|Draft|P0|maggio 09, 2026|- nist csf 2 (PR.DS-11, RC.RP-01)<br>- nis2 (Art. 21.2.c (Business Continuity) Art. 21.2.e)<br>- gdpr (Art. 32.1.c (Availability/Resilience))<br>- cis control (v8 11.1, v8 11.2)|
|[30-Backup-(Veeam-VBR)](10-Playbooks/20-Windows-Core/30-Backup-\(Veeam-VBR\).md)|SEC-BAK-VEEAM|Draft|P0|maggio 09, 2026|- nist csf 2 (PR.DS-11, RC.RP-01, PR.AC-01)<br>- nis2 (Art. 21.2.c, Art. 21.2.e)<br>- gdpr (Art. 32.1.c)<br>- cis control (v8 11.1, v8 11.2, v8 11.5)|
|[00-SQL-Server-(Windows-Focus)](10-Playbooks/30-Services-&-Applications/00-Database-\(RDBMS\)/00-SQL-Server-\(Windows-Focus\).md)|SEC-SQL-00|Draft|P0|maggio 09, 2026|- nist_csf_2: (PR.DS-01, PR.AC-01, PR.DS-11, PR.PS-01)<br>- nis2: (Art. 21.2.a, Art. 21.2.c, Art. 21.2.g)<br>- gdpr: (Art. 32.1.a, Art. 32.1.b)<br>- cis_control: (v8 3.3, v8 4.1, v8 6.2)|
|[00-Identity---Microsoft-Active-Directory](10-Playbooks/30-Services-&-Applications/00-Identity---Microsoft-Active-Directory.md)|SEC-AD-01|Draft|P0|maggio 09, 2026|- nist_csf_2: (PR.AC-01, PR.AC-03, PR.AC-05, PR.IR-02)<br>- nis2: (Art. 21.2.a (Access control), Art. 21.2.g)<br>- gdpr: (Art. 32 (Confidentiality/Integrity))<br>- cis_control: (v8 5.1, v8 6.1, v8 13.1)|
|[00-Identity---Samba-AD-DC](10-Playbooks/30-Services-&-Applications/00-Identity---Samba-AD-DC.md)|SEC-APP-00|Draft|P0|maggio 09, 2026|- nist_csf_2: (PR.AC-01, PR.AC-03, PR.AC-06, PR.PS-01)<br>- nis2: (Art. 21.2.a (Access control), Art. 21.2.g)<br>- gdpr: (Art. 32 (Confidentiality/Integrity))<br>- cis_control: (v8 5.1, v8 6.1, v8 6.2)|
|[10-TeamSystem-&-ERP-Security](10-Playbooks/30-Services-&-Applications/10-TeamSystem-&-ERP-Security.md)|SEC-ERP-TS|Draft|P0|maggio 09, 2026|- nist_csf_2: (PR.AC-01, PR.DS-01, PR.DS-10, PR.PS-01)<br>- nis2: (Art. 21.2.a, Art. 21.2.c, Art. 21.2.j (Hygiene/Training))<br>- gdpr: (Art. 32, Art. 33 (Breach Notification), Art. 35 (DPIA))<br>- cis_control: (v8 3.1, v8 4.1, v8 6.1, v8 14.1)|
|[10-Incident-Response-&-SIEM-Dashboard](10-Playbooks/50-SOC-&-Monitoring/10-Incident-Response-&-SIEM-Dashboard.md)|SEC-SOC-10|Draft|P0|maggio 09, 2026|- nist_csf_2: (RS.MA-01, RS.AN-01, RS.CO-02)<br>- nis2: (Art. 21.2.e (Incident handling), Art. 23 (Reporting))<br>- gdpr: (Art. 33 (Notification), Art. 34)<br>- cis_control: (v8 17.1, v8 17.3, v8 17.5)|
|[00-Wazuh-Manager-Installation](10-Playbooks/50-SOC-&-Monitoring/00-Wazuh-Manager-Installation.md)|SEC-SOC-00|Draft|P0|maggio 09, 2026|- nist_csf_2: (PR.DS-10, DE.CM-01, DE.CM-03)<br>- nis2: (Art. 21.2.e (Supply chain/Monitoring), Art. 21.2.f)<br>- gdpr: (Art. 32 (Integrity/Confidentiality))<br>- cis_control: (v8 8.1, v8 8.2, v8 8.5)|
|[20-Network-Switches-(Layer-2)](10-Playbooks/40-Network-&-Connectivity/20-Network-Switches-\(Layer-2\).md)|SEC-NET-SW|Draft|P1|maggio 09, 2026|- nist_csf_2: (PR.NW-01, PR.PT-03)<br>- nis2: (Art. 21.2.a, Art. 21.2.c)<br>- cis_control: (v8 12.1, v8 12.4)|
|[20-Proxmox-VE-Networking-&-SDN](10-Playbooks/00-Hypervisors/20-Proxmox-VE-Networking-&-SDN.md)|SEC-PVE-NET|Draft|P1|maggio 09, 2026|- nist csf 2 (PR.NW-01, PR.NW-02)<br>- nis2 (Art. 21.2.a (Network Security))<br>- gdpr (Art. 32 (Data isolation))<br>- cis control (v8 12.1, v8 12.2)|
|[00-Partitioning-&-File-Systems](10-Playbooks/10-Linux-Core/00-Partitioning-&-File-Systems.md)|SEC-LX-00|Draft|P1|maggio 09, 2026|- nist csf 2: (PR.DS-01, PR.PS-01)<br>- nis2: (Art. 21.2.c),<br>- gdpr: (Art. 32 (Encryption at rest))<br>- cis control: (v8 3.3, v8 3.11)|
|[50-Fail2Ban-&-Firewall](10-Playbooks/10-Linux-Core/50-Fail2Ban-&-Firewall.md)|SEC-LX-50|Draft|P1|maggio 09, 2026|- nist csf 2 (PR.NW-01, PR.NW-02, DE.AE-01)<br>- nis2 (Art. 21.2.a, Art. 21.2.e)<br>- gdpr (Art. 32 (Technical measures))<br>- cis control (v8 1.1, v8 4.4, v8 12.8)|
|[00-Partitioning-&-ReFS](10-Playbooks/20-Windows-Core/00-Partitioning-&-ReFS.md)|SEC-WIN-00|Draft|P1|maggio 09, 2026|- nist csf 2 (PR.DS-01, PR.DS-10, PR.PS-01)<br>- nis2 (Art. 21.2.c (Business continuity), Art. 21.2.e)<br>- gdpr (Art. 32.1.c (Integrity))<br>- cis control (v8 3.3, v8 11.3)|
|[10-SQL-Server-on-Docker](10-Playbooks/30-Services-&-Applications/00-Database-\(RDBMS\)/10-SQL-Server-on-Docker.md)|SEC-SQL-DOCKER|Draft|P1|maggio 10, 2026|- nist_csf_2: (PR.DS-01, PR.PS-06)<br>- nis2: (Art. 21.2.a, Art. 21.2.f)<br>- gdpr: (Art. 32)<br>- cis_control: (v8 18.1, v8 3.3)|
|[20-PostgreSQL-(Linux-Focus)](10-Playbooks/30-Services-&-Applications/00-Database-\(RDBMS\)/20-PostgreSQL-\(Linux-Focus\).md)|SEC-PG-20|Draft|P1|maggio 09, 2026|- nist_csf_2: (PR.DS-01, PR.AC-01, PR.PT-01)<br>- nis2: (Art. 21.2.a, Art. 21.2.c)<br>- gdpr: (Art. 32.1.a, Art. 32.1.b)<br>- cis_control: (v8 3.3, v8 4.1, v8 6.2)|
|[20-Docker-Engine-&-Container-Security](10-Playbooks/30-Services-&-Applications/20-Docker-Engine-&-Container-Security.md)|SEC-CONT-01|Draft|P1|maggio 09, 2026|- nist_csf_2: (PR.PS-06, PR.AC-03, PR.NW-01)<br>- nis2: (Art. 21.2.f (Vulnerability management), Art. 21.2.g)<br>- gdpr: (Art. 32 (Technical measures))<br>- cis_control: (v8 18.1, v8 18.2, v8 18.3)|
|[20-Vulnerability-Management-(OpenVAS)](10-Playbooks/50-SOC-&-Monitoring/20-Vulnerability-Management-\(OpenVAS\).md)|SEC-VULN-01|Draft|P1|maggio 10, 2026|- nist_csf_2: (ID.RA-01, ID.RA-02, PR.PS-02)<br>- nis2: (Art. 21.2.f (Vulnerability handling), Art. 21.2.e)<br>- gdpr: (Art. 32.1.d (Testing/Assessing effectiveness))<br>- cis_control: (v8 7.1, v8 7.2, v8 7.4)|

---

## How to Use This Vault

1. **Clone the Repository:** Best used with **Obsidian.md** for its internal linking and Dataview capabilities.
2. **Select a Playbook:** Choose a component (e.g., `10_Linux_Baseline.md`).
3. **Execute & Audit:** Follow the *Implementation Steps* and complete the *CIS-Based Audit Checklist* at the end of each file.
4. **Update the Map:** Link your findings in the `99_Compliance_Map` folder to generate an audit-ready compliance report.

---

## Governance & Auditing

This project includes a **Master Audit Tracker** that aggregates all security checklists. This ensures that infrastructure hardening is not a "one-time" event but a continuous process of verification and remediation.

---

## Disclaimer

> [!CAUTION]
> **Test before you deploy.** Hardening measures can restrict system functionality. Always validate these playbooks in a staging environment (e.g., a Proxmox test lab) before applying them to production systems.

## License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

**Project Maintainer:** Christian Cleva

**Last Major Update:** June 2026
