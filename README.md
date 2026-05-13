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

**Last Major Update:** May 2026
