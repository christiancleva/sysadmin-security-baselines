---
title: "Security Governance Dashboard"
icon: "lucide/layout-dashboard"
---

# 🛡️ Infrastructure Security Oversight

> [!INFO] 
> This dashboard automatically aggregates all files with `type: Playbook` in the vault. Use this to track compliance readiness and review cycles.

---

## 📑 Playbook Status & Priority
```dataview
TABLE
	id as "ID",
    status as "Status", 
    substring(priority,0,2) as "Priority", 
    last_review as "Last Review",
    frameworks as "Frameworks"
FROM "sysadmin-security-baselines/10-Playbooks"
WHERE type = "Playbook"
SORT priority ASC, status DESC