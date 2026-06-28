---
type: Playbook
id: SEC-CONT-01
title: "Docker Engine & Container Security"
frameworks:
- "nist_csf_2: (PR.PS-06, PR.AC-03, PR.NW-01)"
- "nis2: (Art. 21.2.f (Vulnerability management), Art. 21.2.g)"
- "gdpr: (Art. 32 (Technical measures))"
- "cis_control: (v8 18.1, v8 18.2, v8 18.3)"
scope: [Containers, Virtualization, Microservices]
priority: P1 - High
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook addresses the risks of containerized environments. We focus on securing the Docker Daemon, restricting container privileges, and ensuring that the "Supply Chain" (Images) is verified and scanned for vulnerabilities to prevent lateral movement to the host OS.

---

## 2. Implementation Steps

#### 2.1 Docker Daemon Hardening (CIS 1.1)
*   **Action:** Run Docker in **Rootless Mode** if possible to ensure the daemon runs as a non-privileged user.
*   **Action:** Limit the Docker socket access. Do **NOT** expose `/var/run/docker.sock` to containers unless strictly necessary (this is a direct path to host root).
*   **Action:** Disable "Inter-Container Communication" (ICC) by default to force explicit linking/networking.
    *   *daemon.json:* `"icc": false`

#### 2.2 Resource Constraints (DoS Protection)
*   **Requirement:** Prevent a single compromised or buggy container from crashing the host (NIS2 Resilience).
*   **Action:** Always set memory and CPU limits.
    *   *Docker Run/Compose:* `--memory="512m"` `--cpus="0.5"`

#### 2.3 Image Security (Supply Chain)
*   **Requirement:** Use only trusted, minimal base images (e.g., Alpine or Distroless).
*   **Action:** Implement **Image Scanning** (using `trivy` or `docker scan`) before deployment.
*   **Action:** Use **Docker Content Trust** to ensure you only run signed images.
    *   *Env Var:* `export DOCKER_CONTENT_TRUST=1`

#### 2.4 Container Runtime Hardening
*   **Action:** Run containers with `--read-only` root filesystems to prevent persistent malware.
*   **Action:** Drop unnecessary Linux Capabilities.
    *   *Docker Run:* `--cap-drop=ALL --cap-add=NET_BIND_SERVICE`
*   **Action:** Ensure containers run as a non-root user (`USER node` or `USER 1000` in Dockerfile).

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Check if Docker is running as root.**
  - `ps -ef | grep dockerd` (Verify if it's running under a standard user).
- [ ] **Audit 02: Verify that 'icc' is disabled.**
  - `docker network inspect bridge` (Check the `com.docker.network.bridge.enable_icc` value).
- [ ] **Audit 03: Check for containers running with '--privileged' flag.**
  - `docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}'` (Should be `false`).
- [ ] **Audit 04: Verify logging driver.**
  - Ensure Docker is using the `json-file` or `syslog` driver so Wazuh can ingest the logs.
  - *daemon.json:* `"log-driver": "json-file"`

---

## 4. Wazuh Monitoring (Docker Integration)

Wazuh has a native module to monitor the Docker API. It can track container lifecycle events and changes to the Docker configuration.

**Key Alerts:**
*   **Container started as root:** High alert.
*   **Container shell opened:** Monitor for interactive sessions (`docker exec -it`).
*   **Image with high CVEs deployed:** Integrates with your vulnerability management policy.

```xml
<!-- Example Wazuh Configuration (ossec.conf) -->
<docker-logs>
  <enabled>yes</enabled>
  <interval>10m</interval>
  <attempts>3</attempts>
</docker-logs>
```