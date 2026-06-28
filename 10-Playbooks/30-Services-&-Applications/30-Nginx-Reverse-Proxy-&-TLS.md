---
type: Playbook
id: SEC-NET-NGINX
title: "Nginx Reverse Proxy & TLS"
frameworks:
- "nist_csf_2: (PR.NW-01, PR.NW-02, PR.PT-04)"
- "nis2: (Art. 21.2.a (Network security), Art. 21.2.e)"
- "gdpr: (Art. 32 (Encryption in transit))"
- "cis_control: (v8 12.2, v8 12.3)"
scope: [Edge Security, Networking, TLS/SSL)"
priority: P0 - Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

This playbook defines the security standard for the edge of the network. Nginx is used to terminate TLS connections, enforce high-security headers, and proxy traffic to internal services (ERP, Docker, Proxmox). This setup ensures that internal systems are never directly exposed to the public internet.

---

## 2. Implementation Steps

#### 2.1 TLS Protocol Hardening (GDPR Art. 32)
*   **Action:** Disable all legacy protocols. Use only **TLS 1.2 and 1.3**.
*   **Cipher Suites:** Use modern, forward-secrecy-enabled ciphers.
    *   *nginx.conf:* 
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
```
https://ssl-config.mozilla.org/

#### 2.2 HTTP Security Headers
- **Action:** Enforce headers to prevent XSS, Clickjacking, and MIME-sniffing.
    - `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`
    - `add_header X-Frame-Options "SAMEORIGIN" always;`
    - `add_header X-Content-Type-Options "nosniff" always;`
    - `add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;`

#### 2.3 Rate Limiting (DoS Protection)
- **Requirement:** Prevent automated bots from flooding your ERP or Login pages.
- **Action:** Define a shared memory zone for rate limiting.
    - _nginx.conf (http block):_ `limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;`
    - _server block:_ `limit_req zone=mylimit burst=20 nodelay;`

#### 2.4 Hiding Server Metadata
- **Action:** Do not reveal the Nginx version or OS details.
    - `server_tokens off;`

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify SSL/TLS score.**
    - Use `ssllabs.com` or `testssl.sh`. (Target: **A+**).
- [ ] **Audit 02: Check for version disclosure.**
    - `curl -I https://yourdomain.com` (Ensure `Server: nginx` does not show a version number).
- [ ] **Audit 03: Verify HSTS (Strict-Transport-Security) is active.**
    - Check headers via Browser DevTools or `curl`.
- [ ] **Audit 04: Test Rate Limiting.**
    - Use a load-testing tool (like `ab` or `wrk`) to ensure the server returns 429 errors when the limit is exceeded.
- [ ] **Audit 05: Check Diffie-Hellman parameters.**
    - Ensure a custom 2048-bit or 4096-bit DH group is generated.
    - `openssl dhparam -out /etc/nginx/dhparam.pem 4096`

---

## 4. Wazuh Monitoring (Web Access)

Nginx logs are a goldmine for the SOC. Wazuh should ingest both `access.log` and `error.log`.
**Critical Events to Track:**
- **4XX Errors:** High frequency indicates a directory scan or broken links.
- **5XX Errors:** Indicates backend (ERP/Docker) instability.
- **ModSecurity (Optional):** If Nginx is compiled with ModSecurity (WAF), Wazuh can alert on specific SQLi or XSS attack patterns.
- 
```xml
<!-- Example Wazuh Rule for Web Attacks -->
<rule id="108001" level="10">
  <if_sid>31100</if_sid> <!-- Base web log group -->
  <match>sql injection|union select|script alert</match>
  <description>Nginx: Potential Web Attack (SQLi/XSS) detected in URL!</description>
  <group>pci_dss_6.5.1,gdpr_IV_35.7.d,nis2_art21</group>
</rule>
```