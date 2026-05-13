---
type: Playbook
id: SEC-NET-VPN
title: "VPN Wireguard & OpenVPN"
frameworks:
- nist_csf_2: [PR.NW-03, PR.AC-03]
- nis2: [Art. 21.2.a (Access control), Art. 21.2.e]
- gdpr: [Art. 32 (Confidentiality)]
- cis_control: [v8 4.1, v8 12.8]
scope: [Remote Access, Networking, VPN, Encryption]
priority: P0 - Critical
status: Draft
last_review: 2026-05-09
auditable: true
---

## 1. Executive Summary

The VPN is the primary gateway for administrative tasks. This playbook ensures that remote connections are encrypted with modern ciphers, authenticated via MFA (where supported), and landed into restricted network segments to prevent lateral movement.

---

## 2. Implementation Steps

#### 2.1 Wireguard: Modern Performance & Security
Wireguard is preferred for its smaller attack surface and modern cryptography (ChaCha20-Poly1305).
*   **Action:** Use **Preshared Keys (PSK)** in addition to the standard public/private key pair to provide a layer of symmetric-key post-quantum resistance.
*   **Action:** Enforce a "Kill Switch" on client configurations to prevent data leaks when the tunnel drops.
*   **Action:** Implement **Firewall-level isolation**; the VPN interface (`wg0`) should only have access to specific management IPs, not the whole LAN.

#### 2.2 OpenVPN: Enterprise Legacy & MFA
OpenVPN is used when advanced features like MFA or LDAP integration are required.
*   **Action:** Use **TLS-Auth** or **TLS-Crypt** to prevent DoS attacks and port scanning.
*   **Cipher:** Enforce `AES-256-GCM`. Disable `BF-CBC` or `AES-128-CBC`.
*   **MFA (NIS2 Requirement):** Integrate OpenVPN with **TOTP** (Google Authenticator/FreeOTP) or an external RADIUS/LDAP provider.
*   **Action:** Run the OpenVPN daemon in a `chroot` jail and under a non-privileged user (`nobody`/`nogroup`).

#### 2.3 Network Segmentation (The "Land-and-Lock" Rule)
*   **Requirement:** Users connecting via VPN must not be able to "see" each other.
*   **Action:** Disable "Client-to-Client" communication in the VPN configuration.
*   **Action:** All VPN traffic must pass through the **PFSense/OPNSense** (or Linux) firewall for inspection.

---

## 3. CIS-Based Audit Checklist

- [ ] **Audit 01: Verify Cipher Strength.**
  - **OpenVPN:** Check `.conf` for `cipher AES-256-GCM` and `auth SHA512`.
  - **Wireguard:** Verified by protocol (ChaCha20).
- [ ] **Audit 02: Check for MFA enforcement.**
  - Attempt to login with just a certificate/password; the connection must fail without the second factor.
- [ ] **Audit 03: Verify Private Key Security.**
  - Ensure private keys on the server are readable only by the root/service user (`chmod 600`).
- [ ] **Audit 04: Check for IP Leaks.**
  - Use a packet sniffer (Tcpdump) on the server to ensure no unencrypted traffic escapes the tunnel.
- [ ] **Audit 05: Verify Logging.**
  - Ensure every connection/disconnection event is logged with the source IP and Username.

---

## 4. Wazuh Monitoring (VPN Access)

Monitoring the VPN is the first line of defense in your SIEM.

**Critical Events:**
*   **Successful Login from Unusual Location:** Alert if an admin logs in from a country outside your operating area.
*   **Multiple Failed Handshakes:** High frequency indicates a stolen certificate or brute-force attempt.
*   **VPN Configuration Change:** Monitor the `/etc/wireguard/` or `/etc/openvpn/` directories for tampering.

```xml
<!-- Example Wazuh Rule for VPN Success -->
<rule id="109001" level="3">
  <if_sid>5715</if_sid> <!-- Base sshd/auth group -->
  <match>ovpn-server: peer connected</match>
  <description>VPN: User $(user) connected from $(srcip)</description>
</rule>
```
