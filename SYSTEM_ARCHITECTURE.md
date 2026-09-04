# Secure OTA Firmware Update & Code Signing Platform
**Final Project Documentation**

## 1. System Overview
The **Secure OTA Firmware Update & Code Signing Platform** provides a robust, end-to-end mechanism for delivering over-the-air software updates to IoT devices and embedded edge nodes. The core goal of this platform is to ensure that devices only install authorized, unmodified firmware, preventing malicious actors from hijacking devices through firmware tampering or downgrade attacks.

The architecture comprises three main components:
1. **Central PKI & Signing Backend:** Manages X.509 certificates (Root CA, Intermediate CA, Signing Certs) and uses RSA/ECDSA private keys to cryptographically sign firmware images.
2. **Firmware Management & Deployment Registry:** Tracks device states, groups fleets, manages semantic versioning, and orchestrates OTA update rollouts (canary and full rollouts).
3. **Edge IoT Device / SecureBoot Simulator:** Simulates edge devices that periodically check for updates, verify digital signatures before installation, and enforce anti-rollback constraints.

---

## 2. Threat Model
The system was designed with the following security assumptions and mitigations in mind:

### 2.1. Firmware Tampering & Man-in-the-Middle (MitM)
- **Threat:** An attacker intercepts the firmware binary during the OTA download process and injects malicious code.
- **Mitigation:** **Digital Signatures & Cryptographic Hashing.** The backend calculates a SHA-256 hash of the firmware and signs it using an RSA-4096 (PSS padding) or ECDSA (P-256/384) private key. The IoT device re-calculates the hash upon download and verifies the signature using the pre-installed public Root CA. If a single bit is changed, the signature validation fails and the firmware is rejected.

### 2.2. Firmware Downgrade (Rollback) Attacks
- **Threat:** An attacker serves a previously valid, legitimately signed but outdated firmware (which may contain known vulnerabilities) to the device.
- **Mitigation:** **Anti-Rollback Mechanism.** The device's SecureBoot logic parses the SemVer (Semantic Versioning) of the incoming update. If the incoming version is logically older than the currently installed version, the update is immediately rejected, even if the cryptographic signature is perfectly valid. The server also enforces rollback policies for deployments.

### 2.3. Certificate Compromise & Supply Chain Risks
- **Threat:** The firmware signing private key is stolen, allowing an attacker to sign their own malicious firmware.
- **Mitigation:** **Hierarchical PKI & Revocation.** The Root CA is kept offline. An Intermediate CA is used to issue short-lived Signing Certificates. If a signing key is compromised, the Certificate Lifecycle Manager can immediately revoke the specific Signing Certificate via the API. The device will dynamically reject any firmware signed by a revoked or expired certificate during the certificate chain validation step.

---

## 3. Cryptographic Architecture

### 3.1. Public Key Infrastructure (PKI)
The platform features an integrated, standalone Certificate Authority module (`app.pki.ca`) built on Python's `cryptography` library.
- **Root CA:** Self-signed, high security, 4096-bit RSA (10-year validity).
- **Intermediate CA:** Signed by Root CA, issues device and firmware signing certs (5-year validity).
- **Firmware Signing Certs:** Short-lived keys (e.g., 1 year) strictly used for code signing.

### 3.2. Code Signing Algorithm
To comply with modern cryptographic standards:
- **Hashing:** `SHA-256` or `SHA-384`.
- **Signature (RSA):** Employs `RSA-PSS` (Probabilistic Signature Scheme) with `MGF1` and maximum salt length, avoiding the legacy vulnerabilities of PKCS#1 v1.5 padding.
- **Signature (ECDSA):** Employs elliptic curve cryptography on `secp256r1` (P-256) or `secp384r1` (P-384) for devices with low compute/storage constraints.

---

## 4. Edge Verification Flow (SecureBoot)
The edge device validates every OTA update through a rigorous 4-step process before flashing:

1. **Manifest Integrity:** The device receives a JSON manifest containing the firmware's SHA-256 hash, version, and the digital signature of the hash.
2. **Anti-Rollback Check:** The version string (e.g., `2.0.1`) is compared against the currently running version (e.g., `2.1.0`). If older, abort.
3. **Chain of Trust Verification:** The device downloads the public certificate of the signer. It verifies the signer's certificate against its embedded Root CA (checking validity dates, path length, and revocation status).
4. **Binary Integrity Check:** The device downloads the raw firmware blob. It calculates `SHA-256(firmware_bytes)` locally. It then cryptographically verifies the `signature` from the manifest against the calculated hash using the signer's verified public key. 

Only if all 4 steps succeed will the device log `Installation successful` and report a positive status back to the Device Registry.
