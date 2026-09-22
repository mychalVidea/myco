# Security Policy
## 🛡️ Supported Versions
We actively release security patches and cryptographic enhancements for the following versions of **MYCO Vault**:

| Version | Supported |
| :--- | :--- |
| **1.1.x** | :white_check_mark: (Current Stable) |
| **1.0.x** | :x: (Deprecated) |
| < 1.0.0 | :x: (Deprecated / Prototype) |

## 🔒 Reporting a Vulnerability
If you discover a security vulnerability, weakness in our cryptographic pipeline (COL4 / Dual AEAD), or unexpected behavior, **please do not disclose it publicly in GitHub Issues**.
Instead, please report it through one of the following channels:

1. **GitHub Private Vulnerability Reporting (Recommended):**
   - Go to the **Security** tab of this repository.
   - Click on **Report a vulnerability** to open a confidential private advisory.
2. **Direct Contact:**
   - Reach out to the maintainer via email or through the official network at [https://mychalsmp.xyz](https://mychalsmp.xyz).

### What to include in your report:
- A clear description of the vulnerability or exploit vector.
- Steps to reproduce or proof-of-concept (PoC) code.
- Impact assessment (e.g., potential unauthorized decryption, denial of service, memory exhaustion).

## ⏱️ Response Timeline
- **Acknowledgment:** We strive to acknowledge and triage security reports within **48 to 72 hours**.
- **Fix & Patch:** Once validated, a security release will be tagged and published promptly.
- **Credit:** We gladly credit responsible security researchers in our release notes and change logs.

## 🔐 Cryptographic Principles
- MYCO Vault strictly uses **audited Node.js native standard library primitives** (`crypto.createCipheriv` with `aes-256-gcm` and `chacha20-poly1305`, `crypto.hkdfSync` with `SHA-512`).
- We **never** implement custom hand-rolled stream ciphers or hash functions.
- Decryption operates with constant-time verification tags (`crypto.timingSafeEqual`) to prevent timing side-channel attacks.
