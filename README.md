# SoboEncrypt
SoboEncrypt is a lightweight Python-based encryption utility by SoboCorp. Secure any file using AES-256 with a simple, clean UI. No installers, no tracking just open the script and protect your data. Includes encryption/decryption tabs, password confirmation, and .sobo file format.
# SoboEncrypt v1  
### A SoboCorp Security Utility

SoboEncrypt is a lightweight Python application that encrypts and decrypts files using AES-256.  
No installers, no bloat, no telemetry. Just pure, simple security written in Python.

---

## 🔒 Features

- AES-256 GCM encryption  
- Password-based key derivation (PBKDF2, 200k iterations)  
- Clean tabbed UI (Encrypt / Decrypt)  
- Custom `.sobo` encrypted file format  
- Hidden password input  
- No dependencies besides `cryptography`  

---

## 📦 Installation

1. Install Python 3.8+  
2. Install required library:

```bash
pip install cryptography
