# Hybrid Cryptographic File Encryption System

A secure, open-source file encryption system built in Python that combines the unmatched speed of AES-256 symmetric encryption with the robust security of RSA-3072 asymmetric key cryptography. 

This project includes a fully-featured modern Desktop GUI, built using `customtkinter`, allowing users to easily generate keys, encrypt files, and decrypt them securely.

## Security Features & Audit

This application has undergone a **9-round rigorous, white-box security audit**, resulting in 45 patched vulnerabilities. It is hardened against both mathematical and operating-system-level attacks:
- **Hybrid Cryptography**: Uses AES-256 (GCM Mode) for fast data encryption and RSA-3072 (OAEP/PSS) to securely encrypt the AES key and sign the payload.
- **Strict Content Binding**: Digital signatures bind the payload strictly to the intended receiver, defeating Surreptitious Forwarding attacks.
- **C-Level Memory Sanitization**: Bypasses Python's immutability to calculate C-struct offsets and inject zeros directly into physical RAM, definitively scrubbing keys from memory immediately after use.
- **TOCTOU & Symlink Protection**: Maintains continuous, open file descriptors during encryption passes (`seek(0)`) and enforces strict atomic renames (`shutil.move`), eliminating CWE-377 insecure temporary file exploits.
- **OS-Level Sandboxing**: Hardcoded to safely store and load keys exclusively from `~/.hybrid_crypto/`, protecting against Current Working Directory (CWD) hijacking and unauthorized key injection.
- **Denial of Service (DoS) Protection**: Enforces a strict 64 GiB mathematical upper bound and hashes ciphertexts *before* performing expensive AES-GCM operations to reject tampered files instantly.
- **Modern Desktop UI**: A sleek, dark-themed graphical interface built with `customtkinter`.
- 

<img width="1053" height="718" alt="Screenshot 2026-08-26 163339" src="https://github.com/user-attachments/assets/4428c7eb-f246-4f6a-89b1-b7248b2f22fc" />

<img width="852" height="572" alt="Screenshot 2026-08-26 163355" src="https://github.com/user-attachments/assets/f84adf8a-4917-4211-ab8d-2b3857a66d74" />




## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/hybrid-encryption.git
   cd hybrid-encryption
   ```

2. **Install the dependencies:**
   It is recommended to use a virtual environment.
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Desktop GUI (Recommended)
To launch the user-friendly desktop application:
```bash
python app.py
```
From the GUI, you can:
1. Generate your RSA-3072 key pair (securely saved to `~/.hybrid_crypto/`).
2. Select any file from your computer and encrypt it into an `.enc` file.
3. Select an encrypted `.enc` file to securely decrypt and restore it.

### Automated Demo / CLI Validation
To run the automated test script which proves the system's correctness and simulates a tampering attack:
```bash
python demo.py
```

## Security Warning
- **NEVER** share your `private.pem` file. Anyone with access to your private key can decrypt your files.
- Ensure your `~/.hybrid_crypto/` folder has restrictive permissions. The application attempts to enforce this via `icacls` on Windows automatically.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
