# Hybrid Cryptographic File Encryption System

A secure, open-source file encryption system built in Python that combines the unmatched speed of AES-256 symmetric encryption with the robust security of RSA-3072 asymmetric key cryptography. 

This project includes a fully-featured modern Desktop GUI, built using `customtkinter`, allowing users to easily generate keys, encrypt files, and decrypt them securely.

## Features

- **Hybrid Cryptography**: Uses AES-256 (GCM Mode) for fast data encryption and RSA-3072 to securely encrypt the AES key.
- **Data Integrity**: AES-GCM automatically provides a mathematical authentication tag. If an encrypted file is tampered with by a malicious actor, the system will immediately reject it during decryption.
- **Modern Desktop UI**: A sleek, dark-themed graphical interface for ease of use.
- **Completely Local**: Keys are generated and stored locally on your machine. Your private key never leaves your device.


<img width="740" height="586" alt="image" src="https://github.com/user-attachments/assets/eb01d9a9-0655-44f9-ba33-40f67261d85f" />



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
1. Generate your RSA-3072 key pair (`private.pem` and `public.pem`).
2. Select any file from your computer and encrypt it into an `.enc` file.
3. Select an encrypted `.enc` file to securely decrypt and restore it.

### Automated Demo / CLI Validation
To run the automated test script which proves the system's correctness and simulates a tampering attack:
```bash
python demo.py
```

## Security Warning
- **NEVER** share your `private.pem` file. Anyone with access to your private key can decrypt your files.
- The `.gitignore` in this project is specifically configured to prevent accidentally committing `.pem` files to version control. Do not override this behavior.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
