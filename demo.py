import os
import sys
from hybrid_crypto import generate_rsa_keys, encrypt_file, decrypt_file, force_remove

# MED-02 Fix: All generated files tracked for guaranteed cleanup
_GENERATED_FILES = []

def _register(*files):
    """Register files for cleanup at the end of the demo."""
    _GENERATED_FILES.extend(files)

def _cleanup():
    """Remove all generated files, using force_remove to handle ACL-restricted PEM files.
    
    R2-MED-03 Fix: Uses force_remove() which resets NTFS ACLs before deletion,
    preventing silent cleanup failures on Windows where _set_private_key_permissions()
    has restricted the PEM files.
    """
    for f in _GENERATED_FILES:
        try:
            force_remove(f)
        except Exception:
            pass

def main():
    print("--- Hybrid Cryptographic System Demo (Secure Edition) ---")
    
    receiver_priv = "demo_receiver_private.pem"
    receiver_pub = "demo_receiver_public.pem"
    sender_priv = "demo_sender_private.pem"
    sender_pub = "demo_sender_public.pem"
    
    # MED-02 Fix: Read password from environment variable, fall back to a demo-only default.
    # In production, NEVER hardcode passwords. Set DEMO_PASSWORD env var to override.
    password_str = os.environ.get("DEMO_PASSWORD", "DemoOnly!Pwd123")
    password = password_str.encode("utf-8")
    
    original_file = "demo_secret.txt"
    encrypted_file = "demo_secret.enc"
    decrypted_file = "demo_secret_decrypted.txt"
    tampered_file = "demo_secret_tampered.enc"
    
    # Register all files for cleanup
    _register(
        receiver_priv, receiver_pub, sender_priv, sender_pub,
        original_file, encrypted_file, decrypted_file, tampered_file,
        "should_fail.txt"
    )
    
    try:
        print("\n[+] Creating sample file...")
        with open(original_file, "w") as f:
            f.write("This is highly confidential data.\nIt must be protected by AES-256 and RSA-3072.")
            
        print("\n[+] Generating Receiver RSA Keys...")
        generate_rsa_keys(receiver_priv, receiver_pub, password)
        
        print("\n[+] Generating Sender RSA Keys...")
        generate_rsa_keys(sender_priv, sender_pub, password)
        
        print("\n[+] Encrypting and Signing the file...")
        encrypt_file(receiver_pub, sender_priv, original_file, encrypted_file, password)
        
        print("\n[+] Decrypting and Verifying the file...")
        decrypt_file(receiver_priv, sender_pub, encrypted_file, decrypted_file, password)
        
        with open(decrypted_file, "r") as f:
            content = f.read()
        
        with open(original_file, "r") as f:
            original_content = f.read()
        
        if content == original_content:
            print(f"\n[+] Success: The decrypted content matches the original!")
        else:
            print(f"\n[-] FAILURE: Decrypted content does NOT match the original!")
            sys.exit(1)
        
        print("\n[+] Demonstrating Integrity Protection (Tampering)...")
        with open(encrypted_file, "rb") as f:
            data = bytearray(f.read())
        data[-1] ^= 0x01
        with open(tampered_file, "wb") as f:
            f.write(data)
            
        try:
            decrypt_file(receiver_priv, sender_pub, tampered_file, "should_fail.txt", password)
            print("\n[-] FAILURE: The system accepted a tampered file!")
            sys.exit(1)
        except Exception as e:
            print(f"\n[+] Integrity Check Passed: The system correctly rejected the tampered file!\nException caught: {type(e).__name__}")
        
        print("\n--- Demo completed successfully! ---")
        
    finally:
        # MED-02 Fix: Always clean up generated files
        print("\n[+] Cleaning up demo files...")
        _cleanup()
        print("[+] Cleanup complete.")

if __name__ == "__main__":
    main()
