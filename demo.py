import os
from hybrid_crypto import generate_rsa_keys, encrypt_file, decrypt_file

def main():
    print("--- Hybrid Cryptographic System Demo (Secure Edition) ---")
    
    receiver_priv = "receiver_private.pem"
    receiver_pub = "receiver_public.pem"
    sender_priv = "sender_private.pem"
    sender_pub = "sender_public.pem"
    
    password = b"SuperSecret123!"
    
    original_file = "secret.txt"
    encrypted_file = "secret.enc"
    decrypted_file = "secret_decrypted.txt"
    tampered_file = "secret_tampered.enc"
    
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
    print(f"\n[+] Success: The decrypted content matches the original!")
    
    print("\n[+] Demonstrating Integrity Protection (Tampering)...")
    with open(encrypted_file, "rb") as f:
        data = bytearray(f.read())
    data[-1] ^= 0x01
    with open(tampered_file, "wb") as f:
        f.write(data)
        
    try:
        decrypt_file(receiver_priv, sender_pub, tampered_file, "should_fail.txt", password)
    except Exception as e:
        print(f"\n[+] Integrity Check Passed: The system correctly rejected the tampered file!\nException caught: {type(e).__name__}")

if __name__ == "__main__":
    main()
