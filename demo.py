import os
from hybrid_crypto import generate_rsa_keys, encrypt_file, decrypt_file

def main():
    print("--- Hybrid Cryptographic File Encryption System Demo ---")
    
    # Files
    private_key_path = "private.pem"
    public_key_path = "public.pem"
    original_file = "secret.txt"
    encrypted_file = "secret.enc"
    decrypted_file = "secret_decrypted.txt"
    tampered_file = "secret_tampered.enc"
    
    # 1. Create a sample file
    print("\n[+] Creating sample file...")
    with open(original_file, "w") as f:
        f.write("This is highly confidential data.\nIt must be protected by AES-256 and RSA-3072.")
    print(f"Created '{original_file}' with secret content.")
    
    # 2. Generate RSA keys
    print("\n[+] Generating RSA Keys...")
    generate_rsa_keys(private_key_path, public_key_path)
    
    # 3. Encrypt the file
    print("\n[+] Encrypting the file...")
    encrypt_file(public_key_path, original_file, encrypted_file)
    
    # 4. Decrypt the file
    print("\n[+] Decrypting the file...")
    decrypt_file(private_key_path, encrypted_file, decrypted_file)
    
    # Verify content
    with open(decrypted_file, "r") as f:
        content = f.read()
    print(f"\n[+] Decrypted content:\n{content}")
    print("\n[+] Success: The decrypted content matches the original!")
    
    # 5. Tampering demonstration
    print("\n[+] Demonstrating Integrity Protection (Tampering)...")
    # Copy the encrypted file to a tampered file and change one byte in the ciphertext
    with open(encrypted_file, "rb") as f:
        data = bytearray(f.read())
        
    # Tamper with the very last byte (part of ciphertext)
    data[-1] ^= 0x01
    
    with open(tampered_file, "wb") as f:
        f.write(data)
        
    print("Tampered with the encrypted file (flipped one bit). Attempting decryption...")
    try:
        decrypt_file(private_key_path, tampered_file, "should_fail.txt")
    except Exception as e:
        print(f"\n[+] Integrity Check Passed: The system correctly rejected the tampered file!\nException caught: {type(e).__name__}")
        
if __name__ == "__main__":
    main()
