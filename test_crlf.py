import os
from hybrid_crypto import generate_rsa_keys, encrypt_file, decrypt_file

def main():
    generate_rsa_keys("alice_priv.pem", "alice_pub.pem")
    generate_rsa_keys("bob_priv.pem", "bob_pub.pem")
    
    # Simulate Bob's pub key having CRLF (e.g. downloaded on Windows)
    with open("bob_pub.pem", "rb") as f:
        bob_pub_content = f.read()
    
    with open("bob_pub_crlf.pem", "wb") as f:
        f.write(bob_pub_content.replace(b"\n", b"\r\n"))
        
    with open("secret.txt", "wb") as f:
        f.write(b"Hello world")
        
    print("Encrypting using bob_pub_crlf.pem...")
    encrypt_file("bob_pub_crlf.pem", "alice_priv.pem", "secret.txt", "secret.enc")
    
    print("Decrypting using bob_priv.pem...")
    try:
        decrypt_file("bob_priv.pem", "alice_pub.pem", "secret.enc", "secret_dec.txt")
        print("Success!")
    except Exception as e:
        print(f"FAILED: {type(e).__name__} - {str(e)}")

if __name__ == "__main__":
    main()
