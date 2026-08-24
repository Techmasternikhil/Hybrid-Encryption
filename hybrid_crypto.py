import os
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

def generate_rsa_keys(private_key_path="private.pem", public_key_path="public.pem"):
    """Generates an RSA-3072 key pair and saves them to disk."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    
    # Save the private key
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    # Save the public key
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"[*] Generated RSA-3072 key pair: {private_key_path}, {public_key_path}")

def encrypt_file(public_key_path, input_file_path, output_file_path):
    """Encrypts a file using AES-256 GCM and secures the AES key with RSA-3072."""
    
    # Load the public key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
        
    # 1. Generate a random AES-256 symmetric key (32 bytes)
    aes_key = os.urandom(32)
    
    # 2. Encrypt the file data using AES-256 in GCM mode
    nonce = os.urandom(12) # GCM standard nonce length is 12 bytes
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    
    with open(input_file_path, "rb") as f:
        plaintext = f.read()
        
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag # 16 bytes authentication tag
    
    # 3. Encrypt the AES key using RSA-3072 public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 4. Package everything into the output file
    # Format:
    # [2 bytes: len(encrypted_aes_key)] -> to know how many bytes to read for the RSA ciphertext
    # [encrypted_aes_key]
    # [12 bytes: nonce]
    # [16 bytes: tag]
    # [ciphertext]
    with open(output_file_path, "wb") as f:
        # Pack the length of the encrypted key as an unsigned short (2 bytes)
        f.write(struct.pack(">H", len(encrypted_aes_key)))
        f.write(encrypted_aes_key)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)
        
    print(f"[*] Encrypted {input_file_path} to {output_file_path} securely.")

def decrypt_file(private_key_path, input_file_path, output_file_path):
    """Decrypts a file using RSA-3072 to retrieve the AES key, then AES-256 GCM for data."""
    
    # Load the private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
        
    # Read and unpack the input file components
    with open(input_file_path, "rb") as f:
        # Read the first 2 bytes to get the length of the encrypted AES key
        enc_key_len_bytes = f.read(2)
        if not enc_key_len_bytes:
            raise ValueError("File is empty or corrupted.")
        
        enc_key_len = struct.unpack(">H", enc_key_len_bytes)[0]
        
        # Read components based on their known lengths
        encrypted_aes_key = f.read(enc_key_len)
        nonce = f.read(12)
        tag = f.read(16)
        ciphertext = f.read() # The rest of the file is ciphertext
        
    # 1. Decrypt the AES key using RSA-3072 private key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 2. Decrypt the file data using AES-256 GCM
    # If the file was tampered with, the cipher will raise an InvalidTag exception here during finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        print("[!] ERROR: Integrity verification failed! The file has been tampered with or corrupted.")
        raise
        
    with open(output_file_path, "wb") as f:
        f.write(plaintext)
        
    print(f"[*] Decrypted {input_file_path} to {output_file_path} successfully (Integrity Verified).")
