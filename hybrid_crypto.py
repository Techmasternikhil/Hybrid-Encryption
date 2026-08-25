import os
import struct
import uuid
import time
import tempfile
import shutil
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag, InvalidSignature

MAGIC = b"HYB1"
CHUNK_SIZE = 65536

def secure_delete(filepath):
    """Securely overwrites a file with zeros before unlinking it from the filesystem."""
    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, "r+b") as f:
            f.write(b"\x00" * file_size)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    finally:
        try:
            os.remove(filepath)
        except OSError:
            pass

def generate_rsa_keys(private_key_path="private.pem", public_key_path="public.pem", password=None):
    """Generates an RSA-3072 key pair and saves them to disk securely."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    
    enc_alg = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()

    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_alg
        ))
    
    # Round 4 Fix: Secure file permissions
    try:
        os.chmod(private_key_path, 0o600)
    except AttributeError:
        pass # Handle Windows/non-POSIX environments gracefully
        
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"[*] Generated RSA-3072 key pair: {private_key_path}, {public_key_path}")

def encrypt_file(receiver_pub_key_path, sender_priv_key_path, input_file_path, output_file_path, sender_password=None):
    """Encrypts a file (AES-GCM), secures AES key (RSA-OAEP), and signs it (RSA-PSS)."""
    
    with open(receiver_pub_key_path, "rb") as f:
        receiver_pub_key_bytes = f.read()
        receiver_pub_key = serialization.load_pem_public_key(receiver_pub_key_bytes)
        
    with open(sender_priv_key_path, "rb") as f:
        sender_priv_key = serialization.load_pem_private_key(f.read(), password=sender_password)

    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    
    encrypted_aes_key = receiver_pub_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    hasher = hashes.Hash(hashes.SHA256())
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    
    # Round 7 Fix: Write temp file to OS secure local temp dir to prevent network leakage
    temp_cipher_path = os.path.join(tempfile.gettempdir(), uuid.uuid4().hex + ".tmp")
    try:
        with open(input_file_path, "rb") as f_in, open(temp_cipher_path, "wb") as f_out:
            # Round 3 Fix: Prepend creation timestamp to plaintext payload (8 bytes double float)
            timestamp_bytes = struct.pack(">d", time.time())
            hasher.update(timestamp_bytes)
            f_out.write(encryptor.update(timestamp_bytes))
            
            while chunk := f_in.read(CHUNK_SIZE):
                hasher.update(chunk)
                f_out.write(encryptor.update(chunk))
            f_out.write(encryptor.finalize())
            
        tag = encryptor.tag
        file_hash = hasher.finalize()
        
        # Surreptitious Forwarding Fix: Sign the file hash + receiver pub key + encrypted AES key
        # Round 4 Fix: Prepend the length of the variable-length public key to prevent ambiguous concatenation
        pub_key_len = struct.pack(">H", len(receiver_pub_key_bytes))
        signature_payload = file_hash + pub_key_len + receiver_pub_key_bytes + encrypted_aes_key
        
        signature = sender_priv_key.sign(
            signature_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        with open(output_file_path, "wb") as f_out:
            f_out.write(MAGIC)
            f_out.write(struct.pack(">H", len(encrypted_aes_key)))
            f_out.write(encrypted_aes_key)
            f_out.write(nonce)
            f_out.write(struct.pack(">H", len(signature)))
            f_out.write(signature)
            
            with open(temp_cipher_path, "rb") as f_tmp:
                while chunk := f_tmp.read(CHUNK_SIZE):
                    f_out.write(chunk)
                    
            f_out.write(tag)
    finally:
        if os.path.exists(temp_cipher_path):
            secure_delete(temp_cipher_path)
            
    print(f"[*] Encrypted and signed {input_file_path} to {output_file_path} securely.")

def decrypt_file(receiver_priv_key_path, sender_pub_key_path, input_file_path, output_file_path, receiver_password=None):
    """Decrypts a file, verifies its digital signature and integrity tag, and returns creation timestamp."""
    
    with open(receiver_priv_key_path, "rb") as f:
        receiver_priv_key = serialization.load_pem_private_key(f.read(), password=receiver_password)
        
    receiver_pub_key_bytes = receiver_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
        
    with open(sender_pub_key_path, "rb") as f:
        sender_pub_key = serialization.load_pem_public_key(f.read())
        
    file_size = os.path.getsize(input_file_path)
    
    with open(input_file_path, "rb") as f_in:
        if f_in.read(4) != MAGIC:
            raise ValueError("Invalid file format: Missing HYB1 magic header.")
            
        enc_key_len = struct.unpack(">H", f_in.read(2))[0]
        assert enc_key_len == 384, f"Invalid RSA ciphertext length: {enc_key_len}"
        encrypted_aes_key = f_in.read(enc_key_len)
        
        nonce = f_in.read(12)
        
        sig_len = struct.unpack(">H", f_in.read(2))[0]
        assert sig_len == 384, f"Invalid RSA signature length: {sig_len}"
        signature = f_in.read(sig_len)
        
        header_size = 4 + 2 + 384 + 12 + 2 + 384
        ciphertext_len = file_size - header_size - 16
        if ciphertext_len < 0:
            raise ValueError("File is corrupted or too small.")
            
        aes_key = receiver_priv_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        
        f_in.seek(-16, os.SEEK_END)
        tag = f_in.read(16)
        
        f_in.seek(header_size)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        hasher = hashes.Hash(hashes.SHA256())
        
        # Round 7 Fix: Write temp file to OS secure local temp dir
        temp_dec_path = os.path.join(tempfile.gettempdir(), uuid.uuid4().hex + ".tmp")
        bytes_read = 0
        timestamp = None
        
        try:
            with open(temp_dec_path, "wb") as f_out:
                buffered_decrypted_data = b""
                
                while bytes_read < ciphertext_len:
                    chunk_size = min(CHUNK_SIZE, ciphertext_len - bytes_read)
                    chunk = f_in.read(chunk_size)
                    
                    if not chunk:
                        raise ValueError("File truncated unexpectedly during decryption.")
                        
                    decrypted_chunk = decryptor.update(chunk)
                    hasher.update(decrypted_chunk)
                    bytes_read += len(chunk)
                    
                    if timestamp is None:
                        buffered_decrypted_data += decrypted_chunk
                        if len(buffered_decrypted_data) >= 8:
                            timestamp_bytes = buffered_decrypted_data[:8]
                            timestamp = struct.unpack(">d", timestamp_bytes)[0]
                            f_out.write(buffered_decrypted_data[8:])
                            buffered_decrypted_data = None
                    else:
                        f_out.write(decrypted_chunk)
                        
                final_chunk = decryptor.finalize()
                hasher.update(final_chunk)
                
                if timestamp is None:
                    buffered_decrypted_data += final_chunk
                    if len(buffered_decrypted_data) >= 8:
                        timestamp_bytes = buffered_decrypted_data[:8]
                        timestamp = struct.unpack(">d", timestamp_bytes)[0]
                        f_out.write(buffered_decrypted_data[8:])
                    else:
                        raise ValueError("File is corrupted or missing timestamp.")
                else:
                    f_out.write(final_chunk)
                
            file_hash = hasher.finalize()
            
            # Round 4 Fix: Must match the new signature payload formatting
            pub_key_len = struct.pack(">H", len(receiver_pub_key_bytes))
            signature_payload = file_hash + pub_key_len + receiver_pub_key_bytes + encrypted_aes_key
            
            sender_pub_key.verify(
                signature,
                signature_payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            
            # Use shutil.move to support cross-device/network-drive moving
            shutil.move(temp_dec_path, output_file_path)
            
        finally:
            if os.path.exists(temp_dec_path):
                secure_delete(temp_dec_path)
                
    print(f"[*] Decrypted and verified {input_file_path} to {output_file_path} successfully.")
    return timestamp
