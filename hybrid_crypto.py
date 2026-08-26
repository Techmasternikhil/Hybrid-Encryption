import os
import sys
import struct
import time
import hmac
import ctypes
import tempfile
import shutil
import subprocess
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag, InvalidSignature

# --- File Format Constants ---
# Format v3: MAGIC(4) + VERSION(2) + KeyLen(2) + EncKey(var) + Nonce(12) + SigLen(2) + Signature(var) + Ciphertext(...) + Tag(16)
# v3 change: Signature now covers header fields AND a SHA-256 hash of the ciphertext stream,
# restoring content binding while preserving early (pre-decryption) verification.
MAGIC = b"HYB1"
FORMAT_VERSION = 3
CHUNK_SIZE = 65536

# MED-04: NIST SP 800-38D recommends AES-GCM plaintext must not exceed 2^39 - 256 bits (~64 GiB)
MAX_GCM_PLAINTEXT_BYTES = (2**39 - 256) // 8  # ~68,719,476,704 bytes (~64 GiB)

logger = logging.getLogger("hybrid_crypto")


def _zero_bytearray(ba):
    """Securely zero a bytearray using ctypes.memset.

    Python's garbage collector does not guarantee when memory is freed, and
    bytearray contents may linger in process memory. ctypes.memset overwrites
    the buffer's internal C-level memory directly.

    LIMITATION: The `cryptography` library internally copies key material into
    OpenSSL's C heap when constructing Cipher objects. That copy is outside
    Python's control and cannot be zeroed from userland. This function only
    covers the Python-side buffer.
    """
    if ba and isinstance(ba, bytearray) and len(ba) > 0:
        try:
            ctypes.memset((ctypes.c_char * len(ba)).from_buffer(ba), 0, len(ba))
        except (TypeError, ValueError):
            # Fallback: manual zeroing if ctypes fails (e.g., buffer is read-only)
            for i in range(len(ba)):
                ba[i] = 0


def _zero_bytes(b):
    """R8-CRIT-01 Fix: Forcefully zero an immutable bytes object in CPython memory.
    
    WARNING: This relies on CPython internals (PyBytesObject struct layout).
    It bypasses Python's immutability guarantees. Use ONLY for highly sensitive
    keys (like 32-byte AES keys) that are guaranteed not to be interned or cached 
    by the interpreter.
    """
    if b and isinstance(b, bytes) and len(b) > 0:
        try:
            # sys.getsizeof(b"") returns the size of an empty bytes object struct
            # which includes the null terminator. The data array starts 1 byte earlier.
            offset = sys.getsizeof(b"") - 1
            ctypes.memset(id(b) + offset, 0, len(b))
        except Exception:
            pass


def _get_current_username():
    """R2-HIGH-01 Fix: Get the current Windows username via Win32 API instead of
    the user-controlled USERNAME environment variable.

    Falls back to os.getlogin() on non-Windows or if the Win32 call fails.
    """
    if sys.platform == "win32":
        try:
            buf = ctypes.create_unicode_buffer(256)
            size = ctypes.c_ulong(256)
            if ctypes.windll.advapi32.GetUserNameW(buf, ctypes.byref(size)):
                return buf.value
        except Exception:
            pass
    # Fallback for non-Windows or Win32 API failure
    try:
        return os.getlogin()
    except OSError:
        return None


def _set_private_key_permissions(filepath):
    """Set restrictive file permissions using platform-appropriate mechanisms.

    On Windows, os.chmod only toggles the read-only flag and does NOT set NTFS ACLs.
    We use icacls to strip inherited permissions and grant access only to the current user.
    On POSIX systems, we use os.chmod(0o600) as expected.
    """
    if sys.platform == "win32":
        try:
            # R2-HIGH-01 Fix: Use Win32 API instead of env var for username
            username = _get_current_username()
            if username:
                subprocess.run(
                    ['icacls', filepath, '/inheritance:r',
                     '/grant:r', f'{username}:(R,W)'],
                    check=True, capture_output=True, timeout=10
                )
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"Could not set NTFS ACLs on {filepath}: {e}")
    else:
        try:
            os.chmod(filepath, 0o600)
        except OSError as e:
            logger.warning(f"Could not set POSIX permissions on {filepath}: {e}")


def best_effort_delete(filepath):
    """Best-effort file deletion with zero-overwrite.

    SECURITY LIMITATIONS:
    - SSDs: Wear-leveling remaps logical blocks. Original data may persist in unmapped
      NAND cells even after overwrite. fsync guarantees new data is flushed, NOT that
      old data is erased from the physical medium.
    - Copy-on-Write filesystems (NTFS w/ compression, BTRFS, ZFS): Writes go to new
      blocks; old blocks are freed but not zeroed.
    - Cloud/Network drives: Snapshots and replication may retain old data indefinitely.
    - Windows NTFS: The OS may re-order writes, and disk firmware may cache/defer
      the actual sector overwrite.

    For true secure deletion on SSDs, use full-disk encryption (BitLocker/LUKS) so that
    file-level deletion is irrelevant. This function provides defense-in-depth only.
    """
    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, "r+b") as f:
            bytes_written = 0
            zero_chunk = b"\x00" * CHUNK_SIZE
            while bytes_written < file_size:
                chunk_to_write = min(CHUNK_SIZE, file_size - bytes_written)
                f.write(zero_chunk[:chunk_to_write])
                bytes_written += chunk_to_write
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    finally:
        try:
            os.remove(filepath)
        except OSError:
            pass

# Backward-compatible alias (deprecated)
secure_delete = best_effort_delete


def force_remove(filepath):
    """Remove a file, resetting NTFS ACLs first if needed on Windows.

    Shared utility for cleanup in demos/tests where ACL-restricted PEM files
    would otherwise cause PermissionError with bare os.remove().
    """
    if not os.path.exists(filepath):
        return
    try:
        os.remove(filepath)
    # R5-LOW-01 Fix: Catch FileNotFoundError to prevent TOCTOU crash if file is deleted concurrently
    except FileNotFoundError:
        pass
    except PermissionError:
        if sys.platform == "win32":
            try:
                subprocess.run(
                    ['icacls', filepath, '/reset'],
                    check=True, capture_output=True, timeout=10
                )
                os.remove(filepath)
            except Exception:
                pass
        else:
            raise


def generate_rsa_keys(private_key_path="private.pem", public_key_path="public.pem", password=None):
    """Generates an RSA-3072 key pair and saves them to disk securely."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    enc_alg = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()

    # Write private key securely to temp file, then move atomically
    out_dir = os.path.dirname(private_key_path) or "."
    
    # R5-LOW-02 Fix: Use try...finally to delete orphaned temp files if serialization fails
    temp_key_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, dir=out_dir, prefix=".hybrid_key_") as temp_key_file:
            temp_key_path = temp_key_file.name
            temp_key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=enc_alg
            ))
        shutil.move(temp_key_path, private_key_path)
        temp_key_path = None  # Clear so it's not deleted in finally block
    finally:
        if temp_key_path and os.path.exists(temp_key_path):
            os.remove(temp_key_path)

    _set_private_key_permissions(private_key_path)

    public_key = private_key.public_key()
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    # R2-LOW-02 Fix: Use logger instead of print to avoid leaking paths to stdout
    logger.info(f"Generated RSA-3072 key pair: {private_key_path}, {public_key_path}")


def encrypt_file(receiver_pub_key_path, sender_priv_key_path, input_file_path, output_file_path, sender_password=None):
    """Encrypts a file (AES-GCM), secures AES key (RSA-OAEP), and signs it (RSA-PSS).

    File format v3:
        MAGIC (4 bytes) | VERSION (2 bytes) | KeyLen (2 bytes) | EncKey (KeyLen bytes)
        | Nonce (12 bytes) | SigLen (2 bytes) | Signature (SigLen bytes)
        | GCM-Ciphertext (variable) | GCM-Tag (16 bytes)

    R2-CRIT-03 Fix: The signature covers header-level fields AND a SHA-256 hash of the
    ciphertext stream. This provides:
    - Early verification: receiver can hash raw ciphertext bytes (no decryption needed)
      and verify the signature BEFORE any AES decryption → eliminates DoS attack.
    - Content binding: the ciphertext hash ties the signature to specific encrypted
      content → an attacker who compromises the AES key cannot swap the ciphertext
      without invalidating the signature.

    Timestamp caveat: The embedded timestamp is SENDER-ASSERTED and NOT externally
    verified. It does NOT prevent replay attacks.
    """

    # R4-HIGH-01 Fix: Enforce AES-GCM plaintext size limit dynamically during reading
    # to prevent TOCTOU bypasses if the file grows during encryption.
    input_file_size = os.path.getsize(input_file_path)
    if input_file_size > MAX_GCM_PLAINTEXT_BYTES:
        raise ValueError(
            f"Input file is {input_file_size:,} bytes, which exceeds the AES-GCM maximum "
            f"plaintext limit of {MAX_GCM_PLAINTEXT_BYTES:,} bytes (~64 GiB) per NIST SP 800-38D. "
            f"Split the file into smaller chunks before encrypting."
        )

    # R4-CRIT-01 Fix: Limit key file reads to 16KB to prevent Memory OOM DoS
    with open(receiver_pub_key_path, "rb") as f:
        pub_bytes = f.read(16384)
        if f.read(1):
            raise ValueError("Receiver public key file is suspiciously large (exceeds 16KB).")
        receiver_pub_key = serialization.load_pem_public_key(pub_bytes)
        
    # R3-CRIT-01 Fix: Re-serialize the public key to ensure consistent formatting 
    # (e.g. LF instead of CRLF) for the signature payload, matching what decrypt_file generates.
    receiver_pub_key_bytes = receiver_pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(sender_priv_key_path, "rb") as f:
        priv_bytes = f.read(16384)
        if f.read(1):
            raise ValueError("Sender private key file is suspiciously large (exceeds 16KB).")
        sender_priv_key = serialization.load_pem_private_key(priv_bytes, password=sender_password)

    # R2-CRIT-01 Fix: Use bytearray for AES key so it can be zeroed after use.
    # LIMITATION: The cryptography library copies this into OpenSSL's C heap internally.
    # We can only zero the Python-side buffer.
    aes_key = bytearray(os.urandom(32))
    nonce = os.urandom(12)

    # R3-HIGH-01 Fix: Use target directory for temp files to ensure atomic renames
    out_dir = os.path.dirname(output_file_path) or "."
    # R9-CRIT-01 Fix: Create and maintain an open file descriptor
    temp_cipher_file = tempfile.NamedTemporaryFile(delete=False, dir=out_dir, prefix=".hybrid_enc_")
    temp_cipher_path = temp_cipher_file.name

    temp_out_file = None
    temp_out_path = None

    try:
        # R8-CRIT-01 Fix: Capture the immutable bytes copy and forcefully zero it
        raw_aes_key = bytes(aes_key)
        try:
            encrypted_aes_key = receiver_pub_key.encrypt(
                raw_aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            cipher = Cipher(algorithms.AES(raw_aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
        finally:
            _zero_bytes(raw_aes_key)

        # R2-CRIT-03: Compute ciphertext hash while streaming encrypted output
        ciphertext_hasher = hashes.Hash(hashes.SHA256())

        with open(input_file_path, "rb") as f_in:
            # Prepend creation timestamp to plaintext payload (8 bytes double float)
            timestamp_bytes = struct.pack(">d", time.time())
            enc_ts = encryptor.update(timestamp_bytes)
            ciphertext_hasher.update(enc_ts)
            temp_cipher_file.write(enc_ts)

            total_bytes_read = 0
            while chunk := f_in.read(CHUNK_SIZE):
                # R4-HIGH-01 Fix: Dynamic TOCTOU limit check
                total_bytes_read += len(chunk)
                if total_bytes_read > MAX_GCM_PLAINTEXT_BYTES:
                    raise ValueError("File grew during encryption and exceeds the AES-GCM 64 GiB limit.")
                
                enc_chunk = encryptor.update(chunk)
                ciphertext_hasher.update(enc_chunk)
                temp_cipher_file.write(enc_chunk)

            final_enc = encryptor.finalize()
            ciphertext_hasher.update(final_enc)
            temp_cipher_file.write(final_enc)
            
        # R9-CRIT-01 Fix: Flush and rewind instead of closing to prevent TOCTOU symlink attack
        temp_cipher_file.flush()
        temp_cipher_file.seek(0)

        tag = encryptor.tag
        ciphertext_hash = ciphertext_hasher.finalize()

        # R2-CRIT-03 Fix: Sign header fields + ciphertext hash for both early verification
        # and content binding. Surreptitious Forwarding Fix: includes receiver's public key.
        pub_key_len = struct.pack(">H", len(receiver_pub_key_bytes))
        signature_payload = encrypted_aes_key + nonce + pub_key_len + receiver_pub_key_bytes + ciphertext_hash

        signature = sender_priv_key.sign(
            signature_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # R6-CRIT-01 Fix: Write final assembled file to a temp file first, then atomically rename
        # R9-CRIT-01 Fix: Use the file descriptor directly and close only before rename
        temp_out_file = tempfile.NamedTemporaryFile(delete=False, dir=out_dir, prefix=".hybrid_out_")
        temp_out_path = temp_out_file.name
        
        temp_out_file.write(MAGIC)
        temp_out_file.write(struct.pack(">H", FORMAT_VERSION))
        temp_out_file.write(struct.pack(">H", len(encrypted_aes_key)))
        temp_out_file.write(encrypted_aes_key)
        temp_out_file.write(nonce)
        temp_out_file.write(struct.pack(">H", len(signature)))
        temp_out_file.write(signature)

        while chunk := temp_cipher_file.read(CHUNK_SIZE):
            temp_out_file.write(chunk)

        temp_out_file.write(tag)
        
        # Close descriptors before Windows allows atomic move
        temp_out_file.close()
        temp_cipher_file.close()
            
        shutil.move(temp_out_path, output_file_path)
        temp_out_path = None  # Clear so it's not deleted in finally block
    finally:
        # R2-CRIT-01 Fix: Zero the AES key material
        _zero_bytearray(aes_key)
        if 'temp_cipher_file' in locals() and not temp_cipher_file.closed:
            try: temp_cipher_file.close()
            except Exception: pass
        if temp_out_file and not temp_out_file.closed:
            try: temp_out_file.close()
            except Exception: pass
        
        if os.path.exists(temp_cipher_path):
            best_effort_delete(temp_cipher_path)
        if temp_out_path and os.path.exists(temp_out_path):
            os.remove(temp_out_path)

    logger.info(f"Encrypted and signed {input_file_path} -> {output_file_path}")


def decrypt_file(receiver_priv_key_path, sender_pub_key_path, input_file_path, output_file_path, receiver_password=None):
    """Decrypts a file, verifies its digital signature and integrity tag, and returns creation timestamp.

    R2-CRIT-03 Fix: The signature is verified BEFORE any AES decryption by hashing the
    raw ciphertext bytes (no decryption needed) and verifying against the signed payload.
    This provides both DoS protection (early rejection) and content binding (signature
    is tied to the specific ciphertext).
    """

    # R4-CRIT-01 Fix: Limit key file reads to 16KB to prevent Memory OOM DoS
    with open(receiver_priv_key_path, "rb") as f:
        priv_bytes = f.read(16384)
        if f.read(1):
            raise ValueError("Receiver private key file is suspiciously large (exceeds 16KB).")
        receiver_priv_key = serialization.load_pem_private_key(priv_bytes, password=receiver_password)

    receiver_pub_key_bytes = receiver_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(sender_pub_key_path, "rb") as f:
        pub_bytes = f.read(16384)
        if f.read(1):
            raise ValueError("Sender public key file is suspiciously large (exceeds 16KB).")
        sender_pub_key = serialization.load_pem_public_key(pub_bytes)

    file_size = os.path.getsize(input_file_path)

    if file_size < 6:  # MAGIC(4) + VERSION(2) minimum
        raise ValueError("File is too small to be a valid encrypted file. It may be corrupted or truncated.")

    with open(input_file_path, "rb") as f_in:
        # R2-LOW-01 Fix: Use constant-time comparison for magic bytes
        file_magic = f_in.read(4)
        if not hmac.compare_digest(file_magic, MAGIC):
            raise ValueError("Invalid file format: Missing HYB1 magic header.")

        version = struct.unpack(">H", f_in.read(2))[0]
        if version != FORMAT_VERSION:
            raise ValueError(
                f"Unsupported file format version: {version}. "
                f"This software supports version {FORMAT_VERSION}."
            )

        enc_key_len = struct.unpack(">H", f_in.read(2))[0]
        if enc_key_len != 384:
            raise ValueError(f"Invalid RSA ciphertext length: {enc_key_len}. Expected 384 bytes for RSA-3072.")
        encrypted_aes_key = f_in.read(enc_key_len)

        nonce = f_in.read(12)

        sig_len = struct.unpack(">H", f_in.read(2))[0]
        if sig_len != 384:
            raise ValueError(f"Invalid RSA signature length: {sig_len}. Expected 384 bytes for RSA-3072.")
        signature = f_in.read(sig_len)

        # Compute header_size dynamically from parsed field lengths
        header_size = 4 + 2 + 2 + enc_key_len + 12 + 2 + sig_len

        if file_size < header_size + 16:
            raise ValueError("File is too small to be a valid encrypted file. It may be corrupted or truncated.")

        ciphertext_len = file_size - header_size - 16
        
        # R5-CRIT-01 Fix: Enforce AES-GCM 64 GiB limit before starting expensive hash operations
        # The +8 accounts for the timestamp embedded in the ciphertext
        if ciphertext_len > MAX_GCM_PLAINTEXT_BYTES + 8:
            raise ValueError(f"Encrypted file is {ciphertext_len:,} bytes, which exceeds the AES-GCM maximum limit.")

        # R2-CRIT-03 Fix: Hash the raw ciphertext bytes WITHOUT decryption for
        # early signature verification with content binding.
        ciphertext_hasher = hashes.Hash(hashes.SHA256())
        f_in.seek(header_size)
        bytes_hashed = 0
        while bytes_hashed < ciphertext_len:
            hash_chunk_size = min(CHUNK_SIZE, ciphertext_len - bytes_hashed)
            hash_chunk = f_in.read(hash_chunk_size)
            if not hash_chunk:
                raise ValueError("File truncated unexpectedly during signature verification.")
            ciphertext_hasher.update(hash_chunk)
            bytes_hashed += len(hash_chunk)
        ciphertext_hash = ciphertext_hasher.finalize()

        # Verify signature: covers header fields + ciphertext hash
        pub_key_len = struct.pack(">H", len(receiver_pub_key_bytes))
        signature_payload = encrypted_aes_key + nonce + pub_key_len + receiver_pub_key_bytes + ciphertext_hash

        # This raises InvalidSignature if sender is not who they claim, or if
        # the ciphertext has been modified in any way.
        sender_pub_key.verify(
            signature,
            signature_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # R8-CRIT-01 Fix: Zero the immutable bytes returned by decrypt()
        raw_decrypted_key = receiver_priv_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        try:
            aes_key = bytearray(raw_decrypted_key)
        finally:
            _zero_bytes(raw_decrypted_key)

        f_in.seek(-16, os.SEEK_END)
        tag = f_in.read(16)

        f_in.seek(header_size)
        cipher = Cipher(algorithms.AES(bytes(aes_key)), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()

        # R3-HIGH-01 Fix: Use target directory for temp file to ensure atomic renames
        # R9-CRIT-01 Fix: Keep the descriptor open to prevent Arbitrary File Overwrite
        out_dir = os.path.dirname(output_file_path) or "."
        temp_dec_file = tempfile.NamedTemporaryFile(delete=False, dir=out_dir, prefix=".hybrid_dec_")
        temp_dec_path = temp_dec_file.name

        bytes_read = 0
        timestamp = None

        try:
            buffered_decrypted_data = b""

            while bytes_read < ciphertext_len:
                chunk_size = min(CHUNK_SIZE, ciphertext_len - bytes_read)
                chunk = f_in.read(chunk_size)

                if not chunk:
                    raise ValueError("File truncated unexpectedly during decryption.")

                # R5-CRIT-01 Fix: Enforce AES-GCM 64 GiB limit during decryption
                if bytes_read + len(chunk) > MAX_GCM_PLAINTEXT_BYTES:
                    raise ValueError("File exceeds the AES-GCM 64 GiB limit during decryption.")

                decrypted_chunk = decryptor.update(chunk)
                bytes_read += len(chunk)

                if timestamp is None:
                    buffered_decrypted_data += decrypted_chunk
                    if len(buffered_decrypted_data) >= 8:
                        timestamp_bytes = buffered_decrypted_data[:8]
                        timestamp = struct.unpack(">d", timestamp_bytes)[0]
                        # R2-MED-02 Fix: Validate timestamp range
                        if not (0 < timestamp < 4102444800):  # 1970 to 2100
                            raise ValueError(
                                "Timestamp is outside valid range (1970-2100). "
                                "The file may be corrupted or maliciously crafted."
                            )
                        temp_dec_file.write(buffered_decrypted_data[8:])
                        buffered_decrypted_data = None
                else:
                    temp_dec_file.write(decrypted_chunk)

            final_chunk = decryptor.finalize()

            if timestamp is None:
                buffered_decrypted_data += final_chunk
                if len(buffered_decrypted_data) >= 8:
                    timestamp_bytes = buffered_decrypted_data[:8]
                    timestamp = struct.unpack(">d", timestamp_bytes)[0]
                    if not (0 < timestamp < 4102444800):
                        raise ValueError(
                            "Timestamp is outside valid range (1970-2100). "
                            "The file may be corrupted or maliciously crafted."
                        )
                    temp_dec_file.write(buffered_decrypted_data[8:])
                else:
                    raise ValueError("File is corrupted or missing timestamp.")
            else:
                temp_dec_file.write(final_chunk)

            # R9-CRIT-01 Fix: Close descriptor before atomic rename on Windows
            temp_dec_file.close()
            shutil.move(temp_dec_path, output_file_path)
            temp_dec_path = None

        finally:
            # R2-CRIT-01 Fix: Zero the AES key material
            _zero_bytearray(aes_key)
            if 'temp_dec_file' in locals() and not temp_dec_file.closed:
                try: temp_dec_file.close()
                except Exception: pass
            if temp_dec_path and os.path.exists(temp_dec_path):
                best_effort_delete(temp_dec_path)

    logger.info(f"Decrypted and verified {input_file_path} -> {output_file_path}")
    return timestamp
