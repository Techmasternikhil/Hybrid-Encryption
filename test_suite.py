import os
import unittest
from hybrid_crypto import generate_rsa_keys, encrypt_file, decrypt_file, force_remove
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from app import _validate_pem_public_key

class TestHybridEncryptionSecure(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # LOW-03 Fix: Use different passwords for sender and receiver to catch
        # bugs that accidentally confuse sender/receiver password parameters
        cls.receiver_pwd = b"ReceiverPwd!456X"
        cls.sender_pwd = b"SenderPwd@789Y!!"
        
        cls.r_priv = "test_receiver_private.pem"
        cls.r_pub = "test_receiver_public.pem"
        generate_rsa_keys(cls.r_priv, cls.r_pub, cls.receiver_pwd)
        
        cls.s_priv = "test_sender_private.pem"
        cls.s_pub = "test_sender_public.pem"
        generate_rsa_keys(cls.s_priv, cls.s_pub, cls.sender_pwd)
        
        # LOW-04: Generate a third "attacker" key pair for wrong-sender tests
        cls.attacker_pwd = b"AttackerPwd#000Z"
        cls.a_priv = "test_attacker_private.pem"
        cls.a_pub = "test_attacker_public.pem"
        generate_rsa_keys(cls.a_priv, cls.a_pub, cls.attacker_pwd)
        
    @classmethod
    def tearDownClass(cls):
        for f in [cls.r_priv, cls.r_pub, cls.s_priv, cls.s_pub, cls.a_priv, cls.a_pub]:
            force_remove(f)

    def _cleanup(self, *files):
        """Register files for guaranteed cleanup after test finishes."""
        for f in files:
            self.addCleanup(lambda path=f: force_remove(path))

    def test_empty_file(self):
        input_file = "empty.txt"
        enc_file = "empty.enc"
        dec_file = "empty_dec.txt"
        self._cleanup(input_file, enc_file, dec_file)
        
        with open(input_file, "wb") as f:
            pass
            
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.sender_pwd)
        decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.receiver_pwd)
        
        with open(dec_file, "rb") as f:
            self.assertEqual(f.read(), b"")

    def test_large_file_streaming(self):
        input_file = "large.bin"
        enc_file = "large.enc"
        dec_file = "large_dec.bin"
        self._cleanup(input_file, enc_file, dec_file)
        
        data = os.urandom(5 * 1024 * 1024) # 5MB to test streaming
        with open(input_file, "wb") as f:
            f.write(data)
            
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.sender_pwd)
        decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.receiver_pwd)
        
        with open(dec_file, "rb") as f:
            self.assertEqual(f.read(), data)

    def test_tampered_tag(self):
        input_file = "normal.txt"
        enc_file = "normal.enc"
        dec_file = "normal_dec.txt"
        self._cleanup(input_file, enc_file, dec_file)
        
        with open(input_file, "wb") as f:
            f.write(b"Hello World")
            
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.sender_pwd)
        
        # Tamper last byte (Tag)
        with open(enc_file, "rb") as f:
            content = bytearray(f.read())
        content[-1] ^= 0x01
        with open(enc_file, "wb") as f:
            f.write(content)
            
        with self.assertRaises(InvalidTag):
            decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.receiver_pwd)

    def test_tampered_signature(self):
        input_file = "normal.txt"
        enc_file = "normal.enc"
        dec_file = "normal_dec.txt"
        self._cleanup(input_file, enc_file, dec_file)
        
        with open(input_file, "wb") as f:
            f.write(b"Hello World")
            
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.sender_pwd)
        
        # Signature is at offset: 4 (Magic) + 2 (Version) + 2 (KeyLen) + 384 (AES key) + 12 (Nonce) + 2 (Sig len) = 406
        with open(enc_file, "rb") as f:
            content = bytearray(f.read())
        content[407] ^= 0x01 # Flip bit in signature
        with open(enc_file, "wb") as f:
            f.write(content)
            
        with self.assertRaises(InvalidSignature):
            decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.receiver_pwd)

    def test_truncated_file_dos(self):
        input_file = "normal.txt"
        enc_file = "normal.enc"
        dec_file = "normal_dec.txt"
        self._cleanup(input_file, enc_file, dec_file)
        
        with open(input_file, "wb") as f:
            f.write(b"Hello World")
            
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.sender_pwd)
        
        # Truncate ciphertext by 50 bytes (removing tag and part of ciphertext)
        with open(enc_file, "rb") as f:
            content = f.read()
        with open(enc_file, "wb") as f:
            f.write(content[:-50])
            
        with self.assertRaises(ValueError) as context:
            decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.receiver_pwd)
        
        self.assertTrue("truncated unexpectedly" in str(context.exception) or "too small" in str(context.exception))

    def test_wrong_sender_key_surreptitious_forwarding(self):
        """LOW-04 Fix: Verify that decryption with the WRONG sender's public key
        correctly raises InvalidSignature. This is the core surreptitious forwarding
        protection — if Alice encrypts a file for Bob, and Eve intercepts it and
        presents it as if she sent it, Bob should detect that the signature doesn't
        match Eve's public key.
        """
        input_file = "forward_test.txt"
        enc_file = "forward_test.enc"
        dec_file = "forward_test_dec.txt"
        self._cleanup(input_file, enc_file, dec_file)
        
        with open(input_file, "wb") as f:
            f.write(b"This file was signed by the real sender")
        
        # Encrypt and sign with the REAL sender's key
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.sender_pwd)
        
        # Try to decrypt using the ATTACKER's public key as the "sender"
        # This should fail because the signature was made with s_priv, not a_priv
        with self.assertRaises(InvalidSignature):
            decrypt_file(self.r_priv, self.a_pub, enc_file, dec_file, self.receiver_pwd)

    def test_wrong_receiver_key(self):
        """Verify that decryption with the wrong receiver's private key fails.
        If the file was encrypted for receiver R, an attacker with a different
        private key should not be able to decrypt it.
        """
        input_file = "wrong_recv.txt"
        enc_file = "wrong_recv.enc"
        dec_file = "wrong_recv_dec.txt"
        self._cleanup(input_file, enc_file, dec_file)
        
        with open(input_file, "wb") as f:
            f.write(b"Only the intended receiver can decrypt this")
        
        # Encrypt for the real receiver
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.sender_pwd)
        
        # Try to decrypt with the attacker's private key (wrong receiver)
        # The RSA-OAEP decryption should fail
        with self.assertRaises(Exception):
            decrypt_file(self.a_priv, self.s_pub, enc_file, dec_file, self.attacker_pwd)

    def test_unencrypted_private_key(self):
        """Verify that encryption/decryption works with unencrypted (no passphrase) private keys."""
        nopass_priv = "test_nopass_private.pem"
        nopass_pub = "test_nopass_public.pem"
        self._cleanup(nopass_priv, nopass_pub)
        
        generate_rsa_keys(nopass_priv, nopass_pub, password=None)
        
        input_file = "nopass_test.txt"
        enc_file = "nopass_test.enc"
        dec_file = "nopass_test_dec.txt"
        self._cleanup(input_file, enc_file, dec_file)
        
        with open(input_file, "wb") as f:
            f.write(b"Testing without passphrase")
        
        # Encrypt with unencrypted sender key, decrypt with unencrypted receiver key
        encrypt_file(self.r_pub, nopass_priv, input_file, enc_file, sender_password=None)
        decrypt_file(self.r_priv, nopass_pub, enc_file, dec_file, self.receiver_pwd)
        
        with open(dec_file, "rb") as f:
            self.assertEqual(f.read(), b"Testing without passphrase")

    def test_crlf_public_key(self):
        """R3-CRIT-01 Fix: Verify that signature verification works even if the receiver's
        public key file uses CRLF (Windows) line endings.
        """
        input_file = "crlf_test.txt"
        enc_file = "crlf_test.enc"
        dec_file = "crlf_test_dec.txt"
        crlf_pub = "test_receiver_public_crlf.pem"
        self._cleanup(input_file, enc_file, dec_file, crlf_pub)
        
        # Create a CRLF version of the receiver's public key
        with open(self.r_pub, "rb") as f:
            pub_content = f.read()
        with open(crlf_pub, "wb") as f:
            f.write(pub_content.replace(b"\n", b"\r\n"))
            
        with open(input_file, "wb") as f:
            f.write(b"CRLF signature test")
            
        # Encrypt using the CRLF public key file
        encrypt_file(crlf_pub, self.s_priv, input_file, enc_file, self.sender_pwd)
        
        # Decrypt using the receiver's private key (which will generate a strict LF public key)
        # This will fail with InvalidSignature if the encryptor didn't re-serialize it.
        decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.receiver_pwd)
        
        with open(dec_file, "rb") as f:
            self.assertEqual(f.read(), b"CRLF signature test")

    def test_inplace_encryption(self):
        """R6-CRIT-01 Fix: Verify that encrypting a file in-place (overwriting itself)
        works flawlessly without corrupting or losing data.
        """
        inplace_file = "inplace_test.txt"
        self._cleanup(inplace_file)
        
        # Write initial data
        test_data = b"This data will be encrypted over itself."
        with open(inplace_file, "wb") as f:
            f.write(test_data)
            
        # Encrypt the file in-place (input == output)
        encrypt_file(self.r_pub, self.s_priv, inplace_file, inplace_file, self.sender_pwd)
        
        # The file should now be encrypted (and thus not match the plaintext)
        with open(inplace_file, "rb") as f:
            encrypted_content = f.read()
        self.assertNotEqual(encrypted_content, test_data)
        self.assertTrue(encrypted_content.startswith(b"HYB1"))
        
        # Decrypt the file in-place (input == output)
        decrypt_file(self.r_priv, self.s_pub, inplace_file, inplace_file, self.receiver_pwd)
        
        # The file should now match the original plaintext
        with open(inplace_file, "rb") as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, test_data)

    def test_fuzz_header_truncation(self):
        """Verify that the application fails gracefully when the header is extremely truncated (e.g., 5 bytes)."""
        input_file = "trunc_test.txt"
        enc_file = "trunc_test.enc"
        dec_file = "trunc_test_dec.txt"
        self._cleanup(input_file, enc_file, dec_file)
        
        with open(input_file, "wb") as f:
            f.write(b"Hello World")
            
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.sender_pwd)
        
        # Truncate to just 5 bytes
        with open(enc_file, "rb") as f:
            content = f.read()
        with open(enc_file, "wb") as f:
            f.write(content[:5])
            
        with self.assertRaises(ValueError) as context:
            decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.receiver_pwd)
        self.assertTrue("too small" in str(context.exception) or "Invalid file format" in str(context.exception))

    def test_fuzz_garbage_data(self):
        """Verify that feeding complete garbage data fails securely without crashing the interpreter."""
        enc_file = "garbage.enc"
        dec_file = "garbage_dec.txt"
        self._cleanup(enc_file, dec_file)
        
        with open(enc_file, "wb") as f:
            f.write(os.urandom(1024))  # 1 KB of random noise
            
        with self.assertRaises(ValueError) as context:
            decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.receiver_pwd)
        self.assertIn("Invalid file format", str(context.exception))

    def test_fuzz_invalid_rsa_key_type(self):
        """Verify that the UI validators reject non-RSA keys (e.g., DSA) even if they are structurally valid PEMs."""
        dsa_priv = "test_dsa_private.pem"
        dsa_pub = "test_dsa_public.pem"
        self._cleanup(dsa_priv, dsa_pub)
        
        # Generate a DSA key pair
        dsa_key = dsa.generate_private_key(key_size=3072)
        with open(dsa_pub, "wb") as f:
            f.write(dsa_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
        # The app's public key validator should reject it (return None)
        validated_key = _validate_pem_public_key(dsa_pub)
        self.assertIsNone(validated_key)

if __name__ == '__main__':
    unittest.main()
