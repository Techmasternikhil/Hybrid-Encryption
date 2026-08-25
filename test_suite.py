import os
import unittest
from hybrid_crypto import generate_rsa_keys, encrypt_file, decrypt_file
from cryptography.exceptions import InvalidTag, InvalidSignature

class TestHybridEncryptionSecure(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.pwd = b"SuperSecret123!"
        
        cls.r_priv = "test_receiver_private.pem"
        cls.r_pub = "test_receiver_public.pem"
        generate_rsa_keys(cls.r_priv, cls.r_pub, cls.pwd)
        
        cls.s_priv = "test_sender_private.pem"
        cls.s_pub = "test_sender_public.pem"
        generate_rsa_keys(cls.s_priv, cls.s_pub, cls.pwd)
        
    @classmethod
    def tearDownClass(cls):
        for f in [cls.r_priv, cls.r_pub, cls.s_priv, cls.s_pub]:
            if os.path.exists(f): os.remove(f)

    def test_empty_file(self):
        input_file = "empty.txt"
        enc_file = "empty.enc"
        dec_file = "empty_dec.txt"
        
        with open(input_file, "wb") as f:
            pass
            
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.pwd)
        decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.pwd)
        
        with open(dec_file, "rb") as f:
            self.assertEqual(f.read(), b"")
            
        for f in [input_file, enc_file, dec_file]: os.remove(f)

    def test_large_file_streaming(self):
        input_file = "large.bin"
        enc_file = "large.enc"
        dec_file = "large_dec.bin"
        
        data = os.urandom(5 * 1024 * 1024) # 5MB to test streaming
        with open(input_file, "wb") as f:
            f.write(data)
            
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.pwd)
        decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.pwd)
        
        with open(dec_file, "rb") as f:
            self.assertEqual(f.read(), data)
            
        for f in [input_file, enc_file, dec_file]: os.remove(f)

    def test_tampered_tag(self):
        input_file = "normal.txt"
        enc_file = "normal.enc"
        dec_file = "normal_dec.txt"
        
        with open(input_file, "wb") as f:
            f.write(b"Hello World")
            
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.pwd)
        
        # Tamper last byte (Tag)
        with open(enc_file, "rb") as f:
            content = bytearray(f.read())
        content[-1] ^= 0x01
        with open(enc_file, "wb") as f:
            f.write(content)
            
        with self.assertRaises(InvalidTag):
            decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.pwd)
            
        for f in [input_file, enc_file]: os.remove(f)
        if os.path.exists(dec_file): os.remove(dec_file)

    def test_tampered_signature(self):
        input_file = "normal.txt"
        enc_file = "normal.enc"
        dec_file = "normal_dec.txt"
        
        with open(input_file, "wb") as f:
            f.write(b"Hello World")
            
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.pwd)
        
        # Signature is at offset: 4 (Magic) + 2 + 384 (AES key) + 12 (Nonce) + 2 (Sig len) = 404
        with open(enc_file, "rb") as f:
            content = bytearray(f.read())
        content[405] ^= 0x01 # Flip bit in signature
        with open(enc_file, "wb") as f:
            f.write(content)
            
        with self.assertRaises(InvalidSignature):
            decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.pwd)
            
        for f in [input_file, enc_file]: os.remove(f)
        if os.path.exists(dec_file): os.remove(dec_file)

    def test_truncated_file_dos(self):
        input_file = "normal.txt"
        enc_file = "normal.enc"
        dec_file = "normal_dec.txt"
        
        with open(input_file, "wb") as f:
            f.write(b"Hello World")
            
        encrypt_file(self.r_pub, self.s_priv, input_file, enc_file, self.pwd)
        
        # Truncate ciphertext by 50 bytes (removing tag and part of ciphertext)
        with open(enc_file, "rb") as f:
            content = f.read()
        with open(enc_file, "wb") as f:
            f.write(content[:-50])
            
        with self.assertRaises(ValueError) as context:
            decrypt_file(self.r_priv, self.s_pub, enc_file, dec_file, self.pwd)
        
        self.assertTrue("truncated unexpectedly" in str(context.exception) or "corrupted or too small" in str(context.exception))
            
        for f in [input_file, enc_file]: os.remove(f)
        if os.path.exists(dec_file): os.remove(dec_file)

if __name__ == '__main__':
    unittest.main()
