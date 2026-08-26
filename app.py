import os
import ctypes
import tempfile
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
import datetime
import re
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidTag, InvalidSignature
from hybrid_crypto import (
    generate_rsa_keys, encrypt_file, decrypt_file,
    _set_private_key_permissions, _zero_bytearray
)

# R7-HIGH-01 Fix: Sandbox application keys and logs to a dedicated directory in the user profile
# to prevent CWD injection attacks.
APP_DIR = os.path.join(os.path.expanduser("~"), ".hybrid_crypto")
os.makedirs(APP_DIR, exist_ok=True)

PRIV_KEY_PATH = os.path.join(APP_DIR, "private.pem")
PUB_KEY_PATH = os.path.join(APP_DIR, "public.pem")

# Configure secure logging — CRIT-05: Log full exceptions to file, not to GUI
_log_file = os.path.join(APP_DIR, "hybrid_crypto_errors.log")
logging.basicConfig(
    filename=_log_file,
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("hybrid_crypto_app")

# R2-HIGH-03 Fix: Set restrictive permissions on the log file so exception
# details (tracebacks, internal paths) are not world-readable.
if os.path.exists(_log_file):
    _set_private_key_permissions(_log_file)

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


def _validate_pem_public_key(filepath):
    """Validate PEM files by cryptographic parsing, not string matching.

    Returns the loaded public key object if valid, or None if the file is not
    a valid PEM public key or is not RSA-3072.
    """
    try:
        # R4-CRIT-01 Fix: Limit read to 16KB to prevent OOM DoS
        with open(filepath, "rb") as f:
            pub_bytes = f.read(16384)
            if f.read(1):
                return None
            key = serialization.load_pem_public_key(pub_bytes)
        
        # R7-LOW-01 Fix: Ensure the key is an RSA public key, not DSA or EC, before checking size
        if isinstance(key, rsa.RSAPublicKey) and hasattr(key, 'key_size') and key.key_size == 3072:
            return key
        return None
    except Exception:
        return None


def _validate_pem_private_key(filepath):
    """R2-HIGH-02 Fix: Validate PEM private key files by checking proper PEM structure.

    We cannot fully parse encrypted private keys without the passphrase, so we
    verify the PEM envelope structure (BEGIN/END markers). Full cryptographic
    validation happens when the key is loaded with the password.
    """
    try:
        # R4-CRIT-01 Fix: Limit read to 16KB to prevent OOM DoS
        with open(filepath, "rb") as f:
            content = f.read(16384)
            if f.read(1):
                return False
        # R2-HIGH-02 Fix: Check for proper PEM envelope, not just substring
        return (
            content.strip().startswith(b"-----BEGIN") and
            b"PRIVATE KEY-----" in content and
            b"-----END" in content
        )
    except Exception:
        return False


class PasswordDialog(ctk.CTkToplevel):
    """A secure custom dialog that masks password input.

    R2-MED-04 Note: The `cryptography` library requires `bytes` objects for passwords,
    which are immutable and cannot be zeroed in Python. We use `bytearray` internally
    and convert to `bytes` only at the exact API call boundary. The `bytes` copy will
    persist in memory until the garbage collector frees it — this is a fundamental
    limitation of all Python crypto wrappers.
    """
    def __init__(self, title, text, parent=None, allow_empty=False):
        super().__init__(parent)
        self.title(title)
        self.geometry("350x180")
        self.resizable(False, False)

        self.transient(parent)
        self.grab_set()

        self.password = None
        self._allow_empty = allow_empty

        self.label = ctk.CTkLabel(self, text=text, font=ctk.CTkFont(weight="bold"))
        self.label.pack(pady=(20, 10))

        self.entry = ctk.CTkEntry(self, show="*", width=250)
        self.entry.pack(pady=(0, 20))
        self.entry.focus()
        self.entry.bind("<Return>", lambda e: self.submit())

        self.btn = ctk.CTkButton(self, text="Submit", command=self.submit)
        self.btn.pack()

        self.wait_window(self)

    def submit(self):
        raw_password = self.entry.get()
        self.password = bytearray(raw_password.encode('utf-8'))
        # Clear the Tk internal buffer
        self.entry.delete(0, 'end')
        self.destroy()

    def get_password_bytes(self):
        """Returns the password as bytes and zeros the internal bytearray.
        Returns None if no password was entered (and empty is not allowed).
        """
        if self.password is None:
            return None
        if len(self.password) == 0 and not self._allow_empty:
            _zero_bytearray(self.password)
            return None
        # R2-MED-04: Convert to bytes only at the boundary; zero the bytearray immediately
        result = bytes(self.password)
        _zero_bytearray(self.password)
        self.password = None
        return result


class EncryptionWizard(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Encryption & Signing Wizard")
        self.geometry("800x450")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.receiver_pub = None
        self.sender_priv = None
        self.input_file = None
        self.output_file = None

        self.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self, text="Encrypt a File", font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, columnspan=3, pady=(20, 20))

        ctk.CTkLabel(self, text="1. Who are you sending this to? (Select THEIR public.pem):", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=20, pady=(10, 5), sticky="w")
        self.lbl_pub = ctk.CTkLabel(self, text="Not Selected", text_color="gray")
        self.lbl_pub.grid(row=1, column=1, padx=10, pady=(10, 5), sticky="w")
        ctk.CTkButton(self, text="Browse", width=80, command=self.sel_pub).grid(row=1, column=2, padx=20, pady=(10, 5))

        ctk.CTkLabel(self, text="2. Your Identity (Select YOUR private.pem):", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, padx=20, pady=5, sticky="w")
        self.lbl_priv = ctk.CTkLabel(self, text="Not Selected", text_color="gray")
        self.lbl_priv.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        ctk.CTkButton(self, text="Browse", width=80, command=self.sel_priv).grid(row=2, column=2, padx=20, pady=5)

        # R2-LOW-03 Fix: Auto-detect with validation
        if os.path.exists(PRIV_KEY_PATH) and _validate_pem_private_key(PRIV_KEY_PATH):
            self.sender_priv = os.path.abspath(PRIV_KEY_PATH)
            self.lbl_priv.configure(text="private.pem (Auto-detected)", text_color="#2ECC71")

        ctk.CTkLabel(self, text="3. Your Private Key Passphrase (leave blank if unencrypted):", font=ctk.CTkFont(weight="bold")).grid(row=3, column=0, padx=20, pady=5, sticky="w")
        self.entry_pwd = ctk.CTkEntry(self, show="*", width=200)
        self.entry_pwd.grid(row=3, column=1, columnspan=2, padx=10, pady=5, sticky="w")

        ctk.CTkLabel(self, text="4. File to Encrypt:", font=ctk.CTkFont(weight="bold")).grid(row=4, column=0, padx=20, pady=5, sticky="w")
        self.lbl_in = ctk.CTkLabel(self, text="Not Selected", text_color="gray")
        self.lbl_in.grid(row=4, column=1, padx=10, pady=5, sticky="w")
        ctk.CTkButton(self, text="Browse", width=80, command=self.sel_in).grid(row=4, column=2, padx=20, pady=5)

        ctk.CTkLabel(self, text="5. Save Encrypted File As:", font=ctk.CTkFont(weight="bold")).grid(row=5, column=0, padx=20, pady=5, sticky="w")
        self.lbl_out = ctk.CTkLabel(self, text="Not Selected", text_color="gray")
        self.lbl_out.grid(row=5, column=1, padx=10, pady=5, sticky="w")
        ctk.CTkButton(self, text="Browse", width=80, command=self.sel_out).grid(row=5, column=2, padx=20, pady=5)

        self.btn_exec = ctk.CTkButton(self, text="Encrypt & Sign", font=ctk.CTkFont(weight="bold"), fg_color="#1E8449", hover_color="#145A32", command=self.execute)
        self.btn_exec.grid(row=6, column=0, columnspan=3, pady=(30, 20))

    def sel_pub(self):
        f = filedialog.askopenfilename(title="Select Receiver's Public Key", filetypes=[("PEM Files", "*.pem")])
        if f:
            if _validate_pem_public_key(f):
                self.receiver_pub = f
                self.lbl_pub.configure(text=os.path.basename(f), text_color="#2ECC71")
            else:
                self.receiver_pub = None
                self.lbl_pub.configure(text="Invalid Public Key (must be RSA-3072 PEM)", text_color="#E74C3C")

    def sel_priv(self):
        f = filedialog.askopenfilename(title="Select YOUR Private Key", filetypes=[("PEM Files", "*.pem")])
        if f:
            if _validate_pem_private_key(f):
                self.sender_priv = f
                self.lbl_priv.configure(text=os.path.basename(f), text_color="#2ECC71")
            else:
                self.sender_priv = None
                self.lbl_priv.configure(text="Invalid Private Key", text_color="#E74C3C")

    def sel_in(self):
        f = filedialog.askopenfilename(title="Select File to Encrypt")
        if f:
            self.input_file = f
            self.lbl_in.configure(text=os.path.basename(f), text_color="#2ECC71")

    def sel_out(self):
        if not self.input_file:
            messagebox.showwarning("Warning", "Please select the file to encrypt first!")
            return
        f = filedialog.asksaveasfilename(title="Save Encrypted File As", defaultextension=".enc", initialfile=os.path.basename(self.input_file) + ".enc")
        if f:
            self.output_file = f
            self.lbl_out.configure(text=os.path.basename(f), text_color="#2ECC71")

    def execute(self):
        if not all([self.receiver_pub, self.sender_priv, self.input_file, self.output_file]):
            messagebox.showerror("Missing Files", "Please select all 4 required files before encrypting.")
            return

        # R2-CRIT-02 Fix: Use bytearray from the start so the password can be zeroed
        pwd_text = self.entry_pwd.get()
        pwd = bytearray(pwd_text.encode('utf-8')) if pwd_text else None
        self.entry_pwd.delete(0, 'end')

        try:
            # Convert to bytes only at the API boundary
            encrypt_file(self.receiver_pub, self.sender_priv, self.input_file, self.output_file,
                         bytes(pwd) if pwd else None)
            messagebox.showinfo("Success", f"File successfully encrypted AND signed!\n\nSaved to: {self.output_file}")
            self.destroy()
        except OSError:
            logger.error("Encryption OSError", exc_info=True)
            messagebox.showerror("File Error", "Could not access or write the file. Please check permissions.")
        except Exception:
            logger.error("Encryption failed", exc_info=True)
            messagebox.showerror("Encryption Failed", "Encryption failed. Please check that you selected the correct key files and entered the right passphrase.\n\nDetails have been logged to hybrid_crypto_errors.log.")
        finally:
            # R2-CRIT-02 Fix: Zero the actual bytearray, not a copy
            if pwd:
                _zero_bytearray(pwd)


class DecryptionWizard(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Decryption & Verification Wizard")
        self.geometry("800x450")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.receiver_priv = None
        self.sender_pub = None
        self.input_file = None
        self.output_file = None

        self.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self, text="Decrypt a File", font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, columnspan=3, pady=(20, 20))

        ctk.CTkLabel(self, text="1. Your Identity (Select YOUR private.pem):", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=20, pady=(10, 5), sticky="w")
        self.lbl_priv = ctk.CTkLabel(self, text="Not Selected", text_color="gray")
        self.lbl_priv.grid(row=1, column=1, padx=10, pady=(10, 5), sticky="w")
        ctk.CTkButton(self, text="Browse", width=80, command=self.sel_priv).grid(row=1, column=2, padx=20, pady=(10, 5))

        # R2-LOW-03 Fix: Auto-detect with validation
        if os.path.exists(PRIV_KEY_PATH) and _validate_pem_private_key(PRIV_KEY_PATH):
            self.receiver_priv = os.path.abspath(PRIV_KEY_PATH)
            self.lbl_priv.configure(text="private.pem (Auto-detected)", text_color="#2ECC71")

        ctk.CTkLabel(self, text="2. Your Private Key Passphrase (leave blank if unencrypted):", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, padx=20, pady=5, sticky="w")
        self.entry_pwd = ctk.CTkEntry(self, show="*", width=200)
        self.entry_pwd.grid(row=2, column=1, columnspan=2, padx=10, pady=5, sticky="w")

        ctk.CTkLabel(self, text="3. Who sent this? (Select THEIR public.pem):", font=ctk.CTkFont(weight="bold")).grid(row=3, column=0, padx=20, pady=5, sticky="w")
        self.lbl_pub = ctk.CTkLabel(self, text="Not Selected", text_color="gray")
        self.lbl_pub.grid(row=3, column=1, padx=10, pady=5, sticky="w")
        ctk.CTkButton(self, text="Browse", width=80, command=self.sel_pub).grid(row=3, column=2, padx=20, pady=5)

        ctk.CTkLabel(self, text="4. Encrypted File (*.enc):", font=ctk.CTkFont(weight="bold")).grid(row=4, column=0, padx=20, pady=5, sticky="w")
        self.lbl_in = ctk.CTkLabel(self, text="Not Selected", text_color="gray")
        self.lbl_in.grid(row=4, column=1, padx=10, pady=5, sticky="w")
        ctk.CTkButton(self, text="Browse", width=80, command=self.sel_in).grid(row=4, column=2, padx=20, pady=5)

        ctk.CTkLabel(self, text="5. Save Decrypted File As:", font=ctk.CTkFont(weight="bold")).grid(row=5, column=0, padx=20, pady=5, sticky="w")
        self.lbl_out = ctk.CTkLabel(self, text="Not Selected", text_color="gray")
        self.lbl_out.grid(row=5, column=1, padx=10, pady=5, sticky="w")
        ctk.CTkButton(self, text="Browse", width=80, command=self.sel_out).grid(row=5, column=2, padx=20, pady=5)

        self.btn_exec = ctk.CTkButton(self, text="Decrypt & Verify", font=ctk.CTkFont(weight="bold"), fg_color="#1E8449", hover_color="#145A32", command=self.execute)
        self.btn_exec.grid(row=6, column=0, columnspan=3, pady=(30, 20))

    def sel_priv(self):
        f = filedialog.askopenfilename(title="Select YOUR Private Key", filetypes=[("PEM Files", "*.pem")])
        if f:
            if _validate_pem_private_key(f):
                self.receiver_priv = f
                self.lbl_priv.configure(text=os.path.basename(f), text_color="#2ECC71")
            else:
                self.receiver_priv = None
                self.lbl_priv.configure(text="Invalid Private Key", text_color="#E74C3C")

    def sel_pub(self):
        f = filedialog.askopenfilename(title="Select Sender's Public Key", filetypes=[("PEM Files", "*.pem")])
        if f:
            if _validate_pem_public_key(f):
                self.sender_pub = f
                self.lbl_pub.configure(text=os.path.basename(f), text_color="#2ECC71")
            else:
                self.sender_pub = None
                self.lbl_pub.configure(text="Invalid Public Key (must be RSA-3072 PEM)", text_color="#E74C3C")

    def sel_in(self):
        f = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        if f:
            self.input_file = f
            self.lbl_in.configure(text=os.path.basename(f), text_color="#2ECC71")

    def sel_out(self):
        if not self.input_file:
            messagebox.showwarning("Warning", "Please select the encrypted file first!")
            return

        default_out = self.input_file.replace(".enc", "")
        if default_out == self.input_file:
            default_out += ".decrypted"

        f = filedialog.asksaveasfilename(title="Save Decrypted File As", initialfile=os.path.basename(default_out))
        if f:
            self.output_file = f
            self.lbl_out.configure(text=os.path.basename(f), text_color="#2ECC71")

    def execute(self):
        if not all([self.receiver_priv, self.sender_pub, self.input_file, self.output_file]):
            messagebox.showerror("Missing Files", "Please select all 4 required files before decrypting.")
            return

        # R2-CRIT-02 Fix: Use bytearray from the start so the password can be zeroed
        pwd_text = self.entry_pwd.get()
        pwd = bytearray(pwd_text.encode('utf-8')) if pwd_text else None
        self.entry_pwd.delete(0, 'end')

        try:
            timestamp = decrypt_file(self.receiver_priv, self.sender_pub, self.input_file, self.output_file,
                                     bytes(pwd) if pwd else None)
            dt = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

            messagebox.showinfo("Success", f"File successfully decrypted AND sender signature verified!\n\nEncrypted on: {dt}\nSaved to: {self.output_file}")
            self.destroy()
        except InvalidTag:
            messagebox.showerror("Integrity Error", "Decryption failed!\nThe file has been tampered with or corrupted.")
        except InvalidSignature:
            messagebox.showerror("Signature Error", "Verification failed!\nThe digital signature does not match the sender's public key.")
        except ValueError:
            # R2-MED-01 Fix: Don't pass str(ve) to GUI — it may leak internal details
            # like expected key sizes, format versions, etc.
            logger.error("Decryption ValueError", exc_info=True)
            messagebox.showerror("Format Error", "The encrypted file appears to be corrupted, truncated, or in an unsupported format.\n\nDetails have been logged to hybrid_crypto_errors.log.")
        except OverflowError:
            messagebox.showerror("Timestamp Error", "The file's creation timestamp is corrupted or maliciously altered.")
        except OSError:
            logger.error("Decryption OSError", exc_info=True)
            messagebox.showerror("File Error", "Could not read the encrypted file. Please check permissions.")
        except Exception:
            logger.error("Decryption failed", exc_info=True)
            messagebox.showerror("Decryption Failed", "Decryption failed. Please check that you selected the correct key files and entered the right passphrase.\n\nDetails have been logged to hybrid_crypto_errors.log.")
        finally:
            # R2-CRIT-02 Fix: Zero the actual bytearray, not a copy
            if pwd:
                _zero_bytearray(pwd)


class HybridEncryptionApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Hybrid Cryptography System (Secure Edition)")
        self.geometry("850x550")
        self.resizable(False, False)

        self.grid_columnconfigure(0, weight=1)

        self.header = ctk.CTkLabel(self, text="Hybrid File Encryption", font=ctk.CTkFont(size=24, weight="bold"))
        self.header.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.subheader = ctk.CTkLabel(self, text="AES-256 GCM + RSA-3072 + Digital Signatures", font=ctk.CTkFont(size=14))
        self.subheader.grid(row=1, column=0, padx=20, pady=(0, 20))

        self.key_frame = ctk.CTkFrame(self)
        self.key_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.encrypt_frame = ctk.CTkFrame(self)
        self.encrypt_frame.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        self.decrypt_frame = ctk.CTkFrame(self)
        self.decrypt_frame.grid(row=4, column=0, padx=20, pady=10, sticky="ew")

        self._setup_key_section()
        self._setup_encrypt_section()
        self._setup_decrypt_section()

        self._check_key_status()

    def _setup_key_section(self):
        self.key_frame.grid_columnconfigure(0, weight=1)
        lbl = ctk.CTkLabel(self.key_frame, text="1. Key Management", font=ctk.CTkFont(weight="bold"))
        lbl.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="w")

        desc = ctk.CTkLabel(self.key_frame, text="First-time users MUST generate their keys here before doing anything else.", text_color="gray", font=ctk.CTkFont(size=12))
        desc.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="w")

        self.btn_generate = ctk.CTkButton(self.key_frame, text="Generate Secure RSA Keys", command=self.generate_keys)
        self.btn_generate.grid(row=0, column=1, rowspan=2, padx=5, pady=10, sticky="e")

        self.btn_change_pwd = ctk.CTkButton(self.key_frame, text="Change Passphrase", command=self.change_password)
        self.btn_change_pwd.grid(row=0, column=2, rowspan=2, padx=(5, 10), pady=10, sticky="e")

    def _setup_encrypt_section(self):
        self.encrypt_frame.grid_columnconfigure(0, weight=1)
        lbl = ctk.CTkLabel(self.encrypt_frame, text="2. Encryption & Signing", font=ctk.CTkFont(weight="bold"))
        lbl.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="w")

        desc = ctk.CTkLabel(self.encrypt_frame, text="Secure a file to send to someone else (requires their public key).", text_color="gray", font=ctk.CTkFont(size=12))
        desc.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="w")

        self.btn_encrypt = ctk.CTkButton(self.encrypt_frame, text="Open Encryption Wizard", command=self.open_encrypt_wizard)
        self.btn_encrypt.grid(row=0, column=1, rowspan=2, padx=10, pady=10, sticky="e")

    def _setup_decrypt_section(self):
        self.decrypt_frame.grid_columnconfigure(0, weight=1)
        lbl = ctk.CTkLabel(self.decrypt_frame, text="3. Decryption & Verification", font=ctk.CTkFont(weight="bold"))
        lbl.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="w")

        desc = ctk.CTkLabel(self.decrypt_frame, text="Unlock a file sent to you (requires your private key password).", text_color="gray", font=ctk.CTkFont(size=12))
        desc.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="w")

        self.btn_decrypt = ctk.CTkButton(self.decrypt_frame, text="Open Decryption Wizard", command=self.open_decrypt_wizard)
        self.btn_decrypt.grid(row=0, column=1, rowspan=2, padx=10, pady=10, sticky="e")

    def get_password(self, prompt="Enter Passphrase:", allow_empty=False):
        dialog = PasswordDialog("Passphrase Required", prompt, parent=self, allow_empty=allow_empty)
        return dialog.get_password_bytes()

    def generate_keys(self):
        if os.path.exists(PRIV_KEY_PATH) or os.path.exists(PUB_KEY_PATH):
            confirm = messagebox.askyesno(
                "CRITICAL WARNING",
                "Keys already exist!\n\nGenerating new keys will permanently overwrite your existing keys. "
                "If you do this, you will NEVER be able to decrypt your old files.\n\nAre you absolutely sure you want to continue?"
            )
            if not confirm:
                return

        password = self.get_password("Set a secure passphrase (min 12 chars, uppercase, lowercase, number, symbol):")
        if not password:
            messagebox.showwarning("Cancelled", "Key generation cancelled.")
            return

        pwd_str = password.decode('utf-8')
        if len(pwd_str) < 12 or not re.search(r"[A-Z]", pwd_str) or not re.search(r"[a-z]", pwd_str) or not re.search(r"[0-9]", pwd_str) or not re.search(r"[^A-Za-z0-9]", pwd_str):
            messagebox.showerror("Weak Password", "Passphrase MUST be at least 12 characters long and contain an uppercase letter, a lowercase letter, a number, and a special character.")
            return

        try:
            generate_rsa_keys(PRIV_KEY_PATH, PUB_KEY_PATH, password)
            messagebox.showinfo("Success", f"RSA-3072 key pair generated successfully and secured with passphrase!\nKeys saved to: {APP_DIR}")
            self._check_key_status()
        except Exception:
            logger.error("Key generation failed", exc_info=True)
            messagebox.showerror("Error", "Failed to generate keys. Details have been logged to hybrid_crypto_errors.log.")

    def _check_key_status(self):
        if not os.path.exists(PRIV_KEY_PATH) or not os.path.exists(PUB_KEY_PATH):
            self.btn_encrypt.configure(state="disabled")
            self.btn_decrypt.configure(state="disabled")
            self.btn_change_pwd.configure(state="disabled")
        else:
            self.btn_encrypt.configure(state="normal")
            self.btn_decrypt.configure(state="normal")
            self.btn_change_pwd.configure(state="normal")

    def change_password(self):
        old_pwd = self.get_password("Enter your CURRENT passphrase:")
        if not old_pwd: return

        new_pwd = self.get_password("Enter your NEW passphrase (min 12 chars, upper, lower, number, symbol):")
        if not new_pwd: return

        pwd_str = new_pwd.decode('utf-8')
        if len(pwd_str) < 12 or not re.search(r"[A-Z]", pwd_str) or not re.search(r"[a-z]", pwd_str) or not re.search(r"[0-9]", pwd_str) or not re.search(r"[^A-Za-z0-9]", pwd_str):
            messagebox.showerror("Weak Password", "New passphrase MUST be at least 12 characters long and contain an uppercase letter, a lowercase letter, a number, and a special character.")
            return

        try:
            with open(PRIV_KEY_PATH, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password=old_pwd
                )

            enc_alg = serialization.BestAvailableEncryption(new_pwd)

            temp_key_path = None
            move_succeeded = False
            try:
                # R3-MED-01 Fix: Use target directory for temp file to ensure atomic renames
                out_dir = os.path.dirname(PRIV_KEY_PATH) or "."
                with tempfile.NamedTemporaryFile(delete=False, dir=out_dir, prefix=".hybrid_key_") as temp_key_file:
                    temp_key_path = temp_key_file.name
                    temp_key_file.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=enc_alg
                    ))

                shutil.move(temp_key_path, PRIV_KEY_PATH)
                move_succeeded = True
            finally:
                if not move_succeeded and temp_key_path and os.path.exists(temp_key_path):
                    logger.error(f"Password change failed. Temp key backup preserved at: {temp_key_path}")

            _set_private_key_permissions(PRIV_KEY_PATH)
            messagebox.showinfo("Success", "Passphrase changed successfully! Your private key is now protected with the new password.")
        except ValueError:
            messagebox.showerror("Error", "Incorrect CURRENT passphrase. Cannot change password.")
        except Exception:
            logger.error("Password change failed", exc_info=True)
            messagebox.showerror("Error", "Failed to change passphrase. Details have been logged to hybrid_crypto_errors.log.")

    def open_encrypt_wizard(self):
        EncryptionWizard(self)

    def open_decrypt_wizard(self):
        DecryptionWizard(self)


if __name__ == "__main__":
    try:
        app = HybridEncryptionApp()
        app.mainloop()
    except KeyboardInterrupt:
        print("\n[*] Application securely closed.")
