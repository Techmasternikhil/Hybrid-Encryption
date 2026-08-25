import os
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
import datetime
from cryptography.exceptions import InvalidTag, InvalidSignature
from hybrid_crypto import generate_rsa_keys, encrypt_file, decrypt_file

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PasswordDialog(ctk.CTkToplevel):
    """A secure custom dialog that masks password input."""
    def __init__(self, title, text, parent=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("350x180")
        self.resizable(False, False)
        
        # Make the window modal
        self.transient(parent)
        self.grab_set()
        
        self.password = None
        
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
        self.password = self.entry.get()
        self.destroy()

class HybridEncryptionApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Hybrid Cryptography System (Secure Edition)")
        self.geometry("700x550")
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

    def _setup_key_section(self):
        self.key_frame.grid_columnconfigure(1, weight=1)
        lbl = ctk.CTkLabel(self.key_frame, text="1. Key Management", font=ctk.CTkFont(weight="bold"))
        lbl.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        btn_generate = ctk.CTkButton(self.key_frame, text="Generate Secure RSA Keys", command=self.generate_keys)
        btn_generate.grid(row=0, column=1, padx=10, pady=10, sticky="e")

    def _setup_encrypt_section(self):
        self.encrypt_frame.grid_columnconfigure(1, weight=1)
        lbl = ctk.CTkLabel(self.encrypt_frame, text="2. Encryption & Signing", font=ctk.CTkFont(weight="bold"))
        lbl.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        btn_encrypt = ctk.CTkButton(self.encrypt_frame, text="Select File to Encrypt", command=self.encrypt_action)
        btn_encrypt.grid(row=0, column=1, padx=10, pady=10, sticky="e")

    def _setup_decrypt_section(self):
        self.decrypt_frame.grid_columnconfigure(1, weight=1)
        lbl = ctk.CTkLabel(self.decrypt_frame, text="3. Decryption & Verification", font=ctk.CTkFont(weight="bold"))
        lbl.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        btn_decrypt = ctk.CTkButton(self.decrypt_frame, text="Select File to Decrypt", command=self.decrypt_action)
        btn_decrypt.grid(row=0, column=1, padx=10, pady=10, sticky="e")

    def get_password(self, prompt="Enter Passphrase:"):
        # Round 3 Fix: Using secure custom modal with password masking
        dialog = PasswordDialog("Passphrase Required", prompt, parent=self)
        res = dialog.password
        return res.encode('utf-8') if res else None

    def generate_keys(self):
        password = self.get_password("Set a secure passphrase (min 12 chars, uppercase, lowercase, number, symbol):")
        if not password:
            messagebox.showwarning("Cancelled", "Key generation cancelled.")
            return
            
        # Round 4 Fix: Enforce strong password policy
        import re
        pwd_str = password.decode('utf-8')
        if len(pwd_str) < 12 or not re.search(r"[A-Z]", pwd_str) or not re.search(r"[a-z]", pwd_str) or not re.search(r"[0-9]", pwd_str) or not re.search(r"[^A-Za-z0-9]", pwd_str):
            messagebox.showerror("Weak Password", "Passphrase MUST be at least 12 characters long and contain an uppercase letter, a lowercase letter, a number, and a special character.")
            return
            
        try:
            generate_rsa_keys("private.pem", "public.pem", password)
            messagebox.showinfo("Success", "RSA-3072 key pair generated successfully and secured with passphrase!\n(private.pem, public.pem)")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")

    def encrypt_action(self):
        receiver_pub = filedialog.askopenfilename(title="Select Receiver's Public Key", filetypes=[("PEM Files", "*.pem")])
        if not receiver_pub: return
        
        sender_priv = filedialog.askopenfilename(title="Select YOUR Private Key (for signing)", filetypes=[("PEM Files", "*.pem")])
        if not sender_priv: return

        password = self.get_password("Enter YOUR private key passphrase:")
        if not password: return

        input_file = filedialog.askopenfilename(title="Select File to Encrypt")
        if not input_file: return

        output_file = filedialog.asksaveasfilename(
            title="Save Encrypted File As",
            defaultextension=".enc",
            initialfile=os.path.basename(input_file) + ".enc"
        )
        if not output_file: return

        try:
            encrypt_file(receiver_pub, sender_priv, input_file, output_file, password)
            messagebox.showinfo("Success", f"File successfully encrypted AND signed!\nSaved to: {output_file}")
        except OSError:
            messagebox.showerror("File Error", "Could not access or write the file. Please check permissions.")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_action(self):
        receiver_priv = filedialog.askopenfilename(title="Select YOUR Private Key", filetypes=[("PEM Files", "*.pem")])
        if not receiver_priv: return
        
        password = self.get_password("Enter YOUR private key passphrase:")
        if not password: return
        
        sender_pub = filedialog.askopenfilename(title="Select Sender's Public Key (for verification)", filetypes=[("PEM Files", "*.pem")])
        if not sender_pub: return

        input_file = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        if not input_file: return

        default_out = input_file.replace(".enc", "")
        if default_out == input_file:
            default_out += ".decrypted"
            
        output_file = filedialog.asksaveasfilename(
            title="Save Decrypted File As",
            initialfile=os.path.basename(default_out)
        )
        if not output_file: return

        try:
            # Round 3 Fix: Retrieve timestamp for anti-replay check
            timestamp = decrypt_file(receiver_priv, sender_pub, input_file, output_file, password)
            dt = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            messagebox.showinfo("Success", f"File successfully decrypted AND sender signature verified!\n\nEncrypted on: {dt}\nSaved to: {output_file}")
        except InvalidTag:
            messagebox.showerror("Integrity Error", "Decryption failed!\nThe file has been tampered with or corrupted.")
        except InvalidSignature:
            messagebox.showerror("Signature Error", "Verification failed!\nThe digital signature does not match the sender's public key.")
        except ValueError as ve:
            messagebox.showerror("Format Error", str(ve))
        except (OverflowError):
            messagebox.showerror("Timestamp Error", "The file's creation timestamp is corrupted or maliciously altered.")
        except OSError:
            messagebox.showerror("File Error", "Could not read the encrypted file. Please check permissions.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed. Did you enter the correct passphrase?\nDetails: {str(e)}")

if __name__ == "__main__":
    try:
        app = HybridEncryptionApp()
        app.mainloop()
    except KeyboardInterrupt:
        print("\n[*] Application securely closed.")
