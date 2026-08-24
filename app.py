import os
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from cryptography.exceptions import InvalidTag
from hybrid_crypto import generate_rsa_keys, encrypt_file, decrypt_file

# Set up customtkinter appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class HybridEncryptionApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Hybrid Cryptography System")
        self.geometry("600x450")
        self.resizable(False, False)

        # UI Layout
        self.grid_columnconfigure(0, weight=1)

        # Header
        self.header = ctk.CTkLabel(self, text="Hybrid File Encryption", font=ctk.CTkFont(size=24, weight="bold"))
        self.header.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        self.subheader = ctk.CTkLabel(self, text="AES-256 GCM + RSA-3072", font=ctk.CTkFont(size=14))
        self.subheader.grid(row=1, column=0, padx=20, pady=(0, 20))

        # Frames for different sections
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
        
        btn_generate = ctk.CTkButton(self.key_frame, text="Generate RSA Keys", command=self.generate_keys)
        btn_generate.grid(row=0, column=1, padx=10, pady=10, sticky="e")

    def _setup_encrypt_section(self):
        self.encrypt_frame.grid_columnconfigure(1, weight=1)
        
        lbl = ctk.CTkLabel(self.encrypt_frame, text="2. Encryption", font=ctk.CTkFont(weight="bold"))
        lbl.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        btn_encrypt = ctk.CTkButton(self.encrypt_frame, text="Select File to Encrypt", command=self.encrypt_action)
        btn_encrypt.grid(row=0, column=1, padx=10, pady=10, sticky="e")

    def _setup_decrypt_section(self):
        self.decrypt_frame.grid_columnconfigure(1, weight=1)
        
        lbl = ctk.CTkLabel(self.decrypt_frame, text="3. Decryption", font=ctk.CTkFont(weight="bold"))
        lbl.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        btn_decrypt = ctk.CTkButton(self.decrypt_frame, text="Select File to Decrypt", command=self.decrypt_action)
        btn_decrypt.grid(row=0, column=1, padx=10, pady=10, sticky="e")

    def generate_keys(self):
        try:
            generate_rsa_keys("private.pem", "public.pem")
            messagebox.showinfo("Success", "RSA-3072 key pair generated successfully!\n(private.pem, public.pem)")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")

    def encrypt_action(self):
        if not os.path.exists("public.pem"):
            messagebox.showerror("Error", "Public key (public.pem) not found. Please generate keys first.")
            return

        input_file = filedialog.askopenfilename(title="Select File to Encrypt")
        if not input_file:
            return

        output_file = filedialog.asksaveasfilename(
            title="Save Encrypted File As",
            defaultextension=".enc",
            initialfile=os.path.basename(input_file) + ".enc"
        )
        if not output_file:
            return

        try:
            encrypt_file("public.pem", input_file, output_file)
            messagebox.showinfo("Success", f"File successfully encrypted using AES-256 and RSA-3072!\nSaved to: {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_action(self):
        if not os.path.exists("private.pem"):
            messagebox.showerror("Error", "Private key (private.pem) not found. Please generate keys or place them in the directory.")
            return

        input_file = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        if not input_file:
            return

        # Try to guess original extension if possible, otherwise default to .decrypted
        default_out = input_file.replace(".enc", "")
        if default_out == input_file:
            default_out += ".decrypted"
            
        output_file = filedialog.asksaveasfilename(
            title="Save Decrypted File As",
            initialfile=os.path.basename(default_out)
        )
        if not output_file:
            return

        try:
            decrypt_file("private.pem", input_file, output_file)
            messagebox.showinfo("Success", f"File successfully decrypted and integrity verified!\nSaved to: {output_file}")
        except InvalidTag:
            messagebox.showerror("Integrity Error", "Decryption failed!\nThe file has been tampered with or corrupted.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    app = HybridEncryptionApp()
    app.mainloop()
