import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


MAGIC_HEADER = b"SOBOENC1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256 bit AES
PBKDF2_ITERATIONS = 200_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aes.encrypt(nonce, data, None)
    return MAGIC_HEADER + salt + nonce + ciphertext


def decrypt_data(blob: bytes, password: str) -> bytes:
    if not blob.startswith(MAGIC_HEADER):
        raise ValueError("File does not look like a SoboEncrypt file")

    offset = len(MAGIC_HEADER)
    salt = blob[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = blob[offset:]

    key = derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)


class SoboEncryptApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SoboEncrypt v1  |  SoboCorp")
        self.root.minsize(560, 320)
        self.root.configure(bg="#030816")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#030816")
        style.configure("TLabel", background="#030816", foreground="#f5f5ff")
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#7aa9ff")
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("TNotebook", background="#030816", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(10, 4), font=("Segoe UI", 10))
        style.map(
            "TButton",
            foreground=[("active", "#030816")],
            background=[("active", "#7aa9ff")]
        )

        outer = ttk.Frame(root, padding=16, style="TFrame")
        outer.pack(fill="both", expand=True)

        header = ttk.Label(outer, text="SoboEncrypt", style="Header.TLabel")
        header.grid(row=0, column=0, sticky="w", pady=(0, 4))

        subtitle = ttk.Label(outer, text="SoboCorp file encryption utility", style="TLabel")
        subtitle.grid(row=1, column=0, sticky="w", pady=(0, 10))

        ttk.Separator(outer, orient="horizontal").grid(
            row=2, column=0, sticky="ew", pady=(0, 10)
        )

        # Notebook (tabs)
        notebook = ttk.Notebook(outer)
        notebook.grid(row=3, column=0, sticky="nsew")

        outer.rowconfigure(3, weight=1)
        outer.columnconfigure(0, weight=1)

        # Encrypt tab
        self.encrypt_frame = ttk.Frame(notebook, padding=12, style="TFrame")
        notebook.add(self.encrypt_frame, text="Encrypt")

        # Decrypt tab
        self.decrypt_frame = ttk.Frame(notebook, padding=12, style="TFrame")
        notebook.add(self.decrypt_frame, text="Decrypt")

        # Status bar
        self.status_var = tk.StringVar(value="Ready.")
        status_label = ttk.Label(outer, textvariable=self.status_var, style="TLabel")
        status_label.grid(row=4, column=0, sticky="w", pady=(8, 0))

        # Build tab UIs
        self.build_encrypt_tab()
        self.build_decrypt_tab()

    # ---------- ENCRYPT TAB ----------

    def build_encrypt_tab(self):
        f = self.encrypt_frame

        ttk.Label(f, text="File to encrypt:", style="TLabel").grid(
            row=0, column=0, sticky="w"
        )

        self.enc_file_var = tk.StringVar()
        enc_entry = ttk.Entry(f, textvariable=self.enc_file_var, width=48)
        enc_entry.grid(row=1, column=0, sticky="ew", pady=4)

        enc_browse = ttk.Button(f, text="Browse", command=self.browse_encrypt_file)
        enc_browse.grid(row=1, column=1, sticky="e", padx=(8, 0))

        # Passwords
        ttk.Label(f, text="Password:", style="TLabel").grid(
            row=2, column=0, sticky="w", pady=(10, 0)
        )
        self.enc_pw_var = tk.StringVar()
        enc_pw_entry = ttk.Entry(f, textvariable=self.enc_pw_var, show="•", width=32)
        enc_pw_entry.grid(row=3, column=0, sticky="w", pady=4)

        ttk.Label(f, text="Confirm password:", style="TLabel").grid(
            row=2, column=1, sticky="w", pady=(10, 0)
        )
        self.enc_pw_confirm_var = tk.StringVar()
        enc_pw_confirm_entry = ttk.Entry(
            f, textvariable=self.enc_pw_confirm_var, show="•", width=32
        )
        enc_pw_confirm_entry.grid(row=3, column=1, sticky="w", pady=4)

        # Encrypt button
        enc_btn = ttk.Button(f, text="Encrypt file", command=self.encrypt_action)
        enc_btn.grid(row=4, column=0, sticky="w", pady=(14, 0))

        # Layout
        f.columnconfigure(0, weight=1)
        f.columnconfigure(1, weight=1)

    def browse_encrypt_file(self):
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if path:
            self.enc_file_var.set(path)
            self.status_var.set("Selected for encryption: " + os.path.basename(path))

    def encrypt_action(self):
        path = self.enc_file_var.get().strip()
        if not path:
            messagebox.showwarning("SoboEncrypt", "Select a file to encrypt.")
            return

        if not os.path.exists(path):
            messagebox.showerror("SoboEncrypt", "File does not exist.")
            return

        password = self.enc_pw_var.get()
        confirm = self.enc_pw_confirm_var.get()

        if not password:
            messagebox.showwarning("SoboEncrypt", "Enter a password.")
            return

        if password != confirm:
            messagebox.showerror("SoboEncrypt", "Passwords do not match.")
            return

        base, ext = os.path.splitext(path)
        suggested = base + ".sobo"
        out_path = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            defaultextension=".sobo",
            initialfile=os.path.basename(suggested),
            filetypes=[("Sobo encrypted file", "*.sobo"), ("All files", "*.*")]
        )
        if not out_path:
            return

        try:
            with open(path, "rb") as f:
                raw = f.read()
            blob = encrypt_data(raw, password)
            with open(out_path, "wb") as f:
                f.write(blob)
        except Exception as e:
            messagebox.showerror("SoboEncrypt", f"Encryption failed.\n\n{e}")
            self.status_var.set("Encryption failed.")
            return

        self.status_var.set(f"Encrypted to: {os.path.basename(out_path)}")
        messagebox.showinfo("SoboEncrypt", "Encryption complete.")

    # ---------- DECRYPT TAB ----------

    def build_decrypt_tab(self):
        f = self.decrypt_frame

        ttk.Label(f, text="File to decrypt (.sobo):", style="TLabel").grid(
            row=0, column=0, sticky="w"
        )

        self.dec_file_var = tk.StringVar()
        dec_entry = ttk.Entry(f, textvariable=self.dec_file_var, width=48)
        dec_entry.grid(row=1, column=0, sticky="ew", pady=4)

        dec_browse = ttk.Button(f, text="Browse", command=self.browse_decrypt_file)
        dec_browse.grid(row=1, column=1, sticky="e", padx=(8, 0))

        # Password
        ttk.Label(f, text="Password:", style="TLabel").grid(
            row=2, column=0, sticky="w", pady=(10, 0)
        )
        self.dec_pw_var = tk.StringVar()
        dec_pw_entry = ttk.Entry(f, textvariable=self.dec_pw_var, show="•", width=32)
        dec_pw_entry.grid(row=3, column=0, sticky="w", pady=4)

        # Decrypt button
        dec_btn = ttk.Button(f, text="Decrypt file", command=self.decrypt_action)
        dec_btn.grid(row=4, column=0, sticky="w", pady=(14, 0))

        f.columnconfigure(0, weight=1)
        f.columnconfigure(1, weight=1)

    def browse_decrypt_file(self):
        path = filedialog.askopenfilename(
            title="Select file to decrypt",
            filetypes=[("Sobo encrypted file", "*.sobo"), ("All files", "*.*")]
        )
        if path:
            self.dec_file_var.set(path)
            self.status_var.set("Selected for decryption: " + os.path.basename(path))

    def decrypt_action(self):
        path = self.dec_file_var.get().strip()
        if not path:
            messagebox.showwarning("SoboEncrypt", "Select a file to decrypt.")
            return

        if not os.path.exists(path):
            messagebox.showerror("SoboEncrypt", "File does not exist.")
            return

        password = self.dec_pw_var.get()
        if not password:
            messagebox.showwarning("SoboEncrypt", "Enter the password.")
            return

        base, ext = os.path.splitext(path)
        suggested = base + "_decrypted"
        out_path = filedialog.asksaveasfilename(
            title="Save decrypted file as",
            initialfile=os.path.basename(suggested),
            filetypes=[("All files", "*.*")]
        )
        if not out_path:
            return

        try:
            with open(path, "rb") as f:
                blob = f.read()
            plain = decrypt_data(blob, password)
            with open(out_path, "wb") as f:
                f.write(plain)
        except Exception as e:
            messagebox.showerror("SoboEncrypt", f"Decryption failed.\n\n{e}")
            self.status_var.set("Decryption failed.")
            return

        self.status_var.set(f"Decrypted to: {os.path.basename(out_path)}")
        messagebox.showinfo("SoboEncrypt", "Decryption complete.")


if __name__ == "__main__":
    root = tk.Tk()
    app = SoboEncryptApp(root)
    root.mainloop()
