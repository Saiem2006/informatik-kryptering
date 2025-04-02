import os
import logging
import sqlite3
import bcrypt
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# ========== LOGGING ==========
logging.basicConfig(filename="file_sharing.log", level=logging.INFO)

# ========== DATABASE SETUP ==========
conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
""")
conn.commit()

# ========== BRUGER LOGIN ==========


def register_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        messagebox.showinfo("✅ Succes", "Bruger registreret!")
    except sqlite3.IntegrityError:
        messagebox.showerror("❌ Fejl", "Brugernavn allerede taget!")


def login_user(username, password):
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user and bcrypt.checkpw(password.encode(), user[0]):
        messagebox.showinfo("✅ Succes", "Login succesfuldt!")
    else:
        messagebox.showerror("❌ Fejl", "Forkert brugernavn eller adgangskode!")

# ========== RSA NØGLE GENERERING ==========


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    messagebox.showinfo("✅ Succes", "RSA nøgler genereret!")


# ========== AES FIL-KRYPTERING ==========
SECURE_FOLDER = "EncryptedFiles"
if not os.path.exists(SECURE_FOLDER):
    os.makedirs(SECURE_FOLDER)


def encrypt_file():
    file_path = filedialog.askopenfilename(title="Vælg en fil til kryptering")
    if not file_path:
        return

    aes_key = os.urandom(32)
    iv = os.urandom(16)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    original_filename = os.path.basename(file_path).encode() + b'\n'
    plaintext = original_filename + plaintext

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = plaintext + b' ' * (16 - len(plaintext) % 16)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    encrypted_file_path = os.path.join(
        SECURE_FOLDER, os.path.basename(file_path) + ".enc")
    with open(encrypted_file_path, "wb") as ef:
        ef.write(iv + aes_key + ciphertext)

    messagebox.showinfo("✅ Succes", f"Fil krypteret: {encrypted_file_path}")

# ========== AES FIL-DEKRYPTERING ==========


def decrypt_file():
    encrypted_file_path = filedialog.askopenfilename(
        title="Vælg en krypteret fil til dekryptering")
    if not encrypted_file_path:
        return

    with open(encrypted_file_path, "rb") as ef:
        iv = ef.read(16)
        aes_key = ef.read(32)
        ciphertext = ef.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = plaintext.rstrip(b' ')

    original_filename, plaintext = plaintext.split(b'\n', 1)
    original_filename = original_filename.decode()

    decrypted_file_path = os.path.join(
        os.path.dirname(encrypted_file_path), original_filename)
    with open(decrypted_file_path, "wb") as df:
        df.write(plaintext)

    messagebox.showinfo("✅ Succes", f"Fil dekrypteret: {decrypted_file_path}")


# ========== GUI DESIGN ==========
ctk.set_appearance_mode("dark")
root = ctk.CTk()
root.title("Secure File Sharing")
root.geometry("500x500")

frame = ctk.CTkFrame(root, corner_radius=15)
frame.pack(pady=20, padx=20, fill="both", expand=True)

title_label = ctk.CTkLabel(
    frame, text="🔒 Secure File Sharing", font=("Arial", 24, "bold"))
title_label.pack(pady=20)

entry_username = ctk.CTkEntry(frame, placeholder_text="Brugernavn", width=250)
entry_username.pack(pady=5)
entry_password = ctk.CTkEntry(
    frame, placeholder_text="Adgangskode", show="*", width=250)
entry_password.pack(pady=5)

btn_register = ctk.CTkButton(frame, text="🆕 Registrér", command=lambda: register_user(
    entry_username.get(), entry_password.get()), width=250)
btn_register.pack(pady=5)
btn_login = ctk.CTkButton(frame, text="🔑 Login", command=lambda: login_user(
    entry_username.get(), entry_password.get()), width=250)
btn_login.pack(pady=5)

btn_encrypt = ctk.CTkButton(frame, text="🛡 Kryptér fil",
                            command=encrypt_file, fg_color="#0066ff", width=250)
btn_encrypt.pack(pady=10)
btn_decrypt = ctk.CTkButton(frame, text="🔓 Dekryptér fil",
                            command=decrypt_file, fg_color="#33cc33", width=250)
btn_decrypt.pack(pady=10)

btn_generate_rsa = ctk.CTkButton(
    frame, text="🔑 Generér RSA Nøgler", command=generate_rsa_keys, fg_color="#ff6600", width=250)
btn_generate_rsa.pack(pady=10)

root.mainloop()
