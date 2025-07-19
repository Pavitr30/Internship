import os
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
import base64
import secrets

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath, password):
    try:
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        iv = secrets.token_bytes(16)

        with open(filepath, 'rb') as f:
            plaintext = f.read()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_data = salt + iv + ciphertext
        with open(filepath + ".enc", 'wb') as f:
            f.write(encrypted_data)

        messagebox.showinfo("Success", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_file(filepath, password):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        output_path = filepath + ".dec"
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def encrypt_file_gui():
    filepath = filedialog.askopenfilename()
    if filepath:
        password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
        if password:
            encrypt_file(filepath, password)

def decrypt_file_gui():
    filepath = filedialog.askopenfilename()
    if filepath:
        password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
        if password:
            decrypt_file(filepath, password)

# GUI setup
root = tk.Tk()
root.title("AES-256 File Encryption Tool")
root.geometry("350x200")

label = tk.Label(root, text="AES-256 Encryption Tool", font=("Arial", 16))
label.pack(pady=20)

encrypt_button = tk.Button(root, text="Encrypt File", width=20, command=encrypt_file_gui)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt File", width=20, command=decrypt_file_gui)
decrypt_button.pack(pady=10)

root.mainloop()
