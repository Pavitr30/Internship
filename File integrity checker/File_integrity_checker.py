import os
import hashlib
import json
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

HASH_FILE = "hash_store.json"

def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None

def scan_folder(folder):
    file_hashes = {}
    for root, _, files in os.walk(folder):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = calculate_hash(filepath)
            if file_hash:
                file_hashes[filepath] = file_hash
    return file_hashes

def load_baseline():
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as f:
            return json.load(f)
    return {}

def save_baseline(baseline):
    with open(HASH_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

def check_integrity(folder, output_box):
    output_box.delete("1.0", tk.END)
    current_hashes = scan_folder(folder)
    baseline = load_baseline()

    changes_detected = False

    for filepath, filehash in current_hashes.items():
        if filepath not in baseline:
            output_box.insert(tk.END, f"[NEW FILE] {filepath}\n")
            changes_detected = True
        elif baseline.get(filepath) != filehash:
            output_box.insert(tk.END, f"[MODIFIED] {filepath}\n")
            changes_detected = True

    for filepath in baseline:
        if filepath not in current_hashes:
            output_box.insert(tk.END, f"[DELETED] {filepath}\n")
            changes_detected = True

    if not changes_detected:
        output_box.insert(tk.END, "\u2611 No changes detected.\n")
    else:
        output_box.insert(tk.END, "Changes detected. Baseline updated.\n")
        save_baseline(current_hashes)

# GUI setup
def start_gui():
    window = tk.Tk()
    window.title("Folder Integrity Checker")
    window.geometry("600x400")

    folder_path = tk.StringVar()

    path_entry = tk.Entry(window, textvariable=folder_path, width=50)
    path_entry.pack(pady=10)

    def browse_folder():
        path = filedialog.askdirectory()
        if path:
            folder_path.set(path)

    browse_btn = tk.Button(window, text="Browse Folder", command=browse_folder)
    browse_btn.pack(pady=5)

    output_box = ScrolledText(window, width=70, height=15)
    output_box.pack(pady=10)

    check_btn = tk.Button(window, text="Check Folder Integrity", command=lambda: check_integrity(folder_path.get(), output_box))
    check_btn.pack(pady=5)

    window.mainloop()

if __name__ == "__main__":
    start_gui()
