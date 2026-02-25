import os
import json
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet

KEY_FILE = "key.key"
META_FILE = "metadata.json"
ENC_FOLDER = "encrypted_files"

# Generate key if not exists
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)

def load_key():
    return open(KEY_FILE, "rb").read()

def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

def encrypt_file(file_path):
    key = load_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)

    filename = os.path.basename(file_path)
    enc_path = os.path.join(ENC_FOLDER, filename + ".enc")

    with open(enc_path, "wb") as f:
        f.write(encrypted)

    file_hash = calculate_hash(file_path)

    metadata = {
        "original_name": filename,
        "encrypted_name": filename + ".enc",
        "hash": file_hash,
        "timestamp": str(datetime.now())
    }

    save_metadata(metadata)

    print("✅ File Encrypted Successfully")

def decrypt_file(enc_filename):
    key = load_key()
    fernet = Fernet(key)

    enc_path = os.path.join(ENC_FOLDER, enc_filename)

    with open(enc_path, "rb") as f:
        encrypted_data = f.read()

    decrypted = fernet.decrypt(encrypted_data)

    original_name = enc_filename.replace(".enc", "")
    output_path = "decrypted_" + original_name

    with open(output_path, "wb") as f:
        f.write(decrypted)

    print("✅ File Decrypted Successfully")

def save_metadata(new_entry):
    try:
        with open(META_FILE, "r") as f:
            data = json.load(f)
    except:
        data = []

    data.append(new_entry)

    with open(META_FILE, "w") as f:
        json.dump(data, f, indent=4)

def menu():
    print("\n1. Encrypt File")
    print("2. Decrypt File")
    choice = input("Choose option: ")

    if choice == "1":
        path = input("Enter file path: ")
        encrypt_file(path)

    elif choice == "2":
        name = input("Enter encrypted file name (.enc): ")
        decrypt_file(name)

generate_key()

if __name__ == "__main__":
    menu()