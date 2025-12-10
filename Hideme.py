# video_encryptor_pro.py
# Save this as video_encryptor_pro.py on your Windows machine

import os
import sys
import secrets
import logging
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# ========================== LOGGING SETUP ==========================
logging.basicConfig(
    filename='video_encryptor.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger()
log.addHandler(logging.StreamHandler(sys.stdout))  # Also print to console

# ========================== KEY DERIVATION ==========================
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,  # Stronger than before
        backend=None
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# ========================== ENCRYPT ==========================
def encrypt_file(input_path: Path, password: str):
    try:
        if not input_path.exists():
            log.error(f"File not found: {input_path}")
            return

        log.info(f"Reading file: {input_path}")
        original_data = input_path.read_bytes()

        # Generate random salt + store it at the beginning of encrypted file
        salt = secrets.token_bytes(16)
        key = derive_key_from_password(password, salt)
        fernet = Fernet(key)

        encrypted_data = fernet.encrypt(original_data)

        # Prepend salt so we can decrypt later
        final_data = salt + encrypted_data

        # Gibberish filename (12 random chars + .enc)
        gibberish = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(12))
        encrypted_path = input_path.parent / f"{gibberish}.enc"

        encrypted_path.write_bytes(final_data)
        log.info(f"Encrypted successfully → {encrypted_path}")

        # Optional: delete original (uncomment next 2 lines if you want auto-delete)
        # input_path.unlink()
        # log.info(f"Original file deleted: {input_path}")

    except Exception as e:
        log.error(f"Encryption failed: {e}")

# ========================== DECRYPT ==========================
def decrypt_file(encrypted_path: Path, password: str):
    try:
        if not encrypted_path.exists():
            log.error(f"Encrypted file not found: {encrypted_path}")
            return

        data = encrypted_path.read_bytes()
        if len(data) < 16:
            log.error("File too small — probably not encrypted with this tool")
            return

        salt = data[:16]
        encrypted_data = data[16:]

        key = derive_key_from_password(password, salt)
        fernet = Fernet(key)

        decrypted_data = fernet.decrypt(encrypted_data)

        # Try to preserve original filename + extension
        original_name = encrypted_path.stem + "_RESTORED" + encrypted_path.suffix.replace(".enc", "")
        if not original_name.endswith(('.mp4', '.mkv', '.avi', '.mov', '.webm')):
            original_name = encrypted_path.stem + "_RESTORED.mp4"

        output_path = encrypted_path.parent / original_name
        output_path.write_bytes(decrypted_data)

        log.info(f"Decrypted successfully → {output_path}")

    except InvalidToken:
        log.error("Wrong password or file corrupted!")
    except Exception as e:
        log.error(f"Decryption failed: {e}")

# ========================== MAIN ==========================
if __name__ == "__main__":
    print("\nVideo File Encrypter/Decrypter (Windows)\n")
    log.info("=== Script started ===")

    mode = input("Encrypt or Decrypt? (e/d): ").strip().lower()
    if mode not in ('e', 'd'):
        log.error("Invalid choice. Type 'e' or 'd'")
        input("Press Enter to exit...")
        sys.exit()

    path_input = input("Drag & drop the file here or paste full path:\n> ").strip().strip('"\'')
    file_path = Path(path_input)

    if not file_path.exists():
        log.error("Path not valid or file doesn't exist!")
        input("Press Enter to exit...")
        sys.exit()

    password = input("Enter password: ")  # You can hide input with getpass if you want

    if mode == 'e':
        encrypt_file(file_path, password)
    else:
        decrypt_file(file_path, password)

    print("\nDone! Check video_encryptor.log for details.")
    log.info("=== Script finished ===\n")
    input("\nPress Enter to close...")