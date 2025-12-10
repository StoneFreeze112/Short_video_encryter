# Save as: Hideme.py
# Double-click to run on Windows – loops forever + auto-deletes original

import os
import sys
import secrets
import logging
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# ========================== LOGGING ==========================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    handlers=[
        logging.FileHandler('Hideme_log.txt', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_and_delete_original(input_path: Path, password: str):
    try:
        data = input_path.read_bytes()
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        encrypted = Fernet(key).encrypt(data)
        final = salt + encrypted

        gibberish = secrets.token_hex(8)  # e.g. a3f9e2d1c7b4
        encrypted_path = input_path.parent / f"{gibberish}.enc"
        encrypted_path.write_bytes(final)

        # PERMANENTLY DELETE ORIGINAL
        input_path.unlink()
        
        log.info(f"ENCRYPTED & ORIGINAL DELETED → {encrypted_path.name}")
        print(f"\nENCRYPTED + ORIGINAL DELETED")
        print(f"   New file → {encrypted_path.name}")
    except Exception as e:
        log.error(f"Encryption failed: {e}")
        print(f"\nERROR: {e}")

def decrypt_file(enc_path: Path, password: str):
    try:
        data = enc_path.read_bytes()
        if len(data) < 16:
            print("Not a valid .enc file!")
            return
        salt, encrypted_data = data[:16], data[16:]
        decrypted = Fernet(derive_key(password, salt)).decrypt(encrypted_data)

        restored_name = enc_path.stem + "_RESTORED.mp4"
        out_path = enc_path.parent / restored_name
        out_path.write_bytes(decrypted)

        log.info(f"DECRYPTED → {out_path.name}")
        print(f"\nDECRYPTED SUCCESSFULLY")
        print(f"   Restored → {out_path.name}")
    except InvalidToken:
        print("\nWrong password!")
    except Exception as e:
        log.error(f"Decryption failed: {e}")
        print(f"\nERROR: {e}")

# ========================== MAIN LOOP ==========================
if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 65)
    print("          HIDEME – Infinite Loop Version")
    print("   Encrypt → original deleted automatically")
    print("   Works forever until you close the window")
    print("=" * 65)

    while True:
        print("\n" + "—" * 50)
        mode = input("\n(e)ncrypt  |  (d)ecrypt  |  (q)uit → ").strip().lower()

        if mode == 'q':
            print("\nGoodbye! Stay safe.")
            break
        if mode not in ('e', 'd'):
            print("Please type e, d or q")
            continue

        print("\nDrag & drop file or paste full path:")
        path_input = input("→ ").strip().strip('"\'')
        file_path = Path(path_input)

        if not file_path.exists():
            print("File not found! Try again.")
            continue

        password = input("\nEnter password → ")

        if mode == 'e':
            print("\nEncrypting and deleting original in 3 seconds...")
            for i in range(3, 0, -1):
                print(f"   {i}...", end="\r")
                import time; time.sleep(1)
            encrypt_and_delete_original(file_path, password)
        else:
            decrypt_file(file_path, password)

        print("\nReady for next file...")
        input("\nPress Enter to continue...")

    print("\nHideme closed.")
    input("Press Enter to exit window...")