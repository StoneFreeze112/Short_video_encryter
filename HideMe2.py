# Save as: Hideme.py  (double-click → infinite loop + screen refresh every time)

import os
import sys
import secrets
import logging
import time
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

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_header():
    clear_screen()
    print("=" * 65)
    print("               HIDEME – Clean Refresh Edition")
    print("       Encrypt → original deleted instantly")
    print("       Screen resets after every file")
    print("=" * 65)

def encrypt_and_delete(input_path: Path, password: str):
    try:
        data = input_path.read_bytes()
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        encrypted = Fernet(key).encrypt(data)

        new_name = secrets.token_hex(8) + ".enc"      # e.g. a1b2c3d4e5f6.enc
        enc_path = input_path.with_name(new_name)
        enc_path.write_bytes(salt + encrypted)

        input_path.unlink()  # PERMANENT DELETE
        print(f"\nENCRYPTED + ORIGINAL DELETED")
        print(f"   → {enc_path.name}")
        log.info(f"Success → {enc_path.name}")
    except Exception as e:
        print(f"\nERROR: {e}")
        log.error(e)

def decrypt_file(enc_path: Path, password: str):
    try:
        data = enc_path.read_bytes()
        if len(data) < 16:
            print("Not a valid .enc file!")
            return
        salt, enc_data = data[:16], data[16:]
        decrypted = Fernet(derive_key(password, salt)).decrypt(enc_data)

        out_path = enc_path.with_name(enc_path.stem + "_RESTORED.mp4")
        out_path.write_bytes(decrypted)
        print(f"\nDECRYPTED SUCCESSFULLY")
        print(f"   → {out_path.name}")
        log.info(f"Decrypted → {out_path.name}")
    except InvalidToken:
        print("\nWrong password!")
    except Exception as e:
        print(f"\nERROR: {e}")
        log.error(e)

# ========================== MAIN LOOP ==========================
if __name__ == "__main__":
    while True:
        show_header()

        choice = input("\n(e)ncrypt   (d)ecrypt   (q)uit → ").strip().lower()
        if choice == 'q':
            clear_screen()
            print("\nHideme closed. Stay safe!")
            time.sleep(1.5)
            break
        if choice not in ('e', 'd'):
            input("\nInvalid → press Enter...")
            continue

        print("\nDrag file here or paste path:")
        path_str = input("→ ").strip().strip('"\'')
        file = Path(path_str)
        if not file.exists():
            input("\nFile not found → press Enter...")
            continue

        pwd = input("\nPassword → ")

        clear_screen()
        print("Working...\n")

        if choice == 'e':
            encrypt_and_delete(file, pwd)
        else:
            decrypt_file(file, pwd)

        input("\nPress Enter for a fresh start...")