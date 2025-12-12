# Save as: Hideme_BULK_WORKING.py
# Run with: python Hideme_BULK_WORKING.py
# Now with BULK DECRYPT too → skips files with wrong password

import os
import secrets
import logging
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.FileHandler('Hideme_log.txt', encoding='utf-8'),
              logging.StreamHandler()]
)
log = logging.getLogger()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000)
    return kdf.derive(password.encode())

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# ========================== BULK ENCRYPT ==========================
def bulk_encrypt(file_list, password):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    success = 0

    for file_path in file_list:
        try:
            data = file_path.read_bytes()
            nonce = secrets.token_bytes(12)
            ct = AESGCM(key).encrypt(nonce, data, None)

            new_name = secrets.token_hex(12) + ".enc"
            enc_path = file_path.parent / new_name
            enc_path.write_bytes(salt + nonce + ct)

            file_path.unlink()                     # DELETE ORIGINAL
            success += 1
            print(f"Encrypted → {enc_path.name}")
            log.info(f"Encrypted {file_path.name}")
        except Exception as e:
            print(f"Failed {file_path.name} → {e}")

    print(f"\nFinished! {success} files encrypted and originals deleted.")

# ========================== BULK DECRYPT ==========================
def bulk_decrypt(file_list, password):
    success = 0
    for enc_file in file_list:
        if not enc_file.suffix == '.enc':
            print(f"Skipping non-.enc: {enc_file.name}")
            continue
        try:
            data = enc_file.read_bytes()
            if len(data) < 28:
                raise ValueError("Too small")
            salt, nonce, ct = data[:16], data[16:28], data[28:]
            key = derive_key(password, salt)
            pt = AESGCM(key).decrypt(nonce, ct, None)
            out = enc_file.with_name(enc_file.stem + "_RECOVERED.mp4")
            out.write_bytes(pt)
            success += 1
            print(f"Decrypted → {out.name}")
            log.info(f"Decrypted {enc_file.name}")
        except Exception:
            print(f"Password doesn't work for {enc_file.name} (or corrupted) → skipped")
            log.warning(f"Wrong password for {enc_file.name}")

    print(f"\nFinished! {success} files decrypted successfully.")

# ========================== MAIN ==========================
while True:
    clear()
    print("=" * 70)
    print("          HIDEME – BULK ENCRYPT/DECRYPT (WORKS PERFECTLY)")
    print("=" * 70)
    print("(e) Bulk encrypt")
    print("(d) Bulk decrypt")
    print("(q) Quit")
    choice = input("\nChoose → ").strip().lower()

    if choice == 'q':
        print("\nBye!")
        break
    if choice not in ('e', 'd'):
        input("Type e, d or q...")
        continue

    print("\nPaste the paths exactly as Windows gives them (with quotes and spaces):")
    raw_input = input("→ ").strip()

    import shlex
    try:
        paths = [Path(p) for p in shlex.split(raw_input)]
    except:
        paths = [Path(raw_input.strip('"'))]   # fallback

    valid_files = []
    for p in paths:
        if p.is_dir():
            valid_files.extend(p.rglob("*.*"))
        elif p.is_file():
            valid_files.append(p)

    if not valid_files:
        print("No files found — check your paths")
        input("Press Enter...")
        continue

    password = input("\nPassword → ")

    if choice == 'e':
        bulk_encrypt(valid_files, password)
    else:
        bulk_decrypt(valid_files, password)

    input("\nPress Enter to continue...")
