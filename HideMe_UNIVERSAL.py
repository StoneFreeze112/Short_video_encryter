# Save as: Hideme_UNIVERSAL_FIXED.py
# Run with: python Hideme_UNIVERSAL_FIXED.py
# Now TRULY handles VERY OLD (no salt), LATER OLD (prepended salt), + NEW files automatically

import os
import secrets
import logging
import base64
from pathlib import Path
from cryptography.fernet import Fernet
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

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# ========================== BULK ENCRYPT (NEW FORMAT ONLY) ==========================
def bulk_encrypt(file_list, password):
    success = 0
    for file_path in file_list:
        try:
            data = file_path.read_bytes()
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000)
            key = kdf.derive(password.encode())
            nonce = secrets.token_bytes(12)
            ct = AESGCM(key).encrypt(nonce, data, None)

            new_name = secrets.token_hex(12) + ".enc"
            enc_path = file_path.parent / new_name
            enc_path.write_bytes(salt + nonce + ct)

            file_path.unlink()                     # DELETE ORIGINAL
            success += 1
            print(f"Encrypted (new format) → {enc_path.name}")
            log.info(f"Encrypted {file_path.name}")
        except Exception as e:
            print(f"Failed {file_path.name} → {e}")

    print(f"\nFinished! {success} files encrypted and originals deleted.")

# ========================== UNIVERSAL DECRYPT (ALL FORMATS) ==========================
def universal_decrypt(enc_file: Path, password):
    try:
        data = enc_file.read_bytes()
        if len(data) < 28:
            raise ValueError("Too small")

        # Try as new AES-GCM
        salt = data[:16]
        nonce = data[16:28]
        ct = data[28:]
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000)
        key = kdf.derive(password.encode())
        pt = AESGCM(key).decrypt(nonce, ct, None)
        format_type = "new AES-GCM"
        out = enc_file.with_name(enc_file.stem + "_RECOVERED.mp4")
        out.write_bytes(pt)
        print(f"Decrypted ({format_type}) → {out.name}")
        log.info(f"Decrypted {enc_file.name} ({format_type})")
        return True

    except:
        pass  # Not new, try next

    try:
        # Try as later old Fernet with prepended salt
        salt = data[:16]
        token = data[16:]
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        pt = Fernet(key).decrypt(token)
        format_type = "later old Fernet"
        out = enc_file.with_name(enc_file.stem + "_RECOVERED.mp4")
        out.write_bytes(pt)
        print(f"Decrypted ({format_type}) → {out.name}")
        log.info(f"Decrypted {enc_file.name} ({format_type})")
        return True

    except:
        pass  # Not later old, try very old

    try:
        # Try as very old Fernet (no prepend, fixed salt, 100000 iterations)
        salt = b'salt_123'
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        pt = Fernet(key).decrypt(data)
        format_type = "very old Fernet"
        out = enc_file.with_name(enc_file.stem + "_RECOVERED.mp4")
        out.write_bytes(pt)
        print(f"Decrypted ({format_type}) → {out.name}")
        log.info(f"Decrypted {enc_file.name} ({format_type})")
        return True

    except Exception as e:
        print(f"Password doesn't work or unknown format for {enc_file.name} → skipped ({e})")
        log.warning(f"Failed {enc_file.name}: {e}")
        return False

# ========================== BULK DECRYPT ==========================
def bulk_decrypt(file_list, password):
    success = 0
    for enc_file in file_list:
        if enc_file.suffix != '.enc':
            print(f"Skipping non-.enc: {enc_file.name}")
            continue
        if universal_decrypt(enc_file, password):
            success += 1

    print(f"\nFinished! {success} files decrypted successfully.")

# ========================== MAIN ==========================
while True:
    clear()
    print("=" * 70)
    print("          HIDEME – UNIVERSAL ENCRYPT/DECRYPT (NOW FIXED FOR ALL OLD FORMATS)")
    print("     Handles VERY OLD + LATER OLD + NEW .enc files automatically")
    print("=" * 70)
    print("(e) Bulk encrypt (new format)")
    print("(d) Bulk decrypt (any format)")
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
