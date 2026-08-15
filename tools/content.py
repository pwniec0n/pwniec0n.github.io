#!/usr/bin/env python3

import argparse
import base64
import getpass
import json
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


ROOT = Path(__file__).resolve().parent.parent

ENCRYPTED_FILE = ROOT / "js" / "content.enc.js"
DECRYPTED_DIR = ROOT / "decrypted"
CONTENT_FILE = DECRYPTED_DIR / "content.html"

PBKDF2_ITERATIONS = 100_000


def fail(message: str) -> None:
    print()
    print(f"ERROR: {message}")
    print()
    raise SystemExit(1)


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data)


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )

    return kdf.derive(
        password.encode("utf-8")
    )


def encrypt_content(
    content: bytes,
    password: str
) -> dict:

    salt = os.urandom(16)
    iv = os.urandom(12)

    key = derive_key(
        password,
        salt
    )

    cipher = AESGCM(key).encrypt(
        iv,
        content,
        None
    )

    return {
        "salt": b64encode(salt),
        "iv": b64encode(iv),
        "cipher": b64encode(cipher),
    }


def decrypt_content(
    data: dict,
    password: str
) -> bytes:

    try:
        salt = b64decode(
            data["salt"]
        )

        iv = b64decode(
            data["iv"]
        )

        cipher = b64decode(
            data["cipher"]
        )

    except (
        KeyError,
        ValueError
    ) as exc:
        raise ValueError(
            "Encrypted data has an invalid format."
        ) from exc

    key = derive_key(
        password,
        salt
    )

    return AESGCM(key).decrypt(
        iv,
        cipher,
        None
    )


def read_encrypted_file() -> dict:
    if not ENCRYPTED_FILE.exists():
        fail(
            f"Encrypted content not found: "
            f"{ENCRYPTED_FILE.relative_to(ROOT)}"
        )

    source = ENCRYPTED_FILE.read_text(
        encoding="utf-8"
    )

    match = re.search(
        r"""(?:const|let|var)\s+ct_serial\s*=\s*["']([^"']+)["']""",
        source
    )

    if not match:
        fail(
            "Unable to find ct_serial in "
            "js/content.enc.js"
        )

    value = match.group(1)

    if (
        not value or
        value == "PASTE_YOUR_EXISTING_CT_SERIAL_VALUE_HERE"
    ):
        fail(
            "js/content.enc.js does not contain "
            "a real encrypted payload yet."
        )

    try:
        serialized = base64.b64decode(
            value,
            validate=True
        )

        data = json.loads(
            serialized.decode("utf-8")
        )

    except (
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError
    ) as exc:
        raise ValueError(
            "ct_serial is not valid encrypted content."
        ) from exc

    return data


def write_encrypted_file(data: dict) -> None:
    serialized = json.dumps(
        data,
        separators=(",", ":")
    ).encode("utf-8")

    ct_serial = base64.b64encode(
        serialized
    ).decode("ascii")

    output = f"""// GENERATED FILE -- DO NOT EDIT.
//
// Development:
//   python tools/content.py decrypt
// Deployment:
//   python tools/content.py encrypt

const ct_serial = "{ct_serial}";
"""

    ENCRYPTED_FILE.write_text(
        output,
        encoding="utf-8"
    )

def decrypt_command() -> None:
    print()
    print("C0nvention content decryptor")
    print("---------------------------")
    print()

    password = getpass.getpass(
        "Password: "
    )

    if not password:
        fail(
            "Password cannot be empty."
        )

    try:
        encrypted = read_encrypted_file()

        plaintext = decrypt_content(
            encrypted,
            password
        )

        content = plaintext.decode(
            "utf-8"
        )

    except InvalidTag:
        fail(
            "Incorrect password or corrupted ciphertext."
        )

    except (
        ValueError,
        UnicodeDecodeError
    ) as exc:
        fail(str(exc))

    DECRYPTED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    CONTENT_FILE.write_text(
        content,
        encoding="utf-8"
    )

    print()
    print("Decryption successful.")
    print()
    print("Generated:")
    print("  decrypted/content.html")
    print()
    print("Edit:")
    print("  decrypted/content.html")
    print()

def encrypt_command() -> None:
    if not CONTENT_FILE.exists():
        fail(
            "decrypted/content.html does not exist. "
            "Run decrypt first."
        )

    print()
    print("PwnieC0n content encryptor")
    print("---------------------------")
    print()

    password = getpass.getpass(
        "Password: "
    )

    confirmation = getpass.getpass(
        "Confirm : "
    )

    if not password:
        fail(
            "Password cannot be empty."
        )

    if password != confirmation:
        fail(
            "Passwords do not match."
        )

    content = CONTENT_FILE.read_bytes()

    encrypted = encrypt_content(
        content,
        password
    )

    write_encrypted_file(
        encrypted
    )

    print()
    print("Encryption successful.")
    print()
    print("Updated:")
    print("  js/content.enc.js")
    print()
    print("Commit that encrypted file.")
    print()


def status_command() -> None:
    print()
    print("C0nvention content status")
    print("-------------------------")
    print()

    print(
        "Encrypted payload:",
        "YES"
        if ENCRYPTED_FILE.exists()
        else "NO"
    )

    print(
        "Plaintext workspace:",
        "YES"
        if DECRYPTED_DIR.exists()
        else "NO"
    )

    print(
        "Editable content:",
        "YES"
        if CONTENT_FILE.exists()
        else "NO"
    )

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Manage encrypted C0nvention HTML content."
        )
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True
    )

    commands.add_parser(
        "decrypt",
        help=(
            "Decrypt deployed content into "
            "the local development workspace."
        )
    )

    commands.add_parser(
        "encrypt",
        help=(
            "Encrypt decrypted/content.html "
            "back into js/content.enc.js."
        )
    )

    commands.add_parser(
        "status",
        help="Show local content state."
    )

    args = parser.parse_args()

    if args.command == "decrypt":
        decrypt_command()

    elif args.command == "encrypt":
        encrypt_command()

    elif args.command == "status":
        status_command()


if __name__ == "__main__":
    main()