#!/usr/bin/env python3

# Usage: python sender.py sender_message.txt --receiver-public-key receiver_public.pem

import argparse
import base64
import json
import sys
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

TRANSMITTED_DATA_FILE = "Transmitted_Data.json"

# Store binary crypto outputs safely in JSON.
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

# Import receiver public key from PEM so we can encrypt the AES key.
def load_rsa_public_key(path: Path) -> RSA.RsaKey:
    with path.open("rb") as fh:
        return RSA.import_key(fh.read())

# Domain-separate MAC key derivation from the AES key.
def derive_mac_key(aes_key: bytes) -> bytes:
    return SHA256.new(b"mac-key-v1|" + aes_key).digest()


def build_transmitted_data(message: str, receiver_public_key: RSA.RsaKey) -> dict:
    # Create one-time symmetric values for this message.
    aes_key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)

    # Encrypt the plaintext message with AES-CBC.
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = aes_cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))

    # Protect the AES key with receiver's RSA public key.
    rsa_cipher = PKCS1_OAEP.new(receiver_public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    # Authenticate encrypted fields so tampering is detected by the receiver.
    mac_key = derive_mac_key(aes_key)
    mac = HMAC.new(mac_key, digestmod=SHA256)
    mac.update(encrypted_aes_key)
    mac.update(iv)
    mac.update(ciphertext)
    mac_tag = mac.digest()

    return {
        "encrypted_aes_key": b64e(encrypted_aes_key),
        "iv": b64e(iv),
        "ciphertext": b64e(ciphertext),
        "mac": b64e(mac_tag),
        "crypto_suite": "RSA-OAEP + AES-256-CBC + HMAC-SHA256",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypt and transmit secure message.")
    parser.add_argument(
        "input_file",
        help="Path to plaintext file to send.",
    )
    parser.add_argument(
        "--receiver-public-key",
        required=True,
        help="Path to receiver RSA public key PEM file.",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        parser.exit(1)

    args = parser.parse_args()

    # Resolve user-provided paths and fixed transmission channel path.
    message_path = Path(args.input_file)
    receiver_pub_path = Path(args.receiver_public_key)
    transmitted_path = Path(TRANSMITTED_DATA_FILE)

    # Fail fast with clear errors if required files are missing.
    if not message_path.exists():
        raise FileNotFoundError(f"Message file not found: {message_path}")
    if not receiver_pub_path.exists():
        raise FileNotFoundError(f"Receiver public key file not found: {receiver_pub_path}")

    # Read input, perform encryption/authentication, then package payload.
    message = message_path.read_text(encoding="utf-8")
    receiver_public_key = load_rsa_public_key(receiver_pub_path)
    transmitted_data = build_transmitted_data(message, receiver_public_key)

    # Write the full simulated network payload for receiver.py to consume.
    with transmitted_path.open("w", encoding="utf-8") as fh:
        json.dump(transmitted_data, fh, indent=2)

    print(f"Encrypted payload written to: {transmitted_path}")


if __name__ == "__main__":
    main()
