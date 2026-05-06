#!/usr/bin/env python3

# Usage: python receiver.py --receiver-private-key receiver_private.pem --output-file receiver_output.txt

import argparse
import base64
import json
import sys
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

TRANSMITTED_DATA_FILE = "Transmitted_Data.json"
RECEIVER_OUTPUT_FILE = "receiver_output.txt"

# Convert JSON-safe base64 strings back to raw bytes.
def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))

# Import receiver private key from PEM for RSA decryption.
def load_rsa_private_key(path: Path) -> RSA.RsaKey:
    with path.open("rb") as fh:
        return RSA.import_key(fh.read())

# Must match sender's derivation exactly.
def derive_mac_key(aes_key: bytes) -> bytes:
    return SHA256.new(b"mac-key-v1|" + aes_key).digest()


def decrypt_and_verify(transmitted_data: dict, receiver_private_key: RSA.RsaKey) -> str:
    # Unpack transmitted encrypted fields from the JSON payload.
    encrypted_aes_key = b64d(transmitted_data["encrypted_aes_key"])
    iv = b64d(transmitted_data["iv"])
    ciphertext = b64d(transmitted_data["ciphertext"])
    received_mac = b64d(transmitted_data["mac"])

    # Recover one-time AES key using receiver's RSA private key.
    rsa_cipher = PKCS1_OAEP.new(receiver_private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)

    # Recompute HMAC over encrypted fields and verify integrity/authenticity.
    mac_key = derive_mac_key(aes_key)
    mac = HMAC.new(mac_key, digestmod=SHA256)
    mac.update(encrypted_aes_key)
    mac.update(iv)
    mac.update(ciphertext)

    # Raises ValueError if payload was modified or wrong key was used.
    mac.verify(received_mac)

    # Only decrypt ciphertext after authentication succeeds.
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_bytes = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
    return plaintext_bytes.decode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify, decrypt, and recover secure message.")
    parser.add_argument(
        "--receiver-private-key",
        required=True,
        help="Path to receiver RSA private key PEM file.",
    )
    parser.add_argument(
        "--output-file",
        default=RECEIVER_OUTPUT_FILE,
        help="Path to recovered plaintext output file.",
    )
    if len(sys.argv) == 1:
        parser.print_help()
        parser.exit(1)

    args = parser.parse_args()

    # Resolve user-provided key/output paths and fixed transmission channel.
    priv_path = Path(args.receiver_private_key)
    input_path = Path(TRANSMITTED_DATA_FILE)
    output_path = Path(args.output_file)

    # Validate required input files before attempting cryptographic operations.
    if not priv_path.exists():
        raise FileNotFoundError(f"Receiver private key file not found: {priv_path}")
    if not input_path.exists():
        raise FileNotFoundError(f"Transmitted data file not found: {input_path}")

    # Load key and payload, then authenticate and decrypt.
    receiver_private_key = load_rsa_private_key(priv_path)
    with input_path.open("r", encoding="utf-8") as fh:
        transmitted_data = json.load(fh)

    plaintext = decrypt_and_verify(transmitted_data, receiver_private_key)
    # Save recovered plaintext to user-selected output file.
    output_path.write_text(plaintext, encoding="utf-8")

    print(f"MAC verified. Message decoded and written to: {output_path}")


if __name__ == "__main__":
    main()
