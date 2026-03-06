import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config import settings


def _get_key() -> bytes:
    """Get 32-byte AES key from config."""
    key = settings.AES_KEY.encode("utf-8")
    # Pad or trim to exactly 32 bytes
    return key.ljust(32, b"\0")[:32]


def encrypt_value(plaintext: str) -> str:
    """Encrypt a string using AES-256-CBC and return base64-encoded ciphertext."""
    key = _get_key()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 padding
    data = plaintext.encode("utf-8")
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len

    ciphertext = encryptor.update(data) + encryptor.finalize()
    # Prepend IV to ciphertext
    return base64.b64encode(iv + ciphertext).decode("utf-8")


def decrypt_value(encrypted: str) -> str:
    """Decrypt a base64-encoded AES-256-CBC ciphertext."""
    key = _get_key()
    raw = base64.b64decode(encrypted)
    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()
    # Remove and validate PKCS7 padding
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS7 padding length")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS7 padding bytes")
    return padded[:-pad_len].decode("utf-8")
