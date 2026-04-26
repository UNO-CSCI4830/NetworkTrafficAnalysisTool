"""
LOG_KEY must be provided to enable encrypted logging.
Without it, logs cannot be accessed or written.

How to set LOG_KEY:

1. Generate a key (32 bytes / 64 hex characters):
   python -c "import os; print(os.urandom(32).hex())"

2. Set the key in your terminal before running the program:

   PowerShell / VS Code Terminal:
   $env:LOG_KEY="paste_your_key_here"

   Command Prompt:
   set LOG_KEY=paste_your_key_here

3. Run the program:
   python main.py

Notes:
- You must set LOG_KEY every time you open a new terminal.
- Use the same key if you want to decrypt logs from previous runs.
- NOTE: Currently, we don't have a set shared key so we should probably share one in Discord for testing if we need to share and decrypt each other's logs for any reason. 
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


IV_SIZE = 12  # IV = Initialization Vector
KEY_SIZE = 32  # 32 bytes = AES-256


def is_log_key_set() -> bool:
    """Return True if the LOG_KEY environment variable is set and non-empty."""
    key_text = os.getenv("LOG_KEY")
    return bool(key_text and key_text.strip())


def load_key() -> bytes:
    # Load the AES-256 key (32 bytes) from the LOG_KEY environment variable.
    # --- read key text ---
    key_text = os.getenv("LOG_KEY")
    if not key_text:
        raise RuntimeError("LOG_KEY is missing")

    key_text = key_text.strip()

    # --- decode key ---
    # Supported formats:
    # - 64 hex characters (32 bytes)
    # - base64 (must decode to 32 bytes)
    try:
        is_hex_64 = (
            len(key_text) == 64
            and all(c in "0123456789abcdefABCDEF" for c in key_text)
        )

        if is_hex_64:
            key = bytes.fromhex(key_text)
        else:
            # Add padding if the base64 key is missing it.
            padded = key_text + ("=" * (-len(key_text) % 4))
            try:
                key = base64.b64decode(padded, validate=True)
            except Exception:
                # Also allow URL-safe base64 (- and _).
                key = base64.b64decode(padded, altchars=b"-_", validate=True)
    except Exception as e:
        raise RuntimeError("LOG_KEY must be valid hex or base64") from e

    # --- validate size ---
    if len(key) != KEY_SIZE:
        raise RuntimeError("LOG_KEY must decode to 32 bytes for AES-256")

    return key


def encrypt_data(data: bytes) -> bytes:
    # Encrypt bytes using AES-256-GCM.
    # Returns: iv + ciphertext
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")

    key = load_key()

    # --- iv (random per message) ---
    iv = os.urandom(IV_SIZE)

    # --- encrypt ---
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, bytes(data), None)

    # Put the iv at the front so we can use it when decrypting.
    return iv + ciphertext


def decrypt_data(data: bytes) -> bytes:
    """
    Decrypt data from logs.enc.

    How to use:
    - Open logs.enc using "rb" mode to read bytes
    - Pass the bytes into decrypt_data()
    - Decode the result (JSON)

    Example:
        with open("logs.enc", "rb") as f:
            encrypted = f.read()

        decrypted = decrypt_data(encrypted)

        import json
        data = json.loads(decrypted.decode("utf-8"))

    Note:
    - LOG_KEY must be the same key used to create logs.enc
    - If the key is wrong or missing, this will fail
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")

    if len(data) <= IV_SIZE:
        raise ValueError("Encrypted data is too short")

    key = load_key()

    # Separate the iv from the encrypted data.
    iv = bytes(data[:IV_SIZE])
    ciphertext = bytes(data[IV_SIZE:])

    # --- decrypt ---
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)
