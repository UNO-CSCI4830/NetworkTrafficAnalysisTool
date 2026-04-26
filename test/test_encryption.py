import base64

import pytest

import src.encryption as enc


@pytest.fixture()
def key_bytes() -> bytes:
    # A fixed 32-byte key so tests are deterministic.
    return bytes(range(32))


def test_is_log_key_set_false_when_missing(monkeypatch):
    monkeypatch.delenv("LOG_KEY", raising=False)
    assert enc.is_log_key_set() is False


def test_is_log_key_set_false_when_whitespace(monkeypatch):
    monkeypatch.setenv("LOG_KEY", "   ")
    assert enc.is_log_key_set() is False


def test_is_log_key_set_true_when_present(monkeypatch):
    monkeypatch.setenv("LOG_KEY", "not-empty")
    assert enc.is_log_key_set() is True


def test_load_key_accepts_hex_64(monkeypatch, key_bytes):
    # 32 bytes => 64 hex characters
    monkeypatch.setenv("LOG_KEY", key_bytes.hex())
    assert enc.load_key() == key_bytes


def test_load_key_accepts_base64_without_padding(monkeypatch, key_bytes):
    # Remove '=' padding on purpose; load_key() should add it back.
    b64 = base64.b64encode(key_bytes).decode("ascii").rstrip("=")
    monkeypatch.setenv("LOG_KEY", b64)
    assert enc.load_key() == key_bytes


def test_encrypt_decrypt_roundtrip(monkeypatch, key_bytes):
    monkeypatch.setenv("LOG_KEY", key_bytes.hex())

    plaintext = b"hello world"
    encrypted = enc.encrypt_data(plaintext)

    assert isinstance(encrypted, (bytes, bytearray))
    assert encrypted != plaintext
    assert len(encrypted) > enc.IV_SIZE

    decrypted = enc.decrypt_data(encrypted)
    assert decrypted == plaintext


def test_encrypt_data_rejects_non_bytes(monkeypatch, key_bytes):
    monkeypatch.setenv("LOG_KEY", key_bytes.hex())

    with pytest.raises(TypeError):
        enc.encrypt_data("not bytes")  # type: ignore[arg-type]


def test_decrypt_data_rejects_too_short(monkeypatch, key_bytes):
    # Set LOG_KEY anyway to keep the test setup consistent.
    monkeypatch.setenv("LOG_KEY", key_bytes.hex())

    with pytest.raises(ValueError):
        enc.decrypt_data(b"x" * enc.IV_SIZE)
