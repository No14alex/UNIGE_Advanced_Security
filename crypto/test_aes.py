import pytest
from cryptography.exceptions import InvalidTag

from crypto.aes import (
    AESGCMCiphertext,
    KEY_SIZE,
    NONCE_SIZE,
    aes_info,
    decrypt,
    encrypt,
    generate_key,
)


TAG_SIZE = 16


class TestAvailability:
    def test_aes_info_returns_expected_values(self):
        info = aes_info()
        assert info["algorithm"] == "AES-256-GCM"
        assert info["key_bytes"] == KEY_SIZE
        assert info["nonce_bytes"] == NONCE_SIZE
        assert info["tag_bytes"] == TAG_SIZE


class TestKeyGeneration:
    def test_generate_key_returns_bytes(self):
        key = generate_key()
        assert isinstance(key, bytes)

    def test_generate_key_correct_size(self):
        key = generate_key()
        assert len(key) == KEY_SIZE

    def test_generate_key_is_not_zero(self):
        key = generate_key()
        assert key != bytes(KEY_SIZE)

    def test_generate_key_is_unique(self):
        k1 = generate_key()
        k2 = generate_key()
        assert k1 != k2


class TestEncryption:
    @pytest.fixture
    def key(self):
        return generate_key()

    def test_encrypt_returns_ciphertext_object(self, key):
        result = encrypt(key, b"hello")
        assert isinstance(result, AESGCMCiphertext)

    def test_encrypt_generates_expected_nonce_size(self, key):
        result = encrypt(key, b"hello")
        assert len(result.nonce) == NONCE_SIZE

    def test_encrypt_ciphertext_contains_tag(self, key):
        plaintext = b"hello"
        result = encrypt(key, plaintext)
        assert len(result.ciphertext) == len(plaintext) + TAG_SIZE

    def test_encrypt_empty_plaintext(self, key):
        result = encrypt(key, b"")
        assert len(result.ciphertext) == TAG_SIZE

    def test_encrypt_with_aad(self, key):
        result = encrypt(key, b"hello", b"header")
        assert len(result.ciphertext) == 5 + TAG_SIZE

    def test_encrypt_same_plaintext_twice_gives_different_outputs(self, key):
        r1 = encrypt(key, b"same", b"aad")
        r2 = encrypt(key, b"same", b"aad")
        assert r1.nonce != r2.nonce
        assert r1.ciphertext != r2.ciphertext

    def test_encrypt_invalid_key_raises_value_error(self):
        with pytest.raises(ValueError, match="Taille de cle incorrecte"):
            encrypt(b"bad", b"hello")

    def test_ciphertext_repr_contains_metadata(self, key):
        result = encrypt(key, b"hello")
        text = repr(result)
        assert "AESGCMCiphertext(" in text
        assert f"nonce[{NONCE_SIZE}B]=" in text
        assert f"ct[{len(result.ciphertext)}B]=" in text


class TestDecryption:
    @pytest.fixture
    def key(self):
        return generate_key()

    def test_decrypt_roundtrip_returns_original_plaintext(self, key):
        plaintext = b"confidential payload"
        aad = b"session-1"
        result = encrypt(key, plaintext, aad)
        recovered = decrypt(key, result.nonce, result.ciphertext, aad)
        assert recovered == plaintext

    def test_decrypt_roundtrip_empty_plaintext(self, key):
        result = encrypt(key, b"", b"header")
        recovered = decrypt(key, result.nonce, result.ciphertext, b"header")
        assert recovered == b""

    def test_decrypt_is_repeatable_for_same_inputs(self, key):
        plaintext = b"hello"
        result = encrypt(key, plaintext)
        assert decrypt(key, result.nonce, result.ciphertext) == plaintext
        assert decrypt(key, result.nonce, result.ciphertext) == plaintext

    def test_decrypt_with_wrong_key_raises_invalid_tag(self, key):
        result = encrypt(key, b"hello")
        wrong_key = generate_key()
        with pytest.raises(InvalidTag):
            decrypt(wrong_key, result.nonce, result.ciphertext)

    def test_decrypt_with_wrong_aad_raises_invalid_tag(self, key):
        result = encrypt(key, b"hello", b"good")
        with pytest.raises(InvalidTag):
            decrypt(key, result.nonce, result.ciphertext, b"bad")

    def test_decrypt_with_tampered_ciphertext_raises_invalid_tag(self, key):
        result = encrypt(key, b"hello", b"aad")
        tampered = bytearray(result.ciphertext)
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt(key, result.nonce, bytes(tampered), b"aad")

    def test_decrypt_with_tampered_nonce_raises_invalid_tag(self, key):
        result = encrypt(key, b"hello", b"aad")
        tampered_nonce = bytearray(result.nonce)
        tampered_nonce[0] ^= 0x01
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(tampered_nonce), result.ciphertext, b"aad")

    def test_decrypt_invalid_key_raises_value_error(self, key):
        result = encrypt(key, b"hello")
        with pytest.raises(ValueError, match="Taille de cle incorrecte"):
            decrypt(b"bad", result.nonce, result.ciphertext)

    def test_decrypt_invalid_nonce_raises_value_error(self, key):
        result = encrypt(key, b"hello")
        with pytest.raises(ValueError, match="Taille de nonce incorrecte"):
            decrypt(key, b"short", result.ciphertext)
