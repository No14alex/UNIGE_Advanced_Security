import hashlib
import hmac

import pytest

from crypto.hkdf import (
    DEFAULT_HASH,
    hkdf,
    hkdf_expand,
    hkdf_extract,
    hkdf_info,
    hmac_digest,
)


class TestAvailability:
    def test_hkdf_info_returns_expected_metadata(self):
        info = hkdf_info()
        assert info["default_hash"] == DEFAULT_HASH
        assert info["rfc"] == "RFC 5869"
        assert "sha256" in info["supported_examples"]


class TestHMACDigest:
    def test_hmac_digest_matches_python_hmac(self):
        key = b"key"
        data = b"data"
        expected = hmac.new(key, data, hashlib.sha512).digest()
        assert hmac_digest(key, data) == expected

    def test_hmac_digest_with_sha512(self):
        key = b"key"
        data = b"data"
        expected = hmac.new(key, data, hashlib.sha512).digest()
        assert hmac_digest(key, data, "sha512") == expected

    def test_invalid_hash_raises_value_error(self):
        with pytest.raises(ValueError, match="Fonction de hash non supportee"):
            hmac_digest(b"k", b"d", "not_a_hash")


class TestExtract:
    def test_hkdf_extract_rfc5869_test_case_1(self):
        salt = bytes.fromhex("000102030405060708090a0b0c")
        ikm = bytes.fromhex("0b" * 22)
        prk = hkdf_extract(salt, ikm, "sha256")
        assert prk == bytes.fromhex(
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5"
        )

    def test_hkdf_extract_zero_salt_is_equivalent_to_hash_len_zero_bytes(self):
        ikm = b"input key material"
        zero_salt = bytes(hashlib.sha512().digest_size)
        assert hkdf_extract(b"", ikm) == hkdf_extract(zero_salt, ikm)


class TestExpand:
    def test_hkdf_expand_rfc5869_test_case_1(self):
        prk = bytes.fromhex(
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5"
        )
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm = hkdf_expand(prk, info, 42, "sha256")
        assert okm == bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )

    def test_hkdf_expand_zero_length_returns_empty_bytes(self):
        prk = bytes.fromhex(
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5"
        )
        assert hkdf_expand(prk, b"info", 0) == b""

    def test_hkdf_expand_negative_length_raises_value_error(self):
        with pytest.raises(ValueError, match="positive or zero"):
            hkdf_expand(b"prk", b"info", -1)

    def test_hkdf_expand_too_long_raises_value_error(self):
        prk = b"\x00" * hashlib.sha512().digest_size
        with pytest.raises(ValueError, match="too big"):
            hkdf_expand(prk, b"info", 255 * hashlib.sha512().digest_size + 1)


class TestHKDF:
    def test_hkdf_rfc5869_test_case_1(self):
        okm = hkdf(
            salt=bytes.fromhex("000102030405060708090a0b0c"),
            ikm=bytes.fromhex("0b" * 22),
            info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
            length=42,
            hash_name="sha256",
        )
        assert okm == bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )

    def test_hkdf_zero_length_salt_case(self):
        okm = hkdf(
            salt=b"",
            ikm=bytes.fromhex("0b" * 22),
            info=b"",
            length=42,
            hash_name="sha256",
        )
        assert okm == bytes.fromhex(
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8"
        )

    def test_hkdf_is_deterministic_for_same_inputs(self):
        params = {
            "salt": b"salt",
            "ikm": b"input key material",
            "info": b"session",
            "length": 48,
        }
        assert hkdf(**params) == hkdf(**params)

    def test_hkdf_changes_when_info_changes(self):
        base = hkdf(b"salt", b"ikm", b"info-1", 32)
        changed = hkdf(b"salt", b"ikm", b"info-2", 32)
        assert base != changed

    def test_hkdf_changes_when_salt_changes(self):
        base = hkdf(b"salt-1", b"ikm", b"info", 32)
        changed = hkdf(b"salt-2", b"ikm", b"info", 32)
        assert base != changed

    def test_hkdf_supports_sha512(self):
        okm = hkdf(b"salt", b"ikm", b"info", 64, hash_name="sha512")
        assert isinstance(okm, bytes)
        assert len(okm) == 64

    def test_hkdf_invalid_hash_raises_value_error(self):
        with pytest.raises(ValueError, match="Fonction de hash non supportee"):
            hkdf(b"salt", b"ikm", b"info", 32, hash_name="not_a_hash")
