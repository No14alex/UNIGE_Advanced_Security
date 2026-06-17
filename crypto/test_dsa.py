import pytest

from crypto.dsa import (
    DSA_ALGORITHM,
    DSAKeyPair,
    dsa_info,
    generate_keypair,
    is_available,
    sign,
    sign_with_context,
    verify,
    verify_with_context,
)


PK_SIZE = 1952
SK_SIZE = 4032
SIG_SIZE = 3309


class TestAvailability:
    def test_ml_dsa_65_is_available(self):
        assert is_available(), f"{DSA_ALGORITHM} non disponible dans liboqs"

    def test_dsa_info_reports_selected_algorithm(self):
        info = dsa_info()
        assert info["algorithm"] == DSA_ALGORITHM

    def test_dsa_info_returns_correct_sizes(self):
        info = dsa_info()
        assert info["public_key_bytes"] == PK_SIZE
        assert info["secret_key_bytes"] == SK_SIZE
        assert info["signature_bytes"] == SIG_SIZE
        assert info["claimed_nist_level"] == 3
        assert info["version"] == "FIPS204"
        assert info["supports_context_signing"] is True

    def test_dsa_info_contains_expected_keys(self):
        info = dsa_info()
        assert set(info.keys()) == {
            "algorithm",
            "version",
            "claimed_nist_level",
            "public_key_bytes",
            "secret_key_bytes",
            "signature_bytes",
            "supports_context_signing",
        }


class TestGenerateKeypair:
    def test_returns_keypair_type(self):
        assert isinstance(generate_keypair(), DSAKeyPair)

    def test_correct_sizes(self):
        kp = generate_keypair()
        assert len(kp.public_key) == PK_SIZE
        assert len(kp.secret_key) == SK_SIZE

    def test_keys_are_not_zero(self):
        kp = generate_keypair()
        assert kp.public_key != bytes(PK_SIZE)
        assert kp.secret_key != bytes(SK_SIZE)

    def test_each_keypair_is_unique(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1.public_key != kp2.public_key
        assert kp1.secret_key != kp2.secret_key

    def test_public_key_hex(self):
        kp = generate_keypair()
        hex_str = kp.public_key_hex()
        assert isinstance(hex_str, str)
        assert len(hex_str) == PK_SIZE * 2
        assert hex_str == kp.public_key.hex()

    def test_keypair_repr_hides_secret_key_material(self):
        kp = generate_keypair()
        text = repr(kp)
        assert "DSAKeyPair(" in text
        assert "sk[" in text
        assert "***" in text
        assert kp.secret_key.hex() not in text


class TestSigning:
    @pytest.fixture
    def alice(self):
        return generate_keypair()

    def test_sign_returns_bytes(self, alice):
        signature = sign(b"hello", alice.secret_key)
        assert isinstance(signature, bytes)

    def test_sign_returns_expected_size(self, alice):
        signature = sign(b"hello", alice.secret_key)
        assert len(signature) == SIG_SIZE

    def test_signatures_are_not_zero(self, alice):
        signature = sign(b"hello", alice.secret_key)
        assert signature != bytes(SIG_SIZE)

    def test_invalid_secret_key_raises_value_error(self):
        with pytest.raises(ValueError, match="Taille de clé secrète incorrecte"):
            sign(b"hello", b"bad")

    def test_secret_key_off_by_one_raises_value_error(self, alice):
        with pytest.raises(ValueError, match=f"attendu {SK_SIZE}"):
            sign(b"hello", alice.secret_key[:-1])

    def test_sign_empty_message(self, alice):
        signature = sign(b"", alice.secret_key)
        assert len(signature) == SIG_SIZE


class TestVerification:
    @pytest.fixture
    def alice(self):
        return generate_keypair()

    @pytest.fixture
    def bob(self):
        return generate_keypair()

    def test_verify_valid_signature_returns_true(self, alice):
        message = b"hello quantum world"
        signature = sign(message, alice.secret_key)
        assert verify(message, signature, alice.public_key) is True

    def test_verify_tampered_message_returns_false(self, alice):
        signature = sign(b"hello", alice.secret_key)
        assert verify(b"hell0", signature, alice.public_key) is False

    def test_verify_wrong_public_key_returns_false(self, alice, bob):
        message = b"authenticated transcript"
        signature = sign(message, alice.secret_key)
        assert verify(message, signature, bob.public_key) is False

    def test_verify_tampered_signature_returns_false(self, alice):
        message = b"hello"
        signature = bytearray(sign(message, alice.secret_key))
        signature[0] ^= 0xFF
        signature[42] ^= 0xAB
        assert verify(message, bytes(signature), alice.public_key) is False

    def test_verify_is_repeatable_for_same_inputs(self, alice):
        message = b"repeatable verify"
        signature = sign(message, alice.secret_key)
        assert verify(message, signature, alice.public_key) is True
        assert verify(message, signature, alice.public_key) is True

    def test_invalid_public_key_raises_value_error(self, alice):
        message = b"hello"
        signature = sign(message, alice.secret_key)
        with pytest.raises(ValueError, match="Taille de clé publique incorrecte"):
            verify(message, signature, b"bad")

    def test_public_key_off_by_one_raises_value_error(self, alice):
        message = b"hello"
        signature = sign(message, alice.secret_key)
        with pytest.raises(ValueError, match=f"attendu {PK_SIZE}"):
            verify(message, signature, alice.public_key[:-1])

    def test_invalid_signature_raises_value_error(self, alice):
        with pytest.raises(ValueError, match="Taille de signature incorrecte"):
            verify(b"hello", b"bad", alice.public_key)

    def test_signature_off_by_one_raises_value_error(self, alice):
        signature = sign(b"hello", alice.secret_key)
        with pytest.raises(ValueError, match=f"attendu {SIG_SIZE}"):
            verify(b"hello", signature[:-1], alice.public_key)


class TestContextSigning:
    @pytest.fixture
    def alice(self):
        return generate_keypair()

    def test_sign_with_context_returns_expected_size(self, alice):
        signature = sign_with_context(b"hello", alice.secret_key, b"chat")
        assert isinstance(signature, bytes)
        assert len(signature) == SIG_SIZE

    def test_verify_with_context_valid_signature_returns_true(self, alice):
        message = b"context-bound message"
        context = b"session-1"
        signature = sign_with_context(message, alice.secret_key, context)
        assert verify_with_context(message, signature, context, alice.public_key) is True

    def test_verify_with_context_wrong_context_returns_false(self, alice):
        message = b"context-bound message"
        signature = sign_with_context(message, alice.secret_key, b"session-1")
        assert verify_with_context(message, signature, b"session-2", alice.public_key) is False

    def test_verify_with_context_tampered_message_returns_false(self, alice):
        context = b"chat"
        signature = sign_with_context(b"hello", alice.secret_key, context)
        assert verify_with_context(b"hell0", signature, context, alice.public_key) is False

    def test_sign_with_context_invalid_secret_key_raises_value_error(self):
        with pytest.raises(ValueError, match="Taille de clé secrète incorrecte"):
            sign_with_context(b"hello", b"bad", b"ctx")

    def test_verify_with_context_invalid_public_key_raises_value_error(self, alice):
        signature = sign_with_context(b"hello", alice.secret_key, b"ctx")
        with pytest.raises(ValueError, match="Taille de clé publique incorrecte"):
            verify_with_context(b"hello", signature, b"ctx", b"bad")

    def test_verify_with_context_invalid_signature_raises_value_error(self, alice):
        with pytest.raises(ValueError, match="Taille de signature incorrecte"):
            verify_with_context(b"hello", b"bad", b"ctx", alice.public_key)
