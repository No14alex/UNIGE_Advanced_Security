import pytest
from crypto.kem import (
    generate_keypair,
    encapsulate,
    decapsulate,
    kem_ratchet_step,
    kem_info,
    is_available,
    KEMKeyPair,
    KEMEncapsulationResult,
    KEM_ALGORITHM,
)

# Tailles FIPS 203 — ML-KEM-768
PK_SIZE = 1184
SK_SIZE = 2400
CT_SIZE = 1088
SS_SIZE = 32


# Availability

class TestAvailability:
    def test_ml_kem_768_is_available(self):
        assert is_available(), f"{KEM_ALGORITHM} non disponible dans liboqs"

    def test_kem_info_reports_selected_algorithm(self):
        info = kem_info()
        assert info["algorithm"] == KEM_ALGORITHM

    def test_kem_info_returns_correct_sizes(self):
        info = kem_info()
        assert info["public_key_bytes"] == PK_SIZE
        assert info["secret_key_bytes"] == SK_SIZE
        assert info["ciphertext_bytes"] == CT_SIZE
        assert info["shared_secret_bytes"] == SS_SIZE
        assert info["claimed_nist_level"] == 3

    def test_kem_info_contains_expected_keys(self):
        info = kem_info()
        assert set(info.keys()) == {
            "algorithm",
            "claimed_nist_level",
            "public_key_bytes",
            "secret_key_bytes",
            "ciphertext_bytes",
            "shared_secret_bytes",
        }

# Key generation


class TestGenerateKeypair:
    def test_returns_keypair_type(self):
        assert isinstance(generate_keypair(), KEMKeyPair)

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
        assert "KEMKeyPair(" in text
        assert "sk[" in text
        assert "***" in text
        assert kp.secret_key.hex()[:16] not in text


# Encapsulation

class TestEncapsulate:
    @pytest.fixture
    def bob(self):
        return generate_keypair()

    def test_returns_result_type(self, bob):
        assert isinstance(encapsulate(bob.public_key), KEMEncapsulationResult)

    def test_correct_sizes(self, bob):
        result = encapsulate(bob.public_key)
        assert len(result.ciphertext) == CT_SIZE
        assert len(result.shared_secret) == SS_SIZE

    def test_result_repr_contains_ciphertext_metadata(self, bob):
        result = encapsulate(bob.public_key)
        text = repr(result)
        assert "KEMEncapsulationResult(" in text
        assert f"ct[{CT_SIZE}B]" in text
        assert result.ciphertext.hex()[:16] in text
        assert result.shared_secret.hex() in text

    def test_shared_secret_not_zero(self, bob):
        result = encapsulate(bob.public_key)
        assert result.shared_secret != bytes(SS_SIZE)

    def test_probabilistic_each_call_differs(self, bob):
        """Deux encapsulations sur la même clé → ciphertexts et secrets différents."""
        r1 = encapsulate(bob.public_key)
        r2 = encapsulate(bob.public_key)
        assert r1.ciphertext != r2.ciphertext
        assert r1.shared_secret != r2.shared_secret

    def test_invalid_key_size_raises_value_error(self):
        with pytest.raises(ValueError, match="Taille de clé publique incorrecte"):
            encapsulate(b"trop_court")

    def test_public_key_off_by_one_raises_value_error(self, bob):
        with pytest.raises(ValueError, match=f"attendu {PK_SIZE}"):
            encapsulate(bob.public_key[:-1])

    def test_empty_key_raises_value_error(self):
        with pytest.raises(ValueError):
            encapsulate(b"")


# Decapslation

class TestDecapsulate:
    @pytest.fixture
    def bob(self):
        return generate_keypair()

    def test_returns_bytes(self, bob):
        result = encapsulate(bob.public_key)
        ss = decapsulate(bob.secret_key, result.ciphertext)
        assert isinstance(ss, bytes)

    def test_correct_size(self, bob):
        result = encapsulate(bob.public_key)
        ss = decapsulate(bob.secret_key, result.ciphertext)
        assert len(ss) == SS_SIZE

    def test_decapsulation_is_deterministic_for_same_inputs(self, bob):
        result = encapsulate(bob.public_key)
        s1 = decapsulate(bob.secret_key, result.ciphertext)
        s2 = decapsulate(bob.secret_key, result.ciphertext)
        assert s1 == s2 == result.shared_secret

    def test_invalid_secret_key_raises_value_error(self, bob):
        result = encapsulate(bob.public_key)
        with pytest.raises(ValueError, match="Taille de clé secrète incorrecte"):
            decapsulate(b"trop_court", result.ciphertext)

    def test_secret_key_off_by_one_raises_value_error(self, bob):
        result = encapsulate(bob.public_key)
        with pytest.raises(ValueError, match=f"attendu {SK_SIZE}"):
            decapsulate(bob.secret_key[:-1], result.ciphertext)

    def test_invalid_ciphertext_raises_value_error(self, bob):
        with pytest.raises(ValueError, match="Taille de ciphertext incorrecte"):
            decapsulate(bob.secret_key, b"trop_court")

    def test_ciphertext_off_by_one_raises_value_error(self, bob):
        result = encapsulate(bob.public_key)
        with pytest.raises(ValueError, match=f"attendu {CT_SIZE}"):
            decapsulate(bob.secret_key, result.ciphertext[:-1])


# Main handshake


class TestAliceBobHandshake:
    """
    Simule le handshake de base du protocole :
    Bob publie sa clé, Alice encapsule, Bob décapsule.
    Les deux doivent obtenir le même secret.
    """

    def test_shared_secrets_match(self):
        bob = generate_keypair()
        alice_result = encapsulate(bob.public_key)
        bob_secret = decapsulate(bob.secret_key, alice_result.ciphertext)
        assert alice_result.shared_secret == bob_secret

    def test_five_independent_sessions_all_match(self):
        """Simule 5 sessions indépendantes."""
        bob = generate_keypair()
        for i in range(5):
            alice_result = encapsulate(bob.public_key)
            bob_secret = decapsulate(bob.secret_key, alice_result.ciphertext)
            assert alice_result.shared_secret == bob_secret, f"Session {i} échouée"

    def test_five_sessions_all_have_different_secrets(self):
        """Chaque session produit un secret distinct."""
        bob = generate_keypair()
        secrets = [encapsulate(bob.public_key).shared_secret for _ in range(5)]
        assert len(set(secrets)) == 5

    def test_ciphertexts_are_all_distinct_across_sessions(self):
        bob = generate_keypair()
        ciphertexts = [encapsulate(bob.public_key).ciphertext for _ in range(5)]
        assert len(set(ciphertexts)) == 5

    def test_wrong_secret_key_gives_wrong_secret(self):
        """
        Eve ne peut pas décapsuler le message d'Alice destiné à Bob.
        """
        bob = generate_keypair()
        eve = generate_keypair()
        alice_result = encapsulate(bob.public_key)
        eve_secret = decapsulate(eve.secret_key, alice_result.ciphertext)
        assert alice_result.shared_secret != eve_secret

    def test_tampered_ciphertext_gives_wrong_secret(self):
        """
        ML-KEM est IND-CCA2 : un ciphertext modifié ne lève pas d'exception,
        mais produit un secret incorrect (pas d'oracle d'erreur).
        """
        bob = generate_keypair()
        alice_result = encapsulate(bob.public_key)

        tampered = bytearray(alice_result.ciphertext)
        tampered[0] ^= 0xFF
        tampered[42] ^= 0xAB

        bob_secret = decapsulate(bob.secret_key, bytes(tampered))
        assert alice_result.shared_secret != bob_secret


# ===========================================================================
# 5. KEM RATCHET
# ===========================================================================

class TestKEMRatchet:
    """
    Teste le KEM Ratchet utilisé dans double_ratchet.py.
    Simule plusieurs tours de ratchet entre Alice et Bob.
    """

    def test_kem_ratchet_step_returns_tuple(self):
        bob = generate_keypair()
        result = kem_ratchet_step(bob.public_key)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_kem_ratchet_new_public_key_correct_size(self):
        bob = generate_keypair()
        new_pk, _ = kem_ratchet_step(bob.public_key)
        assert len(new_pk) == PK_SIZE

    def test_kem_ratchet_generates_fresh_public_key(self):
        bob = generate_keypair()
        new_pk, _ = kem_ratchet_step(bob.public_key)
        assert new_pk != bob.public_key

    def test_kem_ratchet_shared_secret_correct_size(self):
        bob = generate_keypair()
        _, secret = kem_ratchet_step(bob.public_key)
        assert len(secret) == SS_SIZE

    def test_two_ratchet_steps_give_different_secrets(self):
        bob = generate_keypair()
        _, s1 = kem_ratchet_step(bob.public_key)
        _, s2 = kem_ratchet_step(bob.public_key)
        assert s1 != s2

    def test_kem_ratchet_invalid_public_key_raises_value_error(self):
        with pytest.raises(ValueError, match="Taille de clé publique incorrecte"):
            kem_ratchet_step(b"invalid")


# ===========================================================================
# SCRIPT DE DÉMONSTRATION
# ===========================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  ML-KEM-768 — Protocole QSMP")
    print("=" * 60)

    print("\n Paramètres :")
    for k, v in kem_info().items():
        print(f"   {k:<28} {v}")

    print(f"\nML-KEM-768 disponible : {is_available()}")

    print("\n Bob génère ses clés...")
    bob = generate_keypair()
    print(f"   {bob}")

    print("\n Alice encapsule un secret...")
    alice_result = encapsulate(bob.public_key)
    print(f"   {alice_result}")

    print("\n Bob décapsule...")
    bob_secret = decapsulate(bob.secret_key, alice_result.ciphertext)
    print(f"   Secret Bob : {bob_secret.hex()}")

    match = alice_result.shared_secret == bob_secret
    print(f"\n{' Secrets identiques' if match else ' ERREUR : secrets différents'}")

    print("\n KEM Ratchet — 3 tours...")
    current_bob_pk = bob.public_key
    for i in range(1, 4):
        new_pk, ratchet_secret = kem_ratchet_step(current_bob_pk)
        print(f"   Tour {i} : secret={ratchet_secret.hex()[:32]}…")
        current_bob_pk = new_pk

    print("\n" + "=" * 60)
