
from dataclasses import dataclass
from importlib import util as importlib_util
from oqs_load import oqs #post-quantum library liboqs 

    # to have extended information about the signature : help(oqs.Signature)

'''
Digital signature algorithm
ML - DSA - 65 protocol

1. Key Generation   (pk, sk) = Gen()
2. Signing          sig = Sign(sk, m)
3. Verification     ok = Verify(pk, m, sig)
'''
DSA_ALGORITHM = "ML-DSA-65"


@dataclass
class DSAKeyPair:
    """
    ML-DSA-65 Key Pair

    FIPS 204 Sizes:
      - public_key  : 1952 bytes
      - secret_key  : 4032 bytes
    """
    public_key: bytes #to verify signatures
    secret_key: bytes #to sign messages 

    def public_key_hex(self) -> str:
        return self.public_key.hex()

    def __repr__(self):
        return (
            f"DSAKeyPair("
            f"pk[{len(self.public_key)}B]={self.public_key.hex()[:16]}…, "
            f"sk[{len(self.secret_key)}B]=***)"
        )


def generate_keypair() -> DSAKeyPair:
    """
    Generate an ML-DSA-65 key pair (sk,pk)
    Used for the user's long-term identity key
    """
    with oqs.Signature(DSA_ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    return DSAKeyPair(public_key=public_key, secret_key=secret_key)


def sign(message: bytes, secret_key: bytes) -> bytes:
    """
    Sign a message with the ML-DSA secret key

    Args:
        message: binary message to sign
        secret_key: ML-DSA-65 secret key
    """
    _validate_secret_key(secret_key)

    with oqs.Signature(DSA_ALGORITHM, secret_key=secret_key) as signer:
        return signer.sign(message)


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify an ML-DSA signature.

    Returns False if the message, signature, or public key do not match.
    """
    _validate_public_key(public_key)
    _validate_signature(signature)

    with oqs.Signature(DSA_ALGORITHM) as verify:
        return verify.verify(message, signature, public_key)


def sign_with_context(message: bytes, secret_key: bytes, context: bytes) -> bytes:
    """
    Sign a message with a context string (message, signature, )
    """
    _validate_secret_key(secret_key)

    with oqs.Signature(DSA_ALGORITHM, secret_key=secret_key) as sign:
        #produces signature
        return sign.sign_with_ctx_str(message, context) 
        #signature = Sign(sk, context || message)


def verify_with_context(message: bytes, signature: bytes, context: bytes, public_key: bytes) -> bool:
    """
    Verify an ML-DSA signature with context
    return true or false 
    """
    _validate_public_key(public_key)
    _validate_signature(signature)

    with oqs.Signature(DSA_ALGORITHM) as verify:
        return verify.verify_with_ctx_str(message, signature, context, public_key)


def dsa_info() -> dict:
    """Returns the size parameters for ML-DSA-65."""
    with oqs.Signature(DSA_ALGORITHM) as signer:
        d = signer.details
    return {
        "algorithm": d["name"],
        "version": d["version"],
        "claimed_nist_level": d["claimed_nist_level"],
        "public_key_bytes": d["length_public_key"],
        "secret_key_bytes": d["length_secret_key"],
        "signature_bytes": d["length_signature"],
        "supports_context_signing": d["supports_context_signing"],
    }

# Validators and availability

def is_available() -> bool:
    """Verify that ML-DSA-65 is available in liboqs."""
    return DSA_ALGORITHM in oqs.get_enabled_sig_mechanisms()

def _validate_public_key(public_key: bytes) -> None:
    expected = dsa_info()["public_key_bytes"]
    if len(public_key) != expected:
        raise ValueError(
            f"Taille de clé publique incorrecte : "
            f"reçu {len(public_key)} octets, attendu {expected}"
        )


def _validate_secret_key(secret_key: bytes) -> None:
    expected = dsa_info()["secret_key_bytes"]
    if len(secret_key) != expected:
        raise ValueError(
            f"Wrong size of secret key : "
            f"got {len(secret_key)} bytes, expected {expected}"
        )


def _validate_signature(signature: bytes) -> None:
    expected = dsa_info()["signature_bytes"]
    if len(signature) != expected:
        raise ValueError(
            f"Taille de signature incorrecte : "
            f"reçu {len(signature)} octets, attendu {expected}"
        )

"""
if __name__ == "__main__":
    print("=" * 60)
    print("  ML-DSA-65 — QSMP Protocol")
    print("=" * 60)

    print("\nParameters :")
    for key, value in dsa_info().items():
        print(f"   {key:<28} {value}")

    print(f"\nML-DSA-65 available: {is_available()}")

    print("\nGenerating Alice's key pair...")
    alice = generate_keypair()
    print(f"   {alice}")

    message = b"Quantum-safe handshake transcript"
    print(f"\nMessage to sign: {message!r}")

    print("\nClassic signature...")
    signature = sign(message, alice.secret_key)
    print(f"   signature[{len(signature)}B]={signature.hex()[:32]}...")

    print("\nVerifying signature...")
    valid = verify(message, signature, alice.public_key)
    print(f"   Verification OK: {valid}")

    tampered_message = b"Quantum-safe handshake transcripu"
    tampered_valid = verify(tampered_message, signature, alice.public_key)
    print("\nVerifying after modifying the message...")
    print(f"   Verification OK: {tampered_valid}")

    context = b"chat-session-1"
    print(f"\nSignature with context: {context!r}")
    ctx_signature = sign_with_context(message, alice.secret_key, context)
    print(f"   signature_ctx[{len(ctx_signature)}B]={ctx_signature.hex()[:32]}...")

    print("\nVerifying with correct context...")
    ctx_valid = verify_with_context(message, ctx_signature, context, alice.public_key)
    print(f"   Context verification OK: {ctx_valid}")

    wrong_ctx = b"chat-session-2"
    wrong_ctx_valid = verify_with_context(message, ctx_signature, wrong_ctx, alice.public_key)
    print("\nVerifying with wrong context...")
    print(f"   Context verification OK: {wrong_ctx_valid}")

    print("\n" + "=" * 60)



"""