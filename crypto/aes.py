"""
AES-256-GCM symmetric encryption module.

1. Key Generation   k = Random(32 bytes = 256 bits)
2. Encryption       (nonce, c) = Enc(k, m, aad)
3. Decryption       m = Dec(k, nonce, c, aad)
"""

from dataclasses import dataclass
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_SIZE = 32
NONCE_SIZE = 12


@dataclass
class AESGCMCiphertext:
    """
    result of AES-256-GCM encryption.

    - nonce: unique value per message
    - ciphertext: encrypted data + GCM tag
    """

    nonce: bytes
    ciphertext: bytes

    def __repr__(self):
        return (
            f"AESGCMCiphertext("
            f"nonce[{len(self.nonce)}B]={self.nonce.hex()}, "
            f"ct[{len(self.ciphertext)}B]={self.ciphertext.hex()[:32]}...)"
        )


##----------

def generate_key() -> bytes:
    """Generate a random AES-256 key."""
    return os.urandom(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> AESGCMCiphertext:
    """
    Encrypt a message with AES-256-GCM.

    Args:
        key: 32-byte symmetric key
        plaintext: message to encrypt
        aad: additional authenticated data, receiver can verify that nothing was modified
    """

    _validate_key(key)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return AESGCMCiphertext(nonce=nonce, ciphertext=ciphertext)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt an AES-256-GCM message.

    Raises:
        ValueError if the key or nonce size is incorrect
        InvalidTag if the ciphertext, nonce, or AAD have been modified
    """
    _validate_key(key)
    _validate_nonce(nonce)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


def aes_info() -> dict:
    """Returns the parameters used"""
    return {
        "algorithm": "AES-256-GCM",
        "key_bytes": KEY_SIZE,
        "nonce_bytes": NONCE_SIZE,
        "tag_bytes": 16,
    }


def _validate_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"Taille de cle incorrecte : recu {len(key)} octets, attendu {KEY_SIZE}"
        )


def _validate_nonce(nonce: bytes) -> None:
    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"Taille de nonce incorrecte : recu {len(nonce)} octets, attendu {NONCE_SIZE}"
        )
# DEMO of encryption and decryption

if __name__ == "__main__":
    print("=" * 60)
    print("  AES-256-GCM — Protocole QSMP")
    print("=" * 60)

    print("\nParameters :")
    for key, value in aes_info().items():
        print(f"   {key:<16} {value}")

    key = generate_key()
    print(f"\nGenerated key : {len(key)} bytes")

    plaintext = b"Hello Bob, this message is confidential."
    aad = b"session-1|counter-1"
    print(f"\nPlaintext : {plaintext!r}")
    print(f"AAD       : {aad!r}")

    result = encrypt(key, plaintext, aad)
    print("\nEncryption...")
    print(f"   {result}")

    recovered = decrypt(key, result.nonce, result.ciphertext, aad)
    print("\nDecryption...")
    print(f"   Plaintext recovered : {recovered!r}")
    print(f"   Decryption OK   : {recovered == plaintext}")

    print("\nTest of detection of alteration...")
    tampered = bytearray(result.ciphertext)
    tampered[0] ^= 0xFF
    try:
        decrypt(key, result.nonce, bytes(tampered), aad)
        print("   ERROR : alteration not detected")
    except InvalidTag:
        print("   OK : alteration detectee (InvalidTag)")

    print("\n" + "=" * 60)
