"""
AES-256-GCM symmetric encryption module.

1. Key Generation   k = Random(32 bytes)
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
    Resultat d'un chiffrement AES-256-GCM.

    - nonce: valeur unique par message
    - ciphertext: donnees chiffrees + tag GCM
    """

    nonce: bytes
    ciphertext: bytes

    def __repr__(self):
        return (
            f"AESGCMCiphertext("
            f"nonce[{len(self.nonce)}B]={self.nonce.hex()}, "
            f"ct[{len(self.ciphertext)}B]={self.ciphertext.hex()[:32]}...)"
        )


def generate_key() -> bytes:
    """Genere une cle AES-256 aleatoire."""
    return os.urandom(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> AESGCMCiphertext:
    """
    Chiffre un message avec AES-256-GCM.

    Args:
        key: cle symetrique de 32 octets
        plaintext: message a chiffrer
        aad: additional authenticated data
    """
    _validate_key(key)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return AESGCMCiphertext(nonce=nonce, ciphertext=ciphertext)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """
    Dechiffre un message AES-256-GCM.

    Raises:
        ValueError si la taille de la cle ou du nonce est incorrecte
        InvalidTag si le ciphertext, le nonce ou l'AAD ont ete modifies
    """
    _validate_key(key)
    _validate_nonce(nonce)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


def aes_info() -> dict:
    """Retourne les parametres utilises pour AES-256-GCM."""
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


if __name__ == "__main__":
    print("=" * 60)
    print("  AES-256-GCM — Protocole QSMP")
    print("=" * 60)

    print("\nParametres :")
    for key, value in aes_info().items():
        print(f"   {key:<16} {value}")

    key = generate_key()
    print(f"\nCle generee : {len(key)} octets")

    plaintext = b"Hello Bob, this message is confidential."
    aad = b"session-1|counter-1"
    print(f"\nPlaintext : {plaintext!r}")
    print(f"AAD       : {aad!r}")

    result = encrypt(key, plaintext, aad)
    print("\nChiffrement...")
    print(f"   {result}")

    recovered = decrypt(key, result.nonce, result.ciphertext, aad)
    print("\nDechiffrement...")
    print(f"   Plaintext recupere : {recovered!r}")
    print(f"   Dechiffrement OK   : {recovered == plaintext}")

    print("\nTest de detection d'alteration...")
    tampered = bytearray(result.ciphertext)
    tampered[0] ^= 0xFF
    try:
        decrypt(key, result.nonce, bytes(tampered), aad)
        print("   ERREUR : alteration non detectee")
    except InvalidTag:
        print("   OK : alteration detectee (InvalidTag)")

    print("\n" + "=" * 60)
