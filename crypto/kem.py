from dataclasses import dataclass
from importlib import util as importlib_util
from pathlib import Path
import sysconfig
from oqs_load import oqs

'''
Key encapsulation mechanism 
ML - KEM - 768 protocol (Kyber)

1. Key Generation  (pk,sk) = Gen()
2. Encapsulation    (k,c) = Encap(pk)
3. Decapsulation    k' = Decap(sk,c')

'''

KEM_ALGORITHM = "ML-KEM-768"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class KEM_KeyPair:
    """
    ML-KEM-768 key pair

    sizes FIPS 203 :
      - public_key  : 1184 bytes
      - secret_key  : 2400 bytes
    """
    public_key: bytes
    secret_key: bytes

    def public_key_hex(self) -> str:
        return self.public_key.hex() 

    def __repr__(self): #affichage de l'object pour print(keypair)
        return (
            f"KEM_KeyPair("
            f"pk[{len(self.public_key)}B]={self.public_key.hex()[:16]}…, "
            f"sk[{len(self.secret_key)}B]=***)" #doesn't show the secret key 
        )


@dataclass
class KEMEncapsulationResult:
    """
    Result of encapsulation 

    - ciphertext    : to send to the other party (1088 bytes)
    - shared_secret : secret kept locally (32 bytes)
    """
    ciphertext: bytes
    shared_secret: bytes

    def __repr__(self):
        return (
            f"KEMEncapsulationResult("
            f"ct[{len(self.ciphertext)}B]={self.ciphertext.hex()[:16]}…, "
            f"ss={self.shared_secret.hex()})"
        )

#---------------------------------------------------------------------------
#Principal functions 
#---------------------------------------------------------------------------

def generate_keypair() -> KEM_KeyPair:
    """
    Generate a ML-KEM-768 key pair.

    Used by :
      - Bob for his identity key (IK)
      - Bob for his Signed PreKey (SPK)
      - Bob for his One-Time PreKeys (OPK)

    Returns:
        KEM_KeyPair(public_key, secret_key)
    """
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()

    return KEM_KeyPair(public_key=public_key, secret_key=secret_key)


def encapsulate(public_key: bytes) -> KEMEncapsulationResult:
    """
    Encapsulate a shared secret with the recipient's public key.
    Called by the initiator (Alice) during the PQ-X3DH handshake.

    Args:
        public_key : recipient's public key (Bob)

    Returns:
        KEMEncapsulationResult :
          - ciphertext    → to send to Bob via the server
          - shared_secret → kept by Alice to derive the master key

    Raises:
        ValueError : if the public key has an incorrect size
        RuntimeError : if liboqs fails
    """
    _validate_public_key(public_key)

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)

    return KEMEncapsulationResult(ciphertext=ciphertext, shared_secret=shared_secret)


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate the shared secret with the local secret key.
    Called by the recipient (Bob) during the PQ-X3DH handshake
    and at each turn of the KEM Ratchet.

    Args:
        secret_key  : Bob's secret key
        ciphertext  : ciphertext reçu d'Alice

    Returns:
        shared_secret (32 bytes) — identical to Alice's shared_secret
        if the keys are correct.

    Note IND-CCA2 :
        If the ciphertext is modified (active attack), ML-KEM does not raise
        an exception — it returns an incorrect pseudo-random secret.
        This is intentional (no error oracle).

    Raises:
        ValueError : if the sizes are incorrect
        RuntimeError : if liboqs fails
    """
    _validate_secret_key(secret_key)
    _validate_ciphertext(ciphertext)

    with oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)

    return shared_secret


# ---------------------------------------------------------------------------
# KEM Ratchet — for double_ratchet.py - not used here for futur work 
# ---------------------------------------------------------------------------

def kem_ratchet_step(their_public_key: bytes) -> tuple[bytes, bytes]:
    """
    Performs one step of the KEM Ratchet (replaces Signal's DH Ratchet).
    Called by the sender at each new ratchet "turn".

    Returns:
        (our_new_public_key, shared_secret)
        - our_new_public_key : to include in the message header
        - shared_secret      : used to derive new chain keys

    Usage in double_ratchet.py :
        new_pk, ratchet_secret = kem_ratchet_step(their_ratchet_public_key)
    """
    result = encapsulate(their_public_key)
    # Generate our new key for the next ratchet
    new_keypair = generate_keypair()
    return new_keypair.public_key, result.shared_secret


# ---------------------------------------------------------------------------
# Internal validation
# ---------------------------------------------------------------------------

def _validate_public_key(public_key: bytes) -> None:
    info = kem_info()
    expected = info["public_key_bytes"]
    if len(public_key) != expected:
        raise ValueError(
            f"Taille de clé publique incorrecte : "
            f"reçu {len(public_key)} octets, attendu {expected}"
        )


def _validate_secret_key(secret_key: bytes) -> None:
    info = kem_info()
    expected = info["secret_key_bytes"]
    if len(secret_key) != expected:
        raise ValueError(
            f"Taille de clé secrète incorrecte : "
            f"reçu {len(secret_key)} octets, attendu {expected}"
        )


def _validate_ciphertext(ciphertext: bytes) -> None:
    info = kem_info()
    expected = info["ciphertext_bytes"]
    if len(ciphertext) != expected:
        raise ValueError(
            f"Taille de ciphertext incorrecte : "
            f"reçu {len(ciphertext)} octets, attendu {expected}"
        )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def kem_info() -> dict:
    """Returns the size parameters of ML-KEM-768."""
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        d = kem.details
    return {
        "algorithm":             d["name"],
        "claimed_nist_level":    d["claimed_nist_level"],
        "public_key_bytes":      d["length_public_key"],
        "secret_key_bytes":      d["length_secret_key"],
        "ciphertext_bytes":      d["length_ciphertext"],
        "shared_secret_bytes":   d["length_shared_secret"],
    }


def is_available() -> bool:
    """Checks if ML-KEM-768 is available in liboqs."""
    return KEM_ALGORITHM in oqs.get_enabled_kem_mechanisms()
