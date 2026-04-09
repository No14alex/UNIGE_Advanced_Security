'''
Key encapsulation mechanism 
ML - KEM - 768 protocol (Kyber)

1. Key Generation  (pk,sk) = Gen()
2. Encapsulation    (k,c) = Encap(pk)
3. Decapsulation    k' = Decap(sk,c')

'''

from dataclasses import dataclass
import os
import oqs
KEM_Algo = "ML-KEM-768"


# ML-KEM-768 = NIST Level 3 (recommandé pour production)
# ML-KEM-512 = NIST Level 1 (plus rapide, moins sécurisé)
# ML-KEM-1024 = NIST Level 5 (plus lent, plus sécurisé)
KEM_ALGORITHM = "ML-KEM-768"


# ---------------------------------------------------------------------------
# Structures de données
# ---------------------------------------------------------------------------

@dataclass
class KEMKeyPair:
    """
    Paire de clés ML-KEM-768.

    Tailles FIPS 203 :
      - public_key  : 1184 octets
      - secret_key  : 2400 octets
    """
    public_key: bytes
    secret_key: bytes

    def public_key_hex(self) -> str:
        return self.public_key.hex()

    def __repr__(self):
        return (
            f"KEMKeyPair("
            f"pk[{len(self.public_key)}B]={self.public_key.hex()[:16]}…, "
            f"sk[{len(self.secret_key)}B]=***)"
        )


@dataclass
class KEMEncapsulationResult:
    """
    Résultat d'une encapsulation ML-KEM.

    - ciphertext    : à envoyer à l'autre partie (1088 octets)
    - shared_secret : secret gardé localement    (32 octets)
    """
    ciphertext: bytes
    shared_secret: bytes

    def __repr__(self):
        return (
            f"KEMEncapsulationResult("
            f"ct[{len(self.ciphertext)}B]={self.ciphertext.hex()[:16]}…, "
            f"ss={self.shared_secret.hex()})"
        )


# ---------------------------------------------------------------------------
# Fonctions principales
# ---------------------------------------------------------------------------

def generate_keypair() -> KEMKeyPair:
    """
    Génère une paire de clés ML-KEM-768.

    Utilisé par :
      - Bob pour sa clé d'identité (IK)
      - Bob pour sa Signed PreKey (SPK)
      - Bob pour ses One-Time PreKeys (OPK)

    Returns:
        KEMKeyPair(public_key, secret_key)
    """
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()

    return KEMKeyPair(public_key=public_key, secret_key=secret_key)


def encapsulate(public_key: bytes) -> KEMEncapsulationResult:
    """
    Encapsule un secret partagé avec la clé publique du destinataire.
    Appelé par l'initiateur (Alice) durant le handshake PQ-X3DH.

    Args:
        public_key : clé publique du destinataire (Bob)

    Returns:
        KEMEncapsulationResult :
          - ciphertext    → à envoyer à Bob via le serveur
          - shared_secret → conservé par Alice pour dériver la master key

    Raises:
        ValueError : si la clé publique a une taille incorrecte
        RuntimeError : si liboqs échoue
    """
    _validate_public_key(public_key)

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)

    return KEMEncapsulationResult(ciphertext=ciphertext, shared_secret=shared_secret)


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """
    Décapsule le secret partagé avec la clé secrète locale.
    Appelé par le destinataire (Bob) durant le handshake PQ-X3DH
    et à chaque tour du KEM Ratchet.

    Args:
        secret_key  : clé secrète de Bob
        ciphertext  : ciphertext reçu d'Alice

    Returns:
        shared_secret (32 octets) — identique au shared_secret d'Alice
        si les clés sont correctes.

    Note IND-CCA2 :
        Si le ciphertext est modifié (attaque active), ML-KEM ne lève
        pas d'exception — il retourne un secret pseudo-aléatoire incorrect.
        C'est un comportement intentionnel (pas d'oracle d'erreur).

    Raises:
        ValueError : si les tailles sont incorrectes
        RuntimeError : si liboqs échoue
    """
    _validate_secret_key(secret_key)
    _validate_ciphertext(ciphertext)

    with oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)

    return shared_secret


# ---------------------------------------------------------------------------
# KEM Ratchet — utilisé dans double_ratchet.py
# ---------------------------------------------------------------------------

def kem_ratchet_step(their_public_key: bytes) -> tuple[bytes, bytes]:
    """
    Effectue un pas du KEM Ratchet (remplace le DH Ratchet de Signal).

    Appelé par l'émetteur à chaque nouveau "tour" de ratchet.

    Returns:
        (our_new_public_key, shared_secret)
        - our_new_public_key : à inclure dans le header du message
        - shared_secret      : utilisé pour dériver les nouvelles clés de chaîne

    Usage dans double_ratchet.py :
        new_pk, ratchet_secret = kem_ratchet_step(their_ratchet_public_key)
    """
    result = encapsulate(their_public_key)
    # On génère aussi notre nouvelle clé pour le prochain tour
    new_keypair = generate_keypair()
    return new_keypair.public_key, result.shared_secret


# ---------------------------------------------------------------------------
# Validation interne
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
# Utilitaires
# ---------------------------------------------------------------------------

def kem_info() -> dict:
    """Retourne les paramètres de taille de ML-KEM-768."""
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
    """Vérifie que ML-KEM-768 est disponible dans liboqs."""
    return KEM_ALGORITHM in oqs.get_enabled_kem_mechanisms()
