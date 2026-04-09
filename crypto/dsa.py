'''
Digital signature algorithm
ML - DSA - 65 protocol

1. Key Generation   (pk, sk) = Gen()
2. Signing          sig = Sign(sk, m)
3. Verification     ok = Verify(pk, m, sig)
'''

from dataclasses import dataclass
from importlib import util as importlib_util
from pathlib import Path
import sysconfig


def _load_oqs_module():
    """
    Charge le bon module OQS.

    Comme pour le module KEM, on contourne ici un conflit possible avec un
    package tiers également nommé ``oqs``.
    """
    import oqs as imported_oqs

    if hasattr(imported_oqs, "Signature"):
        return imported_oqs

    purelib = Path(sysconfig.get_paths()["purelib"])
    candidate = purelib / "oqs" / "oqs.py"
    if not candidate.exists():
        raise ImportError(
            "liboqs-python introuvable: le module 'oqs' importé n'expose pas "
            "Signature et aucun fallback n'a été trouvé."
        )

    spec = importlib_util.spec_from_file_location("liboqs_python_compat_sig", candidate)
    if spec is None or spec.loader is None:
        raise ImportError(f"Impossible de charger le module OQS depuis {candidate}")

    oqs_module = importlib_util.module_from_spec(spec)
    spec.loader.exec_module(oqs_module)
    return oqs_module


oqs = _load_oqs_module()


# ML-DSA-44 = NIST Level 2
# ML-DSA-65 = NIST Level 3 (bon équilibre pour ce projet)
# ML-DSA-87 = NIST Level 5
DSA_ALGORITHM = "ML-DSA-65"


@dataclass
class DSAKeyPair:
    """
    Paire de clés ML-DSA-65.

    Tailles FIPS 204 :
      - public_key  : 1952 octets
      - secret_key  : 4032 octets
    """
    public_key: bytes
    secret_key: bytes

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
    Génère une paire de clés ML-DSA-65.

    Utilisé pour la clé d'identité long terme de l'utilisateur.
    """
    with oqs.Signature(DSA_ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    return DSAKeyPair(public_key=public_key, secret_key=secret_key)


def sign(message: bytes, secret_key: bytes) -> bytes:
    """
    Signe un message avec la clé secrète ML-DSA.

    Args:
        message: message binaire à signer
        secret_key: clé secrète ML-DSA-65
    """
    _validate_secret_key(secret_key)

    with oqs.Signature(DSA_ALGORITHM, secret_key=secret_key) as signer:
        return signer.sign(message)


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Vérifie une signature ML-DSA.

    Retourne False si le message, la signature ou la clé publique ne
    correspondent pas.
    """
    _validate_public_key(public_key)
    _validate_signature(signature)

    with oqs.Signature(DSA_ALGORITHM) as verifier:
        return verifier.verify(message, signature, public_key)


def sign_with_context(message: bytes, secret_key: bytes, context: bytes) -> bytes:
    """
    Signe un message avec une chaîne de contexte.
    """
    _validate_secret_key(secret_key)

    with oqs.Signature(DSA_ALGORITHM, secret_key=secret_key) as signer:
        return signer.sign_with_ctx_str(message, context)


def verify_with_context(
    message: bytes,
    signature: bytes,
    context: bytes,
    public_key: bytes,
) -> bool:
    """
    Vérifie une signature ML-DSA avec contexte.
    """
    _validate_public_key(public_key)
    _validate_signature(signature)

    with oqs.Signature(DSA_ALGORITHM) as verifier:
        return verifier.verify_with_ctx_str(message, signature, context, public_key)


def dsa_info() -> dict:
    """Retourne les paramètres de taille de ML-DSA-65."""
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


def is_available() -> bool:
    """Vérifie que ML-DSA-65 est disponible dans liboqs."""
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
            f"Taille de clé secrète incorrecte : "
            f"reçu {len(secret_key)} octets, attendu {expected}"
        )


def _validate_signature(signature: bytes) -> None:
    expected = dsa_info()["signature_bytes"]
    if len(signature) != expected:
        raise ValueError(
            f"Taille de signature incorrecte : "
            f"reçu {len(signature)} octets, attendu {expected}"
        )
