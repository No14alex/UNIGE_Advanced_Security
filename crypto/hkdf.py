

"""
HKDF implementation following RFC 5869.

1. Extract   PRK = HMAC(salt, IKM)
2. Expand    OKM = HMAC(PRK, T(n-1) || info || counter)
"""

import hashlib
import hmac


DEFAULT_HASH = "sha256"


def _get_hash_function(hash_name: str):
    try:
        return getattr(hashlib, hash_name)
    except AttributeError as exc:
        raise ValueError(f"Fonction de hash non supportee: {hash_name}") from exc


def hmac_digest(key: bytes, data: bytes, hash_name: str = DEFAULT_HASH) -> bytes:
    hash_function = _get_hash_function(hash_name)
    return hmac.new(key, data, hash_function).digest()


def hkdf_extract(salt: bytes, ikm: bytes, hash_name: str = DEFAULT_HASH) -> bytes:
    hash_function = _get_hash_function(hash_name)
    if len(salt) == 0:
        salt = bytes(hash_function().digest_size)
    return hmac_digest(salt, ikm, hash_name)


def hkdf_expand(
    prk: bytes,
    info: bytes,
    length: int,
    hash_name: str = DEFAULT_HASH,
) -> bytes:
    hash_function = _get_hash_function(hash_name)
    digest_size = hash_function().digest_size

    if length < 0:
        raise ValueError("La longueur derivee doit etre positive ou nulle")
    if length > 255 * digest_size:
        raise ValueError(
            f"La longueur derivee est trop grande: {length}, maximum {255 * digest_size}"
        )
    if length == 0:
        return b""

    t = b""
    okm = b""
    counter = 0
    while len(okm) < length:
        counter += 1
        t = hmac_digest(prk, t + info + bytes([counter]), hash_name)
        okm += t
    return okm[:length]


def hkdf(
    salt: bytes,
    ikm: bytes,
    info: bytes,
    length: int,
    hash_name: str = DEFAULT_HASH,
) -> bytes:
    prk = hkdf_extract(salt, ikm, hash_name)
    return hkdf_expand(prk, info, length, hash_name)


def hkdf_info() -> dict:
    return {
        "default_hash": DEFAULT_HASH,
        "supported_examples": ("sha256", "sha384", "sha512"),
        "rfc": "RFC 5869",
    }


if __name__ == "__main__":
    print("=" * 60)
    print("  HKDF — Protocole QSMP")
    print("=" * 60)

    print("\nParametres :")
    for key, value in hkdf_info().items():
        print(f"   {key:<20} {value}")

    salt = bytes.fromhex("000102030405060708090a0b0c")
    ikm = bytes.fromhex("0b" * 22)
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")

    print(f"\nSalt   : {salt.hex()}")
    print(f"IKM    : {ikm.hex()}")
    print(f"Info   : {info.hex()}")

    prk = hkdf_extract(salt, ikm)
    okm = hkdf(salt, ikm, info, 42)

    print(f"\nPRK[{len(prk)}B] : {prk.hex()}")
    print(f"OKM[{len(okm)}B] : {okm.hex()}")
    print("\nVerification RFC 5869:")
    expected = (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    print(f"   OK : {okm.hex() == expected}")

    print("\n" + "=" * 60)

#wikipedia version modified : - hardcoded sha-256 modified to hkdf-sha-512 and added tests