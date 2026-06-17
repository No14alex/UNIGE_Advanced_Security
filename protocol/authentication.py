from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from crypto import dsa, kem

AUTH_VERSION = b"QSMP-AUTH-1"


"""
IDENTITY SETUP

1. user identity creation 
2. signed prekey bundle creation
3. signed prekey bundle verification
4. identity fingerprints
5. safety number
6. generic signed payloads for handshake/ratchet messages
"""


def _encode_parts(*parts: bytes) -> bytes:
    encoded = bytearray()
    for part in parts:
        encoded.extend(len(part).to_bytes(4, "big"))
        encoded.extend(part)
    return bytes(encoded)


@dataclass
class IdentityRecord:
    """
    long term identity record for a user
    """
    user_id: str
    identity_sig: dsa.DSAKeyPair
    signed_prekey: kem.KEMKeyPair
    signed_prekey_signature: bytes


@dataclass
class SignedPreKeyBundle:
    """
    Public boundle sent to the server
    """
    user_id: str
    identity_public_key: bytes
    signed_prekey_public_key: bytes
    signed_prekey_signature: bytes


@dataclass
class AuthenticatedPayload:
    """
    Signed message with ML-DSA
    """
    sender_id: str
    context: bytes
    payload: bytes
    signature: bytes


def create_identity_record(user_id: str) -> IdentityRecord:
    """
    Generates the long term identity for a user
    """
    identity_sig = dsa.generate_keypair()
    signed_prekey = kem.generate_keypair()
    bundle_payload = build_signed_prekey_payload(
        user_id, signed_prekey.public_key)
    signed_prekey_signature = dsa.sign(bundle_payload, identity_sig.secret_key)
    # -> This ML-KEM prekey belongs to this ML-DSA identity

    return IdentityRecord(
        user_id=user_id,
        identity_sig=identity_sig,
        signed_prekey=signed_prekey,
        signed_prekey_signature=signed_prekey_signature,
    )

# Public part of identityRecord published on the server


def export_signed_prekey_bundle(identity: IdentityRecord) -> SignedPreKeyBundle:
    return SignedPreKeyBundle(
        user_id=identity.user_id,
        identity_public_key=identity.identity_sig.public_key,
        signed_prekey_public_key=identity.signed_prekey.public_key,
        signed_prekey_signature=identity.signed_prekey_signature,
    )

# builds the bytes that are signed for a prekey bundle


def build_signed_prekey_payload(user_id: str, signed_prekey_public_key: bytes) -> bytes:
    return _encode_parts(
        AUTH_VERSION,
        b"signed-prekey-bundle",
        user_id.encode(),
        signed_prekey_public_key,
    )

# Verify validity of the signed prekey bundle


def verify_signed_prekey_bundle(bundle: SignedPreKeyBundle) -> bool:
    payload = build_signed_prekey_payload(
        bundle.user_id, bundle.signed_prekey_public_key)
    return dsa.verify(payload, bundle.signed_prekey_signature, bundle.identity_public_key)

# sha-256 fingerprint of a public identity key (original give through trusted way)


def fingerprint_identity_key(identity_public_key: bytes) -> str:
    return hashlib.sha256(identity_public_key).hexdigest()

# Trust identifier of the conversation


def safety_number(local_identity_key: bytes, remote_identity_key: bytes) -> str:
    # sort the keys
    ordered = sorted([local_identity_key, remote_identity_key])
    # hash of the sorted keys
    return hashlib.sha256(ordered[0] + ordered[1]).hexdigest()

# build the bytes that are signed for a signed prekey bundle


def build_transcript_payload(
    sender_id: str,
    receiver_id: str,
    context: bytes,
    *parts: bytes,
) -> bytes:
    return _encode_parts(
        AUTH_VERSION,
        b"transcript",
        sender_id.encode(),
        receiver_id.encode(),
        context,
        *parts,
    )


def sign_authenticated_payload(
    sender: IdentityRecord,
    receiver_id: str,
    context: bytes,
    *parts: bytes,
) -> AuthenticatedPayload:
    # build the payload -> sign -> return AuthenticatedPayload
    payload = build_transcript_payload(
        sender.user_id, receiver_id, context, *parts)
    signature = dsa.sign(payload, sender.identity_sig.secret_key)
    return AuthenticatedPayload(
        sender_id=sender.user_id,
        context=context,
        payload=payload,
        signature=signature,
    )


def verify_authenticated_payload(
    sender_id: str,
    receiver_id: str,
    context: bytes,
    signature: bytes,
    sender_identity_public_key: bytes,
    *parts: bytes,
) -> bool:
    payload = build_transcript_payload(sender_id, receiver_id, context, *parts)
    # reject tampered or forged handshake
    return dsa.verify(payload, signature, sender_identity_public_key)


# -----------
# DEMO FUNCTION
# -----------
def run_demo_authentication(alice_id: str = "alice", bob_id: str = "bob") -> dict:
    alice = create_identity_record(alice_id)
    bob = create_identity_record(bob_id)

    alice_bundle = export_signed_prekey_bundle(alice)
    bob_bundle = export_signed_prekey_bundle(bob)

    alice_fingerprint = fingerprint_identity_key(alice.identity_sig.public_key)
    bob_fingerprint = fingerprint_identity_key(bob.identity_sig.public_key)
    conversation_safety = safety_number(
        alice.identity_sig.public_key,
        bob.identity_sig.public_key,
    )

    context = b"handshake-init"
    alice_ephemeral = kem.generate_keypair()
    nonce = bytes.fromhex("01" * 32)
    signed_init = sign_authenticated_payload(
        alice,
        bob.user_id,
        context,
        alice_ephemeral.public_key,
        nonce,
    )
    verified = verify_authenticated_payload(
        alice.user_id,
        bob.user_id,
        context,
        signed_init.signature,
        alice.identity_sig.public_key,
        alice_ephemeral.public_key,
        nonce,
    )

    tampered_verified = verify_authenticated_payload(
        alice.user_id,
        bob.user_id,
        context,
        signed_init.signature,
        alice.identity_sig.public_key,
        alice_ephemeral.public_key,
        bytes.fromhex("02" * 32),
    )

    return {
        "alice": alice,
        "bob": bob,
        "alice_bundle_valid": verify_signed_prekey_bundle(alice_bundle),
        "bob_bundle_valid": verify_signed_prekey_bundle(bob_bundle),
        "alice_fingerprint": alice_fingerprint,
        "bob_fingerprint": bob_fingerprint,
        "conversation_safety_number": conversation_safety,
        "signed_init": signed_init,
        "signed_init_verified": verified,
        "signed_init_tampered_verified": tampered_verified,
    }


if __name__ == "__main__":
    result = run_demo_authentication()
    print("=" * 60)
    print("  QSMP Authentication Demo")
    print("=" * 60)
    print(f"Alice bundle valid         : {result['alice_bundle_valid']}")
    print(f"Bob bundle valid           : {result['bob_bundle_valid']}")
    print(
        f"Alice fingerprint          : {result['alice_fingerprint'][:32]}...")
    print(f"Bob fingerprint            : {result['bob_fingerprint'][:32]}...")
    print(
        f"Conversation safety number : {result['conversation_safety_number'][:32]}...")
    print(f"Signed init verified       : {result['signed_init_verified']}")
    print(
        f"Tampered init verified     : {result['signed_init_tampered_verified']}")
    print("=" * 60)
