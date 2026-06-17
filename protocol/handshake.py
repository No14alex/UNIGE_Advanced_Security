from __future__ import annotations
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from crypto import hkdf, kem
from protocol import authentication


PROTOCOL_VERSION = b"QSMP-1"
TRANSCRIPT_HASH = "sha512"
CHAIN_KEY_SIZE = 32


def _encode_parts(*parts: bytes) -> bytes:
    """
    Concatenation with the lengths 
    """
    encoded = bytearray()
    for part in parts:
        encoded.extend(len(part).to_bytes(4, "big"))
        encoded.extend(part)
    return bytes(encoded)


def _hash_bytes(data: bytes) -> bytes:
    return hashlib.new(TRANSCRIPT_HASH, data).digest()


@dataclass
class Identity:
    user_id: str
    identity_sig: authentication.dsa.DSAKeyPair
    signed_prekey: kem.KEMKeyPair
    bundle_signature: bytes

    @classmethod
    def from_auth_record(cls, record: authentication.IdentityRecord) -> "Identity":
        return cls(
            user_id=record.user_id,
            identity_sig=record.identity_sig,
            signed_prekey=record.signed_prekey,
            bundle_signature=record.signed_prekey_signature,
        )

    def to_auth_record(self) -> authentication.IdentityRecord:
        return authentication.IdentityRecord(
            user_id=self.user_id,
            identity_sig=self.identity_sig,
            signed_prekey=self.signed_prekey,
            signed_prekey_signature=self.bundle_signature,
        )


@dataclass
class PreKeyBundle:  # what will be published on the server
    user_id: str
    identity_public_key: bytes
    signed_prekey_public_key: bytes
    bundle_signature: bytes

    @classmethod
    def from_auth_bundle(cls, bundle: authentication.SignedPreKeyBundle) -> "PreKeyBundle":
        return cls(
            user_id=bundle.user_id,
            identity_public_key=bundle.identity_public_key,
            signed_prekey_public_key=bundle.signed_prekey_public_key,
            bundle_signature=bundle.signed_prekey_signature,
        )

    def to_auth_bundle(self) -> authentication.SignedPreKeyBundle:
        return authentication.SignedPreKeyBundle(
            user_id=self.user_id,
            identity_public_key=self.identity_public_key,
            signed_prekey_public_key=self.signed_prekey_public_key,
            signed_prekey_signature=self.bundle_signature,
        )


@dataclass
class HandshakeInit:
    version: bytes
    sender_id: str
    receiver_id: str
    ephemeral_kem_public_key: bytes
    nonce: bytes
    signature: bytes


@dataclass
class HandshakeReply:
    version: bytes
    sender_id: str
    receiver_id: str
    ephemeral_kem_public_key: bytes
    ciphertext_to_initiator: bytes
    nonce: bytes
    signature: bytes


@dataclass
class HandshakeFinish:
    version: bytes
    session_id: bytes
    ciphertext_to_responder: bytes


@dataclass
class HandshakeInitiatorState:
    local_identity: Identity
    peer_bundle: PreKeyBundle
    ephemeral_kem: kem.KEMKeyPair
    init_message: HandshakeInit


@dataclass
class HandshakeResponderState:
    local_identity: Identity
    peer_identity_public_key: bytes
    peer_init: HandshakeInit
    ephemeral_kem: kem.KEMKeyPair
    shared_secret_to_initiator: bytes
    reply_message: HandshakeReply


@dataclass
class SessionState:  # output of handshake
    session_id: bytes
    local_user_id: str
    peer_user_id: str
    root_key: bytes
    send_chain_key: bytes
    recv_chain_key: bytes
    transcript_hash: bytes


# -----------

def create_identity(user_id: str) -> Identity:
    """
    Creates the keys
    - IK : long-term identity signature key pair 
    - SPK : signed medium-term pre-key pair to initiate new sessions
    """
    return Identity.from_auth_record(authentication.create_identity_record(user_id))

# extracts the public part of the boundle


def export_prekey_bundle(identity: Identity) -> PreKeyBundle:
    return PreKeyBundle.from_auth_bundle(
        authentication.export_signed_prekey_bundle(identity.to_auth_record())
    )


def verify_prekey_bundle(bundle: PreKeyBundle) -> bool:
    return authentication.verify_signed_prekey_bundle(bundle.to_auth_bundle())


""" 
start the handshake from Alice's side
1. verify Bob's boundle 
2. Alice creates a short-term KEM 
3. generation of a nonce 
4. construction and signature of payload 
"""
def initiate_handshake(local_identity: Identity, peer_bundle: PreKeyBundle) -> tuple[HandshakeInitiatorState, HandshakeInit]:
    if not verify_prekey_bundle(peer_bundle):
        raise ValueError("Le prekey bundle is invalid")

    ephemeral = kem.generate_keypair()
    nonce = os.urandom(32)
    signed_payload = authentication.sign_authenticated_payload(
        local_identity.to_auth_record(),
        peer_bundle.user_id,
        b"handshake-init",
        ephemeral.public_key,
        nonce,
    )
    init = HandshakeInit(
        version=PROTOCOL_VERSION,
        sender_id=local_identity.user_id,
        receiver_id=peer_bundle.user_id,
        ephemeral_kem_public_key=ephemeral.public_key,
        nonce=nonce,
        signature=signed_payload.signature,
    )
    state = HandshakeInitiatorState(
        local_identity=local_identity,
        peer_bundle=peer_bundle,
        ephemeral_kem=ephemeral,
        init_message=init,
    )
    return state, init


"""
Bob responds to Alice 
1. reconstruct the payload signed by alice 
2. verify alice's signature 
3. Bob creates a short term KEM key 
4. generate a nonce 
5. encapsulate public KEM key of Alice -> creates ciphertext & shared secret 
6. sign the response 

"""
def respond_handshake(
    local_identity: Identity,
    peer_identity_public_key: bytes,
    init_message: HandshakeInit,
) -> tuple[HandshakeResponderState, HandshakeReply]:
    ok = authentication.verify_authenticated_payload(
        init_message.sender_id,
        init_message.receiver_id,
        b"handshake-init",
        init_message.signature,
        peer_identity_public_key,
        init_message.ephemeral_kem_public_key,
        init_message.nonce,
    )
    if not ok:
        raise ValueError("The signature of HANDSHAKE_INIT is invalid")

    ephemeral = kem.generate_keypair()
    nonce = os.urandom(32)
    encapsulated = kem.encapsulate(init_message.ephemeral_kem_public_key)
    signed_payload = authentication.sign_authenticated_payload(
        local_identity.to_auth_record(),
        init_message.sender_id,
        b"handshake-reply",
        init_message.ephemeral_kem_public_key,
        ephemeral.public_key,
        init_message.nonce,
        nonce,
        encapsulated.ciphertext,
    )
    reply = HandshakeReply(
        version=PROTOCOL_VERSION,
        sender_id=local_identity.user_id,
        receiver_id=init_message.sender_id,
        ephemeral_kem_public_key=ephemeral.public_key,
        ciphertext_to_initiator=encapsulated.ciphertext,
        nonce=nonce,
        signature=signed_payload.signature,
    )
    state = HandshakeResponderState(
        local_identity=local_identity,
        peer_identity_public_key=peer_identity_public_key,
        peer_init=init_message,
        ephemeral_kem=ephemeral,
        shared_secret_to_initiator=encapsulated.shared_secret,
        reply_message=reply,
    )
    return state, reply


"""
Finalization from Alice 
1. verify that correct boundle 
2. reconstruct the payload 
3. Alice verifies Bob's signature 
4. decapsulate the ciphertext received 
5. encapsulate public KEM key of bob -> creates ciphertext for Bob & shared secret 
-
6. calculate hash and mix the two secrets 

"""
def finalize_initiator(
    state: HandshakeInitiatorState,
    reply: HandshakeReply,
) -> tuple[HandshakeFinish, SessionState]:
    if reply.sender_id != state.peer_bundle.user_id:
        raise ValueError("The responder doesn't correspond to the boundle ")

    ok = authentication.verify_authenticated_payload(
        reply.sender_id,
        state.local_identity.user_id,
        b"handshake-reply",
        reply.signature,
        state.peer_bundle.identity_public_key,
        state.init_message.ephemeral_kem_public_key,
        reply.ephemeral_kem_public_key,
        state.init_message.nonce,
        reply.nonce,
        reply.ciphertext_to_initiator,
    )
    if not ok:
        raise ValueError("The signature is invalid")

    responder_secret = kem.decapsulate(
        state.ephemeral_kem.secret_key,
        reply.ciphertext_to_initiator,
    )
    encapsulated = kem.encapsulate(reply.ephemeral_kem_public_key)
    transcript_hash = _transcript_hash(state.init_message, reply)
    session = _derive_session(
        local_user_id=state.local_identity.user_id,
        peer_user_id=state.peer_bundle.user_id,
        shared_secret_ab=encapsulated.shared_secret,
        shared_secret_ba=responder_secret,
        transcript_hash=transcript_hash,
        initiator_is_local=True,
    )
    finish = HandshakeFinish(
        version=PROTOCOL_VERSION,
        session_id=session.session_id,
        ciphertext_to_responder=encapsulated.ciphertext,
    )
    return finish, session


"""
Finalization from Bob 
1. Decapsulate the ciphertext received from alice 
2. calcualte the hash and derive the two secrets 
"""

def finalize_responder(
    state: HandshakeResponderState,
    finish: HandshakeFinish,
) -> SessionState:
    initiator_secret = kem.decapsulate(
        state.ephemeral_kem.secret_key,
        finish.ciphertext_to_responder,
    )
    transcript_hash = _transcript_hash(state.peer_init, state.reply_message)
    session = _derive_session(
        local_user_id=state.local_identity.user_id,
        peer_user_id=state.peer_init.sender_id,
        shared_secret_ab=initiator_secret,
        shared_secret_ba=state.shared_secret_to_initiator,
        transcript_hash=transcript_hash,
        initiator_is_local=False,
    )
    if session.session_id != finish.session_id:
        raise ValueError(
            "The session_id derived doesn't correspond to the final message")
    return session

# ---------------------
# ----- DEMO of handshake
# ----------------------
def run_demo_handshake(alice_id: str = "alice", bob_id: str = "bob") -> dict:
    alice = create_identity(alice_id)
    bob = create_identity(bob_id)

    bob_bundle = export_prekey_bundle(bob)
    alice_state, init = initiate_handshake(alice, bob_bundle)
    bob_state, reply = respond_handshake(
        bob, alice.identity_sig.public_key, init)
    finish, alice_session = finalize_initiator(alice_state, reply)
    bob_session = finalize_responder(bob_state, finish)

    return {
        "alice": alice,
        "bob": bob,
        "bob_bundle_valid": verify_prekey_bundle(bob_bundle),
        "init": init,
        "reply": reply,
        "finish": finish,
        "alice_session": alice_session,
        "bob_session": bob_session,
        "same_session_id": alice_session.session_id == bob_session.session_id,
        "same_root_key": alice_session.root_key == bob_session.root_key,
        "opposite_chain_keys": (
            alice_session.send_chain_key == bob_session.recv_chain_key
            and alice_session.recv_chain_key == bob_session.send_chain_key
        ),
    }

#transcript_hash = SHA512(all handshake data)
def _transcript_hash(init_message: HandshakeInit, reply: HandshakeReply) -> bytes:
    transcript = _encode_parts(
        init_message.version,
        init_message.sender_id.encode(),
        init_message.receiver_id.encode(),
        init_message.ephemeral_kem_public_key,
        init_message.nonce,
        init_message.signature,
        reply.version,
        reply.sender_id.encode(),
        reply.receiver_id.encode(),
        reply.ephemeral_kem_public_key,
        reply.ciphertext_to_initiator,
        reply.nonce,
        reply.signature,
    )
    return _hash_bytes(transcript)

"""
Take the two shared secrets + the transcript hash -> compute session keys

2 secrets ML-KEM
+ transcript_hash
+ HKDF
=
root_key + chain keys + session_id
"""
def _derive_session(
    *,
    local_user_id: str,
    peer_user_id: str,
    shared_secret_ab: bytes,
    shared_secret_ba: bytes,
    transcript_hash: bytes,
    initiator_is_local: bool,
) -> SessionState:

    #session depends on the two exchanges
    ikm = shared_secret_ab + shared_secret_ba 
    key_material = hkdf.hkdf(
        salt=transcript_hash,
        ikm=ikm,
        info=b"qsmp-handshake-v1",
        length=4 * CHAIN_KEY_SIZE,  # 4 keys of 32 bytes = 128 bytes
        hash_name=TRANSCRIPT_HASH,
    )
    root_key = key_material[:CHAIN_KEY_SIZE]  # [0:32]
    initiator_send = key_material[CHAIN_KEY_SIZE:2 * CHAIN_KEY_SIZE]  # [32:64]
    responder_send = key_material[2 * CHAIN_KEY_SIZE:3 * CHAIN_KEY_SIZE]  # [64:96]
    session_id = key_material[3 * CHAIN_KEY_SIZE:]  # [96:128]

    if initiator_is_local:
        send_chain_key = initiator_send
        recv_chain_key = responder_send
    else:
        send_chain_key = responder_send
        recv_chain_key = initiator_send

    return SessionState(
        session_id=session_id,
        local_user_id=local_user_id,
        peer_user_id=peer_user_id,
        root_key=root_key,
        send_chain_key=send_chain_key,
        recv_chain_key=recv_chain_key,
        transcript_hash=transcript_hash,
    )


if __name__ == "__main__":
    result = run_demo_handshake()
    print("=" * 60)
    print("  QSMP Handshake Demo")
    print("=" * 60)
    print(f"Bundle valide           : {result['bob_bundle_valid']}")
    print(f"Session ID identique    : {result['same_session_id']}")
    print(f"Root key identique      : {result['same_root_key']}")
    print(f"Chain keys reciproques  : {result['opposite_chain_keys']}")
    print(
        f"Alice session id        : {result['alice_session'].session_id.hex()[:32]}...")
    print(
        f"Bob session id          : {result['bob_session'].session_id.hex()[:32]}...")
    print("=" * 60)
