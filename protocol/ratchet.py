from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import sys
if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))
from crypto import dsa, hkdf, kem
from protocol import authentication, handshake, session


RATCHET_VERSION = b"QSMP-RATCHET-1"
KDF_HASH = "sha512" #to derive the new root_key and the new chain keys
CHAIN_KEY_SIZE = 32


#ratchet managment 
'''

ratchet is a mechanism that allows two parties to establish a new shared secret
when they need to change their root key

'''

def _encode_parts(*parts: bytes) -> bytes:
    # encodes parts with length prefix
    encoded = bytearray()
    for part in parts:
        encoded.extend(len(part).to_bytes(4, "big"))
        encoded.extend(part)
    return bytes(encoded)


@dataclass
# ------ message sent by the initiator to the responder
# to refresh the root key of a session 
class RatchetOffer:
    version: bytes
    session_id: bytes
    sender_id: str
    ratchet_counter: int
    ephemeral_kem_public_key: bytes # ephemeral key pair for the ratchet - used to derive the new root key
    signature: bytes


@dataclass
# ------ message sent by the responder to the initiator
# to confirm the new root key and the new chain keys
class RatchetReply:
    version: bytes
    session_id: bytes
    sender_id: str
    ratchet_counter: int
    ciphertext: bytes   # the encapsulated shared secret
    signature: bytes


@dataclass
# ------ state maintained by the initiator
class RatchetInitiatorState:
    ephemeral_kem: kem.KEMKeyPair
    offer: RatchetOffer


def _offer_payload(
    # builds the payload for the ratchet offer message
    # data that will be signed by initiator 
    session_id: bytes,
    sender_id: str,
    receiver_id: str,
    ratchet_counter: int,
    ephemeral_pub: bytes,
) -> bytes:
    return _encode_parts(
        RATCHET_VERSION,
        b"offer",
        session_id,
        sender_id.encode(),
        receiver_id.encode(),
        ratchet_counter.to_bytes(8, "big"),
        ephemeral_pub,
    )


def _reply_payload(
    session_id: bytes,
    sender_id: str,
    receiver_id: str,
    ratchet_counter: int,
    ciphertext: bytes,
) -> bytes:
    return _encode_parts(
        RATCHET_VERSION,
        b"reply",
        session_id,
        sender_id.encode(),
        receiver_id.encode(),
        ratchet_counter.to_bytes(8, "big"),
        ciphertext,
    )


def _derive_ratchet_state(
    sess: session.MessagingSession,
    shared_secret: bytes,
    ratchet_counter: int,
    initiator_is_local: bool,
) -> None:
#step 1 : HKDF 
    material = hkdf.hkdf(
        salt=sess.root_key, # new ratchet depends on previous root key
        ikm=shared_secret, # new ratchet depends on the shared secret from the KEM
        info=f"pq-ratchet:{ratchet_counter}".encode(), # new ratchet depends on the ratchet counter
        length=3 * CHAIN_KEY_SIZE,
        hash_name=KDF_HASH,
    )
    #step 2 : derive new keys
    new_root_key = material[:CHAIN_KEY_SIZE]
    initiator_send = material[CHAIN_KEY_SIZE:2 * CHAIN_KEY_SIZE]
    responder_send = material[2 * CHAIN_KEY_SIZE:]

    sess.root_key = new_root_key
    #step 3 : update chain keys
    if initiator_is_local:
        sess.send_chain_key = initiator_send
        sess.recv_chain_key = responder_send
    else:
        sess.send_chain_key = responder_send
        sess.recv_chain_key = initiator_send

    sess.previous_counter = sess.send_counter
    sess.send_counter = 0
    sess.recv_counter = 0
    sess.ratchet_counter = ratchet_counter

# -- PRINCIPAL FUNCTIONS --

def initiate_ratchet(
    #function to refresh the root key of a session
    #generate a new ephemeral key pair
    #encapsulate the shared secret
    #sign the offer
    
    sess: session.MessagingSession,
    local_identity: authentication.IdentityRecord | handshake.Identity,
) -> tuple[RatchetInitiatorState, RatchetOffer]:
    next_counter = sess.ratchet_counter + 1
    ephemeral = kem.generate_keypair()
    payload = _offer_payload(
        sess.session_id,
        sess.local_user_id,
        sess.peer_user_id,
        next_counter,
        ephemeral.public_key,
    )
    signature = dsa.sign(payload, local_identity.identity_sig.secret_key)
    offer = RatchetOffer(
        version=RATCHET_VERSION,
        session_id=sess.session_id,
        sender_id=sess.local_user_id,
        ratchet_counter=next_counter,
        ephemeral_kem_public_key=ephemeral.public_key,
        signature=signature,
    )
    return RatchetInitiatorState(ephemeral_kem=ephemeral, offer=offer), offer


def respond_ratchet(
    #function to refresh the root key of a session
    #verify the offer
    #encapsulate the shared secret
    #sign the reply
    
    sess: session.MessagingSession,
    local_identity: authentication.IdentityRecord | handshake.Identity,
    peer_identity_public_key: bytes,
    offer: RatchetOffer,
) -> RatchetReply:
    if offer.session_id != sess.session_id:
        raise ValueError("Session ID invalide pour le ratchet")
    if offer.sender_id != sess.peer_user_id:
        raise ValueError("Expediteur inattendu pour le ratchet")

    payload = _offer_payload(
        sess.session_id,
        offer.sender_id,
        sess.local_user_id,
        offer.ratchet_counter,
        offer.ephemeral_kem_public_key,
    )
    if not dsa.verify(payload, offer.signature, peer_identity_public_key):
        raise ValueError("La signature de RatchetOffer est invalide")

    encapsulated = kem.encapsulate(offer.ephemeral_kem_public_key)
    _derive_ratchet_state(sess, encapsulated.shared_secret, offer.ratchet_counter, initiator_is_local=False)

    reply_payload = _reply_payload(
        sess.session_id,
        sess.local_user_id,
        offer.sender_id,
        offer.ratchet_counter,
        encapsulated.ciphertext,
    )
    signature = dsa.sign(reply_payload, local_identity.identity_sig.secret_key)
    return RatchetReply(
        version=RATCHET_VERSION,
        session_id=sess.session_id,
        sender_id=sess.local_user_id,
        ratchet_counter=offer.ratchet_counter,
        ciphertext=encapsulated.ciphertext,
        signature=signature,
    )


def finalize_ratchet(
    #function to refresh the root key of a session
    #verify the reply
    #derive the new root key
    
    sess: session.MessagingSession,
    state: RatchetInitiatorState,
    reply: RatchetReply,
    peer_identity_public_key: bytes,
) -> None:
    if reply.session_id != sess.session_id:
        raise ValueError("Session ID invalide pour RatchetReply")
    if reply.sender_id != sess.peer_user_id:
        raise ValueError("Expediteur inattendu pour RatchetReply")
    if reply.ratchet_counter != state.offer.ratchet_counter:
        raise ValueError("Compteur de ratchet inattendu")

    payload = _reply_payload(
        sess.session_id,
        reply.sender_id,
        sess.local_user_id,
        reply.ratchet_counter,
        reply.ciphertext,
    )
    if not dsa.verify(payload, reply.signature, peer_identity_public_key):
        raise ValueError("La signature de RatchetReply est invalide")

    shared_secret = kem.decapsulate(state.ephemeral_kem.secret_key, reply.ciphertext)
    _derive_ratchet_state(sess, shared_secret, reply.ratchet_counter, initiator_is_local=True)


def run_demo_ratchet() -> dict:
    hs = handshake.run_demo_handshake()
    alice = session.session_from_handshake(hs["alice_session"], hs["bob"].identity_sig.public_key)
    bob = session.session_from_handshake(hs["bob_session"], hs["alice"].identity_sig.public_key)

    before_root = alice.root_key
    state, offer = initiate_ratchet(alice, hs["alice"])
    reply = respond_ratchet(bob, hs["bob"], hs["alice"].identity_sig.public_key, offer)
    finalize_ratchet(alice, state, reply, hs["bob"].identity_sig.public_key)

    msg = session.encrypt_message(alice, b"Ratchet refreshed message")
    recovered = session.decrypt_message(bob, msg)
    # can encrypt and decrypt means that the sessions are synchronized. 

    return {
        "alice": alice,
        "bob": bob,
        "offer": offer,
        "reply": reply,
        "root_key_changed": before_root != alice.root_key,
        "same_root_key": alice.root_key == bob.root_key,
        "opposite_chain_keys": (
            alice.send_chain_key == bob.recv_chain_key
            and alice.recv_chain_key == bob.send_chain_key
        ),
        "recovered": recovered,
    }


if __name__ == "__main__":
    demo = run_demo_ratchet()
    print("=" * 60)
    print("  QSMP Ratchet Demo")
    print("=" * 60)
    print(f"Root key changed      : {demo['root_key_changed']}")
    print(f"Same root key         : {demo['same_root_key']}")
    print(f"Opposite chain keys   : {demo['opposite_chain_keys']}")
    print(f"Recovered plaintext   : {demo['recovered']!r}")
    print(f"Ratchet counter       : {demo['alice'].ratchet_counter}")
    print("=" * 60)
