from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidTag

from crypto import aes, hkdf
from protocol import authentication, handshake, messages


KDF_HASH = "sha512"
CHAIN_KEY_SIZE = 32

#session managment 
'''
derives per-message keys from the chain key with HKDF-SHA-512
encrypts messages with AES-256-GCM
authenticates the header through AAD
checks session ID, sender identity, and counters on receive
rejects replayed messages
'''

@dataclass
class MessagingSession:
    #Cryptographic memory of the conversation
    session_id: bytes
    local_user_id: str
    peer_user_id: str
    peer_identity_fingerprint: str
    root_key: bytes
    send_chain_key: bytes
    recv_chain_key: bytes
    send_counter: int = 0
    recv_counter: int = 0
    ratchet_counter: int = 0
    previous_counter: int = 0


def session_from_handshake(
    state: handshake.SessionState,
    peer_identity_public_key: bytes,
) -> MessagingSession:
    return MessagingSession(
        session_id=state.session_id,
        local_user_id=state.local_user_id,
        peer_user_id=state.peer_user_id,
        #add fingerprint to verify  who is talking to me later 
        peer_identity_fingerprint=authentication.fingerprint_identity_key(peer_identity_public_key),
        root_key=state.root_key,
        send_chain_key=state.send_chain_key,
        recv_chain_key=state.recv_chain_key,
    )


def _derive_message_key(chain_key: bytes, counter: int) -> tuple[bytes, bytes]:
    material = hkdf.hkdf(
        salt=b"",
        ikm=chain_key,
        info=f"message-key:{counter}".encode(),
        length=2 * CHAIN_KEY_SIZE,
        hash_name=KDF_HASH,
    )
    msg_key = material[:CHAIN_KEY_SIZE] #msg_key to decrypt this message 
    next_chain_key = material[CHAIN_KEY_SIZE:]
    return msg_key, next_chain_key

# encrypts messages with AES-256-GCM
def encrypt_message(session: MessagingSession, plaintext: bytes) -> messages.EncryptedMessage:
    # derive from send_chain_key with HKDF-SHA-512 -> msg_key, next_chain_key
    msg_key, next_chain_key = _derive_message_key(session.send_chain_key, session.send_counter)
    #construct the header
    header = messages.MessageHeader(
        version=messages.PROTOCOL_VERSION,
        session_id=session.session_id,
        sender_id=session.local_user_id,
        counter=session.send_counter,
        ratchet_counter=session.ratchet_counter,
        previous_counter=session.previous_counter,
        flags=[],
    )

    ciphertext = aes.encrypt(msg_key, plaintext, header.aad_bytes()) #header is Additional Authenticated Data
    # advance the send chain key 
    session.send_chain_key = next_chain_key
    session.send_counter += 1
    return messages.EncryptedMessage(
        header=header,
        nonce=ciphertext.nonce,
        ciphertext=ciphertext.ciphertext,
    )


def decrypt_message(session: MessagingSession, message: messages.EncryptedMessage) -> bytes:
    if message.header.session_id != session.session_id:
        raise ValueError("Session ID invalide")
    if message.header.sender_id != session.peer_user_id:
        raise ValueError("Expediteur inattendu")

        
    if message.header.counter != session.recv_counter:
        raise ValueError(
            f"Compteur de reception inattendu: recu {message.header.counter}, attendu {session.recv_counter}"
        )

    msg_key, next_chain_key = _derive_message_key(session.recv_chain_key, session.recv_counter)
    plaintext = aes.decrypt(msg_key, message.nonce, message.ciphertext, message.header.aad_bytes())
    session.recv_chain_key = next_chain_key
    session.recv_counter += 1
    return plaintext

# ----- DEMO of session management -----

def run_demo_session() -> dict:
    result = handshake.run_demo_handshake()
    alice = session_from_handshake(
        result["alice_session"],
        result["bob"].identity_sig.public_key,
    )
    bob = session_from_handshake(
        result["bob_session"],
        result["alice"].identity_sig.public_key,
    )

    alice_message = encrypt_message(alice, b"Hello Bob, this is Alice.")
    bob_plaintext = decrypt_message(bob, alice_message)

    bob_message = encrypt_message(bob, b"Hello Alice, Bob received your message.")
    alice_plaintext = decrypt_message(alice, bob_message)

    replay_error = None
    try:
        decrypt_message(bob, alice_message)
    except ValueError as exc:
        replay_error = str(exc)

    return {
        "alice_session": alice,
        "bob_session": bob,
        "alice_message": alice_message,
        "bob_plaintext": bob_plaintext,
        "bob_message": bob_message,
        "alice_plaintext": alice_plaintext,
        "replay_error": replay_error,
    }


if __name__ == "__main__":
    demo = run_demo_session()
    print("=" * 60)
    print("  QSMP Session Demo")
    print("=" * 60)
    print(f"Alice -> Bob decrypted : {demo['bob_plaintext']!r}")
    print(f"Bob -> Alice decrypted : {demo['alice_plaintext']!r}")
    print(f"Alice peer fingerprint : {demo['alice_session'].peer_identity_fingerprint[:32]}...")
    print(f"Bob peer fingerprint   : {demo['bob_session'].peer_identity_fingerprint[:32]}...")
    print(f"Alice send counter     : {demo['alice_session'].send_counter}")
    print(f"Alice recv counter     : {demo['alice_session'].recv_counter}")
    print(f"Bob send counter       : {demo['bob_session'].send_counter}")
    print(f"Bob recv counter       : {demo['bob_session'].recv_counter}")
    print(f"Replay rejected        : {demo['replay_error']}")
    print("=" * 60)
