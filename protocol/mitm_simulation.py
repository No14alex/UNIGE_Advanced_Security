from __future__ import annotations
import base64
from dataclasses import dataclass
from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from crypto import dsa
from protocol import handshake, session


AUTH_CONTEXT = b"QSMP-REST-AUTH-1"

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _build_auth_headers(identity: handshake.Identity, token: str = "demo-token") -> dict[str, str]:
    # This reproduces the relay's signed-header authentication without importing
    # FastAPI/Pydantic code. That keeps the MITM simulation runnable in the core
    # crypto environment.
    payload = b"|".join([AUTH_CONTEXT, identity.user_id.encode("utf-8"), token.encode("utf-8")])
    signature = dsa.sign(payload, identity.identity_sig.secret_key)
    return {
        "X-User-ID": identity.user_id,
        "X-Auth-Token": token,
        "X-Auth-Signature": _b64e(signature),
    }


@dataclass
class MITMCapture:
    """
    Snapshot of what a man-in-the-middle can observe on the wire

    The point of this dataclass is not to hold secrets. It holds only what an
    attacker can capture from network traffic or from the relay API. 
    """

    description: str
    visible_fields: dict[str, str]
    hidden_fields: list[str]


def simulate_passive_mitm() -> dict:
    """
    Simulate a passive attacker that can record all traffic but cannot alter it.
    """

    alice = handshake.create_identity("alice")
    bob = handshake.create_identity("bob")

    # The attacker can see bundles when they are published to the relay.
    # These values are public by design.
    alice_bundle = handshake.export_prekey_bundle(alice)
    bob_bundle = handshake.export_prekey_bundle(bob)

    # The attacker can record the online handshake traffic.
    alice_state, init = handshake.initiate_handshake(alice, bob_bundle)
    bob_state, reply = handshake.respond_handshake(bob, alice.identity_sig.public_key, init)
    finish, alice_hs_session = handshake.finalize_initiator(alice_state, reply)
    bob_hs_session = handshake.finalize_responder(bob_state, finish)

    # After the handshake, Alice and Bob locally derive the message session.
    alice_session = session.session_from_handshake(
        alice_hs_session,
        bob.identity_sig.public_key,
    )
    bob_session = session.session_from_handshake(
        bob_hs_session,
        alice.identity_sig.public_key,
    )

    # The attacker can record the encrypted message and its metadata.
    message = session.encrypt_message(alice_session, b"Bonjour Bob, ceci reste chiffre.")
    recovered = session.decrypt_message(bob_session, message)

    # The attacker can also see the REST relay headers.
    # This is important because the current token model is replayable if a
    # signed header set is captured.
    alice_headers = _build_auth_headers(alice, token="demo-token")

    return {
        "bundle_capture": MITMCapture(
            description="Bundles published to the relay",
            visible_fields={
                "alice_user_id": alice_bundle.user_id,
                "alice_identity_public_key_b64": _b64e(alice_bundle.identity_public_key),
                "alice_signed_prekey_public_key_b64": _b64e(alice_bundle.signed_prekey_public_key),
                "alice_bundle_signature_b64": _b64e(alice_bundle.bundle_signature),
                "bob_user_id": bob_bundle.user_id,
                "bob_identity_public_key_b64": _b64e(bob_bundle.identity_public_key),
                "bob_signed_prekey_public_key_b64": _b64e(bob_bundle.signed_prekey_public_key),
                "bob_bundle_signature_b64": _b64e(bob_bundle.bundle_signature),
            },
            hidden_fields=[
                "alice ML-DSA secret key",
                "alice ML-KEM secret key",
                "bob ML-DSA secret key",
                "bob ML-KEM secret key",
            ],
        ),
        "handshake_init_capture": MITMCapture(
            description="Captured HANDSHAKE_INIT",
            visible_fields={
                "sender_id": init.sender_id,
                "receiver_id": init.receiver_id,
                "ephemeral_kem_public_key_b64": _b64e(init.ephemeral_kem_public_key),
                "nonce_b64": _b64e(init.nonce),
                "signature_b64": _b64e(init.signature),
            },
            hidden_fields=[
                "Alice ephemeral secret key",
                "shared secret derived later",
            ],
        ),
        "handshake_reply_capture": MITMCapture(
            description="Captured HANDSHAKE_REPLY",
            visible_fields={
                "sender_id": reply.sender_id,
                "receiver_id": reply.receiver_id,
                "ephemeral_kem_public_key_b64": _b64e(reply.ephemeral_kem_public_key),
                "ciphertext_to_initiator_b64": _b64e(reply.ciphertext_to_initiator),
                "nonce_b64": _b64e(reply.nonce),
                "signature_b64": _b64e(reply.signature),
            },
            hidden_fields=[
                "Bob ephemeral secret key",
                "Bob shared secret contribution",
            ],
        ),
        "handshake_finish_capture": MITMCapture(
            description="Captured HANDSHAKE_FINISH",
            visible_fields={
                "session_id_b64": _b64e(finish.session_id),
                "ciphertext_to_responder_b64": _b64e(finish.ciphertext_to_responder),
            },
            hidden_fields=[
                "root_key",
                "send_chain_key",
                "recv_chain_key",
            ],
        ),
        "message_capture": MITMCapture(
            description="Captured encrypted application message",
            visible_fields={
                "session_id_b64": _b64e(message.header.session_id),
                "sender_id": message.header.sender_id,
                "counter": str(message.header.counter),
                "ratchet_counter": str(message.header.ratchet_counter),
                "nonce_b64": _b64e(message.nonce),
                "ciphertext_b64": _b64e(message.ciphertext),
            },
            hidden_fields=[
                "plaintext",
                "message AES key",
                "current send/receive chain keys",
            ],
        ),
        "rest_auth_capture": MITMCapture(
            description="Captured REST relay authentication headers",
            visible_fields=alice_headers,
            hidden_fields=[
                "Alice ML-DSA secret key",
            ],
        ),
        "same_session_id": alice_session.session_id == bob_session.session_id,
        "message_decrypted_by_bob": recovered.decode("utf-8"),
    }


def simulate_replay_attempt() -> dict:
    """
    Simulate an active attacker replaying a previously captured encrypted message.

    This demonstrates the current anti-replay behavior of the session layer:
    the receiver expects the next exact counter and rejects the replay.
    """

    hs = handshake.run_demo_handshake()
    alice_session = session.session_from_handshake(
        hs["alice_session"],
        hs["bob"].identity_sig.public_key,
    )
    bob_session = session.session_from_handshake(
        hs["bob_session"],
        hs["alice"].identity_sig.public_key,
    ) 

    captured_message = session.encrypt_message(alice_session, b"Message capture for replay")
    first_delivery = session.decrypt_message(bob_session, captured_message) #bob decrypts the first message 

    try:
        # The MITM replays the exact same ciphertext after Bob already accepted it.
        session.decrypt_message(bob_session, captured_message) #incompatibility in session id should be 1 for next but is 0
        replay_result = "unexpectedly accepted"
    except ValueError as exc:
        replay_result = str(exc)

    return {
        "captured_counter": captured_message.header.counter,
        "first_delivery": first_delivery.decode("utf-8"),
        "replay_result": replay_result,
    }


def run_demo_mitm() -> dict:
    passive = simulate_passive_mitm()
    replay = simulate_replay_attempt()
    return {
        "passive": passive,
        "replay": replay,
    }


if __name__ == "__main__":
    demo = run_demo_mitm()

    print("=" * 66)
    print("  QSMP MITM Simulation")
    print("=" * 66)

    print("\n[1] Passive attacker view: handshake init")
    for key, value in demo["passive"]["handshake_init_capture"].visible_fields.items():
        shown = value if len(value) < 72 else value[:72] + "..."
        print(f"  {key:<32} {shown}")

    print("\n[2] Passive attacker view: encrypted message")
    for key, value in demo["passive"]["message_capture"].visible_fields.items():
        shown = value if len(value) < 72 else value[:72] + "..."
        print(f"  {key:<32} {shown}")

    print("\n[3] Hidden from the attacker")
    for item in demo["passive"]["message_capture"].hidden_fields:
        print(f"  - {item}")

    print("\n[4] Replay attempt result")
    print(f"  first delivery                {demo['replay']['first_delivery']}")
    print(f"  replay result                 {demo['replay']['replay_result']}")

    print("\n[5] REST relay auth capture")
    print("  The attacker can also record the signed REST headers,")
    print("  which matters because the current token format is replayable.")
    print("=" * 66)
