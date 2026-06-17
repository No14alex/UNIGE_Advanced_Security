from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from crypto import dsa
from protocol import handshake, messages, ratchet, rest_server, session


"""Interactive end-to-end demonstration of the QSMP prototype over REST.

The demo follows the prototype as implemented:
- ML-DSA identity creation
- ML-KEM signed prekey publication
- bundle retrieval from the relay
- authenticated 1.5-RTT / 3-message handshake relayed through the server
- session construction
- AES-256-GCM protected message delivery through the relay
- replay rejection through counters
- post-quantum ratchet refresh
"""


DEFAULT_MESSAGE = "Bonjour Bob depuis le serveur REST."


def _sep(title: str = "") -> None:
    width = 78
    if title:
        pad = max(2, (width - len(title) - 2) // 2)
        print("\n" + "═" * pad + f" {title} " + "═" * pad)
    else:
        print("═" * width)


def _subsep(title: str = "") -> None:
    width = 78
    if title:
        pad = max(2, (width - len(title) - 2) // 2)
        print("\n" + "─" * pad + f" {title} " + "─" * pad)
    else:
        print("─" * width)


def _pause(enabled: bool, prompt: str = "Press Enter to continue...") -> None:
    if enabled:
        input(f"\n  ▶  {prompt} ")


def _trunc(value: str, limit: int = 64) -> str:
    return value if len(value) <= limit else value[:limit] + "…"


def _b64(data: bytes, limit: int = 64) -> str:
    return _trunc(rest_server.b64e(data), limit)


def _show(label: str, value: str) -> None:
    print(f"  {label:<34} {value}")


def _status_text(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def _print_check(label: str, ok: bool, detail: str | None = None) -> None:
    suffix = f"  {detail}" if detail else ""
    print(f"  [{_status_text(ok):^4}] {label}{suffix}")


def _record_check(results: dict[str, bool], label: str, ok: bool) -> None:
    results[label] = ok
    _print_check(label, ok)


def _show_capture(title: str, visible: dict[str, str], hidden: list[str]) -> None:
    _subsep(title)
    print("  What the relay / passive observer can see:")
    for key, value in visible.items():
        _show(key + ":", _trunc(value))
    print("\n  What remains hidden:")
    for item in hidden:
        print(f"  - {item}")


def _show_db_snapshot(db_path: Path, title: str) -> None:
    _subsep(title)
    if not db_path.exists():
        print(f"  Database not found at {db_path}")
        return

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        key_rows = conn.execute(
            """
            SELECT user_id, identity_public_key, signed_prekey_public_key, bundle_signature, updated_at
            FROM key_bundles
            ORDER BY user_id ASC
            """
        ).fetchall()
        msg_rows = conn.execute(
            """
            SELECT id, recipient_id, sender_id, payload_json, created_at
            FROM messages
            ORDER BY id ASC
            """
        ).fetchall()

    print(f"  Database path: {db_path}")
    print("  The relay database should contain only public bundles and opaque ciphertext payloads.")

    print("\n  key_bundles:")
    if not key_rows:
        print("  - <empty>")
    for row in key_rows:
        _show("user_id", row["user_id"])
        _show("identity_public_key", _b64(row["identity_public_key"]))
        _show("signed_prekey_public_key", _b64(row["signed_prekey_public_key"]))
        _show("bundle_signature", _b64(row["bundle_signature"]))
        _show("updated_at", row["updated_at"])
        print("  -")

    print("\n  messages:")
    if not msg_rows:
        print("  - <empty>")
    for row in msg_rows:
        payload = json.loads(row["payload_json"])
        _show("id", str(row["id"]))
        _show("recipient_id", row["recipient_id"])
        _show("sender_id", row["sender_id"])
        _show("created_at", row["created_at"])
        _show("payload.kind", str(payload.get("kind", "ENCRYPTED_MESSAGE")))
        payload_preview = _trunc(json.dumps(payload, sort_keys=True), 96)
        _show("payload_json", payload_preview)
        print("  -")


def auth_headers(identity: handshake.Identity, token: str = "demo-token") -> dict[str, str]:
    signature = dsa.sign(
        rest_server.build_auth_token_payload(identity.user_id, token),
        identity.identity_sig.secret_key,
    )
    return {
        "X-User-ID": identity.user_id,
        "X-Auth-Token": token,
        "X-Auth-Signature": rest_server.b64e(signature),
    }


def bundle_json(identity: handshake.Identity) -> dict[str, str]:
    bundle = handshake.export_prekey_bundle(identity)
    return {
        "identity_public_key": rest_server.b64e(bundle.identity_public_key),
        "signed_prekey_public_key": rest_server.b64e(bundle.signed_prekey_public_key),
        "bundle_signature": rest_server.b64e(bundle.bundle_signature),
    }


def bundle_from_json(data: dict[str, Any]) -> handshake.PreKeyBundle:
    return handshake.PreKeyBundle(
        user_id=data["user_id"],
        identity_public_key=rest_server.b64d(data["identity_public_key"]),
        signed_prekey_public_key=rest_server.b64d(data["signed_prekey_public_key"]),
        bundle_signature=rest_server.b64d(data["bundle_signature"]),
    )


def _handshake_init_to_payload(init: handshake.HandshakeInit) -> dict[str, Any]:
    return {
        "kind": "HANDSHAKE_INIT",
        "body": {
            "version": rest_server.b64e(init.version),
            "sender_id": init.sender_id,
            "receiver_id": init.receiver_id,
            "ephemeral_kem_public_key": rest_server.b64e(init.ephemeral_kem_public_key),
            "nonce": rest_server.b64e(init.nonce),
            "signature": rest_server.b64e(init.signature),
        },
    }


def _handshake_init_from_payload(payload: dict[str, Any]) -> handshake.HandshakeInit:
    body = payload["body"]
    return handshake.HandshakeInit(
        version=rest_server.b64d(body["version"]),
        sender_id=body["sender_id"],
        receiver_id=body["receiver_id"],
        ephemeral_kem_public_key=rest_server.b64d(body["ephemeral_kem_public_key"]),
        nonce=rest_server.b64d(body["nonce"]),
        signature=rest_server.b64d(body["signature"]),
    )


def _handshake_reply_to_payload(reply: handshake.HandshakeReply) -> dict[str, Any]:
    return {
        "kind": "HANDSHAKE_REPLY",
        "body": {
            "version": rest_server.b64e(reply.version),
            "sender_id": reply.sender_id,
            "receiver_id": reply.receiver_id,
            "ephemeral_kem_public_key": rest_server.b64e(reply.ephemeral_kem_public_key),
            "ciphertext_to_initiator": rest_server.b64e(reply.ciphertext_to_initiator),
            "nonce": rest_server.b64e(reply.nonce),
            "signature": rest_server.b64e(reply.signature),
        },
    }


def _handshake_reply_from_payload(payload: dict[str, Any]) -> handshake.HandshakeReply:
    body = payload["body"]
    return handshake.HandshakeReply(
        version=rest_server.b64d(body["version"]),
        sender_id=body["sender_id"],
        receiver_id=body["receiver_id"],
        ephemeral_kem_public_key=rest_server.b64d(body["ephemeral_kem_public_key"]),
        ciphertext_to_initiator=rest_server.b64d(body["ciphertext_to_initiator"]),
        nonce=rest_server.b64d(body["nonce"]),
        signature=rest_server.b64d(body["signature"]),
    )


def _handshake_finish_to_payload(finish: handshake.HandshakeFinish) -> dict[str, Any]:
    return {
        "kind": "HANDSHAKE_FINISH",
        "body": {
            "version": rest_server.b64e(finish.version),
            "session_id": rest_server.b64e(finish.session_id),
            "ciphertext_to_responder": rest_server.b64e(finish.ciphertext_to_responder),
        },
    }


def _handshake_finish_from_payload(payload: dict[str, Any]) -> handshake.HandshakeFinish:
    body = payload["body"]
    return handshake.HandshakeFinish(
        version=rest_server.b64d(body["version"]),
        session_id=rest_server.b64d(body["session_id"]),
        ciphertext_to_responder=rest_server.b64d(body["ciphertext_to_responder"]),
    )


def _ratchet_offer_to_payload(offer: ratchet.RatchetOffer) -> dict[str, Any]:
    return {
        "kind": "RATCHET_OFFER",
        "body": {
            "version": rest_server.b64e(offer.version),
            "session_id": rest_server.b64e(offer.session_id),
            "sender_id": offer.sender_id,
            "ratchet_counter": offer.ratchet_counter,
            "ephemeral_kem_public_key": rest_server.b64e(offer.ephemeral_kem_public_key),
            "signature": rest_server.b64e(offer.signature),
        },
    }


def _ratchet_offer_from_payload(payload: dict[str, Any]) -> ratchet.RatchetOffer:
    body = payload["body"]
    return ratchet.RatchetOffer(
        version=rest_server.b64d(body["version"]),
        session_id=rest_server.b64d(body["session_id"]),
        sender_id=body["sender_id"],
        ratchet_counter=body["ratchet_counter"],
        ephemeral_kem_public_key=rest_server.b64d(body["ephemeral_kem_public_key"]),
        signature=rest_server.b64d(body["signature"]),
    )


def _ratchet_reply_to_payload(reply: ratchet.RatchetReply) -> dict[str, Any]:
    return {
        "kind": "RATCHET_REPLY",
        "body": {
            "version": rest_server.b64e(reply.version),
            "session_id": rest_server.b64e(reply.session_id),
            "sender_id": reply.sender_id,
            "ratchet_counter": reply.ratchet_counter,
            "ciphertext": rest_server.b64e(reply.ciphertext),
            "signature": rest_server.b64e(reply.signature),
        },
    }


def _ratchet_reply_from_payload(payload: dict[str, Any]) -> ratchet.RatchetReply:
    body = payload["body"]
    return ratchet.RatchetReply(
        version=rest_server.b64d(body["version"]),
        session_id=rest_server.b64d(body["session_id"]),
        sender_id=body["sender_id"],
        ratchet_counter=body["ratchet_counter"],
        ciphertext=rest_server.b64d(body["ciphertext"]),
        signature=rest_server.b64d(body["signature"]),
    )


def _message_visibility_payload(msg: messages.EncryptedMessage) -> dict[str, str]:
    return {
        "message_type": "ENCRYPTED_MESSAGE",
        "header.version": msg.header.version,
        "header.session_id": _b64(msg.header.session_id),
        "header.sender_id": msg.header.sender_id,
        "header.counter": str(msg.header.counter),
        "header.ratchet_counter": str(msg.header.ratchet_counter),
        "header.previous_counter": str(msg.header.previous_counter),
        "nonce": _b64(msg.nonce),
        "ciphertext": _b64(msg.ciphertext),
    }


def _prompt_message(pause_enabled: bool, provided_message: str | None) -> str:
    if provided_message is not None:
        return provided_message
    if pause_enabled:
        user_msg = input(
            "\n  Enter the message Alice will send to Bob\n"
            f"  (leave blank for default: '{DEFAULT_MESSAGE}'): "
        ).strip()
        return user_msg or DEFAULT_MESSAGE
    return DEFAULT_MESSAGE


def run_http_demo(
    base_url: str,
    *,
    pause_enabled: bool = True,
    message_text: str | None = None,
    show_db: bool = False,
    db_path: Path | None = None,
) -> dict[str, Any]:
    import httpx

    db_path = db_path or rest_server.DEFAULT_DB_PATH
    checks: dict[str, bool] = {}

    _sep("QSMP REST Demo")
    print(f"\n  Relay server: {base_url}")
    print("\n  This demo shows the full research prototype:")
    print("    1. ML-DSA identity + ML-KEM signed prekey generation")
    print("    2. Bundle publication to the relay")
    print("    3. Bundle retrieval and authenticated 1.5-RTT handshake")
    print("    4. Session construction and AES-256-GCM encrypted messaging")
    print("    5. Replay rejection")
    print("    6. Post-quantum ratchet refresh")
    _pause(pause_enabled, "Ready? Press Enter to start")

    _sep("PHASE 1 — Key Generation")
    print("\n  Generating fresh ML-DSA identity keys and ML-KEM signed prekeys for Alice and Bob.")
    alice = handshake.create_identity("alice")
    bob = handshake.create_identity("bob")

    _show("Alice identity public key", _b64(alice.identity_sig.public_key))
    _show("Alice signed prekey public key", _b64(alice.signed_prekey.public_key))
    _show("Bob identity public key", _b64(bob.identity_sig.public_key))
    _show("Bob signed prekey public key", _b64(bob.signed_prekey.public_key))
    print("\n  Public values may be published or relayed. Private ML-DSA and ML-KEM keys remain local.")
    _pause(pause_enabled, "Phase 1 done")

    with httpx.Client(base_url=base_url, timeout=10.0) as http:
        _sep("PHASE 2 — Bundle Publication")
        print("\n  Each user signs a REST authentication token and publishes a signed prekey bundle.")
        print("  The relay verifies the HTTP token and the signed-prekey bundle before storing it.")

        http.post("/keys/alice", json=bundle_json(alice), headers=auth_headers(alice)).raise_for_status()
        http.post("/keys/bob", json=bundle_json(bob), headers=auth_headers(bob)).raise_for_status()
        print("  Bundle publication complete.")

        if show_db:
            _show_db_snapshot(db_path, "Sanitized Relay Database After Bundle Publication")

        alice_bundle = handshake.export_prekey_bundle(alice)
        bob_bundle = handshake.export_prekey_bundle(bob)
        _show_capture(
            "What the relay can see — published bundles",
            {
                "alice.user_id": alice_bundle.user_id,
                "alice.identity_public_key": _b64(alice_bundle.identity_public_key),
                "alice.signed_prekey_public_key": _b64(alice_bundle.signed_prekey_public_key),
                "alice.bundle_signature": _b64(alice_bundle.bundle_signature),
                "bob.user_id": bob_bundle.user_id,
                "bob.identity_public_key": _b64(bob_bundle.identity_public_key),
                "bob.signed_prekey_public_key": _b64(bob_bundle.signed_prekey_public_key),
                "bob.bundle_signature": _b64(bob_bundle.bundle_signature),
            },
            [
                "Alice ML-DSA private key",
                "Alice ML-KEM private key",
                "Bob ML-DSA private key",
                "Bob ML-KEM private key",
            ],
        )
        _pause(pause_enabled, "Phase 2 done")

        _sep("PHASE 3 — Bundle Retrieval")
        print("\n  Alice fetches Bob's signed prekey bundle from the relay.")
        print("  She can begin setup from Bob's stored bundle, but Bob must later come online")
        print("  to answer HANDSHAKE_INIT in the current authenticated 1.5-RTT flow.")

        bob_bundle_response = http.get("/keys/bob", headers=auth_headers(alice))
        bob_bundle_response.raise_for_status()
        bob_bundle = bundle_from_json(bob_bundle_response.json())
        _show("Bob identity public key", _b64(bob_bundle.identity_public_key))
        _show("Bob signed prekey public key", _b64(bob_bundle.signed_prekey_public_key))
        _show("Bob bundle signature", _b64(bob_bundle.bundle_signature))
        _pause(pause_enabled, "Phase 3 done")

        _sep("PHASE 4 — Authenticated 1.5-RTT Handshake")
        print("\n  Step 1: Alice verifies Bob's bundle, generates an ephemeral ML-KEM key pair,")
        print("  signs HANDSHAKE_INIT, and posts it to Bob's relay inbox.")
        alice_state, init = handshake.initiate_handshake(alice, bob_bundle)
        init_payload = _handshake_init_to_payload(init)
        http.post("/messages/bob", json={"payload": init_payload}, headers=auth_headers(alice)).raise_for_status()

        _show_capture(
            "What the relay can see — HANDSHAKE_INIT",
            {
                "message_type": "HANDSHAKE_INIT",
                "sender_id": init.sender_id,
                "receiver_id": init.receiver_id,
                "ephemeral_kem_public_key": _b64(init.ephemeral_kem_public_key),
                "nonce": _b64(init.nonce),
                "signature": _b64(init.signature),
            },
            [
                "Alice ephemeral ML-KEM private key",
                "ML-KEM shared secret contributions ss_A and ss_B",
                "root key",
                "chain keys",
            ],
        )

        print("\n  Step 2: Bob fetches HANDSHAKE_INIT, verifies Alice's signature, generates")
        print("  his own ephemeral ML-KEM key pair, encapsulates to Alice, signs the reply,")
        print("  and posts HANDSHAKE_REPLY to Alice's inbox.")
        bob_init_batch = http.get("/messages/bob", headers=auth_headers(bob))
        bob_init_batch.raise_for_status()
        init_from_relay = _handshake_init_from_payload(bob_init_batch.json()["messages"][0]["payload"])
        bob_state, reply = handshake.respond_handshake(bob, alice.identity_sig.public_key, init_from_relay)
        reply_payload = _handshake_reply_to_payload(reply)
        http.post("/messages/alice", json={"payload": reply_payload}, headers=auth_headers(bob)).raise_for_status()

        _show_capture(
            "What the relay can see — HANDSHAKE_REPLY",
            {
                "message_type": "HANDSHAKE_REPLY",
                "sender_id": reply.sender_id,
                "receiver_id": reply.receiver_id,
                "ephemeral_kem_public_key": _b64(reply.ephemeral_kem_public_key),
                "ciphertext_to_initiator": _b64(reply.ciphertext_to_initiator),
                "nonce": _b64(reply.nonce),
                "signature": _b64(reply.signature),
            },
            [
                "Bob ephemeral ML-KEM private key",
                "ML-KEM shared secret contributions ss_A and ss_B",
                "root key",
                "chain keys",
            ],
        )

        print("\n  Step 3: Alice fetches HANDSHAKE_REPLY, verifies Bob's signature, decapsulates")
        print("  Bob's ciphertext, encapsulates to Bob's fresh key, derives the session state,")
        print("  and posts HANDSHAKE_FINISH back to Bob.")
        alice_reply_batch = http.get("/messages/alice", headers=auth_headers(alice))
        alice_reply_batch.raise_for_status()
        reply_from_relay = _handshake_reply_from_payload(alice_reply_batch.json()["messages"][0]["payload"])
        finish, alice_handshake_session = handshake.finalize_initiator(alice_state, reply_from_relay)
        finish_payload = _handshake_finish_to_payload(finish)
        http.post("/messages/bob", json={"payload": finish_payload}, headers=auth_headers(alice)).raise_for_status()

        _show_capture(
            "What the relay can see — HANDSHAKE_FINISH",
            {
                "message_type": "HANDSHAKE_FINISH",
                "session_id": _b64(finish.session_id),
                "ciphertext_to_responder": _b64(finish.ciphertext_to_responder),
            },
            [
                "ML-KEM shared secret contributions ss_A and ss_B",
                "root key",
                "sending chain key",
                "receiving chain key",
            ],
        )

        print("\n  Bob fetches HANDSHAKE_FINISH and independently derives the same session state.")
        bob_finish_batch = http.get("/messages/bob", headers=auth_headers(bob))
        bob_finish_batch.raise_for_status()
        finish_from_relay = _handshake_finish_from_payload(bob_finish_batch.json()["messages"][0]["payload"])
        bob_handshake_session = handshake.finalize_responder(bob_state, finish_from_relay)

        _subsep("Handshake Consistency Checks")
        _record_check(checks, "Alice and Bob derive the same session_id", alice_handshake_session.session_id == bob_handshake_session.session_id)
        _record_check(checks, "Alice and Bob derive the same root_key", alice_handshake_session.root_key == bob_handshake_session.root_key)
        _record_check(checks, "Alice send_chain_key equals Bob receive_chain_key", alice_handshake_session.send_chain_key == bob_handshake_session.recv_chain_key)
        _record_check(checks, "Alice receive_chain_key equals Bob send_chain_key", alice_handshake_session.recv_chain_key == bob_handshake_session.send_chain_key)
        _pause(pause_enabled, "Phase 4 done")

        _sep("PHASE 5 — Session Construction")
        print("\n  The handshake output is wrapped into two MessagingSession objects.")
        print("  These hold the shared session_id, root_key, directional chain keys, peer")
        print("  identity fingerprint, and monotonic counters for replay protection.")

        alice_session = session.session_from_handshake(alice_handshake_session, bob.identity_sig.public_key)
        bob_session = session.session_from_handshake(bob_handshake_session, alice.identity_sig.public_key)
        _show("Alice session_id", _b64(alice_session.session_id))
        _show("Bob session_id", _b64(bob_session.session_id))
        _show("Alice peer fingerprint", alice_session.peer_identity_fingerprint[:32] + "…")
        _show("Bob peer fingerprint", bob_session.peer_identity_fingerprint[:32] + "…")
        _pause(pause_enabled, "Phase 5 done")

        _sep("PHASE 6 — Encrypted Messaging")
        message_text = _prompt_message(pause_enabled, message_text)
        plaintext_bytes = message_text.encode("utf-8")

        print("\n  Alice encrypts one application message with AES-256-GCM.")
        print("  The relay receives only the message header, nonce, and ciphertext.")
        encrypted = session.encrypt_message(alice_session, plaintext_bytes)
        enc_dict = encrypted.to_dict()
        http.post("/messages/bob", json={"payload": enc_dict}, headers=auth_headers(alice)).raise_for_status()

        if show_db:
            _show_db_snapshot(db_path, "Sanitized Relay Database After Encrypted Message Posting")

        _show_capture(
            "What the relay can see — encrypted application message",
            _message_visibility_payload(encrypted),
            [
                "ML-DSA private keys",
                "ML-KEM private keys",
                "ML-KEM shared secrets ss_A and ss_B",
                "root keys",
                "chain keys",
                "message AES key",
                "plaintext",
            ],
        )

        print("\n  Bob fetches his inbox and decrypts the message.")
        inbox_response = http.get("/messages/bob", headers=auth_headers(bob))
        inbox_response.raise_for_status()
        queued = inbox_response.json()["messages"]
        received = messages.EncryptedMessage.from_dict(queued[0]["payload"])
        plaintext = session.decrypt_message(bob_session, received)
        _record_check(checks, "Bob successfully decrypts Alice's message", plaintext == plaintext_bytes)
        _show("Recovered plaintext", plaintext.decode("utf-8"))
        _pause(pause_enabled, "Phase 6 done")

        _sep("PHASE 7 — Replay Protection Demonstration")
        print("\n  Replay attack simulated.")
        replay_error = None
        replay_ok = False
        try:
            session.decrypt_message(bob_session, received)
            replay_error = "unexpectedly accepted"
        except Exception as exc:  # noqa: BLE001 - demo should show the real rejection reason
            replay_error = str(exc)
            replay_ok = True

        print(f"  Replay rejected: {replay_error}")
        _record_check(checks, "Replayed ciphertext is rejected", replay_ok)
        _pause(pause_enabled, "Phase 7 done")

        _sep("PHASE 8 — Post-Quantum Ratchet Refresh")
        print("\n  Alice initiates a post-quantum ratchet refresh through the relay.")
        alice_root_before = alice_session.root_key
        bob_root_before = bob_session.root_key

        ratchet_state, offer = ratchet.initiate_ratchet(alice_session, alice)
        offer_payload = _ratchet_offer_to_payload(offer)
        http.post("/messages/bob", json={"payload": offer_payload}, headers=auth_headers(alice)).raise_for_status()

        _show_capture(
            "What the relay can see — RATCHET_OFFER",
            {
                "message_type": "RATCHET_OFFER",
                "session_id": _b64(offer.session_id),
                "sender_id": offer.sender_id,
                "ratchet_counter": str(offer.ratchet_counter),
                "ephemeral_kem_public_key": _b64(offer.ephemeral_kem_public_key),
                "signature": _b64(offer.signature),
            },
            [
                "ratchet shared secret",
                "old root key",
                "new root key",
                "new chain keys",
            ],
        )

        bob_offer_batch = http.get("/messages/bob", headers=auth_headers(bob))
        bob_offer_batch.raise_for_status()
        offer_from_relay = _ratchet_offer_from_payload(bob_offer_batch.json()["messages"][0]["payload"])
        ratchet_reply = ratchet.respond_ratchet(bob_session, bob, alice.identity_sig.public_key, offer_from_relay)
        ratchet_reply_payload = _ratchet_reply_to_payload(ratchet_reply)
        http.post("/messages/alice", json={"payload": ratchet_reply_payload}, headers=auth_headers(bob)).raise_for_status()

        _show_capture(
            "What the relay can see — RATCHET_REPLY",
            {
                "message_type": "RATCHET_REPLY",
                "session_id": _b64(ratchet_reply.session_id),
                "sender_id": ratchet_reply.sender_id,
                "ratchet_counter": str(ratchet_reply.ratchet_counter),
                "ciphertext": _b64(ratchet_reply.ciphertext),
                "signature": _b64(ratchet_reply.signature),
            },
            [
                "ratchet shared secret",
                "old root key",
                "new root key",
                "new chain keys",
            ],
        )

        alice_ratchet_batch = http.get("/messages/alice", headers=auth_headers(alice))
        alice_ratchet_batch.raise_for_status()
        ratchet_reply_from_relay = _ratchet_reply_from_payload(alice_ratchet_batch.json()["messages"][0]["payload"])
        ratchet.finalize_ratchet(alice_session, ratchet_state, ratchet_reply_from_relay, bob.identity_sig.public_key)

        _subsep("Ratchet Checks")
        _record_check(checks, "After ratchet refresh, old root_key != new root_key", alice_root_before != alice_session.root_key and bob_root_before != bob_session.root_key)
        _record_check(checks, "After ratchet refresh, Alice and Bob share the same new root_key", alice_session.root_key == bob_session.root_key)
        _record_check(checks, "After ratchet refresh, Alice send_chain_key equals Bob receive_chain_key", alice_session.send_chain_key == bob_session.recv_chain_key)
        _record_check(checks, "After ratchet refresh, Alice receive_chain_key equals Bob send_chain_key", alice_session.recv_chain_key == bob_session.send_chain_key)

        print("\n  Sending a second encrypted message after the ratchet refresh.")
        second_plaintext = b"Second message after post-quantum ratchet refresh."
        second_encrypted = session.encrypt_message(alice_session, second_plaintext)
        http.post("/messages/bob", json={"payload": second_encrypted.to_dict()}, headers=auth_headers(alice)).raise_for_status()
        bob_after_ratchet_batch = http.get("/messages/bob", headers=auth_headers(bob))
        bob_after_ratchet_batch.raise_for_status()
        second_received = messages.EncryptedMessage.from_dict(bob_after_ratchet_batch.json()["messages"][0]["payload"])
        second_decrypted = session.decrypt_message(bob_session, second_received)
        _record_check(checks, "After ratchet refresh, Bob successfully decrypts Alice's new message", second_decrypted == second_plaintext)
        _show("Recovered post-ratchet plaintext", second_decrypted.decode("utf-8"))

    _sep("FINAL SUMMARY")
    for label, ok in checks.items():
        _print_check(label, ok)

    overall_ok = all(checks.values()) if checks else False
    print(f"\n  Overall demo result: {_status_text(overall_ok)}")
    _sep()

    return {
        "checks": checks,
        "overall_ok": overall_ok,
        "plaintext": plaintext.decode("utf-8"),
        "post_ratchet_plaintext": second_decrypted.decode("utf-8"),
        "replay_error": replay_error,
        "session_id_b64": rest_server.b64e(alice_session.session_id),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QSMP REST client demo")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--message", default=None, help="Plaintext Alice should send to Bob.")
    parser.add_argument("--no-pause", action="store_true", help="Run without waiting for Enter between phases.")
    parser.add_argument("--show-db", action="store_true", help="Print a sanitized view of the relay SQLite database.")
    parser.add_argument(
        "--db-path",
        default=str(rest_server.DEFAULT_DB_PATH),
        help="Path to the relay SQLite database used for --show-db.",
    )
    args = parser.parse_args()

    result = run_http_demo(
        args.base_url,
        pause_enabled=not args.no_pause,
        message_text=args.message,
        show_db=args.show_db,
        db_path=Path(args.db_path),
    )

    print(f"\n  Session ID         : {_trunc(result['session_id_b64'])}")
    print(f"  First plaintext    : {result['plaintext']}")
    print(f"  Post-ratchet text  : {result['post_ratchet_plaintext']}")
    print(f"  Replay result      : {result['replay_error']}")
