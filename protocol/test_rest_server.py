from __future__ import annotations

from fastapi.testclient import TestClient

from crypto import dsa
from protocol import handshake, messages, rest_client_demo, rest_server, session


def _headers(identity: handshake.Identity, token: str = "test-token") -> dict[str, str]:
    signature = dsa.sign(
        rest_server.build_auth_token_payload(identity.user_id, token),
        identity.identity_sig.secret_key,
    )
    return {
        "X-User-ID": identity.user_id,
        "X-Auth-Token": token,
        "X-Auth-Signature": rest_server.b64e(signature),
    }


def _bundle_body(identity: handshake.Identity) -> dict[str, str]:
    bundle = handshake.export_prekey_bundle(identity)
    return {
        "identity_public_key": rest_server.b64e(bundle.identity_public_key),
        "signed_prekey_public_key": rest_server.b64e(bundle.signed_prekey_public_key),
        "bundle_signature": rest_server.b64e(bundle.bundle_signature),
    }


def _client(tmp_path):
    app = rest_server.create_app(tmp_path / "relay.sqlite3")
    return TestClient(app)


def test_publish_and_fetch_key_bundle(tmp_path) -> None:
    alice = handshake.create_identity("alice")
    bob = handshake.create_identity("bob")
    http = _client(tmp_path)

    assert http.post("/keys/alice", json=_bundle_body(alice), headers=_headers(alice)).status_code == 200
    assert http.post("/keys/bob", json=_bundle_body(bob), headers=_headers(bob)).status_code == 200

    response = http.get("/keys/bob", headers=_headers(alice))

    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == "bob"
    assert body["identity_public_key"] == _bundle_body(bob)["identity_public_key"]


def test_publish_rejects_invalid_mldsa_token(tmp_path) -> None:
    alice = handshake.create_identity("alice")
    http = _client(tmp_path)
    headers = _headers(alice)
    headers["X-Auth-Signature"] = rest_server.b64e(b"0" * len(dsa.sign(b"x", alice.identity_sig.secret_key)))

    response = http.post("/keys/alice", json=_bundle_body(alice), headers=headers)

    assert response.status_code == 401


def test_get_messages_requires_matching_user(tmp_path) -> None:
    alice = handshake.create_identity("alice")
    bob = handshake.create_identity("bob")
    http = _client(tmp_path)
    http.post("/keys/alice", json=_bundle_body(alice), headers=_headers(alice))
    http.post("/keys/bob", json=_bundle_body(bob), headers=_headers(bob))

    response = http.get("/messages/bob", headers=_headers(alice))

    assert response.status_code == 403


def test_queue_and_pop_opaque_encrypted_message(tmp_path) -> None:
    alice = handshake.create_identity("alice")
    bob = handshake.create_identity("bob")
    http = _client(tmp_path)
    http.post("/keys/alice", json=_bundle_body(alice), headers=_headers(alice))
    http.post("/keys/bob", json=_bundle_body(bob), headers=_headers(bob))

    demo = handshake.run_demo_handshake("alice", "bob")
    alice_session = session.session_from_handshake(
        demo["alice_session"],
        bob.identity_sig.public_key,
    )
    encrypted = session.encrypt_message(alice_session, b"opaque ciphertext for server")

    post_response = http.post(
        "/messages/bob",
        json={"payload": encrypted.to_dict()},
        headers=_headers(alice),
    )
    assert post_response.status_code == 200

    inbox_response = http.get("/messages/bob", headers=_headers(bob))
    assert inbox_response.status_code == 200
    queued = inbox_response.json()["messages"]
    assert len(queued) == 1
    assert queued[0]["sender_id"] == "alice"
    assert queued[0]["payload"] == encrypted.to_dict()

    second_fetch = http.get("/messages/bob", headers=_headers(bob))
    assert second_fetch.status_code == 200
    assert second_fetch.json()["messages"] == []


def test_payload_roundtrip_stays_decryptable_after_relay(tmp_path) -> None:
    alice = handshake.create_identity("alice")
    bob = handshake.create_identity("bob")
    http = _client(tmp_path)
    http.post("/keys/alice", json=_bundle_body(alice), headers=_headers(alice))
    http.post("/keys/bob", json=_bundle_body(bob), headers=_headers(bob))

    bob_bundle = handshake.export_prekey_bundle(bob)
    alice_state, init = handshake.initiate_handshake(alice, bob_bundle)
    bob_state, reply = handshake.respond_handshake(bob, alice.identity_sig.public_key, init)
    finish, alice_handshake_session = handshake.finalize_initiator(alice_state, reply)
    bob_handshake_session = handshake.finalize_responder(bob_state, finish)
    alice_session = session.session_from_handshake(
        alice_handshake_session,
        bob.identity_sig.public_key,
    )
    bob_session = session.session_from_handshake(
        bob_handshake_session,
        alice.identity_sig.public_key,
    )

    encrypted = session.encrypt_message(alice_session, b"hello through sqlite")
    http.post("/messages/bob", json={"payload": encrypted.to_dict()}, headers=_headers(alice))
    queued = http.get("/messages/bob", headers=_headers(bob)).json()["messages"][0]
    relayed_message = messages.EncryptedMessage.from_dict(queued["payload"])

    assert session.decrypt_message(bob_session, relayed_message) == b"hello through sqlite"


def test_handshake_messages_can_be_relayed_through_server(tmp_path) -> None:
    alice = handshake.create_identity("alice")
    bob = handshake.create_identity("bob")
    http = _client(tmp_path)
    http.post("/keys/alice", json=_bundle_body(alice), headers=_headers(alice))
    http.post("/keys/bob", json=_bundle_body(bob), headers=_headers(bob))

    bob_bundle = handshake.export_prekey_bundle(bob)
    alice_state, init = handshake.initiate_handshake(alice, bob_bundle)
    http.post(
        "/messages/bob",
        json={"payload": rest_client_demo._handshake_init_to_payload(init)},
        headers=_headers(alice),
    )

    queued_init = http.get("/messages/bob", headers=_headers(bob)).json()["messages"][0]["payload"]
    init_from_relay = rest_client_demo._handshake_init_from_payload(queued_init)
    bob_state, reply = handshake.respond_handshake(bob, alice.identity_sig.public_key, init_from_relay)
    http.post(
        "/messages/alice",
        json={"payload": rest_client_demo._handshake_reply_to_payload(reply)},
        headers=_headers(bob),
    )

    queued_reply = http.get("/messages/alice", headers=_headers(alice)).json()["messages"][0]["payload"]
    reply_from_relay = rest_client_demo._handshake_reply_from_payload(queued_reply)
    finish, alice_hs = handshake.finalize_initiator(alice_state, reply_from_relay)
    http.post(
        "/messages/bob",
        json={"payload": rest_client_demo._handshake_finish_to_payload(finish)},
        headers=_headers(alice),
    )

    queued_finish = http.get("/messages/bob", headers=_headers(bob)).json()["messages"][0]["payload"]
    finish_from_relay = rest_client_demo._handshake_finish_from_payload(queued_finish)
    bob_hs = handshake.finalize_responder(bob_state, finish_from_relay)

    assert alice_hs.session_id == bob_hs.session_id
    assert alice_hs.root_key == bob_hs.root_key
