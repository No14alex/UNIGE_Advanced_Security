from __future__ import annotations

from protocol import client, server


def _make_clients() -> tuple[server.RelayServer, client.MessagingClient, client.MessagingClient]:
    relay = server.RelayServer()
    alice = client.MessagingClient("alice", relay)
    bob = client.MessagingClient("bob", relay)
    alice.register()
    bob.register()
    return relay, alice, bob


def _complete_handshake(alice: client.MessagingClient, bob: client.MessagingClient) -> None:
    alice.start_handshake("bob")
    bob.process_handshake_mailbox()
    alice.process_handshake_mailbox()
    bob.process_handshake_mailbox()


def test_server_registers_users_and_exposes_bundles() -> None:
    relay, alice, bob = _make_clients()

    assert relay.has_user("alice")
    assert relay.has_user("bob")
    assert relay.get_bundle("alice").user_id == "alice"
    assert relay.get_identity_public_key("bob") == bob.identity.identity_sig.public_key
    assert relay.stats()["users"] == 2
    assert alice.fetch_peer_bundle("bob").user_id == "bob"


def test_clients_establish_a_session_through_relay() -> None:
    _, alice, bob = _make_clients()
    _complete_handshake(alice, bob)

    assert alice.has_session("bob")
    assert bob.has_session("alice")
    assert alice.sessions["bob"].session_id == bob.sessions["alice"].session_id
    assert alice.sessions["bob"].peer_user_id == "bob"
    assert bob.sessions["alice"].peer_user_id == "alice"


def test_clients_exchange_protected_messages() -> None:
    relay, alice, bob = _make_clients()
    _complete_handshake(alice, bob)

    alice.send_text("bob", "bonjour bob")
    bob.send_text("alice", "bonjour alice")

    bob_messages = bob.receive_messages()
    alice_messages = alice.receive_messages()

    assert [m.plaintext for m in bob_messages] == ["bonjour bob"]
    assert [m.plaintext for m in alice_messages] == ["bonjour alice"]
    assert relay.stats()["messages"] == 0


def test_send_requires_an_active_session() -> None:
    _, alice, _ = _make_clients()

    try:
        alice.send_text("bob", "not yet")
    except ValueError as exc:
        assert "Aucune session active" in str(exc)
    else:
        raise AssertionError("Expected a ValueError when sending without a session")
