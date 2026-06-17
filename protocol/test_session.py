from cryptography.exceptions import InvalidTag
import pytest

from protocol import handshake, messages, session


@pytest.fixture
def paired_sessions():
    result = handshake.run_demo_handshake()
    alice = session.session_from_handshake(
        result["alice_session"],
        result["bob"].identity_sig.public_key,
    )
    bob = session.session_from_handshake(
        result["bob_session"],
        result["alice"].identity_sig.public_key,
    )
    return alice, bob


class TestMessageSerialization:
    def test_encrypted_message_roundtrip_json(self, paired_sessions):
        alice, _ = paired_sessions
        message = session.encrypt_message(alice, b"hello")
        restored = messages.EncryptedMessage.from_json(message.to_json())
        assert restored.header.session_id == message.header.session_id
        assert restored.header.sender_id == message.header.sender_id
        assert restored.header.counter == message.header.counter
        assert restored.nonce == message.nonce
        assert restored.ciphertext == message.ciphertext

    def test_header_aad_is_deterministic(self, paired_sessions):
        alice, _ = paired_sessions
        header = session.encrypt_message(alice, b"hello").header
        assert header.aad_bytes() == header.aad_bytes()


class TestSessionMessaging:
    def test_peer_identity_fingerprint_is_stored(self, paired_sessions):
        alice, bob = paired_sessions
        assert len(alice.peer_identity_fingerprint) == 64
        assert len(bob.peer_identity_fingerprint) == 64
        assert alice.peer_identity_fingerprint != bob.peer_identity_fingerprint

    def test_alice_to_bob_message_roundtrip(self, paired_sessions):
        alice, bob = paired_sessions
        encrypted = session.encrypt_message(alice, b"hello bob")
        plaintext = session.decrypt_message(bob, encrypted)
        assert plaintext == b"hello bob"

    def test_bidirectional_exchange(self, paired_sessions):
        alice, bob = paired_sessions
        first = session.encrypt_message(alice, b"m1")
        assert session.decrypt_message(bob, first) == b"m1"
        second = session.encrypt_message(bob, b"m2")
        assert session.decrypt_message(alice, second) == b"m2"

    def test_counters_advance_after_send_and_receive(self, paired_sessions):
        alice, bob = paired_sessions
        encrypted = session.encrypt_message(alice, b"hello")
        assert alice.send_counter == 1
        assert bob.recv_counter == 0
        session.decrypt_message(bob, encrypted)
        assert bob.recv_counter == 1

    def test_tampered_ciphertext_is_rejected(self, paired_sessions):
        alice, bob = paired_sessions
        encrypted = session.encrypt_message(alice, b"hello")
        tampered = messages.EncryptedMessage(
            header=encrypted.header,
            nonce=encrypted.nonce,
            ciphertext=bytes([encrypted.ciphertext[0] ^ 0xFF]) + encrypted.ciphertext[1:],
        )
        with pytest.raises(InvalidTag):
            session.decrypt_message(bob, tampered)

    def test_wrong_session_id_is_rejected(self, paired_sessions):
        alice, bob = paired_sessions
        encrypted = session.encrypt_message(alice, b"hello")
        bad_header = messages.MessageHeader(
            version=encrypted.header.version,
            session_id=b"\x00" * len(encrypted.header.session_id),
            sender_id=encrypted.header.sender_id,
            counter=encrypted.header.counter,
            ratchet_counter=encrypted.header.ratchet_counter,
            previous_counter=encrypted.header.previous_counter,
            flags=encrypted.header.flags,
        )
        bad_message = messages.EncryptedMessage(
            header=bad_header,
            nonce=encrypted.nonce,
            ciphertext=encrypted.ciphertext,
        )
        with pytest.raises(ValueError, match="Session ID invalide"):
            session.decrypt_message(bob, bad_message)

    def test_wrong_sender_is_rejected(self, paired_sessions):
        alice, bob = paired_sessions
        encrypted = session.encrypt_message(alice, b"hello")
        bad_header = messages.MessageHeader(
            version=encrypted.header.version,
            session_id=encrypted.header.session_id,
            sender_id="mallory",
            counter=encrypted.header.counter,
            ratchet_counter=encrypted.header.ratchet_counter,
            previous_counter=encrypted.header.previous_counter,
            flags=encrypted.header.flags,
        )
        bad_message = messages.EncryptedMessage(
            header=bad_header,
            nonce=encrypted.nonce,
            ciphertext=encrypted.ciphertext,
        )
        with pytest.raises(ValueError, match="Expediteur inattendu"):
            session.decrypt_message(bob, bad_message)

    def test_replay_is_rejected_by_counter_check(self, paired_sessions):
        alice, bob = paired_sessions
        encrypted = session.encrypt_message(alice, b"hello")
        assert session.decrypt_message(bob, encrypted) == b"hello"
        with pytest.raises(ValueError, match="Compteur de reception inattendu"):
            session.decrypt_message(bob, encrypted)
