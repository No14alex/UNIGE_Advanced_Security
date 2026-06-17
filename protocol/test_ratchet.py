from dataclasses import replace

import pytest

from protocol import handshake, ratchet, session


@pytest.fixture
def ratchet_context():
    hs = handshake.run_demo_handshake()
    alice = session.session_from_handshake(hs["alice_session"], hs["bob"].identity_sig.public_key)
    bob = session.session_from_handshake(hs["bob_session"], hs["alice"].identity_sig.public_key)
    return hs, alice, bob


class TestRatchetFlow:
    def test_ratchet_changes_root_key_and_synchronizes_both_sides(self, ratchet_context):
        hs, alice, bob = ratchet_context
        alice_root_before = alice.root_key
        bob_root_before = bob.root_key

        state, offer = ratchet.initiate_ratchet(alice, hs["alice"])
        reply = ratchet.respond_ratchet(bob, hs["bob"], hs["alice"].identity_sig.public_key, offer)
        ratchet.finalize_ratchet(alice, state, reply, hs["bob"].identity_sig.public_key)

        assert alice.root_key != alice_root_before
        assert bob.root_key != bob_root_before
        assert alice.root_key == bob.root_key
        assert alice.send_chain_key == bob.recv_chain_key
        assert alice.recv_chain_key == bob.send_chain_key

    def test_ratchet_resets_message_counters(self, ratchet_context):
        hs, alice, bob = ratchet_context
        session.decrypt_message(bob, session.encrypt_message(alice, b"before"))
        assert alice.send_counter == 1
        assert bob.recv_counter == 1

        state, offer = ratchet.initiate_ratchet(alice, hs["alice"])
        reply = ratchet.respond_ratchet(bob, hs["bob"], hs["alice"].identity_sig.public_key, offer)
        ratchet.finalize_ratchet(alice, state, reply, hs["bob"].identity_sig.public_key)

        assert alice.send_counter == 0
        assert alice.recv_counter == 0
        assert bob.send_counter == 0
        assert bob.recv_counter == 0
        assert alice.ratchet_counter == 1
        assert bob.ratchet_counter == 1

    def test_post_ratchet_message_exchange_works(self, ratchet_context):
        hs, alice, bob = ratchet_context
        state, offer = ratchet.initiate_ratchet(alice, hs["alice"])
        reply = ratchet.respond_ratchet(bob, hs["bob"], hs["alice"].identity_sig.public_key, offer)
        ratchet.finalize_ratchet(alice, state, reply, hs["bob"].identity_sig.public_key)

        encrypted = session.encrypt_message(alice, b"after ratchet")
        recovered = session.decrypt_message(bob, encrypted)
        assert recovered == b"after ratchet"

    def test_tampered_offer_signature_is_rejected(self, ratchet_context):
        hs, alice, bob = ratchet_context
        _, offer = ratchet.initiate_ratchet(alice, hs["alice"])
        bad_signature = bytes([offer.signature[0] ^ 0xFF]) + offer.signature[1:]
        tampered_offer = replace(offer, signature=bad_signature)
        with pytest.raises(ValueError, match="RatchetOffer"):
            ratchet.respond_ratchet(bob, hs["bob"], hs["alice"].identity_sig.public_key, tampered_offer)

    def test_tampered_reply_signature_is_rejected(self, ratchet_context):
        hs, alice, bob = ratchet_context
        state, offer = ratchet.initiate_ratchet(alice, hs["alice"])
        reply = ratchet.respond_ratchet(bob, hs["bob"], hs["alice"].identity_sig.public_key, offer)
        bad_signature = bytes([reply.signature[0] ^ 0xFF]) + reply.signature[1:]
        tampered_reply = replace(reply, signature=bad_signature)
        with pytest.raises(ValueError, match="RatchetReply"):
            ratchet.finalize_ratchet(alice, state, tampered_reply, hs["bob"].identity_sig.public_key)
