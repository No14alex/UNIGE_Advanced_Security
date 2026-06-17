from __future__ import annotations

from protocol import mitm_simulation


def test_passive_mitm_only_sees_public_and_ciphertext_material() -> None:
    result = mitm_simulation.simulate_passive_mitm()

    init_capture = result["handshake_init_capture"]
    msg_capture = result["message_capture"]

    assert "ephemeral_kem_public_key_b64" in init_capture.visible_fields
    assert "ciphertext_b64" in msg_capture.visible_fields
    assert "plaintext" in msg_capture.hidden_fields
    assert result["same_session_id"] is True


def test_replay_attempt_is_rejected() -> None:
    replay = mitm_simulation.simulate_replay_attempt()

    assert replay["first_delivery"] == "Message capture for replay"
    assert "Compteur de reception inattendu" in replay["replay_result"]
