from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
import statistics
import sys
import time

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from crypto import dsa, kem
from protocol import handshake


"""
Comparative metrics for the report.

Goal:
- show the difference between a classical profile and the post-quantum profile
- quantify the cost in sizes and timings
- make the trade-off explicit for the final discussion

Profiles compared:
- Classical   : X25519 + Ed25519
- Post-quantum: ML-KEM-768 + ML-DSA-65


benchmark focuses on the public-key cost of handshake/authentication
"""


BENCH_ITERATIONS = 100
NONCE_SIZE = 32
SESSION_ID_SIZE = 32
USER_ID_EXAMPLE = ("alice", "bob")
DEFAULT_OUTPUT_JSON = Path(__file__).resolve().parents[1] / "security_report" / "benchmark_results.json"


@dataclass
class PrimitiveMetrics:
    profile: str
    kem_public_key_bytes: int
    kem_secret_key_bytes: int
    kem_ciphertext_bytes: int
    signature_public_key_bytes: int
    signature_secret_key_bytes: int
    signature_bytes: int


@dataclass
class TimingMetrics:
    profile: str
    keygen_ms: float
    encaps_or_exchange_ms: float
    decaps_or_exchange_ms: float
    sign_ms: float
    verify_ms: float
    full_handshake_ms: float


@dataclass
class HandshakeSizeMetrics:
    profile: str
    init_bytes: int
    reply_bytes: int
    finish_bytes: int
    total_bytes: int


def _avg_ms(samples: list[float]) -> float:
    return statistics.mean(samples) * 1000.0


def _len_prefixed_size(*parts: bytes) -> int:
    # Matches the style used by the protocol when fields are transcript-bound:
    # every part is length-prefixed on 4 bytes.
    return sum(4 + len(part) for part in parts)


def _measure(fn, iterations: int = BENCH_ITERATIONS) -> float:
    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return _avg_ms(samples)


def classical_primitive_metrics() -> PrimitiveMetrics:
    # X25519 and Ed25519 have fixed key/signature sizes.
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub = x_priv.public_key()
    e_priv = ed25519.Ed25519PrivateKey.generate()
    e_pub = e_priv.public_key()
    sig = e_priv.sign(b"benchmark")

    return PrimitiveMetrics(
        profile="classical",
        kem_public_key_bytes=len(x_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)),
        kem_secret_key_bytes=len(x_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        kem_ciphertext_bytes=0,  # DH has no ciphertext object; both sides exchange public keys
        signature_public_key_bytes=len(e_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)),
        signature_secret_key_bytes=len(e_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        signature_bytes=len(sig),
    )


def pq_primitive_metrics() -> PrimitiveMetrics:
    kem_info = kem.kem_info()
    dsa_info = dsa.dsa_info()
    return PrimitiveMetrics(
        profile="post-quantum",
        kem_public_key_bytes=kem_info["public_key_bytes"],
        kem_secret_key_bytes=kem_info["secret_key_bytes"],
        kem_ciphertext_bytes=kem_info["ciphertext_bytes"],
        signature_public_key_bytes=dsa_info["public_key_bytes"],
        signature_secret_key_bytes=dsa_info["secret_key_bytes"],
        signature_bytes=dsa_info["signature_bytes"],
    )


def benchmark_classical_timings() -> TimingMetrics:
    message = b"authenticated transcript benchmark"

    def do_keygen():
        x25519.X25519PrivateKey.generate()
        ed25519.Ed25519PrivateKey.generate()

    def do_exchange():
        alice = x25519.X25519PrivateKey.generate()
        bob = x25519.X25519PrivateKey.generate()
        alice.exchange(bob.public_key())

    def do_exchange_peer():
        alice = x25519.X25519PrivateKey.generate()
        bob = x25519.X25519PrivateKey.generate()
        bob.exchange(alice.public_key())

    def do_sign():
        sk = ed25519.Ed25519PrivateKey.generate()
        sk.sign(message)

    def do_verify():
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        sig = sk.sign(message)
        pk.verify(sig, message)

    def do_full_handshake():
        # Classical analogue of the implemented 1.5-RTT authenticated handshake:
        # Alice and Bob each contribute fresh X25519 ephemeral keys and authenticate
        # the transcript with Ed25519.
        alice_eph = x25519.X25519PrivateKey.generate()
        bob_eph = x25519.X25519PrivateKey.generate()

        alice_sig_sk = ed25519.Ed25519PrivateKey.generate()
        bob_sig_sk = ed25519.Ed25519PrivateKey.generate()

        alice_init = b"|".join([
            b"QSMP-1",
            b"alice",
            b"bob",
            alice_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            b"\x00" * NONCE_SIZE,
        ])
        init_sig = alice_sig_sk.sign(alice_init)
        alice_sig_sk.public_key().verify(init_sig, alice_init)

        bob_reply = b"|".join([
            b"QSMP-1",
            b"bob",
            b"alice",
            bob_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            b"\x00" * NONCE_SIZE,
        ])
        reply_sig = bob_sig_sk.sign(bob_reply)
        bob_sig_sk.public_key().verify(reply_sig, bob_reply)

        ss_ab = alice_eph.exchange(bob_eph.public_key())
        ss_ba = bob_eph.exchange(alice_eph.public_key())
        assert ss_ab == ss_ba

    return TimingMetrics(
        profile="classical",
        keygen_ms=_measure(do_keygen),
        encaps_or_exchange_ms=_measure(do_exchange),
        decaps_or_exchange_ms=_measure(do_exchange_peer),
        sign_ms=_measure(do_sign),
        verify_ms=_measure(do_verify),
        full_handshake_ms=_measure(do_full_handshake),
    )


def benchmark_pq_timings() -> TimingMetrics:
    message = b"authenticated transcript benchmark"

    def do_keygen():
        kem.generate_keypair()
        dsa.generate_keypair()

    def do_encaps():
        keypair = kem.generate_keypair()
        kem.encapsulate(keypair.public_key)

    def do_decaps():
        keypair = kem.generate_keypair()
        enc = kem.encapsulate(keypair.public_key)
        kem.decapsulate(keypair.secret_key, enc.ciphertext)

    def do_sign():
        sk = dsa.generate_keypair()
        dsa.sign(message, sk.secret_key)

    def do_verify():
        sk = dsa.generate_keypair()
        sig = dsa.sign(message, sk.secret_key)
        dsa.verify(message, sig, sk.public_key)

    def do_full_handshake():
        handshake.run_demo_handshake(*USER_ID_EXAMPLE)

    return TimingMetrics(
        profile="post-quantum",
        keygen_ms=_measure(do_keygen),
        encaps_or_exchange_ms=_measure(do_encaps),
        decaps_or_exchange_ms=_measure(do_decaps),
        sign_ms=_measure(do_sign),
        verify_ms=_measure(do_verify),
        full_handshake_ms=_measure(do_full_handshake),
    )


def classical_handshake_sizes() -> HandshakeSizeMetrics:
    # Classical analogue of the same online authenticated handshake structure.
    # Difference: X25519 has no ciphertext object, so the finish message is tiny.
    primitives = classical_primitive_metrics()
    sender_id, receiver_id = USER_ID_EXAMPLE

    init_bytes = _len_prefixed_size(
        b"QSMP-1",
        sender_id.encode(),
        receiver_id.encode(),
        b"\x00" * primitives.kem_public_key_bytes,
        b"\x00" * NONCE_SIZE,
        b"\x00" * primitives.signature_bytes,
    )
    reply_bytes = _len_prefixed_size(
        b"QSMP-1",
        receiver_id.encode(),
        sender_id.encode(),
        b"\x00" * primitives.kem_public_key_bytes,
        b"\x00" * NONCE_SIZE,
        b"\x00" * primitives.signature_bytes,
    )
    finish_bytes = _len_prefixed_size(
        b"QSMP-1",
        b"\x00" * SESSION_ID_SIZE,
    )

    return HandshakeSizeMetrics(
        profile="classical",
        init_bytes=init_bytes,
        reply_bytes=reply_bytes,
        finish_bytes=finish_bytes,
        total_bytes=init_bytes + reply_bytes + finish_bytes,
    )


def pq_handshake_sizes() -> HandshakeSizeMetrics:
    # Use the real protocol packet field sizes from the implemented 1.5-RTT flow.
    demo = handshake.run_demo_handshake(*USER_ID_EXAMPLE)
    init = demo["init"]
    reply = demo["reply"]
    finish = demo["finish"]

    init_bytes = _len_prefixed_size(
        init.version,
        init.sender_id.encode(),
        init.receiver_id.encode(),
        init.ephemeral_kem_public_key,
        init.nonce,
        init.signature,
    )
    reply_bytes = _len_prefixed_size(
        reply.version,
        reply.sender_id.encode(),
        reply.receiver_id.encode(),
        reply.ephemeral_kem_public_key,
        reply.ciphertext_to_initiator,
        reply.nonce,
        reply.signature,
    )
    finish_bytes = _len_prefixed_size(
        finish.version,
        finish.session_id,
        finish.ciphertext_to_responder,
    )

    return HandshakeSizeMetrics(
        profile="post-quantum",
        init_bytes=init_bytes,
        reply_bytes=reply_bytes,
        finish_bytes=finish_bytes,
        total_bytes=init_bytes + reply_bytes + finish_bytes,
    )


def run_benchmark_report() -> dict:
    classical_primitives = classical_primitive_metrics()
    pq_primitives = pq_primitive_metrics()

    classical_timing = benchmark_classical_timings()
    pq_timing = benchmark_pq_timings()

    classical_handshake = classical_handshake_sizes()
    pq_handshake = pq_handshake_sizes()

    return {
        "iterations": BENCH_ITERATIONS,
        "classical_primitives": classical_primitives,
        "pq_primitives": pq_primitives,
        "classical_timing": classical_timing,
        "pq_timing": pq_timing,
        "classical_handshake": classical_handshake,
        "pq_handshake": pq_handshake,
    }


def _to_dict(report: dict) -> dict:
    return {
        key: (
            value.__dict__
            if hasattr(value, "__dict__")
            else value
        )
        for key, value in report.items()
    }


def export_report_json(report: dict, output_path: Path = DEFAULT_OUTPUT_JSON) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(_to_dict(report), indent=2))
    return output_path


def _print_primitive_table(classical: PrimitiveMetrics, pq: PrimitiveMetrics) -> None:
    print("\n[1] Key and signature sizes")
    print("  profile         kem_pk  kem_sk  kem_ct  sig_pk  sig_sk  signature")
    print(
        f"  classical       {classical.kem_public_key_bytes:6d}  {classical.kem_secret_key_bytes:6d}  "
        f"{classical.kem_ciphertext_bytes:6d}  {classical.signature_public_key_bytes:6d}  "
        f"{classical.signature_secret_key_bytes:6d}  {classical.signature_bytes:9d}"
    )
    print(
        f"  post-quantum    {pq.kem_public_key_bytes:6d}  {pq.kem_secret_key_bytes:6d}  "
        f"{pq.kem_ciphertext_bytes:6d}  {pq.signature_public_key_bytes:6d}  "
        f"{pq.signature_secret_key_bytes:6d}  {pq.signature_bytes:9d}"
    )


def _print_timing_table(classical: TimingMetrics, pq: TimingMetrics) -> None:
    print("\n[2] Average cryptographic timings (ms)")
    print("  profile         keygen   exchange/encap   decap/peer-exch   sign    verify   handshake")
    print(
        f"  classical       {classical.keygen_ms:7.3f}   {classical.encaps_or_exchange_ms:14.3f}   "
        f"{classical.decaps_or_exchange_ms:15.3f}   {classical.sign_ms:6.3f}   {classical.verify_ms:6.3f}   "
        f"{classical.full_handshake_ms:9.3f}"
    )
    print(
        f"  post-quantum    {pq.keygen_ms:7.3f}   {pq.encaps_or_exchange_ms:14.3f}   "
        f"{pq.decaps_or_exchange_ms:15.3f}   {pq.sign_ms:6.3f}   {pq.verify_ms:6.3f}   "
        f"{pq.full_handshake_ms:9.3f}"
    )


def _print_handshake_table(classical: HandshakeSizeMetrics, pq: HandshakeSizeMetrics) -> None:
    print("\n[3] Estimated authenticated handshake payload sizes (bytes)")
    print("  profile         init    reply   finish   total")
    print(
        f"  classical       {classical.init_bytes:5d}   {classical.reply_bytes:5d}   "
        f"{classical.finish_bytes:6d}   {classical.total_bytes:5d}"
    )
    print(
        f"  post-quantum    {pq.init_bytes:5d}   {pq.reply_bytes:5d}   "
        f"{pq.finish_bytes:6d}   {pq.total_bytes:5d}"
    )


def _print_interpretation(classical: PrimitiveMetrics, pq: PrimitiveMetrics, c_hs: HandshakeSizeMetrics, pq_hs: HandshakeSizeMetrics) -> None:
    print("\n[4] Interpretation")
    print(
        "  - Advantage of the post-quantum profile: resistance to future quantum attacks on"
        " public-key cryptography."
    )
    print(
        "  - Main cost: significantly larger public keys, ciphertexts, and signatures,"
        " which increases handshake bandwidth and storage requirements."
    )
    print(
        f"  - ML-KEM-768 public key overhead vs X25519: +{pq.kem_public_key_bytes - classical.kem_public_key_bytes} bytes."
    )
    print(
        f"  - ML-DSA-65 signature overhead vs Ed25519: +{pq.signature_bytes - classical.signature_bytes} bytes."
    )
    print(
        f"  - Total handshake payload overhead: +{pq_hs.total_bytes - c_hs.total_bytes} bytes for the PQ profile."
    )
    print(
        "  - Key management consequence: PQ bundles and transcript objects are bulkier,"
        " so server storage, API transport, and debugging tools are more stressed."
    )


if __name__ == "__main__":
    report = run_benchmark_report()

    print("=" * 72)
    print("  QSMP Classical vs Post-Quantum Metrics")
    print("=" * 72)
    print(f"Averages computed over {report['iterations']} iterations")
    print("Profiles compared:")
    print("  - Classical    : X25519 + Ed25519 + AES-256-GCM")
    print("  - Post-quantum : ML-KEM-768 + ML-DSA-65 + AES-256-GCM")

    _print_primitive_table(report["classical_primitives"], report["pq_primitives"])
    _print_timing_table(report["classical_timing"], report["pq_timing"])
    _print_handshake_table(report["classical_handshake"], report["pq_handshake"])
    _print_interpretation(
        report["classical_primitives"],
        report["pq_primitives"],
        report["classical_handshake"],
        report["pq_handshake"],
    )
    output_path = export_report_json(report)
    print(f"\n[5] JSON export written to: {output_path}")
    print("=" * 72)
