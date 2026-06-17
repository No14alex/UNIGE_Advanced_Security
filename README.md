# Quantum-Safe E2EE Messaging Prototype

Post-quantum end-to-end encrypted messaging prototype built for the `Advanced Security` course at the **University of Geneva**.

This project explores how a Signal/WhatsApp-inspired messaging architecture can be adapted to a post-quantum setting by replacing the classical public-key layer with NIST-standardized post-quantum primitives.

## Overview

The prototype implements:

- **ML-KEM-768** for post-quantum key establishment
- **ML-DSA-65** for post-quantum authentication and signatures
- **AES-256-GCM** for authenticated message encryption
- **HKDF-SHA-512** for session, chain, and message-key derivation
- a **FastAPI** relay server with **SQLite** storage
- a simplified **post-quantum ratchet**
- **MITM visibility** and **replay** simulations
- a **classical vs post-quantum benchmark**

The goal is not to reproduce the full complexity of Signal, but to provide a coherent research prototype that demonstrates:

- authenticated session establishment
- end-to-end encrypted message exchange
- replay rejection
- periodic key refresh
- practical trade-offs of post-quantum migration

## Why this project

Classical secure messaging protocols rely on public-key primitives such as X25519 and Ed25519. Those constructions are vulnerable to large-scale quantum computers through algorithms such as Shor's algorithm.

This prototype studies the impact of replacing:

- `X25519` with `ML-KEM-768`
- `Ed25519` with `ML-DSA-65`

while keeping the symmetric layer modern and efficient:

- `AES-256-GCM`
- `HKDF-SHA-512`

## Main features

### 1. Identity and bundle publication

Each user generates:

- a long-term ML-DSA identity key pair
- a signed ML-KEM prekey pair

The relay stores only the **public bundle**:

- user identifier
- ML-DSA public key
- ML-KEM signed prekey public key
- signature over the prekey

### 2. Authenticated 1.5-RTT handshake

The implemented handshake is an online authenticated three-message flow:

1. Alice sends a signed initiation containing a fresh ML-KEM ephemeral public key.
2. Bob verifies Alice, generates his own fresh ML-KEM ephemeral key, encapsulates to Alice, and signs the reply.
3. Alice verifies Bob, decapsulates, encapsulates back to Bob, and both sides derive the same session state.

The session state includes:

- root key
- sending chain key
- receiving chain key
- session identifier

### 3. Encrypted message exchange

Messages are protected with **AES-256-GCM**.

For each message:

- a fresh message key is derived from the current chain key
- the plaintext is encrypted with AES-GCM
- the protocol header is authenticated as **AAD** (Additional Authenticated Data)

This means metadata such as the session identifier, counters, and sender identity are not encrypted, but they are protected against tampering.

### 4. Replay protection

Each session maintains:

- a sending counter
- a receiving counter

If an attacker replays an old ciphertext, its counter no longer matches the expected receive state and the message is rejected.

### 5. Simplified post-quantum ratchet

The prototype also includes a simplified ratchet refresh mechanism:

- one party generates a fresh ML-KEM ephemeral key
- the peer encapsulates a new shared secret to it
- both sides mix this secret into the root-key schedule with HKDF

This improves key freshness over time, although it is intentionally simpler than a full production Double Ratchet.

## Threat model

The prototype is evaluated against an adversary able to:

- passively observe network traffic
- actively intercept, modify, delay, and replay messages
- control or observe the relay server
- apply classical or future quantum cryptanalysis against public-key components

The evaluation assumes that:

- client endpoints are not compromised during active sessions
- the relay is **untrusted** for confidentiality

## Repository structure

```text
.
├── crypto/            # ML-KEM, ML-DSA, AES-GCM, HKDF, primitive tests
├── protocol/          # authentication, handshake, session, ratchet, relay, benchmarks
├── requirements.txt
└── README.md
```

## Important note about `liboqs_src/`

The runtime code does **not** depend on the local `liboqs_src/` directory.

At runtime, the project uses:

- the system-installed **liboqs** shared library
- the Python package **liboqs-python**

So:

- `liboqs_src/` is useful as local reference material
- it is **not required** to run the project
- it can usually be excluded from a GitHub release archive or academic submission bundle

## Installation

### 1. Install the `liboqs` system library

This project requires the C library `liboqs`.

### macOS

```bash
brew install cmake ninja openssl
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cd liboqs
cmake -S . -B build -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build -j$(sysctl -n hw.logicalcpu)
sudo cmake --install build
echo 'export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH' >> ~/.zshrc
source ~/.zshrc
```

### 2. Create a Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Verify the OQS installation

```bash
python3 -c "import oqs; print('oqs OK')"
```

## Running the project

From the project root:

### Handshake demo

```bash
python3 protocol/handshake.py
```

### Session encryption and replay demo

```bash
python3 protocol/session.py
```

### Ratchet refresh demo

```bash
python3 protocol/ratchet.py
```

### MITM visibility and replay simulation

```bash
python3 protocol/mitm_simulation.py
```

### Benchmark generation

```bash
python3 protocol/benchmark_metrics.py
python3 protocol/benchmark_plot.py
```

## Running the relay server

Start the FastAPI relay with:

```bash
uvicorn protocol.rest_server:create_app --factory --reload
```

The relay:

- stores public bundles
- queues ciphertext-only messages
- does not learn plaintext messages
- does not store private keys or session secrets

## Running the tests

### Core protocol tests

```bash
pytest -q \
  crypto/test_aes.py \
  crypto/test_dsa.py \
  crypto/test_hkdf.py \
  crypto/test_kem.py \
  protocol/test_session.py \
  protocol/test_ratchet.py \
  protocol/test_mitm_simulation.py
```

### REST relay tests

```bash
pytest -q protocol/test_rest_server.py
```

## Benchmark summary

The benchmark compares:

- **Classical profile**: `X25519 + Ed25519 + AES-256-GCM`
- **Post-quantum profile**: `ML-KEM-768 + ML-DSA-65 + AES-256-GCM`

The benchmark measures:

- primitive sizes
- authenticated handshake payload sizes
- key generation time
- exchange / encapsulation cost
- decapsulation / peer exchange cost
- signing and verification time
- full authenticated handshake time

Generated outputs:

- `security_report/benchmark_results.json`
- `security_report/benchmark_timing_chart.png`

## What the evaluation shows

At a high level, the project demonstrates that:

- the relay can observe public metadata and ciphertexts, but not plaintext or session secrets
- replayed ciphertexts are rejected by the session layer
- authenticated session establishment works end-to-end
- post-quantum migration is practical in computation time
- the largest practical cost is **object size and handshake overhead**, not total runtime alone

These benchmark artifacts are generated locally by the benchmark scripts and do
not need to be versioned in the repository.

## Limitations

This is a research prototype, not a production-ready messenger.

Current limitations include:

- point-to-point only
- no group messaging
- no multi-device synchronization
- no full asynchronous PQXDH-style prekey handshake
- simplified ratchet rather than a full Double Ratchet
- minimal relay/API authentication design

## Submission / packaging advice

A minimal runnable archive usually only needs:

- `crypto/`
- `protocol/`
- `requirements.txt`
- `README.md`
- `conftest.py`
- `oqs_load.py`

It is generally safe to exclude:

- `.git/`
- `.venv/`, `.venv-rest/`
- `__pycache__/`, `.pytest_cache/`, `*.pyc`
- `.DS_Store`
- `liboqs_src/`

## License / academic context

This repository was developed as an academic project for:

- **Course**: Advanced Security
- **Institution**: University of Geneva
