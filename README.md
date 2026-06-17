# Quantum-Safe E2EE Messaging Prototype

Post-quantum end-to-end encrypted messaging prototype developed for the
`Advanced Security` course at the University of Geneva.

The project implements:

- ML-KEM-768 for post-quantum key establishment
- ML-DSA-65 for post-quantum authentication
- AES-256-GCM for authenticated message encryption
- HKDF-SHA-512 for session and message-key derivation
- a minimal FastAPI relay server with SQLite storage
- MITM simulation, replay checks, and comparative benchmarks

## Project structure

- `crypto/`: cryptographic primitives and primitive-level tests
- `protocol/`: handshake, session, ratchet, relay, simulations, and benchmarks
- `security_report/`: LaTeX report, benchmark outputs, and figures

## Important note about `liboqs_src/`

The runtime code uses:

- the system `liboqs` shared library
- the Python package `liboqs-python`

In other words, `liboqs_src/` is optional reference material and can be omitted
from a project submission archive if size matters.

## Installation

### 1. System prerequisite: install `liboqs`

This project requires the C library `liboqs` to be installed on the machine.

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

### 2. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Verify installation

```bash
python3 -c "import oqs; print('oqs OK')"
```

## Running the main protocol demos

From the project root:

### Handshake demo

```bash
python3 protocol/handshake.py
```

### Session encryption / replay demo

```bash
python3 protocol/session.py
```

### Ratchet refresh demo

```bash
python3 protocol/ratchet.py
```

### MITM visibility / replay simulation

```bash
python3 protocol/mitm_simulation.py
```

## Relay server

Run the FastAPI relay:

```bash
uvicorn protocol.rest_server:create_app --factory --reload
```

The relay:

- stores public bundles
- queues ciphertext-only messages
- does not have access to plaintext or session keys

## Tests

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

If you use a dedicated environment for the REST stack:

```bash
pytest -q protocol/test_rest_server.py
```

## Benchmarking

Generate the comparison metrics between:

- classical profile: `X25519 + Ed25519`
- post-quantum profile: `ML-KEM-768 + ML-DSA-65`

### Export benchmark results

```bash
python3 protocol/benchmark_metrics.py
```

This writes:

- `security_report/benchmark_results.json`

### Generate the timing chart

```bash
python3 protocol/benchmark_plot.py
```

This writes:

- `security_report/benchmark_timing_chart.png`

## Report

The report sources are in:

- `security_report/main.tex`
- `security_report/sample.bib`

Related generated assets used by the report include:

- `security_report/benchmark_results.json`
- `security_report/benchmark_timing_chart.png`

## Submission advice

For a final academic submission, the recommended archive usually includes:

- `crypto/`
- `protocol/`
- `security_report/`
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

