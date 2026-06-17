# QSMP REST Relay Server

This server is a minimal relay for the post-quantum messaging prototype.
It stores:

- public key bundles,
- opaque encrypted message payloads,
- sender/recipient metadata needed for delivery.

## Run

Use the local REST virtual environment because the project machine's Python 3.14
currently has a FastAPI/Pydantic compatibility issue.

```bash
cd /Users/noella/Desktop/MA1/Security/security_project
.venv-rest/bin/python -m uvicorn protocol.rest_server:app --host 127.0.0.1 --port 8000
```

Then open:

```text
http://127.0.0.1:8000/docs
```

The Swagger UI is useful for Postman-style manual testing.

## Endpoints

```text
POST /keys/{user_id}
GET  /keys/{user_id}
POST /messages/{user_id}
GET  /messages/{user_id}
```

## Authentication Headers

Every request uses a simple ML-DSA signed token:

```text
X-User-ID: alice
X-Auth-Token: demo-token
X-Auth-Signature: <base64 ML-DSA signature>
```

The signed payload is:

```text
QSMP-REST-AUTH-1|<user_id>|<token>
```

For `POST /keys/{user_id}`, the server verifies the signature using the
`identity_public_key` inside the submitted bundle. For all other routes, it
verifies using the public key already stored in SQLite.

## Key Bundle JSON

```json
{
  "identity_public_key": "base64...",
  "signed_prekey_public_key": "base64...",
  "bundle_signature": "base64..."
}
```

The server verifies the signed prekey bundle with ML-DSA before storing it.

## Encrypted Message JSON

```json
{
  "payload": {
    "header": {
      "version": "QSMP-1",
      "session_id": "base64...",
      "sender_id": "alice",
      "counter": 0,
      "ratchet_counter": 0,
      "previous_counter": 0,
      "flags": []
    },
    "nonce": "base64...",
    "ciphertext": "base64..."
  }
}
```

The server treats `payload` as opaque JSON. Decryption is only done by the
recipient client.

## Demo

In a second terminal, while the server is running:

```bash
cd /Users/noella/Desktop/MA1/Security/security_project
.venv-rest/bin/python protocol/rest_client_demo.py --base-url http://127.0.0.1:8000
```

Expected result:

```text
Same session id    : True
Messages received  : 1
Plaintext          : Bonjour Bob depuis le serveur REST.
```

## Tests

```bash
cd /Users/noella/Desktop/MA1/Security/security_project
.venv-rest/bin/python -m pytest -q protocol/test_rest_server.py
```

