from __future__ import annotations

import base64
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parents[1]))

try:
    from fastapi import FastAPI, Header, HTTPException
    from pydantic import BaseModel, Field
except ModuleNotFoundError as exc:  # pragma: no cover - exercised only without deps
    raise ModuleNotFoundError(
        "FastAPI dependencies are missing. Install them with: "
        "pip install fastapi uvicorn pydantic"
    ) from exc

from crypto import dsa
from protocol import handshake


AUTH_CONTEXT = b"QSMP-REST-AUTH-1"
DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "qsmp_relay.sqlite3"

## -------------------------------------
"""REST server : 
- endpoints REST
- token ML-DSA based authentication
- SQLite storage
- gestion bundles/messages 
"""

#Base64 helper functions: encode binary data as printable data
def b64e(data: bytes) -> str:
    #keys and signature need to be base64-encoded for JSON 
    return base64.b64encode(data).decode("ascii")

def b64d(data: str) -> bytes:
    #Base64 -> binary for crypto functions
    return base64.b64decode(data.encode("ascii"), validate=True)

#------------------ Authentication 

def build_auth_token_payload(user_id: str, token: str) -> bytes:
    """
    Payload signed by a client to authenticate to the REST relay.

    This prototype token proves ownership of the ML-DSA identity private key.
    It is intentionally simple and should be replaced with nonce/timestamp based
    challenge tokens in a production design.
    """
    return b"|".join([AUTH_CONTEXT, user_id.encode("utf-8"), token.encode("utf-8")])


class KeyBundleRequest(BaseModel):
    identity_public_key: str = Field(..., description="Base64 ML-DSA public key")
    signed_prekey_public_key: str = Field(..., description="Base64 ML-KEM public key")
    bundle_signature: str = Field(..., description="Base64 ML-DSA signature over the signed prekey")


class KeyBundleResponse(KeyBundleRequest):
    user_id: str


class EncryptedMessageRequest(BaseModel):
    payload: dict[str, Any] = Field(..., description="Opaque encrypted message JSON")


class QueuedMessage(BaseModel):
    id: int
    sender_id: str
    payload: dict[str, Any]
    created_at: str


class MessageBatch(BaseModel):
    messages: list[QueuedMessage]


class StatusResponse(BaseModel):
    status: str


class SQLiteRelayStore:

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:

        self.db_path = Path(db_path)
        self.init_db() # create tables if not exist

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

# Create tables
# key_bundles : user_id, identity_public_key, signed_prekey_public_key, bundle_signature, updated_at
# messages : id, recipient_id, sender_id, payload_json, created_at
    def init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS key_bundles (
                    user_id TEXT PRIMARY KEY,
                    identity_public_key BLOB NOT NULL,
                    signed_prekey_public_key BLOB NOT NULL,
                    bundle_signature BLOB NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_id TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def upsert_bundle(self, bundle: handshake.PreKeyBundle) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO key_bundles (
                    user_id,
                    identity_public_key,
                    signed_prekey_public_key,
                    bundle_signature,
                    updated_at
                )
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    identity_public_key=excluded.identity_public_key,
                    signed_prekey_public_key=excluded.signed_prekey_public_key,
                    bundle_signature=excluded.bundle_signature,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    bundle.user_id,
                    bundle.identity_public_key,
                    bundle.signed_prekey_public_key,
                    bundle.bundle_signature,
                ),
            )

    def get_bundle(self, user_id: str) -> handshake.PreKeyBundle | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT user_id, identity_public_key, signed_prekey_public_key, bundle_signature
                FROM key_bundles
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        return handshake.PreKeyBundle(
            user_id=row["user_id"],
            identity_public_key=row["identity_public_key"],
            signed_prekey_public_key=row["signed_prekey_public_key"],
            bundle_signature=row["bundle_signature"],
        )

    def get_identity_public_key(self, user_id: str) -> bytes | None:
        bundle = self.get_bundle(user_id)
        if bundle is None:
            return None
        return bundle.identity_public_key

    def queue_message(self, recipient_id: str, sender_id: str, payload: dict[str, Any]) -> None:
        canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO messages (recipient_id, sender_id, payload_json)
                VALUES (?, ?, ?)
                """,
                (recipient_id, sender_id, canonical_payload),
            )

    def pop_messages(self, user_id: str) -> list[QueuedMessage]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, sender_id, payload_json, created_at
                FROM messages
                WHERE recipient_id = ?
                ORDER BY id ASC
                """,
                (user_id,),
            ).fetchall()
            ids = [row["id"] for row in rows]
            if ids:
                placeholders = ",".join("?" for _ in ids)
                conn.execute(f"DELETE FROM messages WHERE id IN ({placeholders})", ids)
        return [
            QueuedMessage(
                id=row["id"],
                sender_id=row["sender_id"],
                payload=json.loads(row["payload_json"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]


def bundle_to_response(bundle: handshake.PreKeyBundle) -> KeyBundleResponse:
    return KeyBundleResponse(
        user_id=bundle.user_id,
        identity_public_key=b64e(bundle.identity_public_key),
        signed_prekey_public_key=b64e(bundle.signed_prekey_public_key),
        bundle_signature=b64e(bundle.bundle_signature),
    )


def request_to_bundle(user_id: str, request: KeyBundleRequest) -> handshake.PreKeyBundle:
    try:
        return handshake.PreKeyBundle(
            user_id=user_id,
            identity_public_key=b64d(request.identity_public_key),
            signed_prekey_public_key=b64d(request.signed_prekey_public_key),
            bundle_signature=b64d(request.bundle_signature),
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 key bundle") from exc


def verify_token_or_401(
    *,
    user_id: str,
    token: str,
    signature_b64: str,
    identity_public_key: bytes,
) -> None:
    try:
        signature = b64d(signature_b64)
        payload = build_auth_token_payload(user_id, token)
        ok = dsa.verify(payload, signature, identity_public_key)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid ML-DSA token") from exc
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid ML-DSA token")


def create_app(db_path: str | Path = DEFAULT_DB_PATH) -> FastAPI:
    store = SQLiteRelayStore(db_path)
    app = FastAPI(
        title="QSMP Relay Server",
        description="Minimal SQLite relay for end-to-end encrypted post-quantum messages.",
        version="0.1.0",
    )
#-----
# DEfine the REST API endpoints

    @app.get("/health")
    def health() -> StatusResponse:
        return StatusResponse(status="ok")

    @app.post("/keys/{user_id}")
    def publish_keys(
        user_id: str,
        request: KeyBundleRequest,
        x_user_id: str = Header(..., alias="X-User-ID"),
        x_auth_token: str = Header(..., alias="X-Auth-Token"),
        x_auth_signature: str = Header(..., alias="X-Auth-Signature"),
    ) -> StatusResponse:
        if x_user_id != user_id:
            raise HTTPException(status_code=403, detail="Token user does not match path user")

        bundle = request_to_bundle(user_id, request)
        verify_token_or_401(
            user_id=user_id,
            token=x_auth_token,
            signature_b64=x_auth_signature,
            identity_public_key=bundle.identity_public_key,
        )
        if not handshake.verify_prekey_bundle(bundle):
            raise HTTPException(status_code=400, detail="Invalid signed prekey bundle")

        store.upsert_bundle(bundle)
        return StatusResponse(status="ok")

    @app.get("/keys/{user_id}")
    def get_keys(
        user_id: str,
        x_user_id: str = Header(..., alias="X-User-ID"),
        x_auth_token: str = Header(..., alias="X-Auth-Token"),
        x_auth_signature: str = Header(..., alias="X-Auth-Signature"),
    ) -> KeyBundleResponse:
        authenticate_existing_user(store, x_user_id, x_auth_token, x_auth_signature)

        bundle = store.get_bundle(user_id)
        if bundle is None:
            raise HTTPException(status_code=404, detail="Key bundle not found")
        return bundle_to_response(bundle)

    @app.post("/messages/{user_id}")
    def post_message(
        user_id: str,
        request: EncryptedMessageRequest,
        x_user_id: str = Header(..., alias="X-User-ID"),
        x_auth_token: str = Header(..., alias="X-Auth-Token"),
        x_auth_signature: str = Header(..., alias="X-Auth-Signature"),
    ) -> StatusResponse:
        authenticate_existing_user(store, x_user_id, x_auth_token, x_auth_signature)
        if store.get_bundle(user_id) is None:
            raise HTTPException(status_code=404, detail="Recipient not found")

        store.queue_message(user_id, x_user_id, request.payload)
        return StatusResponse(status="queued")

    @app.get("/messages/{user_id}")
    def get_messages(
        user_id: str,
        x_user_id: str = Header(..., alias="X-User-ID"),
        x_auth_token: str = Header(..., alias="X-Auth-Token"),
        x_auth_signature: str = Header(..., alias="X-Auth-Signature"),
    ) -> MessageBatch:
        if x_user_id != user_id:
            raise HTTPException(status_code=403, detail="Users may only fetch their own messages")
        authenticate_existing_user(store, x_user_id, x_auth_token, x_auth_signature)
        return MessageBatch(messages=store.pop_messages(user_id))

    return app


def authenticate_existing_user(
    store: SQLiteRelayStore,
    user_id: str,
    token: str,
    signature_b64: str,
) -> None:
    identity_public_key = store.get_identity_public_key(user_id)
    if identity_public_key is None:
        raise HTTPException(status_code=401, detail="Unknown authenticated user")
    verify_token_or_401(
        user_id=user_id,
        token=token,
        signature_b64=signature_b64,
        identity_public_key=identity_public_key,
    )


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("protocol.rest_server:app", host="127.0.0.1", port=8000, reload=False)
