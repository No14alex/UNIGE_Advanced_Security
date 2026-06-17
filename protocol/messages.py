from __future__ import annotations

from dataclasses import asdict, dataclass
import base64
import json


PROTOCOL_VERSION = "QSMP-1"


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass
class MessageHeader: #This is the AAD
    version: str
    session_id: bytes
    sender_id: str
    counter: int
    ratchet_counter: int
    previous_counter: int
    flags: list[str]

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "session_id": _b64e(self.session_id),
            "sender_id": self.sender_id,
            "counter": self.counter,
            "ratchet_counter": self.ratchet_counter,
            "previous_counter": self.previous_counter,
            "flags": self.flags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MessageHeader":
        return cls(
            version=data["version"],
            session_id=_b64d(data["session_id"]),
            sender_id=data["sender_id"],
            counter=data["counter"],
            ratchet_counter=data["ratchet_counter"],
            previous_counter=data["previous_counter"],
            flags=list(data["flags"]),
        )

    def aad_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class EncryptedMessage:
    #complete transmitted message : header(AAD)+nonce+ciphertext
    header: MessageHeader
    nonce: bytes
    ciphertext: bytes

    def to_dict(self) -> dict:
        return {
            "header": self.header.to_dict(),
            "nonce": _b64e(self.nonce),
            "ciphertext": _b64e(self.ciphertext),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedMessage":
        return cls(
            header=MessageHeader.from_dict(data["header"]),
            nonce=_b64d(data["nonce"]),
            ciphertext=_b64d(data["ciphertext"]),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> "EncryptedMessage":
        return cls.from_dict(json.loads(data))
