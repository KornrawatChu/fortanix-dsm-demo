"""
Common interface for every way the application can talk to Fortanix DSM.

The rest of the application ONLY depends on this interface. Whether the call
goes over raw REST, the official Python SDK (sdkms), or an offline mock is a
deployment choice made in .env, not something business code knows about.
"""
from __future__ import annotations

import base64
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

# Key operations every demo key needs. Note: no EXPORT -> key material can never leave DSM.
DEMO_KEY_OPS = ["ENCRYPT", "DECRYPT", "WRAPKEY", "UNWRAPKEY", "APPMANAGEABLE"]
RSA_KEY_OPS = ["ENCRYPT", "DECRYPT", "APPMANAGEABLE"]
# RSA keys must declare which paddings they allow; the demo uses OAEP with SHA-256.
RSA_OPTIONS = {"encryption_policy": [{"padding": {"OAEP": {"mgf": {"mgf1": {"hash": "SHA256"}}}}}]}


class DsmError(RuntimeError):
    pass


@dataclass
class EncryptResult:
    kid: str                    # exact key version DSM used -> stored with the data
    cipher: bytes
    iv: Optional[bytes] = None
    tag: Optional[bytes] = None  # only for authenticated modes (GCM)


@dataclass
class KeyInfo:
    kid: str
    name: Optional[str]
    obj_type: str
    key_size: Optional[int]
    created_at: Optional[str] = None
    enabled: bool = True
    state: Optional[str] = None
    replaced_by: Optional[str] = None  # set after a rotation
    raw: dict = field(default_factory=dict)


@dataclass
class ApiCall:
    """One DSM round-trip, kept so the UI can show exactly what went over the wire."""
    ts: float
    backend: str
    method: str
    path: str
    request: Any
    status: int
    response: Any
    ms: float


def b64e(b: Optional[bytes]) -> Optional[str]:
    return base64.b64encode(b).decode() if b is not None else None


def b64d(s: Optional[str]) -> Optional[bytes]:
    return base64.b64decode(s) if s else None


def _shorten(obj: Any, limit: int = 60) -> Any:
    """Truncate long base64 values so the call inspector stays readable."""
    if isinstance(obj, dict):
        return {k: _shorten(v, limit) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_shorten(v, limit) for v in obj[:5]] + (["..."] if len(obj) > 5 else [])
    if isinstance(obj, str) and len(obj) > limit:
        return obj[:limit] + f"...({len(obj)} chars)"
    return obj


class DsmClient(ABC):
    """The ONLY integration point between the application and Fortanix DSM."""

    backend_name = "base"

    def __init__(self) -> None:
        self.calls: list[ApiCall] = []

    # ---- call inspector -------------------------------------------------
    def _record(self, method: str, path: str, request: Any, status: int,
                response: Any, started: float) -> None:
        self.calls.append(ApiCall(
            ts=time.time(), backend=self.backend_name, method=method, path=path,
            request=_shorten(request), status=status, response=_shorten(response),
            ms=(time.perf_counter() - started) * 1000,
        ))
        del self.calls[:-200]  # keep the last 200 only

    def call_count(self) -> int:
        return len(self.calls)

    # ---- 1) authentication ---------------------------------------------
    @abstractmethod
    def authenticate(self) -> None:
        """Exchange the App API key for a short-lived bearer token."""

    # ---- 2) + 3) the two calls business code actually needs --------------
    @abstractmethod
    def encrypt(self, key_name: str, plain: bytes, mode: str, alg: str = "AES") -> EncryptResult:
        """Encrypt with the CURRENT version of the key called `key_name`.
        alg = "AES" | "RSA" (must match the key type in DSM); mode e.g. GCM, CBC, OAEP_MGF1_SHA256."""

    @abstractmethod
    def decrypt(self, kid: str, cipher: bytes, mode: str, iv: Optional[bytes] = None,
                tag: Optional[bytes] = None, alg: str = "AES") -> bytes:
        """Decrypt with the EXACT key version (kid) that encrypted the data."""

    # ---- key lifecycle (used by setup / rotation / compliance screens) ---
    @abstractmethod
    def get_key(self, name: str) -> Optional[KeyInfo]: ...

    @abstractmethod
    def get_key_by_kid(self, kid: str) -> Optional[KeyInfo]: ...

    @abstractmethod
    def create_aes_key(self, name: str, size: int, group_id: Optional[str] = None) -> KeyInfo: ...

    @abstractmethod
    def create_rsa_key(self, name: str, size: int = 2048, group_id: Optional[str] = None) -> KeyInfo: ...

    @abstractmethod
    def rename_key(self, kid: str, new_name: str) -> KeyInfo: ...

    @abstractmethod
    def rotate_key(self, name: str) -> KeyInfo: ...

    @abstractmethod
    def audit_logs(self, size: int = 50) -> list[dict]: ...


def parse_audit_hits(r: Any) -> list[dict]:
    """DSM returns audit logs Elasticsearch-style: {"hits": [{"_source": {...}}]}."""
    if isinstance(r, dict):
        r = r.get("hits", r.get("items", []))
    return [h.get("_source", h) if isinstance(h, dict) else h for h in (r or [])]


def to_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)
