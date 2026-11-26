"""
Fortanix DSM integration over plain REST (HTTPS + JSON).

This file is the whole integration surface. Any language that can send an
HTTPS request (Java, Go, .NET, Node, COBOL gateway...) can do exactly the same.

  POST /sys/v1/session/auth        Basic <App API key>  -> bearer token
  POST /crypto/v1/encrypt          encrypt with key NAME (always latest version)
  POST /crypto/v1/decrypt          decrypt with key KID  (exact version used)
"""
from __future__ import annotations

import time
from typing import Any, Optional

import requests

from .base import (DEMO_KEY_OPS, RSA_KEY_OPS, RSA_OPTIONS, DsmClient, DsmError, EncryptResult,
                   KeyInfo, b64d, b64e, parse_audit_hits, session_expired)


def key_info_from_json(j: dict) -> KeyInfo:
    links = j.get("links") or {}
    return KeyInfo(
        kid=j.get("kid"), name=j.get("name"), obj_type=j.get("obj_type"),
        key_size=j.get("key_size"), created_at=j.get("created_at"),
        enabled=j.get("enabled", True), state=j.get("state"),
        replaced_by=links.get("replacement"), raw=j,
    )


class RestDsmClient(DsmClient):
    backend_name = "REST"

    def __init__(self, endpoint: str, api_key: str, group_id: Optional[str] = None,
                 verify_tls: bool = True, timeout: float = 15.0) -> None:
        super().__init__()
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key            # base64("app-uuid:secret") from DSM UI
        self.group_id = group_id
        self.timeout = timeout
        self.http = requests.Session()
        self.http.verify = verify_tls
        self._token: Optional[str] = None

    # ------------------------------------------------------------------ #
    # Low-level HTTP helper (every DSM call goes through here)           #
    # ------------------------------------------------------------------ #
    def _call(self, method: str, path: str, body: Any = None,
              params: Optional[dict] = None, _retry: bool = True) -> Any:
        if self._token is None:
            self.authenticate()
        started = time.perf_counter()
        r = self.http.request(
            method, self.endpoint + path, json=body, params=params,
            headers={"Authorization": f"Bearer {self._token}"}, timeout=self.timeout,
        )
        payload = r.json() if r.content and "json" in r.headers.get("content-type", "") else r.text
        self._record(method, path + (f"?{requests.compat.urlencode(params)}" if params else ""),
                     body, r.status_code, payload, started)
        if _retry and session_expired(r.status_code, payload):   # token expired -> re-auth once
            self._token = None
            return self._call(method, path, body, params, _retry=False)
        if r.status_code >= 400:
            raise DsmError(f"DSM {method} {path} -> {r.status_code}: {payload}")
        return payload

    # ════════════════════════════════════════════════════════════════════
    # [DSM-INTEGRATION 1/3]  AUTHENTICATE  ->  POST /sys/v1/session/auth
    #   App API key (Basic)  ->  short-lived bearer token
    # ════════════════════════════════════════════════════════════════════
    def authenticate(self) -> None:
        started = time.perf_counter()
        r = self.http.post(f"{self.endpoint}/sys/v1/session/auth",
                           headers={"Authorization": f"Basic {self.api_key}"},
                           timeout=self.timeout)
        body = r.json() if r.content else {}
        self._record("POST", "/sys/v1/session/auth", {"Authorization": "Basic ***"},
                     r.status_code, {k: ("***" if k == "access_token" else v)
                                     for k, v in body.items()}, started)
        if r.status_code >= 400:
            raise DsmError(f"DSM authentication failed ({r.status_code}): {body}")
        self._token = body["access_token"]

    # ════════════════════════════════════════════════════════════════════
    # [DSM-INTEGRATION 2/3]  ENCRYPT  ->  POST /crypto/v1/encrypt
    #   By key NAME -> DSM always uses the latest key version (rotation-safe)
    #   Algorithm/mode are PARAMETERS here - chosen by crypto_service from
    #   the key type in DSM + config.yaml, never hard-coded
    # ════════════════════════════════════════════════════════════════════
    def encrypt(self, key_name: str, plain: bytes, mode: str, alg: str = "AES") -> EncryptResult:
        body = {
            "key": {"name": key_name},
            "alg": alg,                # "AES" | "RSA"   <- algorithm choice is DATA, not code
            "mode": mode,              # "GCM" | "CBC" | "OAEP_MGF1_SHA256"
            "plain": b64e(plain),
        }
        if alg == "AES" and mode == "GCM":
            body["tag_len"] = 128
        r = self._call("POST", "/crypto/v1/encrypt", body)
        return EncryptResult(kid=r["kid"], cipher=b64d(r["cipher"]),
                             iv=b64d(r.get("iv")), tag=b64d(r.get("tag")))

    # ════════════════════════════════════════════════════════════════════
    # [DSM-INTEGRATION 3/3]  DECRYPT  ->  POST /crypto/v1/decrypt
    #   By KID -> the exact key version stored with the data
    # ════════════════════════════════════════════════════════════════════
    def decrypt(self, kid: str, cipher: bytes, mode: str, iv: Optional[bytes] = None,
                tag: Optional[bytes] = None, alg: str = "AES") -> bytes:
        body = {"key": {"kid": kid}, "alg": alg, "mode": mode, "cipher": b64e(cipher)}
        if iv is not None:
            body["iv"] = b64e(iv)
        if tag is not None:
            body["tag"] = b64e(tag)
        r = self._call("POST", "/crypto/v1/decrypt", body)
        return b64d(r["plain"])

    # ------------------------------------------------------------------ #
    # Key lifecycle                                                        #
    # ------------------------------------------------------------------ #
    def get_key(self, name: str) -> Optional[KeyInfo]:
        r = self._call("GET", "/crypto/v1/keys", params={"name": name})
        items = r if isinstance(r, list) else r.get("items", [])
        return key_info_from_json(items[0]) if items else None

    def get_key_by_kid(self, kid: str) -> Optional[KeyInfo]:
        try:
            return key_info_from_json(self._call("GET", f"/crypto/v1/keys/{kid}"))
        except DsmError:
            return None

    def create_aes_key(self, name: str, size: int, group_id: Optional[str] = None) -> KeyInfo:
        body = {"name": name, "obj_type": "AES", "key_size": size, "key_ops": DEMO_KEY_OPS,
                "description": "KBTG DSM demo key"}
        if group_id or self.group_id:
            body["group_id"] = group_id or self.group_id
        return key_info_from_json(self._call("POST", "/crypto/v1/keys", body))

    def create_rsa_key(self, name: str, size: int = 2048, group_id: Optional[str] = None) -> KeyInfo:
        body = {"name": name, "obj_type": "RSA", "key_size": size, "key_ops": RSA_KEY_OPS,
                "rsa": RSA_OPTIONS, "description": "KBTG DSM demo key (RSA)"}
        if group_id or self.group_id:
            body["group_id"] = group_id or self.group_id
        return key_info_from_json(self._call("POST", "/crypto/v1/keys", body))

    def rename_key(self, kid: str, new_name: str) -> KeyInfo:
        return key_info_from_json(self._call("PATCH", f"/crypto/v1/keys/{kid}", {"name": new_name}))

    def rotate_key(self, name: str) -> KeyInfo:
        cur = self.get_key(name)
        if cur is None:
            raise DsmError(f"Key '{name}' not found")
        body = {"name": name, "obj_type": cur.obj_type, "key_size": cur.key_size,
                "key_ops": cur.raw.get("key_ops", DEMO_KEY_OPS)}
        if cur.obj_type == "RSA":
            body["rsa"] = RSA_OPTIONS
        return key_info_from_json(self._call("POST", "/crypto/v1/keys/rekey", body))

    def audit_logs(self, size: int = 50) -> list[dict]:
        return parse_audit_hits(self._call("GET", "/sys/v1/logs", params={"size": size}))
