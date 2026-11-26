"""
Fortanix DSM integration using the official Python SDK (`pip install sdkms`).

The SDK is a generated wrapper around the SAME REST endpoints as rest_client.py.
It saves the base64 / JSON plumbing, but the three integration points are
identical: authenticate -> encrypt (by key name) -> decrypt (by kid).
"""
from __future__ import annotations

import base64
import time
from typing import Optional

import sdkms.v1 as v1
from sdkms.v1.rest import ApiException

from .base import (DEMO_KEY_OPS, KEM_DEK_REQUEST, MLKEM_KEY_OPS, RSA_KEY_OPS, RSA_OPTIONS,
                   DsmClient, DsmError, EncryptResult, KeyInfo, parse_audit_hits, session_expired)
from .rest_client import key_info_from_json


def _val(x):
    """SDK enums -> plain string."""
    return getattr(x, "value", x)


def _key_info(k) -> KeyInfo:
    return KeyInfo(kid=k.kid, name=k.name, obj_type=_val(k.obj_type), key_size=k.key_size,
                   created_at=k.created_at, enabled=bool(k.enabled), state=_val(k.state),
                   raw=k.to_dict())


class SdkDsmClient(DsmClient):
    backend_name = "SDK"

    def __init__(self, endpoint: str, api_key: str, group_id: Optional[str] = None,
                 verify_tls: bool = True) -> None:
        super().__init__()
        self.group_id = group_id
        self.cfg = v1.Configuration()
        self.cfg.host = endpoint.rstrip("/")
        self.cfg.app_api_key = api_key
        self.cfg.verify_ssl = verify_tls
        self.api = v1.ApiClient(configuration=self.cfg)
        self._authed = False

    def _sdk(self, label: str, path: str, fn, request=None, _retry: bool = True):
        """Run one SDK call and record it like a REST call for the inspector."""
        if not self._authed:
            self.authenticate()
        started = time.perf_counter()
        try:
            res = fn()
        except ApiException as e:
            self._record(label, path, request, e.status, e.body, started)
            if session_expired(e.status, e.body):
                self._authed = False
                if _retry:                       # token expired -> re-auth once and retry
                    return self._sdk(label, path, fn, request, _retry=False)
            raise DsmError(f"DSM SDK {label} -> {e.status}: {e.body}") from e
        shown = res.to_dict() if hasattr(res, "to_dict") else (
            [r.to_dict() for r in res] if isinstance(res, list) else res)
        self._record(label, path, request, 200, shown, started)
        return res

    # ════════════════════════════════════════════════════════════════════
    # [DSM-INTEGRATION 1/3 · SDK]  AUTHENTICATE  (AuthenticationApi.authorize)
    # ════════════════════════════════════════════════════════════════════
    def authenticate(self) -> None:
        started = time.perf_counter()
        try:
            auth = v1.AuthenticationApi(api_client=self.api).authorize()
        except ApiException as e:
            self._record("AuthenticationApi.authorize", "/sys/v1/session/auth", None,
                         e.status, e.body, started)
            raise DsmError(f"DSM authentication failed ({e.status})") from e
        self.cfg.api_key["Authorization"] = auth.access_token
        self.cfg.api_key_prefix["Authorization"] = "Bearer"
        self._authed = True
        self._record("AuthenticationApi.authorize", "/sys/v1/session/auth",
                     {"app_api_key": "***"}, 200, {"token_type": auth.token_type,
                                                   "expires_in": auth.expires_in}, started)

    # ════════════════════════════════════════════════════════════════════
    # [DSM-INTEGRATION 2/3 · SDK]  ENCRYPT  (EncryptionAndDecryptionApi.encrypt_ex)
    # ════════════════════════════════════════════════════════════════════
    def encrypt(self, key_name: str, plain: bytes, mode: str, alg: str = "AES") -> EncryptResult:
        req = v1.EncryptRequestEx(
            key=v1.SobjectDescriptor(name=key_name),
            alg=v1.ObjectType(alg),                  # "AES" | "RSA"
            mode=v1.CryptMode(mode),                 # "GCM" | "CBC" | "OAEP_MGF1_SHA256"
            plain=bytearray(plain),
            tag_len=128 if (alg == "AES" and mode == "GCM") else None,
        )
        api = v1.EncryptionAndDecryptionApi(api_client=self.api)
        r = self._sdk("EncryptionAndDecryptionApi.encrypt_ex", "/crypto/v1/encrypt",
                      lambda: api.encrypt_ex(req),
                      {"key": {"name": key_name}, "alg": alg, "mode": mode, "plain": "<bytes>"})
        return EncryptResult(kid=r.kid, cipher=bytes(r.cipher),
                             iv=bytes(r.iv) if r.iv else None,
                             tag=bytes(r.tag) if r.tag else None)

    # ════════════════════════════════════════════════════════════════════
    # [DSM-INTEGRATION 3/3 · SDK]  DECRYPT  (EncryptionAndDecryptionApi.decrypt_ex)
    # ════════════════════════════════════════════════════════════════════
    def decrypt(self, kid: str, cipher: bytes, mode: str, iv: Optional[bytes] = None,
                tag: Optional[bytes] = None, alg: str = "AES") -> bytes:
        req = v1.DecryptRequestEx(
            key=v1.SobjectDescriptor(kid=kid),
            alg=v1.ObjectType(alg),
            mode=v1.CryptMode(mode),
            cipher=bytearray(cipher),
            iv=bytearray(iv) if iv else None,
            tag=bytearray(tag) if tag else None,
        )
        api = v1.EncryptionAndDecryptionApi(api_client=self.api)
        r = self._sdk("EncryptionAndDecryptionApi.decrypt_ex", "/crypto/v1/decrypt",
                      lambda: api.decrypt_ex(req),
                      {"key": {"kid": kid}, "alg": alg, "mode": mode, "cipher": "<bytes>"})
        return bytes(r.plain)

    # Key lifecycle -----------------------------------------------------------
    def _so(self):
        return v1.SecurityObjectsApi(api_client=self.api)

    def get_key(self, name: str) -> Optional[KeyInfo]:
        res = self._sdk("SecurityObjectsApi.get_security_objects", f"/crypto/v1/keys?name={name}",
                        lambda: self._so().get_security_objects(name=name))
        return _key_info(res[0]) if res else None

    def get_key_by_kid(self, kid: str) -> Optional[KeyInfo]:
        try:
            return _key_info(self._sdk("SecurityObjectsApi.get_security_object",
                                       f"/crypto/v1/keys/{kid}",
                                       lambda: self._so().get_security_object(kid)))
        except DsmError:
            return None

    def _sobject_request(self, name: str, size: int, group_id: Optional[str]):
        return v1.SobjectRequest(name=name, obj_type=v1.ObjectType.AES, key_size=size,
                                 key_ops=[v1.KeyOperations(op) for op in DEMO_KEY_OPS],
                                 group_id=group_id or self.group_id,
                                 description="KBTG DSM demo key")

    def create_aes_key(self, name: str, size: int, group_id: Optional[str] = None) -> KeyInfo:
        req = self._sobject_request(name, size, group_id)
        return _key_info(self._sdk("SecurityObjectsApi.generate_security_object",
                                   "/crypto/v1/keys", lambda: self._so().generate_security_object(req),
                                   {"name": name, "obj_type": "AES", "key_size": size}))

    def _raw(self, label: str, method: str, path: str, body: dict):
        """SDK generic call for requests whose generated models are awkward (RSA options, PATCH)."""
        return self._sdk(label, path, lambda: self.api.call_api(
            path, method, body=body, header_params={"Accept": "application/json",
                                                    "Content-Type": "application/json"},
            auth_settings=["bearerToken"], response_type="object", _return_http_data_only=True), body)

    def create_rsa_key(self, name: str, size: int = 2048, group_id: Optional[str] = None) -> KeyInfo:
        body = {"name": name, "obj_type": "RSA", "key_size": size, "key_ops": RSA_KEY_OPS,
                "rsa": RSA_OPTIONS, "group_id": group_id or self.group_id,
                "description": "KBTG DSM demo key (RSA)"}
        return key_info_from_json(self._raw("ApiClient.call_api", "POST", "/crypto/v1/keys", body))

    # Post-quantum ML-KEM: sdkms 5.11 has no ML-KEM models yet -> generic call_api, same endpoints as REST.
    def create_mlkem_key(self, name: str, param_set: str = "MlKem768",
                         group_id: Optional[str] = None) -> KeyInfo:
        body = {"name": name, "obj_type": "MLKEM", "mlkem": {"param_set": param_set},
                "key_ops": MLKEM_KEY_OPS, "group_id": group_id or self.group_id,
                "description": "KBTG DSM demo key (ML-KEM, post-quantum)"}
        return key_info_from_json(self._raw("ApiClient.call_api", "POST", "/crypto/v1/keys", body))

    def _export_transient(self, transient_key: str) -> bytes:
        r = self._raw("ApiClient.call_api", "POST", "/crypto/v1/keys/export", {"transient_key": transient_key})
        return base64.b64decode(r["value"])

    def encapsulate(self, key_name: str, dek_bits: int = 256) -> tuple[bytes, bytes]:
        r = self._raw("ApiClient.call_api", "POST", "/crypto/v1/encapsulate",
                      {"key": {"name": key_name}, "key_size": dek_bits, **KEM_DEK_REQUEST})
        return base64.b64decode(r["ciphertext"]), self._export_transient(r["key"]["transient_key"])

    def decapsulate(self, kid: str, kem_ciphertext: bytes, dek_bits: int = 256) -> bytes:
        r = self._raw("ApiClient.call_api", "POST", "/crypto/v1/decapsulate",
                      {"key": {"kid": kid}, "ciphertext": base64.b64encode(kem_ciphertext).decode(),
                       "key_size": dek_bits, **KEM_DEK_REQUEST})
        return self._export_transient(r["transient_key"])

    def rename_key(self, kid: str, new_name: str) -> KeyInfo:
        return key_info_from_json(self._raw("ApiClient.call_api", "PATCH", f"/crypto/v1/keys/{kid}",
                                            {"name": new_name}))

    def rotate_key(self, name: str) -> KeyInfo:
        cur = self.get_key(name)
        if cur is None:
            raise DsmError(f"Key '{name}' not found")
        if cur.obj_type == "RSA":
            return key_info_from_json(self._raw("ApiClient.call_api", "POST", "/crypto/v1/keys/rekey", {
                "name": name, "obj_type": "RSA", "key_size": cur.key_size, "key_ops": RSA_KEY_OPS,
                "rsa": RSA_OPTIONS}))
        req = self._sobject_request(name, cur.key_size, cur.raw.get("group_id"))
        return _key_info(self._sdk("SecurityObjectsApi.rotate_security_object",
                                   "/crypto/v1/keys/rekey",
                                   lambda: self._so().rotate_security_object(req),
                                   {"name": name, "obj_type": "AES", "key_size": cur.key_size}))

    def audit_logs(self, size: int = 50) -> list[dict]:
        # The generated LogsApi model does not match the live response shape ({"hits": [...]}),
        # so use the SDK's generic call_api with the same auth/session.
        res = self._sdk("ApiClient.call_api", f"/sys/v1/logs?size={size}",
                        lambda: self.api.call_api("/sys/v1/logs", "GET", query_params=[("size", size)],
                                                  header_params={"Accept": "application/json"},
                                                  auth_settings=["bearerToken"], response_type="object",
                                                  _return_http_data_only=True))
        return parse_audit_hits(res)
