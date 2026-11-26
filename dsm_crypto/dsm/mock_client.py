"""
OFFLINE MOCK of Fortanix DSM - for rehearsals or when the venue has no internet.

It mimics DSM behaviour (key names vs kids, rotation, CBC/GCM, audit log) with
local keys stored in data/mock_dsm.json. NEVER a security control - demo only.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .base import (DEMO_KEY_OPS, MLKEM_KEY_OPS, RSA_KEY_OPS, DsmClient, DsmError, EncryptResult, KeyInfo,
                   b64d, b64e)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class MockDsmClient(DsmClient):
    backend_name = "MOCK"

    def __init__(self, store: Path) -> None:
        super().__init__()
        self.store = store
        self.state = {"keys": {}, "logs": []}
        if store.exists():
            self.state = json.loads(store.read_text())

    def _save(self) -> None:
        self.store.parent.mkdir(parents=True, exist_ok=True)
        self.store.write_text(json.dumps(self.state, indent=1))

    def _log(self, action: str, msg: str, kid: Optional[str] = None) -> None:
        self.state["logs"].insert(0, {"time": _now(), "action_type": action, "actor_type": "app",
                                      "severity": "INFO", "message": msg, "object_id": kid})
        del self.state["logs"][500:]

    def _wrap(self, method, path, req, fn):
        started = time.perf_counter()
        time.sleep(0.004)  # pretend there is a network hop
        try:
            res = fn()
        except DsmError as e:
            self._record(method, path, req, 400, str(e), started)
            raise
        if isinstance(res, EncryptResult):          # show it like DSM's JSON response
            shown = {"kid": res.kid, "cipher": b64e(res.cipher), "iv": b64e(res.iv), "tag": b64e(res.tag)}
        elif isinstance(res, bytes):
            shown = {"plain": b64e(res)}
        elif isinstance(res, KeyInfo):
            shown = res.raw
        else:
            shown = res
        self._record(method, path, req, 200, shown, started)
        self._save()
        return res

    def _by_name(self, name: str) -> dict:
        for k in self.state["keys"].values():
            if k["name"] == name and not k.get("replaced_by"):
                return k
        raise DsmError(f"Sobject does not exist: name={name}")

    def _by_kid(self, kid: str) -> dict:
        k = self.state["keys"].get(kid)
        if not k:
            raise DsmError(f"Sobject does not exist: kid={kid}")
        return k

    @staticmethod
    def _info(k: dict) -> KeyInfo:
        return KeyInfo(kid=k["kid"], name=k["name"], obj_type=k.get("type", "AES"), key_size=k["key_size"],
                       created_at=k["created_at"], state="Active" if not k.get("replaced_by") else "Deactivated",
                       replaced_by=k.get("replaced_by"), raw={k2: v for k2, v in k.items() if k2 != "value"})

    @staticmethod
    def _check_alg(k: dict, alg: str) -> None:
        if k.get("type", "AES") != alg:
            raise DsmError("requested algorithm does not match the given key's type")

    @staticmethod
    def _oaep(mode: str):
        h = hashes.SHA256() if mode.endswith("SHA256") else hashes.SHA1()
        return asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=h), algorithm=h, label=None)

    # ------------------------------------------------------------------------
    def authenticate(self) -> None:
        self._wrap("POST", "/sys/v1/session/auth", {"Authorization": "Basic ***"},
                   lambda: {"token_type": "Bearer", "expires_in": 600, "access_token": "***"})

    def encrypt(self, key_name: str, plain: bytes, mode: str, alg: str = "AES") -> EncryptResult:
        def do():
            k = self._by_name(key_name)
            self._check_alg(k, alg)
            if alg == "RSA":
                priv = serialization.load_pem_private_key(b64d(k["value"]), password=None)
                try:
                    ct = priv.public_key().encrypt(plain, self._oaep(mode))
                except ValueError as e:
                    raise DsmError(f"RSA input too large: {e}") from e
                self._log("CryptoOperation", f"Encrypted data with key {key_name} (RSA {mode})", k["kid"])
                return EncryptResult(k["kid"], ct)
            key = b64d(k["value"])
            iv = os.urandom(12 if mode == "GCM" else 16)
            if mode == "GCM":
                ct = AESGCM(key).encrypt(iv, plain, None)
                res = EncryptResult(k["kid"], ct[:-16], iv, ct[-16:])
            elif mode == "CBC":
                p = padding.PKCS7(128).padder()
                data = p.update(plain) + p.finalize()
                e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
                res = EncryptResult(k["kid"], e.update(data) + e.finalize(), iv)
            else:
                raise DsmError(f"Unsupported mode {mode}")
            self._log("CryptoOperation", f"Encrypted data with key {key_name} ({mode})", k["kid"])
            return res
        r = self._wrap("POST", "/crypto/v1/encrypt",
                       {"key": {"name": key_name}, "alg": alg, "mode": mode, "plain": b64e(plain)}, do)
        return r

    def decrypt(self, kid: str, cipher: bytes, mode: str, iv: Optional[bytes] = None,
                tag: Optional[bytes] = None, alg: str = "AES") -> bytes:
        def do():
            k = self._by_kid(kid)
            self._check_alg(k, alg)
            if alg == "RSA":
                priv = serialization.load_pem_private_key(b64d(k["value"]), password=None)
                pt = priv.decrypt(cipher, self._oaep(mode))
                self._log("CryptoOperation", f"Decrypted data with key {k['name']} (RSA {mode})", kid)
                return pt
            key = b64d(k["value"])
            if mode == "GCM":
                pt = AESGCM(key).decrypt(iv, cipher + tag, None)
            else:
                d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                u = padding.PKCS7(128).unpadder()
                pt = u.update(d.update(cipher) + d.finalize()) + u.finalize()
            self._log("CryptoOperation", f"Decrypted data with key {k['name']} ({mode})", kid)
            return pt
        return self._wrap("POST", "/crypto/v1/decrypt",
                          {"key": {"kid": kid}, "alg": alg, "mode": mode, "cipher": b64e(cipher)}, do)

    def get_key(self, name: str) -> Optional[KeyInfo]:
        def do():
            try:
                return self._info(self._by_name(name))
            except DsmError:
                return None
        return self._wrap("GET", f"/crypto/v1/keys?name={name}", None, do)

    def get_key_by_kid(self, kid: str) -> Optional[KeyInfo]:
        k = self.state["keys"].get(kid)
        return self._info(k) if k else None

    def create_aes_key(self, name: str, size: int, group_id: Optional[str] = None) -> KeyInfo:
        def do():
            kid = str(uuid.uuid4())
            self.state["keys"][kid] = {"kid": kid, "name": name, "key_size": size,
                                       "key_ops": DEMO_KEY_OPS, "created_at": _now(),
                                       "value": b64e(os.urandom(size // 8))}
            self._log("Administrative", f"Created AES-{size} key {name}", kid)
            return self._info(self.state["keys"][kid])
        return self._wrap("POST", "/crypto/v1/keys", {"name": name, "obj_type": "AES", "key_size": size}, do)

    def create_rsa_key(self, name: str, size: int = 2048, group_id: Optional[str] = None) -> KeyInfo:
        def do():
            kid = str(uuid.uuid4())
            self.state["keys"][kid] = {"kid": kid, "name": name, "key_size": size, "type": "RSA",
                                       "key_ops": RSA_KEY_OPS, "created_at": _now(), "value": self._new_rsa(size)}
            self._log("Administrative", f"Created RSA-{size} key {name}", kid)
            return self._info(self.state["keys"][kid])
        return self._wrap("POST", "/crypto/v1/keys", {"name": name, "obj_type": "RSA", "key_size": size}, do)

    @staticmethod
    def _new_rsa(size: int) -> str:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=size)
        return b64e(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))

    # ML-KEM is SIMULATED here (no ML-KEM in the local crypto library): the "encapsulation" is the
    # DEK sealed with the key's secret. Same interface and behaviour as DSM, not real post-quantum crypto.
    def create_mlkem_key(self, name: str, param_set: str = "MlKem768",
                         group_id: Optional[str] = None) -> KeyInfo:
        def do():
            kid = str(uuid.uuid4())
            self.state["keys"][kid] = {"kid": kid, "name": name, "key_size": int("".join(c for c in param_set if c.isdigit())),
                                       "type": "MLKEM", "key_ops": MLKEM_KEY_OPS, "created_at": _now(),
                                       "value": b64e(os.urandom(32))}
            self._log("Administrative", f"Created ML-KEM key {name} ({param_set}, simulated)", kid)
            return self._info(self.state["keys"][kid])
        return self._wrap("POST", "/crypto/v1/keys", {"name": name, "obj_type": "MLKEM",
                                                      "mlkem": {"param_set": param_set}}, do)

    def encapsulate(self, key_name: str, dek_bits: int = 256) -> tuple[bytes, bytes]:
        def do():
            k = self._by_name(key_name)
            self._check_alg(k, "MLKEM")
            dek, nonce = os.urandom(dek_bits // 8), os.urandom(12)
            self._log("CryptoOperation", f"Encapsulated a DEK with key {key_name}", k["kid"])
            return nonce + AESGCM(b64d(k["value"])).encrypt(nonce, dek, None), dek
        return self._wrap("POST", "/crypto/v1/encapsulate", {"key": {"name": key_name}, "key_size": dek_bits}, do)

    def decapsulate(self, kid: str, kem_ciphertext: bytes, dek_bits: int = 256) -> bytes:
        def do():
            k = self._by_kid(kid)
            self._check_alg(k, "MLKEM")
            self._log("CryptoOperation", f"Decapsulated a DEK with key {k['name']}", kid)
            return AESGCM(b64d(k["value"])).decrypt(kem_ciphertext[:12], kem_ciphertext[12:], None)
        return self._wrap("POST", "/crypto/v1/decapsulate", {"key": {"kid": kid}}, do)

    def rename_key(self, kid: str, new_name: str) -> KeyInfo:
        def do():
            k = self._by_kid(kid)
            old_name, k["name"] = k["name"], new_name
            self._log("Administrative", f"Renamed key {old_name} -> {new_name}", kid)
            return self._info(k)
        return self._wrap("PATCH", f"/crypto/v1/keys/{kid}", {"name": new_name}, do)

    def rotate_key(self, name: str) -> KeyInfo:
        def do():
            old = self._by_name(name)
            kid = str(uuid.uuid4())
            value = (self._new_rsa(old["key_size"]) if old.get("type") == "RSA"
                     else b64e(os.urandom(old["key_size"] // 8)))
            self.state["keys"][kid] = {**old, "kid": kid, "created_at": _now(), "value": value}
            old["replaced_by"] = kid
            self._log("Administrative", f"Rotated key {name}: {old['kid'][:8]} -> {kid[:8]}", kid)
            return self._info(self.state["keys"][kid])
        return self._wrap("POST", "/crypto/v1/keys/rekey", {"name": name}, do)

    def audit_logs(self, size: int = 50) -> list[dict]:
        return self._wrap("GET", f"/sys/v1/logs?size={size}", None, lambda: self.state["logs"][:size])
