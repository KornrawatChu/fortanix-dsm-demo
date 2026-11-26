"""
Field-level encryption service used by the business code.

Business code calls only:   protect(text) -> str     and     reveal(str) -> text

Every protected value is a small JSON envelope that carries its own metadata
(pattern, key name, kid, mode). That is what makes algorithm changes safe:
old and new formats live side by side and each record knows how to decrypt itself.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dsm_crypto.dsm.base import DsmClient, DsmError, b64d, b64e
from dsm_crypto.settings import Settings

FORMAT_VERSION = 1


# ---------------------------------------------------------------------------
# Envelope pattern only: algorithms the APP runs locally with the DEK.
# Switching between entries = config change. Adding a NEW algorithm
# (e.g. ChaCha20) = code change HERE - the one place, not all over the app.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class LocalCipher:
    key_bytes: int
    mode: str  # GCM | CBC

    def encrypt(self, key: bytes, plain: bytes) -> tuple[bytes, bytes, Optional[bytes]]:
        if self.mode == "GCM":
            iv = os.urandom(12)
            ct = AESGCM(key).encrypt(iv, plain, None)
            return iv, ct[:-16], ct[-16:]
        iv = os.urandom(16)
        p = padding.PKCS7(128).padder()
        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return iv, e.update(p.update(plain) + p.finalize()) + e.finalize(), None

    def decrypt(self, key: bytes, iv: bytes, ct: bytes, tag: Optional[bytes]) -> bytes:
        if self.mode == "GCM":
            return AESGCM(key).decrypt(iv, ct + tag, None)
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        u = padding.PKCS7(128).unpadder()
        return u.update(d.update(ct) + d.finalize()) + u.finalize()


LOCAL_CIPHERS: dict[str, LocalCipher] = {
    "AES-128-CBC": LocalCipher(16, "CBC"),
    "AES-256-CBC": LocalCipher(32, "CBC"),
    "AES-128-GCM": LocalCipher(16, "GCM"),
    "AES-256-GCM": LocalCipher(32, "GCM"),
}


class FieldEncryptor:
    def __init__(self, dsm: DsmClient, settings: Settings) -> None:
        self.dsm = dsm
        self.s = settings
        # Envelope: current DEK in memory + how many records it has protected
        self._dek: Optional[dict] = None
        self._dek_cache: dict[str, bytes] = {}   # wrapped DEK -> plain DEK (for reads)
        # Direct: key NAME -> (key type in DSM, looked-up-at) - see _key_type()
        self._type_cache: dict[str, tuple[str, float]] = {}

    # ════════════════════════════════════════════════════════════════════
    # [DSM-POLICY]  The ONLY two functions business code calls.
    #   protect(): plaintext -> self-describing ciphertext (JSON with kid + alg + mode)
    #   reveal():  reads kid + alg + mode from the stored value -> plaintext
    #   WHICH key: config.yaml (key_name).  WHAT TYPE of key (AES/RSA): asked from DSM.
    # ════════════════════════════════════════════════════════════════════
    def protect(self, text: str) -> str:
        rec = self._direct(text) if self.s.pattern == "direct" else self._envelope(text)
        return json.dumps(rec, separators=(",", ":"))

    def reveal(self, stored: str) -> str:
        rec = json.loads(stored)
        if rec["p"] == "direct":
            return self.dsm.decrypt(rec["kid"], b64d(rec["ct"]), rec["mode"], b64d(rec.get("iv")),
                                    b64d(rec.get("tag")), alg=rec.get("alg", "AES")).decode()
        dek = self._unwrap(rec)
        return LOCAL_CIPHERS[rec["alg"]].decrypt(dek, b64d(rec["iv"]), b64d(rec["ct"]),
                                                 b64d(rec.get("tag"))).decode()

    # =====================================================================
    # Pattern 1: DIRECT - DSM does the crypto
    # =====================================================================
    KEY_TYPE_TTL = 10.0       # seconds; a key-type change in DSM is picked up within this time
    RSA_MAX_PLAINTEXT = 190   # RSA-2048 + OAEP/SHA-256 can encrypt at most 190 bytes

    def _key_lookup(self, name: str, refresh: bool = False) -> tuple[str, str]:
        """Ask DSM what TYPE (AES / RSA / MLKEM) and current kid the key behind this name has,
        cached briefly. This is what lets the security team change the key type in DSM with no
        app change (RSA -> AES for data, RSA -> ML-KEM for envelope KEKs)."""
        hit = self._type_cache.get(name)
        if refresh or hit is None or time.monotonic() - hit[2] > self.KEY_TYPE_TTL:
            k = self.dsm.get_key(name)
            if k is None:
                raise DsmError(f"Key '{name}' not found in DSM")
            hit = self._type_cache[name] = (k.obj_type, k.kid, time.monotonic())
        return hit[0], hit[1]

    def _key_type(self, name: str, refresh: bool = False) -> str:
        return self._key_lookup(name, refresh)[0]

    def mode_for(self, alg: str) -> str:
        return self.s.rsa_mode if alg == "RSA" else self.s.mode

    def _direct(self, text: str, _retry: bool = True) -> dict:
        alg = self._key_type(self.s.key_name)
        mode = self.mode_for(alg)
        data = text.encode()
        if alg == "RSA" and len(data) > self.RSA_MAX_PLAINTEXT:
            raise ValueError(f"RSA-2048 can encrypt at most {self.RSA_MAX_PLAINTEXT} bytes (got {len(data)})")
        try:
            r = self.dsm.encrypt(self.s.key_name, data, mode, alg=alg)
        except DsmError as e:
            # Key type changed in DSM since we cached it -> look again and retry once.
            if _retry and "does not match" in str(e):
                self._key_type(self.s.key_name, refresh=True)
                return self._direct(text, _retry=False)
            raise
        return {"v": FORMAT_VERSION, "p": "direct", "key": self.s.key_name, "kid": r.kid, "alg": alg,
                "mode": mode, "iv": b64e(r.iv), "tag": b64e(r.tag), "ct": b64e(r.cipher)}

    # =====================================================================
    # Pattern 2: ENVELOPE - app does the crypto, DSM protects the DEK.
    # How the DEK is protected follows the TYPE of the KEK in DSM:
    #   AES   -> DSM wraps the DEK (AES-GCM)
    #   RSA   -> DSM wraps the DEK (RSA-OAEP)       <- quantum-vulnerable
    #   MLKEM -> DSM ENCAPSULATES a fresh DEK (ML-KEM, FIPS 203, post-quantum)
    # =====================================================================
    def _new_dek(self, bits: int) -> tuple[bytes, dict]:
        kek = self.s.kek_name
        kek_type, kek_kid = self._key_lookup(kek)
        if kek_type == "MLKEM":
            kem_ct, dek = self.dsm.encapsulate(kek, bits)                   # [PQC] DEK made + sealed in DSM
            return dek, {"kid": kek_kid, "alg": "MLKEM", "ct": b64e(kem_ct)}
        dek = os.urandom(bits // 8)                                          # DEK born in app memory
        mode = self.s.rsa_mode if kek_type == "RSA" else self.s.kek_mode
        w = self.dsm.encrypt(kek, dek, mode, alg=kek_type)                   # ...wrapped by the DSM KEK
        return dek, {"kid": w.kid, "alg": kek_type, "mode": mode, "iv": b64e(w.iv),
                     "tag": b64e(w.tag), "ct": b64e(w.cipher)}

    def _current_dek(self) -> dict:
        d = self._dek
        if (d is None or d["uses"] >= self.s.dek_max_records or d["alg"] != self.s.local_algorithm
                or d["kek"] != self.s.kek_name or d["kek_kid"] != self._key_lookup(self.s.kek_name)[1]):
            cipher = LOCAL_CIPHERS[self.s.local_algorithm]
            dek, wrapped = self._new_dek(cipher.key_bytes * 8)
            d = self._dek = {"dek": dek, "wrapped": wrapped, "uses": 0, "alg": self.s.local_algorithm,
                             "kek": self.s.kek_name, "kek_kid": wrapped["kid"]}
            self._dek_cache[wrapped["ct"]] = dek
        d["uses"] += 1
        return d

    def _envelope(self, text: str) -> dict:
        d = self._current_dek()
        iv, ct, tag = LOCAL_CIPHERS[d["alg"]].encrypt(d["dek"], text.encode())
        return {"v": FORMAT_VERSION, "p": "envelope", "key": self.s.kek_name, "kid": d["wrapped"]["kid"],
                "wdek": d["wrapped"], "alg": d["alg"], "iv": b64e(iv), "tag": b64e(tag), "ct": b64e(ct)}

    def _unwrap(self, rec: dict) -> bytes:
        w = rec["wdek"]
        dek = self._dek_cache.get(w["ct"])
        if dek is None:                                                # 1 DSM call per DEK, not per record
            kek_alg = w.get("alg", "AES")
            if kek_alg == "MLKEM":                                     # [PQC] decapsulate by exact kid
                dek = self.dsm.decapsulate(w["kid"], b64d(w["ct"]), LOCAL_CIPHERS[rec["alg"]].key_bytes * 8)
            else:
                dek = self.dsm.decrypt(w["kid"], b64d(w["ct"]), w["mode"], b64d(w.get("iv")),
                                       b64d(w.get("tag")), alg=kek_alg)
            self._dek_cache[w["ct"]] = dek
        return dek


# ---------------------------------------------------------------------------
# Helpers for the UI / re-encrypt job
# ---------------------------------------------------------------------------
def describe(stored: str) -> dict:
    rec = json.loads(stored)
    if rec["p"] == "direct":
        mode = "OAEP" if rec["mode"].startswith("OAEP") else rec["mode"]
        algo = f"DSM {rec.get('alg', 'AES')} ({mode})"
    else:
        w = rec["wdek"]
        kek_alg = w.get("alg", "AES")
        if kek_alg == "MLKEM":
            how = "DEK encapsulated by DSM ML-KEM (post-quantum)"
        elif kek_alg == "RSA":
            how = "DEK wrapped by DSM RSA-OAEP"
        else:
            how = f"DEK wrapped by DSM AES ({w.get('mode')})"
        algo = f"Local {rec['alg']} / {how}"
    return {"pattern": rec["p"], "key_name": rec["key"], "kid": rec["kid"], "algorithm": algo}


def is_current(stored: str, s: Settings, current_kid: Optional[str]) -> bool:
    rec = json.loads(stored)
    if rec["p"] != s.pattern:
        return False
    if s.pattern == "direct":
        alg = rec.get("alg", "AES")
        expected_mode = s.rsa_mode if alg == "RSA" else s.mode
        return rec["key"] == s.key_name and rec["mode"] == expected_mode and rec["kid"] == current_kid
    w = rec["wdek"]
    kek_alg = w.get("alg", "AES")
    expected_mode = {"AES": s.kek_mode, "RSA": s.rsa_mode}.get(kek_alg)   # MLKEM has no mode
    return (rec["key"] == s.kek_name and rec["alg"] == s.local_algorithm
            and w.get("mode") == expected_mode and rec["kid"] == current_kid)
