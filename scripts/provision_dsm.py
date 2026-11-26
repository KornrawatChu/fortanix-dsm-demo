"""
Provision the demo keys in Fortanix DSM (creates only the ones that are missing).
This is the SECURITY team's job, not the application's: the key list lives in
config/demo_keys.yaml, and the app itself never reads it.

    python scripts/provision_dsm.py
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))  # project root on the import path

import yaml  # noqa: E402

from dsm_crypto.dsm import DsmClient  # noqa: E402

KEYS_FILE = _Path(__file__).resolve().parents[1] / "config" / "demo_keys.yaml"


def load_demo_keys() -> list[tuple[str, str, int, str]]:
    """(name, type, size, purpose) for every key in config/demo_keys.yaml."""
    data = yaml.safe_load(KEYS_FILE.read_text(encoding="utf-8"))
    return [(k["name"], k["type"].upper(), int(k["size"]), k.get("purpose", "")) for k in data["keys"]]


DEMO_KEYS = load_demo_keys()


def ensure_keys(dsm: DsmClient) -> list[tuple[str, str, str]]:
    out = []
    for name, typ, size, purpose in DEMO_KEYS:
        k = dsm.get_key(name)
        if k:
            size_label = k.key_size or (k.raw.get("mlkem") or {}).get("param_set", "")
            out.append((name, k.kid, f"exists ({k.obj_type}-{size_label})"))
            continue
        if typ == "RSA":
            k = dsm.create_rsa_key(name, size)
        elif typ == "MLKEM":
            k = dsm.create_mlkem_key(name, f"MlKem{size}")
        else:
            k = dsm.create_aes_key(name, size)
        out.append((name, k.kid, f"created ({typ}-{size}) - {purpose}"))
    return out


if __name__ == "__main__":
    from dotenv import load_dotenv

    from dsm_crypto.dsm import create_client

    load_dotenv(_Path(__file__).resolve().parents[1] / ".env")
    for row in ensure_keys(create_client()):
        print("  %-20s %-38s %s" % row)
