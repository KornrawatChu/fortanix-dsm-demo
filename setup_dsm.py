"""
One-time setup: create the demo keys in Fortanix DSM if they do not exist.

    python setup_dsm.py
"""
from __future__ import annotations

from dsm import DsmClient

# (name, type, size, purpose)
DEMO_KEYS = [
    ("kbtg-demo-aes128", "AES", 128, "Legacy policy key (AES-128)"),
    ("kbtg-demo-aes256", "AES", 256, "New policy key (AES-256)"),
    ("kbtg-demo-kek", "AES", 256, "Key-Encryption-Key for envelope pattern"),
    ("kbtg-demo-data-key", "RSA", 2048, "Starts as RSA; swapped to AES in scenario E"),
    ("kbtg-demo-kek-rsa", "RSA", 2048, "Legacy envelope KEK: RSA-wrapped DEKs (quantum-vulnerable)"),
    ("kbtg-demo-mlkem", "MLKEM", 768, "Post-quantum envelope KEK: ML-KEM-768 encapsulation"),
]


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

    from dsm import create_client

    load_dotenv()
    for row in ensure_keys(create_client()):
        print("  %-20s %-38s %s" % row)
