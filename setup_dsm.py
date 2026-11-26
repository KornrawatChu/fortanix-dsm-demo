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
]


def ensure_keys(dsm: DsmClient) -> list[tuple[str, str, str]]:
    out = []
    for name, typ, size, purpose in DEMO_KEYS:
        k = dsm.get_key(name)
        if k:
            out.append((name, k.kid, f"exists ({k.obj_type}-{k.key_size})"))
            continue
        k = dsm.create_rsa_key(name, size) if typ == "RSA" else dsm.create_aes_key(name, size)
        out.append((name, k.kid, f"created ({typ}-{size}) - {purpose}"))
    return out


if __name__ == "__main__":
    from dotenv import load_dotenv

    from dsm import create_client

    load_dotenv()
    for row in ensure_keys(create_client()):
        print("  %-20s %-38s %s" % row)
