"""
Change the TYPE of the key behind a name (e.g. RSA -> AES) - something DSM "rotate" cannot do.

DSM refuses to rekey into a different object type, so the swap is:
  1. rename the current key   ->  "<name> (RSA retired 2026-11-26 02:40)"
  2. create a new key with the ORIGINAL name and the new type
The retired key keeps its kid, so data encrypted with it still decrypts.
Apps that encrypt by NAME start using the new key automatically.

This is the same thing you can do by hand in the DSM UI (Security Objects).

    python scripts/swap_key_type.py                              # kbtg-demo-data-key -> AES-256
    python scripts/swap_key_type.py kbtg-demo-data-key RSA       # swap back (to rehearse again)
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))  # project root on the import path

import sys
from datetime import datetime

from dsm_crypto.dsm import DsmClient, DsmError


def swap(dsm: DsmClient, name: str, new_type: str = "AES", size: int | None = None):
    cur = dsm.get_key(name)
    if cur is None:
        raise DsmError(f"No key named '{name}'")
    if cur.obj_type == new_type:
        raise DsmError(f"'{name}' is already {new_type} - nothing to do")
    retired = f"{name} ({cur.obj_type} retired {datetime.now():%Y-%m-%d %H:%M:%S})"
    dsm.rename_key(cur.kid, retired)
    try:
        new = (dsm.create_aes_key(name, size or 256) if new_type == "AES"
               else dsm.create_rsa_key(name, size or 2048))
    except DsmError:
        dsm.rename_key(cur.kid, name)          # roll back so the app keeps working
        raise
    return cur, retired, new


if __name__ == "__main__":
    from dotenv import load_dotenv

    from dsm_crypto.dsm import create_client

    load_dotenv(_Path(__file__).resolve().parents[1] / ".env")
    name = sys.argv[1] if len(sys.argv) > 1 else "kbtg-demo-data-key"
    new_type = (sys.argv[2] if len(sys.argv) > 2 else "AES").upper()
    old, retired, new = swap(create_client(), name, new_type)
    print(f"  retired : {old.obj_type}-{old.key_size}  kid {old.kid}  ->  renamed '{retired}'")
    print(f"  active  : {new.obj_type}-{new.key_size}  kid {new.kid}  ->  name '{name}'")
    print("  Apps encrypting by name now use the new key. Old data still decrypts by its kid.")
